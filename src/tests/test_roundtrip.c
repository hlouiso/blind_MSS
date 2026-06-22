/* KKW prove -> verify roundtrip test for ONE round.
 *
 * Build from src/:
 *   gcc -O2 -Wall -Wextra -Wno-array-parameter \
 *     circuits.c MPC_prove_functions.c MPC_verify_functions.c \
 *     shared.c xmss.c commitment.c gf128.c tests/test_roundtrip.c \
 *     -lssl -lcrypto -o test_roundtrip
 */
#include "../circuits.h"
#include "../shared.h"
#include "../xmss.h"
#include "../commitment.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { \
    printf("  %s %s\n", (c) ? "ok  " : "FAIL", m); \
    if (!(c)) failures++; \
} while (0)

int main(void)
{
    unsigned char sk_seed[32], pk_seed[XMSS_PK_SEED_BYTES];
    RAND_bytes(sk_seed, sizeof sk_seed);
    RAND_bytes(pk_seed, sizeof pk_seed);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    unsigned char m_hat[32], r[HM_R_BYTES], a_mat[HM_A_BYTES];
    RAND_bytes(m_hat, sizeof m_hat);
    RAND_bytes(r, sizeof r);
    RAND_bytes(a_mat, sizeof a_mat);
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, 0, d, 32, &sig)) {
        printf("native sign failed\n"); return 1;
    }

    unsigned char input[W_END];
    memcpy(input + W_R_OFF,   r,      HM_R_BYTES);
    memcpy(input + W_A_OFF,   a_mat,  HM_A_BYTES);
    memset(input + W_LEAFIDX_OFF, 0, 4);
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i*XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h*XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w*4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ── KKW prover: one round ── */
    unsigned char seeds[N_PARTIES][SEED_SIZE];
    RAND_bytes(seeds[0], N_PARTIES * SEED_SIZE);

    unsigned char *x_shares[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) x_shares[p] = malloc(INPUT_LEN);
    for (int p = 0; p < N_PARTIES-1; p++) RAND_bytes(x_shares[p], INPUT_LEN);
    for (int b = 0; b < INPUT_LEN; b++) {
        unsigned char v = input[b];
        for (int p = 0; p < N_PARTIES-1; p++) v ^= x_shares[p][b];
        x_shares[N_PARTIES-1][b] = v;
    }

    unsigned char *tapes[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        tapes[p] = malloc((size_t)TAPE_SIZE);
        expand_tape(seeds[p], tapes[p]);
    }

    uint32_t *broadcast = calloc((size_t)(2 * ySize), sizeof(uint32_t));
    uint32_t *aux       = calloc((size_t)ySize,       sizeof(uint32_t));

    a A;
    building_views(&A, m_hat, pk_seed, x_shares, tapes, broadcast, aux);

    int out_ok = 1;
    for (int j = 0; j < 8; j++) {
        uint32_t xorv = 0;
        for (int p = 0; p < N_PARTIES; p++) xorv ^= A.yp[p][j];
        if (xorv != pubout[j]) out_ok = 0;
    }
    CHECK(out_ok, "prover output XOR == (root | target-sum | 0)");

    /* Commitments */
    for (int p = 0; p < N_PARTIES; p++)
        H_com(seeds[p], x_shares[p], A.yp[p], A.h[p]);

    /* ── Verify all N challenges ── */
    for (int e = 0; e < N_PARTIES; e++) {
        /* Build z for this challenge */
        z Z;
        Z.broadcast  = broadcast;
        Z.aux        = aux;
        Z.x_revealed = malloc((size_t)(N_PARTIES-1) * INPUT_LEN);
        for (int j = 0; j < N_PARTIES-1; j++) {
            int orig = (j < e) ? j : j+1;
            memcpy(Z.ke[j], seeds[orig], SEED_SIZE);
            memcpy(Z.x_revealed + (size_t)j * INPUT_LEN, x_shares[orig], INPUT_LEN);
        }
        memcpy(Z.yp_e, A.yp[e], 8 * sizeof(uint32_t));

        bool err = false;
        verify(m_hat, pk_seed, &err, &A, e, &Z);
        char msg[48];
        snprintf(msg, sizeof msg, "verify accepts honest proof (e=%d)", e);
        CHECK(!err, msg);
        free(Z.x_revealed);
    }

    /* ── Tamper: corrupt a sig_hash share, expect output mismatch ── */
    {
        x_shares[0][W_SIG_OFF] ^= 0x01;
        building_views(&A, m_hat, pk_seed, x_shares, tapes, broadcast, aux);
        int still_root = 1;
        for (int w = 0; w < YP_ROOT_WORDS; w++) {
            uint32_t v = 0;
            for (int p = 0; p < N_PARTIES; p++) v ^= A.yp[p][w];
            if (v != pubout[w]) { still_root = 0; break; }
        }
        CHECK(!still_root, "tampered witness changes the circuit output");
    }

    for (int p = 0; p < N_PARTIES; p++) { free(x_shares[p]); free(tapes[p]); }
    free(broadcast); free(aux);

    /* ── H3 range check ── */
    {
        /* Allocate zero-filled broadcast/aux for the range test. */
        uint32_t *bcast_fake = calloc((size_t)(2 * ySize), sizeof(uint32_t));
        uint32_t *aux_fake   = calloc((size_t)ySize,       sizeof(uint32_t));
        z fake_z;
        memset(&fake_z, 0, sizeof fake_z);
        fake_z.broadcast = bcast_fake;
        fake_z.aux       = aux_fake;

        a *as_arr[NUM_ROUNDS];
        z *zs_arr[NUM_ROUNDS];
        for (int r = 0; r < NUM_ROUNDS; r++) { as_arr[r] = &A; zs_arr[r] = &fake_z; }
        unsigned char fake_digest[32] = {0};
        uint32_t fake_pubout[8] = {0};
        int es[NUM_ROUNDS];
        H3(fake_digest, fake_pubout, as_arr, zs_arr, NUM_ROUNDS, es);
        int range_ok = 1;
        for (int r = 0; r < NUM_ROUNDS; r++)
            if (es[r] < 0 || es[r] >= N_PARTIES) { range_ok = 0; break; }
        CHECK(range_ok, "H3: all challenges in [0, N_PARTIES)");
        printf("  (N_PARTIES=%d, NUM_ROUNDS=%d)\n", N_PARTIES, NUM_ROUNDS);
        free(bcast_fake); free(aux_fake);
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
