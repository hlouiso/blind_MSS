/* Audit test: exercise a NON-ZERO leaf index end-to-end through the circuit.
 * The shipped tests all sign at leaf 0, so the auth-path swap (bit=1) and the
 * (level,index) tweak are never exercised. This drives a nonzero leaf through
 * prove (building_views) + verify() for every hidden party e, and checks the
 * reconstructed (root|sum) equals the native values. */
#include "../circuits.h"
#include "../shared.h"
#include "../xmss.h"
#include "../commitment.h"

#include "test_rng.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { int ok_=(c); printf("  %s %s\n", ok_?"ok  ":"FAIL",(m)); if(!ok_)failures++; } while(0)

static void run_leaf(uint32_t leaf)
{
    printf("--- leaf_index = %u (0x%X) ---\n", leaf, leaf);
    unsigned char sk_seed[32], pk_seed[XMSS_PK_SEED_BYTES];
    test_random_bytes(sk_seed, 32);
    test_random_bytes(pk_seed, XMSS_PK_SEED_BYTES);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    unsigned char m_hat[32], r[HM_R_BYTES], a_mat[HM_A_BYTES];
    test_random_bytes(m_hat, 32); test_random_bytes(r, sizeof r); test_random_bytes(a_mat, sizeof a_mat);
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, leaf, d, 32, &sig)) { printf("FAIL native sign\n"); exit(1); }
    CHECK(xmss_verify(pk_seed, root, d, 32, &sig), "native signature verifies");

    unsigned char input[W_END];
    memset(input, 0, W_END);
    memcpy(input + W_R_OFF, r, HM_R_BYTES);
    memcpy(input + W_A_OFF, a_mat, HM_A_BYTES);
    /* leaf index, big-endian (matches put_epoch_be / circuit load) */
    input[W_LEAFIDX_OFF+0] = (unsigned char)(leaf >> 24);
    input[W_LEAFIDX_OFF+1] = (unsigned char)(leaf >> 16);
    input[W_LEAFIDX_OFF+2] = (unsigned char)(leaf >> 8);
    input[W_LEAFIDX_OFF+3] = (unsigned char)(leaf);
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i*XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h*XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    uint32_t pubout[8];
    memset(pubout, 0, sizeof pubout);
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w*4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* One masked-values instance. */
    unsigned char seed_star[SEED_SIZE]; test_random_bytes(seed_star, SEED_SIZE);
    unsigned char seeds[N_PARTIES][SEED_SIZE];
    expand_seed_star(seed_star, seeds);
    unsigned char *lam[N_PARTIES], *tapes[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        lam[p] = malloc(INPUT_LEN); tapes[p] = malloc(TAPE_SIZE);
        expand_xshare(seeds[p], lam[p]); expand_tape(seeds[p], tapes[p]);
    }
    unsigned char *d_pub = malloc(INPUT_LEN);
    memcpy(d_pub, input, INPUT_LEN);
    for (int p = 0; p < N_PARTIES; p++)
        for (int b = 0; b < INPUT_LEN; b++) d_pub[b] ^= lam[p][b];

    uint32_t *aux = malloc((size_t)ySize*sizeof(uint32_t));
    uint32_t *s_all = malloc((size_t)N_PARTIES*ySize*sizeof(uint32_t));
    unsigned char r_j[32]; test_random_bytes(r_j, 32);
    a A; uint32_t zh[8];
    building_views(&A, m_hat, pk_seed, d_pub, lam, tapes, aux, s_all, r_j, zh);

    unsigned char circ_root[16];
    for (int w = 0; w < YP_ROOT_WORDS; w++) {
        uint32_t v = zh[w];
        for (int p = 0; p < N_PARTIES; p++) v ^= A.yp[p][w];
        memcpy(circ_root + w*4, &v, 4);
    }
    uint32_t circ_sum = zh[YP_SUM_WORD];
    for (int p = 0; p < N_PARTIES; p++) circ_sum ^= A.yp[p][YP_SUM_WORD];
    CHECK(memcmp(circ_root, root, 16) == 0, "prover circuit root == native root");
    CHECK(circ_sum == (uint32_t)XMSS_TARGET_SUM, "prover circuit sum == target");

    /* verify() for every hidden party e.  verify() overwrites A.h_prime with
     * its recomputation; keep the prover's value to check they agree. */
    unsigned char hp_prover[32];
    memcpy(hp_prover, A.h_prime, 32);
    for (int e = 0; e < N_PARTIES; e++) {
        z Z; Z.aux = aux; Z.x_offset = malloc(INPUT_LEN); Z.msgs_e = malloc((size_t)ySize*sizeof(uint32_t));
        for (int j = 0; j < N_PARTIES-1; j++) { int o=(j<e)?j:j+1; memcpy(Z.ke[j], seeds[o], SEED_SIZE); }
        memcpy(Z.x_offset, d_pub, INPUT_LEN);
        memcpy(Z.r_j, r_j, 32);
        compute_msgs_e(e, s_all, Z.msgs_e);
        bool err = false; uint32_t zhc[8];
        verify(m_hat, pk_seed, &err, &A, e, &Z, zhc);
        char msg[64]; snprintf(msg, sizeof msg, "verify() accepts honest proof (e=%d)", e);
        CHECK(!err, msg);
        int bind_ok = 1;
        for (int w = 0; w < 8; w++) {
            uint32_t v = zhc[w];
            for (int p = 0; p < N_PARTIES; p++) v ^= A.yp[p][w];
            if (v != pubout[w]) bind_ok = 0;
        }
        CHECK(bind_ok, "verify() output binding == pubout");
        CHECK(memcmp(A.h_prime, hp_prover, 32) == 0,
              "verify() recomputes the prover's h'_j");
        free(Z.x_offset); free(Z.msgs_e);
    }

    for (int p = 0; p < N_PARTIES; p++) { free(lam[p]); free(tapes[p]); }
    free(aux); free(s_all); free(d_pub);
}

int main(void)
{
    ASSERT_LIB_PARAMS();
    run_leaf(1);
    run_leaf(0x2A5);   /* 677: mixed bit pattern across all 10 levels */
    run_leaf(1023);    /* last leaf: all path bits = 1 */
    printf("\n%s (%d failure%s)\n", failures?"FAILURES":"ALL PASS", failures, failures==1?"":"s");
    return failures?1:0;
}
