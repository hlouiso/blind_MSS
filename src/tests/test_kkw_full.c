/* Full KKW protocol test (Trou 1): M_KKW instances, h* check.
 *
 * NOT in the default TESTS list — run manually:
 *   make N=4 && gcc -O2 -Wall -Wno-array-parameter -fopenmp \
 *     -I. tests/test_kkw_full.c circuits.o MPC_prove_functions.o \
 *     MPC_verify_functions.o shared.o xmss.o commitment.o gf128.o \
 *     -fopenmp -lssl -lcrypto -lm -o tests/test_kkw_full && ./tests/test_kkw_full
 *
 * With N=4: M_KKW=218 instances, NUM_ROUNDS=65. Takes ~30-120 s.
 */
#include "../circuits.h"
#include "../shared.h"
#include "../xmss.h"
#include "../commitment.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { \
    printf("  %s %s\n", (c) ? "ok  " : "FAIL", (m)); \
    if (!(c)) failures++; \
} while (0)

static void build_witness(unsigned char *input_out, unsigned char *m_hat_out,
                           unsigned char *pk_seed_out, uint32_t pubout_out[8])
{
    memset(input_out, 0, W_END);
    memset(pubout_out, 0, 8 * sizeof(uint32_t));

    unsigned char sk_seed[32];
    RAND_bytes(sk_seed, sizeof sk_seed);
    RAND_bytes(pk_seed_out, XMSS_PK_SEED_BYTES);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed_out, root);

    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    RAND_bytes(m_hat_out, 32);
    RAND_bytes(r, sizeof r);
    RAND_bytes(a_mat, sizeof a_mat);
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat_out, r, a_mat, com, d);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed_out, 0, d, 32, &sig)) {
        printf("native sign failed\n"); exit(1);
    }

    memcpy(input_out + W_R_OFF,   r,      HM_R_BYTES);
    memcpy(input_out + W_A_OFF,   a_mat,  HM_A_BYTES);
    memset(input_out + W_LEAFIDX_OFF, 0, 4);
    memcpy(input_out + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input_out + W_SIG_OFF + i*XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input_out + W_PATH_OFF + h*XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout_out[w], root + w*4, 4);
    pubout_out[YP_SUM_WORD] = XMSS_TARGET_SUM;
}

static void run_instance(const unsigned char seed_star[SEED_SIZE],
                          const unsigned char *input,
                          unsigned char *m_hat,
                          unsigned char *pk_seed,
                          unsigned char seeds_out[N_PARTIES][SEED_SIZE],
                          unsigned char *x_shares_out[N_PARTIES],
                          unsigned char *tapes_out[N_PARTIES],
                          a *a_out,
                          uint32_t *broadcast_out, uint32_t *aux_out)
{
    expand_seed_star(seed_star, seeds_out);
    for (int p = 0; p < N_PARTIES - 1; p++)
        expand_xshare(seeds_out[p], x_shares_out[p]);
    memcpy(x_shares_out[N_PARTIES - 1], input, INPUT_LEN);
    for (int p = 0; p < N_PARTIES - 1; p++)
        for (int b = 0; b < INPUT_LEN; b++)
            x_shares_out[N_PARTIES - 1][b] ^= x_shares_out[p][b];
    for (int p = 0; p < N_PARTIES; p++)
        expand_tape(seeds_out[p], tapes_out[p]);
    building_views(a_out, m_hat, pk_seed,
                   (unsigned char **)x_shares_out,
                   (unsigned char **)tapes_out,
                   broadcast_out, aux_out);
}

static void test_full_kkw(const unsigned char *input,
                           unsigned char *m_hat,
                           unsigned char *pk_seed,
                           const uint32_t pubout[8])
{
    printf("--- Full KKW protocol (M=%d, τ=%d, N=%d) ---\n",
           M_KKW, NUM_ROUNDS, N_PARTIES);

    unsigned char (*seed_stars)[SEED_SIZE] = malloc((size_t)M_KKW * SEED_SIZE);
    unsigned char (*h_j_all)[32]           = malloc((size_t)M_KKW * 32);
    unsigned char (*h_prime_all)[32]       = malloc((size_t)M_KKW * 32);
    if (!seed_stars || !h_j_all || !h_prime_all) {
        printf("  FAIL OOM\n"); failures++;
        free(seed_stars); free(h_j_all); free(h_prime_all); return;
    }

    unsigned char *x_shares[N_PARTIES], *tapes[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        x_shares[p] = malloc(INPUT_LEN);
        tapes[p]    = malloc(TAPE_SIZE);
    }
    uint32_t *broadcast = malloc(2 * ySize * sizeof(uint32_t));
    uint32_t *aux       = malloc(ySize * sizeof(uint32_t));

    printf("  Pass 1: generating %d instances...\n", M_KKW);
    bool pass1_ok = true;
    for (int j = 0; j < M_KKW; j++) {
        RAND_bytes(seed_stars[j], SEED_SIZE);
        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        a a_j;
        run_instance(seed_stars[j], input, m_hat, pk_seed,
                     seeds_j, x_shares, tapes, &a_j, broadcast, aux);

        for (int w = 0; w < 8; w++) {
            uint32_t xorv = 0;
            for (int p = 0; p < N_PARTIES; p++) xorv ^= a_j.yp[p][w];
            if (xorv != pubout[w]) { pass1_ok = false; }
        }
        preproc_commit_instance(seeds_j, aux, h_j_all[j]);
        memcpy(h_prime_all[j], a_j.h_prime, 32);
        if ((j+1) % 50 == 0 || j+1 == M_KKW)
            printf("    %d/%d\r", j+1, M_KKW);
    }
    printf("\n");
    CHECK(pass1_ok, "pass 1: all M_KKW circuits produce correct output XOR");

    /* Compute h*. */
    unsigned char h_val[32], h_prime_val[32], h_star[32];
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        unsigned int outl = 0;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_j_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_val, &outl);
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_prime_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_prime_val, &outl);
        EVP_MD_CTX_free(ctx);
        unsigned char in64[64];
        memcpy(in64, h_val, 32); memcpy(in64 + 32, h_prime_val, 32);
        sha256_once(in64, 64, h_star);
    }

    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fiat_shamir((const unsigned char *)m_hat, pubout, h_star, C_out, p_out);

    bool c_ok = true;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        if (C_out[k] < 0 || C_out[k] >= M_KKW) c_ok = false;
        if (k > 0 && C_out[k] <= C_out[k-1])   c_ok = false;
        if (p_out[k] < 0 || p_out[k] >= N_PARTIES) c_ok = false;
    }
    CHECK(c_ok, "kkw_fiat_shamir: C sorted/distinct in [0,M), p in [0,N)");

    bool in_C[M_KKW];
    memset(in_C, 0, sizeof(in_C));
    for (int k = 0; k < NUM_ROUNDS; k++) in_C[C_out[k]] = true;

    /* Preprocessing check. */
    printf("  Preprocessing check (%d instances)...\n", M_KKW - NUM_ROUNDS);
    uint32_t *aux_pp = malloc(ySize * sizeof(uint32_t));
    bool preproc_ok = true;
    for (int j = 0; j < M_KKW; j++) {
        if (in_C[j]) continue;
        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        expand_seed_star(seed_stars[j], seeds_j);
        compute_aux_from_seeds(seeds_j, aux_pp);
        unsigned char h_j_check[32];
        preproc_commit_instance(seeds_j, aux_pp, h_j_check);
        if (memcmp(h_j_check, h_j_all[j], 32) != 0) { preproc_ok = false; }
    }
    free(aux_pp);
    CHECK(preproc_ok, "preprocessing check: h_j recomputed from seed* matches");

    /* Online verification. */
    printf("  Online verification (%d rounds)...\n", NUM_ROUNDS);
    unsigned char h_j_verify[M_KKW][32], h_prime_verify[M_KKW][32];
    for (int j = 0; j < M_KKW; j++) {
        if (!in_C[j]) {
            memcpy(h_j_verify[j], h_j_all[j], 32);
            memcpy(h_prime_verify[j], h_prime_all[j], 32);
        }
    }

    bool online_ok = true;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        int j = C_out[k];
        int e = p_out[k];

        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        a a_j;
        run_instance(seed_stars[j], input, m_hat, pk_seed,
                     seeds_j, x_shares, tapes, &a_j, broadcast, aux);

        for (int p = 0; p < N_PARTIES; p++)
            H_com(seeds_j[p], x_shares[p], a_j.yp[p], a_j.h[p]);

        z Z;
        Z.broadcast  = broadcast;
        Z.aux        = aux;
        Z.x_revealed = malloc((size_t)(N_PARTIES-1) * INPUT_LEN);
        Z.msgs_e     = malloc((size_t)ySize * sizeof(uint32_t));
        for (int q = 0; q < N_PARTIES-1; q++) {
            int orig = (q < e) ? q : q+1;
            memcpy(Z.ke[q], seeds_j[orig], SEED_SIZE);
            memcpy(Z.x_revealed + (size_t)q * INPUT_LEN, x_shares[orig], INPUT_LEN);
        }
        memcpy(Z.yp_e, a_j.yp[e], 8 * sizeof(uint32_t));
        compute_msgs_e(e, tapes[e], broadcast, aux, Z.msgs_e);
        preproc_com_party(e, seeds_j[e], (e == 0 ? aux : NULL), Z.com_hidden);

        bool err = false;
        verify((unsigned char *)m_hat, (unsigned char *)pk_seed, &err, &a_j, e, &Z);
        if (err) online_ok = false;

        unsigned char coms[N_PARTIES][32];
        for (int p = 0; p < N_PARTIES; p++) {
            if (p == e) {
                memcpy(coms[p], Z.com_hidden, 32);
            } else {
                int slot = (p < e) ? p : p - 1;
                preproc_com_party(p, Z.ke[slot], (p == 0 ? aux : NULL), coms[p]);
            }
        }
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        unsigned int outl = 0;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int p = 0; p < N_PARTIES; p++) EVP_DigestUpdate(ctx, coms[p], 32);
        EVP_DigestFinal_ex(ctx, h_j_verify[j], &outl);
        EVP_MD_CTX_free(ctx);
        memcpy(h_prime_verify[j], a_j.h_prime, 32);

        free(Z.x_revealed); free(Z.msgs_e);

        if ((k+1) % 10 == 0 || k+1 == NUM_ROUNDS)
            printf("    %d/%d\r", k+1, NUM_ROUNDS);
    }
    printf("\n");
    CHECK(online_ok, "online verify: all τ rounds pass");

    /* Final h* check. */
    unsigned char h_check[32], h_prime_check[32], h_star_check[32];
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        unsigned int outl = 0;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_j_verify[j], 32);
        EVP_DigestFinal_ex(ctx, h_check, &outl);
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_prime_verify[j], 32);
        EVP_DigestFinal_ex(ctx, h_prime_check, &outl);
        EVP_MD_CTX_free(ctx);
        unsigned char in64[64];
        memcpy(in64, h_check, 32); memcpy(in64 + 32, h_prime_check, 32);
        sha256_once(in64, 64, h_star_check);
    }
    CHECK(memcmp(h_star_check, h_star, 32) == 0,
          "h* check: verifier reconstructs same h_star (Trou 1)");

    for (int p = 0; p < N_PARTIES; p++) { free(x_shares[p]); free(tapes[p]); }
    free(broadcast); free(aux);
    free(seed_stars); free(h_j_all); free(h_prime_all);
}

int main(void)
{
    unsigned char input[W_END], m_hat[32], pk_seed[XMSS_PK_SEED_BYTES];
    uint32_t pubout[8];
    build_witness(input, m_hat, pk_seed, pubout);

    test_full_kkw(input, (unsigned char *)m_hat, (unsigned char *)pk_seed, pubout);

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
