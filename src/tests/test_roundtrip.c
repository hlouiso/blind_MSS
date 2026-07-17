/* KKW prove → verify roundtrip test (light).
 *
 * Tests:
 *   1. Single-round: prove+verify for e=0 and e=N_PARTIES-1.
 *   2. Preprocessing smoke: expand/commit/aux determinism + Fiat-Shamir range.
 *   3. Tamper check.
 *
 * The full M_KKW-instance protocol is exercised end-to-end by test_e2e. */
#include "../circuits.h"
#include "../shared.h"
#include "../xmss.h"
#include "../commitment.h"

#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
/* Evaluate the condition exactly once (side-effecting expressions). */
#define CHECK(c, m) do { \
    int check_ok_ = (c); \
    printf("  %s %s\n", check_ok_ ? "ok  " : "FAIL", (m)); \
    if (!check_ok_) failures++; \
} while (0)

/* ── Build XMSS witness ─────────────────────────────────────────────────── */

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

/* ── Run building_views for one masked-values instance ───────────────────── */

static void run_instance(const unsigned char seed_star[SEED_SIZE],
                          const unsigned char *input,
                          const unsigned char *m_hat,
                          const unsigned char *pk_seed,
                          unsigned char seeds_out[N_PARTIES][SEED_SIZE],
                          unsigned char *lam_out[N_PARTIES],   /* INPUT_LEN each */
                          unsigned char *tapes_out[N_PARTIES], /* TAPE_SIZE each */
                          unsigned char *d_out,                /* INPUT_LEN */
                          a *a_out,
                          uint32_t *aux_out,
                          uint32_t *s_all_out,                 /* N*ySize words */
                          const unsigned char *r_j,            /* 32 B, NULL iff s_all NULL */
                          uint32_t zh_out[8])
{
    expand_seed_star(seed_star, seeds_out);
    for (int p = 0; p < N_PARTIES; p++) {
        expand_xshare(seeds_out[p], lam_out[p]);
        expand_tape(seeds_out[p], tapes_out[p]);
    }
    memcpy(d_out, input, INPUT_LEN);
    for (int p = 0; p < N_PARTIES; p++)
        for (int b = 0; b < INPUT_LEN; b++)
            d_out[b] ^= lam_out[p][b];
    building_views(a_out, m_hat, pk_seed, d_out, lam_out, tapes_out,
                   aux_out, s_all_out, r_j, zh_out);
}

/* ── Test 1: single-round prove+verify for e=0 and e=N_PARTIES-1 only ── */

static void test_single_round(void)
{
    printf("--- Test 1: single-round prove+verify (e=0 and e=N-1) ---\n");

    unsigned char input[W_END], m_hat[32], pk_seed[XMSS_PK_SEED_BYTES];
    uint32_t pubout[8];
    build_witness(input, m_hat, pk_seed, pubout);

    unsigned char seed_star[SEED_SIZE];
    RAND_bytes(seed_star, SEED_SIZE);

    unsigned char seeds[N_PARTIES][SEED_SIZE];
    unsigned char *lam[N_PARTIES], *tapes[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        lam[p]   = malloc(INPUT_LEN);
        tapes[p] = malloc(TAPE_SIZE);
    }
    unsigned char *d_pub = malloc(INPUT_LEN);
    uint32_t *aux   = malloc(ySize * sizeof(uint32_t));
    uint32_t *s_all = malloc((size_t)N_PARTIES * ySize * sizeof(uint32_t));
    unsigned char r_j[32];
    RAND_bytes(r_j, 32);
    a A;
    uint32_t zh[8];
    run_instance(seed_star, input, m_hat, pk_seed, seeds,
                 lam, tapes, d_pub, &A, aux, s_all, r_j, zh);

    int out_ok = 1;
    for (int j = 0; j < 8; j++) {
        uint32_t v = zh[j];
        for (int p = 0; p < N_PARTIES; p++) v ^= A.yp[p][j];
        if (v != pubout[j]) out_ok = 0;
    }
    CHECK(out_ok, "prover unmasked output == pubout");

    /* verify() overwrites A.h_prime with its recomputation — keep the
     * prover's value to check they agree (the h* check relies on this). */
    unsigned char hp_prover[32];
    memcpy(hp_prover, A.h_prime, 32);

    int test_e[] = { 0, N_PARTIES - 1 };
    for (int ti = 0; ti < 2; ti++) {
        int e = test_e[ti];
        z Z;
        Z.aux        = aux;
        Z.x_offset   = malloc((size_t)INPUT_LEN);
        Z.msgs_e     = malloc((size_t)ySize * sizeof(uint32_t));
        for (int j = 0; j < N_PARTIES-1; j++) {
            int orig = (j < e) ? j : j+1;
            memcpy(Z.ke[j], seeds[orig], SEED_SIZE);
        }
        memcpy(Z.x_offset, d_pub, INPUT_LEN);
        memcpy(Z.r_j, r_j, 32);
        compute_msgs_e(e, s_all, Z.msgs_e);

        bool err = false;
        uint32_t zh_check[8];
        verify(m_hat, pk_seed, &err, &A, e, &Z, zh_check);
        char msg[64];
        snprintf(msg, sizeof msg, "verify accepts honest proof (e=%d)", e);
        CHECK(!err, msg);
        CHECK(memcmp(zh_check, zh, sizeof zh) == 0,
              "verify reconstructs the prover's public masked output");
        CHECK(memcmp(A.h_prime, hp_prover, 32) == 0,
              "verify recomputes the prover's h'_j");
        free(Z.x_offset); free(Z.msgs_e);
    }

    for (int p = 0; p < N_PARTIES; p++) { free(lam[p]); free(tapes[p]); }
    free(aux); free(s_all); free(d_pub);
}

/* ── Test 2: preprocessing function smoke test ── */

static void test_preproc_smoke(void)
{
    printf("--- Test 2: preprocessing smoke (expand/commit/aux/fiat-shamir) ---\n");

    unsigned char seed_star[SEED_SIZE];
    RAND_bytes(seed_star, SEED_SIZE);

    /* expand_seed_star: produces N_PARTIES distinct seeds */
    unsigned char seeds[N_PARTIES][SEED_SIZE];
    expand_seed_star(seed_star, seeds);

    int seeds_distinct = 1;
    for (int i = 0; i < N_PARTIES && seeds_distinct; i++)
        for (int j = i+1; j < N_PARTIES && seeds_distinct; j++)
            if (memcmp(seeds[i], seeds[j], SEED_SIZE) == 0) seeds_distinct = 0;
    CHECK(seeds_distinct, "expand_seed_star: N_PARTIES distinct party seeds");

    /* expand_seed_star is deterministic */
    unsigned char seeds2[N_PARTIES][SEED_SIZE];
    expand_seed_star(seed_star, seeds2);
    CHECK(memcmp(seeds, seeds2, sizeof seeds) == 0,
          "expand_seed_star: deterministic");

    /* expand_xshare is deterministic */
    unsigned char xs1[INPUT_LEN], xs2[INPUT_LEN];
    expand_xshare(seeds[0], xs1);
    expand_xshare(seeds[0], xs2);
    CHECK(memcmp(xs1, xs2, INPUT_LEN) == 0, "expand_xshare: deterministic");

    /* compute_aux_from_seeds: deterministic (aux and h_out) */
    uint32_t *aux1 = malloc(ySize * sizeof(uint32_t));
    uint32_t *aux2 = malloc(ySize * sizeof(uint32_t));
    unsigned char h_out1[32], h_out2[32];
    compute_aux_from_seeds(seeds, aux1, h_out1);
    compute_aux_from_seeds(seeds, aux2, h_out2);
    CHECK(memcmp(aux1, aux2, ySize * sizeof(uint32_t)) == 0 &&
          memcmp(h_out1, h_out2, 32) == 0,
          "compute_aux_from_seeds: deterministic (aux + h_out)");

    /* aux depends only on the masks: a full run with a real witness and real
     * publics must produce the exact same aux stream (this is what makes the
     * offline preprocessing check sound). */
    {
        unsigned char input[W_END], m_hat[32], pk_seed[XMSS_PK_SEED_BYTES];
        uint32_t pubout[8];
        build_witness(input, m_hat, pk_seed, pubout);

        unsigned char *lam[N_PARTIES], *tp[N_PARTIES];
        for (int p = 0; p < N_PARTIES; p++) {
            lam[p] = malloc(INPUT_LEN);
            tp[p]  = malloc(TAPE_SIZE);
            expand_xshare(seeds[p], lam[p]);
            expand_tape(seeds[p], tp[p]);
        }
        unsigned char *d_pub = malloc(INPUT_LEN);
        memcpy(d_pub, input, INPUT_LEN);
        for (int p = 0; p < N_PARTIES; p++)
            for (int b = 0; b < INPUT_LEN; b++) d_pub[b] ^= lam[p][b];

        uint32_t *aux_ref = malloc(ySize * sizeof(uint32_t));
        a ref_a;
        uint32_t zh[8];
        building_views(&ref_a, m_hat, pk_seed, d_pub, lam, tp, aux_ref, NULL,
                       NULL, zh);
        CHECK(memcmp(aux1, aux_ref, ySize * sizeof(uint32_t)) == 0,
              "compute_aux_from_seeds == aux of a real-witness run");
        /* yp (output-mask shares) must be witness-independent too: this is
         * what lets the verifier recompute h_out_j from seed* alone. */
        unsigned char h_out_ref[32];
        KKW_TH(KKW_DOM_HOUT, ref_a.yp,
               (size_t)N_PARTIES * 8 * sizeof(uint32_t), h_out_ref);
        CHECK(memcmp(h_out1, h_out_ref, 32) == 0,
              "compute_aux_from_seeds h_out == h_out of a real-witness run");
        for (int p = 0; p < N_PARTIES; p++) { free(lam[p]); free(tp[p]); }
        free(aux_ref); free(d_pub);
    }

    /* preproc_commit_instance: deterministic */
    unsigned char h1[32], h2[32];
    preproc_commit_instance(seeds, aux1, h1);
    preproc_commit_instance(seeds, aux1, h2);
    CHECK(memcmp(h1, h2, 32) == 0, "preproc_commit_instance: deterministic");

    /* different seeds → different commitment */
    unsigned char seed_star2[SEED_SIZE];
    RAND_bytes(seed_star2, SEED_SIZE);
    unsigned char seeds3[N_PARTIES][SEED_SIZE];
    expand_seed_star(seed_star2, seeds3);
    uint32_t *aux3 = malloc(ySize * sizeof(uint32_t));
    compute_aux_from_seeds(seeds3, aux3, NULL);
    unsigned char h3[32];
    preproc_commit_instance(seeds3, aux3, h3);
    CHECK(memcmp(h1, h3, 32) != 0, "preproc_commit_instance: distinct for different seeds");

    /* Fiat-Shamir with grinding: C sorted, distinct, in [0,M_KKW); p in [0,N) */
    unsigned char m_hat[32], h_star[32], pk_seed_fs[XMSS_PK_SEED_BYTES], nonce_fs[32];
    uint32_t pubout[8] = {0};
    RAND_bytes(m_hat, 32);
    RAND_bytes(h_star, 32);
    RAND_bytes(pk_seed_fs, XMSS_PK_SEED_BYTES);
    RAND_bytes(nonce_fs, 32);
    unsigned char h_pre[32], seed_FS[32];
    kkw_fs_prefix(m_hat, pubout, pk_seed_fs, nonce_fs, h_star, h_pre);
    /* Grind until the predicate holds (as the prover does). */
    uint32_t ctr = 0;
    while (!kkw_fs_seed(h_pre, ctr, seed_FS)) ctr++;
    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fs_expand(seed_FS, C_out, p_out);
    int fs_ok = 1;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        if (C_out[k] < 0 || C_out[k] >= M_KKW) { fs_ok = 0; break; }
        if (k > 0 && C_out[k] <= C_out[k-1])   { fs_ok = 0; break; }
        if (p_out[k] < 0 || p_out[k] >= N_PARTIES) { fs_ok = 0; break; }
    }
    CHECK(fs_ok, "kkw_fs_expand: C sorted/distinct in [0,M), p in [0,N)");

    /* fs_seed/fs_expand: deterministic, and grind predicate stable */
    unsigned char seed_FS2[32];
    CHECK(kkw_fs_seed(h_pre, ctr, seed_FS2) == 1 &&
          memcmp(seed_FS, seed_FS2, 32) == 0,
          "kkw_fs_seed: deterministic, grind predicate stable");
    int C_out2[NUM_ROUNDS], p_out2[NUM_ROUNDS];
    kkw_fs_expand(seed_FS2, C_out2, p_out2);
    CHECK(memcmp(C_out, C_out2, NUM_ROUNDS * sizeof(int)) == 0 &&
          memcmp(p_out, p_out2, NUM_ROUNDS * sizeof(int)) == 0,
          "kkw_fs_expand: deterministic");

    printf("  (N_PARTIES=%d, NUM_ROUNDS=%d, M_KKW=%d, GRIND_W=%d)\n",
           N_PARTIES, NUM_ROUNDS, M_KKW, GRIND_W);
    free(aux1); free(aux2); free(aux3);
}

/* ── Test 3: tamper check ── */

static void test_tamper(void)
{
    printf("--- Test 3: tamper check ---\n");

    unsigned char input[W_END], m_hat[32], pk_seed[XMSS_PK_SEED_BYTES];
    uint32_t pubout[8];
    build_witness(input, m_hat, pk_seed, pubout);

    unsigned char seed_star[SEED_SIZE];
    RAND_bytes(seed_star, SEED_SIZE);

    unsigned char seeds[N_PARTIES][SEED_SIZE];
    unsigned char *lam[N_PARTIES], *tapes[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        lam[p]   = malloc(INPUT_LEN);
        tapes[p] = malloc(TAPE_SIZE);
    }
    unsigned char *d_pub = malloc(INPUT_LEN);
    uint32_t *aux = malloc(ySize * sizeof(uint32_t));
    a A;
    uint32_t zh[8];
    run_instance(seed_star, input, m_hat, pk_seed, seeds,
                 lam, tapes, d_pub, &A, aux, NULL, NULL, zh);

    /* Tamper the masked witness (equivalent to a tampered signature hash). */
    d_pub[W_SIG_OFF] ^= 0x01;
    a A2;
    uint32_t zh2[8];
    building_views(&A2, m_hat, pk_seed, d_pub, lam, tapes, aux, NULL, NULL, zh2);

    int still_root = 1;
    for (int w = 0; w < YP_ROOT_WORDS; w++) {
        uint32_t v = zh2[w];
        for (int p = 0; p < N_PARTIES; p++) v ^= A2.yp[p][w];
        if (v != pubout[w]) { still_root = 0; break; }
    }
    CHECK(!still_root, "tampered witness changes the circuit output");

    for (int p = 0; p < N_PARTIES; p++) { free(lam[p]); free(tapes[p]); }
    free(aux); free(d_pub);
}

int main(void)
{
    ASSERT_LIB_PARAMS();
    test_single_round();
    test_preproc_smoke();
    test_tamper();

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
