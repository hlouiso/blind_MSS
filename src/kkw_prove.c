#include "kkw_prove.h"
#include "circuits.h"
#include "commitment.h"
#include "shared.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <omp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void derive_xshares(unsigned char seeds[N_PARTIES][SEED_SIZE],
                             const unsigned char *input,
                             unsigned char *x_shares[N_PARTIES])
{
    for (int p = 0; p < N_PARTIES - 1; p++)
        expand_xshare(seeds[p], x_shares[p]);
    memcpy(x_shares[N_PARTIES - 1], input, INPUT_LEN);
    for (int p = 0; p < N_PARTIES - 1; p++)
        for (int b = 0; b < INPUT_LEN; b++)
            x_shares[N_PARTIES - 1][b] ^= x_shares[p][b];
}

/* Expand one KKW instance from its seed_star: derive the N party seeds, then
 * allocate and fill each party's x-share (INPUT_LEN) and Beaver tape (TAPE_SIZE).
 * On success returns 0 and the caller owns both arrays (free with free_instance).
 * On allocation failure frees everything and returns -1. */
static int expand_instance(const unsigned char seed_star[SEED_SIZE],
                           const unsigned char *input,
                           unsigned char seeds_out[N_PARTIES][SEED_SIZE],
                           unsigned char *x_shares[N_PARTIES],
                           unsigned char *tapes[N_PARTIES])
{
    expand_seed_star(seed_star, seeds_out);
    for (int p = 0; p < N_PARTIES; p++) { x_shares[p] = NULL; tapes[p] = NULL; }
    for (int p = 0; p < N_PARTIES; p++) {
        x_shares[p] = malloc((size_t)INPUT_LEN);
        tapes[p]    = malloc((size_t)TAPE_SIZE);
        if (!x_shares[p] || !tapes[p]) {
            for (int q = 0; q <= p; q++) { free(x_shares[q]); free(tapes[q]); }
            return -1;
        }
        expand_tape(seeds_out[p], tapes[p]);
    }
    derive_xshares(seeds_out, input, x_shares);
    return 0;
}

static void free_instance(unsigned char *x_shares[N_PARTIES], unsigned char *tapes[N_PARTIES])
{
    for (int p = 0; p < N_PARTIES; p++) { free(tapes[p]); free(x_shares[p]); }
}

int kkw_verbose = 1;

int kkw_prove(const unsigned char *input,
              const unsigned char m_hat[32],
              const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
              const uint32_t pubout[8],
              FILE *out)
{
    if (kkw_verbose)
        printf("KKW N=%d  M=%d  τ=%d  soundness 2^{-128}  threads=%d\n\n",
               N_PARTIES, M_KKW, NUM_ROUNDS, omp_get_max_threads());

    unsigned char (*seed_stars)[SEED_SIZE] = malloc((size_t)M_KKW * SEED_SIZE);
    unsigned char (*h_j_all)[32]           = malloc((size_t)M_KKW * 32);
    unsigned char (*h_prime_all)[32]       = malloc((size_t)M_KKW * 32);
    unsigned char (*h_out_all)[32]         = malloc((size_t)M_KKW * 32);
    if (!seed_stars || !h_j_all || !h_prime_all || !h_out_all) {
        fprintf(stderr, "kkw_prove: OOM\n");
        free(seed_stars); free(h_j_all); free(h_prime_all); free(h_out_all);
        return -1;
    }

    /* Pre-generate all seed_stars. */
    for (int j = 0; j < M_KKW; j++) {
        if (RAND_bytes(seed_stars[j], SEED_SIZE) != 1) {
            fprintf(stderr, "kkw_prove: RAND_bytes failed\n");
            free(seed_stars); free(h_j_all); free(h_prime_all);
            return -1;
        }
    }

    /* ── Pass 1: M_KKW circuit evaluations (parallelised) ────────────────── */
    bool pass1_error = false;
    int  pass1_ctr   = 0;

#pragma omp parallel for schedule(dynamic, 1)
    for (int j = 0; j < M_KKW; j++) {
        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        unsigned char *x_shares_j[N_PARTIES], *tapes_j[N_PARTIES];
        if (expand_instance(seed_stars[j], input, seeds_j, x_shares_j, tapes_j) != 0) {
#pragma omp atomic write
            pass1_error = true;
            goto p1_done;
        }

        uint32_t *aux_j = malloc((size_t)ySize * sizeof(uint32_t));
        if (!aux_j) {
            free_instance(x_shares_j, tapes_j);
#pragma omp atomic write
            pass1_error = true;
            goto p1_done;
        }

        {
            a a_j;
            building_views(&a_j, (unsigned char *)m_hat, (unsigned char *)pk_seed,
                           (unsigned char **)x_shares_j,
                           (unsigned char **)tapes_j,
                           aux_j, NULL);

            for (int w = 0; w < 8; w++) {
                uint32_t xorv = 0;
                for (int p = 0; p < N_PARTIES; p++) xorv ^= a_j.yp[p][w];
                if (xorv != pubout[w]) {
#pragma omp atomic write
                    pass1_error = true;
                }
            }
            preproc_commit_instance(seeds_j, aux_j, h_j_all[j]);
            memcpy(h_prime_all[j], a_j.h_prime, 32);
            sha256_once((const unsigned char *)a_j.yp,
                        N_PARTIES * 8 * sizeof(uint32_t), h_out_all[j]);
        }

        free(aux_j);
        free_instance(x_shares_j, tapes_j);

    p1_done:;
        int ctr;
#pragma omp atomic capture
        ctr = ++pass1_ctr;
        if (kkw_verbose && (ctr % 10 == 0 || ctr == M_KKW))
            printf("Pass 1: %d/%d\r", ctr, M_KKW);
    }
    if (kkw_verbose) printf("Pass 1: %d/%d\n\n", M_KKW, M_KKW);

    if (pass1_error) {
        fprintf(stderr, "kkw_prove: pass 1 error\n");
        free(seed_stars); free(h_j_all); free(h_prime_all);
        return -1;
    }

    /* ── Global commitment h* ─────────────────────────────────────────────── */
    /* h* = SHA256( H(h_j…) ‖ H(h'_j…) ‖ H(h_out_j…) )
     * h_out_j = SHA256(yp[0..N-1]) for instance j binds all output shares,
     * including the hidden party's yp[e], preventing adaptive forgery. */
    unsigned char h_val[32], h_prime_val[32], h_out_val[32], h_star[32];
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        unsigned int outl = 0;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_j_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_val, &outl);
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_prime_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_prime_val, &outl);
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_out_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_out_val, &outl);
        EVP_MD_CTX_free(ctx);
        unsigned char in96[96];
        memcpy(in96,      h_val,       32);
        memcpy(in96 + 32, h_prime_val, 32);
        memcpy(in96 + 64, h_out_val,   32);
        sha256_once(in96, 96, h_star);
    }

    /* ── Nonce (per-proof random salt) ──────────────────────────────────── */
    unsigned char nonce[32];
    if (RAND_bytes(nonce, 32) != 1) {
        fprintf(stderr, "kkw_prove: RAND_bytes failed (nonce)\n");
        free(seed_stars); free(h_j_all); free(h_prime_all);
        return -1;
    }

    /* ── Fiat–Shamir challenge ────────────────────────────────────────────── */
    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fiat_shamir(m_hat, pubout, pk_seed, nonce, h_star, C_out, p_out);

    bool in_C[M_KKW];
    memset(in_C, 0, sizeof(in_C));
    for (int k = 0; k < NUM_ROUNDS; k++) in_C[C_out[k]] = true;

    /* ── Pass 2: online instances (parallelised) ──────────────────────────── */
    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    for (int k = 0; k < NUM_ROUNDS; k++) { as[k] = NULL; zs[k] = NULL; }

    bool alloc_ok = true;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        as[k] = calloc(1, sizeof(a));
        zs[k] = calloc(1, sizeof(z));
        if (!as[k] || !zs[k]) { alloc_ok = false; break; }
        zs[k]->aux        = malloc((size_t)ySize * sizeof(uint32_t));
        zs[k]->x_offset   = malloc((size_t)INPUT_LEN);
        zs[k]->msgs_e     = malloc((size_t)2 * ySize * sizeof(uint32_t));
        if (!zs[k]->aux || !zs[k]->x_offset || !zs[k]->msgs_e) {
            alloc_ok = false; break;
        }
    }
    if (!alloc_ok) {
        fprintf(stderr, "kkw_prove: OOM for pass 2\n");
        goto cleanup_fail;
    }

    {
        bool pass2_error = false;
        int  pass2_ctr   = 0;

#pragma omp parallel for schedule(dynamic, 1)
        for (int k = 0; k < NUM_ROUNDS; k++) {
            int j = C_out[k];
            int e = p_out[k];

            unsigned char seeds_j[N_PARTIES][SEED_SIZE];
            unsigned char *x_shares_j[N_PARTIES], *tapes_j[N_PARTIES];
            if (expand_instance(seed_stars[j], input, seeds_j, x_shares_j, tapes_j) != 0) {
#pragma omp atomic write
                pass2_error = true;
                goto p2_done;
            }

            uint32_t *da_db_all_k = malloc((size_t)N_PARTIES * 2 * ySize * sizeof(uint32_t));
            if (!da_db_all_k) {
                free_instance(x_shares_j, tapes_j);
#pragma omp atomic write
                pass2_error = true;
                goto p2_done;
            }

            building_views(as[k], (unsigned char *)m_hat, (unsigned char *)pk_seed,
                           (unsigned char **)x_shares_j,
                           (unsigned char **)tapes_j,
                           zs[k]->aux, da_db_all_k);

            unsigned char h_local[N_PARTIES][32];
            for (int p = 0; p < N_PARTIES; p++)
                H_com(seeds_j[p], x_shares_j[p], as[k]->yp[p], h_local[p]);
            memcpy(as[k]->h, h_local, sizeof(h_local));

            compute_msgs_e(e, da_db_all_k, zs[k]->msgs_e);
            free(da_db_all_k);

            preproc_com_party(e, seeds_j[e],
                              (e == 0 ? zs[k]->aux : NULL),
                              zs[k]->com_hidden);

            /* Revealed seeds (N-1 parties, skip e). The revealed parties' input
             * shares are seed-derived (expand_xshare) and re-derived by the
             * verifier, so they are NOT transmitted — except party N-1's share,
             * which is the witness offset (not seed-derived); send it only when
             * N-1 is revealed. */
            for (int q = 0; q < N_PARTIES - 1; q++) {
                int orig = (q < e) ? q : q + 1;
                memcpy(zs[k]->ke[q], seeds_j[orig], SEED_SIZE);
            }
            if (e != N_PARTIES - 1)
                memcpy(zs[k]->x_offset, x_shares_j[N_PARTIES - 1], INPUT_LEN);
            /* yp_e removed from proof — as[k]->yp[e] is already in struct a */

            free_instance(x_shares_j, tapes_j);

        p2_done:;
            int ctr;
#pragma omp atomic capture
            ctr = ++pass2_ctr;
            if (ctr % 10 == 0 || ctr == NUM_ROUNDS)
                if (kkw_verbose) printf("Pass 2: %d/%d\r", ctr, NUM_ROUNDS);
        }
        if (kkw_verbose) printf("Pass 2: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

        if (pass2_error) {
            fprintf(stderr, "kkw_prove: OOM in pass 2\n");
            goto cleanup_fail;
        }
    }

    /* ── Write proof ─────────────────────────────────────────────────────── */
    {
        bool write_ok = true;

        /* Header: magic "KKW1" + N + M + tau + ySize (all uint32_t LE). */
        const unsigned char magic[4] = {'K','K','W','1'};
        uint32_t hdr[4] = { (uint32_t)N_PARTIES, (uint32_t)M_KKW,
                             (uint32_t)NUM_ROUNDS, (uint32_t)ySize };
        if (fwrite(magic, 4, 1, out) != 1) write_ok = false;
        if (fwrite(hdr,   sizeof(hdr), 1, out) != 1) write_ok = false;
        if (fwrite(nonce, 32, 1, out) != 1) write_ok = false;
        if (fwrite(h_star, 32, 1, out) != 1) write_ok = false;

        for (int j = 0; j < M_KKW && write_ok; j++) {
            if (in_C[j]) continue;
            if (fwrite(seed_stars[j],  SEED_SIZE, 1, out) != 1) write_ok = false;
            if (fwrite(h_prime_all[j], 32,        1, out) != 1) write_ok = false;
            if (fwrite(h_out_all[j],   32,        1, out) != 1) write_ok = false;
        }

        for (int k = 0; k < NUM_ROUNDS && write_ok; k++) {
            if (fwrite(zs[k]->com_hidden, 32, 1, out) != 1) write_ok = false;
            if (fwrite(as[k], sizeof(a), 1, out) != 1)      write_ok = false;
            if (fwrite(zs[k]->ke, SEED_SIZE, N_PARTIES - 1, out) != (size_t)(N_PARTIES - 1))
                write_ok = false;
            /* x_offset present only when party N-1 is revealed (e != N-1). */
            if (p_out[k] != N_PARTIES - 1) {
                if (fwrite(zs[k]->x_offset, (size_t)INPUT_LEN, 1, out) != 1)
                    write_ok = false;
            }
            /* yp_e not written — verifier derives from as[k]->yp[e] */
            if (p_out[k] != 0) {
                if (fwrite(zs[k]->aux, sizeof(uint32_t), (size_t)ySize, out) != (size_t)ySize)
                    write_ok = false;
            }
            if (fwrite(zs[k]->msgs_e, sizeof(uint32_t), (size_t)(2 * ySize), out) != (size_t)(2 * ySize))
                write_ok = false;
        }

        if (!write_ok) {
            fprintf(stderr, "kkw_prove: write error\n");
            goto cleanup_fail;
        }
    }

    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    free(seed_stars); free(h_j_all); free(h_prime_all); free(h_out_all);
    return 0;

cleanup_fail:
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    free(seed_stars); free(h_j_all); free(h_prime_all); free(h_out_all);
    return -1;
}
