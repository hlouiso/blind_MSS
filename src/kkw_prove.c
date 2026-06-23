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

int kkw_prove(const unsigned char *input,
              const unsigned char m_hat[32],
              const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
              const uint32_t pubout[8],
              FILE *out)
{
    printf("KKW N=%d  M=%d  τ=%d  soundness 2^{-128}  threads=%d\n\n",
           N_PARTIES, M_KKW, NUM_ROUNDS, omp_get_max_threads());

    unsigned char (*seed_stars)[SEED_SIZE] = malloc((size_t)M_KKW * SEED_SIZE);
    unsigned char (*h_j_all)[32]           = malloc((size_t)M_KKW * 32);
    unsigned char (*h_prime_all)[32]       = malloc((size_t)M_KKW * 32);
    if (!seed_stars || !h_j_all || !h_prime_all) {
        fprintf(stderr, "kkw_prove: OOM\n");
        free(seed_stars); free(h_j_all); free(h_prime_all);
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
        expand_seed_star(seed_stars[j], seeds_j);

        unsigned char *x_shares_j[N_PARTIES];
        bool xok = true;
        for (int p = 0; p < N_PARTIES; p++) {
            x_shares_j[p] = malloc((size_t)INPUT_LEN);
            if (!x_shares_j[p]) { xok = false; break; }
        }
        if (!xok) {
            for (int p = 0; p < N_PARTIES; p++) free(x_shares_j[p]);
#pragma omp atomic write
            pass1_error = true;
            goto p1_done;
        }
        derive_xshares(seeds_j, input, x_shares_j);

        unsigned char *tapes_j[N_PARTIES];
        bool tok = true;
        for (int p = 0; p < N_PARTIES; p++) {
            tapes_j[p] = malloc((size_t)TAPE_SIZE);
            if (!tapes_j[p]) { tok = false; break; }
            expand_tape(seeds_j[p], tapes_j[p]);
        }
        if (!tok) {
            for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }
#pragma omp atomic write
            pass1_error = true;
            goto p1_done;
        }

        uint32_t *aux_j = malloc((size_t)ySize * sizeof(uint32_t));
        if (!aux_j) {
            for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }
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
        }

        free(aux_j);
        for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }

    p1_done:;
        int ctr;
#pragma omp atomic capture
        ctr = ++pass1_ctr;
        if (ctr % 10 == 0 || ctr == M_KKW) printf("Pass 1: %d/%d\r", ctr, M_KKW);
    }
    printf("Pass 1: %d/%d\n\n", M_KKW, M_KKW);

    if (pass1_error) {
        fprintf(stderr, "kkw_prove: pass 1 error\n");
        free(seed_stars); free(h_j_all); free(h_prime_all);
        return -1;
    }

    /* ── Global commitment h* ─────────────────────────────────────────────── */
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

    /* ── Fiat–Shamir challenge ────────────────────────────────────────────── */
    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fiat_shamir(m_hat, pubout, h_star, C_out, p_out);

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
            expand_seed_star(seed_stars[j], seeds_j);

            unsigned char *x_shares_j[N_PARTIES];
            bool xok = true;
            for (int p = 0; p < N_PARTIES; p++) {
                x_shares_j[p] = malloc((size_t)INPUT_LEN);
                if (!x_shares_j[p]) { xok = false; break; }
            }
            if (!xok) {
                for (int p = 0; p < N_PARTIES; p++) free(x_shares_j[p]);
#pragma omp atomic write
                pass2_error = true;
                goto p2_done;
            }
            derive_xshares(seeds_j, input, x_shares_j);

            unsigned char *tapes_j[N_PARTIES];
            bool tok = true;
            for (int p = 0; p < N_PARTIES; p++) {
                tapes_j[p] = malloc((size_t)TAPE_SIZE);
                if (!tapes_j[p]) { tok = false; break; }
                expand_tape(seeds_j[p], tapes_j[p]);
            }
            if (!tok) {
                for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }
#pragma omp atomic write
                pass2_error = true;
                goto p2_done;
            }

            uint32_t *da_db_all_k = malloc((size_t)N_PARTIES * 2 * ySize * sizeof(uint32_t));
            if (!da_db_all_k) {
                for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }
#pragma omp atomic write
                pass2_error = true;
                goto p2_done;
            }

            building_views(as[k], (unsigned char *)m_hat, (unsigned char *)pk_seed,
                           (unsigned char **)x_shares_j,
                           (unsigned char **)tapes_j,
                           zs[k]->aux, da_db_all_k);

            for (int p = 0; p < N_PARTIES; p++)
                H_com(seeds_j[p], x_shares_j[p], as[k]->yp[p], as[k]->h[p]);

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
            memcpy(zs[k]->yp_e, as[k]->yp[e], 8 * sizeof(uint32_t));

            for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }

        p2_done:;
            int ctr;
#pragma omp atomic capture
            ctr = ++pass2_ctr;
            if (ctr % 10 == 0 || ctr == NUM_ROUNDS)
                printf("Pass 2: %d/%d\r", ctr, NUM_ROUNDS);
        }
        printf("Pass 2: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

        if (pass2_error) {
            fprintf(stderr, "kkw_prove: OOM in pass 2\n");
            goto cleanup_fail;
        }
    }

    /* ── Write proof ─────────────────────────────────────────────────────── */
    {
        bool write_ok = true;

        if (fwrite(h_star, 32, 1, out) != 1) write_ok = false;

        for (int j = 0; j < M_KKW && write_ok; j++) {
            if (in_C[j]) continue;
            if (fwrite(seed_stars[j], SEED_SIZE, 1, out) != 1) write_ok = false;
            if (fwrite(h_prime_all[j], 32, 1, out) != 1)       write_ok = false;
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
            if (fwrite(zs[k]->yp_e, sizeof(uint32_t), 8, out) != 8) write_ok = false;
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
    free(seed_stars); free(h_j_all); free(h_prime_all);
    return 0;

cleanup_fail:
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    free(seed_stars); free(h_j_all); free(h_prime_all);
    return -1;
}
