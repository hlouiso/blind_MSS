#include "kkw_verify.h"
#include "circuits.h"
#include "shared.h"

#include <openssl/evp.h>
#include <omp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int kkw_verify(FILE *proof,
               const unsigned char m_hat[32],
               const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
               const uint32_t pubout[8])
{
    unsigned char h_star[32];
    if (fread(h_star, 32, 1, proof) != 1) {
        fprintf(stderr, "kkw_verify: read error (h_star)\n"); return -1;
    }

    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fiat_shamir(m_hat, pubout, h_star, C_out, p_out);

    bool in_C[M_KKW];
    memset(in_C, 0, sizeof(in_C));
    for (int k = 0; k < NUM_ROUNDS; k++) in_C[C_out[k]] = true;

    unsigned char h_j_all[M_KKW][32];
    unsigned char h_prime_all[M_KKW][32];

    /* ── Preprocessing check ─────────────────────────────────────────────── */
    uint32_t *aux_pp = malloc((size_t)ySize * sizeof(uint32_t));
    if (!aux_pp) { fprintf(stderr, "kkw_verify: OOM\n"); return -1; }

    bool preproc_error = false;
    for (int j = 0; j < M_KKW; j++) {
        if (in_C[j]) continue;
        unsigned char seed_star_j[SEED_SIZE], h_prime_j[32];
        if (fread(seed_star_j, SEED_SIZE, 1, proof) != 1 ||
            fread(h_prime_j,   32,        1, proof) != 1) {
            fprintf(stderr, "kkw_verify: read error (preprocessing j=%d)\n", j);
            preproc_error = true; break;
        }
        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        expand_seed_star(seed_star_j, seeds_j);
        compute_aux_from_seeds(seeds_j, aux_pp);
        preproc_commit_instance(seeds_j, aux_pp, h_j_all[j]);
        memcpy(h_prime_all[j], h_prime_j, 32);
    }
    free(aux_pp);
    if (preproc_error) return -1;

    /* ── Online verification ─────────────────────────────────────────────── */
    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    for (int k = 0; k < NUM_ROUNDS; k++) { as[k] = NULL; zs[k] = NULL; }

    bool alloc_ok = true;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        as[k] = calloc(1, sizeof(a));
        zs[k] = calloc(1, sizeof(z));
        if (!as[k] || !zs[k]) { alloc_ok = false; break; }
        zs[k]->aux        = malloc((size_t)ySize * sizeof(uint32_t));
        zs[k]->x_revealed = malloc((size_t)(N_PARTIES - 1) * INPUT_LEN);
        zs[k]->msgs_e     = malloc((size_t)2 * ySize * sizeof(uint32_t));
        if (!zs[k]->aux || !zs[k]->x_revealed || !zs[k]->msgs_e) {
            alloc_ok = false; break;
        }
    }
    if (!alloc_ok) {
        fprintf(stderr, "kkw_verify: OOM\n");
        goto free_and_fail;
    }

    bool read_error = false;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        if (fread(zs[k]->com_hidden, 32, 1, proof) != 1) { read_error = true; break; }
        if (fread(as[k], sizeof(a), 1, proof) != 1)       { read_error = true; break; }
        if (fread(zs[k]->ke, SEED_SIZE, N_PARTIES - 1, proof) != (size_t)(N_PARTIES - 1))
            { read_error = true; break; }
        if (fread(zs[k]->x_revealed, (size_t)INPUT_LEN, N_PARTIES - 1, proof) != (size_t)(N_PARTIES - 1))
            { read_error = true; break; }
        if (fread(zs[k]->yp_e, sizeof(uint32_t), 8, proof) != 8)
            { read_error = true; break; }
        if (p_out[k] != 0) {
            if (fread(zs[k]->aux, sizeof(uint32_t), (size_t)ySize, proof) != (size_t)ySize)
                { read_error = true; break; }
        } else {
            memset(zs[k]->aux, 0, (size_t)ySize * sizeof(uint32_t));
        }
        if (fread(zs[k]->msgs_e, sizeof(uint32_t), (size_t)(2 * ySize), proof) != (size_t)(2 * ySize))
            { read_error = true; break; }
    }
    if (read_error) {
        fprintf(stderr, "kkw_verify: read error (online section)\n");
        goto free_and_fail;
    }

    bool online_error = false;
    int  round_ctr    = 0;

#pragma omp parallel for schedule(dynamic, 1)
    for (int k = 0; k < NUM_ROUNDS; k++) {
        int e = p_out[k];
        bool round_err = false;

        verify((unsigned char *)m_hat, (unsigned char *)pk_seed, &round_err, as[k], e, zs[k]);
        if (round_err) {
#pragma omp atomic write
            online_error = true;
        }

        unsigned char coms[N_PARTIES][32];
        for (int p = 0; p < N_PARTIES; p++) {
            if (p == e) {
                memcpy(coms[p], zs[k]->com_hidden, 32);
            } else {
                int slot = (p < e) ? p : p - 1;
                preproc_com_party(p, zs[k]->ke[slot],
                                  (p == 0 ? zs[k]->aux : NULL), coms[p]);
            }
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx) {
            unsigned int outl = 0;
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            for (int p = 0; p < N_PARTIES; p++) EVP_DigestUpdate(ctx, coms[p], 32);
            EVP_DigestFinal_ex(ctx, h_j_all[C_out[k]], &outl);
            EVP_MD_CTX_free(ctx);
        } else {
#pragma omp atomic write
            online_error = true;
        }
        memcpy(h_prime_all[C_out[k]], as[k]->h_prime, 32);

#pragma omp atomic
        round_ctr++;
    }

    if (online_error) { fprintf(stderr, "kkw_verify: circuit check failed\n"); goto free_and_fail; }

    /* ── Final h* check ─────────────────────────────────────────────────── */
    {
        unsigned char h_check[32], h_prime_check[32], h_star_check[32];
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) { fprintf(stderr, "kkw_verify: OOM\n"); goto free_and_fail; }
        unsigned int outl = 0;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_j_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_check, &outl);
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_prime_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_prime_check, &outl);
        EVP_MD_CTX_free(ctx);
        unsigned char in64[64];
        memcpy(in64, h_check, 32); memcpy(in64 + 32, h_prime_check, 32);
        sha256_once(in64, 64, h_star_check);
        if (memcmp(h_star_check, h_star, 32) != 0) {
            fprintf(stderr, "kkw_verify: h* mismatch\n"); goto free_and_fail;
        }
    }

    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_revealed); free(zs[k]->msgs_e); free(zs[k]); }
    }
    return 0;

free_and_fail:
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_revealed); free(zs[k]->msgs_e); free(zs[k]); }
    }
    return -1;
}
