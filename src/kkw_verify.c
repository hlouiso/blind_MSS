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
    /* ── Check proof header ─────────────────────────────────────────────── */
    {
        unsigned char magic[4];
        uint32_t hdr[4];
        if (fread(magic, 4, 1, proof) != 1 || fread(hdr, sizeof(hdr), 1, proof) != 1) {
            fprintf(stderr, "kkw_verify: read error (header)\n"); return -1;
        }
        if (magic[0]!='K'||magic[1]!='K'||magic[2]!='W'||magic[3]!='1') {
            fprintf(stderr, "kkw_verify: bad magic\n"); return -1;
        }
        if (hdr[0]!=(uint32_t)N_PARTIES || hdr[1]!=(uint32_t)M_KKW ||
            hdr[2]!=(uint32_t)NUM_ROUNDS || hdr[3]!=(uint32_t)ySize) {
            fprintf(stderr, "kkw_verify: parameter mismatch (proof compiled for N=%u M=%u tau=%u ySize=%u)\n",
                    hdr[0], hdr[1], hdr[2], hdr[3]);
            return -1;
        }
    }

    unsigned char nonce[32];
    if (fread(nonce, 32, 1, proof) != 1) {
        fprintf(stderr, "kkw_verify: read error (nonce)\n"); return -1;
    }

    unsigned char h_star[32];
    if (fread(h_star, 32, 1, proof) != 1) {
        fprintf(stderr, "kkw_verify: read error (h_star)\n"); return -1;
    }

    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fiat_shamir(m_hat, pubout, pk_seed, nonce, h_star, C_out, p_out);

    bool in_C[M_KKW];
    memset(in_C, 0, sizeof(in_C));
    for (int k = 0; k < NUM_ROUNDS; k++) in_C[C_out[k]] = true;

    unsigned char h_j_all[M_KKW][32];
    unsigned char h_prime_all[M_KKW][32];

    /* ── Preprocessing check ─────────────────────────────────────────────── */
    /* Pass 1: read offline data sequentially (fread is not thread-safe). */
    unsigned char seed_star_buf[M_KKW][SEED_SIZE];
    bool preproc_error = false;
    for (int j = 0; j < M_KKW; j++) {
        if (in_C[j]) continue;
        unsigned char h_prime_j[32];
        if (fread(seed_star_buf[j], SEED_SIZE, 1, proof) != 1 ||
            fread(h_prime_j,        32,         1, proof) != 1) {
            fprintf(stderr, "kkw_verify: read error (preprocessing j=%d)\n", j);
            preproc_error = true; break;
        }
        memcpy(h_prime_all[j], h_prime_j, 32);
    }
    if (preproc_error) return -1;

    /* Pass 2: parallelise expand+aux+commit across offline instances. */
    int nthreads = omp_get_max_threads();
    uint32_t **aux_arr = calloc((size_t)nthreads, sizeof(uint32_t *));
    if (!aux_arr) { fprintf(stderr, "kkw_verify: OOM\n"); return -1; }
    for (int t = 0; t < nthreads; t++) {
        aux_arr[t] = malloc((size_t)ySize * sizeof(uint32_t));
        if (!aux_arr[t]) {
            for (int u = 0; u < t; u++) free(aux_arr[u]);
            free(aux_arr);
            fprintf(stderr, "kkw_verify: OOM\n"); return -1;
        }
    }

#pragma omp parallel for schedule(dynamic, 1)
    for (int j = 0; j < M_KKW; j++) {
        if (in_C[j]) continue;
        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        expand_seed_star(seed_star_buf[j], seeds_j);
        compute_aux_from_seeds(seeds_j, aux_arr[omp_get_thread_num()]);
        preproc_commit_instance(seeds_j, aux_arr[omp_get_thread_num()], h_j_all[j]);
    }

    for (int t = 0; t < nthreads; t++) free(aux_arr[t]);
    free(aux_arr);

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
        zs[k]->x_offset   = malloc((size_t)INPUT_LEN);
        zs[k]->msgs_e     = malloc((size_t)2 * ySize * sizeof(uint32_t));
        if (!zs[k]->aux || !zs[k]->x_offset || !zs[k]->msgs_e) {
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
        /* x_offset (party N-1's share) present only when party N-1 is revealed. */
        if (p_out[k] != N_PARTIES - 1) {
            if (fread(zs[k]->x_offset, (size_t)INPUT_LEN, 1, proof) != 1)
                { read_error = true; break; }
        }
        /* yp_e not in proof — use as[k]->yp[e] directly */
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

    /* ── Output binding: XOR of all N output shares must equal pubout ──────
     * verify() only checks that each revealed party's recomputed share matches
     * its commitment; it does NOT tie the circuit output to the public key.
     * Without this loop the proof says "I ran *some* valid circuit", not "…that
     * outputs (root | target-sum)", and any honest proof for a different key
     * verifies (universal forgery). For each online round: XOR all N shares
     * (N-1 from struct a plus a[e] for the hidden party) and check == pubout. */
    for (int k = 0; k < NUM_ROUNDS; k++) {
        for (int w = 0; w < 8; w++) {
            uint32_t xorv = 0;
            for (int p = 0; p < N_PARTIES; p++) xorv ^= as[k]->yp[p][w];
            if (xorv != pubout[w]) {
                fprintf(stderr, "kkw_verify: circuit output != public key (round %d word %d)\n", k, w);
                goto free_and_fail;
            }
        }
    }

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
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    return 0;

free_and_fail:
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    return -1;
}
