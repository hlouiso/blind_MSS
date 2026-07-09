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
        uint32_t hdr[5];
        if (fread(magic, 4, 1, proof) != 1 || fread(hdr, sizeof(hdr), 1, proof) != 1) {
            fprintf(stderr, "kkw_verify: read error (header)\n"); return -1;
        }
        if (magic[0]!='K'||magic[1]!='K'||magic[2]!='W'||magic[3]!='7') {
            fprintf(stderr, "kkw_verify: bad magic\n"); return -1;
        }
        if (hdr[0]!=(uint32_t)N_PARTIES || hdr[1]!=(uint32_t)M_KKW ||
            hdr[2]!=(uint32_t)NUM_ROUNDS || hdr[3]!=(uint32_t)ySize ||
            hdr[4]!=(uint32_t)GRIND_W) {
            fprintf(stderr, "kkw_verify: parameter mismatch (proof compiled for N=%u M=%u tau=%u ySize=%u W=%u)\n",
                    hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]);
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

    uint32_t ctr;
    if (fread(&ctr, sizeof(ctr), 1, proof) != 1) {
        fprintf(stderr, "kkw_verify: read error (ctr)\n"); return -1;
    }

    /* Grinding check: the challenge hash for this ctr must end in GRIND_W
     * zero bits — this is what forces a forger to pay ~2^GRIND_W hashes per
     * attempt.  Rejecting here is mandatory for the soundness argument. */
    unsigned char h_pre[32], seed_FS[32];
    kkw_fs_prefix(m_hat, pubout, pk_seed, nonce, h_star, h_pre);
    if (!kkw_fs_seed(h_pre, ctr, seed_FS)) {
        fprintf(stderr, "kkw_verify: grinding check failed\n"); return -1;
    }

    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fs_expand(seed_FS, C_out, p_out);

    bool in_C[M_KKW];
    memset(in_C, 0, sizeof(in_C));
    for (int k = 0; k < NUM_ROUNDS; k++) in_C[C_out[k]] = true;

    /* Heap block for the four M×32 tables (h_j, h', h_out, seed*): up to
     * ~230 KB at N=256, too large to keep on the stack. */
    unsigned char *hbuf = malloc((size_t)4 * M_KKW * 32);
    if (!hbuf) { fprintf(stderr, "kkw_verify: OOM\n"); return -1; }
    unsigned char (*h_j_all)[32]     = (unsigned char (*)[32])hbuf;
    unsigned char (*h_prime_all)[32] = (unsigned char (*)[32])(hbuf + (size_t)M_KKW * 32);
    unsigned char (*h_out_all)[32]   = (unsigned char (*)[32])(hbuf + (size_t)2 * M_KKW * 32);
    unsigned char (*seed_star_buf)[SEED_SIZE] =
        (unsigned char (*)[SEED_SIZE])(hbuf + (size_t)3 * M_KKW * 32);

    /* ── Preprocessing check ─────────────────────────────────────────────── */
    /* Pass 1: read offline data sequentially (fread is not thread-safe).
     * Only seed* and the (hiding) h'_j travel; h_out_j is seed-derived and
     * recomputed in pass 2. */
    bool preproc_error = false;
    for (int j = 0; j < M_KKW; j++) {
        if (in_C[j]) continue;
        if (fread(seed_star_buf[j], SEED_SIZE, 1, proof) != 1 ||
            fread(h_prime_all[j],   32,         1, proof) != 1) {
            fprintf(stderr, "kkw_verify: read error (preprocessing j=%d)\n", j);
            preproc_error = true; break;
        }
    }
    if (preproc_error) { free(hbuf); return -1; }

    /* Pass 2: parallelise expand+aux+commit across offline instances. */
    int nthreads = omp_get_max_threads();
    uint32_t **aux_arr = calloc((size_t)nthreads, sizeof(uint32_t *));
    if (!aux_arr) { fprintf(stderr, "kkw_verify: OOM\n"); free(hbuf); return -1; }
    for (int t = 0; t < nthreads; t++) {
        aux_arr[t] = malloc((size_t)ySize * sizeof(uint32_t));
        if (!aux_arr[t]) {
            for (int u = 0; u < t; u++) free(aux_arr[u]);
            free(aux_arr);
            fprintf(stderr, "kkw_verify: OOM\n"); free(hbuf); return -1;
        }
    }

#pragma omp parallel for schedule(dynamic, 1)
    for (int j = 0; j < M_KKW; j++) {
        if (in_C[j]) continue;
        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        expand_seed_star(seed_star_buf[j], seeds_j);
        compute_aux_from_seeds(seeds_j, aux_arr[omp_get_thread_num()],
                               h_out_all[j]);
        preproc_commit_instance(seeds_j, aux_arr[omp_get_thread_num()], h_j_all[j]);
    }

    for (int t = 0; t < nthreads; t++) free(aux_arr[t]);
    free(aux_arr);

    /* ── Online verification ─────────────────────────────────────────────── */
    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    uint32_t (*zh_all)[8] = NULL; /* per-round public masked outputs */
    for (int k = 0; k < NUM_ROUNDS; k++) { as[k] = NULL; zs[k] = NULL; }

    bool alloc_ok = true;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        as[k] = calloc(1, sizeof(a));
        zs[k] = calloc(1, sizeof(z));
        if (!as[k] || !zs[k]) { alloc_ok = false; break; }
        zs[k]->aux        = malloc((size_t)ySize * sizeof(uint32_t));
        zs[k]->x_offset   = malloc((size_t)INPUT_LEN);
        zs[k]->msgs_e     = malloc((size_t)ySize * sizeof(uint32_t));
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
        /* Only yp is in the proof; verify() fills as[k]->h_prime with the
         * recomputed h'_j, folded into the h* check below. */
        if (fread(as[k]->yp, sizeof(as[k]->yp), 1, proof) != 1)
            { read_error = true; break; }
        if (fread(zs[k]->ke, SEED_SIZE, N_PARTIES - 1, proof) != (size_t)(N_PARTIES - 1))
            { read_error = true; break; }
        /* Public masked witness d (always present). */
        if (fread(zs[k]->x_offset, (size_t)INPUT_LEN, 1, proof) != 1)
            { read_error = true; break; }
        /* aux only when party 0 (its holder) is revealed. */
        if (p_out[k] != 0) {
            if (fread(zs[k]->aux, sizeof(uint32_t), (size_t)ySize, proof) != (size_t)ySize)
                { read_error = true; break; }
        } else {
            memset(zs[k]->aux, 0, (size_t)ySize * sizeof(uint32_t));
        }
        if (fread(zs[k]->msgs_e, sizeof(uint32_t), (size_t)ySize, proof) != (size_t)ySize)
            { read_error = true; break; }
        /* Commitment randomiser r_j (needed to recompute h'_j). */
        if (fread(zs[k]->r_j, 32, 1, proof) != 1) { read_error = true; break; }
    }
    if (read_error) {
        fprintf(stderr, "kkw_verify: read error (online section)\n");
        goto free_and_fail;
    }

    /* The stream must end exactly here: reject trailing bytes so a valid
     * proof has a single canonical byte encoding (no benign malleability). */
    if (fgetc(proof) != EOF) {
        fprintf(stderr, "kkw_verify: trailing data after proof\n");
        goto free_and_fail;
    }

    bool online_error = false;
    int  round_ctr    = 0;
    zh_all = malloc((size_t)NUM_ROUNDS * 8 * sizeof(uint32_t));
    if (!zh_all) {
        fprintf(stderr, "kkw_verify: OOM\n");
        goto free_and_fail;
    }

#pragma omp parallel for schedule(dynamic, 1)
    for (int k = 0; k < NUM_ROUNDS; k++) {
        int e = p_out[k];
        bool round_err = false;

        verify(m_hat, pk_seed, &round_err, as[k], e, zs[k], zh_all[k]);
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
        /* as[k]->h_prime holds the h'_j recomputed by verify() above. */
        memcpy(h_prime_all[C_out[k]], as[k]->h_prime, 32);
        sha256_once((const unsigned char *)as[k]->yp,
                    N_PARTIES * 8 * sizeof(uint32_t), h_out_all[C_out[k]]);

#pragma omp atomic
        round_ctr++;
    }

    if (online_error) { fprintf(stderr, "kkw_verify: circuit check failed\n"); goto free_and_fail; }

    /* ── Output binding: unmasked circuit output must equal pubout ─────────
     * verify() only checks the revealed parties' output-mask shares against
     * their commitment; it does NOT tie the circuit output to the public key.
     * Without this loop the proof says "I ran *some* valid circuit", not "…that
     * outputs (root | target-sum)", and any honest proof for a different key
     * verifies (universal forgery). For each online round: real output =
     * ẑ_out XOR all N mask shares (N-1 recomputed + a->yp[e], bound by h_out). */
    for (int k = 0; k < NUM_ROUNDS; k++) {
        for (int w = 0; w < 8; w++) {
            uint32_t v = zh_all[k][w];
            for (int p = 0; p < N_PARTIES; p++) v ^= as[k]->yp[p][w];
            if (v != pubout[w]) {
                fprintf(stderr, "kkw_verify: circuit output != public key (round %d word %d)\n", k, w);
                goto free_and_fail;
            }
        }
    }

    /* ── Final h* check ─────────────────────────────────────────────────── */
    {
        unsigned char h_check[32], h_prime_check[32], h_out_check[32], h_star_check[32];
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) { fprintf(stderr, "kkw_verify: OOM\n"); goto free_and_fail; }
        unsigned int outl = 0;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_j_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_check, &outl);
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_prime_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_prime_check, &outl);
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        for (int j = 0; j < M_KKW; j++) EVP_DigestUpdate(ctx, h_out_all[j], 32);
        EVP_DigestFinal_ex(ctx, h_out_check, &outl);
        EVP_MD_CTX_free(ctx);
        unsigned char in96[96];
        memcpy(in96,      h_check,       32);
        memcpy(in96 + 32, h_prime_check, 32);
        memcpy(in96 + 64, h_out_check,   32);
        sha256_once(in96, 96, h_star_check);
        if (memcmp(h_star_check, h_star, 32) != 0) {
            fprintf(stderr, "kkw_verify: h* mismatch\n"); goto free_and_fail;
        }
    }

    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    free(zh_all);
    free(hbuf);
    return 0;

free_and_fail:
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    free(zh_all);
    free(hbuf);
    return -1;
}
