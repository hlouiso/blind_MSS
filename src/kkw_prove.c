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

/* Expand one KKW instance from its seed_star into caller-provided backing
 * buffers (xbuf: N*INPUT_LEN, tbuf: N*TAPE_SIZE, dbuf: INPUT_LEN): derive the
 * N party seeds, each party's witness-mask share and mask tape, then the
 * public masked witness d = input XOR λ_w.  The buffers are per-thread
 * scratch reused across instances, so no allocation happens per instance. */
static void expand_instance_into(const unsigned char seed_star[SEED_SIZE],
                                 const unsigned char *input,
                                 unsigned char seeds_out[N_PARTIES][SEED_SIZE],
                                 unsigned char *lam[N_PARTIES],
                                 unsigned char *tapes[N_PARTIES],
                                 unsigned char *xbuf, unsigned char *tbuf,
                                 unsigned char *dbuf)
{
    expand_seed_star(seed_star, seeds_out);
    for (int p = 0; p < N_PARTIES; p++) {
        lam[p]   = xbuf + (size_t)p * INPUT_LEN;
        tapes[p] = tbuf + (size_t)p * TAPE_SIZE;
        expand_tape(seeds_out[p], tapes[p]);
        expand_xshare(seeds_out[p], lam[p]);
    }
    memcpy(dbuf, input, INPUT_LEN);
    for (int p = 0; p < N_PARTIES; p++)
        for (int b = 0; b < INPUT_LEN; b++)
            dbuf[b] ^= lam[p][b];
}

/* Per-thread scratch for both passes (NULL-safe, callable twice). */
static void free_scratch(int nthreads, unsigned char **xbufs, unsigned char **tbufs,
                         uint32_t **auxbufs, uint32_t **sbufs, unsigned char **dbufs)
{
    for (int t = 0; t < nthreads; t++) {
        if (xbufs)   free(xbufs[t]);
        if (tbufs)   free(tbufs[t]);
        if (auxbufs) free(auxbufs[t]);
        if (sbufs)   free(sbufs[t]);
        if (dbufs)   free(dbufs[t]);
    }
    free(xbufs); free(tbufs); free(auxbufs); free(sbufs); free(dbufs);
}

int kkw_verbose = 1;

int kkw_prove(const unsigned char *input,
              const unsigned char m_hat[32],
              const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
              const uint32_t pubout[8],
              FILE *out)
{
    if (kkw_verbose)
        printf("KKW N=%d  M=%d  τ=%d  W=%d  security 2^{-128}  threads=%d\n\n",
               N_PARTIES, M_KKW, NUM_ROUNDS, GRIND_W, omp_get_max_threads());

    unsigned char (*seed_stars)[SEED_SIZE] = malloc((size_t)M_KKW * SEED_SIZE);
    unsigned char (*r_all)[32]             = malloc((size_t)M_KKW * 32);
    unsigned char (*h_j_all)[32]           = malloc((size_t)M_KKW * 32);
    unsigned char (*h_prime_all)[32]       = malloc((size_t)M_KKW * 32);
    unsigned char (*h_out_all)[32]         = malloc((size_t)M_KKW * 32);
    if (!seed_stars || !r_all || !h_j_all || !h_prime_all || !h_out_all) {
        fprintf(stderr, "kkw_prove: OOM\n");
        free(seed_stars); free(r_all);
        free(h_j_all); free(h_prime_all); free(h_out_all);
        return -1;
    }

    /* Pre-generate all seed_stars and commitment randomisers r_j.  r_j is
     * deliberately NOT derived from seed_star: seed*_j is published for
     * opened instances, and a seed-derived r_j would make h'_j an offline-
     * checkable deterministic commitment to the witness (no ZK). */
    for (int j = 0; j < M_KKW; j++) {
        if (RAND_bytes(seed_stars[j], SEED_SIZE) != 1 ||
            RAND_bytes(r_all[j], 32) != 1) {
            fprintf(stderr, "kkw_prove: RAND_bytes failed\n");
            free(seed_stars); free(r_all);
            free(h_j_all); free(h_prime_all); free(h_out_all);
            return -1;
        }
    }

    /* ── Per-thread scratch, reused across instances in both passes ──────── */
    int nthreads = omp_get_max_threads();
    unsigned char **xbufs   = calloc((size_t)nthreads, sizeof(*xbufs));
    unsigned char **tbufs   = calloc((size_t)nthreads, sizeof(*tbufs));
    uint32_t      **auxbufs = calloc((size_t)nthreads, sizeof(*auxbufs));
    uint32_t      **sbufs   = calloc((size_t)nthreads, sizeof(*sbufs));
    unsigned char **dbufs   = calloc((size_t)nthreads, sizeof(*dbufs));
    bool scratch_ok = xbufs && tbufs && auxbufs && sbufs && dbufs;
    for (int t = 0; scratch_ok && t < nthreads; t++) {
        xbufs[t]   = malloc((size_t)N_PARTIES * INPUT_LEN);
        tbufs[t]   = malloc((size_t)N_PARTIES * TAPE_SIZE);
        auxbufs[t] = malloc((size_t)ySize * sizeof(uint32_t));
        sbufs[t]   = malloc((size_t)N_PARTIES * ySize * sizeof(uint32_t));
        dbufs[t]   = malloc((size_t)INPUT_LEN);
        if (!xbufs[t] || !tbufs[t] || !auxbufs[t] || !sbufs[t] || !dbufs[t])
            scratch_ok = false;
    }
    if (!scratch_ok) {
        fprintf(stderr, "kkw_prove: OOM (scratch)\n");
        free_scratch(nthreads, xbufs, tbufs, auxbufs, sbufs, dbufs);
        free(seed_stars); free(r_all);
        free(h_j_all); free(h_prime_all); free(h_out_all);
        return -1;
    }

    /* ── Pass 1: M_KKW circuit evaluations (parallelised) ────────────────── */
    bool pass1_error = false;
    int  pass1_ctr   = 0;

#pragma omp parallel for schedule(dynamic, 1)
    for (int j = 0; j < M_KKW; j++) {
        int t = omp_get_thread_num();
        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        unsigned char *lam_j[N_PARTIES], *tapes_j[N_PARTIES];
        expand_instance_into(seed_stars[j], input, seeds_j, lam_j, tapes_j,
                             xbufs[t], tbufs[t], dbufs[t]);

        {
            a a_j;
            uint32_t zh[8];
            building_views(&a_j, m_hat, pk_seed, dbufs[t], lam_j, tapes_j,
                           auxbufs[t], sbufs[t], r_all[j], zh);

            /* Real output = ẑ XOR the output-mask shares — must be pubout. */
            for (int w = 0; w < 8; w++) {
                uint32_t v = zh[w];
                for (int p = 0; p < N_PARTIES; p++) v ^= a_j.yp[p][w];
                if (v != pubout[w]) {
#pragma omp atomic write
                    pass1_error = true;
                }
            }
            preproc_commit_instance(seeds_j, auxbufs[t], h_j_all[j]);
            memcpy(h_prime_all[j], a_j.h_prime, 32);
            sha256_once((const unsigned char *)a_j.yp,
                        N_PARTIES * 8 * sizeof(uint32_t), h_out_all[j]);
        }

        int ctr;
#pragma omp atomic capture
        ctr = ++pass1_ctr;
        if (kkw_verbose && (ctr % 10 == 0 || ctr == M_KKW))
            printf("Pass 1: %d/%d\r", ctr, M_KKW);
    }
    if (kkw_verbose) printf("Pass 1: %d/%d\n\n", M_KKW, M_KKW);

    if (pass1_error) {
        fprintf(stderr, "kkw_prove: pass 1 error\n");
        free_scratch(nthreads, xbufs, tbufs, auxbufs, sbufs, dbufs);
        free(seed_stars); free(r_all);
        free(h_j_all); free(h_prime_all); free(h_out_all);
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
        free_scratch(nthreads, xbufs, tbufs, auxbufs, sbufs, dbufs);
        free(seed_stars); free(r_all);
        free(h_j_all); free(h_prime_all); free(h_out_all);
        return -1;
    }

    /* ── Fiat–Shamir challenge with grinding ─────────────────────────────── */
    /* Find ctr such that the challenge hash ends in GRIND_W zero bits
     * (~2^GRIND_W single-compression hashes; ~15 ms at W=16). */
    unsigned char h_pre[32], seed_FS[32];
    kkw_fs_prefix(m_hat, pubout, pk_seed, nonce, h_star, h_pre);
    uint32_t ctr = 0;
    while (!kkw_fs_seed(h_pre, ctr, seed_FS))
        ctr++;
    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fs_expand(seed_FS, C_out, p_out);

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
        zs[k]->msgs_e     = malloc((size_t)ySize * sizeof(uint32_t));
        if (!zs[k]->aux || !zs[k]->x_offset || !zs[k]->msgs_e) {
            alloc_ok = false; break;
        }
    }
    if (!alloc_ok) {
        fprintf(stderr, "kkw_prove: OOM for pass 2\n");
        goto cleanup_fail;
    }

    {
        int pass2_ctr = 0;

#pragma omp parallel for schedule(dynamic, 1)
        for (int k = 0; k < NUM_ROUNDS; k++) {
            int j = C_out[k];
            int e = p_out[k];
            int t = omp_get_thread_num();

            unsigned char seeds_j[N_PARTIES][SEED_SIZE];
            unsigned char *lam_j[N_PARTIES], *tapes_j[N_PARTIES];
            expand_instance_into(seed_stars[j], input, seeds_j, lam_j, tapes_j,
                                 xbufs[t], tbufs[t], dbufs[t]);

            uint32_t zh[8];
            building_views(as[k], m_hat, pk_seed, dbufs[t], lam_j, tapes_j,
                           zs[k]->aux, sbufs[t], r_all[j], zh);

            compute_msgs_e(e, sbufs[t], zs[k]->msgs_e);
            memcpy(zs[k]->r_j, r_all[j], 32);

            preproc_com_party(e, seeds_j[e],
                              (e == 0 ? zs[k]->aux : NULL),
                              zs[k]->com_hidden);

            /* Revealed seeds (N-1 parties, skip e); mask shares are all
             * seed-derived, only the public masked witness d travels. */
            for (int q = 0; q < N_PARTIES - 1; q++) {
                int orig = (q < e) ? q : q + 1;
                memcpy(zs[k]->ke[q], seeds_j[orig], SEED_SIZE);
            }
            memcpy(zs[k]->x_offset, dbufs[t], INPUT_LEN);

            int ctr;
#pragma omp atomic capture
            ctr = ++pass2_ctr;
            if (ctr % 10 == 0 || ctr == NUM_ROUNDS)
                if (kkw_verbose) printf("Pass 2: %d/%d\r", ctr, NUM_ROUNDS);
        }
        if (kkw_verbose) printf("Pass 2: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);
    }

    /* Scratch is no longer needed once both passes are done. */
    free_scratch(nthreads, xbufs, tbufs, auxbufs, sbufs, dbufs);
    xbufs = NULL; tbufs = NULL; auxbufs = NULL; sbufs = NULL; dbufs = NULL;

    /* ── Write proof ─────────────────────────────────────────────────────── */
    {
        bool write_ok = true;

        /* Header: magic "KKW7" + N + M + tau + ySize + GRIND_W (uint32_t LE),
         * then nonce, h*, and the grinding counter ctr (uint32_t LE). */
        const unsigned char magic[4] = {'K','K','W','7'};
        uint32_t hdr[5] = { (uint32_t)N_PARTIES, (uint32_t)M_KKW,
                             (uint32_t)NUM_ROUNDS, (uint32_t)ySize,
                             (uint32_t)GRIND_W };
        if (fwrite(magic, 4, 1, out) != 1) write_ok = false;
        if (fwrite(hdr,   sizeof(hdr), 1, out) != 1) write_ok = false;
        if (fwrite(nonce, 32, 1, out) != 1) write_ok = false;
        if (fwrite(h_star, 32, 1, out) != 1) write_ok = false;
        if (fwrite(&ctr, sizeof(ctr), 1, out) != 1) write_ok = false;

        /* ZK remark: for opened (offline) instances all tapes are derivable
         * from seed_star, so the rest of h'_j's preimage (d, s_all) is a
         * deterministic function of the witness.  The unrevealed randomiser
         * r_j is what makes h'_j hiding (a uniform RO output), per KKW Fig. 2.
         * h_out_j is NOT sent: yp holds the output-wire mask shares, which
         * are seed-derived like aux, so the verifier recomputes h_out_j from
         * seed_star (compute_aux_from_seeds). */
        for (int j = 0; j < M_KKW && write_ok; j++) {
            if (in_C[j]) continue;
            if (fwrite(seed_stars[j],  SEED_SIZE, 1, out) != 1) write_ok = false;
            if (fwrite(h_prime_all[j], 32,        1, out) != 1) write_ok = false;
        }

        for (int k = 0; k < NUM_ROUNDS && write_ok; k++) {
            if (fwrite(zs[k]->com_hidden, 32, 1, out) != 1) write_ok = false;
            /* Only yp travels: the verifier recomputes h'_j itself, and a
             * mismatch is caught by the final h* check. */
            if (fwrite(as[k]->yp, sizeof(as[k]->yp), 1, out) != 1) write_ok = false;
            if (fwrite(zs[k]->ke, SEED_SIZE, N_PARTIES - 1, out) != (size_t)(N_PARTIES - 1))
                write_ok = false;
            /* Public masked witness d (always present). */
            if (fwrite(zs[k]->x_offset, (size_t)INPUT_LEN, 1, out) != 1)
                write_ok = false;
            /* aux only when party 0 (its holder) is revealed. */
            if (p_out[k] != 0) {
                if (fwrite(zs[k]->aux, sizeof(uint32_t), (size_t)ySize, out) != (size_t)ySize)
                    write_ok = false;
            }
            if (fwrite(zs[k]->msgs_e, sizeof(uint32_t), (size_t)ySize, out) != (size_t)ySize)
                write_ok = false;
            /* Commitment randomiser r_j: revealed only for online rounds. */
            if (fwrite(zs[k]->r_j, 32, 1, out) != 1) write_ok = false;
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
    free(seed_stars); free(r_all);
    free(h_j_all); free(h_prime_all); free(h_out_all);
    return 0;

cleanup_fail:
    free_scratch(nthreads, xbufs, tbufs, auxbufs, sbufs, dbufs);
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) { free(zs[k]->aux); free(zs[k]->x_offset); free(zs[k]->msgs_e); free(zs[k]); }
    }
    free(seed_stars); free(r_all);
    free(h_j_all); free(h_prime_all); free(h_out_all);
    return -1;
}
