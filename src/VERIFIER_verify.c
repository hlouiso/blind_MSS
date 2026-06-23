#include "circuits.h"
#include "shared.h"
#include "xmss.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <omp.h>

static int read_hex(FILE *f, unsigned char *out, int n)
{
    int got = 0, hi = -1, c;
    while (got < n && (c = fgetc(f)) != EOF) {
        int v;
        if      (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else continue;
        if (hi < 0) hi = v;
        else { out[got++] = (unsigned char)((hi << 4) | v); hi = -1; }
    }
    return got == n ? 0 : -1;
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("VERIFIER_verify\n\n"
               "  Verifies signature_proof.bin (KKW, M=%d, τ=%d) against XMSS_public_key.txt.\n\n"
               "  Prompts: message m (stdin)\n"
               "  Reads:   XMSS_public_key.txt, signature_proof.bin\n",
               M_KKW, NUM_ROUNDS);
        return 0;
    }

    setbuf(stdout, NULL);

    char *message = NULL;
    size_t bufferSize = 0;
    printf("\nPlease enter the signed message:\n");
    if (getline(&message, &bufferSize, stdin) == -1) {
        perror("Error reading input"); free(message); return 1;
    }
    message[strcspn(message, "\n")] = '\0';
    unsigned char m_hat[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), m_hat);
    free(message);

    unsigned char pk_seed[XMSS_PK_SEED_BYTES], root[XMSS_NODE_BYTES];
    FILE *file = fopen("XMSS_public_key.txt", "r");
    if (!file || read_hex(file, pk_seed, XMSS_PK_SEED_BYTES) != 0 ||
                 read_hex(file, root, XMSS_NODE_BYTES) != 0) {
        fprintf(stderr, "Error reading XMSS_public_key.txt\n"); return 1;
    }
    fclose(file);

    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w*4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    file = fopen("signature_proof.bin", "rb");
    if (!file) { perror("Error opening signature_proof.bin"); return 1; }

    /* ── Read h* from proof header ── */
    unsigned char h_star[32];
    if (fread(h_star, 32, 1, file) != 1) {
        fprintf(stderr, "Error reading h_star\n"); fclose(file); return EXIT_FAILURE;
    }

    /* ── Re-derive Fiat–Shamir challenge ── */
    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fiat_shamir(m_hat, pubout, h_star, C_out, p_out);

    /* Build lookup: is instance j an online instance? */
    bool in_C[M_KKW];
    memset(in_C, 0, sizeof(in_C));
    for (int k = 0; k < NUM_ROUNDS; k++) in_C[C_out[k]] = true;

    /* Accumulators for h* check. */
    unsigned char h_j_all[M_KKW][32];
    unsigned char h_prime_all[M_KKW][32];

    /* ═══════════════════════════════════════════════════════════════════════
     * Phase 1: Preprocessing check (M_KKW - NUM_ROUNDS instances, j ∉ C).
     * Read seed*_j, re-derive aux, verify h_j via preprocessing commitment.
     * ═══════════════════════════════════════════════════════════════════════ */
    printf("Verifying preprocessing (%d instances)...\n", M_KKW - NUM_ROUNDS);

    uint32_t *aux_pp = malloc((size_t)ySize * sizeof(uint32_t));
    if (!aux_pp) {
        fprintf(stderr, "OOM for aux_pp\n"); fclose(file); return EXIT_FAILURE;
    }

    bool preproc_error = false;
    for (int j = 0; j < M_KKW; j++) {
        if (in_C[j]) continue;

        unsigned char seed_star_j[SEED_SIZE], h_prime_j[32];
        if (fread(seed_star_j, SEED_SIZE, 1, file) != 1 ||
            fread(h_prime_j,   32,        1, file) != 1) {
            fprintf(stderr, "Read error at preprocessing entry j=%d\n", j);
            preproc_error = true; break;
        }

        unsigned char seeds_j[N_PARTIES][SEED_SIZE];
        expand_seed_star(seed_star_j, seeds_j);

        compute_aux_from_seeds(seeds_j, aux_pp);
        preproc_commit_instance(seeds_j, aux_pp, h_j_all[j]);
        memcpy(h_prime_all[j], h_prime_j, 32);
    }
    free(aux_pp);

    if (preproc_error) { fclose(file); return EXIT_FAILURE; }
    printf("Preprocessing OK.\n\n");

    /* ═══════════════════════════════════════════════════════════════════════
     * Phase 2: Online verification (NUM_ROUNDS instances, j ∈ C).
     * Read proof data, call verify(), recompute h_j from commitments.
     * ═══════════════════════════════════════════════════════════════════════ */
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
        fprintf(stderr, "OOM allocating verification structures\n");
        fclose(file);
        for (int k = 0; k < NUM_ROUNDS; k++) {
            free(as[k]);
            if (zs[k]) {
                free(zs[k]->aux);
                free(zs[k]->x_revealed); free(zs[k]->msgs_e);
                free(zs[k]);
            }
        }
        return EXIT_FAILURE;
    }

    /* Read online proof entries (ordered by k, i.e. by C_out[k] ascending). */
    bool read_error = false;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        if (fread(zs[k]->com_hidden, 32, 1, file) != 1) { read_error = true; break; }
        if (fread(as[k], sizeof(a), 1, file) != 1)       { read_error = true; break; }
        if (fread(zs[k]->ke, SEED_SIZE, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1))
            { read_error = true; break; }
        if (fread(zs[k]->x_revealed, (size_t)INPUT_LEN, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1))
            { read_error = true; break; }
        if (fread(zs[k]->yp_e, sizeof(uint32_t), 8, file) != 8)
            { read_error = true; break; }
        /* Aux present only when e≠0 (party 0 revealed). When e=0 it is absent
         * from the proof and never read during verification. */
        if (p_out[k] != 0) {
            if (fread(zs[k]->aux, sizeof(uint32_t), (size_t)ySize, file) != (size_t)ySize)
                { read_error = true; break; }
        } else {
            memset(zs[k]->aux, 0, (size_t)ySize * sizeof(uint32_t));
        }
        /* msgs_e: hidden party's (da_e, db_e) pairs = 2*ySize words. */
        if (fread(zs[k]->msgs_e, sizeof(uint32_t), (size_t)(2 * ySize), file) != (size_t)(2 * ySize))
            { read_error = true; break; }
    }
    fclose(file);

    if (read_error) {
        fprintf(stderr, "Error reading signature_proof.bin (online section)\n");
        goto free_and_fail;
    }

    printf("=========================================================================\n\n");
    bool online_error = false;
    int round_ctr = 0;

#pragma omp parallel for schedule(dynamic, 1)
    for (int k = 0; k < NUM_ROUNDS; k++) {
        int e = p_out[k];
        bool round_err = false;

        /* Circuit verification (checks h'_j via Trou 2). */
        verify(m_hat, pk_seed, &round_err, as[k], e, zs[k]);
        if (round_err) {
#pragma omp atomic write
            online_error = true;
        }

        /* Recompute h_j for this online instance from revealed coms + com_hidden.
         * For each party p ≠ e: recompute preproc_com_party from revealed seed.
         * For party e:          use com_hidden directly. */
        unsigned char coms[N_PARTIES][32];
        for (int p = 0; p < N_PARTIES; p++) {
            if (p == e) {
                memcpy(coms[p], zs[k]->com_hidden, 32);
            } else {
                int slot = (p < e) ? p : p - 1;
                /* For party 0, include the revealed aux in the commitment. */
                const uint32_t *aux_arg = (p == 0) ? zs[k]->aux : NULL;
                preproc_com_party(p, zs[k]->ke[slot], aux_arg, coms[p]);
            }
        }

        /* h_j = H(com_0 || ... || com_{N-1}) */
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx) {
            unsigned int outl = 0;
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            for (int p = 0; p < N_PARTIES; p++)
                EVP_DigestUpdate(ctx, coms[p], 32);
            EVP_DigestFinal_ex(ctx, h_j_all[C_out[k]], &outl);
            EVP_MD_CTX_free(ctx);
        } else {
#pragma omp atomic write
            online_error = true;
        }

        /* h'_j is already in as[k]->h_prime (verified by verify() via Trou 2). */
        memcpy(h_prime_all[C_out[k]], as[k]->h_prime, 32);

#pragma omp atomic
        round_ctr++;
        printf("Online verification: %d/%d\r", round_ctr, NUM_ROUNDS);
    }
    printf("Online verification: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

    if (online_error) {
        fprintf(stderr, "Error: online circuit verification failed\n");
        goto free_and_fail;
    }

    /* ── Final h* check: reconstruct from all h_j and h'_j ── */
    {
        unsigned char h_check[32], h_prime_check[32], h_star_check[32];
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) { fprintf(stderr, "OOM\n"); goto free_and_fail; }
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
            fprintf(stderr, "Error: global commitment h* mismatch (Trou 1 check failed)\n");
            goto free_and_fail;
        }
    }

    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) {
            free(zs[k]->aux);
            free(zs[k]->x_revealed); free(zs[k]->msgs_e);
            free(zs[k]);
        }
    }

    printf("=========================================================================\n\n");
    printf("Signature proof verified successfully. The signature is valid.\n\n");
    return EXIT_SUCCESS;

free_and_fail:
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) {
            free(zs[k]->aux);
            free(zs[k]->x_revealed); free(zs[k]->msgs_e);
            free(zs[k]);
        }
    }
    return EXIT_FAILURE;
}
