#include "circuits.h"
#include "commitment.h"
#include "shared.h"
#include "xmss.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
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

/* Derive x_shares from party seeds (deterministic, reproducible in pass 2). */
static bool derive_xshares(unsigned char seeds[N_PARTIES][SEED_SIZE],
                             const unsigned char *input,
                             unsigned char *x_shares[N_PARTIES])
{
    for (int p = 0; p < N_PARTIES - 1; p++)
        expand_xshare(seeds[p], x_shares[p]);
    /* Party N-1: XOR complement so that XOR of all shares == input. */
    memcpy(x_shares[N_PARTIES - 1], input, INPUT_LEN);
    for (int p = 0; p < N_PARTIES - 1; p++)
        for (int b = 0; b < INPUT_LEN; b++)
            x_shares[N_PARTIES - 1][b] ^= x_shares[p][b];
    return true;
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("CLIENT_blind_sign\n\n"
               "  Builds a KKW/MPC-in-the-head proof of a valid WOTS+/XMSS blind signature.\n"
               "  KKW Trou 1 (preprocessing cut-and-choose): M=%d instances, τ=%d online.\n\n"
               "  Prompts: message m (stdin)\n"
               "  Reads:   blinding_key.txt, XMSS_signature.txt, XMSS_public_key.txt\n"
               "  Writes:  signature_proof.bin\n", M_KKW, NUM_ROUNDS);
        return 0;
    }

    setbuf(stdout, NULL);

    /* ── Message digest ── */
    char *message = NULL;
    size_t bufferSize = 0;
    printf("\nPlease enter your message:\n");
    if (getline(&message, &bufferSize, stdin) == -1) {
        perror("Error reading message"); return EXIT_FAILURE;
    }
    message[strcspn(message, "\n")] = '\0';
    unsigned char m_hat[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), m_hat);
    free(message);

    /* ── Blinding key ── */
    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    FILE *f = fopen("blinding_key.txt", "r");
    if (!f || read_hex(f, r, HM_R_BYTES) != 0 || read_hex(f, a_mat, HM_A_BYTES) != 0) {
        fprintf(stderr, "Error reading blinding_key.txt\n"); return EXIT_FAILURE;
    }
    fclose(f);

    /* ── Public key ── */
    unsigned char pk_seed[XMSS_PK_SEED_BYTES], root[XMSS_NODE_BYTES];
    f = fopen("XMSS_public_key.txt", "r");
    if (!f || read_hex(f, pk_seed, XMSS_PK_SEED_BYTES) != 0 || read_hex(f, root, XMSS_NODE_BYTES) != 0) {
        fprintf(stderr, "Error reading XMSS_public_key.txt\n"); return EXIT_FAILURE;
    }
    fclose(f);

    /* ── XMSS signature ── */
    xmss_sig sig;
    f = fopen("XMSS_signature.txt", "r");
    if (!f) { fprintf(stderr, "Error opening XMSS_signature.txt\n"); return EXIT_FAILURE; }
    char buf[64];
    if (!fgets(buf, sizeof buf, f)) {
        fprintf(stderr, "Error reading leaf_index\n"); fclose(f); return EXIT_FAILURE;
    }
    sig.leaf_index = (uint32_t)strtoul(buf, NULL, 10);
    if (sig.leaf_index >= (1u << XMSS_H)) {
        fprintf(stderr, "leaf_index %u out of bounds\n", sig.leaf_index);
        fclose(f); return EXIT_FAILURE;
    }
    int rerr = read_hex(f, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        rerr |= read_hex(f, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        rerr |= read_hex(f, sig.auth_path[h], XMSS_NODE_BYTES);
    fclose(f);
    if (rerr) { fprintf(stderr, "Error parsing XMSS_signature.txt\n"); return EXIT_FAILURE; }

    /* ── Consistency pre-check ── */
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);
    if (!xmss_verify(pk_seed, root, d, 32, &sig)) {
        fprintf(stderr, "Inconsistent inputs: XMSS signature invalid for certified digest.\n");
        return EXIT_FAILURE;
    }

    /* ── Expected public output ── */
    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ── Witness ── */
    unsigned char input[W_END];
    memcpy(input + W_R_OFF,   r,      HM_R_BYTES);
    memcpy(input + W_A_OFF,   a_mat,  HM_A_BYTES);
    input[W_LEAFIDX_OFF + 0] = (sig.leaf_index >> 24) & 0xFF;
    input[W_LEAFIDX_OFF + 1] = (sig.leaf_index >> 16) & 0xFF;
    input[W_LEAFIDX_OFF + 2] = (sig.leaf_index >>  8) & 0xFF;
    input[W_LEAFIDX_OFF + 3] = (sig.leaf_index)       & 0xFF;
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    printf("\n=========================================================================\n");
    printf("KKW N=%d  M=%d instances  τ=%d online  soundness 2^{-128}\n\n",
           N_PARTIES, M_KKW, NUM_ROUNDS);

    /* ═══════════════════════════════════════════════════════════════════════
     * Pass 1: Run M_KKW circuit evaluations.
     * For each j: sample seed*_j, expand to party seeds, derive x_shares,
     * run building_views, commit to preprocessing state and h'_j.
     * ═══════════════════════════════════════════════════════════════════════ */
    unsigned char (*seed_stars)[SEED_SIZE] = malloc((size_t)M_KKW * SEED_SIZE);
    unsigned char (*h_j_all)[32]           = malloc((size_t)M_KKW * 32);
    unsigned char (*h_prime_all)[32]       = malloc((size_t)M_KKW * 32);
    if (!seed_stars || !h_j_all || !h_prime_all) {
        fprintf(stderr, "OOM allocating pass-1 arrays\n");
        free(seed_stars); free(h_j_all); free(h_prime_all);
        return EXIT_FAILURE;
    }

    bool pass1_error = false;
    for (int j = 0; j < M_KKW && !pass1_error; j++) {
        if (RAND_bytes(seed_stars[j], SEED_SIZE) != 1) {
            fprintf(stderr, "RAND_bytes failed\n"); pass1_error = true; break;
        }

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
            pass1_error = true; break;
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
            for (int p = 0; p < N_PARTIES; p++) free(tapes_j[p]);
            for (int p = 0; p < N_PARTIES; p++) free(x_shares_j[p]);
            pass1_error = true; break;
        }

        uint32_t *broadcast_j = malloc((size_t)2 * ySize * sizeof(uint32_t));
        uint32_t *aux_j       = malloc((size_t)ySize * sizeof(uint32_t));
        if (!broadcast_j || !aux_j) {
            free(broadcast_j); free(aux_j);
            for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }
            pass1_error = true; break;
        }

        a a_j;
        building_views(&a_j, m_hat, pk_seed,
                       (unsigned char **)x_shares_j,
                       (unsigned char **)tapes_j,
                       broadcast_j, aux_j);

        /* Check circuit output XOR == pubout. */
        for (int w = 0; w < 8; w++) {
            uint32_t xorv = 0;
            for (int p = 0; p < N_PARTIES; p++) xorv ^= a_j.yp[p][w];
            if (xorv != pubout[w]) { pass1_error = true; }
        }

        preproc_commit_instance(seeds_j, aux_j, h_j_all[j]);
        memcpy(h_prime_all[j], a_j.h_prime, 32);

        free(broadcast_j); free(aux_j);
        for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }

        if ((j + 1) % 10 == 0 || j + 1 == M_KKW)
            printf("Pass 1: %d/%d\r", j + 1, M_KKW);
    }
    printf("Pass 1: %d/%d\n\n", M_KKW, M_KKW);

    if (pass1_error) {
        fprintf(stderr, "Error in pass 1 (circuit output mismatch or OOM)\n");
        free(seed_stars); free(h_j_all); free(h_prime_all);
        return EXIT_FAILURE;
    }

    /* ── Compute global commitment h* ── */
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

    /* ── Fiat–Shamir: derive C ⊂ [M_KKW] (size τ) and hidden party indices ── */
    int C_out[NUM_ROUNDS], p_out[NUM_ROUNDS];
    kkw_fiat_shamir(m_hat, pubout, h_star, C_out, p_out);

    /* Build in-C lookup. */
    bool in_C[M_KKW];
    memset(in_C, 0, sizeof(in_C));
    for (int k = 0; k < NUM_ROUNDS; k++) in_C[C_out[k]] = true;

    /* ═══════════════════════════════════════════════════════════════════════
     * Pass 2: Re-expand the NUM_ROUNDS online instances and build proof data.
     * ═══════════════════════════════════════════════════════════════════════ */
    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    for (int k = 0; k < NUM_ROUNDS; k++) { as[k] = NULL; zs[k] = NULL; }

    bool alloc_ok = true;
    for (int k = 0; k < NUM_ROUNDS; k++) {
        as[k] = calloc(1, sizeof(a));
        zs[k] = calloc(1, sizeof(z));
        if (!as[k] || !zs[k]) { alloc_ok = false; break; }
        zs[k]->broadcast = malloc((size_t)2 * ySize * sizeof(uint32_t));
        zs[k]->aux       = malloc((size_t)ySize * sizeof(uint32_t));
        zs[k]->x_revealed = malloc((size_t)(N_PARTIES - 1) * INPUT_LEN);
        zs[k]->msgs_e    = malloc((size_t)ySize * sizeof(uint32_t));
        if (!zs[k]->broadcast || !zs[k]->aux || !zs[k]->x_revealed || !zs[k]->msgs_e) {
            alloc_ok = false; break;
        }
    }
    if (!alloc_ok) {
        fprintf(stderr, "OOM allocating pass-2 structures\n");
        for (int k = 0; k < NUM_ROUNDS; k++) {
            free(as[k]);
            if (zs[k]) {
                free(zs[k]->broadcast); free(zs[k]->aux);
                free(zs[k]->x_revealed); free(zs[k]->msgs_e);
                free(zs[k]);
            }
        }
        free(seed_stars); free(h_j_all); free(h_prime_all);
        return EXIT_FAILURE;
    }

    bool pass2_error = false;
    int round_ctr = 0;

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
            goto round2_done;
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
            for (int p = 0; p < N_PARTIES; p++) free(tapes_j[p]);
            for (int p = 0; p < N_PARTIES; p++) free(x_shares_j[p]);
#pragma omp atomic write
            pass2_error = true;
            goto round2_done;
        }

        building_views(as[k], m_hat, pk_seed,
                       (unsigned char **)x_shares_j,
                       (unsigned char **)tapes_j,
                       zs[k]->broadcast, zs[k]->aux);

        /* Commitments H_com for all parties. */
        for (int p = 0; p < N_PARTIES; p++)
            H_com(seeds_j[p], x_shares_j[p], as[k]->yp[p], as[k]->h[p]);

        /* Hidden party's per-gate messages. */
        compute_msgs_e(e, tapes_j[e], zs[k]->broadcast, zs[k]->aux, zs[k]->msgs_e);

        /* Preprocessing commitment to hidden party e. */
        preproc_com_party(e, seeds_j[e],
                          (e == 0 ? zs[k]->aux : NULL),
                          zs[k]->com_hidden);

        /* Revealed seeds and x_shares (N-1 parties, skip e). */
        for (int q = 0; q < N_PARTIES - 1; q++) {
            int orig = (q < e) ? q : q + 1;
            memcpy(zs[k]->ke[q], seeds_j[orig], SEED_SIZE);
            memcpy(zs[k]->x_revealed + (size_t)q * INPUT_LEN, x_shares_j[orig], INPUT_LEN);
        }
        memcpy(zs[k]->yp_e, as[k]->yp[e], 8 * sizeof(uint32_t));

        for (int p = 0; p < N_PARTIES; p++) { free(tapes_j[p]); free(x_shares_j[p]); }

    round2_done:
#pragma omp atomic
        round_ctr++;
        printf("Pass 2: %d/%d\r", round_ctr, NUM_ROUNDS);
    }
    printf("Pass 2: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

    if (pass2_error) {
        fprintf(stderr, "OOM in pass 2\n");
        goto cleanup_and_fail;
    }

    /* ── Write proof file ── */
    {
        FILE *file = fopen("signature_proof.bin", "wb");
        if (!file) { perror("signature_proof.bin"); goto cleanup_and_fail; }

        bool write_ok = true;

        /* Header: h* */
        if (fwrite(h_star, 32, 1, file) != 1) write_ok = false;

        /* Preprocessing section: M_KKW - NUM_ROUNDS entries (j ∉ C, ascending). */
        for (int j = 0; j < M_KKW && write_ok; j++) {
            if (in_C[j]) continue;
            if (fwrite(seed_stars[j], SEED_SIZE, 1, file) != 1) write_ok = false;
            if (fwrite(h_prime_all[j], 32, 1, file) != 1)       write_ok = false;
        }

        /* Online section: NUM_ROUNDS entries (k=0..τ-1, ordered by C_out[k]). */
        for (int k = 0; k < NUM_ROUNDS && write_ok; k++) {
            if (fwrite(zs[k]->com_hidden, 32, 1, file) != 1) write_ok = false;
            if (fwrite(as[k], sizeof(a), 1, file) != 1)      write_ok = false;
            if (fwrite(zs[k]->ke, SEED_SIZE, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1))
                write_ok = false;
            if (fwrite(zs[k]->x_revealed, (size_t)INPUT_LEN, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1))
                write_ok = false;
            if (fwrite(zs[k]->yp_e, sizeof(uint32_t), 8, file) != 8) write_ok = false;
            if (fwrite(zs[k]->broadcast, sizeof(uint32_t), (size_t)(2 * ySize), file) != (size_t)(2 * ySize))
                write_ok = false;
            if (fwrite(zs[k]->aux, sizeof(uint32_t), (size_t)ySize, file) != (size_t)ySize)
                write_ok = false;
            if (fwrite(zs[k]->msgs_e, sizeof(uint32_t), (size_t)ySize, file) != (size_t)ySize)
                write_ok = false;
        }

        fclose(file);
        if (!write_ok) {
            fprintf(stderr, "Error writing signature_proof.bin\n");
            goto cleanup_and_fail;
        }
    }

    /* ── Cleanup and success ── */
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) {
            free(zs[k]->broadcast); free(zs[k]->aux);
            free(zs[k]->x_revealed); free(zs[k]->msgs_e);
            free(zs[k]);
        }
    }
    free(seed_stars); free(h_j_all); free(h_prime_all);

    printf("=========================================================================\n");
    printf("\nSignature-Proof generated in 'signature_proof.bin'.\n\n");
    return EXIT_SUCCESS;

cleanup_and_fail:
    for (int k = 0; k < NUM_ROUNDS; k++) {
        free(as[k]);
        if (zs[k]) {
            free(zs[k]->broadcast); free(zs[k]->aux);
            free(zs[k]->x_revealed); free(zs[k]->msgs_e);
            free(zs[k]);
        }
    }
    free(seed_stars); free(h_j_all); free(h_prime_all);
    return EXIT_FAILURE;
}
