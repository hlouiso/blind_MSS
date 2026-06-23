#include "circuits.h"
#include "shared.h"
#include "xmss.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
               "  Verifies signature_proof.bin against XMSS_public_key.txt for a message m.\n\n"
               "  Prompts: message m (stdin)\n"
               "  Reads:   XMSS_public_key.txt, signature_proof.bin\n");
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

    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    if (alloc_structures_verify(as, zs) != 0) {
        fprintf(stderr, "Error allocating verification structures\n");
        fclose(file); return EXIT_FAILURE;
    }

    bool read_error = false;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        if (fread(as[i], sizeof(a), 1, file) != 1) { read_error = true; break; }
        if (fread(zs[i]->ke, SEED_SIZE, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1))
            { read_error = true; break; }
        if (fread(zs[i]->x_revealed, (size_t)INPUT_LEN, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1))
            { read_error = true; break; }
        if (fread(zs[i]->yp_e, sizeof(uint32_t), 8, file) != 8)
            { read_error = true; break; }
        if (fread(zs[i]->broadcast, sizeof(uint32_t), (size_t)(2 * ySize), file) != (size_t)(2 * ySize))
            { read_error = true; break; }
        if (fread(zs[i]->aux, sizeof(uint32_t), (size_t)ySize, file) != (size_t)ySize)
            { read_error = true; break; }
        if (fread(zs[i]->msgs_e, sizeof(uint32_t), (size_t)ySize, file) != (size_t)ySize)
            { read_error = true; break; }
    }
    fclose(file);

    if (read_error) {
        fprintf(stderr, "Error reading signature_proof.bin\n");
        free_structures_verify(as, zs); return EXIT_FAILURE;
    }

    /* Re-derive Fiat–Shamir challenges */
    int es[NUM_ROUNDS];
    H3(m_hat, pubout, as, zs, NUM_ROUNDS, es);

    /* Check each round's XOR of all yp shares equals pubout.
     * yp_e is the hidden party's committed share (from proof). */
    for (int i = 0; i < NUM_ROUNDS; i++) {
        int e = es[i];
        for (int j = 0; j < 8; j++) {
            uint32_t xorv = zs[i]->yp_e[j];
            for (int p = 0; p < N_PARTIES; p++) {
                if (p == e) continue;
                xorv ^= as[i]->yp[p][j];
            }
            if (xorv != pubout[j]) {
                fprintf(stderr, "Output XOR check failed at round %d word %d\n", i+1, j);
                free_structures_verify(as, zs); return EXIT_FAILURE;
            }
        }
        /* Also verify that yp_e matches the committed value in a->yp[e] */
        if (memcmp(zs[i]->yp_e, as[i]->yp[e], 8 * sizeof(uint32_t)) != 0) {
            fprintf(stderr, "yp_e mismatch at round %d\n", i+1);
            free_structures_verify(as, zs); return EXIT_FAILURE;
        }
    }

    printf("===========================================================================\n\n");
    bool error = false;
    int round_ctr = 0;

#pragma omp parallel for schedule(dynamic, 1)
    for (int i = 0; i < NUM_ROUNDS; i++) {
        bool verify_error = false;
        verify(m_hat, pk_seed, &verify_error, as[i], es[i], zs[i]);
        if (verify_error) {
#pragma omp atomic write
            error = true;
        }
#pragma omp atomic
        round_ctr++;
        printf("KKW round verified: %d/%d\r", round_ctr, NUM_ROUNDS);
    }
    printf("KKW round verified: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

    free_structures_verify(as, zs);

    printf("===========================================================================\n\n");
    if (error) {
        fprintf(stderr, "Error: invalid signature-proof\n\n"); return EXIT_FAILURE;
    }
    printf("Signature proof verified successfully. The signature is valid.\n\n");
    return EXIT_SUCCESS;
}
