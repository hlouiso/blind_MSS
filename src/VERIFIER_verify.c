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

/* Read exactly n bytes (2n hex chars), skipping any non-hex characters (newlines). */
static int read_hex(FILE *f, unsigned char *out, int n)
{
    int got = 0, hi = -1, c;
    while (got < n && (c = fgetc(f)) != EOF)
    {
        int v;
        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'A' && c <= 'F')
            v = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            v = c - 'a' + 10;
        else
            continue;
        if (hi < 0)
            hi = v;
        else
        {
            out[got++] = (unsigned char)((hi << 4) | v);
            hi = -1;
        }
    }
    return got == n ? 0 : -1;
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
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
    if (getline(&message, &bufferSize, stdin) == -1)
    {
        perror("Error reading input");
        free(message);
        return 1;
    }
    message[strcspn(message, "\n")] = '\0';
    printf("\n");

    unsigned char m_hat[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), m_hat);
    free(message);

    /* public key: pk_seed (16) then root (16) */
    unsigned char pk_seed[XMSS_PK_SEED_BYTES], root[XMSS_NODE_BYTES];
    FILE *file = fopen("XMSS_public_key.txt", "r");
    if (!file || read_hex(file, pk_seed, XMSS_PK_SEED_BYTES) != 0 || read_hex(file, root, XMSS_NODE_BYTES) != 0)
    {
        fprintf(stderr, "Error reading XMSS_public_key.txt\n");
        return 1;
    }
    fclose(file);

    /* expected public output: root | target sum | 0 */
    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++)
        memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    file = fopen("signature_proof.bin", "rb");
    if (!file)
    {
        perror("Error opening signature_proof.bin");
        return 1;
    }

    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    if (alloc_structures_verify(as, zs) == -1)
    {
        fprintf(stderr, "Error allocating verification structures\n");
        fclose(file);
        return EXIT_FAILURE;
    }

    bool read_error = false;
    uint32_t ysize = (uint32_t)ySize;
    uint32_t input_len = (uint32_t)INPUT_LEN;
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        if (fread(as[i], sizeof(a), 1, file) != 1)
            read_error = true;
        if (fread(zs[i]->ke, 1, 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->ke1, 1, 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->re, 1, 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->re1, 1, 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->ve.x, 1, input_len, file) != input_len)
            read_error = true;
        if (fread(zs[i]->ve1.y, sizeof(uint32_t), ysize, file) != ysize)
            read_error = true;
        if (fread(zs[i]->ve1.x, 1, input_len, file) != input_len)
            read_error = true;
    }
    fclose(file);

    if (read_error)
    {
        fprintf(stderr, "Error reading signature_proof.bin\n");
        free_structures_verify(as, zs);
        return EXIT_FAILURE;
    }

    /* circuit output must reconstruct to (root | target-sum | 0) */
    for (int k = 0; k < NUM_ROUNDS; k++)
        for (int j = 0; j < 8; j++)
            if ((as[k]->yp[0][j] ^ as[k]->yp[1][j] ^ as[k]->yp[2][j]) != pubout[j])
            {
                fprintf(stderr, "Outputs XOR != (root | target-sum) at round %d\n", k + 1);
                free_structures_verify(as, zs);
                return EXIT_FAILURE;
            }

    int es[NUM_ROUNDS];
    H3(m_hat, pubout, as, NUM_ROUNDS, es);

    printf("===========================================================================\n\n");
    bool error = false;
    int round = 0;
#pragma omp parallel for
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        bool verify_error = false;
        verify(m_hat, pk_seed, &verify_error, as[i], es[i], zs[i]);
        if (verify_error)
            error = true;
#pragma omp atomic
        round++;
        printf("ZKBoo round verified: %d/%d\r", round, NUM_ROUNDS);
    }
    printf("ZKBoo round verified: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

    free_structures_verify(as, zs);

    printf("===========================================================================\n\n");
    if (error)
    {
        fprintf(stderr, "Error: invalid signature-proof\n\n");
        return EXIT_FAILURE;
    }
    printf("Signature proof verified successfully. The signature is valid.\n\n");
    return EXIT_SUCCESS;
}
