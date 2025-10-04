#include "circuits.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("VERIFIER_verify\n"
               "\n"
               "Usage:\n"
               "  ./VERIFIER_verify [-h|--help]\n"
               "\n"
               "Description:\n"
               "  Verifies signature_proof.bin against MSS_public_key.txt for a given message m.\n"
               "\n"
               "Prompts:\n"
               "  - message m (stdin)\n"
               "Reads:\n"
               "  - MSS_public_key.txt\n"
               "  - signature_proof.bin\n");
        return 0;
    }

    setbuf(stdout, NULL);

    // Getting m
    char *message = NULL;
    size_t bufferSize = 0;

    printf("\nPlease enter the signed message:\n");
    int length = getline(&message, &bufferSize, stdin);
    if (length == -1)
    {
        perror("Error reading input");
        free(message);
        return 1;
    }

    message[strlen(message) - 1] = '\0'; // to remove '\n' at the end
    printf("\n");

    // Computing message digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), digest);
    free(message);

    // Getting public_key
    FILE *file;
    int c1;
    int c2;
    file = fopen("MSS_public_key.txt", "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    unsigned char public_key[32];
    for (int j = 0; j < 32; ++j)
    {
        c1 = fgetc(file);
        while (c1 == '\n')
        {
            c1 = fgetc(file);
        }

        c2 = fgetc(file);
        while (c2 == '\n')
        {
            c2 = fgetc(file);
        }

        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        public_key[j] = (unsigned char)((c1 << 4) | c2);
    }

    fclose(file);

    file = fopen("signature_proof.bin", "rb");
    if (file == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    /* ============================================== Reading Proof ============================================== */

    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];

    int alloc = alloc_structures_verify(as, zs);
    if (alloc == -1)
    {
        fprintf(stderr, "Error in allocating structures for verification\n");
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
        if (fread(zs[i]->ke, sizeof(unsigned char), 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->ke1, sizeof(unsigned char), 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->re, sizeof(unsigned char), 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->re1, sizeof(unsigned char), 32, file) != 32)
            read_error = true;
        if (fread(zs[i]->ve.y, sizeof(uint32_t), ysize, file) != ysize)
            read_error = true;
        if (fread(zs[i]->ve.x, sizeof(unsigned char), input_len, file) != input_len)
            read_error = true;
        if (fread(zs[i]->ve1.y, sizeof(uint32_t), ysize, file) != ysize)
            read_error = true;
        if (fread(zs[i]->ve1.x, sizeof(unsigned char), input_len, file) != input_len)
            read_error = true;
    }

    fclose(file);

    if (read_error)
    {
        fprintf(stderr, "Error in reading signature_proof.bin\n");
        free_structures_verify(as, zs);
        return EXIT_FAILURE;
    }

    /* ============================================== Verifying proof ============================================== */

    // Verifying Circuit Output

    uint32_t t0;
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0, public_key + j * 4, 4);
            if ((as[k]->yp[0][j] ^ as[k]->yp[1][j] ^ as[k]->yp[2][j]) != t0)
            {
                fprintf(stderr, "Outputs XOR != public-key at round %d\n", k + 1);
                free_structures_verify(as, zs);
                exit(EXIT_FAILURE);
            }
        }
    }

    // Generating e
    int es[NUM_ROUNDS];
    uint32_t y[8];
    memcpy(y, public_key, 32);
    H3(y, as, NUM_ROUNDS, es);

    printf("===========================================================================\n\n");
    bool verify_error = false;
    bool error = false;
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        verify_error = false;
        printf("Verifying round %d/%d\r", i + 1, NUM_ROUNDS);
        verify(digest, &verify_error, as[i], es[i], zs[i]);
        if (verify_error)
        {
            error = true;
        }
    }
    printf("Verifying round %d/%d", NUM_ROUNDS, NUM_ROUNDS);
    printf("\n\nDone verifying all rounds.\n\n");

    /* ============================================================================================================= */

    free_structures_verify(as, zs);

    printf("===========================================================================\n\n");

    if (error)
    {
        fprintf(stderr, "Error: invalid signature-proof\n\n");
        exit(EXIT_FAILURE);
    }

    printf("Signature proof verified successfully. The signature is valid.\n\n");

    return EXIT_SUCCESS;
}
