#include "shared.h"
#include "verifying_views.h"

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
        printf(
            "\nThis binary is used by anyone to verify the zero-knowledge proof of knowledge stored in 'proof.bin'.\n"
            "This proof is used as a blind signature for a WOTS signature of a secretly known 256 bits message "
            "commitment.\n"
            "To verify the proof, we need the public key, stored in 'public_key.txt'.\n");
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
    file = fopen("public_key.txt", "r");
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

    size_t items_read;
    bool read_error = false;

    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        items_read = fread(as[i], sizeof(a), 1, file);
        if (items_read != 1)
            read_error = true;
        items_read = fread(zs[i], sizeof(z), 1, file);
        if (items_read != 1)
            read_error = true;
        items_read = fread(zs[i]->ve.y, sizeof(uint32_t), ySize, file);
        if (items_read != ySize)
            read_error = true;
        items_read = fread(zs[i]->ve.x, sizeof(unsigned char), INPUT_LEN, file);
        if (items_read != INPUT_LEN)
            read_error = true;
        items_read = fread(zs[i]->ve1.y, sizeof(uint32_t), ySize, file);
        if (items_read != ySize)
            read_error = true;
        items_read = fread(zs[i]->ve1.x, sizeof(unsigned char), INPUT_LEN, file);
        if (items_read != INPUT_LEN)
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

    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            if (public_key[i] != (as[i]->yp[0][j] ^ as[i]->yp[1][j] ^ as[i]->yp[2][j]))
            {
                fprintf(stderr, "Outputs XOR != public-key at round %d\n", i);
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
    bool verify_error = false;

    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        printf("Verifying round %d/%d\r", i + 1, NUM_ROUNDS);
        fflush(stdout);
        verify(digest, &verify_error, as[i], es[i], zs[i]);
    }

    /* ============================================================================================================= */

    free_structures_verify(as, zs);

    printf("===========================================================================\n");

    if (verify_error)
    {
        fprintf(stderr, "\nError: invalid signature-proof\n\n");
        exit(EXIT_FAILURE);
    }

    printf("\nSignature proof verified successfully.\n\n");

    return EXIT_SUCCESS;
}
