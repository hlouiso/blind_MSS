#include "circuits.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <omp.h>

#define CH(e, f, g) ((e & f) ^ ((~e) & g)) // Chooses f if e = 0 and g if e = 1

void prove(z *z, int e, unsigned char keys[3][32], unsigned char rs[3][32], View *views[3])
{
    memcpy(&z->ke, keys[e], 32);
    memcpy(&z->ke1, keys[(e + 1) % 3], 32);

    z->ve.x = views[e]->x;
    z->ve1.x = views[(e + 1) % 3]->x;
    z->ve1.y = views[(e + 1) % 3]->y;

    memcpy(&z->re, rs[e], 32);
    memcpy(&z->re1, rs[(e + 1) % 3], 32);
    return;
}

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("CLIENT_blind_sign\n"
               "\n"
               "Usage:\n"
               "  ./CLIENT_blind_sign [-h|--help]\n"
               "\n"
               "Description:\n"
               "  Builds a ZKBoo/MPC-in-the-head proof that you know a valid MSS signature\n"
               "  for the commitment of message m with blinding key r.\n"
               "\n"
               "Prompts:\n"
               "  - message m (stdin)\n"
               "Reads:\n"
               "  - blinding_key.txt\n"
               "  - MSS_signature.txt\n"
               "  - MSS_public_key.txt\n"
               "Output file:\n"
               "  - signature_proof.bin\n");
        return 0;
    }

    setbuf(stdout, NULL);

    // Getting m
    char *message = NULL;
    size_t bufferSize = 0;

    printf("\nPlease enter your message:\n");
    int message_length = getline(&message, &bufferSize, stdin);
    if (message_length == -1)
    {
        perror("Error reading message");
        return EXIT_FAILURE;
    }

    message[strlen(message) - 1] = '\0'; // to remove '\n' at the end

    // Computing message digest
    unsigned char message_digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), message_digest);
    free(message);

    // Getting commitment key
    char hexInput[2 * COMMIT_KEY_LEN + 1];
    unsigned char commitment_key[COMMIT_KEY_LEN];

    FILE *f = fopen("blinding_key.txt", "r");
    if (f == NULL)
    {
        fprintf(stderr, "Error opening blinding_key.txt\n");
        return EXIT_FAILURE;
    }

    if (!fgets(hexInput, sizeof(hexInput), f))
    {
        fclose(f);
        fprintf(stderr, "Error reading blinding_key.txt\n");
        return EXIT_FAILURE;
    }

    fclose(f);

    for (int i = 0; i < COMMIT_KEY_LEN; i++)
    {
        unsigned int byte;
        sscanf(&hexInput[i * 2], "%2X", &byte);
        commitment_key[i] = (unsigned char)byte;
    }

    // Getting MSS signature
    int c1;
    int c2;
    f = fopen("MSS_signature.txt", "r");

    // getting leaf index
    unsigned char leaf_index_bytes[4];
    char buf[32];
    if (fgets(buf, sizeof(buf), f) == NULL)
    {
        fclose(f);
        perror("Error reading leaf index");
        return EXIT_FAILURE;
    }
    uint32_t leaf_index = (uint32_t)strtoul(buf, NULL, 10);
    leaf_index_bytes[0] = (leaf_index >> 24) & 0xFF;
    leaf_index_bytes[1] = (leaf_index >> 16) & 0xFF;
    leaf_index_bytes[2] = (leaf_index >> 8) & 0xFF;
    leaf_index_bytes[3] = (leaf_index) & 0xFF;

    // WOTS signature
    unsigned char sigma[WOTS_len * SHA256_DIGEST_LENGTH];

    for (int i = 0; i < 512; i++)
    {
        for (int j = 0; j < 32; j++)
        {
            c1 = fgetc(f);
            while (c1 == '\n')
            {
                c1 = fgetc(f);
            }

            c2 = fgetc(f);
            while (c2 == '\n')
            {
                c2 = fgetc(f);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            sigma[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    }

    // PATH
    unsigned char PATH[10 * SHA256_DIGEST_LENGTH];
    for (int i = 0; i < 10 * SHA256_DIGEST_LENGTH; i++)
    {
        c1 = fgetc(f);
        while (c1 == '\n')
        {
            c1 = fgetc(f);
        }

        c2 = fgetc(f);
        while (c2 == '\n')
        {
            c2 = fgetc(f);
        }

        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        PATH[i] = (char)((c1 << 4) | c2);
    }

    // Building input
    unsigned char input[INPUT_LEN];
    memcpy(input, commitment_key, 32);
    memcpy(input + 32, leaf_index_bytes, 4);
    memcpy(input + 32 + 4, sigma, WOTS_len * SHA256_DIGEST_LENGTH);
    memcpy(input + 32 + 4 + WOTS_len * SHA256_DIGEST_LENGTH, PATH, 10 * SHA256_DIGEST_LENGTH);

    fclose(f);

    // Getting public_key
    f = fopen("MSS_public_key.txt", "r");
    unsigned char public_key[SHA256_DIGEST_LENGTH];
    for (int j = 0; j < 32; ++j)
    {
        c1 = fgetc(f);
        while (c1 == '\n')
        {
            c1 = fgetc(f);
        }

        c2 = fgetc(f);
        while (c2 == '\n')
        {
            c2 = fgetc(f);
        }

        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        public_key[j] = (char)((c1 << 4) | c2);
    }
    fclose(f);

    /* ========================================== Allocating memory ========================================= */

    unsigned char *shares[NUM_ROUNDS][3];
    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    unsigned char *randomness[NUM_ROUNDS][3];
    View *localViews[NUM_ROUNDS][3];

    int alloc = alloc_structures_prove(shares, as, zs, randomness, localViews);
    if (alloc != 0)
    {
        fprintf(stderr, "Error allocating memory\n");
        return EXIT_FAILURE;
    }

    /* =========================================== Sharing inputs =========================================== */

    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 2; j++)
        {
            if (RAND_bytes(shares[k][j], INPUT_LEN) != 1)
            {
                perror("RAND_bytes failed crypto, aborting\n");
                return EXIT_FAILURE;
            }
        }

        for (int j = 0; j < INPUT_LEN; j++)
        {
            shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
        }

        for (int j = 0; j < 3; j++)
        {
            memcpy(localViews[k][j]->x, shares[k][j], INPUT_LEN);
        }
    }

    /* ========================================== Running Circuit ========================================== */

    bool error = false;

    // Generating keys
    unsigned char keys[NUM_ROUNDS][3][32];
    RAND_bytes((unsigned char *)keys, NUM_ROUNDS * 3 * 32);

    unsigned char rs[NUM_ROUNDS][3][32];
    RAND_bytes((unsigned char *)rs, NUM_ROUNDS * 3 * 32);

    printf("\n===========================================================================\n");
    printf("\nChosen number of ZKBoo rounds: %d (can be changed in 'src/shared.c')\n", NUM_ROUNDS);

    int round = 0;
#pragma omp parallel for // parallelizing the verification
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 3; j++)
        {
            getAllRandomness(keys[k][j], randomness[k][j]);
        }

        building_views(as[k], message_digest, shares[k], randomness[k], localViews[k]);

        uint32_t t0;
        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0, public_key + j * 4, 4);
            if ((as[k]->yp[0][j] ^ as[k]->yp[1][j] ^ as[k]->yp[2][j]) != t0)
            {
                error = true;
            }
        }

        unsigned char hash1[SHA256_DIGEST_LENGTH];

        H_com(keys[k][0], localViews[k][0], rs[k][0], hash1);
        memcpy(&as[k]->h[0], hash1, 32);
        H_com(keys[k][1], localViews[k][1], rs[k][1], hash1);
        memcpy(&as[k]->h[1], hash1, 32);
        H_com(keys[k][2], localViews[k][2], rs[k][2], hash1);
        memcpy(&as[k]->h[2], hash1, 32);

        printf("\b");
        if (k > 8)
            printf("\b");
        if (k > 98)
            printf("\b");

        round++;
        printf("ZKBoo round built: %d/%d\r", round, NUM_ROUNDS);
    }
    printf("ZKBoo round built: %d/%d\n\n", round, NUM_ROUNDS);

    // Generating e
    int es[NUM_ROUNDS];
    uint32_t y[8];
    memcpy(y, public_key, 32);
    H3(y, as, NUM_ROUNDS, es);

    // Getting z
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        prove(zs[i], es[i], keys[i], rs[i], localViews[i]);
    }

    // Writing to file
    FILE *file = fopen("signature_proof.bin", "wb");

    bool write_success = write_to_file(file, as, zs);

    // free memory
    free_structures_prove(shares, as, zs, randomness, localViews);
    fclose(file);

    if (!write_success)
    {
        fprintf(stderr, "Error in writing signature_proof.bin\n\n");
        return EXIT_FAILURE;
    }

    if (error)
    {
        fprintf(stderr, "Error somewhere, the MSS signature is not valid for the "
                        "message or the blinding-key r. The generated proof is invalid.\n\n");
        exit(EXIT_FAILURE);
    }

    printf("===========================================================================\n");
    printf("\nSignature-Proof generated successfully in 'signature_proof.bin'.\n\n");
    return EXIT_SUCCESS;
}
