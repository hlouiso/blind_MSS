#include "shared.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

void build_path(unsigned char sk_seed[32], uint32_t leaf_idx, FILE *f)
{
    unsigned char *level = (unsigned char *)malloc(nb_leaves * SHA256_DIGEST_LENGTH);

    for (uint32_t leaf = 0; leaf < nb_leaves; leaf++)
    {
        unsigned char leaf_buf[WOTS_len * SHA256_DIGEST_LENGTH];
        unsigned char sigma[SHA256_DIGEST_LENGTH];

        for (uint32_t i = 0; i < WOTS_len; ++i)
        {
            prf_aes256_ctr_32(sk_seed, leaf, i, sigma);
            sha256_once(sigma, SHA256_DIGEST_LENGTH, leaf_buf + i * SHA256_DIGEST_LENGTH);
        }

        sha256_once(leaf_buf, WOTS_len * SHA256_DIGEST_LENGTH, level + leaf * SHA256_DIGEST_LENGTH);
    }

    unsigned char *cur = level;
    uint32_t curN = nb_leaves;

    for (int h = 0; h < H; h++)
    {
        uint32_t node_idx = (leaf_idx >> h);
        uint32_t sib_idx = (node_idx ^ 1u);
        unsigned char *sib = cur + sib_idx * SHA256_DIGEST_LENGTH;

        for (int b = 0; b < SHA256_DIGEST_LENGTH; b++)
            fprintf(f, "%02X", sib[b]);
        fprintf(f, "\n");

        if (h == H - 1)
            break;

        uint32_t nextN = (curN >> 1);
        unsigned char *next = (unsigned char *)malloc(nextN * SHA256_DIGEST_LENGTH);

        for (uint32_t k = 0; k < nextN; k++)
        {
            const unsigned char *base = cur + (2 * k) * SHA256_DIGEST_LENGTH;
            sha256_once(base, 2 * SHA256_DIGEST_LENGTH, next + k * SHA256_DIGEST_LENGTH);
        }

        free(cur);
        cur = next;
        curN = nextN;
    }
    free(cur);
}

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("SIGNER_MSS_sign\n"
               "\n"
               "Usage:\n"
               "  ./SIGNER_MSS_sign [-h|--help]\n"
               "\n"
               "Description:\n"
               "  Reads MSS_secret_key.txt and prompts for the blinded message (128 hex chars),\n"
               "  then writes MSS_signature.txt.\n"
               "\n"
               "Input:\n"
               "  - blinded message (64 bytes, 128 hex uppercase) from stdin\n"
               "Reads:\n"
               "  - MSS_secret_key.txt\n"
               "Output file:\n"
               "  - MSS_signature.txt with:\n"
               "    * line1: leaf_index (decimal)\n"
               "    * line2: empty\n"
               "    * next WOTS_len (=512) lines: 32-byte chunks (64 hex uppercase)\n"
               "    * empty line\n"
               "    * next H (=10) lines: authentication path nodes (32 bytes each)\n");
        return 0;
    }

    /* ============================== Getting keys ============================== */
    FILE *f = fopen("MSS_secret_key.txt", "r");
    if (f == NULL)
    {
        fprintf(stderr, "Error opening MSS_secret_key.txt\n");
        return EXIT_FAILURE;
    }

    unsigned char sk_seed[32];
    uint32_t leaf_idx;
    int c1, c2;

    for (int i = 0; i < 32; i++)
    {
        c1 = fgetc(f);
        c2 = fgetc(f);
        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        sk_seed[i] = (unsigned char)((c1 << 4) | c2);
    }

    c1 = fgetc(f); // newline

    if (fscanf(f, "%u", &leaf_idx) != 1)
    {
        fprintf(stderr, "Error reading leaf_idx from MSS_secret_key.txt\n");
        fclose(f);
        return EXIT_FAILURE;
    }

    if (leaf_idx >= (1u << H))
    {
        fprintf(stderr, "Error: leaf_idx out of bounds\n");
        fclose(f);
        return EXIT_FAILURE;
    }

    fclose(f);

    /* ============================== Signing ============================== */

    f = fopen("MSS_signature.txt", "w");
    if (f == NULL)
    {
        fprintf(stderr, "Error opening MSS_signature.txt\n");
        return EXIT_FAILURE;
    }
    fprintf(f, "%d\n\n", leaf_idx);

    // Getting blinded_message
    char *message = NULL;
    size_t bufferSize = 0;

    printf("\nPlease enter the blinded message sent by the CLIENT (64 bytes long = 128 hex chars):\n");
    int length = getline(&message, &bufferSize, stdin);
    printf("\n===========================================================================\n");
    if (length != 129)
    {
        fprintf(stderr, "\nError: blinded message should be 64 bytes long = 128 hex chars\n\n");
        free(message);
        fclose(f);
        return EXIT_FAILURE;
    }

    unsigned char message_bits[2 * SHA256_DIGEST_LENGTH];

    for (int i = 0; i < 2 * SHA256_DIGEST_LENGTH; i++)
    {
        unsigned int byte;
        sscanf(message + 2 * i, "%2X", &byte);
        message_bits[i] = (unsigned char)byte;
    }

    unsigned char sigma[SHA256_DIGEST_LENGTH];
    for (int i = 0; i < WOTS_len; i++)
    {
        prf_aes256_ctr_32(sk_seed, leaf_idx, i, sigma);
        if (((message_bits[i / 8] >> (7 - (i % 8))) & 1) == 1)
        {
            // If bit is 1, hash
            sha256_once(sigma, SHA256_DIGEST_LENGTH, sigma);
        }
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
        {
            fprintf(f, "%02X", sigma[j]);
        }
        fprintf(f, "\n");
    }

    fprintf(f, "\n");

    /* ============================== PATH  ============================== */

    build_path(sk_seed, leaf_idx, f);

    fclose(f);
    free(message);

    /* ============================== Mise à jour MSS_secret_key.txt ============================== */
    leaf_idx++;
    FILE *fkey = fopen("MSS_secret_key.txt", "w");
    if (fkey == NULL)
    {
        fprintf(stderr, "Error updating MSS_secret_key.txt\n");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 32; i++)
    {
        fprintf(fkey, "%02X", sk_seed[i]);
    }
    fprintf(fkey, "\n%u\n", leaf_idx);
    fclose(fkey);

    printf("\nMSS_signature.txt generated\n\n");
    printf("Reminder: MSS_signature = (leaf_index, WOTS signature, PATH)\n\n");

    return 0;
}