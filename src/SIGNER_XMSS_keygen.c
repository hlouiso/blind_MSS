#include "xmss.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

static void write_hex_line(FILE *f, const unsigned char *data, int n)
{
    for (int i = 0; i < n; i++)
        fprintf(f, "%02X", data[i]);
    fprintf(f, "\n");
}

static void print_hex(const unsigned char *data, int n)
{
    for (int i = 0; i < n; i++)
        printf("%02X", data[i]);
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("SIGNER_XMSS_keygen\n"
               "\n"
               "Usage:\n"
               "  ./SIGNER_XMSS_keygen [-h|--help]\n"
               "\n"
               "Description:\n"
               "  Generates a target-sum WOTS+ / XMSS keypair (height %d, 2^%d leaves).\n"
               "  Writes XMSS_secret_key.txt and XMSS_public_key.txt.\n"
               "\n"
               "Files:\n"
               "  - XMSS_secret_key.txt: line1=sk_seed (32 bytes, 64 hex), line2=pk_seed (16 bytes,\n"
               "    32 hex), line3=leaf_index (decimal)\n"
               "  - XMSS_public_key.txt: line1=pk_seed (16 bytes, 32 hex), line2=XMSS root\n"
               "    (16 bytes, 32 hex)\n",
               XMSS_H, XMSS_H);
        return 0;
    }

    unsigned char sk_seed[32] = {0};
    unsigned char pk_seed[XMSS_PK_SEED_BYTES] = {0};

    if (RAND_bytes(sk_seed, sizeof sk_seed) != 1 || RAND_bytes(pk_seed, sizeof pk_seed) != 1)
    {
        fprintf(stderr, "Error with RAND_bytes\n");
        return 1;
    }

    printf("===========================================================================\n\n");
    printf("Reminder: XMSS_sk = (sk_seed, pk_seed, leaf_index), XMSS_pk = (pk_seed, XMSS root)\n\n");

    printf("Computing the XMSS tree (2^%d leaves)...\n", XMSS_H);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    FILE *fsk = fopen("XMSS_secret_key.txt", "w");
    if (fsk == NULL)
    {
        fprintf(stderr, "Error opening XMSS_secret_key.txt\n");
        return 1;
    }
    write_hex_line(fsk, sk_seed, sizeof sk_seed);
    write_hex_line(fsk, pk_seed, sizeof pk_seed);
    fprintf(fsk, "0\n"); // leaf_index starts at 0
    fclose(fsk);

    FILE *fpk = fopen("XMSS_public_key.txt", "w");
    if (fpk == NULL)
    {
        fprintf(stderr, "Error opening XMSS_public_key.txt\n");
        return 1;
    }
    write_hex_line(fpk, pk_seed, sizeof pk_seed);
    write_hex_line(fpk, root, XMSS_NODE_BYTES);
    fclose(fpk);

    printf("\nYour secret key is:\nsk_seed = ");
    print_hex(sk_seed, sizeof sk_seed);
    printf("pk_seed = ");
    print_hex(pk_seed, sizeof pk_seed);
    printf("leaf_index set to 0\n\n");

    printf("Your public key is:\npk_seed = ");
    print_hex(pk_seed, sizeof pk_seed);
    printf("root    = ");
    print_hex(root, XMSS_NODE_BYTES);

    printf("\nXMSS_secret_key.txt and XMSS_public_key.txt generated\n\n");
    return 0;
}
