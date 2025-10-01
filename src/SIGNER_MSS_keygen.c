#include "shared.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

void pk_extract(unsigned char sk_seed[32])
{
    /* Leaves generation */
    unsigned char *level = malloc(nb_leaves * N);
    unsigned char *leafbuf = malloc(WOTS_len * N);

    for (uint32_t leaf = 0; leaf < nb_leaves; leaf++)
    {
        unsigned char sk[N], pk[N];
        unsigned char *w = leafbuf;
        for (uint32_t i = 0; i < WOTS_len; i++)
        {
            prf_aes256_ctr_32(sk_seed, leaf, i, sk);
            sha256_once(sk, N, pk);
            memcpy(w, pk, N);
            w += N;
        }
        sha256_once(leafbuf, WOTS_len * N, level + leaf * N);
    }

    /* Merkle tree root computation */
    unsigned char *next = malloc((nb_leaves / 2) * N);

    uint32_t nodes = nb_leaves;
    while (nodes > 1)
    {
        for (uint32_t i = 0; i < nodes; i += 2)
        {
            unsigned char buf[2 * N];
            memcpy(buf, level + i * N, N);
            memcpy(buf + N, level + (i + 1) * N, N);
            sha256_once(buf, sizeof buf, next + (i / 2) * N);
        }
        unsigned char *tmp = level;
        level = next;
        next = tmp;
        nodes >>= 1;
    }

    /* Public key writing */
    FILE *f = fopen("MSS_public_key.txt", "w");
    for (size_t i = 0; i < N; i++)
        fprintf(f, "%02X", level[i]);
    fprintf(f, "\n");
    fclose(f);

    printf("Your public key is:\n");
    for (size_t i = 0; i < N; i++)
    {
        printf("%02X", level[i]);
    }
    printf("\n\n");

    free(leafbuf);
    free(level);
    free(next);
}

int main(int argc, char *argv[])
{
    unsigned char sk_seed[32] = {0};

    if (RAND_bytes(sk_seed, 32) != 1)
    {
        fprintf(stderr, "Error with RAND_bytes\n");
        return 1;
    }

    FILE *f = fopen("MSS_secret_key.txt", "w");
    if (f == NULL)
    {
        fprintf(stderr, "Error with fopen\n");
        return 1;
    }

    for (size_t i = 0; i < 32; i++)
        fprintf(f, "%02X", sk_seed[i]);
    fprintf(f, "\n");

    fprintf(f, "0\n"); // index set to 0

    fclose(f);
    printf("===========================================================================\n\n");
    printf("Reminder: MSS_sk = (sk_seed, leaf_index) and MSS_pk = Merkle Tree root)\n\n");

    printf("Your secret key is:\nsk_seed = ");

    for (size_t i = 0; i < 32; i++)
    {
        printf("%02X", sk_seed[i]);
    }

    printf("\nleaf_index set to 0\n\n");

    pk_extract(sk_seed); // call to pk_gen function to generate the public key and save it in MSS_public_key.txt

    printf("MSS_secret_key.txt and MSS_public_key.txt generated\n\n");

    return 0;
}
