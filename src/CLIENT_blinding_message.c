#include "commitment.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

static void fwrite_hex(FILE *f, const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        fprintf(f, "%02X", data[i]);
    fprintf(f, "\n");
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("CLIENT_blinding_message\n"
               "\n"
               "Usage:\n"
               "  ./CLIENT_blinding_message [-h|--help]\n"
               "\n"
               "Description:\n"
               "  Prompts for a plaintext message m and builds a Halevi-Micali commitment to\n"
               "  m_hat = SHA256(m) over GF(2^128):\n"
               "    y   = SHA256(r_1 || ... || r_6)                 (n=6 nonces)\n"
               "    b_k = m_hat_k + sum_i a_{k,i} . r_i   (k=0,1, over GF(2^128))\n"
               "    com = a || b || y                               (256-byte commitment)\n"
               "    d   = SHA256(com)                               (digest the signer signs)\n"
               "\n"
               "Files:\n"
               "  - blinding_key.txt:    the secret opening, r (96 B) then a (192 B), hex\n"
               "  - blinded_message.txt: the commitment com = a || b || y (256 B, 512 hex)\n");
        return 0;
    }

    char *message = NULL;
    size_t bufsize = 0;
    ssize_t len;

    printf("\nEnter your message: ");
    len = getline(&message, &bufsize, stdin);
    if (len == -1)
    {
        perror("Error with getline function\n");
        free(message);
        return EXIT_FAILURE;
    }
    if (message[len - 1] == '\n')
        message[len - 1] = '\0';

    /* public message digest m_hat = SHA256(m) */
    unsigned char m_hat[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), m_hat);
    free(message);

    /* secret opening: r (6 nonces) and a (2x6 line matrix), uniform over GF(2^128) */
    unsigned char r[HM_R_BYTES];
    unsigned char a[HM_A_BYTES];
    if (RAND_bytes(r, sizeof r) != 1 || RAND_bytes(a, sizeof a) != 1)
    {
        fprintf(stderr, "RAND_bytes failed\n");
        return EXIT_FAILURE;
    }

    /* com = a || b || y  and  d = SHA256(com) */
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a, com, d);

    printf("\n===========================================================================\n");
    printf("\nCommitment com = a || b || y (256 bytes):\n\n");
    print_hex(com, HM_COM_BYTES);
    printf("\nCertified digest d = SHA256(com) (the signer signs this):\n\n");
    print_hex(d, 32);

    FILE *fk = fopen("blinding_key.txt", "w");
    if (!fk)
    {
        fprintf(stderr, "Error writing blinding_key.txt\n");
        return EXIT_FAILURE;
    }
    fwrite_hex(fk, r, HM_R_BYTES); /* line 1: r   (96 B)  */
    fwrite_hex(fk, a, HM_A_BYTES); /* line 2: a   (192 B) */
    fclose(fk);

    FILE *fm = fopen("blinded_message.txt", "w");
    if (!fm)
    {
        fprintf(stderr, "Error writing blinded_message.txt\n");
        return EXIT_FAILURE;
    }
    fwrite_hex(fm, com, HM_COM_BYTES);
    fclose(fm);

    printf("\n===========================================================================\n\n");
    printf("Secret opening (r, a) and commitment com written to files:\n"
           "  - blinding_key.txt\n"
           "  - blinded_message.txt\n\n");
    return 0;
}
