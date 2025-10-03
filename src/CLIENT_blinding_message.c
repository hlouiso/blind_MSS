#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define BLIND_KEY_LEN 32

void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("CLIENT_blinding_message\n"
               "\n"
               "Usage:\n"
               "  ./CLIENT_blinding_message [-h|--help]\n"
               "\n"
               "Description:\n"
               "  Prompts for a plaintext message, generates a random 32-byte blinding key r,\n"
               "  and prints the 64-byte blinded message = commitment || ~commitment,\n"
               "  with commitment = SHA256( SHA256(m) || r ).\n"
               "\n"
               "Input:\n"
               "  - message m from stdin (one line)\n"
               "Output (stdout):\n"
               "  - r (32 bytes, 64 hex uppercase)\n"
               "  - blinded message (64 bytes, 128 hex uppercase)\n");
        return 0;
    }

    char *message = NULL;
    size_t bufsize = 0;
    ssize_t len;

    unsigned char r[BLIND_KEY_LEN] = {0};
    unsigned char digest1[SHA256_DIGEST_LENGTH] = {0};
    unsigned char final_input[SHA256_DIGEST_LENGTH + BLIND_KEY_LEN] = {0};
    unsigned char commitment[SHA256_DIGEST_LENGTH] = {0};

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

    if (RAND_bytes(r, BLIND_KEY_LEN) != 1)
    {
        fprintf(stderr, "RAND_bytes failed\n");
        return EXIT_FAILURE;
    }

    printf("\nBlinding-key r (32 bytes):\n\n");
    print_hex(r, BLIND_KEY_LEN);

    SHA256((unsigned char *)message, strlen(message), digest1);

    memcpy(final_input, digest1, SHA256_DIGEST_LENGTH);
    memcpy(final_input + SHA256_DIGEST_LENGTH, r, BLIND_KEY_LEN);

    SHA256(final_input, SHA256_DIGEST_LENGTH + BLIND_KEY_LEN, commitment);

    unsigned char final_commitment[2 * SHA256_DIGEST_LENGTH] = {0};
    memcpy(final_commitment, commitment, SHA256_DIGEST_LENGTH);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        final_commitment[SHA256_DIGEST_LENGTH + i] = ~commitment[i];
    }

    printf("\nBlinded message = (commitment || ~commitment) ");
    printf("with commitment = SHA256(SHA256(m) || r)");
    printf("\n\n===========================================================================\n");
    printf("\nBlinded message (64 bytes):\n\n");
    print_hex(final_commitment, 2 * SHA256_DIGEST_LENGTH);
    printf("\n");

    free(message);

    return 0;
}
