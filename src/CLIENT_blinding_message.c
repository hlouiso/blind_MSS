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
               "  and prints the 32-byte commitment M = SHA256( SHA256(m) || r ).\n"
               "\n"
               "Input:\n"
               "  - message m from stdin (one line)\n"
               "Files:\n"
               "  - blinding_key.txt: r (32 bytes, 64 hex uppercase)\n"
               "  - blinded_message.txt: commitment M (32 bytes, 64 hex uppercase)\n");
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
        free(message);
        return EXIT_FAILURE;
    }

    printf("\n===========================================================================\n");
    printf("\nBlinding-key r (32 bytes):\n\n");
    print_hex(r, BLIND_KEY_LEN);

    FILE *fr = fopen("blinding_key.txt", "w");
    if (fr)
    {
        for (int i = 0; i < BLIND_KEY_LEN; i++)
            fprintf(fr, "%02X", r[i]);
        fprintf(fr, "\n");
        fclose(fr);
    }
    else
    {
        fprintf(stderr, "Error writing blinding_key.txt\n");
        free(message);
        return EXIT_FAILURE;
    }

    // commitment M = SHA256( SHA256(m) || r )
    SHA256((unsigned char *)message, strlen(message), digest1);
    memcpy(final_input, digest1, SHA256_DIGEST_LENGTH);
    memcpy(final_input + SHA256_DIGEST_LENGTH, r, BLIND_KEY_LEN);
    SHA256(final_input, SHA256_DIGEST_LENGTH + BLIND_KEY_LEN, commitment);

    printf("\nCommitment M = SHA256(SHA256(m) || r)");
    printf("\n\n===========================================================================\n");
    printf("\nCommitment M (32 bytes):\n\n");
    print_hex(commitment, SHA256_DIGEST_LENGTH);

    FILE *fm = fopen("blinded_message.txt", "w");
    if (fm)
    {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            fprintf(fm, "%02X", commitment[i]);
        fprintf(fm, "\n");
        fclose(fm);
    }
    else
    {
        fprintf(stderr, "Error writing blinded_message.txt\n");
        free(message);
        return EXIT_FAILURE;
    }

    printf("\n===========================================================================\n\n");
    printf("Blinding-key r and commitment M also written to files:\n"
           "  - blinding_key.txt\n"
           "  - blinded_message.txt\n\n");

    free(message);

    return 0;
}
