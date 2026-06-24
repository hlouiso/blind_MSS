#include "kkw_verify.h"
#include "shared.h"
#include "xmss.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_hex(FILE *f, unsigned char *out, int n)
{
    int got = 0, hi = -1, c;
    while (got < n && (c = fgetc(f)) != EOF) {
        int v;
        if      (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else continue;
        if (hi < 0) hi = v;
        else { out[got++] = (unsigned char)((hi << 4) | v); hi = -1; }
    }
    return got == n ? 0 : -1;
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("VERIFIER_verify\n\n"
               "  Verifies signature_proof.bin against XMSS_public_key.txt.\n"
               "  Reads: XMSS_public_key.txt, signature_proof.bin\n");
        return 0;
    }

    setbuf(stdout, NULL);

    /* ── Message ── */
    char *message = NULL; size_t bufsz = 0;
    printf("\nPlease enter the signed message:\n");
    if (getline(&message, &bufsz, stdin) == -1) { perror("getline"); return EXIT_FAILURE; }
    message[strcspn(message, "\n")] = '\0';
    unsigned char m_hat[32];
    SHA256((unsigned char *)message, strlen(message), m_hat);
    free(message);

    /* ── Public key ── */
    unsigned char pk_seed[XMSS_PK_SEED_BYTES], root[XMSS_NODE_BYTES];
    FILE *f = fopen("XMSS_public_key.txt", "r");
    if (!f || read_hex(f, pk_seed, XMSS_PK_SEED_BYTES) || read_hex(f, root, XMSS_NODE_BYTES)) {
        fprintf(stderr, "Error reading XMSS_public_key.txt\n"); return EXIT_FAILURE;
    }
    fclose(f);

    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ── Verify ── */
    printf("\n=========================================================================\n\n");
    FILE *proof = fopen("signature_proof.bin", "rb");
    if (!proof) { perror("signature_proof.bin"); return EXIT_FAILURE; }
    int rc = kkw_verify(proof, m_hat, pk_seed, pubout);
    fclose(proof);

    if (rc != 0) {
        printf("=========================================================================\n\n");
        printf("INVALID proof.\n\n");
        return EXIT_FAILURE;
    }

    printf("=========================================================================\n\n");
    printf("Proof VALID. Signature is authentic.\n\n");
    return EXIT_SUCCESS;
}
