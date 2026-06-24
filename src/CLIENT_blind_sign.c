#include "commitment.h"
#include "kkw_prove.h"
#include "shared.h"
#include "xmss.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
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
        printf("CLIENT_blind_sign\n\n"
               "  Builds a KKW proof of a valid blind XMSS signature.\n"
               "  Reads:  blinding_key.txt, XMSS_signature.txt, XMSS_public_key.txt\n"
               "  Writes: signature_proof.bin\n");
        return 0;
    }

    setbuf(stdout, NULL);

    /* ── Message ── */
    char *message = NULL; size_t bufsz = 0;
    printf("\nPlease enter your message:\n");
    if (getline(&message, &bufsz, stdin) == -1) { perror("getline"); return EXIT_FAILURE; }
    message[strcspn(message, "\n")] = '\0';
    unsigned char m_hat[32];
    SHA256((unsigned char *)message, strlen(message), m_hat);
    free(message);

    /* ── Blinding key ── */
    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    FILE *f = fopen("blinding_key.txt", "r");
    if (!f || read_hex(f, r, HM_R_BYTES) || read_hex(f, a_mat, HM_A_BYTES)) {
        fprintf(stderr, "Error reading blinding_key.txt\n"); return EXIT_FAILURE;
    }
    fclose(f);

    /* ── Public key ── */
    unsigned char pk_seed[XMSS_PK_SEED_BYTES], root[XMSS_NODE_BYTES];
    f = fopen("XMSS_public_key.txt", "r");
    if (!f || read_hex(f, pk_seed, XMSS_PK_SEED_BYTES) || read_hex(f, root, XMSS_NODE_BYTES)) {
        fprintf(stderr, "Error reading XMSS_public_key.txt\n"); return EXIT_FAILURE;
    }
    fclose(f);

    /* ── XMSS signature ── */
    xmss_sig sig;
    f = fopen("XMSS_signature.txt", "r");
    if (!f) { fprintf(stderr, "Error opening XMSS_signature.txt\n"); return EXIT_FAILURE; }
    char buf[64];
    if (!fgets(buf, sizeof buf, f)) { fclose(f); return EXIT_FAILURE; }
    sig.leaf_index = (uint32_t)strtoul(buf, NULL, 10);
    int rerr = read_hex(f, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++) rerr |= read_hex(f, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)         rerr |= read_hex(f, sig.auth_path[h],  XMSS_NODE_BYTES);
    fclose(f);
    if (rerr) { fprintf(stderr, "Error parsing XMSS_signature.txt\n"); return EXIT_FAILURE; }

    /* ── Consistency check ── */
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);
    if (!xmss_verify(pk_seed, root, d, 32, &sig)) {
        fprintf(stderr, "Inconsistent inputs: signature invalid.\n"); return EXIT_FAILURE;
    }

    /* ── Public output ── */
    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ── Witness ── */
    unsigned char input[W_END];
    memcpy(input + W_R_OFF,   r,      HM_R_BYTES);
    memcpy(input + W_A_OFF,   a_mat,  HM_A_BYTES);
    input[W_LEAFIDX_OFF + 0] = (sig.leaf_index >> 24) & 0xFF;
    input[W_LEAFIDX_OFF + 1] = (sig.leaf_index >> 16) & 0xFF;
    input[W_LEAFIDX_OFF + 2] = (sig.leaf_index >>  8) & 0xFF;
    input[W_LEAFIDX_OFF + 3] = (sig.leaf_index)       & 0xFF;
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    /* ── Prove ── */
    printf("\n=========================================================================\n");
    FILE *out = fopen("signature_proof.bin", "wb");
    if (!out) { perror("signature_proof.bin"); return EXIT_FAILURE; }
    int rc = kkw_prove(input, m_hat, pk_seed, pubout, out);
    fclose(out);

    if (rc != 0) { fprintf(stderr, "Proof generation failed.\n"); return EXIT_FAILURE; }

    printf("=========================================================================\n");
    printf("Proof written to signature_proof.bin\n\n");
    return EXIT_SUCCESS;
}
