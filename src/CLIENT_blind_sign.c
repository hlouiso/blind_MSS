#include "circuits.h"
#include "commitment.h"
#include "shared.h"
#include "xmss.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <omp.h>

/* Read exactly n bytes (2n hex chars), skipping any non-hex characters (newlines). */
static int read_hex(FILE *f, unsigned char *out, int n)
{
    int got = 0;
    int hi = -1;
    int c;
    while (got < n && (c = fgetc(f)) != EOF)
    {
        int v;
        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'A' && c <= 'F')
            v = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            v = c - 'a' + 10;
        else
            continue;
        if (hi < 0)
            hi = v;
        else
        {
            out[got++] = (unsigned char)((hi << 4) | v);
            hi = -1;
        }
    }
    return got == n ? 0 : -1;
}

void prove(z *z, int e, unsigned char keys[3][32], unsigned char rs[3][32], View *views[3])
{
    memcpy(&z->ke, keys[e], 32);
    memcpy(&z->ke1, keys[(e + 1) % 3], 32);
    z->ve.x = views[e]->x;
    z->ve1.x = views[(e + 1) % 3]->x;
    z->ve1.y = views[(e + 1) % 3]->y;
    memcpy(&z->re, rs[e], 32);
    memcpy(&z->re1, rs[(e + 1) % 3], 32);
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("CLIENT_blind_sign\n\n"
               "  Builds a ZKBoo/MPC-in-the-head proof of a valid target-sum WOTS+/XMSS\n"
               "  signature on the certified digest d = SHA256(a||b||y) of a Halevi-Micali\n"
               "  commitment that opens to m_hat = SHA256(m).\n\n"
               "  Prompts: message m (stdin)\n"
               "  Reads:   blinding_key.txt, XMSS_signature.txt, XMSS_public_key.txt\n"
               "  Writes:  signature_proof.bin\n");
        return 0;
    }

    setbuf(stdout, NULL);

    /* ---- message digest m_hat = SHA256(m) (public input) ---- */
    char *message = NULL;
    size_t bufferSize = 0;
    printf("\nPlease enter your message:\n");
    if (getline(&message, &bufferSize, stdin) == -1)
    {
        perror("Error reading message");
        return EXIT_FAILURE;
    }
    message[strcspn(message, "\n")] = '\0';
    unsigned char m_hat[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), m_hat);
    free(message);

    /* ---- secret opening: r (6 nonces) then a (2x6 line matrix) ---- */
    unsigned char r[HM_R_BYTES];
    unsigned char a_mat[HM_A_BYTES];
    FILE *f = fopen("blinding_key.txt", "r");
    if (!f || read_hex(f, r, HM_R_BYTES) != 0 || read_hex(f, a_mat, HM_A_BYTES) != 0)
    {
        fprintf(stderr, "Error reading blinding_key.txt\n");
        return EXIT_FAILURE;
    }
    fclose(f);

    /* ---- public key: pk_seed (16) then root (16) ---- */
    unsigned char pk_seed[XMSS_PK_SEED_BYTES], root[XMSS_NODE_BYTES];
    f = fopen("XMSS_public_key.txt", "r");
    if (!f || read_hex(f, pk_seed, XMSS_PK_SEED_BYTES) != 0 || read_hex(f, root, XMSS_NODE_BYTES) != 0)
    {
        fprintf(stderr, "Error reading XMSS_public_key.txt\n");
        return EXIT_FAILURE;
    }
    fclose(f);

    /* ---- signature: leaf_index, nonce, sig_hashes, auth_path ---- */
    xmss_sig sig;
    f = fopen("XMSS_signature.txt", "r");
    if (!f)
    {
        fprintf(stderr, "Error opening XMSS_signature.txt\n");
        return EXIT_FAILURE;
    }
    char buf[64];
    if (!fgets(buf, sizeof buf, f))
    {
        fprintf(stderr, "Error reading leaf_index\n");
        fclose(f);
        return EXIT_FAILURE;
    }
    sig.leaf_index = (uint32_t)strtoul(buf, NULL, 10);
    if (sig.leaf_index >= (1u << XMSS_H))
    {
        fprintf(stderr, "Error: leaf_index %u out of bounds\n", sig.leaf_index);
        fclose(f);
        return EXIT_FAILURE;
    }
    int rerr = read_hex(f, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        rerr |= read_hex(f, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        rerr |= read_hex(f, sig.auth_path[h], XMSS_NODE_BYTES);
    fclose(f);
    if (rerr != 0)
    {
        fprintf(stderr, "Error parsing XMSS_signature.txt\n");
        return EXIT_FAILURE;
    }

    /* ---- native consistency pre-check (user verifies Sigma before proving) ---- */
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d); /* com = a||b||y, d = SHA256(com) */
    if (!xmss_verify(pk_seed, root, d, 32, &sig))
    {
        fprintf(stderr, "Inconsistent inputs: the XMSS signature is not valid for the certified digest\n"
                        "d = SHA256(a||b||y) under this public key. Check the message, opening, and signature.\n");
        return EXIT_FAILURE;
    }

    /* ---- expected public output: root | target sum | 0 ---- */
    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++)
        memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ---- witness ---- */
    unsigned char input[W_END];
    memcpy(input + W_R_OFF, r, HM_R_BYTES);
    memcpy(input + W_A_OFF, a_mat, HM_A_BYTES);
    input[W_LEAFIDX_OFF + 0] = (sig.leaf_index >> 24) & 0xFF;
    input[W_LEAFIDX_OFF + 1] = (sig.leaf_index >> 16) & 0xFF;
    input[W_LEAFIDX_OFF + 2] = (sig.leaf_index >> 8) & 0xFF;
    input[W_LEAFIDX_OFF + 3] = (sig.leaf_index) & 0xFF;
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    /* ---- allocate prover structures ---- */
    unsigned char *shares[NUM_ROUNDS][3];
    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    unsigned char *randomness[NUM_ROUNDS][3];
    View *localViews[NUM_ROUNDS][3];
    if (alloc_structures_prove(shares, as, zs, randomness, localViews) != 0)
    {
        fprintf(stderr, "Error allocating memory\n");
        return EXIT_FAILURE;
    }

    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 2; j++)
            if (RAND_bytes(shares[k][j], INPUT_LEN) != 1)
            {
                fprintf(stderr, "RAND_bytes failed\n");
                free_structures_prove(shares, as, zs, randomness, localViews);
                return EXIT_FAILURE;
            }
        for (int j = 0; j < INPUT_LEN; j++)
            shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
        for (int j = 0; j < 3; j++)
            memcpy(localViews[k][j]->x, shares[k][j], INPUT_LEN);
    }

    bool error = false;
    unsigned char keys[NUM_ROUNDS][3][32];
    unsigned char rs[NUM_ROUNDS][3][32];
    if (RAND_bytes((unsigned char *)keys, NUM_ROUNDS * 3 * 32) != 1 ||
        RAND_bytes((unsigned char *)rs, NUM_ROUNDS * 3 * 32) != 1)
    {
        fprintf(stderr, "Error: RAND_bytes failed (entropy source unavailable)\n");
        free_structures_prove(shares, as, zs, randomness, localViews);
        return EXIT_FAILURE;
    }

    printf("\n===========================================================================\n");
    printf("\nChosen number of ZKBoo rounds: %d (can be changed in 'src/shared.c')\n", NUM_ROUNDS);

    int round = 0;
#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 3; j++)
            getAllRandomness(keys[k][j], randomness[k][j]);

        building_views(as[k], m_hat, pk_seed, shares[k], randomness[k], localViews[k]);

        for (int j = 0; j < 8; j++)
            if ((as[k]->yp[0][j] ^ as[k]->yp[1][j] ^ as[k]->yp[2][j]) != pubout[j])
                error = true;

        for (int j = 0; j < 3; j++)
        {
            unsigned char hash1[SHA256_DIGEST_LENGTH];
            H_com(keys[k][j], localViews[k][j], rs[k][j], hash1);
            memcpy(&as[k]->h[j], hash1, 32);
        }

#pragma omp atomic
        round++;
        printf("ZKBoo round built: %d/%d\r", round, NUM_ROUNDS);
    }
    printf("ZKBoo round built: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

    int es[NUM_ROUNDS];
    H3(m_hat, pubout, as, NUM_ROUNDS, es);

    for (int i = 0; i < NUM_ROUNDS; i++)
        prove(zs[i], es[i], keys[i], rs[i], localViews[i]);

    FILE *file = fopen("signature_proof.bin", "wb");
    bool write_success = file && write_to_file(file, as, zs);
    if (file)
        fclose(file);

    free_structures_prove(shares, as, zs, randomness, localViews);

    if (!write_success)
    {
        fprintf(stderr, "Error writing signature_proof.bin\n\n");
        return EXIT_FAILURE;
    }
    if (error)
    {
        fprintf(stderr, "Circuit output != public key. The proof would be invalid.\n\n");
        return EXIT_FAILURE;
    }

    printf("===========================================================================\n");
    printf("\nSignature-Proof generated successfully in 'signature_proof.bin'.\n\n");
    return EXIT_SUCCESS;
}
