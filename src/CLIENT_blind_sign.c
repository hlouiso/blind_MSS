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

static int read_hex(FILE *f, unsigned char *out, int n)
{
    int got = 0, hi = -1, c;
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

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("CLIENT_blind_sign\n\n"
               "  Builds a KKW/MPC-in-the-head proof of a valid WOTS+/XMSS blind signature.\n\n"
               "  Prompts: message m (stdin)\n"
               "  Reads:   blinding_key.txt, XMSS_signature.txt, XMSS_public_key.txt\n"
               "  Writes:  signature_proof.bin\n");
        return 0;
    }

    setbuf(stdout, NULL);

    /* ── message digest ── */
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

    /* ── blinding key ── */
    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    FILE *f = fopen("blinding_key.txt", "r");
    if (!f || read_hex(f, r, HM_R_BYTES) != 0 || read_hex(f, a_mat, HM_A_BYTES) != 0)
    {
        fprintf(stderr, "Error reading blinding_key.txt\n");
        return EXIT_FAILURE;
    }
    fclose(f);

    /* ── public key ── */
    unsigned char pk_seed[XMSS_PK_SEED_BYTES], root[XMSS_NODE_BYTES];
    f = fopen("XMSS_public_key.txt", "r");
    if (!f || read_hex(f, pk_seed, XMSS_PK_SEED_BYTES) != 0 || read_hex(f, root, XMSS_NODE_BYTES) != 0)
    {
        fprintf(stderr, "Error reading XMSS_public_key.txt\n");
        return EXIT_FAILURE;
    }
    fclose(f);

    /* ── XMSS signature ── */
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
        fprintf(stderr, "leaf_index %u out of bounds\n", sig.leaf_index);
        fclose(f);
        return EXIT_FAILURE;
    }
    int rerr = read_hex(f, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        rerr |= read_hex(f, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        rerr |= read_hex(f, sig.auth_path[h], XMSS_NODE_BYTES);
    fclose(f);
    if (rerr)
    {
        fprintf(stderr, "Error parsing XMSS_signature.txt\n");
        return EXIT_FAILURE;
    }

    /* ── Consistency pre-check ── */
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);
    if (!xmss_verify(pk_seed, root, d, 32, &sig))
    {
        fprintf(stderr, "Inconsistent inputs: XMSS signature invalid for certified digest.\n");
        return EXIT_FAILURE;
    }

    /* ── Expected public output ── */
    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++)
        memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ── Witness ── */
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

    /* ── Allocate prover structures ── */
    unsigned char seeds[NUM_ROUNDS][N_PARTIES][SEED_SIZE];
    unsigned char *x_shares[NUM_ROUNDS][N_PARTIES];
    a *as[NUM_ROUNDS];
    z *zs[NUM_ROUNDS];
    if (alloc_structures_prove(seeds, x_shares, as, zs) != 0)
    {
        fprintf(stderr, "Error allocating memory\n");
        return EXIT_FAILURE;
    }

    /* ── Generate random seeds and x shares ── */
    for (int round = 0; round < NUM_ROUNDS; round++)
    {
        /* Random seeds for all N parties */
        if (RAND_bytes(seeds[round][0], N_PARTIES * SEED_SIZE) != 1)
        {
            fprintf(stderr, "RAND_bytes failed\n");
            free_structures_prove(x_shares, as, zs);
            return EXIT_FAILURE;
        }
        /* Random x shares for parties 0..N-2; party N-1 = XOR complement */
        for (int p = 0; p < N_PARTIES - 1; p++)
        {
            if (RAND_bytes(x_shares[round][p], INPUT_LEN) != 1)
            {
                fprintf(stderr, "RAND_bytes failed\n");
                free_structures_prove(x_shares, as, zs);
                return EXIT_FAILURE;
            }
        }
        for (int byte = 0; byte < INPUT_LEN; byte++)
        {
            unsigned char xor_val = input[byte];
            for (int p = 0; p < N_PARTIES - 1; p++)
                xor_val ^= x_shares[round][p][byte];
            x_shares[round][N_PARTIES - 1][byte] = xor_val;
        }
    }

    printf("\n===========================================================================\n");
    printf("\nKKW rounds: %d, parties: %d, soundness 2^{-128}\n", NUM_ROUNDS, N_PARTIES);

    bool error = false;
    int round_ctr = 0;

#pragma omp parallel for schedule(dynamic, 1)
    for (int round = 0; round < NUM_ROUNDS; round++)
    {
        /* Expand Beaver tapes */
        unsigned char *tapes[N_PARTIES];
        bool tape_ok = true;
        for (int p = 0; p < N_PARTIES; p++)
        {
            tapes[p] = malloc((size_t)TAPE_SIZE);
            if (!tapes[p])
            {
                tape_ok = false;
                break;
            }
            expand_tape(seeds[round][p], tapes[p]);
        }
        if (!tape_ok)
        {
            for (int p = 0; p < N_PARTIES; p++)
                free(tapes[p]);
#pragma omp atomic write
            error = true;
            goto round_done;
        }

        building_views(as[round], m_hat, pk_seed, x_shares[round], tapes, zs[round]->broadcast, zs[round]->aux);

        /* Verify circuit output XOR */
        for (int j = 0; j < 8; j++)
        {
            uint32_t xorv = 0;
            for (int p = 0; p < N_PARTIES; p++)
                xorv ^= as[round]->yp[p][j];
            if (xorv != pubout[j]) {
#pragma omp atomic write
                error = true;
            }
        }

        /* Compute commitments */
        for (int p = 0; p < N_PARTIES; p++)
            H_com(seeds[round][p], x_shares[round][p], as[round]->yp[p], as[round]->h[p]);

        for (int p = 0; p < N_PARTIES; p++)
            free(tapes[p]);

    round_done:
        round_ctr++;
        printf("KKW round built: %d/%d\r", round_ctr, NUM_ROUNDS);
    }
    printf("KKW round built: %d/%d\n\n", NUM_ROUNDS, NUM_ROUNDS);

    /* ── Fiat–Shamir challenges ── */
    int es[NUM_ROUNDS];
    H3(m_hat, pubout, as, zs, NUM_ROUNDS, es);

    /* ── Fill proof z structs ── */
    for (int round = 0; round < NUM_ROUNDS; round++)
    {
        int e = es[round];
        /* Copy revealed seeds (N-1 of them) into z->ke */
        for (int j = 0; j < N_PARTIES - 1; j++)
        {
            int orig = (j < e) ? j : j + 1;
            memcpy(zs[round]->ke[j], seeds[round][orig], SEED_SIZE);
        }
        /* Copy revealed x shares into z->x_revealed */
        for (int j = 0; j < N_PARTIES - 1; j++)
        {
            int orig = (j < e) ? j : j + 1;
            memcpy(zs[round]->x_revealed + (size_t)j * INPUT_LEN, x_shares[round][orig], INPUT_LEN);
        }
        /* Hidden party's output share */
        memcpy(zs[round]->yp_e, as[round]->yp[e], 8 * sizeof(uint32_t));
    }

    FILE *file = fopen("signature_proof.bin", "wb");
    bool write_ok = file && write_to_file(file, as, zs);
    if (file)
        fclose(file);

    free_structures_prove(x_shares, as, zs);

    if (!write_ok)
    {
        fprintf(stderr, "Error writing signature_proof.bin\n\n");
        return EXIT_FAILURE;
    }
    if (error)
    {
        fprintf(stderr, "Circuit output mismatch. Proof would be invalid.\n\n");
        return EXIT_FAILURE;
    }

    printf("===========================================================================\n");
    printf("\nSignature-Proof generated in 'signature_proof.bin'.\n\n");
    return EXIT_SUCCESS;
}
