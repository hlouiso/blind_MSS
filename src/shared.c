#include "shared.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── KKW parameters ─────────────────────────────────────────────────────── */
const int NUM_ROUNDS = 32;
/* ySize: number of nonlinear gates (word-level) in one circuit execution.
 * Measured by test_circuit after any parameter change. */
const int ySize = 151776;
const int INPUT_LEN = 2762; /* W_END — see circuits.h */

/* TAPE_SIZE = 3 * ySize * 4 (u[], v[], w_raw[] blocks, each ySize uint32_t). */
const int TAPE_SIZE = 3 * 151776 * 4; /* = 1 821 312 bytes */

const uint32_t hA[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ── Tape expansion ─────────────────────────────────────────────────────── */

void expand_tape(const unsigned char seed[SEED_SIZE], unsigned char *tape)
{
    /* AES-256-CTR: seed → TAPE_SIZE bytes of pseudo-random Beaver triple data.
     * IV = {0xA5,0xA5,0xA5,0xA5, 0,0,...} (same domain separator as ZKBoo era). */
    unsigned char iv[16] = {0};
    iv[0] = iv[1] = iv[2] = iv[3] = 0xA5;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { memset(tape, 0, TAPE_SIZE); return; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, seed, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        memset(tape, 0, TAPE_SIZE);
        return;
    }

    unsigned char zeros[64] = {0};
    size_t offset = 0;
    size_t total = (size_t)TAPE_SIZE;
    int outl = 0;
    while (offset < total) {
        size_t chunk = (total - offset < 64) ? (total - offset) : 64;
        EVP_EncryptUpdate(ctx, tape + offset, &outl, zeros, (int)chunk);
        offset += chunk;
    }
    EVP_CIPHER_CTX_free(ctx);
}

/* ── SHA-256 helpers ────────────────────────────────────────────────────── */

int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, in, inlen) == 1 &&
             EVP_DigestFinal_ex(ctx, out32, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

void H_com(const unsigned char seed[SEED_SIZE],
           const unsigned char *x,
           const uint32_t yp[8],
           unsigned char hash[32])
{
    /* Encode yp as 32 big-endian bytes. */
    unsigned char yp_bytes[32];
    for (int i = 0; i < 8; i++) {
        yp_bytes[i*4+0] = (unsigned char)(yp[i] >> 24);
        yp_bytes[i*4+1] = (unsigned char)(yp[i] >> 16);
        yp_bytes[i*4+2] = (unsigned char)(yp[i] >>  8);
        yp_bytes[i*4+3] = (unsigned char)(yp[i]);
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(hash, 0, 32); return; }
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, seed, SEED_SIZE) == 1 &&
             EVP_DigestUpdate(ctx, x, (size_t)INPUT_LEN) == 1 &&
             EVP_DigestUpdate(ctx, yp_bytes, 32) == 1 &&
             EVP_DigestFinal_ex(ctx, hash, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) memset(hash, 0, 32);
}

/* ── Fiat–Shamir challenge ─────────────────────────────────────────────── */

void H3(const unsigned char message_digest[32], const uint32_t pubout[8],
        a *as[NUM_ROUNDS], int s, int *es)
{
    /* Encode pubout as 32 big-endian bytes. */
    unsigned char pubout_bytes[32];
    for (int i = 0; i < 8; i++) {
        pubout_bytes[i*4+0] = (unsigned char)(pubout[i] >> 24);
        pubout_bytes[i*4+1] = (unsigned char)(pubout[i] >> 16);
        pubout_bytes[i*4+2] = (unsigned char)(pubout[i] >>  8);
        pubout_bytes[i*4+3] = (unsigned char)(pubout[i]);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(es, 0, s * sizeof(*es)); return; }
    unsigned int outl = 0;

    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, message_digest, 32) == 1 &&
             EVP_DigestUpdate(ctx, pubout_bytes, 32) == 1;
    for (int i = 0; i < s && ok; i++)
        ok = EVP_DigestUpdate(ctx, as[i], sizeof(a)) == 1;
    ok = ok && EVP_DigestFinal_ex(ctx, hash, &outl) == 1;
    if (!ok) {
        EVP_MD_CTX_free(ctx);
        memset(es, 0, s * sizeof(*es));
        return;
    }

    /* Extract challenges in {0 .. N_PARTIES-1}.
     * Use 4 bits per challenge (N_PARTIES=16 is a power of two → no rejection). */
    int i = 0, byteIdx = 0, nibble = 0;
    while (i < s) {
        if (byteIdx >= SHA256_DIGEST_LENGTH) {
            ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
                 EVP_DigestUpdate(ctx, hash, sizeof(hash)) == 1 &&
                 EVP_DigestFinal_ex(ctx, hash, &outl) == 1;
            if (!ok) {
                EVP_MD_CTX_free(ctx);
                memset(es, 0, s * sizeof(*es));
                return;
            }
            byteIdx = 0; nibble = 0;
        }
        /* Extract one 4-bit nibble from current byte. */
        int val;
        if (nibble == 0) {
            val = (hash[byteIdx] >> 4) & 0xF;
            nibble = 1;
        } else {
            val = hash[byteIdx] & 0xF;
            nibble = 0;
            byteIdx++;
        }
        es[i++] = val; /* val ∈ {0..15} = {0..N_PARTIES-1} */
    }
    EVP_MD_CTX_free(ctx);
}

/* ── Prove allocation ───────────────────────────────────────────────────── */

int alloc_structures_prove(
    unsigned char  seeds[NUM_ROUNDS][N_PARTIES][SEED_SIZE],
    unsigned char *x_shares[NUM_ROUNDS][N_PARTIES],
    a             *as[NUM_ROUNDS],
    z             *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) {
        as[i] = NULL; zs[i] = NULL;
        for (int j = 0; j < N_PARTIES; j++)
            x_shares[i][j] = NULL;
    }
    /* Initialize seeds to zero; caller fills via RAND_bytes. */
    memset(seeds, 0, (size_t)NUM_ROUNDS * N_PARTIES * SEED_SIZE);

    int round = 0;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        round = i;
        for (int j = 0; j < N_PARTIES; j++) {
            x_shares[i][j] = malloc((size_t)INPUT_LEN);
            if (!x_shares[i][j]) goto err;
        }
        as[i] = calloc(1, sizeof(a));
        if (!as[i]) goto err;
        zs[i] = calloc(1, sizeof(z));
        if (!zs[i]) goto err;

        /* Allocate z internals (broadcast and aux; x_revealed set later). */
        zs[i]->broadcast = malloc((size_t)2 * ySize * sizeof(uint32_t));
        if (!zs[i]->broadcast) goto err;
        zs[i]->aux = malloc((size_t)ySize * sizeof(uint32_t));
        if (!zs[i]->aux) goto err;
        zs[i]->x_revealed = malloc((size_t)(N_PARTIES - 1) * INPUT_LEN);
        if (!zs[i]->x_revealed) goto err;
    }
    return 0;

err:
    for (int i = 0; i <= round; i++) {
        for (int j = 0; j < N_PARTIES; j++) { free(x_shares[i][j]); x_shares[i][j] = NULL; }
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->broadcast);
            free(zs[i]->aux);
            free(zs[i]->x_revealed);
            free(zs[i]);
        }
    }
    return -1;
}

void free_structures_prove(
    unsigned char *x_shares[NUM_ROUNDS][N_PARTIES],
    a             *as[NUM_ROUNDS],
    z             *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) {
        for (int j = 0; j < N_PARTIES; j++) free(x_shares[i][j]);
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->broadcast);
            free(zs[i]->aux);
            free(zs[i]->x_revealed);
            free(zs[i]);
        }
    }
}

/* ── Verify allocation ──────────────────────────────────────────────────── */

int alloc_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) { as[i] = NULL; zs[i] = NULL; }

    int round = 0;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        round = i;
        as[i] = calloc(1, sizeof(a));
        if (!as[i]) goto err;
        zs[i] = calloc(1, sizeof(z));
        if (!zs[i]) goto err;
        zs[i]->broadcast = malloc((size_t)2 * ySize * sizeof(uint32_t));
        if (!zs[i]->broadcast) goto err;
        zs[i]->aux = malloc((size_t)ySize * sizeof(uint32_t));
        if (!zs[i]->aux) goto err;
        zs[i]->x_revealed = malloc((size_t)(N_PARTIES - 1) * INPUT_LEN);
        if (!zs[i]->x_revealed) goto err;
    }
    return 0;

err:
    for (int i = 0; i <= round; i++) {
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->broadcast);
            free(zs[i]->aux);
            free(zs[i]->x_revealed);
            free(zs[i]);
        }
    }
    return -1;
}

void free_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) {
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->broadcast);
            free(zs[i]->aux);
            free(zs[i]->x_revealed);
            free(zs[i]);
        }
    }
}

/* ── Proof serialization ────────────────────────────────────────────────── */

bool write_to_file(FILE *file, a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    bool ok = true;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        /* Commitment struct (yp[N][8] + h[N][32]). */
        if (fwrite(as[i], sizeof(a), 1, file) != 1) {
            fprintf(stderr, "fwrite as[%d] failed\n", i); ok = false;
        }
        /* Revealed seeds: (N-1) * SEED_SIZE bytes. */
        if (fwrite(zs[i]->ke, SEED_SIZE, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1)) {
            fprintf(stderr, "fwrite ke[%d] failed\n", i); ok = false;
        }
        /* Revealed x shares: (N-1) * INPUT_LEN bytes. */
        if (fwrite(zs[i]->x_revealed, (size_t)INPUT_LEN, N_PARTIES - 1, file) != (size_t)(N_PARTIES - 1)) {
            fprintf(stderr, "fwrite x_revealed[%d] failed\n", i); ok = false;
        }
        /* Hidden party's output share. */
        if (fwrite(zs[i]->yp_e, sizeof(uint32_t), 8, file) != 8) {
            fprintf(stderr, "fwrite yp_e[%d] failed\n", i); ok = false;
        }
        /* Broadcast: 2*ySize uint32_t. */
        if (fwrite(zs[i]->broadcast, sizeof(uint32_t), (size_t)(2 * ySize), file) != (size_t)(2 * ySize)) {
            fprintf(stderr, "fwrite broadcast[%d] failed\n", i); ok = false;
        }
        /* Aux: ySize uint32_t. */
        if (fwrite(zs[i]->aux, sizeof(uint32_t), (size_t)ySize, file) != (size_t)ySize) {
            fprintf(stderr, "fwrite aux[%d] failed\n", i); ok = false;
        }
    }
    return ok;
}
