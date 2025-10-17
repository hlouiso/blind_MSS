#include "shared.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// MSS parameters
const int H = 10;
const int N = 32;
const int WOTS_len = 512;
const int nb_leaves = (1u << H);

// ZKBoo parameters & needed values
const int COMMIT_KEY_LEN = 32;
const int NUM_ROUNDS = 137; // Usually 137
const int ySize = 584360;
const int Random_Bytes_Needed = 2337440;

/* 16740 bytes = COMMIT_KEY_LEN (32 bytes) + leaf_index (4 bytes) + Sigma_size (512 * 32 bytes) + PATH (10*32 bytes) */
const int INPUT_LEN = 16740;

const uint32_t hA[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

const uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

int prf_aes256_ctr_32(const unsigned char sk_seed[32], uint32_t leaf, uint32_t j, unsigned char out32[32])
{
    unsigned char iv[16] = {0};

    iv[0] = iv[1] = iv[2] = iv[3] = 0xA5;

    iv[4] = (unsigned char)(leaf >> 24);
    iv[5] = (unsigned char)(leaf >> 16);
    iv[6] = (unsigned char)(leaf >> 8);
    iv[7] = (unsigned char)(leaf);

    iv[8] = (unsigned char)(j >> 24);
    iv[9] = (unsigned char)(j >> 16);
    iv[10] = (unsigned char)(j >> 8);
    iv[11] = (unsigned char)(j);

    iv[12] = iv[13] = iv[14] = iv[15] = 0;

    unsigned char zeros[32] = {0}; // The ciphered input is 32 bytes of zeros
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    int tmplen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, sk_seed, iv);
    EVP_EncryptUpdate(ctx, out32, &outl, zeros, sizeof zeros);
    EVP_EncryptFinal_ex(ctx, out32 + outl, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outl = 0;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal_ex(ctx, out32, &outl);
    EVP_MD_CTX_free(ctx);
    return 1;
}

void getAllRandomness(unsigned char key[32], unsigned char *randomness)
{
    unsigned char iv[16] = {0};
    iv[0] = iv[1] = iv[2] = iv[3] = 0xA5;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);

    size_t total = Random_Bytes_Needed;
    size_t offset = 0;
    unsigned char zeros[32] = {0};
    int outl = 0;

    while (offset < total)
    {
        size_t chunk = (total - offset > 32) ? 32 : (total - offset);
        unsigned char out[32];
        EVP_EncryptUpdate(ctx, out, &outl, zeros, 32);
        memcpy(randomness + offset, out, chunk);
        offset += chunk;
    }

    EVP_CIPHER_CTX_free(ctx);
}

uint32_t getRandom32(unsigned char *randomness, int randCount)
{
    uint32_t ret;
    memcpy(&ret, &randomness[randCount], 4);
    return ret;
}

int alloc_structures_prove(unsigned char *shares[NUM_ROUNDS][3], a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS],
                           unsigned char *randomness[NUM_ROUNDS][3], View *localViews[NUM_ROUNDS][3])
{
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        as[i] = NULL;
        zs[i] = NULL;
        for (int j = 0; j < 3; j++)
        {
            shares[i][j] = NULL;
            randomness[i][j] = NULL;
            localViews[i][j] = NULL;
        }
    }

    int round;
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        round = i;
        for (int j = 0; j < 3; j++)
        {
            shares[i][j] = malloc(INPUT_LEN);
            if (!shares[i][j])
                goto alloc_error;

            localViews[i][j] = malloc(sizeof(View));
            if (!localViews[i][j])
                goto alloc_error;

            localViews[i][j]->x = malloc(INPUT_LEN);
            if (!localViews[i][j]->x)
                goto alloc_error;

            localViews[i][j]->y = malloc(ySize * sizeof(uint32_t));
            if (!localViews[i][j]->y)
                goto alloc_error;

            randomness[i][j] = malloc(Random_Bytes_Needed);
            if (!randomness[i][j])
                goto alloc_error;
        }

        as[i] = malloc(sizeof(a));
        if (!as[i])
            goto alloc_error;

        zs[i] = malloc(sizeof(z));
        if (!zs[i])
            goto alloc_error;
    }

    return 0;

alloc_error:
    for (int i = 0; i <= round; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            free(shares[i][j]);
            if (localViews[i][j])
            {
                free(localViews[i][j]->x);
                free(localViews[i][j]->y);
                free(localViews[i][j]);
            }
            free(randomness[i][j]);
        }
        free(as[i]);
        free(zs[i]);
    }
    return -1;
}

void free_structures_prove(unsigned char *shares[NUM_ROUNDS][3], a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS],
                           unsigned char *randomness[NUM_ROUNDS][3], View *localViews[NUM_ROUNDS][3])
{
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 3; j++)
        {
            free(shares[k][j]);
            if (localViews[k][j])
            {
                free(localViews[k][j]->x);
                free(localViews[k][j]->y);
                free(localViews[k][j]);
            }
            free(randomness[k][j]);
        }
        free(as[k]);
        free(zs[k]);
    }
}

void H_com(unsigned char k[32], View *v, unsigned char r[32], unsigned char hash[SHA256_DIGEST_LENGTH])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outl = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, k, 32);
    EVP_DigestUpdate(ctx, v->x, INPUT_LEN);
    EVP_DigestUpdate(ctx, v->y, ySize * sizeof(uint32_t));
    EVP_DigestUpdate(ctx, r, 32);
    EVP_DigestFinal_ex(ctx, hash, &outl);

    EVP_MD_CTX_free(ctx);
}

void H3(uint32_t y[8], a *as[NUM_ROUNDS], int s, int *es)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outl = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, y, 32);

    for (int i = 0; i < s; i++)
    {
        EVP_DigestUpdate(ctx, as[i], sizeof(a));
    }

    EVP_DigestFinal_ex(ctx, hash, &outl);

    int i = 0;
    int bitTracker = 0;
    while (i < s)
    {
        if (bitTracker >= SHA256_DIGEST_LENGTH * 8)
        {
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, hash, sizeof(hash));
            EVP_DigestFinal_ex(ctx, hash, &outl);
            bitTracker = 0;
        }

        int b1 = GETBIT(hash[bitTracker / 8], bitTracker % 8);
        int b2 = GETBIT(hash[(bitTracker + 1) / 8], (bitTracker + 1) % 8);
        if (b1 == 0)
        {
            if (b2 == 0)
            {
                es[i] = 0;
                bitTracker += 2;
                i++;
            }
            else
            {
                es[i] = 1;
                bitTracker += 2;
                i++;
            }
        }
        else
        {
            if (b2 == 0)
            {
                es[i] = 2;
                bitTracker += 2;
                i++;
            }
            else
            {
                bitTracker += 2;
            }
        }
    }

    EVP_MD_CTX_free(ctx);
}

int alloc_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        as[i] = NULL;
        zs[i] = NULL;
    }

    int round;
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        round = i;
        as[i] = malloc(sizeof(a));
        if (!as[i])
            goto alloc_error;

        zs[i] = malloc(sizeof(z));
        if (!zs[i])
            goto alloc_error;

        zs[i]->ve.y = malloc(ySize * sizeof(uint32_t));
        if (!zs[i]->ve.y)
            goto alloc_error;

        zs[i]->ve.x = malloc(INPUT_LEN);
        if (!zs[i]->ve.x)
            goto alloc_error;

        zs[i]->ve1.y = malloc(ySize * sizeof(uint32_t));
        if (!zs[i]->ve1.y)
            goto alloc_error;

        zs[i]->ve1.x = malloc(INPUT_LEN);
        if (!zs[i]->ve1.x)
            goto alloc_error;
    }

    return 0;

alloc_error:
    for (int i = 0; i <= round; i++)
    {
        if (zs[i])
        {
            free(zs[i]->ve.y);
            free(zs[i]->ve.x);
            free(zs[i]->ve1.y);
            free(zs[i]->ve1.x);
            free(zs[i]);
        }
        free(as[i]);
    }
    return -1;
}

void free_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        free(zs[i]->ve.y);
        free(zs[i]->ve.x);
        free(zs[i]->ve1.y);
        free(zs[i]->ve1.x);
        free(zs[i]);

        free(as[i]);
    }
    return;
}

bool write_to_file(FILE *file, a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    bool write_success = true;
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        if (fwrite(as[i], sizeof(a), 1, file) != 1)
        {
            fprintf(stderr, "Erreur fwrite as[%d]\n", i);
            write_success = false;
        }
        if (fwrite(zs[i]->ke, sizeof(unsigned char), 32, file) != 32)
        {
            fprintf(stderr, "Erreur fwrite zs[%d]->ke\n", i);
            write_success = false;
        }
        if (fwrite(zs[i]->ke1, sizeof(unsigned char), 32, file) != 32)
        {
            fprintf(stderr, "Erreur fwrite zs[%d]->ke1\n", i);
            write_success = false;
        }
        if (fwrite(zs[i]->re, sizeof(unsigned char), 32, file) != 32)
        {
            fprintf(stderr, "Erreur fwrite zs[%d]->re\n", i);
            write_success = false;
        }
        if (fwrite(zs[i]->re1, sizeof(unsigned char), 32, file) != 32)
        {
            fprintf(stderr, "Erreur fwrite zs[%d]->re1\n", i);
            write_success = false;
        }
        if (fwrite(zs[i]->ve.x, sizeof(unsigned char), INPUT_LEN, file) != INPUT_LEN)
        {
            fprintf(stderr, "Erreur fwrite zs[%d]->ve.x\n", i);
            write_success = false;
        }
        if (fwrite(zs[i]->ve1.y, sizeof(uint32_t), ySize, file) != ySize)
        {
            fprintf(stderr, "Erreur fwrite zs[%d]->ve1.y\n", i);
            write_success = false;
        }
        if (fwrite(zs[i]->ve1.x, sizeof(unsigned char), INPUT_LEN, file) != INPUT_LEN)
        {
            fprintf(stderr, "Erreur fwrite zs[%d]->ve1.x\n", i);
            write_success = false;
        }
    }
    return write_success;
}