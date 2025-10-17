#include "circuits.h"
#include "MPC_prove_functions.h"
#include "MPC_verify_functions.h"
#include "shared.h"

#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void building_views(a *a, unsigned char message_digest[32], unsigned char *shares[3], unsigned char *randomness[3],
                    View *views[3])
{
    const int leaf_index_index = 32;
    const int sigma_index = 36;
    const int path_index = 36 + WOTS_len * SHA256_DIGEST_LENGTH;

    /* =========== First compute the share of (commitment || ~commitment) =========== */

    unsigned char *inputs[3];
    for (int i = 0; i < 3; i++)
    {
        inputs[i] = calloc(64, 1);
        memcpy(inputs[i] + 32, shares[i], 32);
    }
    memcpy(inputs[0], message_digest, 32); // digest isn't secret so don´t need to be shared

    int *countY = calloc(1, sizeof(int));
    int *randCount = calloc(1, sizeof(int));
    unsigned char *results[3];
    results[0] = malloc(32);
    results[1] = malloc(32);
    results[2] = malloc(32);

    mpc_sha256(inputs, 64 * 8, randomness, results, views, countY, randCount);

    unsigned char final_digest[3][64];
    for (int i = 0; i < 3; i++)
    {
        memcpy(final_digest[i], results[i], 32);
        for (int j = 0; j < 32; j++)
        {
            results[i][j] = ~results[i][j];
        }
        memcpy(final_digest[i] + 32, results[i], 32);
    }

    /* =============================== Leaf extraction =============================== */

    uint32_t t0[3], t1[3], t2[3];
    uint32_t tmp1[8][3];
    uint32_t tmp2[8][3];
    uint32_t tmp[8][3];
    uint32_t MASK[3];
    unsigned char *sigma_i[3];
    sigma_i[0] = malloc(SHA256_DIGEST_LENGTH);
    sigma_i[1] = malloc(SHA256_DIGEST_LENGTH);
    sigma_i[2] = malloc(SHA256_DIGEST_LENGTH);
    int bit[3];
    unsigned char *giga_input[3];
    giga_input[0] = malloc(WOTS_len * SHA256_DIGEST_LENGTH);
    giga_input[1] = malloc(WOTS_len * SHA256_DIGEST_LENGTH);
    giga_input[2] = malloc(WOTS_len * SHA256_DIGEST_LENGTH);

    for (int i = 0; i < WOTS_len; i++)
    {
        // tmp1 = sigma_i & MASK
        for (int k = 0; k < 3; k++)
        {
            memcpy(sigma_i[k], shares[k] + sigma_index + i * SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
        }

        for (int k = 0; k < 3; k++)
        {
            bit[k] = (final_digest[k][i / 8] >> (7 - (i % 8))) & 1;
            MASK[k] = -bit[k];
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &sigma_i[k][j * 4], 4);
            }
            mpc_AND(t0, MASK, tmp1[j], randomness, randCount, views, countY);
        }

        // tmp2 = H(sigma_i) & ~MASK

        for (int k = 0; k < 3; k++)
        {
            MASK[k] = -(bit[k] ^ 1);
        }

        mpc_sha256(sigma_i, SHA256_DIGEST_LENGTH * 8, randomness, results, views, countY, randCount);

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], results[k] + j * 4, 4);
            }

            mpc_AND(t0, MASK, tmp2[j], randomness, randCount, views, countY);
        }

        // building giga_input
        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &tmp1[j][k], 4);
                memcpy(&t1[k], &tmp2[j][k], 4);
            }

            mpc_XOR(t0, t1, t2);

            for (int k = 0; k < 3; k++)
            {
                memcpy(giga_input[k] + i * 32 + j * 4, &t2[k], 4);
            }
        }
    }
    // Problem here
    // Computing the leaf
    mpc_sha256(giga_input, WOTS_len * SHA256_DIGEST_LENGTH * 8, randomness, results, views, countY, randCount);

    /* =============================== root compting =============================== */
    unsigned char *shared_index[3];
    for (int k = 0; k < 3; k++)
    {
        shared_index[k] = malloc(4);
        memcpy(shared_index[k], shares[k] + leaf_index_index, 4);
    }

    for (int i = 0; i < H; i++)
    {
        // left sibling
        for (int k = 0; k < 3; k++)
        {
            bit[k] = shared_index[k][3 - (i / 8)] >> (i % 8) & 1;
            MASK[k] = -(bit[k] ^ 1);
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], results[k] + j * 4, 4);
            }
            mpc_AND(t0, MASK, tmp1[j], randomness, randCount, views, countY);
        }

        for (int k = 0; k < 3; k++)
        {
            MASK[k] = -bit[k];
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], shares[k] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            }
            mpc_AND(t0, MASK, tmp2[j], randomness, randCount, views, countY);
        }

        for (int j = 0; j < 8; j++)
        {
            mpc_XOR(tmp1[j], tmp2[j], tmp[j]);
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(inputs[k] + 4 * j, &tmp[j][k], 4);
            }
        }

        // right sibling
        for (int k = 0; k < 3; k++)
        {
            bit[k] = shared_index[k][3 - (i / 8)] >> (i % 8) & 1;
            MASK[k] = -bit[k];
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], results[k] + j * 4, 4);
            }
            mpc_AND(t0, MASK, tmp1[j], randomness, randCount, views, countY);
        }

        for (int k = 0; k < 3; k++)
        {
            MASK[k] = -(bit[k] ^ 1);
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], shares[k] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            }
            mpc_AND(t0, MASK, tmp2[j], randomness, randCount, views, countY);
        }

        for (int j = 0; j < 8; j++)
        {
            mpc_XOR(tmp1[j], tmp2[j], tmp[j]);
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(inputs[k] + 32 + 4 * j, &tmp[j][k], 4);
            }
        }

        mpc_sha256(inputs, 64 * 8, randomness, results, views, countY, randCount);
    }

    for (int i = 0; i < 8; i++)
    {
        memcpy(&a->yp[0][i], results[0] + i * 4, 4);
        memcpy(&a->yp[1][i], results[1] + i * 4, 4);
        memcpy(&a->yp[2][i], results[2] + i * 4, 4);
    }

    // freeing memory
    for (int i = 0; i < 3; i++)
    {
        free(inputs[i]);
        free(results[i]);
        free(sigma_i[i]);
        free(giga_input[i]);
        free(shared_index[i]);
    }
    free(randCount);
    free(countY);

    return;
}

void verify(unsigned char message_digest[32], bool *error, a *a, int e, z *z)
{
    const int leaf_index_index = 32;
    const int sigma_index = 36;
    const int path_index = 36 + WOTS_len * SHA256_DIGEST_LENGTH;

    unsigned char hash[SHA256_DIGEST_LENGTH];

    H_com(z->ke, &z->ve, z->re, hash);
    if (memcmp(a->h[e], hash, 32) != 0)
    {
        *error = true;
        return;
    }

    H_com(z->ke1, &z->ve1, z->re1, hash);
    if (memcmp(a->h[(e + 1) % 3], hash, 32) != 0)
    {
        *error = true;
        return;
    }

    unsigned char *randomness[2];
    randomness[0] = malloc(Random_Bytes_Needed);
    randomness[1] = malloc(Random_Bytes_Needed);

    getAllRandomness(z->ke, randomness[0]);
    getAllRandomness(z->ke1, randomness[1]);

    int *randCount = calloc(1, sizeof(int));
    int *countY = calloc(1, sizeof(int));

    unsigned char *inputs[2];
    inputs[0] = calloc(64, 1);
    inputs[1] = calloc(64, 1);

    unsigned char *results[2];
    results[0] = malloc(32);
    results[1] = malloc(32);

    const unsigned char *vx[2];
    vx[0] = z->ve.x;
    vx[1] = z->ve1.x;

    int opened[2] = {e, (e + 1) % 3};

    for (int j = 0; j < 2; j++)
    {
        memcpy(inputs[j] + 32, vx[j], 32);
        if (opened[j] == 0)
            memcpy(inputs[j], message_digest, 32);
    }

    mpc_sha256_verify(inputs, 64 * 8, results, randCount, countY, randomness, z->ve, z->ve1);

    unsigned char final_digest[2][64];
    for (int j = 0; j < 2; j++)
    {
        memcpy(final_digest[j], results[j], 32);
        for (int i = 0; i < 32; i++)
            final_digest[j][32 + i] = ~results[j][i];
    }

    // WOTS leaf extraction
    uint32_t t0[2], t2[2];
    uint32_t tmp1[8][2];
    uint32_t tmp2[8][2];
    uint32_t tmp[8][2];
    uint32_t MASK[2];
    int bit[2];

    unsigned char *sigma_i[2];
    sigma_i[0] = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    sigma_i[1] = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);

    unsigned char *giga_input[2];
    giga_input[0] = (unsigned char *)malloc(WOTS_len * SHA256_DIGEST_LENGTH);
    giga_input[1] = (unsigned char *)malloc(WOTS_len * SHA256_DIGEST_LENGTH);

    for (int i = 0; i < WOTS_len; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            memcpy(sigma_i[j], vx[j] + sigma_index + i * SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
        }

        for (int j = 0; j < 2; j++)
        {
            bit[j] = (final_digest[j][i / 8] >> (7 - (i % 8))) & 1;
            MASK[j] = -bit[j];
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], sigma_i[0] + j * 4, 4);
            memcpy(&t0[1], sigma_i[1] + j * 4, 4);

            mpc_AND_verify(t0, MASK, tmp1[j], z->ve, z->ve1, randomness, randCount, countY);
        }

        for (int j = 0; j < 2; j++)
        {
            MASK[j] = -((bit[j]) ^ 1);
        }

        mpc_sha256_verify(sigma_i, SHA256_DIGEST_LENGTH * 8, results, randCount, countY, randomness, z->ve, z->ve1);

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], results[0] + j * 4, 4);
            memcpy(&t0[1], results[1] + j * 4, 4);
            mpc_AND_verify(t0, MASK, tmp2[j], z->ve, z->ve1, randomness, randCount, countY);
        }

        for (int j = 0; j < 8; j++)
        {
            mpc_XOR2(tmp1[j], tmp2[j], t2);
            memcpy(giga_input[0] + i * 32 + j * 4, &t2[0], 4);
            memcpy(giga_input[1] + i * 32 + j * 4, &t2[1], 4);
        }
    }

    mpc_sha256_verify(giga_input, WOTS_len * SHA256_DIGEST_LENGTH * 8, results, randCount, countY, randomness, z->ve,
                      z->ve1);

    // Path verification
    unsigned char shared_index[2][4];
    memcpy(shared_index[0], vx[0] + leaf_index_index, 4);
    memcpy(shared_index[1], vx[1] + leaf_index_index, 4);

    for (int i = 0; i < H; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            int b = (shared_index[j][3 - (i / 8)] >> (i % 8)) & 1;
            bit[j] = b;
            MASK[j] = -(b ^ 1);
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], results[0] + j * 4, 4);
            memcpy(&t0[1], results[1] + j * 4, 4);
            mpc_AND_verify(t0, MASK, tmp1[j], z->ve, z->ve1, randomness, randCount, countY);
        }

        for (int j = 0; j < 2; j++)
        {
            MASK[j] = -bit[j];
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], vx[0] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            memcpy(&t0[1], vx[1] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            mpc_AND_verify(t0, MASK, tmp2[j], z->ve, z->ve1, randomness, randCount, countY);
        }

        for (int j = 0; j < 8; j++)
        {
            mpc_XOR2(tmp1[j], tmp2[j], tmp[j]);
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(inputs[0] + 4 * j, &tmp[j][0], 4);
            memcpy(inputs[1] + 4 * j, &tmp[j][1], 4);
        }

        for (int j = 0; j < 2; j++)
        {
            int b = (shared_index[j][3 - (i / 8)] >> (i % 8)) & 1;
            bit[j] = b;
            MASK[j] = -b;
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], results[0] + j * 4, 4);
            memcpy(&t0[1], results[1] + j * 4, 4);
            mpc_AND_verify(t0, MASK, tmp1[j], z->ve, z->ve1, randomness, randCount, countY);
        }

        for (int j = 0; j < 2; j++)
        {
            MASK[j] = -(bit[j] ^ 1);
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], vx[0] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            memcpy(&t0[1], vx[1] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            mpc_AND_verify(t0, MASK, tmp2[j], z->ve, z->ve1, randomness, randCount, countY);
        }

        for (int j = 0; j < 8; j++)
        {
            mpc_XOR2(tmp1[j], tmp2[j], tmp[j]);
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(inputs[0] + 32 + 4 * j, &tmp[j][0], 4);
            memcpy(inputs[1] + 32 + 4 * j, &tmp[j][1], 4);
        }

        mpc_sha256_verify(inputs, 64 * 8, results, randCount, countY, randomness, z->ve, z->ve1);
    }

    // Verify announced outputs
    for (int i = 0; i < 8; i++)
    {
        uint32_t v0, v1;
        memcpy(&v0, results[0] + i * 4, 4);
        memcpy(&v1, results[1] + i * 4, 4);
        if (v0 != a->yp[e][i])
        {
            *error = true;
            return;
        }
        if (v1 != a->yp[(e + 1) % 3][i])
        {
            *error = true;
            return;
        }
    }

    // Free allocated memory
    for (int i = 0; i < 2; i++)
    {
        free(inputs[i]);
        free(results[i]);
        free(sigma_i[i]);
        free(giga_input[i]);
        free(randomness[i]);
    }
    free(randCount);
    free(countY);
}