#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void verify(unsigned char message_digest[32], bool *error, a *a, int e, z *z)
{
    const int leaf_index_index = 32;
    const int sigma_index = 36;
    const int path_index = 36 + WOTS_len * SHA256_DIGEST_LENGTH;

    unsigned char hash[SHA256_DIGEST_LENGTH];

    H_com(z->ke, &z->ve, &z->re, hash);
    if (memcmp(a->h[e], hash, 32) != 0)
    {
        printf("[DEBUG][round %d] Error: hash e\n", e);
        *error = true;
        return;
    }

    H_com(z->ke1, &z->ve1, &z->re1, hash);
    if (memcmp(a->h[(e + 1) % 3], hash, 32) != 0)
    {
        printf("[DEBUG][round %d] Error: hash e+1\n", e);
        *error = true;
        return;
    }

    unsigned char randomness[2][Random_Bytes_Needed];
    getAllRandomness(z->ke, randomness[0]);
    getAllRandomness(z->ke1, randomness[1]);

    int *randCount = calloc(1, sizeof(int));
    int *countY = calloc(1, sizeof(int));

    unsigned char *inputs[2];
    inputs[0] = (unsigned char *)calloc(64, 1);
    inputs[1] = (unsigned char *)calloc(64, 1);

    unsigned char *results[2];
    results[0] = (unsigned char *)malloc(32);
    results[1] = (unsigned char *)malloc(32);

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

    if (mpc_sha256_verify(inputs, 64 * 8, results, randCount, countY, randomness, z->ve, z->ve1) == 1)
    {
        printf("[DEBUG][round %d] Error: mpc_sha256_verify (inputs)\n", e);
        *error = true;
        return;
    }

    unsigned char final_digest[2][64];
    for (int j = 0; j < 2; j++)
    {
        memcpy(final_digest[j], results[j], 32);
        for (int i = 0; i < 32; i++)
            final_digest[j][32 + i] = ~results[j][i];
    }

    // WOTS leaf extraction
    uint32_t t0[2], t1[2], t2[2];
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

            if (mpc_AND_verify(t0, MASK, tmp1[j], z->ve, z->ve1, randomness, randCount, countY) == 1)
            {
                printf("[DEBUG][round %d] Error: mpc_AND_verify (tmp1, WOTS)\n", e);
                *error = true;
                return;
            }
        }

        for (int j = 0; j < 2; j++)
        {
            MASK[j] = -((bit[j]) ^ 1);
        }

        if (mpc_sha256_verify(sigma_i, SHA256_DIGEST_LENGTH * 8, results, randCount, countY, randomness, z->ve,
                              z->ve1) == 1)
        {
            printf("[DEBUG][round %d] Error: mpc_sha256_verify (sigma_i)\n", e);
            *error = true;
            return;
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], results[0] + j * 4, 4);
            memcpy(&t0[1], results[1] + j * 4, 4);
            if (mpc_AND_verify(t0, MASK, tmp2[j], z->ve, z->ve1, randomness, randCount, countY) == 1)
            {
                printf("[DEBUG][round %d] Error: mpc_AND_verify (tmp2, WOTS)\n", e);
                *error = true;
                return;
            }
        }

        for (int j = 0; j < 8; j++)
        {
            mpc_XOR2(tmp1[j], tmp2[j], t2);
            memcpy(giga_input[0] + i * 32 + j * 4, &t2[0], 4);
            memcpy(giga_input[1] + i * 32 + j * 4, &t2[1], 4);
        }
    }

    if (mpc_sha256_verify(giga_input, WOTS_len * SHA256_DIGEST_LENGTH * 8, results, randCount, countY, randomness,
                          z->ve, z->ve1) == 1)
    {
        printf("[DEBUG][round %d] Error: mpc_sha256_verify (giga_input)\n", e);
        *error = true;
        return;
    }

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
            if (mpc_AND_verify(t0, MASK, tmp1[j], z->ve, z->ve1, randomness, randCount, countY) == 1)
            {
                printf("[DEBUG][round %d] Error: mpc_AND_verify (tmp1, PATH)\n", e);
                *error = true;
                return;
            }
        }

        for (int j = 0; j < 2; j++)
        {
            MASK[j] = -bit[j];
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], vx[0] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            memcpy(&t0[1], vx[1] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            if (mpc_AND_verify(t0, MASK, tmp2[j], z->ve, z->ve1, randomness, randCount, countY) == 1)
            {
                printf("[DEBUG][round %d] Error: mpc_AND_verify (tmp2, PATH)\n", e);
                *error = true;
                return;
            }
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
            if (mpc_AND_verify(t0, MASK, tmp1[j], z->ve, z->ve1, randomness, randCount, countY) == 1)
                *error = true;
        }

        for (int j = 0; j < 2; j++)
        {
            MASK[j] = -(bit[j] ^ 1);
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], vx[0] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            memcpy(&t0[1], vx[1] + path_index + i * SHA256_DIGEST_LENGTH + j * 4, 4);
            if (mpc_AND_verify(t0, MASK, tmp2[j], z->ve, z->ve1, randomness, randCount, countY) == 1)
                *error = true;
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

        if (mpc_sha256_verify(inputs, 64 * 8, results, randCount, countY, randomness, z->ve, z->ve1) == 1)
        {
            printf("[DEBUG][round %d] Error: mpc_sha256_verify (inputs, PATH)\n", e);
            *error = true;
            return;
        }
    }

    // Verify announced outputs
    for (int i = 0; i < 8; i++)
    {
        uint32_t v0, v1;
        memcpy(&v0, results[0] + i * 4, 4);
        memcpy(&v1, results[1] + i * 4, 4);
        if (v0 != a->yp[e][i])
        {
            printf("[DEBUG][round %d] Error: yp[e][%d]\n", e, i);
            *error = true;
            return;
        }
        if (v1 != a->yp[(e + 1) % 3][i])
        {
            printf("[DEBUG][round %d] Error: yp[e+1][%d]\n", e, i);
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
    }
    free(randCount);
    free(countY);
}