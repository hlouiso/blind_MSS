#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{
    uint32_t r[2] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint32_t t = 0;

    t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
    if (ve.y[*countY] != t)
    {
        return 1;
    }
    z[0] = t;
    z[1] = ve1.y[*countY];

    (*countY)++;
    return 0;
}

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{
    uint32_t r[2] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint8_t a[2], b[2];

    uint8_t t;

    for (int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ ve.y[*countY], i);
        a[1] = GETBIT(x[1] ^ ve1.y[*countY], i);

        b[0] = GETBIT(y[0] ^ ve.y[*countY], i);
        b[1] = GETBIT(y[1] ^ ve1.y[*countY], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
        if (GETBIT(ve.y[*countY], i + 1) != (t ^ (a[0] & b[0]) ^ GETBIT(ve.y[*countY], i) ^ GETBIT(r[0], i)))
        {
            return 1;
        }
    }

    z[0] = x[0] ^ y[0] ^ ve.y[*countY];
    z[1] = x[1] ^ y[1] ^ ve1.y[*countY];
    (*countY)++;
    return 0;
}

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[])
{
    z[0] = RIGHTROTATE(x[0], i);
    z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2])
{
    z[0] = x[0] >> i;
    z[1] = x[1] >> i;
}

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{
    uint32_t t0[3];
    uint32_t t1[3];

    mpc_XOR2(a, b, t0);
    mpc_XOR2(a, c, t1);
    if (mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1)
    {
        return 1;
    }
    mpc_XOR2(z, a, z);
    return 0;
}

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1,
                  unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{

    uint32_t t0[3];
    mpc_XOR2(f, g, t0);
    if (mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1)
    {
        return 1;
    }
    mpc_XOR2(t0, g, z);

    return 0;
}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2])
{
    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2])
{
    z[0] = ~x[0];
    z[1] = ~x[1];
}

int mpc_sha256_verify(uint32_t w[64][2], unsigned char *results[2], int numBits, int *randCount, int *countY,
                      unsigned char randomness[2][Random_Bytes_Needed], z *z)
{
    int chars = numBits >> 3;
    chars = chars;

    for (int i = 0; i < 2; i++)
    {
        w[15][i] = numBits;
        w[chars / 4][i] = w[chars / 4][i] ^ (0x80 << (24 - (chars % 4) * 8));
    }

    uint32_t s0[2], s1[2];
    uint32_t t0[2], t1[2];
    for (int j = 16; j < 64; j++)
    {
        // s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
        mpc_RIGHTROTATE2(w[j - 15], 7, t0);
        mpc_RIGHTROTATE2(w[j - 15], 18, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTSHIFT2(w[j - 15], 3, t1);
        mpc_XOR2(t0, t1, s0);

        // s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
        mpc_RIGHTROTATE2(w[j - 2], 17, t0);
        mpc_RIGHTROTATE2(w[j - 2], 19, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTSHIFT2(w[j - 2], 10, t1);
        mpc_XOR2(t0, t1, s1);

        // w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

        if (mpc_ADD_verify(w[j - 16], s0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }

        if (mpc_ADD_verify(w[j - 7], t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }
        if (mpc_ADD_verify(t1, s1, w[j], z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }
    }

    uint32_t va[2] = {hA[0], hA[0]};
    uint32_t vb[2] = {hA[1], hA[1]};
    uint32_t vc[2] = {hA[2], hA[2]};
    uint32_t vd[2] = {hA[3], hA[3]};
    uint32_t ve[2] = {hA[4], hA[4]};
    uint32_t vf[2] = {hA[5], hA[5]};
    uint32_t vg[2] = {hA[6], hA[6]};
    uint32_t vh[2] = {hA[7], hA[7]};
    uint32_t temp1[3], temp2[3], maj[3];
    for (int i = 0; i < 64; i++)
    {
        // s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
        mpc_RIGHTROTATE2(ve, 6, t0);
        mpc_RIGHTROTATE2(ve, 11, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTROTATE2(ve, 25, t1);
        mpc_XOR2(t0, t1, s1);

        // ch = (e & f) ^ ((~e) & g);
        // temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

        // t0 = h + s1

        if (mpc_ADD_verify(vh, s1, t0, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        if (mpc_CH_verify(ve, vf, vg, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // t1 = t0 + t1 (h+s1+ch)
        if (mpc_ADD_verify(t0, t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        t0[0] = k[i];
        t0[1] = k[i];
        if (mpc_ADD_verify(t1, t0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        if (mpc_ADD_verify(t1, w[i], temp1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
        mpc_RIGHTROTATE2(va, 2, t0);
        mpc_RIGHTROTATE2(va, 13, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTROTATE2(va, 22, t1);
        mpc_XOR2(t0, t1, s0);

        // maj = (a & (b ^ c)) ^ (b & c);
        //(a & b) ^ (a & c) ^ (b & c)

        if (mpc_MAJ_verify(va, vb, vc, maj, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // temp2 = s0+maj;
        if (mpc_ADD_verify(s0, maj, temp2, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        memcpy(vh, vg, sizeof(uint32_t) * 2);
        memcpy(vg, vf, sizeof(uint32_t) * 2);
        memcpy(vf, ve, sizeof(uint32_t) * 2);
        // e = d+temp1;
        if (mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        memcpy(vd, vc, sizeof(uint32_t) * 2);
        memcpy(vc, vb, sizeof(uint32_t) * 2);
        memcpy(vb, va, sizeof(uint32_t) * 2);
        // a = temp1+temp2;

        if (mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }
    }

    uint32_t hHa[8][3] = {{hA[0], hA[0], hA[0]}, {hA[1], hA[1], hA[1]}, {hA[2], hA[2], hA[2]}, {hA[3], hA[3], hA[3]},
                          {hA[4], hA[4], hA[4]}, {hA[5], hA[5], hA[5]}, {hA[6], hA[6], hA[6]}, {hA[7], hA[7], hA[7]}};
    if (mpc_ADD_verify(hHa[0], va, hHa[0], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[1], vb, hHa[1], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[2], vc, hHa[2], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[3], vd, hHa[3], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[4], ve, hHa[4], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[5], vf, hHa[5], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[6], vg, hHa[6], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[7], vh, hHa[7], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }

    for (int i = 0; i < 8; i++)
    {
        mpc_RIGHTSHIFT2(hHa[i], 24, t0);
        results[0][i * 4] = t0[0];
        results[1][i * 4] = t0[1];
        mpc_RIGHTSHIFT2(hHa[i], 16, t0);
        results[0][i * 4 + 1] = t0[0];
        results[1][i * 4 + 1] = t0[1];
        mpc_RIGHTSHIFT2(hHa[i], 8, t0);
        results[0][i * 4 + 2] = t0[0];
        results[1][i * 4 + 2] = t0[1];

        results[0][i * 4 + 3] = hHa[i][0];
        results[1][i * 4 + 3] = hHa[i][1];
    }
    *countY += 8;

    return 0;
}

int mpc_sha256_extended_verify(unsigned char *inputs[2], int numBits, unsigned char *results[2], int *randCount,
                               int *countY, unsigned char randomness[2][Random_Bytes_Needed], View ve, View ve1)
{
    // Compute SHA-256 padding for an arbitrary bit-length message (numBits)
    const uint64_t bitlen64 = (uint64_t)((numBits < 0) ? 0 : numBits);
    const size_t fullBytes = (size_t)(bitlen64 >> 3);
    const int remBits = (int)(bitlen64 & 7);
    const size_t srcBytes = fullBytes + (remBits ? 1 : 0);
    const size_t bytesBeforeLen = fullBytes + 1; // +1 for the 0x80 bit (or partial 1-bit in the same byte)
    const size_t padZeroBytes = (size_t)((56 - (bytesBeforeLen % 64) + 64) % 64);
    const size_t totalLen = bytesBeforeLen + padZeroBytes + 8; // final 8 bytes store bit length (big endian)
    const size_t nBlocks = totalLen / 64;

    // Build padded messages for the two opened views
    unsigned char *padded[2] = {NULL, NULL};
    for (int i = 0; i < 2; i++)
    {
        padded[i] = (unsigned char *)calloc(totalLen, 1);
        if (!padded[i])
        {
            // Allocation failure -> reject
            return 1;
        }
        if (srcBytes)
            memcpy(padded[i], inputs[i], srcBytes);

        // Append the 1 bit
        if (remBits)
        {
            // Keep the existing remBits and append a single '1' bit immediately after
            padded[i][fullBytes] &= (unsigned char)(0xFFu << (8 - remBits));
            padded[i][fullBytes] |= (unsigned char)(0x80u >> remBits);
        }
        else
        {
            padded[i][fullBytes] = 0x80u;
        }

        // Append 64-bit big-endian length (in bits)
        uint64_t L = bitlen64;
        padded[i][totalLen - 1] = (unsigned char)(L & 0xFFu);
        padded[i][totalLen - 2] = (unsigned char)((L >> 8) & 0xFFu);
        padded[i][totalLen - 3] = (unsigned char)((L >> 16) & 0xFFu);
        padded[i][totalLen - 4] = (unsigned char)((L >> 24) & 0xFFu);
        padded[i][totalLen - 5] = (unsigned char)((L >> 32) & 0xFFu);
        padded[i][totalLen - 6] = (unsigned char)((L >> 40) & 0xFFu);
        padded[i][totalLen - 7] = (unsigned char)((L >> 48) & 0xFFu);
        padded[i][totalLen - 8] = (unsigned char)((L >> 56) & 0xFFu);
    }

    // Initial hash value H0..H7 (replicated for the two opened views)
    uint32_t H[8][2] = {{hA[0], hA[0]}, {hA[1], hA[1]}, {hA[2], hA[2]}, {hA[3], hA[3]},
                        {hA[4], hA[4]}, {hA[5], hA[5]}, {hA[6], hA[6]}, {hA[7], hA[7]}};

    // Working buffers
    uint32_t w[64][2];
    uint32_t a[2], b[2], c[2], d[2], e[2], f[2], g[2], h[2];
    uint32_t s0[2], s1[2], t0[2], t1[2], maj[2], temp1[2], temp2[2];

    for (size_t blk = 0; blk < nBlocks; blk++)
    {
        // Load message schedule w[0..15] from the padded message (big-endian bytes)
        for (int i = 0; i < 2; i++)
        {
            const unsigned char *base = padded[i] + blk * 64;
            for (int j = 0; j < 16; j++)
            {
                w[j][i] = ((uint32_t)base[j * 4 + 0] << 24) | ((uint32_t)base[j * 4 + 1] << 16) |
                          ((uint32_t)base[j * 4 + 2] << 8) | ((uint32_t)base[j * 4 + 3] << 0);
            }
        }

        // Expand the message schedule
        for (int j = 16; j < 64; j++)
        {
            mpc_RIGHTROTATE2(w[j - 15], 7, t0);
            mpc_RIGHTROTATE2(w[j - 15], 18, t1);
            mpc_XOR2(t0, t1, t0);
            mpc_RIGHTSHIFT2(w[j - 15], 3, t1);
            mpc_XOR2(t0, t1, s0);

            mpc_RIGHTROTATE2(w[j - 2], 17, t0);
            mpc_RIGHTROTATE2(w[j - 2], 19, t1);
            mpc_XOR2(t0, t1, t0);
            mpc_RIGHTSHIFT2(w[j - 2], 10, t1);
            mpc_XOR2(t0, t1, s1);

            if (mpc_ADD_verify(w[j - 16], s0, t1, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int i = 0; i < 2; i++)
                    free(padded[i]);
                return 1;
            }
            if (mpc_ADD_verify(w[j - 7], t1, t1, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int i = 0; i < 2; i++)
                    free(padded[i]);
                return 1;
            }
            if (mpc_ADD_verify(t1, s1, w[j], ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int i = 0; i < 2; i++)
                    free(padded[i]);
                return 1;
            }
        }

        // Initialize working variables from current hash value
        memcpy(a, H[0], sizeof(a));
        memcpy(b, H[1], sizeof(b));
        memcpy(c, H[2], sizeof(c));
        memcpy(d, H[3], sizeof(d));
        memcpy(e, H[4], sizeof(e));
        memcpy(f, H[5], sizeof(f));
        memcpy(g, H[6], sizeof(g));
        memcpy(h, H[7], sizeof(h));

        // Main compression loop
        for (int i = 0; i < 64; i++)
        {
            // Σ1(e)
            mpc_RIGHTROTATE2(e, 6, t0);
            mpc_RIGHTROTATE2(e, 11, t1);
            mpc_XOR2(t0, t1, t0);
            mpc_RIGHTROTATE2(e, 25, t1);
            mpc_XOR2(t0, t1, s1);

            // temp1 = h + Σ1(e)
            if (mpc_ADD_verify(h, s1, t0, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }

            // temp1 += Ch(e,f,g)
            if (mpc_CH_verify(e, f, g, t1, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }
            if (mpc_ADD_verify(t0, t1, t1, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }

            // temp1 += K[i]  (public constant injected as {k[i], k[i]} share)
            uint32_t Kpair[2] = {k[i], k[i]};
            if (mpc_ADD_verify(t1, Kpair, t1, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }

            // temp1 += w[i]
            if (mpc_ADD_verify(t1, w[i], temp1, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }

            // Σ0(a)
            mpc_RIGHTROTATE2(a, 2, t0);
            mpc_RIGHTROTATE2(a, 13, t1);
            mpc_XOR2(t0, t1, t0);
            mpc_RIGHTROTATE2(a, 22, t1);
            mpc_XOR2(t0, t1, s0);

            // temp2 = Σ0(a) + Maj(a,b,c)
            if (mpc_MAJ_verify(a, b, c, maj, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }
            if (mpc_ADD_verify(s0, maj, temp2, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }

            // Rotate the working variables
            memcpy(h, g, sizeof(uint32_t) * 2);
            memcpy(g, f, sizeof(uint32_t) * 2);
            memcpy(f, e, sizeof(uint32_t) * 2);
            if (mpc_ADD_verify(d, temp1, e, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }
            memcpy(d, c, sizeof(uint32_t) * 2);
            memcpy(c, b, sizeof(uint32_t) * 2);
            memcpy(b, a, sizeof(uint32_t) * 2);
            if (mpc_ADD_verify(temp1, temp2, a, ve, ve1, randomness, randCount, countY) == 1)
            {
                for (int ii = 0; ii < 2; ii++)
                    free(padded[ii]);
                return 1;
            }
        }

        // Add the compressed chunk to the current hash value
        if (mpc_ADD_verify(H[0], a, H[0], ve, ve1, randomness, randCount, countY) == 1 ||
            mpc_ADD_verify(H[1], b, H[1], ve, ve1, randomness, randCount, countY) == 1 ||
            mpc_ADD_verify(H[2], c, H[2], ve, ve1, randomness, randCount, countY) == 1 ||
            mpc_ADD_verify(H[3], d, H[3], ve, ve1, randomness, randCount, countY) == 1 ||
            mpc_ADD_verify(H[4], e, H[4], ve, ve1, randomness, randCount, countY) == 1 ||
            mpc_ADD_verify(H[5], f, H[5], ve, ve1, randomness, randCount, countY) == 1 ||
            mpc_ADD_verify(H[6], g, H[6], ve, ve1, randomness, randCount, countY) == 1 ||
            mpc_ADD_verify(H[7], h, H[7], ve, ve1, randomness, randCount, countY) == 1)
        {
            for (int ii = 0; ii < 2; ii++)
                free(padded[ii]);
            return 1;
        }
    }

    // Free temporary padded messages
    for (int i = 0; i < 2; i++)
        free(padded[i]);

    // Write the final digest into results[0] and results[1] as big-endian bytes
    for (int i = 0; i < 8; i++)
    {
        mpc_RIGHTSHIFT2(H[i], 24, t0);
        results[0][i * 4 + 0] = (unsigned char)t0[0];
        results[1][i * 4 + 0] = (unsigned char)t0[1];

        mpc_RIGHTSHIFT2(H[i], 16, t0);
        results[0][i * 4 + 1] = (unsigned char)t0[0];
        results[1][i * 4 + 1] = (unsigned char)t0[1];

        mpc_RIGHTSHIFT2(H[i], 8, t0);
        results[0][i * 4 + 2] = (unsigned char)t0[0];
        results[1][i * 4 + 2] = (unsigned char)t0[1];

        results[0][i * 4 + 3] = (unsigned char)H[i][0];
        results[1][i * 4 + 3] = (unsigned char)H[i][1];
    }

    return 0;
}
