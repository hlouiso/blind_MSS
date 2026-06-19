#include "gf128.h"

#include <string.h>

/* acc[0..7] ^= (word << pos); pos <= 223 so the carry never overflows acc[7]. */
void gf128_word_shift_xor(uint32_t acc[8], uint32_t word, int pos)
{
    int wq = pos >> 5;
    int wr = pos & 31;
    uint64_t v = (uint64_t)word << wr;
    acc[wq] ^= (uint32_t)v;
    if (wq + 1 < 8)
        acc[wq + 1] ^= (uint32_t)(v >> 32);
}

/* x^128 ≡ x^7 + x^2 + x + 1 (mod P).  Fold every set bit at position >= 128 down
 * into positions {pos-128} + {0,1,2,7}; a single downward pass suffices because
 * each fold lands strictly below the bit being cleared. */
void gf128_reduce(const uint32_t acc_in[8], uint32_t out[4])
{
    uint32_t acc[8];
    memcpy(acc, acc_in, sizeof acc);

    for (int i = 255; i >= 128; i--)
    {
        if ((acc[i >> 5] >> (i & 31)) & 1u)
        {
            acc[i >> 5] ^= (1u << (i & 31)); /* clear bit i */
            int t = i - 128;
            acc[(t + 7) >> 5] ^= (1u << ((t + 7) & 31));
            acc[(t + 2) >> 5] ^= (1u << ((t + 2) & 31));
            acc[(t + 1) >> 5] ^= (1u << ((t + 1) & 31));
            acc[(t + 0) >> 5] ^= (1u << ((t + 0) & 31));
        }
    }

    out[0] = acc[0];
    out[1] = acc[1];
    out[2] = acc[2];
    out[3] = acc[3];
}

void gf128_mul_words(const uint32_t X[4], const uint32_t Y[4], uint32_t out[4])
{
    uint32_t acc[8] = {0};
    for (int j = 0; j < 128; j++)
    {
        if ((Y[j >> 5] >> (j & 31)) & 1u)
        {
            /* acc ^= X << j */
            for (int w = 0; w < 4; w++)
                gf128_word_shift_xor(acc, X[w], 32 * w + j);
        }
    }
    gf128_reduce(acc, out);
}

void gf128_load(uint32_t w[4], const uint8_t b[16])
{
    for (int i = 0; i < 4; i++)
        w[i] = (uint32_t)b[4 * i] | ((uint32_t)b[4 * i + 1] << 8) | ((uint32_t)b[4 * i + 2] << 16) |
               ((uint32_t)b[4 * i + 3] << 24);
}

void gf128_store(uint8_t b[16], const uint32_t w[4])
{
    for (int i = 0; i < 4; i++)
    {
        b[4 * i] = (uint8_t)(w[i]);
        b[4 * i + 1] = (uint8_t)(w[i] >> 8);
        b[4 * i + 2] = (uint8_t)(w[i] >> 16);
        b[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
}

void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t z[16])
{
    uint32_t X[4], Y[4], Z[4];
    gf128_load(X, x);
    gf128_load(Y, y);
    gf128_mul_words(X, Y, Z);
    gf128_store(z, Z);
}
