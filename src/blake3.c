#include "blake3.h"

#include <string.h>

/* BLAKE3 IV (= the SHA-256 IV, by design of BLAKE). */
static const uint32_t B3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/* schedule_{r+1}[i] = schedule_r[MSG_PERMUTATION[i]], schedule_0 = identity. */
static const uint8_t MSG_PERMUTATION[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline void g(uint32_t v[16], int a, int b, int c, int d,
                     uint32_t x, uint32_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 7);
}

void blake3_compress(const uint32_t cv[8], const uint32_t block_words[16],
                     uint64_t counter, uint32_t block_len, uint32_t flags,
                     uint32_t out[8])
{
    uint32_t v[16];
    uint8_t s[16], t[16];
    for (int i = 0; i < 8; i++) v[i] = cv[i];
    v[8]  = B3_IV[0]; v[9]  = B3_IV[1]; v[10] = B3_IV[2]; v[11] = B3_IV[3];
    v[12] = (uint32_t)counter;
    v[13] = (uint32_t)(counter >> 32);
    v[14] = block_len;
    v[15] = flags;

    for (int i = 0; i < 16; i++) s[i] = (uint8_t)i;
    for (int r = 0; r < 7; r++) {
        const uint32_t *m = block_words;
        g(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
        g(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
        g(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
        g(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
        g(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        g(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
        for (int i = 0; i < 16; i++) t[i] = s[MSG_PERMUTATION[i]];
        memcpy(s, t, 16);
    }

    for (int i = 0; i < 8; i++) out[i] = v[i] ^ v[i + 8];
}

static void load_words_le(const uint8_t *bytes, size_t len, uint32_t *w, int nwords)
{
    for (int i = 0; i < nwords; i++) {
        uint32_t v = 0;
        for (int b = 3; b >= 0; b--) {
            size_t idx = (size_t)i * 4 + (size_t)b;
            v = (v << 8) | (idx < len ? bytes[idx] : 0);
        }
        w[i] = v;
    }
}

void blake3_th(const uint8_t *domain, size_t domain_len,
               const uint8_t *data, size_t data_len,
               uint8_t *out, size_t out_len)
{
    if (domain_len > 28) { memset(out, 0, out_len); return; }
    uint32_t cv[8];
    load_words_le(domain, domain_len, cv, 8);
    cv[7] = (uint32_t)domain_len;   /* binds the domain length (see blake3.h) */

    size_t nblocks = data_len ? (data_len + 63) / 64 : 1;
    for (size_t b = 0; b < nblocks; b++) {
        size_t off = b * 64;
        size_t blen = (data_len - off > 64) ? 64 : data_len - off;
        uint32_t m[16];
        load_words_le(data ? data + off : NULL, data ? blen : 0, m, 16);
        blake3_compress(cv, m, 0, (uint32_t)blen,
                        (b + 1 == nblocks) ? BLAKE3_ROOT : 0, cv);
    }

    uint8_t full[32];
    for (int i = 0; i < 8; i++) {
        full[i*4+0] = (uint8_t)(cv[i]);
        full[i*4+1] = (uint8_t)(cv[i] >> 8);
        full[i*4+2] = (uint8_t)(cv[i] >> 16);
        full[i*4+3] = (uint8_t)(cv[i] >> 24);
    }
    memcpy(out, full, out_len);
}
