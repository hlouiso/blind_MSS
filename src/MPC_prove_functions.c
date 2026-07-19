#include "MPC_prove_functions.h"
#include "blake3_th.h"
#include "shared.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Word-level masked AND ──────────────────────────────────────────────── */

void mpc_AND(const mw *x, const mw *y, mw *z,
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *s_all, int *gateCount)
{
    int g = *gateCount;

    uint32_t lz[N_PARTIES], t[N_PARTIES];
    uint32_t lx = 0, ly = 0, t_xor = 0;
    for (int i = 0; i < N_PARTIES; i++) {
        lz[i] = tape_lam(tapes[i], g);
        t[i]  = tape_prod(tapes[i], g);
        lx ^= x->l[i]; ly ^= y->l[i]; t_xor ^= t[i];
    }
    /* Correction for party 0: makes XOR of the t_i equal λ_x AND λ_y. */
    const uint32_t corr = (lx & ly) ^ t_xor;
    aux[g] = corr;

    /* s_i = x̂·λ_y,i ⊕ ŷ·λ_x,i ⊕ t_i ⊕ λ_z,i  (party 0 adds x̂ŷ and corr);
     * XOR of all broadcasts = (x AND y) ⊕ λ_z = ẑ. */
    const uint32_t xh = x->h, yh = y->h;
    uint32_t zh = 0;
    for (int i = 0; i < N_PARTIES; i++) {
        uint32_t s = (xh & y->l[i]) ^ (yh & x->l[i]) ^ t[i] ^ lz[i];
        if (i == 0) s ^= (xh & yh) ^ corr;
        if (s_all) s_all[(size_t)i * ySize + (size_t)g] = s;
        zh ^= s;
        z->l[i] = lz[i];
    }
    z->h = zh;
    (*gateCount)++;
}

/* ── 32-bit masked ADD ──────────────────────────────────────────────────── */
/* One gate slot: bit b of the tape words is the Beaver material for carry
 * bit b.  Fully word-parallel on the prover: it knows the masks, so the real
 * carry word is (x+y)^x^y and every per-party quantity is a whole-word
 * expression; carry masks are the shifted prefix-XOR of the fresh λ_r. */

static inline uint32_t prefix_xor_shift(uint32_t v)
{
    v ^= v << 1; v ^= v << 2; v ^= v << 4; v ^= v << 8; v ^= v << 16;
    return v << 1;
}

void mpc_ADD(const mw *x, const mw *y, mw *z,
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *s_all, int *gateCount)
{
    int g = *gateCount;

    uint32_t lr[N_PARTIES], t[N_PARTIES], lc[N_PARTIES];
    uint32_t lx = 0, ly = 0, t_xor = 0, lc_xor = 0;
    for (int i = 0; i < N_PARTIES; i++) {
        lr[i] = tape_lam(tapes[i], g);
        t[i]  = tape_prod(tapes[i], g);
        lc[i] = prefix_xor_shift(lr[i]);  /* share of the carry-wire mask */
        lx ^= x->l[i]; ly ^= y->l[i]; t_xor ^= t[i]; lc_xor ^= lc[i];
    }

    /* Real operands and carries (prover-only shortcut). */
    const uint32_t xv = x->h ^ lx, yv = y->h ^ ly;
    const uint32_t c  = (xv + yv) ^ xv ^ yv;   /* real carry word */
    const uint32_t ch = c ^ lc_xor;            /* ĉ (public) */
    const uint32_t ph = x->h ^ ch, qh = y->h ^ ch; /* p̂ = x̂⊕ĉ, q̂ = ŷ⊕ĉ */

    /* aux corrects the product shares against λ_p = λ_x⊕λ_c, λ_q = λ_y⊕λ_c.
     * Only carry bits 0..30 exist; clear bit 31 for a canonical value. */
    const uint32_t corr = (((lx ^ lc_xor) & (ly ^ lc_xor)) ^ t_xor) & 0x7FFFFFFFu;
    aux[g] = corr;

    for (int i = 0; i < N_PARTIES; i++) {
        uint32_t lpi = x->l[i] ^ lc[i];
        uint32_t lqi = y->l[i] ^ lc[i];
        uint32_t s = (ph & lqi) ^ (qh & lpi) ^ t[i] ^ lr[i];
        if (i == 0) s ^= (ph & qh) ^ corr;
        if (s_all) s_all[(size_t)i * ySize + (size_t)g] = s;
        z->l[i] = x->l[i] ^ y->l[i] ^ lc[i];   /* λ_z share */
    }
    z->h = x->h ^ y->h ^ ch;                   /* ẑ = x̂⊕ŷ⊕ĉ */
    (*gateCount)++;
}

/* ── N-party BLAKE3 compression / tweakable hash ────────────────────────── */

/* v[8..11] of the compression state (= first half of the BLAKE3 IV). */
static const uint32_t B3_IV4[4] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A};
/* schedule_{r+1}[i] = schedule_r[B3_PERM[i]], schedule_0 = identity. */
static const uint8_t B3_PERM[16] = {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};

/* G function: 6 ADD gates; the rotations/XORs are linear (free). */
static void b3_g(mw v[16], int a, int b, int c, int d, const mw *x, const mw *y,
                 unsigned char *tapes[N_PARTIES], uint32_t *aux,
                 uint32_t *s_all, int *gc)
{
    mw t;
    mpc_ADD(&v[a], &v[b], &t, tapes, aux, s_all, gc);
    mpc_ADD(&t, x, &v[a], tapes, aux, s_all, gc);
    mpc_XOR(&v[d], &v[a], &t); mpc_RIGHTROTATE(&t, 16, &v[d]);
    mpc_ADD(&v[c], &v[d], &v[c], tapes, aux, s_all, gc);
    mpc_XOR(&v[b], &v[c], &t); mpc_RIGHTROTATE(&t, 12, &v[b]);
    mpc_ADD(&v[a], &v[b], &t, tapes, aux, s_all, gc);
    mpc_ADD(&t, y, &v[a], tapes, aux, s_all, gc);
    mpc_XOR(&v[d], &v[a], &t); mpc_RIGHTROTATE(&t, 8, &v[d]);
    mpc_ADD(&v[c], &v[d], &v[c], tapes, aux, s_all, gc);
    mpc_XOR(&v[b], &v[c], &t); mpc_RIGHTROTATE(&t, 7, &v[b]);
}

void mpc_blake3_compress(const mw cv[8], const mw m[16], uint32_t block_len,
                         uint32_t flags, mw out[8],
                         unsigned char *tapes[N_PARTIES], uint32_t *aux,
                         uint32_t *s_all, int *gateCount)
{
    mw v[16];
    for (int i = 0; i < 8; i++) v[i] = cv[i];
    for (int i = 0; i < 4; i++) mw_const(B3_IV4[i], &v[8 + i]);
    mw_const(0, &v[12]);          /* counter = 0 in Th usage */
    mw_const(0, &v[13]);
    mw_const(block_len, &v[14]);
    mw_const(flags, &v[15]);      /* public constant (ROOT on final block) */

    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = (uint8_t)i;
    for (int r = 0; r < 7; r++) {
        b3_g(v, 0, 4,  8, 12, &m[s[0]],  &m[s[1]],  tapes, aux, s_all, gateCount);
        b3_g(v, 1, 5,  9, 13, &m[s[2]],  &m[s[3]],  tapes, aux, s_all, gateCount);
        b3_g(v, 2, 6, 10, 14, &m[s[4]],  &m[s[5]],  tapes, aux, s_all, gateCount);
        b3_g(v, 3, 7, 11, 15, &m[s[6]],  &m[s[7]],  tapes, aux, s_all, gateCount);
        b3_g(v, 0, 5, 10, 15, &m[s[8]],  &m[s[9]],  tapes, aux, s_all, gateCount);
        b3_g(v, 1, 6, 11, 12, &m[s[10]], &m[s[11]], tapes, aux, s_all, gateCount);
        b3_g(v, 2, 7,  8, 13, &m[s[12]], &m[s[13]], tapes, aux, s_all, gateCount);
        b3_g(v, 3, 4,  9, 14, &m[s[14]], &m[s[15]], tapes, aux, s_all, gateCount);
        for (int i = 0; i < 16; i++) t[i] = s[B3_PERM[i]];
        memcpy(s, t, 16);
    }

    for (int i = 0; i < 8; i++) mpc_XOR(&v[i], &v[i + 8], &out[i]);
}

/* Little-endian word from a byte buffer; bytes past len (or a NULL buffer)
 * read as zero — this implements the Th zero-padding. */
static inline uint32_t b3_le_word(const unsigned char *buf, int len, int off)
{
    uint32_t v = 0;
    for (int b = 3; b >= 0; b--) {
        int i = off + b;
        v = (v << 8) | (uint32_t)((buf && i < len) ? buf[i] : 0);
    }
    return v;
}

void mpc_blake3_th(const unsigned char *dom_pub, unsigned char *dom_lam[N_PARTIES],
                   int dom_len,
                   const unsigned char *data_pub, unsigned char *data_lam[N_PARTIES],
                   int data_len,
                   unsigned char *out_pub, unsigned char *out_lam[N_PARTIES],
                   int out_len,
                   unsigned char *tapes[N_PARTIES], uint32_t *aux,
                   uint32_t *s_all, int *gateCount)
{
    /* cv <- domain, zero-padded to 32 bytes; cv[7] binds dom_len (<= 28,
     * so word 7 of the loaded domain is always zero — see blake3_th.h). */
    mw cv[8];
    for (int w = 0; w < 8; w++) {
        cv[w].h = b3_le_word(dom_pub, dom_len, w * 4);
        for (int p = 0; p < N_PARTIES; p++)
            cv[w].l[p] = b3_le_word(dom_lam ? dom_lam[p] : NULL, dom_len, w * 4);
    }
    cv[7].h = (uint32_t)dom_len;

    int nblocks = data_len ? (data_len + 63) / 64 : 1;
    for (int b = 0; b < nblocks; b++) {
        int off  = b * 64;
        int blen = (data_len - off > 64) ? 64 : data_len - off;
        mw m[16];
        for (int w = 0; w < 16; w++) {
            m[w].h = b3_le_word(data_pub, data_len, off + w * 4);
            for (int p = 0; p < N_PARTIES; p++)
                m[w].l[p] = b3_le_word(data_lam ? data_lam[p] : NULL,
                                       data_len, off + w * 4);
        }
        mpc_blake3_compress(cv, m, (uint32_t)blen,
                            (b + 1 == nblocks) ? BLAKE3_ROOT : 0,
                            cv, tapes, aux, s_all, gateCount);
    }

    for (int i = 0; i < out_len; i++) {
        out_pub[i] = (unsigned char)(cv[i / 4].h >> (8 * (i % 4)));
        for (int p = 0; p < N_PARTIES; p++)
            out_lam[p][i] = (unsigned char)(cv[i / 4].l[p] >> (8 * (i % 4)));
    }
}
