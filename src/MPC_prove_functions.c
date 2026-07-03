#include "MPC_prove_functions.h"
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

/* ── ADD with public constant ───────────────────────────────────────────── */

void mpc_ADDK(const mw *x, uint32_t K, mw *z,
              unsigned char *tapes[N_PARTIES], uint32_t *aux,
              uint32_t *s_all, int *gateCount)
{
    mw kw;
    mw_const(K, &kw);
    mpc_ADD(x, &kw, z, tapes, aux, s_all, gateCount);
}

/* ── SHA-256 derived gates ──────────────────────────────────────────────── */

void mpc_MAJ(const mw *a, const mw *b, const mw *c, mw *z,
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *s_all, int *gateCount)
{
    /* MAJ(a,b,c) = (a XOR b) AND (a XOR c) XOR a */
    mw t0, t1;
    mpc_XOR(a, b, &t0);
    mpc_XOR(a, c, &t1);
    mpc_AND(&t0, &t1, z, tapes, aux, s_all, gateCount);
    mpc_XOR(z, a, z);
}

void mpc_CH(const mw *e, const mw *f, const mw *g, mw *z,
            unsigned char *tapes[N_PARTIES], uint32_t *aux,
            uint32_t *s_all, int *gateCount)
{
    /* CH(e,f,g) = (e AND (f XOR g)) XOR g */
    mw t;
    mpc_XOR(f, g, &t);
    mpc_AND(e, &t, &t, tapes, aux, s_all, gateCount);
    mpc_XOR(&t, g, z);
}

/* ── N-party SHA-256 ────────────────────────────────────────────────────── */

void mpc_sha256(const unsigned char *in_pub, unsigned char *in_lam[N_PARTIES],
                int numBits,
                unsigned char *out_pub, unsigned char *out_lam[N_PARTIES],
                unsigned char *tapes[N_PARTIES],
                uint32_t *aux, uint32_t *s_all, int *gateCount)
{
    const uint64_t bitlen64 = (uint64_t)((numBits < 0) ? 0 : numBits);
    const size_t fullBytes = (size_t)(bitlen64 >> 3);
    const int remBits = (int)(bitlen64 & 7);
    const size_t srcBytes = fullBytes + (remBits ? 1 : 0);
    const size_t bytesBeforeLen = fullBytes + 1;
    const size_t padZeroBytes = (size_t)((56 - (int)(bytesBeforeLen % 64) + 64) % 64);
    const size_t totalLen = bytesBeforeLen + padZeroBytes + 8;
    const size_t nBlocks = totalLen / 64;

    /* Padding is public: it lives in the public buffer, masks stay zero. */
    unsigned char *pad_pub = calloc(totalLen, 1);
    unsigned char *pad_lam[N_PARTIES];
    for (int i = 0; i < N_PARTIES; i++) pad_lam[i] = NULL;
    bool ok = (pad_pub != NULL);
    for (int i = 0; i < N_PARTIES && ok; i++) {
        pad_lam[i] = calloc(totalLen, 1);
        if (!pad_lam[i]) ok = false;
    }
    if (!ok) {
        free(pad_pub);
        for (int i = 0; i < N_PARTIES; i++) free(pad_lam[i]);
        return;
    }
    if (srcBytes) memcpy(pad_pub, in_pub, srcBytes);
    for (int i = 0; i < N_PARTIES; i++)
        if (srcBytes) memcpy(pad_lam[i], in_lam[i], srcBytes);
    if (remBits) {
        unsigned char m = (unsigned char)(0xFFu << (8 - remBits));
        pad_pub[fullBytes] = (unsigned char)((pad_pub[fullBytes] & m) | (0x80u >> remBits));
        for (int i = 0; i < N_PARTIES; i++) pad_lam[i][fullBytes] &= m;
    } else {
        pad_pub[fullBytes] = 0x80u;
    }
    for (int b = 0; b < 8; b++)
        pad_pub[totalLen - 1 - b] = (unsigned char)((bitlen64 >> (8*b)) & 0xFF);

    mw H[8];
    for (int j = 0; j < 8; j++) mw_const(hA[j], &H[j]); /* IV is public */

    mw w[64];
    mw A, B, C, D, E, F, G, Hv;
    mw s0, s1, t0, t1, maj, temp1, temp2;

    for (size_t blk = 0; blk < nBlocks; blk++) {
        for (int j = 0; j < 16; j++) {
            const unsigned char *bp = pad_pub + blk * 64 + (size_t)j * 4;
            w[j].h = ((uint32_t)bp[0] << 24) | ((uint32_t)bp[1] << 16) |
                     ((uint32_t)bp[2] <<  8) | ((uint32_t)bp[3]);
            for (int i = 0; i < N_PARTIES; i++) {
                const unsigned char *bl = pad_lam[i] + blk * 64 + (size_t)j * 4;
                w[j].l[i] = ((uint32_t)bl[0] << 24) | ((uint32_t)bl[1] << 16) |
                            ((uint32_t)bl[2] <<  8) | ((uint32_t)bl[3]);
            }
        }

        for (int j = 16; j < 64; j++) {
            mpc_RIGHTROTATE(&w[j-15], 7,  &t0);
            mpc_RIGHTROTATE(&w[j-15], 18, &t1); mpc_XOR(&t0, &t1, &t0);
            mpc_RIGHTSHIFT( &w[j-15], 3,  &t1); mpc_XOR(&t0, &t1, &s0);

            mpc_RIGHTROTATE(&w[j-2], 17, &t0);
            mpc_RIGHTROTATE(&w[j-2], 19, &t1); mpc_XOR(&t0, &t1, &t0);
            mpc_RIGHTSHIFT( &w[j-2], 10, &t1); mpc_XOR(&t0, &t1, &s1);

            mpc_ADD(&w[j-16], &s0,  &t1,  tapes, aux, s_all, gateCount);
            mpc_ADD(&w[j-7],  &t1,  &t1,  tapes, aux, s_all, gateCount);
            mpc_ADD(&t1,      &s1,  &w[j], tapes, aux, s_all, gateCount);
        }

        A = H[0]; B = H[1]; C = H[2]; D = H[3];
        E = H[4]; F = H[5]; G = H[6]; Hv = H[7];

        for (int j = 0; j < 64; j++) {
            mpc_RIGHTROTATE(&E, 6,  &t0);
            mpc_RIGHTROTATE(&E, 11, &t1); mpc_XOR(&t0, &t1, &t0);
            mpc_RIGHTROTATE(&E, 25, &t1); mpc_XOR(&t0, &t1, &s1);

            mpc_ADD(&Hv, &s1, &t0, tapes, aux, s_all, gateCount);
            mpc_CH(&E, &F, &G, &t1, tapes, aux, s_all, gateCount);
            mpc_ADD(&t0, &t1, &t1, tapes, aux, s_all, gateCount);
            mpc_ADDK(&t1, k[j], &t1, tapes, aux, s_all, gateCount);
            mpc_ADD(&t1, &w[j], &temp1, tapes, aux, s_all, gateCount);

            mpc_RIGHTROTATE(&A, 2,  &t0);
            mpc_RIGHTROTATE(&A, 13, &t1); mpc_XOR(&t0, &t1, &t0);
            mpc_RIGHTROTATE(&A, 22, &t1); mpc_XOR(&t0, &t1, &s0);

            mpc_MAJ(&A, &B, &C, &maj, tapes, aux, s_all, gateCount);
            mpc_ADD(&s0, &maj, &temp2, tapes, aux, s_all, gateCount);

            Hv = G; G = F; F = E;
            mpc_ADD(&D, &temp1, &E, tapes, aux, s_all, gateCount);
            D = C; C = B; B = A;
            mpc_ADD(&temp1, &temp2, &A, tapes, aux, s_all, gateCount);
        }

        mw tmp;
        mpc_ADD(&H[0], &A,  &tmp, tapes, aux, s_all, gateCount); H[0] = tmp;
        mpc_ADD(&H[1], &B,  &tmp, tapes, aux, s_all, gateCount); H[1] = tmp;
        mpc_ADD(&H[2], &C,  &tmp, tapes, aux, s_all, gateCount); H[2] = tmp;
        mpc_ADD(&H[3], &D,  &tmp, tapes, aux, s_all, gateCount); H[3] = tmp;
        mpc_ADD(&H[4], &E,  &tmp, tapes, aux, s_all, gateCount); H[4] = tmp;
        mpc_ADD(&H[5], &F,  &tmp, tapes, aux, s_all, gateCount); H[5] = tmp;
        mpc_ADD(&H[6], &G,  &tmp, tapes, aux, s_all, gateCount); H[6] = tmp;
        mpc_ADD(&H[7], &Hv, &tmp, tapes, aux, s_all, gateCount); H[7] = tmp;
    }

    free(pad_pub);
    for (int i = 0; i < N_PARTIES; i++) free(pad_lam[i]);

    /* Pack outputs big-endian: public digest and per-party mask shares. */
    for (int j = 0; j < 8; j++) {
        out_pub[j*4+0] = (unsigned char)(H[j].h >> 24);
        out_pub[j*4+1] = (unsigned char)(H[j].h >> 16);
        out_pub[j*4+2] = (unsigned char)(H[j].h >>  8);
        out_pub[j*4+3] = (unsigned char)(H[j].h);
        for (int i = 0; i < N_PARTIES; i++) {
            out_lam[i][j*4+0] = (unsigned char)(H[j].l[i] >> 24);
            out_lam[i][j*4+1] = (unsigned char)(H[j].l[i] >> 16);
            out_lam[i][j*4+2] = (unsigned char)(H[j].l[i] >>  8);
            out_lam[i][j*4+3] = (unsigned char)(H[j].l[i]);
        }
    }
}
