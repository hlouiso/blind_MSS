#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Map slot index j and hidden party e to original party index. */
static inline int orig(int j, int e) { return (j < e) ? j : j + 1; }

/* ── Word-level masked AND (verify) ─────────────────────────────────────── */

void mpc_AND_verify(const mwv *x, const mwv *y, mwv *z,
                    unsigned char *tapes[N_PARTIES - 1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *s_slots, int *gateCount)
{
    int g = *gateCount;

    const uint32_t xh = x->h, yh = y->h;
    /* ẑ = hidden party's broadcast XOR the revealed slots' broadcasts. */
    uint32_t zh = msgs_e[g];
    for (int j = 0; j < N_PARTIES - 1; j++) {
        uint32_t lz = tape_lam(tapes[j], g);
        uint32_t t  = tape_prod(tapes[j], g);
        uint32_t s = (xh & y->l[j]) ^ (yh & x->l[j]) ^ t ^ lz;
        if (orig(j, e) == 0) s ^= (xh & yh) ^ aux[g];
        s_slots[(size_t)j * ySize + (size_t)g] = s;
        zh ^= s;
        z->l[j] = lz;
    }
    z->h = zh;
    (*gateCount)++;
}

/* ── 32-bit masked ADD (verify) ─────────────────────────────────────────── */
/* The verifier lacks the hidden party, so the public carry word ĉ is rebuilt
 * with a 31-step scalar recurrence on the revealed parity words plus the
 * hidden party's broadcast bits; the per-slot work is then word-parallel and
 * must match the prover's s formula bit for bit (h' equality). */

static inline uint32_t prefix_xor_shift(uint32_t v)
{
    v ^= v << 1; v ^= v << 2; v ^= v << 4; v ^= v << 8; v ^= v << 16;
    return v << 1;
}

void mpc_ADD_verify(const mwv *x, const mwv *y, mwv *z,
                    unsigned char *tapes[N_PARTIES - 1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *s_slots, int *gateCount)
{
    int g = *gateCount;

    uint32_t lr[N_PARTIES - 1], t[N_PARTIES - 1], lc[N_PARTIES - 1];
    uint32_t lp[N_PARTIES - 1], lq[N_PARTIES - 1];
    uint32_t Plp = 0, Plq = 0, Pt = 0, Plr = 0;
    for (int j = 0; j < N_PARTIES - 1; j++) {
        lr[j] = tape_lam(tapes[j], g);
        t[j]  = tape_prod(tapes[j], g);
        lc[j] = prefix_xor_shift(lr[j]);
        lp[j] = x->l[j] ^ lc[j];
        lq[j] = y->l[j] ^ lc[j];
        Plp ^= lp[j]; Plq ^= lq[j]; Pt ^= t[j]; Plr ^= lr[j];
    }
    const uint32_t corr = aux[g];
    const uint32_t me   = msgs_e[g];
    const uint32_t has0 = (uint32_t)(e != 0);
    const uint32_t xh = x->h, yh = y->h;

    /* Rebuild ĉ bit by bit: ĉ_{b+1} = ĉ_b ^ r̂_b, where r̂_b combines the
     * hidden party's broadcast bit with the revealed slots' parity. */
    uint32_t ch = 0;
    for (int b = 0; b < 31; b++) {
        uint32_t pb = ((xh ^ ch) >> b) & 1;
        uint32_t qb = ((yh ^ ch) >> b) & 1;
        uint32_t srev = (pb & ((Plq >> b) & 1))
                      ^ (qb & ((Plp >> b) & 1))
                      ^ ((Pt >> b) & 1)
                      ^ ((Plr >> b) & 1)
                      ^ (has0 & ((pb & qb) ^ ((corr >> b) & 1)));
        uint32_t rb = ((me >> b) & 1) ^ srev;
        ch |= (((ch >> b) & 1) ^ rb) << (b + 1);
    }

    /* Word-parallel per-slot broadcasts — same formula as the prover. */
    const uint32_t ph = xh ^ ch, qh = yh ^ ch;
    for (int j = 0; j < N_PARTIES - 1; j++) {
        uint32_t s = (ph & lq[j]) ^ (qh & lp[j]) ^ t[j] ^ lr[j];
        if (orig(j, e) == 0) s ^= (ph & qh) ^ corr;
        s_slots[(size_t)j * ySize + (size_t)g] = s;
        z->l[j] = x->l[j] ^ y->l[j] ^ lc[j];
    }
    z->h = xh ^ yh ^ ch;
    (*gateCount)++;
}

/* ── ADD with public constant (verify) ──────────────────────────────────── */

void mpc_ADDK_verify(const mwv *x, uint32_t K, mwv *z,
                     unsigned char *tapes[N_PARTIES - 1], int e,
                     const uint32_t *msgs_e, const uint32_t *aux,
                     uint32_t *s_slots, int *gateCount)
{
    mwv kw;
    mwv_const(K, &kw);
    mpc_ADD_verify(x, &kw, z, tapes, e, msgs_e, aux, s_slots, gateCount);
}

/* ── N-1 party BLAKE3 compression / tweakable hash (verify) ─────────────── */

static const uint32_t B3_IV4[4] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A};
static const uint8_t B3_PERM[16] = {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};

static void b3_g_v(mwv v[16], int a, int b, int c, int d,
                   const mwv *x, const mwv *y,
                   unsigned char *tapes[N_PARTIES-1], int e,
                   const uint32_t *msgs_e, const uint32_t *aux,
                   uint32_t *s_slots, int *gc)
{
    mwv t;
    mpc_ADD_verify(&v[a], &v[b], &t, tapes, e, msgs_e, aux, s_slots, gc);
    mpc_ADD_verify(&t, x, &v[a], tapes, e, msgs_e, aux, s_slots, gc);
    mpc_XOR_v(&v[d], &v[a], &t); mpc_RIGHTROTATE_v(&t, 16, &v[d]);
    mpc_ADD_verify(&v[c], &v[d], &v[c], tapes, e, msgs_e, aux, s_slots, gc);
    mpc_XOR_v(&v[b], &v[c], &t); mpc_RIGHTROTATE_v(&t, 12, &v[b]);
    mpc_ADD_verify(&v[a], &v[b], &t, tapes, e, msgs_e, aux, s_slots, gc);
    mpc_ADD_verify(&t, y, &v[a], tapes, e, msgs_e, aux, s_slots, gc);
    mpc_XOR_v(&v[d], &v[a], &t); mpc_RIGHTROTATE_v(&t, 8, &v[d]);
    mpc_ADD_verify(&v[c], &v[d], &v[c], tapes, e, msgs_e, aux, s_slots, gc);
    mpc_XOR_v(&v[b], &v[c], &t); mpc_RIGHTROTATE_v(&t, 7, &v[b]);
}

void mpc_blake3_compress_verify(const mwv cv[8], const mwv m[16],
                                uint32_t block_len, mwv out[8],
                                unsigned char *tapes[N_PARTIES-1], int e,
                                const uint32_t *msgs_e, const uint32_t *aux,
                                uint32_t *s_slots, int *gateCount)
{
    mwv v[16];
    for (int i = 0; i < 8; i++) v[i] = cv[i];
    for (int i = 0; i < 4; i++) mwv_const(B3_IV4[i], &v[8 + i]);
    mwv_const(0, &v[12]);
    mwv_const(0, &v[13]);
    mwv_const(block_len, &v[14]);
    mwv_const(0, &v[15]);

    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = (uint8_t)i;
    for (int r = 0; r < 7; r++) {
        b3_g_v(v, 0, 4,  8, 12, &m[s[0]],  &m[s[1]],  tapes, e, msgs_e, aux, s_slots, gateCount);
        b3_g_v(v, 1, 5,  9, 13, &m[s[2]],  &m[s[3]],  tapes, e, msgs_e, aux, s_slots, gateCount);
        b3_g_v(v, 2, 6, 10, 14, &m[s[4]],  &m[s[5]],  tapes, e, msgs_e, aux, s_slots, gateCount);
        b3_g_v(v, 3, 7, 11, 15, &m[s[6]],  &m[s[7]],  tapes, e, msgs_e, aux, s_slots, gateCount);
        b3_g_v(v, 0, 5, 10, 15, &m[s[8]],  &m[s[9]],  tapes, e, msgs_e, aux, s_slots, gateCount);
        b3_g_v(v, 1, 6, 11, 12, &m[s[10]], &m[s[11]], tapes, e, msgs_e, aux, s_slots, gateCount);
        b3_g_v(v, 2, 7,  8, 13, &m[s[12]], &m[s[13]], tapes, e, msgs_e, aux, s_slots, gateCount);
        b3_g_v(v, 3, 4,  9, 14, &m[s[14]], &m[s[15]], tapes, e, msgs_e, aux, s_slots, gateCount);
        for (int i = 0; i < 16; i++) t[i] = s[B3_PERM[i]];
        memcpy(s, t, 16);
    }

    for (int i = 0; i < 8; i++) mpc_XOR_v(&v[i], &v[i + 8], &out[i]);
}

static inline uint32_t b3_le_word(const unsigned char *buf, int len, int off)
{
    uint32_t v = 0;
    for (int b = 3; b >= 0; b--) {
        int i = off + b;
        v = (v << 8) | (uint32_t)((buf && i < len) ? buf[i] : 0);
    }
    return v;
}

void mpc_blake3_th_verify(const unsigned char *dom_pub,
                          unsigned char *dom_lam[N_PARTIES-1], int dom_len,
                          const unsigned char *data_pub,
                          unsigned char *data_lam[N_PARTIES-1], int data_len,
                          unsigned char *out_pub,
                          unsigned char *out_lam[N_PARTIES-1], int out_len,
                          unsigned char *tapes[N_PARTIES-1], int e,
                          const uint32_t *msgs_e, const uint32_t *aux,
                          uint32_t *s_slots, int *gateCount)
{
    mwv cv[8];
    for (int w = 0; w < 8; w++) {
        cv[w].h = b3_le_word(dom_pub, dom_len, w * 4);
        for (int j = 0; j < N_PARTIES-1; j++)
            cv[w].l[j] = b3_le_word(dom_lam ? dom_lam[j] : NULL, dom_len, w * 4);
    }

    int nblocks = data_len ? (data_len + 63) / 64 : 1;
    for (int b = 0; b < nblocks; b++) {
        int off  = b * 64;
        int blen = (data_len - off > 64) ? 64 : data_len - off;
        mwv m[16];
        for (int w = 0; w < 16; w++) {
            m[w].h = b3_le_word(data_pub, data_len, off + w * 4);
            for (int j = 0; j < N_PARTIES-1; j++)
                m[w].l[j] = b3_le_word(data_lam ? data_lam[j] : NULL,
                                       data_len, off + w * 4);
        }
        mpc_blake3_compress_verify(cv, m, (uint32_t)blen, cv,
                                   tapes, e, msgs_e, aux, s_slots, gateCount);
    }

    for (int i = 0; i < out_len; i++) {
        out_pub[i] = (unsigned char)(cv[i / 4].h >> (8 * (i % 4)));
        for (int j = 0; j < N_PARTIES-1; j++)
            out_lam[j][i] = (unsigned char)(cv[i / 4].l[j] >> (8 * (i % 4)));
    }
}

