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

/* ── SHA-256 derived gates (verify) ─────────────────────────────────────── */

void mpc_MAJ_verify(const mwv *a, const mwv *b, const mwv *c, mwv *z,
                    unsigned char *tapes[N_PARTIES - 1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *s_slots, int *gateCount)
{
    mwv t0, t1;
    mpc_XOR_v(a, b, &t0);
    mpc_XOR_v(a, c, &t1);
    mpc_AND_verify(&t0, &t1, z, tapes, e, msgs_e, aux, s_slots, gateCount);
    mpc_XOR_v(z, a, z);
}

void mpc_CH_verify(const mwv *e_w, const mwv *f, const mwv *g_w, mwv *z,
                   unsigned char *tapes[N_PARTIES - 1], int e,
                   const uint32_t *msgs_e, const uint32_t *aux,
                   uint32_t *s_slots, int *gateCount)
{
    mwv t;
    mpc_XOR_v(f, g_w, &t);
    mpc_AND_verify(e_w, &t, &t, tapes, e, msgs_e, aux, s_slots, gateCount);
    mpc_XOR_v(&t, g_w, z);
}

/* ── N-1 party SHA-256 (verify) ─────────────────────────────────────────── */

void mpc_sha256_verify(const unsigned char *in_pub,
                       unsigned char *in_lam[N_PARTIES - 1], int numBits,
                       unsigned char *out_pub,
                       unsigned char *out_lam[N_PARTIES - 1],
                       unsigned char *tapes[N_PARTIES - 1], int e,
                       const uint32_t *msgs_e, const uint32_t *aux,
                       uint32_t *s_slots, int *gateCount)
{
    const uint64_t bitlen64 = (uint64_t)((numBits < 0) ? 0 : numBits);
    const size_t fullBytes = (size_t)(bitlen64 >> 3);
    const int remBits = (int)(bitlen64 & 7);
    const size_t srcBytes = fullBytes + (remBits ? 1 : 0);
    const size_t bytesBeforeLen = fullBytes + 1;
    const size_t padZeroBytes = (size_t)((56 - (int)(bytesBeforeLen % 64) + 64) % 64);
    const size_t totalLen = bytesBeforeLen + padZeroBytes + 8;
    const size_t nBlocks = totalLen / 64;

    unsigned char *pad_pub = calloc(totalLen, 1);
    unsigned char *pad_lam[N_PARTIES - 1];
    for (int j = 0; j < N_PARTIES - 1; j++) pad_lam[j] = NULL;
    bool ok = (pad_pub != NULL);
    for (int j = 0; j < N_PARTIES - 1 && ok; j++) {
        pad_lam[j] = calloc(totalLen, 1);
        if (!pad_lam[j]) ok = false;
    }
    if (!ok) {
        free(pad_pub);
        for (int j = 0; j < N_PARTIES - 1; j++) free(pad_lam[j]);
        return;
    }
    if (srcBytes) memcpy(pad_pub, in_pub, srcBytes);
    for (int j = 0; j < N_PARTIES - 1; j++)
        if (srcBytes) memcpy(pad_lam[j], in_lam[j], srcBytes);
    if (remBits) {
        unsigned char m = (unsigned char)(0xFFu << (8 - remBits));
        pad_pub[fullBytes] = (unsigned char)((pad_pub[fullBytes] & m) | (0x80u >> remBits));
        for (int j = 0; j < N_PARTIES - 1; j++) pad_lam[j][fullBytes] &= m;
    } else {
        pad_pub[fullBytes] = 0x80u;
    }
    for (int b = 0; b < 8; b++)
        pad_pub[totalLen - 1 - b] = (unsigned char)((bitlen64 >> (8*b)) & 0xFF);

    mwv H[8];
    for (int j = 0; j < 8; j++) mwv_const(hA[j], &H[j]);

    mwv w[64];
    mwv A, B, C, D, E, F, G, Hv;
    mwv s0, s1, t0, t1, maj, temp1, temp2;

    for (size_t blk = 0; blk < nBlocks; blk++) {
        for (int jw = 0; jw < 16; jw++) {
            const unsigned char *bp = pad_pub + blk * 64 + (size_t)jw * 4;
            w[jw].h = ((uint32_t)bp[0] << 24) | ((uint32_t)bp[1] << 16) |
                      ((uint32_t)bp[2] <<  8) | ((uint32_t)bp[3]);
            for (int j = 0; j < N_PARTIES - 1; j++) {
                const unsigned char *bl = pad_lam[j] + blk * 64 + (size_t)jw * 4;
                w[jw].l[j] = ((uint32_t)bl[0] << 24) | ((uint32_t)bl[1] << 16) |
                             ((uint32_t)bl[2] <<  8) | ((uint32_t)bl[3]);
            }
        }

        for (int jw = 16; jw < 64; jw++) {
            mpc_RIGHTROTATE_v(&w[jw-15], 7,  &t0);
            mpc_RIGHTROTATE_v(&w[jw-15], 18, &t1); mpc_XOR_v(&t0, &t1, &t0);
            mpc_RIGHTSHIFT_v( &w[jw-15], 3,  &t1); mpc_XOR_v(&t0, &t1, &s0);

            mpc_RIGHTROTATE_v(&w[jw-2], 17, &t0);
            mpc_RIGHTROTATE_v(&w[jw-2], 19, &t1); mpc_XOR_v(&t0, &t1, &t0);
            mpc_RIGHTSHIFT_v( &w[jw-2], 10, &t1); mpc_XOR_v(&t0, &t1, &s1);

            mpc_ADD_verify(&w[jw-16], &s0, &t1,   tapes, e, msgs_e, aux, s_slots, gateCount);
            mpc_ADD_verify(&w[jw-7],  &t1, &t1,   tapes, e, msgs_e, aux, s_slots, gateCount);
            mpc_ADD_verify(&t1,       &s1, &w[jw], tapes, e, msgs_e, aux, s_slots, gateCount);
        }

        A = H[0]; B = H[1]; C = H[2]; D = H[3];
        E = H[4]; F = H[5]; G = H[6]; Hv = H[7];

        for (int jw = 0; jw < 64; jw++) {
            mpc_RIGHTROTATE_v(&E, 6,  &t0);
            mpc_RIGHTROTATE_v(&E, 11, &t1); mpc_XOR_v(&t0, &t1, &t0);
            mpc_RIGHTROTATE_v(&E, 25, &t1); mpc_XOR_v(&t0, &t1, &s1);

            mpc_ADD_verify(&Hv, &s1, &t0, tapes, e, msgs_e, aux, s_slots, gateCount);
            mpc_CH_verify(&E, &F, &G, &t1, tapes, e, msgs_e, aux, s_slots, gateCount);
            mpc_ADD_verify(&t0, &t1, &t1, tapes, e, msgs_e, aux, s_slots, gateCount);
            mpc_ADDK_verify(&t1, k[jw], &t1, tapes, e, msgs_e, aux, s_slots, gateCount);
            mpc_ADD_verify(&t1, &w[jw], &temp1, tapes, e, msgs_e, aux, s_slots, gateCount);

            mpc_RIGHTROTATE_v(&A, 2,  &t0);
            mpc_RIGHTROTATE_v(&A, 13, &t1); mpc_XOR_v(&t0, &t1, &t0);
            mpc_RIGHTROTATE_v(&A, 22, &t1); mpc_XOR_v(&t0, &t1, &s0);

            mpc_MAJ_verify(&A, &B, &C, &maj, tapes, e, msgs_e, aux, s_slots, gateCount);
            mpc_ADD_verify(&s0, &maj, &temp2, tapes, e, msgs_e, aux, s_slots, gateCount);

            Hv = G; G = F; F = E;
            mpc_ADD_verify(&D, &temp1, &E, tapes, e, msgs_e, aux, s_slots, gateCount);
            D = C; C = B; B = A;
            mpc_ADD_verify(&temp1, &temp2, &A, tapes, e, msgs_e, aux, s_slots, gateCount);
        }

        mwv tmp;
        mpc_ADD_verify(&H[0], &A,  &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[0] = tmp;
        mpc_ADD_verify(&H[1], &B,  &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[1] = tmp;
        mpc_ADD_verify(&H[2], &C,  &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[2] = tmp;
        mpc_ADD_verify(&H[3], &D,  &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[3] = tmp;
        mpc_ADD_verify(&H[4], &E,  &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[4] = tmp;
        mpc_ADD_verify(&H[5], &F,  &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[5] = tmp;
        mpc_ADD_verify(&H[6], &G,  &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[6] = tmp;
        mpc_ADD_verify(&H[7], &Hv, &tmp, tapes, e, msgs_e, aux, s_slots, gateCount); H[7] = tmp;
    }

    free(pad_pub);
    for (int j = 0; j < N_PARTIES - 1; j++) free(pad_lam[j]);

    for (int jw = 0; jw < 8; jw++) {
        out_pub[jw*4+0] = (unsigned char)(H[jw].h >> 24);
        out_pub[jw*4+1] = (unsigned char)(H[jw].h >> 16);
        out_pub[jw*4+2] = (unsigned char)(H[jw].h >>  8);
        out_pub[jw*4+3] = (unsigned char)(H[jw].h);
        for (int j = 0; j < N_PARTIES - 1; j++) {
            out_lam[j][jw*4+0] = (unsigned char)(H[jw].l[j] >> 24);
            out_lam[j][jw*4+1] = (unsigned char)(H[jw].l[j] >> 16);
            out_lam[j][jw*4+2] = (unsigned char)(H[jw].l[j] >>  8);
            out_lam[j][jw*4+3] = (unsigned char)(H[jw].l[j]);
        }
    }
}
