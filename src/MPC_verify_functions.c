#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Map slot index j and hidden party e to original party index. */
static inline int orig(int j, int e) { return (j < e) ? j : j + 1; }

/* SIMD lanes over slots: 4 × uint32 = 128 bits (SSE on x86, NEON on arm64).
 * NVCHUNK = ceil((N-1)/4); the last chunk is padded with inert zero lanes. */
typedef uint32_t v4u __attribute__((vector_size(16)));
#define NVCHUNK ((N_PARTIES - 1 + 3) / 4)

/* ── Linear gates ───────────────────────────────────────────────────────── */

void mpc_XOR_v(uint32_t x[N_PARTIES-1], uint32_t y[N_PARTIES-1],
               uint32_t z[N_PARTIES-1])
{
    for (int j = 0; j < N_PARTIES-1; j++) z[j] = x[j] ^ y[j];
}

void mpc_NEGATE_v(uint32_t x[N_PARTIES-1], uint32_t z[N_PARTIES-1])
{
    for (int j = 0; j < N_PARTIES-1; j++) z[j] = ~x[j];
}

void mpc_RIGHTROTATE_v(uint32_t x[N_PARTIES-1], int n, uint32_t z[N_PARTIES-1])
{
    for (int j = 0; j < N_PARTIES-1; j++) z[j] = RIGHTROTATE(x[j], n);
}

void mpc_RIGHTSHIFT_v(uint32_t x[N_PARTIES-1], int n, uint32_t z[N_PARTIES-1])
{
    for (int j = 0; j < N_PARTIES-1; j++) z[j] = x[j] >> n;
}

/* ── Word-level Beaver AND (verify) ────────────────────────────────────── */

void mpc_AND_verify(uint32_t x[N_PARTIES-1], uint32_t y[N_PARTIES-1],
                    uint32_t z[N_PARTIES-1],
                    unsigned char *tapes[N_PARTIES-1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *per_party_da_db, int *gateCount)
{
    int g = *gateCount;

    /* Reconstruct da, db from revealed parties' contributions and msgs_e. */
    uint32_t da_rev = 0, db_rev = 0;
    for (int j = 0; j < N_PARTIES-1; j++) {
        uint32_t da_j = x[j] ^ tape_u(tapes[j], g);
        uint32_t db_j = y[j] ^ tape_v(tapes[j], g);
        da_rev ^= da_j;
        db_rev ^= db_j;
        if (per_party_da_db) {
            per_party_da_db[(size_t)j * 2 * ySize + (size_t)(2*g)  ] = da_j;
            per_party_da_db[(size_t)j * 2 * ySize + (size_t)(2*g+1)] = db_j;
        }
    }
    /* da = XOR of all parties = revealed XOR hidden party's contribution from proof. */
    uint32_t da = da_rev ^ msgs_e[2*g];
    uint32_t db = db_rev ^ msgs_e[2*g+1];

    for (int j = 0; j < N_PARTIES-1; j++) {
        int o = orig(j, e);
        uint32_t u = tape_u(tapes[j], g);
        uint32_t v = tape_v(tapes[j], g);
        uint32_t w = tape_w(tapes[j], g);
        if (o == 0) w ^= aux[g];
        z[j] = w ^ (da & v) ^ (db & u);
        if (o == 0) z[j] ^= da & db;
    }
    (*gateCount)++;
}

/* ── 32-bit ADD (verify) ────────────────────────────────────────────────── */

void mpc_ADD_verify(uint32_t x[N_PARTIES-1], uint32_t y[N_PARTIES-1],
                    uint32_t z[N_PARTIES-1],
                    unsigned char *tapes[N_PARTIES-1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *per_party_da_db, int *gateCount)
{
    int g = *gateCount;

    /* Vectorised mirror of mpc_ADD (see MPC_prove_functions.c): the global
     * broadcast bits da_b/db_b combine the hidden party's msgs_e with the
     * revealed parties' parity words, and the revealed-parity carry follows
     * a public recurrence, so the slot dimension is pure SIMD work.  The
     * N-1 slots are padded to a multiple of 4 with all-zero lanes, which are
     * inert (zero tape and inputs keep their carry and da/db at zero). */
    v4u u[NVCHUNK], v[NVCHUNK], w_tape[NVCHUNK], xu[NVCHUNK], yv[NVCHUNK];
    memset(u, 0, sizeof(u)); memset(v, 0, sizeof(v)); memset(w_tape, 0, sizeof(w_tape));
    memset(xu, 0, sizeof(xu)); memset(yv, 0, sizeof(yv));
    uint32_t pu = 0, pv = 0, pw = 0, pxu = 0, pyv = 0;
    for (int j = 0; j < N_PARTIES-1; j++) {
        uint32_t uj = tape_u(tapes[j], g);
        uint32_t vj = tape_v(tapes[j], g);
        uint32_t wj = tape_w(tapes[j], g);
        uint32_t xuj = x[j] ^ uj, yvj = y[j] ^ vj;
        u[j/4][j%4] = uj; v[j/4][j%4] = vj; w_tape[j/4][j%4] = wj;
        xu[j/4][j%4] = xuj; yv[j/4][j%4] = yvj;
        pu ^= uj; pv ^= vj; pw ^= wj;
        pxu ^= xuj; pyv ^= yvj;
    }
    const uint32_t corr = aux[g];
    const uint32_t me_da = msgs_e[2*g], me_db = msgs_e[2*g+1];
    /* Party 0's correction terms apply to slot 0 iff party 0 is revealed. */
    const uint32_t has0 = (uint32_t)(e != 0);

    /* Reconstruct the broadcast words DA/DB with a scalar bit recurrence
     * (the verifier lacks the hidden party, so the prover's real-addition
     * shortcut does not apply): DA_b combines msgs_e with the revealed
     * parties' parity words and their carry parity, which itself follows
     * the public prefix recurrence crw_{b+1} = crw_b ^ gao_b. */
    uint32_t DA = 0, DB = 0, crw_b = 0;
    for (int b = 0; b < 31; b++) {
        uint32_t da_b = ((me_da >> b) ^ (pxu >> b) ^ crw_b) & 1;
        uint32_t db_b = ((me_db >> b) ^ (pyv >> b) ^ crw_b) & 1;
        DA |= da_b << b;
        DB |= db_b << b;
        uint32_t gao = ((pw >> b) & 1)
                     ^ (da_b & ((pv >> b) & 1))
                     ^ (db_b & ((pu >> b) & 1))
                     ^ (has0 & (((corr >> b) & 1) ^ (da_b & db_b)));
        crw_b ^= gao;
    }
    const uint32_t p0w = (corr ^ (DA & DB)) & (0u - has0);

    /* Word-parallel per-slot part (see mpc_ADD): each slot's carry word is
     * the shifted prefix-XOR of its whole-word AND outputs. */
    v4u cw[NVCHUNK], pda[NVCHUNK], pdb[NVCHUNK];
    for (int c = 0; c < NVCHUNK; c++) {
        v4u ao = w_tape[c] ^ (DA & v[c]) ^ (DB & u[c]);
        if (c == 0) ao[0] ^= p0w;
        ao ^= ao << 1; ao ^= ao << 2; ao ^= ao << 4; ao ^= ao << 8; ao ^= ao << 16;
        cw[c] = ao << 1;
        pda[c] = (xu[c] ^ cw[c]) & 0x7FFFFFFFu;
        pdb[c] = (yv[c] ^ cw[c]) & 0x7FFFFFFFu;
    }

    for (int j = 0; j < N_PARTIES-1; j++) z[j] = x[j] ^ y[j] ^ cw[j/4][j%4];

    if (per_party_da_db) {
        for (int j = 0; j < N_PARTIES-1; j++) {
            per_party_da_db[(size_t)j * 2 * ySize + (size_t)(2*g)  ] = pda[j/4][j%4];
            per_party_da_db[(size_t)j * 2 * ySize + (size_t)(2*g+1)] = pdb[j/4][j%4];
        }
    }
    (*gateCount)++;
}

/* ── SHA-256 derived gates (verify) ─────────────────────────────────────── */

void mpc_MAJ_verify(uint32_t a[N_PARTIES-1], uint32_t b[N_PARTIES-1],
                    uint32_t c[N_PARTIES-1], uint32_t z[N_PARTIES-1],
                    unsigned char *tapes[N_PARTIES-1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *per_party_da_db, int *gateCount)
{
    uint32_t t0[N_PARTIES-1], t1[N_PARTIES-1];
    mpc_XOR_v(a, b, t0);
    mpc_XOR_v(a, c, t1);
    mpc_AND_verify(t0, t1, z, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
    mpc_XOR_v(z, a, z);
}

void mpc_CH_verify(uint32_t e_sh[N_PARTIES-1], uint32_t f[N_PARTIES-1],
                   uint32_t g_sh[N_PARTIES-1], uint32_t z[N_PARTIES-1],
                   unsigned char *tapes[N_PARTIES-1], int e,
                   const uint32_t *msgs_e, const uint32_t *aux,
                   uint32_t *per_party_da_db, int *gateCount)
{
    uint32_t t[N_PARTIES-1];
    mpc_XOR_v(f, g_sh, t);
    mpc_AND_verify(e_sh, t, t, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
    mpc_XOR_v(t, g_sh, z);
}

/* ── N-1 party SHA-256 (verify) ─────────────────────────────────────────── */

void mpc_sha256_verify(unsigned char *inputs[N_PARTIES-1], int numBits,
                       unsigned char *results[N_PARTIES-1],
                       unsigned char *tapes[N_PARTIES-1], int e,
                       const uint32_t *msgs_e, const uint32_t *aux,
                       uint32_t *per_party_da_db, int *gateCount)
{
    const uint64_t bitlen64 = (uint64_t)((numBits < 0) ? 0 : numBits);
    const size_t fullBytes = (size_t)(bitlen64 >> 3);
    const int remBits = (int)(bitlen64 & 7);
    const size_t srcBytes = fullBytes + (remBits ? 1 : 0);
    const size_t bytesBeforeLen = fullBytes + 1;
    const size_t padZeroBytes = (size_t)((56 - (int)(bytesBeforeLen % 64) + 64) % 64);
    const size_t totalLen = bytesBeforeLen + padZeroBytes + 8;
    const size_t nBlocks = totalLen / 64;

    unsigned char *padded[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) padded[j] = NULL;
    /* Slot j corresponds to original party orig(j,e).
     * Padding and IV are PUBLIC → only the slot for party 0 (if revealed) holds them. */
    int slot0 = (e != 0) ? 0 : -1; /* slot index for party 0, or -1 if party 0 is hidden */

    for (int j = 0; j < N_PARTIES-1; j++) {
        padded[j] = calloc(totalLen, 1);
        if (!padded[j]) {
            for (int k = 0; k < j; k++) free(padded[k]);
            return;
        }
        if (srcBytes) memcpy(padded[j], inputs[j], srcBytes);
        if (j == slot0) {
            if (remBits) {
                padded[j][fullBytes] &= (unsigned char)(0xFFu << (8 - remBits));
                padded[j][fullBytes] |= (unsigned char)(0x80u >> remBits);
            } else {
                padded[j][fullBytes] = 0x80u;
            }
            uint64_t L = bitlen64;
            for (int bb = 0; bb < 8; bb++)
                padded[j][totalLen - 1 - bb] = (unsigned char)((L >> (8*bb)) & 0xFF);
        } else if (remBits) {
            padded[j][fullBytes] &= (unsigned char)(0xFFu << (8 - remBits));
        }
    }

    uint32_t H[8][N_PARTIES-1];
    for (int ww = 0; ww < 8; ww++) {
        /* IV is PUBLIC → only slot for party 0 holds hA; others hold 0. */
        for (int j = 0; j < N_PARTIES-1; j++)
            H[ww][j] = (j == slot0) ? hA[ww] : 0;
    }

    uint32_t w[64][N_PARTIES-1];
    uint32_t A[N_PARTIES-1], B[N_PARTIES-1], C[N_PARTIES-1], D[N_PARTIES-1];
    uint32_t E[N_PARTIES-1], F[N_PARTIES-1], G[N_PARTIES-1], Hv[N_PARTIES-1];
    uint32_t s0[N_PARTIES-1], s1[N_PARTIES-1];
    uint32_t t0[N_PARTIES-1], t1[N_PARTIES-1];
    uint32_t maj[N_PARTIES-1], temp1[N_PARTIES-1], temp2[N_PARTIES-1];

    for (size_t blk = 0; blk < nBlocks; blk++) {
        for (int j = 0; j < N_PARTIES-1; j++) {
            const unsigned char *base = padded[j] + blk * 64;
            for (int ww = 0; ww < 16; ww++) {
                w[ww][j] = ((uint32_t)base[ww*4+0] << 24) | ((uint32_t)base[ww*4+1] << 16)
                          | ((uint32_t)base[ww*4+2] <<  8) | ((uint32_t)base[ww*4+3]);
            }
        }
        for (int ww = 16; ww < 64; ww++) {
            mpc_RIGHTROTATE_v(w[ww-15], 7,  t0);
            mpc_RIGHTROTATE_v(w[ww-15], 18, t1); mpc_XOR_v(t0, t1, t0);
            mpc_RIGHTSHIFT_v( w[ww-15], 3,  t1); mpc_XOR_v(t0, t1, s0);
            mpc_RIGHTROTATE_v(w[ww-2],  17, t0);
            mpc_RIGHTROTATE_v(w[ww-2],  19, t1); mpc_XOR_v(t0, t1, t0);
            mpc_RIGHTSHIFT_v( w[ww-2],  10, t1); mpc_XOR_v(t0, t1, s1);
            mpc_ADD_verify(w[ww-16], s0, t1, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            mpc_ADD_verify(w[ww-7],  t1, t1, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            mpc_ADD_verify(t1, s1, w[ww], tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        }

        for (int j = 0; j < N_PARTIES-1; j++) {
            A[j]=H[0][j]; B[j]=H[1][j]; C[j]=H[2][j]; D[j]=H[3][j];
            E[j]=H[4][j]; F[j]=H[5][j]; G[j]=H[6][j]; Hv[j]=H[7][j];
        }

        for (int ww = 0; ww < 64; ww++) {
            mpc_RIGHTROTATE_v(E, 6,  t0);
            mpc_RIGHTROTATE_v(E, 11, t1); mpc_XOR_v(t0, t1, t0);
            mpc_RIGHTROTATE_v(E, 25, t1); mpc_XOR_v(t0, t1, s1);
            mpc_ADD_verify(Hv, s1, t0, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            mpc_CH_verify(E, F, G, t1, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            mpc_ADD_verify(t0, t1, t1, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            /* ADDK: public constant k[ww] goes to the slot for party 0 only. */
            {
                uint32_t Kshares[N_PARTIES-1];
                for (int j = 0; j < N_PARTIES-1; j++) Kshares[j] = 0;
                if (slot0 >= 0) Kshares[slot0] = k[ww];
                mpc_ADD_verify(t1, Kshares, t1, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            }
            mpc_ADD_verify(t1, w[ww], temp1, tapes, e, msgs_e, aux, per_party_da_db, gateCount);

            mpc_RIGHTROTATE_v(A, 2,  t0);
            mpc_RIGHTROTATE_v(A, 13, t1); mpc_XOR_v(t0, t1, t0);
            mpc_RIGHTROTATE_v(A, 22, t1); mpc_XOR_v(t0, t1, s0);
            mpc_MAJ_verify(A, B, C, maj, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            mpc_ADD_verify(s0, maj, temp2, tapes, e, msgs_e, aux, per_party_da_db, gateCount);

            for (int j = 0; j < N_PARTIES-1; j++) Hv[j] = G[j];
            for (int j = 0; j < N_PARTIES-1; j++) G[j]  = F[j];
            for (int j = 0; j < N_PARTIES-1; j++) F[j]  = E[j];
            mpc_ADD_verify(D, temp1, E, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
            for (int j = 0; j < N_PARTIES-1; j++) D[j] = C[j];
            for (int j = 0; j < N_PARTIES-1; j++) C[j] = B[j];
            for (int j = 0; j < N_PARTIES-1; j++) B[j] = A[j];
            mpc_ADD_verify(temp1, temp2, A, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        }

        uint32_t tmp[N_PARTIES-1];
        mpc_ADD_verify(H[0], A,  tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[0][j]=tmp[j];
        mpc_ADD_verify(H[1], B,  tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[1][j]=tmp[j];
        mpc_ADD_verify(H[2], C,  tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[2][j]=tmp[j];
        mpc_ADD_verify(H[3], D,  tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[3][j]=tmp[j];
        mpc_ADD_verify(H[4], E,  tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[4][j]=tmp[j];
        mpc_ADD_verify(H[5], F,  tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[5][j]=tmp[j];
        mpc_ADD_verify(H[6], G,  tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[6][j]=tmp[j];
        mpc_ADD_verify(H[7], Hv, tmp, tapes, e, msgs_e, aux, per_party_da_db, gateCount);
        for (int j=0;j<N_PARTIES-1;j++) H[7][j]=tmp[j];
    }

    for (int j = 0; j < N_PARTIES-1; j++) free(padded[j]);

    for (int ww = 0; ww < 8; ww++) {
        for (int j = 0; j < N_PARTIES-1; j++) {
            results[j][ww*4+0] = (unsigned char)(H[ww][j] >> 24);
            results[j][ww*4+1] = (unsigned char)(H[ww][j] >> 16);
            results[j][ww*4+2] = (unsigned char)(H[ww][j] >>  8);
            results[j][ww*4+3] = (unsigned char)(H[ww][j]);
        }
    }
}
