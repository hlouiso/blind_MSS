#include "MPC_prove_functions.h"
#include "shared.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Linear gates (free, no Beaver cost) ───────────────────────────────── */

void mpc_XOR(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES])
{
    for (int i = 0; i < N_PARTIES; i++) z[i] = x[i] ^ y[i];
}

void mpc_NEGATE(uint32_t x[N_PARTIES], uint32_t z[N_PARTIES])
{
    for (int i = 0; i < N_PARTIES; i++) z[i] = ~x[i];
}

void mpc_RIGHTROTATE(uint32_t x[N_PARTIES], int n, uint32_t z[N_PARTIES])
{
    for (int i = 0; i < N_PARTIES; i++) z[i] = RIGHTROTATE(x[i], n);
}

void mpc_RIGHTSHIFT(uint32_t x[N_PARTIES], int n, uint32_t z[N_PARTIES])
{
    for (int i = 0; i < N_PARTIES; i++) z[i] = x[i] >> n;
}

/* ── Word-level Beaver AND ──────────────────────────────────────────────── */

void mpc_AND(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *da_db_all, int *gateCount)
{
    int g = *gateCount;

    uint32_t u_xor = 0, v_xor = 0, w_xor = 0;
    uint32_t u[N_PARTIES], v[N_PARTIES], w[N_PARTIES];
    for (int i = 0; i < N_PARTIES; i++) {
        u[i] = tape_u(tapes[i], g);
        v[i] = tape_v(tapes[i], g);
        w[i] = tape_w(tapes[i], g);
        u_xor ^= u[i]; v_xor ^= v[i]; w_xor ^= w[i];
    }
    /* Correction for party 0: makes XOR of all w[i] equal to u_xor AND v_xor. */
    uint32_t corr = (u_xor & v_xor) ^ w_xor;
    aux[g] = corr;
    w[0] ^= corr;

    /* Compute per-party contributions da_i = x_i XOR u_i, db_i = y_i XOR v_i.
     * da = XOR_i(da_i), db = XOR_i(db_i) are the broadcast values used for output. */
    uint32_t da = 0, db = 0;
    for (int i = 0; i < N_PARTIES; i++) {
        uint32_t da_i = x[i] ^ u[i];
        uint32_t db_i = y[i] ^ v[i];
        da ^= da_i;
        db ^= db_i;
        if (da_db_all) {
            da_db_all[(size_t)i * 2 * ySize + (size_t)(2*g)  ] = da_i;
            da_db_all[(size_t)i * 2 * ySize + (size_t)(2*g+1)] = db_i;
        }
    }

    /* Output shares. */
    for (int i = 0; i < N_PARTIES; i++) {
        z[i] = w[i] ^ (da & v[i]) ^ (db & u[i]);
        if (i == 0) z[i] ^= da & db;
    }
    (*gateCount)++;
}

/* ── 32-bit ADD with bit-serial Beaver carry ────────────────────────────── */
/* Each ADD uses ONE gate slot (one u/v/w triple per party, 32 bits wide).
 * Carry propagation uses bit b of the word-triple for carry bit b. */

void mpc_ADD(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *da_db_all, int *gateCount)
{
    int g = *gateCount;

    uint32_t u[N_PARTIES], v[N_PARTIES], w[N_PARTIES];
    for (int i = 0; i < N_PARTIES; i++) {
        u[i] = tape_u(tapes[i], g);
        v[i] = tape_v(tapes[i], g);
        w[i] = tape_w(tapes[i], g);
    }

    /* Carry shares: c[i][bit b] = party i's share of carry into position b+1. */
    uint32_t c[N_PARTIES];
    memset(c, 0, sizeof(c));

    /* Per-party accumulated (da_i, db_i) words (one bit per iteration). */
    uint32_t pda[N_PARTIES], pdb[N_PARTIES];
    memset(pda, 0, sizeof(pda));
    memset(pdb, 0, sizeof(pdb));

    uint32_t aux_word = 0;

    for (int b = 0; b < 31; b++) {
        /* Each party's inputs to carry AND: a_b = (x[i] XOR c[i]) >> b & 1,
         * similarly b_b.  Triple bits taken from bit b of u[i]/v[i]/w[i]. */
        uint32_t u_b_xor = 0, v_b_xor = 0, w_b_xor = 0;
        for (int i = 0; i < N_PARTIES; i++) {
            u_b_xor ^= (u[i] >> b) & 1;
            v_b_xor ^= (v[i] >> b) & 1;
            w_b_xor ^= (w[i] >> b) & 1;
        }
        uint32_t corr_b = (u_b_xor & v_b_xor) ^ w_b_xor;
        aux_word |= (corr_b & 1u) << b;

        uint32_t da_b = 0, db_b = 0;
        for (int i = 0; i < N_PARTIES; i++) {
            uint32_t a_b = ((x[i] ^ c[i]) >> b) & 1;
            uint32_t b_b = ((y[i] ^ c[i]) >> b) & 1;
            uint32_t da_i_b = a_b ^ ((u[i] >> b) & 1);
            uint32_t db_i_b = b_b ^ ((v[i] >> b) & 1);
            da_b ^= da_i_b;
            db_b ^= db_i_b;
            pda[i] |= (da_i_b & 1u) << b;
            pdb[i] |= (db_i_b & 1u) << b;
        }
        da_b &= 1; db_b &= 1;

        /* Compute carry shares for bit b+1. */
        for (int i = 0; i < N_PARTIES; i++) {
            uint32_t u_b = (u[i] >> b) & 1;
            uint32_t v_b = (v[i] >> b) & 1;
            uint32_t w_b = (w[i] >> b) & 1;
            if (i == 0) w_b ^= corr_b;

            uint32_t and_out = w_b ^ (da_b & v_b) ^ (db_b & u_b);
            if (i == 0) and_out ^= da_b & db_b;

            /* carry[b+1]_i = and_out XOR carry[b]_i */
            uint32_t old_c = (c[i] >> b) & 1;
            uint32_t new_c = and_out ^ old_c;
            if (b + 1 < 32)
                c[i] = (c[i] & ~(1u << (b+1))) | (new_c << (b+1));
        }
    }

    for (int i = 0; i < N_PARTIES; i++) z[i] = x[i] ^ y[i] ^ c[i];

    if (da_db_all) {
        for (int i = 0; i < N_PARTIES; i++) {
            da_db_all[(size_t)i * 2 * ySize + (size_t)(2*g)  ] = pda[i];
            da_db_all[(size_t)i * 2 * ySize + (size_t)(2*g+1)] = pdb[i];
        }
    }

    aux[g] = aux_word;
    (*gateCount)++;
}

/* ── ADD with public constant ───────────────────────────────────────────── */

void mpc_ADDK(uint32_t x[N_PARTIES], uint32_t K, uint32_t z[N_PARTIES],
              unsigned char *tapes[N_PARTIES], uint32_t *aux,
              uint32_t *da_db_all, int *gateCount)
{
    /* K is public: party 0 holds K; other parties hold 0. */
    uint32_t y[N_PARTIES];
    memset(y, 0, sizeof(y));
    y[0] = K;
    mpc_ADD(x, y, z, tapes, aux, da_db_all, gateCount);
}

/* ── SHA-256 derived gates ──────────────────────────────────────────────── */

void mpc_MAJ(uint32_t a[N_PARTIES], uint32_t b[N_PARTIES], uint32_t c[N_PARTIES],
             uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *da_db_all, int *gateCount)
{
    /* MAJ(a,b,c) = (a XOR b) AND (a XOR c) XOR a */
    uint32_t t0[N_PARTIES], t1[N_PARTIES];
    mpc_XOR(a, b, t0);
    mpc_XOR(a, c, t1);
    mpc_AND(t0, t1, z, tapes, aux, da_db_all, gateCount);
    mpc_XOR(z, a, z);
}

void mpc_CH(uint32_t e[N_PARTIES], uint32_t f[N_PARTIES], uint32_t g[N_PARTIES],
            uint32_t z[N_PARTIES],
            unsigned char *tapes[N_PARTIES], uint32_t *aux,
            uint32_t *da_db_all, int *gateCount)
{
    /* CH(e,f,g) = (e AND (f XOR g)) XOR g */
    uint32_t t[N_PARTIES];
    mpc_XOR(f, g, t);
    mpc_AND(e, t, t, tapes, aux, da_db_all, gateCount);
    mpc_XOR(t, g, z);
}

/* ── N-party SHA-256 ────────────────────────────────────────────────────── */

void mpc_sha256(unsigned char *inputs[N_PARTIES], int numBits,
                unsigned char *results[N_PARTIES],
                unsigned char *tapes[N_PARTIES],
                uint32_t *aux, uint32_t *da_db_all, int *gateCount)
{
    const uint64_t bitlen64 = (uint64_t)((numBits < 0) ? 0 : numBits);
    const size_t fullBytes = (size_t)(bitlen64 >> 3);
    const int remBits = (int)(bitlen64 & 7);
    const size_t srcBytes = fullBytes + (remBits ? 1 : 0);
    const size_t bytesBeforeLen = fullBytes + 1;
    const size_t padZeroBytes = (size_t)((56 - (int)(bytesBeforeLen % 64) + 64) % 64);
    const size_t totalLen = bytesBeforeLen + padZeroBytes + 8;
    const size_t nBlocks = totalLen / 64;

    unsigned char *padded[N_PARTIES];
    for (int i = 0; i < N_PARTIES; i++) padded[i] = NULL;
    for (int i = 0; i < N_PARTIES; i++) {
        padded[i] = calloc(totalLen, 1);
        if (!padded[i]) {
            for (int j = 0; j < i; j++) free(padded[j]);
            return;
        }
        if (srcBytes) memcpy(padded[i], inputs[i], srcBytes);
        /* SHA-256 padding bytes are PUBLIC: place into party 0 only.
         * Other parties' buffers remain zero in the padding region (calloc). */
        if (i == 0) {
            if (remBits) {
                padded[0][fullBytes] &= (unsigned char)(0xFFu << (8 - remBits));
                padded[0][fullBytes] |= (unsigned char)(0x80u >> remBits);
            } else {
                padded[0][fullBytes] = 0x80u;
            }
            uint64_t L = bitlen64;
            for (int b = 0; b < 8; b++)
                padded[0][totalLen - 1 - b] = (unsigned char)((L >> (8*b)) & 0xFF);
        } else if (remBits) {
            /* Mask out the padding bits in the partial byte for non-zero parties. */
            padded[i][fullBytes] &= (unsigned char)(0xFFu << (8 - remBits));
        }
    }

    uint32_t H[8][N_PARTIES];
    for (int j = 0; j < 8; j++) {
        /* SHA-256 IV is PUBLIC: party 0 holds it; all others hold 0. */
        H[j][0] = hA[j];
        for (int i = 1; i < N_PARTIES; i++) H[j][i] = 0;
    }

    uint32_t w[64][N_PARTIES];
    uint32_t A[N_PARTIES], B[N_PARTIES], C[N_PARTIES], D[N_PARTIES];
    uint32_t E[N_PARTIES], F[N_PARTIES], G[N_PARTIES], Hv[N_PARTIES];
    uint32_t s0[N_PARTIES], s1[N_PARTIES], t0[N_PARTIES], t1[N_PARTIES];
    uint32_t maj[N_PARTIES], temp1[N_PARTIES], temp2[N_PARTIES];

    for (size_t blk = 0; blk < nBlocks; blk++) {
        for (int i = 0; i < N_PARTIES; i++) {
            const unsigned char *base = padded[i] + blk * 64;
            for (int j = 0; j < 16; j++) {
                w[j][i] = ((uint32_t)base[j*4+0] << 24) | ((uint32_t)base[j*4+1] << 16) |
                          ((uint32_t)base[j*4+2] <<  8) | ((uint32_t)base[j*4+3]);
            }
        }

        for (int j = 16; j < 64; j++) {
            mpc_RIGHTROTATE(w[j-15], 7,  t0);
            mpc_RIGHTROTATE(w[j-15], 18, t1); mpc_XOR(t0, t1, t0);
            mpc_RIGHTSHIFT( w[j-15], 3,  t1); mpc_XOR(t0, t1, s0);

            mpc_RIGHTROTATE(w[j-2], 17, t0);
            mpc_RIGHTROTATE(w[j-2], 19, t1); mpc_XOR(t0, t1, t0);
            mpc_RIGHTSHIFT( w[j-2], 10, t1); mpc_XOR(t0, t1, s1);

            mpc_ADD(w[j-16], s0,   t1, tapes, aux, da_db_all, gateCount);
            mpc_ADD(w[j-7],  t1,   t1, tapes, aux, da_db_all, gateCount);
            mpc_ADD(t1,      s1, w[j], tapes, aux, da_db_all, gateCount);
        }

        for (int i = 0; i < N_PARTIES; i++) {
            A[i] = H[0][i]; B[i] = H[1][i]; C[i] = H[2][i]; D[i] = H[3][i];
            E[i] = H[4][i]; F[i] = H[5][i]; G[i] = H[6][i]; Hv[i] = H[7][i];
        }

        for (int j = 0; j < 64; j++) {
            mpc_RIGHTROTATE(E, 6,  t0);
            mpc_RIGHTROTATE(E, 11, t1); mpc_XOR(t0, t1, t0);
            mpc_RIGHTROTATE(E, 25, t1); mpc_XOR(t0, t1, s1);

            mpc_ADD(Hv, s1, t0, tapes, aux, da_db_all, gateCount);
            mpc_CH(E, F, G, t1, tapes, aux, da_db_all, gateCount);
            mpc_ADD(t0, t1, t1, tapes, aux, da_db_all, gateCount);
            mpc_ADDK(t1, k[j], t1, tapes, aux, da_db_all, gateCount);
            mpc_ADD(t1, w[j], temp1, tapes, aux, da_db_all, gateCount);

            mpc_RIGHTROTATE(A, 2,  t0);
            mpc_RIGHTROTATE(A, 13, t1); mpc_XOR(t0, t1, t0);
            mpc_RIGHTROTATE(A, 22, t1); mpc_XOR(t0, t1, s0);

            mpc_MAJ(A, B, C, maj, tapes, aux, da_db_all, gateCount);
            mpc_ADD(s0, maj, temp2, tapes, aux, da_db_all, gateCount);

            for (int i = 0; i < N_PARTIES; i++) Hv[i] = G[i];
            for (int i = 0; i < N_PARTIES; i++) G[i]  = F[i];
            for (int i = 0; i < N_PARTIES; i++) F[i]  = E[i];
            mpc_ADD(D, temp1, E, tapes, aux, da_db_all, gateCount);
            for (int i = 0; i < N_PARTIES; i++) D[i] = C[i];
            for (int i = 0; i < N_PARTIES; i++) C[i] = B[i];
            for (int i = 0; i < N_PARTIES; i++) B[i] = A[i];
            mpc_ADD(temp1, temp2, A, tapes, aux, da_db_all, gateCount);
        }

        uint32_t tmp[N_PARTIES];
        mpc_ADD(H[0], A,  tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[0][i]=tmp[i];
        mpc_ADD(H[1], B,  tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[1][i]=tmp[i];
        mpc_ADD(H[2], C,  tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[2][i]=tmp[i];
        mpc_ADD(H[3], D,  tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[3][i]=tmp[i];
        mpc_ADD(H[4], E,  tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[4][i]=tmp[i];
        mpc_ADD(H[5], F,  tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[5][i]=tmp[i];
        mpc_ADD(H[6], G,  tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[6][i]=tmp[i];
        mpc_ADD(H[7], Hv, tmp, tapes, aux, da_db_all, gateCount); for(int i=0;i<N_PARTIES;i++) H[7][i]=tmp[i];
    }

    for (int i = 0; i < N_PARTIES; i++) free(padded[i]);

    /* Pack output: big-endian bytes. */
    for (int j = 0; j < 8; j++) {
        for (int i = 0; i < N_PARTIES; i++) {
            results[i][j*4+0] = (unsigned char)(H[j][i] >> 24);
            results[i][j*4+1] = (unsigned char)(H[j][i] >> 16);
            results[i][j*4+2] = (unsigned char)(H[j][i] >>  8);
            results[i][j*4+3] = (unsigned char)(H[j][i]);
        }
    }
}
