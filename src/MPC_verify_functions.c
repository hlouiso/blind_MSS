#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Map slot index j and hidden party e to original party index. */
static inline int orig(int j, int e) { return (j < e) ? j : j + 1; }

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

    uint32_t u[N_PARTIES-1], v[N_PARTIES-1], w_tape[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) {
        u[j]      = tape_u(tapes[j], g);
        v[j]      = tape_v(tapes[j], g);
        w_tape[j] = tape_w(tapes[j], g);
    }

    uint32_t c[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) c[j] = 0;

    /* Accumulate per-party (da_j, db_j) contributions bit by bit. */
    uint32_t pda[N_PARTIES-1], pdb[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) { pda[j] = 0; pdb[j] = 0; }

    for (int b = 0; b < 31; b++) {
        /* Reconstruct bit b of da/db from revealed parties + hidden party's msgs_e. */
        uint32_t da_b = (msgs_e[2*g] >> b) & 1;
        uint32_t db_b = (msgs_e[2*g+1] >> b) & 1;
        for (int j = 0; j < N_PARTIES-1; j++) {
            /* carry c[j] at bit b is already known from previous iterations. */
            uint32_t da_j_b = (((x[j] ^ c[j]) >> b) ^ (u[j] >> b)) & 1;
            uint32_t db_j_b = (((y[j] ^ c[j]) >> b) ^ (v[j] >> b)) & 1;
            da_b ^= da_j_b;
            db_b ^= db_j_b;
            pda[j] |= (da_j_b & 1u) << b;
            pdb[j] |= (db_j_b & 1u) << b;
        }

        for (int j = 0; j < N_PARTIES-1; j++) {
            int o = orig(j, e);
            uint32_t u_b = (u[j] >> b) & 1;
            uint32_t v_b = (v[j] >> b) & 1;
            uint32_t corr_b = (aux[g] >> b) & 1;
            uint32_t w_b = (w_tape[j] >> b) & 1;
            if (o == 0) w_b ^= corr_b;

            uint32_t and_out = w_b ^ (da_b & v_b) ^ (db_b & u_b);
            if (o == 0) and_out ^= da_b & db_b;

            uint32_t old_c = (c[j] >> b) & 1;
            uint32_t new_c = and_out ^ old_c;
            if (b + 1 < 32)
                c[j] = (c[j] & ~(1u << (b+1))) | (new_c << (b+1));
        }
    }

    for (int j = 0; j < N_PARTIES-1; j++) z[j] = x[j] ^ y[j] ^ c[j];

    if (per_party_da_db) {
        for (int j = 0; j < N_PARTIES-1; j++) {
            per_party_da_db[(size_t)j * 2 * ySize + (size_t)(2*g)  ] = pda[j];
            per_party_da_db[(size_t)j * 2 * ySize + (size_t)(2*g+1)] = pdb[j];
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
