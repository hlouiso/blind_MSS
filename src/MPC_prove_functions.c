#include "MPC_prove_functions.h"
#include "shared.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Gate-type recorder (see shared.h). NULL except during one-time table build. */
uint8_t *g_gate_type_rec = NULL;

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
    if (g_gate_type_rec) g_gate_type_rec[g] = 0; /* AND gate */

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

/* SIMD lanes over parties: 4 × uint32 = 128 bits (SSE on x86, NEON on arm64).
 * GCC/Clang vector extensions — portable, no per-ISA intrinsics. */
typedef uint32_t v4u __attribute__((vector_size(16)));
#define NCHUNK (N_PARTIES / 4)
_Static_assert(N_PARTIES % 4 == 0, "vectorised gates require N_PARTIES % 4 == 0");

void mpc_ADD(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *da_db_all, int *gateCount)
{
    int g = *gateCount;
    if (g_gate_type_rec) g_gate_type_rec[g] = 1; /* ADD gate */

    /* Vectorised reformulation of the bit-serial Beaver carry.  Produces
     * bit-identical (aux, da/db, z) to the reference version:
     *   - all 31 corrections at once: corr = (XOR u AND XOR v) XOR (XOR w);
     *   - the global broadcast bits da_b/db_b come from the parity words
     *     pxu = XOR_i (x_i^u_i), pyv = XOR_i (y_i^v_i) and the global carry,
     *     removing the per-bit reduction over parties;
     *   - the global carry itself follows the public recurrence on parities,
     *     so the party dimension is pure data-parallel SIMD work. */
    v4u u[NCHUNK], v[NCHUNK], w[NCHUNK], xu[NCHUNK], yv[NCHUNK];
    uint32_t pu = 0, pv = 0, pw = 0, pxu = 0, pyv = 0;
    for (int i = 0; i < N_PARTIES; i++) {
        uint32_t ui = tape_u(tapes[i], g);
        uint32_t vi = tape_v(tapes[i], g);
        uint32_t wi = tape_w(tapes[i], g);
        uint32_t xui = x[i] ^ ui, yvi = y[i] ^ vi;
        u[i/4][i%4] = ui; v[i/4][i%4] = vi; w[i/4][i%4] = wi;
        xu[i/4][i%4] = xui; yv[i/4][i%4] = yvi;
        pu ^= ui; pv ^= vi; pw ^= wi;
        pxu ^= xui; pyv ^= yvi;
    }
    const uint32_t corr = (pu & pv) ^ pw; /* bits 0..30 used */

    v4u cb[NCHUNK];  /* carry-bit share at the current position */
    v4u cw[NCHUNK];  /* accumulated carry word (bits 1..31) */
    v4u pda[NCHUNK], pdb[NCHUNK];
    memset(cb, 0, sizeof(cb));
    memset(cw, 0, sizeof(cw));
    memset(pda, 0, sizeof(pda));
    memset(pdb, 0, sizeof(pdb));
    const v4u lane_p0 = {1u, 0, 0, 0}; /* party 0 lives in lane 0 of chunk 0 */

    uint32_t cgb = 0; /* global carry bit = XOR_i cb[i] */
    for (int b = 0; b < 31; b++) {
        const uint32_t da_b = ((pxu >> b) & 1) ^ cgb;
        const uint32_t db_b = ((pyv >> b) & 1) ^ cgb;
        const uint32_t corr_b = (corr >> b) & 1;
        /* Party 0's extra term: correction word plus the public da·db. */
        const uint32_t p0 = corr_b ^ (da_b & db_b);

        for (int c = 0; c < NCHUNK; c++) {
            v4u da_i_b = ((xu[c] >> b) & 1) ^ cb[c];
            v4u db_i_b = ((yv[c] >> b) & 1) ^ cb[c];
            pda[c] |= da_i_b << b;
            pdb[c] |= db_i_b << b;
            v4u and_out = ((w[c] >> b) & 1)
                        ^ (da_b & ((v[c] >> b) & 1))
                        ^ (db_b & ((u[c] >> b) & 1));
            if (c == 0) and_out ^= p0 & lane_p0;
            cb[c] ^= and_out; /* carry share for bit b+1 */
            cw[c] |= cb[c] << (b + 1);
        }

        /* Public carry recurrence on the parity words. */
        cgb ^= ((pw >> b) & 1) ^ corr_b
             ^ (da_b & ((pv >> b) & 1))
             ^ (db_b & ((pu >> b) & 1))
             ^ (da_b & db_b);
    }

    for (int i = 0; i < N_PARTIES; i++) z[i] = x[i] ^ y[i] ^ cw[i/4][i%4];

    if (da_db_all) {
        for (int i = 0; i < N_PARTIES; i++) {
            da_db_all[(size_t)i * 2 * ySize + (size_t)(2*g)  ] = pda[i/4][i%4];
            da_db_all[(size_t)i * 2 * ySize + (size_t)(2*g+1)] = pdb[i/4][i%4];
        }
    }

    aux[g] = corr & 0x7FFFFFFFu; /* mpc_ADD only uses carry bits 0..30 */
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
