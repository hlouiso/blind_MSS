#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "shared.h"
#include <stdint.h>

/* ── KKW N-party prover gate functions ──────────────────────────────────
 *
 * All gate functions share the same context parameters:
 *   tapes[N_PARTIES]  — expanded Beaver triple tapes, one per party.
 *   broadcast         — output array [2*ySize]: broadcast[2g]=da[g], [2g+1]=db[g].
 *   aux               — output array [ySize]:   aux[g] = Beaver correction word.
 *   gateCount         — index of the current gate (incremented on each call).
 *
 * The Beaver triple for gate g of party i is read from tapes[i]:
 *   u_i[g] = tape_u(tapes[i], g)
 *   v_i[g] = tape_v(tapes[i], g)
 *   w_raw_i[g] = tape_w(tapes[i], g)
 *
 * Correction: aux[g] = (XOR_i u_i[g]) AND (XOR_i v_i[g]) XOR (XOR_i w_raw_i[g])
 *             Applied to party 0: w_0[g] = w_raw_0[g] XOR aux[g].
 *
 * Online (for AND at word level):
 *   da[g] = XOR_i (x_i XOR u_i[g])
 *   db[g] = XOR_i (y_i XOR v_i[g])
 *   z_i   = w_i[g] XOR (da AND v_i[g]) XOR (db AND u_i[g]) XOR (i==0 ? da AND db : 0)
 *
 * ADD uses the same framework bit-by-bit for carry propagation.
 */

/* Bitwise XOR, free (no gate). */
void mpc_XOR(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES]);

/* Bitwise NOT, free. */
void mpc_NEGATE(uint32_t x[N_PARTIES], uint32_t z[N_PARTIES]);

/* Right-rotate, free. */
void mpc_RIGHTROTATE(uint32_t x[N_PARTIES], int n, uint32_t z[N_PARTIES]);

/* Logical right-shift, free. */
void mpc_RIGHTSHIFT(uint32_t x[N_PARTIES], int n, uint32_t z[N_PARTIES]);

/* Word-level Beaver AND (one gate). */
void mpc_AND(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *broadcast, uint32_t *aux, int *gateCount);

/* 32-bit modular ADD via bit-serial carry with Beaver (one gate). */
void mpc_ADD(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *broadcast, uint32_t *aux, int *gateCount);

/* ADD with public constant K (added into party 0's share). */
void mpc_ADDK(uint32_t x[N_PARTIES], uint32_t K, uint32_t z[N_PARTIES],
              unsigned char *tapes[N_PARTIES], uint32_t *broadcast, uint32_t *aux, int *gateCount);

/* SHA-256 majority gate: z = MAJ(a, b, c). */
void mpc_MAJ(uint32_t a[N_PARTIES], uint32_t b[N_PARTIES], uint32_t c[N_PARTIES],
             uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *broadcast, uint32_t *aux, int *gateCount);

/* SHA-256 choice gate: z = CH(e, f, g) = (e AND (f XOR g)) XOR g. */
void mpc_CH(uint32_t e[N_PARTIES], uint32_t f[N_PARTIES], uint32_t g[N_PARTIES],
            uint32_t z[N_PARTIES],
            unsigned char *tapes[N_PARTIES], uint32_t *broadcast, uint32_t *aux, int *gateCount);

/* N-party SHA-256 compression over numBits of input.
 * inputs[i]  — party i's share of the message (srcBytes bytes).
 * results[i] — party i's 32-byte digest share (output). */
void mpc_sha256(unsigned char *inputs[N_PARTIES], int numBits,
                unsigned char *results[N_PARTIES],
                unsigned char *tapes[N_PARTIES],
                uint32_t *broadcast, uint32_t *aux, int *gateCount);

#endif /* FUNCTIONS_H */
