#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "shared.h"
#include <stdint.h>

/* ── KKW N-party prover gate functions ──────────────────────────────────
 *
 * All gate functions share the same context parameters:
 *   tapes[N_PARTIES]  — expanded Beaver triple tapes, one per party.
 *   aux               — output array [ySize]: aux[g] = Beaver correction word.
 *   da_db_all         — output array [N*2*ySize]: per-party (da_i, db_i) pairs.
 *                       da_db_all[i*2*ySize + 2*g]   = da_i[g] = x_i[g] XOR u_i[g]
 *                       da_db_all[i*2*ySize + 2*g+1] = db_i[g] = y_i[g] XOR v_i[g]
 *                       Pass NULL if per-party data is not needed.
 *   gateCount         — index of the current gate (incremented on each call).
 *
 * Beaver triple for gate g, party i: u_i[g]=tape_u, v_i[g]=tape_v, w_i[g]=tape_w.
 * Correction: aux[g] = (XOR_i u_i) AND (XOR_i v_i) XOR (XOR_i w_raw_i); party 0 applies it.
 * Online: da[g]=XOR_i da_i[g], db[g]=XOR_i db_i[g].
 *         z_i = w_i[g] XOR (da AND v_i) XOR (db AND u_i) XOR (i==0 ? da AND db : 0)
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
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *da_db_all, int *gateCount);

/* 32-bit modular ADD via bit-serial carry with Beaver (one gate). */
void mpc_ADD(uint32_t x[N_PARTIES], uint32_t y[N_PARTIES], uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *da_db_all, int *gateCount);

/* ADD with public constant K (added into party 0's share). */
void mpc_ADDK(uint32_t x[N_PARTIES], uint32_t K, uint32_t z[N_PARTIES],
              unsigned char *tapes[N_PARTIES], uint32_t *aux,
              uint32_t *da_db_all, int *gateCount);

/* SHA-256 majority gate: z = MAJ(a, b, c). */
void mpc_MAJ(uint32_t a[N_PARTIES], uint32_t b[N_PARTIES], uint32_t c[N_PARTIES],
             uint32_t z[N_PARTIES],
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *da_db_all, int *gateCount);

/* SHA-256 choice gate: z = CH(e, f, g) = (e AND (f XOR g)) XOR g. */
void mpc_CH(uint32_t e[N_PARTIES], uint32_t f[N_PARTIES], uint32_t g[N_PARTIES],
            uint32_t z[N_PARTIES],
            unsigned char *tapes[N_PARTIES], uint32_t *aux,
            uint32_t *da_db_all, int *gateCount);

/* N-party SHA-256 compression over numBits of input.
 * inputs[i]  — party i's share of the message (srcBytes bytes).
 * results[i] — party i's 32-byte digest share (output). */
void mpc_sha256(unsigned char *inputs[N_PARTIES], int numBits,
                unsigned char *results[N_PARTIES],
                unsigned char *tapes[N_PARTIES],
                uint32_t *aux, uint32_t *da_db_all, int *gateCount);

#endif /* FUNCTIONS_H */
