#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "shared.h"

#include <stdint.h>

/**
 * Bitwise XOR on 3-party shared 32-bit words.
 * z[i] = x[i] ^ y[i] for i=0..2.
 */
void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]);

/**
 * Secure AND on 3-party shares using pre-shared random tapes.
 * Consumes randomness via randCount, writes gate output to z, and appends to each view->y.
 */
void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View *views[3],
             int *countY);

/**
 * Bitwise NOT on 3-party shares.
 * z[i] = ~x[i] for i=0..2.
 */
void mpc_NEGATE(uint32_t x[3], uint32_t z[3]);

/**
 * Secure 32-bit addition modulo 2^32 on 3-party shares.
 * Uses randomness for carry propagation; appends carry to views->y and advances counters.
 */
void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View *views[3],
             int *countY);

/**
 * Secure addition with a public constant: z = x + y (mod 2^32), where x is 3-party shared and y is public.
 *
 * Uses pre-shared random tapes to mask carries and appends transcript data to each view->y.
 *
 * @param x          3-party shares of the 32-bit input addend.
 * @param y          Public 32-bit constant to add.
 * @param z          3-party shares of the sum (output).
 * @param randomness Three random tapes (one per party).
 * @param randCount  In/out counter into the random tapes (bytes consumed).
 * @param views      Three MPC views; the function appends gate outputs.
 * @param countY     In/out counter for the per-view y-transcript.
 */
void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int *randCount, View *views[3],
              int *countY);

/**
 * Right-rotate each shared 32-bit word by i bits.
 * (Operates lane-wise on the 3-party shares in x, writes into z.)
 */
void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]);

/**
 * Logical right-shift by i bits (zeros shifted in) on 3-party shares.
 */
void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]);

/**
 * Majority function: z = MAJ(a,b,c) used by SHA-256 (secure MPC version).
 * Consumes randomness and records transcript in views->y.
 */
void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
             View *views[3], int *countY);

/**
 * Choice function: z = (e & (f ^ g)) ^ g, as in SHA-256 (secure MPC version).
 */
void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
            View *views[3], int *countY);

/**
 * Three-party MPC evaluation of SHA-256.
 *
 * Inputs:
 *  - inputs:    pointers to each party's input bitstring (length = numBits bits).
 *  - numBits:   number of input bits.
 *  - randomness: three random tapes used for AND/add gates.
 * Outputs:
 *  - results:   three 32-byte digests (one per party share).
 *  - views:     transcripts updated with gate outputs.
 *  - countY, randCount: advanced accordingly.
 */
void mpc_sha256(unsigned char *inputs[3], int numBits, unsigned char *randomness[3], unsigned char *results[3],
                View *views[3], int *countY, int *randCount);

#endif // FUNCTIONS_H