#ifndef MPC_VERIFY_FUNCTIONS_H
#define MPC_VERIFY_FUNCTIONS_H

#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * AND gate (verify, MPC-in-the-head).
 * Recomputes the missing view e output, writes ve.y[*countY] and z[0], sets z[1] from ve1,
 * and advances *randCount / *countY. No return value.
 *
 * @param x Two 32-bit shares of input X: x[0] for ve, x[1] for ve1.
 * @param y Two 32-bit shares of input Y: y[0] for ve, y[1] for ve1.
 * @param z Output shares written by the function: z[0] (ve), z[1] (ve1).
 * @param ve Reconstructed view e (write ve.y[*countY]).
 * @param ve1 Open view e+1 (read ve1.y[*countY] if needed).
 * @param randomness Random tapes for the two opened views.
 * @param randCount Index into the random tapes (updated).
 * @param countY Index into ve.y (incremented).
 */
void mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char *randomness[2],
                    int *randCount, int *countY);

/**
 * ADD gate mod 2^32 (verify).
 * Recomputes carry/output for view e, writes ve.y[*countY] and the shared sum in z,
 * and advances *randCount / *countY.
 */
void mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char *randomness[2],
                    int *randCount, int *countY);

/**
 * RightRotate by i on two opened shares. No randomness/views consumed.
 * Writes z = ROTR_i(x) share-wise.
 */
void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]);

/**
 * Logical RightShift by i on two opened shares. No randomness/views consumed.
 * Writes z = x >> i share-wise.
 */
void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]);

/**
 * MAJ gate (verify): z = MAJ(a,b,c).
 * Uses local XORs + a secure AND; records the gate output in ve.y[*countY].
 */
void mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[2], View ve, View ve1,
                    unsigned char *randomness[2], int *randCount, int *countY);

/**
 * CH gate (verify): z = (e & f) ^ (~e & g).
 * Uses local XORs + a secure AND; records the gate output in ve.y[*countY].
 */
void mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1,
                   unsigned char *randomness[2], int *randCount, int *countY);

/** XOR on two opened shares. Writes z = x ^ y. */
void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]);

/** Bitwise NOT on two opened shares. Writes z = ~x. */
void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]);

/**
 * SHA-256 replay from two opened views.
 * - inputs[0..1]: message shares over numBits; padding is applied internally.
 * - results[0..1]: output digest shares (32 bytes each).
 * - Consumes randomness via secure gates and appends each costly-gate output to ve.y[*countY].
 * This function only replays; the caller performs comparisons against full protocol announced outputs.
 */
void mpc_sha256_verify(unsigned char *inputs[2], int numBits, unsigned char *results[2], int *randCount, int *countY,
                       unsigned char *randomness[2], View ve, View ve1);

#endif // MPC_VERIFY_FUNCTIONS_H