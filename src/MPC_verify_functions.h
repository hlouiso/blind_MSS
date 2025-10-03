#ifndef MPC_VERIFY_FUNCTIONS_H
#define MPC_VERIFY_FUNCTIONS_H

#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Verify secure AND gate using two opened views (ve, ve1) and their random tapes.
 * Returns 0 on success, 1 on mismatch.
 */
int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char *randomness[2],
                   int *randCount, int *countY);

/**
 * Verify secure 32-bit addition (mod 2^32) gate with two opened views.
 * Returns 0 on success, 1 on mismatch.
 */
int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char *randomness[2],
                   int *randCount, int *countY);

/**
 * Right-rotate each opened 32-bit share by i bits (verification helper).
 *
 * @param x  Two-party opened shares (length 2).
 * @param i  Rotation amount (0..31).
 * @param z  Output rotated shares.
 */
void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]);

/**
 * Logical right shift by i bits (zeros in) on two opened shares (verification helper).
 *
 * @param x  Two-party opened shares.
 * @param i  Shift amount (0..31).
 * @param z  Output shifted shares.
 */
void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]);

/**
 * Verify a MAJ (majority) gate as used in SHA-256 using two opened views.
 * Checks transcript consistency against randomness and increments counters.
 *
 * @param a,b,c     Two-party opened inputs.
 * @param z         Expected gate output shares (two lanes used; array size may be 3 in header).
 * @param ve, ve1   Opened views for the revealed parties.
 * @param randomness Two random tapes for the revealed parties.
 * @param randCount  In/out randomness cursor.
 * @param countY     In/out y-transcript cursor.
 * @return 0 on success; 1 on mismatch.
 */
int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[2], View ve, View ve1,
                   unsigned char *randomness[2], int *randCount, int *countY);

/**
 * Verify SHA-256 choice function gate using two opened views.
 * Returns 0 on success, 1 on mismatch.
 */
int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1,
                  unsigned char *randomness[2], int *randCount, int *countY);

/**
 * XOR on two-party opened shares (helper for verification).
 */
void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]);

/**
 * Bitwise NOT on two-party opened shares (helper for verification).
 */
void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]);

/**
 * Verify SHA-256 evaluation transcript using two opened views and random tapes.
 * Returns 0 on success, 1 on mismatch.
 */
int mpc_sha256_verify(unsigned char *inputs[2], int numBits, unsigned char *results[2], int *randCount, int *countY,
                      unsigned char *randomness[2], View ve, View ve1);

#endif // MPC_VERIFY_FUNCTIONS_H