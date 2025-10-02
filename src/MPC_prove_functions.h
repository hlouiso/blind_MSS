#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "shared.h"

#include <stdint.h>

void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]);

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View *views[3],
             int *countY);

void mpc_NEGATE(uint32_t x[3], uint32_t z[3]);

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View *views[3],
             int *countY);

void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int *randCount, View *views[3],
              int *countY);

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]);

void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]);

void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
             View *views[3], int *countY);

void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
            View *views[3], int *countY);

void mpc_sha256(unsigned char *inputs[3], int numBits, unsigned char *randomness[3], unsigned char *results[3],
                View *views[3], int *countY, int *randCount);

#endif // FUNCTIONS_H