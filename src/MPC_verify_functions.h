#ifndef MPC_VERIFY_FUNCTIONS_H
#define MPC_VERIFY_FUNCTIONS_H

#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY);

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY);

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]);

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]);

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY);

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1,
                  unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY);

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]);

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]);

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY);

#endif // MPC_VERIFY_FUNCTIONS_H