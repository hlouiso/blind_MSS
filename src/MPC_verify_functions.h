#ifndef MPC_VERIFY_FUNCTIONS_H
#define MPC_VERIFY_FUNCTIONS_H

#include "shared.h"

#include <stdint.h>
#include <string.h>

/* KKW verify-side gate functions.
 *
 * All functions operate on (N_PARTIES-1) revealed party shares, indexed by
 * "slot" j = 0..N_PARTIES-2, where slot j corresponds to original party
 *   orig(j, e) = (j < e) ? j : j+1
 * Party 0 gets the Beaver correction (aux[g]) and the da*db bias term.
 *
 * Parameters:
 *   x[], y[]    — revealed input shares  [N_PARTIES-1]
 *   z[]         — revealed output shares [N_PARTIES-1]  (written)
 *   tapes[]     — expanded Beaver tapes for revealed parties [N_PARTIES-1]
 *   e           — hidden party index
 *   broadcast   — da/db array from proof: broadcast[2g]=da, [2g+1]=db
 *   aux         — Beaver correction array from proof: aux[g]
 *   gateCount   — current gate index (incremented by each call)
 */

void mpc_AND_verify(uint32_t x[N_PARTIES-1], uint32_t y[N_PARTIES-1],
                    uint32_t z[N_PARTIES-1],
                    unsigned char *tapes[N_PARTIES-1], int e,
                    const uint32_t *broadcast, const uint32_t *aux,
                    int *gateCount);

void mpc_ADD_verify(uint32_t x[N_PARTIES-1], uint32_t y[N_PARTIES-1],
                    uint32_t z[N_PARTIES-1],
                    unsigned char *tapes[N_PARTIES-1], int e,
                    const uint32_t *broadcast, const uint32_t *aux,
                    int *gateCount);

/* Linear gates — same as prove-side but for N-1 parties. */
void mpc_XOR_v(uint32_t x[N_PARTIES-1], uint32_t y[N_PARTIES-1],
               uint32_t z[N_PARTIES-1]);

void mpc_NEGATE_v(uint32_t x[N_PARTIES-1], uint32_t z[N_PARTIES-1]);

void mpc_RIGHTROTATE_v(uint32_t x[N_PARTIES-1], int n, uint32_t z[N_PARTIES-1]);

void mpc_RIGHTSHIFT_v(uint32_t x[N_PARTIES-1], int n, uint32_t z[N_PARTIES-1]);

void mpc_MAJ_verify(uint32_t a[N_PARTIES-1], uint32_t b[N_PARTIES-1],
                    uint32_t c[N_PARTIES-1], uint32_t z[N_PARTIES-1],
                    unsigned char *tapes[N_PARTIES-1], int e,
                    const uint32_t *broadcast, const uint32_t *aux,
                    int *gateCount);

void mpc_CH_verify(uint32_t e_sh[N_PARTIES-1], uint32_t f[N_PARTIES-1],
                   uint32_t g[N_PARTIES-1], uint32_t z[N_PARTIES-1],
                   unsigned char *tapes[N_PARTIES-1], int e,
                   const uint32_t *broadcast, const uint32_t *aux,
                   int *gateCount);

void mpc_sha256_verify(unsigned char *inputs[N_PARTIES-1], int numBits,
                       unsigned char *results[N_PARTIES-1],
                       unsigned char *tapes[N_PARTIES-1], int e,
                       const uint32_t *broadcast, const uint32_t *aux,
                       int *gateCount);

#endif /* MPC_VERIFY_FUNCTIONS_H */
