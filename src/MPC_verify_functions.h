#ifndef MPC_VERIFY_FUNCTIONS_H
#define MPC_VERIFY_FUNCTIONS_H

#include "shared.h"
#include <stdint.h>

/* ── KKW masked-values online phase (verifier side) ──────────────────────
 *
 * The verifier re-runs the online phase with the N-1 revealed parties in
 * slot order (slot j = original party (j < e) ? j : j+1) and completes each
 * gate's public masked output with the hidden party's broadcast from the
 * proof (msgs_e[g]).  Revealed slots' broadcast streams are collected into
 * s_slots[j*ySize + g] for the h'_j recomputation. */

/* Masked word, verifier view: public value + N-1 revealed mask shares. */
typedef struct { uint32_t h; uint32_t l[N_PARTIES - 1]; } mwv;

/* ── Linear gates (free) ─────────────────────────────────────────────────── */

static inline void mwv_const(uint32_t K, mwv *z)
{
    z->h = K;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = 0;
}

static inline void mpc_XOR_v(const mwv *x, const mwv *y, mwv *z)
{
    z->h = x->h ^ y->h;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = x->l[j] ^ y->l[j];
}

static inline void mpc_NEGATE_v(const mwv *x, mwv *z)
{
    z->h = ~x->h;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = x->l[j];
}

static inline void mpc_RIGHTROTATE_v(const mwv *x, int n, mwv *z)
{
    z->h = RIGHTROTATE(x->h, n);
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = RIGHTROTATE(x->l[j], n);
}

static inline void mpc_RIGHTSHIFT_v(const mwv *x, int n, mwv *z)
{
    z->h = x->h >> n;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = x->l[j] >> n;
}

/* ── Nonlinear gates ────────────────────────────────────────────────────── */

void mpc_AND_verify(const mwv *x, const mwv *y, mwv *z,
                    unsigned char *tapes[N_PARTIES - 1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *s_slots, int *gateCount);

void mpc_ADD_verify(const mwv *x, const mwv *y, mwv *z,
                    unsigned char *tapes[N_PARTIES - 1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *s_slots, int *gateCount);

/* Verify-side BLAKE3 compression / tweakable hash — mirror of the prove
 * side (MPC_prove_functions.h); NULL lam arrays mean all-public bytes. */
void mpc_blake3_compress_verify(const mwv cv[8], const mwv m[16],
                                uint32_t block_len, uint32_t flags, mwv out[8],
                                unsigned char *tapes[N_PARTIES - 1], int e,
                                const uint32_t *msgs_e, const uint32_t *aux,
                                uint32_t *s_slots, int *gateCount);

void mpc_blake3_th_verify(const unsigned char *dom_pub,
                          unsigned char *dom_lam[N_PARTIES - 1], int dom_len,
                          const unsigned char *data_pub,
                          unsigned char *data_lam[N_PARTIES - 1], int data_len,
                          unsigned char *out_pub,
                          unsigned char *out_lam[N_PARTIES - 1], int out_len,
                          unsigned char *tapes[N_PARTIES - 1], int e,
                          const uint32_t *msgs_e, const uint32_t *aux,
                          uint32_t *s_slots, int *gateCount);

#endif /* MPC_VERIFY_FUNCTIONS_H */
