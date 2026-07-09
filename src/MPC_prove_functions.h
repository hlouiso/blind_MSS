#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "shared.h"
#include <stdint.h>

/* ── KKW masked-values online phase (prover side) ────────────────────────
 *
 * Every wire carries a PUBLIC masked value h = value XOR mask, plus the N
 * parties' XOR-shares l[i] of the (secret) mask.  Linear gates act on h and
 * on the shares independently and are free.  Each nonlinear gate consumes
 * one tape slot per party (λ_z share + λ_x·λ_y product share, see tape_lam/
 * tape_prod) and produces ONE broadcast word s_i per party; the XOR of the
 * broadcasts is the public masked output.  aux[g] corrects party 0's product
 * share so that XOR_i t_i = λ_x AND λ_y.
 *
 * s_all (when non-NULL) collects every party's broadcast stream:
 *   s_all[i*ySize + g] = s_i[g]   — hashed into h'_j together with the
 * masked witness d.  The hidden party's stream is the proof's msgs_e. */

/* Masked word. */
typedef struct { uint32_t h; uint32_t l[N_PARTIES]; } mw;

/* ── Linear gates (free) ─────────────────────────────────────────────────── */

static inline void mw_const(uint32_t K, mw *z)
{
    z->h = K;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = 0;
}

static inline void mpc_XOR(const mw *x, const mw *y, mw *z)
{
    z->h = x->h ^ y->h;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = x->l[i] ^ y->l[i];
}

static inline void mpc_NEGATE(const mw *x, mw *z)
{
    z->h = ~x->h;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = x->l[i];
}

static inline void mpc_RIGHTROTATE(const mw *x, int n, mw *z)
{
    z->h = RIGHTROTATE(x->h, n);
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = RIGHTROTATE(x->l[i], n);
}

static inline void mpc_RIGHTSHIFT(const mw *x, int n, mw *z)
{
    z->h = x->h >> n;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = x->l[i] >> n;
}

/* ── Nonlinear gates (one tape slot + one broadcast word per party) ──────── */

/* z = x AND y. */
void mpc_AND(const mw *x, const mw *y, mw *z,
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *s_all, int *gateCount);

/* z = x + y mod 2^32 (bit-serial carries, packed in one gate slot). */
void mpc_ADD(const mw *x, const mw *y, mw *z,
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *s_all, int *gateCount);

/* z = x + K mod 2^32 for public K. */
void mpc_ADDK(const mw *x, uint32_t K, mw *z,
              unsigned char *tapes[N_PARTIES], uint32_t *aux,
              uint32_t *s_all, int *gateCount);

/* N-party BLAKE3 compression: out = first half of the output state.
 * cv/m are masked words; counter=0 and flags=0 (Th usage, see blake3.h);
 * block_len is public.  336 nonlinear gates (7 rounds x 8 G x 6 ADD). */
void mpc_blake3_compress(const mw cv[8], const mw m[16], uint32_t block_len,
                         mw out[8],
                         unsigned char *tapes[N_PARTIES], uint32_t *aux,
                         uint32_t *s_all, int *gateCount);

/* N-party tweakable hash Th(domain, data) — see blake3.h for the mode.
 * dom/data are masked byte buffers (little-endian word packing); a NULL
 * lam array means all-zero mask shares (fully public bytes).
 * dom_len <= 32, out_len <= 32. */
void mpc_blake3_th(const unsigned char *dom_pub, unsigned char *dom_lam[N_PARTIES],
                   int dom_len,
                   const unsigned char *data_pub, unsigned char *data_lam[N_PARTIES],
                   int data_len,
                   unsigned char *out_pub, unsigned char *out_lam[N_PARTIES],
                   int out_len,
                   unsigned char *tapes[N_PARTIES], uint32_t *aux,
                   uint32_t *s_all, int *gateCount);

#endif /* FUNCTIONS_H */
