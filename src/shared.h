#ifndef SHARED_H
#define SHARED_H

#include "xmss.h"
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── KKW parameters (ρ=128) ──────────────────────────────────────────────────
 * Override N_PARTIES at build time: make N=4  (or -DN_PARTIES=4).
 * Supported: N a multiple of 4 ∈ {4, 8, 12, …, 32} ∪ {64, 128, 256}.
 *
 * M_KKW    : total instances the prover evaluates (preprocessing + online).
 * NUM_ROUNDS: τ — online instances included in the proof.
 *
 * Soundness formula (KKW cut-and-choose, see Katz-Kolesnikov-Wang 2018):
 *   ε = max_{0≤s≤τ} [C(M-s, τ-s) / C(M, τ)] · N^{-(τ-s)} ≤ 2^{-128}
 * Adversary strategy: corrupt s preprocessing instances (forces output=pubout
 * for any hidden party e), and predict party e for the τ-s honest online
 * instances (probability 1/N each). The s corrupted instances must all land
 * in the online set (probability C(M-s,τ-s)/C(M,τ)); the offline check
 * catches any corrupted instance in the opened set via aux recomputation.
 * Parameters computed by src/params.py (exact minimum M for each (N,τ)).
 * τ = ⌈128/log₂N⌉+1.  M_KKW only affects pass-1 and proof offline section.
 *
 * Trou 1 (preprocessing cut-and-choose): IMPLEMENTED.
 * Trou 2 (h'_j commitment): IMPLEMENTED.
 * Trou 3 (H3 binding msgs_e+aux): IMPLEMENTED. */

#ifndef N_PARTIES
#define N_PARTIES 4
#endif

/* ── Grinding (FAESTER-style proof of work, eprint 2024/490 §4) ──────────────
 * GRIND_W: the Fiat–Shamir challenge hash must end in GRIND_W zero bits; the
 * prover greps for a counter ctr achieving this (~2^W short hashes, one-time).
 * Every forgery attempt pays the same 2^W, so the cut-and-choose target can
 * be relaxed to 2^{-(128-W)} — total attack cost stays 2^128 (per RO query:
 * P[W zero bits AND cheatable challenge] = 2^{-W} · 2^{-(128-W)} = 2^{-128}).
 * τ = ⌈(128-W)/log₂N⌉ + 1; M from params.py with target 128-W.
 * Override at build time: make W=<0|16|24>. */
#ifndef GRIND_W
#define GRIND_W 16
#endif

#if GRIND_W == 0
#  if   N_PARTIES == 4
#    define M_KKW 218
#    define NUM_ROUNDS 65
#  elif N_PARTIES == 8
#    define M_KKW 252
#    define NUM_ROUNDS 44
#  elif N_PARTIES == 12
#    define M_KKW 295
#    define NUM_ROUNDS 37
#  elif N_PARTIES == 16
#    define M_KKW 352
#    define NUM_ROUNDS 33
#  elif N_PARTIES == 20
#    define M_KKW 366
#    define NUM_ROUNDS 31
#  elif N_PARTIES == 24
#    define M_KKW 425
#    define NUM_ROUNDS 29
#  elif N_PARTIES == 28
#    define M_KKW 433
#    define NUM_ROUNDS 28
#  elif N_PARTIES == 32
#    define M_KKW 462
#    define NUM_ROUNDS 27
#  elif N_PARTIES == 64
#    define M_KKW 631
#    define NUM_ROUNDS 23
#  elif N_PARTIES == 128
#    define M_KKW 916
#    define NUM_ROUNDS 20
#  elif N_PARTIES == 256
#    define M_KKW 1794
#    define NUM_ROUNDS 17
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#elif GRIND_W == 16
#  if   N_PARTIES == 4
#    define M_KKW 189
#    define NUM_ROUNDS 57
#  elif N_PARTIES == 8
#    define M_KKW 209
#    define NUM_ROUNDS 39
#  elif N_PARTIES == 12
#    define M_KKW 237
#    define NUM_ROUNDS 33
#  elif N_PARTIES == 16
#    define M_KKW 301
#    define NUM_ROUNDS 29
#  elif N_PARTIES == 20
#    define M_KKW 330
#    define NUM_ROUNDS 27
#  elif N_PARTIES == 24
#    define M_KKW 327
#    define NUM_ROUNDS 26
#  elif N_PARTIES == 28
#    define M_KKW 344
#    define NUM_ROUNDS 25
#  elif N_PARTIES == 32
#    define M_KKW 374
#    define NUM_ROUNDS 24
#  elif N_PARTIES == 64
#    define M_KKW 573
#    define NUM_ROUNDS 20
#  elif N_PARTIES == 128
#    define M_KKW 963
#    define NUM_ROUNDS 17
#  elif N_PARTIES == 256
#    define M_KKW 1488
#    define NUM_ROUNDS 15
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#elif GRIND_W == 24
#  if   N_PARTIES == 4
#    define M_KKW 175
#    define NUM_ROUNDS 53
#  elif N_PARTIES == 8
#    define M_KKW 199
#    define NUM_ROUNDS 36
#  elif N_PARTIES == 12
#    define M_KKW 211
#    define NUM_ROUNDS 31
#  elif N_PARTIES == 16
#    define M_KKW 276
#    define NUM_ROUNDS 27
#  elif N_PARTIES == 20
#    define M_KKW 259
#    define NUM_ROUNDS 26
#  elif N_PARTIES == 24
#    define M_KKW 314
#    define NUM_ROUNDS 24
#  elif N_PARTIES == 28
#    define M_KKW 335
#    define NUM_ROUNDS 23
#  elif N_PARTIES == 32
#    define M_KKW 372
#    define NUM_ROUNDS 22
#  elif N_PARTIES == 64
#    define M_KKW 474
#    define NUM_ROUNDS 19
#  elif N_PARTIES == 128
#    define M_KKW 823
#    define NUM_ROUNDS 16
#  elif N_PARTIES == 256
#    define M_KKW 1339
#    define NUM_ROUNDS 14
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#else
#  error "Unsupported GRIND_W: run src/params.py and add a (τ,M) table"
#endif

_Static_assert(N_PARTIES >= 4 && N_PARTIES <= 256, "N_PARTIES must be 4..256");
_Static_assert(NUM_ROUNDS < M_KKW, "NUM_ROUNDS must be < M_KKW");

#define SEED_SIZE 32
extern const int ySize;     /* gate count, measured by test_circuit */
extern const int INPUT_LEN; /* witness byte length = W_END = 2762 */

/* TAPE_SIZE = 2 * ySize * 4: per gate, each party's share of the fresh output
 * mask λ_z (lam block) and of the input-mask product λ_x·λ_y (prod block). */
extern const int TAPE_SIZE;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1u << (i)) : (x) & (~(1u << (i)))

/* SHA-256 IV and round constants */
extern const uint32_t hA[8];
extern const uint32_t k[64];

/* ── Per-round commitment data ─────────────────────────────────────────── */
/* Everything the verifier needs is bound in h* before the challenge:
 *   seeds+aux via h_j, masked witness + broadcasts via h'_j, output-mask
 *   shares via h_out_j. */
typedef struct
{
    /* Per-party shares of the output-wire masks λ_out (masked-values online
     * phase): real output = ẑ_out XOR (XOR_i yp[i]). */
    uint32_t yp[N_PARTIES][8];
    /* h'_j = H(d || s_0 || … || s_{N-1} || r_j) — masked witness and every
     * party's per-gate broadcast stream, blinded by the per-instance
     * randomiser r_j (KKW Fig. 2).  Committed in h* before the challenge. */
    unsigned char h_prime[32];
} a;

/* ── Per-round revealed proof data ─────────────────────────────────────── */
typedef struct
{
    unsigned char ke[N_PARTIES - 1][SEED_SIZE]; /* revealed party seeds */
    /* Masked witness d = witness XOR λ_w (INPUT_LEN bytes, malloc'd).
     * Public: always in the proof; λ_w shares are all seed-derived. */
    unsigned char *x_offset;
    uint32_t *aux;                              /* ySize uint32_t, malloc'd */
    /* Hidden party's per-gate broadcast words s_e[g]: ySize uint32_t. */
    uint32_t *msgs_e;
    /* Preprocessing commitment to hidden party: com_{j,e}. */
    unsigned char com_hidden[32];
    /* Per-instance commitment randomiser r_j: revealed only for online
     * instances (j ∈ C) so the verifier can recompute h'_j.  For j ∉ C it
     * never leaves the prover, which is what makes h'_j hiding (the rest of
     * its preimage is derivable from the published seed*_j and the witness). */
    unsigned char r_j[32];
} z;

/* ── Tape / seed expansion ──────────────────────────────────────────────── */

/** AES-256-CTR: seed → TAPE_SIZE bytes of Beaver triple data (IV domain 0xA5). */
void expand_tape(const unsigned char seed[SEED_SIZE], unsigned char *tape);

/** AES-256-CTR: master seed seed* → N_PARTIES party seeds (IV domain 0xB7). */
void expand_seed_star(const unsigned char seed_star[SEED_SIZE],
                      unsigned char seeds_out[N_PARTIES][SEED_SIZE]);

/** AES-256-CTR: party seed → INPUT_LEN bytes of x_share (IV domain 0xC3). */
void expand_xshare(const unsigned char seed[SEED_SIZE], unsigned char *xshare_out);

/* ── Preprocessing commitment ───────────────────────────────────────────── */

/**
 * Compute com_{j,party} = H("ppcom" || party_byte || seed || [aux if party==0]).
 * Party 0 holds aux in our implementation (gate_msg uses it for p==0).
 */
void preproc_com_party(int party, const unsigned char seed[SEED_SIZE],
                        const uint32_t *aux,
                        unsigned char com_out[32]);

/**
 * Compute h_j = H(com_{j,0} || … || com_{j,N-1}).
 * Commits the Beaver triple seeds and aux for one KKW instance.
 */
void preproc_commit_instance(unsigned char seeds[N_PARTIES][SEED_SIZE],
                              const uint32_t *aux,
                              unsigned char h_j_out[32]);

/**
 * Compute aux from N_PARTIES seeds (for preprocessing verification).
 * aux[g] = (λ_x AND λ_y) XOR (XOR_i t_i) for gate g, where λ_x/λ_y are the
 * gate's input-wire masks.  Masks flow through the circuit, so this runs the
 * mask part of the circuit (building_views with zero public inputs; aux does
 * not depend on the witness or on public values).
 */
void compute_aux_from_seeds(unsigned char seeds[N_PARTIES][SEED_SIZE],
                             uint32_t *aux_out);

/* ── Fiat–Shamir challenge with grinding (full KKW protocol) ────────────── */

/**
 * h_pre = H(msg || pubout_be || pk_seed || nonce || h_star).
 * Hashed once; the grinding loop then costs one compression per candidate.
 */
void kkw_fs_prefix(const unsigned char msg[32], const uint32_t pubout[8],
                   const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                   const unsigned char nonce[32],
                   const unsigned char h_star[32],
                   unsigned char h_pre[32]);

/**
 * seed_FS = H(h_pre || ctr_be4).  Returns 1 iff seed_FS ends in GRIND_W zero
 * bits (the grinding predicate); the prover increments ctr until this holds,
 * the verifier checks it for the ctr carried in the proof.
 */
int kkw_fs_seed(const unsigned char h_pre[32], uint32_t ctr,
                unsigned char seed_FS[32]);

/**
 * Expand seed_FS into the KKW challenge:
 *   C_out[NUM_ROUNDS]: sorted, distinct indices in [0..M_KKW-1] — online instances.
 *   p_out[NUM_ROUNDS]: party index in [0..N_PARTIES-1] for each online instance.
 */
void kkw_fs_expand(const unsigned char seed_FS[32],
                   int C_out[NUM_ROUNDS], int p_out[NUM_ROUNDS]);

/* ── SHA-256 / commitment helpers ───────────────────────────────────────── */

/** Single-shot SHA-256. Returns 1 on success. */
int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32]);

/* ── KKW online-transcript helpers ─────────────────────────────────────── */

/* h'_j = H(d || s_all || r_j) where d is the masked witness (INPUT_LEN bytes),
 * s_all is N×ySize uint32_t (s_all[i*ySize + g] = party i's broadcast s_i[g])
 * and r_j is the 32-byte per-instance commitment randomiser.  r_j MUST be
 * independent randomness — never derived from seed*_j, which is published for
 * opened instances (that would make h'_j a deterministic, offline-checkable
 * commitment to the witness and break the ZK property). */
void compute_h_prime(const unsigned char *d_pub, const uint32_t *s_all,
                     const unsigned char r_j[32],
                     unsigned char h_prime[32]);

/* Extract party e's broadcast stream from s_all into msgs_e_out (ySize). */
void compute_msgs_e(int e, const uint32_t *s_all, uint32_t *msgs_e_out);

/* Recompute h'_j on the verify side.
 * s_slots: (N-1)×ySize array filled during circuit re-execution (slot order).
 * msgs_e:  ySize array from the proof (hidden party's stream).
 * r_j:     32-byte commitment randomiser from the proof's online section. */
void recompute_h_prime_verify(int e, const unsigned char *d_pub,
                               const uint32_t *s_slots,
                               const uint32_t *msgs_e,
                               const unsigned char r_j[32],
                               unsigned char h_prime_out[32]);

/* ── Tape accessors ─────────────────────────────────────────────────────── */

static inline uint32_t tape_get32(const unsigned char *tape, int pos)
{
    uint32_t v;
    memcpy(&v, tape + pos, 4);
    return v;
}

/* Party's share of gate g's fresh output mask λ_z (AND) / λ_r (ADD carries). */
static inline uint32_t tape_lam(const unsigned char *tape, int g) { return tape_get32(tape, g * 4); }
/* Party's share of the input-mask product λ_x·λ_y (corrected via aux). */
static inline uint32_t tape_prod(const unsigned char *tape, int g) { return tape_get32(tape, ySize * 4 + g * 4); }

#endif /* SHARED_H */
