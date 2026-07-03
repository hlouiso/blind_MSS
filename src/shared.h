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

/* TAPE_SIZE = 3 * ySize * 4 (u[], v[], w_raw[] blocks, each ySize uint32_t). */
extern const int TAPE_SIZE;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1u << (i)) : (x) & (~(1u << (i)))

/* SHA-256 IV and round constants */
extern const uint32_t hA[8];
extern const uint32_t k[64];

/* ── Per-round commitment data ─────────────────────────────────────────── */
/* Everything the verifier needs is bound in h* before the challenge:
 *   seeds+aux via h_j, broadcasts (hence x-shares) via h'_j, yp via h_out_j.
 * A per-party online commitment H(seed||x||yp) would be redundant: the
 * verifier recomputes every input to it from proof data, so a prover can
 * always satisfy it and it adds no binding beyond h_j/h'/h_out. */
typedef struct
{
    uint32_t yp[N_PARTIES][8];      /* circuit output shares */
    /* h'_j = H2(broadcast || msgs_0 || … || msgs_{N-1}).
     * Committed in h* = H(H(h_j), H(h'_j)) before challenge derivation. */
    unsigned char h_prime[32];
} a;

/* ── Per-round revealed proof data ─────────────────────────────────────── */
typedef struct
{
    unsigned char ke[N_PARTIES - 1][SEED_SIZE]; /* revealed party seeds */
    /* Party (N-1)'s witness-offset input share (INPUT_LEN bytes, malloc'd).
     * Present in the proof only when the hidden party e != N-1; the other
     * revealed parties' shares are re-derived from their seeds via expand_xshare. */
    unsigned char *x_offset;
    uint32_t *aux;                              /* ySize uint32_t, malloc'd */
    /* Hidden party's per-gate (da_e, db_e) pairs: 2*ySize uint32_t, malloc'd.
     * msgs_e[2*g] = da_e[g], msgs_e[2*g+1] = db_e[g]. */
    uint32_t *msgs_e;
    /* Preprocessing commitment to hidden party: com_{j,e}. */
    unsigned char com_hidden[32];
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
 * aux[g] = (XOR_i u_i[g]) AND (XOR_i v_i[g]) XOR (XOR_i w_i[g]), with bit 31
 * forced to 0 on ADD gates (see compute_aux_from_seeds in shared.c).
 * Uses the fast tape-only path; does NOT re-run the full circuit.
 */
void compute_aux_from_seeds(unsigned char seeds[N_PARTIES][SEED_SIZE],
                             uint32_t *aux_out);

/* Gate-type recorder: when non-NULL, mpc_AND/mpc_ADD write the type of each
 * Beaver gate (0 = AND, 1 = ADD) at index g into this array. Used once to build
 * the gate-type table that drives the fast aux path. NULL in normal operation. */
extern uint8_t *g_gate_type_rec;

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

/**
 * Legacy Fiat–Shamir (single-level, used by test_roundtrip H3 range check).
 * Produces es[0..s-1] ∈ {0..N_PARTIES-1}.
 */
void H3(const unsigned char message_digest[32], const uint32_t pubout[8],
        a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS], int s, int *es);

/* ── KKW online-transcript helpers ─────────────────────────────────────── */

/* Compute h'_j = H(da_db_all) where da_db_all is N×2×ySize uint32_t:
 *   da_db_all[i*2*ySize + 2*g]   = da_i[g] = x_i[g] XOR u_i[g]
 *   da_db_all[i*2*ySize + 2*g+1] = db_i[g] = y_i[g] XOR v_i[g] */
void compute_h_prime(const uint32_t *da_db_all, unsigned char h_prime[32]);

/* Extract party e's (da_e, db_e) pairs from da_db_all into msgs_e_out (2*ySize). */
void compute_msgs_e(int e, const uint32_t *da_db_all, uint32_t *msgs_e_out);

/* Recompute h'_j on the verify side.
 * per_party_da_db: (N-1)×2×ySize array filled during circuit execution.
 * msgs_e:         2*ySize array from proof (hidden party's (da_e, db_e)). */
void recompute_h_prime_verify(int e,
                               const uint32_t *per_party_da_db,
                               const uint32_t *msgs_e,
                               unsigned char h_prime_out[32]);

/* ── Allocation helpers (for online rounds) ─────────────────────────────── */

int alloc_structures_prove(unsigned char seeds[NUM_ROUNDS][N_PARTIES][SEED_SIZE],
                           unsigned char *x_shares[NUM_ROUNDS][N_PARTIES],
                           a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

void free_structures_prove(unsigned char *x_shares[NUM_ROUNDS][N_PARTIES],
                           a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

int alloc_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);
void free_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);


/* ── Tape accessors ─────────────────────────────────────────────────────── */

static inline uint32_t tape_get32(const unsigned char *tape, int pos)
{
    uint32_t v;
    memcpy(&v, tape + pos, 4);
    return v;
}

static inline uint32_t tape_u(const unsigned char *tape, int g) { return tape_get32(tape, g * 4); }
static inline uint32_t tape_v(const unsigned char *tape, int g) { return tape_get32(tape, ySize * 4 + g * 4); }
static inline uint32_t tape_w(const unsigned char *tape, int g) { return tape_get32(tape, 2 * ySize * 4 + g * 4); }

#endif /* SHARED_H */
