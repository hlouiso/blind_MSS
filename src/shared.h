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
 * Supported: N ∈ {4, 8, 16, 32, 64, 128, 256}.
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

#if   N_PARTIES == 4
#  define M_KKW      218   /* soundness 2^{-128.00}, τ=65  */
#  define NUM_ROUNDS  65
#elif N_PARTIES == 8
#  define M_KKW      252   /* soundness 2^{-128.05}, τ=44  */
#  define NUM_ROUNDS  44
#elif N_PARTIES == 16
#  define M_KKW      352   /* soundness 2^{-128.00}, τ=33  */
#  define NUM_ROUNDS  33
#elif N_PARTIES == 32
#  define M_KKW      462   /* soundness 2^{-128.03}, τ=27  */
#  define NUM_ROUNDS  27
#elif N_PARTIES == 64
#  define M_KKW      631   /* soundness 2^{-128.03}, τ=23  */
#  define NUM_ROUNDS  23
#elif N_PARTIES == 128
#  define M_KKW      916   /* soundness 2^{-128.01}, τ=20  */
#  define NUM_ROUNDS  20
#elif N_PARTIES == 256
#  define M_KKW     1794   /* soundness 2^{-128.01}, τ=17  */
#  define NUM_ROUNDS  17
#else
#  error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
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
typedef struct
{
    uint32_t yp[N_PARTIES][8];      /* circuit output shares */
    unsigned char h[N_PARTIES][32]; /* com_i = H_com(seed_i || x_i || yp_i); h[e] not in proof */
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

/* ── Fiat–Shamir challenge (full KKW protocol) ──────────────────────────── */

/**
 * Derive the KKW challenge from the global commitment h_star:
 *   C_out[NUM_ROUNDS]: sorted, distinct indices in [0..M_KKW-1] — online instances.
 *   p_out[NUM_ROUNDS]: party index in [0..N_PARTIES-1] for each online instance.
 * Uses hash-based PRG seeded by H(msg || pubout_be || pk_seed || nonce || h_star).
 * nonce is a fresh 32-byte random value generated by the prover and stored in the proof.
 */
void kkw_fiat_shamir(const unsigned char msg[32], const uint32_t pubout[8],
                     const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                     const unsigned char nonce[32],
                     const unsigned char h_star[32],
                     int C_out[NUM_ROUNDS], int p_out[NUM_ROUNDS]);

/* ── SHA-256 / commitment helpers ───────────────────────────────────────── */

/** Single-shot SHA-256. Returns 1 on success. */
int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32]);

/** Commit: H(seed || x[INPUT_LEN] || yp[8] as 32 BE bytes). */
void H_com(const unsigned char seed[SEED_SIZE], const unsigned char *x,
           const uint32_t yp[8], unsigned char hash[32]);

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
