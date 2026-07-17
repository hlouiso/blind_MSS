#ifndef SHARED_H
#define SHARED_H

#include "blake3.h"
#include "xmss.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── KKW parameters ──────────────────────────────────────────────────────────
 * Override N_PARTIES at build time: make N=4  (or -DN_PARTIES=4).
 * Supported: N a multiple of 4 ∈ {4, 8, 12, …, 32} ∪ {64, 128, 256}.
 *
 * M_KKW    : total instances the prover evaluates (preprocessing + online).
 * NUM_ROUNDS: τ — online instances included in the proof.
 *
 * Soundness formula (KKW cut-and-choose, see Katz-Kolesnikov-Wang 2018):
 *   ε = max_{0≤s≤τ} [C(M-s, τ-s) / C(M, τ)] · N^{-(τ-s)} ≤ 2^{-(SEC-W)}
 * Adversary strategy: corrupt s preprocessing instances (forces output=pubout
 * for any hidden party e), and predict party e for the τ-s honest online
 * instances (probability 1/N each). The s corrupted instances must all land
 * in the online set (probability C(M-s,τ-s)/C(M,τ)); the offline check
 * catches any corrupted instance in the opened set via aux recomputation.
 * Parameters computed by src/params.py (exact minimum M for each (N,τ)).
 * τ = ⌈(SEC-W)/log₂N⌉+1.  M_KKW only affects pass-1 and proof offline section.
 *
 * The three KKW binding requirements are all implemented: the preprocessing
 * cut-and-choose (h_j commits seeds+aux, recomputed for opened instances),
 * the online-transcript commitment (h'_j commits d, every broadcast stream
 * and the r_j randomiser), and the binding of msgs_e/aux to the challenge
 * (both feed the h'_j / com_{j,0} recomputations checked against h*). */

#ifndef N_PARTIES
#define N_PARTIES 4
#endif

/* ── Security target (classical vs. post-quantum), make SEC=<128|256> ────────
 * SEC_TARGET = 128 (default): ε ≤ 2^{-(128-W)} — KKW Table 1's ρ=128 column,
 * a CLASSICAL 128-bit Fiat–Shamir soundness bound.
 * SEC_TARGET = 256: ε ≤ 2^{-(256-W)} — the ρ=256 column KKW themselves use
 * for post-quantum claims (§3.2: parameters set so ε ≤ 2^-256).  A quantum
 * forger Grover-searches ctr over the combined predicate [W zero bits ∧
 * cheatable challenge], at cost sqrt(1/(2^-W·ε)) ≥ 2^128 ⟹ ε ≤ 2^-(256-W):
 * grinding still buys exactly W bits, off a 2λ baseline.  Caveats (also for
 * the write-up): Fiat–Shamir has no general quantum security proof (KKW §3.1
 * mention Unruh's transform), and whether the 2λ doubling is truly necessary
 * is debated (FAEST, refined Grover-on-FS bounds) — 2λ is the conservative
 * margin, not a theorem. */
#ifndef SEC_TARGET
#define SEC_TARGET 128
#endif

/* ── Grinding (FAESTER-style proof of work, eprint 2024/490 §4) ──────────────
 * GRIND_W: the Fiat–Shamir challenge hash must end in GRIND_W zero bits; the
 * prover greps for a counter ctr achieving this (~2^W short hashes, one-time).
 * Every forgery attempt pays the same 2^W, so the cut-and-choose target can
 * be relaxed to 2^{-(SEC-W)} — total attack cost stays 2^SEC (per RO query:
 * P[W zero bits AND cheatable challenge] = 2^{-W} · 2^{-(SEC-W)} = 2^{-SEC}).
 * τ = ⌈(SEC-W)/log₂N⌉ + 1; M from params.py with target SEC-W.
 * Override at build time: make W=<0|16|24>. */
#ifndef GRIND_W
#define GRIND_W 16
#endif
/* The grinding counter is a uint32_t, serialized as 4 bytes in the FS input
 * and the proof: the design caps grinding at 32 bits.  Expected work is 2^W
 * tries, so W must stay well below 32 or the honest prover may exhaust the
 * counter space (at W=32, P[no solution in 2^32] ≈ 37%). */
_Static_assert(GRIND_W >= 0 && GRIND_W < 30, "GRIND_W must fit the uint32 grinding counter");

#if SEC_TARGET == 128

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

#elif SEC_TARGET == 256

#if GRIND_W == 0
#  if   N_PARTIES == 4
#    define M_KKW 456
#    define NUM_ROUNDS 129
#  elif N_PARTIES == 8
#    define M_KKW 533
#    define NUM_ROUNDS 87
#  elif N_PARTIES == 12
#    define M_KKW 634
#    define NUM_ROUNDS 73
#  elif N_PARTIES == 16
#    define M_KKW 781
#    define NUM_ROUNDS 65
#  elif N_PARTIES == 20
#    define M_KKW 799
#    define NUM_ROUNDS 61
#  elif N_PARTIES == 24
#    define M_KKW 951
#    define NUM_ROUNDS 57
#  elif N_PARTIES == 28
#    define M_KKW 957
#    define NUM_ROUNDS 55
#  elif N_PARTIES == 32
#    define M_KKW 1024
#    define NUM_ROUNDS 53
#  elif N_PARTIES == 64
#    define M_KKW 1662
#    define NUM_ROUNDS 44
#  elif N_PARTIES == 128
#    define M_KKW 2540
#    define NUM_ROUNDS 38
#  elif N_PARTIES == 256
#    define M_KKW 4547
#    define NUM_ROUNDS 33
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#elif GRIND_W == 16
#  if   N_PARTIES == 4
#    define M_KKW 426
#    define NUM_ROUNDS 121
#  elif N_PARTIES == 8
#    define M_KKW 524
#    define NUM_ROUNDS 81
#  elif N_PARTIES == 12
#    define M_KKW 624
#    define NUM_ROUNDS 68
#  elif N_PARTIES == 16
#    define M_KKW 726
#    define NUM_ROUNDS 61
#  elif N_PARTIES == 20
#    define M_KKW 767
#    define NUM_ROUNDS 57
#  elif N_PARTIES == 24
#    define M_KKW 825
#    define NUM_ROUNDS 54
#  elif N_PARTIES == 28
#    define M_KKW 977
#    define NUM_ROUNDS 51
#  elif N_PARTIES == 32
#    define M_KKW 1071
#    define NUM_ROUNDS 49
#  elif N_PARTIES == 64
#    define M_KKW 1645
#    define NUM_ROUNDS 41
#  elif N_PARTIES == 128
#    define M_KKW 2193
#    define NUM_ROUNDS 36
#  elif N_PARTIES == 256
#    define M_KKW 4182
#    define NUM_ROUNDS 31
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#elif GRIND_W == 24
#  if   N_PARTIES == 4
#    define M_KKW 411
#    define NUM_ROUNDS 117
#  elif N_PARTIES == 8
#    define M_KKW 477
#    define NUM_ROUNDS 79
#  elif N_PARTIES == 12
#    define M_KKW 585
#    define NUM_ROUNDS 66
#  elif N_PARTIES == 16
#    define M_KKW 699
#    define NUM_ROUNDS 59
#  elif N_PARTIES == 20
#    define M_KKW 751
#    define NUM_ROUNDS 55
#  elif N_PARTIES == 24
#    define M_KKW 819
#    define NUM_ROUNDS 52
#  elif N_PARTIES == 28
#    define M_KKW 850
#    define NUM_ROUNDS 50
#  elif N_PARTIES == 32
#    define M_KKW 933
#    define NUM_ROUNDS 48
#  elif N_PARTIES == 64
#    define M_KKW 1470
#    define NUM_ROUNDS 40
#  elif N_PARTIES == 128
#    define M_KKW 2035
#    define NUM_ROUNDS 35
#  elif N_PARTIES == 256
#    define M_KKW 4002
#    define NUM_ROUNDS 30
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#else
#  error "Unsupported GRIND_W: run src/params.py and add a (τ,M) table"
#endif

#else
#  error "Unsupported SEC_TARGET: 128 or 256 (run src/params.py for tables)"
#endif

_Static_assert(N_PARTIES >= 4 && N_PARTIES <= 256, "N_PARTIES must be 4..256");
_Static_assert(NUM_ROUNDS < M_KKW, "NUM_ROUNDS must be < M_KKW");

#define SEED_SIZE 32
extern const int ySize;     /* gate count, measured by test_circuit */
extern const int INPUT_LEN; /* witness byte length = W_END = 2762 */

/* Compile-time parameters baked into libblindmss.a, exported so programs can
 * detect a flag mismatch at startup: a binary built with a different
 * N_PARTIES than the library corrupts memory (buffer sizes derive from it),
 * and a different (M, τ) silently breaks the protocol logic.  `make test`
 * always rebuilds consistently; this guards manual links. */
extern const int lib_n_parties, lib_m_kkw, lib_num_rounds;
#define ASSERT_LIB_PARAMS() do { \
    if (lib_n_parties != N_PARTIES || lib_m_kkw != M_KKW || \
        lib_num_rounds != NUM_ROUNDS) { \
        fprintf(stderr, "libblindmss parameter mismatch: binary N=%d M=%d " \
                "tau=%d vs library N=%d M=%d tau=%d (rebuild with the same " \
                "N/W/SEC flags)\n", N_PARTIES, M_KKW, NUM_ROUNDS, \
                lib_n_parties, lib_m_kkw, lib_num_rounds); \
        exit(1); \
    } } while (0)

/* TAPE_SIZE = 2 * ySize * 4: per gate, each party's share of the fresh output
 * mask λ_z (lam block) and of the input-mask product λ_x·λ_y (prod block). */
extern const int TAPE_SIZE;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1u << (i)) : (x) & (~(1u << (i)))

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
 * Compute com_{j,party} = Th("KKWppcom", party_byte || seed || [aux if party==0]).
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
 * If h_out32 is non-NULL, also writes h_out_j = H(yp[0..N-1]) — the yp
 * output-mask shares are seed-derived like aux, so the same zero-publics run
 * reproduces them and the proof need not carry h_out_j for opened instances.
 */
void compute_aux_from_seeds(unsigned char seeds[N_PARTIES][SEED_SIZE],
                             uint32_t *aux_out, unsigned char *h_out32);

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

/* ── KKW-layer hashing: BLAKE3 Th domains ────────────────────────────────────
 * Since the full-BLAKE3 migration (KKW9) every KKW-layer hash is the tweakable
 * hash Th (blake3.h) under one of the fixed ASCII domains below, so the whole
 * scheme rests on a single hash assumption (the BLAKE3 compression function).
 * Domain rules (frozen by test_blake3): pairwise distinct, never 16 bytes long
 * (the WOTS chain-step domain is a witness-chosen 16-byte node), and distinct
 * from the XMSS (16/20/21 B) and HM ("HMy"/"HMd", 3 B) call-site families —
 * all tags here are 5..9 bytes. */
#define KKW_DOM_PPCOM  "KKWppcom"  /* per-party preproc commitment: party‖seed[‖aux] */
#define KKW_DOM_HJ     "KKWhj"     /* per-instance commitment h_j = Th(com_0..com_{N-1}) */
#define KKW_DOM_HPRIME "KKWhprime" /* h'_j = Th(d ‖ s_0..s_{N-1} ‖ r_j)         */
#define KKW_DOM_HOUT   "KKWhout"   /* h_out_j = Th(yp[0..N-1])                  */
#define KKW_DOM_HSTAR1 "KKWhstar1" /* Th over the M-entry h_j table             */
#define KKW_DOM_HSTAR2 "KKWhstar2" /* Th over the M-entry h'_j table            */
#define KKW_DOM_HSTAR3 "KKWhstar3" /* Th over the M-entry h_out_j table         */
#define KKW_DOM_HSTAR  "KKWhstar"  /* h* = Th(H1 ‖ H2 ‖ H3)                     */
#define KKW_DOM_FS     "KKWfs"     /* Fiat–Shamir prefix h_pre                  */
#define KKW_DOM_GRIND  "KKWgrind"  /* seed_FS = Th(h_pre ‖ ctr), grinding target */
#define KKW_DOM_PRG    "KKWprg"    /* challenge-expansion PRG fill              */
#define KKW_DOM_MHAT   "KKWmhat"   /* public message digest m̂ = Th(m)           */

/* One-shot / incremental Th under a KKW_DOM_* string literal, 32-byte output.
 * The "" forces a literal so sizeof gives the tag length. */
#define KKW_TH(dom, data, len, out32) \
    blake3_th((const uint8_t *)"" dom, sizeof(dom) - 1, \
              (const uint8_t *)(data), (len), (out32), 32)
#define KKW_TH_INIT(ctx, dom) \
    blake3_th_init((ctx), (const uint8_t *)"" dom, sizeof(dom) - 1)

/* ── KKW online-transcript helpers ─────────────────────────────────────── */

/* h'_j = Th("KKWhprime", d || s_all || r_j) where d is the masked witness (INPUT_LEN bytes),
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
