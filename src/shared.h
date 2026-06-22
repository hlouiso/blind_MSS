#ifndef SHARED_H
#define SHARED_H

#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── KKW parameters ────────────────────────────────────────────────────────
 * Override N_PARTIES at build time: make N=8  (or -DN_PARTIES=8).
 * Must be a power of 2 in {2,4,8,16,32,64,128,256}.
 * NUM_ROUNDS = ceil(128 / log2(N_PARTIES)) — guarantees 2^{-128} soundness.
 * SEED_SIZE  = 32 bytes per party seed.
 * TAPE_SIZE  = 3 * ySize * 4 (Beaver triple words: u, v, w_raw per gate).
 * Commitments: com_i = SHA256(seed_i || x_i || yp_i_as_bytes).
 * Proof per round: N coms + (N-1) seeds + (N-1) x-shares + yp_e
 *                + broadcast[2*ySize] + aux[ySize]. */
#ifndef N_PARTIES
#define N_PARTIES 256
#endif

/* NUM_ROUNDS = ceil(128 / log2(N_PARTIES)) — computed in shared.c via <math.h>.
 * Any N_PARTIES in [2, 256] is valid. */
_Static_assert(N_PARTIES >= 2 && N_PARTIES <= 256, "N_PARTIES must be between 2 and 256");
_Static_assert((N_PARTIES & (N_PARTIES - 1)) == 0, "N_PARTIES must be a power of 2");
extern const int NUM_ROUNDS;

#define SEED_SIZE 32
extern const int ySize;     /* gate count, measured by test_circuit */
extern const int INPUT_LEN; /* witness byte length = W_END = 2762 */

/* Tape size (Beaver triples only, no x share): 3 * ySize * 4 bytes. */
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
    unsigned char h[N_PARTIES][32]; /* com_i = H(seed_i || x_i || yp_i) */
} a;

/* ── Per-round revealed proof data ─────────────────────────────────────── */
/* Seeds are stored in slot order: ke[j] = seed of party (j < e ? j : j+1).
 * Likewise x_revealed[j * INPUT_LEN] for the same mapping.
 * broadcast[2*g]   = da[g],  broadcast[2*g+1] = db[g]  (per gate g).
 * aux[g]           = Beaver correction word for gate g (applied to party 0). */
typedef struct
{
    unsigned char ke[N_PARTIES - 1][SEED_SIZE]; /* revealed seeds */
    unsigned char *x_revealed;                  /* (N-1) * INPUT_LEN bytes, malloc'd  */
    uint32_t yp_e[8];                           /* hidden party's output share */
    uint32_t *broadcast;                        /* 2 * ySize uint32_t, malloc'd */
    uint32_t *aux;                              /* ySize uint32_t, malloc'd */
} z;

/* ── PRF / hash helpers ─────────────────────────────────────────────────── */

/**
 * AES-256-CTR: expand seed into TAPE_SIZE bytes of Beaver triple data.
 * Layout: first ySize*4 bytes = u[], next ySize*4 = v[], last ySize*4 = w_raw[].
 */
void expand_tape(const unsigned char seed[SEED_SIZE], unsigned char *tape);

/** Single-shot SHA-256. Returns 1 on success. */
int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32]);

/** Commit: H(seed || x[INPUT_LEN] || yp[8] as 32 bytes big-endian). */
void H_com(const unsigned char seed[SEED_SIZE], const unsigned char *x, const uint32_t yp[8], unsigned char hash[32]);

/**
 * Fiat–Shamir challenge derivation.
 * Produces es[0..s-1] ∈ {0 .. N_PARTIES-1} from message_digest, pubout, and
 * the per-round commitment metadata as[0..s-1].
 */
void H3(const unsigned char message_digest[32], const uint32_t pubout[8], a *as[NUM_ROUNDS], int s, int *es);

/* ── Allocation helpers ─────────────────────────────────────────────────── */

/**
 * Allocate per-round prover structures.
 * seeds[NUM_ROUNDS][N_PARTIES][SEED_SIZE]: flat array of party seeds.
 * x_shares[NUM_ROUNDS][N_PARTIES]: pointers to INPUT_LEN-byte share buffers.
 * as[NUM_ROUNDS], zs[NUM_ROUNDS]: commitment and proof structs.
 * Returns 0 on success, -1 on OOM (partial state freed).
 */
int alloc_structures_prove(unsigned char seeds[NUM_ROUNDS][N_PARTIES][SEED_SIZE],
                           unsigned char *x_shares[NUM_ROUNDS][N_PARTIES], a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

void free_structures_prove(unsigned char *x_shares[NUM_ROUNDS][N_PARTIES], a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

/**
 * Allocate per-round verifier structures (as[], zs[] with broadcast/aux).
 * Returns 0 on success, -1 on OOM.
 */
int alloc_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);
void free_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

/**
 * Serialize proof to file.
 * Format per round: a struct | ke[N-1][32] | x_revealed[(N-1)*INPUT_LEN]
 *                 | yp_e[8 uint32] | broadcast[2*ySize uint32]
 *                 | aux[ySize uint32].
 */
bool write_to_file(FILE *file, a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

/* Read a single uint32 from tape at byte position pos (big-endian from AES stream). */
static inline uint32_t tape_get32(const unsigned char *tape, int pos)
{
    uint32_t v;
    memcpy(&v, tape + pos, 4);
    return v;
}

/* Retrieve u[g], v[g], w_raw[g] from a party's Beaver triple tape. */
static inline uint32_t tape_u(const unsigned char *tape, int g) { return tape_get32(tape, g * 4); }
static inline uint32_t tape_v(const unsigned char *tape, int g) { return tape_get32(tape, ySize * 4 + g * 4); }
static inline uint32_t tape_w(const unsigned char *tape, int g) { return tape_get32(tape, 2 * ySize * 4 + g * 4); }

#endif /* SHARED_H */
