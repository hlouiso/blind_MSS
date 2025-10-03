#ifndef SHARED_H
#define SHARED_H

#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// MSS parameters
extern const int H;
extern const int N;
extern const int WOTS_len;
extern const int nb_leaves;

// ZKBoo parameters & needed values
extern const int COMMIT_KEY_LEN;
extern const int NUM_ROUNDS;
extern const int ySize;
extern const int Random_Bytes_Needed;

/* 16740 bytes = COMMIT_KEY_LEN (32 bytes) + leaf_index (4 bytes) + Sigma_size (512*32 bytes) + PATH (10*32 bytes) */
extern const int INPUT_LEN;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1 << (i)) : (x) & (~(1 << (i)))

// Initial hash value for SHA-256
extern const uint32_t hA[8];

// SHA-256 constants
extern const uint32_t k[64];

// MPC view structure
typedef struct
{
    unsigned char *x;
    uint32_t *y;
} View;

// Per-round commitment and circuit outputs
typedef struct
{
    uint32_t yp[3][8];
    unsigned char h[3][32];
} a;

// Per-round opened data for the two revealed parties
typedef struct
{
    unsigned char ke[32];
    unsigned char ke1[32];
    View ve;
    View ve1;
    unsigned char re[32];
    unsigned char re1[32];
} z;

/**
 * PRF based on AES-256-CTR to derive 32 bytes from a 32-byte seed.
 *
 * Key:  sk_seed (32 bytes).
 * IV:   [0xA5,0xA5,0xA5,0xA5] || BE32(leaf) || BE32(j) || 0x00000000.
 * Data: 32 zero bytes are encrypted; the ciphertext is written to out32.
 *
 * @param sk_seed  32-byte secret seed.
 * @param leaf     Merkle leaf index (big-endian encoded in IV).
 * @param j        Per-leaf counter/index (big-endian encoded in IV).
 * @param out32    Output buffer for 32 derived bytes.
 * @return 1 on success.
 */
int prf_aes256_ctr_32(const unsigned char sk_seed[32], uint32_t leaf, uint32_t j, unsigned char out32[32]);

/**
 * Single-shot SHA-256.
 *
 * @param in       Input buffer.
 * @param inlen    Input length in bytes.
 * @param out32    Output buffer for the 32-byte digest.
 * @return 1 on success.
 */
int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32]);

/**
 * Allocate and initialize all per-round/per-party buffers for the prover.
 * On success every pointer for rounds 0..NUM_ROUNDS-1 and parties 0..2 is allocated.
 * On failure, frees any partial allocations.
 *
 * @param shares        [NUM_ROUNDS][3] inputs for each party (size = INPUT_LEN bytes each).
 * @param as            [NUM_ROUNDS] per-round commitment metadata.
 * @param zs            [NUM_ROUNDS] per-round opened data (keys, views) to be challenged later.
 * @param randomness    [NUM_ROUNDS][3] random tapes (size = Random_Bytes_Needed bytes each).
 * @param localViews    [NUM_ROUNDS][3] MPC views (with allocated x and y arrays).
 * @return 0 on success; -1 on allocation error (in which case partial state is cleaned up).
 */
int alloc_structures_prove(unsigned char *shares[NUM_ROUNDS][3], a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS],
                           unsigned char *randomness[NUM_ROUNDS][3], View *localViews[NUM_ROUNDS][3]);

/**
 * Free all structures allocated by alloc_structures_prove().
 * Safe to call even if some inner pointers are NULL.
 *
 * @param shares        [NUM_ROUNDS][3] party inputs to free.
 * @param as            [NUM_ROUNDS] commitment metadata to free.
 * @param zs            [NUM_ROUNDS] opened data to free.
 * @param randomness    [NUM_ROUNDS][3] random tapes to free.
 * @param localViews    [NUM_ROUNDS][3] views to free (also frees their x and y buffers).
 */
void free_structures_prove(unsigned char *shares[NUM_ROUNDS][3], a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS],
                           unsigned char *randomness[NUM_ROUNDS][3], View *localViews[NUM_ROUNDS][3]);

/**
 * Expand a 32-byte commitment key into the per-party random tape using AES-256-CTR.
 * Writes Random_Bytes_Needed bytes into 'randomness'.
 */
void getAllRandomness(unsigned char key[32], unsigned char *randomness);

/**
 * Read a 32-bit word from 'randomness' at byte offset 'randCount'. Does not advance it.
 */
uint32_t getRandom32(unsigned char *randomness, int randCount);

/**
 * Commitment hash used in ZKBoo: SHA256(k || v->x || v->y || r).
 * Produces a 32-byte digest in 'hash'.
 */
void H_com(unsigned char k[32], View *v, unsigned char r[32], unsigned char hash[SHA256_DIGEST_LENGTH]);

/**
 * Derive Fiat–Shamir challenges es[0..s-1] ∈ {0,1,2} from the output vector y (32 bytes)
 * and the per-round seeds/commitments a[0..s-1].
 */
void H3(uint32_t y[8], a *as[NUM_ROUNDS], int s, int *es);

/**
 * Allocate and initialize the arrays needed during verification (as[], zs[]).
 * Returns 0 on success, -1 on allocation failure.
 */
int alloc_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

/**
 * Free structures allocated by alloc_structures_verify(). Safe to call on partial allocations.
 */
void free_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

/**
 * Serialize as[i] and zs[i] to 'file' in the project-specific binary format.
 * Returns true on full success; false if any fwrite fails.
 */
bool write_to_file(FILE *file, a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS]);

#endif