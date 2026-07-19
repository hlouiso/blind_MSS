#ifndef XMSS_NATIVE_H
#define XMSS_NATIVE_H

/*
 * Native (host-side) target-sum WOTS+ / XMSS.  All hashing is the BLAKE3
 * tweakable hash Th (blake3_th.h) — the construction of binius-zk/binius64
 * PR #1620 — with SPHINCS+-style domain separation; every internal node is a
 * Th output truncated to 16 bytes (128-bit).  This is NOT byte-compatible
 * with the SHA-256 blind-longfellow instantiation any more: the security
 * argument is "same construction as Binius64's audited BLAKE3 XMSS verifier
 * (+ eprint 2025/055 framework)", under the assumption that the BLAKE3
 * compression function is ideal.
 *
 * Th call layouts (Th(domain -> cv, data -> 64-byte blocks), blake3_th.h):
 *   message    : dom = pk_seed(16)||0x02||epoch(4 BE)   data = nonce(6)||msg
 *   chain step : dom = in(16)                           data = pk_seed(16)||0x00||epoch(4 BE)||chain_idx(1)||pos(1)
 *   tree node  : dom = pk_seed(16)||0x01||level(1)||index(2 LE)   data = left(16)||right(16)
 *   leaf (pk)  : dom = pk_seed(16)||0x03||epoch(4 BE)   data = pk_hash[0..LEN-1]
 * Domain separation is two-layered (see blake3_th.h): Th binds domain_len into
 * cv[7], separating families of different lengths (chain 16 B, tree 20 B,
 * message/leaf 21 B, HM 3 B) even where domain bytes are zero; the separator
 * byte at offset 16 separates equal-length families — 0x03 vs 0x02 is what
 * keeps leaf and message apart (both 21 B), so it stays REQUIRED.
 *
 * WOTS+ uses the target-sum encoding (no checksum chains): the low
 * XMSS_MSG_HASH_LEN bytes of the message hash decode into XMSS_WOTS_LEN base-w
 * coordinates that MUST sum to XMSS_TARGET_SUM; the signer grinds the nonce
 * until they do.
 */

#include <stddef.h>
#include <stdint.h>

/* ── Parameters ───────────────────────────────────────────────────────────── */
#define XMSS_NODE_BYTES 16    /* Th output truncated to 128 bits */
#define XMSS_PK_SEED_BYTES 16 /* domain parameter */
#define XMSS_H 10             /* tree height: 2^10 = 1024 leaves */
#define XMSS_WOTS_W 2         /* Winternitz parameter (1-bit coords) */
#define XMSS_WOTS_LOGW 1
#define XMSS_WOTS_LEN 144     /* number of WOTS+ chains */
#define XMSS_WOTS_MAX_STEPS 1 /* W - 1 */
#define XMSS_TARGET_SUM 72    /* required sum of the LEN coordinates */
#define XMSS_NONCE_LEN 6      /* grinding nonce length */
#define XMSS_MSG_HASH_LEN 18  /* low bytes of msg hash feeding the codeword */
#define XMSS_COORD_RES_BITS 1
#define XMSS_EPOCH_BYTES 4    /* leaf index bound into msg/chain/L-tree tweaks (BE) */

/* Tweak (domain-separation) bytes. */
#define XMSS_TWEAK_CHAIN 0x00
#define XMSS_TWEAK_TREE 0x01
#define XMSS_TWEAK_MESSAGE 0x02
#define XMSS_TWEAK_LEAF 0x03 /* leaf/pk hash — MUST differ from TREE (see above) */

/* A truncated tweakable-hash value (and the pk_seed type). */
typedef uint8_t xmss_node[XMSS_NODE_BYTES];

/* An XMSS signature.  pk_hashes are NOT stored: the verifier recomputes them
 * from sig_hashes + coords. */
typedef struct
{
    uint32_t leaf_index;
    uint8_t nonce[XMSS_NONCE_LEN];
    xmss_node sig_hashes[XMSS_WOTS_LEN]; /* WOTS+ chain starts */
    xmss_node auth_path[XMSS_H];         /* Merkle authentication path */
} xmss_sig;

/* ── Tweaked hashes (exposed for the circuit / witness builder) ───────────── */

/* Th(pk_seed||0x02||epoch, nonce||message), full 32-byte output. */
void xmss_hash_message(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const uint8_t *nonce,
                       size_t nonce_len, const uint8_t *message, size_t message_len, uint8_t out32[32]);

/* trunc16(Th(in, pk_seed||0x00||epoch||chain_idx||pos)) — one compression. */
void xmss_hash_chain_step(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node in,
                          uint8_t chain_idx, uint8_t pos, xmss_node out);

/* Iterate `steps` chain hashes from `start` at `start_pos`; step i hashes at
 * position (start_pos + i + 1), all under the same `epoch` tweak. */
void xmss_hash_chain_multi(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node start,
                           uint8_t chain_idx, uint8_t start_pos, uint8_t steps, xmss_node out);

/* trunc16(Th(pk_seed||0x01||level||index, left||right)).  No epoch: the
 * (level, index) tweak already binds the node to its position. */
void xmss_hash_tree_node(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node left, const xmss_node right,
                         uint32_t level, uint32_t index, xmss_node out);

/* trunc16(Th(pk_seed||0x03||epoch, pk_hash[0] || ... || pk_hash[LEN-1])). */
void xmss_hash_public_key(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node pk_hashes[XMSS_WOTS_LEN], xmss_node out);

/* Decode `dimension` base-(2^res) coordinates from `hash`, LSB-first per byte. */
void xmss_extract_coords(const uint8_t *hash, int dimension, int res_bits, uint8_t *coords_out);

/* ── WOTS+ chain computations ─────────────────────────────────────────────── */

/* Derive the WOTS+ secret key (LEN chain starts) for one leaf, deterministically
 * from sk_seed via the BLAKE3 keyed XOF. */
void xmss_wots_gen_sk(const uint8_t sk_seed[32], uint32_t leaf_index, xmss_node sk_out[XMSS_WOTS_LEN]);

/* pk[i] = chain start hashed MAX_STEPS times (chain endpoint at position W-1).
 * Tweaked by `epoch` (the leaf index). */
void xmss_wots_pk_from_sk(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node sk[XMSS_WOTS_LEN], xmss_node pk_out[XMSS_WOTS_LEN]);

/* sig[i] = sk[i] hashed coords[i] times. */
void xmss_wots_sign(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node sk[XMSS_WOTS_LEN],
                    const uint8_t coords[XMSS_WOTS_LEN], xmss_node sig_out[XMSS_WOTS_LEN]);

/* pk[i] = sig[i] hashed (W-1 - coords[i]) more times → chain endpoint. */
void xmss_wots_pk_from_sig(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                           const xmss_node sig[XMSS_WOTS_LEN], const uint8_t coords[XMSS_WOTS_LEN],
                           xmss_node pk_out[XMSS_WOTS_LEN]);

/* ── XMSS top level ───────────────────────────────────────────────────────── */

/* Build the full tree from sk_seed and return the root (= public key). */
void xmss_compute_root(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], xmss_node root_out);

/* Sign `message` with leaf `leaf_index`.  Grinds the nonce so the codeword hits
 * the target sum.  Returns 1 on success, 0 on failure (grinding budget
 * exhausted, allocation failure, or leaf_index >= 2^XMSS_H).
 *
 * SECURITY — STATEFUL SIGNATURE, CALLER-OWNED STATE: this library keeps NO
 * record of used leaves.  The caller MUST guarantee each leaf_index is used
 * at most once over the key's whole lifetime, across restarts and replicas
 * (persist a monotonic counter before releasing a signature).  Reusing a
 * leaf on two different messages is fatal with W=2: each 0-coordinate
 * reveals that chain's secret start, two codewords leave only ~36 unbroken
 * coordinates, and an attacker can then grind a message hash covering them
 * (~2^36 hashes) — an existential forgery.  Key lifetime is 2^XMSS_H = 1024
 * signatures; after that the key MUST be retired. */
int xmss_sign(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t leaf_index,
              const uint8_t *message, size_t message_len, xmss_sig *out);

/* Verify `sig` on `message` under (pk_seed, root).  Returns 1 if valid. */
int xmss_verify(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node root, const uint8_t *message,
                size_t message_len, const xmss_sig *sig);

#endif /* XMSS_NATIVE_H */
