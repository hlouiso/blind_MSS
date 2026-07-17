#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

/*
 * Raw BLAKE3 compression function and the tweakable hash Th built on it,
 * following binius-zk/binius64 PR #1620 (itself the binary-hash analog of
 * leanSig / eprint 2025/055).  This is NOT BLAKE3-the-hash: no chunk tree,
 * no CHUNK_START/CHUNK_END/ROOT flags in Th, so Th outputs do not match
 * BLAKE3 digests and the official test vectors do not apply to Th (they do
 * apply to blake3_compress itself with the root flags — see test_blake3).
 *
 * Security model: the compression function is assumed ideal (random oracle
 * for our fixed-length, domain-separated inputs) — the same heuristic the
 * SPHINCS+ family makes for its tweakable hashes (cf. SPHINCS+-Haraka).
 *
 * Th(domain, data):
 *   cv <- domain, zero-padded to 32 bytes, with cv word 7 = domain_len
 *         (so domain_len <= 28)
 *   for each 64-byte block of data (>= 1 block even if data is empty):
 *       cv <- compress(cv, block zero-padded, counter=0, real_len,
 *                      flags = ROOT on the last block, 0 otherwise)
 *   out = first out_len bytes of cv                  (out_len <= 32)
 *
 * Two deliberate strengthenings over the PR #1620 construction (both are
 * public constants — zero cost in the MPC circuit):
 *   1. cv[7] = domain_len makes domain separation structural: without it,
 *      Th(D, l) == Th(D || 0^k, l+k), and separation rested on the implicit
 *      invariant that no two call-site domains are zero-extensions of each
 *      other (true today — every non-chain domain has a nonzero separator
 *      byte at offset 16 — but fragile).
 *   2. The ROOT flag finalises the last compression, so Th is not length-
 *      extendable even where the full 32-byte cv is output on block-aligned
 *      data (the Th("HMd", com) call site: 256 = 4x64 bytes).
 *
 * The WOTS+ chain step is Th with domain = previous node (16 B) and
 * data = the 23-byte tweak block — exactly one compression, no special case.
 *
 * All words are little-endian, as in BLAKE3.
 */

/* One compression: out[0..7] = first half of the output state
 * (v[i] ^ v[i+8]).  block_len = number of meaningful bytes in the block. */
void blake3_compress(const uint32_t cv[8], const uint32_t block_words[16],
                     uint64_t counter, uint32_t block_len, uint32_t flags,
                     uint32_t out[8]);

/* Flags needed to cross-check blake3_compress against official BLAKE3
 * digests of inputs <= 64 bytes (single root compression). */
#define BLAKE3_CHUNK_START (1u << 0)
#define BLAKE3_CHUNK_END   (1u << 1)
#define BLAKE3_ROOT        (1u << 3)

/* Tweakable hash as above.  domain_len <= 28, out_len <= 32. */
void blake3_th(const uint8_t *domain, size_t domain_len,
               const uint8_t *data, size_t data_len,
               uint8_t *out, size_t out_len);

/* Incremental Th over the same construction: init, update(s), final produces
 * exactly the bytes of the one-shot blake3_th on the concatenated updates
 * (blake3_th itself is implemented on top of this context).  Needed by the
 * KKW layer, whose h'_j preimage (d ‖ s_0..s_{N-1} ‖ r_j) is scattered and
 * several MB long. */
typedef struct {
    uint32_t cv[8];
    uint8_t buf[64];   /* pending partial block */
    size_t buflen;     /* bytes pending in buf, 0..64 */
    int poisoned;      /* domain_len > 28: output zeros, like the one-shot */
} blake3_th_ctx;

void blake3_th_init(blake3_th_ctx *ctx, const uint8_t *domain, size_t domain_len);
void blake3_th_update(blake3_th_ctx *ctx, const void *data, size_t len);
void blake3_th_final(blake3_th_ctx *ctx, uint8_t *out, size_t out_len);

#endif /* BLAKE3_H */
