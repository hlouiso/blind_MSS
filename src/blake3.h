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
 *   cv <- domain, zero-padded to 32 bytes            (domain_len <= 32)
 *   for each 64-byte block of data (>= 1 block even if data is empty):
 *       cv <- compress(cv, block zero-padded, counter=0, real_len, flags=0)
 *   out = first out_len bytes of cv                  (out_len <= 32)
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

/* Tweakable hash as above.  domain_len <= 32, out_len <= 32. */
void blake3_th(const uint8_t *domain, size_t domain_len,
               const uint8_t *data, size_t data_len,
               uint8_t *out, size_t out_len);

#endif /* BLAKE3_H */
