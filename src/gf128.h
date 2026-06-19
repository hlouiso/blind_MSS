#ifndef GF128_H
#define GF128_H

#include <stdint.h>

/*
 * GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)  (the AES-GCM polynomial).
 *
 * Canonical representation (shared by the native code and the ZKBoo MPC gadget):
 *   - A field element is 16 bytes.  Byte b holds coefficients x^(8b) .. x^(8b+7),
 *     LSB of the byte = the lowest degree.
 *   - In word form it is 4 little-endian uint32 words W[0..3]; bit i of W[w] is
 *     the coefficient of x^(32w + i).  So gf128_load is a little-endian load.
 *
 * The reduce/shift helpers are exposed (not static) so that circuits.c can build
 * the in-circuit multiply share-by-share with the *same* GF(2)-linear reduction
 * the native multiply uses — reduce/shift are linear and value-independent, so
 * applying them per XOR-share reconstructs the native product exactly.
 */

/* out[0..7] (256-bit accumulator) ^= (word << pos).  pos in [0, 223]. */
void gf128_word_shift_xor(uint32_t acc[8], uint32_t word, int pos);

/* Reduce a 256-bit accumulator acc[0..7] modulo the field polynomial into the
 * 128-bit result out[0..3].  Linear over GF(2) and value-independent. */
void gf128_reduce(const uint32_t acc[8], uint32_t out[4]);

/* out = X * Y in GF(2^128) (all in word form). */
void gf128_mul_words(const uint32_t X[4], const uint32_t Y[4], uint32_t out[4]);

/* Byte-oriented helpers. */
void gf128_load(uint32_t w[4], const uint8_t b[16]);  /* little-endian load  */
void gf128_store(uint8_t b[16], const uint32_t w[4]); /* little-endian store */
void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]);

#endif /* GF128_H */
