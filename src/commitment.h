#ifndef COMMITMENT_H
#define COMMITMENT_H

#include <stdint.h>

/*
 * Halevi–Micali statistically-hiding commitment over GF(2^128).  Structure as
 * in https://github.com/diegode/blind-longfellow; since the BLAKE3 migration
 * the two hashes are the BLAKE3 tweakable hash Th (blake3_th.h) with fixed
 * domains "HMy"/"HMd", so the byte formats are no longer identical.
 *
 *   y   = Th("HMy", r_1 || ... || r_6)       (hashes the n=6 nonces ONLY)
 *   b_k = m̂_k + Σ_i a_{k,i} · r_i  over GF(2^128)   (k = 0,1; one line per
 *                                                     16-byte half of m̂)
 *   com = a || b || y                        (the commitment, 256 bytes)
 *   d   = Th("HMd", com)                     (the digest the signer certifies)
 *
 * The opening is (r, a); b, y, com, d are all derived.  The 256-bit message
 * digest m̂ = Th("KKWmhat", m) (see shared.h) is public and is bound,
 * word-for-word over its two 16-byte halves, by the two affine lines.
 */

#define HM_NONCES 6                              /* n */
#define HM_LINES 2                               /* one per 16-byte half of m̂ */
#define HM_ELT 16                                /* GF(2^128) element bytes     */
#define HM_R_BYTES (HM_NONCES * HM_ELT)          /* 96  */
#define HM_A_BYTES (HM_LINES * HM_NONCES * HM_ELT) /* 192 */
#define HM_B_BYTES (HM_LINES * HM_ELT)           /* 32  */
#define HM_Y_BYTES 32                            /* full Th output */
#define HM_COM_BYTES (HM_A_BYTES + HM_B_BYTES + HM_Y_BYTES) /* 256 */
#define HM_OPEN_BYTES (HM_R_BYTES + HM_A_BYTES)  /* 288: the secret opening (r,a) */

/* y = Th("HMy", r_1 || ... || r_6). */
void hm_y(const uint8_t r[HM_R_BYTES], uint8_t y[HM_Y_BYTES]);

/* b_k = m̂_k + Σ_i a_{k,i} · r_i  over GF(2^128), for k = 0,1. */
void hm_lines(const uint8_t m_hat[32], const uint8_t a[HM_A_BYTES], const uint8_t r[HM_R_BYTES],
              uint8_t b[HM_B_BYTES]);

/* com = a || b || y. */
void hm_commitment(const uint8_t a[HM_A_BYTES], const uint8_t b[HM_B_BYTES], const uint8_t y[HM_Y_BYTES],
                   uint8_t com[HM_COM_BYTES]);

/* d = Th("HMd", com). */
void hm_digest(const uint8_t com[HM_COM_BYTES], uint8_t d[32]);

/* Convenience: from opening (r, a) and public m̂, produce com (256 B) and d (32 B). */
void hm_commit(const uint8_t m_hat[32], const uint8_t r[HM_R_BYTES], const uint8_t a[HM_A_BYTES],
               uint8_t com[HM_COM_BYTES], uint8_t d[32]);

#endif /* COMMITMENT_H */
