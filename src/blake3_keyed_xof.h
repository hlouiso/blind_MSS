#ifndef BLIND_MSS_BLAKE3_KEYED_XOF_H
#define BLIND_MSS_BLAKE3_KEYED_XOF_H

#include <stddef.h>
#include <stdint.h>

#define BLIND_MSS_BLAKE3_KEY_LEN 32

/* Fixed, protocol-specific domains for independent pseudorandom streams. */
#define BLAKE3_XOF_DOM_KKW_TAPE       "blind-mss KKW tape expansion v1"
#define BLAKE3_XOF_DOM_KKW_SEEDS      "blind-mss KKW party-seed expansion v1"
#define BLAKE3_XOF_DOM_KKW_XSHARE     "blind-mss KKW witness-mask expansion v1"
#define BLAKE3_XOF_DOM_XMSS_WOTS_SK   "blind-mss XMSS WOTS secret-key expansion v1"

/* Expand a 256-bit key into out_len pseudorandom bytes using the official
 * BLAKE3 keyed XOF. The domain is length-framed before the optional input. */
void blake3_keyed_xof(const uint8_t key[BLIND_MSS_BLAKE3_KEY_LEN],
                      const char *domain,
                      const void *input, size_t input_len,
                      uint8_t *out, size_t out_len);

#endif /* BLIND_MSS_BLAKE3_KEYED_XOF_H */
