#ifndef KKW_PROVE_H
#define KKW_PROVE_H

#include "shared.h"
#include "xmss.h"
#include <stdint.h>
#include <stdio.h>

/* Set to 0 to suppress pass-1/pass-2 progress output (default: 1). */
extern int kkw_verbose;

/* Run the full KKW prover and write the binary proof to `out`.
 * Returns 0 on success, -1 on error. */
int kkw_prove(const unsigned char *input /* W_END bytes */,
              const unsigned char m_hat[32],
              const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
              const uint32_t pubout[8],
              FILE *out);

#endif /* KKW_PROVE_H */
