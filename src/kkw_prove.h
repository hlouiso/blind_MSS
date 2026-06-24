#ifndef KKW_PROVE_H
#define KKW_PROVE_H

#include "shared.h"
#include "xmss.h"
#include <stdint.h>
#include <stdio.h>

/* Run the full KKW prover and write the binary proof to `out`.
 * Returns 0 on success, -1 on error. */
int kkw_prove(const unsigned char *input /* W_END bytes */,
              const unsigned char m_hat[32],
              const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
              const uint32_t pubout[8],
              FILE *out);

#endif /* KKW_PROVE_H */
