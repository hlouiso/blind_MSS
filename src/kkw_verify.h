#ifndef KKW_VERIFY_H
#define KKW_VERIFY_H

#include "shared.h"
#include "xmss.h"
#include <stdint.h>
#include <stdio.h>

/* Verify a KKW proof read from `proof`.
 * Returns 0 if valid, -1 if invalid or I/O error. */
int kkw_verify(FILE *proof,
               const unsigned char m_hat[32],
               const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
               const uint32_t pubout[8]);

#endif /* KKW_VERIFY_H */
