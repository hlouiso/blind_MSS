#ifndef BUILDING_H
#define BUILDING_H

#include "shared.h"
#include "xmss.h"

#include <stdbool.h>

/* ── Witness layout (the XOR-shared INPUT_LEN buffer) ─────────────────────────
 *   r           (32)                blinding randomness
 *   leaf_index  (4, big-endian)     XMSS leaf index (secret, for blindness)
 *   nonce       (XMSS_NONCE_LEN)    WOTS+ target-sum grinding nonce
 *   sig_hashes  (LEN * NODE)        WOTS+ chain start values
 *   auth_path   (XMSS_H * NODE)     XMSS authentication path
 * Total = INPUT_LEN (defined in shared.c, must equal W_END). */
#define W_R_OFF 0
#define W_R_LEN 32
#define W_LEAFIDX_OFF (W_R_OFF + W_R_LEN)      /* 32 */
#define W_LEAFIDX_LEN 4
#define W_NONCE_OFF (W_LEAFIDX_OFF + W_LEAFIDX_LEN) /* 36 */
#define W_SIG_OFF (W_NONCE_OFF + XMSS_NONCE_LEN)    /* 42 */
#define W_SIG_LEN (XMSS_WOTS_LEN * XMSS_NODE_BYTES) /* 1152 */
#define W_PATH_OFF (W_SIG_OFF + W_SIG_LEN)          /* 1194 */
#define W_PATH_LEN (XMSS_H * XMSS_NODE_BYTES)       /* 160 */
#define W_END (W_PATH_OFF + W_PATH_LEN)             /* 1354 */

/* The circuit's public output (a->yp), per share:
 *   words 0..3 : XMSS root (16 bytes)
 *   word  4    : WOTS+ codeword sum (must reconstruct to XMSS_TARGET_SUM)
 *   words 5..7 : 0 */
#define YP_ROOT_WORDS 4
#define YP_SUM_WORD 4

/* Set to the final countY of the last building_views call (gate-count probe). */
extern int g_circuit_gates;

/**
 * Build the three MPC views for one ZKBoo round of the target-sum WOTS+/XMSS
 * blind-signature circuit.  Public inputs: message digest m̂ = SHA256(m) and the
 * 16-byte XMSS public seed.  All signature material is in the shared witness.
 */
void building_views(a *a, unsigned char message_digest[32], unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                    unsigned char *shares[3], unsigned char *randomness[3], View *views[3]);

/**
 * Verify one round given challenge e ∈ {0,1,2} (MPC-in-the-head, ZKBoo-like).
 * Sets *error = true on first inconsistency, leaves it unchanged otherwise.
 */
void verify(unsigned char message_digest[32], unsigned char pk_seed[XMSS_PK_SEED_BYTES], bool *error, a *a, int e,
            z *z);

#endif // BUILDING_H
