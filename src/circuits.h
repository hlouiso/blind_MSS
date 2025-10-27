#ifndef BUILDING_H
#define BUILDING_H

#include "shared.h"

#include <stdbool.h>

/**
 * Build the three MPC views for a single ZKBoo-style round.
 * - Fills `views[0..2]` with inputs/outputs for each party, using `shares` and `randomness`.
 * - Uses the 32-byte public `message_digest` as circuit input where needed.
 * - No return value: all outputs are written via `views` and the per-round container `a`.
 */
void building_views(a *a, unsigned char message_digest[32], unsigned char *shares[3], unsigned char *randomness[3],
                    View *views[3]);

/**
 * Verify one round given challenge e ∈ {0,1,2} (MPC-in-the-head, ZKBoo-like).
 * - Replays commitments and transcript consistency, reconstructing the hidden view e as needed.
 * - Sets `*error = true` on first failure, leaves it unchanged otherwise. Returns void.
 */
void verify(unsigned char message_digest[32], bool *error, a *a, int e, z *z);

#endif // BUILDING_H