#ifndef BUILDING_H
#define BUILDING_H

#include "shared.h"

#include <stdbool.h>

/**
 * Build the three MPC views for one ZKBoo round of the circuit.
 *
 * Inputs:
 *  - a:      Per-round containers (stores commitment hashes/keys for the round).
 *  - digest: 32-byte public message digest.
 *  - shares: Three pointers to party inputs (each INPUT_LEN bytes).
 *  - randomness: Three per-party random tapes (each Random_Bytes_Needed bytes).
 *  - views:  Output array of 3 View structs; function fills x (inputs) and y (gate outputs).
 *
 * Effect:
 *  Evaluates the circuit under 3-party secret sharing (includes SHA-256 and MSS selection logic)
 *  and records the transcript into views[0..2]. Updates 'a' with per-party commitments used later
 *  by Fiat–Shamir and verification.
 */
void building_views(a *a, unsigned char digest[32], unsigned char *shares[3], unsigned char *randomness[3],
                    View *views[3]);

/**
 * Verify one ZKBoo round for challenge e ∈ {0,1,2}.
 *
 * Inputs:
 *  - digest: 32-byte public message digest.
 *  - error:  Output flag set to true on first verification failure.
 *  - a:      Round commitments/metadata (contains hashes h[], etc.).
 *  - e:      Challenge index in {0,1,2} specifying which view is hidden.
 *  - z:      Opened proof data (two views, keys/salts) for the two revealed parties.
 *
 * Returns: void. Sets *error=true if any commitment/transcript check fails; leaves false on success.
 */
void verify(unsigned char digest[32], bool *error, a *a, int e, z *z);

#endif // BUILDING_H