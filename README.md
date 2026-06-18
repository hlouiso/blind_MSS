# Blind XMSS (target-sum WOTS+) with ZKBoo (MPC-in-the-Head)

This project implements a **blind signature** over **XMSS** (a stateful Merkle signature scheme) with **target-sum WOTS+** one-time signatures in the leaves, and a ZK proof in the **ZKBoo / MPC-in-the-head** style to prove knowledge of a valid signature **without revealing** the secret material (the commitment opening, the leaf index, or the signature).

It is the ZKBoo-based instantiation of the generic hash-based blind signature construction: a commitment scheme, a hash-based signature scheme, and a NIZK. Here the commitment is `M = SHA256(SHA256(m) || r)`, the signature is target-sum WOTS+/XMSS, and the NIZK is ZKBoo. The same XMSS/WOTS+ scheme is shared with the Longfellow- and Binius64-based instantiations; only the NIZK differs.

> ⚠️ This code is for research/education. Do not use in production.

## Context

This work was carried out during my final internship for the Master's degree in **Cryptology and Computer Security** at the [University of Bordeaux](https://mastercsi.labri.fr/). The internship took place in the first half of 2025 at [UPC (Barcelona)](https://www.upc.edu/ca), supervised by [Javier Herranz Sotoca](https://web.mat.upc.edu/javier.herranz/).

## Build

Requirements:
- A C compiler (GCC/Clang) with OpenMP support
- OpenSSL **libcrypto**
- `make`

```bash
make          # build everything
make clean    # remove binaries and intermediates
```

Binaries produced: `CLIENT_blinding_message`, `SIGNER_XMSS_keygen`, `SIGNER_XMSS_sign`, `CLIENT_blind_sign`, `VERIFIER_verify`.

## Parameters

Signature scheme (`xmss.h`), matching the Longfellow/Binius64 instantiations:
- `XMSS_H = 10` — Merkle tree height (`2^10 = 1024` signatures per key pair)
- `XMSS_WOTS_W = 4` — Winternitz parameter (2-bit coordinates)
- `XMSS_WOTS_LEN = 72` — number of WOTS+ chains (target-sum encoding, no checksum)
- `XMSS_TARGET_SUM = 132` — required sum of the 72 coordinates
- `XMSS_NODE_BYTES = 16` — every internal node is a SHA-256 output truncated to 128 bits
- `XMSS_PK_SEED_BYTES = 16`, `XMSS_NONCE_LEN = 6`
- All hashing is SHA-256, SPHINCS+-style keyed/tweaked (tweaks `0x00` chain, `0x01` tree/pk, `0x02` message).

ZKBoo (`shared.c`):
- `NUM_ROUNDS = 137` parallel executions (soundness error `(2/3)^137`); raise to `219` for `2^-128`.
- `INPUT_LEN = 1354`, `ySize = 181664` (nonlinear-gate transcript words per view).

## Files & Formats

All hex is **UPPERCASE** without spaces.

- **`XMSS_secret_key.txt`** (`SIGNER_XMSS_keygen`)
  - Line 1: `sk_seed` — 32 bytes (64 hex)
  - Line 2: `pk_seed` — 16 bytes (32 hex)
  - Line 3: `leaf_index` — decimal (initially `0`)

- **`XMSS_public_key.txt`** (`SIGNER_XMSS_keygen`)
  - Line 1: `pk_seed` — 16 bytes (32 hex)
  - Line 2: XMSS root — 16 bytes (32 hex)

- **`blinding_key.txt`** (`CLIENT_blinding_message`)
  - Blinding randomness `r` — 32 bytes (64 hex)

- **`blinded_message.txt`** (`CLIENT_blinding_message`)
  - Commitment `M = SHA256( SHA256(m) || r )` — 32 bytes (64 hex)

- **`XMSS_signature.txt`** (`SIGNER_XMSS_sign`)
  - Line 1: `leaf_index` — decimal
  - Line 2: `nonce` — 6 bytes (12 hex)
  - Next `72` lines: WOTS+ chain values — 16 bytes (32 hex) each
  - Next `10` lines: XMSS authentication path — 16 bytes (32 hex) each

- **`signature_proof.bin`** (`CLIENT_blind_sign`)
  - Binary ZKBoo proof that a valid XMSS signature exists on the committed message.

## Typical Workflow

1. **Signer** generates keys: `./SIGNER_XMSS_keygen` → `XMSS_secret_key.txt`, `XMSS_public_key.txt`.
2. **Client** blinds a message: `./CLIENT_blinding_message` (prompts for `m`) → `blinding_key.txt`, `blinded_message.txt` (the commitment `M`). The client keeps `r` secret and sends `M` to the signer.
3. **Signer** signs `M`: `./SIGNER_XMSS_sign` (reads `XMSS_secret_key.txt`, `blinded_message.txt`; self-checks the signature against the public key) → `XMSS_signature.txt`, and advances the leaf index.
4. **Client** proves: `./CLIENT_blind_sign` (prompts for `m`; reads `blinding_key.txt`, `XMSS_signature.txt`, `XMSS_public_key.txt`). It first re-checks that the XMSS signature is valid for `SHA256(SHA256(m)||r)`, then writes the ZK proof to `signature_proof.bin`.
5. **Verifier** checks: `./VERIFIER_verify` (prompts for `m`; reads `XMSS_public_key.txt`, `signature_proof.bin`).

## The circuit C

`CLIENT_blind_sign` / `VERIFIER_verify` prove/verify in zero knowledge that the witness `(r, leaf_index, nonce, WOTS+ chain values, auth path)` satisfies, for public `(m̂ = SHA256(m), pk = pk_seed || root)`:
1. `M = SHA256(m̂ || r)` — the commitment;
2. `mh = SHA256(pk_seed || 0x02 || nonce || M)`, decoded into 72 base-4 coordinates whose sum is `132`;
3. each WOTS+ chain walks from its secret start to the public-key endpoint (data-dependent step count handled by a fixed 3-stage pipeline with a secret-selector mux);
4. the leaf `SHA256(pk_seed || 0x01 || pk_hash[0..71])` walks the authentication path (left/right and the tweak index routed by the secret leaf-index bits) up to `root`.

The circuit outputs `root` and the codeword sum, which the verifier checks equal the public root and `132`.

## References

- [ZKBoo: Faster Zero-Knowledge for Boolean Circuits — ePrint 2016/163](https://eprint.iacr.org/2016/163)
- [Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives — ePrint 2017/279](https://eprint.iacr.org/2017/279.pdf)
- [Original ZKBoo implementation (Aarhus University)](https://github.com/Sobuno/ZKBoo)
- [XMSS — RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
