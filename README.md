# Blind XMSS (target-sum WOTS+) with ZKBoo (MPC-in-the-Head)

This project implements a **blind signature** over **XMSS** (a stateful Merkle signature scheme) with **target-sum WOTS+** one-time signatures in the leaves, and a ZK proof in the **ZKBoo / MPC-in-the-head** style to prove knowledge of a valid signature **without revealing** the secret material (the commitment opening, the leaf index, or the signature).

It is the ZKBoo-based instantiation of the generic hash-based blind signature construction: a commitment scheme, a hash-based signature scheme, and a NIZK. Here the commitment is **Halevi–Micali over GF(2¹²⁸)**, the signature is target-sum WOTS+/XMSS, and the NIZK is ZKBoo.

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

Halevi–Micali commitment (`commitment.h`):
- `HM_NONCES = 6`, `HM_LINES = 2`, field `GF(2¹²⁸)` — same layout as the Longfellow-based instantiation.
- Opening `(r, a)` is `96 + 192 = 288` bytes; the commitment `com = a‖b‖y` is `256` bytes.

ZKBoo (`shared.c`):
- `NUM_ROUNDS = 137` parallel executions (soundness error `(2/3)^137`); raise to `219` for `2^-128`.
- `INPUT_LEN = 1610`, `ySize = 191448` (nonlinear-gate transcript words per view).

## Files & Formats

All hex is **UPPERCASE** without spaces.

- **`XMSS_secret_key.txt`** (`SIGNER_XMSS_keygen`)
  - Line 1: `sk_seed` — 32 bytes (64 hex)
  - Line 2: `pk_seed` — 16 bytes (32 hex)
  - Line 3: `leaf_index` — decimal (initially `0`)

- **`XMSS_public_key.txt`** (`SIGNER_XMSS_keygen`)
  - Line 1: `pk_seed` — 16 bytes (32 hex)
  - Line 2: XMSS root — 16 bytes (32 hex)

- **`blinding_key.txt`** (`CLIENT_blinding_message`) — the secret opening `(r, a)`
  - Line 1: nonces `r₁‖…‖r₆` — 96 bytes (192 hex)
  - Line 2: line matrix `a` (row-major `a_{0,0..5} ‖ a_{1,0..5}`) — 192 bytes (384 hex)

- **`blinded_message.txt`** (`CLIENT_blinding_message`)
  - Commitment `com = a ‖ b ‖ y` — 256 bytes (512 hex). The signer derives `d = SHA256(com)`.

- **`XMSS_signature.txt`** (`SIGNER_XMSS_sign`)
  - Line 1: `leaf_index` — decimal
  - Line 2: `nonce` — 6 bytes (12 hex)
  - Next `72` lines: WOTS+ chain values — 16 bytes (32 hex) each
  - Next `10` lines: XMSS authentication path — 16 bytes (32 hex) each

- **`signature_proof.bin`** (`CLIENT_blind_sign`)
  - Binary ZKBoo proof that a valid XMSS signature exists on the committed message.

## Typical Workflow

1. **Signer** generates keys: `./SIGNER_XMSS_keygen` → `XMSS_secret_key.txt`, `XMSS_public_key.txt`.
2. **Client** blinds a message: `./CLIENT_blinding_message` (prompts for `m`) → `blinding_key.txt` (the secret opening `(r, a)`), `blinded_message.txt` (the commitment `com = a‖b‖y`). The client keeps `(r, a)` secret and sends `com` to the signer.
3. **Signer** signs the commitment: `./SIGNER_XMSS_sign` (reads `XMSS_secret_key.txt`, `blinded_message.txt`; derives `d = SHA256(com)`, signs `d`, self-checks against the public key) → `XMSS_signature.txt`, and advances the leaf index.
4. **Client** proves: `./CLIENT_blind_sign` (prompts for `m`; reads `blinding_key.txt`, `XMSS_signature.txt`, `XMSS_public_key.txt`). It first re-checks that the XMSS signature is valid for `d = SHA256(a‖b‖y)`, then writes the ZK proof to `signature_proof.bin`.
5. **Verifier** checks: `./VERIFIER_verify` (prompts for `m`; reads `XMSS_public_key.txt`, `signature_proof.bin`).

## Performance

Message length affects only the native
`m̂ = SHA256(m)`, so prove/verify time is independent of `|m|`.

### Artefact sizes

| Artefact | Size |
|---|---:|
| Public key (`pk_seed ‖ root`) | $32$ B |
| Secret key (`sk_seed ‖ pk_seed ‖ leaf_index`) | $52$ B |
| Commitment `com = a ‖ b ‖ y` | $256$ B |
| Raw XMSS signature (`leaf ‖ nonce ‖ 72 chains ‖ 10 path`) | $1.29$ KB |
| **Blind signature (ZKBoo proof)** | $\approx 168.5$ MB |

### Timing

| Phase | Mean time |
|---|---:|
| Commitment computation | $< 1$ ms |
| Key generation | $\approx 130$ ms |
| Signing | $\approx 130$ ms |
| Proof generation | $\approx 1.7$ s |
| Proof verification | $\approx 0.9$ s |

The proof is huge because it is inherent to ZKBoo: each of the `NUM_ROUNDS` rounds
serialises one full per-view nonlinear-gate transcript, so

```
proof ≈ NUM_ROUNDS · (ySize·4 + 2·INPUT_LEN + sizeof(a) + 128)
      = 219 · (765792 + 3220 + 192 + 128) ≈ 168.5 MB
```

## References

- [ZKBoo: Faster Zero-Knowledge for Boolean Circuits — ePrint 2016/163](https://eprint.iacr.org/2016/163)
- [Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives — ePrint 2017/279](https://eprint.iacr.org/2017/279.pdf)
- [Original ZKBoo implementation (Aarhus University)](https://github.com/Sobuno/ZKBoo)
- [XMSS — RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
