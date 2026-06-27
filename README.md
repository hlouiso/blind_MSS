# Blind XMSS (target-sum WOTS+) with KKW (MPC-in-the-Head)

This project implements a **blind signature** over **XMSS** (a stateful Merkle signature scheme) with **target-sum WOTS+** one-time signatures in the leaves, and a zero-knowledge proof in the **KKW / MPC-in-the-head** style (Katz-Kolesnikov-Wang 2018) to prove knowledge of a valid signature **without revealing** the secret material (the commitment opening, the leaf index, or the signature).

The commitment scheme is **Halevi–Micali over GF(2¹²⁸)**, the signature is target-sum WOTS+/XMSS, and the NIZK is KKW (cut-and-choose over MPC preprocessing).

> ⚠️ This code is for research/education. Do not use in production.

## Context

This work was carried out during my final internship for the Master's degree in **Cryptology and Computer Security** at the [University of Bordeaux](https://mastercsi.labri.fr/). The internship took place in the first half of 2025 at [UPC (Barcelona)](https://www.upc.edu/ca), supervised by [Javier Herranz Sotoca](https://web.mat.upc.edu/javier.herranz/).

## Build

Requirements:
- A C compiler (GCC/Clang) with OpenMP support
- OpenSSL **libcrypto**
- `make`

```bash
make          # build everything (default N=4)
make N=<N>    # build with N ∈ {4, 8, 16, 32, 64, 128, 256}
make clean    # remove binaries and intermediates
make bench    # benchmark all N values
```

Binaries produced: `CLIENT_blinding_message`, `SIGNER_XMSS_keygen`, `SIGNER_XMSS_sign`, `CLIENT_blind_sign`, `VERIFIER_verify`.

## Parameters

Signature scheme (`xmss.h`), matching the Longfellow/Binius64 instantiations:
- `XMSS_H = 10` — Merkle tree height (`2^10 = 1024` signatures per key pair)
- `XMSS_WOTS_W = 2` — Winternitz parameter (1-bit coordinates)
- `XMSS_WOTS_LEN = 144` — number of WOTS+ chains (target-sum encoding, no checksum)
- `XMSS_TARGET_SUM = 72` — required sum of the 144 coordinates
- `XMSS_NODE_BYTES = 16` — every internal node is a SHA-256 output truncated to 128 bits
- `XMSS_PK_SEED_BYTES = 16`, `XMSS_NONCE_LEN = 6`
- All hashing is SHA-256, SPHINCS+-style keyed/tweaked (tweaks `0x00` chain, `0x01` tree/pk, `0x02` message).

Halevi–Micali commitment (`commitment.h`):
- `HM_NONCES = 6`, `HM_LINES = 2`, field `GF(2¹²⁸)` — same layout as the Longfellow-based instantiation.
- Opening `(r, a)` is `96 + 192 = 288` bytes; the commitment `com = a‖b‖y` is `256` bytes.

KKW proof (`shared.h`, selectable at build time with `N=<N>`):
- `N_PARTIES` — number of MPC parties (default 4)
- `NUM_ROUNDS` (`τ`) — online rounds included in the proof; drives prove/verify cost
- `M_KKW` (`M`) — total preprocessing instances; drives pass-1 cost (offline section ≈ negligible)
- `INPUT_LEN = 2762` — witness byte length
- `ySize = 151776` — nonlinear-gate count in the SHA-256/WOTS/XMSS circuit

### Soundness parameters (128-bit security, ROM)

The KKW cut-and-choose soundness formula is:

```
ε = max_{0 ≤ s ≤ τ} C(M-s, τ-s) / C(M, τ) · N^{-(τ-s)}  ≤  2^{-128}
```

Minimum M for each N (computed by `src/params.py`; τ = ⌈128/log₂N⌉ + 1):

| N | τ | M | Soundness | Offline section |
|--:|--:|--:|:---------:|----------------:|
| 4 | 65 | 218 | 2^{-128.00} | 9.6 KB |
| 8 | 44 | 252 | 2^{-128.05} | 13.0 KB |
| 16 | 33 | 352 | 2^{-128.00} | 19.9 KB |
| 32 | 27 | 462 | 2^{-128.03} | 27.2 KB |
| 64 | 23 | 631 | 2^{-128.03} | 38.0 KB |
| 128 | 20 | 916 | 2^{-128.01} | 56.0 KB |
| 256 | 17 | 1794 | 2^{-128.01} | 111.1 KB |

τ controls prove/verify time; M only affects pass-1 (preprocessing) and the tiny offline proof section.

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
  - Next `144` lines: WOTS+ chain values — 16 bytes (32 hex) each
  - Next `10` lines: XMSS authentication path — 16 bytes (32 hex) each

- **`signature_proof.bin`** (`CLIENT_blind_sign`)
  - Binary KKW proof. Format: `"KKW1"` magic (4 B) + header (N, M, τ, ySize as uint32_t LE, 16 B) + nonce (32 B) + h\* (32 B) + offline section ((M−τ) × 64 B) + online section (τ rounds).
  - A verifier compiled for a different N rejects the proof immediately (parameter mismatch).

## Typical Workflow

1. **Signer** generates keys: `./SIGNER_XMSS_keygen` → `XMSS_secret_key.txt`, `XMSS_public_key.txt`.
2. **Client** blinds a message: `./CLIENT_blinding_message` (prompts for `m`) → `blinding_key.txt` (the secret opening `(r, a)`), `blinded_message.txt` (the commitment `com = a‖b‖y`). The client keeps `(r, a)` secret and sends `com` to the signer.
3. **Signer** signs the commitment: `./SIGNER_XMSS_sign` (reads `XMSS_secret_key.txt`, `blinded_message.txt`; derives `d = SHA256(com)`, signs `d`, self-checks against the public key) → `XMSS_signature.txt`, and advances the leaf index.
4. **Client** proves: `./CLIENT_blind_sign` (prompts for `m`; reads `blinding_key.txt`, `XMSS_signature.txt`, `XMSS_public_key.txt`). It first re-checks that the XMSS signature is valid for `d = SHA256(a‖b‖y)`, then writes the ZK proof to `signature_proof.bin`.
5. **Verifier** checks: `./VERIFIER_verify` (prompts for `m`; reads `XMSS_public_key.txt`, `signature_proof.bin`).

## Performance

Measured on Intel i5-9300H @ 2.40 GHz, 8 threads, 1 iteration (N=4 default):

### Artefact sizes

| Artefact | Size |
|---|---:|
| Public key (`pk_seed ‖ root`) | 32 B |
| Secret key (`sk_seed ‖ pk_seed ‖ leaf_index`) | 52 B |
| Commitment `com = a ‖ b ‖ y` | 256 B |
| Raw XMSS signature (`leaf ‖ nonce ‖ 144 chains ‖ 10 path`) | 2.31 KB |
| **Blind signature (KKW proof, N=4)** | ≈ 106 MB |

### Timing (N=4, τ=65, M=218)

| Phase | Time |
|---|---:|
| Commitment computation | < 1 ms |
| Key generation | ≈ 130 ms |
| Signing | ≈ 130 ms |
| Proof generation | ≈ 4 s |
| Proof verification | ≈ 4 s |

The proof is large because the online section dominates: each of the τ rounds serialises `aux` (ySize words) and `msgs_e` (2·ySize words) for the hidden party, plus the committed output shares for all N parties:

```
proof ≈ header(20) + nonce(32) + h*(32) + (M−τ)·64          [offline, tiny]
       + τ · (sizeof(a) + (N−1)·SEED_SIZE + INPUT_LEN + aux + 2·aux)
       ≈ τ · 3·ySize·4  [dominant term]
       = 65 · 3 · 151776 · 4  ≈  119 MB  [upper bound; conditional terms reduce it]
```

Larger N reduces τ (fewer rounds) → smaller proof, at the cost of more parties per circuit evaluation and a larger M (more preprocessing instances). The offline section grows by only tens of KB.

## References

- [KKW: Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures — Katz, Kolesnikov, Wang, CCS 2018](https://eprint.iacr.org/2018/475)
- [Picnic: Post-Quantum Signatures from Zero-Knowledge Proofs — ePrint 2017/279](https://eprint.iacr.org/2017/279.pdf)
- [XMSS — RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
