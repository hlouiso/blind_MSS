# Blind MSS (WOTS-OTS) with ZKBoo (MPC-in-the-Head)

This project implements a **blind signature**  over an **MSS (Merkle Signature Scheme)** using **WOTS** as the one-time signature (OTS) and a ZK proof in the **ZKBoo / MPC-in-the-head** style to prove knowledge of a valid signature **without revealing** secret material.

> ⚠️ This code is for research/education. Do not use in production.

## Context

This work was carried out during my final internship for the Master's degree in **Cryptology and Computer Security** at the [University of Bordeaux](https://mastercsi.labri.fr/). The internship took place in the first half of 2025 at [UPC (Barcelona)](https://www.upc.edu/ca), supervised by [Javier Herranz Sotoca](https://web.mat.upc.edu/javier.herranz/).

## Build

Requirements:
- A C compiler (GCC/Clang)
- OpenSSL **libcrypto**
- `make`

Build everything:
```bash
make
```

Clean:
```bash
make clean
```

Binaries produced:
- `CLIENT_blinding_message` (client)
- `SIGNER_MSS_keygen` (signer)
- `SIGNER_MSS_sign` (signer)
- `CLIENT_blind_sign` (client)
- `VERIFIER_verify` (verifier / anyone)

## Parameters (hard-coded)

From `shared.c`:
- `H = 10` (Merkle tree height → `2^10 = 1024` leaves)
- `N = 32` (byte length of hashes / words)
- `WOTS_len = 512` (number of WOTS chain elements)

## Files & Formats

All hex in files is **UPPERCASE** without spaces.

- **`MSS_secret_key.txt`** (created by `SIGNER_MSS_keygen`)
  - **Line 1:** `sk_seed` — 32 bytes as 64 hex chars
  - **Line 2:** `leaf_index` — decimal (initially `0`)

- **`MSS_public_key.txt`** (created by `SIGNER_MSS_keygen`)
  - Merkle-tree root — 32 bytes as 64 hex chars, newline-terminated

- **`MSS_signature.txt`** (created by `SIGNER_MSS_sign`)
  - **Line 1:** `leaf_index` — decimal
  - **Line 2:** empty line
  - **Lines 3 .. 3+WOTS_len-1:** WOTS signature; each line is **32 bytes** (64 hex chars)
  - **Next line:** empty line
  - **Next `H` lines:** authentication path; each line is **32 bytes** (64 hex chars)

- **`signature_proof.bin`** (created by `CLIENT_blind_sign`)
  - Binary ZK proof (ZKBoo/MPC-in-the-head) that a valid MSS signature exists for the committed message.

## Typical Workflow

1) **Signer** generates keys
   ```bash
   ./SIGNER_MSS_keygen
   ```
   Produces `MSS_secret_key.txt` and `MSS_public_key.txt`. Prints the public key and the secret seed to stdout as a convenience.

2) **Client** blinds a message
   ```bash
   ./CLIENT_blinding_message
   ```
   - Prompts: plaintext message `m` (one line from stdin).

   - Produces: 
   - `blinding_key.txt` with **Blinding key `r`** (32 bytes, 64 hex chars)
   - `blinded_messge.txt` with **Blinded message** (64 bytes, 128 hex chars) defined as `commitment || ~commitment`, where `commitment = SHA256( SHA256(m) || r )`.

   Client keeps `r` secret and sends the **blinded message** to the signer.

3) **Signer** signs the **blinded message**
   ```bash
   ./SIGNER_MSS_sign
   ```
   - Reads `MSS_secret_key.txt`, `blinded_messge.txt`

   - Produces `MSS_signature.txt` with: `leaf_index`, the WOTS signature (512 × 32-byte lines), and the Merkle authentication path (10 × 32-byte lines).

4) **Client** produces a zero-knowledge **signature proof**
   ```bash
   ./CLIENT_blind_sign
   ```
   - Prompts for:
     - plaintext message `m` (stdin)

   - Reads: `blinding_key.txt`, `MSS_signature.txt`, `MSS_public_key.txt`
   - Verifies internal consistency; on success writes **`signature_proof.bin`**.  
     If anything is inconsistent (message or `r` doesn’t match, signature invalid, etc.), it prints an error and exits.

5) **Verifier** checks the proof against the public key and message
   ```bash
   ./VERIFIER_verify
   ```
   - Prompts for the **signed message** `m` (stdin).
   - Reads: `MSS_public_key.txt` and `signature_proof.bin`.
   - Prints success/failure.

## Binary Summaries

- **CLIENT_blinding_message**
  - Input: message `m` from stdin
  - Output (stdout): blinding key `r` (32 bytes), and the 64-byte **blinded message**
  - Files: none

- **SIGNER_MSS_keygen**
  - Output files: `MSS_secret_key.txt`, `MSS_public_key.txt`

- **SIGNER_MSS_sign**
  - Input: blinded message (128 hex chars) from stdin
  - Reads: `MSS_secret_key.txt`
  - Output file: `MSS_signature.txt`

- **CLIENT_blind_sign**
  - Inputs: message `m` (stdin), blinding key `r` (64 hex chars)
  - Reads: `MSS_signature.txt`, `MSS_public_key.txt`
  - Output file: `signature_proof.bin`

- **VERIFIER_verify**
  - Input: message `m` (stdin)
  - Reads: `MSS_public_key.txt`, `signature_proof.bin`
  - Output: success/failure (stdout)

## References

- [ZKBoo: Faster Zero-Knowledge for Boolean Circuits — ePrint 2016/163](https://eprint.iacr.org/2016/163)
- [GitHub Repository for Original ZKBoo Implementation (Aarhus University) - Proof of knowledge of a SHA-256 preimage](https://github.com/Sobuno/ZKBoo)