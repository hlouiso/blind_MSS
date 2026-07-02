# Blind XMSS (target-sum WOTS+) with KKW (MPC-in-the-Head)

This project implements a **blind signature** over **XMSS** (a stateful Merkle signature scheme) with **target-sum WOTS+** one-time signatures in the leaves, and a zero-knowledge proof in the **KKW / MPC-in-the-head** style (Katz-Kolesnikov-Wang 2018) to prove knowledge of a valid signature **without revealing** the secret material (the commitment opening, the leaf index, or the signature).

The commitment scheme is **Halevi–Micali over GF(2¹²⁸)**, the signature is target-sum WOTS+/XMSS, and the NIZK is KKW (cut-and-choose over MPC preprocessing).

> ⚠️ This code is for research/education. Do not use in production.

## Context

This work was carried out during my final internship for the Master's degree in **Cryptology and Computer Security** at the [University of Bordeaux](https://mastercsi.labri.fr/). The internship took place in the first half of 2025 at [UPC (Barcelona)](https://www.upc.edu/ca), supervised by [Javier Herranz Sotoca](https://web.mat.upc.edu/javier.herranz/).

## Build & test

Requirements:
- A C compiler (GCC/Clang) with OpenMP support
- OpenSSL **libcrypto**
- `make`

```bash
make          # build the static library libblindmss.a (default N=4)
make N=<N>    # build with N a multiple of 4 ∈ {4, 8, …, 32} ∪ {64, 128, 256}
make test     # build and run the test suite
make bench    # benchmark all N values
make clean    # remove build products
```

The project builds a single static library, `libblindmss.a`. The programs in
`src/tests/` link against it; [`test_e2e`](src/tests/test_e2e.c) runs the whole
keygen → blind → sign → prove → verify protocol in memory.

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
- `ySize = 152504` — nonlinear-gate count in the SHA-256/WOTS/XMSS circuit

### Soundness parameters (128-bit security, ROM)

The KKW cut-and-choose soundness formula is:

```
ε = max_{0 ≤ s ≤ τ} C(M-s, τ-s) / C(M, τ) · N^{-(τ-s)}  ≤  2^{-128}
```

Minimum M for each N (computed by `src/params.py`; τ = ⌈128/log₂N⌉ + 1). For
N ≤ 128 these reproduce Table 1 (ρ = 128) of the KKW paper exactly:

| N | τ | M | Soundness | Offline section |
|--:|--:|--:|:---------:|----------------:|
| 4 | 65 | 218 | 2^{-128.00} | 14.3 KB |
| 8 | 44 | 252 | 2^{-128.05} | 19.5 KB |
| 16 | 33 | 352 | 2^{-128.00} | 29.9 KB |
| 32 | 27 | 462 | 2^{-128.03} | 40.8 KB |
| 64 | 23 | 631 | 2^{-128.03} | 57.0 KB |
| 128 | 20 | 916 | 2^{-128.01} | 84.0 KB |
| 256 | 17 | 1794 | 2^{-128.01} | 166.6 KB |

τ controls prove/verify time; M only affects pass-1 (preprocessing) and the tiny
offline proof section (96 bytes per checked instance: seed\* + h'_j + h_out).

## Library API

Everything is exposed as a C library (`libblindmss.a`); the headers in `src/`
are the API. The full flow is shown in [`src/tests/test_e2e.c`](src/tests/test_e2e.c):

- **Key generation** — `xmss_compute_root(sk_seed, pk_seed, root)` builds the
  Merkle tree and returns the public root (`xmss.h`).
- **Blinding** — `hm_commit(m_hat, r, a, com, d)` produces the Halevi–Micali
  commitment `com = a‖b‖y` and the certified digest `d = SHA256(com)`
  (`commitment.h`). The opening `(r, a)` is the client's secret.
- **Signing** — `xmss_sign(sk_seed, pk_seed, leaf, d, 32, &sig)` target-sum
  WOTS+/XMSS-signs the digest; `xmss_verify(...)` checks it (`xmss.h`).
- **Proving** — `kkw_prove(input, m_hat, pk_seed, pubout, out)` writes the KKW
  proof, where `input` is the witness (opening + leaf index + signature, laid
  out per `circuits.h`) and `pubout = root ‖ target_sum` (`kkw_prove.h`).
- **Verifying** — `kkw_verify(proof, m_hat, pk_seed, pubout)` returns 0 iff the
  proof is valid (`kkw_verify.h`).

The proof is a byte stream (a `FILE *`, e.g. an on-disk file or `tmpfile()`), so
it can be stored or sent over a wire between the client and the verifier. Its
format is `"KKW2"` magic (4 B) + header (N, M, τ, ySize as uint32_t LE, 16 B) +
nonce (32 B) + h\* (32 B) + offline section ((M−τ) × 96 B) + online section
(τ rounds). A verifier built for a different N rejects it on the header check.

## Protocol

The three parties never share secrets:

1. **Signer** generates `(sk_seed, pk_seed)` and publishes `pk_seed ‖ root`.
2. **Client** blinds its message `m` into `com` and keeps the opening `(r, a)`
   secret; it sends only `com` to the signer.
3. **Signer** signs `d = SHA256(com)` with the next XMSS leaf and returns the
   raw signature — it never learns `m` or the opening.
4. **Client** builds a KKW zero-knowledge proof that it holds a valid XMSS
   signature on a commitment to `m`, **without** revealing the opening, the
   leaf index, or the signature.
5. **Verifier** checks the proof against `pk_seed ‖ root` and `m`.

## Performance

Measured on Intel i5-9300H @ 2.40 GHz, 8 threads, 1 iteration (N=4 default):

### Artefact sizes

| Artefact | Size |
|---|---:|
| Public key (`pk_seed ‖ root`) | 32 B |
| Secret key (`sk_seed ‖ pk_seed ‖ leaf_index`) | 52 B |
| Commitment `com = a ‖ b ‖ y` | 256 B |
| Raw XMSS signature (`leaf ‖ nonce ‖ 144 chains ‖ 10 path`) | 2.42 KB |
| **Blind signature (KKW proof, N=4)** | ≈ 108 MB |

### Timing (N=4, τ=65, M=218)

| Phase | Time |
|---|---:|
| Commitment computation | < 1 ms |
| Key generation | ≈ 130 ms |
| Signing | ≈ 130 ms |
| Proof generation | ≈ 1.8 s |
| Proof verification | ≈ 0.9 s |

Prove/verify times reflect the word-parallel MPC gates (SIMD over parties via
portable vector extensions — SSE on x86, NEON on arm64) and single-shot
AES-CTR tape expansion; the transcript is bit-identical to the reference
bit-serial implementation.

The proof is large because the online section dominates: each of the τ rounds serialises `aux` (ySize words) and `msgs_e` (2·ySize words) for the hidden party, plus the committed output shares for all N parties:

```
proof ≈ header(20) + nonce(32) + h*(32) + (M−τ)·96          [offline, tiny]
       + τ · (sizeof(a) + (N−1)·SEED_SIZE + INPUT_LEN + aux + 2·aux)
       ≈ τ · 3·ySize·4  [dominant term]
       = 65 · 3 · 152504 · 4  ≈  119 MB  [upper bound; conditional terms reduce it]
```

Larger N reduces τ (fewer rounds) → smaller proof, at the cost of more parties per circuit evaluation and a larger M (more preprocessing instances). The offline section grows by only tens of KB.

## References

- [KKW: Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures — CCS 2018](https://eprint.iacr.org/2018/475)
- [Picnic: Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives — CCS 2017](https://eprint.iacr.org/2017/279)
- [XMSS — RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
