# Blind XMSS (target-sum WOTS+) with KKW (MPC-in-the-Head)

This project implements a **blind signature** over **XMSS** (a stateful Merkle signature scheme) with **target-sum WOTS+** one-time signatures in the leaves, and a zero-knowledge proof in the **KKW / MPC-in-the-head** style (Katz-Kolesnikov-Wang 2018) to prove knowledge of a valid signature **without revealing** the secret material (the commitment opening, the leaf index, or the signature).

The commitment scheme is **Halevi–Micali over GF(2¹²⁸)**, the signature is target-sum WOTS+/XMSS, and the NIZK is KKW (cut-and-choose over MPC preprocessing). All hashing — in-circuit **and** in the KKW layer (commitments, Fiat–Shamir, challenge PRG) — is a **tweakable hash Th built on the raw BLAKE3 compression function** (the construction of [binius64 PR #1620](https://github.com/binius-zk/binius64/pull/1620)), each call site under its own fixed domain (`shared.h`), so the whole scheme rests on a single hash assumption. The only remaining OpenSSL primitives are AES-256-CTR (tape-expansion PRF) and `RAND_bytes`.

> ⚠️ This code is for research/education. Do not use in production.

## Build & test

Requirements:
- A C compiler (GCC/Clang) with OpenMP support
- OpenSSL **libcrypto**
- `make`

```bash
make          # build the static library libblindmss.a (default N=4)
make N=<N>    # build with N a multiple of 4 ∈ {4, 8, …, 32} ∪ {64, 128, 256}
make SEC=256  # post-quantum parameter set (ρ=256; default 128 is classical)
make test     # build and run the test suite
make bench    # benchmark all N values
make clean    # remove build products
```

The project builds a single static library, `libblindmss.a`. The programs in
`src/tests/` link against it; [`test_e2e`](src/tests/test_e2e.c) runs the whole
keygen → blind → sign → prove → verify protocol in memory.

## Parameters

Signature scheme (`xmss.h`), following the Binius64 BLAKE3 instantiation:
- `XMSS_H = 10` — Merkle tree height (`2^10 = 1024` signatures per key pair)
- `XMSS_WOTS_W = 2` — Winternitz parameter (1-bit coordinates)
- `XMSS_WOTS_LEN = 144` — number of WOTS+ chains (target-sum encoding, no checksum)
- `XMSS_TARGET_SUM = 72` — required sum of the 144 coordinates
- `XMSS_NODE_BYTES = 16` — every internal node is a Th output truncated to 128 bits
- `XMSS_PK_SEED_BYTES = 16`, `XMSS_NONCE_LEN = 6`
- All hashing is the BLAKE3-compression tweakable hash `Th(domain, data)`
  (`blake3.h`), SPHINCS+-style keyed/tweaked: domain separators `0x00` chain,
  `0x01` tree, `0x02` message, `0x03` leaf/pk. This is **not** BLAKE3-the-hash:
  no tree mode, so outputs do not match BLAKE3 digests, and the byte formats
  are no longer compatible with the SHA-256 blind-longfellow instantiation.
  The security assumption is that the BLAKE3 compression function is ideal —
  the same heuristic SPHINCS+ makes for its tweakable hashes (cf.
  SPHINCS+-Haraka), and the construction follows Binius64's reviewed BLAKE3
  XMSS verifier (their audit items S1–S5 are mapped to this codebase in
  `OPTIMIZATIONS.txt`, entry 11) with two zero-cost strengthenings over the
  PR: `domain_len` is bound into the chaining value (structural domain
  separation across lengths) and the final compression carries the `ROOT`
  flag (`Th` is not length-extendable).

Halevi–Micali commitment (`commitment.h`):
- `HM_NONCES = 6`, `HM_LINES = 2`, field `GF(2¹²⁸)` — structure as in the Longfellow-based instantiation, hashes moved to `Th("HMy", ·)` / `Th("HMd", ·)`.
- Opening `(r, a)` is `96 + 192 = 288` bytes; the commitment `com = a‖b‖y` is `256` bytes.

KKW proof (`shared.h`, selectable at build time with `N=<N>` and `W=<W>`):
- `N_PARTIES` — number of MPC parties (default 4)
- `NUM_ROUNDS` (`τ`) — online rounds included in the proof; drives prove/verify cost
- `M_KKW` (`M`) — total preprocessing instances; drives pass-1 cost (offline section ≈ negligible)
- `GRIND_W` (`W`, default 16) — FAESTER-style grinding: the Fiat–Shamir challenge
  hash must end in `W` zero bits, found by counting a `ctr` (~2^W short hashes at
  prove time, one-time). Every forgery attempt pays the same 2^W, so the
  cut-and-choose target relaxes to 2^-(128-W) and τ shrinks — total attack cost
  stays 2^128. Supported: 0, 16, 24 (τ = 65/57/53 at N=4).
- `INPUT_LEN = 2762` — witness byte length
- `ySize = 73096` — nonlinear-gate count in the BLAKE3-Th/WOTS/XMSS circuit
  (was 152504 with SHA-256: BLAKE3's compression costs 336 gate slots vs 728,
  and the tweak moves into the chaining value instead of consuming blocks)

### Soundness parameters (128-bit security, ROM)

The KKW cut-and-choose soundness formula is:

```
ε = max_{0 ≤ s ≤ τ} C(M-s, τ-s) / C(M, τ) · N^{-(τ-s)}  ≤  2^{-128}
```

Minimum M for each N (computed by `src/params.py`; τ = ⌈128/log₂N⌉ + 1). For
N ≤ 128 these reproduce Table 1 (ρ = 128) of the KKW paper exactly:

| N | τ | M | Soundness |
|--:|--:|--:|:---------:|
| 4 | 65 | 218 | 2^{-128.00} |
| 8 | 44 | 252 | 2^{-128.05} |
| 16 | 33 | 352 | 2^{-128.00} |
| 32 | 27 | 462 | 2^{-128.03} |
| 64 | 23 | 631 | 2^{-128.03} |
| 128 | 20 | 916 | 2^{-128.01} |
| 256 | 17 | 1794 | 2^{-128.01} |

τ controls prove/verify time; M only affects pass-1 (preprocessing) and the tiny
offline proof section (64 bytes per checked instance: seed\* + h'_j).

### Classical vs. post-quantum target

The tables above (and the default build) are KKW Table 1's **ρ = 128** column —
a **classical** 128-bit Fiat–Shamir soundness bound. KKW themselves size their
post-quantum signature parameters at **ρ = 256** (§3.2: M, n, τ set so that
ε ≤ 2^-256). The reason: a quantum forger can Grover-search the grinding
counter over the combined predicate [W zero bits ∧ cheatable challenge] at cost
√(1/(2^-W · ε)), so 128-bit post-quantum security needs ε ≤ 2^-(256-W) —
grinding still buys exactly W bits, but off a 2λ baseline. Build it with
`make SEC=256` (τ = ⌈(256-W)/log₂N⌉ + 1; tables in `shared.h`, from
`params.py`). At the default W = 16:

| N | τ | M |
|--:|--:|--:|
| 4 | 121 | 426 |
| 8 | 81 | 524 |
| 16 | 61 | 726 |
| 64 | 41 | 1645 |

Two caveats that belong in any write-up: there is no general security proof for
the Fiat–Shamir transform against quantum adversaries (KKW §3.1 point to
Unruh's transform for that), and whether the 2λ doubling is truly necessary is
debated (cf. FAEST and refined Grover-on-Fiat–Shamir bounds) — ρ = 256 is the
conservative margin, not a theorem.

## Library API

Everything is exposed as a C library (`libblindmss.a`); the headers in `src/`
are the API. The full flow is shown in [`src/tests/test_e2e.c`](src/tests/test_e2e.c):

- **Key generation** — `xmss_compute_root(sk_seed, pk_seed, root)` builds the
  Merkle tree and returns the public root (`xmss.h`).
- **Blinding** — `hm_commit(m_hat, r, a, com, d)` produces the Halevi–Micali
  commitment `com = a‖b‖y` and the certified digest `d = Th("HMd", com)`
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
format is `"KKW9"` magic (4 B) + header (N, M, τ, ySize, W, SEC as uint32_t, 24 B) +
nonce (32 B) + h\* (32 B) + grinding counter `ctr` (4 B) +
offline section ((M−τ) × 64 B: seed\*_j + h'_j) + online section (τ rounds:
com_hidden, the `yp` output-mask shares, N−1 seeds, the masked witness `d`,
`aux` (absent when party 0 is hidden), `msgs_e`, and the 32 B commitment
randomiser `r_j` that blinds `h'_j` for the unopened instances; the online
`h'_j` and offline `h_out_j` are recomputed by the verifier, not sent). The
verifier rejects trailing bytes, and a verifier built for different parameters
rejects the proof on the header check.

## Protocol

The three parties never share secrets:

1. **Signer** generates `(sk_seed, pk_seed)` and publishes `pk_seed ‖ root`.
2. **Client** blinds its message `m` into `com` and keeps the opening `(r, a)`
   secret; it sends only `com` to the signer.
3. **Signer** signs `d = Th("HMd", com)` with the next XMSS leaf and returns
   the raw signature — it never learns `m` or the opening.
4. **Client** builds a KKW zero-knowledge proof that it holds a valid XMSS
   signature on a commitment to `m`, **without** revealing the opening, the
   leaf index, or the signature.
5. **Verifier** checks the proof against `pk_seed ‖ root` and `m`.

## References

- [KKW: Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures — CCS 2018](https://eprint.iacr.org/2018/475)
- [Picnic: Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives — CCS 2017](https://eprint.iacr.org/2017/279)
- [XMSS — RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391) (this target-sum BLAKE3 variant is not RFC 8391)
- [binius64 PR #1620 — BLAKE3 tweakable-hash XMSS verifier](https://github.com/binius-zk/binius64/pull/1620) (the Th construction followed here)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) (only the raw compression function is used)
