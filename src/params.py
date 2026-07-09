#!/usr/bin/env python3
"""
KKW soundness parameter calculator.

Correct formula (Katz-Kolesnikov-Wang 2018, cut-and-choose):

  eps = max_{0 <= s <= tau} C(M-s, tau-s) / C(M, tau) * N^{-(tau-s)}

Adversary strategy: corrupt s preprocessing instances (forces output=pubout
for any hidden party); predict party e for the tau-s honest online instances
(probability 1/N each). The s corrupted instances must all land in the online
set; the offline check catches corrupted instances via aux recomputation.

With grinding (GRIND_W = w bits of proof-of-work on the Fiat-Shamir hash,
FAESTER-style), the cut-and-choose only needs 2^-(SEC-w): every challenge
attempt costs the forger 2^w hashes, so total attack cost stays 2^SEC.

SEC = 128 is KKW Table 1's rho=128 column — a CLASSICAL soundness bound.
SEC = 256 is the rho=256 column KKW use for post-quantum claims (a quantum
forger Grover-searches ctr over the combined predicate [w zero bits AND
cheatable challenge] at cost sqrt(1/(2^-w * eps)), so eps <= 2^-(256-w)
keeps the attack at 2^128; the 2*lambda margin is conservative, not proven).

Usage:
  python3 params.py                    # tables for SEC in {128,256}, w in {0,16,24}
  python3 params.py N tau M [w] [SEC]  # soundness bits for specific parameters
"""

import math
import sys


def log2_binom(n, k):
    if k < 0 or k > n:
        return float("-inf")
    k = min(k, n - k)
    result = 0.0
    for i in range(k):
        result += math.log2(n - i) - math.log2(i + 1)
    return result


def soundness_bits(M, tau, N):
    """Return -log2(eps) for the KKW cut-and-choose soundness formula."""
    lb = log2_binom(M, tau)
    best = float("-inf")
    for s in range(tau + 1):
        v = log2_binom(M - s, tau - s) - lb - (tau - s) * math.log2(N)
        if v > best:
            best = v
    return -best


def min_M(N, tau, target_bits=128.0):
    """Minimum M achieving at least target_bits of soundness."""
    lo, hi = tau + 1, 10000
    while lo < hi:
        mid = (lo + hi) // 2
        if soundness_bits(mid, tau, N) >= target_bits:
            hi = mid
        else:
            lo = mid + 1
    return lo


if len(sys.argv) >= 4:
    N, tau, M = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    w = int(sys.argv[4]) if len(sys.argv) >= 5 else 0
    sec = int(sys.argv[5]) if len(sys.argv) >= 6 else 128
    print(f"N={N}, tau={tau}, M={M}: {soundness_bits(M, tau, N):.4f} bits "
          f"(target {sec - w} with w={w}, SEC={sec})")
    sys.exit(0)

for sec in (128, 256):
    for w in (0, 16, 24):
        target = float(sec - w)
        print(f"--- SEC = {sec}, GRIND_W = {w} (cut-and-choose target 2^-{sec - w}) ---")
        print(f"{'N':>4} {'tau':>4} {'M':>5}  soundness       offline_KB")
        for N in list(range(4, 33, 4)) + [64, 128, 256]:
            tau = math.ceil(target / math.log2(N)) + 1
            M = min_M(N, tau, target)
            bits = soundness_bits(M, tau, N)
            offline_kb = (M - tau) * 64 / 1024  # seed* (32) + h'_j (32)
            print(f"{N:>4} {tau:>4} {M:>5}  2^{{-{bits:.2f}}}  {offline_kb:8.1f} KB")
