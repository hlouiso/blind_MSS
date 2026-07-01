#!/usr/bin/env python3
"""
KKW soundness parameter calculator.

Correct formula (Katz-Kolesnikov-Wang 2018, cut-and-choose):

  eps = max_{0 <= s <= tau} C(M-s, tau-s) / C(M, tau) * N^{-(tau-s)}

Adversary strategy: corrupt s preprocessing instances (forces output=pubout
for any hidden party); predict party e for the tau-s honest online instances
(probability 1/N each). The s corrupted instances must all land in the online
set; the offline check catches corrupted instances via aux recomputation.

Usage:
  python3 params.py              # print table for N in {4,8,16,32,64,128,256}
  python3 params.py N tau M      # print soundness bits for specific parameters
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


if len(sys.argv) == 4:
    N, tau, M = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    print(f"N={N}, tau={tau}, M={M}: {soundness_bits(M, tau, N):.4f} bits")
    sys.exit(0)

print(f"{'N':>4} {'tau':>4} {'M':>5}  soundness       offline_KB")
for N in list(range(4, 33, 4)) + [64, 128, 256]:
    tau = math.ceil(128.0 / math.log2(N)) + 1
    M = min_M(N, tau)
    bits = soundness_bits(M, tau, N)
    offline_kb = (M - tau) * 96 / 1024  # seed* (32) + h'_j (32) + h_out (32)
    print(f"{N:>4} {tau:>4} {M:>5}  2^{{-{bits:.2f}}}  {offline_kb:8.1f} KB")
