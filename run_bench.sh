#!/bin/bash
# Run the blind-signature pipeline benchmark for a chosen number of players (N)
# and a chosen number of loops (iterations). Results go into one file in output/.
#
# Usage:
#   ./run_bench.sh <players> <loops>
#
#   players : number of MPC parties N — any multiple of 4 in 4..32, or 64, 128, 256.
#             A space-separated list runs several in sequence, e.g. "4 8 16".
#   loops   : number of iterations per N.
#
# Examples:
#   ./run_bench.sh 8 100
#   ./run_bench.sh "4 8 16" 50
#
# Optional environment:
#   OUT=/path/results.txt ./run_bench.sh 8 100   # choose the results file
#   SHUTDOWN=1            ./run_bench.sh 64 100   # power off when finished
#                                                 # (needs passwordless sudo)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Arguments ───────────────────────────────────────────────────────────────
if [ $# -lt 2 ]; then
    echo "Usage: $0 <players> <loops>" >&2
    echo "  players : N multiple of 4 in 4..32, or 64, 128, 256 (a list like \"4 8 16\" runs several)" >&2
    echo "  loops   : iterations per N" >&2
    exit 1
fi
PLAYERS="$1"
LOOPS="$2"

if ! [[ "$LOOPS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: loops must be a positive integer (got '$LOOPS')" >&2
    exit 1
fi
for n in $PLAYERS; do
    if ! [[ "$n" =~ ^[0-9]+$ ]]; then
        echo "Error: players must be integers (got '$n')" >&2; exit 1
    fi
    if ! { { [ "$n" -ge 4 ] && [ "$n" -le 32 ] && [ $((n % 4)) -eq 0 ]; } \
           || [ "$n" = 64 ] || [ "$n" = 128 ] || [ "$n" = 256 ]; }; then
        echo "Error: unsupported N '$n' (allowed: multiples of 4 in 4..32, or 64, 128, 256)" >&2; exit 1
    fi
done

# ── Output file ─────────────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/output"
OUT="${OUT:-$SCRIPT_DIR/output/pipeline_$(date +%Y%m%d_%H%M%S).txt}"
: > "$OUT"
echo "Pipeline benchmark — players=[$PLAYERS], loops=$LOOPS — $(date)" >> "$OUT"
echo >> "$OUT"

# ── Run ─────────────────────────────────────────────────────────────────────
cd "$SCRIPT_DIR/src"
for n in $PLAYERS; do
    echo ">>> N=$n ($LOOPS iterations) ..." >&2
    make --no-print-directory N="$n" PIPELINE_ITERS="$LOOPS" bench_pipeline_bin 2>/dev/null
    start=$(date +%s)
    ./bench_pipeline_bin >> "$OUT"
    end=$(date +%s)
    echo "  (wall time for the N=$n run: $((end - start)) s)" >> "$OUT"
    echo >> "$OUT"
done

echo "Done — $(date)" >> "$OUT"
make --no-print-directory clean >/dev/null 2>&1 || true
sync

echo "" >&2
echo "Results written to $OUT" >&2

if [ "${SHUTDOWN:-0}" = "1" ]; then
    echo "Scheduling shutdown in 1 minute (cancel: sudo shutdown -c)" >&2
    sudo shutdown -h +1 || echo "shutdown failed (need passwordless sudo — see run_benchmarks.sh header)" >&2
fi
