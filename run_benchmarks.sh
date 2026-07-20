#!/bin/bash
# Full blind-signature pipeline benchmark for N = 4, 8, 16, 32, 64.
# Measures commitment / sign / prove / verify (time + cycles) and proof size,
# PIPELINE_ITERS runs per N, and writes everything into one results file.
#
# Usage:
#   ./run_benchmarks.sh                     # 100 iterations per N (default)
#   PIPELINE_ITERS=20 ./run_benchmarks.sh   # fewer iterations (faster)
#   PLAYERS="4 8" PIPELINE_ITERS=1 ./run_benchmarks.sh  # smoke/subset run
#   KEEP_BUILD=1 ./run_benchmarks.sh         # retain the CMake build tree
#   SHUTDOWN=1 ./run_benchmarks.sh          # power off the machine when finished
#
# To keep it running after you close the terminal:
#   nohup ./run_benchmarks.sh > output/bench.log 2>&1 &
#
# At 100 iterations the whole run takes ~1 h with the BLAKE3 circuit
# (N=64 alone ~30 min; it was ~9 h in the pre-optimization SHA-256 era).
# Per-iteration progress is printed to the terminal; the tables go to the file.
#
# SHUTDOWN=1 powers off only AFTER all files are written and synced to disk, and
# only if the run completed without error. `shutdown` needs root, and in a
# detached (nohup) run sudo cannot prompt for a password, so enable passwordless
# shutdown once (replace `hugo` with your user):
#   echo 'hugo ALL=(root) NOPASSWD: /sbin/shutdown, /usr/sbin/shutdown' \
#     | sudo tee /etc/sudoers.d/benchmark-shutdown
# To cancel a pending shutdown:  sudo shutdown -c

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

ITERS=${PIPELINE_ITERS:-100}
PLAYERS=${PLAYERS:-"4 8 16 32 64"}
OUT=${OUT:-$SCRIPT_DIR/output/pipeline_bench.txt}
BENCH_BUILD_DIR="$SCRIPT_DIR/build/pipeline-bench"
mkdir -p "$SCRIPT_DIR/output"
: > "$OUT"

echo "Full pipeline benchmark — players=[$PLAYERS], $ITERS iterations per N — started $(date)" >> "$OUT"
echo >> "$OUT"

for n in $PLAYERS; do
    echo ">>> N=$n (building + running $ITERS iterations) ..." >&2
    make --no-print-directory N="$n" PIPELINE_ITERS="$ITERS" \
        BUILD_DIR="$BENCH_BUILD_DIR" bench_pipeline_bin
    start=$(date +%s)
    "$BENCH_BUILD_DIR/bench_pipeline_bin" >> "$OUT"
    end=$(date +%s)
    echo "  (wall time for the N=$n run: $((end - start)) s)" >> "$OUT"
    echo >> "$OUT"
done

echo "Done — $(date)" >> "$OUT"
if [ "${KEEP_BUILD:-0}" != "1" ]; then
    make --no-print-directory clean >/dev/null 2>&1 || true
fi

# Make sure every result is flushed from the page cache to the physical disk
# before we consider the run complete (important if we are about to power off).
sync

echo "" >&2
echo "Results written to $OUT" >&2

# Optional power-off, only reached if everything above succeeded.
if [ "${SHUTDOWN:-0}" = "1" ]; then
    echo "All files written and synced — scheduling shutdown in 1 minute." >&2
    echo "Cancel with:  sudo shutdown -c" >&2
    sudo shutdown -h +1 || echo "shutdown failed (need passwordless sudo — see script header)" >&2
fi
