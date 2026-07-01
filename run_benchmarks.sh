#!/bin/bash
# Full blind-signature pipeline benchmark for N = 4, 8, 16, 32, 64.
# Measures commitment / sign / prove / verify (time + cycles) and proof size,
# PIPELINE_ITERS runs per N, and writes everything into one results file.
#
# Usage:
#   ./run_benchmarks.sh                     # 100 iterations per N (default)
#   PIPELINE_ITERS=20 ./run_benchmarks.sh   # fewer iterations (faster)
#   SHUTDOWN=1 ./run_benchmarks.sh          # power off the machine when finished
#
# To keep it running after you close the terminal:
#   nohup ./run_benchmarks.sh > output/bench.log 2>&1 &
#
# WARNING: at 100 iterations, N=64 alone takes ~6 h (the whole run ~9 h).
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
cd "$(dirname "$0")/src"

ITERS=${PIPELINE_ITERS:-100}
OUT=../output/pipeline_bench.txt
mkdir -p ../output
: > "$OUT"

echo "Full pipeline benchmark — $ITERS iterations per N — started $(date)" >> "$OUT"
echo >> "$OUT"

for n in 4 8 16 32 64; do
    echo ">>> N=$n (building + running $ITERS iterations) ..." >&2
    make --no-print-directory N=$n PIPELINE_ITERS=$ITERS bench_pipeline_bin 2>/dev/null
    start=$(date +%s)
    ./bench_pipeline_bin >> "$OUT"
    end=$(date +%s)
    echo "  (wall time for the N=$n run: $((end - start)) s)" >> "$OUT"
    echo >> "$OUT"
done

echo "Done — $(date)" >> "$OUT"
make --no-print-directory clean >/dev/null 2>&1 || true

# Make sure every result is flushed from the page cache to the physical disk
# before we consider the run complete (important if we are about to power off).
sync

echo "" >&2
echo "Results written to output/pipeline_bench.txt" >&2

# Optional power-off, only reached if everything above succeeded.
if [ "${SHUTDOWN:-0}" = "1" ]; then
    echo "All files written and synced — scheduling shutdown in 1 minute." >&2
    echo "Cancel with:  sudo shutdown -c" >&2
    sudo shutdown -h +1 || echo "shutdown failed (need passwordless sudo — see script header)" >&2
fi
