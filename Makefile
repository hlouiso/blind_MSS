# Root Makefile — the build lives in src/; this just delegates to it.
#
# The project builds a single static library, libblindmss.a, plus an in-memory
# regression test suite and two benchmark programs.  The build options
#   N=<N>          parties (multiple of 4 in {4..32}, or 64/128/256; default 4)
#   W=<W>          Fiat-Shamir grinding bits (0, 16 [default], 24)
#   SEC=<128|256>  security target (128 classical [default], 256 post-quantum)
# are command-line variables, so `make N=8 SEC=256` propagates them to src/.

.PHONY: all lib test bench bench-pipeline clean help

all lib:
	$(MAKE) -C src lib

# Build and run the regression tests in src/tests/.
test:
	$(MAKE) -C src test

# Benchmark all supported N values (one result row per N).
bench:
	$(MAKE) -C src bench

# Full-pipeline benchmark (commitment / sign / prove / verify) for one N.
bench-pipeline:
	$(MAKE) -C src bench-pipeline

# Remove all build products (src/*.o, the library, benchmark and test binaries).
clean:
	$(MAKE) -C src clean

help:
	@echo "Usage: make <target> [N=<N>] [W=<W>] [SEC=<128|256>]"
	@echo
	@echo "Targets:"
	@echo "  make            Build the static library libblindmss.a (default N=4)"
	@echo "  test            Build and run the regression tests in src/tests/"
	@echo "  bench           Benchmark all supported N values"
	@echo "  bench-pipeline  Full-pipeline benchmark for one N"
	@echo "  clean           Remove build products"
	@echo
	@echo "Options:"
	@echo "  N=<N>           Parties: multiple of 4 in {4..32}, or 64, 128, 256 (default 4)"
	@echo "  W=<W>           Fiat-Shamir grinding bits: 0, 16 (default), 24"
	@echo "  SEC=<128|256>   Security target: 128 classical (default), 256 post-quantum"
