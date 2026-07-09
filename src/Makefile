# ---------------------------------------------------------------------------
# Cross-platform configuration (macOS + Homebrew clang/libomp, or Linux + gcc).
# Override any of these on the command line, e.g. `make CC=clang-18 OPT=-O0`.
# ---------------------------------------------------------------------------
UNAME_S := $(shell uname -s)
PKG_CONFIG ?= pkg-config

# Default compiler: clang on macOS, gcc on Linux. (`?=` won't override make's
# built-in `cc` default, so override it explicitly only when CC wasn't set by
# the user/environment.)
ifeq ($(origin CC),default)
  ifeq ($(UNAME_S),Darwin)
    CC := clang
  else
    CC := gcc
  endif
endif

# `-Wno-gnu-folding-constant` is a clang-only warning name; gcc rejects it.
WARNINGS = -Wall -Wextra -Werror -Wno-array-parameter
ifneq ($(shell $(CC) --version 2>/dev/null | grep -ci clang),0)
  WARNINGS += -Wno-gnu-folding-constant
endif

# OpenMP: clang needs -Xclang plus libomp's path and -lomp; gcc's -fopenmp does both.
ifeq ($(UNAME_S),Darwin)
  LIBOMP_PREFIX := $(shell brew --prefix libomp 2>/dev/null)
  OMP_CFLAGS = -Xclang -fopenmp -I$(LIBOMP_PREFIX)/include
  OMP_LDFLAGS = -L$(LIBOMP_PREFIX)/lib
  OMP_LIBS = -lomp
else
  OMP_CFLAGS = -fopenmp
  OMP_LDFLAGS =
  OMP_LIBS = -fopenmp
endif

# OpenSSL: prefer pkg-config; fall back to Homebrew on macOS or default paths on Linux.
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
  ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
    OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
    OPENSSL_LIBS   := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
  else
    OPENSSL_LIBS   := -lssl -lcrypto
  endif
endif

OPT ?= -O3
# Tune for the build machine on Linux/x86 (enables AVX2 etc. for the
# auto-vectorised gate loops).  Apple clang on arm64 rejects -march=native and
# already targets NEON+crypto by default, so leave NATIVE empty on Darwin.
ifeq ($(UNAME_S),Linux)
  NATIVE ?= -march=native
endif
BENCH_ITERS ?= 100
CFLAGS = $(OPT) $(NATIVE) $(WARNINGS) $(OMP_CFLAGS) $(OPENSSL_CFLAGS) $(EXTRA_CFLAGS)
ifdef N
CFLAGS += -DN_PARTIES=$(N)
endif
# Grinding parameter (proof-of-work bits on the Fiat-Shamir challenge).
# Supported: 0, 16 (default), 24 — see src/params.py for the (tau, M) tables.
ifdef W
CFLAGS += -DGRIND_W=$(W)
endif
LDFLAGS = $(OMP_LDFLAGS)
LDLIBS = $(OMP_LIBS) $(OPENSSL_LIBS) -lm

# ---------------------------------------------------------------------------
# Library + tests.  This project is a library (libblindmss.a) exercised by the
# programs in tests/; there are no standalone CLI binaries.  `make` builds the
# library, `make test` builds and runs the test suite, `make bench` benchmarks.
# ---------------------------------------------------------------------------
LIB     = libblindmss.a
LIBOBJS = xmss.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o gf128.o commitment.o kkw_prove.o kkw_verify.o

# `make` with no target builds the library (rule order below would otherwise
# make the first object file the default goal).
.DEFAULT_GOAL := lib

# Rebuild all objects (and the library/bench) when N or W changes.  The stamp
# file is named .n_stamp_<N>_w<W>; switching either deletes the old stamp and
# every build product so they are recompiled for the new parameters.
N_ACTUAL := $(if $(N),$(N),default)_w$(if $(W),$(W),default)
N_STAMP  := .n_stamp_$(N_ACTUAL)
$(N_STAMP):
	@rm -f .n_stamp_* $(LIBOBJS) $(LIB) bench_bin bench_pipeline_bin && touch $@
$(LIBOBJS): $(N_STAMP)

# Tests in tests/ (built and run by `make test`).  test_e2e exercises the full
# keygen→blind→sign→prove→verify protocol in memory.
TESTS = test_xmss test_circuit test_roundtrip test_leaf test_e2e

BENCH_NS := 4 8 16 32 64
PIPELINE_ITERS ?= 100

.PHONY: lib all clean test bench bench-pipeline

lib: $(LIB)
all: lib

$(LIB): $(LIBOBJS)
	$(AR) rcs $@ $(LIBOBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Build each test against the library (-I. so tests/ finds the headers) and run it.
test: $(LIB)
	@set -e; for t in $(TESTS); do \
		echo "=== $$t ==="; \
		$(CC) $(CFLAGS) -I. tests/$$t.c $(LIB) $(LDFLAGS) $(LDLIBS) -o tests/$$t; \
		./tests/$$t; \
	done

bench_bin: $(LIB) bench.c
	$(CC) $(CFLAGS) -DBENCH_ITERS=$(BENCH_ITERS) bench.c $(LIB) $(LDFLAGS) $(LDLIBS) -o bench_bin

# Run the full benchmark for all N values in sequence.
# Output: one header line then one result row per N (stdout).
# Progress per iteration printed to stderr.
bench:
	@$(MAKE) --no-print-directory N=4 bench_bin
	@./bench_bin --header
	@for n in $(BENCH_NS); do \
		$(MAKE) --no-print-directory N=$$n bench_bin; \
		./bench_bin; \
	done

# Full-pipeline benchmark (commitment / sign / prove / verify) for one N.
# Override iteration count: make N=<N> PIPELINE_ITERS=<k> bench-pipeline
bench_pipeline_bin: $(LIB) bench_pipeline.c
	$(CC) $(CFLAGS) -DPIPELINE_ITERS=$(PIPELINE_ITERS) bench_pipeline.c $(LIB) $(LDFLAGS) $(LDLIBS) -o bench_pipeline_bin

bench-pipeline: bench_pipeline_bin
	@./bench_pipeline_bin

# Only named build artifacts — no *.txt / *.bin globs, which would delete
# tracked files if any lived here (see root Makefile).
clean:
	rm -f $(LIB) bench_bin bench_pipeline_bin *.o .n_stamp_* $(addprefix tests/,$(TESTS))
