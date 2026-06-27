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

OPT ?= -O2
BENCH_ITERS ?= 100
CFLAGS = $(OPT) $(WARNINGS) $(OMP_CFLAGS) $(OPENSSL_CFLAGS) $(EXTRA_CFLAGS)
ifdef N
CFLAGS += -DN_PARTIES=$(N)
endif
LDFLAGS = $(OMP_LDFLAGS)
LDLIBS = $(OMP_LIBS) $(OPENSSL_LIBS) -lm

PROGS = CLIENT_blinding_message SIGNER_XMSS_keygen SIGNER_XMSS_sign CLIENT_blind_sign VERIFIER_verify

# The N-stamp rules below come first textually, so set the default goal
# explicitly: otherwise `make` (no target) would pick the first normal target
# it finds (xmss.o) instead of building all the programs.
.DEFAULT_GOAL := all

# Non-main library objects shared by the binaries and the tests.
# LIBOBJS must be defined before the N-stamp rules so $(LIBOBJS) expands
# correctly in both the rule target and the recipe.
LIBOBJS = xmss.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o gf128.o commitment.o kkw_prove.o kkw_verify.o

# Rebuild all objects (and bench_bin) if N changes.
# The stamp file is named .n_stamp_<N>; switching N deletes the old stamp,
# all .o files, and bench_bin so they are rebuilt fresh for the new N.
N_ACTUAL := $(if $(N),$(N),default)
N_STAMP  := .n_stamp_$(N_ACTUAL)
$(N_STAMP):
	@rm -f .n_stamp_* $(LIBOBJS) bench_bin && touch $@
$(LIBOBJS): $(N_STAMP)
# Regression tests in tests/ (built and run by `make test`).
TESTS = test_xmss test_circuit test_roundtrip

BENCH_NS := 4 8 16 32 64

.PHONY: all clean test bench

all: $(PROGS)

CLIENT_blinding_message: CLIENT_blinding_message.o commitment.o gf128.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_XMSS_keygen: SIGNER_XMSS_keygen.o xmss.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_XMSS_sign: SIGNER_XMSS_sign.o xmss.o commitment.o gf128.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

CLIENT_blind_sign: CLIENT_blind_sign.o kkw_prove.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o xmss.o commitment.o gf128.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

VERIFIER_verify: VERIFIER_verify.o kkw_verify.o shared.o circuits.o MPC_verify_functions.o MPC_prove_functions.o commitment.o gf128.o xmss.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Build each test against the library objects (-I. so tests/ finds the headers) and run it.
test: $(LIBOBJS)
	@set -e; for t in $(TESTS); do \
		echo "=== $$t ==="; \
		$(CC) $(CFLAGS) -I. tests/$$t.c $(LIBOBJS) $(LDFLAGS) $(LDLIBS) -o tests/$$t; \
		./tests/$$t; \
	done

bench_bin: $(LIBOBJS) bench.c
	$(CC) $(CFLAGS) -DBENCH_ITERS=$(BENCH_ITERS) bench.c $(LIBOBJS) $(LDFLAGS) $(LDLIBS) -o bench_bin

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

clean:
	rm -f $(PROGS) bench_bin *.o .n_stamp_* *.txt *.bin $(addprefix tests/,$(TESTS))

