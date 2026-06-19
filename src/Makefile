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
CFLAGS = $(OPT) $(WARNINGS) $(OMP_CFLAGS) $(OPENSSL_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS = $(OMP_LDFLAGS)
LDLIBS = $(OMP_LIBS) $(OPENSSL_LIBS)

PROGS = CLIENT_blinding_message SIGNER_XMSS_keygen SIGNER_XMSS_sign CLIENT_blind_sign VERIFIER_verify

# Non-main library objects shared by the binaries and the tests.
LIBOBJS = xmss.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o gf128.o commitment.o
# Regression tests in tests/ (built and run by `make test`).
TESTS = test_xmss test_circuit test_roundtrip

.PHONY: all clean test

all: $(PROGS)

CLIENT_blinding_message: CLIENT_blinding_message.o commitment.o gf128.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_XMSS_keygen: SIGNER_XMSS_keygen.o xmss.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_XMSS_sign: SIGNER_XMSS_sign.o xmss.o commitment.o gf128.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

CLIENT_blind_sign: CLIENT_blind_sign.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o xmss.o commitment.o gf128.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

VERIFIER_verify: VERIFIER_verify.o shared.o circuits.o MPC_verify_functions.o MPC_prove_functions.o commitment.o gf128.o
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

clean:
	rm -f $(PROGS) *.o *.txt *.bin $(addprefix tests/,$(TESTS))

