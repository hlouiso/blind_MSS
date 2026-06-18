CC = clang
CFLAGS = -Xclang -fopenmp -O2 -Wall -Wextra -Werror -Wno-gnu-folding-constant -Wno-array-parameter -I/opt/homebrew/opt/libomp/include -I/opt/homebrew/opt/openssl/include
LDFLAGS = -L/opt/homebrew/opt/libomp/lib -L/opt/homebrew/opt/openssl/lib
LDLIBS = -lomp -lssl -lcrypto

PROGS = CLIENT_blinding_message SIGNER_XMSS_keygen SIGNER_XMSS_sign CLIENT_blind_sign VERIFIER_verify

# Non-main library objects shared by the binaries and the tests.
LIBOBJS = xmss.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o
# Regression tests in tests/ (built and run by `make test`).
TESTS = test_xmss test_circuit test_roundtrip

.PHONY: all clean test

all: $(PROGS)

CLIENT_blinding_message: CLIENT_blinding_message.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_XMSS_keygen: SIGNER_XMSS_keygen.o xmss.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_XMSS_sign: SIGNER_XMSS_sign.o xmss.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

CLIENT_blind_sign: CLIENT_blind_sign.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o xmss.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

VERIFIER_verify: VERIFIER_verify.o shared.o circuits.o MPC_verify_functions.o MPC_prove_functions.o
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

