PROGS = CLIENT_blinding_message SIGNER_XMSS_keygen SIGNER_XMSS_sign CLIENT_blind_sign VERIFIER_verify

.PHONY: all clean test help

all:
	$(MAKE) -C src
	mv src/CLIENT_blinding_message .
	mv src/SIGNER_XMSS_keygen .
	mv src/SIGNER_XMSS_sign .
	mv src/CLIENT_blind_sign .
	mv src/VERIFIER_verify .

# Build and run the regression tests in src/tests/.
test:
	$(MAKE) -C src test

# Delegate to src (cleans src/*.o, src-built binaries, and src/tests/ binaries),
# then remove the binaries moved up here.  Only named build artifacts — no
# *.txt / *.bin globs, which would delete tracked files like OPTIMIZATIONS.txt.
clean:
	$(MAKE) -C src clean
	rm -f $(PROGS) *.o

help:
	@echo "Usage: make <target>"
	@echo
	@echo "Targets:"
	@echo "  all            Build all binaries: $(PROGS)"
	@echo "  test           Build and run the regression tests in src/tests/"
	@echo "  clean          Remove binaries (root, src/, src/tests/) and intermediates"
	@echo
	@echo "Binaries:"
	@echo "  CLIENT_blinding_message  Client: blind a message"
	@echo "  SIGNER_XMSS_keygen        Signer: generate XMSS keys"
	@echo "  SIGNER_XMSS_sign          Signer: sign a blinded message"
	@echo "  CLIENT_blind_sign        Client: produce ZK proof (ZKBoo/MPC-in-the-head)"
	@echo "  VERIFIER_verify          Verify the proof against the public key"
