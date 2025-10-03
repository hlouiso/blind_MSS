PROGS = CLIENT_blinding_message SIGNER_MSS_keygen SIGNER_MSS_sign CLIENT_blind_sign VERIFIER_verify

all:
	$(MAKE) -C src
	mv src/CLIENT_blinding_message .
	mv src/SIGNER_MSS_keygen .
	mv src/SIGNER_MSS_sign .
	mv src/CLIENT_blind_sign .
	mv src/VERIFIER_verify .

clean:
	rm -f $(PROGS) *.o MSS*.txt *.bin src/*.o

help:
	@echo "Usage: make <target>"
	@echo
	@echo "Targets:"
	@echo "  all            Build all binaries: $(PROGS)"
	@echo "  clean          Remove binaries and intermediates"
	@echo
	@echo "Binaries:"
	@echo "  CLIENT_blinding_message  Client: blind a message"
	@echo "  SIGNER_MSS_keygen        Signer: generate MSS keys"
	@echo "  SIGNER_MSS_sign          Signer: sign a blinded message"
	@echo "  CLIENT_blind_sign        Client: produce ZK proof (ZKBoo/MPC-in-the-head)"
	@echo "  VERIFIER_verify          Verify the proof against the public key"
