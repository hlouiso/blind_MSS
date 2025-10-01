CC = gcc -O2 -Wall

all: CLIENT_blinding_message SIGNER_MSS_keygen SIGNER_MSS_sign CLIENT_blind_sign

CLIENT_blinding_message: CLIENT_blinding_message.c
	$(CC) CLIENT_blinding_message.c -o CLIENT_blinding_message -lcrypto

SIGNER_MSS_keygen: SIGNER_MSS_keygen.c shared.c
	$(CC) SIGNER_MSS_keygen.c shared.c -o SIGNER_MSS_keygen -lcrypto

SIGNER_MSS_sign: SIGNER_MSS_sign.c shared.c
	$(CC) SIGNER_MSS_sign.c shared.c -o SIGNER_MSS_sign -lcrypto

CLIENT_blind_sign: CLIENT_blind_sign.c shared.c building_views.c MPC_prove_functions.c
	$(CC) CLIENT_blind_sign.c shared.c building_views.c MPC_prove_functions.c -o CLIENT_blind_sign -lcrypto

VERIFIER_verify: VERIFIER_verify.c shared.c MPC_verify_functions.c
	$(CC) VERIFIER_verify.c shared.c MPC_verify_functions.c -o VERIFIER_verify -lcrypto

clean:
	rm -f CLIENT_blinding_message SIGNER_MSS_keygen SIGNER_MSS_sign CLIENT_blind_sign MSS*.txt VERIFIER_verify signature_proof.bin
