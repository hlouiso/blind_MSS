CC = gcc
CFLAGS = -O2 -Wall
LDLIBS = -lcrypto

PROGS = CLIENT_blinding_message SIGNER_MSS_keygen SIGNER_MSS_sign CLIENT_blind_sign VERIFIER_verify

all: $(PROGS)

CLIENT_blinding_message: CLIENT_blinding_message.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_MSS_keygen: SIGNER_MSS_keygen.o shared.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

SIGNER_MSS_sign: SIGNER_MSS_sign.o shared.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

CLIENT_blind_sign: CLIENT_blind_sign.o shared.o circuits.o MPC_prove_functions.o MPC_verify_functions.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

VERIFIER_verify: VERIFIER_verify.o shared.o circuits.o MPC_verify_functions.o MPC_prove_functions.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(PROGS) *.o MSS*.txt *.bin

