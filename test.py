import time
import os
import random
import string

L = []
test = 16
length = 10000
for i in range(test):
    length += 1
    message = ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=length))
    L.append(message)

S = 0
for i in range(test):
    os.system("echo %s | ./CLIENT_blinding_message" % L[i])
    os.system("./SIGNER_MSS_sign")
    os.system("echo %s | ./CLIENT_blind_sign" % L[i])
    S = S - time.time()
    os.system("echo %s | ./VERIFIER_verify" % L[i])
    S = S + time.time()
print(S/test)
-+