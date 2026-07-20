#ifndef BLIND_MSS_RANDOMBYTES_H
#define BLIND_MSS_RANDOMBYTES_H

#include <stddef.h>

/* Fill `buffer` with bytes from the operating system's cryptographic random
 * generator. Returns 1 on success and 0 on failure, preserving errno. */
int randombytes_fill(void *buffer, size_t length);

#endif /* BLIND_MSS_RANDOMBYTES_H */
