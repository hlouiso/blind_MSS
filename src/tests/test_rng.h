#ifndef BLIND_MSS_TEST_RNG_H
#define BLIND_MSS_TEST_RNG_H

#include <stddef.h>
#include <stdint.h>

/* Deterministic test-data generator. This is intentionally not suitable for
 * keys or protocol randomness; production paths use randombytes_fill(). */
static inline void test_random_bytes(void *buffer, size_t length)
{
    static uint64_t state = UINT64_C(0x6a09e667f3bcc909);
    uint8_t *out = buffer;
    size_t offset = 0;

    while (offset < length) {
        uint64_t z = (state += UINT64_C(0x9e3779b97f4a7c15));
        z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
        z ^= z >> 31;
        for (size_t i = 0; i < 8 && offset < length; i++, offset++)
            out[offset] = (uint8_t)(z >> (8 * i));
    }
}

#endif /* BLIND_MSS_TEST_RNG_H */
