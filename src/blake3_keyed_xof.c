#include "blake3_keyed_xof.h"
#include "third_party/blake3/blake3.h"

#include <assert.h>
#include <string.h>

_Static_assert(BLIND_MSS_BLAKE3_KEY_LEN == BLAKE3_KEY_LEN,
               "blind-mss and BLAKE3 key lengths must agree");

void blake3_keyed_xof(const uint8_t key[BLIND_MSS_BLAKE3_KEY_LEN],
                      const char *domain,
                      const void *input, size_t input_len,
                      uint8_t *out, size_t out_len)
{
    static const uint8_t framing[] = "blind-mss BLAKE3 keyed XOF v1";
    uint8_t domain_len_le[8];
    size_t domain_len;
    uint64_t domain_len64;

    assert(key != NULL);
    assert(domain != NULL);
    assert(input != NULL || input_len == 0);
    assert(out != NULL || out_len == 0);

    domain_len = strlen(domain);
    domain_len64 = (uint64_t)domain_len;
    for (size_t i = 0; i < sizeof domain_len_le; i++)
        domain_len_le[i] = (uint8_t)(domain_len64 >> (8 * i));

    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key);
    /* sizeof includes the terminating NUL, making the framing prefix-free. */
    blake3_hasher_update(&hasher, framing, sizeof framing);
    blake3_hasher_update(&hasher, domain_len_le, sizeof domain_len_le);
    blake3_hasher_update(&hasher, domain, domain_len);
    if (input_len != 0)
        blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out, out_len);
}
