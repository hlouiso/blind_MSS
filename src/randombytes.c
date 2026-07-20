#include "randombytes.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__) || defined(__linux__)
#include <sys/random.h>
#else
#error "blind-mss randombytes supports macOS and Linux"
#endif

/* POSIX getentropy() accepts at most 256 bytes per call. Keeping that limit
 * here also gives Linux getrandom()'s small-request, all-bytes semantics. */
#define BLIND_MSS_GETENTROPY_MAX 256u

int randombytes_fill(void *buffer, size_t length)
{
    if (length != 0 && buffer == NULL) {
        errno = EINVAL;
        return 0;
    }

    uint8_t *out = buffer;
    const size_t original_length = length;
    while (length != 0) {
        const size_t chunk = length < BLIND_MSS_GETENTROPY_MAX
                                 ? length
                                 : BLIND_MSS_GETENTROPY_MAX;
        if (getentropy(out, chunk) != 0) {
            const int saved_errno = errno;
            memset(buffer, 0, original_length);
            errno = saved_errno;
            return 0;
        }
        out += chunk;
        length -= chunk;
    }
    return 1;
}
