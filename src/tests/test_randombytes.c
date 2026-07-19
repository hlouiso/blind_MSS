#include "randombytes.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); failures++; } \
} while (0)

int main(void)
{
    uint8_t small[1], boundary[256], chunked[257], large[8192];

    CHECK(randombytes_fill(NULL, 0), "zero-length request succeeds");
    CHECK(randombytes_fill(small, sizeof small), "one-byte request succeeds");
    CHECK(randombytes_fill(boundary, sizeof boundary),
          "256-byte boundary request succeeds");
    CHECK(randombytes_fill(chunked, sizeof chunked),
          "257-byte request crosses the getentropy boundary");
    CHECK(randombytes_fill(large, sizeof large),
          "multi-kilobyte request is filled in chunks");

    errno = 0;
    CHECK(!randombytes_fill(NULL, 1) && errno == EINVAL,
          "non-empty null request fails with EINVAL");

    /* This is only a smoke check that calls produced output, not a statistical
     * test of the operating system generator. */
    uint8_t zeros[sizeof boundary];
    memset(zeros, 0, sizeof zeros);
    CHECK(memcmp(boundary, zeros, sizeof boundary) != 0,
          "OS generator overwrites the destination");

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
