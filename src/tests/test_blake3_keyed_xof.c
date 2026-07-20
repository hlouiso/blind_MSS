#include "blake3_keyed_xof.h"
#include <blake3.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); failures++; } \
} while (0)

static int hex2bin(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return 0;
        out[i] = (uint8_t)byte;
    }
    return hex[2 * out_len] == '\0';
}

static void test_official_keyed_xof_vector(void)
{
    static const uint8_t key_string[] =
        "whats the Elvish word for friend";
    static const char expected_hex[] =
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"
        "b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3"
        "b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758"
        "be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851"
        "bc8f";
    uint8_t expected[131], got[131];
    blake3_hasher hasher;

    CHECK(sizeof key_string - 1 == BLAKE3_KEY_LEN,
          "official keyed-XOF test key is 32 bytes");
    blake3_hasher_init_keyed(&hasher, key_string);
    blake3_hasher_finalize(&hasher, got, sizeof got);
    CHECK(hex2bin(expected_hex, expected, sizeof expected),
          "official keyed-XOF vector parses");
    CHECK(memcmp(got, expected, sizeof got) == 0,
          "official BLAKE3 keyed-XOF vector (empty input, 131 bytes)");
    CHECK(strcmp(blake3_version(), "1.8.5") == 0,
          "upstream BLAKE3 version is pinned to 1.8.5");
}

static void test_protocol_framing(void)
{
    uint8_t key[32], a[256], b[256], c[256], d[256], e[256];
    uint8_t expected_a[32], expected_c[32], expected_d[32], expected_e[32];
    const uint8_t input_a[4] = {0, 0, 0, 7};
    const uint8_t input_b[4] = {0, 0, 0, 8};
    for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8_t)i;

    blake3_keyed_xof(key, BLAKE3_XOF_DOM_KKW_TAPE,
                     NULL, 0, a, sizeof a);
    blake3_keyed_xof(key, BLAKE3_XOF_DOM_KKW_TAPE,
                     NULL, 0, b, sizeof b);
    blake3_keyed_xof(key, BLAKE3_XOF_DOM_KKW_XSHARE,
                     NULL, 0, c, sizeof c);
    blake3_keyed_xof(key, BLAKE3_XOF_DOM_KKW_SEEDS,
                     NULL, 0, e, sizeof e);
    blake3_keyed_xof(key, BLAKE3_XOF_DOM_XMSS_WOTS_SK,
                     input_a, sizeof input_a, d, sizeof d);

    CHECK(hex2bin("25fec9eb5e0f7bc5af433f28bb7f5f0f"
                  "717c1e99cffb0125702050e38028734e",
                  expected_a, sizeof expected_a) &&
          memcmp(a, expected_a, sizeof expected_a) == 0,
          "KKW tape expansion matches the frozen protocol vector");
    CHECK(hex2bin("64dbd414d1bddab02d994a3ce02eb1d7"
                  "2e5e13939c0553b818676974be0f4748",
                  expected_d, sizeof expected_d) &&
          memcmp(d, expected_d, sizeof expected_d) == 0,
          "XMSS WOTS expansion matches the frozen protocol vector");
    CHECK(hex2bin("ff41afeb9f91916ce4e17c1443cb343e"
                  "9c2f63f2e39e61f2f3844a45dedf44d0",
                  expected_c, sizeof expected_c) &&
          memcmp(c, expected_c, sizeof expected_c) == 0,
          "KKW witness-mask expansion matches the frozen protocol vector");
    CHECK(hex2bin("2dee42a38feac242bd503d30ba3e632a"
                  "b4415bcd0ef84504b932de9da5727f9d",
                  expected_e, sizeof expected_e) &&
          memcmp(e, expected_e, sizeof expected_e) == 0,
          "KKW party-seed expansion matches the frozen protocol vector");

    CHECK(memcmp(a, b, sizeof a) == 0, "protocol XOF is deterministic");
    CHECK(memcmp(a, c, sizeof a) != 0, "KKW expansion domains are separated");
    CHECK(memcmp(a, e, sizeof a) != 0 && memcmp(c, e, sizeof c) != 0,
          "all three KKW expansion domains are distinct");
    CHECK(memcmp(a, d, sizeof a) != 0, "KKW and XMSS domains are separated");

    blake3_keyed_xof(key, BLAKE3_XOF_DOM_XMSS_WOTS_SK,
                     input_b, sizeof input_b, c, sizeof c);
    CHECK(memcmp(c, d, sizeof c) != 0, "XMSS leaf indices are separated");
}

int main(void)
{
    printf("--- Official BLAKE3 keyed-XOF tests ---\n");
    test_official_keyed_xof_vector();
    test_protocol_framing();
    printf("\n%s (%d failure%s)\n", failures == 0 ? "ALL PASS" : "FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
