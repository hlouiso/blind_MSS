/* Standalone self-test for the native target-sum WOTS+/XMSS module.
 * Build:  clang -O2 -Wall -Wextra -I/opt/homebrew/opt/openssl/include \
 *            xmss.c test_xmss.c -L/opt/homebrew/opt/openssl/lib -lcrypto -o test_xmss
 */
#include "xmss.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg)                                                                                          \
    do                                                                                                            \
    {                                                                                                             \
        if (cond)                                                                                                 \
            printf("  ok   %s\n", msg);                                                                           \
        else                                                                                                      \
        {                                                                                                         \
            printf("  FAIL %s\n", msg);                                                                           \
            failures++;                                                                                           \
        }                                                                                                         \
    } while (0)

int main(void)
{
    uint8_t sk_seed[32];
    uint8_t pk_seed[XMSS_PK_SEED_BYTES];
    RAND_bytes(sk_seed, sizeof sk_seed);
    RAND_bytes(pk_seed, sizeof pk_seed);

    /* --- determinism of keygen --- */
    xmss_node root1, root2;
    xmss_compute_root(sk_seed, pk_seed, root1);
    xmss_compute_root(sk_seed, pk_seed, root2);
    CHECK(memcmp(root1, root2, XMSS_NODE_BYTES) == 0, "root is deterministic in (sk_seed, pk_seed)");

    int nonzero = 0;
    for (int i = 0; i < XMSS_NODE_BYTES; i++)
        nonzero |= root1[i];
    CHECK(nonzero != 0, "root is non-zero");

    /* --- WOTS+ chain consistency: pk_from_sig(sign(sk,c),c) == pk_from_sk(sk) --- */
    {
        xmss_node sk[XMSS_WOTS_LEN], sig[XMSS_WOTS_LEN], pk_a[XMSS_WOTS_LEN], pk_b[XMSS_WOTS_LEN];
        uint8_t coords[XMSS_WOTS_LEN];
        xmss_wots_gen_sk(sk_seed, 7, sk);
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
        {
            uint8_t r;
            RAND_bytes(&r, 1);
            coords[i] = r & 0x3; /* random 0..3 */
        }
        xmss_wots_sign(pk_seed, sk, coords, sig);
        xmss_wots_pk_from_sig(pk_seed, sig, coords, pk_a);
        xmss_wots_pk_from_sk(pk_seed, sk, pk_b);
        CHECK(memcmp(pk_a, pk_b, sizeof pk_a) == 0, "WOTS+ chain endpoints agree for random coords");
    }

    /* --- sign / verify round-trips at several leaves --- */
    const uint32_t leaves[] = {0, 1, 2, 511, 512, 1023};
    int all_valid = 1, all_target = 1;
    for (size_t t = 0; t < sizeof leaves / sizeof leaves[0]; t++)
    {
        uint8_t msg[32];
        RAND_bytes(msg, sizeof msg);
        xmss_sig sig;
        int ok = xmss_sign(sk_seed, pk_seed, leaves[t], msg, sizeof msg, &sig);
        if (!ok)
        {
            all_valid = 0;
            continue;
        }
        /* confirm the grind really hit the target sum */
        uint8_t mh[32], coords[XMSS_WOTS_LEN];
        xmss_hash_message(pk_seed, sig.nonce, XMSS_NONCE_LEN, msg, sizeof msg, mh);
        xmss_extract_coords(mh, XMSS_WOTS_LEN, XMSS_COORD_RES_BITS, coords);
        int sum = 0;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
            sum += coords[i];
        if (sum != XMSS_TARGET_SUM)
            all_target = 0;

        if (!xmss_verify(pk_seed, root1, msg, sizeof msg, &sig))
            all_valid = 0;
    }
    CHECK(all_target, "grind always lands on the target sum");
    CHECK(all_valid, "valid signatures verify at leaves 0,1,2,511,512,1023");

    /* --- negative tests --- */
    {
        uint8_t msg[32];
        RAND_bytes(msg, sizeof msg);
        xmss_sig sig;
        if (!xmss_sign(sk_seed, pk_seed, 42, msg, sizeof msg, &sig))
        {
            printf("  FAIL could not sign for negative tests\n");
            failures++;
        }
        else
        {
            CHECK(xmss_verify(pk_seed, root1, msg, sizeof msg, &sig), "baseline valid before tampering");

            xmss_sig bad = sig;
            bad.sig_hashes[3][0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, root1, msg, sizeof msg, &bad), "tampered sig_hash rejected");

            bad = sig;
            bad.auth_path[2][0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, root1, msg, sizeof msg, &bad), "tampered auth path rejected");

            bad = sig;
            bad.leaf_index ^= 1;
            CHECK(!xmss_verify(pk_seed, root1, msg, sizeof msg, &bad), "wrong leaf index rejected");

            uint8_t msg2[32];
            memcpy(msg2, msg, 32);
            msg2[0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, root1, msg2, sizeof msg2, &sig), "wrong message rejected");

            uint8_t other_root[XMSS_NODE_BYTES];
            memcpy(other_root, root1, XMSS_NODE_BYTES);
            other_root[0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, other_root, msg, sizeof msg, &sig), "wrong root rejected");
        }
    }

    printf("\n%s (%d failure%s)\n", failures == 0 ? "ALL PASS" : "FAILURES", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
