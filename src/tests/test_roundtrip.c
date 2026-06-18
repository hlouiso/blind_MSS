/* Fast in-process prove -> verify check for ONE ZKBoo round (validates that
 * verify() mirrors building_views before wiring the full binaries).
 *
 * Build:
 *   clang -O2 -Wall -Wextra -Wno-gnu-folding-constant -Wno-array-parameter \
 *     -I/opt/homebrew/opt/openssl/include circuits.c MPC_prove_functions.c \
 *     MPC_verify_functions.c shared.c xmss.c test_roundtrip.c \
 *     -L/opt/homebrew/opt/openssl/lib -lcrypto -o test_roundtrip
 */
#include "circuits.h"
#include "shared.h"
#include "xmss.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m)                                                                                                \
    do                                                                                                             \
    {                                                                                                              \
        printf("  %s %s\n", (c) ? "ok  " : "FAIL", m);                                                            \
        if (!(c))                                                                                                  \
            failures++;                                                                                            \
    } while (0)

int main(void)
{
    unsigned char sk_seed[32], pk_seed[XMSS_PK_SEED_BYTES];
    RAND_bytes(sk_seed, sizeof sk_seed);
    RAND_bytes(pk_seed, sizeof pk_seed);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    unsigned char m_hat[32], r[32];
    RAND_bytes(m_hat, sizeof m_hat);
    RAND_bytes(r, sizeof r);
    unsigned char preM[64], M[32];
    memcpy(preM, m_hat, 32);
    memcpy(preM + 32, r, 32);
    SHA256(preM, 64, M);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, 0, M, 32, &sig))
    {
        printf("native sign failed\n");
        return 1;
    }

    unsigned char input[1354];
    memcpy(input + W_R_OFF, r, 32);
    memset(input + W_LEAFIDX_OFF, 0, 4); /* leaf 0 */
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    /* expected public output: root | target sum | 0 */
    uint32_t pubout[8] = {0};
    for (int w = 0; w < 4; w++)
        memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ---- prover: one round ---- */
    unsigned char *shares[3], *randomness[3];
    View *views[3];
    unsigned char keys[3][32], rs[3][32];
    RAND_bytes((unsigned char *)keys, sizeof keys);
    RAND_bytes((unsigned char *)rs, sizeof rs);
    for (int k = 0; k < 3; k++)
    {
        shares[k] = malloc(INPUT_LEN);
        randomness[k] = malloc(Random_Bytes_Needed);
        views[k] = malloc(sizeof(View));
        views[k]->x = shares[k];
        views[k]->y = malloc((size_t)ySize * sizeof(uint32_t));
    }
    RAND_bytes(shares[0], INPUT_LEN);
    RAND_bytes(shares[1], INPUT_LEN);
    for (int j = 0; j < INPUT_LEN; j++)
        shares[2][j] = input[j] ^ shares[0][j] ^ shares[1][j];
    for (int k = 0; k < 3; k++)
        getAllRandomness(keys[k], randomness[k]);

    a A;
    building_views(&A, m_hat, pk_seed, shares, randomness, views);

    int out_ok = 1;
    for (int j = 0; j < 8; j++)
        if ((A.yp[0][j] ^ A.yp[1][j] ^ A.yp[2][j]) != pubout[j])
            out_ok = 0;
    CHECK(out_ok, "prover output XOR == (root | target-sum | 0)");

    for (int k = 0; k < 3; k++)
        H_com(keys[k], views[k], rs[k], A.h[k]);

    /* ---- verify each challenge e in {0,1,2} ---- */
    for (int e = 0; e < 3; e++)
    {
        z Z;
        int e1 = (e + 1) % 3;
        memcpy(Z.ke, keys[e], 32);
        memcpy(Z.ke1, keys[e1], 32);
        memcpy(Z.re, rs[e], 32);
        memcpy(Z.re1, rs[e1], 32);
        Z.ve.x = views[e]->x;
        Z.ve.y = malloc((size_t)ySize * sizeof(uint32_t));
        Z.ve1.x = views[e1]->x;
        Z.ve1.y = views[e1]->y;

        bool err = false;
        verify(m_hat, pk_seed, &err, &A, e, &Z);
        char msg[40];
        snprintf(msg, sizeof msg, "verify accepts honest proof (e=%d)", e);
        CHECK(!err, msg);
        free(Z.ve.y);
    }

    /* ---- tamper: corrupt a sig_hash share, expect rejection ---- */
    {
        shares[0][W_SIG_OFF] ^= 0x01;
        building_views(&A, m_hat, pk_seed, shares, randomness, views);
        int still_root = ((A.yp[0][0] ^ A.yp[1][0] ^ A.yp[2][0]) == pubout[0]);
        for (int k = 0; k < 3; k++)
            H_com(keys[k], views[k], rs[k], A.h[k]);
        /* the tampered witness yields a different root (output check fails) */
        CHECK(!still_root, "tampered witness changes the circuit output (root mismatch)");
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
