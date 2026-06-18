/* Standalone cross-check for the prover circuit (building_views):
 * builds a real native XMSS signature, runs the ZKBoo prover circuit on the
 * shared witness, and confirms the reconstructed output (root | codeword sum)
 * matches the native values.  Also prints the exact gate count (countY) used to
 * size ySize / Random_Bytes_Needed.
 *
 * Build:
 *   clang -O2 -Wall -Wextra -Wno-array-parameter -I/opt/homebrew/opt/openssl/include \
 *     circuits.c MPC_prove_functions.c MPC_verify_functions.c shared.c xmss.c test_circuit.c \
 *     -L/opt/homebrew/opt/openssl/lib -lcrypto -o test_circuit
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

#define YBIG 300000              /* generous per-view transcript size (words) */
#define RBIG (4 * YBIG + 64)     /* generous random-tape size (bytes) */

int main(void)
{
    /* ---- native key + signature on a commitment M = SHA256(m_hat || r) ---- */
    unsigned char sk_seed[32], pk_seed[XMSS_PK_SEED_BYTES];
    RAND_bytes(sk_seed, sizeof sk_seed);
    RAND_bytes(pk_seed, sizeof pk_seed);

    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    unsigned char m_hat[32], r[32];
    RAND_bytes(m_hat, sizeof m_hat);
    RAND_bytes(r, sizeof r);

    unsigned char preM[64];
    memcpy(preM, m_hat, 32);
    memcpy(preM + 32, r, 32);
    unsigned char M[32];
    SHA256(preM, 64, M);

    uint32_t leaf_index = 0;
    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, leaf_index, M, 32, &sig))
    {
        printf("FAIL: native signing failed\n");
        return 1;
    }
    if (!xmss_verify(pk_seed, root, M, 32, &sig))
    {
        printf("FAIL: native signature does not verify\n");
        return 1;
    }

    /* ---- assemble the witness in the new layout ---- */
    unsigned char input[1354];
    memcpy(input + W_R_OFF, r, 32);
    input[W_LEAFIDX_OFF + 0] = (leaf_index >> 24) & 0xFF;
    input[W_LEAFIDX_OFF + 1] = (leaf_index >> 16) & 0xFF;
    input[W_LEAFIDX_OFF + 2] = (leaf_index >> 8) & 0xFF;
    input[W_LEAFIDX_OFF + 3] = (leaf_index) & 0xFF;
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    if ((int)W_END != INPUT_LEN)
    {
        printf("FAIL: witness layout mismatch (W_END=%d INPUT_LEN=%d)\n", (int)W_END, INPUT_LEN);
        return 1;
    }

    /* ---- XOR-share the witness across 3 parties ---- */
    unsigned char *shares[3], *randomness[3];
    View *views[3];
    for (int k = 0; k < 3; k++)
    {
        shares[k] = malloc(INPUT_LEN);
        randomness[k] = malloc(RBIG);
        RAND_bytes(randomness[k], RBIG);
        views[k] = malloc(sizeof(View));
        views[k]->x = shares[k];
        views[k]->y = malloc((size_t)YBIG * sizeof(uint32_t));
    }
    RAND_bytes(shares[0], INPUT_LEN);
    RAND_bytes(shares[1], INPUT_LEN);
    for (int j = 0; j < INPUT_LEN; j++)
        shares[2][j] = input[j] ^ shares[0][j] ^ shares[1][j];

    /* ---- run the prover circuit ---- */
    a A;
    building_views(&A, m_hat, pk_seed, shares, randomness, views);

    /* ---- reconstruct and compare ---- */
    unsigned char circ_root[16];
    for (int w = 0; w < YP_ROOT_WORDS; w++)
    {
        uint32_t v = A.yp[0][w] ^ A.yp[1][w] ^ A.yp[2][w];
        memcpy(circ_root + w * 4, &v, 4);
    }
    uint32_t circ_sum = A.yp[0][YP_SUM_WORD] ^ A.yp[1][YP_SUM_WORD] ^ A.yp[2][YP_SUM_WORD];

    int ok_root = (memcmp(circ_root, root, 16) == 0);
    int ok_sum = (circ_sum == (uint32_t)XMSS_TARGET_SUM);

    printf("  circuit root  %s native root\n", ok_root ? "==" : "!=  MISMATCH");
    printf("  circuit sum   = %u (target %d) %s\n", circ_sum, XMSS_TARGET_SUM, ok_sum ? "ok" : "MISMATCH");
    printf("  gate count (countY) = %d   -> set ySize=%d, Random_Bytes_Needed=%d\n", g_circuit_gates,
           g_circuit_gates, 4 * g_circuit_gates);

    for (int k = 0; k < 3; k++)
    {
        free(shares[k]);
        free(randomness[k]);
        free(views[k]->y);
        free(views[k]);
    }

    if (ok_root && ok_sum)
    {
        printf("\nCIRCUIT OK\n");
        return 0;
    }
    printf("\nCIRCUIT FAILED\n");
    return 1;
}
