/* End-to-end in-memory integration test of the full blind-signature protocol:
 *
 *   keygen  →  blind (Halevi–Micali commit)  →  XMSS sign  →  KKW prove  →  KKW verify
 *
 * This drives the real library API directly (no files, no subprocesses), and is
 * the reference test for the complete protocol. The honest path must verify; a
 * tampered message or a wrong public key must be rejected.
 *
 * The proof is a byte stream, so it travels through an in-memory tmpfile() the
 * same way it would travel over a wire between the client and the verifier.
 */
#include "../circuits.h"
#include "../commitment.h"
#include "../kkw_prove.h"
#include "../kkw_verify.h"
#include "../shared.h"
#include "../xmss.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { \
    printf("  %s %s\n", (c) ? "ok  " : "FAIL", (m)); \
    if (!(c)) failures++; \
} while (0)

/* Run keygen + blind + sign + witness assembly exactly as the separate parties
 * would, leaving the prover's inputs (input, m_hat, pk_seed, pubout) ready. */
static void run_parties(unsigned char input[W_END], unsigned char m_hat[32],
                        unsigned char pk_seed[XMSS_PK_SEED_BYTES], uint32_t pubout[8])
{
    /* ── Signer: key generation ── */
    unsigned char sk_seed[32];
    RAND_bytes(sk_seed, 32);
    RAND_bytes(pk_seed, XMSS_PK_SEED_BYTES);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    /* ── Client: blind the message into a Halevi–Micali commitment ── */
    RAND_bytes(m_hat, 32);
    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    RAND_bytes(r, sizeof r);
    RAND_bytes(a_mat, sizeof a_mat);
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);

    /* ── Signer: XMSS-sign the certified digest d (self-check) ── */
    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, 0, d, 32, &sig)) { printf("FAIL: xmss_sign\n"); exit(1); }
    if (!xmss_verify(pk_seed, root, d, 32, &sig))      { printf("FAIL: native verify\n"); exit(1); }

    /* ── Client: assemble the prover witness ── */
    memcpy(input + W_R_OFF, r, HM_R_BYTES);
    memcpy(input + W_A_OFF, a_mat, HM_A_BYTES);
    memset(input + W_LEAFIDX_OFF, 0, 4);
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    memset(pubout, 0, 8 * sizeof(uint32_t));
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;
}

int main(void)
{
    printf("--- End-to-end protocol (keygen→blind→sign→prove→verify) ---\n");
    kkw_verbose = 0;

    unsigned char input[W_END], m_hat[32], pk_seed[XMSS_PK_SEED_BYTES];
    uint32_t pubout[8];
    run_parties(input, m_hat, pk_seed, pubout);

    FILE *proof = tmpfile();
    if (!proof) { printf("FAIL: tmpfile\n"); return 1; }

    CHECK(kkw_prove(input, m_hat, pk_seed, pubout, proof) == 0, "prover produces a proof");

    rewind(proof);
    CHECK(kkw_verify(proof, m_hat, pk_seed, pubout) == 0, "verify accepts the honest proof");

    /* Negative: a different signed message must not verify. */
    unsigned char bad_m[32];
    memcpy(bad_m, m_hat, 32);
    bad_m[0] ^= 0x01;
    rewind(proof);
    CHECK(kkw_verify(proof, bad_m, pk_seed, pubout) != 0, "verify rejects a wrong message");

    /* Negative: a forged public key (different root) must not verify. */
    uint32_t bad_pubout[8];
    memcpy(bad_pubout, pubout, sizeof bad_pubout);
    bad_pubout[0] ^= 0x01;
    rewind(proof);
    CHECK(kkw_verify(proof, m_hat, pk_seed, bad_pubout) != 0, "verify rejects a forged public key");

    fclose(proof);

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
