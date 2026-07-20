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

#include "test_rng.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
/* Evaluate the condition exactly once: CHECK(kkw_prove(...) == 0, ...) must
 * not run the prover twice (it used to, appending two proofs to the file). */
#define CHECK(c, m) do { \
    int check_ok_ = (c); \
    printf("  %s %s\n", check_ok_ ? "ok  " : "FAIL", (m)); \
    if (!check_ok_) failures++; \
} while (0)

/* Run keygen + blind + sign + witness assembly exactly as the separate parties
 * would, leaving the prover's inputs (input, m_hat, pk_seed, pubout) ready. */
static void run_parties(unsigned char input[W_END], unsigned char m_hat[32],
                        unsigned char pk_seed[XMSS_PK_SEED_BYTES], uint32_t pubout[8])
{
    /* ── Signer: key generation ── */
    unsigned char sk_seed[32];
    test_random_bytes(sk_seed, 32);
    test_random_bytes(pk_seed, XMSS_PK_SEED_BYTES);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    /* ── Client: blind the message into a Halevi–Micali commitment ── */
    test_random_bytes(m_hat, 32);
    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    test_random_bytes(r, sizeof r);
    test_random_bytes(a_mat, sizeof a_mat);
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
    ASSERT_LIB_PARAMS();
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

    /* Negative: every byte of the proof must be binding — flip one byte at
     * targeted offsets (nonce, h*, ctr, offline section, online section) and
     * at random offsets; the verifier must reject each time. */
    {
        fseek(proof, 0, SEEK_END);
        long plen = ftell(proof);
        rewind(proof);
        unsigned char *buf = malloc((size_t)plen);
        if (!buf || fread(buf, 1, (size_t)plen, proof) != (size_t)plen) {
            printf("FAIL: proof read-back\n"); return 1;
        }

        const long hdr_end     = 4 + 6*4 + 32 + 32 + 4;      /* magic..ctr */
        const long online_off  = hdr_end + (long)(M_KKW - NUM_ROUNDS) * 64;
        long offsets[14];
        int  n_off = 0;
        offsets[n_off++] = 4 + 6*4 + 3;            /* nonce */
        offsets[n_off++] = 4 + 6*4 + 32 + 7;       /* h*    */
        offsets[n_off++] = hdr_end - 2;            /* ctr   */
        offsets[n_off++] = hdr_end + 16;           /* offline: inside a seed* */
        offsets[n_off++] = hdr_end + 40;           /* offline: inside h'_j    */
        offsets[n_off++] = online_off + 16;        /* online: com_hidden      */
        offsets[n_off++] = online_off + 32 + 4;    /* online: inside yp (h_out path) */
        offsets[n_off++] = online_off + 32 + (long)N_PARTIES*32 + 4; /* inside ke */
        offsets[n_off++] = plen - 16;              /* r_j of the last round   */
        for (int i = 0; i < 5; i++) {              /* random online bytes     */
            uint32_t rnd;
            test_random_bytes((unsigned char *)&rnd, 4);
            offsets[n_off++] = online_off + (long)(rnd % (uint32_t)(plen - online_off));
        }

        int all_rejected = 1;
        FILE *tampered = tmpfile();
        if (!tampered) { printf("FAIL: tmpfile\n"); return 1; }
        for (int i = 0; i < n_off; i++) {
            buf[offsets[i]] ^= 0x01;
            rewind(tampered);
            if (fwrite(buf, 1, (size_t)plen, tampered) != (size_t)plen) {
                printf("FAIL: tamper write\n"); return 1;
            }
            rewind(tampered);
            if (kkw_verify(tampered, m_hat, pk_seed, pubout) == 0) {
                printf("  FAIL byte flip at offset %ld ACCEPTED\n", offsets[i]);
                all_rejected = 0;
            }
            buf[offsets[i]] ^= 0x01;               /* restore */
        }
        fclose(tampered);
        CHECK(all_rejected, "verify rejects every single-byte proof tampering (14 offsets, incl. yp/ke/r_j)");

        /* Negative: appending a byte to a valid proof must be rejected (the
         * verifier requires EOF right after the online section). */
        FILE *padded = tmpfile();
        if (!padded) { printf("FAIL: tmpfile\n"); return 1; }
        if (fwrite(buf, 1, (size_t)plen, padded) != (size_t)plen ||
            fputc(0x00, padded) == EOF) {
            printf("FAIL: padded write\n"); return 1;
        }
        rewind(padded);
        CHECK(kkw_verify(padded, m_hat, pk_seed, pubout) != 0,
              "verify rejects a proof with trailing data");
        fclose(padded);
        free(buf);
    }

    fclose(proof);

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
