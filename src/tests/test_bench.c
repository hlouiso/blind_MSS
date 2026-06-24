/* Benchmark end-to-end: génère un témoin aléatoire, mesure prove+verify, affiche taille. */
#include "../circuits.h"
#include "../commitment.h"
#include "../kkw_prove.h"
#include "../kkw_verify.h"
#include "../shared.h"
#include "../xmss.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double elapsed(struct timespec a, struct timespec b)
{
    return (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) * 1e-9;
}

int main(void)
{
    /* ── Témoin aléatoire ── */
    unsigned char sk_seed[32], pk_seed[XMSS_PK_SEED_BYTES];
    RAND_bytes(sk_seed, sizeof sk_seed);
    RAND_bytes(pk_seed, sizeof pk_seed);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    unsigned char m_hat[32], r[HM_R_BYTES], a_mat[HM_A_BYTES];
    RAND_bytes(m_hat, sizeof m_hat);
    RAND_bytes(r, sizeof r);
    RAND_bytes(a_mat, sizeof a_mat);
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, 0, d, 32, &sig)) {
        fprintf(stderr, "xmss_sign failed\n"); return 1;
    }

    unsigned char input[W_END];
    memcpy(input + W_R_OFF,   r,      HM_R_BYTES);
    memcpy(input + W_A_OFF,   a_mat,  HM_A_BYTES);
    memset(input + W_LEAFIDX_OFF, 0, 4);
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i*XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h*XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w*4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    /* ── Prove ── */
    FILE *proof = tmpfile();
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (kkw_prove(input, m_hat, pk_seed, pubout, proof) != 0) {
        fprintf(stderr, "kkw_prove failed\n"); return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double t_prove = elapsed(t0, t1);

    long proof_size = ftell(proof);
    rewind(proof);

    /* ── Verify ── */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = kkw_verify(proof, m_hat, pk_seed, pubout);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double t_verify = elapsed(t0, t1);
    fclose(proof);

    /* ── Résultats ── */
    printf("\n=== Résultats (N=%d, M=%d, τ=%d) ===\n",
           N_PARTIES, M_KKW, NUM_ROUNDS);
    printf("Prove  : %.2f s\n", t_prove);
    printf("Verify : %.2f s\n", t_verify);
    printf("Taille : %.1f MB\n", proof_size / 1e6);
    printf("Résultat: %s\n", rc == 0 ? "VALIDE" : "INVALIDE");

    return rc == 0 ? 0 : 1;
}
