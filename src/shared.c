#include "shared.h"
#include "circuits.h"

#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* YSIZE_GATES: number of nonlinear gates (word-level) in one circuit
 * execution.  Measured by test_circuit after any circuit change — update this
 * single definition; ySize and TAPE_SIZE both derive from it. */
#define YSIZE_GATES 73096
const int ySize = YSIZE_GATES;
const int INPUT_LEN = 2762; /* W_END — see circuits.h */

/* Exported compile-time parameters (see ASSERT_LIB_PARAMS in shared.h). */
const int lib_n_parties = N_PARTIES;
const int lib_m_kkw     = M_KKW;
const int lib_num_rounds = NUM_ROUNDS;

/* TAPE_SIZE = 2 * ySize * 4 (λ_z and λ_x·λ_y product blocks, each ySize u32). */
const int TAPE_SIZE = 2 * YSIZE_GATES * 4; /* = 584 768 bytes */

/* ── Tape / seed expansion ───────────────────────────────────────────────── */

static void aes_ctr_expand(const unsigned char seed[SEED_SIZE],
                            unsigned char iv_domain,
                            unsigned char *out, size_t outlen)
{
    unsigned char iv[16] = {0};
    iv[0] = iv[1] = iv[2] = iv[3] = iv_domain;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { memset(out, 0, outlen); return; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, seed, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); memset(out, 0, outlen); return;
    }
    /* CTR keystream = encryption of zeros; one in-place update over the whole
     * buffer keeps OpenSSL on its fast path (the previous 64-byte loop paid
     * per-call overhead ~28k times per tape). */
    memset(out, 0, outlen);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, out, (int)outlen);
    EVP_CIPHER_CTX_free(ctx);
}

void expand_tape(const unsigned char seed[SEED_SIZE], unsigned char *tape)
{
    aes_ctr_expand(seed, 0xA5, tape, (size_t)TAPE_SIZE);
}

void expand_seed_star(const unsigned char seed_star[SEED_SIZE],
                      unsigned char seeds_out[N_PARTIES][SEED_SIZE])
{
    aes_ctr_expand(seed_star, 0xB7, (unsigned char *)seeds_out,
                   (size_t)N_PARTIES * SEED_SIZE);
}

void expand_xshare(const unsigned char seed[SEED_SIZE], unsigned char *xshare_out)
{
    aes_ctr_expand(seed, 0xC3, xshare_out, (size_t)INPUT_LEN);
}

/* ── Preprocessing commitment ────────────────────────────────────────────── */

void preproc_com_party(int party, const unsigned char seed[SEED_SIZE],
                        const uint32_t *aux, unsigned char com_out[32])
{
    blake3_th_ctx ctx;
    unsigned char pbyte = (unsigned char)party;
    KKW_TH_INIT(&ctx, KKW_DOM_PPCOM);
    blake3_th_update(&ctx, &pbyte, 1);
    blake3_th_update(&ctx, seed, SEED_SIZE);
    /* Party 0 holds aux; including it in the commitment binds aux to this seed. */
    if (party == 0 && aux != NULL)
        blake3_th_update(&ctx, aux, (size_t)ySize * sizeof(uint32_t));
    blake3_th_final(&ctx, com_out, 32);
}

void preproc_commit_instance(unsigned char seeds[N_PARTIES][SEED_SIZE],
                              const uint32_t *aux, unsigned char h_j_out[32])
{
    unsigned char coms[N_PARTIES][32];
    for (int i = 0; i < N_PARTIES; i++)
        preproc_com_party(i, seeds[i], aux, coms[i]);
    KKW_TH(KKW_DOM_HJ, coms, (size_t)N_PARTIES * 32, h_j_out);
}

void compute_aux_from_seeds(unsigned char seeds[N_PARTIES][SEED_SIZE],
                            uint32_t *aux_out, unsigned char *h_out32)
{
    /* aux[g] = (λ_x AND λ_y) XOR (XOR_i t_i) where λ_x/λ_y are the gate's
     * input-wire masks.  Masks depend only on the tapes and witness-mask
     * shares — never on the witness or the public inputs — so running the
     * circuit with all-zero publics reproduces exactly the aux stream of any
     * real instance built from the same seeds (s_all = NULL skips the
     * broadcast collection and h'). */
    unsigned char *tapes[N_PARTIES], *lam[N_PARTIES];
    unsigned char *d0 = NULL;
    bool alloc_ok = true;
    for (int p = 0; p < N_PARTIES; p++) { tapes[p] = NULL; lam[p] = NULL; }
    for (int p = 0; p < N_PARTIES && alloc_ok; p++) {
        tapes[p] = malloc((size_t)TAPE_SIZE);
        lam[p]   = malloc((size_t)INPUT_LEN);
        if (!tapes[p] || !lam[p]) { alloc_ok = false; break; }
        expand_tape(seeds[p], tapes[p]);
        expand_xshare(seeds[p], lam[p]);
    }
    d0 = alloc_ok ? calloc((size_t)INPUT_LEN, 1) : NULL;
    if (!alloc_ok || !d0) {
        free(d0);
        for (int p = 0; p < N_PARTIES; p++) { free(tapes[p]); free(lam[p]); }
        memset(aux_out, 0, (size_t)ySize * sizeof(uint32_t));
        if (h_out32) memset(h_out32, 0, 32);
        return;
    }

    unsigned char zero_m[32] = {0}, zero_pk[XMSS_PK_SEED_BYTES] = {0};
    a dummy_a;
    uint32_t zh_dummy[8];
    building_views(&dummy_a, zero_m, zero_pk, d0, lam, tapes, aux_out, NULL,
                   NULL, zh_dummy);
    if (h_out32)
        KKW_TH(KKW_DOM_HOUT, dummy_a.yp,
               (size_t)N_PARTIES * 8 * sizeof(uint32_t), h_out32);

    free(d0);
    for (int p = 0; p < N_PARTIES; p++) { free(tapes[p]); free(lam[p]); }
}

/* ── Fiat–Shamir challenge (full KKW protocol) ───────────────────────────── */

typedef struct {
    unsigned char state[32];
    uint32_t ctr;
    unsigned char buf[32];
    int pos;
} prg_ctx;

static void prg_fill(prg_ctx *p)
{
    unsigned char in[36];
    memcpy(in, p->state, 32);
    in[32] = (unsigned char)(p->ctr >> 24);
    in[33] = (unsigned char)(p->ctr >> 16);
    in[34] = (unsigned char)(p->ctr >>  8);
    in[35] = (unsigned char)(p->ctr);
    KKW_TH(KKW_DOM_PRG, in, 36, p->buf);
    p->ctr++;
    p->pos = 0;
}

static void prg_init(prg_ctx *p, const unsigned char seed[32])
{
    memcpy(p->state, seed, 32);
    p->ctr = 0;
    prg_fill(p);
}

static uint32_t prg_u32(prg_ctx *p)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (p->pos >= 32) prg_fill(p);
        v = (v << 8) | (unsigned char)p->buf[p->pos++];
    }
    return v;
}

/* Uniform integer in [0, bound) via rejection sampling (bound > 0).
 * Rejects the short final interval so there is no modulo bias. */
static uint32_t prg_below(prg_ctx *p, uint32_t bound)
{
    uint64_t limit = ((uint64_t)1 << 32) - (((uint64_t)1 << 32) % bound);
    uint32_t r;
    do { r = prg_u32(p); } while ((uint64_t)r >= limit);
    return r % bound;
}

static int cmp_int(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

void kkw_fs_prefix(const unsigned char msg[32], const uint32_t pubout[8],
                   const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                   const unsigned char nonce[32],
                   const unsigned char h_star[32],
                   unsigned char h_pre[32])
{
    unsigned char pubout_bytes[32];
    for (int i = 0; i < 8; i++) {
        pubout_bytes[i*4+0] = (unsigned char)(pubout[i] >> 24);
        pubout_bytes[i*4+1] = (unsigned char)(pubout[i] >> 16);
        pubout_bytes[i*4+2] = (unsigned char)(pubout[i] >>  8);
        pubout_bytes[i*4+3] = (unsigned char)(pubout[i]);
    }
    unsigned char in[32 + 32 + XMSS_PK_SEED_BYTES + 32 + 32];
    memcpy(in,                              msg,          32);
    memcpy(in + 32,                         pubout_bytes, 32);
    memcpy(in + 64,                         pk_seed,      XMSS_PK_SEED_BYTES);
    memcpy(in + 64 + XMSS_PK_SEED_BYTES,    nonce,        32);
    memcpy(in + 96 + XMSS_PK_SEED_BYTES,    h_star,       32);
    KKW_TH(KKW_DOM_FS, in, sizeof in, h_pre);
}

int kkw_fs_seed(const unsigned char h_pre[32], uint32_t ctr,
                unsigned char seed_FS[32])
{
    unsigned char in[36];
    memcpy(in, h_pre, 32);
    in[32] = (unsigned char)(ctr >> 24);
    in[33] = (unsigned char)(ctr >> 16);
    in[34] = (unsigned char)(ctr >>  8);
    in[35] = (unsigned char)(ctr);
    KKW_TH(KKW_DOM_GRIND, in, 36, seed_FS);
    /* Grinding predicate: the GRIND_W trailing bits of seed_FS are zero. */
    for (int b = 0; b < GRIND_W; b++)
        if ((seed_FS[31 - b/8] >> (b % 8)) & 1) return 0;
    return 1;
}

void kkw_fs_expand(const unsigned char seed_FS[32],
                   int C_out[NUM_ROUNDS], int p_out[NUM_ROUNDS])
{
    prg_ctx prg;
    prg_init(&prg, seed_FS);

    /* Fisher-Yates: pick NUM_ROUNDS distinct indices from [0..M_KKW-1].
     * prg_below is unbiased (rejection sampling), matching the party draw below. */
    int arr[M_KKW];
    for (int i = 0; i < M_KKW; i++) arr[i] = i;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        int j = i + (int)prg_below(&prg, (uint32_t)(M_KKW - i));
        int tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
    memcpy(C_out, arr, NUM_ROUNDS * sizeof(int));
    qsort(C_out, NUM_ROUNDS, sizeof(int), cmp_int);

    /* Hidden party index for each online round (uniform in [0..N_PARTIES-1]).
     * Rejection sampling: discard bytes >= threshold to get exact uniformity.
     * For power-of-2 N, threshold==256 so no byte is ever rejected. */
    {
        const unsigned int p_thresh =
            (unsigned int)N_PARTIES * (256u / (unsigned int)N_PARTIES);
        for (int k = 0; k < NUM_ROUNDS; k++) {
            unsigned int val;
            do {
                if (prg.pos >= 32) prg_fill(&prg);
                val = (unsigned char)prg.buf[prg.pos++];
            } while (val >= p_thresh);
            p_out[k] = (int)(val % (unsigned int)N_PARTIES);
        }
    }
}

/* ── KKW online-transcript helpers ─────────────────────────────────────── */

void compute_h_prime(const unsigned char *d_pub, const uint32_t *s_all,
                     const unsigned char r_j[32],
                     unsigned char h_prime[32])
{
    /* h'_j = Th(d || s_0 || … || s_{N-1} || r_j): binds the masked witness and
     * every party's broadcast stream (s_all[i*ySize + g] = s_i[g]).  r_j
     * blinds the hash for unopened instances (revealed only for j ∈ C). */
    blake3_th_ctx ctx;
    KKW_TH_INIT(&ctx, KKW_DOM_HPRIME);
    blake3_th_update(&ctx, d_pub, (size_t)INPUT_LEN);
    blake3_th_update(&ctx, s_all, (size_t)N_PARTIES * ySize * sizeof(uint32_t));
    blake3_th_update(&ctx, r_j, 32);
    blake3_th_final(&ctx, h_prime, 32);
}

void compute_msgs_e(int e, const uint32_t *s_all, uint32_t *msgs_e_out)
{
    memcpy(msgs_e_out, s_all + (size_t)e * ySize,
           (size_t)ySize * sizeof(uint32_t));
}

void recompute_h_prime_verify(int e, const unsigned char *d_pub,
                               const uint32_t *s_slots,
                               const uint32_t *msgs_e,
                               const unsigned char r_j[32],
                               unsigned char h_prime_out[32])
{
    /* Reconstruct the prover's (d || s streams || r_j) in party order, hash. */
    blake3_th_ctx ctx;
    KKW_TH_INIT(&ctx, KKW_DOM_HPRIME);
    blake3_th_update(&ctx, d_pub, (size_t)INPUT_LEN);
    for (int p = 0; p < N_PARTIES; p++) {
        if (p == e) {
            blake3_th_update(&ctx, msgs_e, (size_t)ySize * sizeof(uint32_t));
        } else {
            int slot = (p < e) ? p : p - 1;
            blake3_th_update(&ctx, s_slots + (size_t)slot * ySize,
                             (size_t)ySize * sizeof(uint32_t));
        }
    }
    blake3_th_update(&ctx, r_j, 32);
    blake3_th_final(&ctx, h_prime_out, 32);
}
