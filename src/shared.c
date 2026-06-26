#include "shared.h"
#include "circuits.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* ySize: number of nonlinear gates (word-level) in one circuit execution.
 * Measured by test_circuit after any parameter change. */
const int ySize = 151776;
const int INPUT_LEN = 2762; /* W_END — see circuits.h */

/* TAPE_SIZE = 3 * ySize * 4 (u[], v[], w_raw[] blocks, each ySize uint32_t). */
const int TAPE_SIZE = 3 * 151776 * 4; /* = 1 821 312 bytes */

const uint32_t hA[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

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
    unsigned char zeros[64] = {0};
    size_t offset = 0;
    int outl = 0;
    while (offset < outlen) {
        size_t chunk = (outlen - offset < 64) ? (outlen - offset) : 64;
        EVP_EncryptUpdate(ctx, out + offset, &outl, zeros, (int)chunk);
        offset += chunk;
    }
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
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(com_out, 0, 32); return; }
    unsigned int outl = 0;
    unsigned char pbyte = (unsigned char)party;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, "ppcom", 5) == 1 &&
             EVP_DigestUpdate(ctx, &pbyte, 1) == 1 &&
             EVP_DigestUpdate(ctx, seed, SEED_SIZE) == 1;
    /* Party 0 holds aux; including it in the commitment binds aux to this seed. */
    if (party == 0 && aux != NULL)
        ok = ok && EVP_DigestUpdate(ctx, aux, (size_t)ySize * sizeof(uint32_t)) == 1;
    ok = ok && EVP_DigestFinal_ex(ctx, com_out, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) memset(com_out, 0, 32);
}

void preproc_commit_instance(unsigned char seeds[N_PARTIES][SEED_SIZE],
                              const uint32_t *aux, unsigned char h_j_out[32])
{
    unsigned char coms[N_PARTIES][32];
    for (int i = 0; i < N_PARTIES; i++)
        preproc_com_party(i, seeds[i], aux, coms[i]);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(h_j_out, 0, 32); return; }
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    for (int i = 0; i < N_PARTIES && ok; i++)
        ok = EVP_DigestUpdate(ctx, coms[i], 32) == 1;
    ok = ok && EVP_DigestFinal_ex(ctx, h_j_out, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) memset(h_j_out, 0, 32);
}

void compute_aux_from_seeds(unsigned char seeds[N_PARTIES][SEED_SIZE], uint32_t *aux_out)
{
    /* Run building_views with dummy inputs to extract aux from the party seeds.
     * aux[g] is set by mpc_AND and mpc_ADD using only the Beaver triple tapes
     * (u_i, v_i, w_i) — it does NOT depend on x_shares, m_hat, or pk_seed.
     *
     * Using the simple formula (XOR u_i) AND (XOR v_i) XOR (XOR w_i) would be
     * wrong for mpc_ADD gates: that function only writes bits 0..30 to aux[g]
     * (bit 31 stays 0), but the word-level formula computes bit 31 from tape data. */
    unsigned char *x_dummy[N_PARTIES];
    unsigned char *tapes[N_PARTIES];
    bool alloc_ok = true;
    for (int p = 0; p < N_PARTIES; p++) {
        x_dummy[p] = calloc((size_t)INPUT_LEN, 1);
        tapes[p]   = malloc((size_t)TAPE_SIZE);
        if (!x_dummy[p] || !tapes[p]) { alloc_ok = false; break; }
        expand_tape(seeds[p], tapes[p]);
    }
    if (!alloc_ok) {
        for (int p = 0; p < N_PARTIES; p++) { free(x_dummy[p]); free(tapes[p]); }
        memset(aux_out, 0, (size_t)ySize * sizeof(uint32_t));
        return;
    }
    unsigned char zero_m[32] = {0};
    unsigned char zero_pk[16] = {0};
    a dummy_a;
    /* Pass NULL for da_db_all_out; building_views allocates internally. */
    building_views(&dummy_a, zero_m, zero_pk, x_dummy, tapes, aux_out, NULL);
    for (int p = 0; p < N_PARTIES; p++) { free(x_dummy[p]); free(tapes[p]); }
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
    sha256_once(in, 36, p->buf);
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

static int cmp_int(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

void kkw_fiat_shamir(const unsigned char msg[32], const uint32_t pubout[8],
                     const unsigned char h_star[32],
                     int C_out[NUM_ROUNDS], int p_out[NUM_ROUNDS])
{
    /* seed_FS = H(msg || pubout_be || h_star) */
    unsigned char pubout_bytes[32];
    for (int i = 0; i < 8; i++) {
        pubout_bytes[i*4+0] = (unsigned char)(pubout[i] >> 24);
        pubout_bytes[i*4+1] = (unsigned char)(pubout[i] >> 16);
        pubout_bytes[i*4+2] = (unsigned char)(pubout[i] >>  8);
        pubout_bytes[i*4+3] = (unsigned char)(pubout[i]);
    }
    unsigned char seed_FS[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(C_out, 0, NUM_ROUNDS*sizeof(int)); memset(p_out, 0, NUM_ROUNDS*sizeof(int)); return; }
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, msg, 32) == 1 &&
             EVP_DigestUpdate(ctx, pubout_bytes, 32) == 1 &&
             EVP_DigestUpdate(ctx, h_star, 32) == 1 &&
             EVP_DigestFinal_ex(ctx, seed_FS, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) { memset(C_out, 0, NUM_ROUNDS*sizeof(int)); memset(p_out, 0, NUM_ROUNDS*sizeof(int)); return; }

    prg_ctx prg;
    prg_init(&prg, seed_FS);

    /* Fisher-Yates: pick NUM_ROUNDS distinct indices from [0..M_KKW-1]. */
    int arr[M_KKW];
    for (int i = 0; i < M_KKW; i++) arr[i] = i;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        uint32_t r = prg_u32(&prg);
        int j = i + (int)(r % (uint32_t)(M_KKW - i));
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

/* ── SHA-256 helpers ────────────────────────────────────────────────────── */

int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, in, inlen) == 1 &&
             EVP_DigestFinal_ex(ctx, out32, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

void H_com(const unsigned char seed[SEED_SIZE],
           const unsigned char *x,
           const uint32_t yp[8],
           unsigned char hash[32])
{
    /* Encode yp as 32 big-endian bytes. */
    unsigned char yp_bytes[32];
    for (int i = 0; i < 8; i++) {
        yp_bytes[i*4+0] = (unsigned char)(yp[i] >> 24);
        yp_bytes[i*4+1] = (unsigned char)(yp[i] >> 16);
        yp_bytes[i*4+2] = (unsigned char)(yp[i] >>  8);
        yp_bytes[i*4+3] = (unsigned char)(yp[i]);
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(hash, 0, 32); return; }
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, seed, SEED_SIZE) == 1 &&
             EVP_DigestUpdate(ctx, x, (size_t)INPUT_LEN) == 1 &&
             EVP_DigestUpdate(ctx, yp_bytes, 32) == 1 &&
             EVP_DigestFinal_ex(ctx, hash, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) memset(hash, 0, 32);
}

/* ── KKW online-transcript helpers ─────────────────────────────────────── */

void compute_h_prime(const uint32_t *da_db_all, unsigned char h_prime[32])
{
    /* h'_j = H(da_db_all) where da_db_all is N×2×ySize uint32_t.
     * da_db_all[i*2*ySize + 2*g]   = da_i[g] = x_i[g] XOR u_i[g]
     * da_db_all[i*2*ySize + 2*g+1] = db_i[g] = y_i[g] XOR v_i[g] */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(h_prime, 0, 32); return; }
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, da_db_all,
                              (size_t)N_PARTIES * 2 * ySize * sizeof(uint32_t)) == 1 &&
             EVP_DigestFinal_ex(ctx, h_prime, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) memset(h_prime, 0, 32);
}

void compute_msgs_e(int e, const uint32_t *da_db_all, uint32_t *msgs_e_out)
{
    /* msgs_e = (da_e[0], db_e[0], ..., da_e[ySize-1], db_e[ySize-1]) */
    memcpy(msgs_e_out, da_db_all + (size_t)e * 2 * ySize,
           (size_t)2 * ySize * sizeof(uint32_t));
}

void recompute_h_prime_verify(int e,
                               const uint32_t *per_party_da_db,
                               const uint32_t *msgs_e,
                               unsigned char h_prime_out[32])
{
    /* Reconstruct the prover's da_db_all in party order 0..N-1, then hash it. */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(h_prime_out, 0, 32); return; }
    unsigned int outl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    for (int p = 0; p < N_PARTIES && ok; p++) {
        if (p == e) {
            /* Hidden party: use msgs_e from proof (2*ySize words). */
            ok = EVP_DigestUpdate(ctx, msgs_e,
                                  (size_t)2 * ySize * sizeof(uint32_t)) == 1;
        } else {
            int slot = (p < e) ? p : p - 1;
            ok = EVP_DigestUpdate(ctx,
                                  per_party_da_db + (size_t)slot * 2 * ySize,
                                  (size_t)2 * ySize * sizeof(uint32_t)) == 1;
        }
    }
    ok = ok && EVP_DigestFinal_ex(ctx, h_prime_out, &outl) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) memset(h_prime_out, 0, 32);
}

/* ── Fiat–Shamir challenge ─────────────────────────────────────────────── */

void H3(const unsigned char message_digest[32], const uint32_t pubout[8],
        a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS], int s, int *es)
{
    /* Encode pubout as 32 big-endian bytes. */
    unsigned char pubout_bytes[32];
    for (int i = 0; i < 8; i++) {
        pubout_bytes[i*4+0] = (unsigned char)(pubout[i] >> 24);
        pubout_bytes[i*4+1] = (unsigned char)(pubout[i] >> 16);
        pubout_bytes[i*4+2] = (unsigned char)(pubout[i] >>  8);
        pubout_bytes[i*4+3] = (unsigned char)(pubout[i]);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(es, 0, s * sizeof(*es)); return; }
    unsigned int outl = 0;

    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, message_digest, 32) == 1 &&
             EVP_DigestUpdate(ctx, pubout_bytes, 32) == 1;
    for (int i = 0; i < s && ok; i++) {
        ok = EVP_DigestUpdate(ctx, as[i], sizeof(a)) == 1;
        /* Trou 3 fix: bind msgs_e (hidden party's da_e/db_e) and aux so the
         * prover cannot adapt them after committing to the yp/commitment transcript.
         * msgs_e is 2*ySize words; aux is ySize words. */
        if (ok)
            ok = EVP_DigestUpdate(ctx, zs[i]->msgs_e,
                                  (size_t)(2 * ySize) * sizeof(uint32_t)) == 1;
        if (ok)
            ok = EVP_DigestUpdate(ctx, zs[i]->aux,
                                  (size_t)ySize * sizeof(uint32_t)) == 1;
    }
    ok = ok && EVP_DigestFinal_ex(ctx, hash, &outl) == 1;
    if (!ok) {
        EVP_MD_CTX_free(ctx);
        memset(es, 0, s * sizeof(*es));
        return;
    }

    /* Extract challenges in {0 .. N_PARTIES-1} using rejection sampling.
     * threshold = largest multiple of N_PARTIES that fits in a byte (0..255).
     * For power-of-2 N_PARTIES (≤256), threshold == 256 → no byte is ever
     * rejected and the distribution is perfectly uniform. */
    const unsigned int threshold = (unsigned int)N_PARTIES * (256u / (unsigned int)N_PARTIES);
    int i = 0, byteIdx = 0;
    while (i < s) {
        if (byteIdx >= SHA256_DIGEST_LENGTH) {
            ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
                 EVP_DigestUpdate(ctx, hash, sizeof(hash)) == 1 &&
                 EVP_DigestFinal_ex(ctx, hash, &outl) == 1;
            if (!ok) {
                EVP_MD_CTX_free(ctx);
                memset(es, 0, s * sizeof(*es));
                return;
            }
            byteIdx = 0;
        }
        unsigned int val = (unsigned char)hash[byteIdx++];
        if (val < threshold)
            es[i++] = (int)(val % (unsigned int)N_PARTIES);
    }
    EVP_MD_CTX_free(ctx);
}

/* ── Prove allocation ───────────────────────────────────────────────────── */

int alloc_structures_prove(
    unsigned char  seeds[NUM_ROUNDS][N_PARTIES][SEED_SIZE],
    unsigned char *x_shares[NUM_ROUNDS][N_PARTIES],
    a             *as[NUM_ROUNDS],
    z             *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) {
        as[i] = NULL; zs[i] = NULL;
        for (int j = 0; j < N_PARTIES; j++)
            x_shares[i][j] = NULL;
    }
    /* Initialize seeds to zero; caller fills via RAND_bytes. */
    memset(seeds, 0, (size_t)NUM_ROUNDS * N_PARTIES * SEED_SIZE);

    int round = 0;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        round = i;
        for (int j = 0; j < N_PARTIES; j++) {
            x_shares[i][j] = malloc((size_t)INPUT_LEN);
            if (!x_shares[i][j]) goto err;
        }
        as[i] = calloc(1, sizeof(a));
        if (!as[i]) goto err;
        zs[i] = calloc(1, sizeof(z));
        if (!zs[i]) goto err;

        /* Allocate z internals (aux, msgs_e=2*ySize; x_offset set later). */
        zs[i]->aux = malloc((size_t)ySize * sizeof(uint32_t));
        if (!zs[i]->aux) goto err;
        zs[i]->x_offset = malloc((size_t)INPUT_LEN);
        if (!zs[i]->x_offset) goto err;
        zs[i]->msgs_e = malloc((size_t)2 * ySize * sizeof(uint32_t));
        if (!zs[i]->msgs_e) goto err;
    }
    return 0;

err:
    for (int i = 0; i <= round; i++) {
        for (int j = 0; j < N_PARTIES; j++) { free(x_shares[i][j]); x_shares[i][j] = NULL; }
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->aux);
            free(zs[i]->x_offset);
            free(zs[i]->msgs_e);
            free(zs[i]);
        }
    }
    return -1;
}

void free_structures_prove(
    unsigned char *x_shares[NUM_ROUNDS][N_PARTIES],
    a             *as[NUM_ROUNDS],
    z             *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) {
        for (int j = 0; j < N_PARTIES; j++) free(x_shares[i][j]);
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->aux);
            free(zs[i]->x_offset);
            free(zs[i]->msgs_e);
            free(zs[i]);
        }
    }
}

/* ── Verify allocation ──────────────────────────────────────────────────── */

int alloc_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) { as[i] = NULL; zs[i] = NULL; }

    int round = 0;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        round = i;
        as[i] = calloc(1, sizeof(a));
        if (!as[i]) goto err;
        zs[i] = calloc(1, sizeof(z));
        if (!zs[i]) goto err;
        zs[i]->aux = malloc((size_t)ySize * sizeof(uint32_t));
        if (!zs[i]->aux) goto err;
        zs[i]->x_offset = malloc((size_t)INPUT_LEN);
        if (!zs[i]->x_offset) goto err;
        zs[i]->msgs_e = malloc((size_t)2 * ySize * sizeof(uint32_t));
        if (!zs[i]->msgs_e) goto err;
    }
    return 0;

err:
    for (int i = 0; i <= round; i++) {
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->aux);
            free(zs[i]->x_offset);
            free(zs[i]->msgs_e);
            free(zs[i]);
        }
    }
    return -1;
}

void free_structures_verify(a *as[NUM_ROUNDS], z *zs[NUM_ROUNDS])
{
    for (int i = 0; i < NUM_ROUNDS; i++) {
        free(as[i]);
        if (zs[i]) {
            free(zs[i]->aux);
            free(zs[i]->x_offset);
            free(zs[i]->msgs_e);
            free(zs[i]);
        }
    }
}
