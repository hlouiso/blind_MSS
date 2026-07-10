/* BLAKE3 self-test.
 *
 * 1. blake3_compress against official BLAKE3 digests: for inputs <= 64 bytes,
 *    blake3(input) = compress(IV, block, 0, len, CHUNK_START|CHUNK_END|ROOT)
 *    truncated to 32 bytes.  Inputs use the official test-vector byte pattern
 *    (i % 251); digests generated with the reference implementation.
 * 2. blake3_th structural checks: domain separation, length separation,
 *    determinism, chain-step layout.
 * 3. mpc_blake3_th (prove path) against the native blake3_th on random
 *    masked inputs, and the verify path for every hidden party e.
 */
#include "../blake3.h"
#include "../shared.h"
#include "../xmss.h"
#include "../MPC_prove_functions.h"
#include "../MPC_verify_functions.h"

#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { int ok_=(c); printf("  %s %s\n", ok_?"ok  ":"FAIL",(m)); if(!ok_)failures++; } while(0)

static int hex2bin(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* ── 1. compress vs. official BLAKE3 digests (root compression) ─────────── */

static void root_digest(const uint8_t *in, size_t len, uint8_t out32[32])
{
    uint32_t iv[8] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,
                      0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
    uint32_t m[16] = {0}, cv[8];
    uint8_t block[64] = {0};
    memcpy(block, in, len);
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)block[4*i] | ((uint32_t)block[4*i+1] << 8)
             | ((uint32_t)block[4*i+2] << 16) | ((uint32_t)block[4*i+3] << 24);
    blake3_compress(iv, m, 0, (uint32_t)len,
                    BLAKE3_CHUNK_START | BLAKE3_CHUNK_END | BLAKE3_ROOT, cv);
    for (int i = 0; i < 8; i++) {
        out32[i*4+0] = (uint8_t)(cv[i]);
        out32[i*4+1] = (uint8_t)(cv[i] >> 8);
        out32[i*4+2] = (uint8_t)(cv[i] >> 16);
        out32[i*4+3] = (uint8_t)(cv[i] >> 24);
    }
}

static void test_vectors(void)
{
    printf("--- Test 1: compress vs official BLAKE3 vectors ---\n");
    static const struct { size_t len; const char *hex; } V[] = {
        {  0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" },
        {  1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213" },
        { 33, "4f4e6c1dffd3a6c9959876d15aa96b5fb0da8632b995f6ca2e30503f2829fa29" },
        { 64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98" },
    };
    uint8_t in[64], got[32], want[32];
    for (int i = 0; i < 64; i++) in[i] = (uint8_t)(i % 251);
    for (size_t t = 0; t < sizeof V / sizeof V[0]; t++) {
        root_digest(in, V[t].len, got);
        hex2bin(V[t].hex, want, 32);
        char msg[64];
        snprintf(msg, sizeof msg, "official vector, len=%zu", V[t].len);
        CHECK(memcmp(got, want, 32) == 0, msg);
    }
}

/* ── 2. Th structural checks ─────────────────────────────────────────────── */

static void test_th(void)
{
    printf("--- Test 2: blake3_th structure ---\n");
    uint8_t a[32], b[32], data[130];
    RAND_bytes(data, sizeof data);

    blake3_th((const uint8_t *)"dom1", 4, data, 100, a, 32);
    blake3_th((const uint8_t *)"dom1", 4, data, 100, b, 32);
    CHECK(memcmp(a, b, 32) == 0, "deterministic");

    blake3_th((const uint8_t *)"dom2", 4, data, 100, b, 32);
    CHECK(memcmp(a, b, 32) != 0, "domain separation");

    blake3_th((const uint8_t *)"dom1", 4, data, 99, b, 32);
    CHECK(memcmp(a, b, 32) != 0, "length separation (block_len in compress)");

    /* 64 vs 65 bytes: same first block content, extra empty-ish block. */
    blake3_th((const uint8_t *)"dom1", 4, data, 64, a, 32);
    blake3_th((const uint8_t *)"dom1", 4, data, 65, b, 32);
    CHECK(memcmp(a, b, 32) != 0, "block-count separation");

    /* cv[7] binds domain_len: a zero-extended domain is a DIFFERENT domain. */
    blake3_th((const uint8_t *)"dom1\0", 5, data, 100, b, 32);
    blake3_th((const uint8_t *)"dom1", 4, data, 100, a, 32);
    CHECK(memcmp(a, b, 32) != 0, "domain-length binding (D vs D||0x00)");

    /* ROOT finalisation: the 32-byte output of a block-aligned Th is NOT the
     * chaining state, so Th(dom, data||E) cannot be computed from Th(dom,
     * data) — recompressing the output must not match. */
    uint8_t ext[64];
    RAND_bytes(ext, 64);
    blake3_th((const uint8_t *)"dom1", 4, data, 64, a, 32);      /* aligned */
    uint8_t cat[128];
    memcpy(cat, data, 64); memcpy(cat + 64, ext, 64);
    blake3_th((const uint8_t *)"dom1", 4, cat, 128, b, 32);
    uint32_t st[8], em[16];
    for (int i = 0; i < 8; i++)
        st[i] = (uint32_t)a[4*i] | ((uint32_t)a[4*i+1] << 8)
              | ((uint32_t)a[4*i+2] << 16) | ((uint32_t)a[4*i+3] << 24);
    for (int i = 0; i < 16; i++)
        em[i] = (uint32_t)ext[4*i] | ((uint32_t)ext[4*i+1] << 8)
              | ((uint32_t)ext[4*i+2] << 16) | ((uint32_t)ext[4*i+3] << 24);
    blake3_compress(st, em, 0, 64, BLAKE3_ROOT, st);
    uint8_t extended[32];
    for (int i = 0; i < 8; i++) {
        extended[i*4+0] = (uint8_t)(st[i]);
        extended[i*4+1] = (uint8_t)(st[i] >> 8);
        extended[i*4+2] = (uint8_t)(st[i] >> 16);
        extended[i*4+3] = (uint8_t)(st[i] >> 24);
    }
    CHECK(memcmp(extended, b, 32) != 0, "not length-extendable (ROOT finalisation)");

    /* Chain step = Th(domain=prev, data=23-byte tweak): one compression
     * with cv = prev || 0-pad, cv[7] = 16, ROOT flag (single block). */
    uint8_t prev[16], tweak[23], cv_bytes[32];
    RAND_bytes(prev, 16); RAND_bytes(tweak, 23);
    blake3_th(prev, 16, tweak, 23, a, 16);
    uint32_t cv[8], m[16] = {0};
    memset(cv_bytes, 0, 32); memcpy(cv_bytes, prev, 16);
    for (int i = 0; i < 8; i++)
        cv[i] = (uint32_t)cv_bytes[4*i] | ((uint32_t)cv_bytes[4*i+1] << 8)
              | ((uint32_t)cv_bytes[4*i+2] << 16) | ((uint32_t)cv_bytes[4*i+3] << 24);
    cv[7] = 16;
    uint8_t blk[64] = {0}; memcpy(blk, tweak, 23);
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)blk[4*i] | ((uint32_t)blk[4*i+1] << 8)
             | ((uint32_t)blk[4*i+2] << 16) | ((uint32_t)blk[4*i+3] << 24);
    blake3_compress(cv, m, 0, 23, BLAKE3_ROOT, cv);
    uint8_t direct[16];
    for (int i = 0; i < 4; i++) {
        direct[i*4+0] = (uint8_t)(cv[i]);
        direct[i*4+1] = (uint8_t)(cv[i] >> 8);
        direct[i*4+2] = (uint8_t)(cv[i] >> 16);
        direct[i*4+3] = (uint8_t)(cv[i] >> 24);
    }
    CHECK(memcmp(a, direct, 16) == 0, "chain step == single compression");
}

/* ── 2b. Call-site domain separation ─────────────────────────────────────── */

/* Mirror blake3_th's cv construction: domain zero-padded to 32 bytes, then
 * cv word 7 (bytes 28..31, LE) = domain_len. */
static void build_cv(const uint8_t *dom, size_t len, uint8_t cv[32])
{
    memset(cv, 0, 32);
    memcpy(cv, dom, len);
    cv[28] = (uint8_t)len;
}

static void test_domains(void)
{
    printf("--- Test 2b: pairwise-distinct chaining values across call sites ---\n");

    /* One fixed parameter set; family separation must not depend on values. */
    uint8_t pk_seed[XMSS_PK_SEED_BYTES], node[16];
    RAND_bytes(pk_seed, sizeof pk_seed);
    RAND_bytes(node, sizeof node);
    const uint32_t epoch = 0x000002A5, level = 3, idx = 0x0042;

    enum { NDOM = 6 };
    uint8_t dom[NDOM][32], cv[NDOM][32];
    size_t len[NDOM];
    const char *name[NDOM] = { "chain", "tree", "leaf", "message", "HMy", "HMd" };

    /* chain: dom = previous node (16 B) — the tweak travels in the data. */
    memcpy(dom[0], node, 16); len[0] = 16;
    /* tree: pk_seed || 0x01 || level || idx (2 LE). */
    memcpy(dom[1], pk_seed, 16);
    dom[1][16] = XMSS_TWEAK_TREE;
    dom[1][17] = (uint8_t)level;
    dom[1][18] = (uint8_t)(idx & 0xFF);
    dom[1][19] = (uint8_t)((idx >> 8) & 0xFF);
    len[1] = 20;
    /* leaf: pk_seed || 0x03 || epoch (4 BE). */
    memcpy(dom[2], pk_seed, 16);
    dom[2][16] = XMSS_TWEAK_LEAF;
    for (int b = 0; b < 4; b++) dom[2][17 + b] = (uint8_t)(epoch >> (8 * (3 - b)));
    len[2] = 21;
    /* message: pk_seed || 0x02 || epoch (4 BE). */
    memcpy(dom[3], dom[2], 21);
    dom[3][16] = XMSS_TWEAK_MESSAGE;
    len[3] = 21;
    /* HM commitment hashes (fixed domains, match commitment.c). */
    memcpy(dom[4], "HMy", 3); len[4] = 3;
    memcpy(dom[5], "HMd", 3); len[5] = 3;

    for (int i = 0; i < NDOM; i++) build_cv(dom[i], len[i], cv[i]);

    int distinct = 1;
    for (int i = 0; i < NDOM && distinct; i++)
        for (int j = i + 1; j < NDOM && distinct; j++)
            if (memcmp(cv[i], cv[j], 32) == 0) {
                printf("  cv collision: %s vs %s\n", name[i], name[j]);
                distinct = 0;
            }
    CHECK(distinct, "all six call-site cvs pairwise distinct");

    /* Worst case for the chain family: its domain is the previous node,
     * which the WITNESS chooses (chain starts are witness bytes).  Even a
     * node equal to the first 16 bytes of another family's domain must give
     * a different cv — this is exactly what cv[7] = domain_len (16 vs
     * 20/21/3) guarantees, since the chain cv is zero from byte 16 on. */
    int adv_ok = 1;
    for (int j = 1; j < NDOM && adv_ok; j++) {
        uint8_t evil_cv[32];
        uint8_t evil_node[16] = {0};
        memcpy(evil_node, dom[j], len[j] < 16 ? len[j] : 16);
        build_cv(evil_node, 16, evil_cv);
        if (memcmp(evil_cv, cv[j], 32) == 0) {
            printf("  adversarial chain node collides with %s\n", name[j]);
            adv_ok = 0;
        }
    }
    CHECK(adv_ok, "witness-chosen chain node cannot reach another family's cv");
}

/* ── 3. MPC gadget vs native ─────────────────────────────────────────────── */

static void test_mpc(void)
{
    printf("--- Test 3: mpc_blake3_th vs native (prove + verify paths) ---\n");

    /* Random masked instance: secret data, mixed public/secret domain. */
    const int dom_len = 21, data_len = 100;
    uint8_t dom[21], data[100], want[32];
    RAND_bytes(dom, dom_len); RAND_bytes(data, data_len);
    blake3_th(dom, dom_len, data, data_len, want, 32);

    unsigned char seed_star[SEED_SIZE];
    RAND_bytes(seed_star, SEED_SIZE);
    unsigned char seeds[N_PARTIES][SEED_SIZE];
    expand_seed_star(seed_star, seeds);
    unsigned char *tapes[N_PARTIES], *lamb[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        tapes[p] = malloc(TAPE_SIZE);
        lamb[p]  = malloc(dom_len + data_len);
        expand_tape(seeds[p], tapes[p]);
        /* Derive input-mask shares from the xshare stream (any bytes do). */
        unsigned char xs[4096];
        expand_xshare(seeds[p], xs);
        memcpy(lamb[p], xs, dom_len + data_len);
    }
    /* Masked public values = value XOR all mask shares. */
    unsigned char dom_pub[21], data_pub[100];
    memcpy(dom_pub, dom, dom_len);
    memcpy(data_pub, data, data_len);
    for (int p = 0; p < N_PARTIES; p++) {
        for (int i = 0; i < dom_len; i++)  dom_pub[i]  ^= lamb[p][i];
        for (int i = 0; i < data_len; i++) data_pub[i] ^= lamb[p][dom_len + i];
    }
    unsigned char *dom_lam[N_PARTIES], *data_lam[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        dom_lam[p]  = lamb[p];
        data_lam[p] = lamb[p] + dom_len;
    }

    uint32_t *aux   = calloc((size_t)ySize, sizeof(uint32_t));
    uint32_t *s_all = calloc((size_t)N_PARTIES * ySize, sizeof(uint32_t));
    unsigned char out_pub[32], out_lam_buf[N_PARTIES][32];
    unsigned char *out_lam[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) out_lam[p] = out_lam_buf[p];

    int gc = 0;
    mpc_blake3_th(dom_pub, dom_lam, dom_len, data_pub, data_lam, data_len,
                  out_pub, out_lam, 32, tapes, aux, s_all, &gc);
    printf("  (gadget gates: %d)\n", gc);

    /* Unmask: value = pub XOR all shares. */
    unsigned char got[32];
    memcpy(got, out_pub, 32);
    for (int p = 0; p < N_PARTIES; p++)
        for (int i = 0; i < 32; i++) got[i] ^= out_lam_buf[p][i];
    CHECK(memcmp(got, want, 32) == 0, "prove path unmasks to native blake3_th");

    /* Verify path for every hidden party e. */
    uint32_t *msgs_e   = malloc((size_t)ySize * sizeof(uint32_t));
    uint32_t *s_slots  = malloc((size_t)(N_PARTIES-1) * ySize * sizeof(uint32_t));
    for (int e = 0; e < N_PARTIES; e++) {
        for (int g2 = 0; g2 < gc; g2++)
            msgs_e[g2] = s_all[(size_t)e * ySize + (size_t)g2];
        unsigned char *vtapes[N_PARTIES-1], *vdlam[N_PARTIES-1], *vdatalam[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            int o = (j < e) ? j : j + 1;
            vtapes[j]   = tapes[o];
            vdlam[j]    = dom_lam[o];
            vdatalam[j] = data_lam[o];
        }
        unsigned char vout_pub[32], vout_lam_buf[N_PARTIES-1][32];
        unsigned char *vout_lam[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) vout_lam[j] = vout_lam_buf[j];
        int vgc = 0;
        mpc_blake3_th_verify(dom_pub, vdlam, dom_len, data_pub, vdatalam, data_len,
                             vout_pub, vout_lam, 32,
                             vtapes, e, msgs_e, aux, s_slots, &vgc);
        char msg[64];
        snprintf(msg, sizeof msg, "verify path matches public output (e=%d)", e);
        int ok = (vgc == gc) && (memcmp(vout_pub, out_pub, 32) == 0);
        /* Revealed parties' broadcast streams must match the prover's. */
        for (int j = 0; j < N_PARTIES-1 && ok; j++) {
            int o = (j < e) ? j : j + 1;
            for (int g2 = 0; g2 < gc && ok; g2++)
                if (s_slots[(size_t)j * ySize + (size_t)g2] !=
                    s_all[(size_t)o * ySize + (size_t)g2]) ok = 0;
        }
        CHECK(ok, msg);
    }

    for (int p = 0; p < N_PARTIES; p++) { free(tapes[p]); free(lamb[p]); }
    free(aux); free(s_all); free(msgs_e); free(s_slots);
}

int main(void)
{
    test_vectors();
    test_th();
    test_domains();
    test_mpc();
    printf("\n%s (%d failure%s)\n", failures?"FAILURES":"ALL PASS", failures, failures==1?"":"s");
    return failures ? 1 : 0;
}
