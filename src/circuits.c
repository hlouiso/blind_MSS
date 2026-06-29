#include "circuits.h"
#include "MPC_prove_functions.h"
#include "MPC_verify_functions.h"
#include "commitment.h"
#include "gf128.h"
#include "shared.h"
#include "xmss.h"

#include <omp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_circuit_gates = 0;

/* ── Prove-side helpers ─────────────────────────────────────────────────── */

/* Run SHA-256 over [prefix | sec (shared) | suffix], truncating to out_len bytes.
 * prefix and suffix are public (placed into party 0's input share only).
 * All N party buffers are allocated/freed internally. */
static void mpc_thash(
    unsigned char *tapes[N_PARTIES], uint32_t *aux, uint32_t *da_db_all, int *gc,
    const unsigned char *prefix, int prefix_len,
    unsigned char *sec[N_PARTIES], int sec_len,
    const unsigned char *suffix, int suffix_len,
    unsigned char *out[N_PARTIES], int out_len)
{
    int total = prefix_len + sec_len + suffix_len;
    unsigned char *inp[N_PARTIES], *res[N_PARTIES];
    for (int i = 0; i < N_PARTIES; i++) { inp[i] = NULL; res[i] = NULL; }
    for (int i = 0; i < N_PARTIES; i++) {
        inp[i] = calloc(total, 1);
        res[i] = malloc(32);
        if (!inp[i] || !res[i]) {
            for (int j = 0; j <= i; j++) { free(inp[j]); free(res[j]); }
            return;
        }
        memcpy(inp[i] + prefix_len, sec[i], sec_len);
    }
    /* Public prefix/suffix go into party 0 only. */
    if (prefix_len) memcpy(inp[0], prefix, prefix_len);
    if (suffix_len) memcpy(inp[0] + prefix_len + sec_len, suffix, suffix_len);

    mpc_sha256(inp, total * 8, res, tapes, aux, da_db_all, gc);

    for (int i = 0; i < N_PARTIES; i++) {
        memcpy(out[i], res[i], out_len);
        free(inp[i]);
        free(res[i]);
    }
}

/* Broadcast a shared selector bit to a full-word mask.
 * For even N, XOR parity of the mask words = 0xFFFF... when bit=1. */
static void mask_from_bit(const uint32_t selw[N_PARTIES], uint32_t mask[N_PARTIES])
{
    for (int i = 0; i < N_PARTIES; i++) mask[i] = 0u - (selw[i] & 1u);
}

/* Like mask_from_bit but for a NEGATED selector: gives mask_xor=0xFFFF...
 * when the original (pre-negation) bit = 0.  For odd N this is just
 * mask_from_bit(selw,...) since negating flips parity; for even N it does
 * not flip parity, so we apply a public correction to party 0. */
static void mask_from_neg_bit(const uint32_t selw[N_PARTIES], uint32_t mask[N_PARTIES])
{
    mask_from_bit(selw, mask);
#if (N_PARTIES % 2 == 0)
    mask[0] ^= 0xFFFFFFFFu;
#endif
}

/* x[i][16] ← sel ? h[i] : x[i], word-wise.  One AND per 32-bit word. */
static void mpc_mux16(
    unsigned char x[N_PARTIES][16], unsigned char h[N_PARTIES][16],
    const uint32_t mask[N_PARTIES],
    unsigned char *tapes[N_PARTIES], uint32_t *aux, uint32_t *da_db_all, int *gc)
{
    for (int w = 0; w < 4; w++) {
        uint32_t xt[N_PARTIES], ht[N_PARTIES], t[N_PARTIES], mt[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(&xt[i], x[i] + w*4, 4);
            memcpy(&ht[i], h[i] + w*4, 4);
        }
        mpc_XOR(xt, ht, t);
        mpc_AND((uint32_t *)mask, t, mt, tapes, aux, da_db_all, gc);
        mpc_XOR(xt, mt, xt);
        for (int i = 0; i < N_PARTIES; i++) memcpy(x[i] + w*4, &xt[i], 4);
    }
}

/* GF(2^128) multiply, N-party. */
static void mpc_gf128_mul(
    const uint32_t X[N_PARTIES][4], const uint32_t Y[N_PARTIES][4],
    uint32_t out[N_PARTIES][4],
    unsigned char *tapes[N_PARTIES], uint32_t *aux, uint32_t *da_db_all, int *gc)
{
    uint32_t acc[N_PARTIES][8];
    for (int i = 0; i < N_PARTIES; i++) memset(acc[i], 0, sizeof(acc[i]));
    for (int j = 0; j < 128; j++) {
        uint32_t mask[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++)
            mask[i] = 0u - ((Y[i][j >> 5] >> (j & 31)) & 1u);
        for (int w = 0; w < 4; w++) {
            uint32_t xw[N_PARTIES], mw[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++) xw[i] = X[i][w];
            mpc_AND(mask, xw, mw, tapes, aux, da_db_all, gc);
            for (int i = 0; i < N_PARTIES; i++)
                gf128_word_shift_xor(acc[i], mw[i], 32 * w + j);
        }
    }
    for (int i = 0; i < N_PARTIES; i++) gf128_reduce(acc[i], out[i]);
}

/* ── building_views ─────────────────────────────────────────────────────── */

void building_views(
    a *a, unsigned char message_digest[32], unsigned char pk_seed[XMSS_PK_SEED_BYTES],
    unsigned char *x_shares[N_PARTIES],
    unsigned char *tapes[N_PARTIES],
    uint32_t *aux, uint32_t *da_db_all_out)
{
    int *gc = calloc(1, sizeof(int));
    if (!gc) { memset(a->yp, 0, sizeof(a->yp)); return; }

    /* Allocate da_db_all internally if caller passed NULL (Pass 1). */
    uint32_t *da_db_all = da_db_all_out;
    bool da_db_internal = false;
    if (!da_db_all) {
        da_db_all = malloc((size_t)N_PARTIES * 2 * ySize * sizeof(uint32_t));
        if (!da_db_all) {
            free(gc);
            memset(a->yp, 0, sizeof(a->yp));
            return;
        }
        da_db_internal = true;
    }

    /* ── (1) Halevi–Micali commitment → certified digest d ── */
    unsigned char dsh[N_PARTIES][32];
    {
        /* (1a) y = SHA256(r_1 ‖ … ‖ r_6) */
        unsigned char ysh[N_PARTIES][32];
        {
            unsigned char *sec[N_PARTIES], *out[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++) {
                sec[i] = x_shares[i] + W_R_OFF;
                out[i] = ysh[i];
            }
            mpc_thash(tapes, aux, da_db_all, gc, NULL, 0, sec, HM_R_BYTES, NULL, 0, out, 32);
        }

        /* (1b) b_k = m̂_k + Σ_i a_{k,i}·r_i  over GF(2^128) */
        unsigned char bsh[N_PARTIES][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++) {
            uint32_t acc[N_PARTIES][4];
            for (int i = 0; i < N_PARTIES; i++) memset(acc[i], 0, sizeof(acc[i]));
            for (int idx = 0; idx < HM_NONCES; idx++) {
                uint32_t A[N_PARTIES][4], R[N_PARTIES][4], P[N_PARTIES][4];
                for (int i = 0; i < N_PARTIES; i++) {
                    gf128_load(A[i], x_shares[i] + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                    gf128_load(R[i], x_shares[i] + W_R_OFF + idx * HM_ELT);
                }
                mpc_gf128_mul(A, R, P, tapes, aux, da_db_all, gc);
                for (int i = 0; i < N_PARTIES; i++)
                    for (int w = 0; w < 4; w++) acc[i][w] ^= P[i][w];
            }
            /* Public m̂_line → party 0 only */
            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            for (int w = 0; w < 4; w++) acc[0][w] ^= Mk[w];
            for (int i = 0; i < N_PARTIES; i++)
                gf128_store(bsh[i] + line * HM_ELT, acc[i]);
        }

        /* (1c) d = SHA256(a ‖ b ‖ y) */
        unsigned char secbuf[N_PARTIES][HM_COM_BYTES];
        unsigned char *sec[N_PARTIES], *out[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(secbuf[i], x_shares[i] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[i] + HM_A_BYTES, bsh[i], HM_B_BYTES);
            memcpy(secbuf[i] + HM_A_BYTES + HM_B_BYTES, ysh[i], HM_Y_BYTES);
            sec[i] = secbuf[i]; out[i] = dsh[i];
        }
        mpc_thash(tapes, aux, da_db_all, gc, NULL, 0, sec, HM_COM_BYTES, NULL, 0, out, 32);
    }

    /* ── (2) mh = SHA256(pk_seed ‖ 0x02 ‖ epoch ‖ nonce ‖ d) ── */
    unsigned char mh[N_PARTIES][32];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        unsigned char secbuf[N_PARTIES][XMSS_EPOCH_BYTES + XMSS_NONCE_LEN + 32];
        unsigned char *sec[N_PARTIES], *out[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(secbuf[i], x_shares[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            memcpy(secbuf[i] + XMSS_EPOCH_BYTES, x_shares[i] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[i] + XMSS_EPOCH_BYTES + XMSS_NONCE_LEN, dsh[i], 32);
            sec[i] = secbuf[i]; out[i] = mh[i];
        }
        mpc_thash(tapes, aux, da_db_all, gc, prefix, XMSS_PK_SEED_BYTES + 1,
                  sec, XMSS_EPOCH_BYTES + XMSS_NONCE_LEN + 32, NULL, 0, out, 32);
    }

    /* ── (3) WOTS+ chains → pk_hashes ── */
    unsigned char pkh[N_PARTIES][XMSS_EPOCH_BYTES + XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    {
        unsigned char chain_prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(chain_prefix, pk_seed, XMSS_PK_SEED_BYTES);
        chain_prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_CHAIN;
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        /* The L-tree leaf hashes pk_seed‖0x01‖epoch‖pk_hashes; reserve the epoch
         * prefix at the front of pkh so the leaf hash reads it in place. */
        for (int i = 0; i < N_PARTIES; i++)
            memcpy(pkh[i], x_shares[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);

        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            unsigned char x[N_PARTIES][16];
            for (int i = 0; i < N_PARTIES; i++)
                memcpy(x[i], x_shares[i] + W_SIG_OFF + ci * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            int byte_idx = ci / cpb;
            int shift = (ci % cpb) * XMSS_COORD_RES_BITS;
            uint32_t c0[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++)
                c0[i] = (uint32_t)((mh[i][byte_idx] >> shift) & 1u);

#if XMSS_WOTS_MAX_STEPS == 1
            uint32_t nc0[N_PARTIES];
            mpc_NEGATE(c0, nc0);
            uint32_t *sels[1] = {nc0};
#else
            uint32_t c1[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++)
                c1[i] = (uint32_t)((mh[i][byte_idx] >> (shift + 1)) & 1u);
            uint32_t nc0[N_PARTIES], nc1[N_PARTIES];
            uint32_t sel1[N_PARTIES], sel2[N_PARTIES], and3[N_PARTIES], sel3[N_PARTIES];
            mpc_NEGATE(c0, nc0); mpc_NEGATE(c1, nc1);
            mpc_AND(nc0, nc1, sel1, tapes, aux, da_db_all, gc);
            mpc_NEGATE(c1, sel2);
            mpc_AND(c0, c1, and3, tapes, aux, da_db_all, gc);
            mpc_NEGATE(and3, sel3);
            uint32_t *sels[3] = {sel1, sel2, sel3};
#endif
            for (int stage = 0; stage < XMSS_WOTS_MAX_STEPS; stage++) {
                unsigned char h[N_PARTIES][16];
                unsigned char suffix[2] = {(unsigned char)ci, (unsigned char)(stage + 1)};
                unsigned char xe[N_PARTIES][XMSS_EPOCH_BYTES + XMSS_NODE_BYTES];
                unsigned char *secp[N_PARTIES], *outp[N_PARTIES];
                for (int i = 0; i < N_PARTIES; i++) {
                    memcpy(xe[i], x_shares[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
                    memcpy(xe[i] + XMSS_EPOCH_BYTES, x[i], XMSS_NODE_BYTES);
                    secp[i] = xe[i]; outp[i] = h[i];
                }
                mpc_thash(tapes, aux, da_db_all, gc, chain_prefix, XMSS_PK_SEED_BYTES + 1,
                          secp, XMSS_EPOCH_BYTES + XMSS_NODE_BYTES, suffix, 2, outp, 16);
                uint32_t mask[N_PARTIES];
                mask_from_neg_bit(sels[stage], mask);
                mpc_mux16(x, h, mask, tapes, aux, da_db_all, gc);
            }
            for (int i = 0; i < N_PARTIES; i++)
                memcpy(pkh[i] + XMSS_EPOCH_BYTES + ci * XMSS_NODE_BYTES, x[i], XMSS_NODE_BYTES);
        }
    }

    /* ── (4) leaf = SHA256(pk_seed ‖ 0x01 ‖ epoch ‖ pk_hashes) ──
     * pkh already carries the epoch prefix (set in (3)). */
    unsigned char node[N_PARTIES][16];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_TREE;
        unsigned char *sec[N_PARTIES], *out[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++) { sec[i] = pkh[i]; out[i] = node[i]; }
        mpc_thash(tapes, aux, da_db_all, gc, prefix, XMSS_PK_SEED_BYTES + 1,
                  sec, XMSS_EPOCH_BYTES + XMSS_WOTS_LEN * XMSS_NODE_BYTES, NULL, 0, out, 16);
    }

    /* ── (5) XMSS auth-path walk → root ── */
    {
        uint32_t li[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++) {
            const unsigned char *b = x_shares[i] + W_LEAFIDX_OFF;
            li[i] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                  | ((uint32_t)b[2] <<  8) | (uint32_t)b[3];
        }
        for (int level = 0; level < XMSS_H; level++) {
            unsigned char sib[N_PARTIES][16];
            for (int i = 0; i < N_PARTIES; i++)
                memcpy(sib[i], x_shares[i] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            uint32_t bitw[N_PARTIES], mask[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++) bitw[i] = (li[i] >> level) & 1u;
            mask_from_bit(bitw, mask);

            unsigned char left[N_PARTIES][16], right[N_PARTIES][16];
            for (int w = 0; w < 4; w++) {
                uint32_t nd[N_PARTIES], sb[N_PARTIES], t[N_PARTIES], mt[N_PARTIES];
                uint32_t lw[N_PARTIES], rw[N_PARTIES];
                for (int i = 0; i < N_PARTIES; i++) {
                    memcpy(&nd[i], node[i] + w*4, 4);
                    memcpy(&sb[i], sib[i]  + w*4, 4);
                }
                mpc_XOR(nd, sb, t);
                mpc_AND((uint32_t *)mask, t, mt, tapes, aux, da_db_all, gc);
                mpc_XOR(nd, mt, lw);
                mpc_XOR(sb, mt, rw);
                for (int i = 0; i < N_PARTIES; i++) {
                    memcpy(left[i]  + w*4, &lw[i], 4);
                    memcpy(right[i] + w*4, &rw[i], 4);
                }
            }

            unsigned char prefix[XMSS_PK_SEED_BYTES + 2];
            memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
            prefix[XMSS_PK_SEED_BYTES]     = XMSS_TWEAK_TREE;
            prefix[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            unsigned char secbuf[N_PARTIES][2 + 16 + 16];
            unsigned char *sec[N_PARTIES], *out[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++) {
                uint32_t idx = (li[i] >> (level + 1)) & 0xFFFFu;
                secbuf[i][0] = (unsigned char)(idx & 0xFF);
                secbuf[i][1] = (unsigned char)((idx >> 8) & 0xFF);
                memcpy(secbuf[i] + 2,      left[i],  16);
                memcpy(secbuf[i] + 2 + 16, right[i], 16);
                sec[i] = secbuf[i]; out[i] = node[i];
            }
            mpc_thash(tapes, aux, da_db_all, gc,
                      prefix, XMSS_PK_SEED_BYTES + 2,
                      sec, 2 + 16 + 16, NULL, 0, out, 16);
        }
    }

    /* ── (6) codeword target sum ── */
    uint32_t acc[N_PARTIES];
    memset(acc, 0, sizeof(acc));
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        const uint32_t cmask = (1u << XMSS_COORD_RES_BITS) - 1u;
        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            int byte_idx = ci / cpb;
            int shift    = (ci % cpb) * XMSS_COORD_RES_BITS;
            uint32_t coord[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++)
                coord[i] = (uint32_t)((mh[i][byte_idx] >> shift) & cmask);
            mpc_ADD(acc, coord, acc, tapes, aux, da_db_all, gc);
        }
    }

    /* ── Output shares ── */
    for (int i = 0; i < N_PARTIES; i++) {
        for (int w = 0; w < YP_ROOT_WORDS; w++)
            memcpy(&a->yp[i][w], node[i] + w*4, 4);
        a->yp[i][YP_SUM_WORD] = acc[i];
        for (int w = YP_SUM_WORD + 1; w < 8; w++) a->yp[i][w] = 0;
    }

    /* Record the gate count only when called standalone (test_circuit).
     * The parallel prove/verify passes all run the same fixed circuit, so
     * skipping the write there avoids a benign-but-real data race on this global. */
    if (!omp_in_parallel()) g_circuit_gates = *gc;
    free(gc);

    /* KKW Trou 2: h'_j = H(da_db_all) — symmetric across all parties.
     * Committed in h* before challenge derivation. */
    compute_h_prime(da_db_all, a->h_prime);

    if (da_db_internal) free(da_db_all);
}

/* ── Verify-side helpers ────────────────────────────────────────────────── */

/* Slot j maps to original party (j < e) ? j : j+1.
 * Party 0 gets prefix/suffix in ADDK; public prefix/suffix go into slot
 * for party 0 (i.e., slot 0 when e > 0). */

static void mpc_thash_verify(
    unsigned char *tapes[N_PARTIES-1], int e,
    const uint32_t *msgs_e, const uint32_t *aux,
    uint32_t *per_party_da_db, int *gc,
    const unsigned char *prefix, int prefix_len,
    unsigned char *sec[N_PARTIES-1], int sec_len,
    const unsigned char *suffix, int suffix_len,
    unsigned char *out[N_PARTIES-1], int out_len)
{
    int total = prefix_len + sec_len + suffix_len;
    unsigned char *inp[N_PARTIES-1], *res[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) { inp[j] = NULL; res[j] = NULL; }
    for (int j = 0; j < N_PARTIES-1; j++) {
        inp[j] = calloc(total, 1);
        res[j] = malloc(32);
        if (!inp[j] || !res[j]) {
            for (int k = 0; k <= j; k++) { free(inp[k]); free(res[k]); }
            return;
        }
        memcpy(inp[j] + prefix_len, sec[j], sec_len);
        /* Public prefix/suffix go to party 0; slot 0 = party 0 iff e != 0. */
        if (e != 0 && j == 0) {
            if (prefix_len) memcpy(inp[j], prefix, prefix_len);
            if (suffix_len) memcpy(inp[j] + prefix_len + sec_len, suffix, suffix_len);
        }
    }
    mpc_sha256_verify(inp, total * 8, res, tapes, e, msgs_e, aux, per_party_da_db, gc);
    for (int j = 0; j < N_PARTIES-1; j++) {
        memcpy(out[j], res[j], out_len);
        free(inp[j]); free(res[j]);
    }
}

static void mpc_mux16_verify(
    unsigned char x[N_PARTIES-1][16], unsigned char h[N_PARTIES-1][16],
    const uint32_t mask[N_PARTIES-1],
    unsigned char *tapes[N_PARTIES-1], int e,
    const uint32_t *msgs_e, const uint32_t *aux,
    uint32_t *per_party_da_db, int *gc)
{
    for (int w = 0; w < 4; w++) {
        uint32_t xt[N_PARTIES-1], ht[N_PARTIES-1], t[N_PARTIES-1], mt[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(&xt[j], x[j] + w*4, 4);
            memcpy(&ht[j], h[j] + w*4, 4);
        }
        mpc_XOR_v(xt, ht, t);
        mpc_AND_verify((uint32_t *)mask, t, mt, tapes, e, msgs_e, aux, per_party_da_db, gc);
        mpc_XOR_v(xt, mt, xt);
        for (int j = 0; j < N_PARTIES-1; j++) memcpy(x[j] + w*4, &xt[j], 4);
    }
}

static void mpc_gf128_mul_verify(
    const uint32_t X[N_PARTIES-1][4], const uint32_t Y[N_PARTIES-1][4],
    uint32_t out[N_PARTIES-1][4],
    unsigned char *tapes[N_PARTIES-1], int e,
    const uint32_t *msgs_e, const uint32_t *aux,
    uint32_t *per_party_da_db, int *gc)
{
    uint32_t acc[N_PARTIES-1][8];
    for (int j = 0; j < N_PARTIES-1; j++) memset(acc[j], 0, sizeof(acc[j]));
    for (int bit = 0; bit < 128; bit++) {
        uint32_t mask[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++)
            mask[j] = 0u - ((Y[j][bit >> 5] >> (bit & 31)) & 1u);
        for (int w = 0; w < 4; w++) {
            uint32_t xw[N_PARTIES-1], mw[N_PARTIES-1];
            for (int j = 0; j < N_PARTIES-1; j++) xw[j] = X[j][w];
            mpc_AND_verify(mask, xw, mw, tapes, e, msgs_e, aux, per_party_da_db, gc);
            for (int j = 0; j < N_PARTIES-1; j++)
                gf128_word_shift_xor(acc[j], mw[j], 32 * w + bit);
        }
    }
    for (int j = 0; j < N_PARTIES-1; j++) gf128_reduce(acc[j], out[j]);
}

/* ── verify ─────────────────────────────────────────────────────────────── */

void verify(
    unsigned char message_digest[32], unsigned char pk_seed[XMSS_PK_SEED_BYTES],
    bool *error, a *a_struct, int e, z *z_proof)
{
    /* Expand tapes for the N-1 revealed parties. */
    unsigned char *tapes[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) tapes[j] = NULL;
    for (int j = 0; j < N_PARTIES-1; j++) {
        tapes[j] = malloc((size_t)TAPE_SIZE);
        if (!tapes[j]) {
            for (int k = 0; k < j; k++) free(tapes[k]);
            *error = true; return;
        }
        expand_tape(z_proof->ke[j], tapes[j]);
    }

    /* Allocate per_party_da_db for h_prime recomputation. */
    uint32_t *per_party_da_db = malloc((size_t)(N_PARTIES-1) * 2 * ySize * sizeof(uint32_t));
    if (!per_party_da_db) {
        for (int j = 0; j < N_PARTIES-1; j++) free(tapes[j]);
        *error = true; return;
    }

    /* Reconstruct the N-1 revealed parties' input shares.  Parties 0..N-2 are
     * seed-derived, so re-expand them from the revealed seed; party N-1 (when
     * revealed, i.e. e != N-1) is the witness offset carried in the proof.
     * This avoids transmitting all N-1 shares (saves (N-2)*INPUT_LEN/round). */
    unsigned char *xbuf = malloc((size_t)(N_PARTIES-1) * INPUT_LEN);
    if (!xbuf) {
        free(per_party_da_db);
        for (int j = 0; j < N_PARTIES-1; j++) free(tapes[j]);
        *error = true; return;
    }
    unsigned char *vx[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) {
        int o = (j < e) ? j : j + 1;
        vx[j] = xbuf + (size_t)j * INPUT_LEN;
        if (o == N_PARTIES - 1)
            memcpy(vx[j], z_proof->x_offset, INPUT_LEN);
        else
            expand_xshare(z_proof->ke[j], vx[j]);
    }

    int gc = 0;
    const uint32_t *msgs_e = z_proof->msgs_e;

    /* ── (1) Halevi–Micali commitment → d ── */
    unsigned char dsh[N_PARTIES-1][32];
    {
        unsigned char ysh[N_PARTIES-1][32];
        {
            unsigned char *sec[N_PARTIES-1], *out[N_PARTIES-1];
            for (int j = 0; j < N_PARTIES-1; j++) { sec[j] = vx[j] + W_R_OFF; out[j] = ysh[j]; }
            mpc_thash_verify(tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc,
                             NULL, 0, sec, HM_R_BYTES, NULL, 0, out, 32);
        }

        unsigned char bsh[N_PARTIES-1][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++) {
            uint32_t acc[N_PARTIES-1][4];
            for (int j = 0; j < N_PARTIES-1; j++) memset(acc[j], 0, sizeof(acc[j]));
            for (int idx = 0; idx < HM_NONCES; idx++) {
                uint32_t A[N_PARTIES-1][4], R[N_PARTIES-1][4], P[N_PARTIES-1][4];
                for (int j = 0; j < N_PARTIES-1; j++) {
                    gf128_load(A[j], vx[j] + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                    gf128_load(R[j], vx[j] + W_R_OFF + idx * HM_ELT);
                }
                mpc_gf128_mul_verify(A, R, P, tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc);
                for (int j = 0; j < N_PARTIES-1; j++)
                    for (int w = 0; w < 4; w++) acc[j][w] ^= P[j][w];
            }
            /* + m̂_line into party 0's slot (slot 0 when e > 0) */
            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            if (e != 0)
                for (int w = 0; w < 4; w++) acc[0][w] ^= Mk[w];
            for (int j = 0; j < N_PARTIES-1; j++)
                gf128_store(bsh[j] + line * HM_ELT, acc[j]);
        }

        unsigned char secbuf[N_PARTIES-1][HM_COM_BYTES];
        unsigned char *sec[N_PARTIES-1], *out[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(secbuf[j], vx[j] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES, bsh[j], HM_B_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES + HM_B_BYTES, ysh[j], HM_Y_BYTES);
            sec[j] = secbuf[j]; out[j] = dsh[j];
        }
        mpc_thash_verify(tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc,
                         NULL, 0, sec, HM_COM_BYTES, NULL, 0, out, 32);
    }

    /* ── (2) mh ── */
    unsigned char mh[N_PARTIES-1][32];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        unsigned char secbuf[N_PARTIES-1][XMSS_EPOCH_BYTES + XMSS_NONCE_LEN + 32];
        unsigned char *sec[N_PARTIES-1], *out[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(secbuf[j], vx[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            memcpy(secbuf[j] + XMSS_EPOCH_BYTES, vx[j] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[j] + XMSS_EPOCH_BYTES + XMSS_NONCE_LEN, dsh[j], 32);
            sec[j] = secbuf[j]; out[j] = mh[j];
        }
        mpc_thash_verify(tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc,
                         prefix, XMSS_PK_SEED_BYTES + 1, sec,
                         XMSS_EPOCH_BYTES + XMSS_NONCE_LEN + 32, NULL, 0, out, 32);
    }

    /* ── (3) WOTS+ chains ── */
    unsigned char pkh[N_PARTIES-1][XMSS_EPOCH_BYTES + XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    {
        unsigned char chain_prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(chain_prefix, pk_seed, XMSS_PK_SEED_BYTES);
        chain_prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_CHAIN;
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        /* epoch prefix at the front of pkh for the L-tree leaf hash. */
        for (int j = 0; j < N_PARTIES-1; j++)
            memcpy(pkh[j], vx[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);

        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            unsigned char x[N_PARTIES-1][16];
            for (int j = 0; j < N_PARTIES-1; j++)
                memcpy(x[j], vx[j] + W_SIG_OFF + ci * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            int byte_idx = ci / cpb;
            int shift = (ci % cpb) * XMSS_COORD_RES_BITS;
            uint32_t c0[N_PARTIES-1];
            for (int j = 0; j < N_PARTIES-1; j++)
                c0[j] = (uint32_t)((mh[j][byte_idx] >> shift) & 1u);

#if XMSS_WOTS_MAX_STEPS == 1
            uint32_t nc0[N_PARTIES-1];
            mpc_NEGATE_v(c0, nc0);
            uint32_t *sels[1] = {nc0};
#else
            uint32_t c1[N_PARTIES-1];
            for (int j = 0; j < N_PARTIES-1; j++)
                c1[j] = (uint32_t)((mh[j][byte_idx] >> (shift + 1)) & 1u);
            uint32_t nc0[N_PARTIES-1], nc1[N_PARTIES-1];
            uint32_t sel1[N_PARTIES-1], sel2[N_PARTIES-1];
            uint32_t and3[N_PARTIES-1], sel3[N_PARTIES-1];
            mpc_NEGATE_v(c0, nc0); mpc_NEGATE_v(c1, nc1);
            mpc_AND_verify(nc0, nc1, sel1, tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc);
            mpc_NEGATE_v(c1, sel2);
            mpc_AND_verify(c0, c1, and3, tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc);
            mpc_NEGATE_v(and3, sel3);
            uint32_t *sels[3] = {sel1, sel2, sel3};
#endif
            for (int stage = 0; stage < XMSS_WOTS_MAX_STEPS; stage++) {
                unsigned char h[N_PARTIES-1][16];
                unsigned char suffix[2] = {(unsigned char)ci, (unsigned char)(stage + 1)};
                unsigned char xe[N_PARTIES-1][XMSS_EPOCH_BYTES + XMSS_NODE_BYTES];
                unsigned char *secp[N_PARTIES-1], *outp[N_PARTIES-1];
                for (int j = 0; j < N_PARTIES-1; j++) {
                    memcpy(xe[j], vx[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
                    memcpy(xe[j] + XMSS_EPOCH_BYTES, x[j], XMSS_NODE_BYTES);
                    secp[j] = xe[j]; outp[j] = h[j];
                }
                mpc_thash_verify(tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc,
                                 chain_prefix, XMSS_PK_SEED_BYTES + 1,
                                 secp, XMSS_EPOCH_BYTES + XMSS_NODE_BYTES, suffix, 2, outp, 16);
                uint32_t mask[N_PARTIES-1];
                for (int j = 0; j < N_PARTIES-1; j++)
                    mask[j] = 0u - (sels[stage][j] & 1u);
#if (N_PARTIES % 2 == 0)
                /* mask_from_neg_bit correction: party 0's mask gets XOR'd with
                 * 0xFFFF... to flip the polarity for even N.  Apply to the slot
                 * for party 0, which is slot 0 whenever e != 0. */
                if (e != 0) mask[0] ^= 0xFFFFFFFFu;
#endif
                mpc_mux16_verify(x, h, mask, tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc);
            }
            for (int j = 0; j < N_PARTIES-1; j++)
                memcpy(pkh[j] + XMSS_EPOCH_BYTES + ci * XMSS_NODE_BYTES, x[j], XMSS_NODE_BYTES);
        }
    }

    /* ── (4) leaf = SHA256(pk_seed ‖ 0x01 ‖ epoch ‖ pk_hashes) ── */
    unsigned char node[N_PARTIES-1][16];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_TREE;
        unsigned char *sec[N_PARTIES-1], *out[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) { sec[j] = pkh[j]; out[j] = node[j]; }
        mpc_thash_verify(tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc,
                         prefix, XMSS_PK_SEED_BYTES + 1,
                         sec, XMSS_EPOCH_BYTES + XMSS_WOTS_LEN * XMSS_NODE_BYTES, NULL, 0, out, 16);
    }

    /* ── (5) auth-path walk ── */
    {
        uint32_t li[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            const unsigned char *b = vx[j] + W_LEAFIDX_OFF;
            li[j] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                  | ((uint32_t)b[2] <<  8) | (uint32_t)b[3];
        }
        for (int level = 0; level < XMSS_H; level++) {
            unsigned char sib[N_PARTIES-1][16];
            for (int j = 0; j < N_PARTIES-1; j++)
                memcpy(sib[j], vx[j] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            uint32_t mask[N_PARTIES-1];
            for (int j = 0; j < N_PARTIES-1; j++)
                mask[j] = 0u - ((li[j] >> level) & 1u);

            unsigned char left[N_PARTIES-1][16], right[N_PARTIES-1][16];
            for (int w = 0; w < 4; w++) {
                uint32_t nd[N_PARTIES-1], sb[N_PARTIES-1];
                uint32_t t[N_PARTIES-1], mt[N_PARTIES-1];
                uint32_t lw[N_PARTIES-1], rw[N_PARTIES-1];
                for (int j = 0; j < N_PARTIES-1; j++) {
                    memcpy(&nd[j], node[j] + w*4, 4);
                    memcpy(&sb[j], sib[j]  + w*4, 4);
                }
                mpc_XOR_v(nd, sb, t);
                mpc_AND_verify((uint32_t *)mask, t, mt,
                               tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc);
                mpc_XOR_v(nd, mt, lw);
                mpc_XOR_v(sb, mt, rw);
                for (int j = 0; j < N_PARTIES-1; j++) {
                    memcpy(left[j]  + w*4, &lw[j], 4);
                    memcpy(right[j] + w*4, &rw[j], 4);
                }
            }

            unsigned char prefix[XMSS_PK_SEED_BYTES + 2];
            memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
            prefix[XMSS_PK_SEED_BYTES]     = XMSS_TWEAK_TREE;
            prefix[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            unsigned char secbuf[N_PARTIES-1][2 + 16 + 16];
            unsigned char *sec[N_PARTIES-1], *out[N_PARTIES-1];
            for (int j = 0; j < N_PARTIES-1; j++) {
                uint32_t idx = (li[j] >> (level + 1)) & 0xFFFFu;
                secbuf[j][0] = (unsigned char)(idx & 0xFF);
                secbuf[j][1] = (unsigned char)((idx >> 8) & 0xFF);
                memcpy(secbuf[j] + 2,      left[j],  16);
                memcpy(secbuf[j] + 2 + 16, right[j], 16);
                sec[j] = secbuf[j]; out[j] = node[j];
            }
            mpc_thash_verify(tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc,
                             prefix, XMSS_PK_SEED_BYTES + 2,
                             sec, 2 + 16 + 16, NULL, 0, out, 16);
        }
    }

    /* ── (6) target sum ── */
    uint32_t sum[N_PARTIES-1];
    memset(sum, 0, sizeof(sum));
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        const uint32_t cmask = (1u << XMSS_COORD_RES_BITS) - 1u;
        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            int byte_idx = ci / cpb;
            int shift    = (ci % cpb) * XMSS_COORD_RES_BITS;
            uint32_t coord[N_PARTIES-1];
            for (int j = 0; j < N_PARTIES-1; j++)
                coord[j] = (uint32_t)((mh[j][byte_idx] >> shift) & cmask);
            mpc_ADD_verify(sum, coord, sum, tapes, e, msgs_e, z_proof->aux, per_party_da_db, &gc);
        }
    }

    /* ── Check output shares against commitments ── */
    for (int j = 0; j < N_PARTIES-1; j++) {
        int o = (j < e) ? j : j + 1;
        uint32_t root_v;
        for (int w = 0; w < YP_ROOT_WORDS; w++) {
            memcpy(&root_v, node[j] + w*4, 4);
            if (root_v != a_struct->yp[o][w]) { *error = true; }
        }
        if (sum[j] != a_struct->yp[o][YP_SUM_WORD]) { *error = true; }
    }

    /* ── Check commitments for each revealed party ── */
    for (int j = 0; j < N_PARTIES-1; j++) {
        int o = (j < e) ? j : j + 1;
        unsigned char hash[32];
        H_com(z_proof->ke[j], vx[j], a_struct->yp[o], hash);
        if (memcmp(a_struct->h[o], hash, 32) != 0) { *error = true; }
    }

    /* ── KKW Trou 2: verify h'_j = H(da_db_all) ── */
    {
        unsigned char h_prime_check[32];
        recompute_h_prime_verify(e, per_party_da_db, msgs_e, h_prime_check);
        if (memcmp(h_prime_check, a_struct->h_prime, 32) != 0) { *error = true; }
    }

    free(per_party_da_db);
    free(xbuf);
    for (int j = 0; j < N_PARTIES-1; j++) free(tapes[j]);
}
