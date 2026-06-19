#include "circuits.h"
#include "MPC_prove_functions.h"
#include "MPC_verify_functions.h"
#include "commitment.h"
#include "gf128.h"
#include "shared.h"
#include "xmss.h"

#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Number of nonlinear-gate transcript words written by the last building_views
 * call (== final countY).  Used to size ySize / Random_Bytes_Needed exactly. */
int g_circuit_gates = 0;

/* ────────────────────────────── prove-side helpers ──────────────────────────── */

/* One keyed/tweaked SHA-256 over [public prefix | secret region (3 shares) |
 * public suffix].  Public bytes go into party 0 only (zero for parties 1,2) so
 * they reconstruct to the constant; the secret region is XOR-shared.  Writes the
 * first out_len bytes of each party's digest to out[k] (out_len=16 truncates a
 * tweakable-hash node; out_len=32 keeps the full digest). */
static void mpc_thash(View *views[3], unsigned char *randomness[3], int *countY, int *randCount,
                      const unsigned char *prefix, int prefix_len, unsigned char *sec[3], int sec_len,
                      const unsigned char *suffix, int suffix_len, unsigned char *out[3], int out_len)
{
    int total = prefix_len + sec_len + suffix_len;
    unsigned char *inp[3];
    unsigned char *res[3];
    for (int k = 0; k < 3; k++)
    {
        inp[k] = calloc(total, 1);
        res[k] = malloc(32);
        if (prefix_len && k == 0)
            memcpy(inp[0], prefix, prefix_len);
        memcpy(inp[k] + prefix_len, sec[k], sec_len);
    }
    if (suffix_len)
        memcpy(inp[0] + prefix_len + sec_len, suffix, suffix_len);

    mpc_sha256(inp, total * 8, randomness, res, views, countY, randCount);

    for (int k = 0; k < 3; k++)
    {
        memcpy(out[k], res[k], out_len);
        free(inp[k]);
        free(res[k]);
    }
}

/* Broadcast a shared selector bit (held in bit 0 of selw[k]) to a full-word mask
 * mask[k] = -(selw[k] & 1).  Under XOR-sharing this is a valid sharing of
 * -(sel), because XOR of {0x0, 0xFFFFFFFF} words equals 0xFFFFFFFF iff the bit
 * parity (= the reconstructed selector) is 1. */
static void mask_from_bit(const uint32_t selw[3], uint32_t mask[3])
{
    for (int k = 0; k < 3; k++)
        mask[k] = 0u - (selw[k] & 1u);
}

/* x[k] (16 bytes, 3 shares) ← sel ? h[k] : x[k], word-wise:  x = x ^ (mask & (x ^ h)).
 * One mpc_AND per 32-bit word (4 total). */
static void mpc_mux16(unsigned char x[3][16], unsigned char h[3][16], const uint32_t mask[3],
                      unsigned char *randomness[3], int *randCount, View *views[3], int *countY)
{
    for (int w = 0; w < 4; w++)
    {
        uint32_t xt[3], ht[3], t[3], mt[3];
        for (int k = 0; k < 3; k++)
        {
            memcpy(&xt[k], x[k] + w * 4, 4);
            memcpy(&ht[k], h[k] + w * 4, 4);
        }
        mpc_XOR(xt, ht, t);
        mpc_AND((uint32_t *)mask, t, mt, randomness, randCount, views, countY);
        mpc_XOR(xt, mt, xt);
        for (int k = 0; k < 3; k++)
            memcpy(x[k] + w * 4, &xt[k], 4);
    }
}

/* Shared GF(2^128) multiply: out = X * Y, each a 3-share 128-bit element in word
 * form (4 little-endian words).  Conditional shift-and-XOR over the 128 bits of Y:
 * each Y-bit broadcasts (locally, free) to a full-word mask, AND'd with X (4
 * mpc_AND gates) and shift-accumulated into a 256-bit product, which is then
 * reduced mod the field polynomial.  512 mpc_AND gates per multiply; the
 * shift-accumulate and reduction are GF(2)-linear (value-independent) so they run
 * per share with no transcript/randomness cost — guaranteeing the reconstructed
 * product equals the native gf128_mul. */
static void mpc_gf128_mul(const uint32_t X[3][4], const uint32_t Y[3][4], uint32_t out[3][4],
                          unsigned char *randomness[3], int *randCount, View *views[3], int *countY)
{
    uint32_t acc[3][8] = {{0}};
    for (int j = 0; j < 128; j++)
    {
        uint32_t mask[3];
        for (int k = 0; k < 3; k++)
            mask[k] = 0u - ((Y[k][j >> 5] >> (j & 31)) & 1u);
        for (int w = 0; w < 4; w++)
        {
            uint32_t xw[3] = {X[0][w], X[1][w], X[2][w]};
            uint32_t mw[3];
            mpc_AND(mask, xw, mw, randomness, randCount, views, countY);
            for (int k = 0; k < 3; k++)
                gf128_word_shift_xor(acc[k], mw[k], 32 * w + j);
        }
    }
    for (int k = 0; k < 3; k++)
        gf128_reduce(acc[k], out[k]);
}

/* ──────────────────────────────── building_views ────────────────────────────── */

void building_views(a *a, unsigned char message_digest[32], unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                    unsigned char *shares[3], unsigned char *randomness[3], View *views[3])
{
    int *countY = calloc(1, sizeof(int));
    int *randCount = calloc(1, sizeof(int));

    /* =================== (1) Halevi–Micali commitment → digest d =================== */
    unsigned char dsh[3][32];
    {
        /* (1a) y = SHA256(r_1 ‖ … ‖ r_6) — hashes the n=6 nonces only */
        unsigned char ysh[3][32];
        {
            unsigned char *sec[3], *out[3];
            for (int k = 0; k < 3; k++)
            {
                sec[k] = shares[k] + W_R_OFF;
                out[k] = ysh[k];
            }
            mpc_thash(views, randomness, countY, randCount, NULL, 0, sec, HM_R_BYTES, NULL, 0, out, 32);
        }

        /* (1b) two affine lines b_k = m̂_k + Σ_i a_{k,i}·r_i over GF(2^128) */
        unsigned char bsh[3][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++)
        {
            uint32_t acc[3][4] = {{0}};
            for (int i = 0; i < HM_NONCES; i++)
            {
                uint32_t A[3][4], R[3][4], P[3][4];
                for (int k = 0; k < 3; k++)
                {
                    gf128_load(A[k], shares[k] + W_A_OFF + (line * HM_NONCES + i) * HM_ELT);
                    gf128_load(R[k], shares[k] + W_R_OFF + i * HM_ELT);
                }
                mpc_gf128_mul(A, R, P, randomness, randCount, views, countY);
                for (int k = 0; k < 3; k++)
                    for (int w = 0; w < 4; w++)
                        acc[k][w] ^= P[k][w];
            }
            /* + m̂_line (public): XOR the public 16-byte half into party 0 only */
            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            for (int w = 0; w < 4; w++)
                acc[0][w] ^= Mk[w];
            for (int k = 0; k < 3; k++)
                gf128_store(bsh[k] + line * HM_ELT, acc[k]);
        }

        /* (1c) certified digest d = SHA256(a ‖ b ‖ y) — a,b,y all secret */
        unsigned char secbuf[3][HM_COM_BYTES];
        unsigned char *sec[3], *out[3];
        for (int k = 0; k < 3; k++)
        {
            memcpy(secbuf[k], shares[k] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[k] + HM_A_BYTES, bsh[k], HM_B_BYTES);
            memcpy(secbuf[k] + HM_A_BYTES + HM_B_BYTES, ysh[k], HM_Y_BYTES);
            sec[k] = secbuf[k];
            out[k] = dsh[k];
        }
        mpc_thash(views, randomness, countY, randCount, NULL, 0, sec, HM_COM_BYTES, NULL, 0, out, 32);
    }

    /* =========== (2) message hash mh = SHA256(pk_seed ‖ 0x02 ‖ nonce ‖ d) =========== */
    unsigned char mh[3][32];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        unsigned char secbuf[3][XMSS_NONCE_LEN + 32];
        unsigned char *sec[3], *out[3];
        for (int k = 0; k < 3; k++)
        {
            memcpy(secbuf[k], shares[k] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[k] + XMSS_NONCE_LEN, dsh[k], 32);
            sec[k] = secbuf[k];
            out[k] = mh[k];
        }
        mpc_thash(views, randomness, countY, randCount, prefix, XMSS_PK_SEED_BYTES + 1, sec, XMSS_NONCE_LEN + 32,
                  NULL, 0, out, 32);
    }

    /* =================== (3) WOTS+ chains → pk_hashes =================== */
    unsigned char pkh[3][XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    {
        unsigned char chain_prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(chain_prefix, pk_seed, XMSS_PK_SEED_BYTES);
        chain_prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_CHAIN;

        const int cpb = 8 / XMSS_COORD_RES_BITS; /* coords per byte = 4 */
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
        {
            unsigned char x[3][16];
            for (int k = 0; k < 3; k++)
                memcpy(x[k], shares[k] + W_SIG_OFF + i * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            /* coordinate bits c0,c1 (LSB-first) from mh share bytes */
            int byte_idx = i / cpb;
            int shift = (i % cpb) * XMSS_COORD_RES_BITS;
            uint32_t c0[3], c1[3];
            for (int k = 0; k < 3; k++)
            {
                unsigned char b = mh[k][byte_idx];
                c0[k] = (uint32_t)((b >> shift) & 1u);
                c1[k] = (uint32_t)((b >> (shift + 1)) & 1u);
            }

            /* predicates: sel(p) = (p > coord). p=1: NOR(c0,c1); p=2: ~c1; p=3: NAND(c0,c1) */
            uint32_t nc0[3], nc1[3], sel1[3], and3[3], sel3[3];
            mpc_NEGATE(c0, nc0);
            mpc_NEGATE(c1, nc1);
            mpc_AND(nc0, nc1, sel1, randomness, randCount, views, countY); /* sel for p=1 */
            uint32_t sel2[3];
            mpc_NEGATE(c1, sel2); /* sel for p=2 */
            mpc_AND(c0, c1, and3, randomness, randCount, views, countY);
            mpc_NEGATE(and3, sel3); /* sel for p=3 */

            uint32_t *sels[3] = {sel1, sel2, sel3};
            for (int stage = 0; stage < XMSS_WOTS_MAX_STEPS; stage++)
            {
                int p = stage + 1;
                unsigned char h[3][16], *secp[3], *outp[3];
                unsigned char suffix[2] = {(unsigned char)i, (unsigned char)p};
                for (int k = 0; k < 3; k++)
                {
                    secp[k] = x[k];
                    outp[k] = h[k];
                }
                mpc_thash(views, randomness, countY, randCount, chain_prefix, XMSS_PK_SEED_BYTES + 1, secp,
                          XMSS_NODE_BYTES, suffix, 2, outp, 16);

                uint32_t mask[3];
                mask_from_bit(sels[stage], mask);
                mpc_mux16(x, h, mask, randomness, randCount, views, countY);
            }
            for (int k = 0; k < 3; k++)
                memcpy(pkh[k] + i * XMSS_NODE_BYTES, x[k], XMSS_NODE_BYTES);
        }
    }

    /* =================== (4) leaf = SHA256(pk_seed ‖ 0x01 ‖ pk_hashes) =================== */
    unsigned char node[3][16];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_TREE;
        unsigned char *sec[3], *out[3];
        for (int k = 0; k < 3; k++)
        {
            sec[k] = pkh[k];
            out[k] = node[k];
        }
        mpc_thash(views, randomness, countY, randCount, prefix, XMSS_PK_SEED_BYTES + 1, sec,
                  XMSS_WOTS_LEN * XMSS_NODE_BYTES, NULL, 0, out, 16);
    }

    /* =================== (5) XMSS auth-path walk → root =================== */
    {
        uint32_t li[3];
        for (int k = 0; k < 3; k++)
        {
            const unsigned char *b = shares[k] + W_LEAFIDX_OFF;
            li[k] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
        }

        for (int level = 0; level < XMSS_H; level++)
        {
            /* sibling = auth_path[level] (secret) */
            unsigned char sib[3][16];
            for (int k = 0; k < 3; k++)
                memcpy(sib[k], shares[k] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            /* routing bit = (leaf_index >> level) & 1 ; ordering mux selects sibling when bit==1 */
            uint32_t bitw[3], mask[3];
            for (int k = 0; k < 3; k++)
                bitw[k] = (li[k] >> level) & 1u;
            mask_from_bit(bitw, mask);

            unsigned char left[3][16], right[3][16];
            for (int w = 0; w < 4; w++)
            {
                uint32_t nd[3], sb[3], t[3], mt[3], lw[3], rw[3];
                for (int k = 0; k < 3; k++)
                {
                    memcpy(&nd[k], node[k] + w * 4, 4);
                    memcpy(&sb[k], sib[k] + w * 4, 4);
                }
                mpc_XOR(nd, sb, t);
                mpc_AND((uint32_t *)mask, t, mt, randomness, randCount, views, countY);
                mpc_XOR(nd, mt, lw); /* left  = bit ? sib : node */
                mpc_XOR(sb, mt, rw); /* right = bit ? node : sib */
                for (int k = 0; k < 3; k++)
                {
                    memcpy(left[k] + w * 4, &lw[k], 4);
                    memcpy(right[k] + w * 4, &rw[k], 4);
                }
            }

            /* tree-node tweak: index = (leaf_index >> (level+1)) & 0xFFFF, secret, 2 LE bytes */
            unsigned char prefix[XMSS_PK_SEED_BYTES + 2];
            memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
            prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_TREE;
            prefix[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            unsigned char secbuf[3][2 + 16 + 16];
            unsigned char *sec[3], *out[3];
            for (int k = 0; k < 3; k++)
            {
                uint32_t idx = (li[k] >> (level + 1)) & 0xFFFFu;
                secbuf[k][0] = (unsigned char)(idx & 0xFF);
                secbuf[k][1] = (unsigned char)((idx >> 8) & 0xFF);
                memcpy(secbuf[k] + 2, left[k], 16);
                memcpy(secbuf[k] + 2 + 16, right[k], 16);
                sec[k] = secbuf[k];
                out[k] = node[k];
            }
            mpc_thash(views, randomness, countY, randCount, prefix, XMSS_PK_SEED_BYTES + 2, sec, 2 + 16 + 16, NULL,
                      0, out, 16);
        }
    }

    /* =================== (6) codeword target sum =================== */
    uint32_t acc[3] = {0, 0, 0};
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        const uint32_t cmask = (1u << XMSS_COORD_RES_BITS) - 1u;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
        {
            int byte_idx = i / cpb;
            int shift = (i % cpb) * XMSS_COORD_RES_BITS;
            uint32_t coord[3];
            for (int k = 0; k < 3; k++)
                coord[k] = (uint32_t)((mh[k][byte_idx] >> shift) & cmask);
            mpc_ADD(acc, coord, acc, randomness, randCount, views, countY);
        }
    }

    /* =================== output: root (words 0..3) | sum (word 4) | 0 =================== */
    for (int k = 0; k < 3; k++)
    {
        for (int w = 0; w < YP_ROOT_WORDS; w++)
            memcpy(&a->yp[k][w], node[k] + w * 4, 4);
        a->yp[k][YP_SUM_WORD] = acc[k];
        for (int w = YP_SUM_WORD + 1; w < 8; w++)
            a->yp[k][w] = 0;
    }

    g_circuit_gates = *countY;
    free(countY);
    free(randCount);
}

/* ────────────────────────────── verify-side helpers ─────────────────────────── */

/* Mirror of mpc_thash on the two opened parties.  Public prefix/suffix bytes are
 * placed into an opened party's input only when that party is party 0 (opened[j]==0),
 * exactly as the prover put them into party 0 alone. */
static void mpc_thash_verify(View ve, View ve1, unsigned char *randomness[2], int *countY, int *randCount,
                             const int opened[2], const unsigned char *prefix, int prefix_len, unsigned char *sec[2],
                             int sec_len, const unsigned char *suffix, int suffix_len, unsigned char *out[2],
                             int out_len)
{
    int total = prefix_len + sec_len + suffix_len;
    unsigned char *inp[2], *res[2];
    for (int j = 0; j < 2; j++)
    {
        inp[j] = calloc(total, 1);
        res[j] = malloc(32);
        memcpy(inp[j] + prefix_len, sec[j], sec_len);
        if (opened[j] == 0)
        {
            if (prefix_len)
                memcpy(inp[j], prefix, prefix_len);
            if (suffix_len)
                memcpy(inp[j] + prefix_len + sec_len, suffix, suffix_len);
        }
    }
    mpc_sha256_verify(inp, total * 8, res, randCount, countY, randomness, ve, ve1);
    for (int j = 0; j < 2; j++)
    {
        memcpy(out[j], res[j], out_len);
        free(inp[j]);
        free(res[j]);
    }
}

static void mpc_mux16_verify(unsigned char x[2][16], unsigned char h[2][16], const uint32_t mask[2], View ve,
                             View ve1, unsigned char *randomness[2], int *randCount, int *countY)
{
    for (int w = 0; w < 4; w++)
    {
        uint32_t xt[2], ht[2], t[2], mt[2];
        for (int j = 0; j < 2; j++)
        {
            memcpy(&xt[j], x[j] + w * 4, 4);
            memcpy(&ht[j], h[j] + w * 4, 4);
        }
        mpc_XOR2(xt, ht, t);
        mpc_AND_verify((uint32_t *)mask, t, mt, ve, ve1, randomness, randCount, countY);
        mpc_XOR2(xt, mt, xt);
        for (int j = 0; j < 2; j++)
            memcpy(x[j] + w * 4, &xt[j], 4);
    }
}

/* Mirror of mpc_gf128_mul on the two opened parties. */
static void mpc_gf128_mul_verify(const uint32_t X[2][4], const uint32_t Y[2][4], uint32_t out[2][4], View ve,
                                 View ve1, unsigned char *randomness[2], int *randCount, int *countY)
{
    uint32_t acc[2][8] = {{0}};
    for (int j = 0; j < 128; j++)
    {
        uint32_t mask[2];
        for (int t = 0; t < 2; t++)
            mask[t] = 0u - ((Y[t][j >> 5] >> (j & 31)) & 1u);
        for (int w = 0; w < 4; w++)
        {
            uint32_t xw[2] = {X[0][w], X[1][w]};
            uint32_t mw[2];
            mpc_AND_verify(mask, xw, mw, ve, ve1, randomness, randCount, countY);
            for (int t = 0; t < 2; t++)
                gf128_word_shift_xor(acc[t], mw[t], 32 * w + j);
        }
    }
    for (int t = 0; t < 2; t++)
        gf128_reduce(acc[t], out[t]);
}

/* ──────────────────────────────────── verify ─────────────────────────────────── */

void verify(unsigned char message_digest[32], unsigned char pk_seed[XMSS_PK_SEED_BYTES], bool *error, a *a, int e,
            z *z)
{
    const int opened[2] = {e, (e + 1) % 3};
    unsigned char hash[SHA256_DIGEST_LENGTH];

    /* commitment-opening check for the partner view (e+1) */
    H_com(z->ke1, &z->ve1, z->re1, hash);
    if (memcmp(a->h[(e + 1) % 3], hash, 32) != 0)
    {
        *error = true;
        return;
    }

    unsigned char *randomness[2];
    randomness[0] = malloc(Random_Bytes_Needed);
    randomness[1] = malloc(Random_Bytes_Needed);
    getAllRandomness(z->ke, randomness[0]);
    getAllRandomness(z->ke1, randomness[1]);

    int *randCount = calloc(1, sizeof(int));
    int *countY = calloc(1, sizeof(int));

    View ve = z->ve, ve1 = z->ve1;
    unsigned char *vx[2] = {z->ve.x, z->ve1.x};

    /* =================== (1) Halevi–Micali commitment → digest d =================== */
    unsigned char dsh[2][32];
    {
        /* (1a) y = SHA256(r_1 ‖ … ‖ r_6) — hashes the n=6 nonces only */
        unsigned char ysh[2][32];
        {
            unsigned char *sec[2], *out[2];
            for (int j = 0; j < 2; j++)
            {
                sec[j] = vx[j] + W_R_OFF;
                out[j] = ysh[j];
            }
            mpc_thash_verify(ve, ve1, randomness, countY, randCount, opened, NULL, 0, sec, HM_R_BYTES, NULL, 0, out,
                             32);
        }

        /* (1b) two affine lines b_k = m̂_k + Σ_i a_{k,i}·r_i over GF(2^128) */
        unsigned char bsh[2][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++)
        {
            uint32_t acc[2][4] = {{0}};
            for (int i = 0; i < HM_NONCES; i++)
            {
                uint32_t A[2][4], R[2][4], P[2][4];
                for (int j = 0; j < 2; j++)
                {
                    gf128_load(A[j], vx[j] + W_A_OFF + (line * HM_NONCES + i) * HM_ELT);
                    gf128_load(R[j], vx[j] + W_R_OFF + i * HM_ELT);
                }
                mpc_gf128_mul_verify(A, R, P, ve, ve1, randomness, randCount, countY);
                for (int j = 0; j < 2; j++)
                    for (int w = 0; w < 4; w++)
                        acc[j][w] ^= P[j][w];
            }
            /* + m̂_line (public): XOR into the opened party that is party 0 (if any) */
            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            for (int j = 0; j < 2; j++)
                if (opened[j] == 0)
                    for (int w = 0; w < 4; w++)
                        acc[j][w] ^= Mk[w];
            for (int j = 0; j < 2; j++)
                gf128_store(bsh[j] + line * HM_ELT, acc[j]);
        }

        /* (1c) certified digest d = SHA256(a ‖ b ‖ y) — a,b,y all secret */
        unsigned char secbuf[2][HM_COM_BYTES];
        unsigned char *sec[2], *out[2];
        for (int j = 0; j < 2; j++)
        {
            memcpy(secbuf[j], vx[j] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES, bsh[j], HM_B_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES + HM_B_BYTES, ysh[j], HM_Y_BYTES);
            sec[j] = secbuf[j];
            out[j] = dsh[j];
        }
        mpc_thash_verify(ve, ve1, randomness, countY, randCount, opened, NULL, 0, sec, HM_COM_BYTES, NULL, 0, out,
                         32);
    }

    /* =========== (2) message hash mh = SHA256(pk_seed ‖ 0x02 ‖ nonce ‖ d) =========== */
    unsigned char mh[2][32];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        unsigned char secbuf[2][XMSS_NONCE_LEN + 32];
        unsigned char *sec[2], *out[2];
        for (int j = 0; j < 2; j++)
        {
            memcpy(secbuf[j], vx[j] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[j] + XMSS_NONCE_LEN, dsh[j], 32);
            sec[j] = secbuf[j];
            out[j] = mh[j];
        }
        mpc_thash_verify(ve, ve1, randomness, countY, randCount, opened, prefix, XMSS_PK_SEED_BYTES + 1, sec,
                         XMSS_NONCE_LEN + 32, NULL, 0, out, 32);
    }

    /* =================== (3) WOTS+ chains → pk_hashes =================== */
    unsigned char pkh[2][XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    {
        unsigned char chain_prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(chain_prefix, pk_seed, XMSS_PK_SEED_BYTES);
        chain_prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_CHAIN;

        const int cpb = 8 / XMSS_COORD_RES_BITS;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
        {
            unsigned char x[2][16];
            for (int j = 0; j < 2; j++)
                memcpy(x[j], vx[j] + W_SIG_OFF + i * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            int byte_idx = i / cpb;
            int shift = (i % cpb) * XMSS_COORD_RES_BITS;
            uint32_t c0[2], c1[2];
            for (int j = 0; j < 2; j++)
            {
                unsigned char b = mh[j][byte_idx];
                c0[j] = (uint32_t)((b >> shift) & 1u);
                c1[j] = (uint32_t)((b >> (shift + 1)) & 1u);
            }

            uint32_t nc0[2], nc1[2], sel1[2], sel2[2], and3[2], sel3[2];
            mpc_NEGATE2(c0, nc0);
            mpc_NEGATE2(c1, nc1);
            mpc_AND_verify(nc0, nc1, sel1, ve, ve1, randomness, randCount, countY);
            mpc_NEGATE2(c1, sel2);
            mpc_AND_verify(c0, c1, and3, ve, ve1, randomness, randCount, countY);
            mpc_NEGATE2(and3, sel3);

            uint32_t *sels[3] = {sel1, sel2, sel3};
            for (int stage = 0; stage < XMSS_WOTS_MAX_STEPS; stage++)
            {
                int p = stage + 1;
                unsigned char h[2][16], *secp[2], *outp[2];
                unsigned char suffix[2] = {(unsigned char)i, (unsigned char)p};
                for (int j = 0; j < 2; j++)
                {
                    secp[j] = x[j];
                    outp[j] = h[j];
                }
                mpc_thash_verify(ve, ve1, randomness, countY, randCount, opened, chain_prefix,
                                 XMSS_PK_SEED_BYTES + 1, secp, XMSS_NODE_BYTES, suffix, 2, outp, 16);

                uint32_t mask[2];
                for (int j = 0; j < 2; j++)
                    mask[j] = 0u - (sels[stage][j] & 1u);
                mpc_mux16_verify(x, h, mask, ve, ve1, randomness, randCount, countY);
            }
            for (int j = 0; j < 2; j++)
                memcpy(pkh[j] + i * XMSS_NODE_BYTES, x[j], XMSS_NODE_BYTES);
        }
    }

    /* =================== (4) leaf = SHA256(pk_seed ‖ 0x01 ‖ pk_hashes) =================== */
    unsigned char node[2][16];
    {
        unsigned char prefix[XMSS_PK_SEED_BYTES + 1];
        memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
        prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_TREE;
        unsigned char *sec[2], *out[2];
        for (int j = 0; j < 2; j++)
        {
            sec[j] = pkh[j];
            out[j] = node[j];
        }
        mpc_thash_verify(ve, ve1, randomness, countY, randCount, opened, prefix, XMSS_PK_SEED_BYTES + 1, sec,
                         XMSS_WOTS_LEN * XMSS_NODE_BYTES, NULL, 0, out, 16);
    }

    /* =================== (5) XMSS auth-path walk → root =================== */
    {
        uint32_t li[2];
        for (int j = 0; j < 2; j++)
        {
            const unsigned char *b = vx[j] + W_LEAFIDX_OFF;
            li[j] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
        }

        for (int level = 0; level < XMSS_H; level++)
        {
            unsigned char sib[2][16];
            for (int j = 0; j < 2; j++)
                memcpy(sib[j], vx[j] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            uint32_t mask[2];
            for (int j = 0; j < 2; j++)
                mask[j] = 0u - ((li[j] >> level) & 1u);

            unsigned char left[2][16], right[2][16];
            for (int w = 0; w < 4; w++)
            {
                uint32_t nd[2], sb[2], t[2], mt[2], lw[2], rw[2];
                for (int j = 0; j < 2; j++)
                {
                    memcpy(&nd[j], node[j] + w * 4, 4);
                    memcpy(&sb[j], sib[j] + w * 4, 4);
                }
                mpc_XOR2(nd, sb, t);
                mpc_AND_verify((uint32_t *)mask, t, mt, ve, ve1, randomness, randCount, countY);
                mpc_XOR2(nd, mt, lw);
                mpc_XOR2(sb, mt, rw);
                for (int j = 0; j < 2; j++)
                {
                    memcpy(left[j] + w * 4, &lw[j], 4);
                    memcpy(right[j] + w * 4, &rw[j], 4);
                }
            }

            unsigned char prefix[XMSS_PK_SEED_BYTES + 2];
            memcpy(prefix, pk_seed, XMSS_PK_SEED_BYTES);
            prefix[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_TREE;
            prefix[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            unsigned char secbuf[2][2 + 16 + 16];
            unsigned char *sec[2], *out[2];
            for (int j = 0; j < 2; j++)
            {
                uint32_t idx = (li[j] >> (level + 1)) & 0xFFFFu;
                secbuf[j][0] = (unsigned char)(idx & 0xFF);
                secbuf[j][1] = (unsigned char)((idx >> 8) & 0xFF);
                memcpy(secbuf[j] + 2, left[j], 16);
                memcpy(secbuf[j] + 2 + 16, right[j], 16);
                sec[j] = secbuf[j];
                out[j] = node[j];
            }
            mpc_thash_verify(ve, ve1, randomness, countY, randCount, opened, prefix, XMSS_PK_SEED_BYTES + 2, sec,
                             2 + 16 + 16, NULL, 0, out, 16);
        }
    }

    /* =================== (6) codeword target sum =================== */
    uint32_t acc[2] = {0, 0};
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        const uint32_t cmask = (1u << XMSS_COORD_RES_BITS) - 1u;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
        {
            int byte_idx = i / cpb;
            int shift = (i % cpb) * XMSS_COORD_RES_BITS;
            uint32_t coord[2];
            for (int j = 0; j < 2; j++)
                coord[j] = (uint32_t)((mh[j][byte_idx] >> shift) & cmask);
            mpc_ADD_verify(acc, coord, acc, ve, ve1, randomness, randCount, countY);
        }
    }

    /* =================== compare announced outputs =================== */
    for (int j = 0; j < 2; j++)
    {
        for (int w = 0; w < YP_ROOT_WORDS; w++)
        {
            uint32_t v;
            memcpy(&v, node[j] + w * 4, 4);
            if (v != a->yp[opened[j]][w])
                *error = true;
        }
        if (acc[j] != a->yp[opened[j]][YP_SUM_WORD])
            *error = true;
    }

    /* commitment-opening check for the reconstructed view e */
    H_com(z->ke, &z->ve, z->re, hash);
    if (memcmp(a->h[e], hash, 32) != 0)
        *error = true;

    free(randomness[0]);
    free(randomness[1]);
    free(randCount);
    free(countY);
}
