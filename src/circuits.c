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

/* Fixed Th domains for the HM commitment hashes (must match commitment.c). */
static const unsigned char HM_DOM_Y[3] = {'H', 'M', 'y'};
static const unsigned char HM_DOM_D[3] = {'H', 'M', 'd'};

/* ── Prove-side helpers ─────────────────────────────────────────────────── */

/* Broadcast a masked selector bit to a full-word mask wire (value ±sel). */
static void mask_from_bit(const mw *sel, mw *mask)
{
    mask->h = 0u - (sel->h & 1u);
    for (int i = 0; i < N_PARTIES; i++) mask->l[i] = 0u - (sel->l[i] & 1u);
}

/* x[16] ← sel ? h : x, word-wise.  One AND per 32-bit word. */
static void mpc_mux16(
    unsigned char x_pub[16], unsigned char x_lam[N_PARTIES][16],
    const unsigned char h_pub[16], unsigned char h_lam[N_PARTIES][16],
    const mw *mask,
    unsigned char *tapes[N_PARTIES], uint32_t *aux, uint32_t *s_all, int *gc)
{
    for (int w = 0; w < 4; w++) {
        mw xt, ht, t, mt;
        memcpy(&xt.h, x_pub + w*4, 4);
        memcpy(&ht.h, h_pub + w*4, 4);
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(&xt.l[i], x_lam[i] + w*4, 4);
            memcpy(&ht.l[i], h_lam[i] + w*4, 4);
        }
        mpc_XOR(&xt, &ht, &t);
        mpc_AND(mask, &t, &mt, tapes, aux, s_all, gc);
        mpc_XOR(&xt, &mt, &xt);
        memcpy(x_pub + w*4, &xt.h, 4);
        for (int i = 0; i < N_PARTIES; i++) memcpy(x_lam[i] + w*4, &xt.l[i], 4);
    }
}

/* GF(2^128) multiply on masked words. */
static void mpc_gf128_mul(
    const mw X[4], const mw Y[4], mw out[4],
    unsigned char *tapes[N_PARTIES], uint32_t *aux, uint32_t *s_all, int *gc)
{
    uint32_t acc_pub[8];
    uint32_t acc_lam[N_PARTIES][8];
    memset(acc_pub, 0, sizeof(acc_pub));
    memset(acc_lam, 0, sizeof(acc_lam));
    for (int j = 0; j < 128; j++) {
        mw mask;
        mask.h = 0u - ((Y[j >> 5].h >> (j & 31)) & 1u);
        for (int i = 0; i < N_PARTIES; i++)
            mask.l[i] = 0u - ((Y[j >> 5].l[i] >> (j & 31)) & 1u);
        for (int w = 0; w < 4; w++) {
            mw mwout;
            mpc_AND(&mask, &X[w], &mwout, tapes, aux, s_all, gc);
            gf128_word_shift_xor(acc_pub, mwout.h, 32 * w + j);
            for (int i = 0; i < N_PARTIES; i++)
                gf128_word_shift_xor(acc_lam[i], mwout.l[i], 32 * w + j);
        }
    }
    uint32_t red[4];
    gf128_reduce(acc_pub, red);
    for (int w = 0; w < 4; w++) out[w].h = red[w];
    for (int i = 0; i < N_PARTIES; i++) {
        gf128_reduce(acc_lam[i], red);
        for (int w = 0; w < 4; w++) out[w].l[i] = red[w];
    }
}

/* ── building_views ─────────────────────────────────────────────────────── */

void building_views(
    a *a, const unsigned char message_digest[32],
    const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
    const unsigned char *d_pub,
    unsigned char *lam[N_PARTIES],
    unsigned char *tapes[N_PARTIES],
    uint32_t *aux, uint32_t *s_all,
    const unsigned char *r_j, uint32_t zh_out[8])
{
    int gc = 0;

    /* ── (1) Halevi–Micali commitment → certified digest d ── */
    unsigned char dsh_pub[32], dsh_lam_buf[N_PARTIES][32];
    unsigned char *dsh_lam[N_PARTIES];
    for (int i = 0; i < N_PARTIES; i++) dsh_lam[i] = dsh_lam_buf[i];
    {
        /* (1a) y = SHA256(r_1 ‖ … ‖ r_6) */
        unsigned char ysh_pub[32], ysh_lam_buf[N_PARTIES][32];
        unsigned char *ysh_lam[N_PARTIES], *sec_lam[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++) {
            ysh_lam[i] = ysh_lam_buf[i];
            sec_lam[i] = lam[i] + W_R_OFF;
        }
        mpc_blake3_th(HM_DOM_Y, NULL, 3,
                      d_pub + W_R_OFF, sec_lam, HM_R_BYTES,
                      ysh_pub, ysh_lam, 32, tapes, aux, s_all, &gc);

        /* (1b) b_k = m̂_k + Σ_i a_{k,i}·r_i over GF(2^128) */
        unsigned char bsh_pub[HM_B_BYTES], bsh_lam[N_PARTIES][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++) {
            mw acc[4];
            for (int w = 0; w < 4; w++) mw_const(0, &acc[w]);
            for (int idx = 0; idx < HM_NONCES; idx++) {
                mw A[4], R[4], P[4];
                uint32_t tmp4[4];
                gf128_load(tmp4, d_pub + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                for (int w = 0; w < 4; w++) A[w].h = tmp4[w];
                gf128_load(tmp4, d_pub + W_R_OFF + idx * HM_ELT);
                for (int w = 0; w < 4; w++) R[w].h = tmp4[w];
                for (int i = 0; i < N_PARTIES; i++) {
                    gf128_load(tmp4, lam[i] + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                    for (int w = 0; w < 4; w++) A[w].l[i] = tmp4[w];
                    gf128_load(tmp4, lam[i] + W_R_OFF + idx * HM_ELT);
                    for (int w = 0; w < 4; w++) R[w].l[i] = tmp4[w];
                }
                mpc_gf128_mul(A, R, P, tapes, aux, s_all, &gc);
                for (int w = 0; w < 4; w++) mpc_XOR(&acc[w], &P[w], &acc[w]);
            }
            /* Public m̂_line adds to the public part only. */
            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            for (int w = 0; w < 4; w++) acc[w].h ^= Mk[w];
            uint32_t tmp4[4];
            for (int w = 0; w < 4; w++) tmp4[w] = acc[w].h;
            gf128_store(bsh_pub + line * HM_ELT, tmp4);
            for (int i = 0; i < N_PARTIES; i++) {
                for (int w = 0; w < 4; w++) tmp4[w] = acc[w].l[i];
                gf128_store(bsh_lam[i] + line * HM_ELT, tmp4);
            }
        }

        /* (1c) d = Th("HMd", a ‖ b ‖ y) */
        unsigned char sec_pub[HM_COM_BYTES], secbuf[N_PARTIES][HM_COM_BYTES];
        unsigned char *sec_lam2[N_PARTIES];
        memcpy(sec_pub, d_pub + W_A_OFF, HM_A_BYTES);
        memcpy(sec_pub + HM_A_BYTES, bsh_pub, HM_B_BYTES);
        memcpy(sec_pub + HM_A_BYTES + HM_B_BYTES, ysh_pub, HM_Y_BYTES);
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(secbuf[i], lam[i] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[i] + HM_A_BYTES, bsh_lam[i], HM_B_BYTES);
            memcpy(secbuf[i] + HM_A_BYTES + HM_B_BYTES, ysh_lam_buf[i], HM_Y_BYTES);
            sec_lam2[i] = secbuf[i];
        }
        mpc_blake3_th(HM_DOM_D, NULL, 3, sec_pub, sec_lam2, HM_COM_BYTES,
                      dsh_pub, dsh_lam, 32, tapes, aux, s_all, &gc);
    }

    /* ── (2) mh = Th(pk_seed ‖ 0x02 ‖ epoch, nonce ‖ d) ── */
    unsigned char mh_pub[32], mh_lam[N_PARTIES][32];
    {
        /* Domain: pk_seed and the tweak are public, epoch is masked. */
        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int i = 0; i < N_PARTIES; i++) {
            memset(dombuf[i], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[i] + XMSS_PK_SEED_BYTES + 1, lam[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[i] = dombuf[i];
        }
        const int slen = XMSS_NONCE_LEN + 32;
        unsigned char sec_pub[XMSS_NONCE_LEN + 32];
        unsigned char secbuf[N_PARTIES][XMSS_NONCE_LEN + 32];
        unsigned char *sec_lam[N_PARTIES], *out_lam[N_PARTIES];
        memcpy(sec_pub, d_pub + W_NONCE_OFF, XMSS_NONCE_LEN);
        memcpy(sec_pub + XMSS_NONCE_LEN, dsh_pub, 32);
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(secbuf[i], lam[i] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[i] + XMSS_NONCE_LEN, dsh_lam_buf[i], 32);
            sec_lam[i] = secbuf[i]; out_lam[i] = mh_lam[i];
        }
        mpc_blake3_th(dom_pub, dom_lam, dlen, sec_pub, sec_lam, slen,
                      mh_pub, out_lam, 32, tapes, aux, s_all, &gc);
    }

    /* ── (3) WOTS+ chains → pk_hashes ── */
    unsigned char pkh_pub[XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    unsigned char pkh_lam[N_PARTIES][XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;

        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            unsigned char x_pub[16], x_lam[N_PARTIES][16];
            memcpy(x_pub, d_pub + W_SIG_OFF + ci * XMSS_NODE_BYTES, XMSS_NODE_BYTES);
            for (int i = 0; i < N_PARTIES; i++)
                memcpy(x_lam[i], lam[i] + W_SIG_OFF + ci * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            int byte_idx = ci / cpb;
            int shift = (ci % cpb) * XMSS_COORD_RES_BITS;
            mw c0;
            c0.h = (uint32_t)((mh_pub[byte_idx] >> shift) & 1u);
            for (int i = 0; i < N_PARTIES; i++)
                c0.l[i] = (uint32_t)((mh_lam[i][byte_idx] >> shift) & 1u);

#if XMSS_WOTS_MAX_STEPS == 1
            mw nc0;
            mpc_NEGATE(&c0, &nc0);
            mw *sels[1] = {&nc0};
#else
            mw c1;
            c1.h = (uint32_t)((mh_pub[byte_idx] >> (shift + 1)) & 1u);
            for (int i = 0; i < N_PARTIES; i++)
                c1.l[i] = (uint32_t)((mh_lam[i][byte_idx] >> (shift + 1)) & 1u);
            mw nc0, nc1, sel1, sel2, and3, sel3;
            mpc_NEGATE(&c0, &nc0); mpc_NEGATE(&c1, &nc1);
            mpc_AND(&nc0, &nc1, &sel1, tapes, aux, s_all, &gc);
            mpc_NEGATE(&c1, &sel2);
            mpc_AND(&c0, &c1, &and3, tapes, aux, s_all, &gc);
            mpc_NEGATE(&and3, &sel3);
            mw *sels[3] = {&sel1, &sel2, &sel3};
#endif
            for (int stage = 0; stage < XMSS_WOTS_MAX_STEPS; stage++) {
                unsigned char h_pub[16], h_lam[N_PARTIES][16];
                /* Th chain step: dom = current node, data = the tweak block
                 * pk_seed ‖ 0x00 ‖ epoch ‖ chain ‖ pos (epoch masked). */
                const int tlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES + 2;
                unsigned char tw_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES + 2];
                unsigned char twbuf[N_PARTIES][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES + 2];
                unsigned char *tw_lam[N_PARTIES], *domp[N_PARTIES], *outp[N_PARTIES];
                memcpy(tw_pub, pk_seed, XMSS_PK_SEED_BYTES);
                tw_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_CHAIN;
                memcpy(tw_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
                tw_pub[tlen - 2] = (unsigned char)ci;
                tw_pub[tlen - 1] = (unsigned char)(stage + 1);
                for (int i = 0; i < N_PARTIES; i++) {
                    memset(twbuf[i], 0, tlen);
                    memcpy(twbuf[i] + XMSS_PK_SEED_BYTES + 1, lam[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
                    tw_lam[i] = twbuf[i]; domp[i] = x_lam[i]; outp[i] = h_lam[i];
                }
                mpc_blake3_th(x_pub, domp, XMSS_NODE_BYTES, tw_pub, tw_lam, tlen,
                              h_pub, outp, 16, tapes, aux, s_all, &gc);
                mw mask;
                mask_from_bit(sels[stage], &mask);
                mpc_mux16(x_pub, x_lam, h_pub, h_lam, &mask, tapes, aux, s_all, &gc);
            }
            memcpy(pkh_pub + ci * XMSS_NODE_BYTES, x_pub, XMSS_NODE_BYTES);
            for (int i = 0; i < N_PARTIES; i++)
                memcpy(pkh_lam[i] + ci * XMSS_NODE_BYTES, x_lam[i], XMSS_NODE_BYTES);
        }
    }

    /* ── (4) leaf = Th(pk_seed ‖ 0x03 ‖ epoch, pk_hashes) ── */
    unsigned char node_pub[16], node_lam[N_PARTIES][16];
    {
        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES], *sec_lam[N_PARTIES], *out_lam[N_PARTIES];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_LEAF;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int i = 0; i < N_PARTIES; i++) {
            memset(dombuf[i], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[i] + XMSS_PK_SEED_BYTES + 1, lam[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[i] = dombuf[i]; sec_lam[i] = pkh_lam[i]; out_lam[i] = node_lam[i];
        }
        mpc_blake3_th(dom_pub, dom_lam, dlen,
                      pkh_pub, sec_lam, XMSS_WOTS_LEN * XMSS_NODE_BYTES,
                      node_pub, out_lam, 16, tapes, aux, s_all, &gc);
    }

    /* ── (5) XMSS auth-path walk → root ── */
    {
        mw li;
        {
            const unsigned char *b = d_pub + W_LEAFIDX_OFF;
            li.h = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                 | ((uint32_t)b[2] <<  8) | (uint32_t)b[3];
            for (int i = 0; i < N_PARTIES; i++) {
                const unsigned char *bl = lam[i] + W_LEAFIDX_OFF;
                li.l[i] = ((uint32_t)bl[0] << 24) | ((uint32_t)bl[1] << 16)
                        | ((uint32_t)bl[2] <<  8) | (uint32_t)bl[3];
            }
        }
        for (int level = 0; level < XMSS_H; level++) {
            unsigned char sib_pub[16], sib_lam[N_PARTIES][16];
            memcpy(sib_pub, d_pub + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);
            for (int i = 0; i < N_PARTIES; i++)
                memcpy(sib_lam[i], lam[i] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            mw bitw, mask;
            bitw.h = (li.h >> level) & 1u;
            for (int i = 0; i < N_PARTIES; i++) bitw.l[i] = (li.l[i] >> level) & 1u;
            mask_from_bit(&bitw, &mask);

            unsigned char left_pub[16], right_pub[16];
            unsigned char left_lam[N_PARTIES][16], right_lam[N_PARTIES][16];
            for (int w = 0; w < 4; w++) {
                mw nd, sb, t, mt, lw, rw;
                memcpy(&nd.h, node_pub + w*4, 4);
                memcpy(&sb.h, sib_pub  + w*4, 4);
                for (int i = 0; i < N_PARTIES; i++) {
                    memcpy(&nd.l[i], node_lam[i] + w*4, 4);
                    memcpy(&sb.l[i], sib_lam[i]  + w*4, 4);
                }
                mpc_XOR(&nd, &sb, &t);
                mpc_AND(&mask, &t, &mt, tapes, aux, s_all, &gc);
                mpc_XOR(&nd, &mt, &lw);
                mpc_XOR(&sb, &mt, &rw);
                memcpy(left_pub  + w*4, &lw.h, 4);
                memcpy(right_pub + w*4, &rw.h, 4);
                for (int i = 0; i < N_PARTIES; i++) {
                    memcpy(left_lam[i]  + w*4, &lw.l[i], 4);
                    memcpy(right_lam[i] + w*4, &rw.l[i], 4);
                }
            }

            /* Th tree node: dom = pk_seed ‖ 0x01 ‖ level ‖ idx (idx masked),
             * data = left ‖ right. */
            const int dlen = XMSS_PK_SEED_BYTES + 2 + 2;
            unsigned char dom_pub[XMSS_PK_SEED_BYTES + 2 + 2];
            unsigned char dombuf[N_PARTIES][XMSS_PK_SEED_BYTES + 2 + 2];
            unsigned char sec_pub[16 + 16], secbuf[N_PARTIES][16 + 16];
            unsigned char *dom_lam[N_PARTIES], *sec_lam[N_PARTIES], *out_lam[N_PARTIES];
            memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
            dom_pub[XMSS_PK_SEED_BYTES]     = XMSS_TWEAK_TREE;
            dom_pub[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            {
                uint32_t idx = (li.h >> (level + 1)) & 0xFFFFu;
                dom_pub[dlen - 2] = (unsigned char)(idx & 0xFF);
                dom_pub[dlen - 1] = (unsigned char)((idx >> 8) & 0xFF);
            }
            memcpy(sec_pub,      left_pub,  16);
            memcpy(sec_pub + 16, right_pub, 16);
            for (int i = 0; i < N_PARTIES; i++) {
                uint32_t idx = (li.l[i] >> (level + 1)) & 0xFFFFu;
                memset(dombuf[i], 0, dlen - 2);
                dombuf[i][dlen - 2] = (unsigned char)(idx & 0xFF);
                dombuf[i][dlen - 1] = (unsigned char)((idx >> 8) & 0xFF);
                memcpy(secbuf[i],      left_lam[i],  16);
                memcpy(secbuf[i] + 16, right_lam[i], 16);
                dom_lam[i] = dombuf[i]; sec_lam[i] = secbuf[i]; out_lam[i] = node_lam[i];
            }
            mpc_blake3_th(dom_pub, dom_lam, dlen, sec_pub, sec_lam, 16 + 16,
                          node_pub, out_lam, 16, tapes, aux, s_all, &gc);
        }
    }

    /* ── (6) codeword target sum ── */
    mw acc;
    mw_const(0, &acc);
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        const uint32_t cmask = (1u << XMSS_COORD_RES_BITS) - 1u;
        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            int byte_idx = ci / cpb;
            int shift    = (ci % cpb) * XMSS_COORD_RES_BITS;
            mw coord;
            coord.h = (uint32_t)((mh_pub[byte_idx] >> shift) & cmask);
            for (int i = 0; i < N_PARTIES; i++)
                coord.l[i] = (uint32_t)((mh_lam[i][byte_idx] >> shift) & cmask);
            mpc_ADD(&acc, &coord, &acc, tapes, aux, s_all, &gc);
        }
    }

    /* ── Outputs: public masked words + per-party mask shares ── */
    for (int w = 0; w < YP_ROOT_WORDS; w++) {
        memcpy(&zh_out[w], node_pub + w*4, 4);
        for (int i = 0; i < N_PARTIES; i++)
            memcpy(&a->yp[i][w], node_lam[i] + w*4, 4);
    }
    zh_out[YP_SUM_WORD] = acc.h;
    for (int i = 0; i < N_PARTIES; i++) a->yp[i][YP_SUM_WORD] = acc.l[i];
    for (int w = YP_SUM_WORD + 1; w < 8; w++) {
        zh_out[w] = 0;
        for (int i = 0; i < N_PARTIES; i++) a->yp[i][w] = 0;
    }

    /* Record the gate count only when called standalone (test_circuit). */
    if (!omp_in_parallel()) g_circuit_gates = gc;

    /* h'_j = H(d || s_all || r_j): masked witness + all broadcast streams,
     * blinded by r_j, committed in h* before challenge derivation. */
    if (s_all) compute_h_prime(d_pub, s_all, r_j, a->h_prime);
}

/* ── Verify-side helpers ────────────────────────────────────────────────── */

static void mask_from_bit_v(const mwv *sel, mwv *mask)
{
    mask->h = 0u - (sel->h & 1u);
    for (int j = 0; j < N_PARTIES-1; j++) mask->l[j] = 0u - (sel->l[j] & 1u);
}

static void mpc_mux16_verify(
    unsigned char x_pub[16], unsigned char x_lam[N_PARTIES-1][16],
    const unsigned char h_pub[16], unsigned char h_lam[N_PARTIES-1][16],
    const mwv *mask,
    unsigned char *tapes[N_PARTIES-1], int e,
    const uint32_t *msgs_e, const uint32_t *aux,
    uint32_t *s_slots, int *gc)
{
    for (int w = 0; w < 4; w++) {
        mwv xt, ht, t, mt;
        memcpy(&xt.h, x_pub + w*4, 4);
        memcpy(&ht.h, h_pub + w*4, 4);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(&xt.l[j], x_lam[j] + w*4, 4);
            memcpy(&ht.l[j], h_lam[j] + w*4, 4);
        }
        mpc_XOR_v(&xt, &ht, &t);
        mpc_AND_verify(mask, &t, &mt, tapes, e, msgs_e, aux, s_slots, gc);
        mpc_XOR_v(&xt, &mt, &xt);
        memcpy(x_pub + w*4, &xt.h, 4);
        for (int j = 0; j < N_PARTIES-1; j++) memcpy(x_lam[j] + w*4, &xt.l[j], 4);
    }
}

static void mpc_gf128_mul_verify(
    const mwv X[4], const mwv Y[4], mwv out[4],
    unsigned char *tapes[N_PARTIES-1], int e,
    const uint32_t *msgs_e, const uint32_t *aux,
    uint32_t *s_slots, int *gc)
{
    uint32_t acc_pub[8];
    uint32_t acc_lam[N_PARTIES-1][8];
    memset(acc_pub, 0, sizeof(acc_pub));
    memset(acc_lam, 0, sizeof(acc_lam));
    for (int bit = 0; bit < 128; bit++) {
        mwv mask;
        mask.h = 0u - ((Y[bit >> 5].h >> (bit & 31)) & 1u);
        for (int j = 0; j < N_PARTIES-1; j++)
            mask.l[j] = 0u - ((Y[bit >> 5].l[j] >> (bit & 31)) & 1u);
        for (int w = 0; w < 4; w++) {
            mwv mwout;
            mpc_AND_verify(&mask, &X[w], &mwout, tapes, e, msgs_e, aux, s_slots, gc);
            gf128_word_shift_xor(acc_pub, mwout.h, 32 * w + bit);
            for (int j = 0; j < N_PARTIES-1; j++)
                gf128_word_shift_xor(acc_lam[j], mwout.l[j], 32 * w + bit);
        }
    }
    uint32_t red[4];
    gf128_reduce(acc_pub, red);
    for (int w = 0; w < 4; w++) out[w].h = red[w];
    for (int j = 0; j < N_PARTIES-1; j++) {
        gf128_reduce(acc_lam[j], red);
        for (int w = 0; w < 4; w++) out[w].l[j] = red[w];
    }
}

/* ── verify ─────────────────────────────────────────────────────────────── */

void verify(
    const unsigned char message_digest[32],
    const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
    bool *error, a *a_struct, int e, z *z_proof, uint32_t zh_out[8])
{
    /* Expand tapes and witness-mask shares for the N-1 revealed parties
     * (all seed-derived; the masked witness d itself is in the proof). */
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

    uint32_t *s_slots = malloc((size_t)(N_PARTIES-1) * ySize * sizeof(uint32_t));
    unsigned char *xbuf = malloc((size_t)(N_PARTIES-1) * INPUT_LEN);
    if (!s_slots || !xbuf) {
        free(s_slots); free(xbuf);
        for (int j = 0; j < N_PARTIES-1; j++) free(tapes[j]);
        *error = true; return;
    }
    unsigned char *vlam[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) {
        vlam[j] = xbuf + (size_t)j * INPUT_LEN;
        expand_xshare(z_proof->ke[j], vlam[j]);
    }
    const unsigned char *d_pub = z_proof->x_offset;

    int gc = 0;
    const uint32_t *msgs_e = z_proof->msgs_e;

    /* ── (1) Halevi–Micali commitment → d ── */
    unsigned char dsh_pub[32], dsh_lam_buf[N_PARTIES-1][32];
    unsigned char *dsh_lam[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) dsh_lam[j] = dsh_lam_buf[j];
    {
        unsigned char ysh_pub[32], ysh_lam_buf[N_PARTIES-1][32];
        unsigned char *ysh_lam[N_PARTIES-1], *sec_lam[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            ysh_lam[j] = ysh_lam_buf[j];
            sec_lam[j] = vlam[j] + W_R_OFF;
        }
        mpc_blake3_th_verify(HM_DOM_Y, NULL, 3,
                             d_pub + W_R_OFF, sec_lam, HM_R_BYTES,
                             ysh_pub, ysh_lam, 32,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);

        unsigned char bsh_pub[HM_B_BYTES], bsh_lam[N_PARTIES-1][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++) {
            mwv acc[4];
            for (int w = 0; w < 4; w++) mwv_const(0, &acc[w]);
            for (int idx = 0; idx < HM_NONCES; idx++) {
                mwv A[4], R[4], P[4];
                uint32_t tmp4[4];
                gf128_load(tmp4, d_pub + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                for (int w = 0; w < 4; w++) A[w].h = tmp4[w];
                gf128_load(tmp4, d_pub + W_R_OFF + idx * HM_ELT);
                for (int w = 0; w < 4; w++) R[w].h = tmp4[w];
                for (int j = 0; j < N_PARTIES-1; j++) {
                    gf128_load(tmp4, vlam[j] + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                    for (int w = 0; w < 4; w++) A[w].l[j] = tmp4[w];
                    gf128_load(tmp4, vlam[j] + W_R_OFF + idx * HM_ELT);
                    for (int w = 0; w < 4; w++) R[w].l[j] = tmp4[w];
                }
                mpc_gf128_mul_verify(A, R, P, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
                for (int w = 0; w < 4; w++) mpc_XOR_v(&acc[w], &P[w], &acc[w]);
            }
            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            for (int w = 0; w < 4; w++) acc[w].h ^= Mk[w];
            uint32_t tmp4[4];
            for (int w = 0; w < 4; w++) tmp4[w] = acc[w].h;
            gf128_store(bsh_pub + line * HM_ELT, tmp4);
            for (int j = 0; j < N_PARTIES-1; j++) {
                for (int w = 0; w < 4; w++) tmp4[w] = acc[w].l[j];
                gf128_store(bsh_lam[j] + line * HM_ELT, tmp4);
            }
        }

        unsigned char sec_pub[HM_COM_BYTES], secbuf[N_PARTIES-1][HM_COM_BYTES];
        unsigned char *sec_lam2[N_PARTIES-1];
        memcpy(sec_pub, d_pub + W_A_OFF, HM_A_BYTES);
        memcpy(sec_pub + HM_A_BYTES, bsh_pub, HM_B_BYTES);
        memcpy(sec_pub + HM_A_BYTES + HM_B_BYTES, ysh_pub, HM_Y_BYTES);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(secbuf[j], vlam[j] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES, bsh_lam[j], HM_B_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES + HM_B_BYTES, ysh_lam_buf[j], HM_Y_BYTES);
            sec_lam2[j] = secbuf[j];
        }
        mpc_blake3_th_verify(HM_DOM_D, NULL, 3, sec_pub, sec_lam2, HM_COM_BYTES,
                             dsh_pub, dsh_lam, 32,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
    }

    /* ── (2) mh ── */
    unsigned char mh_pub[32], mh_lam[N_PARTIES-1][32];
    {
        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES-1][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES-1];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memset(dombuf[j], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[j] + XMSS_PK_SEED_BYTES + 1, vlam[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[j] = dombuf[j];
        }
        const int slen = XMSS_NONCE_LEN + 32;
        unsigned char sec_pub[XMSS_NONCE_LEN + 32];
        unsigned char secbuf[N_PARTIES-1][XMSS_NONCE_LEN + 32];
        unsigned char *sec_lam[N_PARTIES-1], *out_lam[N_PARTIES-1];
        memcpy(sec_pub, d_pub + W_NONCE_OFF, XMSS_NONCE_LEN);
        memcpy(sec_pub + XMSS_NONCE_LEN, dsh_pub, 32);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(secbuf[j], vlam[j] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[j] + XMSS_NONCE_LEN, dsh_lam_buf[j], 32);
            sec_lam[j] = secbuf[j]; out_lam[j] = mh_lam[j];
        }
        mpc_blake3_th_verify(dom_pub, dom_lam, dlen, sec_pub, sec_lam, slen,
                             mh_pub, out_lam, 32,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
    }

    /* ── (3) WOTS+ chains ── */
    unsigned char pkh_pub[XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    unsigned char pkh_lam[N_PARTIES-1][XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;

        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            unsigned char x_pub[16], x_lam[N_PARTIES-1][16];
            memcpy(x_pub, d_pub + W_SIG_OFF + ci * XMSS_NODE_BYTES, XMSS_NODE_BYTES);
            for (int j = 0; j < N_PARTIES-1; j++)
                memcpy(x_lam[j], vlam[j] + W_SIG_OFF + ci * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            int byte_idx = ci / cpb;
            int shift = (ci % cpb) * XMSS_COORD_RES_BITS;
            mwv c0;
            c0.h = (uint32_t)((mh_pub[byte_idx] >> shift) & 1u);
            for (int j = 0; j < N_PARTIES-1; j++)
                c0.l[j] = (uint32_t)((mh_lam[j][byte_idx] >> shift) & 1u);

#if XMSS_WOTS_MAX_STEPS == 1
            mwv nc0;
            mpc_NEGATE_v(&c0, &nc0);
            mwv *sels[1] = {&nc0};
#else
            mwv c1;
            c1.h = (uint32_t)((mh_pub[byte_idx] >> (shift + 1)) & 1u);
            for (int j = 0; j < N_PARTIES-1; j++)
                c1.l[j] = (uint32_t)((mh_lam[j][byte_idx] >> (shift + 1)) & 1u);
            mwv nc0, nc1, sel1, sel2, and3, sel3;
            mpc_NEGATE_v(&c0, &nc0); mpc_NEGATE_v(&c1, &nc1);
            mpc_AND_verify(&nc0, &nc1, &sel1, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
            mpc_NEGATE_v(&c1, &sel2);
            mpc_AND_verify(&c0, &c1, &and3, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
            mpc_NEGATE_v(&and3, &sel3);
            mwv *sels[3] = {&sel1, &sel2, &sel3};
#endif
            for (int stage = 0; stage < XMSS_WOTS_MAX_STEPS; stage++) {
                unsigned char h_pub[16], h_lam[N_PARTIES-1][16];
                const int tlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES + 2;
                unsigned char tw_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES + 2];
                unsigned char twbuf[N_PARTIES-1][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES + 2];
                unsigned char *tw_lam[N_PARTIES-1], *domp[N_PARTIES-1], *outp[N_PARTIES-1];
                memcpy(tw_pub, pk_seed, XMSS_PK_SEED_BYTES);
                tw_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_CHAIN;
                memcpy(tw_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
                tw_pub[tlen - 2] = (unsigned char)ci;
                tw_pub[tlen - 1] = (unsigned char)(stage + 1);
                for (int j = 0; j < N_PARTIES-1; j++) {
                    memset(twbuf[j], 0, tlen);
                    memcpy(twbuf[j] + XMSS_PK_SEED_BYTES + 1, vlam[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
                    tw_lam[j] = twbuf[j]; domp[j] = x_lam[j]; outp[j] = h_lam[j];
                }
                mpc_blake3_th_verify(x_pub, domp, XMSS_NODE_BYTES, tw_pub, tw_lam, tlen,
                                     h_pub, outp, 16,
                                     tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
                mwv mask;
                mask_from_bit_v(sels[stage], &mask);
                mpc_mux16_verify(x_pub, x_lam, h_pub, h_lam, &mask,
                                 tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
            }
            memcpy(pkh_pub + ci * XMSS_NODE_BYTES, x_pub, XMSS_NODE_BYTES);
            for (int j = 0; j < N_PARTIES-1; j++)
                memcpy(pkh_lam[j] + ci * XMSS_NODE_BYTES, x_lam[j], XMSS_NODE_BYTES);
        }
    }

    /* ── (4) leaf hash ── */
    unsigned char node_pub[16], node_lam[N_PARTIES-1][16];
    {
        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES-1][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES-1], *sec_lam[N_PARTIES-1], *out_lam[N_PARTIES-1];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_LEAF;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memset(dombuf[j], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[j] + XMSS_PK_SEED_BYTES + 1, vlam[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[j] = dombuf[j]; sec_lam[j] = pkh_lam[j]; out_lam[j] = node_lam[j];
        }
        mpc_blake3_th_verify(dom_pub, dom_lam, dlen,
                             pkh_pub, sec_lam, XMSS_WOTS_LEN * XMSS_NODE_BYTES,
                             node_pub, out_lam, 16,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
    }

    /* ── (5) auth-path walk ── */
    {
        mwv li;
        {
            const unsigned char *b = d_pub + W_LEAFIDX_OFF;
            li.h = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                 | ((uint32_t)b[2] <<  8) | (uint32_t)b[3];
            for (int j = 0; j < N_PARTIES-1; j++) {
                const unsigned char *bl = vlam[j] + W_LEAFIDX_OFF;
                li.l[j] = ((uint32_t)bl[0] << 24) | ((uint32_t)bl[1] << 16)
                        | ((uint32_t)bl[2] <<  8) | (uint32_t)bl[3];
            }
        }
        for (int level = 0; level < XMSS_H; level++) {
            unsigned char sib_pub[16], sib_lam[N_PARTIES-1][16];
            memcpy(sib_pub, d_pub + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);
            for (int j = 0; j < N_PARTIES-1; j++)
                memcpy(sib_lam[j], vlam[j] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            mwv bitw, mask;
            bitw.h = (li.h >> level) & 1u;
            for (int j = 0; j < N_PARTIES-1; j++) bitw.l[j] = (li.l[j] >> level) & 1u;
            mask_from_bit_v(&bitw, &mask);

            unsigned char left_pub[16], right_pub[16];
            unsigned char left_lam[N_PARTIES-1][16], right_lam[N_PARTIES-1][16];
            for (int w = 0; w < 4; w++) {
                mwv nd, sb, t, mt, lw, rw;
                memcpy(&nd.h, node_pub + w*4, 4);
                memcpy(&sb.h, sib_pub  + w*4, 4);
                for (int j = 0; j < N_PARTIES-1; j++) {
                    memcpy(&nd.l[j], node_lam[j] + w*4, 4);
                    memcpy(&sb.l[j], sib_lam[j]  + w*4, 4);
                }
                mpc_XOR_v(&nd, &sb, &t);
                mpc_AND_verify(&mask, &t, &mt, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
                mpc_XOR_v(&nd, &mt, &lw);
                mpc_XOR_v(&sb, &mt, &rw);
                memcpy(left_pub  + w*4, &lw.h, 4);
                memcpy(right_pub + w*4, &rw.h, 4);
                for (int j = 0; j < N_PARTIES-1; j++) {
                    memcpy(left_lam[j]  + w*4, &lw.l[j], 4);
                    memcpy(right_lam[j] + w*4, &rw.l[j], 4);
                }
            }

            const int dlen = XMSS_PK_SEED_BYTES + 2 + 2;
            unsigned char dom_pub[XMSS_PK_SEED_BYTES + 2 + 2];
            unsigned char dombuf[N_PARTIES-1][XMSS_PK_SEED_BYTES + 2 + 2];
            unsigned char sec_pub[16 + 16], secbuf[N_PARTIES-1][16 + 16];
            unsigned char *dom_lam[N_PARTIES-1], *sec_lam[N_PARTIES-1], *out_lam[N_PARTIES-1];
            memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
            dom_pub[XMSS_PK_SEED_BYTES]     = XMSS_TWEAK_TREE;
            dom_pub[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            {
                uint32_t idx = (li.h >> (level + 1)) & 0xFFFFu;
                dom_pub[dlen - 2] = (unsigned char)(idx & 0xFF);
                dom_pub[dlen - 1] = (unsigned char)((idx >> 8) & 0xFF);
            }
            memcpy(sec_pub,      left_pub,  16);
            memcpy(sec_pub + 16, right_pub, 16);
            for (int j = 0; j < N_PARTIES-1; j++) {
                uint32_t idx = (li.l[j] >> (level + 1)) & 0xFFFFu;
                memset(dombuf[j], 0, dlen - 2);
                dombuf[j][dlen - 2] = (unsigned char)(idx & 0xFF);
                dombuf[j][dlen - 1] = (unsigned char)((idx >> 8) & 0xFF);
                memcpy(secbuf[j],      left_lam[j],  16);
                memcpy(secbuf[j] + 16, right_lam[j], 16);
                dom_lam[j] = dombuf[j]; sec_lam[j] = secbuf[j]; out_lam[j] = node_lam[j];
            }
            mpc_blake3_th_verify(dom_pub, dom_lam, dlen, sec_pub, sec_lam, 16 + 16,
                                 node_pub, out_lam, 16,
                                 tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
        }
    }

    /* ── (6) target sum ── */
    mwv sum;
    mwv_const(0, &sum);
    {
        const int cpb = 8 / XMSS_COORD_RES_BITS;
        const uint32_t cmask = (1u << XMSS_COORD_RES_BITS) - 1u;
        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            int byte_idx = ci / cpb;
            int shift    = (ci % cpb) * XMSS_COORD_RES_BITS;
            mwv coord;
            coord.h = (uint32_t)((mh_pub[byte_idx] >> shift) & cmask);
            for (int j = 0; j < N_PARTIES-1; j++)
                coord.l[j] = (uint32_t)((mh_lam[j][byte_idx] >> shift) & cmask);
            mpc_ADD_verify(&sum, &coord, &sum, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
        }
    }

    /* ── Public masked output + check revealed parties' mask shares ── */
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&zh_out[w], node_pub + w*4, 4);
    zh_out[YP_SUM_WORD] = sum.h;
    for (int w = YP_SUM_WORD + 1; w < 8; w++) zh_out[w] = 0;

    for (int j = 0; j < N_PARTIES-1; j++) {
        int o = (j < e) ? j : j + 1;
        uint32_t lam_v;
        for (int w = 0; w < YP_ROOT_WORDS; w++) {
            memcpy(&lam_v, node_lam[j] + w*4, 4);
            if (lam_v != a_struct->yp[o][w]) { *error = true; }
        }
        if (sum.l[j] != a_struct->yp[o][YP_SUM_WORD]) { *error = true; }
        for (int w = YP_SUM_WORD + 1; w < 8; w++)
            if (a_struct->yp[o][w] != 0) { *error = true; }
    }

    /* ── Recompute h'_j = H(d || s streams || r_j) ──
     * Written into a_struct->h_prime for the caller to fold into the h*
     * recomputation: a transcript inconsistent with the prover's commitment
     * yields a different h'_j and the final h* check fails.  (h'_j itself no
     * longer travels in the proof — it is redundant with this recomputation.) */
    recompute_h_prime_verify(e, d_pub, s_slots, msgs_e, z_proof->r_j,
                             a_struct->h_prime);

    free(s_slots);
    free(xbuf);
    for (int j = 0; j < N_PARTIES-1; j++) free(tapes[j]);
}
