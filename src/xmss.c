#include "xmss.h"
#include "blake3_th.h"
#include "blake3_keyed_xof.h"
#include "randombytes.h"

#include <stdlib.h>
#include <string.h>

/* ── Low-level primitives ─────────────────────────────────────────────────── */

/* ── Tweaked hashes ───────────────────────────────────────────────────────── */

/* Append the epoch (leaf index) as XMSS_EPOCH_BYTES big-endian bytes.  Big-endian
 * matches the secret leaf_index witness layout (circuits.h, W_LEAFIDX), so the
 * in-circuit hashes splice the witness bytes directly. */
static void put_epoch_be(uint8_t *buf, size_t *o, uint32_t epoch)
{
    for (size_t k = 0; k < XMSS_EPOCH_BYTES; k++)
        buf[(*o)++] = (uint8_t)((epoch >> (8 * (XMSS_EPOCH_BYTES - 1 - k))) & 0xff);
}

void xmss_hash_message(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const uint8_t *nonce,
                       size_t nonce_len, const uint8_t *message, size_t message_len, uint8_t out32[32])
{
    uint8_t dom[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
    size_t o = 0;
    memcpy(dom + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    dom[o++] = XMSS_TWEAK_MESSAGE;
    put_epoch_be(dom, &o, epoch);

    uint8_t *data = malloc(nonce_len + message_len);
    if (!data)
    {
        memset(out32, 0, 32);
        return;
    }
    memcpy(data, nonce, nonce_len);
    memcpy(data + nonce_len, message, message_len);
    blake3_th(dom, o, data, nonce_len + message_len, out32, 32);
    free(data);
}

void xmss_hash_chain_step(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node in,
                          uint8_t chain_idx, uint8_t pos, xmss_node out)
{
    /* dom = previous node; the tweak travels in the (single) data block. */
    uint8_t data[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES + 1 + 1];
    size_t o = 0;
    memcpy(data + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    data[o++] = XMSS_TWEAK_CHAIN;
    put_epoch_be(data, &o, epoch);
    data[o++] = chain_idx;
    data[o++] = pos;
    blake3_th(in, XMSS_NODE_BYTES, data, o, out, XMSS_NODE_BYTES);
}

void xmss_hash_chain_multi(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node start,
                           uint8_t chain_idx, uint8_t start_pos, uint8_t steps, xmss_node out)
{
    xmss_node cur;
    memcpy(cur, start, XMSS_NODE_BYTES);
    for (uint8_t i = 0; i < steps; i++)
    {
        uint8_t pos = (uint8_t)(start_pos + i + 1);
        xmss_node next;
        xmss_hash_chain_step(pk_seed, epoch, cur, chain_idx, pos, next);
        memcpy(cur, next, XMSS_NODE_BYTES);
    }
    memcpy(out, cur, XMSS_NODE_BYTES);
}

void xmss_hash_tree_node(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node left, const xmss_node right,
                         uint32_t level, uint32_t index, xmss_node out)
{
    uint8_t dom[XMSS_PK_SEED_BYTES + 1 + 1 + 2];
    uint8_t data[2 * XMSS_NODE_BYTES];
    size_t o = 0;
    memcpy(dom + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    dom[o++] = XMSS_TWEAK_TREE;
    dom[o++] = (uint8_t)(level & 0xff);
    dom[o++] = (uint8_t)(index & 0xff);        /* index, 2-byte LE */
    dom[o++] = (uint8_t)((index >> 8) & 0xff);
    memcpy(data, left, XMSS_NODE_BYTES);
    memcpy(data + XMSS_NODE_BYTES, right, XMSS_NODE_BYTES);
    blake3_th(dom, o, data, sizeof data, out, XMSS_NODE_BYTES);
}

void xmss_hash_public_key(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node pk_hashes[XMSS_WOTS_LEN], xmss_node out)
{
    uint8_t dom[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
    size_t o = 0;
    memcpy(dom + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    dom[o++] = XMSS_TWEAK_LEAF;
    put_epoch_be(dom, &o, epoch);
    blake3_th(dom, o, (const uint8_t *)pk_hashes,
              (size_t)XMSS_WOTS_LEN * XMSS_NODE_BYTES, out, XMSS_NODE_BYTES);
}

void xmss_extract_coords(const uint8_t *hash, int dimension, int res_bits, uint8_t *coords_out)
{
    const uint8_t mask = (uint8_t)((1u << res_bits) - 1);
    const int coords_per_byte = 8 / res_bits;
    for (int i = 0; i < dimension; i++)
    {
        int byte_idx = i / coords_per_byte;
        int coord_idx = i % coords_per_byte;
        int shift = coord_idx * res_bits;
        coords_out[i] = (uint8_t)((hash[byte_idx] >> shift) & mask);
    }
}

/* ── WOTS+ ────────────────────────────────────────────────────────────────── */

void xmss_wots_gen_sk(const uint8_t sk_seed[32], uint32_t leaf_index, xmss_node sk_out[XMSS_WOTS_LEN])
{
    uint8_t leaf_be[4] = {
        (uint8_t)(leaf_index >> 24), (uint8_t)(leaf_index >> 16),
        (uint8_t)(leaf_index >> 8),  (uint8_t)leaf_index
    };
    /* One XOF call produces the chain starts consecutively; the chain index
     * is therefore bound by its fixed byte offset in this stream. */
    blake3_keyed_xof(sk_seed, BLAKE3_XOF_DOM_XMSS_WOTS_SK,
                     leaf_be, sizeof leaf_be,
                     (uint8_t *)sk_out, sizeof(xmss_node) * XMSS_WOTS_LEN);
}

void xmss_wots_pk_from_sk(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node sk[XMSS_WOTS_LEN], xmss_node pk_out[XMSS_WOTS_LEN])
{
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        xmss_hash_chain_multi(pk_seed, epoch, sk[i], (uint8_t)i, 0, XMSS_WOTS_MAX_STEPS, pk_out[i]);
}

void xmss_wots_sign(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node sk[XMSS_WOTS_LEN],
                    const uint8_t coords[XMSS_WOTS_LEN], xmss_node sig_out[XMSS_WOTS_LEN])
{
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
    {
        if (coords[i] == 0)
            memcpy(sig_out[i], sk[i], XMSS_NODE_BYTES);
        else
            xmss_hash_chain_multi(pk_seed, epoch, sk[i], (uint8_t)i, 0, coords[i], sig_out[i]);
    }
}

void xmss_wots_pk_from_sig(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                           const xmss_node sig[XMSS_WOTS_LEN], const uint8_t coords[XMSS_WOTS_LEN],
                           xmss_node pk_out[XMSS_WOTS_LEN])
{
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
    {
        uint8_t remaining = (uint8_t)(XMSS_WOTS_MAX_STEPS - coords[i]);
        if (remaining == 0)
            memcpy(pk_out[i], sig[i], XMSS_NODE_BYTES);
        else
            xmss_hash_chain_multi(pk_seed, epoch, sig[i], (uint8_t)i, coords[i], remaining, pk_out[i]);
    }
}

/* ── XMSS tree ────────────────────────────────────────────────────────────── */

/* Build the full Merkle tree from sk_seed.  tree[h] (h=0..XMSS_H) is an array of
 * (1 << (XMSS_H - h)) nodes; tree[0] are the leaves, tree[XMSS_H][0] the root.
 * Caller must free every tree[h].  Returns 0 on success, -1 on allocation error. */
static int xmss_build_tree(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                           xmss_node *tree[XMSS_H + 1])
{
    size_t n_leaves = (size_t)1u << XMSS_H;

    for (int h = 0; h <= XMSS_H; h++)
        tree[h] = NULL;
    for (int h = 0; h <= XMSS_H; h++)
    {
        size_t n = (size_t)1u << (XMSS_H - h);
        tree[h] = malloc(n * sizeof(xmss_node));
        if (!tree[h])
        {
            for (int g = 0; g <= XMSS_H; g++)
                free(tree[g]);
            return -1;
        }
    }

    for (size_t l = 0; l < n_leaves; l++)
    {
        xmss_node sk[XMSS_WOTS_LEN];
        xmss_node pk[XMSS_WOTS_LEN];
        xmss_wots_gen_sk(sk_seed, (uint32_t)l, sk);
        xmss_wots_pk_from_sk(pk_seed, (uint32_t)l, sk, pk);
        xmss_hash_public_key(pk_seed, (uint32_t)l, pk, tree[0][l]);
    }

    for (int h = 1; h <= XMSS_H; h++)
    {
        size_t n = (size_t)1u << (XMSS_H - h);
        for (size_t i = 0; i < n; i++)
            xmss_hash_tree_node(pk_seed, tree[h - 1][2 * i], tree[h - 1][2 * i + 1], (uint32_t)(h - 1),
                                (uint32_t)i, tree[h][i]);
    }
    return 0;
}

static void xmss_free_tree(xmss_node *tree[XMSS_H + 1])
{
    for (int h = 0; h <= XMSS_H; h++)
        free(tree[h]);
}

void xmss_compute_root(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], xmss_node root_out)
{
    xmss_node *tree[XMSS_H + 1];
    if (xmss_build_tree(sk_seed, pk_seed, tree) != 0)
    {
        memset(root_out, 0, XMSS_NODE_BYTES);
        return;
    }
    memcpy(root_out, tree[XMSS_H][0], XMSS_NODE_BYTES);
    xmss_free_tree(tree);
}

/* Walk an authentication path from `leaf` to the root. */
static void xmss_walk_auth_path(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node leaf, uint32_t leaf_index,
                                const xmss_node auth_path[XMSS_H], xmss_node root_out)
{
    xmss_node node;
    memcpy(node, leaf, XMSS_NODE_BYTES);
    uint32_t idx = leaf_index;
    for (int h = 0; h < XMSS_H; h++)
    {
        xmss_node parent;
        if ((idx & 1) == 0)
            xmss_hash_tree_node(pk_seed, node, auth_path[h], (uint32_t)h, idx >> 1, parent);
        else
            xmss_hash_tree_node(pk_seed, auth_path[h], node, (uint32_t)h, idx >> 1, parent);
        memcpy(node, parent, XMSS_NODE_BYTES);
        idx >>= 1;
    }
    memcpy(root_out, node, XMSS_NODE_BYTES);
}

/* Grind a random nonce until the codeword coordinates sum to the target.  The
 * codeword is epoch-dependent, so the leaf index is bound into the message hash. */
static int grind_nonce(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const uint8_t *message,
                       size_t message_len, uint8_t nonce_out[XMSS_NONCE_LEN], uint8_t coords_out[XMSS_WOTS_LEN])
{
    for (uint32_t attempt = 0; attempt < (1u << 20); attempt++)
    {
        uint8_t nonce[XMSS_NONCE_LEN];
        if (!randombytes_fill(nonce, sizeof nonce))
            return 0;
        uint8_t mh[32];
        xmss_hash_message(pk_seed, epoch, nonce, XMSS_NONCE_LEN, message, message_len, mh);
        uint8_t coords[XMSS_WOTS_LEN];
        xmss_extract_coords(mh, XMSS_WOTS_LEN, XMSS_COORD_RES_BITS, coords);
        int sum = 0;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
            sum += coords[i];
        if (sum == XMSS_TARGET_SUM)
        {
            memcpy(nonce_out, nonce, XMSS_NONCE_LEN);
            memcpy(coords_out, coords, XMSS_WOTS_LEN);
            return 1;
        }
    }
    return 0;
}

int xmss_sign(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t leaf_index,
              const uint8_t *message, size_t message_len, xmss_sig *out)
{
    /* Range guard: the tree has 2^XMSS_H leaves; a larger index would read
     * past the level-0 array when collecting the authentication path. */
    if (leaf_index >= (1u << XMSS_H))
        return 0;

    uint8_t coords[XMSS_WOTS_LEN];
    if (!grind_nonce(pk_seed, leaf_index, message, message_len, out->nonce, coords))
        return 0;

    xmss_node sk[XMSS_WOTS_LEN];
    xmss_wots_gen_sk(sk_seed, leaf_index, sk);
    xmss_wots_sign(pk_seed, leaf_index, sk, coords, out->sig_hashes);

    xmss_node *tree[XMSS_H + 1];
    if (xmss_build_tree(sk_seed, pk_seed, tree) != 0)
        return 0;

    uint32_t idx = leaf_index;
    for (int h = 0; h < XMSS_H; h++)
    {
        uint32_t sibling = (idx & 1) == 0 ? idx + 1 : idx - 1;
        memcpy(out->auth_path[h], tree[h][sibling], XMSS_NODE_BYTES);
        idx >>= 1;
    }
    xmss_free_tree(tree);

    out->leaf_index = leaf_index;
    return 1;
}

int xmss_verify(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node root, const uint8_t *message,
                size_t message_len, const xmss_sig *sig)
{
    uint8_t mh[32];
    xmss_hash_message(pk_seed, sig->leaf_index, sig->nonce, XMSS_NONCE_LEN, message, message_len, mh);
    uint8_t coords[XMSS_WOTS_LEN];
    xmss_extract_coords(mh, XMSS_WOTS_LEN, XMSS_COORD_RES_BITS, coords);

    int sum = 0;
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        sum += coords[i];
    if (sum != XMSS_TARGET_SUM)
        return 0;

    xmss_node pk_hashes[XMSS_WOTS_LEN];
    xmss_wots_pk_from_sig(pk_seed, sig->leaf_index, sig->sig_hashes, coords, pk_hashes);

    xmss_node leaf;
    xmss_hash_public_key(pk_seed, sig->leaf_index, pk_hashes, leaf);

    xmss_node computed_root;
    xmss_walk_auth_path(pk_seed, leaf, sig->leaf_index, sig->auth_path, computed_root);

    return memcmp(computed_root, root, XMSS_NODE_BYTES) == 0;
}
