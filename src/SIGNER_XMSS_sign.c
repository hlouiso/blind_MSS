#include "commitment.h"
#include "xmss.h"

#include <openssl/sha.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_to_bytes(const char *hex, unsigned char *out, int n)
{
    for (int i = 0; i < n; i++)
    {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2X", &byte) != 1)
            return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

static void write_hex_line(FILE *f, const unsigned char *data, int n)
{
    for (int i = 0; i < n; i++)
        fprintf(f, "%02X", data[i]);
    fprintf(f, "\n");
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("SIGNER_XMSS_sign\n"
               "\n"
               "Usage:\n"
               "  ./SIGNER_XMSS_sign [-h|--help]\n"
               "\n"
               "Description:\n"
               "  Reads XMSS_secret_key.txt and blinded_message.txt (the 256-byte Halevi-Micali\n"
               "  commitment com = a||b||y), derives d = SHA256(com), produces a target-sum\n"
               "  WOTS+ / XMSS signature on d, self-checks it against the public key, and writes\n"
               "  XMSS_signature.txt.\n"
               "\n"
               "Output file (XMSS_signature.txt):\n"
               "  * line1: leaf_index (decimal)\n"
               "  * line2: nonce (%d bytes, %d hex)\n"
               "  * next %d lines: WOTS+ chain values (%d bytes / %d hex each)\n"
               "  * next %d lines: XMSS authentication path (%d bytes / %d hex each)\n",
               XMSS_NONCE_LEN, 2 * XMSS_NONCE_LEN, XMSS_WOTS_LEN, XMSS_NODE_BYTES, 2 * XMSS_NODE_BYTES, XMSS_H,
               XMSS_NODE_BYTES, 2 * XMSS_NODE_BYTES);
        return 0;
    }

    /* ============================== Getting keys ============================== */
    FILE *f = fopen("XMSS_secret_key.txt", "r");
    if (f == NULL)
    {
        fprintf(stderr, "Error opening XMSS_secret_key.txt\n");
        return EXIT_FAILURE;
    }

    char line[256];
    unsigned char sk_seed[32];
    unsigned char pk_seed[XMSS_PK_SEED_BYTES];
    uint32_t leaf_idx;

    if (!fgets(line, sizeof line, f) || hex_to_bytes(line, sk_seed, sizeof sk_seed) != 0 ||
        !fgets(line, sizeof line, f) || hex_to_bytes(line, pk_seed, sizeof pk_seed) != 0 ||
        !fgets(line, sizeof line, f) || sscanf(line, "%u", &leaf_idx) != 1)
    {
        fprintf(stderr, "Error parsing XMSS_secret_key.txt\n");
        fclose(f);
        return EXIT_FAILURE;
    }
    fclose(f);

    if (leaf_idx >= (1u << XMSS_H))
    {
        fprintf(stderr, "Error: leaf_index %u out of bounds (key exhausted)\n", leaf_idx);
        return EXIT_FAILURE;
    }

    /* ===================== Reading commitment com = a||b||y, deriving d ===================== */
    FILE *fbm = fopen("blinded_message.txt", "r");
    if (!fbm)
    {
        fprintf(stderr, "Error opening blinded_message.txt\n");
        return EXIT_FAILURE;
    }
    char comhex[2 * HM_COM_BYTES + 2];
    unsigned char com[HM_COM_BYTES], d[32];
    if (!fgets(comhex, sizeof comhex, fbm) || hex_to_bytes(comhex, com, HM_COM_BYTES) != 0)
    {
        fprintf(stderr, "Error reading blinded_message.txt (expected %d hex chars)\n", 2 * HM_COM_BYTES);
        fclose(fbm);
        return EXIT_FAILURE;
    }
    fclose(fbm);
    hm_digest(com, d); /* d = SHA256(com): the signer certifies the full commitment */

    /* ============================== Signing ============================== */
    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, leaf_idx, d, 32, &sig))
    {
        fprintf(stderr, "Error: XMSS signing failed (nonce grinding budget exhausted)\n");
        return EXIT_FAILURE;
    }

    /* ============================== Self-check vs public key ============================== */
    FILE *fpk = fopen("XMSS_public_key.txt", "r");
    if (!fpk)
    {
        fprintf(stderr, "Error opening XMSS_public_key.txt\n");
        return EXIT_FAILURE;
    }
    unsigned char pk_seed_pub[XMSS_PK_SEED_BYTES];
    xmss_node root;
    if (!fgets(line, sizeof line, f = fpk) || hex_to_bytes(line, pk_seed_pub, sizeof pk_seed_pub) != 0 ||
        !fgets(line, sizeof line, fpk) || hex_to_bytes(line, root, XMSS_NODE_BYTES) != 0)
    {
        fprintf(stderr, "Error parsing XMSS_public_key.txt\n");
        fclose(fpk);
        return EXIT_FAILURE;
    }
    fclose(fpk);

    if (!xmss_verify(pk_seed_pub, root, d, 32, &sig))
    {
        fprintf(stderr, "Self-check FAILED: produced signature does not verify against the public key.\n");
        return EXIT_FAILURE;
    }
    printf("Self-check: signature verifies against the public key.\n");

    /* ============================== Advancing the state (before writing sig) ============================== */
    /* Write the incremented leaf_index FIRST so a crash between the two writes
     * never leaves the key file pointing to a leaf that was already signed. */
    FILE *fkey = fopen("XMSS_secret_key.txt", "w");
    if (fkey == NULL)
    {
        fprintf(stderr, "Error updating XMSS_secret_key.txt\n");
        return EXIT_FAILURE;
    }
    write_hex_line(fkey, sk_seed, sizeof sk_seed);
    write_hex_line(fkey, pk_seed, sizeof pk_seed);
    fprintf(fkey, "%u\n", leaf_idx + 1);
    if (fclose(fkey) != 0)
    {
        fprintf(stderr, "Error flushing XMSS_secret_key.txt\n");
        return EXIT_FAILURE;
    }

    /* ============================== Writing XMSS_signature.txt ============================== */
    f = fopen("XMSS_signature.txt", "w");
    if (f == NULL)
    {
        fprintf(stderr, "Error opening XMSS_signature.txt\n");
        return EXIT_FAILURE;
    }
    fprintf(f, "%u\n", leaf_idx);
    write_hex_line(f, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        write_hex_line(f, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int i = 0; i < XMSS_H; i++)
        write_hex_line(f, sig.auth_path[i], XMSS_NODE_BYTES);
    if (fclose(f) != 0)
    {
        fprintf(stderr, "Error flushing XMSS_signature.txt\n");
        return EXIT_FAILURE;
    }

    printf("\nXMSS_signature.txt generated\n\n");
    printf("Reminder: XMSS_signature = (leaf_index, nonce, WOTS+ chain values, XMSS path)\n\n");
    return 0;
}
