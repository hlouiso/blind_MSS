#include "commitment.h"
#include "blake3_th.h"
#include "gf128.h"

#include <string.h>

/* Fixed Th domains for the two commitment hashes — distinct from each other
 * and from every XMSS domain (those all start with the 16-byte pk_seed). */
static const uint8_t HM_DOM_Y[3] = { 'H', 'M', 'y' };
static const uint8_t HM_DOM_D[3] = { 'H', 'M', 'd' };

void hm_y(const uint8_t r[HM_R_BYTES], uint8_t y[HM_Y_BYTES])
{
    blake3_th(HM_DOM_Y, sizeof HM_DOM_Y, r, HM_R_BYTES, y, HM_Y_BYTES);
}

void hm_lines(const uint8_t m_hat[32], const uint8_t a[HM_A_BYTES], const uint8_t r[HM_R_BYTES],
              uint8_t b[HM_B_BYTES])
{
    for (int k = 0; k < HM_LINES; k++)
    {
        uint8_t acc[HM_ELT];
        memcpy(acc, m_hat + k * HM_ELT, HM_ELT); /* b_k starts at m̂_k */
        for (int i = 0; i < HM_NONCES; i++)
        {
            uint8_t prod[HM_ELT];
            gf128_mul(a + (k * HM_NONCES + i) * HM_ELT, r + i * HM_ELT, prod);
            for (int t = 0; t < HM_ELT; t++)
                acc[t] ^= prod[t];
        }
        memcpy(b + k * HM_ELT, acc, HM_ELT);
    }
}

void hm_commitment(const uint8_t a[HM_A_BYTES], const uint8_t b[HM_B_BYTES], const uint8_t y[HM_Y_BYTES],
                   uint8_t com[HM_COM_BYTES])
{
    memcpy(com, a, HM_A_BYTES);
    memcpy(com + HM_A_BYTES, b, HM_B_BYTES);
    memcpy(com + HM_A_BYTES + HM_B_BYTES, y, HM_Y_BYTES);
}

void hm_digest(const uint8_t com[HM_COM_BYTES], uint8_t d[32])
{
    blake3_th(HM_DOM_D, sizeof HM_DOM_D, com, HM_COM_BYTES, d, 32);
}

void hm_commit(const uint8_t m_hat[32], const uint8_t r[HM_R_BYTES], const uint8_t a[HM_A_BYTES],
               uint8_t com[HM_COM_BYTES], uint8_t d[32])
{
    uint8_t y[HM_Y_BYTES], b[HM_B_BYTES];
    hm_y(r, y);
    hm_lines(m_hat, a, r, b);
    hm_commitment(a, b, y, com);
    hm_digest(com, d);
}
