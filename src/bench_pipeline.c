/* bench_pipeline.c — full blind-signature pipeline benchmark.
 *
 * Runs PIPELINE_ITERS independent iterations of the complete protocol and
 * measures wall time (CLOCK_MONOTONIC) and reference CPU cycles (rdtsc) for
 * each of the four phases:
 *
 *     1. Commitment building   (client: hm_commit)
 *     2. Sign commitment       (signer: xmss_sign — grind + tree + WOTS)
 *     3. Proof generation      (client: kkw_prove)
 *     4. Verification          (verifier: kkw_verify)
 *
 * Reports the median and the average of both metrics per phase.
 *
 * Build:  make N=<N> bench-pipeline           (or PIPELINE_ITERS=<k> to shorten)
 *
 * Note on messages: the message length is irrelevant to every measured phase.
 * The message only feeds m_hat = Th("KKWmhat", m), computed once and outside the timed
 * region; the commitment, signature, proof and verification all operate on the
 * 32-byte m_hat. We still draw a fresh random PIPELINE_MSG_LEN-byte message per
 * iteration so nothing is cached, but its size does not affect the numbers.
 */
#include "circuits.h"
#include "commitment.h"
#include "kkw_prove.h"
#include "kkw_verify.h"
#include "randombytes.h"
#include "shared.h"
#include "xmss.h"

#include <errno.h>
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#ifndef PIPELINE_ITERS
#define PIPELINE_ITERS 100
#endif
#ifndef PIPELINE_MSG_LEN
#define PIPELINE_MSG_LEN 10000   /* 10 kB; size is immaterial to the measured phases */
#endif

static void random_or_die(void *buffer, size_t length)
{
    if (!randombytes_fill(buffer, length)) {
        fprintf(stderr, "OS random generator failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/* ── timing helpers ─────────────────────────────────────────────────────── */

/* Free-running hardware counter. On x86 this is the TSC (CPU cycles); on
 * AArch64 (e.g. Apple Silicon) it is the fixed-frequency virtual counter
 * cntvct_el0 — NOT the CPU clock, so the "cycle" numbers there are counter
 * ticks, not cycles. The wall-time (ms) columns are the portable, meaningful
 * metric on every platform. */
static uint64_t rdtsc(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t v;
    __asm__ __volatile__ ("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static double elapsed_ms(struct timespec a, struct timespec b)
{
    return (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) * 1e-6;
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

/* median of an array (sorts it in place). */
static double median(double *v, int n)
{
    qsort(v, n, sizeof(double), cmp_double);
    return (n & 1) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

static double average(const double *v, int n)
{
    double s = 0.0;
    for (int i = 0; i < n; i++) s += v[i];
    return s / n;
}

static void cpu_model(char *buf, size_t n)
{
#if defined(__APPLE__)
    /* macOS has no /proc; query the machdep CPU brand string via sysctl. */
    if (sysctlbyname("machdep.cpu.brand_string", buf, &n, NULL, 0) == 0) return;
    snprintf(buf, n, "unknown");
    return;
#else
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) { snprintf(buf, n, "unknown"); return; }
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "model name", 10) == 0) {
            char *p = strchr(line, ':');
            if (p) { p += 2; p[strcspn(p, "\n")] = '\0'; snprintf(buf, n, "%s", p); fclose(f); return; }
        }
    }
    fclose(f);
    snprintf(buf, n, "unknown");
#endif
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    ASSERT_LIB_PARAMS();
    const int iters = PIPELINE_ITERS;
    kkw_verbose = 0;

    /* Per-phase samples: wall time (ms) and reference cycles (Mcyc). */
    double commit_ms[iters], sign_ms[iters], prove_ms[iters], verify_ms[iters];
    double commit_mc[iters], sign_mc[iters], prove_mc[iters], verify_mc[iters];
    double proof_mb[iters];

    /* One key pair for the whole run (key generation is setup, not measured). */
    unsigned char sk_seed[32], pk_seed[XMSS_PK_SEED_BYTES];
    random_or_die(sk_seed, 32);
    random_or_die(pk_seed, XMSS_PK_SEED_BYTES);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    uint32_t pubout[8] = {0};
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;

    char cpu[128]; cpu_model(cpu, sizeof cpu);
    fprintf(stderr, "N=%d: %d iterations", N_PARTIES, iters);

    for (int i = 0; i < iters; i++) {
        struct timespec t0, t1;
        uint64_t c0, c1;

        /* Fresh random message (size is immaterial — see file header). */
        unsigned char msg[PIPELINE_MSG_LEN], m_hat[32];
        random_or_die(msg, PIPELINE_MSG_LEN);
        KKW_TH(KKW_DOM_MHAT, msg, PIPELINE_MSG_LEN, m_hat);

        /* Fresh secret opening (r, a) for the Halevi–Micali commitment. */
        unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
        random_or_die(r, sizeof r);
        random_or_die(a_mat, sizeof a_mat);

        /* ── Phase 1: commitment building ── */
        unsigned char com[HM_COM_BYTES], d[32];
        c0 = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &t0);
        hm_commit(m_hat, r, a_mat, com, d);
        clock_gettime(CLOCK_MONOTONIC, &t1); c1 = rdtsc();
        commit_ms[i] = elapsed_ms(t0, t1);
        commit_mc[i] = (double)(c1 - c0) / 1e6;

        /* ── Phase 2: signer signs the commitment digest d ── */
        xmss_sig sig;
        c0 = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &t0);
        int sok = xmss_sign(sk_seed, pk_seed, 0, d, 32, &sig);
        clock_gettime(CLOCK_MONOTONIC, &t1); c1 = rdtsc();
        sign_ms[i] = elapsed_ms(t0, t1);
        sign_mc[i] = (double)(c1 - c0) / 1e6;
        if (!sok) { fprintf(stderr, "\nxmss_sign failed at iter %d\n", i); return 1; }

        /* Assemble the prover witness (untimed: a few memcpy). */
        unsigned char input[W_END];
        memcpy(input + W_R_OFF, r, HM_R_BYTES);
        memcpy(input + W_A_OFF, a_mat, HM_A_BYTES);
        memset(input + W_LEAFIDX_OFF, 0, 4);
        memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
        for (int j = 0; j < XMSS_WOTS_LEN; j++)
            memcpy(input + W_SIG_OFF + j * XMSS_NODE_BYTES, sig.sig_hashes[j], XMSS_NODE_BYTES);
        for (int h = 0; h < XMSS_H; h++)
            memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

        FILE *proof = tmpfile();
        if (!proof) { fprintf(stderr, "\ntmpfile() failed at iter %d\n", i); return 1; }

        /* ── Phase 3: proof generation ── */
        c0 = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &t0);
        int pok = kkw_prove(input, m_hat, pk_seed, pubout, proof);
        clock_gettime(CLOCK_MONOTONIC, &t1); c1 = rdtsc();
        prove_ms[i] = elapsed_ms(t0, t1);
        prove_mc[i] = (double)(c1 - c0) / 1e6;
        if (pok != 0) { fprintf(stderr, "\nkkw_prove failed at iter %d\n", i); fclose(proof); return 1; }

        proof_mb[i] = (double)ftell(proof) / 1e6;   /* size varies with the drawn parties */
        rewind(proof);

        /* ── Phase 4: verification ── */
        c0 = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &t0);
        int vok = kkw_verify(proof, m_hat, pk_seed, pubout);
        clock_gettime(CLOCK_MONOTONIC, &t1); c1 = rdtsc();
        verify_ms[i] = elapsed_ms(t0, t1);
        verify_mc[i] = (double)(c1 - c0) / 1e6;
        fclose(proof);
        if (vok != 0) { fprintf(stderr, "\nkkw_verify FAILED at iter %d\n", i); return 1; }

        fprintf(stderr, "\r  %d/%d", i + 1, iters);
        fflush(stderr);
    }
    fprintf(stderr, "\n\n");

    printf("Pipeline benchmark  ·  %s  ·  %d threads  ·  N=%d  ·  %d iterations  ·  msg=%d B\n\n",
           cpu, omp_get_max_threads(), N_PARTIES, iters, PIPELINE_MSG_LEN);
    printf("Phase                    | median ms |    avg ms | median Mcyc |   avg Mcyc\n");
    printf("-------------------------+-----------+-----------+-------------+-----------\n");
    struct { const char *name; double *ms, *mc; } rows[] = {
        { "1. Commitment building",  commit_ms, commit_mc },
        { "2. Sign commitment",      sign_ms,   sign_mc   },
        { "3. Proof generation",     prove_ms,  prove_mc  },
        { "4. Verification",         verify_ms, verify_mc },
    };
    for (int k = 0; k < 4; k++) {
        double med_ms = median(rows[k].ms, iters);
        double avg_ms = average(rows[k].ms, iters);
        double med_mc = median(rows[k].mc, iters);
        double avg_mc = average(rows[k].mc, iters);
        printf("%-24s | %9.4f | %9.4f | %11.3f | %9.3f\n",
               rows[k].name, med_ms, avg_ms, med_mc, avg_mc);
    }

    printf("\nProof size: median %.2f MB, average %.2f MB\n",
           median(proof_mb, iters), average(proof_mb, iters));
    return 0;
}
