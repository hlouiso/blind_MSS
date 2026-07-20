/* bench.c — KKW end-to-end benchmark
 * Build via Makefile: make N=<N> bench-bin
 * Run all N values:   make bench
 *
 * For each compiled N: runs BENCH_ITERS prove+verify pairs, records wall time
 * (CLOCK_MONOTONIC) and TSC reference cycles (rdtsc), then prints the median.
 *
 * Usage: ./bench_bin [--header]
 *   --header  print CPU info + table header then exit (no iterations run)
 *
 * Expected total runtime (8 threads): ~1 hour for all 5 N values × 100 iters.
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

#ifndef BENCH_ITERS
#define BENCH_ITERS 100
#endif

static void random_or_die(void *buffer, size_t length)
{
    if (!randombytes_fill(buffer, length)) {
        fprintf(stderr, "OS random generator failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/* ── timing helpers ─────────────────────────────────────────────────────── */

/* Free-running hardware counter (same caveats as bench_pipeline.c: on AArch64
 * this is the fixed-frequency virtual counter, not CPU cycles — the wall-time
 * column is the portable metric). */
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

static double elapsed_s(struct timespec a, struct timespec b)
{
    return (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) * 1e-9;
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a, ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

/* ── system info ────────────────────────────────────────────────────────── */

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
            if (p) {
                p += 2;
                p[strcspn(p, "\n")] = '\0';
                snprintf(buf, n, "%s", p);
                fclose(f); return;
            }
        }
    }
    fclose(f);
    snprintf(buf, n, "unknown");
#endif
}

/* ── witness generation ─────────────────────────────────────────────────── */

static void build_witness(unsigned char *input,
                          unsigned char m_hat[32],
                          unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                          uint32_t pubout[8])
{
    unsigned char sk_seed[32];
    random_or_die(sk_seed, 32);
    random_or_die(pk_seed, XMSS_PK_SEED_BYTES);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, root);

    random_or_die(m_hat, 32);
    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    random_or_die(r, sizeof r);
    random_or_die(a_mat, sizeof a_mat);
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, 0, d, 32, &sig)) {
        fprintf(stderr, "xmss_sign failed while building the benchmark witness\n");
        exit(EXIT_FAILURE);
    }

    memcpy(input + W_R_OFF,   r,     HM_R_BYTES);
    memcpy(input + W_A_OFF,   a_mat, HM_A_BYTES);
    memset(input + W_LEAFIDX_OFF, 0, 4);
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF  + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h],  XMSS_NODE_BYTES);

    memset(pubout, 0, 8 * sizeof(uint32_t));
    for (int w = 0; w < YP_ROOT_WORDS; w++) memcpy(&pubout[w], root + w * 4, 4);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    ASSERT_LIB_PARAMS();
    char cpu[128]; cpu_model(cpu, sizeof cpu);
    int nthreads = omp_get_max_threads();

    if (argc > 1 && strcmp(argv[1], "--header") == 0) {
        printf("KKW Benchmark  ·  %s  ·  %d threads  ·  %d iterations\n\n",
               cpu, nthreads, BENCH_ITERS);
        printf("  N |   M |  τ |"
               " Prove wall (s) | Prove Gcyc |"
               " Verify wall (s) | Verify Gcyc |"
               " Proof (MB)\n");
        printf("----+-----+----+"
               "----------------+------------+"
               "-----------------+-------------+"
               "-----------\n");
        return 0;
    }

    unsigned char input[W_END], m_hat[32], pk_seed[XMSS_PK_SEED_BYTES];
    uint32_t pubout[8];
    build_witness(input, m_hat, pk_seed, pubout);

    double   prove_wall [BENCH_ITERS];
    uint64_t prove_cyc  [BENCH_ITERS];
    double   verify_wall[BENCH_ITERS];
    uint64_t verify_cyc [BENCH_ITERS];
    long     proof_bytes = 0;

    kkw_verbose = 0;

    fprintf(stderr, "N=%d: %d iterations", N_PARTIES, BENCH_ITERS);
    fflush(stderr);

    for (int i = 0; i < BENCH_ITERS; i++) {
        FILE *proof = tmpfile();
        if (!proof) { fprintf(stderr, "\ntmpfile() failed\n"); return 1; }

        struct timespec t0, t1;
        uint64_t c0, c1;

        /* prove */
        c0 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (kkw_prove(input, m_hat, pk_seed, pubout, proof) != 0) {
            fprintf(stderr, "\nkkw_prove failed at iter %d\n", i); return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        c1 = rdtsc();
        prove_wall[i] = elapsed_s(t0, t1);
        prove_cyc[i]  = c1 - c0;

        if (i == 0) proof_bytes = ftell(proof);
        rewind(proof);

        /* verify */
        c0 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = kkw_verify(proof, m_hat, pk_seed, pubout);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        c1 = rdtsc();
        verify_wall[i] = elapsed_s(t0, t1);
        verify_cyc[i]  = c1 - c0;

        fclose(proof);

        if (rc != 0) {
            fprintf(stderr, "\nkkw_verify FAILED at iter %d\n", i); return 1;
        }

        if ((i + 1) % 10 == 0 || i + 1 == BENCH_ITERS) {
            fprintf(stderr, " %d/%d", i + 1, BENCH_ITERS);
            fflush(stderr);
        }
    }
    fprintf(stderr, "\n");

    qsort(prove_wall,  BENCH_ITERS, sizeof(double),   cmp_double);
    qsort(prove_cyc,   BENCH_ITERS, sizeof(uint64_t), cmp_u64);
    qsort(verify_wall, BENCH_ITERS, sizeof(double),   cmp_double);
    qsort(verify_cyc,  BENCH_ITERS, sizeof(uint64_t), cmp_u64);

    int m = BENCH_ITERS / 2;
    printf("%3d | %3d | %2d |"
           " %14.3f | %10.2f |"
           " %15.3f | %11.2f |"
           " %9.1f\n",
           N_PARTIES, M_KKW, NUM_ROUNDS,
           prove_wall[m],  prove_cyc[m]  / 1e9,
           verify_wall[m], verify_cyc[m] / 1e9,
           proof_bytes / 1e6);

    return 0;
}
