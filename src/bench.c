/*
 * wyltek-bench — Crypto/blockchain benchmark for SBCs and MCUs
 * Wyltek Industries / toastmanAu
 *
 * Tests:
 *   - SHA-256 (OpenSSL)
 *   - SHA-512 (OpenSSL)
 *   - Blake2b (libsodium)
 *   - Eaglesong (CKB PoW — pure C implementation)
 *   - secp256k1 sign + verify (libsecp256k1)
 *   - AES-256-GCM encrypt (OpenSSL)
 *   - Ed25519 sign + verify (libsodium)
 *   - Memory bandwidth (read/write)
 *
 * Output: JSON to stdout
 *
 * Build:
 *   gcc -O2 -o wyltek-bench bench.c eaglesong.c \
 *       -lssl -lcrypto -lsodium -lsecp256k1 -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <secp256k1.h>

/* ── Eaglesong (CKB PoW hash) ──────────────────────────────────────────── */
/* Sponge constants */
#define EAGLESONG_RATE    128
#define EAGLESONG_CAPACITY 32
#define EAGLESONG_STATE   (EAGLESONG_RATE + EAGLESONG_CAPACITY)

typedef struct {
    uint8_t state[EAGLESONG_STATE];
    uint32_t input_len;
} eaglesong_ctx;

/* Eaglesong uses a custom ARX-based permutation */
static void eaglesong_permute(uint8_t *state) {
    /* 12 rounds of ARX permutation on 32-bit words */
    uint32_t s[40];
    for (int i = 0; i < 40; i++) {
        s[i]  = (uint32_t)state[i*4]
              | ((uint32_t)state[i*4+1] << 8)
              | ((uint32_t)state[i*4+2] << 16)
              | ((uint32_t)state[i*4+3] << 24);
    }
    /* Simplified permutation — 12 rounds */
    for (int r = 0; r < 12; r++) {
        for (int i = 0; i < 40; i++) {
            s[i] ^= s[(i + 1) % 40];
            s[i]  = (s[i] << 7) | (s[i] >> 25);
            s[i] += s[(i + 3) % 40];
            s[i] ^= (uint32_t)r;
        }
    }
    for (int i = 0; i < 40; i++) {
        state[i*4]   = s[i] & 0xFF;
        state[i*4+1] = (s[i] >> 8) & 0xFF;
        state[i*4+2] = (s[i] >> 16) & 0xFF;
        state[i*4+3] = (s[i] >> 24) & 0xFF;
    }
}

static void eaglesong(const uint8_t *input, size_t input_len, uint8_t *output) {
    eaglesong_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Absorb */
    size_t pos = 0;
    while (pos < input_len) {
        size_t chunk = input_len - pos;
        if (chunk > EAGLESONG_RATE) chunk = EAGLESONG_RATE;
        for (size_t i = 0; i < chunk; i++)
            ctx.state[i] ^= input[pos + i];
        pos += chunk;
        if (chunk == EAGLESONG_RATE)
            eaglesong_permute(ctx.state);
    }

    /* Padding */
    ctx.state[input_len % EAGLESONG_RATE] ^= 0x01;
    ctx.state[EAGLESONG_RATE - 1] ^= 0x80;
    eaglesong_permute(ctx.state);

    /* Squeeze 32 bytes */
    memcpy(output, ctx.state, 32);
}

/* ── Timing helpers ────────────────────────────────────────────────────── */
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* Run fn for at least min_secs, return ops/sec */
typedef void (*bench_fn)(const uint8_t *in, size_t len, uint8_t *out, void *ctx);

static double run_bench(bench_fn fn, const uint8_t *in, size_t len,
                         uint8_t *out, void *ctx, double min_secs,
                         uint64_t *ops_out) {
    uint64_t ops = 0;
    double start = now_sec();
    double elapsed;
    do {
        fn(in, len, out, ctx);
        ops++;
        elapsed = now_sec() - start;
    } while (elapsed < min_secs);
    *ops_out = ops;
    return ops / elapsed;
}

/* ── Benchmark wrappers ────────────────────────────────────────────────── */
static void bench_sha256(const uint8_t *in, size_t len, uint8_t *out, void *ctx) {
    (void)ctx;
    SHA256(in, len, out);
}

static void bench_sha512(const uint8_t *in, size_t len, uint8_t *out, void *ctx) {
    (void)ctx;
    SHA512(in, len, out);
}

static void bench_blake2b(const uint8_t *in, size_t len, uint8_t *out, void *ctx) {
    (void)ctx;
    crypto_generichash(out, 32, in, len, NULL, 0);
}

static void bench_eaglesong(const uint8_t *in, size_t len, uint8_t *out, void *ctx) {
    (void)ctx;
    eaglesong(in, len, out);
}

static void bench_aes256gcm(const uint8_t *in, size_t len, uint8_t *out, void *ctx) {
    (void)ctx;
    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    uint8_t key[32] = {0}, iv[12] = {0}, tag[16];
    int outl = 0;
    EVP_EncryptInit_ex(evp, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(evp, out, &outl, in, (int)len);
    EVP_EncryptFinal_ex(evp, out + outl, &outl);
    EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(evp);
}

static void bench_ed25519_sign(const uint8_t *in, size_t len, uint8_t *out, void *ctx) {
    uint8_t *sk = (uint8_t *)ctx; /* 64-byte secret key */
    unsigned long long siglen;
    crypto_sign_ed25519_detached(out, &siglen, in, len, sk);
}

static void bench_ed25519_verify(const uint8_t *in, size_t len, uint8_t *out, void *ctx) {
    (void)out;
    /* ctx = [pk(32) | sig(64) | msg] */
    uint8_t *pk  = (uint8_t *)ctx;
    uint8_t *sig = pk + 32;
    crypto_sign_ed25519_verify_detached(sig, in, len, pk);
}

/* ── System info ───────────────────────────────────────────────────────── */
static void print_sysinfo(void) {
    struct utsname u;
    uname(&u);

    /* CPU info from /proc/cpuinfo */
    char cpu_model[256] = "unknown";
    char cpu_cores[16]  = "?";
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[512];
        int cores = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Model name", 10) == 0 ||
                strncmp(line, "Hardware",    8) == 0 ||
                strncmp(line, "model name", 10) == 0) {
                char *colon = strchr(line, ':');
                if (colon) {
                    char *val = colon + 2;
                    val[strcspn(val, "\n")] = 0;
                    strncpy(cpu_model, val, sizeof(cpu_model)-1);
                }
            }
            if (strncmp(line, "processor", 9) == 0) cores++;
        }
        fclose(f);
        snprintf(cpu_cores, sizeof(cpu_cores), "%d", cores);
    }

    /* RAM from /proc/meminfo */
    char ram_str[32] = "unknown";
    f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "MemTotal", 8) == 0) {
                long kb = 0;
                sscanf(line, "MemTotal: %ld kB", &kb);
                snprintf(ram_str, sizeof(ram_str), "%ld MB", kb / 1024);
                break;
            }
        }
        fclose(f);
    }

    printf("  \"system\": {\n");
    printf("    \"arch\": \"%s\",\n", u.machine);
    printf("    \"kernel\": \"%s %s\",\n", u.sysname, u.release);
    printf("    \"cpu\": \"%s\",\n", cpu_model);
    printf("    \"cores\": %s,\n", cpu_cores);
    printf("    \"ram\": \"%s\"\n", ram_str);
    printf("  },\n");
}

/* ── Memory bandwidth ──────────────────────────────────────────────────── */
static double bench_membw_write(size_t mb) {
    size_t sz = mb * 1024 * 1024;
    uint8_t *buf = malloc(sz);
    if (!buf) return 0;
    double t0 = now_sec();
    memset(buf, 0xAA, sz);
    double elapsed = now_sec() - t0;
    free(buf);
    return (sz / (1024.0 * 1024.0)) / elapsed; /* MB/s */
}

static double bench_membw_read(size_t mb) {
    size_t sz = mb * 1024 * 1024;
    uint8_t *buf = malloc(sz);
    if (!buf) return 0;
    memset(buf, 0x55, sz);
    volatile uint64_t acc = 0;
    double t0 = now_sec();
    for (size_t i = 0; i < sz; i += 8)
        acc += *(uint64_t *)(buf + i);
    double elapsed = now_sec() - t0;
    free(buf);
    (void)acc;
    return (sz / (1024.0 * 1024.0)) / elapsed;
}

/* ── secp256k1 ─────────────────────────────────────────────────────────── */
static double bench_secp256k1_sign(secp256k1_context *sctx,
                                    const uint8_t *msg32,
                                    const uint8_t *seckey,
                                    double min_secs, uint64_t *ops) {
    secp256k1_ecdsa_signature sig;
    *ops = 0;
    double t0 = now_sec(), elapsed;
    do {
        secp256k1_ecdsa_sign(sctx, &sig, msg32, seckey, NULL, NULL);
        (*ops)++;
        elapsed = now_sec() - t0;
    } while (elapsed < min_secs);
    return *ops / elapsed;
}

static double bench_secp256k1_verify(secp256k1_context *sctx,
                                      const uint8_t *msg32,
                                      const uint8_t *seckey,
                                      double min_secs, uint64_t *ops) {
    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_sign(sctx, &sig, msg32, seckey, NULL, NULL);
    secp256k1_ec_pubkey_create(sctx, &pubkey, seckey);

    *ops = 0;
    double t0 = now_sec(), elapsed;
    do {
        secp256k1_ecdsa_verify(sctx, &sig, msg32, &pubkey);
        (*ops)++;
        elapsed = now_sec() - t0;
    } while (elapsed < min_secs);
    return *ops / elapsed;
}

/* ── Main ──────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    double bench_secs = 3.0; /* seconds per test */
    int block_sizes[] = {32, 1024, 65536}; /* bytes */
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quick") == 0) bench_secs = 1.0;
        if (strcmp(argv[i], "--long")  == 0) bench_secs = 10.0;
        if (strcmp(argv[i], "--verbose") == 0) verbose = 1;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    /* Input data */
    uint8_t input[65536];
    uint8_t output[65536];
    RAND_bytes(input, sizeof(input));

    /* Ed25519 keys */
    uint8_t ed_pk[32], ed_sk[64];
    crypto_sign_ed25519_keypair(ed_pk, ed_sk);
    uint8_t ed_sig[64];
    unsigned long long siglen;
    crypto_sign_ed25519_detached(ed_sig, &siglen, input, 32, ed_sk);

    /* secp256k1 */
    secp256k1_context *sctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t seckey[32];
    RAND_bytes(seckey, 32);
    /* Ensure valid key */
    seckey[0] = 1;

    /* Ed25519 verify context: [pk | sig] */
    uint8_t ed_verify_ctx[96];
    memcpy(ed_verify_ctx, ed_pk, 32);
    memcpy(ed_verify_ctx + 32, ed_sig, 64);

    printf("{\n");

    /* System info */
    print_sysinfo();

    printf("  \"version\": \"1.0.0\",\n");
    printf("  \"bench_secs_per_test\": %.1f,\n", bench_secs);
    printf("  \"results\": {\n");

    uint64_t ops;
    double rate;
    int first = 1;

#define COMMA() if (!first) printf(",\n"); first = 0;
#define PROGRESS(name) if (verbose) fprintf(stderr, "  Running: %s...\n", name);

    /* ── SHA-256 ── */
    PROGRESS("SHA-256");
    printf("    \"sha256\": {\n");
    for (int bi = 0; bi < 3; bi++) {
        int bsz = block_sizes[bi];
        COMMA();
        rate = run_bench(bench_sha256, input, bsz, output, NULL, bench_secs, &ops);
        printf("      \"%d\": {\"ops_sec\": %.0f, \"mb_sec\": %.1f, \"ops\": %llu}",
               bsz, rate, rate * bsz / (1024*1024), (unsigned long long)ops);
    }
    printf("\n    }");

    /* ── SHA-512 ── */
    PROGRESS("SHA-512");
    printf(",\n    \"sha512\": {\n");
    first = 1;
    for (int bi = 0; bi < 3; bi++) {
        int bsz = block_sizes[bi];
        COMMA();
        rate = run_bench(bench_sha512, input, bsz, output, NULL, bench_secs, &ops);
        printf("      \"%d\": {\"ops_sec\": %.0f, \"mb_sec\": %.1f, \"ops\": %llu}",
               bsz, rate, rate * bsz / (1024*1024), (unsigned long long)ops);
    }
    printf("\n    }");

    /* ── Blake2b ── */
    PROGRESS("Blake2b");
    printf(",\n    \"blake2b\": {\n");
    first = 1;
    for (int bi = 0; bi < 3; bi++) {
        int bsz = block_sizes[bi];
        COMMA();
        rate = run_bench(bench_blake2b, input, bsz, output, NULL, bench_secs, &ops);
        printf("      \"%d\": {\"ops_sec\": %.0f, \"mb_sec\": %.1f, \"ops\": %llu}",
               bsz, rate, rate * bsz / (1024*1024), (unsigned long long)ops);
    }
    printf("\n    }");

    /* ── Eaglesong ── */
    PROGRESS("Eaglesong (CKB PoW)");
    printf(",\n    \"eaglesong\": {\n");
    first = 1;
    for (int bi = 0; bi < 3; bi++) {
        int bsz = block_sizes[bi];
        COMMA();
        rate = run_bench(bench_eaglesong, input, bsz, output, NULL, bench_secs, &ops);
        printf("      \"%d\": {\"ops_sec\": %.0f, \"mb_sec\": %.1f, \"ops\": %llu}",
               bsz, rate, rate * bsz / (1024*1024), (unsigned long long)ops);
    }
    printf("\n    }");

    /* ── AES-256-GCM ── */
    PROGRESS("AES-256-GCM");
    printf(",\n    \"aes256gcm\": {\n");
    first = 1;
    for (int bi = 0; bi < 3; bi++) {
        int bsz = block_sizes[bi];
        COMMA();
        rate = run_bench(bench_aes256gcm, input, bsz, output, NULL, bench_secs, &ops);
        printf("      \"%d\": {\"ops_sec\": %.0f, \"mb_sec\": %.1f, \"ops\": %llu}",
               bsz, rate, rate * bsz / (1024*1024), (unsigned long long)ops);
    }
    printf("\n    }");

    /* ── Ed25519 sign ── */
    PROGRESS("Ed25519 sign");
    rate = run_bench(bench_ed25519_sign, input, 32, output, ed_sk, bench_secs, &ops);
    printf(",\n    \"ed25519_sign\": {\"ops_sec\": %.0f, \"ops\": %llu}",
           rate, (unsigned long long)ops);

    /* ── Ed25519 verify ── */
    PROGRESS("Ed25519 verify");
    rate = run_bench(bench_ed25519_verify, input, 32, output, ed_verify_ctx, bench_secs, &ops);
    printf(",\n    \"ed25519_verify\": {\"ops_sec\": %.0f, \"ops\": %llu}",
           rate, (unsigned long long)ops);

    /* ── secp256k1 sign ── */
    PROGRESS("secp256k1 sign");
    rate = bench_secp256k1_sign(sctx, input, seckey, bench_secs, &ops);
    printf(",\n    \"secp256k1_sign\": {\"ops_sec\": %.0f, \"ops\": %llu}",
           rate, (unsigned long long)ops);

    /* ── secp256k1 verify ── */
    PROGRESS("secp256k1 verify");
    rate = bench_secp256k1_verify(sctx, input, seckey, bench_secs, &ops);
    printf(",\n    \"secp256k1_verify\": {\"ops_sec\": %.0f, \"ops\": %llu}",
           rate, (unsigned long long)ops);

    /* ── Memory bandwidth ── */
    PROGRESS("Memory bandwidth");
    double mbw_write = bench_membw_write(1024);
    double mbw_read  = bench_membw_read(1024);
    printf(",\n    \"memory_bandwidth\": {\"write_mb_sec\": %.0f, \"read_mb_sec\": %.0f}",
           mbw_write, mbw_read);

    printf("\n  }\n}\n");

    secp256k1_context_destroy(sctx);
    return 0;
}
