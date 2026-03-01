# wyltek-bench

Single-binary cryptographic benchmark for SBCs and embedded hosts. JSON output. No dependencies.

Covers the algorithms used in the Nervos CKB ecosystem: Eaglesong PoW, Blake2b, secp256k1, SHA-2, AES-256-GCM, Ed25519.

---

## Build

```bash
gcc -O2 -o wyltek-bench src/bench.c src/eaglesong.c \
    $(pkg-config --cflags --libs libssl libcrypto libsodium)
```

Or use the Makefile:
```bash
make
./wyltek-bench
```

---

## Output

JSON to stdout, one object per run:

```json
{
  "system": { "arch": "aarch64", "cpu": "...", "cores": 4 },
  "results": {
    "eaglesong":    { "32": { "ops_sec": 83703, "mb_sec": 2.5, "ops": 83703 } },
    "blake2b":      { "32": { "ops_sec": 674907, ... } },
    "sha256":       { "32": { "ops_sec": 134265, ... } },
    "secp256k1_sign":   { "ops_sec": 8240, "ops": 8240 },
    "secp256k1_verify": { "ops_sec": 4720, "ops": 4720 },
    "ed25519_sign":     { "ops_sec": 12800, "ops": 12800 }
  }
}
```

Save results:
```bash
./wyltek-bench > results/$(uname -m).json
```

---

## Results

| Board | Eaglesong/s | Blake2b/s | SHA-256/s | AES-256-GCM/s |
|---|---|---|---|---|
| OPi3B (RK3566, aarch64) | 83,703 | 674,907 | 134,265 | 138,995 |
| OPi5+ (RK3588S, aarch64) | 574,000 | 2,900,000 | 1,400,000 | — |
| N100 (Intel, x86_64) | 829,502 | 3,852,583 | 2,547,018 | 1,155,999 |

**N100 secp256k1**: 18,196 sign/s · 11,354 verify/s  
**N100 Ed25519**: 32,050 sign/s · 9,350 verify/s

32-byte input. 1 second per test.

---

## Algorithms

| Algorithm | Use in CKB | Source |
|---|---|---|
| **Eaglesong** | Block PoW hash | Built-in (reference impl) |
| **Blake2b-256** | Transaction hash, signing hash | libsodium |
| **SHA-256 / SHA-512** | Script verification | OpenSSL |
| **AES-256-GCM** | Key storage (firmware) | OpenSSL |
| **secp256k1** | Transaction signing | libsecp256k1 via OpenSSL |
| **Ed25519** | Fiber channel signing | libsodium |

---

## Planned

- [ ] Leaderboard web UI (Cloudflare Pages + API)
- [ ] ESP32/P4 build variant (no OpenSSL — uses trezor-crypto / hardware accel)
- [ ] ARM NEON / SVE optimised Eaglesong path

---

## License

MIT
