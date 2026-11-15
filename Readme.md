# cbcrypto

Fast MTProto crypto for **wzgram** — a drop-in replacement for `warpcrypto`
(same function names, argument types, return values and error messages), written in Rust.

| function | what it is |
|---|---|
| `ige256_encrypt/decrypt` | AES-256-IGE (hand-written AES-NI kernel, critical path = 1 XOR + 14 AES rounds/block) |
| `ctr256_encrypt/decrypt` (+ `_inplace`, `_batch`) | AES-256-CTR for obfuscated transports, 8 blocks in flight |
| `kdf` | MTProto 2.0 key derivation |
| `pack_message` | fused: padding + SHA-256 msg_key + KDF + IGE, written straight into the output `bytes` |
| `unpack_message` | fused: IGE decrypt **interleaved with** SHA-256 of the plaintext, then all MTProto checks |
| `backend()` | tells you which CPU acceleration this build really uses |

The GIL is released for anything ≥ 8 KiB, so wzgram's crypto thread pool runs in parallel.

## Install

**Linux x86-64 (Heroku, VPS):** `pip install cbcrypto-0.1.0-cp38-abi3-manylinux_2_34_x86_64.whl`
(needs glibc ≥ 2.34: Heroku-22/24, Ubuntu 22.04+, Debian 12+).

**From source (any platform):**
```bash
# needs Rust >= 1.70 (rustup.rs, or `pkg install rust` on Termux)
./build.sh            # builds and installs into the current Python
python -c "import cbcrypto; print(cbcrypto.backend())"
```

wzgram picks it up automatically (`WZGRAM_CRYPTO=warpcrypto` forces the old backend).
If cbcrypto is missing, fails to import, or fails its self-test, wzgram silently keeps using warpcrypto.

## Verify before you trust it

```bash
pip install warpcrypto cryptography
python tests/test_vs_warpcrypto.py                    # byte-for-byte vs warpcrypto, AES-NI path
CBCRYPTO_GENERIC=1 python tests/test_vs_warpcrypto.py # same, forced portable path
python tests/bench.py                                 # speed comparison on YOUR machine
```
The test covers IGE/CTR/KDF, CTR iv/state tracking across random call sequences, batch,
pack<->unpack across both libraries, every body size 0..2200 (all SHA padding cases),
and ~15 malformed-packet cases (same exception types and messages as warpcrypto).

## Platforms

| platform | AES | SHA-256 | status |
|---|---|---|---|
| x86-64 with AES-NI | own AES-NI kernels | SHA-NI if present (runtime detection) | **tested** |
| x86-64 without AES-NI | RustCrypto `aes` (software) | software | portable path tested |
| aarch64 (Termux phone, Apple Silicon, Graviton) | RustCrypto `aes` + ARMv8 crypto ext. (`--cfg aes_armv8`, set in `.cargo/config.toml`) | `sha2` aarch64 asm backend | **compiles as portable code, NOT run on ARM yet** — please run the tests and `bench.py` on your phone |

On ARM the fused decrypt+SHA overlap is plain 4-block grouping (no hand-written NEON kernel yet),
so expect parity-to-modest gains there; `backend()` shows whether hardware AES/SHA2 was detected.

## Security notes
No custom cryptographic primitives: AES rounds are the CPU's own instructions (AES-NI / ARMv8),
SHA-256 comes from the audited RustCrypto `sha2` crate. cbcrypto only implements the IGE/CTR *modes*
and MTProto framing, and is checked against warpcrypto on every build you run `tests/` on.
