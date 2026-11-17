# cbcrypto

The Rust core of **cbgram**: MTProto crypto **and** the file download/upload engine in one compiled
extension. cbgram uses it as its only crypto backend (no fallback).

## Crypto

| function | what it is |
|---|---|
| `ige256_encrypt/decrypt` | AES-256-IGE, hand-written AES-NI kernel (critical path = 1 XOR + 14 AES rounds per block) |
| `ctr256_encrypt/decrypt` (+ `_inplace`, `_batch`) | AES-256-CTR for obfuscated transports: **VAES (256-bit) and AVX-512 VAES (512-bit) kernels**, AES-NI otherwise, 8-32 blocks in flight |
| `kdf` | MTProto 2.0 key derivation |
| `pack_message` | fused: padding + SHA-256 msg_key + KDF + IGE, written straight into the output `bytes` |
| `unpack_message` | fused: IGE decrypt **interleaved with** SHA-256 of the plaintext, then all MTProto checks |
| `backend()` | which acceleration this build really uses (`aes_ni`, `sha_ni`, `vaes`, `vaes512`, ...) |
| `_after_fork()` | registered automatically at import via `os.register_at_fork`, so a forked child never replays its parent's buffered padding randomness |

* VAES / AVX-512 are detected at run time (CPUID + OS support); nothing needs a special build flag.
* AES-256 key schedules are cached per thread (a large share of the cost of small messages).
* Padding randomness comes from the OS CSPRNG in per-thread 2 KiB batches, handed out once and wiped.
* The GIL is released for anything >= 8 KiB.

## Transfer engine

| function | what it does |
|---|---|
| `download(...)` | whole-file download: TCP sockets, obfuscated transport, MTProto session, acks/salts/flood waits, reconnects, adaptive pacing, zero-copy positional file writes. No Python, no GIL |
| `upload(...)` | whole-file upload (`saveBigFilePart` / `saveFilePart`), same machinery |

Python keeps everything else (sessions and auth keys, DC lookup, TL request templates, progress
callbacks, error mapping, fallback for what the engine does not cover). See cbgram's
`pyrogram/core_transfer.py` and `RUST_CORE.md`.

* many connections, a pipeline of requests per connection, one shared adaptive pacer
* `FLOOD_WAIT_n` is waited out (per-wait and total caps), 5xx is retried, wrong salt and clock skew are
  corrected, dropped connections reopen on a fresh session and the lost chunks are re-queued
* errors arrive as `cbcrypto.CoreError(kind, code, message)`; a transfer can never "succeed" with
  missing data (completeness is verified)
* the progress callback is polled ~25x/s; raising from it (e.g. `StopTransmission`) cancels the transfer
* `CBCRYPTO_DEBUG=1` prints a per-request trace to stderr

Not covered by the engine (cbgram's Python path handles it): the auth-key handshake, proxies, CDN
downloads, in-memory/stream targets, resuming a partial upload.

## Install

Linux x86-64 (glibc >= 2.34): `pip install cbcrypto-<version>-cp38-abi3-manylinux_2_34_x86_64.whl`

From source (Linux, macOS, Termux): `./build.sh` (needs Rust >= 1.70).

## Platforms

| platform | AES / SHA | status |
|---|---|---|
| x86-64, AES-NI (+VAES / AVX-512 / SHA-NI when present) | own kernels | **tested** |
| x86-64 without AES-NI | RustCrypto software | portable path tested |
| aarch64 (Termux, Apple Silicon, Graviton) | RustCrypto + ARMv8 crypto (`--cfg aes_armv8`), `sha2` asm backend | compiles as portable code, **not run on ARM yet** |

Never tested against real Telegram servers, only against the mock DC.

## Native TL codec (0.4)

`tl_init`, `tl_parse`, `tl_write` decode and encode whole TL object trees in one native pass
(instead of one interpreter call per field), driven by a schema table that cbgram's compiler
emits (`pyrogram/raw/tl_spec.py`). Containers, gzip and bare vectors are handled natively;
anything outside the table (legacy constructors, subclasses overriding `write`) falls back to
the generated Python classes. Measured 3-4x faster parsing and ~3x faster serialising on
realistic payloads, 5x on small service messages.

`factorize_pq(pq) -> (p, q)` is a Pollard-Brent factoriser for the handshake (GIL released);
~15-120x faster than the pure-Python one.
