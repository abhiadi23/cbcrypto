<div align="center">

<img src="assets/logo (1).png" alt="cbcrypto" width="420">

<br><br>

### ***Fast MTProto crypto and file transfer engine, written in Rust.***
**The Rust core behind cbgram**

<br>

![Rust](https://img.shields.io/badge/CORE-Rust-EA580C?style=for-the-badge&logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/PYTHON-3.8%2B-D97706?style=for-the-badge&logo=python&logoColor=white)
![Release](https://img.shields.io/badge/RELEASE-v0.5.1-F59E0B?style=for-the-badge)
![abi3](https://img.shields.io/badge/WHEEL-abi3-C2410C?style=for-the-badge)

<br>

**[Features](#-features)** &nbsp;·&nbsp; **[Install](#-install)** &nbsp;·&nbsp; **[Verify](#-verify-your-install)** &nbsp;·&nbsp; **[Build](#-build-from-source)** &nbsp;·&nbsp; **[Used by](#-used-by)**

</div>

<br>

---

## ✦ &nbsp;**About**

**cbcrypto** is a compact **Rust extension for Python** that handles the *performance-critical* parts of **MTProto**: encryption, key derivation, and the entire file download and upload engine.

It is the engine that powers **[cbgram](https://github.com/abhiadi23/cbgram)**, but it is its own package, so anything that needs *fast MTProto crypto* can use it.

<br>

## ✦ &nbsp;**Features**

| | **Feature** | |
|:---:|:---|:---|
| 🔐 | **MTProto crypto** | *AES-IGE and AES-CTR with MTProto key derivation.* |
| 📦 | **Fused pack / unpack** | *Encrypt and frame messages in a single fast step.* |
| ⬇️ | **Download engine** | *Sockets, transport, acks, salts, flood waits, reconnects, pacing and file writes, all in Rust.* |
| ⬆️ | **Upload engine** | *The same engine for sending files, driven by a request template from Python.* |
| 🧵 | **No GIL contention** | *Transfers run on real threads, so multiple cores actually get used.* |
| 📝 | **Zero-copy writes** | *Data goes to disk without extra buffer shuffling.* |
| 🏎️ | **Hardware acceleration** | *Uses AES-NI, and VAES on newer CPUs.* |
| 🧰 | **abi3 wheels** | *One wheel works across Python 3.8 and newer.* |

<br>

## ✦ &nbsp;**Install**

**Prebuilt wheel** &nbsp;*(Linux x86_64 · Python 3.8+)*

```bash
pip install https://github.com/abhiadi23/cbcrypto/releases/download/v0.5.1/cbcrypto-0.5.1-cp38-abi3-manylinux_2_28_x86_64.whl
```

**From source** &nbsp;*(needs Rust)*

```bash
pip install git+https://github.com/abhiadi23/cbcrypto.git
```

**In `requirements.txt`**

```text
cbcrypto @ https://github.com/abhiadi23/cbcrypto/releases/download/v0.5.1/cbcrypto-0.5.1-cp38-abi3-manylinux_2_28_x86_64.whl
```

> **Using cbgram?** You do not need to install this by hand, because cbcrypto is a dependency of cbgram.

<br>

## ✦ &nbsp;**Verify your install**

```bash
python -c "import cbcrypto; print(cbcrypto.__version__, cbcrypto.backend())"
```

You should see **`aes_ni=true`** in the output, and **`vaes=true`** on newer CPUs.

<br>

## ✦ &nbsp;**Build from source**

For platforms with no prebuilt wheel, such as ***Termux*** and other Linux or ARM setups:

```bash
git clone https://github.com/abhiadi23/cbcrypto
cd cbcrypto
./build.sh
```

> Building requires a **Rust toolchain**. Get it from [rustup.rs](https://rustup.rs).

<br>

## ✦ &nbsp;**Performance, honestly**

- ⚙️ &nbsp;***About 3 ms per MiB on one core*** &nbsp;*(≈ 340 MiB/s per core, x86-64 test VM).*
- 🤝 &nbsp;***Per core, it is in the same ballpark as pure Python.*** &nbsp;*Crypto and kernel copies dominate.*
- 🚀 &nbsp;***The real win*** is *no GIL contention, real multi-core use and zero-copy writes*, not a faster network.
- 🧪 &nbsp;*Tested against a mock Telegram DC with wrong salts, clock skew, flood waits, 5xx errors, dropped connections, gzip, CDN redirects and cancellation.*

<br>

## ✦ &nbsp;**Used by**

**[cbgram](https://github.com/abhiadi23/cbgram)** &nbsp;·&nbsp; *Elegant, async Telegram MTProto framework for users and bots.*

<br>

## ✦ &nbsp;**Resources**

- 🔒 &nbsp;*[Source code](https://github.com/abhiadi23/cbcrypto)*
- 📦 &nbsp;*[Releases](https://github.com/abhiadi23/cbcrypto/releases)*
- 🐞 &nbsp;*[Issues](https://github.com/abhiadi23/cbcrypto/issues)*

<br>

---

<div align="center">

***Made with ♥ by [abhiadi23](https://github.com/abhiadi23)***

</div>
