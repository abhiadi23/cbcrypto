//! cbcrypto - fast MTProto crypto for cbgram.
//!
//! return values and error messages) with a faster fused `unpack_message`.
//!
//! Why it can beat a plain "decrypt, then hash" implementation:
//! AES-IGE is one long dependency chain (every block needs the previous one),
//! so the CPU's AES units sit mostly idle. `unpack_message` feeds the SHA-256
//! of the plaintext group by group while the next group is still decrypting, so
//! the out-of-order core overlaps the two jobs instead of running them
//! back to back.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use pyo3::exceptions::{PyOverflowError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyByteArray, PyBytes};
use sha2::digest::generic_array::{typenum::U64, GenericArray as ShaBlock};
use sha2::{Digest, Sha256};

mod engine;

type Block = GenericArray<u8, aes::cipher::consts::U16>;

/// Below this size the GIL is kept (releasing it costs more than the work).
const GIL_THRESHOLD: usize = 8 * 1024;
/// AES blocks decrypted between two SHA-256 feeds in the fused unpack.
const FUSE_GROUP_BLOCKS: usize = 4;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// ---------------------------------------------------------------- helpers

#[inline(always)]
fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    (u128::from_ne_bytes(*a) ^ u128::from_ne_bytes(*b)).to_ne_bytes()
}

fn verr<T>(msg: &str) -> PyResult<T> {
    Err(PyValueError::new_err(msg.to_string()))
}

fn check_len(name: &str, got: usize, want: usize) -> PyResult<()> {
    if got != want {
        return verr(&format!("{} must be {} bytes", name, want));
    }
    Ok(())
}

/// Run `f` without the GIL when the job is big enough to matter.
fn maybe_nogil<R: Send, F: FnOnce() -> R + Send>(py: Python<'_>, size: usize, f: F) -> R {
    if size >= GIL_THRESHOLD {
        py.allow_threads(f)
    } else {
        f()
    }
}


// ---------------------------------------------------------------- x86-64 AES-NI path

#[cfg(target_arch = "x86_64")]
mod ni {
    //! Hand-written AES-NI kernels. The AES-IGE chain is latency bound: every
    //! block needs the previous block's output, so the only things that matter are
    //! (a) a critical path of exactly 1 XOR + 14 AES rounds per block and (b) keeping
    //! the round keys in registers. Everything that does not depend on the previous
    //! block (the "p_{i+1} ^ p_{i-1} ^ rk0" whitening) is computed off that path.
    use core::arch::x86_64::*;

    pub type Rk = [__m128i; 15];

    #[inline]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn ks1(t1: __m128i, t2: __m128i) -> __m128i {
        let t2 = _mm_shuffle_epi32(t2, 0xff);
        let mut t4 = _mm_slli_si128(t1, 4);
        let mut t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 4);
        t1 = _mm_xor_si128(t1, t4);
        _mm_xor_si128(t1, t2)
    }

    #[inline]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn ks2(t1: __m128i, t3: __m128i) -> __m128i {
        let t4 = _mm_aeskeygenassist_si128(t1, 0);
        let t2 = _mm_shuffle_epi32(t4, 0xaa);
        let mut t4 = _mm_slli_si128(t3, 4);
        let mut t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 4);
        t3 = _mm_xor_si128(t3, t4);
        _mm_xor_si128(t3, t2)
    }

    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn expand(key: &[u8]) -> Rk {
        let mut rk = [_mm_setzero_si128(); 15];
        rk[0] = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        rk[1] = _mm_loadu_si128(key.as_ptr().add(16) as *const __m128i);
        macro_rules! round {
            ($i:expr, $rcon:expr) => {
                rk[$i] = ks1(rk[$i - 2], _mm_aeskeygenassist_si128(rk[$i - 1], $rcon));
                rk[$i + 1] = ks2(rk[$i], rk[$i - 1]);
            };
        }
        round!(2, 0x01);
        round!(4, 0x02);
        round!(6, 0x04);
        round!(8, 0x08);
        round!(10, 0x10);
        round!(12, 0x20);
        rk[14] = ks1(rk[12], _mm_aeskeygenassist_si128(rk[13], 0x40));
        rk
    }

    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn dec_keys(rk: &Rk) -> Rk {
        let mut dk = *rk;
        dk[0] = rk[14];
        for i in 1..14 {
            dk[i] = _mm_aesimc_si128(rk[14 - i]);
        }
        dk[14] = rk[0];
        dk
    }

    #[inline(always)]
    unsafe fn ld(p: *const u8) -> __m128i {
        _mm_loadu_si128(p as *const __m128i)
    }
    #[inline(always)]
    unsafe fn st(p: *mut u8, v: __m128i) {
        _mm_storeu_si128(p as *mut __m128i, v)
    }

    /// AES-IGE encrypt `n` blocks, `src` -> `dst` (may be the same pointer).
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn ige_enc(rk: &Rk, iv: &[u8], src: *const u8, dst: *mut u8, n: usize) {
        if n == 0 {
            return;
        }
        let y = ld(iv.as_ptr());
        let mut p_prev = ld(iv.as_ptr().add(16));
        let mut p_cur = ld(src);
        let rk0 = rk[0];
        let rk14 = rk[14];
        let mut s = _mm_xor_si128(_mm_xor_si128(p_cur, y), rk0);
        for i in 0..n {
            let mut b = _mm_aesenc_si128(s, rk[1]);
            b = _mm_aesenc_si128(b, rk[2]);
            b = _mm_aesenc_si128(b, rk[3]);
            b = _mm_aesenc_si128(b, rk[4]);
            b = _mm_aesenc_si128(b, rk[5]);
            b = _mm_aesenc_si128(b, rk[6]);
            b = _mm_aesenc_si128(b, rk[7]);
            b = _mm_aesenc_si128(b, rk[8]);
            b = _mm_aesenc_si128(b, rk[9]);
            b = _mm_aesenc_si128(b, rk[10]);
            b = _mm_aesenc_si128(b, rk[11]);
            b = _mm_aesenc_si128(b, rk[12]);
            b = _mm_aesenc_si128(b, rk[13]);
            // The final AES round ends with an XOR of the round key, so `e ^ t`
            // == aesenclast(b, rk14 ^ t): the chaining XOR moves off the critical
            // path (it is folded into a key that only depends on inputs).
            let p_next = if i + 1 < n { ld(src.add(16 * (i + 1))) } else { p_cur };
            st(dst.add(16 * i), _mm_aesenclast_si128(b, _mm_xor_si128(rk14, p_prev))); // c_i = e_i ^ p_{i-1}
            s = _mm_aesenclast_si128(b, _mm_xor_si128(rk14, _mm_xor_si128(_mm_xor_si128(p_next, p_prev), rk0)));
            p_prev = p_cur;
            p_cur = p_next;
        }
    }

    /// AES-IGE decrypt `n` blocks. When `hash` is given, the plaintext (which lives
    /// at `dst`, preceded by 32 prefix bytes at `dst - 32`) is fed to SHA-256 every
    /// 64 bytes, interleaved with the AES chain so the CPU overlaps them.
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn ige_dec(
        dk: &Rk,
        iv: &[u8],
        src: *const u8,
        dst: *mut u8,
        n: usize,
        mut hash: Option<(&mut [u32; 8], &mut usize)>,
    ) {
        if n == 0 {
            return;
        }
        let mut c_prev = ld(iv.as_ptr());
        let _p0 = ld(iv.as_ptr().add(16));
        let mut c_cur = ld(src);
        let dk0 = dk[0];
        let dk14 = dk[14];
        let mut s = _mm_xor_si128(_mm_xor_si128(c_cur, _p0), dk0);
        for i in 0..n {
            let mut b = _mm_aesdec_si128(s, dk[1]);
            b = _mm_aesdec_si128(b, dk[2]);
            b = _mm_aesdec_si128(b, dk[3]);
            b = _mm_aesdec_si128(b, dk[4]);
            b = _mm_aesdec_si128(b, dk[5]);
            b = _mm_aesdec_si128(b, dk[6]);
            b = _mm_aesdec_si128(b, dk[7]);
            b = _mm_aesdec_si128(b, dk[8]);
            b = _mm_aesdec_si128(b, dk[9]);
            b = _mm_aesdec_si128(b, dk[10]);
            b = _mm_aesdec_si128(b, dk[11]);
            b = _mm_aesdec_si128(b, dk[12]);
            b = _mm_aesdec_si128(b, dk[13]);
            let c_next = if i + 1 < n { ld(src.add(16 * (i + 1))) } else { c_cur };
            st(dst.add(16 * i), _mm_aesdeclast_si128(b, _mm_xor_si128(dk14, c_prev))); // p_i = D_i ^ c_{i-1}
            s = _mm_aesdeclast_si128(b, _mm_xor_si128(dk14, _mm_xor_si128(_mm_xor_si128(c_next, c_prev), dk0)));
            c_prev = c_cur;
            c_cur = c_next;
            if let Some((sha, hashed)) = hash.as_mut() {
                let avail = (32 + 16 * (i + 1)) / 128 * 128;
                if avail > **hashed {
                    let base = dst.sub(32);
                    let blocks = core::slice::from_raw_parts(base.add(**hashed), avail - **hashed);
                    super::sha_compress(sha, blocks);
                    **hashed = avail;
                }
            }
        }
    }

    #[inline(always)]
    unsafe fn enc_one(rk: &Rk, x: __m128i) -> __m128i {
        let mut b = _mm_xor_si128(x, rk[0]);
        for k in 1..14 {
            b = _mm_aesenc_si128(b, rk[k]);
        }
        _mm_aesenclast_si128(b, rk[14])
    }


    // ---- VAES (256-bit AES, two blocks per instruction) --------------------
    // `vaesenc ymm` needs the unstable `vaes` target feature on old rustc, so the
    // instructions are emitted with inline asm (stable since 1.59). Pure + nomem
    // lets the compiler schedule them like intrinsics.
    macro_rules! vaesenc {
        ($a:expr, $k:expr) => {{
            let mut r: __m256i = $a;
            core::arch::asm!("vaesenc {r}, {r}, {k}", r = inout(ymm_reg) r, k = in(ymm_reg) $k,
                options(pure, nomem, nostack, preserves_flags));
            r
        }};
    }
    macro_rules! vaesenclast {
        ($a:expr, $k:expr) => {{
            let mut r: __m256i = $a;
            core::arch::asm!("vaesenclast {r}, {r}, {k}", r = inout(ymm_reg) r, k = in(ymm_reg) $k,
                options(pure, nomem, nostack, preserves_flags));
            r
        }};
    }

    /// True if the CPU (and OS) can run 256-bit VAES. cpuid bit is cached.
    pub fn has_vaes() -> bool {
        use std::sync::atomic::{AtomicU8, Ordering};
        static C: AtomicU8 = AtomicU8::new(0);
        match C.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                let ok = std::arch::is_x86_feature_detected!("avx2")
                    && std::arch::is_x86_feature_detected!("aes")
                    && unsafe { __cpuid_count(7, 0).ecx } & (1 << 9) != 0;
                C.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
                ok
            }
        }
    }

    // Explicit unrolling (the compiler would not unroll loops around the asm, then
    // keeps the block array on the stack, which costs a store-forward per round).
    macro_rules! unroll {
        ($n:expr, $j:ident, $body:block) => {
            if $n > 0 { let $j = 0usize; $body }
            if $n > 1 { let $j = 1usize; $body }
            if $n > 2 { let $j = 2usize; $body }
            if $n > 3 { let $j = 3usize; $body }
            if $n > 4 { let $j = 4usize; $body }
            if $n > 5 { let $j = 5usize; $body }
            if $n > 6 { let $j = 6usize; $body }
            if $n > 7 { let $j = 7usize; $body }
        };
    }

    /// N ymm registers = 2N counter blocks, src -> dst (may alias).
    #[inline]
    #[target_feature(enable = "avx,avx2")]
    unsafe fn ctr_step<const N: usize>(
        rkv: &[__m256i; 15],
        swap: __m256i,
        ctr: &mut u128,
        src: *const u8,
        dst: *mut u8,
    ) {
        let c = *ctr;
        let lo = c as u64;
        let hi = (c >> 64) as u64;
        let rk0 = rkv[0];
        let mut b = [_mm256_setzero_si256(); N];
        if lo <= u64::MAX - 2 * N as u64 {
            let base = _mm256_set_epi64x(hi as i64, (lo + 1) as i64, hi as i64, lo as i64);
            unroll!(N, j, {
                let inc = 2 * j as i64;
                let v = _mm256_add_epi64(base, _mm256_set_epi64x(0, inc, 0, inc));
                b[j] = _mm256_xor_si256(_mm256_shuffle_epi8(v, swap), rk0);
            });
        } else {
            // 64-bit carry inside this group: build the counters the slow way
            for j in 0..N {
                let mut t = [0u8; 32];
                t[..16].copy_from_slice(&c.wrapping_add(2 * j as u128).to_be_bytes());
                t[16..].copy_from_slice(&c.wrapping_add(2 * j as u128 + 1).to_be_bytes());
                b[j] = _mm256_xor_si256(_mm256_loadu_si256(t.as_ptr() as *const __m256i), rk0);
            }
        }
        for r in 1..14 {
            let k = rkv[r];
            unroll!(N, j, {
                b[j] = vaesenc!(b[j], k);
            });
        }
        let kl = rkv[14];
        unroll!(N, j, {
            let x = _mm256_loadu_si256(src.add(32 * j) as *const __m256i);
            // data ^ aesenclast(b, k) == aesenclast(b, k ^ data)
            let o = vaesenclast!(b[j], _mm256_xor_si256(kl, x));
            _mm256_storeu_si256(dst.add(32 * j) as *mut __m256i, o);
        });
        *ctr = c.wrapping_add(2 * N as u128);
    }


    /// AVX-512 + VAES available (512-bit AES: four blocks per instruction)?
    pub fn has_vaes512() -> bool {
        use std::sync::atomic::{AtomicU8, Ordering};
        static C: AtomicU8 = AtomicU8::new(0);
        match C.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                let ok = std::arch::is_x86_feature_detected!("avx512f")
                    && std::arch::is_x86_feature_detected!("avx512bw")
                    && std::arch::is_x86_feature_detected!("aes")
                    && unsafe { __cpuid_count(7, 0).ecx } & (1 << 9) != 0;
                C.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
                ok
            }
        }
    }

    /// `iters` x 32 blocks (512 bytes) of CTR, src -> dst, using zmm registers.
    /// The asm uses explicit zmm names (the compiler only sees ymm clobbers, since
    /// the `avx512f` target feature is unstable on old rustc). Counters are kept
    /// little-endian in a zmm and byte-swapped per block. The caller guarantees the
    /// low 64 bits of the counter do not wrap during these iterations.
    #[target_feature(enable = "avx,avx2")]
    pub unsafe fn ctr_zmm(rk: &Rk, ctr: u128, src: *const u8, dst: *mut u8, iters: usize) {
        let lo = ctr as u64;
        let hi = (ctr >> 64) as u64;
        let cnt: [u64; 8] = [lo, hi, lo + 1, hi, lo + 2, hi, lo + 3, hi];
        static SWAP: [u8; 64] = {
            let mut a = [0u8; 64];
            let mut i = 0;
            while i < 64 {
                a[i] = (15 - (i % 16)) as u8;
                i += 1;
            }
            a
        };
        static INC: [u64; 8] = [4, 0, 4, 0, 4, 0, 4, 0];
        core::arch::asm!(
            "vmovdqu64 zmm10, zmmword ptr [{cnt}]",
            "vmovdqu64 zmm14, zmmword ptr [{swap}]",
            "vmovdqu64 zmm13, zmmword ptr [{inc}]",
            "vbroadcasti32x4 zmm15, xmmword ptr [{rk}]",
            "2:",
            "vpshufb zmm0, zmm10, zmm14", "vpxorq zmm0, zmm0, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "vpshufb zmm1, zmm10, zmm14", "vpxorq zmm1, zmm1, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "vpshufb zmm2, zmm10, zmm14", "vpxorq zmm2, zmm2, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "vpshufb zmm3, zmm10, zmm14", "vpxorq zmm3, zmm3, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "vpshufb zmm4, zmm10, zmm14", "vpxorq zmm4, zmm4, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "vpshufb zmm5, zmm10, zmm14", "vpxorq zmm5, zmm5, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "vpshufb zmm6, zmm10, zmm14", "vpxorq zmm6, zmm6, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "vpshufb zmm7, zmm10, zmm14", "vpxorq zmm7, zmm7, zmm15", "vpaddq zmm10, zmm10, zmm13",
            "lea {kp}, [{rk} + 16]",
            "mov {rn}, 13",
            "3:",
            "vbroadcasti32x4 zmm8, xmmword ptr [{kp}]",
            "vaesenc zmm0, zmm0, zmm8", "vaesenc zmm1, zmm1, zmm8", "vaesenc zmm2, zmm2, zmm8", "vaesenc zmm3, zmm3, zmm8",
            "vaesenc zmm4, zmm4, zmm8", "vaesenc zmm5, zmm5, zmm8", "vaesenc zmm6, zmm6, zmm8", "vaesenc zmm7, zmm7, zmm8",
            "add {kp}, 16",
            "dec {rn}",
            "jnz 3b",
            "vbroadcasti32x4 zmm8, xmmword ptr [{kp}]",
            "vpxorq zmm9, zmm8, zmmword ptr [{src}]",       "vaesenclast zmm0, zmm0, zmm9", "vmovdqu64 zmmword ptr [{dst}], zmm0",
            "vpxorq zmm9, zmm8, zmmword ptr [{src} + 64]",  "vaesenclast zmm1, zmm1, zmm9", "vmovdqu64 zmmword ptr [{dst} + 64], zmm1",
            "vpxorq zmm9, zmm8, zmmword ptr [{src} + 128]", "vaesenclast zmm2, zmm2, zmm9", "vmovdqu64 zmmword ptr [{dst} + 128], zmm2",
            "vpxorq zmm9, zmm8, zmmword ptr [{src} + 192]", "vaesenclast zmm3, zmm3, zmm9", "vmovdqu64 zmmword ptr [{dst} + 192], zmm3",
            "vpxorq zmm9, zmm8, zmmword ptr [{src} + 256]", "vaesenclast zmm4, zmm4, zmm9", "vmovdqu64 zmmword ptr [{dst} + 256], zmm4",
            "vpxorq zmm9, zmm8, zmmword ptr [{src} + 320]", "vaesenclast zmm5, zmm5, zmm9", "vmovdqu64 zmmword ptr [{dst} + 320], zmm5",
            "vpxorq zmm9, zmm8, zmmword ptr [{src} + 384]", "vaesenclast zmm6, zmm6, zmm9", "vmovdqu64 zmmword ptr [{dst} + 384], zmm6",
            "vpxorq zmm9, zmm8, zmmword ptr [{src} + 448]", "vaesenclast zmm7, zmm7, zmm9", "vmovdqu64 zmmword ptr [{dst} + 448], zmm7",
            "add {src}, 512",
            "add {dst}, 512",
            "dec {it}",
            "jnz 2b",
            "vzeroupper",
            cnt = in(reg) cnt.as_ptr(),
            swap = in(reg) SWAP.as_ptr(),
            inc = in(reg) INC.as_ptr(),
            rk = in(reg) rk.as_ptr(),
            kp = out(reg) _,
            rn = out(reg) _,
            src = inout(reg) src => _,
            dst = inout(reg) dst => _,
            it = inout(reg) iters => _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm13") _,
            out("ymm14") _, out("ymm15") _,
            options(nostack),
        );
    }

    pub type Rkv = [__m256i; 15];

    /// Round keys duplicated into both 128-bit lanes (for the VAES kernel).
    #[target_feature(enable = "avx,avx2")]
    pub unsafe fn bcast_keys(rk: &Rk) -> Rkv {
        let mut rkv = [_mm256_setzero_si256(); 15];
        for i in 0..15 {
            rkv[i] = _mm256_broadcastsi128_si256(rk[i]);
        }
        rkv
    }

    /// CTR over whole blocks with VAES: 16 blocks in flight, src -> dst.
    #[target_feature(enable = "avx,avx2,aes,sse2,ssse3")]
    pub unsafe fn ctr_blocks_vaes(rk: &Rk, rkv: &Rkv, ctr: &mut u128, src: *const u8, dst: *mut u8, mut nblocks: usize) {
        let swap = _mm256_broadcastsi128_si256(_mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
        // local copy: lets the compiler assume the keys do not alias `dst`
        let rkv_local: Rkv = *rkv;
        let rkv = &rkv_local;
        let (mut s, mut d) = (src, dst);
        if nblocks >= 32 && has_vaes512() {
            // stay clear of a 64-bit counter wrap inside the asm loop
            let safe = ((u64::MAX - *ctr as u64) / 32) as usize;
            let it = (nblocks / 32).min(safe);
            if it > 0 {
                ctr_zmm(rk, *ctr, s, d, it);
                *ctr = ctr.wrapping_add(32 * it as u128);
                s = s.add(512 * it);
                d = d.add(512 * it);
                nblocks -= 32 * it;
            }
        }
        while nblocks >= 16 {
            ctr_step::<8>(rkv, swap, ctr, s, d);
            s = s.add(256);
            d = d.add(256);
            nblocks -= 16;
        }
        while nblocks >= 4 {
            ctr_step::<2>(rkv, swap, ctr, s, d);
            s = s.add(64);
            d = d.add(64);
            nblocks -= 4;
        }
        while nblocks >= 2 {
            ctr_step::<1>(rkv, swap, ctr, s, d);
            s = s.add(32);
            d = d.add(32);
            nblocks -= 2;
        }
        if nblocks == 1 {
            let ks = enc_one(rk, ld(ctr.to_be_bytes().as_ptr()));
            st(d, _mm_xor_si128(ld(s), ks));
            *ctr = ctr.wrapping_add(1);
        }
    }

    /// CTR keystream XOR over whole blocks, 8 blocks in flight.
    /// `ctr` is the numeric big-endian counter of the next block.
    #[target_feature(enable = "aes,sse2,ssse3")]
    pub unsafe fn ctr_blocks(rk: &Rk, ctr: &mut u128, src: *const u8, data: *mut u8, mut nblocks: usize) {
        let mut sp = src;
        let swap = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let rk0 = rk[0];
        let mut p = data;
        while nblocks >= 8 {
            let lo = *ctr as u64;
            let mut blk = [_mm_setzero_si128(); 8];
            if lo <= u64::MAX - 8 {
                let base = _mm_set_epi64x((*ctr >> 64) as i64, lo as i64);
                for j in 0..8 {
                    let v = _mm_add_epi64(base, _mm_set_epi64x(0, j as i64));
                    blk[j] = _mm_xor_si128(_mm_shuffle_epi8(v, swap), rk0);
                }
            } else {
                for j in 0..8 {
                    let v = ctr.wrapping_add(j as u128).to_be_bytes();
                    blk[j] = _mm_xor_si128(ld(v.as_ptr()), rk0);
                }
            }
            for r in 1..14 {
                let k = rk[r];
                for j in 0..8 {
                    blk[j] = _mm_aesenc_si128(blk[j], k);
                }
            }
            let kl = rk[14];
            for j in 0..8 {
                let ks = _mm_aesenclast_si128(blk[j], kl);
                st(p.add(16 * j), _mm_xor_si128(ld(sp.add(16 * j)), ks));
            }
            p = p.add(128);
            sp = sp.add(128);
            *ctr = ctr.wrapping_add(8);
            nblocks -= 8;
        }
        while nblocks > 0 {
            let ks = enc_one(rk, ld(ctr.to_be_bytes().as_ptr()));
            st(p, _mm_xor_si128(ld(sp), ks));
            p = p.add(16);
            sp = sp.add(16);
            *ctr = ctr.wrapping_add(1);
            nblocks -= 1;
        }
    }

    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn keystream_block(rk: &Rk, ctr: u128) -> [u8; 16] {
        let mut out = [0u8; 16];
        st(out.as_mut_ptr(), enc_one(rk, ld(ctr.to_be_bytes().as_ptr())));
        out
    }
}

use std::sync::atomic::{AtomicBool, Ordering};
static FORCE_GENERIC: AtomicBool = AtomicBool::new(false);

#[inline]
#[allow(dead_code)]
fn use_ni() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        !FORCE_GENERIC.load(Ordering::Relaxed)
            && std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = &FORCE_GENERIC;
        false
    }
}

/// Test hook: force the portable (RustCrypto) path even on AES-NI machines.
#[pyfunction]
fn _force_generic(on: bool) {
    FORCE_GENERIC.store(on, Ordering::Relaxed);
}


// ---------------------------------------------------------------- per-thread key schedule cache
// Callers nearly always reuse one key for many calls; expanding AES-256 keys costs
// ~50 ns, which is a large slice of a 256-byte call. The cache is thread-local and
// the key compare is branch-free so a hit/miss does not depend on how many bytes match.
#[cfg(target_arch = "x86_64")]
mod kcache {
    use super::ni::{self, Rk, Rkv};
    use std::cell::UnsafeCell;
    pub struct E {
        key: [u8; 32],
        pub enc: Rk,
        dec: Rk,
        vk: Rkv,
        valid: bool,
        have_dec: bool,
        have_vk: bool,
    }
    thread_local! {
        static C: UnsafeCell<E> = UnsafeCell::new(unsafe { core::mem::zeroed() });
    }
    #[inline(always)]
    fn same(a: &[u8; 32], b: &[u8]) -> bool {
        let x = u128::from_ne_bytes(a[..16].try_into().unwrap()) ^ u128::from_ne_bytes(b[..16].try_into().unwrap());
        let y = u128::from_ne_bytes(a[16..].try_into().unwrap()) ^ u128::from_ne_bytes(b[16..32].try_into().unwrap());
        (x | y) == 0
    }
    /// Key schedule for `key` (32 bytes). The returned reference points into this
    /// thread's cache: valid until the next `get` on the same thread; callers
    /// use it only inside one call, and no Python code can run on the thread meanwhile.
    #[inline]
    pub unsafe fn get(key: &[u8]) -> &'static mut E {
        C.with(|c| {
            let e = &mut *c.get();
            if !(e.valid && same(&e.key, key)) {
                e.enc = ni::expand(key);
                e.key.copy_from_slice(key);
                e.valid = true;
                e.have_dec = false;
                e.have_vk = false;
            }
            &mut *(e as *mut E)
        })
    }
    impl E {
        #[inline]
        pub unsafe fn dec(&mut self) -> &Rk {
            if !self.have_dec {
                self.dec = ni::dec_keys(&self.enc);
                self.have_dec = true;
            }
            &self.dec
        }
        #[inline]
        pub unsafe fn vk(&mut self) -> &Rkv {
            if !self.have_vk {
                self.vk = ni::bcast_keys(&self.enc);
                self.have_vk = true;
            }
            &self.vk
        }
    }
}

/// IGE encrypt whole blocks `src -> dst` (equal length, multiple of 16).
fn ige_enc_any(key: &[u8], iv: &[u8], src: &[u8], dst: &mut [u8]) {
    debug_assert!(src.len() == dst.len() && src.len() % 16 == 0);
    #[cfg(target_arch = "x86_64")]
    if use_ni() {
        unsafe {
            let e = kcache::get(key);
            ni::ige_enc(&e.enc, iv, src.as_ptr(), dst.as_mut_ptr(), src.len() / 16);
        }
        return;
    }
    let cipher = Aes256::new_from_slice(key).unwrap();
    IgeEnc::new(&cipher, iv).run(src, dst);
}

/// IGE encrypt in place.
fn ige_enc_inplace_any(key: &[u8], iv: &[u8], buf: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if use_ni() {
        unsafe {
            let rk = ni::expand(key); // one-shot (KDF) keys: bypass the cache
            let p = buf.as_mut_ptr();
            ni::ige_enc(&rk, iv, p, p, buf.len() / 16);
        }
        return;
    }
    let cipher = Aes256::new_from_slice(key).unwrap();
    IgeEnc::new(&cipher, iv).run_inplace(buf);
}

fn ige_dec_any(key: &[u8], iv: &[u8], src: &[u8], dst: &mut [u8]) {
    debug_assert!(src.len() == dst.len() && src.len() % 16 == 0);
    #[cfg(target_arch = "x86_64")]
    if use_ni() {
        unsafe {
            let e = kcache::get(key);
            ni::ige_dec(e.dec(), iv, src.as_ptr(), dst.as_mut_ptr(), src.len() / 16, None);
        }
        return;
    }
    let cipher = Aes256::new_from_slice(key).unwrap();
    IgeDec::new(&cipher, iv).run(src, dst);
}

// ---------------------------------------------------------------- IGE

struct IgeEnc<'a> {
    c: &'a Aes256,
    y: [u8; 16], // previous ciphertext block
    x: [u8; 16], // previous plaintext block
}

impl<'a> IgeEnc<'a> {
    fn new(c: &'a Aes256, iv: &[u8]) -> Self {
        Self { c, y: iv[..16].try_into().unwrap(), x: iv[16..32].try_into().unwrap() }
    }

    /// c_i = E(p_i ^ c_{i-1}) ^ p_{i-1}
    #[inline(always)]
    fn block(&mut self, p: [u8; 16]) -> [u8; 16] {
        let mut b = Block::from(xor16(&p, &self.y));
        self.c.encrypt_block(&mut b);
        let c = xor16(&b.into(), &self.x);
        self.y = c;
        self.x = p;
        c
    }

    fn run_inplace(&mut self, buf: &mut [u8]) {
        for ch in buf.chunks_exact_mut(16) {
            let p: [u8; 16] = (&*ch).try_into().unwrap();
            let c = self.block(p);
            ch.copy_from_slice(&c);
        }
    }

    fn run(&mut self, src: &[u8], dst: &mut [u8]) {
        for (s, d) in src.chunks_exact(16).zip(dst.chunks_exact_mut(16)) {
            let c = self.block(s.try_into().unwrap());
            d.copy_from_slice(&c);
        }
    }
}

struct IgeDec<'a> {
    c: &'a Aes256,
    y: [u8; 16],
    x: [u8; 16],
}

impl<'a> IgeDec<'a> {
    fn new(c: &'a Aes256, iv: &[u8]) -> Self {
        Self { c, y: iv[..16].try_into().unwrap(), x: iv[16..32].try_into().unwrap() }
    }

    /// p_i = D(c_i ^ p_{i-1}) ^ c_{i-1}
    #[inline(always)]
    fn block(&mut self, c: [u8; 16]) -> [u8; 16] {
        let mut b = Block::from(xor16(&c, &self.x));
        self.c.decrypt_block(&mut b);
        let p = xor16(&b.into(), &self.y);
        self.y = c;
        self.x = p;
        p
    }

    fn run(&mut self, src: &[u8], dst: &mut [u8]) {
        for (s, d) in src.chunks_exact(16).zip(dst.chunks_exact_mut(16)) {
            let p = self.block(s.try_into().unwrap());
            d.copy_from_slice(&p);
        }
    }
}

#[pyfunction]
fn ige256_encrypt<'py>(
    py: Python<'py>,
    data: PyBackedBytes,
    key: PyBackedBytes,
    iv: PyBackedBytes,
) -> PyResult<Bound<'py, PyBytes>> {
    check_len("Key", key.len(), 32)?;
    check_len("IV", iv.len(), 32)?;
    let n = data.len();
    PyBytes::new_bound_with(py, n, |out| {
        maybe_nogil(py, n, || {
            let full = n / 16 * 16;
            ige_enc_any(&key, &iv, &data[..full], &mut out[..full]);
            out[full..].copy_from_slice(&data[full..]);
        });
        Ok(())
    })
}

#[pyfunction]
fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: PyBackedBytes,
    key: PyBackedBytes,
    iv: PyBackedBytes,
) -> PyResult<Bound<'py, PyBytes>> {
    check_len("Key", key.len(), 32)?;
    check_len("IV", iv.len(), 32)?;
    let n = data.len();
    PyBytes::new_bound_with(py, n, |out| {
        maybe_nogil(py, n, || {
            let full = n / 16 * 16;
            ige_dec_any(&key, &iv, &data[..full], &mut out[..full]);
            out[full..].copy_from_slice(&data[full..]);
        });
        Ok(())
    })
}

// ---------------------------------------------------------------- CTR

/// AES-256-CTR with the TgCrypto/warpcrypto state convention:
/// `iv` is the counter of the *current* block (big-endian 128 bit, wrapping),
/// `state` is how many bytes of that block were already used. The counter is
/// incremented as soon as a block is fully consumed.
pub(crate) fn ctr_apply(key: &[u8], data: &mut [u8], iv: &mut [u8; 16], state: &mut u8) {
    #[cfg(target_arch = "x86_64")]
    if use_ni() {
        return ctr_apply_ni(key, data.as_ptr(), data.as_mut_ptr(), data.len(), iv, state);
    }
    let cipher = &Aes256::new_from_slice(key).unwrap();
    let n = data.len();
    let mut ctr = u128::from_be_bytes(*iv);
    let mut s = (*state as usize) % 16;
    let mut pos = 0usize;

    if s > 0 && n > 0 {
        let mut ks = Block::from(ctr.to_be_bytes());
        cipher.encrypt_block(&mut ks);
        let take = (16 - s).min(n);
        for i in 0..take {
            data[i] ^= ks[s + i];
        }
        pos = take;
        s += take;
        if s == 16 {
            s = 0;
            ctr = ctr.wrapping_add(1);
        }
    }

    const PAR: usize = 8;
    let mut blocks = [Block::default(); PAR];
    while n - pos >= 16 {
        let nb = ((n - pos) / 16).min(PAR);
        for (j, b) in blocks.iter_mut().enumerate().take(nb) {
            *b = Block::from(ctr.wrapping_add(j as u128).to_be_bytes());
        }
        cipher.encrypt_blocks(&mut blocks[..nb]);
        for (j, ks) in blocks.iter().enumerate().take(nb) {
            let ch = &mut data[pos + j * 16..pos + j * 16 + 16];
            let x = u128::from_ne_bytes((&*ch).try_into().unwrap())
                ^ u128::from_ne_bytes((*ks).into());
            ch.copy_from_slice(&x.to_ne_bytes());
        }
        pos += nb * 16;
        ctr = ctr.wrapping_add(nb as u128);
    }

    if pos < n {
        let mut ks = Block::from(ctr.to_be_bytes());
        cipher.encrypt_block(&mut ks);
        let rest = n - pos;
        for i in 0..rest {
            data[pos + i] ^= ks[i];
        }
        s = rest;
    }

    *iv = ctr.to_be_bytes();
    *state = s as u8;
}


#[cfg(target_arch = "x86_64")]
fn ctr_apply_ni(key: &[u8], src: *const u8, dst: *mut u8, n: usize, iv: &mut [u8; 16], state: &mut u8) {
    unsafe {
        let e = kcache::get(key);
        let rk = &*(&e.enc as *const ni::Rk);
        let mut ctr = u128::from_be_bytes(*iv);
        let mut s = (*state as usize) % 16;
        let mut pos = 0usize;
        if s > 0 && n > 0 {
            let ks = ni::keystream_block(rk, ctr);
            let take = (16 - s).min(n);
            for i in 0..take {
                *dst.add(i) = *src.add(i) ^ ks[s + i];
            }
            pos = take;
            s += take;
            if s == 16 {
                s = 0;
                ctr = ctr.wrapping_add(1);
            }
        }
        let nb = (n - pos) / 16;
        if nb > 0 {
            if ni::has_vaes() {
                let rkv = e.vk() as *const ni::Rkv;
                ni::ctr_blocks_vaes(&e.enc, &*rkv, &mut ctr, src.add(pos), dst.add(pos), nb);
            } else {
                ni::ctr_blocks(&e.enc, &mut ctr, src.add(pos), dst.add(pos), nb);
            }
            pos += nb * 16;
        }
        if pos < n {
            let ks = ni::keystream_block(rk, ctr);
            let rest = n - pos;
            for i in 0..rest {
                *dst.add(pos + i) = *src.add(pos + i) ^ ks[i];
            }
            s = rest;
        }
        *iv = ctr.to_be_bytes();
        *state = s as u8;
    }
}

/// `src -> dst` CTR (dst must be the same length). One pass, no pre-copy.
fn ctr_apply_io(key: &[u8], src: &[u8], dst: &mut [u8], iv: &mut [u8; 16], state: &mut u8) {
    debug_assert!(src.len() == dst.len());
    #[cfg(target_arch = "x86_64")]
    if use_ni() {
        return ctr_apply_ni(key, src.as_ptr(), dst.as_mut_ptr(), src.len(), iv, state);
    }
    dst.copy_from_slice(src);
    ctr_apply(key, dst, iv, state);
}

fn ctr_args(
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<([u8; 32], [u8; 16], u8)> {
    check_len("Key", key.len(), 32)?;
    check_len("IV", iv.len(), 16)?;
    if state.len() < 1 {
        return verr("state must be at least 1 byte");
    }
    let cipher: [u8; 32] = key.try_into().unwrap();
    // SAFETY: GIL is held and no Python code runs while the slices are alive.
    let (iv_l, st_l) = unsafe {
        let mut a = [0u8; 16];
        a.copy_from_slice(iv.as_bytes());
        (a, state.as_bytes()[0])
    };
    Ok((cipher, iv_l, st_l))
}

fn ctr_store(iv: &Bound<'_, PyByteArray>, state: &Bound<'_, PyByteArray>, iv_l: [u8; 16], st_l: u8) {
    // SAFETY: GIL held, lengths were validated in ctr_args.
    unsafe {
        iv.as_bytes_mut().copy_from_slice(&iv_l);
        state.as_bytes_mut()[0] = st_l;
    }
}

#[pyfunction]
fn ctr256_encrypt<'py>(
    py: Python<'py>,
    src: PyBackedBytes,
    key: PyBackedBytes,
    iv: &Bound<'py, PyByteArray>,
    state: &Bound<'py, PyByteArray>,
) -> PyResult<Bound<'py, PyBytes>> {
    let (cipher, mut iv_l, mut st_l) = ctr_args(&key, iv, state)?;
    let n = src.len();
    let out = PyBytes::new_bound_with(py, n, |out| {
        maybe_nogil(py, n, || ctr_apply_io(&cipher, &src, out, &mut iv_l, &mut st_l));
        Ok(())
    })?;
    ctr_store(iv, state, iv_l, st_l);
    Ok(out)
}

#[pyfunction]
fn ctr256_decrypt<'py>(
    py: Python<'py>,
    src: PyBackedBytes,
    key: PyBackedBytes,
    iv: &Bound<'py, PyByteArray>,
    state: &Bound<'py, PyByteArray>,
) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt(py, src, key, iv, state)
}

#[pyfunction]
fn ctr256_encrypt_inplace<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyByteArray>,
    key: PyBackedBytes,
    iv: &Bound<'py, PyByteArray>,
    state: &Bound<'py, PyByteArray>,
) -> PyResult<()> {
    let (cipher, mut iv_l, mut st_l) = ctr_args(&key, iv, state)?;
    // copy out, work without the GIL, write back (the bytearray may not be
    // touched by other threads while we hold no GIL, so we never keep a
    // reference into it across allow_threads).
    let mut buf: Vec<u8> = unsafe { data.as_bytes().to_vec() };
    let n = buf.len();
    maybe_nogil(py, n, || ctr_apply(&cipher, &mut buf, &mut iv_l, &mut st_l));
    unsafe {
        let dst = data.as_bytes_mut();
        if dst.len() != n {
            return Err(PyRuntimeError::new_err("data was resized during encryption"));
        }
        dst.copy_from_slice(&buf);
    }
    ctr_store(iv, state, iv_l, st_l);
    Ok(())
}

#[pyfunction]
fn ctr256_decrypt_inplace<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyByteArray>,
    key: PyBackedBytes,
    iv: &Bound<'py, PyByteArray>,
    state: &Bound<'py, PyByteArray>,
) -> PyResult<()> {
    ctr256_encrypt_inplace(py, data, key, iv, state)
}

#[pyfunction]
fn ctr256_encrypt_batch<'py>(
    py: Python<'py>,
    data_flat: PyBackedBytes,
    sizes: &Bound<'py, PyByteArray>,
    key: PyBackedBytes,
    ivs: &Bound<'py, PyByteArray>,
    states: &Bound<'py, PyByteArray>,
) -> PyResult<Bound<'py, PyBytes>> {
    check_len("Key", key.len(), 32)?;
    let sz_raw: Vec<u8> = unsafe { sizes.as_bytes().to_vec() };
    if sz_raw.len() % 4 != 0 {
        return verr("sizes must be 4*n bytes");
    }
    let n = sz_raw.len() / 4;
    let sizes_v: Vec<usize> = sz_raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()) as usize)
        .collect();
    let total: usize = sizes_v.iter().sum();
    if data_flat.len() < total {
        return verr("data_flat too short for given sizes");
    }
    let mut ivs_v: Vec<u8> = unsafe { ivs.as_bytes().to_vec() };
    let mut st_v: Vec<u8> = unsafe { states.as_bytes().to_vec() };
    if ivs_v.len() != 16 * n {
        return verr("ivs must be 16*n bytes");
    }
    if st_v.len() != n {
        return verr("states must be n bytes");
    }
    let cipher: [u8; 32] = (&*key).try_into().unwrap();
    let out = PyBytes::new_bound_with(py, total, |out| {
        out.copy_from_slice(&data_flat[..total]);
        maybe_nogil(py, total, || {
            let mut off = 0usize;
            for (i, &sz) in sizes_v.iter().enumerate() {
                let mut iv: [u8; 16] = ivs_v[i * 16..i * 16 + 16].try_into().unwrap();
                ctr_apply(&cipher, &mut out[off..off + sz], &mut iv, &mut st_v[i]);
                ivs_v[i * 16..i * 16 + 16].copy_from_slice(&iv);
                off += sz;
            }
        });
        Ok(())
    })?;
    unsafe {
        ivs.as_bytes_mut().copy_from_slice(&ivs_v);
        states.as_bytes_mut().copy_from_slice(&st_v);
    }
    Ok(out)
}

#[pyfunction]
fn ctr256_decrypt_batch<'py>(
    py: Python<'py>,
    data_flat: PyBackedBytes,
    sizes: &Bound<'py, PyByteArray>,
    key: PyBackedBytes,
    ivs: &Bound<'py, PyByteArray>,
    states: &Bound<'py, PyByteArray>,
) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt_batch(py, data_flat, sizes, key, ivs, states)
}

// ---------------------------------------------------------------- KDF / SHA

fn kdf_raw(auth_key: &[u8], msg_key: &[u8], outgoing: bool) -> ([u8; 32], [u8; 32]) {
    let x = if outgoing { 0 } else { 8 };
    let a = Sha256::new().chain_update(msg_key).chain_update(&auth_key[x..x + 36]).finalize();
    let b = Sha256::new().chain_update(&auth_key[40 + x..40 + x + 36]).chain_update(msg_key).finalize();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 32];
    key[..8].copy_from_slice(&a[..8]);
    key[8..24].copy_from_slice(&b[8..24]);
    key[24..].copy_from_slice(&a[24..]);
    iv[..8].copy_from_slice(&b[..8]);
    iv[8..24].copy_from_slice(&a[8..24]);
    iv[24..].copy_from_slice(&b[24..]);
    (key, iv)
}

#[pyfunction]
fn kdf<'py>(
    py: Python<'py>,
    auth_key: PyBackedBytes,
    msg_key: PyBackedBytes,
    outgoing: bool,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    if auth_key.len() != 256 {
        return verr("auth_key must be 256 bytes");
    }
    check_len("msg_key", msg_key.len(), 16)?;
    let (k, iv) = kdf_raw(&auth_key, &msg_key, outgoing);
    Ok((PyBytes::new_bound(py, &k), PyBytes::new_bound(py, &iv)))
}

#[inline]
fn sha_compress(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert!(blocks.len() % 64 == 0);
    if blocks.is_empty() {
        return;
    }
    // SAFETY: GenericArray<u8, U64> is repr(transparent) over [u8; 64].
    let g: &[ShaBlock<u8, U64>] = unsafe {
        std::slice::from_raw_parts(blocks.as_ptr() as *const ShaBlock<u8, U64>, blocks.len() / 64)
    };
    sha2::compress256(state, g);
}

/// Finish a SHA-256 whose first `hashed` bytes (multiple of 64) of `msg` are
/// already folded into `state`; `msg` is the whole message (any remainder).
fn sha_finish(state: &mut [u32; 8], msg: &[u8], mut hashed: usize) -> [u8; 32] {
    // fold in any complete 64-byte blocks first, so the tail is always < 64 bytes
    let full = (msg.len() - hashed) / 64 * 64;
    if full > 0 {
        sha_compress(state, &msg[hashed..hashed + full]);
        hashed += full;
    }
    let rest = &msg[hashed..];
    let mut tmp = [0u8; 128];
    tmp[..rest.len()].copy_from_slice(rest);
    tmp[rest.len()] = 0x80;
    let blocks = if rest.len() < 56 { 1 } else { 2 };
    let bits = (msg.len() as u64) * 8;
    tmp[blocks * 64 - 8..blocks * 64].copy_from_slice(&bits.to_be_bytes());
    sha_compress(state, &tmp[..blocks * 64]);
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}


// ---------------------------------------------------------------- padding randomness
// MTProto 2.0 needs random padding. Calling getrandom(2) per message costs a
// syscall (~0.4 us), so each thread draws 2 KiB of OS randomness at once and hands
// out disjoint slices. Bytes come straight from the OS CSPRNG and are never reused.
// A fork bumps FORK_GEN (see `_after_fork`) so a child never replays its parent's buffer.
use std::cell::UnsafeCell as RCell;
use std::sync::atomic::AtomicU64;
static FORK_GEN: AtomicU64 = AtomicU64::new(0);
const RBUF: usize = 2048;
struct RandBuf { buf: [u8; RBUF], pos: usize, gen: u64 }
thread_local! { static RB: RCell<RandBuf> = const { RCell::new(RandBuf { buf: [0; RBUF], pos: RBUF, gen: 0 }) }; }

#[pyfunction]
fn _after_fork() {
    FORK_GEN.fetch_add(1, Ordering::SeqCst);
}

fn fill_random(out: &mut [u8]) -> Result<(), getrandom::Error> {
    if out.len() > RBUF / 4 {
        return getrandom::getrandom(out);
    }
    RB.with(|c| unsafe {
        let rb = &mut *c.get();
        let g = FORK_GEN.load(Ordering::Relaxed);
        if rb.gen != g {
            rb.gen = g;
            rb.pos = RBUF; // discard anything inherited from before a fork
        }
        if rb.pos + out.len() > RBUF {
            getrandom::getrandom(&mut rb.buf)?;
            rb.pos = 0;
        }
        out.copy_from_slice(&rb.buf[rb.pos..rb.pos + out.len()]);
        // wipe what we handed out so the buffer never holds a second copy
        rb.buf[rb.pos..rb.pos + out.len()].fill(0);
        rb.pos += out.len();
        Ok(())
    })
}

// ---------------------------------------------------------------- pack / unpack

fn validate_keys(session_id: &[u8], auth_key: &[u8], auth_key_id: &[u8]) -> PyResult<()> {
    check_len("session_id", session_id.len(), 8)?;
    check_len("auth_key", auth_key.len(), 256)?;
    check_len("auth_key_id", auth_key_id.len(), 8)?;
    Ok(())
}

/// Size of a packed message for a body of `body_len` bytes.
pub(crate) fn packed_len(body_len: usize) -> usize {
    let plain_len = 32 + body_len;
    let pad = (16 - (plain_len + 12) % 16) % 16 + 12;
    24 + plain_len + pad
}

/// Pure-Rust pack: fills `out` (exactly `packed_len(body.len())` bytes). False if the RNG failed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn pack_fill(
    out: &mut [u8],
    msg_id: i64,
    seq_no: i32,
    body: &[u8],
    salt: i64,
    session_id: &[u8],
    auth_key: &[u8],
    auth_key_id: &[u8],
) -> bool {
    let plain_len = 32 + body.len();
    let (head, plain) = out.split_at_mut(24);
    head[..8].copy_from_slice(auth_key_id);
    plain[..8].copy_from_slice(&salt.to_le_bytes());
    plain[8..16].copy_from_slice(session_id);
    plain[16..24].copy_from_slice(&msg_id.to_le_bytes());
    plain[24..28].copy_from_slice(&seq_no.to_le_bytes());
    plain[28..32].copy_from_slice(&(body.len() as u32).to_le_bytes());
    plain[32..plain_len].copy_from_slice(body);
    if fill_random(&mut plain[plain_len..]).is_err() {
        return false;
    }
    let h = Sha256::new().chain_update(&auth_key[88..120]).chain_update(&*plain).finalize();
    head[8..24].copy_from_slice(&h[8..24]);
    let (k, iv) = kdf_raw(auth_key, &head[8..24], true);
    ige_enc_inplace_any(&k, &iv, plain);
    true
}

#[pyfunction]
#[pyo3(signature = (msg_id, seq_no, body, salt, session_id, auth_key, auth_key_id))]
fn pack_message<'py>(
    py: Python<'py>,
    msg_id: i64,
    seq_no: i32,
    body: PyBackedBytes,
    salt: i64,
    session_id: PyBackedBytes,
    auth_key: PyBackedBytes,
    auth_key_id: PyBackedBytes,
) -> PyResult<Bound<'py, PyBytes>> {
    validate_keys(&session_id, &auth_key, &auth_key_id)?;
    let out_len = packed_len(body.len());
    let mut failed = false;
    let res = PyBytes::new_bound_with(py, out_len, |out| {
        let ok = maybe_nogil(py, out_len, || {
            pack_fill(out, msg_id, seq_no, &body, salt, &session_id, &auth_key, &auth_key_id)
        });
        failed = !ok;
        Ok(())
    })?;
    if failed {
        return Err(PyRuntimeError::new_err("system random source failed"));
    }
    Ok(res)
}

/// Decrypt + verify. Returns the buffer `[auth_key slice (32) | plaintext]`.
pub(crate) fn unpack_core(
    packed: &[u8],
    session_id: &[u8],
    auth_key: &[u8],
    auth_key_id: &[u8],
    incoming: bool,
) -> Result<Vec<u8>, &'static str> {
    if packed.len() < 24 {
        return Err("packed data too short");
    }
    if packed[..8] != *auth_key_id {
        return Err("auth_key_id mismatch");
    }
    let msg_key = &packed[8..24];
    let ct = &packed[24..];
    if ct.len() % 16 != 0 {
        return Err("msg_key mismatch");
    }
    let x = if incoming { 8 } else { 0 };
    let (k, iv) = kdf_raw(auth_key, msg_key, !incoming);
    let total = ct.len();
    let mut sha = H0;
    let mut hashed = 0usize;
    let mut buf: Vec<u8>;
    #[allow(unused_mut)]
    let mut fused = false;
    #[cfg(target_arch = "x86_64")]
    if use_ni() {
        // The AES-NI kernel writes every byte of buf[32..], and the prefix is
        // copied below, so skip the zero-fill (saves a memset + page touch of the
        // whole packet on every call).
        buf = Vec::with_capacity(32 + total);
        unsafe {
            std::ptr::copy_nonoverlapping(auth_key.as_ptr().add(88 + x), buf.as_mut_ptr(), 32);
            let dk = ni::dec_keys(&ni::expand(&k));
            let dst = buf.as_mut_ptr().add(32);
            ni::ige_dec(&dk, &iv, ct.as_ptr(), dst, total / 16, Some((&mut sha, &mut hashed)));
            buf.set_len(32 + total);
        }
        fused = true;
    } else {
        buf = vec![0u8; 32 + total];
        buf[..32].copy_from_slice(&auth_key[88 + x..120 + x]);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        buf = vec![0u8; 32 + total];
        buf[..32].copy_from_slice(&auth_key[88 + x..120 + x]);
    }
    if !fused {
        let cipher = Aes256::new_from_slice(&k).unwrap();
        let mut dec = IgeDec::new(&cipher, &iv);
        let group = FUSE_GROUP_BLOCKS * 16;
        let mut off = 0usize;
        while off < total {
            let end = (off + group).min(total);
            dec.run(&ct[off..end], &mut buf[32 + off..32 + end]);
            off = end;
            let avail = (32 + off) / 64 * 64;
            if avail > hashed {
                sha_compress(&mut sha, &buf[hashed..avail]);
                hashed = avail;
            }
        }
    }
    let digest = sha_finish(&mut sha, &buf, hashed);
    if digest[8..24] != *msg_key {
        return Err("msg_key mismatch");
    }
    if total < 16 {
        return Err("packed data too short");
    }
    if buf[32 + 8..32 + 16] != *session_id {
        return Err("session_id mismatch");
    }
    if total < 32 {
        return Err("packed data too short");
    }
    Ok(buf)
}

/// Checks done on the decrypted plaintext (same rules and order as warpcrypto):
/// negative length -> length exceeds data -> length % 4 -> padding 12..=1024.
pub(crate) fn parse_plain(p: &[u8]) -> Result<(i64, i32, u32), &'static str> {
    if p.len() < 32 {
        return Err("packed data too short");
    }
    let msg_id = i64::from_le_bytes(p[16..24].try_into().unwrap());
    let seq_no = i32::from_le_bytes(p[24..28].try_into().unwrap());
    let length_raw = i32::from_le_bytes(p[28..32].try_into().unwrap());
    if length_raw < 0 {
        return Err("negative body length");
    }
    let length = length_raw as u32;
    if 32 + length as usize > p.len() {
        return Err("body length exceeds decrypted data");
    }
    if length % 4 != 0 {
        return Err("body length not divisible by 4");
    }
    let padding = p.len() - 32 - length as usize;
    if !(12..=1024).contains(&padding) {
        return Err("padding length out of range");
    }
    Ok((msg_id, seq_no, length))
}

#[pyfunction]
#[pyo3(signature = (packed, session_id, auth_key, auth_key_id, incoming=true))]
fn unpack_message<'py>(
    py: Python<'py>,
    packed: PyBackedBytes,
    session_id: PyBackedBytes,
    auth_key: PyBackedBytes,
    auth_key_id: PyBackedBytes,
    incoming: bool,
) -> PyResult<(i64, i32, u32, Bound<'py, PyBytes>, usize)> {
    validate_keys(&session_id, &auth_key, &auth_key_id)?;
    let res = maybe_nogil(py, packed.len(), || {
        unpack_core(&packed, &session_id, &auth_key, &auth_key_id, incoming)
    });
    let buf = match res {
        Ok(b) => b,
        Err(e) => return verr(e),
    };
    let p = &buf[32..]; // plaintext
    let (msg_id, seq_no, length) = match parse_plain(p) {
        Ok(v) => v,
        Err(e) => return verr(e),
    };
    let end = 32usize + length as usize;
    let body = PyBytes::new_bound(py, &p[32..end]);
    Ok((msg_id, seq_no, length, body, p.len() - 16))
}

// ---------------------------------------------------------------- diagnostics

/// Which hardware acceleration this build is really using.
#[pyfunction]
fn backend() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        format!(
            "x86_64 aes_ni={} sha_ni={} avx2={} vaes={} vaes512={}",
            std::arch::is_x86_feature_detected!("aes"),
            std::arch::is_x86_feature_detected!("sha"),
            std::arch::is_x86_feature_detected!("avx2"),
            ni::has_vaes(),
            ni::has_vaes512()
        )
    }
    #[cfg(target_arch = "aarch64")]
    {
        format!(
            "aarch64 aes={} sha2={}",
            std::arch::is_aarch64_feature_detected!("aes"),
            std::arch::is_aarch64_feature_detected!("sha2")
        )
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        format!("{} (software)", std::env::consts::ARCH)
    }
}

#[pymodule]
fn cbcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(_after_fork, m)?)?;
    // after os.fork() the child must not replay the parent's buffered padding bytes
    let py = m.py();
    if let Ok(os) = py.import_bound("os") {
        if let Ok(reg) = os.getattr("register_at_fork") {
            let kw = pyo3::types::PyDict::new_bound(py);
            kw.set_item("after_in_child", m.getattr("_after_fork")?)?;
            let _ = reg.call((), Some(&kw));
        }
    }
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(kdf, m)?)?;
    m.add_function(wrap_pyfunction!(pack_message, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_message, m)?)?;
    m.add_function(wrap_pyfunction!(backend, m)?)?;
    m.add_function(wrap_pyfunction!(_force_generic, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    engine::register(m)?;
    let _ = PyOverflowError::new_err("");
    Ok(())
            }
