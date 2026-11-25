//! The cbgram transfer core: file download and upload entirely in Rust.
//!
//! Python hands over what only Python knows (auth key, DC address, the serialized
//! request templates, pacing numbers) and gets back a finished transfer. In between,
//! no Python code runs and the GIL is released: this module owns the TCP sockets, the
//! obfuscated-abridged transport, MTProto framing + crypto, acks / salts / flood waits /
//! reconnects, the adaptive pacer and positional file I/O.
//!
//! Scope (everything else stays in Python): it speaks only to a DC with an already
//! valid auth key; it does not do the auth-key handshake, proxies, or CDN downloads
//! (a CDN redirect is reported to Python, which falls back to its own path).

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pyo3::prelude::*;

use crate::pacer::{Pacer, PacerCfg};
use crate::{ctr_apply, pack_fill, packed_len, parse_plain, unpack_core};

pyo3::create_exception!(cbcrypto, CoreError, pyo3::exceptions::PyException);

// ------------------------------------------------------------------ constructors

const CONTAINER: u32 = 0x73f1f8dc;
const RPC_RESULT: u32 = 0xf35c6d01;
const GZIP_PACKED: u32 = 0x3072cfa1;
const MSGS_ACK: u32 = 0x62d6b459;
const NEW_SESSION: u32 = 0x9ec20908;
const BAD_SERVER_SALT: u32 = 0xedab447b;
const BAD_MSG_NOTIFICATION: u32 = 0xa7eff811;
const RPC_ERROR: u32 = 0x2144ca19;
const UPLOAD_FILE: u32 = 0x096a18d5;
const CDN_REDIRECT: u32 = 0xf18cda44;
const BOOL_TRUE: u32 = 0x997275b5;
const BOOL_FALSE: u32 = 0xbc799737;
const VECTOR: u32 = 0x1cb5c415;
const SAVE_FILE_PART: u32 = 0xb304a621;
const SAVE_BIG_FILE_PART: u32 = 0xde7b673d;

/// Tell Python which constructor ids this build expects, so the test-suite can check
/// them against the generated TL classes instead of trusting my memory.
pub(crate) fn constants() -> Vec<(&'static str, u32)> {
    vec![
        ("CONTAINER", CONTAINER), ("RPC_RESULT", RPC_RESULT), ("GZIP_PACKED", GZIP_PACKED),
        ("MSGS_ACK", MSGS_ACK), ("NEW_SESSION", NEW_SESSION), ("BAD_SERVER_SALT", BAD_SERVER_SALT),
        ("BAD_MSG_NOTIFICATION", BAD_MSG_NOTIFICATION), ("RPC_ERROR", RPC_ERROR),
        ("UPLOAD_FILE", UPLOAD_FILE), ("CDN_REDIRECT", CDN_REDIRECT), ("BOOL_TRUE", BOOL_TRUE),
        ("BOOL_FALSE", BOOL_FALSE), ("VECTOR", VECTOR), ("SAVE_FILE_PART", SAVE_FILE_PART),
        ("SAVE_BIG_FILE_PART", SAVE_BIG_FILE_PART),
    ]
}

// ------------------------------------------------------------------ errors

#[derive(Debug, Clone)]
pub enum EngineError {
    Io(String),
    PeerDisconnected(String),
    FileIo(String),
    Timeout(String),
    Rpc { code: i32, message: String },
    Cdn,
    Protocol(String),
    Cancelled,
}

type Res<T> = Result<T, EngineError>;

fn dbg_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("CBCRYPTO_DEBUG").is_some())
}
macro_rules! dbg_log {
    ($($a:tt)*) => { if dbg_on() { eprintln!("[cbcrypto {:?}] {}", std::thread::current().id(), format!($($a)*)); } };
}

fn ioerr(e: std::io::Error) -> EngineError {
    use std::io::ErrorKind::*;
    match e.kind() {
        WouldBlock | TimedOut => EngineError::Timeout(e.to_string()),
        BrokenPipe | ConnectionAborted | ConnectionReset | UnexpectedEof => {
            EngineError::PeerDisconnected(e.to_string())
        }
        _ => EngineError::Io(e.to_string()),
    }
}

fn to_pyerr(e: EngineError) -> PyErr {
    let (kind, code, msg) = match e {
        EngineError::Io(m) | EngineError::PeerDisconnected(m) | EngineError::FileIo(m) => ("io", 0, m),
        EngineError::Timeout(m) => ("timeout", 0, m),
        EngineError::Rpc { code, message } => ("rpc", code, message),
        EngineError::Cdn => ("cdn", 0, String::new()),
        EngineError::Protocol(m) => ("protocol", 0, m),
        EngineError::Cancelled => ("cancelled", 0, "cancelled".to_string()),
    };
    PyErr::new::<CoreError, _>((kind.to_string(), code, msg))
}

// ------------------------------------------------------------------ TL helpers

fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap()))
}
fn rd_i32(b: &[u8], o: usize) -> Option<i32> {
    rd_u32(b, o).map(|v| v as i32)
}
fn rd_i64(b: &[u8], o: usize) -> Option<i64> {
    b.get(o..o + 8).map(|x| i64::from_le_bytes(x.try_into().unwrap()))
}

/// TL `bytes` at `o`: returns (data_start, data_len, next_offset).
fn tl_bytes_at(b: &[u8], o: usize) -> Option<(usize, usize, usize)> {
    let first = *b.get(o)? as usize;
    let (start, len) = if first < 254 {
        (o + 1, first)
    } else {
        let l = b.get(o + 1..o + 4)?;
        (o + 4, l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16)
    };
    let end = start.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    let total = (start - o) + len;
    Some((start, len, o + total.div_ceil(4) * 4))
}

fn tl_bytes_put(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    let head = if n < 254 {
        out.push(n as u8);
        1
    } else {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
        4
    };
    out.extend_from_slice(data);
    let pad = (4 - (head + n) % 4) % 4;
    out.extend(std::iter::repeat(0u8).take(pad));
}

fn gunzip(data: &[u8]) -> Res<Vec<u8>> {
    let mut d = flate2::read::GzDecoder::new(data);
    let mut out = Vec::with_capacity(data.len() * 2);
    d.read_to_end(&mut out).map_err(|e| EngineError::Protocol(format!("gzip: {e}")))?;
    Ok(out)
}

// ------------------------------------------------------------------ file I/O

#[cfg(unix)]
fn write_all_at(f: &File, buf: &[u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(f, buf, off)
}
#[cfg(unix)]
fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}
#[cfg(windows)]
fn write_all_at(f: &File, mut buf: &[u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_write(buf, off)?;
        buf = &buf[n..];
        off += n as u64;
    }
    Ok(())
}
#[cfg(windows)]
fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let tmp = buf;
        buf = &mut tmp[n..];
        off += n as u64;
    }
    Ok(())
}

// ------------------------------------------------------------------ pacer
// (see pacer.rs)

// ------------------------------------------------------------------ MTProto connection

struct CtrSt {
    key: [u8; 32],
    iv: [u8; 16],
    st: u8,
}

impl CtrSt {
    fn apply(&mut self, data: &mut [u8]) {
        ctr_apply(&self.key, data, &mut self.iv, &mut self.st);
    }
}

#[derive(Clone)]
pub struct ConnCfg {
    pub host: String,
    pub port: u16,
    pub auth_key: Vec<u8>,
    pub auth_key_id: Vec<u8>,
    pub salt: i64,
    pub init_prefix: Vec<u8>,
    pub time_offset: f64,
    pub recv_buf: usize,
    pub read_timeout: Duration,
}

enum Event<'a> {
    File { req: i64, data: &'a [u8] },
    Bool { req: i64, ok: bool },
    RpcError { req: i64, code: i32, message: String, sent: Option<Instant> },
    Cdn,
    BadSalt { bad_msg_id: i64 },
    BadMsg { bad_msg_id: i64, code: i32 },
    Other,
}

struct Conn {
    s: TcpStream,
    enc: CtrSt,
    dec: CtrSt,
    auth_key: Vec<u8>,
    auth_key_id: Vec<u8>,
    session_id: [u8; 8],
    salt: i64,
    seq: u32,
    last_msg_id: i64,
    time_offset: f64,
    acks: Vec<i64>,
    last_ack: Instant,
    /// true once a real result came back, i.e. the server has seen initConnection
    inited: bool,
    init_prefix: Vec<u8>,
    rbuf: Vec<u8>,
    /// when each request still waiting for an answer was sent, so a flood reply can be told apart:
    /// an answer to a request sent before the pause we already reacted to is the same flood again
    sent: HashMap<i64, Instant>,
}

fn rand_fill(b: &mut [u8]) -> Res<()> {
    getrandom::getrandom(b).map_err(|e| EngineError::Protocol(format!("rng: {e}")))
}

impl Conn {
    fn connect(cfg: &ConnCfg) -> Res<Conn> {
        let addr = (cfg.host.as_str(), cfg.port)
            .to_socket_addrs()
            .map_err(ioerr)?
            .next()
            .ok_or_else(|| EngineError::Io("address did not resolve".into()))?;
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(ioerr)?;
        let _ = s.set_nodelay(true);
        // keep parked and idle-while-paused connections alive: a socket that sends nothing during a flood
        // pause or between files gets dropped by the NAT / the peer and then fails with "reset by peer"
        let ka = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(15))
            .with_interval(Duration::from_secs(10));
        let _ = socket2::SockRef::from(&s).set_tcp_keepalive(&ka);
        // BBR ramps up faster and holds its speed on a long or slightly lossy path (cubic backs off on
        // every loss). Best effort: a kernel or sandbox without it just keeps its default.
        #[cfg(target_os = "linux")]
        {
            let cc = std::env::var("CBCRYPTO_TCP_CC").unwrap_or_else(|_| "bbr".into());
            if !cc.is_empty() && cc != "off" {
                let _ = socket2::SockRef::from(&s).set_tcp_congestion(cc.as_bytes());
            }
        }
        if cfg.recv_buf > 0 {
            let _ = socket2::SockRef::from(&s).set_recv_buffer_size(cfg.recv_buf);
        }
        let _ = s.set_read_timeout(Some(cfg.read_timeout));
        let _ = s.set_write_timeout(Some(Duration::from_secs(30)));

        // obfuscated abridged init, identical to pyrogram's TCPAbridgedO
        let mut nonce = [0u8; 64];
        loop {
            rand_fill(&mut nonce)?;
            let head = &nonce[..4];
            let reserved = head == b"HEAD" || head == b"POST" || head == b"GET " || head == b"OPTI" || head == [0xee; 4];
            if nonce[0] != 0xef && !reserved && nonce[4..8] != [0u8; 4] {
                nonce[56..60].copy_from_slice(&[0xef; 4]);
                break;
            }
        }
        let rev: Vec<u8> = nonce[8..56].iter().rev().copied().collect();
        let mut enc = CtrSt { key: nonce[8..40].try_into().unwrap(), iv: nonce[40..56].try_into().unwrap(), st: 0 };
        let dec = CtrSt { key: rev[0..32].try_into().unwrap(), iv: rev[32..48].try_into().unwrap(), st: 0 };
        let mut enc_nonce = nonce;
        enc.apply(&mut enc_nonce); // advances the send stream past the 64 init bytes
        let mut init = nonce;
        init[56..64].copy_from_slice(&enc_nonce[56..64]);
        let mut s = s;
        s.write_all(&init).map_err(ioerr)?;

        let mut session_id = [0u8; 8];
        rand_fill(&mut session_id)?;
        Ok(Conn {
            s,
            enc,
            dec,
            auth_key: cfg.auth_key.clone(),
            auth_key_id: cfg.auth_key_id.clone(),
            session_id,
            salt: cfg.salt,
            seq: 0,
            last_msg_id: 0,
            time_offset: cfg.time_offset,
            acks: Vec::new(),
            last_ack: Instant::now(),
            inited: false,
            init_prefix: cfg.init_prefix.clone(),
            rbuf: Vec::new(),
            sent: HashMap::new(),
        })
    }

    /// Server-corrected unix time as a raw msg_id base (seconds << 32 | fraction), integer exact:
    /// an f64 cannot hold 2^63-sized ids precisely enough to keep two sends apart.
    fn time_id(&self) -> i64 {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let nanos = d.as_nanos() as i128 + (self.time_offset * 1e9) as i128;
        let secs = nanos.div_euclid(1_000_000_000);
        let frac = (nanos.rem_euclid(1_000_000_000) << 32) / 1_000_000_000;
        ((secs << 32) | frac) as i64
    }

    fn new_msg_id(&mut self) -> i64 {
        let mut id = self.time_id() & !3;
        if id <= self.last_msg_id {
            id = self.last_msg_id + 4; // strictly increasing, never a repeat
        }
        self.last_msg_id = id;
        id
    }

    fn sync_time(&mut self, server_msg_id: i64) {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        self.time_offset = (server_msg_id >> 32) as f64 - wall;
        // Forget the "last id" guard only if our earlier ids ran AHEAD of the corrected clock
        // (they would otherwise keep us in the future). Resetting it unconditionally let two
        // messages share an id when several bad_msg_notifications arrived back to back.
        if self.last_msg_id > self.time_id() + (1i64 << 32) {
            self.last_msg_id = 0;
        }
    }

    /// Send one TL body; returns its msg_id. Wraps it in invokeWithLayer+initConnection
    /// until the server has answered once.
    fn send_request(&mut self, body: &[u8]) -> Res<i64> {
        if self.inited || self.init_prefix.is_empty() {
            self.send_body(body, true)
        } else {
            let mut wrapped = Vec::with_capacity(self.init_prefix.len() + body.len());
            wrapped.extend_from_slice(&self.init_prefix);
            wrapped.extend_from_slice(body);
            self.send_body(&wrapped, true)
        }
    }

    fn send_body(&mut self, body: &[u8], content: bool) -> Res<i64> {
        let msg_id = self.new_msg_id();
        if content {
            if self.sent.len() > 8192 {
                self.sent.clear(); // answers that never came (bad salt, resent): do not grow without bound
            }
            self.sent.insert(msg_id, Instant::now());
        }
        let seq_no = if content {
            let v = self.seq * 2 + 1;
            self.seq += 1;
            v
        } else {
            self.seq * 2
        } as i32;
        let plen = packed_len(body.len());
        let words = plen / 4;
        let hdr = if words <= 126 { 1 } else { 4 };
        let mut buf = vec![0u8; hdr + plen];
        if hdr == 1 {
            buf[0] = words as u8;
        } else {
            buf[0] = 0x7f;
            buf[1..4].copy_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        if !pack_fill(&mut buf[hdr..], msg_id, seq_no, body, self.salt, &self.session_id, &self.auth_key, &self.auth_key_id) {
            return Err(EngineError::Protocol("rng failure".into()));
        }
        self.enc.apply(&mut buf);
        self.s.write_all(&buf).map_err(ioerr)?;
        Ok(msg_id)
    }

    fn read_exact(&mut self, n: usize, field: &str) -> Res<()> {
        self.rbuf.resize(n, 0);
        self.s.read_exact(&mut self.rbuf[..n]).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => {
                EngineError::PeerDisconnected(format!(
                    "connection closed by peer while reading {field} ({n} bytes expected)"
                ))
            }
            _ => ioerr(e),
        })
    }

    /// Read one transport packet into `self.rbuf`.
    fn recv_packet(&mut self) -> Res<()> {
        self.read_exact(1, "packet header")?;
        let mut first = [self.rbuf[0]];
        self.dec.apply(&mut first);
        let mut words = first[0] as usize;
        if first[0] == 0x7f {
            self.read_exact(3, "extended packet length")?;
            let mut l = [self.rbuf[0], self.rbuf[1], self.rbuf[2]];
            self.dec.apply(&mut l);
            words = l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16;
        }
        let len = words * 4;
        if len == 0 || len > (1 << 25) {
            return Err(EngineError::Protocol(format!("bad packet length {len}")));
        }
        self.read_exact(len, "packet body")?;
        let mut buf = std::mem::take(&mut self.rbuf);
        self.dec.apply(&mut buf[..len]);
        self.rbuf = buf;
        if len == 4 {
            let code = i32::from_le_bytes(self.rbuf[..4].try_into().unwrap());
            return Err(EngineError::Io(format!("transport error {code}")));
        }
        Ok(())
    }

    fn recv_events<F>(&mut self, f: &mut F) -> Res<()>
    where
        F: FnMut(Event<'_>) -> Res<()>,
    {
        self.recv_packet()?;
        let packet = std::mem::take(&mut self.rbuf);
        let r = unpack_core(&packet, &self.session_id, &self.auth_key, &self.auth_key_id, true);
        self.rbuf = packet;
        let buf = r.map_err(|e| EngineError::Protocol(e.to_string()))?;
        let p = &buf[32..];
        let (msg_id, seq, length) = parse_plain(p).map_err(|e| EngineError::Protocol(e.to_string()))?;
        let body = &p[32..32 + length as usize];
        self.dispatch(msg_id, seq, body, f)
    }

    fn dispatch<F>(&mut self, msg_id: i64, seq: i32, body: &[u8], f: &mut F) -> Res<()>
    where
        F: FnMut(Event<'_>) -> Res<()>,
    {
        if seq & 1 == 1 {
            self.acks.push(msg_id);
        }
        let bad = || EngineError::Protocol("truncated message".into());
        match rd_u32(body, 0).ok_or_else(bad)? {
            CONTAINER => {
                let n = rd_i32(body, 4).ok_or_else(bad)?;
                let mut off = 8usize;
                for _ in 0..n.clamp(0, 1020) {
                    let mid = rd_i64(body, off).ok_or_else(bad)?;
                    let sq = rd_i32(body, off + 8).ok_or_else(bad)?;
                    let bl = rd_i32(body, off + 12).ok_or_else(bad)?;
                    if bl < 0 {
                        return Err(bad());
                    }
                    let inner = body.get(off + 16..off + 16 + bl as usize).ok_or_else(bad)?;
                    self.dispatch(mid, sq, inner, f)?;
                    off += 16 + bl as usize;
                }
                Ok(())
            }
            GZIP_PACKED => {
                let (s, l, _) = tl_bytes_at(body, 4).ok_or_else(bad)?;
                let inner = gunzip(&body[s..s + l])?;
                self.dispatch(msg_id, 0, &inner, f)
            }
            RPC_RESULT => {
                let req = rd_i64(body, 4).ok_or_else(bad)?;
                self.handle_result(req, body.get(12..).ok_or_else(bad)?, f)
            }
            NEW_SESSION => {
                self.salt = rd_i64(body, 20).ok_or_else(bad)?;
                Ok(())
            }
            BAD_SERVER_SALT => {
                let bad_msg_id = rd_i64(body, 4).ok_or_else(bad)?;
                self.salt = rd_i64(body, 20).ok_or_else(bad)?;
                f(Event::BadSalt { bad_msg_id })
            }
            BAD_MSG_NOTIFICATION => {
                let bad_msg_id = rd_i64(body, 4).ok_or_else(bad)?;
                let code = rd_i32(body, 16).ok_or_else(bad)?;
                if code == 16 || code == 17 {
                    self.sync_time(msg_id);
                }
                f(Event::BadMsg { bad_msg_id, code })
            }
            MSGS_ACK => Ok(()),
            _ => f(Event::Other),
        }
    }

    fn handle_result<F>(&mut self, req: i64, res: &[u8], f: &mut F) -> Res<()>
    where
        F: FnMut(Event<'_>) -> Res<()>,
    {
        let bad = || EngineError::Protocol("truncated result".into());
        let sent = self.sent.remove(&req);
        match rd_u32(res, 0).ok_or_else(bad)? {
            RPC_ERROR => {
                let code = rd_i32(res, 4).ok_or_else(bad)?;
                let (s, l, _) = tl_bytes_at(res, 8).ok_or_else(bad)?;
                let message = String::from_utf8_lossy(&res[s..s + l]).into_owned();
                f(Event::RpcError { req, code, message, sent })
            }
            UPLOAD_FILE => {
                // ctor, storage.FileType ctor, mtime:int, bytes
                let (s, l, _) = tl_bytes_at(res, 12).ok_or_else(bad)?;
                self.inited = true;
                f(Event::File { req, data: &res[s..s + l] })
            }
            CDN_REDIRECT => f(Event::Cdn),
            BOOL_TRUE => {
                self.inited = true;
                f(Event::Bool { req, ok: true })
            }
            BOOL_FALSE => f(Event::Bool { req, ok: false }),
            GZIP_PACKED => {
                let (s, l, _) = tl_bytes_at(res, 4).ok_or_else(bad)?;
                let inner = gunzip(&res[s..s + l])?;
                self.handle_result(req, &inner, f)
            }
            _ => f(Event::Other),
        }
    }

    fn flush_acks(&mut self, force: bool) -> Res<()> {
        if self.acks.is_empty() {
            return Ok(());
        }
        if !force && self.acks.len() < 8 && self.last_ack.elapsed() < Duration::from_secs(2) {
            return Ok(());
        }
        let ids = std::mem::take(&mut self.acks);
        let mut body = Vec::with_capacity(16 + ids.len() * 8);
        body.extend_from_slice(&MSGS_ACK.to_le_bytes());
        body.extend_from_slice(&VECTOR.to_le_bytes());
        body.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in ids {
            body.extend_from_slice(&id.to_le_bytes());
        }
        self.last_ack = Instant::now();
        self.send_body(&body, false)?;
        Ok(())
    }
}


// ------------------------------------------------------------------ warm connection pool

/// Connections kept open between transfers. A new file used to open every connection from scratch
/// (TCP handshake, a cold congestion window, initConnection) and only then reach full speed, which
/// is why short files never got there and big ones started slowly. A connection that finished its
/// share cleanly is parked here for a short time and handed to the next transfer on the same
/// endpoint and account. Off with CBCRYPTO_POOL=0.
type PoolKey = (String, u16, Vec<u8>);
const POOL_MAX_PER_KEY: usize = 24;

fn pool_enabled() -> bool {
    std::env::var("CBCRYPTO_POOL").map_or(true, |v| v != "0")
}

fn pool_ttl() -> Duration {
    Duration::from_secs(
        std::env::var("CBCRYPTO_POOL_TTL").ok().and_then(|v| v.parse().ok()).unwrap_or(45),
    )
}

fn pool_reg() -> &'static Mutex<HashMap<PoolKey, Vec<(Conn, Instant)>>> {
    static REG: OnceLock<Mutex<HashMap<PoolKey, Vec<(Conn, Instant)>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pool_key(c: &ConnCfg) -> PoolKey {
    (c.host.clone(), c.port, c.auth_key_id.clone())
}

/// False if the peer closed the socket or it errored while idle.
fn conn_alive(c: &Conn) -> bool {
    if c.s.set_nonblocking(true).is_err() {
        return false;
    }
    let mut b = [0u8; 1];
    let r = c.s.peek(&mut b);
    let _ = c.s.set_nonblocking(false);
    match r {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
    }
}

fn pool_put(cfg: &ConnCfg, c: Conn) {
    if !pool_enabled() {
        return;
    }
    let ttl = pool_ttl();
    let now = Instant::now();
    let mut reg = pool_reg().lock().unwrap();
    reg.retain(|_, v| {
        v.retain(|(_, t)| now.duration_since(*t) < ttl);
        !v.is_empty()
    });
    let mut c = c;
    c.sent.clear();
    let slot = reg.entry(pool_key(cfg)).or_default();
    if slot.len() < POOL_MAX_PER_KEY {
        slot.push((c, now));
    }
}

fn pool_take(cfg: &ConnCfg) -> Option<Conn> {
    if !pool_enabled() {
        return None;
    }
    let ttl = pool_ttl();
    loop {
        let c = {
            let mut reg = pool_reg().lock().unwrap();
            let slot = reg.get_mut(&pool_key(cfg))?;
            let (c, t) = slot.pop()?;
            if slot.is_empty() {
                reg.remove(&pool_key(cfg));
            }
            (c, t)
        };
        if c.1.elapsed() < ttl && conn_alive(&c.0) {
            let _ = c.0.s.set_read_timeout(Some(cfg.read_timeout));
            return Some(c.0);
        }
        // expired or closed by the peer: drop it and try the next one
    }
}

// ------------------------------------------------------------------ shared transfer state

struct Shared {
    cancel: AtomicBool,
    err: Mutex<Option<EngineError>>,
    last_err: Mutex<Option<EngineError>>,
    done_bytes: AtomicU64,
    active: AtomicUsize,
    next: AtomicUsize,
    total: usize,
    retry: Mutex<VecDeque<usize>>,
    pacer: Option<Arc<Pacer>>,
    flood_slept: Mutex<f64>,
    flood_events: Mutex<Vec<f64>>,
    floods: AtomicU64,
    flood_ms: AtomicU64,
    flood_max_ms: AtomicU64,
    reconnects: AtomicU64,
    timeouts: AtomicU64,
    server_errs: AtomicUsize,
    completed: AtomicUsize,
    remaining: usize,
    last_progress: Mutex<Instant>,
    stall_limit: Duration,
    flood_total_cap: f64,
    flood_each_cap: f64,
    file: File,
    // geometry
    size: u64,
    unit: u64,
    start: u64,
}

impl Shared {
    fn fail(&self, e: EngineError) {
        let mut g = self.err.lock().unwrap();
        // keep the first real error; Cancelled is only ever a symptom of somebody else's failure
        if g.is_none() && !matches!(e, EngineError::Cancelled) {
            *g = Some(e);
        }
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// The worker's chunks are back in the queue. Report its error if the transfer ends incomplete.
    fn give_up(&self, e: EngineError) {
        *self.last_err.lock().unwrap() = Some(e);
    }

    fn take(&self) -> Option<usize> {
        if let Some(i) = self.retry.lock().unwrap().pop_front() {
            return Some(i);
        }
        let i = self.next.fetch_add(1, Ordering::SeqCst);
        (i < self.total).then_some(i)
    }

    fn requeue(&self, i: usize) {
        self.retry.lock().unwrap().push_back(i);
    }

    /// Keep pending chunks spread across workers as the unassigned queue gets shorter.
    fn fair_share(&self) -> usize {
        let unassigned = self.total.saturating_sub(self.next.load(Ordering::Relaxed))
            + self.retry.lock().unwrap().len();
        let active = self.active.load(Ordering::Relaxed).max(1);
        unassigned.div_ceil(active).max(1)
    }

    fn sleep_cancellable(&self, secs: f64) -> bool {
        let end = Instant::now() + Duration::from_secs_f64(secs);
        while Instant::now() < end {
            if self.cancel.load(Ordering::Relaxed) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        true
    }
}

fn parse_flood(message: &str) -> Option<f64> {
    for p in ["FLOOD_WAIT_", "FLOOD_PREMIUM_WAIT_", "SLOWMODE_WAIT_"] {
        if let Some(r) = message.strip_prefix(p) {
            return r.parse::<f64>().ok();
        }
    }
    None
}

/// (chunk index, seconds to wait before re-sending it)
struct Act(usize, f64);

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Download,
    Upload,
}

#[derive(Clone)]
struct TransferCfg {
    conn: ConnCfg,
    mode: Mode,
    inflight: usize,
    max_reconnects: u32,
    // download
    req_prefix: Vec<u8>,
    // upload
    file_id: i64,
    is_big: bool,
    total_parts: i32,
}

fn build_request(sh: &Shared, cfg: &TransferCfg, idx: usize) -> Res<Vec<u8>> {
    let off = sh.start + idx as u64 * sh.unit;
    match cfg.mode {
        Mode::Download => {
            let mut b = Vec::with_capacity(cfg.req_prefix.len() + 12);
            b.extend_from_slice(&cfg.req_prefix);
            b.extend_from_slice(&(off as i64).to_le_bytes());
            b.extend_from_slice(&(sh.unit as i32).to_le_bytes());
            Ok(b)
        }
        Mode::Upload => {
            let len = (sh.size - off).min(sh.unit) as usize;
            let mut data = vec![0u8; len];
            read_exact_at(&sh.file, &mut data, off).map_err(|e| {
                let reason = if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    "unexpected end of file".to_string()
                } else {
                    e.to_string()
                };
                EngineError::FileIo(format!("reading upload file at offset {off} ({len} bytes): {reason}"))
            })?;
            let mut b = Vec::with_capacity(len + 40);
            b.extend_from_slice(&(if cfg.is_big { SAVE_BIG_FILE_PART } else { SAVE_FILE_PART }).to_le_bytes());
            b.extend_from_slice(&cfg.file_id.to_le_bytes());
            // part numbers are absolute: `start` is a byte offset only for the unit math
            let part = (off / sh.unit) as i32;
            b.extend_from_slice(&part.to_le_bytes());
            if cfg.is_big {
                b.extend_from_slice(&cfg.total_parts.to_le_bytes());
            }
            tl_bytes_put(&mut b, &data);
            Ok(b)
        }
    }
}

fn send_chunk(sh: &Shared, cfg: &TransferCfg, c: &mut Conn, idx: usize) -> Res<i64> {
    let body = build_request(sh, cfg, idx)?;
    let r = c.send_request(&body);
    dbg_log!("send chunk {idx} -> {:?}", r.as_ref().map_err(|e| format!("{e:?}")));
    r
}

/// One connected session's work loop. Returns Ok when there is nothing left to do.
fn run_session(sh: &Shared, cfg: &TransferCfg, c: &mut Conn, inflight: &mut HashMap<i64, usize>, failures: &mut u32) -> Res<()> {
    loop {
        if sh.cancel.load(Ordering::Relaxed) {
            return Err(EngineError::Cancelled);
        }
        let window = cfg.inflight.min(sh.fair_share());
        while inflight.len() < window {
            let Some(idx) = sh.take() else { break };
            if let Some(p) = &sh.pacer {
                if cfg.mode == Mode::Download && !inflight.is_empty() {
                    // Process replies already on the way while the pacer limits new sends.
                    if !p.try_acquire() {
                        sh.requeue(idx);
                        break;
                    }
                } else if !p.acquire(&sh.cancel) {
                    sh.requeue(idx);
                    return Err(EngineError::Cancelled);
                }
            }
            match send_chunk(sh, cfg, c, idx) {
                Ok(mid) => {
                    if let Some(old) = inflight.insert(mid, idx) {
                        sh.requeue(old); // msg_id collision: never lose the earlier chunk
                    }
                }
                Err(e) => {
                    sh.requeue(idx);
                    return Err(e);
                }
            }
        }
        if inflight.is_empty() {
            // nothing queued and nothing in flight here: only finish when EVERY chunk is done,
            // another connection may still fail and hand its chunks back to the queue
            if sh.completed.load(Ordering::SeqCst) >= sh.remaining {
                return Ok(());
            }
            if sh.last_progress.lock().unwrap().elapsed() > sh.stall_limit {
                return Err(EngineError::Protocol(format!(
                    "transfer stalled: {} of {} chunks done, none in flight",
                    sh.completed.load(Ordering::SeqCst), sh.remaining
                )));
            }
            std::thread::sleep(Duration::from_millis(15));
            continue;
        }

        let mut acts: Vec<Act> = Vec::new();
        let mut fatal: Option<EngineError> = None;
        let mut reconnect = false;
        let recv = c.recv_events(&mut |ev| {
            match ev {
                Event::File { req, data } if cfg.mode == Mode::Download => {
                    dbg_log!("file for req {req} known={}", inflight.contains_key(&req));
                    if let Some(idx) = inflight.remove(&req) {
                        let off = sh.start + idx as u64 * sh.unit;
                        let expect = (sh.size - off).min(sh.unit) as usize;
                        if data.len() < expect {
                            fatal = Some(EngineError::Protocol(format!("short chunk: got {} of {} bytes at offset {}", data.len(), expect, off)));
                            return Ok(());
                        }
                        write_all_at(&sh.file, &data[..expect], off).map_err(|e| {
                            EngineError::FileIo(format!("writing download file at offset {off} ({expect} bytes): {e}"))
                        })?;
                        *failures = 0;
                        sh.done_bytes.fetch_add(expect as u64, Ordering::Relaxed);
                        { sh.completed.fetch_add(1, Ordering::SeqCst); *sh.last_progress.lock().unwrap() = Instant::now(); }
                        if let Some(p) = &sh.pacer {
                            p.on_success();
                        }
                    }
                }
                Event::Bool { req, ok } if cfg.mode == Mode::Upload => {
                    if let Some(idx) = inflight.remove(&req) {
                        if !ok {
                            fatal = Some(EngineError::Protocol(format!("server refused part {idx}")));
                            return Ok(());
                        }
                        let off = sh.start + idx as u64 * sh.unit;
                        *failures = 0;
                        sh.done_bytes.fetch_add((sh.size - off).min(sh.unit), Ordering::Relaxed);
                        { sh.completed.fetch_add(1, Ordering::SeqCst); *sh.last_progress.lock().unwrap() = Instant::now(); }
                        if let Some(p) = &sh.pacer {
                            p.on_success();
                        }
                    }
                }
                Event::RpcError { req, code, message, sent } => {
                    if let Some(idx) = inflight.remove(&req) {
                        if let Some(secs) = parse_flood(&message) {
                            if secs > sh.flood_each_cap {
                                fatal = Some(EngineError::Rpc { code, message });
                            } else {
                                // One flood is answered by every request that was in flight; only the first
                                // reply starts the shared pause. Count and report the flood once, and charge
                                // the total budget what was really waited, not once per answering request.
                                let fresh = match &sh.pacer {
                                    Some(p) => p.on_flood_wait_for(secs, sent),
                                    None => true,
                                };
                                let mut slept = sh.flood_slept.lock().unwrap();
                                if fresh && *slept + secs > sh.flood_total_cap {
                                    fatal = Some(EngineError::Rpc { code, message });
                                } else {
                                    if fresh {
                                        *slept += secs;
                                        sh.flood_events.lock().unwrap().push(secs);
                                    }
                                    sh.floods.fetch_add(1, Ordering::Relaxed);
                                    sh.flood_ms.fetch_add((secs * 1000.0) as u64, Ordering::Relaxed);
                                    sh.flood_max_ms.fetch_max((secs * 1000.0) as u64, Ordering::Relaxed);
                                    // With a pacer the pause already holds every connection (acquire waits for
                                    // it), so a per-request sleep on top only stacked waits: four refused
                                    // requests on one connection slept four times as long.
                                    acts.push(Act(idx, if sh.pacer.is_some() { 0.0 } else { secs }));
                                }
                            }
                        } else if (500..600).contains(&code) && sh.server_errs.fetch_add(1, Ordering::Relaxed) < 20 {
                            acts.push(Act(idx, 1.0)); // INTERNAL & friends: transient, retry
                        } else {
                            fatal = Some(EngineError::Rpc { code, message });
                        }
                    }
                }
                Event::Cdn => fatal = Some(EngineError::Cdn),
                Event::BadSalt { bad_msg_id } => {
                    dbg_log!("bad_salt for {bad_msg_id} inflight={}", inflight.contains_key(&bad_msg_id));
                    if let Some(idx) = inflight.remove(&bad_msg_id) {
                        acts.push(Act(idx, 0.0));
                    }
                }
                Event::BadMsg { bad_msg_id, code } => { dbg_log!("bad_msg {code} for {bad_msg_id} inflight={}", inflight.contains_key(&bad_msg_id)); match code {
                    16 | 17 => {
                        if let Some(idx) = inflight.remove(&bad_msg_id) {
                            acts.push(Act(idx, 0.0));
                        }
                    }
                    32 | 33 => reconnect = true, // seq_no out of step: a fresh session fixes it
                    _ => fatal = Some(EngineError::Protocol(format!("bad_msg_notification {code}"))),
                } },
                _ => {}
            }
            Ok(())
        });
        if let Some(e) = fatal {
            return Err(e);
        }
        let session_error = recv.err().or_else(|| {
            reconnect.then(|| EngineError::Io("server asked for a fresh session".into()))
        });
        if let Some(e) = session_error {
            for Act(idx, _) in acts {
                sh.requeue(idx);
            }
            return Err(e);
        }
        if sh.completed.load(Ordering::SeqCst) >= sh.remaining {
            return Ok(());
        }
        let mut acts: VecDeque<Act> = acts.into();
        while let Some(Act(idx, secs)) = acts.pop_front() {
            let step = (|| -> Res<()> {
                if secs > 0.0 && !sh.sleep_cancellable(secs) {
                    return Err(EngineError::Cancelled);
                }
                // a retry is a request like any other: without this, every chunk that was refused
                // at the same moment comes back at the same instant, as an unpaced burst
                if let Some(p) = &sh.pacer {
                    if !p.acquire(&sh.cancel) {
                        return Err(EngineError::Cancelled);
                    }
                }
                let mid = send_chunk(sh, cfg, c, idx)?;
                if let Some(old) = inflight.insert(mid, idx) {
                    sh.requeue(old);
                }
                Ok(())
            })();
            if let Err(e) = step {
                sh.requeue(idx);
                for Act(i, _) in acts.drain(..) {
                    sh.requeue(i);
                }
                return Err(e);
            }
        }
        c.flush_acks(false)?;
    }
}

/// 0.5 s, 1 s, 2 s, 4 s, 8 s, then 8 s, plus up to 0.5 s of jitter so that 15 workers whose sockets
/// were reset together do not all dial again in the same instant.
fn backoff_secs(failures: u32) -> f64 {
    let base = (0.5 * 2f64.powi(failures.saturating_sub(1).min(4) as i32)).min(8.0);
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() % 500) as f64 / 1000.0)
        .unwrap_or(0.0);
    base + jitter
}

static RECONNECT_LOGS: AtomicUsize = AtomicUsize::new(0);

fn worker(sh: Arc<Shared>, mut cfg: TransferCfg) {
    let mut conn: Option<Conn> = None;
    let mut inflight: HashMap<i64, usize> = HashMap::new();
    let mut failures = 0u32;
    let mut clean = false;
    loop {
        if sh.cancel.load(Ordering::Relaxed) {
            break;
        }
        if conn.is_none() {
            if failures > 0 && sh.completed.load(Ordering::SeqCst) >= sh.remaining {
                break;
            }
            // first connection of this worker: reuse a warm one if there is one. After an error the
            // worker always dials a fresh connection (the pool may hold ones from the same bad path).
            let warm = if failures == 0 { pool_take(&cfg.conn) } else { None };
            let attempt = match warm {
                Some(c) => Ok(c),
                None => Conn::connect(&cfg.conn),
            };
            match attempt {
                Ok(c) => conn = Some(c),
                Err(e) => {
                    failures += 1;
                    if failures > cfg.max_reconnects {
                        sh.give_up(e);
                        break;
                    }
                    if !sh.sleep_cancellable(backoff_secs(failures)) {
                        break;
                    }
                    continue;
                }
            }
        }
        let c = conn.as_mut().unwrap();
        // Only progress made on this connection resets its retry budget.
        let result = run_session(&sh, &cfg, c, &mut inflight, &mut failures);
        match result {
            Ok(()) => {
                clean = c.flush_acks(true).is_ok();
                break;
            }
            Err(EngineError::Cancelled) => {
                break;
            }
            Err(e @ (EngineError::Io(_) | EngineError::PeerDisconnected(_) | EngineError::Timeout(_))) => {
                sh.reconnects.fetch_add(1, Ordering::Relaxed);
                if matches!(e, EngineError::Timeout(_)) {
                    sh.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                if cfg.mode == Mode::Download && matches!(e, EngineError::PeerDisconnected(_)) {
                    // Retry on a fresh socket with fewer outstanding download requests.
                    cfg.inflight = cfg.inflight.div_ceil(2);
                }
                // always say WHY a connection was lost (a few lines per process, so the log never floods):
                // "transport error -429" = Telegram refused us, a bare "Connection reset" = the network did
                if std::env::var_os("CBCRYPTO_DEBUG").is_some() || RECONNECT_LOGS.fetch_add(1, Ordering::Relaxed) < 40 {
                    eprintln!(
                        "[cbcrypto] connection lost: {e:?} | {} MiB done, {} connections, next window {}, failure #{}",
                        sh.done_bytes.load(Ordering::Relaxed) >> 20,
                        sh.active.load(Ordering::Relaxed),
                        cfg.inflight,
                        failures + 1
                    );
                }
                for (_, idx) in inflight.drain() {
                    sh.requeue(idx);
                }
                conn = None;
                failures += 1;
                if failures > cfg.max_reconnects {
                    sh.give_up(e);
                    break;
                }
                if !sh.sleep_cancellable(backoff_secs(failures)) {
                    break;
                }
            }
            Err(e) => {
                sh.fail(e);
                break;
            }
        }
    }
    if clean && inflight.is_empty() && !sh.cancel.load(Ordering::Relaxed) {
        if let Some(c) = conn.take() {
            pool_put(&cfg.conn, c);
        }
    }
    dbg_log!("worker exit (completed {}/{})", sh.completed.load(Ordering::SeqCst), sh.remaining);
    sh.active.fetch_sub(1, Ordering::SeqCst);
}

// ------------------------------------------------------------------ python entry points

/// One pacer per (account auth key, direction), shared by every transfer running on that account at
/// the same time and kept for ten minutes after, so what was learned about the limit is not thrown away.
/// Telegram judges the *account*: three files uploading at once with a pacer each ask for three times
/// the allowed rate, which is exactly what produced the flood storms. Off with CBCRYPTO_SHARED_PACER=0.
type PacerKey = (Vec<u8>, bool);
const PACER_KEEP: Duration = Duration::from_secs(600); // what was learned about the limit survives gaps between files

fn shared_pacer(key: PacerKey, c: &PacerCfg) -> Arc<Pacer> {
    static REG: OnceLock<Mutex<HashMap<PacerKey, (Arc<Pacer>, Instant)>>> = OnceLock::new();
    let mut reg = REG.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    let now = Instant::now();
    reg.retain(|_, (p, used)| Arc::strong_count(p) > 1 || now.duration_since(*used) < PACER_KEEP);
    let slot = reg.entry(key).or_insert_with(|| (Arc::new(Pacer::new(c)), now));
    slot.1 = now;
    slot.0.clone()
}

fn make_pacer(cfg: &TransferCfg, c: &PacerCfg) -> Arc<Pacer> {
    if std::env::var("CBCRYPTO_SHARED_PACER").map_or(false, |v| v == "0") {
        return Arc::new(Pacer::new(c));
    }
    let p = shared_pacer((cfg.conn.auth_key_id.clone(), cfg.mode == Mode::Upload), c);
    p.lift_to_dip_level();
    p
}

#[allow(clippy::too_many_arguments)]
fn run_transfer(
    py: Python<'_>,
    cfg: TransferCfg,
    file: File,
    size: u64,
    unit: u64,
    start: u64,
    total_units: usize,
    first_unit: usize,
    connections: usize,
    pacer: Option<PacerCfg>,
    flood_each_cap: f64,
    flood_total_cap: f64,
    progress: Option<PyObject>,
    stats: Option<Py<pyo3::types::PyDict>>,
    on_flood: Option<PyObject>,
) -> PyResult<u64> {
    let sh = Arc::new(Shared {
        cancel: AtomicBool::new(false),
        err: Mutex::new(None),
        last_err: Mutex::new(None),
        done_bytes: AtomicU64::new(0),
        active: AtomicUsize::new(0),
        next: AtomicUsize::new(first_unit),
        total: total_units,
        retry: Mutex::new(VecDeque::new()),
        pacer: pacer.as_ref().map(|c| make_pacer(&cfg, c)),
        flood_slept: Mutex::new(0.0),
        flood_events: Mutex::new(Vec::new()),
        floods: AtomicU64::new(0),
        flood_ms: AtomicU64::new(0),
        flood_max_ms: AtomicU64::new(0),
        reconnects: AtomicU64::new(0),
        timeouts: AtomicU64::new(0),
        server_errs: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        remaining: total_units.saturating_sub(first_unit),
        last_progress: Mutex::new(Instant::now()),
        stall_limit: Duration::from_secs_f64((cfg.conn.read_timeout.as_secs_f64() * 2.0 + flood_each_cap + 5.0).max(10.0)),
        flood_total_cap,
        flood_each_cap,
        file,
        size,
        unit,
        start,
    });
    let n = connections.max(1).min(total_units.saturating_sub(first_unit).max(1));
    sh.active.store(n, Ordering::SeqCst);
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let (s, c) = (sh.clone(), cfg.clone());
            std::thread::spawn(move || worker(s, c))
        })
        .collect();

    let mut last_reported = u64::MAX;
    let mut py_err: Option<PyErr> = None;
    loop {
        py.allow_threads(|| std::thread::sleep(Duration::from_millis(40)));
        if let Err(e) = py.check_signals() {
            py_err = Some(e);
            sh.cancel.store(true, Ordering::SeqCst);
            break;
        }
        let done = sh.done_bytes.load(Ordering::Relaxed);
        if let Some(cb) = &progress {
            // every tick, even without new bytes: this is also how Python gets to cancel a stalled transfer
            last_reported = done;
            if let Err(e) = cb.call1(py, (done,)) {
                py_err = Some(e);
                sh.cancel.store(true, Ordering::SeqCst);
                break;
            }
        }
        if let Some(cb) = &on_flood {
            let evs = std::mem::take(&mut *sh.flood_events.lock().unwrap());
            for secs in evs {
                let _ = cb.call1(py, (secs,));
            }
        }
        if sh.active.load(Ordering::SeqCst) == 0 {
            break;
        }
    }
    py.allow_threads(|| {
        for h in handles {
            let _ = h.join();
        }
    });
    if let Some(cb) = &on_flood {
        for secs in std::mem::take(&mut *sh.flood_events.lock().unwrap()) {
            let _ = cb.call1(py, (secs,));
        }
    }
    if let Some(d) = &stats {
        // what really happened on the wire: lets the caller tell flood waits, reconnects and a slow
        // link apart instead of guessing from the speed curve
        let d = d.bind(py);
        let _ = d.set_item("floods", sh.floods.load(Ordering::Relaxed));
        let _ = d.set_item("flood_seconds", sh.flood_ms.load(Ordering::Relaxed) as f64 / 1000.0);
        let _ = d.set_item("flood_max_seconds", sh.flood_max_ms.load(Ordering::Relaxed) as f64 / 1000.0);
        let _ = d.set_item("reconnects", sh.reconnects.load(Ordering::Relaxed));
        let _ = d.set_item("timeouts", sh.timeouts.load(Ordering::Relaxed));
        let _ = d.set_item("server_errors", sh.server_errs.load(Ordering::Relaxed));
        if let Some(p) = &sh.pacer {
            let _ = d.set_item("pace_end", p.rate());
        }
    }
    if let Some(e) = py_err {
        return Err(e);
    }
    let done = sh.done_bytes.load(Ordering::Relaxed);
    if let Some(cb) = &progress {
        if done != last_reported {
            cb.call1(py, (done,))?;
        }
    }
    if let Some(e) = sh.err.lock().unwrap().take() {
        return Err(to_pyerr(e));
    }
    let expected = if cfg.mode == Mode::Download {
        size - start
    } else {
        size - (first_unit as u64 * unit).min(size)
    };
    if done != expected {
        if let Some(e) = sh.last_err.lock().unwrap().take() {
            return Err(to_pyerr(e));
        }
        return Err(to_pyerr(EngineError::Protocol(format!("incomplete transfer: {done} of {expected} bytes"))));
    }
    Ok(done)
}

fn pacer_cfg(paced: bool, rate: f64, burst: f64, ceiling: f64, step: f64, growth: f64, cap: f64, floor: f64, burst_credit: f64, sustain: f64) -> Option<PacerCfg> {
    paced.then_some(PacerCfg { rate, burst, ceiling, step, growth, slow_start_cap: cap, hard_floor: floor, burst_credit, sustain })
}

#[pyfunction]
#[pyo3(signature = (host, port, auth_key, auth_key_id, salt, init_prefix, req_prefix, path, file_size,
                    start_offset=0, chunk_size=1048576, connections=5, inflight=3, paced=true,
                    rate=8.0, burst=8.0, ceiling=150.0, step=0.5, growth=1.5, slow_start_cap=40.0,
                    progress=None, time_offset=0.0, recv_buffer=0, read_timeout=30.0,
                    flood_each_cap=30.0, flood_total_cap=300.0, max_reconnects=5, floor=1.0, stats=None, on_flood=None, burst_credit=0.0, sustain=0.0))]
#[allow(clippy::too_many_arguments)]
fn download(
    py: Python<'_>,
    host: String,
    port: u16,
    auth_key: Vec<u8>,
    auth_key_id: Vec<u8>,
    salt: i64,
    init_prefix: Vec<u8>,
    req_prefix: Vec<u8>,
    path: String,
    file_size: u64,
    start_offset: u64,
    chunk_size: u64,
    connections: usize,
    inflight: usize,
    paced: bool,
    rate: f64,
    burst: f64,
    ceiling: f64,
    step: f64,
    growth: f64,
    slow_start_cap: f64,
    progress: Option<PyObject>,
    time_offset: f64,
    recv_buffer: usize,
    read_timeout: f64,
    flood_each_cap: f64,
    flood_total_cap: f64,
    max_reconnects: u32,
    floor: f64,
    stats: Option<Py<pyo3::types::PyDict>>,
    on_flood: Option<PyObject>,
    burst_credit: f64,
    sustain: f64,
) -> PyResult<u64> {
    check_common(&auth_key, &auth_key_id, chunk_size)?;
    if start_offset % chunk_size != 0 || start_offset >= file_size {
        return Err(pyo3::exceptions::PyValueError::new_err("start_offset must be chunk aligned and inside the file"));
    }
    let total = ((file_size - start_offset).div_ceil(chunk_size)) as usize;
    let file = std::fs::OpenOptions::new().write(true).open(&path).map_err(|e| to_pyerr(ioerr(e)))?;
    let cfg = TransferCfg {
        conn: ConnCfg {
            host, port, auth_key, auth_key_id, salt, init_prefix, time_offset, recv_buf: recv_buffer,
            read_timeout: Duration::from_secs_f64(read_timeout),
        },
        mode: Mode::Download,
        inflight: inflight.max(1),
        max_reconnects,
        req_prefix,
        file_id: 0,
        is_big: false,
        total_parts: 0,
    };
    run_transfer(
        py, cfg, file, file_size, chunk_size, start_offset, total, 0, connections,
        pacer_cfg(paced, rate, burst, ceiling, step, growth, slow_start_cap, floor, burst_credit, sustain),
        flood_each_cap, flood_total_cap, progress, stats, on_flood,
    )
}

#[pyfunction]
#[pyo3(signature = (host, port, auth_key, auth_key_id, salt, init_prefix, path, file_size, file_id,
                    part_size=524288, start_part=0, is_big=true, connections=5, inflight=3, paced=true,
                    rate=32.0, burst=16.0, ceiling=300.0, step=1.0, growth=1.5, slow_start_cap=80.0,
                    progress=None, time_offset=0.0, recv_buffer=0, read_timeout=30.0,
                    flood_each_cap=30.0, flood_total_cap=300.0, max_reconnects=5, floor=1.0, stats=None, on_flood=None, burst_credit=0.0, sustain=0.0))]
#[allow(clippy::too_many_arguments)]
fn upload(
    py: Python<'_>,
    host: String,
    port: u16,
    auth_key: Vec<u8>,
    auth_key_id: Vec<u8>,
    salt: i64,
    init_prefix: Vec<u8>,
    path: String,
    file_size: u64,
    file_id: i64,
    part_size: u64,
    start_part: usize,
    is_big: bool,
    connections: usize,
    inflight: usize,
    paced: bool,
    rate: f64,
    burst: f64,
    ceiling: f64,
    step: f64,
    growth: f64,
    slow_start_cap: f64,
    progress: Option<PyObject>,
    time_offset: f64,
    recv_buffer: usize,
    read_timeout: f64,
    flood_each_cap: f64,
    flood_total_cap: f64,
    max_reconnects: u32,
    floor: f64,
    stats: Option<Py<pyo3::types::PyDict>>,
    on_flood: Option<PyObject>,
    burst_credit: f64,
    sustain: f64,
) -> PyResult<u64> {
    check_common(&auth_key, &auth_key_id, part_size)?;
    let total_parts = file_size.div_ceil(part_size) as usize;
    if total_parts == 0 || start_part >= total_parts {
        return Err(pyo3::exceptions::PyValueError::new_err("nothing to upload"));
    }
    let file = File::open(&path).map_err(|e| to_pyerr(ioerr(e)))?;
    let cfg = TransferCfg {
        conn: ConnCfg {
            host, port, auth_key, auth_key_id, salt, init_prefix, time_offset, recv_buf: recv_buffer,
            read_timeout: Duration::from_secs_f64(read_timeout),
        },
        mode: Mode::Upload,
        inflight: inflight.max(1),
        max_reconnects,
        req_prefix: Vec::new(),
        file_id,
        is_big,
        total_parts: total_parts as i32,
    };
    run_transfer(
        py, cfg, file, file_size, part_size, 0, total_parts, start_part, connections,
        pacer_cfg(paced, rate, burst, ceiling, step, growth, slow_start_cap, floor, burst_credit, sustain),
        flood_each_cap, flood_total_cap, progress, stats, on_flood,
    )
}

fn check_common(auth_key: &[u8], auth_key_id: &[u8], unit: u64) -> PyResult<()> {
    use pyo3::exceptions::PyValueError;
    if auth_key.len() != 256 {
        return Err(PyValueError::new_err("auth_key must be 256 bytes"));
    }
    if auth_key_id.len() != 8 {
        return Err(PyValueError::new_err("auth_key_id must be 8 bytes"));
    }
    if unit == 0 || unit % 1024 != 0 {
        return Err(PyValueError::new_err("chunk/part size must be a positive multiple of 1024"));
    }
    Ok(())
}

#[pyfunction]
fn _constants() -> HashMap<&'static str, u32> {
    constants().into_iter().collect()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(download, m)?)?;
    m.add_function(wrap_pyfunction!(upload, m)?)?;
    m.add_function(wrap_pyfunction!(_constants, m)?)?;
    m.add("CoreError", m.py().get_type_bound::<CoreError>())?;
    Ok(())
        }

#[cfg(test)]
mod shared_pacer_tests {
    use super::*;

    fn cfg() -> PacerCfg {
        PacerCfg { rate: 45.0, burst: 8.0, ceiling: 60.0, step: 0.5, growth: 1.1, slow_start_cap: 60.0, hard_floor: 20.0, burst_credit: 0.0, sustain: 0.0 }
    }

    #[test]
    fn same_account_shares_one_pacer_others_do_not() {
        let a1 = shared_pacer((vec![1; 8], true), &cfg());
        let a2 = shared_pacer((vec![1; 8], true), &cfg());
        let down = shared_pacer((vec![1; 8], false), &cfg());
        let b = shared_pacer((vec![2; 8], true), &cfg());
        assert!(Arc::ptr_eq(&a1, &a2), "two uploads of one account must share a pacer");
        assert!(!Arc::ptr_eq(&a1, &down), "upload and download are judged separately");
        assert!(!Arc::ptr_eq(&a1, &b), "another bot has its own limit");
        a1.on_flood_wait(0.0);
        assert!(a2.rate() < 45.0, "a flood seen by one upload slows the other");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tcp_cc_tests {
    #[test]
    fn bbr_is_applied_when_the_kernel_has_it() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let s = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let avail = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control").unwrap_or_default();
        let r = socket2::SockRef::from(&s).set_tcp_congestion(b"bbr");
        if avail.split_whitespace().any(|a| a == "bbr") {
            r.expect("bbr is available but could not be set");
            let got = socket2::SockRef::from(&s).tcp_congestion().unwrap();
            assert!(got.starts_with(b"bbr"), "socket reports {:?}", String::from_utf8_lossy(&got));
        } // else: a kernel without bbr must simply fail quietly, which is what connect() relies on
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use std::net::TcpListener;

    fn cfg_for(port: u16, key: u8) -> ConnCfg {
        ConnCfg {
            host: "127.0.0.1".into(),
            port,
            auth_key: vec![key; 256],
            auth_key_id: vec![key; 8],
            salt: 0,
            init_prefix: Vec::new(),
            time_offset: 0.0,
            recv_buf: 0,
            read_timeout: Duration::from_secs(5),
        }
    }

    /// A listener that accepts and keeps every connection open, reading the 64 init bytes.
    fn quiet_server() -> (u16, std::sync::mpsc::Receiver<TcpStream>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s2 = s.try_clone().unwrap();
                let mut b = [0u8; 64];
                let _ = s2.read_exact(&mut b);
                let _ = tx.send(s);
            }
        });
        (port, rx)
    }

    #[test]
    fn a_parked_connection_is_handed_to_the_next_transfer() {
        let (port, _rx) = quiet_server();
        let cfg = cfg_for(port, 11);
        let c = Conn::connect(&cfg).unwrap();
        let local = c.s.local_addr().unwrap();
        pool_put(&cfg, c);
        let again = pool_take(&cfg).expect("a warm connection should be available");
        assert_eq!(again.s.local_addr().unwrap(), local, "must be the same socket, not a new one");
        assert!(pool_take(&cfg).is_none(), "a connection is handed out once");
    }

    #[test]
    fn another_account_never_gets_it() {
        let (port, _rx) = quiet_server();
        let cfg = cfg_for(port, 12);
        pool_put(&cfg, Conn::connect(&cfg).unwrap());
        assert!(pool_take(&cfg_for(port, 13)).is_none());
        assert!(pool_take(&cfg).is_some());
    }

    #[test]
    fn a_connection_closed_by_the_peer_is_not_reused() {
        let (port, rx) = quiet_server();
        let cfg = cfg_for(port, 14);
        pool_put(&cfg, Conn::connect(&cfg).unwrap());
        let server_side = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(server_side);
        std::thread::sleep(Duration::from_millis(200));
        assert!(pool_take(&cfg).is_none(), "a dead socket must be skipped, not handed out");
    }
}

#[cfg(test)]
mod e2e_tests {
    //! Whole-transfer tests against a fake Telegram: real sockets, real MTProto framing and crypto, a
    //! server that enforces a requests/s limit and answers over-limit requests with FLOOD_WAIT_1.
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize as AU;

    const TEST_GET_FILE: u32 = 0x0387_a08e;

    pub struct Srv {
        pub limit: usize,
        pub accepted: AU,
        pub parts: Mutex<HashSet<i32>>,
        pub flood_replies: AU,
        first_download_reply: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        reject_download_pipeline: AtomicBool,
        window: Mutex<VecDeque<Instant>>,
        penalty: Mutex<Option<Instant>>,
    }

    fn tl_str(b: &mut Vec<u8>, s: &str) {
        b.push(s.len() as u8);
        b.extend_from_slice(s.as_bytes());
        while b.len() % 4 != 0 {
            b.push(0);
        }
    }

    fn srv_packet(tx: &mut CtrSt, auth_key: &[u8], session_id: &[u8], msg_id: i64, body: &[u8]) -> Vec<u8> {
        let plain_len = 32 + body.len();
        let pad = (16 - (plain_len + 12) % 16) % 16 + 12;
        let total = 24 + plain_len + pad;
        let mut buf = vec![0u8; total];
        let (head, plain) = buf.split_at_mut(24);
        head[..8].copy_from_slice(&auth_key[..8]); // test auth_key_id == first 8 bytes of the key
        plain[8..16].copy_from_slice(session_id);
        plain[16..24].copy_from_slice(&msg_id.to_le_bytes());
        plain[24..28].copy_from_slice(&1i32.to_le_bytes()); // content-related: the client acks it
        plain[28..32].copy_from_slice(&(body.len() as u32).to_le_bytes());
        plain[32..plain_len].copy_from_slice(body);
        let h = Sha256::new().chain_update(&auth_key[96..128]).chain_update(&*plain).finalize();
        head[8..24].copy_from_slice(&h[8..24]);
        let (k, iv) = crate::kdf_raw(auth_key, &head[8..24], false);
        crate::ige_enc_inplace_any(&k, &iv, plain);
        let words = total / 4;
        let mut out = Vec::with_capacity(4 + total);
        if words <= 126 {
            out.push(words as u8);
        } else {
            out.push(0x7f);
            out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        out.extend_from_slice(&buf);
        tx.apply(&mut out);
        out
    }

    fn request_new_session(msg_id: i64) -> Vec<u8> {
        let mut reply = Vec::new();
        reply.extend_from_slice(&CONTAINER.to_le_bytes());
        reply.extend_from_slice(&2i32.to_le_bytes());
        for (id, constructor, code, len) in [
            (0x6000_0000_0000_0005i64, BAD_SERVER_SALT, 48i32, 28i32),
            (0x6000_0000_0000_0009i64, BAD_MSG_NOTIFICATION, 32i32, 20i32),
        ] {
            reply.extend_from_slice(&id.to_le_bytes());
            reply.extend_from_slice(&0i32.to_le_bytes()); // seq_no
            reply.extend_from_slice(&len.to_le_bytes());
            reply.extend_from_slice(&constructor.to_le_bytes());
            reply.extend_from_slice(&msg_id.to_le_bytes());
            reply.extend_from_slice(&1i32.to_le_bytes()); // bad_msg_seqno
            reply.extend_from_slice(&code.to_le_bytes());
            if constructor == BAD_SERVER_SALT {
                reply.extend_from_slice(&1i64.to_le_bytes());
            }
        }
        reply
    }

    fn serve(mut s: TcpStream, auth_key: Vec<u8>, st: Arc<Srv>, interrupt_connections: bool) {
        let mut init = [0u8; 64];
        if s.read_exact(&mut init).is_err() {
            return;
        }
        let connection = st.accepted.fetch_add(1, Ordering::SeqCst);
        let rev: Vec<u8> = init[8..56].iter().rev().copied().collect();
        let mut rx = CtrSt { key: init[8..40].try_into().unwrap(), iv: init[40..56].try_into().unwrap(), st: 0 };
        let mut skip = init;
        rx.apply(&mut skip);
        let mut tx = CtrSt { key: rev[0..32].try_into().unwrap(), iv: rev[32..48].try_into().unwrap(), st: 0 };
        let mut counter = 0i64;
        loop {
            let mut b = [0u8; 1];
            if s.read_exact(&mut b).is_err() {
                return;
            }
            rx.apply(&mut b);
            let mut words = b[0] as usize;
            if b[0] == 0x7f {
                let mut l = [0u8; 3];
                if s.read_exact(&mut l).is_err() {
                    return;
                }
                rx.apply(&mut l);
                words = l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16;
            }
            let mut pkt = vec![0u8; words * 4];
            if s.read_exact(&mut pkt).is_err() {
                return;
            }
            rx.apply(&mut pkt);
            let (k, iv) = crate::kdf_raw(&auth_key, &pkt[8..24], true);
            let mut plain = vec![0u8; pkt.len() - 24];
            crate::ige_dec_any(&k, &iv, &pkt[24..], &mut plain);
            let session_id: [u8; 8] = plain[8..16].try_into().unwrap();
            let msg_id = i64::from_le_bytes(plain[16..24].try_into().unwrap());
            let len = u32::from_le_bytes(plain[28..32].try_into().unwrap()) as usize;
            let body = &plain[32..32 + len];
            if rd_u32(body, 0) == Some(TEST_GET_FILE) {
                if counter == 0 && st.reject_download_pipeline.load(Ordering::Relaxed) {
                    // Reset sockets that send a second request before the first reply.
                    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
                    let mut next = [0];
                    match s.peek(&mut next) {
                        Ok(0) => return,
                        Ok(_) => {
                            socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO)).unwrap();
                            return;
                        }
                        Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {}
                        Err(_) => return,
                    }
                    s.set_read_timeout(None).unwrap();
                }
                let limit = rd_i32(body, 12).unwrap() as usize;
                let mut reply = RPC_RESULT.to_le_bytes().to_vec();
                reply.extend_from_slice(&msg_id.to_le_bytes());
                reply.extend_from_slice(&UPLOAD_FILE.to_le_bytes());
                reply.extend_from_slice(&[0; 8]); // storage type and mtime
                tl_bytes_put(&mut reply, &vec![7; limit]);
                counter += 1;
                let packet = srv_packet(&mut tx, &auth_key, &session_id, 0x6000_0000_0000_0000 + counter * 4 + 1, &reply);
                s.write_all(&packet).unwrap();
                if let Some(sent) = st.first_download_reply.lock().unwrap().take() {
                    let _ = sent.send(());
                }
                continue;
            }
            if body.len() < 20 || u32::from_le_bytes(body[0..4].try_into().unwrap()) != SAVE_BIG_FILE_PART {
                continue; // an ack
            }
            if interrupt_connections {
                match connection {
                    0 => {
                        socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO)).unwrap();
                        return;
                    }
                    1 | 2 => {
                        let reply = if connection == 1 {
                            BOOL_TRUE.to_le_bytes().to_vec()
                        } else {
                            request_new_session(msg_id)
                        };
                        let mut packet = srv_packet(&mut tx, &auth_key, &session_id, 0x6000_0000_0000_000d, &reply);
                        if connection == 1 {
                            packet.truncate(packet.len() - 4);
                        }
                        s.write_all(&packet).unwrap();
                        s.shutdown(std::net::Shutdown::Write).unwrap();
                        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        let _ = std::io::copy(&mut s, &mut std::io::sink());
                        return;
                    }
                    _ => {}
                }
            }
            let part = i32::from_le_bytes(body[12..16].try_into().unwrap());
            let now = Instant::now();
            let flood = {

                let mut pen = st.penalty.lock().unwrap();
                let mut w = st.window.lock().unwrap();
                while w.front().map_or(false, |t| now.duration_since(*t) > Duration::from_secs(1)) {
                    w.pop_front();
                }
                if pen.map_or(false, |t| now < t) {
                    true
                } else if w.len() >= st.limit {
                    *pen = Some(now + Duration::from_secs(1));
                    true
                } else {
                    w.push_back(now);
                    false
                }
            };
            let mut reply = Vec::new();
            reply.extend_from_slice(&RPC_RESULT.to_le_bytes());
            reply.extend_from_slice(&msg_id.to_le_bytes());
            if flood {
                st.flood_replies.fetch_add(1, Ordering::SeqCst);
                reply.extend_from_slice(&RPC_ERROR.to_le_bytes());
                reply.extend_from_slice(&420i32.to_le_bytes());
                tl_str(&mut reply, "FLOOD_WAIT_1");
            } else {
                st.parts.lock().unwrap().insert(part);
                reply.extend_from_slice(&BOOL_TRUE.to_le_bytes());
            }
            counter += 1;
            let packet = srv_packet(&mut tx, &auth_key, &session_id, 0x6000_0000_0000_0000 + counter * 4 + 1, &reply);
            let _ = s.write_all(&packet);
        }
    }

    pub fn start_server(key: u8, limit: usize, interrupt_connections: bool) -> (u16, Arc<Srv>, Vec<u8>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut auth_key = vec![key; 256];
        for (i, b) in auth_key.iter_mut().enumerate() {
            *b = key.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let st = Arc::new(Srv {
            limit,
            accepted: AU::new(0),
            parts: Mutex::new(HashSet::new()),
            flood_replies: AU::new(0),
            first_download_reply: Mutex::new(None),
            reject_download_pipeline: AtomicBool::new(false),
            window: Mutex::new(VecDeque::new()),
            penalty: Mutex::new(None),
        });
        let (st2, ak) = (st.clone(), auth_key.clone());
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (st3, ak3) = (st2.clone(), ak.clone());
                std::thread::spawn(move || serve(s, ak3, st3, interrupt_connections));
            }
        });
        (port, st, auth_key)
    }

    pub struct Out {
        pub sh: Arc<Shared>,
        pub secs: f64,
    }

    pub fn upload(port: u16, auth_key: &[u8], parts: usize, unit: u64, conns: usize, rate: f64, ceiling: f64) -> Out {
        transfer(port, auth_key, parts, unit, conns, rate, ceiling, Mode::Upload)
    }

    fn transfer_path(port: u16, parts: usize) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cbcrypto-e2e-{}-{}-{}", port, parts, std::process::id()))
    }

    fn transfer(port: u16, auth_key: &[u8], parts: usize, unit: u64, conns: usize, rate: f64, ceiling: f64, mode: Mode) -> Out {
        let size = parts as u64 * unit;
        let path = transfer_path(port, parts);
        let file = if mode == Mode::Download {
            File::create(&path).unwrap()
        } else {
            std::fs::write(&path, vec![7u8; size as usize]).unwrap();
            File::open(&path).unwrap()
        };
        let conn = ConnCfg {
            host: "127.0.0.1".into(),
            port,
            auth_key: auth_key.to_vec(),
            auth_key_id: auth_key[..8].to_vec(),
            salt: 0,
            init_prefix: Vec::new(),
            time_offset: 0.0,
            recv_buf: 0,
            read_timeout: Duration::from_secs(10),
        };
        let cfg = TransferCfg {
            conn,
            mode,
            inflight: 4,
            max_reconnects: 5,
            req_prefix: TEST_GET_FILE.to_le_bytes().to_vec(),
            file_id: 42,
            is_big: true,
            total_parts: parts as i32,
        };
        let burst = if mode == Mode::Download { 1.0 } else { 8.0 };
        let pc = PacerCfg { rate, burst, ceiling, step: 1.0, growth: 1.1, slow_start_cap: rate, hard_floor: 20.0, burst_credit: 0.0, sustain: 0.0 };
        let sh = Arc::new(Shared {
            cancel: AtomicBool::new(false),
            err: Mutex::new(None),
            last_err: Mutex::new(None),
            done_bytes: AtomicU64::new(0),
            active: AtomicUsize::new(conns),
            next: AtomicUsize::new(0),
            total: parts,
            retry: Mutex::new(VecDeque::new()),
            pacer: (rate > 0.0).then(|| make_pacer(&cfg, &pc)),
            flood_slept: Mutex::new(0.0),
            flood_events: Mutex::new(Vec::new()),
            floods: AtomicU64::new(0),
            flood_ms: AtomicU64::new(0),
            flood_max_ms: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            server_errs: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            remaining: parts,
            last_progress: Mutex::new(Instant::now()),
            stall_limit: Duration::from_secs(60),
            flood_total_cap: 300.0,
            flood_each_cap: 30.0,
            file,
            size,
            unit,
            start: 0,
        });
        let t0 = Instant::now();
        let hs: Vec<_> = (0..conns)
            .map(|_| {
                let (s, c) = (sh.clone(), cfg.clone());
                std::thread::spawn(move || worker(s, c))
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let _ = std::fs::remove_file(path);
        Out { sh, secs: t0.elapsed().as_secs_f64() }
    }

    pub fn failed(o: &Out) -> Option<String> {
        o.sh.err.lock().unwrap().as_ref().map(|e| format!("{e:?}"))
    }

    #[test]
    fn download_writes_ready_chunk_before_waiting_for_next_send_permit() {
        let (port, srv, key) = start_server(4, 100_000, false);
        let (sent, received) = std::sync::mpsc::channel();
        *srv.first_download_reply.lock().unwrap() = Some(sent);
        // With a burst of one, the second request has to wait four seconds.
        let worker = std::thread::spawn(move || transfer(port, &key, 2, 4096, 1, 0.25, 0.25, Mode::Download));
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        let path = transfer_path(port, 2);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut first_chunk_ready = false;
        while Instant::now() < deadline {
            if std::fs::read(&path).is_ok_and(|data| data.len() == 4096 && data.iter().all(|&byte| byte == 7)) {
                first_chunk_ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = worker.join().unwrap();
        assert!(first_chunk_ready, "the first reply must be written before the next send permit");
        assert!(failed(&out).is_none(), "transfer failed: {:?}", failed(&out));
        assert_eq!(out.sh.done_bytes.load(Ordering::Relaxed), 2 * 4096);
    }

    #[test]
    fn download_reduces_pipeline_after_repeated_peer_resets() {
        let (port, srv, key) = start_server(5, 100_000, false);
        srv.reject_download_pipeline.store(true, Ordering::Relaxed);
        let out = transfer(port, &key, 4, 4096, 1, 0.0, 0.0, Mode::Download);
        assert!(failed(&out).is_none(), "transfer failed: {:?}", failed(&out));
        assert_eq!(out.sh.reconnects.load(Ordering::Relaxed), 2);
        assert_eq!(out.sh.done_bytes.load(Ordering::Relaxed), 4 * 4096);
    }

    #[test]
    fn upload_resends_all_unconfirmed_parts_after_connection_loss() {
        let (port, srv, key) = start_server(3, 100_000, true);
        let out = upload(port, &key, 8, 4096, 1, 100.0, 100.0);
        assert!(failed(&out).is_none(), "transfer failed: {:?}", failed(&out));
        assert_eq!(out.sh.reconnects.load(Ordering::Relaxed), 3);
        assert_eq!(out.sh.done_bytes.load(Ordering::Relaxed), 8 * 4096);
        assert_eq!(srv.parts.lock().unwrap().len(), 8);
    }

    /// A pacer that asks for twice what the server allows: many floods, and the transfer must still
    /// deliver every part exactly once without being killed by the flood budget.
    #[test]
    fn a_flood_storm_does_not_kill_or_corrupt_the_transfer() {
        let (port, srv, key) = start_server(1, 60, false);
        let o = upload(port, &key, 900, 4096, 8, 150.0, 200.0);
        let floods = srv.flood_replies.load(Ordering::SeqCst);
        eprintln!("storm: {:.1}s, flood replies {}, logged floods {}, slept {:.0}s, err {:?}",
            o.secs, floods, o.sh.flood_events.lock().unwrap().len(), *o.sh.flood_slept.lock().unwrap(), failed(&o));
        assert!(failed(&o).is_none(), "transfer failed: {:?}", failed(&o));
        assert_eq!(srv.parts.lock().unwrap().len(), 900, "every part must arrive");
        assert!(floods > 0, "the test must actually flood");
        // The server refuses only while the pacer is above its limit. Before the fix, replies to requests
        // already in the pipe were each taken for a new flood: the rate fell to 5 req/s after a single
        // refusal and the file took ~63 s instead of ~23 s.
        assert!(o.secs < 40.0, "a flood storm must not collapse the rate: took {:.1}s", o.secs);
    }

    /// The next file reuses the connections the previous one finished with instead of dialling again.
    #[test]
    fn the_next_transfer_reuses_warm_connections() {
        let (port, srv, key) = start_server(2, 100_000, false);
        let a = upload(port, &key, 200, 4096, 8, 400.0, 600.0);
        assert!(failed(&a).is_none());
        let after_first = srv.accepted.load(Ordering::SeqCst);
        assert_eq!(after_first, 8, "first transfer dials its 8 connections");
        let b = upload(port, &key, 200, 4096, 8, 400.0, 600.0);
        assert!(failed(&b).is_none());
        assert_eq!(srv.accepted.load(Ordering::SeqCst), after_first, "second transfer must dial nothing new");
        assert_eq!(srv.parts.lock().unwrap().len(), 200);
    }
    }
