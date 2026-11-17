//! Native TL codec: the hot path of every incoming and outgoing MTProto message.
//!
//! The generated Python classes parse and serialize themselves field by field,
//! which costs several interpreter calls per field (BytesIO.read, struct.unpack,
//! slicing, ...). Here the whole object tree is decoded in one native pass and
//! only the final Python objects are created. The layout comes from a schema
//! table emitted by cbgram's compiler (`raw/tl_spec.py`), so it can never drift
//! away from the generated classes.
//!
//! Anything the table does not cover (legacy constructors, user subclasses that
//! override `write`) transparently falls back to the original Python code.

use pyo3::exceptions::{PyKeyError, PyOverflowError, PyTypeError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{OnceLock, RwLock};

const ID_VECTOR: u32 = 0x1cb5_c415;
const ID_BOOL_TRUE: u32 = 0x9972_75b5;
const ID_BOOL_FALSE: u32 = 0xbc79_9737;
const ID_CONTAINER: u32 = 0x73f1_f8dc;
const ID_GZIP: u32 = 0x3072_cfa1;
const ID_MESSAGE: u32 = 0x5bb8_e511;
const ID_FUTURE_SALTS: u32 = 0xae50_0895;
const ID_FUTURE_SALT: u32 = 0x0949_d9dc;

const NO_SLOT: u8 = 255;
const MAX_DEPTH: u32 = 256;
const MAX_GUNZIP: u64 = 1 << 28;

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

struct Field {
    name: Py<PyString>,
    code: u8,  // # i q I J d b s B t O W V
    vcode: u8, // element code when code == V
    slot: u8,  // flags word index, NO_SLOT if unconditional
    bit: u8,
}

struct Spec {
    id: u32,
    fields: Vec<Field>,
    cls: OnceLock<Py<PyAny>>,
}

struct Hooks {
    resolver: Py<PyAny>, // objects.__getitem__
    fallback: Py<PyAny>, // (cid_pos, buf, pos) -> (obj, newpos)
    list_cls: Py<PyAny>,
    msg_cls: Py<PyAny>,
    container_cls: Py<PyAny>,
    fsalts_cls: Py<PyAny>,
    fsalt_cls: Py<PyAny>,
    on_skip: Py<PyAny>,
}

struct Registry {
    specs: HashMap<u32, Spec>,
    hooks: Hooks,
    // type pointer -> (keep-alive, Some(cid) when the native writer may be used)
    types: RwLock<HashMap<usize, (Py<PyAny>, Option<u32>)>>,
}

static REG: OnceLock<Registry> = OnceLock::new();

fn reg() -> PyResult<&'static Registry> {
    REG.get()
        .ok_or_else(|| PyValueError::new_err("cbcrypto TL codec is not initialised (tl_init)"))
}

impl Spec {
    fn class<'py>(&self, py: Python<'py>, hooks: &Hooks) -> PyResult<Bound<'py, PyAny>> {
        if let Some(c) = self.cls.get() {
            return Ok(c.bind(py).clone());
        }
        let c = hooks.resolver.bind(py).call1((self.id,))?;
        let _ = self.cls.set(c.clone().unbind());
        Ok(c)
    }
}

fn parse_spec(py: Python<'_>, text: &str) -> PyResult<HashMap<u32, Spec>> {
    let mut specs = HashMap::with_capacity(3000);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, '|');
        let bad = || PyValueError::new_err(format!("bad TL spec line: {line}"));
        let id = u32::from_str_radix(parts.next().ok_or_else(bad)?, 16).map_err(|_| bad())?;
        let _path = parts.next().ok_or_else(bad)?;
        let rest = parts.next().ok_or_else(bad)?;
        let mut fields = Vec::new();
        if !rest.is_empty() {
            for f in rest.split(';') {
                let mut it = f.split(',');
                let name = it.next().ok_or_else(bad)?;
                let code = it.next().ok_or_else(bad)?.as_bytes();
                let slot = it.next().ok_or_else(bad)?;
                let bit = it.next().ok_or_else(bad)?;
                let slot = if slot == "-" { NO_SLOT } else { slot.parse::<u8>().map_err(|_| bad())? };
                let bit = if bit == "-" { 0 } else { bit.parse::<u8>().map_err(|_| bad())? };
                if code.is_empty() || slot != NO_SLOT && slot > 3 || bit > 31 {
                    return Err(bad());
                }
                let code0 = code[0];
                if !b"#iqIJdbsBtOWV".contains(&code0) {
                    return Err(bad());
                }
                let vcode = if code0 == b'V' { *code.get(1).ok_or_else(bad)? } else { 0 };
                fields.push(Field {
                    name: PyString::intern_bound(py, name).unbind(),
                    code: code0,
                    vcode,
                    slot,
                    bit,
                });
            }
        }
        specs.insert(id, Spec { id, fields, cls: OnceLock::new() });
    }
    Ok(specs)
}

/// Install the schema table and the Python-side hooks. Idempotent.
#[pyfunction]
fn tl_init(py: Python<'_>, spec: &str, hooks: &Bound<'_, PyDict>) -> PyResult<()> {
    if REG.get().is_some() {
        return Ok(());
    }
    let get = |k: &str| -> PyResult<Py<PyAny>> {
        Ok(hooks
            .get_item(k)?
            .ok_or_else(|| PyValueError::new_err(format!("tl_init: missing hook '{k}'")))?
            .unbind())
    };
    let hooks = Hooks {
        resolver: get("resolver")?,
        fallback: get("fallback")?,
        list_cls: get("list")?,
        msg_cls: get("message")?,
        container_cls: get("container")?,
        fsalts_cls: get("fsalts")?,
        fsalt_cls: get("fsalt")?,
        on_skip: get("on_skip")?,
    };
    let specs = parse_spec(py, spec)?;
    let _ = REG.set(Registry { specs, hooks, types: RwLock::new(HashMap::new()) });
    Ok(())
}

#[pyfunction]
fn tl_ready() -> bool {
    REG.get().is_some()
}

// ---------------------------------------------------------------------------
// reader
// ---------------------------------------------------------------------------

enum E {
    Eof,
    Deep,
    Unknown(u32),
    Py(PyErr),
}

impl From<PyErr> for E {
    fn from(e: PyErr) -> Self {
        E::Py(e)
    }
}

fn to_py(e: E) -> PyErr {
    match e {
        E::Eof => PyValueError::new_err("TL: unexpected end of data"),
        E::Deep => PyValueError::new_err("TL: object nesting too deep"),
        E::Unknown(c) => PyKeyError::new_err(c),
        E::Py(e) => e,
    }
}

type R<T> = Result<T, E>;

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    #[inline]
    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or(E::Eof)?;
        if end > self.b.len() {
            return Err(E::Eof);
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    #[inline]
    fn u32(&mut self) -> R<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    #[inline]
    fn i32(&mut self) -> R<i32> {
        Ok(self.u32()? as i32)
    }
    #[inline]
    fn i64(&mut self) -> R<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// TL `bytes` / `string` wire format.
    fn tl_bytes(&mut self) -> R<&'a [u8]> {
        let head = *self.b.get(self.p).ok_or(E::Eof)?;
        self.p += 1;
        let (len, pad) = if head <= 253 {
            (head as usize, (4 - (head as usize + 1) % 4) % 4)
        } else {
            let l = self.take(3)?;
            let len = l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16;
            (len, (4 - len % 4) % 4)
        };
        let data = self.take(len)?;
        // the Python reader tolerates a truncated trailer; so do we
        self.p = (self.p + pad).min(self.b.len());
        Ok(data)
    }
}

fn py_string(py: Python<'_>, raw: &[u8]) -> PyResult<PyObject> {
    if let Ok(s) = std::str::from_utf8(raw) {
        return Ok(PyString::new_bound(py, s).into_any().unbind());
    }
    // exactly Python's bytes.decode(errors="replace")
    unsafe {
        let p = ffi::PyUnicode_DecodeUTF8(
            raw.as_ptr() as *const std::os::raw::c_char,
            raw.len() as ffi::Py_ssize_t,
            b"replace\0".as_ptr() as *const std::os::raw::c_char,
        );
        if p.is_null() {
            return Err(PyErr::fetch(py));
        }
        Ok(Py::from_owned_ptr(py, p))
    }
}

fn big_int(py: Python<'_>, raw: &[u8]) -> PyResult<PyObject> {
    let kw = PyDict::new_bound(py);
    kw.set_item("signed", true)?;
    let int_t = py.get_type_bound::<pyo3::types::PyInt>();
    Ok(int_t.call_method("from_bytes", (PyBytes::new_bound(py, raw), "little"), Some(&kw))?.unbind())
}

fn read_core(py: Python<'_>, rd: &mut Rd<'_>, code: u8) -> R<PyObject> {
    Ok(match code {
        b'i' => rd.i32()?.into_py(py),
        b'q' => rd.i64()?.into_py(py),
        b'I' => big_int(py, rd.take(16)?)?,
        b'J' => big_int(py, rd.take(32)?)?,
        b'd' => f64::from_le_bytes(rd.take(8)?.try_into().unwrap()).into_py(py),
        b'b' => PyBytes::new_bound(py, rd.tl_bytes()?).into_any().unbind(),
        b's' => py_string(py, rd.tl_bytes()?)?,
        b'B' => (rd.u32()? == ID_BOOL_TRUE).into_py(py),
        _ => unreachable!("core code"),
    })
}

fn new_list(py: Python<'_>, h: &Hooks, items: Vec<PyObject>) -> PyResult<PyObject> {
    let l = PyList::new_bound(py, items);
    Ok(h.list_cls.bind(py).call1((l,))?.unbind())
}

fn read_typed_vector(py: Python<'_>, rd: &mut Rd<'_>, code: u8, h: &Hooks) -> R<PyObject> {
    let count = rd.i32()?;
    let mut items = Vec::with_capacity((count.max(0) as usize).min(rd.b.len().saturating_sub(rd.p) / 4 + 1));
    for _ in 0..count.max(0) {
        items.push(read_core(py, rd, code)?);
    }
    Ok(new_list(py, h, items)?)
}

/// `Vector.read(data)` with no element type: elements are TL objects, and when
/// they are not (a bare Vector<int>/<long> RPC result) the layout is guessed
/// from the remaining size, exactly like the Python implementation does.
fn read_dyn_vector(py: Python<'_>, rd: &mut Rd<'_>, r: &Registry, depth: u32) -> R<PyObject> {
    let count = rd.i32()?;
    if count <= 0 {
        return Ok(new_list(py, &r.hooks, Vec::new())?);
    }
    let pos = rd.p;
    let remaining = rd.b.len().saturating_sub(pos);
    let mut items = Vec::with_capacity((count as usize).min(remaining / 4 + 1));
    let mut ok = true;
    for _ in 0..count {
        match read_obj(py, rd, r, depth + 1) {
            Ok(o) => items.push(o),
            Err(_) => {
                ok = false;
                break;
            }
        }
    }
    if ok {
        return Ok(new_list(py, &r.hooks, items)?);
    }
    rd.p = pos;
    items = Vec::with_capacity((count as usize).min(remaining / 4 + 1));
    let cnt = count as usize;
    if remaining == cnt * 4 {
        for _ in 0..cnt {
            items.push(rd.i32()?.into_py(py));
        }
    } else if remaining == cnt * 8 {
        for _ in 0..cnt {
            items.push(rd.i64()?.into_py(py));
        }
    } else {
        for _ in 0..cnt {
            items.push(read_obj(py, rd, r, depth + 1)?);
        }
    }
    Ok(new_list(py, &r.hooks, items)?)
}

fn make_message(py: Python<'_>, h: &Hooks, body: PyObject, msg_id: i64, seq: i32, len: i32) -> PyResult<PyObject> {
    Ok(h.msg_cls.bind(py).call1((body, msg_id, seq, len))?.unbind())
}

fn sub_len(rd: &mut Rd<'_>) -> R<(i64, i32, i32, usize)> {
    let msg_id = rd.i64()?;
    let seq = rd.i32()?;
    let len = rd.i32()?;
    if len < 0 {
        return Err(E::Eof);
    }
    Ok((msg_id, seq, len, len as usize))
}

fn read_container(py: Python<'_>, rd: &mut Rd<'_>, r: &Registry, depth: u32) -> R<PyObject> {
    let count = rd.i32()?;
    let mut msgs: Vec<PyObject> = Vec::with_capacity((count.max(0) as usize).min(4096));
    for _ in 0..count.max(0) {
        let (msg_id, seq, len, n) = sub_len(rd)?;
        let body = rd.take(n)?;
        let mut sub = Rd { b: body, p: 0 };
        match read_obj(py, &mut sub, r, depth + 1) {
            Ok(o) => msgs.push(make_message(py, &r.hooks, o, msg_id, seq, len)?),
            Err(E::Unknown(cid)) => {
                r.hooks.on_skip.bind(py).call1((cid,))?;
            }
            Err(e) => return Err(e),
        }
    }
    let l = PyList::new_bound(py, msgs);
    Ok(r.hooks.container_cls.bind(py).call1((l,))?.unbind())
}

fn read_gzip(py: Python<'_>, rd: &mut Rd<'_>, r: &Registry, depth: u32) -> R<PyObject> {
    let packed = rd.tl_bytes()?;
    let mut out = Vec::with_capacity(packed.len() * 4);
    flate2::read::MultiGzDecoder::new(packed)
        .take(MAX_GUNZIP)
        .read_to_end(&mut out)
        .map_err(|e| PyValueError::new_err(format!("gzip: {e}")))?;
    let mut sub = Rd { b: &out, p: 0 };
    read_obj(py, &mut sub, r, depth + 1)
}

fn read_spec(py: Python<'_>, rd: &mut Rd<'_>, spec: &Spec, r: &Registry, depth: u32) -> R<PyObject> {
    let cls = spec.class(py, &r.hooks)?;
    let obj: PyObject = unsafe {
        let p = ffi::PyType_GenericAlloc(cls.as_ptr() as *mut ffi::PyTypeObject, 0);
        if p.is_null() {
            return Err(E::Py(PyErr::fetch(py)));
        }
        Py::from_owned_ptr(py, p)
    };
    let mut flags = [0u32; 4];

    for f in &spec.fields {
        if f.code == b'#' {
            flags[f.slot as usize] = rd.u32()?;
            continue;
        }
        let present = f.slot == NO_SLOT || flags[f.slot as usize] & (1u32 << f.bit) != 0;
        let value: PyObject = match f.code {
            b't' => present.into_py(py),
            b'V' => {
                if present {
                    let cid = rd.u32()?;
                    if cid == ID_VECTOR {
                        read_typed_vector(py, rd, f.vcode, &r.hooks)?
                    } else {
                        read_with_cid(py, rd, cid, r, depth + 1)?
                    }
                } else {
                    PyList::empty_bound(py).into_any().unbind()
                }
            }
            b'W' => {
                if present {
                    read_obj(py, rd, r, depth + 1)?
                } else {
                    PyList::empty_bound(py).into_any().unbind()
                }
            }
            b'O' => {
                if present {
                    read_obj(py, rd, r, depth + 1)?
                } else {
                    py.None()
                }
            }
            c => {
                if present {
                    read_core(py, rd, c)?
                } else {
                    py.None()
                }
            }
        };
        let rc = unsafe { ffi::PyObject_SetAttr(obj.as_ptr(), f.name.as_ptr(), value.as_ptr()) };
        if rc != 0 {
            return Err(E::Py(PyErr::fetch(py)));
        }
    }
    Ok(obj)
}

fn read_obj(py: Python<'_>, rd: &mut Rd<'_>, r: &Registry, depth: u32) -> R<PyObject> {
    let start = rd.p;
    let cid = rd.u32()?;
    read_with_cid_at(py, rd, cid, start, r, depth)
}

fn read_with_cid(py: Python<'_>, rd: &mut Rd<'_>, cid: u32, r: &Registry, depth: u32) -> R<PyObject> {
    let start = rd.p.saturating_sub(4);
    read_with_cid_at(py, rd, cid, start, r, depth)
}

fn read_with_cid_at(py: Python<'_>, rd: &mut Rd<'_>, cid: u32, start: usize, r: &Registry, depth: u32) -> R<PyObject> {
    if depth > MAX_DEPTH {
        return Err(E::Deep);
    }
    if let Some(spec) = r.specs.get(&cid) {
        return read_spec(py, rd, spec, r, depth);
    }
    match cid {
        ID_BOOL_TRUE => Ok(true.into_py(py)),
        ID_BOOL_FALSE => Ok(false.into_py(py)),
        ID_VECTOR => read_dyn_vector(py, rd, r, depth),
        ID_CONTAINER => read_container(py, rd, r, depth),
        ID_GZIP => read_gzip(py, rd, r, depth),
        ID_MESSAGE => {
            let (msg_id, seq, len, n) = sub_len(rd)?;
            let body = rd.take(n)?;
            let mut sub = Rd { b: body, p: 0 };
            let o = read_obj(py, &mut sub, r, depth + 1)?;
            Ok(make_message(py, &r.hooks, o, msg_id, seq, len)?)
        }
        ID_FUTURE_SALT => {
            let (a, b, c) = (rd.i32()?, rd.i32()?, rd.i64()?);
            Ok(r.hooks.fsalt_cls.bind(py).call1((a, b, c))?.unbind())
        }
        ID_FUTURE_SALTS => {
            let (req, now, count) = (rd.i64()?, rd.i32()?, rd.i32()?);
            let mut salts = Vec::new();
            // FutureSalt entries are bare (no constructor id) on the wire
            for _ in 0..count.max(0) {
                let (a, b, c) = (rd.i32()?, rd.i32()?, rd.i64()?);
                salts.push(r.hooks.fsalt_cls.bind(py).call1((a, b, c))?.unbind());
            }
            let l = PyList::new_bound(py, salts);
            Ok(r.hooks.fsalts_cls.bind(py).call1((req, now, l))?.unbind())
        }
        _ => fallback(py, rd, cid, start, r),
    }
}

/// Constructor the native table does not know: let the original Python reader
/// decide (legacy layouts, or an unknown id which raises KeyError).
fn fallback(py: Python<'_>, rd: &mut Rd<'_>, cid: u32, start: usize, r: &Registry) -> R<PyObject> {
    let buf = PyBytes::new_bound(py, rd.b);
    match r.hooks.fallback.bind(py).call1((start, buf)) {
        Ok(res) => {
            let (obj, newpos): (PyObject, usize) = res.extract()?;
            rd.p = newpos;
            Ok(obj)
        }
        Err(e) if e.is_instance_of::<PyKeyError>(py) => Err(E::Unknown(cid)),
        Err(e) => Err(E::Py(e)),
    }
}

/// `TLObject.read(BytesIO(data))`, natively.
#[pyfunction]
fn tl_parse(py: Python<'_>, data: &[u8]) -> PyResult<PyObject> {
    let r = reg()?;
    let mut rd = Rd { b: data, p: 0 };
    read_obj(py, &mut rd, r, 0).map_err(to_py)
}

// ---------------------------------------------------------------------------
// writer
// ---------------------------------------------------------------------------

fn put_tl_bytes(out: &mut Vec<u8>, data: &[u8]) -> PyResult<()> {
    let len = data.len();
    if len <= 253 {
        out.push(len as u8);
        out.extend_from_slice(data);
        out.extend(std::iter::repeat(0u8).take((4 - (len + 1) % 4) % 4));
    } else {
        if len >= 1 << 24 {
            return Err(PyOverflowError::new_err("int too big to convert"));
        }
        out.push(254);
        out.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
        out.extend_from_slice(data);
        out.extend(std::iter::repeat(0u8).take((4 - len % 4) % 4));
    }
    Ok(())
}

fn put_core(py: Python<'_>, v: &Bound<'_, PyAny>, code: u8, out: &mut Vec<u8>) -> PyResult<()> {
    match code {
        b'i' => {
            let n: i64 = v.extract()?;
            let n = i32::try_from(n).map_err(|_| PyOverflowError::new_err("int too big to convert"))?;
            out.extend_from_slice(&n.to_le_bytes());
        }
        b'q' => {
            let n: i64 = v.extract()?;
            out.extend_from_slice(&n.to_le_bytes());
        }
        b'I' | b'J' => {
            let size = if code == b'I' { 16 } else { 32 };
            let kw = PyDict::new_bound(py);
            kw.set_item("signed", true)?;
            let b = v.call_method("to_bytes", (size, "little"), Some(&kw))?;
            out.extend_from_slice(b.downcast::<PyBytes>()?.as_bytes());
        }
        b'd' => out.extend_from_slice(&v.extract::<f64>()?.to_le_bytes()),
        b'b' => {
            if let Ok(b) = v.downcast::<PyBytes>() {
                put_tl_bytes(out, b.as_bytes())?;
            } else if v.is_none() || v.downcast::<PyString>().is_ok() {
                return Err(PyTypeError::new_err("TL bytes field needs a bytes-like value"));
            } else {
                let b = py.get_type_bound::<PyBytes>().call1((v,))?;
                put_tl_bytes(out, b.downcast::<PyBytes>()?.as_bytes())?;
            }
        }
        b's' => {
            let s = v
                .downcast::<PyString>()
                .map_err(|_| PyTypeError::new_err("TL string field needs a str"))?;
            put_tl_bytes(out, s.to_cow()?.as_bytes())?;
        }
        b'B' => out.extend_from_slice(&(if v.is_truthy()? { ID_BOOL_TRUE } else { ID_BOOL_FALSE }).to_le_bytes()),
        _ => unreachable!("core code"),
    }
    Ok(())
}

/// Which spec (if any) may serialize this exact type natively.
fn native_cid(py: Python<'_>, r: &Registry, v: &Bound<'_, PyAny>) -> Option<u32> {
    let tp = v.get_type();
    let key = tp.as_ptr() as usize;
    if let Some((_, cid)) = r.types.read().unwrap().get(&key) {
        return *cid;
    }
    let cid = (|| -> Option<u32> {
        let cid: u32 = tp.getattr("ID").ok()?.extract().ok()?;
        let spec = r.specs.get(&cid)?;
        // a subclass that overrides write() must keep its own behaviour
        let cls = spec.class(py, &r.hooks).ok()?;
        cls.is(&tp).then_some(cid)
    })();
    r.types.write().unwrap().insert(key, (tp.into_any().unbind(), cid));
    cid
}

fn write_obj(py: Python<'_>, v: &Bound<'_, PyAny>, r: &Registry, out: &mut Vec<u8>, depth: u32) -> PyResult<()> {
    if depth > MAX_DEPTH {
        return Err(PyValueError::new_err("TL: object nesting too deep"));
    }
    if v.is_none() {
        return Err(pyo3::exceptions::PyAttributeError::new_err("'NoneType' object has no attribute 'write'"));
    }
    match native_cid(py, r, v) {
        Some(cid) => write_spec(py, v, &r.specs[&cid], r, out, depth),
        None => {
            let b = v.call_method0("write")?;
            out.extend_from_slice(b.downcast::<PyBytes>()?.as_bytes());
            Ok(())
        }
    }
}

fn write_spec(py: Python<'_>, obj: &Bound<'_, PyAny>, spec: &Spec, r: &Registry, out: &mut Vec<u8>, depth: u32) -> PyResult<()> {
    out.extend_from_slice(&spec.id.to_le_bytes());
    let mut flags = [0u32; 4];
    // value per field, None when the field is absent. Presence is decided per
    // field, not per flag bit: several fields may share one bit in a layer, and
    // the Python writer checks each field on its own.
    let mut vals: Vec<Option<Bound<'_, PyAny>>> = Vec::with_capacity(spec.fields.len());

    for f in &spec.fields {
        if f.code == b'#' {
            vals.push(None);
            continue;
        }
        let v = obj.getattr(f.name.bind(py))?;
        if f.slot != NO_SLOT {
            let present = match f.code {
                b't' | b'V' | b'W' => v.is_truthy()?,
                _ => !v.is_none(),
            };
            if present {
                flags[f.slot as usize] |= 1u32 << f.bit;
                vals.push(Some(v));
            } else {
                vals.push(None);
            }
        } else {
            vals.push(Some(v));
        }
    }

    for (f, v) in spec.fields.iter().zip(vals.iter()) {
        if f.code == b'#' {
            out.extend_from_slice(&flags[f.slot as usize].to_le_bytes());
            continue;
        }
        let v = match v {
            Some(v) => v,
            None => continue,
        };
        if f.code == b't' {
            continue;
        }
        match f.code {
            b'O' => write_obj(py, v, r, out, depth + 1)?,
            b'V' | b'W' => {
                out.extend_from_slice(&ID_VECTOR.to_le_bytes());
                let n = v.len()?;
                out.extend_from_slice(&(n as i32).to_le_bytes());
                for item in v.iter()? {
                    let item = item?;
                    if f.code == b'V' {
                        put_core(py, &item, f.vcode, out)?;
                    } else {
                        write_obj(py, &item, r, out, depth + 1)?;
                    }
                }
            }
            c => put_core(py, v, c, out)?,
        }
    }
    Ok(())
}

/// `obj.write()`, natively. Falls back to the object's own `write` for types
/// outside the schema table.
#[pyfunction]
fn tl_write<'py>(py: Python<'py>, obj: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let r = reg()?;
    let mut out = Vec::with_capacity(256);
    write_obj(py, obj, r, &mut out, 0)?;
    Ok(PyBytes::new_bound(py, &out))
}

// ---------------------------------------------------------------------------
// handshake: PQ factorisation
// ---------------------------------------------------------------------------

#[inline]
fn mulmod(a: u64, b: u64, n: u64) -> u64 {
    ((a as u128 * b as u128) % n as u128) as u64
}

#[inline]
fn step(y: u64, c: u64, n: u64) -> u64 {
    ((y as u128 * y as u128 + c as u128) % n as u128) as u64
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Pollard-Brent; returns a non-trivial factor of an odd composite `n`, or `n`.
fn brent(n: u64, c: u64) -> u64 {
    const M: u64 = 128;
    let (mut y, mut g, mut r, mut q) = (2u64, 1u64, 1u64, 1u64);
    let (mut x, mut ys) = (0u64, 0u64);
    while g == 1 {
        x = y;
        for _ in 0..r {
            y = step(y, c, n);
        }
        let mut k = 0;
        while k < r && g == 1 {
            ys = y;
            for _ in 0..M.min(r - k) {
                y = step(y, c, n);
                q = mulmod(q, x.abs_diff(y), n);
            }
            g = gcd(q, n);
            k += M;
        }
        r *= 2;
    }
    if g == n {
        loop {
            ys = step(ys, c, n);
            g = gcd(x.abs_diff(ys), n);
            if g > 1 {
                break;
            }
        }
    }
    g
}

/// Split Telegram's `pq` (a product of two ~32-bit primes) into `(p, q)`, p < q.
/// The GIL is released while it runs.
#[pyfunction]
fn factorize_pq(py: Python<'_>, pq: u64) -> PyResult<(u64, u64)> {
    if pq < 4 {
        return Err(PyValueError::new_err("pq too small to factorise"));
    }
    let res = py.allow_threads(|| {
        if pq % 2 == 0 {
            return Some(2u64);
        }
        for c in 1..64u64 {
            let g = brent(pq, c);
            if g != 1 && g != pq {
                return Some(g);
            }
        }
        None
    });
    let p = res.ok_or_else(|| PyValueError::new_err("pq is prime or could not be factorised"))?;
    let q = pq / p;
    Ok(if p < q { (p, q) } else { (q, p) })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(tl_init, m)?)?;
    m.add_function(wrap_pyfunction!(tl_ready, m)?)?;
    m.add_function(wrap_pyfunction!(tl_parse, m)?)?;
    m.add_function(wrap_pyfunction!(tl_write, m)?)?;
    m.add_function(wrap_pyfunction!(factorize_pq, m)?)?;
    Ok(())
}
