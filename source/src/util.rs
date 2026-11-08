//! User-facing error type and small shared helpers (progress, secure buffers,
//! atomic writes, safe file names).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

// ---------------------------------------------------------------- errors

/// Errors shown to the user. The messages are deliberately distinct.
#[derive(Debug)]
pub enum CryptonError {
    InvalidFile,
    UnknownAlgorithm,
    WrongPasswordOrCorrupted,
    IntegrityCompromised,
    PasswordRequired,
    Message(String),
}

pub type Result<T> = std::result::Result<T, CryptonError>;

use CryptonError as E;

impl fmt::Display for CryptonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFile => write!(
                f,
                "Invalid file: it is not a Crypton file, contains no hidden data, or is incomplete."
            ),
            Self::UnknownAlgorithm => write!(
                f,
                "Unknown algorithm: the file was created with an unsupported version or method."
            ),
            Self::WrongPasswordOrCorrupted => write!(f, "Wrong password or damaged file."),
            Self::IntegrityCompromised => write!(
                f,
                "Integrity compromised: the file was modified or is corrupted. Nothing was written."
            ),
            Self::PasswordRequired => write!(f, "The content is protected: enter the password."),
            Self::Message(m) => write!(f, "{m}"),
        }
    }
}

impl From<io::Error> for CryptonError {
    fn from(e: io::Error) -> Self {
        Self::Message(format!("Read/write error: {e}"))
    }
}

/// Shorthand for returning a plain message error.
pub fn message<T>(s: impl Into<String>) -> Result<T> {
    Err(CryptonError::Message(s.into()))
}

// ---------------------------------------------------------------- helpers

/// Progress shared between worker threads and the interface.
#[derive(Default)]
pub struct Progress {
    done: AtomicU64,
    total: AtomicU64,
}

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn start(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
    }
    pub fn add(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }
    pub fn fraction(&self) -> f32 {
        let t = self.total.load(Ordering::Relaxed);
        if t == 0 {
            return 0.0;
        }
        (self.done.load(Ordering::Relaxed) as f32 / t as f32).clamp(0.0, 1.0)
    }
}

/// Buffer for sensitive bytes: wiped on drop and with a fixed capacity
/// (it never reallocates, so it never leaves stray copies behind).
pub struct ZVec {
    buf: Zeroizing<Vec<u8>>,
    cap: usize,
}

impl ZVec {
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Zeroizing::new(Vec::with_capacity(cap)), cap }
    }
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

impl Write for ZVec {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() + data.len() > self.cap {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "data exceeds the declared size"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| E::Message("Secure random number generator unavailable.".into()))
}

/// Random number in `0..=max`.
pub fn random_upto(max: u64) -> Result<u64> {
    let mut b = [0u8; 8];
    random_bytes(&mut b)?;
    let v = u64::from_le_bytes(b);
    Ok(if max == u64::MAX { v } else { v % (max + 1) })
}

/// Writes to a temporary file next to the target and renames it only when
/// everything succeeded: the destination is never left half written.
pub fn write_atomic<F>(target: &Path, f: F) -> Result<()>
where
    F: FnOnce(&mut BufWriter<File>) -> Result<()>,
{
    let name = target.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "out".into());
    let tmp = target.with_file_name(format!(".{name}.part"));
    let file = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
    let mut w = BufWriter::new(file);
    let r = f(&mut w).and_then(|_| {
        w.flush()?;
        w.get_ref().sync_all()?;
        Ok(())
    });
    drop(w);
    match r {
        Ok(()) => fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            E::from(e)
        }),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Reduces a name coming from untrusted data to a plain file name: no paths,
/// no reserved Windows names, no odd characters.
pub fn sanitize_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !"<>:\"|?*".contains(*c))
        .collect();
    let cleaned = cleaned.trim().trim_end_matches(['.', ' ']).to_string();
    let mut cleaned: String = cleaned.chars().take(200).collect();
    if cleaned.is_empty() {
        return "extracted_file".into();
    }
    let stem = cleaned.split('.').next().unwrap_or("").trim().to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    if reserved {
        cleaned.insert(0, '_');
    }
    cleaned
}

/// Free path inside `dir` for `name` (adds " (1)", " (2)"... if it exists).
pub fn unique_path(dir: &Path, name: &str) -> Result<PathBuf> {
    let first = dir.join(name);
    if !first.exists() {
        return Ok(first);
    }
    let p = Path::new(name);
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| name.to_string());
    let ext = p.extension().map(|s| format!(".{}", s.to_string_lossy())).unwrap_or_default();
    for i in 1..10_000 {
        let cand = dir.join(format!("{stem} ({i}){ext}"));
        if !cand.exists() {
            return Ok(cand);
        }
    }
    Err(E::Message("Could not find a free file name in the folder.".into()))
}
