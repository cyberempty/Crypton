//! `.crypton` file format (version 2)
//!
//! ```text
//! header (56 bytes, authenticated as associated data of every block):
//!   "CRYPTON\0" | version | kdf | cipher | reserved | m_kib | t | p | salt(32)
//! metadata block (encrypted):  [length u32][ciphertext]
//!   content: compressed(1) | original size(8) | name length(2) | name
//! data blocks (encrypted, 64 KiB each): [length u32][ciphertext] ...
//! ```
//!
//! Key derivation: Argon2id (memory-hard) from the password with a fresh random
//! 256-bit salt per file, then HKDF-SHA-512 splits the result into two
//! independent 256-bit keys, bound to the header.
//!
//! Encryption: a cascade of two independent, authenticated 256-bit ciphers.
//! Every block is first sealed with ChaCha20-Poly1305 and the result is sealed
//! again with AES-256-GCM. An attacker would have to break both algorithms.
//!
//! The nonce of each block carries its sequence number and a kind
//! (data / last block / metadata): reordering, removing or appending
//! blocks makes authentication fail.

use crate::util::{random_bytes, read_full, CryptonError as E, Progress, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha512;
use flate2::write::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"CRYPTON\0";
pub const EXTENSION: &str = "crypton";
const VERSION: u8 = 2;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_CASCADE: u8 = 2; // ChaCha20-Poly1305 inside AES-256-GCM
pub const HEADER_LEN: usize = 56;
const SALT_LEN: usize = 32;
const CHUNK: usize = 64 * 1024;
/// Two authentication tags of 16 bytes: one per cipher layer.
const OVERHEAD: usize = 32;
const MAX_META_CT: usize = 1 + 8 + 2 + 255 + OVERHEAD;
const SAMPLE: usize = 1024 * 1024;

const KIND_DATA: u8 = 0;
const KIND_LAST: u8 = 1;
const KIND_META: u8 = 2;

// Limits accepted when reading (a hostile file cannot ask for GBs of memory).
const MAX_M_KIB: u32 = 1024 * 1024;
const MAX_T: u32 = 16;
const MAX_P: u32 = 16;

#[cfg(not(test))]
fn default_params() -> (u32, u32, u32) {
    // 256 MiB of memory, 4 passes, 1 lane: roughly a second on a modern
    // computer, and enormously expensive for anyone guessing passwords.
    (256 * 1024, 4, 1)
}
#[cfg(test)]
fn default_params() -> (u32, u32, u32) {
    (64, 1, 1)
}

// ---------------------------------------------------------------- header

#[derive(Clone)]
pub struct Header {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    raw: [u8; HEADER_LEN],
}

impl Header {
    fn generate() -> Result<Self> {
        let (m, t, p) = default_params();
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        let mut raw = [0u8; HEADER_LEN];
        raw[..8].copy_from_slice(MAGIC);
        raw[8] = VERSION;
        raw[9] = KDF_ARGON2ID;
        raw[10] = CIPHER_CASCADE;
        raw[12..16].copy_from_slice(&m.to_le_bytes());
        raw[16..20].copy_from_slice(&t.to_le_bytes());
        raw[20..24].copy_from_slice(&p.to_le_bytes());
        raw[24..56].copy_from_slice(&salt);
        Ok(Self { m_kib: m, t_cost: t, p_cost: p, salt, raw })
    }

    fn parse<R: Read>(r: &mut R) -> Result<Self> {
        let mut raw = [0u8; HEADER_LEN];
        let n = read_full(r, &mut raw)?;
        if n < HEADER_LEN || &raw[..8] != MAGIC {
            return Err(E::InvalidFile);
        }
        if raw[8] != VERSION || raw[9] != KDF_ARGON2ID || raw[10] != CIPHER_CASCADE {
            return Err(E::UnknownAlgorithm);
        }
        if raw[11] != 0 {
            return Err(E::InvalidFile);
        }
        let u = |a: usize| u32::from_le_bytes(raw[a..a + 4].try_into().unwrap());
        let (m, t, p) = (u(12), u(16), u(20));
        if p == 0 || p > MAX_P || t == 0 || t > MAX_T || m < 8 * p || m > MAX_M_KIB {
            return Err(E::InvalidFile);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[24..56]);
        Ok(Self { m_kib: m, t_cost: t, p_cost: p, salt, raw })
    }
}

/// The two independent 256-bit keys of the cascade.
pub struct Keys {
    chacha: Zeroizing<[u8; 32]>,
    aes: Zeroizing<[u8; 32]>,
}

/// Argon2id, then HKDF-SHA-512 (salted with the whole header) into two keys.
fn derive_keys(password: &[u8], h: &Header) -> Result<Keys> {
    let params = Params::new(h.m_kib, h.t_cost, h.p_cost, Some(32)).map_err(|_| E::InvalidFile)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, &h.salt, &mut *master)
        .map_err(|_| E::Message("Key derivation failed (not enough memory?).".into()))?;
    let hk = Hkdf::<Sha512>::new(Some(&h.raw), &*master);
    let mut chacha = Zeroizing::new([0u8; 32]);
    let mut aes = Zeroizing::new([0u8; 32]);
    hk.expand(b"crypton v2 chacha20-poly1305 key", &mut *chacha)
        .map_err(|_| E::Message("Key expansion failed.".into()))?;
    hk.expand(b"crypton v2 aes-256-gcm key", &mut *aes)
        .map_err(|_| E::Message("Key expansion failed.".into()))?;
    Ok(Keys { chacha, aes })
}

/// Both cipher instances, built from the keys.
struct Ciphers {
    chacha: ChaCha20Poly1305,
    aes: Aes256Gcm,
}

fn ciphers_from(k: &Keys) -> Result<Ciphers> {
    let bad = |_| E::Message("Invalid key.".into());
    Ok(Ciphers {
        chacha: ChaCha20Poly1305::new_from_slice(&k.chacha[..]).map_err(bad)?,
        aes: Aes256Gcm::new_from_slice(&k.aes[..]).map_err(bad)?,
    })
}

fn nonce_bytes(counter: u64, kind: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n[11] = kind;
    n
}

/// Seals with ChaCha20-Poly1305 first, then seals that result with AES-256-GCM.
fn seal(c: &Ciphers, aad: &[u8], counter: u64, kind: u8, plain: &[u8]) -> Result<Vec<u8>> {
    let n = nonce_bytes(counter, kind);
    let mut buf = Zeroizing::new(Vec::with_capacity(plain.len() + OVERHEAD));
    buf.extend_from_slice(plain);
    c.chacha
        .encrypt_in_place(&n.into(), aad, &mut *buf)
        .map_err(|_| E::Message("Encryption failed.".into()))?;
    c.aes
        .encrypt_in_place(&n.into(), aad, &mut *buf)
        .map_err(|_| E::Message("Encryption failed.".into()))?;
    Ok(buf.to_vec())
}

/// Opens both layers; any failure in either one is a failure of the block.
fn open(c: &Ciphers, aad: &[u8], counter: u64, kind: u8, ct: Vec<u8>) -> std::result::Result<Zeroizing<Vec<u8>>, ()> {
    if ct.len() < OVERHEAD {
        return Err(());
    }
    let n = nonce_bytes(counter, kind);
    let mut buf = Zeroizing::new(ct);
    c.aes.decrypt_in_place(&n.into(), aad, &mut *buf).map_err(|_| ())?;
    c.chacha.decrypt_in_place(&n.into(), aad, &mut *buf).map_err(|_| ())?;
    Ok(buf)
}

// ---------------------------------------------------------------- metadata

#[derive(Clone, PartialEq, Debug)]
pub struct Meta {
    pub name: String,
    pub original_size: u64,
    pub compressed: bool,
}

impl Meta {
    fn to_bytes(&self) -> Vec<u8> {
        let nb = self.name.as_bytes();
        let mut v = Vec::with_capacity(11 + nb.len());
        v.push(self.compressed as u8);
        v.extend_from_slice(&self.original_size.to_le_bytes());
        v.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        v.extend_from_slice(nb);
        v
    }
    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 11 || b[0] > 1 {
            return Err(E::InvalidFile);
        }
        let size = u64::from_le_bytes(b[1..9].try_into().unwrap());
        let nl = u16::from_le_bytes(b[9..11].try_into().unwrap()) as usize;
        if b.len() != 11 + nl {
            return Err(E::InvalidFile);
        }
        let name = String::from_utf8(b[11..].to_vec()).map_err(|_| E::InvalidFile)?;
        Ok(Self { name, original_size: size, compressed: b[0] == 1 })
    }
}

/// File name (no path) of at most 255 bytes.
pub fn clip_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut end = base.len().min(255);
    while !base.is_char_boundary(end) {
        end -= 1;
    }
    base[..end].to_string()
}

// ---------------------------------------------------------------- blocks

fn write_frame<W: Write>(w: &mut W, ct: &[u8]) -> io::Result<()> {
    w.write_all(&(ct.len() as u32).to_le_bytes())?;
    w.write_all(ct)
}

fn read_frame<R: Read>(r: &mut R, max_ct: usize) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let n = read_full(r, &mut len)?;
    if n == 0 {
        return Ok(None);
    }
    if n < 4 {
        return Err(E::InvalidFile);
    }
    let l = u32::from_le_bytes(len) as usize;
    if l < OVERHEAD || l > max_ct {
        return Err(E::InvalidFile);
    }
    let mut ct = vec![0u8; l];
    if read_full(r, &mut ct)? < l {
        return Err(E::InvalidFile);
    }
    Ok(Some(ct))
}

/// Skips a block without reading it; returns its length.
fn skip_frame<R: Read + Seek>(r: &mut R, max_ct: usize, file_len: u64) -> Result<Option<usize>> {
    let mut len = [0u8; 4];
    let n = read_full(r, &mut len)?;
    if n == 0 {
        return Ok(None);
    }
    if n < 4 {
        return Err(E::InvalidFile);
    }
    let l = u32::from_le_bytes(len) as usize;
    if l < OVERHEAD || l > max_ct {
        return Err(E::InvalidFile);
    }
    let pos = r.stream_position()?;
    if pos + l as u64 > file_len {
        return Err(E::InvalidFile);
    }
    r.seek(SeekFrom::Start(pos + l as u64))?;
    Ok(Some(l))
}

struct ChunkWriter<'a, W: Write> {
    w: &'a mut W,
    cipher: &'a Ciphers,
    aad: &'a [u8],
    buf: Zeroizing<Vec<u8>>,
    counter: u64,
}

impl<'a, W: Write> ChunkWriter<'a, W> {
    fn new(w: &'a mut W, cipher: &'a Ciphers, aad: &'a [u8]) -> Self {
        Self { w, cipher, aad, buf: Zeroizing::new(Vec::with_capacity(CHUNK)), counter: 1 }
    }
    fn flush_chunk(&mut self, last: bool) -> io::Result<()> {
        let kind = if last { KIND_LAST } else { KIND_DATA };
        let ct = seal(self.cipher, self.aad, self.counter, kind, &self.buf)
            .map_err(|e| io::Error::other(e.to_string()))?;
        write_frame(self.w, &ct)?;
        self.counter += 1;
        self.buf.zeroize();
        Ok(())
    }
    /// Writes the last block (empty if the file is empty).
    fn finish(mut self) -> io::Result<()> {
        self.flush_chunk(true)
    }
}

impl<W: Write> Write for ChunkWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // A full block is written only when more data arrives, so the
        // last block is always recognizable.
        if self.buf.len() == CHUNK {
            self.flush_chunk(false)?;
        }
        let n = (CHUNK - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CountWriter<W: Write> {
    inner: W,
    n: u64,
}
impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, d: &[u8]) -> io::Result<usize> {
        let k = self.inner.write(d)?;
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------- encryption

fn should_compress(sample: &[u8]) -> bool {
    if sample.len() < 256 {
        return false;
    }
    let out = crate::util::ZVec::with_capacity(sample.len());
    let mut enc = ZlibEncoder::new(out, Compression::fast());
    if enc.write_all(sample).is_err() {
        return false;
    }
    match enc.finish() {
        Ok(v) => v.into_inner().len() < sample.len() / 10 * 9,
        Err(_) => false,
    }
}

fn pump<R: Read, W: Write>(mut src: R, w: &mut W, progress: &Progress) -> io::Result<u64> {
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        w.write_all(&buf[..n])?;
        total += n as u64;
        progress.add(n as u64);
    }
    Ok(total)
}

pub fn encrypt_stream<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    password: &[u8],
    name: &str,
    size: u64,
    progress: &Progress,
) -> Result<()> {
    let header = Header::generate()?;
    let keys = derive_keys(password, &header)?;
    let cipher = ciphers_from(&keys)?;

    let mut head = Zeroizing::new(vec![0u8; SAMPLE]);
    let n = read_full(&mut input, &mut head)?;
    head.truncate(n);
    let compress = should_compress(&head);

    let meta = Meta { name: clip_name(name), original_size: size, compressed: compress };
    output.write_all(&header.raw)?;
    let meta_ct = seal(&cipher, &header.raw, 0, KIND_META, &meta.to_bytes())?;
    write_frame(&mut output, &meta_ct)?;

    let src = io::Cursor::new(&head[..]).chain(&mut input);
    let mut cw = ChunkWriter::new(&mut output, &cipher, &header.raw);
    let total = if compress {
        let mut enc = ZlibEncoder::new(&mut cw, Compression::new(6));
        let t = pump(src, &mut enc, progress)?;
        enc.finish()?;
        t
    } else {
        pump(src, &mut cw, progress)?
    };
    cw.finish()?;
    output.flush()?;
    if total != size {
        return Err(E::Message("The file changed while it was being read: operation cancelled.".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------- decryption

pub struct Session {
    header: Header,
    keys: Keys,
    pub meta: Meta,
}

fn read_meta<R: Read>(r: &mut R, header: &Header, keys: &Keys) -> Result<Meta> {
    let ct = read_frame(r, MAX_META_CT)?.ok_or(E::InvalidFile)?;
    let cipher = ciphers_from(keys)?;
    let pt = open(&cipher, &header.raw, 0, KIND_META, ct).map_err(|_| E::WrongPasswordOrCorrupted)?;
    Meta::parse(&pt)
}

/// Reads the header, derives the key and opens the metadata.
/// If the metadata does not authenticate: wrong password or damaged file.
pub fn unlock<R: Read>(r: &mut R, password: &[u8]) -> Result<Session> {
    let header = Header::parse(r)?;
    let keys = derive_keys(password, &header)?;
    let meta = read_meta(r, &header, &keys)?;
    Ok(Session { header, keys, meta })
}

/// Reopens the same file with the already derived key, checking it did not change.
pub fn reopen<R: Read>(s: &Session, r: &mut R) -> Result<()> {
    let h = Header::parse(r)?;
    if h.raw != s.header.raw {
        return Err(E::IntegrityCompromised);
    }
    let m = read_meta(r, &h, &s.keys).map_err(|_| E::IntegrityCompromised)?;
    if m != s.meta {
        return Err(E::IntegrityCompromised);
    }
    Ok(())
}

fn write_err(e: io::Error) -> E {
    match e.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => E::IntegrityCompromised,
        _ => E::from(e),
    }
}

fn run_frames<R: Read, W: Write>(
    cipher: &Ciphers,
    header: &Header,
    r: &mut R,
    w: &mut W,
    progress: &Progress,
) -> Result<()> {
    let fix = |e: E| if matches!(e, E::InvalidFile) { E::IntegrityCompromised } else { e };
    let mut cur = read_frame(r, CHUNK + OVERHEAD).map_err(fix)?.ok_or(E::IntegrityCompromised)?;
    let mut counter = 1u64;
    loop {
        let next = read_frame(r, CHUNK + OVERHEAD).map_err(fix)?;
        let kind = if next.is_none() { KIND_LAST } else { KIND_DATA };
        let clen = cur.len() as u64 + 4;
        let pt = open(cipher, &header.raw, counter, kind, cur).map_err(|_| E::IntegrityCompromised)?;
        w.write_all(&pt).map_err(write_err)?;
        progress.add(clen);
        counter += 1;
        match next {
            Some(n) => cur = n,
            None => break,
        }
    }
    Ok(())
}

/// Decrypts every data block. With `io::sink()` as destination this is a
/// full verification that writes nothing.
pub fn decrypt_body<R: Read, W: Write>(s: &Session, r: &mut R, out: W, progress: &Progress) -> Result<()> {
    let cipher = ciphers_from(&s.keys)?;
    let mut cw = CountWriter { inner: out, n: 0 };
    if s.meta.compressed {
        let mut dec = ZlibDecoder::new(&mut cw);
        run_frames(&cipher, &s.header, r, &mut dec, progress)?;
        dec.finish().map_err(write_err)?;
    } else {
        run_frames(&cipher, &s.header, r, &mut cw, progress)?;
    }
    if cw.n != s.meta.original_size {
        return Err(E::IntegrityCompromised);
    }
    cw.inner.flush()?;
    Ok(())
}

// ---------------------------------------------------------------- structure (no password)

pub struct Structure {
    pub header: Header,
    pub chunks: u64,
}

pub fn check_structure<R: Read + Seek>(r: &mut R, file_len: u64) -> Result<Structure> {
    let header = Header::parse(r)?;
    skip_frame(r, MAX_META_CT, file_len)?.ok_or(E::InvalidFile)?;
    let mut chunks = 0u64;
    let mut prev: Option<usize> = None;
    while let Some(len) = skip_frame(r, CHUNK + OVERHEAD, file_len)? {
        if let Some(p) = prev {
            if p != CHUNK + OVERHEAD {
                return Err(E::InvalidFile);
            }
        }
        prev = Some(len);
        chunks += 1;
    }
    if chunks == 0 {
        return Err(E::InvalidFile);
    }
    Ok(Structure { header, chunks })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn enc(data: &[u8], pw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt_stream(Cursor::new(data), &mut out, pw, "dir/sample.txt", data.len() as u64, &Progress::new()).unwrap();
        out
    }
    fn dec(file: &[u8], pw: &[u8]) -> Result<Vec<u8>> {
        let mut c = Cursor::new(file);
        let s = unlock(&mut c, pw)?;
        let mut out = Vec::new();
        decrypt_body(&s, &mut c, &mut out, &Progress::new())?;
        Ok(out)
    }

    #[test]
    fn roundtrip_various_inputs() {
        let mut pseudo = vec![0u8; 300_000];
        let mut x = 12345u32;
        for b in pseudo.iter_mut() {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (x >> 24) as u8;
        }
        let compressible: Vec<u8> = b"hello world ".iter().cycle().take(500_000).cloned().collect();
        for data in [vec![], b"x".to_vec(), vec![7u8; CHUNK], vec![9u8; CHUNK + 1], pseudo, compressible] {
            let f = enc(&data, b"pw");
            assert_eq!(dec(&f, b"pw").unwrap(), data, "len {}", data.len());
        }
    }

    #[test]
    fn compression_only_when_worthwhile() {
        let comp: Vec<u8> = vec![0u8; 400_000];
        let f = enc(&comp, b"pw");
        assert!(f.len() < 10_000);
        let s = unlock(&mut Cursor::new(&f), b"pw").unwrap();
        assert!(s.meta.compressed);
        assert_eq!(s.meta.name, "sample.txt");
    }

    #[test]
    fn wrong_password_and_distinct_ciphertexts() {
        let f = enc(b"secret", b"right");
        assert!(matches!(dec(&f, b"wrong"), Err(E::WrongPasswordOrCorrupted)));
        assert_ne!(f, enc(b"secret", b"right"));
    }

    #[test]
    fn tampering_is_detected() {
        let mut x = 7u32;
        let data: Vec<u8> = (0..200_000u32)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect();
        let f = enc(&data, b"pw");
        // flipped bit in a data block
        let mut m = f.clone();
        let i = m.len() / 2;
        m[i] ^= 1;
        assert!(matches!(dec(&m, b"pw"), Err(E::IntegrityCompromised)));
        // truncated file (clean cut between blocks and mid-block)
        for cut in [f.len() - 1, f.len() - 70_000, f.len() - 10] {
            let r = dec(&f[..cut], b"pw");
            assert!(matches!(r, Err(E::IntegrityCompromised)), "cut {cut}: {r:?}");
        }
        // data appended at the end
        let mut a = f.clone();
        a.extend_from_slice(&[0, 0, 0, 0]);
        assert!(dec(&a, b"pw").is_err());
        // modified header
        let mut h = f.clone();
        h[24] ^= 1; // salt
        assert!(dec(&h, b"pw").is_err());
    }

    #[test]
    fn invalid_files() {
        assert!(matches!(dec(b"I am not a Crypton file, really I am not at all.....", b"x"), Err(E::InvalidFile)));
        let mut f = enc(b"abc", b"pw");
        f[8] = 9;
        assert!(matches!(dec(&f, b"pw"), Err(E::UnknownAlgorithm)));
    }

    #[test]
    fn structure_without_password() {
        let f = enc(&vec![1u8; 150_000], b"pw");
        let s = check_structure(&mut Cursor::new(&f), f.len() as u64).unwrap();
        assert!(s.chunks >= 1);
        assert!(check_structure(&mut Cursor::new(&f[..f.len() - 5]), (f.len() - 5) as u64).is_err());
    }

    #[test]
    fn real_argon2_parameters() {
        let mut raw = [0u8; HEADER_LEN];
        raw[..8].copy_from_slice(MAGIC);
        raw[8] = VERSION;
        raw[9] = KDF_ARGON2ID;
        raw[10] = CIPHER_CASCADE;
        raw[12..16].copy_from_slice(&(256u32 * 1024).to_le_bytes());
        raw[16..20].copy_from_slice(&4u32.to_le_bytes());
        raw[20..24].copy_from_slice(&1u32.to_le_bytes());
        let h = Header::parse(&mut Cursor::new(&raw[..])).unwrap();
        let t = std::time::Instant::now();
        let k1 = derive_keys(b"pw", &h).unwrap();
        let k2 = derive_keys(b"pw", &h).unwrap();
        let k3 = derive_keys(b"px", &h).unwrap();
        eprintln!("real argon2: {:?} per derivation", t.elapsed() / 3);
        assert_eq!(*k1.chacha, *k2.chacha);
        assert_eq!(*k1.aes, *k2.aes);
        assert_ne!(*k1.chacha, *k3.chacha);
        assert_ne!(*k1.chacha, *k1.aes, "the two keys must be independent");
    }
}
