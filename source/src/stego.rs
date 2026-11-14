//! Steganography: hides a file inside an image.
//!
//! Hidden content ("payload"):  "CRST" | flag | ...
//!   flag 0: name, data and CRC32 in the clear
//!   flag 1: a whole Crypton file (name and data encrypted and authenticated)
//!
//! "Pixel" method: 1 bit per color channel (R, G, B) in the least significant bit.
//!   A 96-bit header at the start says where and how the payload bits are
//!   spread: evenly spaced over the whole image.
//! "Tail" method: the payload is appended after the end of the image, followed
//!   by its length and a marker. Image viewers ignore trailing data.

use crate::crypto;
use crate::folder;
use crate::util::{message, random_upto, same_file, sanitize_name, unique_path, write_atomic, CryptonError as E, Progress, Result, ZVec};
use image::{DynamicImage, ImageFormat};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const PAYLOAD_MAGIC: &[u8; 4] = b"CRST";
const TAIL_MAGIC: &[u8; 8] = b"CRYPTAIL";
const LSB_MAGIC: &[u8; 4] = b"CLSB";
const LSB_HEADER_BITS: usize = 96;
const MAX_FILE: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Method {
    Pixel,
    Tail,
}

impl Method {
    pub fn label(self) -> &'static str {
        match self {
            Method::Pixel => "pixel (least significant bits)",
            Method::Tail => "appended to the image file",
        }
    }
}

pub struct Extracted {
    pub name: String,
    pub data: Zeroizing<Vec<u8>>,
    pub method: Method,
}

impl Extracted {
    /// The hidden content is a whole folder, not a single file.
    pub fn is_folder(&self) -> bool {
        folder::is_folder_data(&self.data)
    }
}

// ---------------------------------------------------------------- payload

pub fn pack(name: &str, data: &[u8], password: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + 128);
    out.extend_from_slice(PAYLOAD_MAGIC);
    match password {
        None => {
            out.push(0);
            let nb = crypto::clip_name(name).into_bytes();
            out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
            out.extend_from_slice(&nb);
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
            let crc = crc32fast::hash(&out);
            out.extend_from_slice(&crc.to_le_bytes());
        }
        Some(pw) => {
            out.push(1);
            crypto::encrypt_stream(Cursor::new(data), &mut out, pw, name, data.len() as u64, &Progress::new())?;
        }
    }
    Ok(out)
}

pub fn unpack(payload: &[u8], password: Option<&[u8]>) -> Result<(String, Zeroizing<Vec<u8>>)> {
    if payload.len() < 5 || &payload[..4] != PAYLOAD_MAGIC {
        return Err(E::InvalidFile);
    }
    match payload[4] {
        0 => {
            let b = &payload[5..];
            if b.len() < 2 + 8 + 4 {
                return Err(E::InvalidFile);
            }
            let (body, crc) = payload.split_at(payload.len() - 4);
            if crc32fast::hash(body) != u32::from_le_bytes(crc.try_into().unwrap()) {
                return Err(E::IntegrityCompromised);
            }
            let nl = u16::from_le_bytes(b[..2].try_into().unwrap()) as usize;
            if b.len() < 2 + nl + 8 + 4 {
                return Err(E::InvalidFile);
            }
            let name = String::from_utf8(b[2..2 + nl].to_vec()).map_err(|_| E::InvalidFile)?;
            let dl = u64::from_le_bytes(b[2 + nl..10 + nl].try_into().unwrap());
            let rest = &b[10 + nl..b.len() - 4];
            if rest.len() as u64 != dl {
                return Err(E::IntegrityCompromised);
            }
            Ok((sanitize_name(&name), Zeroizing::new(rest.to_vec())))
        }
        1 => {
            let pw = password.ok_or(E::PasswordRequired)?;
            let mut c = Cursor::new(&payload[5..]);
            let s = crypto::unlock(&mut c, pw)?;
            if s.meta.original_size > MAX_FILE {
                return Err(E::IntegrityCompromised);
            }
            let mut out = ZVec::with_capacity(s.meta.original_size as usize);
            crypto::decrypt_body(&s, &mut c, &mut out, &Progress::new())?;
            Ok((sanitize_name(&s.meta.name), out.into_inner()))
        }
        _ => Err(E::UnknownAlgorithm),
    }
}

// ---------------------------------------------------------------- tail method

fn tail_payload(bytes: &[u8]) -> Option<&[u8]> {
    let n = bytes.len();
    if n < 16 || &bytes[n - 8..] != TAIL_MAGIC {
        return None;
    }
    let plen = u64::from_le_bytes(bytes[n - 16..n - 8].try_into().unwrap());
    if plen > (n - 16) as u64 {
        return None;
    }
    Some(&bytes[n - 16 - plen as usize..n - 16])
}

fn append_tail(image: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    if image::guess_format(image).is_err() {
        return Err(E::InvalidFile);
    }
    if tail_payload(image).is_some() {
        return message("The image already contains hidden content: use another image.");
    }
    let mut out = Vec::with_capacity(image.len() + payload.len() + 16);
    out.extend_from_slice(image);
    out.extend_from_slice(payload);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(TAIL_MAGIC);
    Ok(out)
}

// ---------------------------------------------------------------- pixel method

fn load_pixels(bytes: &[u8]) -> Result<(Vec<u8>, u32, u32, usize)> {
    let img = image::load_from_memory(bytes).map_err(|_| E::InvalidFile)?;
    if img.color().has_alpha() {
        let b = img.to_rgba8();
        let (w, h) = b.dimensions();
        Ok((b.into_raw(), w, h, 4))
    } else {
        let b = img.to_rgb8();
        let (w, h) = b.dimensions();
        Ok((b.into_raw(), w, h, 3))
    }
}

#[inline]
fn slot(k: usize, ch: usize) -> usize {
    (k / 3) * ch + (k % 3)
}

fn embed_pixels(buf: &mut [u8], ch: usize, payload: &[u8]) -> Result<()> {
    let n_slots = (buf.len() / ch) * 3;
    let need = payload.len() * 8;
    let m = n_slots.saturating_sub(LSB_HEADER_BITS);
    if need == 0 || need > m || n_slots > u32::MAX as usize || payload.len() > u32::MAX as usize {
        let cap = m / 8;
        return message(format!(
            "The image is too small for this file: it can hold about {cap} bytes at most ({} needed). Choose a larger image or the \"appended\" method.",
            payload.len()
        ));
    }
    let step = m / need;
    let max_start = m - ((need - 1) * step + 1);
    let start = random_upto(max_start as u64)? as usize;

    let mut head = Vec::with_capacity(12);
    head.extend_from_slice(LSB_MAGIC);
    head.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    head.extend_from_slice(&(start as u32).to_le_bytes());
    for bit in 0..LSB_HEADER_BITS {
        let i = slot(bit, ch);
        buf[i] = (buf[i] & 0xFE) | ((head[bit / 8] >> (bit % 8)) & 1);
    }
    for i in 0..need {
        let k = LSB_HEADER_BITS + start + i * step;
        let j = slot(k, ch);
        buf[j] = (buf[j] & 0xFE) | ((payload[i / 8] >> (i % 8)) & 1);
    }
    Ok(())
}

fn extract_pixels(buf: &[u8], ch: usize) -> Result<Vec<u8>> {
    let n_slots = (buf.len() / ch) * 3;
    if n_slots <= LSB_HEADER_BITS {
        return Err(E::InvalidFile);
    }
    let mut head = [0u8; 12];
    for bit in 0..LSB_HEADER_BITS {
        head[bit / 8] |= (buf[slot(bit, ch)] & 1) << (bit % 8);
    }
    if &head[..4] != LSB_MAGIC {
        return Err(E::InvalidFile);
    }
    let plen = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
    let start = u32::from_le_bytes(head[8..12].try_into().unwrap()) as usize;
    let m = n_slots - LSB_HEADER_BITS;
    let need = plen * 8;
    if need == 0 || need > m {
        return Err(E::InvalidFile);
    }
    let step = m / need;
    if start + (need - 1) * step >= m {
        return Err(E::InvalidFile);
    }
    let mut out = vec![0u8; plen];
    for i in 0..need {
        let k = LSB_HEADER_BITS + start + i * step;
        out[i / 8] |= (buf[slot(k, ch)] & 1) << (i % 8);
    }
    Ok(out)
}

fn encode_pixels(buf: Vec<u8>, w: u32, h: u32, ch: usize, fmt: ImageFormat) -> Result<Vec<u8>> {
    let img = if ch == 4 {
        DynamicImage::ImageRgba8(image::RgbaImage::from_raw(w, h, buf).ok_or(E::InvalidFile)?)
    } else {
        DynamicImage::ImageRgb8(image::RgbImage::from_raw(w, h, buf).ok_or(E::InvalidFile)?)
    };
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), fmt)
        .map_err(|e| E::Message(format!("Could not save the image: {e}")))?;
    Ok(out)
}

// ---------------------------------------------------------------- detection

pub fn find_payload(bytes: &[u8]) -> Result<(Method, Vec<u8>)> {
    if let Some(p) = tail_payload(bytes) {
        return Ok((Method::Tail, p.to_vec()));
    }
    let (buf, _, _, ch) = load_pixels(bytes)?;
    Ok((Method::Pixel, extract_pixels(&buf, ch)?))
}

/// Describes the hidden content without needing a password.
pub fn inspect(bytes: &[u8]) -> Option<String> {
    let (method, p) = find_payload(bytes).ok()?;
    if p.len() < 5 || &p[..4] != PAYLOAD_MAGIC {
        return None;
    }
    let mut s = format!("Method: {}\nHidden content: {} bytes\n", method.label(), p.len());
    match p[4] {
        0 => {
            s += "Password protected: no\n";
            if let Ok((name, data)) = unpack(&p, None) {
                let what = if folder::is_folder_data(&data) { "folder" } else { "file" };
                s += &format!("Hidden {what} name: {name}\nSize: {} bytes\n", data.len());
            }
        }
        1 => s += "Password protected: yes (name and content encrypted)\n",
        _ => return None,
    }
    Some(s)
}

// ---------------------------------------------------------------- file operations

fn read_limited(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    let len = fs::metadata(path)?.len();
    if len > MAX_FILE {
        return message(format!("{what} is too large (maximum {} MiB).", MAX_FILE / 1024 / 1024));
    }
    Ok(Zeroizing::new(fs::read(path)?))
}

fn secret_name(p: &Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())
}

/// Reads what has to be hidden: a file, or a whole folder packed into one archive.
/// Returns the name, the bytes and how many links were skipped (folders only).
fn load_secret(secret: &Path) -> Result<(String, Zeroizing<Vec<u8>>, u64)> {
    if secret.is_dir() {
        let (data, skipped) = folder::pack_to_memory(secret, MAX_FILE)?;
        Ok((secret_name(secret), data, skipped))
    } else {
        Ok((secret_name(secret), read_limited(secret, "The file to hide")?, 0))
    }
}

/// Hides `secret` (a file or a folder) in the pixels of `image`.
/// Returns the path written and the number of skipped links.
pub fn hide_pixels(secret: &Path, image: &Path, out: &Path, password: Option<&[u8]>) -> Result<(PathBuf, u64)> {
    if same_file(image, out) || same_file(secret, out) {
        return message("Choose a name different from the source files.");
    }
    let (name, data, skipped) = load_secret(secret)?;
    let payload = pack(&name, &data, password)?;
    drop(data);
    let img_bytes = read_limited(image, "The image")?;
    let (mut buf, w, h, ch) = load_pixels(&img_bytes)?;
    embed_pixels(&mut buf, ch, &payload)?;
    // Lossless formats only: compressed formats would destroy the data.
    let is_bmp = out.extension().map(|e| e.eq_ignore_ascii_case("bmp")).unwrap_or(false);
    let (fmt, ext) = if is_bmp { (ImageFormat::Bmp, "bmp") } else { (ImageFormat::Png, "png") };
    let final_path = if is_bmp || out.extension().map(|e| e.eq_ignore_ascii_case("png")).unwrap_or(false) {
        out.to_path_buf()
    } else {
        out.with_extension(ext)
    };
    let encoded = encode_pixels(buf, w, h, ch, fmt)?;
    write_atomic(&final_path, |w| Ok(w.write_all(&encoded)?))?;
    Ok((final_path, skipped))
}

/// Hides `secret` (a file or a folder) at the end of the image file.
/// Returns the path written and the number of skipped links.
pub fn hide_tail(secret: &Path, image: &Path, out: &Path, password: Option<&[u8]>) -> Result<(PathBuf, u64)> {
    if same_file(image, out) || same_file(secret, out) {
        return message("Choose a name different from the source files.");
    }
    let (name, data, skipped) = load_secret(secret)?;
    let payload = pack(&name, &data, password)?;
    drop(data);
    let img_bytes = read_limited(image, "The image")?;
    let combined = append_tail(&img_bytes, &payload)?;
    write_atomic(out, |w| Ok(w.write_all(&combined)?))?;
    Ok((out.to_path_buf(), skipped))
}

/// Finds and opens the hidden content (every check happens here, in memory).
pub fn extract_to_memory(image: &Path, password: Option<&[u8]>) -> Result<Extracted> {
    let bytes = read_limited(image, "The image")?;
    let (method, payload) = find_payload(&bytes)?;
    let (name, data) = unpack(&payload, password)?;
    Ok(Extracted { name, data, method })
}

/// Writes the extracted file (or rebuilds the extracted folder) inside `dir`,
/// never outside it and never overwriting anything.
pub fn write_extracted(ex: &Extracted, dir: &Path) -> Result<PathBuf> {
    let name = sanitize_name(&ex.name);
    if ex.is_folder() {
        return folder::extract_slice(&ex.data, dir, &name);
    }
    let target = unique_path(dir, &name)?;
    if target.parent() != Some(dir) || target.file_name().is_none() {
        return message("Unsafe hidden file name: extraction cancelled.");
    }
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&target)?;
    if let Err(e) = f.write_all(&ex.data).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(&target);
        return Err(e.into());
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32, alpha: bool) -> Vec<u8> {
        let mut x = 99u32;
        let mut next = move || {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            (x >> 24) as u8
        };
        let img = if alpha {
            DynamicImage::ImageRgba8(image::RgbaImage::from_fn(w, h, |_, _| image::Rgba([next(), next(), next(), 255])))
        } else {
            DynamicImage::ImageRgb8(image::RgbImage::from_fn(w, h, |_, _| image::Rgb([next(), next(), next()])))
        };
        let mut v = Vec::new();
        img.write_to(&mut Cursor::new(&mut v), ImageFormat::Png).unwrap();
        v
    }

    #[test]
    fn pixel_roundtrip_with_and_without_password() {
        for alpha in [false, true] {
            for pw in [None, Some(&b"pw"[..])] {
                let secret = b"secret message \x00\xff".repeat(20);
                let payload = pack("../../evil.txt", &secret, pw).unwrap();
                let (mut buf, w, h, ch) = load_pixels(&png(80, 60, alpha)).unwrap();
                let orig = buf.clone();
                embed_pixels(&mut buf, ch, &payload).unwrap();
                // each channel changes by at most 1
                assert!(orig.iter().zip(&buf).all(|(a, b)| a.abs_diff(*b) <= 1));
                let enc = encode_pixels(buf, w, h, ch, ImageFormat::Png).unwrap();
                let (m, p) = find_payload(&enc).unwrap();
                assert_eq!(m, Method::Pixel);
                let (name, data) = unpack(&p, pw).unwrap();
                assert_eq!(name, "evil.txt");
                assert_eq!(&data[..], &secret[..]);
                if pw.is_some() {
                    assert!(matches!(unpack(&p, None), Err(E::PasswordRequired)));
                    assert!(matches!(unpack(&p, Some(b"no")), Err(E::WrongPasswordOrCorrupted)));
                }
            }
        }
    }

    #[test]
    fn tail_roundtrip_and_image_still_valid() {
        let img = png(20, 20, false);
        let payload = pack("a.bin", &[1, 2, 3, 4], Some(b"pw")).unwrap();
        let out = append_tail(&img, &payload).unwrap();
        assert!(image::load_from_memory(&out).is_ok());
        let (m, p) = find_payload(&out).unwrap();
        assert_eq!(m, Method::Tail);
        assert_eq!(&unpack(&p, Some(b"pw")).unwrap().1[..], &[1, 2, 3, 4]);
        assert!(append_tail(&out, &payload).is_err());
    }

    #[test]
    fn insufficient_capacity_and_no_content() {
        let (mut buf, _, _, ch) = load_pixels(&png(10, 10, false)).unwrap();
        let big = pack("x", &vec![0u8; 1000], None).unwrap();
        assert!(embed_pixels(&mut buf, ch, &big).is_err());
        assert!(matches!(find_payload(&png(30, 30, false)), Err(E::InvalidFile)));
    }

    #[test]
    fn tampered_payload() {
        let mut p = pack("a", b"data", None).unwrap();
        let i = p.len() - 6;
        p[i] ^= 1;
        assert!(matches!(unpack(&p, None), Err(E::IntegrityCompromised)));
    }

    #[test]
    fn safe_names() {
        for (i, o) in [
            ("../../etc/passwd", "passwd"),
            ("C:\\Windows\\system32\\x.dll", "x.dll"),
            ("..", "extracted_file"),
            ("", "extracted_file"),
            ("con.txt", "_con.txt"),
            ("a:b?.txt", "ab.txt"),
            ("name.", "name"),
        ] {
            assert_eq!(sanitize_name(i), o, "{i}");
        }
    }
}
