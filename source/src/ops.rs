//! File operations: connect the format (crypto) to the disk.

use crate::crypto::{self, Session};
use crate::stego;
use crate::util::{message, same_file, sanitize_name, write_atomic, CryptonError as E, Progress, Result};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub struct Prepared {
    pub session: Session,
    pub input: PathBuf,
    pub suggested_name: String,
}

fn open_regular(path: &Path) -> Result<(File, u64)> {
    let f = File::open(path)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return message("The chosen path is not a file.");
    }
    Ok((f, md.len()))
}

pub fn encrypt_file(input: &Path, output: &Path, password: &[u8], progress: &Progress) -> Result<()> {
    if same_file(input, output) {
        return message("The encrypted file cannot overwrite the original: choose another name.");
    }
    let (f, size) = open_regular(input)?;
    let name = input.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    progress.start(size);
    write_atomic(output, |w| {
        crypto::encrypt_stream(BufReader::with_capacity(256 * 1024, f), w, password, &name, size, progress)
    })
}

/// Decryption phase 1: full verification, nothing is written.
pub fn prepare_decrypt(input: &Path, password: &[u8], progress: &Progress) -> Result<Prepared> {
    let (f, len) = open_regular(input)?;
    let mut r = BufReader::with_capacity(256 * 1024, f);
    progress.start(len);
    let session = crypto::unlock(&mut r, password)?;
    crypto::decrypt_body(&session, &mut r, io::sink(), progress)?;
    let suggested_name = sanitize_name(&session.meta.name);
    Ok(Prepared { session, input: input.to_path_buf(), suggested_name })
}

/// Phase 2: the file is written only after every check has passed.
pub fn finish_decrypt(prep: &Prepared, output: &Path, progress: &Progress) -> Result<()> {
    if same_file(&prep.input, output) {
        return message("The decrypted file cannot overwrite the encrypted one: choose another name.");
    }
    let (f, len) = open_regular(&prep.input)?;
    let mut r = BufReader::with_capacity(256 * 1024, f);
    progress.start(len);
    crypto::reopen(&prep.session, &mut r)?;
    write_atomic(output, |w| crypto::decrypt_body(&prep.session, &mut r, w, progress))
}

fn fmt_size(n: u64) -> String {
    const U: [&str; 4] = ["bytes", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} bytes") } else { format!("{v:.1} {} ({n} bytes)", U[i]) }
}

/// Integrity check that writes nothing to disk.
pub fn verify_file(input: &Path, password: Option<&[u8]>, progress: &Progress) -> Result<String> {
    let (f, len) = open_regular(input)?;
    let mut r = BufReader::with_capacity(256 * 1024, f);
    progress.start(len);
    match password {
        None => {
            let s = crypto::check_structure(&mut r, len)?;
            Ok(format!(
                "Structure is valid: correct header and {} consistent blocks. \
                 Without a password the authenticity of the data cannot be verified.",
                s.chunks
            ))
        }
        Some(pw) => {
            let s = crypto::unlock(&mut r, pw)?;
            crypto::decrypt_body(&s, &mut r, io::sink(), progress)?;
            Ok(format!(
                "Full check passed: all data is authentic and intact ({}).",
                fmt_size(s.meta.original_size)
            ))
        }
    }
}

/// Details about a Crypton file or an image with hidden data.
pub fn info_file(input: &Path, password: Option<&[u8]>) -> Result<String> {
    let (f, len) = open_regular(input)?;
    let mut r = BufReader::new(f);
    let mut magic = [0u8; 8];
    let n = crate::util::read_full(&mut r, &mut magic)?;
    r.seek(SeekFrom::Start(0))?;
    if n == 8 && &magic == crypto::MAGIC {
        let s = crypto::check_structure(&mut r, len)?;
        let h = &s.header;
        let mut out = String::new();
        out += "Type: Crypton encrypted file\n";
        out += &format!("Size: {}\n", fmt_size(len));
        out += "Cipher: ChaCha20-Poly1305 (authenticated)\n";
        out += &format!(
            "Key derivation: Argon2id ({} MiB, {} passes, {} lanes)\n",
            h.m_kib / 1024,
            h.t_cost,
            h.p_cost
        );
        out += &format!("Data blocks: {}\n", s.chunks);
        match password {
            Some(pw) => {
                r.seek(SeekFrom::Start(0))?;
                let ses = crypto::unlock(&mut r, pw)?;
                out += &format!("Original name: {}\n", ses.meta.name);
                out += &format!("Original size: {}\n", fmt_size(ses.meta.original_size));
                out += &format!("Compressed: {}\n", if ses.meta.compressed { "yes" } else { "no" });
            }
            None => out += "Original name and size: protected, password required.\n",
        }
        return Ok(out);
    }
    if len > 512 * 1024 * 1024 {
        return Err(E::InvalidFile);
    }
    let mut bytes = Vec::with_capacity(len as usize);
    r.read_to_end(&mut bytes)?;
    match stego::inspect(&bytes) {
        Some(text) => Ok(format!("Type: image with hidden content\nImage size: {}\n{}", fmt_size(len), text)),
        None => Err(E::InvalidFile),
    }
}
