//! File operations: connect the format (crypto) to the disk.

use crate::crypto::{self, Session};
use crate::folder;
use crate::stego;
use crate::util::{is_inside, message, same_file, sanitize_name, write_atomic, CryptonError as E, Progress, Result};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub struct Prepared {
    pub session: Session,
    pub input: PathBuf,
    pub suggested_name: String,
    /// The decrypted content is a whole folder, not a single file.
    pub is_folder: bool,
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

/// Encrypts a whole folder into a single `.crypton` file. The folder is streamed
/// (no plaintext copy on disk). Returns how many symbolic links were left out.
pub fn encrypt_folder(input: &Path, output: &Path, password: &[u8], progress: &Progress) -> Result<u64> {
    if same_file(input, output) || is_inside(output, input) {
        return message("Save the encrypted file outside the folder you are encrypting.");
    }
    let sc = folder::scan(input)?;
    let name = input.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "folder".into());
    let (size, skipped) = (sc.total, sc.skipped);
    progress.start(size);
    write_atomic(output, |w| crypto::encrypt_stream(sc.reader(), w, password, &name, size, progress))?;
    Ok(skipped)
}

/// File or folder: picks the right way by looking at the path.
pub fn encrypt_path(input: &Path, output: &Path, password: &[u8], progress: &Progress) -> Result<u64> {
    if input.is_dir() {
        encrypt_folder(input, output, password, progress)
    } else {
        encrypt_file(input, output, password, progress).map(|_| 0)
    }
}

/// Decryption phase 1: full verification, nothing is written.
pub fn prepare_decrypt(input: &Path, password: &[u8], progress: &Progress) -> Result<Prepared> {
    let (f, len) = open_regular(input)?;
    let mut r = BufReader::with_capacity(256 * 1024, f);
    progress.start(len);
    let session = crypto::unlock(&mut r, password)?;
    // The probe discards a plain file, and fully validates a folder archive.
    let mut probe = folder::ProbeSink::new();
    crypto::decrypt_body(&session, &mut r, &mut probe, progress)?;
    let is_folder = probe.finish()?;
    let suggested_name = sanitize_name(&session.meta.name);
    Ok(Prepared { session, input: input.to_path_buf(), suggested_name, is_folder })
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

/// Phase 2 for folders: rebuilds the folder inside `dest_dir` (never overwriting
/// anything) and returns its path.
pub fn finish_decrypt_folder(prep: &Prepared, dest_dir: &Path, progress: &Progress) -> Result<PathBuf> {
    let (f, len) = open_regular(&prep.input)?;
    let mut r = BufReader::with_capacity(256 * 1024, f);
    progress.start(len);
    crypto::reopen(&prep.session, &mut r)?;
    let mut restore = folder::Restore::begin(dest_dir)?;
    crypto::decrypt_body(&prep.session, &mut r, restore.writer(), progress)?;
    restore.commit(&prep.suggested_name)
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
        out += "Cipher: AES-256-GCM + ChaCha20-Poly1305 (cascade, authenticated)\n";
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("crypton-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x = 5u32;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn real_files_encrypt_verify_info_decrypt() {
        let d = tmp("ops");
        let p = Progress::new();
        let data = noise(150_000);
        let src = d.join("note.bin");
        fs::write(&src, &data).unwrap();
        let enc = d.join("note.bin.crypton");

        encrypt_file(&src, &enc, b"pw", &p).unwrap();
        assert!(encrypt_file(&src, &src, b"pw", &p).is_err(), "must refuse to overwrite the source");
        assert!(matches!(prepare_decrypt(&enc, b"bad", &p), Err(E::WrongPasswordOrCorrupted)));

        let prep = prepare_decrypt(&enc, b"pw", &p).unwrap();
        assert_eq!(prep.suggested_name, "note.bin");
        assert!(!prep.is_folder, "a plain file must not be mistaken for a folder");
        let out = d.join("restored.bin");
        finish_decrypt(&prep, &out, &p).unwrap();
        assert_eq!(fs::read(&out).unwrap(), data);

        assert!(verify_file(&enc, None, &p).unwrap().contains("valid"));
        assert!(verify_file(&enc, Some(b"pw"), &p).unwrap().contains("passed"));
        let info = info_file(&enc, Some(b"pw")).unwrap();
        assert!(info.contains("note.bin") && info.contains("AES-256-GCM"));

        // a modified file is rejected and nothing is written
        let mut raw = fs::read(&enc).unwrap();
        let i = raw.len() / 2;
        raw[i] ^= 1;
        let bad = d.join("bad.crypton");
        fs::write(&bad, &raw).unwrap();
        assert!(matches!(prepare_decrypt(&bad, b"pw", &p), Err(E::IntegrityCompromised)));
        let leftovers: Vec<_> = fs::read_dir(&d).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().ends_with(".part")).collect();
        assert!(leftovers.is_empty(), "no temporary files may remain");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn real_files_steganography_both_methods() {
        use image::{DynamicImage, ImageFormat};
        let d = tmp("stego");
        let img = DynamicImage::ImageRgb8(image::RgbImage::from_fn(120, 90, |x, y| image::Rgb([(x * 2) as u8, (y * 2) as u8, (x + y) as u8])));
        let cover = d.join("cover.png");
        img.save_with_format(&cover, ImageFormat::Png).unwrap();
        let secret = d.join("secret.txt");
        fs::write(&secret, b"top secret").unwrap();
        let dest = d.join("out");
        fs::create_dir_all(&dest).unwrap();

        for (i, pixels) in [true, false].into_iter().enumerate() {
            let out = d.join(format!("hidden{i}.png"));
            let written = if pixels {
                stego::hide_pixels(&secret, &cover, &out, Some(b"pw")).unwrap().0
            } else {
                stego::hide_tail(&secret, &cover, &out, Some(b"pw")).unwrap().0
            };
            assert!(matches!(stego::extract_to_memory(&written, None), Err(E::PasswordRequired)));
            assert!(stego::extract_to_memory(&written, Some(b"nope")).is_err());
            let ex = stego::extract_to_memory(&written, Some(b"pw")).unwrap();
            assert_eq!(ex.name, "secret.txt");
            assert_eq!(&ex.data[..], b"top secret");
            let saved = stego::write_extracted(&ex, &dest).unwrap();
            assert_eq!(fs::read(&saved).unwrap(), b"top secret");
            assert_eq!(saved.parent().unwrap(), dest);
        }
        // the second extraction did not overwrite the first
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
        fs::remove_dir_all(&d).ok();
    }
    fn leftovers(d: &Path) -> Vec<String> {
        fs::read_dir(d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".part"))
            .collect()
    }

    #[test]
    fn folder_encrypt_verify_decrypt() {
        use crate::folder::tests::{sample_tree, snapshot};
        let d = tmp("folder-enc");
        let p = Progress::new();
        let src = d.join("My Folder");
        sample_tree(&src);
        let enc = d.join("My Folder.crypton");

        // the encrypted file may not be written inside the folder being encrypted
        let inside = src.join("x.crypton");
        assert!(encrypt_path(&src, &inside, b"pw", &p).is_err());
        assert!(!inside.exists());

        let skipped = encrypt_path(&src, &enc, b"pw", &p).unwrap();
        assert_eq!(skipped, 0);
        assert!(matches!(prepare_decrypt(&enc, b"bad", &p), Err(E::WrongPasswordOrCorrupted)));
        assert!(verify_file(&enc, None, &p).unwrap().contains("valid"));
        assert!(verify_file(&enc, Some(b"pw"), &p).unwrap().contains("passed"));
        assert!(info_file(&enc, Some(b"pw")).unwrap().contains("My Folder"));

        let prep = prepare_decrypt(&enc, b"pw", &p).unwrap();
        assert!(prep.is_folder);
        assert_eq!(prep.suggested_name, "My Folder");
        let dest = d.join("restored");
        fs::create_dir_all(&dest).unwrap();
        let out = finish_decrypt_folder(&prep, &dest, &p).unwrap();
        assert_eq!(out, dest.join("My Folder"));
        assert_eq!(snapshot(&src), snapshot(&out));

        // restoring again never overwrites: a new folder is created next to the first
        let out2 = finish_decrypt_folder(&prep, &dest, &p).unwrap();
        assert_ne!(out, out2);
        assert_eq!(snapshot(&src), snapshot(&out2));

        // a modified file is rejected before anything is written
        let mut raw = fs::read(&enc).unwrap();
        let i = raw.len() / 2;
        raw[i] ^= 1;
        let bad = d.join("bad.crypton");
        fs::write(&bad, &raw).unwrap();
        assert!(matches!(prepare_decrypt(&bad, b"pw", &p), Err(E::IntegrityCompromised)));
        assert!(leftovers(&dest).is_empty() && leftovers(&d).is_empty());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn empty_folder_encrypts_and_restores() {
        let d = tmp("folder-empty");
        let p = Progress::new();
        let src = d.join("nothing");
        fs::create_dir_all(&src).unwrap();
        let enc = d.join("nothing.crypton");
        encrypt_path(&src, &enc, b"pw", &p).unwrap();
        let prep = prepare_decrypt(&enc, b"pw", &p).unwrap();
        assert!(prep.is_folder);
        let dest = d.join("dest");
        fs::create_dir_all(&dest).unwrap();
        let out = finish_decrypt_folder(&prep, &dest, &p).unwrap();
        assert!(out.is_dir() && fs::read_dir(&out).unwrap().count() == 0);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn folder_steganography_both_methods() {
        use crate::folder::tests::{sample_tree, snapshot};
        use image::{DynamicImage, ImageFormat};
        let d = tmp("folder-stego");
        let src = d.join("secret-folder");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::create_dir_all(src.join("sub/inner")).unwrap();
        fs::write(src.join("sub/inner/b.bin"), vec![7u8; 3_000]).unwrap();
        fs::create_dir_all(src.join("empty")).unwrap();
        // a bigger tree for the tail method, which has no capacity limit
        let big = d.join("big-folder");
        sample_tree(&big);

        let img = DynamicImage::ImageRgb8(image::RgbImage::from_fn(300, 200, |x, y| image::Rgb([(x % 251) as u8, (y % 241) as u8, ((x + y) % 239) as u8])));
        let cover = d.join("cover.png");
        img.save_with_format(&cover, ImageFormat::Png).unwrap();

        for (i, (pixels, pw)) in [(true, Some(&b"pw"[..])), (true, None), (false, Some(&b"pw"[..])), (false, None)].into_iter().enumerate() {
            let out = d.join(format!("hidden{i}.png"));
            let folder = if pixels { &src } else { &big };
            let (written, skipped) = if pixels {
                stego::hide_pixels(folder, &cover, &out, pw).unwrap()
            } else {
                stego::hide_tail(folder, &cover, &out, pw).unwrap()
            };
            assert_eq!(skipped, 0);
            if pw.is_some() {
                assert!(matches!(stego::extract_to_memory(&written, None), Err(E::PasswordRequired)));
                assert!(stego::extract_to_memory(&written, Some(b"nope")).is_err());
            }
            let ex = stego::extract_to_memory(&written, pw).unwrap();
            assert!(ex.is_folder());
            let dest = d.join(format!("dest{i}"));
            fs::create_dir_all(&dest).unwrap();
            let restored = stego::write_extracted(&ex, &dest).unwrap();
            assert!(restored.is_dir());
            assert_eq!(restored.file_name().unwrap().to_string_lossy(), folder.file_name().unwrap().to_string_lossy());
            assert_eq!(snapshot(folder), snapshot(&restored));
            let info = info_file(&written, None).unwrap();
            if pw.is_none() {
                assert!(info.contains("Hidden folder name"), "{info}");
            }
            assert!(leftovers(&dest).is_empty());
        }
        fs::remove_dir_all(&d).ok();
    }
}
