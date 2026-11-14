//! Folders: turns a whole directory tree into a single stream of bytes (and back),
//! so that the existing encryption and steganography code can treat it like a file.
//!
//! Archive format (uncompressed container; compression is done later, by the
//! encryption layer, when it is worthwhile):
//!
//! ```text
//! magic (8 bytes)
//! entry*:   kind u8 (1 = folder, 2 = file) | path length u16 | path (UTF-8, '/' separated)
//!           files only: size u64 | data
//! end marker: kind u8 = 0
//! ```
//!
//! Packing is streamed (`FolderReader`): no plaintext copy of the folder is ever
//! written to disk. Unpacking (`Extractor`) validates every path, never follows
//! or creates links, and writes into a hidden staging folder that is renamed to
//! its final name only when everything succeeded.
//!
//! Not stored: symbolic links (skipped and counted), permissions, timestamps.

use crate::util::{message, random_bytes, sanitize_name, unique_path, CryptonError as E, Result, ZVec};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"\x89CRDIR\x1a\n";

const KIND_END: u8 = 0;
const KIND_DIR: u8 = 1;
const KIND_FILE: u8 = 2;

const MAX_ENTRIES: u64 = 2_000_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DEPTH: usize = 128;

fn bad(why: &str) -> io::Error {
    io::Error::other(format!("Invalid folder archive: {why}."))
}

/// True when decrypted/extracted bytes are a folder archive.
pub fn is_folder_data(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

// ---------------------------------------------------------------- packing

struct Entry {
    rel: String,
    abs: PathBuf,
    /// `None` for a folder, the size in bytes for a file.
    size: Option<u64>,
}

/// The result of walking a folder: what will be packed and how big the archive will be.
pub struct Scan {
    entries: Vec<Entry>,
    /// Exact size of the archive in bytes.
    pub total: u64,
    /// Symbolic links and special files that were left out.
    pub skipped: u64,
}

pub fn scan(root: &Path) -> Result<Scan> {
    if !fs::metadata(root)?.is_dir() {
        return message("The chosen path is not a folder.");
    }
    let mut s = Scan { entries: Vec::new(), total: MAGIC.len() as u64 + 1, skipped: 0 };
    walk(root, "", 0, &mut s)?;
    Ok(s)
}

fn walk(dir: &Path, prefix: &str, depth: usize, s: &mut Scan) -> Result<()> {
    if depth > MAX_DEPTH {
        return message("The folder is nested too deeply.");
    }
    let mut kids = fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?;
    kids.sort_by_key(|e| e.file_name());
    for e in kids {
        let fname = e.file_name();
        let Some(name) = fname.to_str() else {
            return message(format!("Unsupported file name (not valid text): {}", e.path().display()));
        };
        let rel = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        if rel.len() > MAX_PATH_BYTES {
            return message(format!("Path too long: {rel}"));
        }
        let md = fs::symlink_metadata(e.path())?;
        let ft = md.file_type();
        if ft.is_symlink() {
            s.skipped += 1;
            continue;
        }
        if !ft.is_dir() && !ft.is_file() {
            s.skipped += 1;
            continue;
        }
        if s.entries.len() as u64 >= MAX_ENTRIES {
            return message("The folder contains too many items.");
        }
        if ft.is_dir() {
            s.total += 1 + 2 + rel.len() as u64;
            s.entries.push(Entry { rel: rel.clone(), abs: e.path(), size: None });
            walk(&e.path(), &rel, depth + 1, s)?;
        } else {
            let size = md.len();
            s.total += 1 + 2 + rel.len() as u64 + 8 + size;
            s.entries.push(Entry { rel, abs: e.path(), size: Some(size) });
        }
    }
    Ok(())
}

impl Scan {
    pub fn reader(self) -> FolderReader {
        FolderReader { entries: self.entries.into_iter(), buf: MAGIC.to_vec(), pos: 0, file: None, finished: false }
    }
}

/// Produces the archive bytes on the fly, one file at a time.
pub struct FolderReader {
    entries: std::vec::IntoIter<Entry>,
    buf: Vec<u8>,
    pos: usize,
    file: Option<(File, u64)>,
    finished: bool,
}

impl Read for FolderReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.buf.len() {
                let n = (self.buf.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if let Some((f, rem)) = self.file.as_mut() {
                if *rem == 0 {
                    self.file = None;
                    continue;
                }
                let want = (*rem).min(out.len() as u64) as usize;
                let n = f.read(&mut out[..want])?;
                if n == 0 {
                    return Err(io::Error::other("A file changed while it was being read: operation cancelled."));
                }
                *rem -= n as u64;
                return Ok(n);
            }
            if self.finished {
                return Ok(0);
            }
            self.buf.clear();
            self.pos = 0;
            match self.entries.next() {
                Some(e) => {
                    self.buf.push(if e.size.is_some() { KIND_FILE } else { KIND_DIR });
                    self.buf.extend_from_slice(&(e.rel.len() as u16).to_le_bytes());
                    self.buf.extend_from_slice(e.rel.as_bytes());
                    if let Some(size) = e.size {
                        self.buf.extend_from_slice(&size.to_le_bytes());
                        self.file = Some((File::open(&e.abs)?, size));
                    }
                }
                None => {
                    self.buf.push(KIND_END);
                    self.finished = true;
                }
            }
        }
    }
}

/// Packs a folder into memory (used by steganography). Returns the archive and
/// the number of skipped links.
pub fn pack_to_memory(root: &Path, max: u64) -> Result<(Zeroizing<Vec<u8>>, u64)> {
    let sc = scan(root)?;
    if sc.total > max {
        return message(format!("The folder is too large (maximum {} MiB).", max / 1024 / 1024));
    }
    let skipped = sc.skipped;
    let mut out = ZVec::with_capacity(sc.total as usize);
    io::copy(&mut sc.reader(), &mut out)?;
    Ok((out.into_inner(), skipped))
}

// ---------------------------------------------------------------- unpacking

/// Turns an archive path into a safe relative path: no empty parts, no `.` or
/// `..`, and every part reduced to a plain file name.
fn safe_rel(text: &str) -> io::Result<PathBuf> {
    let mut out = PathBuf::new();
    for part in text.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(bad("unsafe path"));
        }
        out.push(sanitize_name(part));
    }
    Ok(out)
}

fn create_file(root: &Path, rel: &Path) -> io::Result<File> {
    let target = root.join(rel);
    if let Some(p) = target.parent() {
        fs::create_dir_all(p)?;
    }
    let open = |p: &Path| OpenOptions::new().write(true).create_new(true).open(p);
    match open(&target) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // two names that became equal after cleaning (or differ only by case)
            let parent = target.parent().unwrap_or(root);
            let name = target.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let alt = unique_path(parent, &name).map_err(|e| io::Error::other(e.to_string()))?;
            open(&alt)
        }
        other => other,
    }
}

enum St {
    Magic,
    Kind,
    PathLen(u8),
    Path(u8, usize),
    Size(PathBuf),
    Data(Option<File>, u64),
    End,
}

/// Incremental parser: it is a `Write` sink, so decrypted data can be poured
/// straight into it. With no `root` it only validates (nothing touches the disk).
pub struct Extractor {
    root: Option<PathBuf>,
    st: St,
    buf: Vec<u8>,
    entries: u64,
}

impl Extractor {
    fn new(root: Option<PathBuf>) -> Self {
        Self { root, st: St::Magic, buf: Vec::new(), entries: 0 }
    }

    /// A validator that writes nothing.
    pub fn dry() -> Self {
        Self::new(None)
    }

    fn need(&self) -> usize {
        match &self.st {
            St::Magic => MAGIC.len(),
            St::Kind => 1,
            St::PathLen(_) => 2,
            St::Path(_, n) => *n,
            St::Size(_) => 8,
            St::Data(..) | St::End => 0,
        }
    }

    fn step(&mut self) -> io::Result<()> {
        let buf = std::mem::take(&mut self.buf);
        let st = std::mem::replace(&mut self.st, St::End);
        self.st = match st {
            St::Magic => {
                if buf.as_slice() != MAGIC.as_slice() {
                    return Err(bad("wrong signature"));
                }
                St::Kind
            }
            St::Kind => match buf[0] {
                KIND_END => St::End,
                k @ (KIND_DIR | KIND_FILE) => St::PathLen(k),
                _ => return Err(bad("unknown entry type")),
            },
            St::PathLen(k) => {
                let n = u16::from_le_bytes([buf[0], buf[1]]) as usize;
                if n == 0 || n > MAX_PATH_BYTES {
                    return Err(bad("bad path length"));
                }
                St::Path(k, n)
            }
            St::Path(k, _) => {
                let text = std::str::from_utf8(&buf).map_err(|_| bad("name is not valid text"))?;
                let rel = safe_rel(text)?;
                self.entries += 1;
                if self.entries > MAX_ENTRIES {
                    return Err(bad("too many items"));
                }
                if k == KIND_DIR {
                    if let Some(root) = &self.root {
                        fs::create_dir_all(root.join(&rel))?;
                    }
                    St::Kind
                } else {
                    St::Size(rel)
                }
            }
            St::Size(rel) => {
                let size = u64::from_le_bytes(buf.try_into().map_err(|_| bad("bad size"))?);
                let file = match &self.root {
                    Some(root) => Some(create_file(root, &rel)?),
                    None => None,
                };
                if size == 0 { St::Kind } else { St::Data(file, size) }
            }
            St::Data(..) | St::End => return Err(bad("unexpected state")),
        };
        Ok(())
    }

    /// Call after all data was written: the archive must have ended properly.
    pub fn finish(&mut self) -> Result<()> {
        if matches!(self.st, St::End) {
            Ok(())
        } else {
            message("The folder archive is incomplete: nothing was restored.")
        }
    }
}

impl Write for Extractor {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let total = data.len();
        let mut data = data;
        while !data.is_empty() {
            if let St::Data(file, rem) = &mut self.st {
                let take = (*rem).min(data.len() as u64) as usize;
                if let Some(f) = file {
                    f.write_all(&data[..take])?;
                }
                *rem -= take as u64;
                data = &data[take..];
                if *rem == 0 {
                    self.st = St::Kind;
                }
                continue;
            }
            if matches!(self.st, St::End) {
                return Err(bad("unexpected extra data"));
            }
            let need = self.need();
            let take = (need - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == need {
                self.step()?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write sink used while verifying a decryption: it detects whether the data is
/// a folder archive and, if so, validates its whole structure without writing.
pub struct ProbeSink {
    head: Vec<u8>,
    ex: Option<Extractor>,
}

impl ProbeSink {
    pub fn new() -> Self {
        Self { head: Vec::new(), ex: None }
    }

    /// `Ok(true)` if the data is a valid folder archive, `Ok(false)` if it is a plain file.
    pub fn finish(self) -> Result<bool> {
        match self.ex {
            Some(mut e) => {
                e.finish()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl Write for ProbeSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if let Some(ex) = self.ex.as_mut() {
            return ex.write(data);
        }
        if self.head.len() < MAGIC.len() {
            let used = (MAGIC.len() - self.head.len()).min(data.len());
            self.head.extend_from_slice(&data[..used]);
            if self.head.as_slice() == MAGIC.as_slice() {
                let mut ex = Extractor::dry();
                ex.write_all(&self.head)?;
                ex.write_all(&data[used..])?;
                self.ex = Some(ex);
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Restores a folder inside `dest`: everything goes into a hidden staging folder
/// first, and only `commit` gives it its final name. If anything fails (or the
/// value is dropped), the staging folder is deleted.
pub struct Restore {
    tmp: PathBuf,
    dest: PathBuf,
    ex: Extractor,
}

impl Restore {
    pub fn begin(dest: &Path) -> Result<Self> {
        if !dest.is_dir() {
            return message("The destination folder does not exist.");
        }
        let mut r = [0u8; 6];
        random_bytes(&mut r)?;
        let tag: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dest.join(format!(".crypton-{tag}.part"));
        fs::create_dir(&tmp)?;
        Ok(Self { ex: Extractor::new(Some(tmp.clone())), tmp, dest: dest.to_path_buf() })
    }

    pub fn writer(&mut self) -> &mut Extractor {
        &mut self.ex
    }

    /// Verifies the archive ended properly and moves it to its final name.
    pub fn commit(mut self, name: &str) -> Result<PathBuf> {
        self.ex.finish()?;
        let target = unique_path(&self.dest, &sanitize_name(name))?;
        fs::rename(&self.tmp, &target).map_err(E::from)?;
        Ok(target)
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        // after a successful commit the staging folder no longer exists
        let _ = fs::remove_dir_all(&self.tmp);
    }
}

/// Restores an archive held in memory (steganography) into `dest/<name>`.
pub fn extract_slice(data: &[u8], dest: &Path, name: &str) -> Result<PathBuf> {
    let mut r = Restore::begin(dest)?;
    r.writer().write_all(data).map_err(|e| E::Message(e.to_string()))?;
    r.commit(name)
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("crypton-folder-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn noise(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect()
    }

    /// Builds a sample tree: nested folders, an empty folder, an empty file, binary and text files.
    pub fn sample_tree(root: &Path) {
        fs::create_dir_all(root.join("docs/deep/deeper")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::write(root.join("zero.bin"), b"").unwrap();
        fs::write(root.join("docs/b.bin"), noise(200_000, 1)).unwrap();
        fs::write(root.join("docs/deep/deeper/c.txt"), "ciao ".repeat(50_000)).unwrap();
        fs::write(root.join("docs/nome con spazi e àèì.txt"), b"unicode").unwrap();
    }

    /// (relative path, is_dir, content) for every item, sorted.
    pub fn snapshot(root: &Path) -> Vec<(String, bool, Vec<u8>)> {
        fn rec(dir: &Path, base: &Path, out: &mut Vec<(String, bool, Vec<u8>)>) {
            for e in fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
                if p.is_dir() {
                    out.push((rel, true, vec![]));
                    rec(&p, base, out);
                } else {
                    out.push((rel, false, fs::read(&p).unwrap()));
                }
            }
        }
        let mut v = Vec::new();
        rec(root, root, &mut v);
        v.sort();
        v
    }

    fn pack(root: &Path) -> Vec<u8> {
        let sc = scan(root).unwrap();
        let total = sc.total;
        let mut v = Vec::new();
        sc.reader().read_to_end(&mut v).unwrap();
        assert_eq!(v.len() as u64, total, "the announced size must be exact");
        v
    }

    #[test]
    fn roundtrip_preserves_the_whole_tree() {
        let d = tmp("rt");
        let src = d.join("src");
        sample_tree(&src);
        let archive = pack(&src);
        assert!(is_folder_data(&archive));

        let out = d.join("out");
        fs::create_dir_all(&out).unwrap();
        let restored = extract_slice(&archive, &out, "src").unwrap();
        assert_eq!(snapshot(&src), snapshot(&restored));
        // no staging leftovers, and a second restore does not overwrite the first
        let again = extract_slice(&archive, &out, "src").unwrap();
        assert_ne!(restored, again);
        let names: Vec<_> = fs::read_dir(&out).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn empty_folder_roundtrip() {
        let d = tmp("empty");
        let src = d.join("src");
        fs::create_dir_all(&src).unwrap();
        let archive = pack(&src);
        let out = d.join("out");
        fs::create_dir_all(&out).unwrap();
        let restored = extract_slice(&archive, &out, "src").unwrap();
        assert!(restored.is_dir() && snapshot(&restored).is_empty());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn works_with_any_write_chunking() {
        let d = tmp("chunks");
        let src = d.join("src");
        sample_tree(&src);
        let archive = pack(&src);
        for size in [1usize, 2, 3, 7, 4096, 65_536] {
            let mut ex = Extractor::dry();
            for c in archive.chunks(size) {
                ex.write_all(c).unwrap();
            }
            ex.finish().unwrap();
        }
        fs::remove_dir_all(&d).ok();
    }

    /// Builds an archive by hand, for hostile-input tests.
    fn raw_archive(entries: &[(u8, &str, Option<&[u8]>)]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        for (k, p, data) in entries {
            v.push(*k);
            v.extend_from_slice(&(p.len() as u16).to_le_bytes());
            v.extend_from_slice(p.as_bytes());
            if let Some(d) = data {
                v.extend_from_slice(&(d.len() as u64).to_le_bytes());
                v.extend_from_slice(d);
            }
        }
        v.push(KIND_END);
        v
    }

    #[test]
    fn hostile_paths_are_rejected_and_nothing_escapes() {
        let d = tmp("evil");
        let out = d.join("out");
        fs::create_dir_all(&out).unwrap();
        for evil in ["../escape.txt", "a/../../escape.txt", "/etc/escape.txt", "a//b", "./x", "a/./b", ".."] {
            let a = raw_archive(&[(KIND_FILE, evil, Some(b"pwned"))]);
            assert!(extract_slice(&a, &out, "x").is_err(), "{evil} must be rejected");
        }
        assert!(!d.join("escape.txt").exists());
        // staging folders are cleaned up after failures
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
        // backslashes and drive letters are cleaned into plain names
        let a = raw_archive(&[(KIND_FILE, "..\\..\\evil.txt", Some(b"x")), (KIND_FILE, "C:/x.txt", Some(b"y"))]);
        let r = extract_slice(&a, &out, "x").unwrap();
        assert!(r.join("evil.txt").is_file(), "backslash path reduced to a plain name");
        assert!(r.join("C").join("x.txt").is_file(), "drive letter colon removed");
        assert!(!d.join("evil.txt").exists());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn truncated_or_garbled_archives_are_rejected() {
        let d = tmp("trunc");
        let src = d.join("src");
        sample_tree(&src);
        let archive = pack(&src);
        let out = d.join("out");
        fs::create_dir_all(&out).unwrap();
        for cut in [0usize, 5, 8, 9, 20, archive.len() / 2, archive.len() - 1] {
            assert!(extract_slice(&archive[..cut], &out, "x").is_err(), "cut at {cut}");
        }
        let mut extra = archive.clone();
        extra.push(7);
        assert!(extract_slice(&extra, &out, "x").is_err(), "trailing data");
        let mut wrong = archive.clone();
        wrong[2] ^= 0xff;
        assert!(extract_slice(&wrong, &out, "x").is_err(), "wrong magic");
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0, "no leftovers");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn probe_sink_tells_folders_from_files() {
        let d = tmp("probe");
        let src = d.join("src");
        sample_tree(&src);
        let archive = pack(&src);

        let mut p = ProbeSink::new();
        for c in archive.chunks(5) {
            p.write_all(c).unwrap();
        }
        assert!(p.finish().unwrap());

        let mut p = ProbeSink::new();
        p.write_all(b"just a normal file, not a folder").unwrap();
        assert!(!p.finish().unwrap());

        let mut p = ProbeSink::new();
        p.write_all(b"tiny").unwrap();
        assert!(!p.finish().unwrap());

        // a truncated archive is caught during verification
        let mut p = ProbeSink::new();
        p.write_all(&archive[..archive.len() / 2]).unwrap();
        assert!(p.finish().is_err());
        fs::remove_dir_all(&d).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_not_followed() {
        let d = tmp("links");
        let src = d.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("real.txt"), b"real").unwrap();
        std::os::unix::fs::symlink("/etc", src.join("link-to-etc")).unwrap();
        std::os::unix::fs::symlink(&src, src.join("loop")).unwrap();
        let sc = scan(&src).unwrap();
        assert_eq!(sc.skipped, 2);
        let (data, skipped) = pack_to_memory(&src, 1 << 20).unwrap();
        assert_eq!(skipped, 2);
        let out = d.join("out");
        fs::create_dir_all(&out).unwrap();
        let r = extract_slice(&data, &out, "src").unwrap();
        assert_eq!(snapshot(&r).len(), 1);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn size_limit_for_memory_packing() {
        let d = tmp("limit");
        fs::write(d.join("big.bin"), noise(10_000, 3)).unwrap();
        assert!(pack_to_memory(&d, 5_000).is_err());
        assert!(pack_to_memory(&d, 50_000).is_ok());
        fs::remove_dir_all(&d).ok();
    }
}
