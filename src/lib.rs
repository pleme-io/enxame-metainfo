//! Typed BitTorrent metainfo — a `.torrent` file (or a bare info dict
//! from a magnet metadata exchange) parsed into a typed [`Metainfo`],
//! with the v1 **info-hash** ([BEP-3]) computed from the bencoded info
//! dict.
//!
//! Part of the pleme-io ENXAME suite (`theory/ENXAME.md`). The wire
//! format is [`bencode`]; this crate is the typed border between those
//! bytes and the engine: a parsed [`Metainfo`] is the proof a torrent is
//! well-formed, and its [`InfoHash`] is the swarm's identity.
//!
//! **Canonical-only (M1 scope).** [`bencode::parse`] accepts only
//! canonical bencode (sorted, unique dict keys), so the info dict
//! re-encodes to the exact bytes a conforming client produced — and the
//! SHA-1 of those bytes is the correct info-hash. Lenient parsing with
//! raw-span hashing (for the rare non-canonical torrent in the wild) is
//! a documented follow-up; it cannot change the value for any
//! conforming torrent.
//!
//! [BEP-3]: https://www.bittorrent.org/beps/bep_0003.html

#![forbid(unsafe_code)]

use bencode::Bencode;
use sha1::{Digest, Sha1};

/// A 20-byte BitTorrent v1 info-hash — the swarm's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InfoHash(pub [u8; 20]);

impl InfoHash {
    /// Lower-hex rendering (the announce / magnet form). Typed emission
    /// — hex nibbles written to a fixed buffer, never a `format!()`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(40);
        for &b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }
}

impl std::fmt::Display for InfoHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// One file in a multi-file torrent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Length in bytes.
    pub length: u64,
    /// Path components, relative to the torrent's `name` directory.
    pub path: Vec<String>,
}

/// The layout of a torrent's content — the two shapes BEP-3 admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layout {
    /// A single file of `length` bytes (the info dict carried `length`).
    SingleFile { length: u64 },
    /// A directory of files (the info dict carried `files`).
    MultiFile { files: Vec<FileEntry> },
}

/// The info dict — the hashed, swarm-identifying core of a torrent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoDict {
    /// Suggested file / directory name.
    pub name: String,
    /// Bytes per piece (a power of two in practice).
    pub piece_length: u64,
    /// Concatenated 20-byte SHA-1 piece hashes, split out.
    pub pieces: Vec<[u8; 20]>,
    /// Single- vs multi-file layout.
    pub layout: Layout,
    /// `private` flag (BEP-27) — `1` confines the torrent to its
    /// trackers (no DHT/PEX).
    pub private: bool,
}

impl InfoDict {
    /// Total content length in bytes.
    #[must_use]
    pub fn total_length(&self) -> u64 {
        match &self.layout {
            Layout::SingleFile { length } => *length,
            Layout::MultiFile { files } => files.iter().map(|f| f.length).sum(),
        }
    }

    /// Number of pieces.
    #[must_use]
    pub fn piece_count(&self) -> usize {
        self.pieces.len()
    }
}

/// A parsed `.torrent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metainfo {
    /// Primary tracker announce URL (`announce`), if present.
    pub announce: Option<String>,
    /// Tiered tracker list (`announce-list`, BEP-12).
    pub announce_list: Vec<Vec<String>>,
    /// The info dict.
    pub info: InfoDict,
    /// `creation date` (unix seconds), if present.
    pub creation_date: Option<i64>,
    /// `comment`, if present.
    pub comment: Option<String>,
    /// `created by`, if present.
    pub created_by: Option<String>,
    /// The v1 info-hash (SHA-1 of the bencoded info dict).
    pub info_hash: InfoHash,
}

/// A typed metainfo parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The outer bytes weren't valid bencode.
    Bencode(bencode::Error),
    /// The top-level value (or info) wasn't a dict.
    NotADict { what: &'static str },
    /// A required key was missing.
    MissingKey { key: &'static str },
    /// A key had the wrong bencode type.
    WrongType {
        key: &'static str,
        expected: &'static str,
    },
    /// `pieces` length wasn't a multiple of 20.
    BadPieces,
    /// Neither `length` nor `files` present, or both.
    BadLayout,
    /// A textual field wasn't valid UTF-8.
    NotUtf8 { key: &'static str },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bencode(e) => write!(f, "bencode: {e}"),
            Error::NotADict { what } => write!(f, "{what} is not a dict"),
            Error::MissingKey { key } => write!(f, "missing key `{key}`"),
            Error::WrongType { key, expected } => write!(f, "key `{key}` is not {expected}"),
            Error::BadPieces => write!(f, "`pieces` length is not a multiple of 20"),
            Error::BadLayout => write!(f, "info dict must have exactly one of `length` / `files`"),
            Error::NotUtf8 { key } => write!(f, "key `{key}` is not valid UTF-8"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bencode::Error> for Error {
    fn from(e: bencode::Error) -> Self {
        Error::Bencode(e)
    }
}

impl Metainfo {
    /// Parse a `.torrent` from its raw bytes.
    ///
    /// # Errors
    /// [`Error`] for any malformed-torrent condition.
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        let root = bencode::parse(input)?;
        let dict = root.as_dict().ok_or(Error::NotADict { what: "torrent" })?;

        let info_value = dict
            .get(b"info".as_slice())
            .ok_or(Error::MissingKey { key: "info" })?;
        let info = parse_info(info_value)?;
        // v1 info-hash = SHA-1 of the canonical bencoded info dict. Safe
        // here because bencode::parse only accepts canonical input, so
        // re-encoding reproduces the producer's exact bytes.
        let info_hash = InfoHash(Sha1::digest(info_value.to_bytes()).into());

        Ok(Metainfo {
            announce: opt_str(&root, b"announce", "announce")?,
            announce_list: parse_announce_list(&root)?,
            info,
            creation_date: root.get(b"creation date").and_then(Bencode::as_int),
            comment: opt_str(&root, b"comment", "comment")?,
            created_by: opt_str(&root, b"created by", "created by")?,
            info_hash,
        })
    }
}

fn parse_info(value: &Bencode) -> Result<InfoDict, Error> {
    let info = value.as_dict().ok_or(Error::NotADict { what: "info" })?;

    let name = req_str(value, b"name", "name")?;
    let piece_length =
        value
            .get(b"piece length")
            .and_then(Bencode::as_int)
            .ok_or(Error::MissingKey {
                key: "piece length",
            })?;
    let piece_length = u64::try_from(piece_length).map_err(|_| Error::WrongType {
        key: "piece length",
        expected: "a non-negative integer",
    })?;

    let pieces_bytes = value
        .get(b"pieces")
        .and_then(Bencode::as_bytes)
        .ok_or(Error::MissingKey { key: "pieces" })?;
    if pieces_bytes.len() % 20 != 0 {
        return Err(Error::BadPieces);
    }
    let pieces: Vec<[u8; 20]> = pieces_bytes
        .chunks_exact(20)
        .map(|c| c.try_into().expect("chunks_exact(20) yields 20 bytes"))
        .collect();

    let private = value.get(b"private").and_then(Bencode::as_int) == Some(1);

    // Exactly one of `length` (single-file) / `files` (multi-file).
    let length = value.get(b"length").and_then(Bencode::as_int);
    let files = value.get(b"files");
    let layout = match (length, files) {
        (Some(len), None) => Layout::SingleFile {
            length: u64::try_from(len).map_err(|_| Error::WrongType {
                key: "length",
                expected: "a non-negative integer",
            })?,
        },
        (None, Some(files_value)) => Layout::MultiFile {
            files: parse_files(files_value)?,
        },
        _ => return Err(Error::BadLayout),
    };

    // Touch `info` so the unused binding reads as the validated dict.
    let _ = info;
    Ok(InfoDict {
        name,
        piece_length,
        pieces,
        layout,
        private,
    })
}

fn parse_files(value: &Bencode) -> Result<Vec<FileEntry>, Error> {
    let list = value.as_list().ok_or(Error::WrongType {
        key: "files",
        expected: "a list",
    })?;
    list.iter()
        .map(|entry| {
            let length =
                entry
                    .get(b"length")
                    .and_then(Bencode::as_int)
                    .ok_or(Error::MissingKey {
                        key: "files[].length",
                    })?;
            let length = u64::try_from(length).map_err(|_| Error::WrongType {
                key: "files[].length",
                expected: "a non-negative integer",
            })?;
            let path_list =
                entry
                    .get(b"path")
                    .and_then(Bencode::as_list)
                    .ok_or(Error::MissingKey {
                        key: "files[].path",
                    })?;
            let path = path_list
                .iter()
                .map(|c| {
                    c.as_str().map(str::to_owned).ok_or(Error::NotUtf8 {
                        key: "files[].path",
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(FileEntry { length, path })
        })
        .collect()
}

fn parse_announce_list(root: &Bencode) -> Result<Vec<Vec<String>>, Error> {
    let Some(tiers) = root.get(b"announce-list").and_then(Bencode::as_list) else {
        return Ok(Vec::new());
    };
    tiers
        .iter()
        .map(|tier| {
            tier.as_list()
                .ok_or(Error::WrongType {
                    key: "announce-list",
                    expected: "a list of lists",
                })?
                .iter()
                .map(|u| {
                    u.as_str().map(str::to_owned).ok_or(Error::NotUtf8 {
                        key: "announce-list",
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

fn req_str(d: &Bencode, key: &'static [u8], name: &'static str) -> Result<String, Error> {
    d.get(key)
        .ok_or(Error::MissingKey { key: name })?
        .as_str()
        .map(str::to_owned)
        .ok_or(Error::NotUtf8 { key: name })
}

fn opt_str(d: &Bencode, key: &[u8], name: &'static str) -> Result<Option<String>, Error> {
    match d.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or(Error::NotUtf8 { key: name }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Build a minimal single-file torrent's bytes for testing.
    fn single_file_torrent() -> Vec<u8> {
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Bencode::Bytes(b"hello.txt".to_vec()));
        info.insert(b"piece length".to_vec(), Bencode::Int(16384));
        info.insert(b"length".to_vec(), Bencode::Int(1234));
        // one 20-byte piece hash
        info.insert(b"pieces".to_vec(), Bencode::Bytes(vec![0xab; 20]));
        let mut root = BTreeMap::new();
        root.insert(
            b"announce".to_vec(),
            Bencode::Bytes(b"http://t.example/announce".to_vec()),
        );
        root.insert(b"info".to_vec(), Bencode::Dict(info));
        Bencode::Dict(root).to_bytes()
    }

    #[test]
    fn parses_a_single_file_torrent() {
        let m = Metainfo::from_bytes(&single_file_torrent()).unwrap();
        assert_eq!(m.announce.as_deref(), Some("http://t.example/announce"));
        assert_eq!(m.info.name, "hello.txt");
        assert_eq!(m.info.piece_length, 16384);
        assert_eq!(m.info.piece_count(), 1);
        assert_eq!(m.info.total_length(), 1234);
        assert!(matches!(m.info.layout, Layout::SingleFile { length: 1234 }));
        assert!(!m.info.private);
    }

    #[test]
    fn info_hash_is_sha1_of_the_canonical_info_dict() {
        let m = Metainfo::from_bytes(&single_file_torrent()).unwrap();
        // Recompute independently from the re-encoded info dict.
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Bencode::Bytes(b"hello.txt".to_vec()));
        info.insert(b"piece length".to_vec(), Bencode::Int(16384));
        info.insert(b"length".to_vec(), Bencode::Int(1234));
        info.insert(b"pieces".to_vec(), Bencode::Bytes(vec![0xab; 20]));
        let expected: [u8; 20] = Sha1::digest(Bencode::Dict(info).to_bytes()).into();
        assert_eq!(m.info_hash.0, expected);
        // hex is 40 chars, lower-case
        assert_eq!(m.info_hash.to_hex().len(), 40);
        assert!(m.info_hash.to_hex().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn parses_a_multi_file_torrent() {
        let mut f1 = BTreeMap::new();
        f1.insert(b"length".to_vec(), Bencode::Int(100));
        f1.insert(
            b"path".to_vec(),
            Bencode::List(vec![
                Bencode::Bytes(b"a".to_vec()),
                Bencode::Bytes(b"x.txt".to_vec()),
            ]),
        );
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Bencode::Bytes(b"dir".to_vec()));
        info.insert(b"piece length".to_vec(), Bencode::Int(16384));
        info.insert(b"pieces".to_vec(), Bencode::Bytes(vec![0u8; 40]));
        info.insert(b"files".to_vec(), Bencode::List(vec![Bencode::Dict(f1)]));
        let mut root = BTreeMap::new();
        root.insert(b"info".to_vec(), Bencode::Dict(info));
        let m = Metainfo::from_bytes(&Bencode::Dict(root).to_bytes()).unwrap();
        assert_eq!(m.info.piece_count(), 2);
        assert_eq!(m.info.total_length(), 100);
        match &m.info.layout {
            Layout::MultiFile { files } => {
                assert_eq!(files[0].path, vec!["a".to_string(), "x.txt".to_string()]);
            }
            Layout::SingleFile { .. } => panic!("expected multi-file"),
        }
    }

    #[test]
    fn rejects_both_length_and_files() {
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Bencode::Bytes(b"x".to_vec()));
        info.insert(b"piece length".to_vec(), Bencode::Int(16384));
        info.insert(b"pieces".to_vec(), Bencode::Bytes(vec![0u8; 20]));
        info.insert(b"length".to_vec(), Bencode::Int(1));
        info.insert(b"files".to_vec(), Bencode::List(vec![]));
        let mut root = BTreeMap::new();
        root.insert(b"info".to_vec(), Bencode::Dict(info));
        assert_eq!(
            Metainfo::from_bytes(&Bencode::Dict(root).to_bytes()),
            Err(Error::BadLayout)
        );
    }
}
