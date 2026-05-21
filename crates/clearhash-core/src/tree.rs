//! File-tree hashing: the comparison primitive ClearHash uses instead of byte-identical tarball SHA.
//!
//! A `FileTreeHash` is the SHA-256 of a canonical, mode-normalized, mtime-stripped, path-sorted
//! description of a directory tree. Two trees produce the same `FileTreeHash` iff every file path
//! has the same content and the same normalized mode — independent of timestamps, archive format,
//! or compression level.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{hex_digest, sha256};

/// One normalized entry in a tree: path, content hash, and a coarse mode bit (exec or not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Forward-slashed relative path from the tree root.
    pub path: String,
    /// SHA-256 of the file's content.
    pub content_sha256: [u8; 32],
    /// `true` if mode bit 0o100 is set on the source file.
    pub executable: bool,
}

impl FileEntry {
    /// Canonical bytes hashed into the Merkle root: `<path>\0<exec-byte><content-hash>`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.path.len() + 1 + 1 + 32);
        out.extend_from_slice(self.path.as_bytes());
        out.push(0);
        out.push(if self.executable { 1 } else { 0 });
        out.extend_from_slice(&self.content_sha256);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTreeHash(pub [u8; 32]);

impl FileTreeHash {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        FileTreeHash(b)
    }

    /// Compute the tree hash from a sorted slice of entries.
    /// Caller is responsible for sorting by `path` (lexicographic byte order).
    pub fn from_sorted_entries(entries: &[FileEntry]) -> Self {
        let mut hasher = Sha256::new();
        // Domain separation prefix so a tree hash can't collide with a plain SHA-256.
        hasher.update(b"clearhash.tree.v1\0");
        for e in entries {
            // Length-prefix each entry so concatenation is unambiguous.
            let bytes = e.canonical_bytes();
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
        }
        FileTreeHash(hasher.finalize().into())
    }

    pub fn to_hex(self) -> String {
        hex_digest(&self.0)
    }
}

/// Difference between two normalized trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeDifference {
    OnlyInRegistry { path: String },
    OnlyInRebuild { path: String },
    ContentDiffers { path: String },
    ModeDiffers { path: String },
}

/// Diff two sorted entry slices. Returns differences in path order.
pub fn diff_sorted(registry: &[FileEntry], rebuild: &[FileEntry]) -> Vec<TreeDifference> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < registry.len() && j < rebuild.len() {
        let r = &registry[i];
        let b = &rebuild[j];
        match r.path.cmp(&b.path) {
            std::cmp::Ordering::Less => {
                out.push(TreeDifference::OnlyInRegistry {
                    path: r.path.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(TreeDifference::OnlyInRebuild {
                    path: b.path.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if r.content_sha256 != b.content_sha256 {
                    out.push(TreeDifference::ContentDiffers {
                        path: r.path.clone(),
                    });
                } else if r.executable != b.executable {
                    out.push(TreeDifference::ModeDiffers {
                        path: r.path.clone(),
                    });
                }
                i += 1;
                j += 1;
            }
        }
    }
    while i < registry.len() {
        out.push(TreeDifference::OnlyInRegistry {
            path: registry[i].path.clone(),
        });
        i += 1;
    }
    while j < rebuild.len() {
        out.push(TreeDifference::OnlyInRebuild {
            path: rebuild[j].path.clone(),
        });
        j += 1;
    }
    out
}

/// Helper for callers building an entry from raw bytes.
pub fn entry_from_bytes(path: impl Into<String>, content: &[u8], executable: bool) -> FileEntry {
    FileEntry {
        path: path.into(),
        content_sha256: sha256(content),
        executable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(p: &str, c: &[u8], x: bool) -> FileEntry {
        entry_from_bytes(p, c, x)
    }

    #[test]
    fn identical_trees_hash_equal() {
        let a = vec![e("a.js", b"hello", false), e("b.js", b"world", false)];
        let b = vec![e("a.js", b"hello", false), e("b.js", b"world", false)];
        assert_eq!(
            FileTreeHash::from_sorted_entries(&a),
            FileTreeHash::from_sorted_entries(&b)
        );
    }

    #[test]
    fn content_change_changes_hash() {
        let a = vec![e("a.js", b"hello", false)];
        let b = vec![e("a.js", b"hello!", false)];
        assert_ne!(
            FileTreeHash::from_sorted_entries(&a),
            FileTreeHash::from_sorted_entries(&b)
        );
    }

    #[test]
    fn mode_change_changes_hash() {
        let a = vec![e("bin/run", b"#!/bin/sh\n", false)];
        let b = vec![e("bin/run", b"#!/bin/sh\n", true)];
        assert_ne!(
            FileTreeHash::from_sorted_entries(&a),
            FileTreeHash::from_sorted_entries(&b)
        );
    }

    #[test]
    fn diff_detects_each_category() {
        let r = vec![
            e("a", b"x", false),
            e("b", b"x", false),
            e("c", b"x", false),
        ];
        let b = vec![
            e("a", b"x", true),  // mode differs
            e("b", b"y", false), // content differs
            // c missing (only-in-registry)
            e("d", b"x", false), // only-in-rebuild
        ];
        let diffs = diff_sorted(&r, &b);
        assert_eq!(diffs.len(), 4);
        assert!(matches!(diffs[0], TreeDifference::ModeDiffers { ref path } if path == "a"));
        assert!(matches!(diffs[1], TreeDifference::ContentDiffers { ref path } if path == "b"));
        assert!(matches!(diffs[2], TreeDifference::OnlyInRegistry { ref path } if path == "c"));
        assert!(matches!(diffs[3], TreeDifference::OnlyInRebuild { ref path } if path == "d"));
    }
}
