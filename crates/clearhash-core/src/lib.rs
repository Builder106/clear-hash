//! Shared types for ClearHash. No I/O, no async — pure data.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod tree;

pub use tree::{FileEntry, FileTreeHash, TreeDifference};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    Cargo,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Cargo => "cargo",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Ecosystem {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "npm" => Ok(Ecosystem::Npm),
            "pypi" => Ok(Ecosystem::Pypi),
            "cargo" | "crates" => Ok(Ecosystem::Cargo),
            other => Err(Error::UnknownEcosystem(other.to_string())),
        }
    }
}

/// A canonical package reference: `npm:litellm@1.82.7`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl fmt::Display for PackageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}@{}", self.ecosystem, self.name, self.version)
    }
}

impl FromStr for PackageRef {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (ecosystem_s, rest) = s
            .split_once(':')
            .ok_or_else(|| Error::ParsePackageRef(s.to_string()))?;
        let ecosystem = Ecosystem::from_str(ecosystem_s)?;

        // Find the LAST '@' so scoped npm names (`@scope/name@1.2.3`) work.
        let at_idx = rest
            .rfind('@')
            .ok_or_else(|| Error::ParsePackageRef(s.to_string()))?;
        let (name, version_with_at) = rest.split_at(at_idx);
        let version = &version_with_at[1..];

        if name.is_empty() || version.is_empty() {
            return Err(Error::ParsePackageRef(s.to_string()));
        }

        Ok(PackageRef {
            ecosystem,
            name: name.to_string(),
            version: version.to_string(),
        })
    }
}

/// The verified claim extracted from a SLSA attestation: where the source lives and which commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceClaim {
    /// Git URL of the source repository.
    pub source_repo: String,
    /// Full 40-char hex commit SHA.
    pub commit_sha: String,
    /// Builder identity from the SLSA statement (e.g. `https://github.com/actions/runner/github-hosted`).
    pub builder_id: String,
    /// Time the Rekor entry was recorded.
    pub signed_at: DateTime<Utc>,
}

/// Terminal outcome of a verify run.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    Match { tree_hash: FileTreeHash },
    TreeMismatch { differences: Vec<TreeDifference> },
    NoAttestation,
    RebuildFailed { stderr_tail: String },
    SignatureInvalid { reason: String },
}

impl VerifyOutcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            VerifyOutcome::Match { .. } => 0,
            VerifyOutcome::TreeMismatch { .. } | VerifyOutcome::SignatureInvalid { .. } => 1,
            VerifyOutcome::NoAttestation => 2,
            VerifyOutcome::RebuildFailed { .. } => 3,
        }
    }
}

/// SHA-256 of a byte slice, returned as a 32-byte array.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn hex_digest(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("unknown ecosystem: {0}")]
    UnknownEcosystem(String),

    #[error("could not parse package reference {0:?}: expected `<ecosystem>:<name>@<version>`")]
    ParsePackageRef(String),

    #[error("attestation envelope was malformed: {0}")]
    MalformedAttestation(String),

    #[error(
        "commit SHA from registry ({registry}) did not match git HEAD after checkout ({actual})"
    )]
    CommitDriftAfterCheckout { registry: String, actual: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_simple() {
        let p: PackageRef = "npm:litellm@1.82.7".parse().unwrap();
        assert_eq!(p.ecosystem, Ecosystem::Npm);
        assert_eq!(p.name, "litellm");
        assert_eq!(p.version, "1.82.7");
    }

    #[test]
    fn parses_npm_scoped() {
        let p: PackageRef = "npm:@sigstore/sign@2.3.1".parse().unwrap();
        assert_eq!(p.name, "@sigstore/sign");
        assert_eq!(p.version, "2.3.1");
    }

    #[test]
    fn parses_pypi() {
        let p: PackageRef = "pypi:sigstore@3.0.0".parse().unwrap();
        assert_eq!(p.ecosystem, Ecosystem::Pypi);
    }

    #[test]
    fn parses_cargo() {
        let p: PackageRef = "cargo:serde@1.0.197".parse().unwrap();
        assert_eq!(p.ecosystem, Ecosystem::Cargo);
    }

    #[test]
    fn rejects_missing_version() {
        assert!("npm:litellm".parse::<PackageRef>().is_err());
    }

    #[test]
    fn rejects_unknown_ecosystem() {
        assert!("rubygems:rails@7.0".parse::<PackageRef>().is_err());
    }

    #[test]
    fn round_trips_display() {
        let s = "npm:@sigstore/sign@2.3.1";
        let p: PackageRef = s.parse().unwrap();
        assert_eq!(p.to_string(), s);
    }

    #[test]
    fn exit_codes_map() {
        assert_eq!(
            VerifyOutcome::Match {
                tree_hash: FileTreeHash::from_bytes([0u8; 32])
            }
            .exit_code(),
            0
        );
        assert_eq!(
            VerifyOutcome::TreeMismatch {
                differences: vec![]
            }
            .exit_code(),
            1
        );
        assert_eq!(VerifyOutcome::NoAttestation.exit_code(), 2);
    }
}
