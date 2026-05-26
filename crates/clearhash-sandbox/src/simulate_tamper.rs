//! Demo-only tamper simulator.
//!
//! Applies real, observable modifications to the registry-extracted tree so the downstream
//! `compare_trees` call produces a genuine MISMATCH. The point is to demonstrate what
//! ClearHash *catches* — the comparison logic is unchanged, only the input to it is poisoned
//! deterministically.
//!
//! **This is NEVER enabled by default and is always announced loudly in the output.** It
//! exists for documentation, demos, and tests — not for production use. The simulation only
//! makes sense in the context of `clearhash verify --simulate-tamper`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::SandboxError;

/// Which kind of tamper to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperMode {
    /// Inject a new file. Demonstrates `OnlyInRegistry`.
    InjectedPayload,
    /// Modify the contents of an existing file. Demonstrates `ContentDiffers`.
    ContentSwap,
    /// Flip the executable bit on an existing file. Demonstrates `ModeDiffers`.
    ModeFlip,
    /// Delete an existing file. Demonstrates `OnlyInRebuild`.
    Deletion,
    /// Apply all four — punchiest demo, surfaces every diff category.
    All,
}

impl TamperMode {
    /// All concrete modes that should run when `All` is selected.
    fn expand(self) -> &'static [TamperMode] {
        match self {
            TamperMode::All => &[
                TamperMode::InjectedPayload,
                TamperMode::ContentSwap,
                TamperMode::ModeFlip,
                TamperMode::Deletion,
            ],
            TamperMode::InjectedPayload => &[TamperMode::InjectedPayload],
            TamperMode::ContentSwap => &[TamperMode::ContentSwap],
            TamperMode::ModeFlip => &[TamperMode::ModeFlip],
            TamperMode::Deletion => &[TamperMode::Deletion],
        }
    }
}

/// One applied change. Returned so the CLI can report exactly what was simulated.
#[derive(Debug)]
pub struct TamperApplied {
    pub mode: TamperMode,
    pub path: String,
    pub detail: &'static str,
}

/// Apply tampers to the directory at `root`. The directory must contain the extracted
/// contents of the *registry* artifact (we want to simulate "the registry served bad bytes").
///
/// Tampers must operate on *disjoint files* — otherwise e.g. deletion erases mode-flip's
/// work and only one diff category surfaces. We thread a `used` set through to guarantee
/// each subsequent tamper picks a fresh target.
pub fn apply(root: &Path, mode: TamperMode) -> Result<Vec<TamperApplied>, SandboxError> {
    use std::collections::HashSet;

    let mut applied = Vec::new();
    let regular_files = walk_regular_files(root)?;
    if regular_files.is_empty() {
        return Err(SandboxError::Extract(
            "tamper simulation: extracted tree is empty".into(),
        ));
    }
    let mut used: HashSet<PathBuf> = HashSet::new();

    for sub in mode.expand() {
        let t = match sub {
            TamperMode::InjectedPayload => inject_payload(root)?,
            TamperMode::ContentSwap => content_swap(root, &regular_files, &used)?,
            TamperMode::ModeFlip => mode_flip(root, &regular_files, &used)?,
            TamperMode::Deletion => deletion(root, &regular_files, &used)?,
            TamperMode::All => unreachable!("expand() flattens All"),
        };
        // Record the absolute path so later tampers can avoid it.
        let abs = root.join(&t.path);
        used.insert(abs);
        applied.push(t);
    }
    Ok(applied)
}

// ---- individual tampers -------------------------------------------------------------------

const PAYLOAD_BYTES: &[u8] = b"// === ClearHash tamper-simulation marker ===\n\
// In a real attack, this would be a credential stealer or wallet drainer.\n\
// ClearHash spotted it because the rebuilt tree does not contain this file.\n";

fn inject_payload(root: &Path) -> Result<TamperApplied, SandboxError> {
    // Plausible-looking name + location: a dotfile under dist/ that linting tools would skip.
    let candidate_dirs = ["dist", "lib", "build", "src"];
    let mut dest = None;
    for d in candidate_dirs {
        let p = root.join(d);
        if p.is_dir() {
            dest = Some(p.join(".clearhash-tamper-demo.js"));
            break;
        }
    }
    let path = dest.unwrap_or_else(|| root.join(".clearhash-tamper-demo.js"));
    fs::write(&path, PAYLOAD_BYTES)?;

    Ok(TamperApplied {
        mode: TamperMode::InjectedPayload,
        path: relative(root, &path),
        detail: "added a file that the source rebuild did not produce",
    })
}

fn content_swap(
    root: &Path,
    files: &[PathBuf],
    used: &std::collections::HashSet<PathBuf>,
) -> Result<TamperApplied, SandboxError> {
    // Prefer .js / .ts / .mjs / .cjs (most package payloads are JS). Fall back to any unused file.
    let target = files
        .iter()
        .filter(|p| !used.contains(*p))
        .find(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("js" | "ts" | "mjs" | "cjs")
            )
        })
        .or_else(|| files.iter().find(|p| !used.contains(*p)))
        .ok_or_else(|| SandboxError::Extract("no files to swap content in".into()))?;

    let mut bytes = fs::read(target)?;
    bytes.extend_from_slice(
        b"\n/* ClearHash tamper-simulation: 1 byte appended.\n   Real attacks modify whole functions. */\n",
    );
    fs::write(target, bytes)?;

    Ok(TamperApplied {
        mode: TamperMode::ContentSwap,
        path: relative(root, target),
        detail: "appended bytes to an existing file (real attacks rewrite functions)",
    })
}

fn mode_flip(
    root: &Path,
    files: &[PathBuf],
    used: &std::collections::HashSet<PathBuf>,
) -> Result<TamperApplied, SandboxError> {
    // Pick a non-executable file and make it executable (or vice versa). Skip files already
    // used by other tampers AND skip files deletion is likely to want (priority README/LICENSE
    // names) so the two tampers stay disjoint.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        const DELETION_PRIORITY: &[&str] = &["README.md", "README", "LICENSE", "CHANGELOG.md"];

        for f in files {
            if used.contains(f) {
                continue;
            }
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == ".clearhash-tamper-demo.js" || DELETION_PRIORITY.contains(&name) {
                continue;
            }
            let meta = fs::metadata(f)?;
            let mut perms = meta.permissions();
            let current_mode = perms.mode();
            let new_mode = if current_mode & 0o111 == 0 {
                current_mode | 0o111
            } else {
                current_mode & !0o111
            };
            if new_mode != current_mode {
                perms.set_mode(new_mode);
                fs::set_permissions(f, perms)?;
                return Ok(TamperApplied {
                    mode: TamperMode::ModeFlip,
                    path: relative(root, f),
                    detail: "flipped the executable bit (lets attackers run arbitrary scripts)",
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (root, files, used);
    }
    Ok(TamperApplied {
        mode: TamperMode::ModeFlip,
        path: "<skipped>".into(),
        detail: "no eligible file (e.g. running on Windows)",
    })
}

fn deletion(
    root: &Path,
    files: &[PathBuf],
    used: &std::collections::HashSet<PathBuf>,
) -> Result<TamperApplied, SandboxError> {
    // Walk the priority list in *order* so README.md wins before LICENSE etc.
    const PRIORITY: &[&str] = &["README.md", "README", "LICENSE", "CHANGELOG.md"];
    let target = PRIORITY.iter().find_map(|wanted| {
        files
            .iter()
            .find(|p| !used.contains(*p) && p.file_name().and_then(|n| n.to_str()) == Some(*wanted))
            .cloned()
    });

    // Fall back: any unused file that isn't the injected payload.
    let target = target.unwrap_or_else(|| {
        files
            .iter()
            .rfind(|p| {
                !used.contains(*p)
                    && p.file_name().and_then(|n| n.to_str()) != Some(".clearhash-tamper-demo.js")
            })
            .cloned()
            .unwrap_or_else(|| files[0].clone())
    });

    let path_str = relative(root, &target);
    fs::remove_file(&target)?;
    Ok(TamperApplied {
        mode: TamperMode::Deletion,
        path: path_str,
        detail: "removed a file (rebuild still has it; registry tree no longer does)",
    })
}

// ---- helpers ------------------------------------------------------------------------------

fn walk_regular_files(root: &Path) -> Result<Vec<PathBuf>, SandboxError> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|x| x.ok())
    {
        if e.file_type().is_file() {
            out.push(e.path().to_path_buf());
        }
    }
    Ok(out)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn seed_tree(dir: &Path) {
        fs::create_dir_all(dir.join("dist")).unwrap();
        fs::write(dir.join("dist/index.js"), b"console.log('ok')\n").unwrap();
        fs::write(dir.join("README.md"), b"# package\n").unwrap();
        fs::write(dir.join("package.json"), br#"{"name":"x","version":"1"}"#).unwrap();
    }

    #[test]
    fn injected_payload_creates_a_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        seed_tree(tmp.path());
        let res = apply(tmp.path(), TamperMode::InjectedPayload).unwrap();
        assert_eq!(res.len(), 1);
        assert!(tmp.path().join("dist/.clearhash-tamper-demo.js").exists());
    }

    #[test]
    fn content_swap_grows_an_existing_js_file() {
        let tmp = tempfile::tempdir().unwrap();
        seed_tree(tmp.path());
        let before = fs::read(tmp.path().join("dist/index.js")).unwrap();
        apply(tmp.path(), TamperMode::ContentSwap).unwrap();
        let after = fs::read(tmp.path().join("dist/index.js")).unwrap();
        assert!(after.len() > before.len());
        assert!(String::from_utf8_lossy(&after).contains("ClearHash tamper-simulation"));
    }

    #[test]
    fn deletion_removes_readme_first() {
        let tmp = tempfile::tempdir().unwrap();
        seed_tree(tmp.path());
        let res = apply(tmp.path(), TamperMode::Deletion).unwrap();
        assert_eq!(res[0].path, "README.md");
        assert!(!tmp.path().join("README.md").exists());
    }

    #[test]
    fn all_mode_surfaces_every_category() {
        let tmp = tempfile::tempdir().unwrap();
        seed_tree(tmp.path());
        let res = apply(tmp.path(), TamperMode::All).unwrap();
        let modes: Vec<_> = res.iter().map(|t| t.mode).collect();
        assert!(modes.contains(&TamperMode::InjectedPayload));
        assert!(modes.contains(&TamperMode::ContentSwap));
        assert!(modes.contains(&TamperMode::ModeFlip));
        assert!(modes.contains(&TamperMode::Deletion));
    }

    #[test]
    fn all_mode_targets_are_disjoint() {
        // Regression: previously mode_flip and deletion could both pick LICENSE,
        // causing only 3 of 4 diff categories to surface in the downstream tree compare.
        let tmp = tempfile::tempdir().unwrap();
        seed_tree(tmp.path());
        // Add one more file so there's enough room for both mode_flip and deletion.
        fs::write(tmp.path().join("LICENSE"), b"MIT\n").unwrap();

        let res = apply(tmp.path(), TamperMode::All).unwrap();
        let paths: Vec<_> = res.iter().map(|t| t.path.clone()).collect();
        let mut unique = paths.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            paths.len(),
            "tampers shared a target path: {paths:?}"
        );
    }
}
