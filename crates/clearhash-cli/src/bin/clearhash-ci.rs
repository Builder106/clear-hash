//! Verify new npm lock tuples against a trusted Git baseline without installing.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Output};

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use clearhash_cli::npm_lock::{locked_packages, LockedPackage};

#[derive(Parser)]
#[command(
    version,
    about = "Verify added/changed npm lock entries against a Git base."
)]
struct Args {
    /// Trusted baseline commit/ref, already available locally (not fetched).
    #[arg(long, required_unless_present = "staged", conflicts_with = "staged")]
    base: Option<String>,

    /// Compare the Git index to HEAD; supports the first commit too.
    #[arg(long)]
    staged: bool,

    /// Lock path relative to repository root. A sibling shrinkwrap takes precedence.
    #[arg(long, default_value = "package-lock.json")]
    lockfile: String,
}

fn git(root: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(root);
    command
}

fn checked(output: Output) -> Result<Vec<u8>> {
    ensure!(
        output.status.success(),
        "Git command failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

enum Snapshot<'a> {
    Commit(&'a str),
    Index,
    Worktree,
    Empty,
}

fn read_lock(root: &Path, snapshot: &Snapshot<'_>, path: &str) -> Result<Option<Vec<u8>>> {
    let listing = match snapshot {
        Snapshot::Empty => return Ok(None),
        Snapshot::Worktree => {
            let file = root.join(path);
            let metadata = match fs::symlink_metadata(&file) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            ensure!(
                metadata.is_file(),
                "lockfile must be a regular file: {path}"
            );
            ensure!(
                file.canonicalize()?.starts_with(root),
                "lockfile escapes repository"
            );
            return Ok(Some(fs::read(file)?));
        }
        Snapshot::Index => checked(
            git(root)
                .args([
                    "--literal-pathspecs",
                    "ls-files",
                    "--stage",
                    "-z",
                    "--",
                    path,
                ])
                .output()?,
        )?,
        Snapshot::Commit(commit) => checked(
            git(root)
                .args(["--literal-pathspecs", "ls-tree", "-z", commit, "--", path])
                .output()?,
        )?,
    };
    if listing.is_empty() {
        return Ok(None);
    }
    let listing = std::str::from_utf8(&listing)?;
    let records: Vec<_> = listing.split_terminator('\0').collect();
    ensure!(records.len() == 1, "unmerged or ambiguous lockfile: {path}");
    let (header, listed_path) = records[0].split_once('\t').context("invalid Git listing")?;
    ensure!(listed_path == path, "unexpected Git path: {listed_path}");
    let fields: Vec<_> = header.split_whitespace().collect();
    ensure!(fields.len() == 3, "invalid Git entry");
    ensure!(
        matches!(fields[0], "100644" | "100755"),
        "lockfile must be a regular file: {path}"
    );
    let oid = match snapshot {
        Snapshot::Index => {
            ensure!(fields[2] == "0", "unmerged lockfile: {path}");
            fields[1]
        }
        _ => {
            ensure!(fields[1] == "blob", "lockfile must be a blob: {path}");
            fields[2]
        }
    };
    Ok(Some(checked(
        git(root).args(["cat-file", "blob", oid]).output()?,
    )?))
}

fn packages(
    root: &Path,
    snapshot: Snapshot<'_>,
    path: &str,
) -> Result<Option<BTreeSet<LockedPackage>>> {
    // npm consumes shrinkwrap rather than package-lock when both exist. Select
    // independently in each snapshot, including when shrinkwrap is added/deleted.
    if path.ends_with("package-lock.json") {
        let shrinkwrap = Path::new(path).with_file_name("npm-shrinkwrap.json");
        if let Some(bytes) = read_lock(
            root,
            &snapshot,
            shrinkwrap.to_str().context("invalid path")?,
        )? {
            return Ok(Some(
                locked_packages(&bytes).context("parsing npm-shrinkwrap.json")?,
            ));
        }
    }
    read_lock(root, &snapshot, path)?
        .map(|bytes| locked_packages(&bytes).with_context(|| format!("parsing {path}")))
        .transpose()
}

fn baseline(root: &Path, args: &Args) -> Result<Option<String>> {
    let base = args.base.as_deref().unwrap_or("HEAD");
    let output = git(root)
        .args([
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ])
        .output()?;
    if output.status.success() {
        return Ok(Some(String::from_utf8(output.stdout)?.trim().into()));
    }
    if args.staged {
        // Only an unborn branch may use an empty baseline. Missing/shallow CI
        // refs and corrupt repositories must never silently verify a partial diff.
        let branch = checked(
            git(root)
                .args(["symbolic-ref", "--quiet", "HEAD"])
                .output()?,
        )?;
        let branch = std::str::from_utf8(&branch)?.trim();
        let status = git(root)
            .args(["show-ref", "--verify", "--quiet", branch])
            .status()?;
        if status.code() == Some(1) {
            return Ok(None);
        }
    }
    bail!("baseline {base:?} is unavailable; fetch the trusted base commit and retry")
}

fn run(args: Args) -> Result<u8> {
    let path = Path::new(&args.lockfile);
    ensure!(
        path.components().all(|c| matches!(c, Component::Normal(_)))
            && !args.lockfile.contains(['\\', '\n', '\r', '\0'])
            && matches!(
                path.file_name().and_then(|v| v.to_str()),
                Some("package-lock.json" | "npm-shrinkwrap.json")
            ),
        "--lockfile must be a repository-relative package-lock.json or npm-shrinkwrap.json path"
    );
    let cwd = env::current_dir()?;
    let root = checked(git(&cwd).args(["rev-parse", "--show-toplevel"]).output()?)?;
    let root = PathBuf::from(std::str::from_utf8(&root)?.trim_end()).canonicalize()?;
    let base = baseline(&root, &args)?;
    let before = packages(
        &root,
        base.as_deref().map_or(Snapshot::Empty, Snapshot::Commit),
        &args.lockfile,
    )?;
    let after = packages(
        &root,
        if args.staged {
            Snapshot::Index
        } else {
            Snapshot::Worktree
        },
        &args.lockfile,
    )?;
    // A removed lock cannot be used to bypass verification. If neither snapshot
    // contains one, this is a configuration error as well.
    let after = after.context("current lockfile is missing; commit a supported npm lockfile")?;
    let before = before.unwrap_or_default();
    let added: Vec<_> = after.difference(&before).collect();
    let mut blocked = false;
    for package in &added {
        let reference = format!("npm:{}@{}", package.name, package.version);
        let verifier = env::var_os("CLEARHASH_VERIFY_BIN")
            .map(PathBuf::from)
            .unwrap_or(
                env::current_exe()?.with_file_name(format!("clearhash{}", env::consts::EXE_SUFFIX)),
            );
        ensure!(
            verifier.is_absolute(),
            "CLEARHASH_VERIFY_BIN must be absolute"
        );
        let status = Command::new(verifier)
            .args([
                "verify",
                &reference,
                "--expected-integrity",
                &package.integrity,
            ])
            .status()
            .with_context(|| format!("verifying {reference}"))?;
        blocked |= !status.success();
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"clearhash-ci.verify", "package":reference,
                "matched":status.success(), "exit_code":status.code()
            })
        );
    }
    eprintln!(
        "clearhash-ci: checked {} added/changed package(s)",
        added.len()
    );
    Ok(u8::from(blocked))
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("clearhash-ci: {error:#}");
            ExitCode::from(3)
        }
    }
}
