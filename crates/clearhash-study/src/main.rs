//! Measurement driver for `docs/specs/hermetic-verifiability.md`.
//!
//! This binary is not a verifier. Arms N and I give rebuild or resolver containers
//! network access on purpose. `clearhash`, `clearhash-npm`, and `clearhash-ci` never
//! call into it.

use std::collections::HashSet;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use clearhash_core::{Ecosystem, PackageRef, VerifyOutcome};
use clearhash_ecosystems::{for_ecosystem, EcosystemAdapter};
use clearhash_registry::{FetchError, FetchedArtifact};
use clearhash_sandbox::{ContainerJob, RebuildOptions, RebuildSource, SandboxError};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Per-container limit from the study plan.
const TIME_LIMIT: Duration = Duration::from_secs(30 * 60);
const MEMORY_BYTES: i64 = 4 * 1024 * 1024 * 1024;
/// Keep ledger lines readable; the build log tail is diagnostic only.
const MAX_ERROR_CHARS: usize = 4000;

#[derive(Parser)]
#[command(about = "Network-off verifiability study driver (not a verifier)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Rebuild each sampled release in each arm and append one ledger line per arm.
    Run {
        /// JSON Lines sample, one release per line.
        #[arg(long)]
        sample: PathBuf,
        /// JSON Lines ledger. Existing non-infrastructure results are not rerun.
        #[arg(long)]
        ledger: PathBuf,
        /// Scratch root for per-arm work directories, removed after each arm.
        #[arg(long)]
        workdir: PathBuf,
        /// Commit of the ClearHash checkout that built this binary.
        #[arg(long)]
        tool_commit: String,
        #[arg(long, default_value_t = 1)]
        jobs: usize,
        #[arg(long, value_delimiter = ',', default_value = "h,n,i")]
        arms: Vec<Arm>,
    },
    /// Walk PyPI candidates in sample order and keep releases whose sdist has provenance.
    ScreenPypi {
        #[arg(long)]
        candidates: PathBuf,
        /// Kept releases, in order.
        #[arg(long)]
        sample: PathBuf,
        /// Every screened candidate with its decision.
        #[arg(long)]
        screened: PathBuf,
        #[arg(long)]
        target: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Arm {
    /// No network; committed hash-pinned lock only (the shipped verifier).
    H,
    /// Network during dependency installation, bounded to the publish time.
    N,
    /// Lock inferred as of the publish time, then no network.
    I,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Release {
    /// deps.dev system name: `NPM` or `PYPI`.
    system: String,
    name: String,
    version: String,
    /// RFC 3339 upload time.
    published_at: String,
    #[serde(default)]
    attestation_url: Option<String>,
    #[serde(default)]
    source_repo: Option<String>,
    #[serde(default)]
    commit: Option<String>,
}

impl Release {
    fn package(&self) -> Result<PackageRef> {
        let ecosystem = match self.system.as_str() {
            "NPM" => "npm",
            "PYPI" => "pypi",
            other => bail!("unsupported system {other}"),
        };
        Ok(format!("{ecosystem}:{}@{}", self.name, self.version).parse()?)
    }

    fn key(&self, arm: Arm) -> Key {
        (
            self.system.clone(),
            self.name.clone(),
            self.version.clone(),
            arm,
        )
    }

    fn slug(&self) -> String {
        format!("{}-{}-{}", self.system, self.name, self.version)
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
}

type Key = (String, String, String, Arm);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Fetch,
    Attestation,
    Source,
    Lock,
    Dependencies,
    Build,
    Artifact,
    Compared,
    /// Host or Docker trouble, not a property of the package. Rerun on resume.
    Infrastructure,
}

#[derive(Debug, Serialize, Deserialize)]
struct Comparison {
    matched: bool,
    tree_hash: Option<String>,
    differences: Vec<String>,
}

impl From<VerifyOutcome> for Comparison {
    fn from(outcome: VerifyOutcome) -> Self {
        match outcome {
            VerifyOutcome::Match { tree_hash } => Self {
                matched: true,
                tree_hash: Some(tree_hash.to_hex()),
                differences: Vec::new(),
            },
            VerifyOutcome::TreeMismatch { differences } => Self {
                matched: false,
                tree_hash: None,
                differences: differences.iter().map(|d| format!("{d:?}")).collect(),
            },
            other => Self {
                matched: false,
                tree_hash: None,
                differences: vec![format!("{other:?}")],
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    system: String,
    name: String,
    version: String,
    arm: Arm,
    tool_commit: String,
    started_at: String,
    seconds: f64,
    stage: Stage,
    error: Option<String>,
    attested_repo: Option<String>,
    attested_commit: Option<String>,
    /// Arm I only: `committed` or `inferred`.
    lock_source: Option<String>,
    t1: Option<Comparison>,
    t0: Option<Comparison>,
    image: Option<String>,
    image_id: Option<String>,
}

#[derive(Debug)]
struct Failure {
    stage: Stage,
    error: String,
}

impl Failure {
    fn new(stage: Stage, error: impl Display) -> Self {
        let error = error.to_string();
        let start = error.len().saturating_sub(MAX_ERROR_CHARS);
        let start = (start..=error.len())
            .find(|&i| error.is_char_boundary(i))
            .unwrap_or(error.len());
        Self {
            stage,
            error: error[start..].to_string(),
        }
    }
}

/// Docker and host I/O errors are infrastructure; everything else belongs to `stage`.
fn sandbox(stage: Stage, error: SandboxError) -> Failure {
    match error {
        SandboxError::Docker(_) | SandboxError::Io(_) => Failure::new(Stage::Infrastructure, error),
        SandboxError::Timeout(_) => Failure::new(stage, format!("timeout: {error}")),
        _ => Failure::new(stage, error),
    }
}

struct Prepared {
    fetched: FetchedArtifact,
    source: RebuildSource,
}

struct ArmResult {
    t1: Comparison,
    t0: Comparison,
    lock_source: Option<String>,
}

struct Study {
    workdir: PathBuf,
    tool_commit: String,
    ledger: Mutex<tokio::fs::File>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clearhash_study=info".into()),
        )
        .init();
    match Cli::parse().command {
        Command::Run {
            sample,
            ledger,
            workdir,
            tool_commit,
            jobs,
            arms,
        } => run(&sample, &ledger, workdir, tool_commit, jobs.max(1), &arms).await,
        Command::ScreenPypi {
            candidates,
            sample,
            screened,
            target,
        } => screen_pypi(&candidates, &sample, &screened, target).await,
    }
}

fn read_jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str(line).with_context(|| format!("{} line {}", path.display(), i + 1))
        })
        .collect()
}

async fn run(
    sample: &Path,
    ledger: &Path,
    workdir: PathBuf,
    tool_commit: String,
    jobs: usize,
    arms: &[Arm],
) -> Result<()> {
    let releases: Vec<Release> = read_jsonl(sample)?;
    let done: HashSet<Key> = if ledger.exists() {
        read_jsonl::<Record>(ledger)?
            .into_iter()
            .filter(|r| r.stage != Stage::Infrastructure)
            .map(|r| (r.system, r.name, r.version, r.arm))
            .collect()
    } else {
        HashSet::new()
    };
    std::fs::create_dir_all(&workdir)?;
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger)
        .await?;
    let context = Study {
        workdir,
        tool_commit,
        ledger: Mutex::new(file),
    };
    let total = releases.len();
    futures_util::stream::iter(releases.iter().enumerate())
        .for_each_concurrent(jobs, |(index, release)| {
            let pending: Vec<Arm> = arms
                .iter()
                .copied()
                .filter(|arm| !done.contains(&release.key(*arm)))
                .collect();
            let context = &context;
            async move {
                if pending.is_empty() {
                    return;
                }
                tracing::info!(n = index + 1, total, release = %release.slug(), "start");
                if let Err(error) = study_release(release, &pending, context).await {
                    tracing::error!(release = %release.slug(), "{error:#}");
                }
            }
        })
        .await;
    Ok(())
}

async fn study_release(release: &Release, arms: &[Arm], context: &Study) -> Result<()> {
    let pkg = release.package()?;
    let adapter = for_ecosystem(pkg.ecosystem);
    let started = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();
    let prepared = prepare(&*adapter, &pkg).await;
    for &arm in arms {
        let arm_started = Instant::now();
        let arm_started_at = chrono::Utc::now().to_rfc3339();
        let (result, attested) = match &prepared {
            Err(failure) => (Err(Failure::new(failure.stage, &failure.error)), None),
            Ok(prepared) => {
                let dir = context
                    .workdir
                    .join(release.slug())
                    .join(format!("{arm:?}"));
                let result = run_arm(arm, &*adapter, &pkg, release, prepared, &dir).await;
                release_workdir(adapter.rebuild_image(), &dir).await;
                (result, Some(&prepared.source))
            }
        };
        let (seconds, started_at) = match &prepared {
            Ok(_) => (arm_started.elapsed().as_secs_f64(), arm_started_at),
            Err(_) => (started.elapsed().as_secs_f64(), started_at.clone()),
        };
        let image_id = clearhash_sandbox::image_id(adapter.rebuild_image())
            .await
            .ok()
            .flatten();
        let record = match result {
            Ok(done) => Record {
                stage: Stage::Compared,
                error: None,
                lock_source: done.lock_source,
                t1: Some(done.t1),
                t0: Some(done.t0),
                ..base_record(release, arm, &context.tool_commit, started_at, seconds)
            },
            Err(failure) => Record {
                stage: failure.stage,
                error: Some(failure.error),
                ..base_record(release, arm, &context.tool_commit, started_at, seconds)
            },
        };
        let record = Record {
            attested_repo: attested.map(|s| s.source_repo.clone()),
            attested_commit: attested.map(|s| s.commit_sha.clone()),
            image: Some(adapter.rebuild_image().to_string()),
            image_id,
            ..record
        };
        tracing::info!(release = %release.slug(), ?arm, stage = ?record.stage,
            t1 = record.t1.as_ref().map(|c| c.matched), seconds = record.seconds, "done");
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let mut ledger = context.ledger.lock().await;
        ledger.write_all(&line).await?;
        ledger.flush().await?;
    }
    Ok(())
}

fn base_record(
    release: &Release,
    arm: Arm,
    tool_commit: &str,
    started_at: String,
    seconds: f64,
) -> Record {
    Record {
        system: release.system.clone(),
        name: release.name.clone(),
        version: release.version.clone(),
        arm,
        tool_commit: tool_commit.to_string(),
        started_at,
        seconds,
        stage: Stage::Infrastructure,
        error: None,
        attested_repo: None,
        attested_commit: None,
        lock_source: None,
        t1: None,
        t0: None,
        image: None,
        image_id: None,
    }
}

/// Fetch the registry artifact and verify its attestation once for all arms.
async fn prepare(adapter: &dyn EcosystemAdapter, pkg: &PackageRef) -> Result<Prepared, Failure> {
    let fetched = clearhash_registry::fetch(adapter, pkg)
        .await
        .map_err(|e| match &e {
            FetchError::Http(http) if http.is_connect() || http.is_timeout() => {
                Failure::new(Stage::Infrastructure, &e)
            }
            _ => Failure::new(Stage::Fetch, &e),
        })?;
    let bundle = fetched
        .attestation_bundle
        .clone()
        .ok_or_else(|| Failure::new(Stage::Attestation, "no attestation published"))?;
    let verified = clearhash_provenance::verify(adapter, &bundle)
        .await
        .map_err(|e| Failure::new(Stage::Attestation, e))?;
    Ok(Prepared {
        fetched,
        source: RebuildSource::from(&verified.claim),
    })
}

async fn run_arm(
    arm: Arm,
    adapter: &dyn EcosystemAdapter,
    pkg: &PackageRef,
    release: &Release,
    prepared: &Prepared,
    dir: &Path,
) -> Result<ArmResult, Failure> {
    let _ = std::fs::remove_dir_all(dir);
    let source_dir = dir.join("source");
    std::fs::create_dir_all(&source_dir).map_err(|e| Failure::new(Stage::Infrastructure, e))?;
    let source = &prepared.source;
    clearhash_sandbox::clone_and_pin(&source.source_repo, &source.commit_sha, &source_dir)
        .await
        .map_err(|e| sandbox(Stage::Source, e))?;

    let mut options = RebuildOptions {
        timeout: Some(TIME_LIMIT),
        memory_bytes: Some(MEMORY_BYTES),
        ..Default::default()
    };
    let mut lock_source = None;
    match arm {
        Arm::H => options.dependencies = offline(adapter, &source_dir, dir).await?,
        Arm::N => {
            options.env = vec![
                "CLEARHASH_DEPENDENCY_MODE=network".into(),
                format!("CLEARHASH_RESOLVE_BEFORE={}", release.published_at),
            ]
        }
        Arm::I => {
            let committed = adapter.offline_dependencies(&source_dir).is_ok();
            if !committed {
                resolve(adapter, pkg.ecosystem, &source_dir, release).await?;
            }
            lock_source = Some(if committed { "committed" } else { "inferred" }.to_string());
            options.dependencies = offline(adapter, &source_dir, dir).await?;
        }
    }

    let rebuilt = clearhash_sandbox::rebuild_checked_out(adapter, source, pkg, dir, &options)
        .await
        .map_err(|e| sandbox(Stage::Build, e))?;
    let artifact = |e| sandbox(Stage::Artifact, e);
    let registry_root = clearhash_sandbox::extract_archive(
        adapter,
        &prepared.fetched.archive_path,
        pkg,
        &dir.join("registry"),
    )
    .map_err(artifact)?;
    let rebuild_root = clearhash_sandbox::extract_archive(
        adapter,
        &rebuilt.artifact_path,
        pkg,
        &dir.join("rebuild"),
    )
    .map_err(artifact)?;
    Ok(ArmResult {
        t1: clearhash_sandbox::compare_trees(adapter, &registry_root, &rebuild_root)
            .map_err(artifact)?
            .into(),
        t0: clearhash_sandbox::compare_trees_strict(&registry_root, &rebuild_root)
            .map_err(artifact)?
            .into(),
        lock_source,
    })
}

/// Parse the committed lock (lock stage), then fetch and hash-check its archives.
async fn offline(
    adapter: &dyn EcosystemAdapter,
    source_dir: &Path,
    dir: &Path,
) -> Result<Option<PathBuf>, Failure> {
    adapter
        .offline_dependencies(source_dir)
        .map_err(|e| Failure::new(Stage::Lock, e))?;
    clearhash_sandbox::prepare_offline(adapter, source_dir, dir)
        .await
        .map_err(|e| sandbox(Stage::Dependencies, e))
}

/// Arm I: write a hash-pinned lock as of the publish time, with the network on.
async fn resolve(
    adapter: &dyn EcosystemAdapter,
    ecosystem: Ecosystem,
    source_dir: &Path,
    release: &Release,
) -> Result<(), Failure> {
    let script = match ecosystem {
        Ecosystem::Npm => include_str!("resolve-npm.sh"),
        Ecosystem::Pypi => include_str!("resolve-pypi.sh"),
        Ecosystem::Cargo => return Err(Failure::new(Stage::Lock, "no Cargo resolver")),
    };
    let options = RebuildOptions {
        env: vec![format!("CLEARHASH_RESOLVE_BEFORE={}", release.published_at)],
        timeout: Some(TIME_LIMIT),
        memory_bytes: Some(MEMORY_BYTES),
        ..Default::default()
    };
    clearhash_sandbox::run_job(ContainerJob {
        image: adapter.rebuild_image(),
        platform: adapter.rebuild_platform(),
        script: script.into(),
        source_dir,
        options: &options,
        collect: None,
    })
    .await
    .map_err(|e| {
        let failure = sandbox(Stage::Lock, e);
        Failure::new(failure.stage, format!("resolver: {}", failure.error))
    })
}

/// Rebuild containers run as root and leave root-owned files in the bind-mounted
/// source tree. Hand them back to the work directory's owner, then delete the tree.
async fn release_workdir(image: &str, dir: &Path) {
    hand_back_source(image, dir).await;
    if let Err(error) = std::fs::remove_dir_all(dir) {
        tracing::warn!(dir = %dir.display(), "work directory not removed: {error}");
    }
}

#[cfg(unix)]
async fn hand_back_source(image: &str, dir: &Path) {
    use std::os::unix::fs::MetadataExt;
    let source_dir = dir.join("source");
    let Ok(metadata) = std::fs::metadata(dir) else {
        return;
    };
    if !source_dir.exists() {
        return;
    }
    let options = RebuildOptions {
        timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    };
    let _ = clearhash_sandbox::run_job(ContainerJob {
        image,
        platform: None,
        script: format!("chown -R {}:{} /src", metadata.uid(), metadata.gid()),
        source_dir: &source_dir,
        options: &options,
        collect: None,
    })
    .await;
}

/// Docker Desktop on other hosts does not leave root-owned files behind.
#[cfg(not(unix))]
async fn hand_back_source(_image: &str, _dir: &Path) {}

#[derive(Serialize)]
struct Screened<'a> {
    #[serde(flatten)]
    release: &'a Release,
    decision: &'static str,
}

/// Keep candidates, in order, whose release has exactly one sdist with PEP 740 provenance.
async fn screen_pypi(
    candidates: &Path,
    sample: &Path,
    screened: &Path,
    target: usize,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("clearhash-study/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .build()?;
    let mut kept = Vec::new();
    let mut log = Vec::new();
    for release in read_jsonl::<Release>(candidates)? {
        if kept.len() == target {
            break;
        }
        let decision = screen_one(&client, &release).await?;
        log.push(serde_json::to_string(&Screened {
            release: &release,
            decision,
        })?);
        if decision == "kept" {
            kept.push(serde_json::to_string(&release)?);
        }
    }
    if kept.len() < target {
        bail!(
            "only {} of {target} candidates kept; extend the candidate list",
            kept.len()
        );
    }
    std::fs::write(sample, kept.join("\n") + "\n")?;
    std::fs::write(screened, log.join("\n") + "\n")?;
    Ok(())
}

async fn screen_one(client: &reqwest::Client, release: &Release) -> Result<&'static str> {
    #[derive(Deserialize)]
    struct Metadata {
        urls: Vec<File>,
    }
    #[derive(Deserialize)]
    struct File {
        filename: String,
        packagetype: String,
    }
    let url = format!(
        "https://pypi.org/pypi/{}/{}/json",
        release.name, release.version
    );
    let response = client.get(&url).send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok("release_missing");
    }
    let metadata: Metadata = response.error_for_status()?.json().await?;
    let sdists: Vec<&File> = metadata
        .urls
        .iter()
        .filter(|f| f.packagetype == "sdist")
        .collect();
    let sdist = match sdists.as_slice() {
        [] => return Ok("no_sdist"),
        [one] => one,
        _ => return Ok("multiple_sdists"),
    };
    let provenance = format!(
        "https://pypi.org/integrity/{}/{}/{}/provenance",
        release.name, release.version, sdist.filename
    );
    let response = client
        .get(&provenance)
        .header("Accept", "application/vnd.pypi.integrity.v1+json")
        .send()
        .await?;
    match response.status() {
        reqwest::StatusCode::OK => Ok("kept"),
        reqwest::StatusCode::NOT_FOUND => Ok("sdist_without_provenance"),
        status => bail!("{provenance} returned {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructed fixture row in the sample format the frame export writes.
    fn fixture_release(system: &str, name: &str) -> Release {
        serde_json::from_value(serde_json::json!({
            "system": system, "name": name, "version": "1.0.0",
            "published_at": "2026-10-01T00:00:00Z"
        }))
        .unwrap()
    }

    #[test]
    fn sample_rows_map_to_package_references_and_safe_slugs() {
        let npm = fixture_release("NPM", "@scope/pkg");
        assert_eq!(npm.package().unwrap().to_string(), "npm:@scope/pkg@1.0.0");
        assert_eq!(npm.slug(), "NPM-_scope_pkg-1.0.0");
        let pypi = fixture_release("PYPI", "pkg");
        assert_eq!(pypi.package().unwrap().ecosystem, Ecosystem::Pypi);
        assert!(fixture_release("CARGO", "x").package().is_err());
    }

    #[test]
    fn infrastructure_errors_are_separated_from_package_failures() {
        let io = SandboxError::Io(std::io::Error::other("disk"));
        assert_eq!(sandbox(Stage::Build, io).stage, Stage::Infrastructure);
        let timeout = sandbox(Stage::Build, SandboxError::Timeout(TIME_LIMIT));
        assert_eq!(timeout.stage, Stage::Build);
        assert!(timeout.error.starts_with("timeout:"));
        let failed = sandbox(
            Stage::Build,
            SandboxError::RebuildFailed(1, "x".repeat(10_000)),
        );
        assert_eq!(failed.stage, Stage::Build);
        assert_eq!(failed.error.len(), MAX_ERROR_CHARS);
    }

    #[test]
    fn ledger_lines_round_trip_for_resume() {
        let release = fixture_release("NPM", "pkg");
        let record = base_record(&release, Arm::I, "abc", "now".into(), 1.5);
        let line = serde_json::to_string(&record).unwrap();
        assert!(line.contains(r#""arm":"i""#) && line.contains(r#""stage":"infrastructure""#));
        let back: Record = serde_json::from_str(&line).unwrap();
        assert_eq!(back.arm, Arm::I);
    }
}
