//! `clearhash` CLI entry point. Drives the verify pipeline end-to-end.

use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use clearhash_core::{hex_digest, PackageRef};
use clearhash_ecosystems::for_ecosystem;
use clearhash_sandbox::simulate_tamper::TamperMode;
use console::{style, Term};

#[derive(Parser)]
#[command(
    name = "clearhash",
    version,
    about = "Rebuild-and-compare verifier for package artifacts.",
    long_about = "ClearHash fetches a package, verifies its SLSA attestation via Sigstore,\n\
                  rebuilds the source in an isolated Docker container, and compares the rebuilt\n\
                  tree against the registry artifact. Mismatches block installation."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    /// Enable verbose tracing output.
    #[arg(long, short, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Full pipeline: fetch, verify attestation, rebuild, compare.
    Verify {
        /// Package reference in `<ecosystem>:<name>@<version>` form.
        package: String,

        /// Allow verification of packages with no SLSA attestation. Required for cargo.
        #[arg(long)]
        allow_unattested: bool,

        /// Keep the working directory (sandbox source tree, extracted archives) after exit.
        #[arg(long)]
        keep_workdir: bool,

        /// Output machine-readable JSON instead of human text.
        #[arg(long)]
        json: bool,

        /// Demo mode: deliberately tamper with the registry-extracted tree before comparison
        /// so the diff output is non-empty. The output is clearly marked as a simulation.
        /// Usage: `--simulate-tamper` (defaults to `all`) or `--simulate-tamper=content-swap`.
        #[arg(
            long,
            value_enum,
            num_args = 0..=1,
            default_missing_value = "all",
            require_equals = true
        )]
        simulate_tamper: Option<TamperModeArg>,
    },

    /// Fetch a package and report the SHA-256 + attestation summary without rebuilding.
    Inspect {
        package: String,

        /// Output machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Clap-friendly mirror of `clearhash_sandbox::simulate_tamper::TamperMode`.
/// Kept separate so the CLI owns its kebab-case spellings.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum TamperModeArg {
    InjectedPayload,
    ContentSwap,
    ModeFlip,
    Deletion,
    All,
}

impl From<TamperModeArg> for TamperMode {
    fn from(a: TamperModeArg) -> Self {
        match a {
            TamperModeArg::InjectedPayload => TamperMode::InjectedPayload,
            TamperModeArg::ContentSwap => TamperMode::ContentSwap,
            TamperModeArg::ModeFlip => TamperMode::ModeFlip,
            TamperModeArg::Deletion => TamperMode::Deletion,
            TamperModeArg::All => TamperMode::All,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let filter = if cli.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .compact()
        .init();

    let exit = match cli.command {
        Cmd::Inspect { package, json } => run_inspect(&package, json).await,
        Cmd::Verify {
            package,
            allow_unattested,
            keep_workdir,
            json,
            simulate_tamper,
        } => {
            run_verify(
                &package,
                allow_unattested,
                keep_workdir,
                json,
                simulate_tamper.map(TamperMode::from),
            )
            .await
        }
    };

    match exit {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("{} {:#}", style("error:").red().bold(), e);
            ExitCode::from(3)
        }
    }
}

async fn run_inspect(package: &str, json: bool) -> Result<i32> {
    let pkg = PackageRef::from_str(package).context("parsing package reference")?;
    let adapter = for_ecosystem(pkg.ecosystem);

    let term = Term::stderr();
    let _ = term.write_line(&format!(
        "{} {}",
        style("[1/2]").cyan(),
        style(format!("Fetching {pkg} from {}", pkg.ecosystem)).dim()
    ));
    let fetched = clearhash_registry::fetch(&*adapter, &pkg)
        .await
        .context("fetching artifact")?;
    let _ = term.write_line(&format!(
        "      sha256: {}",
        hex_digest(&fetched.registry_sha256)
    ));

    let _ = term.write_line(&format!(
        "{} {}",
        style("[2/2]").cyan(),
        style("Parsing attestation envelope").dim()
    ));

    let verified_opt = match &fetched.attestation_bundle {
        Some(bytes) => Some(
            clearhash_provenance::verify(&*adapter, bytes)
                .await
                .context("verifying attestation")?,
        ),
        None => None,
    };

    if json {
        let out = serde_json::json!({
            "package": pkg.to_string(),
            "registry_sha256": hex_digest(&fetched.registry_sha256),
            "attestation": verified_opt.as_ref().map(|v| serde_json::json!({
                "source_repo": v.claim.source_repo,
                "commit_sha": v.claim.commit_sha,
                "builder_id": v.claim.builder_id,
                "issuer_dn": v.identity.issuer_dn,
                "workflow_uri": v.identity.workflow_uri,
                "rekor_log_index": v.identity.rekor_log_index,
            })),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!();
        println!("{}", style(format!("Package      {}", pkg)).bold());
        println!("Registry SHA  {}", hex_digest(&fetched.registry_sha256));
        match verified_opt {
            Some(v) => {
                println!("{}", style("Attestation").bold());
                println!("  Source       {}", v.claim.source_repo);
                println!("  Commit       {}", v.claim.commit_sha);
                println!("  Builder      {}", v.claim.builder_id);
                println!("  Cert issuer  {}", v.identity.issuer_dn);
                if let Some(wf) = v.identity.workflow_uri {
                    println!("  Workflow     {}", wf);
                }
                if let Some(li) = v.identity.rekor_log_index {
                    println!("  Rekor index  {}", li);
                }
            }
            None => println!(
                "{} {}",
                style("Attestation").bold(),
                style("not published").yellow()
            ),
        }
    }

    Ok(0)
}

async fn run_verify(
    package: &str,
    allow_unattested: bool,
    keep_workdir: bool,
    json: bool,
    simulate_tamper: Option<TamperMode>,
) -> Result<i32> {
    let pkg = PackageRef::from_str(package).context("parsing package reference")?;
    let adapter = for_ecosystem(pkg.ecosystem);
    let term = Term::stderr();

    if let Some(mode) = simulate_tamper {
        let _ = term.write_line(&format!(
            "{} {} The registry-extracted tree will be modified before comparison ({:?} mode). \
             The MISMATCH below is real but the registry tarball is clean.",
            style("⚠ TAMPER SIMULATION").yellow().bold(),
            style("·").dim(),
            mode
        ));
    }

    // --- [1/5] Fetch ---
    let _ = term.write_line(&format!(
        "{} Fetching {} from {}",
        style("[1/5]").cyan(),
        pkg.name,
        pkg.ecosystem
    ));
    let fetched = clearhash_registry::fetch(&*adapter, &pkg)
        .await
        .context("fetching artifact")?;
    let _ = term.write_line(&format!(
        "      sha256: {}",
        hex_digest(&fetched.registry_sha256)
    ));

    // --- [2/5] Verify attestation ---
    let claim = match (&fetched.attestation_bundle, allow_unattested) {
        (Some(bytes), _) => {
            let _ = term.write_line(&format!(
                "{} Verifying Sigstore attestation",
                style("[2/5]").cyan()
            ));
            let v = clearhash_provenance::verify(&*adapter, bytes)
                .await
                .context("verifying attestation")?;
            let _ = term.write_line(&format!(
                "      commit: {}  (workflow: {})",
                &v.claim.commit_sha[..12.min(v.claim.commit_sha.len())],
                v.identity.workflow_uri.as_deref().unwrap_or("?")
            ));
            v.claim
        }
        (None, true) => {
            let _ = term.write_line(&format!(
                "{} {} No SLSA attestation; proceeding under --allow-unattested",
                style("[2/5]").cyan(),
                style("warn:").yellow()
            ));
            return Ok(2);
        }
        (None, false) => {
            let _ = term.write_line(&format!(
                "{} No SLSA attestation published for {pkg}. \
                 Pass --allow-unattested to verify the registry artifact's SHA alone.",
                style("error:").red()
            ));
            return Ok(2);
        }
    };

    // --- [3/5] Spin up rebuild container ---
    let workdir = tempfile::Builder::new()
        .prefix("clearhash-rebuild-")
        .tempdir()?;
    let workdir_path = workdir.path().to_path_buf();
    let _ = term.write_line(&format!(
        "{} Spinning up rebuild container ({})",
        style("[3/5]").cyan(),
        adapter.rebuild_image()
    ));
    if !clearhash_sandbox::docker_reachable().await {
        let _ = term.write_line(&format!(
            "{} Docker daemon unreachable. Start Docker Desktop / OrbStack and try again.",
            style("error:").red()
        ));
        return Ok(3);
    }

    // --- [4/5] Rebuild ---
    let _ = term.write_line(&format!(
        "{} Rebuilding from source at commit {}",
        style("[4/5]").cyan(),
        &claim.commit_sha[..12.min(claim.commit_sha.len())]
    ));
    let rebuild = clearhash_sandbox::rebuild(&*adapter, &claim, &pkg, &workdir_path)
        .await
        .context("rebuilding from source")?;
    let _ = term.write_line(&format!("      built: {}", rebuild.artifact_path.display()));

    // --- [5/5] Compare ---
    let _ = term.write_line(&format!("{} Comparing file trees", style("[5/5]").cyan()));
    let reg_root = clearhash_sandbox::extract_archive(
        &*adapter,
        &fetched.archive_path,
        &pkg,
        &workdir_path.join("registry"),
    )
    .context("extracting registry artifact")?;
    let rb_root = clearhash_sandbox::extract_archive(
        &*adapter,
        &rebuild.artifact_path,
        &pkg,
        &workdir_path.join("rebuild"),
    )
    .context("extracting rebuilt artifact")?;

    // Demo-only: apply real modifications to the registry tree so the diff is non-empty.
    if let Some(mode) = simulate_tamper {
        let applied = clearhash_sandbox::simulate_tamper::apply(&reg_root, mode)
            .context("simulating tamper")?;
        for t in &applied {
            let _ = term.write_line(&format!(
                "      {} tampered {}: {} ({})",
                style("·").yellow(),
                format!("{:?}", t.mode).to_lowercase(),
                style(&t.path).cyan(),
                t.detail
            ));
        }
    }

    let outcome = clearhash_sandbox::compare_trees(&*adapter, &reg_root, &rb_root)
        .context("comparing trees")?;

    if keep_workdir {
        let kept = workdir.keep();
        let _ = term.write_line(&format!("      workdir kept at: {}", kept.display()));
    }

    print_outcome(&pkg, &claim, &outcome, json)?;
    Ok(outcome.exit_code())
}

fn print_outcome(
    pkg: &PackageRef,
    claim: &clearhash_core::ProvenanceClaim,
    outcome: &clearhash_core::VerifyOutcome,
    json: bool,
) -> Result<()> {
    use clearhash_core::VerifyOutcome;
    if json {
        let v = serde_json::json!({
            "package": pkg.to_string(),
            "commit": claim.commit_sha,
            "result": match outcome {
                VerifyOutcome::Match { .. } => "match",
                VerifyOutcome::TreeMismatch { .. } => "mismatch",
                _ => "other",
            },
            "differences": match outcome {
                VerifyOutcome::TreeMismatch { differences } => {
                    serde_json::json!(differences.iter().map(|d| format!("{:?}", d)).collect::<Vec<_>>())
                }
                _ => serde_json::json!([]),
            }
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    match outcome {
        VerifyOutcome::Match { tree_hash } => {
            println!();
            println!(
                "{} {} tree-hash {}",
                style("✓ MATCH").green().bold(),
                pkg,
                tree_hash.to_hex()
            );
        }
        VerifyOutcome::TreeMismatch { differences } => {
            println!();
            println!(
                "{} {} — {} difference(s)",
                style("✗ MISMATCH").red().bold(),
                pkg,
                differences.len()
            );
            for d in differences.iter().take(20) {
                println!("    {:?}", d);
            }
            if differences.len() > 20 {
                println!("    … and {} more", differences.len() - 20);
            }
        }
        other => println!("{:?}", other),
    }
    Ok(())
}
