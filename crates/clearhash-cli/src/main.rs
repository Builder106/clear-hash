//! `clearhash` CLI entry point. Drives the verify pipeline end-to-end.

use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use clearhash_core::{hex_digest, Ecosystem, PackageRef};
use clearhash_ecosystems::for_ecosystem;
use clearhash_ecosystems::npm::{NpmAdapter, NpmPlatform};
use clearhash_ecosystems::EcosystemAdapter;
use clearhash_sandbox::simulate_tamper::TamperMode;
use clearhash_sandbox::RebuildSource;
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

        /// Allow verification without a SLSA attestation using a manually pinned Cargo source.
        #[arg(long)]
        allow_unattested: bool,

        /// Git repository to rebuild for an unattested Cargo crate.
        #[arg(long, value_name = "GIT_URL", requires_all = ["commit", "allow_unattested"])]
        source: Option<String>,

        /// Full 40-character Git commit SHA for --source.
        #[arg(long, value_name = "SHA", requires = "source", value_parser = parse_commit)]
        commit: Option<String>,

        /// Native npm rebuild target: linux/amd64 or linux/arm64 (glibc).
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<NpmPlatform>,

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
            source,
            commit,
            platform,
            keep_workdir,
            json,
            simulate_tamper,
        } => {
            async {
                let manual_source = manual_source(&package, source, commit)?;
                run_verify(
                    &package,
                    allow_unattested,
                    manual_source,
                    keep_workdir,
                    json,
                    simulate_tamper.map(TamperMode::from),
                    platform,
                )
                .await
            }
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

fn parse_commit(value: &str) -> std::result::Result<String, String> {
    if value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("expected a full 40-character hexadecimal Git commit SHA".into())
    }
}

fn manual_source(
    package: &str,
    source: Option<String>,
    commit: Option<String>,
) -> Result<Option<RebuildSource>> {
    match (source, commit) {
        (None, None) => Ok(None),
        (Some(source_repo), Some(commit_sha)) => {
            let pkg: PackageRef = package.parse().context("parsing package reference")?;
            anyhow::ensure!(
                pkg.ecosystem == Ecosystem::Cargo,
                "--source and --commit are supported only for Cargo"
            );
            anyhow::ensure!(
                !source_repo.trim().is_empty() && !source_repo.starts_with('-'),
                "--source must name a Git repository"
            );
            let commit_sha = parse_commit(&commit_sha).map_err(anyhow::Error::msg)?;
            Ok(Some(RebuildSource {
                source_repo,
                commit_sha,
            }))
        }
        _ => anyhow::bail!("--source and --commit must be supplied together"),
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

fn verification_adapter(
    pkg: &PackageRef,
    platform: Option<NpmPlatform>,
) -> Result<Box<dyn EcosystemAdapter>> {
    match platform {
        Some(platform) => {
            anyhow::ensure!(
                pkg.ecosystem == Ecosystem::Npm,
                "--platform is supported only for npm"
            );
            Ok(Box::new(NpmAdapter::for_platform(platform)))
        }
        None => Ok(for_ecosystem(pkg.ecosystem)),
    }
}

async fn run_verify(
    package: &str,
    allow_unattested: bool,
    manual_source: Option<RebuildSource>,
    keep_workdir: bool,
    json: bool,
    simulate_tamper: Option<TamperMode>,
    platform: Option<NpmPlatform>,
) -> Result<i32> {
    let pkg = PackageRef::from_str(package).context("parsing package reference")?;
    let adapter = verification_adapter(&pkg, platform)?;
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
    let manually_pinned = fetched.attestation_bundle.is_none() && manual_source.is_some();
    let source = match (&fetched.attestation_bundle, allow_unattested, manual_source) {
        (Some(bytes), _, manual_source) => {
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
            anyhow::ensure!(
                manual_source.is_none(),
                "manual source cannot override an attestation"
            );
            RebuildSource::from(&v.claim)
        }
        (None, true, Some(source)) => {
            let _ = term.write_line(&format!(
                "{} {} No SLSA attestation; comparing against manually pinned source",
                style("[2/5]").cyan(),
                style("warn:").yellow()
            ));
            source
        }
        (None, _, _) => {
            let _ = term.write_line(&format!(
                "{} No SLSA attestation published for {pkg}. \
                 For Cargo, pass --allow-unattested --source <git-url> --commit <sha> to rebuild and compare.",
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
        &source.commit_sha[..12.min(source.commit_sha.len())]
    ));
    let rebuild = clearhash_sandbox::rebuild(&*adapter, &source, &pkg, &workdir_path)
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

    print_outcome(&pkg, &source, manually_pinned, &outcome, json, platform)?;
    Ok(outcome.exit_code())
}

fn print_outcome(
    pkg: &PackageRef,
    source: &RebuildSource,
    manually_pinned: bool,
    outcome: &clearhash_core::VerifyOutcome,
    json: bool,
    platform: Option<NpmPlatform>,
) -> Result<()> {
    use clearhash_core::VerifyOutcome;
    if json {
        let v = serde_json::json!({
            "package": pkg.to_string(),
            "commit": source.commit_sha,
            "source_repo": source.source_repo,
            "platform": platform.map(NpmPlatform::as_str),
            "source_verification": if manually_pinned { "manual" } else { "attested" },
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
    if let Some(platform) = platform {
        println!("Platform      {} (glibc)", platform.as_str());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn verify_parses_with_defaults() {
        let cli = parse(&["clearhash", "verify", "npm:left-pad@1.0.0"]).unwrap();
        assert!(!cli.verbose);
        match cli.command {
            Cmd::Verify {
                package,
                allow_unattested,
                keep_workdir,
                json,
                simulate_tamper,
                source,
                commit,
                platform,
            } => {
                assert_eq!(package, "npm:left-pad@1.0.0");
                assert!(!allow_unattested);
                assert!(!keep_workdir);
                assert!(!json);
                assert!(simulate_tamper.is_none());
                assert!(source.is_none() && commit.is_none());
                assert!(platform.is_none());
            }
            _ => panic!("expected Verify"),
        }
    }

    #[test]
    fn verify_flags_parse() {
        let cli = parse(&[
            "clearhash",
            "verify",
            "cargo:serde@1.0.0",
            "--allow-unattested",
            "--keep-workdir",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Cmd::Verify {
                allow_unattested,
                keep_workdir,
                json,
                ..
            } => {
                assert!(allow_unattested && keep_workdir && json);
            }
            _ => panic!("expected Verify"),
        }
    }

    const PIN: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn cargo_manual_pin_requires_both_flags_and_unattested_consent() {
        for flags in [
            vec!["--source", "https://example.com/repo.git"],
            vec!["--commit", PIN],
            vec!["--source", "https://example.com/repo.git", "--commit", PIN],
            vec![
                "--allow-unattested",
                "--source",
                "https://example.com/repo.git",
            ],
            vec!["--allow-unattested", "--commit", PIN],
        ] {
            let mut args = vec!["clearhash", "verify", "cargo:example@1.0.0"];
            args.extend(flags);
            assert!(parse(&args).is_err());
        }
        let cli = parse(&[
            "clearhash",
            "verify",
            "cargo:example@1.0.0",
            "--allow-unattested",
            "--source",
            "git@example.com:owner/repo.git",
            "--commit",
            PIN,
        ])
        .unwrap();
        let Cmd::Verify { source, commit, .. } = cli.command else {
            panic!("expected Verify")
        };
        let pin = manual_source("cargo:example@1.0.0", source, commit)
            .unwrap()
            .unwrap();
        assert_eq!(pin.source_repo, "git@example.com:owner/repo.git");
        assert_eq!(pin.commit_sha, PIN);
    }

    #[test]
    fn manual_pin_rejects_non_cargo_packages_and_invalid_repositories() {
        for package in ["npm:x@1.0.0", "pypi:x@1.0.0"] {
            assert!(manual_source(
                package,
                Some("https://example.com/repo".into()),
                Some(PIN.into())
            )
            .is_err());
        }
        for repo in ["", "  ", "--upload-pack=anything"] {
            assert!(manual_source("cargo:x@1.0.0", Some(repo.into()), Some(PIN.into())).is_err());
        }
    }

    #[test]
    fn commit_must_be_a_full_hex_sha() {
        for commit in [
            "main",
            "v1.0.0",
            "0123456",
            "--help",
            "gggggggggggggggggggggggggggggggggggggggg",
            "0123456789abcdef0123456789abcdef012345678",
        ] {
            assert!(parse_commit(commit).is_err());
            assert!(parse(&[
                "clearhash",
                "verify",
                "cargo:x@1.0.0",
                "--allow-unattested",
                "--source",
                "https://example.com/repo",
                "--commit",
                commit,
            ])
            .is_err());
        }
        assert_eq!(parse_commit(&PIN.to_ascii_uppercase()).unwrap(), PIN);
    }

    #[test]
    fn native_platform_requires_a_supported_npm_target() {
        for value in ["linux/amd64", "linux/arm64"] {
            let cli = parse(&[
                "clearhash",
                "verify",
                "npm:@example/addon-linux-arm64@1.0.0",
                "--platform",
                value,
            ])
            .unwrap();
            let Cmd::Verify {
                platform, package, ..
            } = cli.command
            else {
                panic!("expected Verify")
            };
            let adapter = verification_adapter(&package.parse().unwrap(), platform).unwrap();
            assert_eq!(adapter.rebuild_platform(), Some(value));
        }
        for value in [
            "darwin/arm64",
            "windows/amd64",
            "linux/x64",
            "linux/arm64/musl",
            "linux",
            "",
        ] {
            assert!(parse(&["clearhash", "verify", "npm:x@1.0.0", "--platform", value]).is_err());
        }
        for pkg in ["cargo:x@1.0.0", "pypi:x@1.0.0"] {
            assert!(
                verification_adapter(&pkg.parse().unwrap(), Some(NpmPlatform::LinuxAmd64)).is_err()
            );
        }
        assert!(parse(&[
            "clearhash",
            "inspect",
            "npm:x@1.0.0",
            "--platform",
            "linux/arm64"
        ])
        .is_err());
    }

    #[test]
    fn simulate_tamper_bare_defaults_to_all() {
        // `default_missing_value = "all"` — the bare flag means "tamper everything".
        let cli = parse(&["clearhash", "verify", "npm:x@1.0.0", "--simulate-tamper"]).unwrap();
        match cli.command {
            Cmd::Verify {
                simulate_tamper, ..
            } => {
                assert!(matches!(simulate_tamper, Some(TamperModeArg::All)));
            }
            _ => panic!("expected Verify"),
        }
    }

    #[test]
    fn simulate_tamper_takes_an_explicit_kebab_value() {
        let cli = parse(&[
            "clearhash",
            "verify",
            "npm:x@1.0.0",
            "--simulate-tamper=content-swap",
        ])
        .unwrap();
        match cli.command {
            Cmd::Verify {
                simulate_tamper, ..
            } => {
                assert!(matches!(simulate_tamper, Some(TamperModeArg::ContentSwap)));
            }
            _ => panic!("expected Verify"),
        }
    }

    #[test]
    fn simulate_tamper_requires_equals_for_its_value() {
        // `require_equals = true`: the space form must NOT consume the next token as
        // the tamper mode (it would otherwise swallow a positional). Bare flag is fine.
        let cli = parse(&["clearhash", "verify", "npm:x@1.0.0", "--simulate-tamper"]).unwrap();
        assert!(matches!(
            cli.command,
            Cmd::Verify {
                simulate_tamper: Some(TamperModeArg::All),
                ..
            }
        ));
    }

    #[test]
    fn rejects_unknown_tamper_mode() {
        assert!(parse(&[
            "clearhash",
            "verify",
            "npm:x@1.0.0",
            "--simulate-tamper=nonsense"
        ])
        .is_err());
    }

    #[test]
    fn verify_requires_a_package_argument() {
        assert!(parse(&["clearhash", "verify"]).is_err());
    }

    #[test]
    fn inspect_parses_with_json_and_global_verbose() {
        let cli = parse(&[
            "clearhash",
            "--verbose",
            "inspect",
            "npm:left-pad@1.0.0",
            "--json",
        ])
        .unwrap();
        assert!(cli.verbose);
        match cli.command {
            Cmd::Inspect { package, json } => {
                assert_eq!(package, "npm:left-pad@1.0.0");
                assert!(json);
            }
            _ => panic!("expected Inspect"),
        }
    }

    #[test]
    fn tamper_mode_arg_maps_onto_every_core_mode() {
        assert!(matches!(
            TamperMode::from(TamperModeArg::InjectedPayload),
            TamperMode::InjectedPayload
        ));
        assert!(matches!(
            TamperMode::from(TamperModeArg::ContentSwap),
            TamperMode::ContentSwap
        ));
        assert!(matches!(
            TamperMode::from(TamperModeArg::ModeFlip),
            TamperMode::ModeFlip
        ));
        assert!(matches!(
            TamperMode::from(TamperModeArg::Deletion),
            TamperMode::Deletion
        ));
        assert!(matches!(
            TamperMode::from(TamperModeArg::All),
            TamperMode::All
        ));
    }

    #[test]
    fn cli_definition_is_valid() {
        // Catches clap configuration errors (conflicting args, bad value parsers)
        // at test time instead of first run.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
