//! Server-rendered HTML. maud DSL — no template files, no build pipeline.

use maud::{html, Markup, PreEscaped, DOCTYPE};

use super::{InspectError, InspectResult};

/// Inline CSS shared across pages. Kept here so the binary has no external asset deps
/// beyond `/assets/` static files (banner + demo GIFs).
const STYLES: &str = r#"
:root {
    color-scheme: light dark;
    --bg: #0a0e1a;
    --bg-elev: #11182e;
    --fg: #f8fafc;
    --fg-dim: #94a3b8;
    --accent: #a78bfa;
    --accent-2: #7dd3fc;
    --ok: #22c55e;
    --warn: #f59e0b;
    --bad: #f472b6;
    --border: #1e293b;
}
@media (prefers-color-scheme: light) {
    :root {
        --bg: #ffffff;
        --bg-elev: #f8fafc;
        --fg: #0f172a;
        --fg-dim: #475569;
        --accent: #7c3aed;
        --accent-2: #0284c7;
        --ok: #16a34a;
        --warn: #d97706;
        --bad: #db2777;
        --border: #e2e8f0;
    }
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
    font-family: ui-sans-serif, -apple-system, "Helvetica Neue", system-ui, sans-serif;
    background: var(--bg);
    color: var(--fg);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 960px; margin: 0 auto; padding: 0 24px; }
header { padding: 32px 0 16px; border-bottom: 1px solid var(--border); }
header nav { display: flex; align-items: center; gap: 24px; }
header .brand { font-weight: 800; font-size: 20px; text-decoration: none; color: var(--fg); }
header .brand .hash { color: var(--accent); }
header a { color: var(--fg-dim); text-decoration: none; font-size: 14px; }
header a:hover { color: var(--fg); }
header .spacer { flex: 1; }
.hero { padding: 64px 0 32px; }
.hero .banner { width: 100%; max-width: 960px; border-radius: 12px; overflow: hidden; display: block; }
.hero h1 {
    margin: 32px 0 8px;
    font-size: clamp(32px, 5vw, 52px);
    line-height: 1.1;
    letter-spacing: -1.5px;
    font-weight: 800;
}
.hero h1 .accent { background: linear-gradient(90deg, var(--accent-2), var(--accent), var(--bad)); -webkit-background-clip: text; background-clip: text; color: transparent; }
.hero p.lede {
    font-size: 19px;
    color: var(--fg-dim);
    max-width: 720px;
    margin: 0 0 24px;
}
.cta { display: flex; gap: 12px; flex-wrap: wrap; }
.btn {
    display: inline-block; padding: 10px 18px; border-radius: 8px; text-decoration: none;
    font-size: 14px; font-weight: 600; transition: transform .08s ease;
    border: 1px solid var(--border);
}
.btn:hover { transform: translateY(-1px); }
.btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn.secondary { background: transparent; color: var(--fg); }
section { padding: 32px 0; border-top: 1px solid var(--border); }
section h2 { font-size: 24px; margin: 0 0 16px; letter-spacing: -0.5px; }
section p { color: var(--fg-dim); max-width: 720px; }
.grid {
    display: grid; gap: 20px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    margin-top: 24px;
}
.card {
    padding: 20px; background: var(--bg-elev); border: 1px solid var(--border);
    border-radius: 10px;
}
.card h3 { margin: 0 0 6px; font-size: 16px; }
.card p { font-size: 14px; margin: 0; color: var(--fg-dim); }
pre, code {
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 13px;
}
pre {
    background: var(--bg-elev); padding: 16px; border-radius: 8px;
    border: 1px solid var(--border); overflow-x: auto;
}
.inline-code { background: var(--bg-elev); padding: 2px 6px; border-radius: 4px; color: var(--accent-2); }
form.inspect {
    display: flex; gap: 8px; margin: 16px 0 24px; flex-wrap: wrap;
}
form.inspect input[type="text"] {
    flex: 1; min-width: 280px;
    background: var(--bg-elev); border: 1px solid var(--border); color: var(--fg);
    padding: 12px 14px; border-radius: 8px; font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 14px;
}
form.inspect input[type="text"]:focus { outline: 2px solid var(--accent); border-color: var(--accent); }
.example-pills { display: flex; gap: 6px; flex-wrap: wrap; margin: -10px 0 24px; font-size: 13px; }
.example-pills a {
    padding: 4px 10px; border-radius: 999px; background: var(--bg-elev); border: 1px solid var(--border);
    color: var(--fg-dim); text-decoration: none; font-family: ui-monospace, "SF Mono", Menlo, monospace;
}
.example-pills a:hover { color: var(--fg); border-color: var(--accent); }
.result table { width: 100%; border-collapse: collapse; }
.result th, .result td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 14px; }
.result th { color: var(--fg-dim); font-weight: 500; width: 160px; }
.result td { font-family: ui-monospace, "SF Mono", Menlo, monospace; word-break: break-all; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.badge.ok { background: rgba(34, 197, 94, 0.18); color: var(--ok); }
.badge.warn { background: rgba(245, 158, 11, 0.18); color: var(--warn); }
.badge.bad { background: rgba(244, 114, 182, 0.18); color: var(--bad); }
footer { padding: 48px 0 64px; color: var(--fg-dim); font-size: 13px; }
footer a { color: var(--fg-dim); }
"#;

fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                meta name="description" content="ClearHash — rebuild every package, compare every byte, block every tamper. A supply-chain integrity verifier.";
                meta property="og:title" content=(title);
                meta property="og:description" content="Rebuild every package. Compare every byte. Block every tamper.";
                meta property="og:image" content="/assets/banner-dark.png";
                link rel="icon" type="image/svg+xml" href="/assets/favicon.svg";
                link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32.png";
                link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16.png";
                link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png";
                style { (PreEscaped(STYLES)) }
            }
            body {
                header {
                    div.wrap {
                        nav {
                            a.brand href="/" { "Clear" span.hash { "#" } "Hash" }
                            div.spacer {}
                            a href="/inspect" { "Inspect" }
                            a href="https://github.com/Builder106/ClearHash" { "GitHub" }
                        }
                    }
                }
                (body)
                footer {
                    div.wrap {
                        "ClearHash — MIT-licensed. " a href="https://github.com/Builder106/ClearHash" { "Source on GitHub" } "."
                    }
                }
            }
        }
    }
}

pub async fn landing() -> Markup {
    layout(
        "ClearHash — supply-chain integrity verifier",
        html! {
            div.wrap {
                section.hero {
                    picture {
                        source media="(prefers-color-scheme: dark)" srcset="/assets/banner-dark.png";
                        source media="(prefers-color-scheme: light)" srcset="/assets/banner-light.png";
                        img.banner src="/assets/banner-dark.png" alt="ClearHash";
                    }
                    h1 { "Don't just check signatures. " span.accent { "Rebuild the source." } }
                    p.lede {
                        "ClearHash fetches a package, verifies its SLSA attestation through Sigstore + Rekor, "
                        "rebuilds it from the attested source commit in a Docker container, and compares the "
                        "rebuilt file tree against the registry artifact. If anything differs, the install is blocked."
                    }
                    div.cta {
                        a.btn.primary href="/inspect" { "Try it →" }
                        a.btn.secondary href="https://github.com/Builder106/ClearHash" { "GitHub" }
                    }
                }
                section {
                    h2 { "Live demo" }
                    p {
                        "A real verify run against "
                        code.inline-code { "npm:sigstore@2.3.1" }
                        " — full pipeline in ~36 seconds (shown at 4× playback)."
                    }
                    img src="/assets/demo-verify.gif" alt="verify demo" style="max-width:100%; border-radius:8px; border:1px solid var(--border); margin-top:16px;";
                }
                section {
                    h2 { "What it catches" }
                    p {
                        "The supply-chain attacks of the last five years (event-stream, ua-parser-js, the post-install crypto-wallet stealers, xz-utils) "
                        "all share one shape: the registry tarball diverges from the source repo. "
                        "Existing tools verify who signed the tarball or that the tarball matches itself across mirrors — but not whether the tarball is what the source code would produce. "
                        "ClearHash does the rebuild and the comparison."
                    }
                    div.grid {
                        div.card {
                            h3 { "Sigstore + Rekor" }
                            p { "Verifies the SLSA attestation envelope, extracts the Fulcio-issued leaf cert, "
                                "cross-checks the workflow URI against the attested source repo, and confirms a Rekor transparency-log entry." }
                        }
                        div.card {
                            h3 { "Real rebuild" }
                            p { "Clones the attested commit, pins HEAD, runs the ecosystem's build script "
                                "(npm ci + npm pack) in a Docker container — with --ignore-scripts to block lifecycle hooks." }
                        }
                        div.card {
                            h3 { "File-tree compare" }
                            p { "Normalizes both archives (strips mtimes, scrubs npm-injected metadata), "
                                "Merkle-hashes the file trees, and surfaces per-file diffs on mismatch." }
                        }
                    }
                }
                section {
                    h2 { "Install the CLI" }
                    pre {
"git clone https://github.com/Builder106/ClearHash.git
cd ClearHash
cargo install --path crates/clearhash-cli

clearhash verify npm:sigstore@2.3.1"
                    }
                    p {
                        "The full verify pipeline needs a running Docker daemon (Docker Desktop or OrbStack on macOS). "
                        "The "
                        a href="/inspect" { code.inline-code { "/inspect" } }
                        " endpoint on this site runs the fetch + attestation parse parts without Docker."
                    }
                }
                section {
                    h2 { "API" }
                    p {
                        "Programmatic access to the inspect endpoint:"
                    }
                    pre {
"$ curl 'https://clear-hash.vercel.app/api/inspect?package=npm:sigstore@2.3.1'
{
  \"package\": \"npm:sigstore@2.3.1\",
  \"registry_sha256\": \"1b5041a35f86125db7f872742502470753fd2e1109521b7dbff8a61d229a03c2\",
  \"attestation\": {
    \"source_repo\": \"git+https://github.com/sigstore/sigstore-js@refs/heads/main\",
    \"commit_sha\": \"46e7056ff9912ebfee5298d94024895a9fea76c0\",
    \"builder_id\": \"https://github.com/actions/runner/github-hosted\",
    \"issuer_dn\": \"O=sigstore.dev, CN=sigstore-intermediate\",
    \"workflow_uri\": \"https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main\",
    \"rekor_log_index\": 94408136
  }
}"
                    }
                    p {
                        "Rate-limited to 30 requests/minute globally. For higher throughput, run the CLI locally."
                    }
                }
            }
        },
    )
}

pub fn inspect_empty() -> Markup {
    layout(
        "ClearHash · inspect",
        html! {
            div.wrap {
                section {
                    h2 { "Inspect a package" }
                    p { "Fetches the artifact, parses its SLSA attestation, validates the certificate chain. No rebuild." }
                    (inspect_form(""))
                }
            }
        },
    )
}

pub fn inspect_result(package: &str, result: &InspectResult) -> Markup {
    let attestation_badge = match &result.attestation {
        Some(_) => html! { span.badge.ok { "attested" } },
        None => html! { span.badge.warn { "no attestation" } },
    };
    layout(
        &format!("ClearHash · {}", package),
        html! {
            div.wrap {
                section {
                    h2 { "Inspect a package" }
                    (inspect_form(package))
                    div.result {
                        table {
                            tr { th { "Package" } td { (result.package) " " (attestation_badge) } }
                            tr { th { "Registry SHA-256" } td { (result.registry_sha256) } }
                            @if let Some(a) = &result.attestation {
                                tr { th { "Source repo" } td { (a.source_repo) } }
                                tr { th { "Commit" } td { (a.commit_sha) } }
                                tr { th { "Builder" } td { (a.builder_id) } }
                                tr { th { "Cert issuer" } td { (a.issuer_dn) } }
                                @if let Some(w) = &a.workflow_uri {
                                    tr { th { "Workflow" } td { (w) } }
                                }
                                @if let Some(li) = a.rekor_log_index {
                                    tr { th { "Rekor index" } td { (li) } }
                                }
                            } @else {
                                tr {
                                    th { "Note" }
                                    td {
                                        "This package has no SLSA attestation. "
                                        "The CLI's "
                                        code.inline-code { "verify" }
                                        " refuses to rebuild it without "
                                        code.inline-code { "--allow-unattested" }
                                        "."
                                    }
                                }
                            }
                        }
                    }
                    p { "JSON: " code.inline-code { "GET /api/inspect?package=" (package) } }
                }
            }
        },
    )
}

pub fn inspect_error(package: &str, err: &InspectError) -> Markup {
    layout(
        "ClearHash · error",
        html! {
            div.wrap {
                section {
                    h2 { "Inspect a package" }
                    (inspect_form(package))
                    div.result {
                        table {
                            tr { th { "Package" } td { (package) " " span.badge.bad { "error " (err.status) } } }
                            tr { th { "Error" } td { (err.message) } }
                        }
                    }
                }
            }
        },
    )
}

fn inspect_form(prefill: &str) -> Markup {
    html! {
        form.inspect method="get" action="/inspect" {
            input
                type="text"
                name="package"
                placeholder="npm:sigstore@2.3.1"
                value=(prefill)
                autocomplete="off"
                autofocus?[prefill.is_empty()] ;
            button.btn.primary type="submit" { "Inspect" }
        }
        div.example-pills {
            a href="/inspect?package=npm:sigstore@2.3.1" { "npm:sigstore@2.3.1" }
            a href="/inspect?package=npm:@sigstore/sign@2.3.2" { "npm:@sigstore/sign@2.3.2" }
            a href="/inspect?package=npm:left-pad@1.3.0" { "npm:left-pad@1.3.0 (unattested)" }
        }
    }
}
