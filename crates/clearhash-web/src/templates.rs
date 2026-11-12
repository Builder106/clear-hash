//! Server-rendered HTML. maud DSL — no template files, no build pipeline.
//!
//! Visual direction: **hacker terminal**.  The entire page reads as one long
//! terminal session — Homebrew-style `==>` markers in phosphor green, bold
//! white for package names and emphasis, yellow Warning: lines, cyan for
//! URLs and paths, red for tamper / mismatch.  Single monospace face
//! (JetBrains Mono) throughout; faint CRT scanlines + a subtle phosphor
//! glow.  Forms render as command prompts; verdicts as `[ OK ]` /
//! `[WARN]` / `[FAIL]` status badges.

use maud::{html, Markup, PreEscaped, DOCTYPE};

use super::{InspectError, InspectResult};

/// Inline CSS shared across pages. Kept here so the binary has no external asset deps
/// beyond `/assets/` static files (banner + demo GIFs) and the Google Fonts stylesheet
/// loaded in the document head.
const STYLES: &str = r#"
:root {
    color-scheme: dark;

    /* Terminal palette — phosphor green on warm black, with the Homebrew
     * convention of bold-white package names against `==>` green arrows. */
    --bg: #0a0e0a;
    --bg-elev: #11151a;
    --bg-prompt: #1a1f1f;

    --fg: #e8eaed;
    --fg-dim: #8b938b;
    --fg-deep: #5a5f5a;

    --prompt: #5eff8b;        /* the $ prompt and ==> arrows */
    --prompt-deep: #3ee072;
    --bold: #ffffff;           /* bold white emphasis */
    --link: #7dd3fc;           /* cyan for paths + URLs */
    --warn: #f1c40f;           /* Warning: yellow */
    --err: #ff5555;            /* error / tamper red */
    --ok: #50fa7b;             /* pass / verified green */
    --rule: #1f2522;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }

body {
    font-family: "JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 14px;
    line-height: 1.55;
    background: var(--bg);
    color: var(--fg);
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
    font-feature-settings: "calt", "ss20";

    /* CRT scanlines — a 3px horizontal stripe pattern, intentionally faint
     * so it never interferes with reading.  Fixed so it doesn't move with
     * scroll.  Phosphor green tint at extremely low alpha. */
    background-image: repeating-linear-gradient(
        to bottom,
        rgba(94, 255, 139, 0.018) 0px,
        rgba(94, 255, 139, 0.018) 1px,
        transparent 1px,
        transparent 3px
    );
    background-attachment: fixed;
    background-size: 100% 3px;
}

::selection {
    background: var(--prompt);
    color: var(--bg);
}

/* Typographic Tokens */

.prompt { color: var(--prompt); }
.bold { color: var(--bold); font-weight: 700; }
.dim { color: var(--fg-dim); }
.dimmer { color: var(--fg-deep); }
.link { color: var(--link); }
.warn { color: var(--warn); }
.err  { color: var(--err); }
.ok   { color: var(--ok); }
.under { text-decoration: underline; text-decoration-color: var(--fg-deep); }

/* Inline link styling — keep the underline; tint cyan on hover. */
a {
    color: var(--link);
    text-decoration: underline;
    text-decoration-color: rgba(125, 211, 252, 0.4);
    text-underline-offset: 3px;
}
a:hover {
    color: var(--prompt);
    text-decoration-color: var(--prompt);
}

/* Container — 80ch is the canonical terminal width.  No centered marketing
 * grid; the page reads like a single column of `man` output. */
.wrap {
    max-width: 86ch;
    margin: 0 auto;
    padding: 0 1.5rem;
}

/* Header (tmux-style status bar) */

header.bar {
    border-bottom: 1px solid var(--rule);
    background: var(--bg);
    position: sticky;
    top: 0;
    z-index: 30;
}
header.bar .wrap {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.55rem 1.5rem;
    font-size: 12px;
    gap: 1rem;
    flex-wrap: wrap;
}
header.bar .lhs {
    display: flex;
    align-items: center;
    gap: 1rem;
}
header.bar .ses { color: var(--fg-dim); }
header.bar .ses b { color: var(--fg); font-weight: 500; }
header.bar nav { display: flex; gap: 1.25rem; }
header.bar nav a { color: var(--fg-dim); text-decoration: none; }
header.bar nav a:hover { color: var(--prompt); }

/* ASCII Banner */

pre.banner {
    font-family: inherit;
    margin: 2.5rem 0 0.5rem;
    color: var(--prompt);
    line-height: 1.1;
    /* Scales aggressively at narrow widths so the 75-char banner fits an
     * iPhone-class viewport without clipping; capped at 0.95rem on wide. */
    font-size: clamp(0.42rem, 1.55vw, 0.95rem);
    white-space: pre;
    overflow-x: auto;
    text-shadow: 0 0 6px rgba(94, 255, 139, 0.45), 0 0 14px rgba(94, 255, 139, 0.22);
}
@media (max-width: 480px) {
    pre.banner { font-size: 0.46rem; }
}

/* Brew-Style Output Block */

/* The whole page is rendered as a stream of these blocks.  Each opens
 * with `==>` (green) followed by a heading (bold white), then indented
 * body copy underneath. */
.block {
    margin: 1.8rem 0;
}
.block .arrow {
    color: var(--prompt);
    font-weight: 700;
    margin-right: 0.5em;
}
.block h2 {
    display: inline;
    font-size: 1rem;
    font-weight: 700;
    color: var(--bold);
    letter-spacing: 0;
    margin: 0;
}
.block h2 .sub {
    color: var(--fg-dim);
    font-weight: 400;
    margin-left: 0.5em;
}
.block .body {
    margin: 0.65rem 0 0;
    padding-left: 2.2em;
    color: var(--fg);
}
.block .body p { margin: 0 0 0.65rem; }
.block .body p:last-child { margin-bottom: 0; }

/* The hero block uses a slightly larger heading for the headline. */
.block.hero { text-wrap: balance; }
.block.hero .body { text-wrap: pretty; }
.block.hero h2 {
    font-size: 1.2rem;
}
.block.hero h2 strong {
    color: var(--prompt);
    font-weight: 700;
}

/* Header Metadata Strip */
/* A pseudo brew-cask "info" output — the case metadata. */

.info-strip {
    margin-top: 1.5rem;
    padding-left: 2.2em;
    color: var(--fg-dim);
    display: grid;
    grid-template-columns: max-content 1fr;
    column-gap: 1.5rem;
    row-gap: 0.15rem;
    font-size: 13px;
}
.info-strip dt {
    color: var(--fg-dim);
}
.info-strip dd {
    color: var(--fg);
    margin: 0;
}

/* CTA Buttons */

.cta {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin-top: 1rem;
    padding-left: 2.2em;
}
a.btn {
    display: inline-flex;
    align-items: center;
    gap: 0.4em;
    padding: 0.45rem 0.9rem;
    font-family: inherit;
    font-size: 13px;
    text-decoration: none;
    border: 1px solid var(--prompt);
    color: var(--prompt);
    background: transparent;
    transition: background 100ms ease, color 100ms ease;
}
a.btn:hover {
    background: var(--prompt);
    color: var(--bg);
    text-decoration: none;
}
a.btn.dim {
    border-color: var(--fg-deep);
    color: var(--fg-dim);
}
a.btn.dim:hover {
    background: var(--fg-dim);
    color: var(--bg);
    border-color: var(--fg-dim);
}

/* Code and Log Blocks */

/* Indented log block: appears under the section body, presented as the
 * actual command's stdout.  No box, no border, just the lines themselves. */
pre.log {
    margin: 0.6rem 0 0 0;
    padding: 0;
    font-family: inherit;
    font-size: 13px;
    line-height: 1.7;
    color: var(--fg);
    white-space: pre;
    overflow-x: auto;
    background: transparent;
}
pre.log .arrow { color: var(--prompt); font-weight: 700; }
pre.log .dim { color: var(--fg-dim); }
pre.log .ok  { color: var(--ok); }
pre.log .err { color: var(--err); }
pre.log .warn { color: var(--warn); }
pre.log .bold { color: var(--bold); font-weight: 700; }
pre.log .link { color: var(--link); }

/* Inline code — appears in prose, gets a small chip background. */
code.inl {
    font-family: inherit;
    color: var(--prompt-deep);
    background: var(--bg-elev);
    padding: 0.05em 0.4em;
    border: 1px solid var(--rule);
    font-size: 0.92em;
}

/* Inspect Form (the prompt) */

form.prompt-form {
    margin: 0.6rem 0 0;
    padding-left: 2.2em;
    display: flex;
    align-items: center;
    gap: 0.5em;
    font-family: inherit;
    font-size: 14px;
    flex-wrap: wrap;
}
form.prompt-form .ps {
    color: var(--prompt);
    user-select: none;
    flex-shrink: 0;
}
form.prompt-form .cmd {
    color: var(--bold);
    font-weight: 700;
    flex-shrink: 0;
}
form.prompt-form input[type="text"] {
    flex: 1;
    min-width: 220px;
    background: transparent;
    border: 0;
    border-bottom: 1px solid var(--fg-deep);
    color: var(--fg);
    font-family: inherit;
    font-size: 14px;
    padding: 0.2rem 0;
    outline: 0;
    caret-color: var(--prompt);
}
form.prompt-form input[type="text"]::placeholder {
    color: var(--fg-deep);
}
form.prompt-form input[type="text"]:focus {
    border-bottom-color: var(--prompt);
    color: var(--bold);
}
form.prompt-form button {
    background: transparent;
    border: 1px solid var(--prompt);
    color: var(--prompt);
    font-family: inherit;
    font-size: 12px;
    padding: 0.25rem 0.65rem;
    cursor: pointer;
    flex-shrink: 0;
    transition: background 100ms ease, color 100ms ease;
}
form.prompt-form button:hover {
    background: var(--prompt);
    color: var(--bg);
}
/* A blinking cursor block that follows the input: gives the prompt a
 * live-terminal feel even before the user starts typing. */
form.prompt-form .caret {
    display: inline-block;
    width: 0.55em;
    height: 1.05em;
    background: var(--prompt);
    margin-left: -0.4em;
    animation: caret-blink 1.05s steps(2) infinite;
    transform: translateY(0.15em);
    flex-shrink: 0;
}
@keyframes caret-blink {
    0%, 50% { opacity: 1; }
    51%, 100% { opacity: 0; }
}

.example-pills {
    margin: 0.45rem 0 1rem;
    padding-left: 2.2em;
    font-size: 12px;
    color: var(--fg-dim);
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1rem;
    align-items: baseline;
}
.example-pills .label { color: var(--fg-dim); }
.example-pills a {
    color: var(--link);
    text-decoration: none;
    border-bottom: 1px dashed rgba(125, 211, 252, 0.35);
}
.example-pills a:hover {
    color: var(--prompt);
    border-bottom-color: var(--prompt);
}

/* Result Verdict and Report */

/* Verdict — a [STATUS] tag styled like a service-start message. */
.verdict {
    margin: 0.9rem 0 0;
    padding-left: 2.2em;
    font-size: 14px;
    color: var(--fg);
}
.verdict .tag {
    display: inline-block;
    padding: 0 0.5em;
    margin-right: 0.6em;
    font-weight: 700;
    border: 1px solid currentColor;
}
.verdict.ok .tag    { color: var(--ok); }
.verdict.warn .tag  { color: var(--warn); }
.verdict.err .tag   { color: var(--err); }
.verdict .ttl       { color: var(--bold); font-weight: 700; }
.verdict .sub       { color: var(--fg-dim); display: block; margin-top: 0.3rem; }

.report-table {
    margin: 0.9rem 0 0;
    padding-left: 2.2em;
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    line-height: 1.6;
}
.report-table th, .report-table td {
    text-align: left;
    padding: 0.4rem 0.85rem 0.4rem 0;
    vertical-align: top;
}
.report-table th {
    color: var(--fg-dim);
    font-weight: 400;
    width: 11rem;
    white-space: nowrap;
}
.report-table td {
    color: var(--fg);
    word-break: break-all;
}
.report-table tr {
    border-bottom: 1px dashed var(--rule);
}
.report-table tr:last-child { border-bottom: 0; }

/* Badge inline with a row value. */
.badge {
    display: inline-block;
    padding: 0 0.45em;
    margin-left: 0.45em;
    font-size: 11px;
    border: 1px solid currentColor;
}
.badge.ok    { color: var(--ok); }
.badge.warn  { color: var(--warn); }
.badge.err   { color: var(--err); }
.badge.info  { color: var(--link); }

/* Exhibit Frames */

figure.exhibit {
    margin: 0.7rem 0 0;
    padding-left: 2.2em;
}
figure.exhibit .frame {
    border: 1px solid var(--rule);
    background: var(--bg-elev);
}
figure.exhibit .titlebar {
    display: flex;
    justify-content: space-between;
    padding: 0.35rem 0.7rem;
    border-bottom: 1px solid var(--rule);
    font-size: 11px;
    color: var(--fg-dim);
}
figure.exhibit img { display: block; width: 100%; }
figure.exhibit figcaption {
    margin-top: 0.55rem;
    font-size: 12px;
    color: var(--fg-dim);
}

/* Method Steps */

/* Numbered like the CLI's own `[1/5]` progress lines, one under the other,
 * so the section reads as continuous terminal output. */
.method-list {
    margin: 0.9rem 0 0;
    padding-left: 2.2em;
}
.method-list article + article { margin-top: 1.1rem; }
.method-list h3 {
    margin: 0 0 0.25rem;
    color: var(--bold);
    font-weight: 700;
    font-size: 0.95rem;
}
.method-list h3 .n {
    color: var(--fg-dim);
    font-weight: 400;
    margin-right: 0.6em;
}
.method-list p,
.method-list .specimen {
    margin: 0;
    padding-left: 4.4em;
    font-size: 13px;
    line-height: 1.55;
}
.method-list .specimen {
    margin-top: 0.3rem;
    color: var(--fg-dim);
}
.method-list .specimen .v { color: var(--link); }
@media (max-width: 480px) {
    .method-list p,
    .method-list .specimen { padding-left: 0; }
}

/* Footer */

footer.term {
    margin-top: 3rem;
    padding: 1.4rem 0 2.5rem;
    border-top: 1px dashed var(--rule);
    color: var(--fg-dim);
    font-size: 12px;
}
footer.term .wrap {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
}
footer.term .arrow { color: var(--prompt); font-weight: 700; margin-right: 0.5em; }

/* Scrollbar */

::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb {
    background: var(--rule);
    border: 2px solid var(--bg);
}
::-webkit-scrollbar-thumb:hover { background: var(--prompt-deep); }

/* Reduced Motion */

@media (prefers-reduced-motion: reduce) {
    form.prompt-form .caret { animation: none; opacity: 1; }
}
"#;

/// ASCII banner — drawn freehand, tuned to read as `CLEARHASH` in a chunky
/// block-letter form.  Stays under 86ch (the body container width) at the
/// minimum supported font size.
const ASCII_BANNER: &str = r#"   ██████╗██╗     ███████╗ █████╗ ██████╗ ██╗  ██╗ █████╗ ███████╗██╗  ██╗
  ██╔════╝██║     ██╔════╝██╔══██╗██╔══██╗██║  ██║██╔══██╗██╔════╝██║  ██║
  ██║     ██║     █████╗  ███████║██████╔╝███████║███████║███████╗███████║
  ██║     ██║     ██╔══╝  ██╔══██║██╔══██╗██╔══██║██╔══██║╚════██║██╔══██║
  ╚██████╗███████╗███████╗██║  ██║██║  ██║██║  ██║██║  ██║███████║██║  ██║
   ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"#;

const SITE_URL: &str = "https://clearhash.vercel.app";

const DESCRIPTION: &str = "ClearHash rebuilds npm, PyPI and Cargo packages from their attested \
    source commit and blocks the install if the result differs from what the registry serves.";

fn layout(path: &str, title: &str, body: Markup) -> Markup {
    let url = format!("{SITE_URL}{path}");
    let card = format!("{SITE_URL}/assets/og.png");
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                meta name="description" content=(DESCRIPTION);
                meta property="og:type" content="website";
                meta property="og:site_name" content="ClearHash";
                meta property="og:title" content=(title);
                meta property="og:description" content=(DESCRIPTION);
                meta property="og:url" content=(url);
                meta property="og:image" content=(card);
                meta property="og:image:width" content="1200";
                meta property="og:image:height" content="630";
                meta property="og:image:alt" content="ClearHash shield mark beside the line: Rebuild every package. Compare every byte. Block every tamper.";
                meta name="twitter:card" content="summary_large_image";
                meta name="twitter:image" content=(card);
                meta name="theme-color" content="#0a0e0a";
                link rel="icon" type="image/svg+xml" href="/assets/favicon.svg";
                link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32.png";
                link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16.png";
                link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png";

                // JetBrains Mono only — single face used at 400 / 700.
                link rel="preconnect" href="https://fonts.googleapis.com";
                link rel="preconnect" href="https://fonts.gstatic.com" crossorigin;
                link
                    rel="stylesheet"
                    href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap";

                style { (PreEscaped(STYLES)) }
            }
            body {
                header.bar {
                    div.wrap {
                        div.lhs {
                            span.ses { b { "clearhash" } "@verifier" }
                            span.dim { "v" (env!("CARGO_PKG_VERSION")) }
                            span.dim { "MIT" }
                        }
                        nav {
                            a href="/inspect" { "inspect" }
                            a href="https://github.com/Builder106/clear-hash" { "source ↗" }
                        }
                    }
                }
                (body)
                footer.term {
                    div.wrap {
                        span {
                            span.arrow { "==>" }
                            "ClearHash is MIT-licensed."
                        }
                        span.dim {
                            "source: "
                            a href="https://github.com/Builder106/clear-hash" { "github.com/Builder106/clear-hash" }
                        }
                    }
                }

                // Vercel Web Analytics + Speed Insights.
                // Scripts are served by Vercel's edge at the canonical paths; they 404
                // harmlessly in local dev. Enable each in the Vercel dashboard
                // (clear-hash → Analytics → Enable, same for Speed Insights) for data
                // to start flowing.
                script { (PreEscaped("window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };")) }
                script defer src="/_vercel/insights/script.js" {}
                script { (PreEscaped("window.si = window.si || function () { (window.siq = window.siq || []).push(arguments); };")) }
                script defer src="/_vercel/speed-insights/script.js" {}
            }
        }
    }
}

/// Shared `clearhash info` header — the ASCII banner + a brew-style info
/// strip with project metadata.  Used at the top of every page.
fn info_header() -> Markup {
    html! {
        pre.banner aria-label="ClearHash" { (ASCII_BANNER) }

        p style="padding-left:0;margin:0.4rem 0 1.4rem;" class="dim" {
            "supply-chain integrity verifier for npm, PyPI and Cargo packages."
        }

        div.block {
            span.arrow { "==>" }
            h2 { "clearhash info" }
            dl.info-strip {
                dt { "license" }      dd { "MIT" }
                dt { "ecosystems" }   dd { "npm, PyPI, Cargo" }
                dt { "method" }       dd { "rebuild from the attested source commit, then compare file trees" }
                dt { "rate limit" }   dd { "30 inspects/min across the page and API, shared by all visitors" }
            }
        }
    }
}

pub async fn landing() -> Markup {
    layout(
        "/",
        "ClearHash: supply-chain integrity verifier",
        html! {
            div.wrap {
                (info_header())

                div.block.hero {
                    span.arrow { "==>" }
                    h2 {
                        "Checks that a registry package is "
                        strong { "what its source code builds" } "."
                    }
                    div.body {
                        p {
                            "ClearHash fetches a package, verifies its SLSA attestation through "
                            "Sigstore + Rekor, rebuilds it from the attested source commit in a "
                            "Docker container, and compares the rebuilt file tree against the "
                            "registry artifact. If anything differs, the install is blocked."
                        }
                    }
                    div.cta {
                        a.btn href="/inspect" { "[ inspect a package → ]" }
                        a.btn.dim href="https://github.com/Builder106/clear-hash" { "[ source on github ↗ ]" }
                    }
                }

                div.block {
                    span.arrow { "==>" }
                    h2 { "demo " span.sub { "clearhash verify npm:sigstore@2.3.1" } }
                    div.body {
                        p {
                            "A recording of the full pipeline from an earlier release, which rebuilt "
                            "online. The run took about 36 seconds; the GIF plays at 4× speed. The "
                            "current release rebuilds offline and refuses this package because its "
                            "pinned source has no dependency integrity hashes."
                        }
                    }
                    figure.exhibit {
                        div.frame {
                            div.titlebar {
                                span { "$ clearhash verify npm:sigstore@2.3.1" }
                                span { "36 s at 4× speed" }
                            }
                            img src="/assets/demo-verify.gif"
                                alt="Terminal recording of clearhash verify npm:sigstore@2.3.1 running all five steps and ending in MATCH";
                        }
                        figcaption {
                            "The rebuilt file tree hashed the same as the registry tarball's, so the run ended in "
                            span.ok { "MATCH" } "."
                        }
                    }

                    pre.log style="margin-top:1rem;" {
        "  " (PreEscaped("<span class=\"dim\">[1/5]</span> Fetching <span class=\"bold\">sigstore</span> from <span class=\"link\">npm</span>\n"))
        "        sha256: " (PreEscaped("<span class=\"dim\">1b5041a35f86125db7f872742502470753fd2e1109521b7dbff8a61d229a03c2</span>\n"))
        "  " (PreEscaped("<span class=\"dim\">[2/5]</span> Verifying Sigstore attestation\n"))
        "        " (PreEscaped("<span class=\"warn\">WARN</span> clearhash_provenance: provenance: validated\n"))
        "        commit: " (PreEscaped("<span class=\"link\">46e7056ff991</span>  (<span class=\"dim\">workflow: github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main</span>)\n"))
        "  " (PreEscaped("<span class=\"dim\">[3/5]</span> Spinning up rebuild container (<span class=\"bold\">node:20.11.1-bookworm-slim</span>)\n"))
        "  " (PreEscaped("<span class=\"dim\">[4/5]</span> Rebuilding from source at commit <span class=\"link\">46e7056ff991</span>\n"))
        "  " (PreEscaped("<span class=\"dim\">[5/5]</span> Comparing file trees\n\n"))
        "  " (PreEscaped("<span class=\"ok\">✓ MATCH</span> npm:sigstore@2.3.1 tree-hash <span class=\"dim\">ec714016d7e4ce742f9aa23b6f16f19cb967bf82</span>"))
                    }
                }

                div.block {
                    span.arrow { "==>" }
                    h2 { "what it catches, and how" }
                    div.body {
                        p {
                            "In event-stream, ua-parser-js, xz-utils and the post-install wallet "
                            "stealers, the published tarball held code the source repo did not. A "
                            "signature tells you who published a tarball, and a transparency log tells "
                            "you every mirror serves the same one. Neither tells you whether the "
                            "tarball is what the source would build. ClearHash rebuilds it and compares."
                        }
                    }
                    div.method-list {
                        article {
                            h3 { span.n { "[1/3]" } "Sigstore + Rekor" }
                            p {
                                "Checks the Fulcio certificate's issuer identity, verifies the DSSE "
                                "signature, authenticates the Rekor checkpoint and Merkle inclusion "
                                "proof, and confirms the workflow URI names the source repo."
                            }
                            div.specimen {
                                "rekor_log_index: " span.v { "94408136" }
                            }
                        }
                        article {
                            h3 { span.n { "[2/3]" } "Rebuild" }
                            p {
                                "Clones the source repo, checks out the attested commit, and builds the "
                                "package in a pinned Docker image. npm builds run with "
                                code.inl { "--ignore-scripts" } ", so lifecycle hooks never execute."
                            }
                            div.specimen {
                                "commit_sha: " span.v { "46e7056ff991…" }
                            }
                        }
                        article {
                            h3 { span.n { "[3/3]" } "File-tree compare" }
                            p {
                                "Extracts both archives, drops the metadata the registry adds, and "
                                "compares Merkle-hashed file trees. A match exits 0; a mismatch exits 1 "
                                "with a per-file diff."
                            }
                            div.specimen {
                                "tree_hash: " span.v { "ec714016d7e4ce74…" }
                            }
                        }
                    }
                }

                div.block {
                    span.arrow { "==>" }
                    h2 { "install the CLI" }
                    div.body {
                        p {
                            "Needs Rust 1.88+ and a running Docker daemon (Docker Desktop or OrbStack "
                            "on macOS). The "
                            a href="/inspect" { code.inl { "/inspect" } }
                            " page on this site skips the rebuild, so it needs neither."
                        }
                    }
                    pre.log style="padding-left:2.2em;" {
        "  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">git</span> clone https://github.com/Builder106/clear-hash.git\n"))
        "  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">cd</span> clear-hash\n"))
        "  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">cargo</span> install --path crates/clearhash-cli\n\n"))
        "  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">clearhash</span> inspect <span class=\"link\">npm:sigstore@2.3.1</span>"))
                    }
                }

                div.block {
                    span.arrow { "==>" }
                    h2 { "API" }
                    div.body {
                        p { "The inspect endpoint also returns JSON:" }
                    }
                    pre.log style="padding-left:2.2em;" {
        "  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">curl</span> '<span class=\"link\">https://clearhash.vercel.app/api/inspect?package=npm:sigstore@2.3.1</span>'\n"))
        "  {\n"
        "    \"package\": \"npm:sigstore@2.3.1\",\n"
        "    \"registry_sha256\": " (PreEscaped("<span class=\"dim\">\"1b5041a35f86125db7f872742502470753fd2e1109521b7dbff8a61d229a03c2\"</span>")) ",\n"
        "    \"attestation\": {\n"
        "      \"source_repo\": " (PreEscaped("<span class=\"link\">\"git+https://github.com/sigstore/sigstore-js@refs/heads/main\"</span>")) ",\n"
        "      \"commit_sha\": " (PreEscaped("<span class=\"link\">\"46e7056ff9912ebfee5298d94024895a9fea76c0\"</span>")) ",\n"
        "      \"builder_id\": \"https://github.com/actions/runner/github-hosted\",\n"
        "      \"issuer_dn\": \"O=sigstore.dev, CN=sigstore-intermediate\",\n"
        "      \"workflow_uri\": " (PreEscaped("<span class=\"link\">\"https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main\"</span>")) ",\n"
        "      \"rekor_log_index\": 94408136\n"
        "    }\n"
        "  }"
                    }
                    div.body style="margin-top:0.8rem;" {
                        p class="dim" {
                            span.warn { "Warning:" }
                            " rate-limited to 30 requests/minute globally. For higher throughput, "
                            "run the CLI locally."
                        }
                    }
                }
            }
        },
    )
}

pub fn inspect_empty() -> Markup {
    layout(
        "/inspect",
        "Inspect a package | ClearHash",
        html! {
            div.wrap {
                (info_header())

                div.block {
                    span.arrow { "==>" }
                    h2 { "inspect a package " span.sub { "attestation only, no rebuild" } }
                    div.body {
                        p {
                            "Fetches the artifact, parses its SLSA attestation and validates the "
                            "certificate chain. The rebuild and file-tree comparison run only in the CLI."
                        }
                    }
                    (inspect_form(""))
                    (example_pills())
                }
            }
        },
    )
}

pub fn inspect_result(package: &str, result: &InspectResult) -> Markup {
    let (verdict_class, tag, ttl, sub) = match &result.attestation {
        Some(_) => (
            "ok",
            "[ OK ]",
            "attestation verified",
            "Checked the Fulcio leaf certificate and the Rekor log entry, and matched the workflow URI to the source repo.",
        ),
        None => (
            "warn",
            "[WARN]",
            "no attestation on file",
            "The CLI's verify refuses to rebuild this artifact without --allow-unattested.",
        ),
    };
    let prefill: &str = if result.inferred_latest {
        &result.package
    } else {
        package
    };
    let latest_badge = if result.inferred_latest {
        html! { " " span.badge.info { "resolved → latest" } }
    } else {
        html! {}
    };

    layout(
        "/inspect",
        &format!("{} | ClearHash", result.package),
        html! {
            div.wrap {
                (info_header())

                div.block {
                    span.arrow { "==>" }
                    h2 { "inspect a package" }
                    (inspect_form(prefill))
                    (example_pills())

                    div class=(format!("verdict {}", verdict_class)) {
                        span.tag { (tag) }
                        span.ttl { (ttl) }
                        (latest_badge)
                        span.sub { (sub) }
                    }

                    table.report-table {
                        tr { th { "package" } td { (result.package) } }
                        tr { th { "registry sha-256" } td class="link" { (result.registry_sha256) } }
                        @if let Some(a) = &result.attestation {
                            tr { th { "source repo" } td class="link" { (a.source_repo) } }
                            tr { th { "commit" } td class="link" { (a.commit_sha) } }
                            tr { th { "builder" } td { (a.builder_id) } }
                            tr { th { "cert issuer" } td { (a.issuer_dn) } }
                            @if let Some(w) = &a.workflow_uri {
                                tr { th { "workflow" } td class="link" { (w) } }
                            }
                            @if let Some(li) = a.rekor_log_index {
                                tr { th { "rekor index" } td { (li) } }
                            }
                        } @else {
                            tr {
                                th { "note" }
                                td {
                                    "This package has no SLSA attestation. The CLI's "
                                    code.inl { "verify" }
                                    " refuses to rebuild it without "
                                    code.inl { "--allow-unattested" } "."
                                }
                            }
                        }
                    }

                    p style="padding-left:0;margin-top:1rem;font-size:12px;" class="dim" {
                        span.arrow { "==>" }
                        " as JSON: "
                        code.inl { "GET /api/inspect?package=" (package) }
                    }
                }
            }
        },
    )
}

pub fn inspect_error(package: &str, err: &InspectError) -> Markup {
    layout(
        "/inspect",
        "Inspect failed | ClearHash",
        html! {
            div.wrap {
                (info_header())

                div.block {
                    span.arrow { "==>" }
                    h2 { "inspect a package" }
                    (inspect_form(package))
                    (example_pills())

                    div.verdict.err {
                        span.tag { "[FAIL]" }
                        span.ttl { "inspect failed (" (err.status) ")" }
                        span.sub { (err.message) }
                    }

                    table.report-table {
                        tr { th { "package" } td { (package) } }
                        tr { th { "status" } td class="err" { (err.status) } }
                        tr { th { "detail" } td { (err.message) } }
                    }
                }
            }
        },
    )
}

fn inspect_form(prefill: &str) -> Markup {
    html! {
        form.prompt-form method="get" action="/inspect" {
            span.ps { "$" }
            span.cmd { "clearhash inspect" }
            input
                type="text"
                name="package"
                placeholder="npm:sigstore@2.3.1"
                value=(prefill)
                autocomplete="off"
                spellcheck="false"
                autofocus?[prefill.is_empty()] ;
            span.caret aria-hidden="true" {}
            button type="submit" { "↵ run" }
        }
    }
}

fn example_pills() -> Markup {
    html! {
        div.example-pills {
            span.label { "==> examples:" }
            a href="/inspect?package=npm:sigstore@2.3.1" { "npm:sigstore@2.3.1" }
            a href="/inspect?package=npm:@sigstore/sign" title="no version → latest" { "npm:@sigstore/sign" }
            a href="/inspect?package=npm:left-pad@1.3.0" { "npm:left-pad@1.3.0" }
        }
    }
}
