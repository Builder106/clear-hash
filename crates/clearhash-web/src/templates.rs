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
    background-image:
        repeating-linear-gradient(
            to bottom,
            rgba(94, 255, 139, 0.018) 0px,
            rgba(94, 255, 139, 0.018) 1px,
            transparent 1px,
            transparent 3px
        ),
        /* corner phosphor wash — top-left, simulating an old CRT glow */
        radial-gradient(
            70% 50% at 0% 0%,
            rgba(94, 255, 139, 0.045) 0%,
            transparent 60%
        );
    background-attachment: fixed, fixed;
    background-size: 100% 3px, 100% 100%;
}

::selection {
    background: var(--prompt);
    color: var(--bg);
}

/* Phosphor glow on the highest-contrast prompts only — used sparingly so
 * the text doesn't blur the rest of the time. */
.glow {
    text-shadow: 0 0 6px rgba(94, 255, 139, 0.55), 0 0 14px rgba(94, 255, 139, 0.25);
}

/* ============== TYPOGRAPHIC TOKENS ============== */

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

/* ============== HEADER (tmux-style status bar) ============== */

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
header.bar .traffic {
    display: inline-flex;
    gap: 0.4rem;
}
header.bar .traffic span {
    width: 9px; height: 9px; border-radius: 50%;
    display: inline-block;
    background: var(--fg-deep);
}
header.bar .traffic span:nth-child(1) { background: #ff5f56; }
header.bar .traffic span:nth-child(2) { background: #ffbd2e; }
header.bar .traffic span:nth-child(3) { background: #27c93f; }
header.bar .ses { color: var(--fg-dim); }
header.bar .ses b { color: var(--fg); font-weight: 500; }
header.bar nav { display: flex; gap: 1.25rem; }
header.bar nav a { color: var(--fg-dim); text-decoration: none; }
header.bar nav a:hover { color: var(--prompt); }

/* ============== ASCII BANNER ============== */

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

/* ============== BREW-STYLE OUTPUT BLOCK ============== */

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
.block.hero h2 {
    font-size: 1.2rem;
}
.block.hero h2 strong {
    color: var(--prompt);
    font-weight: 700;
}

/* ============== HEADER METADATA STRIP ============== */
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

/* ============== CTA BUTTONS — bracketed commands ============== */

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

/* ============== CODE / LOG BLOCKS ============== */

/* Indented log block — appears under the section body, presented as the
 * actual command's stdout.  No box, no border — just the lines themselves. */
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

/* ============== INSPECT FORM (the prompt) ============== */

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
/* A blinking cursor block that follows the input — gives the prompt a
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

/* ============== RESULT — verdict + report ============== */

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

/* ============== EXHIBIT / FIGURE FRAMES ============== */

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
figure.exhibit .titlebar .dots {
    display: inline-flex;
    gap: 0.35rem;
}
figure.exhibit .titlebar .dots span {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--fg-deep);
}
figure.exhibit .titlebar .dots span:nth-child(1) { background: #ff5f56; }
figure.exhibit .titlebar .dots span:nth-child(2) { background: #ffbd2e; }
figure.exhibit .titlebar .dots span:nth-child(3) { background: #27c93f; }
figure.exhibit img { display: block; width: 100%; }
figure.exhibit figcaption {
    margin-top: 0.55rem;
    font-size: 12px;
    color: var(--fg-dim);
}

/* ============== EVIDENCE TRIPTYCH (the three method cards) ============== */

/* Render as three indented brew-style sub-blocks rather than a card grid —
 * keeps the page reading as continuous terminal output. */
.method-list {
    margin: 0.6rem 0 0;
    padding-left: 2.2em;
    display: grid;
    grid-template-columns: 1fr;
    gap: 1.2rem;
}
@media (min-width: 760px) {
    .method-list { grid-template-columns: repeat(3, 1fr); }
}
.method-list article {
    border-left: 2px solid var(--prompt);
    padding: 0.1rem 0 0.1rem 0.9rem;
}
.method-list article.err  { border-left-color: var(--err); }
.method-list article.warn { border-left-color: var(--warn); }
.method-list .file {
    color: var(--fg-dim);
    font-size: 11px;
    margin-bottom: 0.2rem;
}
.method-list h3 {
    margin: 0 0 0.3rem;
    color: var(--bold);
    font-weight: 700;
    font-size: 0.95rem;
}
.method-list p {
    margin: 0;
    color: var(--fg);
    font-size: 13px;
    line-height: 1.55;
}
.method-list .specimen {
    margin-top: 0.55rem;
    color: var(--fg-dim);
    font-size: 11px;
    border-top: 1px dashed var(--rule);
    padding-top: 0.45rem;
}
.method-list .specimen .v { color: var(--link); }

/* ============== FOOTER ============== */

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

/* ============== SCROLLBAR ============== */

::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb {
    background: var(--rule);
    border: 2px solid var(--bg);
}
::-webkit-scrollbar-thumb:hover { background: var(--prompt-deep); }

/* ============== REDUCED MOTION ============== */

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
                            span.traffic { span {} span {} span {} }
                            span.ses {
                                b { "clearhash" }
                                "@verifier — "
                                "v0.1 · MIT · "
                                span.prompt { "● ready" }
                            }
                        }
                        nav {
                            a href="/inspect" { "inspect" }
                            a href="https://github.com/Builder106/ClearHash" { "source ↗" }
                        }
                    }
                }
                (body)
                footer.term {
                    div.wrap {
                        span {
                            span.arrow { "==>" }
                            "Filed under supply-chain integrity. "
                            span.dim { "MIT-licensed." }
                        }
                        span.dim {
                            "CLH-26 · "
                            a href="https://github.com/Builder106/ClearHash" { "github.com/Builder106/ClearHash" }
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
            "supply-chain integrity verifier — rebuild every package, compare every byte, block every tamper."
        }

        div.block {
            span.arrow { "==>" }
            h2 { "clearhash info " span.sub { "· case CLH-26" } }
            dl.info-strip {
                dt { "classification" }   dd { "open · public · MIT" }
                dt { "subject" }          dd { "Supply-chain integrity (npm · PyPI · Cargo)" }
                dt { "method" }           dd { "rebuild ✕ compare against attested source commit" }
                dt { "rate-limit" }       dd { "30 req/min global, /inspect endpoint" }
            }
        }
    }
}

pub async fn landing() -> Markup {
    layout(
        "ClearHash — supply-chain integrity verifier",
        html! {
            div.wrap {
                (info_header())

                /* ============== HERO ============== */
                div.block.hero {
                    span.arrow { "==>" }
                    h2 {
                        "Don't just check signatures. "
                        strong { "Rebuild the source." }
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
                        a.btn.dim href="https://github.com/Builder106/ClearHash" { "[ source on github ↗ ]" }
                    }
                }

                /* ============== EXHIBIT A — DEMO ============== */
                div.block {
                    span.arrow { "==>" }
                    h2 { "exhibit A " span.sub { "· live verify run · npm:sigstore@2.3.1" } }
                    div.body {
                        p {
                            "Full pipeline in ~36 seconds (shown at 4× playback). The fetch, the "
                            "attestation parse, the Docker rebuild, the tree-diff — every step in "
                            "the recording, in order."
                        }
                    }
                    figure.exhibit {
                        div.frame {
                            div.titlebar {
                                span.dots { span {} span {} span {} }
                                span { "clearhash verify npm:sigstore@2.3.1" }
                                span { "rec · 36s" }
                            }
                            img src="/assets/demo-verify.gif" alt="verify demo";
                        }
                        figcaption {
                            "The rebuild reproduces the registry artifact byte-for-byte. "
                            span.ok { "MATCH" } " — tree-hash logged."
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

                /* ============== METHOD ============== */
                div.block {
                    span.arrow { "==>" }
                    h2 { "method of examination " span.sub { "· what it catches, and how" } }
                    div.body {
                        p {
                            "The supply-chain attacks of the last five years (event-stream, ua-parser-js, "
                            "the post-install crypto-wallet stealers, xz-utils) all share one shape: "
                            "the registry tarball diverges from the source repo. Existing tools verify "
                            span.bold { "who " } "signed the tarball, or that the tarball matches itself "
                            "across mirrors — but not whether the tarball is what the source code would "
                            "produce. ClearHash does the rebuild and the comparison."
                        }
                    }
                    div.method-list {
                        article {
                            div.file { "step 1/3" }
                            h3 { "Sigstore + Rekor" }
                            p {
                                "Verifies the SLSA attestation envelope, extracts the Fulcio-issued "
                                "leaf cert, cross-checks the workflow URI against the attested source "
                                "repo, and confirms a Rekor transparency-log entry."
                            }
                            div.specimen {
                                "rekor_log_index → " span.v { "94,408,136" }
                            }
                        }
                        article {
                            div.file { "step 2/3" }
                            h3 { "Real rebuild" }
                            p {
                                "Clones the attested commit, pins HEAD, runs the ecosystem's build "
                                "script (npm ci + npm pack) in a Docker container — with "
                                code.inl { "--ignore-scripts" } " to block lifecycle hooks."
                            }
                            div.specimen {
                                "commit_sha → " span.v { "46e7056ff991…" }
                            }
                        }
                        article.err {
                            div.file { "step 3/3" }
                            h3 { "File-tree compare" }
                            p {
                                "Normalises both archives (strips mtimes, scrubs npm-injected "
                                "metadata), Merkle-hashes the file trees, and surfaces per-file diffs "
                                "on mismatch."
                            }
                            div.specimen {
                                "tree_hash → " span.v { "ec714016d7e4ce74…" }
                            }
                        }
                    }
                }

                /* ============== INSTALL ============== */
                div.block {
                    span.arrow { "==>" }
                    h2 { "install the CLI" }
                    div.body {
                        p {
                            "The full verify pipeline needs a running Docker daemon (Docker Desktop or "
                            "OrbStack on macOS). The "
                            a href="/inspect" { code.inl { "/inspect" } }
                            " endpoint on this site runs the fetch + attestation parse parts without Docker."
                        }
                    }
                    pre.log style="padding-left:2.2em;" {
"  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">git</span> clone https://github.com/Builder106/ClearHash.git\n"))
"  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">cd</span> ClearHash\n"))
"  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">cargo</span> install --path crates/clearhash-cli\n\n"))
"  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">clearhash</span> verify <span class=\"link\">npm:sigstore@2.3.1</span>"))
                    }
                }

                /* ============== API ============== */
                div.block {
                    span.arrow { "==>" }
                    h2 { "API " span.sub { "· programmatic specimen request" } }
                    div.body {
                        p { "Programmatic access to the inspect endpoint:" }
                    }
                    pre.log style="padding-left:2.2em;" {
"  " (PreEscaped("<span class=\"dim\">$</span> <span class=\"bold\">curl</span> '<span class=\"link\">https://clear-hash.vercel.app/api/inspect?package=npm:sigstore@2.3.1</span>'\n"))
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
        "ClearHash · inspect",
        html! {
            div.wrap {
                (info_header())

                div.block {
                    span.arrow { "==>" }
                    h2 { "inspect a package " span.sub { "· no rebuild, attestation parse only" } }
                    div.body {
                        p {
                            "Fetches the artifact, parses its SLSA attestation, validates the certificate "
                            "chain. Use the CLI for the full byte-by-byte verify."
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
            "Fulcio leaf cert · Rekor transparency-log entry · workflow URI cross-checked against source repo.",
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
        &format!("ClearHash · {}", result.package),
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
                        " json · "
                        code.inl { "GET /api/inspect?package=" (package) }
                    }
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
                (info_header())

                div.block {
                    span.arrow { "==>" }
                    h2 { "inspect a package" }
                    (inspect_form(package))
                    (example_pills())

                    div.verdict.err {
                        span.tag { "[FAIL]" }
                        span.ttl { "specimen rejected (" (err.status) ")" }
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
            span.cmd { "clearhash verify" }
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
