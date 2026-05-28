//! Server-rendered HTML. maud DSL — no template files, no build pipeline.
//!
//! Visual direction: **the forensic dossier**.  Bone-white paper, ink black,
//! cinnabar red for tamper/mismatch and sage green for a verified match — the
//! palette of an evidence binder, not a SaaS dashboard.  Hash strings, commit
//! SHAs, and registry digests are treated as evidence labels: monospace, grouped
//! every four hexits, framed with hairline rules.

use maud::{html, Markup, PreEscaped, DOCTYPE};

use super::{InspectError, InspectResult};

/// Inline CSS shared across pages. Kept here so the binary has no external asset deps
/// beyond `/assets/` static files (banner + demo GIFs) and the Google Fonts stylesheet
/// loaded in the document head.
const STYLES: &str = r#"
:root {
    color-scheme: light dark;

    /* Dossier paper — warm bone-white with a faint sepia drift. */
    --paper: #f5f2ea;
    --paper-shade: #ebe6d7;
    --paper-edge: #d8d1bd;
    --ink: #161311;
    --ink-soft: #4a423b;
    --ink-faint: #6c6357;
    --hairline: #c9c0ac;
    --rule: #1c1916;

    /* Signal palette — used sparingly, always with intent. */
    --cinnabar: #b32820;      /* tamper / mismatch */
    --cinnabar-deep: #7a1812;
    --sage: #4d6b3a;          /* verified / match */
    --sage-deep: #324822;
    --amber: #a87325;         /* caution / no attestation */
    --amber-deep: #6e4a14;

    /* Highlight stripes — like a marker pass across a page. */
    --marker-yellow: rgba(255, 220, 60, 0.28);
    --marker-blue: rgba(60, 110, 175, 0.16);
}

@media (prefers-color-scheme: dark) {
    :root {
        /* Carbon-copy fallback for users who insist on dark mode. */
        --paper: #131210;
        --paper-shade: #1a1815;
        --paper-edge: #2a2620;
        --ink: #efeadc;
        --ink-soft: #b8b09f;
        --ink-faint: #8a8273;
        --hairline: #3a342a;
        --rule: #efeadc;

        --cinnabar: #e16156;
        --cinnabar-deep: #b3382b;
        --sage: #9bbb7a;
        --sage-deep: #6b8a4f;
        --amber: #d4a25a;
        --amber-deep: #a87325;

        --marker-yellow: rgba(255, 220, 60, 0.14);
        --marker-blue: rgba(120, 170, 230, 0.10);
    }
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }

body {
    font-family: "Geist", "Inter Tight", system-ui, sans-serif;
    background: var(--paper);
    color: var(--ink);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
    font-feature-settings: "ss01", "cv11";

    /* Subtle paper grain — a single fixed SVG noise layer. */
    background-image:
        url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='280' height='280'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='1' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0.55  0 0 0 0 0.50  0 0 0 0 0.40  0 0 0 0.05 0'/></filter><rect width='100%25' height='100%25' filter='url(%23n)'/></svg>");
    background-attachment: fixed;
    background-size: 280px 280px;
}

::selection {
    background: var(--marker-yellow);
    color: var(--ink);
}

/* Layout container — narrower than the AI-default 1200px; reads like a single
 * column of evidence rather than a marketing grid. */
.wrap {
    max-width: 1080px;
    margin: 0 auto;
    padding: 0 1.5rem;
}

/* ============== TYPOGRAPHY ============== */

.serif {
    font-family: "Newsreader", "Source Serif 4", Georgia, serif;
    font-feature-settings: "ss01", "lnum";
    font-optical-sizing: auto;
}

.display {
    font-family: "Newsreader", "Source Serif 4", Georgia, serif;
    font-weight: 500;
    font-optical-sizing: auto;
    font-variation-settings: "opsz" 144;
    letter-spacing: -0.018em;
    line-height: 1.02;
}

.display .accent-italic {
    font-style: italic;
    font-weight: 400;
    color: var(--ink);
    background-image: linear-gradient(to top, var(--marker-yellow) 0%, var(--marker-yellow) 32%, transparent 32%);
    padding: 0 0.18em;
}

.mono {
    font-family: "JetBrains Mono", "IBM Plex Mono", ui-monospace, "SF Mono", monospace;
    font-feature-settings: "ss20", "calt";
}

.tabular { font-variant-numeric: tabular-nums; }
.uppercase { text-transform: uppercase; }

.case-label {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 0.68rem;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--ink-faint);
}

/* ============== HEADER (the case-file slip) ============== */

header.dossier {
    border-bottom: 1px solid var(--ink);
    background:
        linear-gradient(to bottom, var(--paper) 0%, var(--paper) 90%, var(--paper-shade) 100%);
}
header.dossier .wrap {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1.2rem 1.5rem;
    gap: 1.5rem;
    flex-wrap: wrap;
}

.brand {
    font-family: "Newsreader", serif;
    font-weight: 600;
    font-size: 1.25rem;
    letter-spacing: -0.01em;
    color: var(--ink);
    text-decoration: none;
    display: inline-flex;
    align-items: baseline;
    gap: 0.05em;
}
.brand .crosshatch { color: var(--cinnabar); font-style: italic; }
.brand:hover .crosshatch { color: var(--cinnabar-deep); }

nav.dossier-nav {
    display: flex;
    align-items: center;
    gap: 1.6rem;
    font-size: 0.85rem;
}
nav.dossier-nav a {
    color: var(--ink-soft);
    text-decoration: none;
    border-bottom: 1px solid transparent;
    padding-bottom: 2px;
}
nav.dossier-nav a:hover {
    color: var(--ink);
    border-bottom-color: var(--cinnabar);
}

/* ============== CASE STRIP — perforated metadata bar ============== */

.case-strip {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0;
    border-top: 1px solid var(--ink);
    border-bottom: 1px solid var(--ink);
    background: var(--paper-shade);
    margin-top: 2.5rem;
}
@media (min-width: 720px) {
    .case-strip { grid-template-columns: repeat(4, minmax(0, 1fr)); }
}
.case-strip > div {
    padding: 0.9rem 1.2rem;
    border-right: 1px dashed var(--hairline);
    border-bottom: 1px dashed var(--hairline);
}
/* On the 2-column mobile layout, the bottom row carries no bottom border. */
.case-strip > div:nth-last-child(-n+2) { border-bottom: 0; }
.case-strip > div:nth-child(2n) { border-right: 0; }
@media (min-width: 720px) {
    .case-strip > div { border-bottom: 0; }
    .case-strip > div:nth-child(2n) { border-right: 1px dashed var(--hairline); }
    .case-strip > div:last-child { border-right: 0; }
}
.case-strip dt {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.62rem;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--ink-faint);
    margin: 0 0 0.3rem;
}
.case-strip dd {
    margin: 0;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.86rem;
    color: var(--ink);
    font-feature-settings: "tnum", "calt";
}

/* ============== HERO ============== */

.hero { padding: 5.5rem 0 4rem; }
.hero h1 {
    margin: 0 0 1.8rem;
    font-family: "Newsreader", serif;
    font-weight: 500;
    font-size: clamp(2.6rem, 6.5vw, 5.2rem);
    line-height: 1.02;
    letter-spacing: -0.022em;
    font-variation-settings: "opsz" 144;
    color: var(--ink);
}
.hero h1 .accent-italic {
    font-style: italic;
    font-weight: 400;
    background-image: linear-gradient(to top, var(--marker-yellow) 0%, var(--marker-yellow) 36%, transparent 36%);
    padding: 0 0.15em;
}
.hero p.lede {
    font-size: 1.125rem;
    line-height: 1.65;
    color: var(--ink-soft);
    max-width: 38rem;
    margin: 0 0 2rem;
}

/* Examiner-signed stamp — a circular evidence seal. */
.stamp {
    position: absolute;
    top: 1rem;
    right: 0;
    width: 9.5rem;
    height: 9.5rem;
    transform: rotate(-7deg);
    pointer-events: none;
}
.stamp svg { width: 100%; height: 100%; }
.stamp text {
    fill: var(--cinnabar);
    font-family: "JetBrains Mono", monospace;
    font-weight: 700;
    letter-spacing: 0.12em;
}
@media (max-width: 900px) {
    .stamp { display: none; }
}

.hero-row {
    position: relative;
    display: grid;
    grid-template-columns: minmax(0, 1fr);
}

.cta {
    display: flex;
    gap: 0.75rem;
    flex-wrap: wrap;
    margin-top: 1.6rem;
}
.btn {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.7rem 1.2rem;
    border-radius: 0;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    text-decoration: none;
    transition: transform 120ms ease, background-color 120ms ease;
    border: 1px solid var(--ink);
}
.btn.primary {
    background: var(--ink);
    color: var(--paper);
}
.btn.primary:hover {
    background: var(--cinnabar);
    border-color: var(--cinnabar);
    transform: translateY(-1px);
}
.btn.secondary {
    background: transparent;
    color: var(--ink);
}
.btn.secondary:hover {
    background: var(--ink);
    color: var(--paper);
    transform: translateY(-1px);
}

/* ============== SECTION CONVENTION ============== */

section {
    padding: 3.5rem 0;
    border-top: 1px solid var(--hairline);
    position: relative;
}
section .section-mark {
    display: flex;
    align-items: baseline;
    gap: 1rem;
    margin-bottom: 1.5rem;
}
section .section-mark .num {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.7rem;
    color: var(--cinnabar);
    letter-spacing: 0.22em;
}
section .section-mark .ttl {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.7rem;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--ink-faint);
}
section .section-mark .rule {
    flex: 1;
    height: 1px;
    background: var(--hairline);
}

section h2 {
    font-family: "Newsreader", serif;
    font-weight: 500;
    font-variation-settings: "opsz" 80;
    font-size: clamp(1.8rem, 3.4vw, 2.6rem);
    margin: 0 0 1rem;
    letter-spacing: -0.015em;
    color: var(--ink);
    max-width: 36rem;
}
section h2 em {
    font-style: italic;
    font-weight: 400;
}
section p {
    color: var(--ink-soft);
    max-width: 38rem;
    margin: 0 0 1rem;
    font-size: 1.025rem;
    line-height: 1.65;
}

/* ============== EVIDENCE CARDS (replaces feature grid) ============== */

.evidence {
    display: grid;
    gap: 0;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    margin-top: 2.5rem;
    border: 1px solid var(--ink);
    background: var(--paper);
}
.evidence article {
    padding: 1.6rem 1.4rem 1.8rem;
    position: relative;
    border-right: 1px solid var(--hairline);
}
.evidence article:last-child { border-right: 0; }

.evidence article .file-no {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.62rem;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--cinnabar);
    margin-bottom: 0.6rem;
}
.evidence article h3 {
    font-family: "Newsreader", serif;
    font-weight: 600;
    font-size: 1.15rem;
    margin: 0 0 0.5rem;
    color: var(--ink);
}
.evidence article p {
    font-size: 0.92rem;
    color: var(--ink-soft);
    line-height: 1.55;
    margin: 0;
}
.evidence article .specimen {
    margin-top: 1rem;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.72rem;
    color: var(--ink-faint);
    line-height: 1.7;
    padding-top: 0.8rem;
    border-top: 1px dashed var(--hairline);
}

/* Cardboard tape — a sage strip across the top of one card. */
.evidence article.tape::before {
    content: "";
    position: absolute;
    top: -1px;
    left: 1rem;
    right: 1rem;
    height: 6px;
    background: var(--sage);
    opacity: 0.7;
}
.evidence article.tape.red::before { background: var(--cinnabar); }
.evidence article.tape.amber::before { background: var(--amber); }

/* ============== FIELD-LAB CODE BLOCK ============== */

pre.field-log {
    background: var(--paper-shade);
    border: 1px solid var(--ink);
    border-left: 4px solid var(--cinnabar);
    padding: 1.25rem 1.5rem;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 0.84rem;
    line-height: 1.7;
    overflow-x: auto;
    color: var(--ink);
    border-radius: 0;
    margin: 1.5rem 0;
    position: relative;
}
pre.field-log::before {
    /* Lab notebook tab — green PASS strip at top corner. */
    content: "OBSERVED";
    position: absolute;
    top: -1px;
    right: -1px;
    background: var(--sage-deep);
    color: var(--paper);
    font-size: 0.6rem;
    letter-spacing: 0.18em;
    padding: 0.3rem 0.7rem;
    font-weight: 700;
}
.field-log .dim { color: var(--ink-faint); }
.field-log .red { color: var(--cinnabar); }
.field-log .green { color: var(--sage); }

code.inline {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.85em;
    background: var(--paper-shade);
    padding: 0.15em 0.45em;
    border: 1px solid var(--hairline);
    border-radius: 0;
    color: var(--ink);
}

/* ============== INSPECT FORM ============== */

form.inspect {
    display: flex;
    gap: 0;
    margin: 1.5rem 0 1rem;
    flex-wrap: wrap;
    border: 1px solid var(--ink);
    background: var(--paper);
    align-items: stretch;
}
form.inspect .specimen-tag {
    background: var(--ink);
    color: var(--paper);
    padding: 0.95rem 1.2rem;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.7rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    flex-shrink: 0;
}
form.inspect input[type="text"] {
    flex: 1;
    min-width: 220px;
    background: var(--paper);
    border: 0;
    color: var(--ink);
    padding: 0.9rem 1.1rem;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.95rem;
    outline: 0;
}
form.inspect input[type="text"]::placeholder {
    color: var(--ink-faint);
}
form.inspect input[type="text"]:focus {
    background: var(--marker-yellow);
}
form.inspect button {
    background: var(--cinnabar);
    color: var(--paper);
    border: 0;
    padding: 0.9rem 1.4rem;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    cursor: pointer;
    border-left: 1px solid var(--ink);
}
form.inspect button:hover {
    background: var(--cinnabar-deep);
}

.example-pills {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
    margin: 0 0 2rem;
    font-size: 0.78rem;
}
.example-pills .label {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.62rem;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--ink-faint);
    align-self: center;
    margin-right: 0.5rem;
}
.example-pills a {
    padding: 0.35rem 0.7rem;
    border: 1px solid var(--hairline);
    background: var(--paper);
    color: var(--ink-soft);
    text-decoration: none;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.75rem;
    transition: border-color 120ms ease, color 120ms ease;
}
.example-pills a:hover {
    color: var(--ink);
    border-color: var(--ink);
}

/* ============== RESULT — the verdict & report ============== */

.verdict {
    display: flex;
    align-items: center;
    gap: 1.5rem;
    padding: 1.5rem 1.6rem;
    border: 1px solid var(--ink);
    margin: 1.5rem 0;
    background: var(--paper);
    position: relative;
}
.verdict.attested { border-left: 6px solid var(--sage); }
.verdict.unattested { border-left: 6px solid var(--amber); }
.verdict.error { border-left: 6px solid var(--cinnabar); }

.verdict .seal {
    width: 4.5rem;
    height: 4.5rem;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 2px solid currentColor;
    border-radius: 50%;
    font-family: "JetBrains Mono", monospace;
    font-weight: 700;
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    transform: rotate(-6deg);
}
.verdict.attested .seal { color: var(--sage-deep); }
.verdict.unattested .seal { color: var(--amber-deep); }
.verdict.error .seal { color: var(--cinnabar-deep); }

.verdict .body { flex: 1; min-width: 0; }
.verdict .body .ttl {
    font-family: "Newsreader", serif;
    font-weight: 600;
    font-size: 1.1rem;
    color: var(--ink);
    margin: 0;
}
.verdict .body .sub {
    margin: 0.2rem 0 0;
    font-size: 0.9rem;
    color: var(--ink-soft);
}

.result-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1.5rem;
    border: 1px solid var(--ink);
    background: var(--paper);
}
.result-table th, .result-table td {
    text-align: left;
    padding: 0.85rem 1.1rem;
    border-bottom: 1px solid var(--hairline);
    vertical-align: top;
    font-size: 0.92rem;
}
.result-table tr:last-child th, .result-table tr:last-child td { border-bottom: 0; }
.result-table th {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.65rem;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--ink-faint);
    font-weight: 600;
    width: 11rem;
    background: var(--paper-shade);
    border-right: 1px solid var(--hairline);
}
.result-table td {
    font-family: "JetBrains Mono", monospace;
    word-break: break-all;
    color: var(--ink);
}

/* Hash group rule — adds visual rhythm to long hex strings. */
.hashgroup {
    display: inline;
    word-break: break-all;
    font-feature-settings: "ss01", "tnum";
}

.badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.15rem 0.6rem;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.65rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    font-weight: 700;
    border: 1px solid currentColor;
}
.badge.ok { color: var(--sage-deep); }
.badge.warn { color: var(--amber-deep); }
.badge.bad { color: var(--cinnabar-deep); }
.badge.info { color: var(--ink); }
.badge::before {
    content: "";
    width: 6px;
    height: 6px;
    background: currentColor;
    border-radius: 50%;
}

/* ============== HERO BANNER FRAME ============== */

.banner-frame {
    border: 1px solid var(--ink);
    padding: 0.4rem;
    background: var(--paper);
    margin: 2rem 0 1rem;
}
.banner-frame img { display: block; width: 100%; }

/* Hero demo-gif frame styled as an exhibit photograph. */
.exhibit {
    border: 1px solid var(--ink);
    background: var(--paper);
    padding: 0.5rem 0.5rem 1.2rem;
    margin: 1.5rem 0;
    position: relative;
}
.exhibit .caption-strip {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0.6rem;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.6rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--ink-faint);
    border-bottom: 1px dashed var(--hairline);
    margin-bottom: 0.5rem;
}
.exhibit img { display: block; width: 100%; }
.exhibit figcaption {
    margin: 0.8rem 0.5rem 0;
    font-family: "Newsreader", serif;
    font-style: italic;
    color: var(--ink-soft);
    font-size: 0.92rem;
}

/* ============== FOOTER ============== */

footer.dossier {
    margin-top: 3rem;
    padding: 2.5rem 0 4rem;
    border-top: 1px solid var(--ink);
    background: var(--paper-shade);
}
footer.dossier .wrap {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 1rem;
    flex-wrap: wrap;
}
footer.dossier .sig {
    font-family: "Newsreader", serif;
    font-style: italic;
    color: var(--ink-soft);
}
footer.dossier .meta {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.7rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--ink-faint);
}

/* ============== SCROLLBAR (paper edge) ============== */
::-webkit-scrollbar { width: 10px; }
::-webkit-scrollbar-track { background: var(--paper-shade); }
::-webkit-scrollbar-thumb {
    background: var(--ink-faint);
    border: 2px solid var(--paper-shade);
}
::-webkit-scrollbar-thumb:hover { background: var(--ink); }
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

                // Google Fonts — Newsreader (literary serif w/ italic), Geist
                // (clean grotesque body), JetBrains Mono (hash / evidence labels).
                // Preconnect speeds up the font CSS handshake.
                link rel="preconnect" href="https://fonts.googleapis.com";
                link rel="preconnect" href="https://fonts.gstatic.com" crossorigin;
                link
                    rel="stylesheet"
                    href="https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,400..700;1,6..72,400..600&family=Geist:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600;700&display=swap";

                style { (PreEscaped(STYLES)) }
            }
            body {
                header.dossier {
                    div.wrap {
                        a.brand href="/" {
                            "Clear" span.crosshatch { "#" } "hash"
                        }
                        nav.dossier-nav {
                            a href="/inspect" { "Inspect a package" }
                            a href="https://github.com/Builder106/ClearHash" { "Source ↗" }
                        }
                    }
                }
                (body)
                footer.dossier {
                    div.wrap {
                        span.sig { "Filed under supply-chain integrity. " span.case-label { "MIT-licensed" } "." }
                        span.meta {
                            "CLH-26 · "
                            a href="https://github.com/Builder106/ClearHash" style="color:inherit;text-decoration:underline;text-decoration-color:var(--cinnabar);" { "Github" }
                        }
                    }
                }

                // Vercel Web Analytics + Speed Insights.
                // Scripts are served by Vercel's edge at the canonical paths; they 404
                // harmlessly in local dev. Enable each in the Vercel dashboard
                // (clear-hash → Analytics → Enable, same for Speed Insights) for data to
                // start flowing.
                script { (PreEscaped("window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };")) }
                script defer src="/_vercel/insights/script.js" {}
                script { (PreEscaped("window.si = window.si || function () { (window.siq = window.siq || []).push(arguments); };")) }
                script defer src="/_vercel/speed-insights/script.js" {}
            }
        }
    }
}

/// Examiner-signed circular stamp — a tiny SVG rendered top-right of the hero.
/// Reads like the wax-impressed seal on the cover of a case file.
fn examiner_stamp() -> Markup {
    let svg = r##"<svg viewBox="0 0 180 180" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <path id="circ" d="M 90 90 m -68 0 a 68 68 0 1 1 136 0 a 68 68 0 1 1 -136 0" fill="none"/>
        </defs>
        <circle cx="90" cy="90" r="80" fill="none" stroke="currentColor" stroke-width="1.4"/>
        <circle cx="90" cy="90" r="68" fill="none" stroke="currentColor" stroke-width="0.6" stroke-dasharray="3 3"/>
        <text font-size="9.6">
            <textPath href="#circ" startOffset="2%">CASE NO. CLH-26 · EXAMINED &amp; FILED · SUPPLY-CHAIN INTEGRITY · </textPath>
        </text>
        <text x="90" y="86" text-anchor="middle" font-size="14" font-weight="700" letter-spacing="2">CLEARED</text>
        <text x="90" y="104" text-anchor="middle" font-size="9" letter-spacing="2">REBUILD ✕ COMPARE</text>
        <line x1="40" y1="118" x2="140" y2="118" stroke="currentColor" stroke-width="0.6"/>
        <text x="90" y="132" text-anchor="middle" font-size="7.5" letter-spacing="2">SLSA · SIGSTORE · REKOR</text>
    </svg>"##;
    html! {
        div.stamp { (PreEscaped(svg)) }
    }
}

/// Case-strip — the perforated dossier metadata bar that sits below the header
/// on the landing page. Looks like the header of a real evidence binder.
fn case_strip() -> Markup {
    html! {
        dl.case-strip {
            div {
                dt { "Case no." }
                dd { "CLH-26" }
            }
            div {
                dt { "Classification" }
                dd { "OPEN · PUBLIC" }
            }
            div {
                dt { "Subject" }
                dd { "Supply-chain integrity" }
            }
            div {
                dt { "Method" }
                dd { "Rebuild ✕ Compare" }
            }
        }
    }
}

pub async fn landing() -> Markup {
    layout(
        "ClearHash — supply-chain integrity verifier",
        html! {
            div.wrap {
                (case_strip())

                section.hero {
                    div.hero-row {
                        (examiner_stamp())

                        h1 {
                            "Don't just check signatures. "
                            span.accent-italic { "Rebuild the source." }
                        }

                        p.lede {
                            "ClearHash fetches a package, verifies its SLSA attestation through "
                            "Sigstore + Rekor, rebuilds it from the attested source commit in a "
                            "Docker container, and compares the rebuilt file tree against the "
                            "registry artifact. If anything differs, the install is blocked."
                        }

                        div.cta {
                            a.btn.primary href="/inspect" { "Inspect a package" span aria-hidden="true" { "→" } }
                            a.btn.secondary href="https://github.com/Builder106/ClearHash" { "Source on GitHub ↗" }
                        }
                    }

                    div.banner-frame {
                        picture {
                            source media="(prefers-color-scheme: dark)" srcset="/assets/banner-dark.png";
                            source media="(prefers-color-scheme: light)" srcset="/assets/banner-light.png";
                            img src="/assets/banner-light.png" alt="ClearHash";
                        }
                    }
                }

                section {
                    div.section-mark {
                        span.num { "§ 01" }
                        span.ttl { "Exhibit A · Live verify run" }
                        span.rule {}
                    }
                    h2 { "A real run against " em { "npm:sigstore@2.3.1" } "." }
                    p {
                        "Full pipeline in ~36 seconds (shown at 4× playback). "
                        "The fetch, the attestation parse, the Docker rebuild, the tree-diff — "
                        "every step is in the recording, in order."
                    }
                    figure.exhibit {
                        div.caption-strip {
                            span { "Exhibit A — verify, npm:sigstore@2.3.1" }
                            span { "CLH-26 · 1 / 1" }
                        }
                        img src="/assets/demo-verify.gif" alt="verify demo";
                        figcaption {
                            "The rebuild reproduces the registry artifact byte-for-byte. "
                            "Result: MATCH, tree-hash logged."
                        }
                    }
                }

                section {
                    div.section-mark {
                        span.num { "§ 02" }
                        span.ttl { "Method of examination" }
                        span.rule {}
                    }
                    h2 { "What it catches — and how." }
                    p {
                        "The supply-chain attacks of the last five years (event-stream, ua-parser-js, "
                        "the post-install crypto-wallet stealers, xz-utils) all share one shape: the "
                        "registry tarball diverges from the source repo. Existing tools verify "
                        em { "who" } " signed the tarball, or that the tarball matches itself across "
                        "mirrors — but not whether the tarball is what the source code would produce. "
                        "ClearHash does the rebuild and the comparison."
                    }
                    div.evidence {
                        article.tape {
                            div.file-no { "§ 02.A" }
                            h3 { "Sigstore + Rekor" }
                            p {
                                "Verifies the SLSA attestation envelope, extracts the Fulcio-issued "
                                "leaf cert, cross-checks the workflow URI against the attested source "
                                "repo, and confirms a Rekor transparency-log entry."
                            }
                            div.specimen {
                                "specimen: rekor_log_index"
                                br;
                                "→ 94,408,136"
                            }
                        }
                        article.tape {
                            div.file-no { "§ 02.B" }
                            h3 { "Real rebuild" }
                            p {
                                "Clones the attested commit, pins HEAD, runs the ecosystem's build "
                                "script (npm ci + npm pack) in a Docker container — with "
                                code.inline { "--ignore-scripts" } " to block lifecycle hooks."
                            }
                            div.specimen {
                                "specimen: commit_sha"
                                br;
                                "→ 46e7056ff991…"
                            }
                        }
                        article.tape.red {
                            div.file-no { "§ 02.C" }
                            h3 { "File-tree compare" }
                            p {
                                "Normalises both archives (strips mtimes, scrubs npm-injected "
                                "metadata), Merkle-hashes the file trees, and surfaces per-file diffs "
                                "on mismatch."
                            }
                            div.specimen {
                                "specimen: tree_hash"
                                br;
                                "→ ec714016d7e4ce74…"
                            }
                        }
                    }
                }

                section {
                    div.section-mark {
                        span.num { "§ 03" }
                        span.ttl { "Field-lab instructions" }
                        span.rule {}
                    }
                    h2 { "Install the CLI." }
                    p {
                        "The full verify pipeline needs a running Docker daemon (Docker Desktop or "
                        "OrbStack on macOS). The "
                        a href="/inspect" style="color:var(--cinnabar);text-decoration:none;border-bottom:1px solid currentColor;" {
                            code.inline { "/inspect" }
                        }
                        " endpoint on this site runs the fetch + attestation parse parts without Docker."
                    }
                    pre.field-log {
                        (PreEscaped("<span class=\"dim\"># clone &amp; install</span>
<span class=\"red\">git</span> clone https://github.com/Builder106/ClearHash.git
<span class=\"red\">cd</span> ClearHash
<span class=\"red\">cargo</span> install --path crates/clearhash-cli

<span class=\"dim\"># first verify run</span>
<span class=\"green\">clearhash</span> verify npm:sigstore@2.3.1"))
                    }
                }

                section {
                    div.section-mark {
                        span.num { "§ 04" }
                        span.ttl { "Programmatic specimen request" }
                        span.rule {}
                    }
                    h2 { "API." }
                    p { "Programmatic access to the inspect endpoint:" }
                    pre.field-log {
                        (PreEscaped("$ <span class=\"red\">curl</span> 'https://clear-hash.vercel.app/api/inspect?package=npm:sigstore@2.3.1'
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
}"))
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
                (case_strip())

                section {
                    div.section-mark {
                        span.num { "§ 00" }
                        span.ttl { "Specimen intake form" }
                        span.rule {}
                    }
                    h2 { "Inspect a package." }
                    p {
                        "Fetches the artifact, parses its SLSA attestation, validates the "
                        "certificate chain. No rebuild. Use the CLI for the full byte-by-byte verify."
                    }
                    (inspect_form(""))
                }
            }
        },
    )
}

pub fn inspect_result(package: &str, result: &InspectResult) -> Markup {
    let (verdict_class, seal_text, verdict_title, verdict_sub) = match &result.attestation {
        Some(_) => (
            "attested",
            "ATTESTED",
            "Attestation verified.",
            "Fulcio leaf cert, Rekor transparency-log entry, workflow URI cross-checked against source repo.",
        ),
        None => (
            "unattested",
            "NO ATT.",
            "No attestation on file.",
            "The CLI's verify refuses to rebuild without --allow-unattested.",
        ),
    };
    let latest_badge = if result.inferred_latest {
        html! { " " span.badge.info { "resolved → latest" } }
    } else {
        html! {}
    };
    let prefill: &str = if result.inferred_latest {
        &result.package
    } else {
        package
    };
    layout(
        &format!("ClearHash · {}", result.package),
        html! {
            div.wrap {
                (case_strip())

                section {
                    div.section-mark {
                        span.num { "§ 00" }
                        span.ttl { "Specimen intake form" }
                        span.rule {}
                    }
                    h2 { "Inspect a package." }
                    (inspect_form(prefill))

                    div class=(format!("verdict {}", verdict_class)) {
                        div.seal { (seal_text) }
                        div.body {
                            p.ttl { (verdict_title) " " (latest_badge) }
                            p.sub { (verdict_sub) }
                        }
                    }

                    table.result-table {
                        tr { th { "Package" } td { (result.package) } }
                        tr { th { "Registry SHA-256" } td { span.hashgroup { (result.registry_sha256) } } }
                        @if let Some(a) = &result.attestation {
                            tr { th { "Source repo" } td { (a.source_repo) } }
                            tr { th { "Commit" } td { span.hashgroup { (a.commit_sha) } } }
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
                                    "This package has no SLSA attestation. The CLI's "
                                    code.inline { "verify" }
                                    " refuses to rebuild it without "
                                    code.inline { "--allow-unattested" } "."
                                }
                            }
                        }
                    }

                    p style="margin-top:1.5rem; font-family:'JetBrains Mono',monospace; font-size:0.78rem; color:var(--ink-faint); letter-spacing:0.12em; text-transform:uppercase;" {
                        "JSON · "
                        code.inline { "GET /api/inspect?package=" (package) }
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
                (case_strip())

                section {
                    div.section-mark {
                        span.num { "§ 00" }
                        span.ttl { "Specimen intake form" }
                        span.rule {}
                    }
                    h2 { "Inspect a package." }
                    (inspect_form(package))

                    div.verdict.error {
                        div.seal { "ERROR " (err.status) }
                        div.body {
                            p.ttl { "Specimen rejected." }
                            p.sub { (err.message) }
                        }
                    }

                    table.result-table {
                        tr { th { "Package" } td { (package) } }
                        tr { th { "Status" } td { (err.status) } }
                        tr { th { "Detail" } td { (err.message) } }
                    }
                }
            }
        },
    )
}

fn inspect_form(prefill: &str) -> Markup {
    html! {
        form.inspect method="get" action="/inspect" {
            span.specimen-tag { "Specimen" }
            input
                type="text"
                name="package"
                placeholder="npm:sigstore@2.3.1"
                value=(prefill)
                autocomplete="off"
                autofocus?[prefill.is_empty()] ;
            button type="submit" { "Inspect →" }
        }
        div.example-pills {
            span.label { "Examples →" }
            a href="/inspect?package=npm:sigstore@2.3.1" { "npm:sigstore@2.3.1" }
            a href="/inspect?package=npm:@sigstore/sign" title="no version → latest" { "npm:@sigstore/sign (latest)" }
            a href="/inspect?package=npm:left-pad@1.3.0" { "npm:left-pad@1.3.0 (unattested)" }
        }
    }
}
