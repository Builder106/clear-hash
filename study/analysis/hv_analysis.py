"""Analysis for docs/specs/hermetic-verifiability.md.

Reads the study sample and ledger and reports, per ecosystem:

- T1 and T0 match rates in each arm, with Wilson 95% intervals;
- the paired arm N minus arm H difference with a Newcombe (1998, method 10)
  interval and an exact McNemar test, Holm-corrected across ecosystems;
- the degenerate-case rule: an ecosystem with fewer than 10 arm H T1 matches
  is reported descriptively and left out of the test family;
- secondary paired differences (I minus H, N minus I), outside the family;
- the repository clustering check (cluster bootstrap, and one release per
  repository in draw order);
- stage outcomes per arm and arm I lock sources.

Rerun ledgers (the plan's source retry and pinned-release rerun) are given in
the order they were applied. A release that appears in one has all its arms
replaced by the rerun's records, whatever the outcome.

Standard library only, so the analysis has nothing to install.

Usage:
    python hv_analysis.py --sample SAMPLE.jsonl --ledger LEDGER.jsonl \
        [--rerun RERUN.jsonl ...] [--screened PYPI-SCREENED.jsonl] \
        [--out RESULTS.json]
"""

import argparse
import collections
import json
import math
import random
import re
import statistics
import sys
from fractions import Fraction

ARMS = ("h", "n", "i")
Z = statistics.NormalDist().inv_cdf(0.975)
DEGENERATE_BELOW = 10
BOOTSTRAP_RESAMPLES = 4000
BOOTSTRAP_SEED = "clearhash-hv-2026-11"
ALPHA = 0.05


def read_jsonl(path):
    with open(path) as handle:
        return [json.loads(line) for line in handle if line.strip()]


def wilson(successes, n):
    """Wilson score interval for one proportion (no continuity correction)."""
    if n == 0:
        return (math.nan, math.nan)
    p = successes / n
    centre = (p + Z * Z / (2 * n)) / (1 + Z * Z / n)
    half = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / (1 + Z * Z / n)
    return (max(0.0, centre - half), min(1.0, centre + half))


def mcnemar_exact(b, c):
    """Two-sided exact McNemar p-value: a binomial test on the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(min(b, c) + 1))
    return min(1.0, float(Fraction(2 * tail, 2**n)))


def newcombe_paired(a, b, c, d):
    """Difference p1 - p2 for paired proportions, p1 = (a+b)/n and p2 = (a+c)/n.

    a: both succeed; b: only the first succeeds; c: only the second; d: neither.
    Returns (difference, lower, upper) using Newcombe's method 10.
    """
    n = a + b + c + d
    if n == 0:
        return (math.nan, math.nan, math.nan)
    p1, p2 = (a + b) / n, (a + c) / n
    l1, u1 = wilson(a + b, n)
    l2, u2 = wilson(a + c, n)
    denominator = (a + b) * (c + d) * (a + c) * (b + d)
    phi = (a * d - b * c) / math.sqrt(denominator) if denominator else 0.0
    theta = (b - c) / n
    lower = theta - math.sqrt(
        (p1 - l1) ** 2 - 2 * phi * (p1 - l1) * (u2 - p2) + (u2 - p2) ** 2
    )
    upper = theta + math.sqrt(
        (u1 - p1) ** 2 - 2 * phi * (u1 - p1) * (p2 - l2) + (p2 - l2) ** 2
    )
    return (theta, max(-1.0, lower), min(1.0, upper))


def holm(pvalues):
    """Holm step-down adjusted p-values, in the input order."""
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    adjusted = [0.0] * len(pvalues)
    running = 0.0
    for rank, index in enumerate(order):
        running = max(running, min(1.0, (len(pvalues) - rank) * pvalues[index]))
        adjusted[index] = running
    return adjusted


def repository(url):
    """Repository key for clustering: host and path, lower case, no ref or .git."""
    url = re.sub(r"^git\+", "", url or "").split("@refs/")[0].split("#")[0]
    url = re.sub(r"^[a-z]+://", "", url.lower()).rstrip("/")
    return re.sub(r"\.git$", "", url)


def final_records(ledger, reruns=()):
    """Last record per (system, name, version, arm). The driver appends a new
    record when it reruns an infrastructure failure, so the last one counts.

    Each rerun ledger then replaces every arm of each release it contains.
    Returns the records and, per rerun ledger, the releases it replaced.
    """
    def latest(records):
        out = {}
        for record in records:
            out[(record["system"], record["name"], record["version"], record["arm"])] = record
        return out

    final = latest(ledger)
    replaced = []
    for rerun in reruns:
        newer = latest(rerun)
        releases = {key[:3] for key in newer}
        final = {key: r for key, r in final.items() if key[:3] not in releases}
        final.update(newer)
        replaced.append(sorted(f"{system}:{name}@{version}" for system, name, version in releases))
    return final, replaced


def matched(record, level):
    comparison = record.get(level) if record["stage"] == "compared" else None
    return bool(comparison and comparison.get("matched"))


def paired(rows, first, second, level="t1"):
    """2x2 counts (a, b, c, d) for arm `first` against arm `second`."""
    a = b = c = d = 0
    for arms in rows:
        x, y = matched(arms[first], level), matched(arms[second], level)
        a += x and y
        b += x and not y
        c += y and not x
        d += not x and not y
    return a, b, c, d


def describe_pair(rows, first, second):
    a, b, c, d = paired(rows, first, second)
    theta, lower, upper = newcombe_paired(a, b, c, d)
    return {
        "table": {"both": a, "only_" + first: b, "only_" + second: c, "neither": d},
        "difference": theta,
        "ci95": [lower, upper],
        "mcnemar_exact_p": mcnemar_exact(b, c),
    }


def cluster_bootstrap(rows, keys, first, second):
    """Percentile 95% interval for the paired difference, resampling repositories."""
    clusters = collections.defaultdict(list)
    for arms, key in zip(rows, keys):
        clusters[key].append(
            int(matched(arms[first], "t1")) - int(matched(arms[second], "t1"))
        )
    groups = [(sum(v), len(v)) for v in clusters.values()]
    rng = random.Random(BOOTSTRAP_SEED)
    estimates = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        total = size = 0
        for _ in groups:
            difference, count = groups[rng.randrange(len(groups))]
            total += difference
            size += count
        estimates.append(total / size)
    estimates.sort()
    low = estimates[int(0.025 * BOOTSTRAP_RESAMPLES)]
    high = estimates[int(0.975 * BOOTSTRAP_RESAMPLES) - 1]
    return {"repositories": len(groups), "resamples": BOOTSTRAP_RESAMPLES, "ci95": [low, high]}


def analyse(sample, ledger, screened=None, reruns=()):
    final, replaced = final_records(ledger, reruns)
    results = {"ecosystems": {}, "missing": {}, "rerun_releases": replaced}
    tested = []
    for system in sorted({r["system"] for r in sample}):
        releases = [r for r in sample if r["system"] == system]
        rows, keys, missing = [], [], []
        for release in releases:
            arms = {
                arm: final.get((system, release["name"], release["version"], arm))
                for arm in ARMS
            }
            if any(r is None or r["stage"] == "infrastructure" for r in arms.values()):
                missing.append(f"{release['name']}@{release['version']}")
                continue
            rows.append(arms)
            keys.append(repository(release["source_repo"]))
        n = len(rows)
        summary = {"releases_drawn": len(releases), "releases_complete": n, "arms": {}}
        for arm in ARMS:
            stages = collections.Counter(r[arm]["stage"] for r in rows)
            t1 = sum(matched(r[arm], "t1") for r in rows)
            t0 = sum(matched(r[arm], "t0") for r in rows)
            summary["arms"][arm] = {
                "t1_matches": t1,
                "t1_rate": t1 / n if n else math.nan,
                "t1_wilson95": list(wilson(t1, n)),
                "t0_matches": t0,
                "t0_rate": t0 / n if n else math.nan,
                "t0_wilson95": list(wilson(t0, n)),
                "stages": dict(sorted(stages.items())),
            }
        summary["arm_i_lock_source"] = dict(
            collections.Counter(r["i"].get("lock_source") or "none" for r in rows)
        )
        primary = describe_pair(rows, "n", "h")
        degenerate = summary["arms"]["h"]["t1_matches"] < DEGENERATE_BELOW
        primary["confirmatory"] = not degenerate
        summary["primary_n_minus_h"] = primary
        summary["secondary"] = {
            "i_minus_h": describe_pair(rows, "i", "h"),
            "n_minus_i": describe_pair(rows, "n", "i"),
        }
        first_seen = {}
        for arms, key in zip(rows, keys):
            first_seen.setdefault(key, arms)
        summary["clustering"] = {
            "cluster_bootstrap_n_minus_h": cluster_bootstrap(rows, keys, "n", "h"),
            "one_per_repository": describe_pair(list(first_seen.values()), "n", "h"),
        }
        if not degenerate:
            tested.append(system)
        results["ecosystems"][system] = summary
        results["missing"][system] = missing
    adjusted = holm([results["ecosystems"][s]["primary_n_minus_h"]["mcnemar_exact_p"] for s in tested])
    for system, p in zip(tested, adjusted):
        primary = results["ecosystems"][system]["primary_n_minus_h"]
        primary["holm_p"] = p
        primary["reject_at_alpha"] = p < ALPHA
    if screened is not None:
        results["pypi_screening"] = dict(collections.Counter(r["decision"] for r in screened))
    results["tool_commits"] = sorted({r["tool_commit"] for r in final.values()})
    return results


def percent(x):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{100 * x:.1f}%"


def report(results):
    lines = []
    for system, s in results["ecosystems"].items():
        lines.append(f"## {system}: {s['releases_complete']} of {s['releases_drawn']} releases complete")
        for arm in ARMS:
            a = s["arms"][arm]
            lo, hi = a["t1_wilson95"]
            lines.append(
                f"- arm {arm.upper()}: T1 {a['t1_matches']} ({percent(a['t1_rate'])}, "
                f"{percent(lo)} to {percent(hi)}); T0 {a['t0_matches']}"
            )
        p = s["primary_n_minus_h"]
        lo, hi = p["ci95"]
        label = "confirmatory" if p["confirmatory"] else "descriptive (fewer than 10 arm H matches)"
        lines.append(
            f"- N minus H: {percent(p['difference'])} ({percent(lo)} to {percent(hi)}), "
            f"exact McNemar p = {p['mcnemar_exact_p']:.3g}, {label}"
            + (f", Holm p = {p['holm_p']:.3g}" if "holm_p" in p else "")
        )
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sample", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--rerun", action="append", default=[],
                        help="rerun ledger, in the order applied; repeatable")
    parser.add_argument("--screened")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    results = analyse(
        read_jsonl(args.sample),
        read_jsonl(args.ledger),
        read_jsonl(args.screened) if args.screened else None,
        [read_jsonl(path) for path in args.rerun],
    )
    if args.out:
        with open(args.out, "w") as handle:
            json.dump(results, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(report(results))


if __name__ == "__main__":
    sys.exit(main())
