"""Tests for hv_analysis.

Reference values come from R 4.6.1 (`prop.test(..., correct = FALSE)`,
`binom.test`, `p.adjust(..., "holm")`) and from a separate R implementation of
Newcombe's method 10. The ledgers below are hand-written fixtures, not study
data.
"""

import unittest

import hv_analysis as hv


class Statistics(unittest.TestCase):
    def test_wilson_matches_r(self):
        lower, upper = hv.wilson(81, 263)
        self.assertAlmostEqual(lower, 0.255288519878274, places=12)
        self.assertAlmostEqual(upper, 0.366209576982800, places=12)
        lower, upper = hv.wilson(0, 20)
        self.assertAlmostEqual(lower, 0.0, places=12)
        self.assertAlmostEqual(upper, 0.161125158052819, places=12)

    def test_exact_mcnemar_matches_r_binom_test(self):
        self.assertAlmostEqual(hv.mcnemar_exact(1, 9), 0.021484375, places=12)
        self.assertAlmostEqual(hv.mcnemar_exact(7, 2), 0.1796875, places=12)
        self.assertEqual(hv.mcnemar_exact(0, 0), 1.0)
        self.assertEqual(hv.mcnemar_exact(5, 5), 1.0)

    def test_holm_matches_r(self):
        self.assertEqual(hv.holm([0.01, 0.04]), [0.02, 0.04])
        for got, want in zip(hv.holm([0.03, 0.01, 0.20]), [0.06, 0.03, 0.20]):
            self.assertAlmostEqual(got, want, places=12)

    def test_newcombe_matches_the_r_implementation(self):
        for cells, want in [
            ((12, 9, 2, 21), (0.159090909090909, 0.018210226243592, 0.289156659588272)),
            ((300, 40, 5, 255), (0.058333333333333, 0.036893306775815, 0.079588401349626)),
        ]:
            for got, expected in zip(hv.newcombe_paired(*cells), want):
                self.assertAlmostEqual(got, expected, places=12)

    def test_newcombe_is_antisymmetric_and_bounded(self):
        theta, lower, upper = hv.newcombe_paired(30, 4, 11, 55)
        swapped = hv.newcombe_paired(30, 11, 4, 55)
        self.assertAlmostEqual(theta, -swapped[0], places=12)
        self.assertAlmostEqual(lower, -swapped[2], places=12)
        self.assertAlmostEqual(upper, -swapped[1], places=12)
        self.assertTrue(-1 <= lower <= theta <= upper <= 1)
        theta, lower, upper = hv.newcombe_paired(0, 0, 0, 10)
        self.assertEqual(theta, 0.0)
        self.assertTrue(lower <= 0 <= upper)

    def test_repository_keys_ignore_prefix_ref_case_and_suffix(self):
        for url in [
            "git+https://github.com/Owner/Repo.git@refs/heads/main",
            "https://github.com/owner/repo",
            "https://github.com/owner/repo/",
        ]:
            self.assertEqual(hv.repository(url), "github.com/owner/repo")


def record(system, name, arm, stage, t1=None, t0=None, **extra):
    """Hand-written fixture record in the ledger's shape."""
    row = {
        "system": system,
        "name": name,
        "version": "1.0.0",
        "arm": arm,
        "stage": stage,
        "tool_commit": "fixture",
    }
    if stage == "compared":
        row["t1"] = {"matched": t1}
        row["t0"] = {"matched": t0 if t0 is not None else t1}
    row.update(extra)
    return row


def fixture_release(system, name, repo):
    return {"system": system, "name": name, "version": "1.0.0", "source_repo": repo}


class Analysis(unittest.TestCase):
    def test_last_record_wins_and_infrastructure_releases_are_missing(self):
        sample = [fixture_release("NPM", "a", "https://github.com/x/a"),
                  fixture_release("NPM", "b", "https://github.com/x/b")]
        ledger = [
            record("NPM", "a", "h", "infrastructure"),
            record("NPM", "a", "h", "compared", t1=True),
            record("NPM", "a", "n", "compared", t1=True),
            record("NPM", "a", "i", "compared", t1=True, lock_source="committed"),
            record("NPM", "b", "h", "lock"),
            record("NPM", "b", "n", "compared", t1=True),
            record("NPM", "b", "i", "infrastructure"),
        ]
        results = hv.analyse(sample, ledger)
        npm = results["ecosystems"]["NPM"]
        self.assertEqual(npm["releases_complete"], 1)
        self.assertEqual(results["missing"]["NPM"], ["b@1.0.0"])
        self.assertEqual(npm["arms"]["h"]["t1_matches"], 1)
        self.assertEqual(npm["arm_i_lock_source"], {"committed": 1})

    def test_degenerate_ecosystems_are_descriptive_and_holm_covers_the_rest(self):
        sample, ledger = [], []
        # NPM fixture: 12 releases match in every arm, 8 match only with the network.
        for k in range(20):
            name = f"npm-{k}"
            sample.append(fixture_release("NPM", name, f"https://github.com/x/{name}"))
            ledger += [
                record("NPM", name, "h", "compared" if k < 12 else "lock", t1=k < 12),
                record("NPM", name, "n", "compared", t1=True),
                record("NPM", name, "i", "compared", t1=k < 12),
            ]
        # PYPI fixture: nothing matches without the network.
        for k in range(5):
            name = f"py-{k}"
            sample.append(fixture_release("PYPI", name, f"https://github.com/y/{name}"))
            ledger += [
                record("PYPI", name, "h", "lock"),
                record("PYPI", name, "n", "compared", t1=True),
                record("PYPI", name, "i", "compared", t1=True),
            ]
        results = hv.analyse(sample, ledger)
        npm = results["ecosystems"]["NPM"]["primary_n_minus_h"]
        pypi = results["ecosystems"]["PYPI"]["primary_n_minus_h"]
        self.assertTrue(npm["confirmatory"])
        self.assertFalse(pypi["confirmatory"])
        self.assertNotIn("holm_p", pypi)
        self.assertEqual(npm["table"], {"both": 12, "only_n": 8, "only_h": 0, "neither": 0})
        self.assertAlmostEqual(npm["difference"], 0.4)
        # One tested ecosystem: the Holm p-value equals the raw p-value.
        self.assertAlmostEqual(npm["holm_p"], npm["mcnemar_exact_p"])
        self.assertAlmostEqual(npm["mcnemar_exact_p"], 2 / 2**8)

    def test_clustering_counts_each_repository_once(self):
        sample, ledger = [], []
        # Fixture: five releases from one monorepo that only match with the network,
        # and five single-release repositories that match in both arms.
        for k in range(10):
            name = f"pkg-{k}"
            repo = "https://github.com/mono/repo" if k < 5 else f"https://github.com/solo/{name}"
            sample.append(fixture_release("NPM", name, repo))
            ledger += [
                record("NPM", name, "h", "compared" if k >= 5 else "build", t1=k >= 5),
                record("NPM", name, "n", "compared", t1=True),
                record("NPM", name, "i", "compared", t1=True),
            ]
        clustering = hv.analyse(sample, ledger)["ecosystems"]["NPM"]["clustering"]
        once = clustering["one_per_repository"]
        self.assertEqual(once["table"], {"both": 5, "only_n": 1, "only_h": 0, "neither": 0})
        boot = clustering["cluster_bootstrap_n_minus_h"]
        self.assertEqual(boot["repositories"], 6)
        lower, upper = boot["ci95"]
        self.assertTrue(0 <= lower <= 0.5 <= upper <= 1)
        # The resampling is seeded, so a rerun gives the same interval.
        again = hv.analyse(sample, ledger)["ecosystems"]["NPM"]["clustering"]
        self.assertEqual(again["cluster_bootstrap_n_minus_h"]["ci95"], boot["ci95"])


if __name__ == "__main__":
    unittest.main()
