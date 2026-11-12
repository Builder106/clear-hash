-- Sampling frame and ordered draw for docs/specs/hermetic-verifiability.md.
-- Parameters: @system (NPM or PYPI), @seed (draw seed string), @limit.
-- One release per package: the latest version with a verified attestation
-- that names a commit, uploaded on or before 2026-10-31 23:59:59 UTC.
-- The 2026-11-09 snapshot partition is selected by range, because an
-- equality test on its displayed timestamp matches no rows.
WITH attested AS (
  SELECT
    v.System AS system,
    v.Name AS name,
    v.Version AS version,
    v.UpstreamPublishedAt AS published,
    a.URL AS attestation_url,
    a.SourceRepository AS source_repo,
    a.Commit AS commit
  FROM `bigquery-public-data.deps_dev_v1.PackageVersions` AS v, UNNEST(v.Attestations) AS a
  WHERE v.SnapshotAt >= TIMESTAMP('2026-11-09')
    AND v.SnapshotAt < TIMESTAMP('2026-11-10')
    AND v.System = @system
    AND a.Verified
    AND a.Commit IS NOT NULL
    AND v.UpstreamPublishedAt <= TIMESTAMP('2026-10-31 23:59:59+00')
),
latest AS (
  SELECT *
  FROM attested
  QUALIFY ROW_NUMBER() OVER (
    PARTITION BY name
    ORDER BY published DESC, version DESC, attestation_url
  ) = 1
)
SELECT
  system,
  name,
  version,
  FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', published, 'UTC') AS published_at,
  attestation_url,
  source_repo,
  commit
FROM latest
ORDER BY FARM_FINGERPRINT(CONCAT(@seed, system, name))
LIMIT @limit
