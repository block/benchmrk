-- Pin the scorer to each run so F1 numbers are only compared across runs
-- that used the same matcher logic and the same annotation set.
--
--   matcher_version   bumped manually in internal/analysis/version.go
--                     whenever matching semantics change. NULL on rows
--                     scored before this migration — which is the correct
--                     signal: "unknown scorer, don't compare."
--
--   annotation_hash   SHA-256 of a deterministic serialization of the
--                     project's annotations+groups at the moment MatchRun
--                     stamps the row. Two runs with different hashes were
--                     graded against different ground truth.
--
-- Both stamped at MatchRun time, not at experiment-run time: the scorer
-- that matters is the one that produced finding_matches, not the one that
-- was current when the scanner ran.

ALTER TABLE runs ADD COLUMN matcher_version TEXT;
ALTER TABLE runs ADD COLUMN annotation_hash TEXT;
