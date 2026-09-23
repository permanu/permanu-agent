-- Agent-only additions to the normative schema (signed-plan.md 6.4 allows new
-- tables and trailing nullable columns). The runner never reads these.

-- NULL when the store was created in bootstrap state (no trusted-keys.json,
-- so no plan can have been admitted before); else store_created_at + 1200 s.
ALTER TABLE meta ADD COLUMN quarantine_ends_at TEXT;

-- Last admitted spec per service: the spec of its most recent admitted
-- deploy, rollback or scale (section 3.7), for rule deploys and restarts.
CREATE TABLE service_specs (
  service_id      TEXT PRIMARY KEY,
  spec_digest_hex TEXT NOT NULL REFERENCES specs (spec_digest_hex),
  plan_id         TEXT NOT NULL REFERENCES admissions (plan_id),
  admitted_at     TEXT NOT NULL
);

-- Commit each service last deployed per ref (section 3.5 step 4, 6.1 step 12).
CREATE TABLE deployed_commits (
  service_id  TEXT NOT NULL,
  ref         TEXT NOT NULL,
  commit_sha  TEXT NOT NULL,
  commit_time TEXT NOT NULL,
  plan_id     TEXT NOT NULL REFERENCES admissions (plan_id),
  PRIMARY KEY (service_id, ref)
);

-- WatchOperation replay (agent-protocol.md 6: kept 7 days). `event` is the
-- base64 of the encoded permanu.agent.v2.OperationEvent.
CREATE TABLE operation_events (
  operation_id TEXT    NOT NULL,
  seq          INTEGER NOT NULL CHECK (seq >= 1),
  at           TEXT    NOT NULL,
  event        TEXT    NOT NULL,
  PRIMARY KEY (operation_id, seq)
);
CREATE INDEX operation_events_at ON operation_events (at);
