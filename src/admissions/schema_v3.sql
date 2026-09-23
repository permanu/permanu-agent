-- signed-plan.md 6.4 v1.0.8 DDL (contracts v1.1.0, migration stated in
-- v1.0.10, D-060): the 14th table `rejected_deliveries` and the reshaped
-- `deliveries`. Runs with foreign_keys OFF inside one BEGIN IMMEDIATE
-- transaction (`migrate`), then `PRAGMA foreign_key_check`.
CREATE TABLE rejected_deliveries (
  body_digest_hex TEXT NOT NULL,
  body_bytes      INTEGER NOT NULL,
  project_id      TEXT NOT NULL,                    -- the path's project id, as received
  provider        TEXT NOT NULL DEFAULT '',
  received_at     TEXT NOT NULL,
  reason          TEXT NOT NULL CHECK (reason IN ('signature', 'unknown_project', 'malformed'))
);
CREATE INDEX rejected_deliveries_received ON rejected_deliveries (received_at);

CREATE TABLE deliveries_v3 (
  delivery_id     TEXT PRIMARY KEY,                 -- UUIDv7 minted by the agent
  provider        TEXT NOT NULL CHECK (provider IN ('github', 'gitlab', 'gitea')),
  event           TEXT NOT NULL DEFAULT 'push',     -- v1.0.8: provider event; non-push events end 'ignored'
  body_digest_hex TEXT NOT NULL UNIQUE,             -- DUPLICATE on conflict
  repo            TEXT NOT NULL,
  ref             TEXT NOT NULL,
  commit_sha      TEXT NOT NULL,
  commit_time     TEXT NOT NULL,
  environments    TEXT NOT NULL DEFAULT '[]',       -- v1.0.8: JSON array of the environments whose secret matched
  received_at     TEXT NOT NULL,
  expires_at      TEXT NOT NULL,                    -- v1.0.8: received_at + 7 days (pending -> expired)
  status          TEXT NOT NULL CHECK (status IN ('pending', 'building', 'deployed', 'ignored', 'stale',
                                                  'failed', 'expired'))  -- v1.0.8: agent-protocol.md 11.1
);
INSERT INTO deliveries_v3 (delivery_id, provider, event, body_digest_hex, repo, ref, commit_sha, commit_time,
                           environments, received_at, expires_at, status)
SELECT delivery_id, provider, 'push', body_digest_hex, repo, ref, commit_sha, commit_time, '[]', received_at,
       strftime('%Y-%m-%dT%H:%M:%SZ', received_at, '+7 days'),
       CASE status
         WHEN 'verified' THEN CASE WHEN strftime('%Y-%m-%dT%H:%M:%SZ', received_at, '+7 days') <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                                   THEN 'expired' ELSE 'pending' END
         ELSE status
       END
FROM deliveries;
DROP TABLE deliveries;
ALTER TABLE deliveries_v3 RENAME TO deliveries;
CREATE INDEX deliveries_received ON deliveries (received_at);
UPDATE meta SET schema_version = 3;
