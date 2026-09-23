-- One row, written when the store is created (section 6.3 quarantine).
CREATE TABLE meta (
  id               INTEGER PRIMARY KEY CHECK (id = 1),
  store_created_at TEXT    NOT NULL,              -- quarantine ends 1200 s later
  schema_version   INTEGER NOT NULL DEFAULT 1
);

-- Replay reservations (section 6.1 step 8). Pruned once now > expires_at + 120 s.
CREATE TABLE seen (
  nonce           TEXT PRIMARY KEY,
  plan_id         TEXT NOT NULL UNIQUE,
  plan_digest_hex TEXT NOT NULL,
  expires_at      TEXT NOT NULL
);

-- One row per admitted plan; the server's audit log. Never deleted.
CREATE TABLE admissions (
  plan_id          TEXT PRIMARY KEY,                -- R
  plan_digest_hex  TEXT NOT NULL,                   -- R
  signed_plan_json TEXT NOT NULL,                   -- R  the envelope exactly as submitted (<= 64 KiB)
  submitter        TEXT NOT NULL                    -- R
                   CHECK (submitter IN ('client', 'agent_webhook')),
  operation_id     TEXT NOT NULL UNIQUE,
  admitted_at      TEXT NOT NULL,                   -- R  execution window ends admitted_at + 60 min
  finished_at      TEXT,                            -- R  NULL until every action has a result
  outcome          TEXT NOT NULL DEFAULT ''         -- R
                   CHECK (outcome IN ('', 'succeeded', 'failed', 'rolled_back', 'cancelled', 'expired')),
  admission_seq    INTEGER NOT NULL UNIQUE,         -- ascending admission order; ListAdmissions position
  nonce            TEXT NOT NULL UNIQUE,
  author_kind      TEXT NOT NULL CHECK (author_kind IN ('user', 'agent-draft', 'rule')),
  signer_key_ids   TEXT NOT NULL,                   -- JSON array, [] for rule plans
  action_kinds     TEXT NOT NULL,                   -- JSON array in action order
  project_id       TEXT NOT NULL DEFAULT '',        -- '' for server-level plans
  environment      TEXT NOT NULL DEFAULT '',
  head_before_hex  TEXT NOT NULL,
  head_after_hex   TEXT NOT NULL,
  rule_id          TEXT,                            -- NULL unless author_kind = 'rule'
  delivery_id      TEXT,                            -- NULL unless author_kind = 'rule'
  expires_at       TEXT NOT NULL                    -- plan.expires_at
);
CREATE INDEX admissions_scope ON admissions (project_id, environment, admission_seq);
CREATE INDEX admissions_open  ON admissions (finished_at) WHERE finished_at IS NULL;

-- One row per action of every admission, inserted at admission with consumed_at NULL; the agent then reconciles
-- the runner's consumed log (section 14.5) into it. The log wins over this table.
CREATE TABLE admission_actions (
  plan_id      TEXT    NOT NULL REFERENCES admissions (plan_id),   -- R
  action_index INTEGER NOT NULL CHECK (action_index >= 0),         -- R
  kind         TEXT    NOT NULL,
  consumed_at  TEXT,                                               -- R  NULL until a `consumed` line
  finished_at  TEXT,                                               -- R  NULL until a `result` line
  outcome      TEXT    NOT NULL DEFAULT ''
               CHECK (outcome IN ('', 'succeeded', 'failed', 'rolled_back', 'cancelled', 'expired')),
  consumed_seq INTEGER,                                            -- consumed.log seq of the lines
  result_seq   INTEGER,
  deployment_id TEXT,        -- UUIDv7 minted at admission for deploy/rollback/restart/scale; NULL for other kinds
  PRIMARY KEY (plan_id, action_index)
);

-- Admitted ServiceSpecs (section 3.7). A spec admitted by several plans is stored once.
CREATE TABLE specs (
  spec_digest_hex  TEXT PRIMARY KEY,                -- R
  service_id       TEXT NOT NULL,
  spec_jcs         TEXT NOT NULL,                   -- R  JCS text, <= 16 KiB
  admitted_plan_id TEXT NOT NULL REFERENCES admissions (plan_id),  -- first plan that admitted it
  admitted_at      TEXT NOT NULL,
  elevated         INTEGER NOT NULL DEFAULT 0 CHECK (elevated IN (0, 1))
);
CREATE INDEX specs_service ON specs (service_id, admitted_at);

-- Scope heads (section 3.6). No row = genesis (64 x "0").
CREATE TABLE heads (
  project_id      TEXT NOT NULL DEFAULT '',
  environment     TEXT NOT NULL DEFAULT '',
  head_digest_hex TEXT NOT NULL,
  plan_id         TEXT NOT NULL REFERENCES admissions (plan_id),   -- plan that set this head
  updated_at      TEXT NOT NULL,
  PRIMARY KEY (project_id, environment)
);

-- Standing rules admitted through rule.create (section 3.4); rule.revoke sets revoked_at.
CREATE TABLE rules (
  rule              TEXT NOT NULL,                  -- R  JCS text of the StandingRule
  rule_digest_hex   TEXT PRIMARY KEY,               -- R
  created_by_key_id TEXT NOT NULL,                  -- R
  created_plan_id   TEXT NOT NULL REFERENCES admissions (plan_id),
  revoked_at        TEXT,                           -- R  NULL while active
  rule_id           TEXT NOT NULL UNIQUE,
  revoked_plan_id   TEXT REFERENCES admissions (plan_id)
);

-- Admissions per rule, for the per-hour limit (section 6.1 step 12). Pruned after 3600 s.
CREATE TABLE rule_invocations (
  rule_id     TEXT NOT NULL,
  plan_id     TEXT NOT NULL REFERENCES admissions (plan_id),
  admitted_at TEXT NOT NULL,
  PRIMARY KEY (rule_id, plan_id)
);
CREATE INDEX rule_invocations_window ON rule_invocations (rule_id, admitted_at);

-- Authenticated webhook deliveries (section 3.5). Only verified deliveries are stored.
CREATE TABLE deliveries (
  delivery_id     TEXT PRIMARY KEY,                 -- UUIDv7 minted by the agent
  provider        TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
  body_digest_hex TEXT NOT NULL UNIQUE,             -- DUPLICATE on conflict
  repo            TEXT NOT NULL,
  ref             TEXT NOT NULL,
  commit_sha      TEXT NOT NULL,
  commit_time     TEXT NOT NULL,
  received_at     TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('verified', 'stale', 'ignored'))
);
CREATE INDEX deliveries_received ON deliveries (received_at);

-- Consumption per (delivery, rule), inserted in the admission transaction.
CREATE TABLE delivery_consumptions (
  delivery_id TEXT NOT NULL REFERENCES deliveries (delivery_id),
  rule_id     TEXT NOT NULL,
  plan_id     TEXT NOT NULL REFERENCES admissions (plan_id),
  consumed_at TEXT NOT NULL,
  UNIQUE (delivery_id, rule_id)
);

-- Images the agent built for rule deploys (section 3.5 step 5).
CREATE TABLE builds (
  build_id         TEXT PRIMARY KEY,
  service_id       TEXT NOT NULL,
  commit_sha       TEXT NOT NULL,
  image_digest_hex TEXT NOT NULL,
  delivery_id      TEXT REFERENCES deliveries (delivery_id),
  built_at         TEXT NOT NULL,
  UNIQUE (service_id, commit_sha)
);

-- Age ciphertexts of secret.set / alert.channel.* actions (section 3.2, SignedPlan.sealed_secrets), stored at
-- admission. The digest is the one the plan signs.
CREATE TABLE sealed_secrets (
  ciphertext_digest_hex TEXT PRIMARY KEY,
  plan_id               TEXT NOT NULL REFERENCES admissions (plan_id),
  ciphertext            BLOB NOT NULL               -- binary age v1 file, <= 64 KiB
);

-- Consumed-log reconciliation cursor (section 14.5). One row.
CREATE TABLE consumed_reconciliation (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  last_seq      INTEGER NOT NULL DEFAULT 0,         -- highest consumed.log seq applied
  log_inode     INTEGER,                            -- inode of consumed.log when last read
  log_offset    INTEGER NOT NULL DEFAULT 0,         -- byte offset after the last complete line applied
  reconciled_at TEXT
);
