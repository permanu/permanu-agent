-- signed-plan.md 6.4 v1.0.2 columns (D-026, D-027): a v1.0.1 store
-- (user_version = 1) gains them with ADD COLUMN and moves to user_version 2.
ALTER TABLE admissions ADD COLUMN environment_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sealed_secrets ADD COLUMN action_index INTEGER NOT NULL DEFAULT -1;
ALTER TABLE sealed_secrets ADD COLUMN project_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sealed_secrets ADD COLUMN environment TEXT NOT NULL DEFAULT '';
ALTER TABLE sealed_secrets ADD COLUMN service_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sealed_secrets ADD COLUMN name TEXT NOT NULL DEFAULT '';
CREATE INDEX sealed_secrets_scope ON sealed_secrets (project_id, environment, name);
UPDATE meta SET schema_version = 2;
