//! `DatabaseService` (agent-protocol.md 4, contracts v1.1.6 D-064 #1;
//! capability `database.v1`): `ListTables` and `QueryRows` are each one
//! runner `db_query` (signed-plan.md 14.3), a fixed-purpose, read-only op
//! that takes a structured request and never raw SQL. The runner checks every
//! identifier against the live catalog, binds every value, runs a read-only
//! transaction with a 5 s statement timeout and caps a page at 500 rows.
//!
//! The agent checks the request's shape, that `resource_id` is a `database`
//! service on this server (else `NOT_FOUND`), runs at most 1 query per
//! resource and 4 per agent (others wait up to 5 s, then `RATE_LIMITED`)
//! and maps the runner's answer. Rows are not redacted and may hold secret
//! values; they are never logged (agent-protocol.md 4: the engine serves
//! them app-only).
//!
//! Contracts v1.1.8 (D-066, proto v2.1.8): a refused request is
//! `INVALID_ARGUMENT` + `VALIDATION`; numbers travel as decimal strings in
//! `string_value` (`number_value` is refused); cells are cut at 64 KiB; the
//! statement timeout is `DEADLINE_EXCEEDED` "statement timeout"; a database
//! without the reader role is `FAILED_PRECONDITION` + `EXEC_PRECONDITION`;
//! a `QueryRowsResponse` over 3 MiB encoded fails whole (`INTERNAL`).
//!
//! Contracts v1.1.9 (D-067 #3, proto v2.1.9): a database without a working
//! `permanu_reader` is `FAILED_PRECONDITION` + `READER_MISSING` with the
//! runner's detail in the message, and `EnsureReader` (capability
//! `database.reader.v1`) re-runs the reader provisioning through the
//! runner's unbound `db_reader_ensure`, one call per database at a time.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use serde_json::{json, Map, Value};
use tokio::sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};
use tonic::{Code, Request, Response, Status};

use super::runner::Runner;
use super::status_with_reason;
use crate::proto::agent::v2::database_service_server::DatabaseService;
use crate::proto::agent::v2::{
    db_filter, db_order, db_reader_status, DbCell, DbColumn, DbReaderStatus, DbRow, DbTable,
    EnsureReaderRequest, ErrorReason, ListTablesRequest, ListTablesResponse, QueryRowsRequest,
    QueryRowsResponse,
};
use crate::signed_plan::text;

/// v2.1.6 (D-064 #1).
pub const CAPABILITY_DATABASE: &str = "database.v1";
/// v2.1.9 (D-067 #3): `DatabaseService.EnsureReader`.
pub const CAPABILITY_DATABASE_READER: &str = "database.reader.v1";
/// signed-plan.md 14.3 `db_reader_ensure`: up to 120 s for the database to
/// accept an authenticated connection, then create, grant and log in.
const ENSURE_TIMEOUT: Duration = Duration::from_secs(180);
/// agent-protocol.md 7: concurrent `db_query` calls per agent.
const PER_AGENT: usize = 4;
/// agent-protocol.md 7: how long a query waits for its slot.
pub const SLOT_WAIT: Duration = Duration::from_secs(5);
/// The runner's 5 s statement timeout plus connecting and reading.
const RUNNER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_COLUMNS: usize = 64;
const MAX_FILTERS: usize = 16;
const MAX_ORDER: usize = 4;
const MAX_LIMIT: u32 = 500;
const DEFAULT_LIMIT: u32 = 100;
const MAX_LIKE_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 512;
const MAX_TABLES: usize = 1_000;
/// A filter value (a `like` pattern has its own 256 B cap).
const MAX_VALUE_BYTES: usize = 4_096;
/// v2.1.8 (D-066 #1): a cell's text form is cut here.
const MAX_CELL_BYTES: usize = 64 * 1024;
/// v2.1.8 (D-066 #2): a `QueryRowsResponse`'s encoded budget.
const MAX_ROWS_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

/// The kind of a service's last admitted spec (`service_kind`).
pub trait ServiceKinds: Send + Sync {
    fn service_kind(&self, service_id: &str) -> Option<String>;
}

impl ServiceKinds for crate::admissions::AdmissionStore {
    fn service_kind(&self, service_id: &str) -> Option<String> {
        self.last_spec(service_id)
            .ok()
            .flatten()
            .and_then(|last| last.spec["service_kind"].as_str().map(str::to_owned))
    }
}

pub struct DatabaseSvc {
    pub runner: Arc<dyn Runner>,
    pub kinds: Arc<dyn ServiceKinds>,
    agent: Arc<Semaphore>,
    resources: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// One `EnsureReader` per database at a time (a second waits).
    ensuring: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    wait: Duration,
}

fn lock_of(
    map: &Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    key: &str,
) -> Arc<tokio::sync::Mutex<()>> {
    map.lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.to_owned())
        .or_default()
        .clone()
}

impl DatabaseSvc {
    pub fn new(runner: Arc<dyn Runner>, kinds: Arc<dyn ServiceKinds>) -> Self {
        Self::with_wait(runner, kinds, SLOT_WAIT)
    }

    fn with_wait(runner: Arc<dyn Runner>, kinds: Arc<dyn ServiceKinds>, wait: Duration) -> Self {
        Self {
            runner,
            kinds,
            agent: Arc::new(Semaphore::new(PER_AGENT)),
            resources: Mutex::new(HashMap::new()),
            ensuring: Mutex::new(HashMap::new()),
            wait,
        }
    }

    /// `NOT_FOUND` unless `resource_id` is a `database` service here.
    fn check_resource(&self, resource_id: &str) -> Result<(), Status> {
        if !text::uuid7(resource_id) {
            return Err(invalid("resource_id must be a service id"));
        }
        match self.kinds.service_kind(resource_id).as_deref() {
            Some("database") => Ok(()),
            _ => Err(Status::not_found(
                "resource_id is not a database service on this server",
            )),
        }
    }

    /// One slot of the agent and the resource's lock, within the wait.
    async fn slots(
        &self,
        resource_id: &str,
    ) -> Result<(OwnedSemaphorePermit, OwnedMutexGuard<()>), Status> {
        let lock = lock_of(&self.resources, resource_id);
        let agent = self.agent.clone();
        tokio::time::timeout(self.wait, async move {
            let guard = lock.lock_owned().await;
            let permit = agent.acquire_owned().await.ok()?;
            Some((permit, guard))
        })
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            status_with_reason(
                Code::ResourceExhausted,
                "database queries are busy; retry",
                ErrorReason::RateLimited,
            )
        })
    }

    /// One `db_query`; the answer when `ok`.
    async fn query(&self, resource_id: &str, payload: Value) -> Result<Value, Status> {
        let _slots = self.slots(resource_id).await?;
        let request = json!({"op": "db_query", "payload": payload});
        let answer = self
            .runner
            .exchange(request, RUNNER_TIMEOUT)
            .await
            .map_err(|failure| {
                tracing::warn!(code = %failure.code, "db_query did not complete");
                Status::unavailable("the runner did not answer the database query")
            })?;
        if answer["ok"] == true {
            return Ok(answer);
        }
        Err(runner_error(&answer["error"]))
    }
}

/// `INVALID_ARGUMENT` + `VALIDATION` naming the field (agent-protocol.md 3;
/// proto v2.1.8, D-066 #4).
fn invalid(message: &str) -> Status {
    status_with_reason(Code::InvalidArgument, message, ErrorReason::Validation)
}

/// A runner refusal as a status (agent-protocol.md 4).
fn runner_error(error: &Value) -> Status {
    let message: String = error["message"]
        .as_str()
        .unwrap_or("the database query failed")
        .chars()
        .take(256)
        .collect();
    match (error["code"].as_str(), error["reason"].as_str()) {
        (Some("invalid_request"), _) => invalid(&message),
        (Some("not_found"), _) => Status::not_found(message),
        // D-066 #1: the runner's 5 s statement timeout.
        (Some("runtime_failed"), Some("timeout")) => Status::deadline_exceeded("statement timeout"),
        // D-067 #3: no working permanu_reader (never provisioned, failed,
        // or its login fails); the runner's detail travels in the message.
        (Some("runtime_failed"), Some("reader_missing")) => status_with_reason(
            Code::FailedPrecondition,
            &with_reader_detail(message, &error["detail"]),
            ErrorReason::ReaderMissing,
        ),
        _ => Status::failed_precondition(message),
    }
}

/// `message` plus the runner's reader record (`reader_status`,
/// `reader_reason`), each a short token.
fn with_reader_detail(message: String, detail: &Value) -> String {
    let token = |key: &str| {
        detail[key]
            .as_str()
            .filter(|t| !t.is_empty() && t.len() <= 64)
            .filter(|t| t.bytes().all(|b| b.is_ascii_graphic()))
            .map(|t| format!("{key} {t}"))
    };
    let parts: Vec<String> = ["reader_status", "reader_reason"]
        .into_iter()
        .filter_map(token)
        .collect();
    if parts.is_empty() {
        message
    } else {
        format!("{message} ({})", parts.join(", "))
    }
}

/// A runner `db_reader_ensure` refusal as a status (agent-protocol.md 4,
/// contracts v1.1.9).
fn ensure_error(error: &Value) -> Status {
    let message: String = error["message"]
        .as_str()
        .unwrap_or("the reader could not be provisioned")
        .chars()
        .take(256)
        .collect();
    match (error["code"].as_str(), error["reason"].as_str()) {
        (Some("invalid_request" | "not_found"), _) => invalid(&message),
        (Some("runtime_failed"), Some("not_active")) => status_with_reason(
            Code::FailedPrecondition,
            &message,
            ErrorReason::ExecPrecondition,
        ),
        _ => Status::failed_precondition(message),
    }
}

/// The runner's `db_reader_ensure` answer as `DbReaderStatus`.
fn reader_status(answer: &Value, now: i64) -> Result<DbReaderStatus, Status> {
    use db_reader_status::Status as S;
    let (status, reason) = match answer["reader_status"].as_str() {
        Some("ready") => (S::Ready, String::new()),
        Some("failed") => (S::Failed, text_of(&answer["reader_reason"], 128)),
        _ => return Err(Status::internal("the runner returned no reader status")),
    };
    Ok(DbReaderStatus {
        status: status as i32,
        reason,
        deployment_id: text_of(&answer["deployment_id"], 64),
        checked_at: Some(prost_types::Timestamp {
            seconds: now,
            nanos: 0,
        }),
    })
}

/// A catalog name as the runner takes it: 1–63 bytes, no NUL.
fn name_ok(name: &str) -> bool {
    (1..=63).contains(&name.len()) && !name.contains('\0')
}

fn schema_of(schema: &str) -> Result<String, Status> {
    if schema.is_empty() {
        return Ok("public".to_owned());
    }
    if !name_ok(schema) {
        return Err(invalid("schema is not a name"));
    }
    Ok(schema.to_owned())
}

fn filter_json(filter: &crate::proto::agent::v2::DbFilter) -> Result<Value, Status> {
    use db_filter::{Op, Value as V};
    if !name_ok(&filter.column) {
        return Err(invalid("filters.column is not a name"));
    }
    let op = Op::try_from(filter.op).map_err(|_| invalid("filters.op is unknown"))?;
    let op_name = match op {
        Op::Unspecified => return Err(invalid("filters.op is required")),
        Op::Eq => "eq",
        Op::Ne => "ne",
        Op::Lt => "lt",
        Op::Lte => "lte",
        Op::Gt => "gt",
        Op::Gte => "gte",
        Op::Like => "like",
        Op::IsNull => "is_null",
    };
    let value = match (op, &filter.value) {
        (Op::IsNull, Some(V::BoolValue(is_null))) => json!(is_null),
        (Op::IsNull, _) => return Err(invalid("filters.value of is_null is a bool")),
        (Op::Like, Some(V::StringValue(pattern))) if pattern.len() <= MAX_LIKE_BYTES => {
            json!(pattern)
        }
        (Op::Like, _) => return Err(invalid("filters.value of like is a pattern of ≤ 256 bytes")),
        (_, None | Some(V::NullValue(_))) => Value::Null,
        (_, Some(V::StringValue(text))) if text.len() <= MAX_VALUE_BYTES => json!(text),
        (_, Some(V::StringValue(_))) => return Err(invalid("filters.value is too long")),
        // D-066 #1: a number travels as its decimal string, never a float.
        (_, Some(V::NumberValue(_))) => {
            return Err(invalid(
                "filters.value: send a number as its decimal string (string_value)",
            ))
        }
        (_, Some(V::BoolValue(b))) => json!(b),
    };
    Ok(json!({"column": filter.column, "op": op_name, "value": value}))
}

fn rows_payload(request: &QueryRowsRequest) -> Result<Value, Status> {
    let schema = schema_of(&request.schema)?;
    if !name_ok(&request.table) {
        return Err(invalid("table is not a name"));
    }
    if request.columns.len() > MAX_COLUMNS {
        return Err(invalid("columns has at most 64 names"));
    }
    if !request.columns.iter().all(|c| name_ok(c)) {
        return Err(invalid("columns holds a name that is not a name"));
    }
    if request.filters.len() > MAX_FILTERS {
        return Err(invalid("filters has at most 16 entries"));
    }
    if request.order_by.len() > MAX_ORDER {
        return Err(invalid("order_by has at most 4 entries"));
    }
    let limit = match request.limit {
        0 => DEFAULT_LIMIT,
        n if n > MAX_LIMIT => return Err(invalid("limit is at most 500")),
        n => n,
    };
    if request.cursor.len() > MAX_CURSOR_BYTES {
        return Err(invalid("cursor is not a cursor of this request"));
    }
    let filters = request
        .filters
        .iter()
        .map(filter_json)
        .collect::<Result<Vec<_>, _>>()?;
    let mut order = Vec::new();
    for entry in &request.order_by {
        if !name_ok(&entry.column) {
            return Err(invalid("order_by.column is not a name"));
        }
        let dir = match db_order::Dir::try_from(entry.dir) {
            Ok(db_order::Dir::Desc) => "desc",
            Ok(_) => "asc",
            Err(_) => return Err(invalid("order_by.dir is unknown")),
        };
        order.push(json!({"column": entry.column, "dir": dir}));
    }
    let mut payload = json!({
        "resource_id": request.resource_id,
        "query": "rows",
        "schema": schema,
        "table": request.table,
        "columns": request.columns,
        "filters": filters,
        "order_by": order,
        "limit": limit,
    });
    if !request.cursor.is_empty() {
        payload["cursor"] = json!(request.cursor);
    }
    Ok(payload)
}

/// `value`'s string cut at `max` bytes on a UTF-8 boundary, and whether it
/// was cut.
fn cut(value: &Value, max: usize) -> (String, bool) {
    let text = value.as_str().unwrap_or_default();
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), end < text.len())
}

fn text_of(value: &Value, max: usize) -> String {
    cut(value, max).0
}

/// A runner cell: `null`, the text form, or `{text, truncated: true}`.
fn cell_of(value: &Value) -> DbCell {
    match value {
        Value::Null => DbCell {
            is_null: true,
            ..Default::default()
        },
        Value::String(_) => {
            let (text, truncated) = cut(value, MAX_CELL_BYTES);
            DbCell {
                text,
                truncated,
                is_null: false,
            }
        }
        Value::Object(map) => {
            let (text, cut_here) = cut(map.get("text").unwrap_or(&Value::Null), MAX_CELL_BYTES);
            DbCell {
                text,
                truncated: cut_here || map.get("truncated") == Some(&Value::Bool(true)),
                is_null: false,
            }
        }
        // A number or boolean: its text form.
        other => DbCell {
            text: other.to_string(),
            ..Default::default()
        },
    }
}

fn rows_response(answer: &Value, limit: usize) -> QueryRowsResponse {
    let columns: Vec<DbColumn> = answer["columns"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_COLUMNS * 4)
        .map(|c| DbColumn {
            name: text_of(&c["name"], 63),
            r#type: text_of(&c["type"], 128),
        })
        .collect();
    let rows = answer["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .take(limit)
        .map(|row| DbRow {
            cells: row
                .as_array()
                .into_iter()
                .flatten()
                .take(columns.len())
                .map(cell_of)
                .collect(),
        })
        .collect();
    QueryRowsResponse {
        columns,
        rows,
        next_cursor: text_of(&answer["next_cursor"], MAX_CURSOR_BYTES),
    }
}

fn tables_response(answer: &Value) -> ListTablesResponse {
    ListTablesResponse {
        tables: answer["tables"]
            .as_array()
            .into_iter()
            .flatten()
            .take(MAX_TABLES)
            .map(|t| DbTable {
                schema: text_of(&t["schema"], 63),
                name: text_of(&t["name"], 63),
                rows_estimate: t["rows_estimate"].as_u64().unwrap_or_default(),
                size_bytes: t["size_bytes"].as_u64().unwrap_or_default(),
            })
            .collect(),
    }
}

#[tonic::async_trait]
impl DatabaseService for DatabaseSvc {
    async fn list_tables(
        &self,
        request: Request<ListTablesRequest>,
    ) -> Result<Response<ListTablesResponse>, Status> {
        super::log_peer(&request, "ListTables");
        let request = request.into_inner();
        let schema = schema_of(&request.schema)?;
        self.check_resource(&request.resource_id)?;
        let mut payload = Map::new();
        payload.insert("resource_id".into(), json!(request.resource_id));
        payload.insert("query".into(), json!("tables"));
        payload.insert("schema".into(), json!(schema));
        let answer = self
            .query(&request.resource_id, Value::Object(payload))
            .await?;
        Ok(Response::new(tables_response(&answer)))
    }

    async fn query_rows(
        &self,
        request: Request<QueryRowsRequest>,
    ) -> Result<Response<QueryRowsResponse>, Status> {
        super::log_peer(&request, "QueryRows");
        let request = request.into_inner();
        let payload = rows_payload(&request)?;
        self.check_resource(&request.resource_id)?;
        let limit = payload["limit"]
            .as_u64()
            .unwrap_or(u64::from(DEFAULT_LIMIT)) as usize;
        let answer = self.query(&request.resource_id, payload).await?;
        let response = rows_response(&answer, limit);
        // D-066 #2: the runner's page already fits; never a partial page.
        if response.encoded_len() > MAX_ROWS_RESPONSE_BYTES {
            tracing::warn!(
                bytes = response.encoded_len(),
                "db_query page is over the 3 MiB budget"
            );
            return Err(status_with_reason(
                Code::Internal,
                "the rows page is over 3 MiB",
                ErrorReason::Internal,
            ));
        }
        Ok(Response::new(response))
    }

    /// v2.1.9 (D-067 #3): re-runs the reader provisioning of one managed
    /// PostgreSQL service (runner `db_reader_ensure`, bound by the runner to
    /// the service's last admitted spec; the request names only the
    /// resource, never credentials).
    async fn ensure_reader(
        &self,
        request: Request<EnsureReaderRequest>,
    ) -> Result<Response<DbReaderStatus>, Status> {
        super::log_peer(&request, "EnsureReader");
        let resource_id = request.into_inner().resource_id;
        if !text::uuid7(&resource_id)
            || self.kinds.service_kind(&resource_id).as_deref() != Some("database")
        {
            return Err(invalid(
                "resource_id is not a managed PostgreSQL service on this server",
            ));
        }
        let lock = lock_of(&self.ensuring, &resource_id);
        let _one = lock.lock().await;
        let request = json!({"op": "db_reader_ensure", "payload": {"resource_id": resource_id}});
        let answer = self
            .runner
            .exchange(request, ENSURE_TIMEOUT)
            .await
            .map_err(|failure| {
                tracing::warn!(code = %failure.code, "db_reader_ensure did not complete");
                Status::unavailable("the runner did not answer the reader repair")
            })?;
        if answer["ok"] != true {
            return Err(ensure_error(&answer["error"]));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let status = reader_status(&answer, now)?;
        tracing::info!(
            %resource_id,
            status = status.status,
            reason = %status.reason,
            "database reader ensured"
        );
        Ok(Response::new(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::runner::{EventLines, RunnerFailure};
    use crate::proto::agent::v2::{db_reader_status, DbFilter, DbOrder, EnsureReaderRequest};

    const DB: &str = "01a0cdb5-3500-70c1-8000-000000000002";
    const WEB: &str = "01a0cdb5-3500-70c1-8000-000000000001";

    struct Kinds;

    impl ServiceKinds for Kinds {
        fn service_kind(&self, service_id: &str) -> Option<String> {
            match service_id {
                DB => Some("database".into()),
                WEB => Some("web".into()),
                _ => None,
            }
        }
    }

    /// Answers `db_query` with a scripted answer; can hold every call.
    struct DbRunner {
        answer: Mutex<Value>,
        requests: Mutex<Vec<Value>>,
        hold: tokio::sync::Semaphore,
    }

    impl DbRunner {
        fn new(answer: Value, held: bool) -> Arc<Self> {
            Arc::new(Self {
                answer: Mutex::new(answer),
                requests: Mutex::new(Vec::new()),
                hold: tokio::sync::Semaphore::new(if held { 0 } else { 1_000 }),
            })
        }
    }

    #[tonic::async_trait]
    impl Runner for DbRunner {
        async fn exchange(&self, request: Value, _: Duration) -> Result<Value, RunnerFailure> {
            self.requests.lock().unwrap().push(request);
            let _permit = self.hold.acquire().await;
            Ok(self.answer.lock().unwrap().clone())
        }

        async fn open(&self, _: Value) -> Result<EventLines, RunnerFailure> {
            Err(RunnerFailure::transport("not used"))
        }
    }

    fn svc(runner: Arc<DbRunner>) -> DatabaseSvc {
        DatabaseSvc::with_wait(runner, Arc::new(Kinds), Duration::from_millis(100))
    }

    fn reason(status: &Status) -> String {
        status
            .metadata()
            .get(crate::local::ERROR_REASON_HEADER)
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn list_tables_is_one_tables_query() {
        let runner = DbRunner::new(
            json!({"ok": true, "op": "db_query", "tables": [
                {"schema": "public", "name": "users", "rows_estimate": 12, "size_bytes": 8192}]}),
            false,
        );
        let svc = svc(runner.clone());
        let answer = svc
            .list_tables(Request::new(ListTablesRequest {
                resource_id: DB.into(),
                schema: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(answer.tables.len(), 1);
        assert_eq!(answer.tables[0].name, "users");
        assert_eq!(answer.tables[0].rows_estimate, 12);
        assert_eq!(
            runner.requests.lock().unwrap()[0],
            json!({"op": "db_query", "payload": {"resource_id": DB, "query": "tables",
                "schema": "public"}})
        );
    }

    #[tokio::test]
    async fn query_rows_sends_a_structured_request_and_maps_cells() {
        let runner = DbRunner::new(
            json!({"ok": true, "op": "db_query",
                "columns": [{"name": "id", "type": "integer"}, {"name": "note", "type": "text"}],
                "rows": [["9007199254740993", null], ["12.50", {"text": "abc", "truncated": true}]],
                "next_cursor": "MTAwLmFi"}),
            false,
        );
        let svc = svc(runner.clone());
        let request = QueryRowsRequest {
            resource_id: DB.into(),
            schema: "app".into(),
            table: "users".into(),
            columns: vec!["id".into(), "note".into()],
            filters: vec![
                DbFilter {
                    column: "id".into(),
                    op: db_filter::Op::Gte as i32,
                    // v2.1.8 (D-066 #1): numbers travel as decimal strings.
                    value: Some(db_filter::Value::StringValue("9007199254740993".into())),
                },
                DbFilter {
                    column: "note".into(),
                    op: db_filter::Op::IsNull as i32,
                    value: Some(db_filter::Value::BoolValue(false)),
                },
                DbFilter {
                    column: "email".into(),
                    op: db_filter::Op::Like as i32,
                    value: Some(db_filter::Value::StringValue("%@example.com".into())),
                },
            ],
            order_by: vec![DbOrder {
                column: "id".into(),
                dir: db_order::Dir::Desc as i32,
            }],
            limit: 0,
            cursor: String::new(),
        };
        let answer = svc
            .query_rows(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            runner.requests.lock().unwrap()[0]["payload"],
            json!({"resource_id": DB, "query": "rows", "schema": "app", "table": "users",
                "columns": ["id", "note"],
                "filters": [{"column": "id", "op": "gte", "value": "9007199254740993"},
                            {"column": "note", "op": "is_null", "value": false},
                            {"column": "email", "op": "like", "value": "%@example.com"}],
                "order_by": [{"column": "id", "dir": "desc"}], "limit": 100})
        );
        assert_eq!(answer.columns[1].r#type, "text");
        assert_eq!(answer.rows.len(), 2);
        assert_eq!(answer.rows[0].cells[0].text, "9007199254740993");
        assert!(answer.rows[0].cells[1].is_null);
        assert_eq!(answer.rows[1].cells[0].text, "12.50");
        assert_eq!(answer.rows[1].cells[1].text, "abc");
        assert!(answer.rows[1].cells[1].truncated);
        assert_eq!(answer.next_cursor, "MTAwLmFi");
    }

    #[tokio::test]
    async fn only_a_database_service_is_queried() {
        let runner = DbRunner::new(json!({"ok": true, "tables": []}), false);
        let svc = svc(runner.clone());
        for resource in [WEB, "01a0cdb5-3500-70c1-8000-000000000009"] {
            let status = svc
                .list_tables(Request::new(ListTablesRequest {
                    resource_id: resource.into(),
                    schema: String::new(),
                }))
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::NotFound);
        }
        assert!(runner.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_requests_are_refused_before_the_runner() {
        let runner = DbRunner::new(json!({"ok": true, "rows": []}), false);
        let svc = svc(runner.clone());
        let base = QueryRowsRequest {
            resource_id: DB.into(),
            table: "users".into(),
            ..Default::default()
        };
        let filter = |op: db_filter::Op, value: Option<db_filter::Value>| DbFilter {
            column: "c".into(),
            op: op as i32,
            value,
        };
        for bad in [
            QueryRowsRequest {
                table: String::new(),
                ..base.clone()
            },
            QueryRowsRequest {
                limit: 501,
                ..base.clone()
            },
            QueryRowsRequest {
                columns: vec!["c".into(); 65],
                ..base.clone()
            },
            QueryRowsRequest {
                filters: vec![filter(db_filter::Op::Eq, None); 17],
                ..base.clone()
            },
            QueryRowsRequest {
                order_by: vec![DbOrder::default(); 5],
                ..base.clone()
            },
            QueryRowsRequest {
                filters: vec![filter(db_filter::Op::Unspecified, None)],
                ..base.clone()
            },
            QueryRowsRequest {
                filters: vec![filter(db_filter::Op::IsNull, None)],
                ..base.clone()
            },
            QueryRowsRequest {
                filters: vec![filter(
                    db_filter::Op::Like,
                    Some(db_filter::Value::StringValue("x".repeat(257))),
                )],
                ..base.clone()
            },
            QueryRowsRequest {
                filters: vec![filter(
                    db_filter::Op::Eq,
                    Some(db_filter::Value::NumberValue(f64::NAN)),
                )],
                ..base.clone()
            },
            // v2.1.8 (D-066 #1): number_value is never sent.
            QueryRowsRequest {
                filters: vec![filter(
                    db_filter::Op::Eq,
                    Some(db_filter::Value::NumberValue(2.0)),
                )],
                ..base.clone()
            },
            QueryRowsRequest {
                resource_id: "x".into(),
                ..base.clone()
            },
        ] {
            let status = svc.query_rows(Request::new(bad)).await.unwrap_err();
            assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
            // v2.1.8 (D-066 #4).
            assert_eq!(reason(&status), "ERROR_REASON_VALIDATION", "{status:?}");
        }
        assert!(runner.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn runner_refusals_map_to_statuses() {
        for (error, code, why, message) in [
            (
                json!({"code": "invalid_request", "message": "unknown column \"x\""}),
                Code::InvalidArgument,
                "ERROR_REASON_VALIDATION",
                "unknown column \"x\"",
            ),
            (
                json!({"code": "not_found", "message": "no running container"}),
                Code::NotFound,
                "",
                "no running container",
            ),
            // v2.1.8 (D-066 #1): the statement timeout.
            (
                json!({"code": "runtime_failed", "reason": "timeout", "message": "t"}),
                Code::DeadlineExceeded,
                "",
                "statement timeout",
            ),
            // v2.1.9 (D-067 #3): READER_MISSING with the runner's detail.
            (
                json!({"code": "runtime_failed", "reason": "reader_missing", "message": "no reader",
                    "detail": {"reader_status": "failed", "reader_reason": "not_ready"}}),
                Code::FailedPrecondition,
                "ERROR_REASON_READER_MISSING",
                "no reader (reader_status failed, reader_reason not_ready)",
            ),
            (
                json!({"code": "runtime_failed", "reason": "reader_missing", "message": "no reader",
                    "detail": {"reader_status": "missing", "reader_reason": null}}),
                Code::FailedPrecondition,
                "ERROR_REASON_READER_MISSING",
                "no reader (reader_status missing)",
            ),
            // A runner before v1.0.17 sends no detail.
            (
                json!({"code": "runtime_failed", "reason": "reader_missing", "message": "no reader"}),
                Code::FailedPrecondition,
                "ERROR_REASON_READER_MISSING",
                "no reader",
            ),
            (
                json!({"code": "runtime_failed", "message": "refused"}),
                Code::FailedPrecondition,
                "",
                "refused",
            ),
        ] {
            let runner = DbRunner::new(json!({"ok": false, "error": error}), false);
            let status = svc(runner)
                .list_tables(Request::new(ListTablesRequest {
                    resource_id: DB.into(),
                    schema: String::new(),
                }))
                .await
                .unwrap_err();
            assert_eq!(status.code(), code);
            assert_eq!(reason(&status), why);
            assert_eq!(status.message(), message);
        }
    }

    /// v2.1.8 (D-066 #1): cells are cut at 64 KiB on a UTF-8 boundary and
    /// then marked truncated.
    #[test]
    fn cells_are_cut_at_64_kib() {
        let long = "é".repeat(40 * 1024);
        let cell = cell_of(&json!(long));
        assert!(cell.truncated);
        assert!(!cell.is_null);
        assert_eq!(cell.text.len(), 64 * 1024);
        let cell = cell_of(&json!({"text": long, "truncated": true}));
        assert!(cell.truncated);
        assert_eq!(cell.text.len(), 64 * 1024);
        let short = cell_of(&json!("x".repeat(64 * 1024)));
        assert!(!short.truncated);
        assert_eq!(short.text.len(), 64 * 1024);
    }

    /// v2.1.8 (D-066 #2): a `QueryRowsResponse` is at most 3 MiB encoded;
    /// the agent never adds or drops rows, so a runner page over it fails.
    #[tokio::test]
    async fn a_page_over_3_mib_is_refused_whole() {
        let request = QueryRowsRequest {
            resource_id: DB.into(),
            table: "blobs".into(),
            limit: 500,
            ..Default::default()
        };
        let cell = "x".repeat(60 * 1024);
        let page = |rows: usize| {
            json!({"ok": true, "op": "db_query",
                "columns": [{"name": "b", "type": "text"}],
                "rows": vec![json!([cell]); rows], "next_cursor": "NTEuYWI"})
        };
        // 51 rows of 60 KiB: 3,060 KiB, within 3 MiB.
        let answer = svc(DbRunner::new(page(51), false))
            .query_rows(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(answer.rows.len(), 51);
        assert_eq!(answer.next_cursor, "NTEuYWI");
        // 60 rows: 3,600 KiB, over 3 MiB.
        let status = svc(DbRunner::new(page(60), false))
            .query_rows(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(reason(&status), "ERROR_REASON_INTERNAL");
    }

    /// agent-protocol.md 7: one query per resource at a time; a second
    /// waits, then `RATE_LIMITED`.
    #[tokio::test]
    async fn one_query_per_resource_at_a_time() {
        let runner = DbRunner::new(json!({"ok": true, "tables": []}), true);
        let svc = Arc::new(svc(runner.clone()));
        let first = {
            let svc = svc.clone();
            tokio::spawn(async move {
                svc.list_tables(Request::new(ListTablesRequest {
                    resource_id: DB.into(),
                    schema: String::new(),
                }))
                .await
            })
        };
        while runner.requests.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        let status = svc
            .list_tables(Request::new(ListTablesRequest {
                resource_id: DB.into(),
                schema: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::ResourceExhausted);
        assert_eq!(reason(&status), "ERROR_REASON_RATE_LIMITED");
        runner.hold.add_permits(10);
        assert!(first.await.unwrap().is_ok());
    }

    fn ensure(resource_id: &str) -> Request<EnsureReaderRequest> {
        Request::new(EnsureReaderRequest {
            resource_id: resource_id.into(),
        })
    }

    /// v2.1.9 (D-067 #3): `EnsureReader` is one unbound `db_reader_ensure`
    /// naming only the resource; the answer becomes `DbReaderStatus`.
    #[tokio::test]
    async fn ensure_reader_runs_db_reader_ensure() {
        let deployment = "01a0cdb5-3500-70d1-8000-000000000009";
        let runner = DbRunner::new(
            json!({"ok": true, "op": "db_reader_ensure", "deployment_id": deployment,
                "reader_status": "ready", "reader_reason": null}),
            false,
        );
        let status = svc(runner.clone())
            .ensure_reader(ensure(DB))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.status, db_reader_status::Status::Ready as i32);
        assert_eq!(status.reason, "");
        assert_eq!(status.deployment_id, deployment);
        assert!(status.checked_at.is_some());
        assert_eq!(
            runner.requests.lock().unwrap().as_slice(),
            [json!({"op": "db_reader_ensure", "payload": {"resource_id": DB}})]
        );

        let runner = DbRunner::new(
            json!({"ok": true, "op": "db_reader_ensure", "deployment_id": deployment,
                "reader_status": "failed", "reader_reason": "sql_error:42501"}),
            false,
        );
        let status = svc(runner)
            .ensure_reader(ensure(DB))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.status, db_reader_status::Status::Failed as i32);
        assert_eq!(status.reason, "sql_error:42501");
    }

    /// v2.1.9: a resource that is not a database service here is
    /// `INVALID_ARGUMENT` + `VALIDATION` (never sent); the runner's
    /// refusals map to the contract's statuses.
    #[tokio::test]
    async fn ensure_reader_refusals() {
        let runner = DbRunner::new(json!({"ok": true}), false);
        for id in [WEB, "01a0cdb5-3500-70c1-8000-00000000000f", "x"] {
            let status = svc(runner.clone())
                .ensure_reader(ensure(id))
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::InvalidArgument, "{id}");
            assert_eq!(reason(&status), "ERROR_REASON_VALIDATION");
        }
        assert!(runner.requests.lock().unwrap().is_empty());
        for (error, code, why) in [
            (
                json!({"code": "invalid_request", "message": "not PostgreSQL"}),
                Code::InvalidArgument,
                "ERROR_REASON_VALIDATION",
            ),
            (
                json!({"code": "not_found", "message": "no such service"}),
                Code::InvalidArgument,
                "ERROR_REASON_VALIDATION",
            ),
            (
                json!({"code": "runtime_failed", "reason": "not_active", "message": "no release"}),
                Code::FailedPrecondition,
                "ERROR_REASON_EXEC_PRECONDITION",
            ),
            (
                json!({"code": "runtime_failed", "message": "boom"}),
                Code::FailedPrecondition,
                "",
            ),
        ] {
            let runner = DbRunner::new(json!({"ok": false, "error": error}), false);
            let status = svc(runner).ensure_reader(ensure(DB)).await.unwrap_err();
            assert_eq!(status.code(), code, "{status:?}");
            assert_eq!(reason(&status), why, "{status:?}");
        }
        // A malformed answer is never READY.
        let runner = DbRunner::new(json!({"ok": true, "reader_status": "maybe"}), false);
        let status = svc(runner).ensure_reader(ensure(DB)).await.unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    /// v2.1.9: one `EnsureReader` per database at a time; a second waits
    /// for the first (no `RATE_LIMITED`), and queries of the database are
    /// not blocked by it.
    #[tokio::test]
    async fn ensure_reader_calls_of_one_database_wait_for_each_other() {
        let runner = DbRunner::new(
            json!({"ok": true, "deployment_id": "d", "reader_status": "ready", "reader_reason": null}),
            true,
        );
        let svc = Arc::new(svc(runner.clone()));
        let spawn = || {
            let svc = svc.clone();
            tokio::spawn(async move { svc.ensure_reader(ensure(DB)).await })
        };
        let first = spawn();
        while runner.requests.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        let second = spawn();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Past the query wait (100 ms here): still waiting, not refused.
        assert_eq!(runner.requests.lock().unwrap().len(), 1);
        assert!(!second.is_finished());
        runner.hold.add_permits(10);
        assert!(first.await.unwrap().is_ok());
        assert!(second.await.unwrap().is_ok());
        assert_eq!(runner.requests.lock().unwrap().len(), 2);
    }
}
