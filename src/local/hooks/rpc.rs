//! `WebhookService` (agent-protocol.md 11, 12.2): read-only views of the
//! deliveries and server builds the webhook path recorded in `ops.db`.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use super::Hooks;
use crate::local::sched::ops_store::{Listing, RecordKind};
use crate::local::sched::pts;
use crate::local::sched::rpc::{page_size, seq_page};
use crate::proto::agent::v2::{
    webhook_service_server::WebhookService, GetServerBuildRequest, GetWebhookDeliveryRequest,
    GetWebhookQueueStatusRequest, ListServerBuildsRequest, ListServerBuildsResponse,
    ListWebhookDeliveriesRequest, ListWebhookDeliveriesResponse, PageInfo, ServerBuild,
    WebhookDelivery, WebhookDeliveryStatus, WebhookQueueStatus,
};
use crate::signed_plan::text;

pub struct WebhookSvc {
    pub hooks: Arc<Hooks>,
}

fn project_filter(project_id: &str) -> Result<Option<&str>, Status> {
    if project_id.is_empty() {
        return Ok(None);
    }
    if !text::uuid7(project_id) {
        return Err(Status::invalid_argument("project_id is not a UUIDv7"));
    }
    Ok(Some(project_id))
}

impl WebhookSvc {
    /// `after_delivery_id` (12.2 step 4): deliveries with a greater id, in
    /// ascending order.
    fn after(
        &self,
        after: &str,
        request: &ListWebhookDeliveriesRequest,
    ) -> Result<ListWebhookDeliveriesResponse, Status> {
        if !text::uuid7(after) {
            return Err(Status::invalid_argument(
                "after_delivery_id is not a UUIDv7",
            ));
        }
        let subject = project_filter(&request.project_id)?;
        let size = page_size(request.page.as_ref());
        let mut cursor = None;
        let mut out = Vec::new();
        loop {
            let rows = self.hooks.deps.ops.list(
                RecordKind::WebhookDelivery,
                &Listing {
                    subject,
                    statuses: &request.statuses,
                    after: cursor,
                    ascending: true,
                    limit: 500,
                    ..Default::default()
                },
            );
            let done = rows.len() < 500;
            for row in rows {
                cursor = Some(row.seq);
                if row.id.as_str() > after {
                    if let Some(delivery) = row.decode::<WebhookDelivery>() {
                        out.push(delivery);
                    }
                }
            }
            if done || out.len() > size {
                break;
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        let more = out.len() > size;
        out.truncate(size);
        let next = if more {
            out.last().map(|d| d.id.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        Ok(ListWebhookDeliveriesResponse {
            deliveries: out,
            page: Some(PageInfo {
                // The next page continues after the last id returned.
                next_page_token: next,
            }),
        })
    }
}

#[tonic::async_trait]
impl WebhookService for WebhookSvc {
    async fn list_webhook_deliveries(
        &self,
        request: Request<ListWebhookDeliveriesRequest>,
    ) -> Result<Response<ListWebhookDeliveriesResponse>, Status> {
        let request = request.into_inner();
        if !request.after_delivery_id.is_empty() {
            let after = match request.page.as_ref().map(|p| p.page_token.as_str()) {
                Some(token) if !token.is_empty() => token.to_owned(),
                _ => request.after_delivery_id.clone(),
            };
            return self.after(&after, &request).map(Response::new);
        }
        let subject = project_filter(&request.project_id)?;
        let (deliveries, page) = seq_page::<WebhookDelivery>(
            &self.hooks.deps.ops,
            RecordKind::WebhookDelivery,
            subject,
            &request.statuses,
            request.range.as_ref(),
            request.page.as_ref(),
            |_| true,
        )?;
        Ok(Response::new(ListWebhookDeliveriesResponse {
            deliveries,
            page: Some(page),
        }))
    }

    async fn get_webhook_delivery(
        &self,
        request: Request<GetWebhookDeliveryRequest>,
    ) -> Result<Response<WebhookDelivery>, Status> {
        let id = request.into_inner().delivery_id;
        if !text::uuid7(&id) {
            return Err(Status::invalid_argument("delivery_id is not a UUIDv7"));
        }
        self.hooks
            .delivery(&id)
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such delivery"))
    }

    async fn get_webhook_queue_status(
        &self,
        _request: Request<GetWebhookQueueStatusRequest>,
    ) -> Result<Response<WebhookQueueStatus>, Status> {
        let hooks = &self.hooks;
        let now = hooks.now();
        let ops = &hooks.deps.ops;
        let day = Some(now - 86_400);
        let oldest_pending = ops
            .list(
                RecordKind::WebhookDelivery,
                &Listing {
                    statuses: &[WebhookDeliveryStatus::Pending as i32],
                    ascending: true,
                    limit: 1,
                    ..Default::default()
                },
            )
            .first()
            .map(|row| pts(row.at));
        let presence = hooks.deps.presence.as_ref().map(|p| p.view());
        Ok(Response::new(WebhookQueueStatus {
            pending: hooks.pending(),
            building: ops.count(
                RecordKind::WebhookDelivery,
                &[WebhookDeliveryStatus::Building as i32],
                None,
            ),
            oldest_pending_at: oldest_pending,
            processed_24h: ops.count(
                RecordKind::WebhookDelivery,
                &[
                    WebhookDeliveryStatus::Deployed as i32,
                    WebhookDeliveryStatus::Failed as i32,
                    WebhookDeliveryStatus::Ignored as i32,
                    WebhookDeliveryStatus::Stale as i32,
                ],
                day,
            ),
            failed_24h: ops.count(
                RecordKind::WebhookDelivery,
                &[WebhookDeliveryStatus::Failed as i32],
                day,
            ),
            engine_connected: presence.as_ref().is_some_and(|p| p.engine_online),
            engine_last_seen_at: presence
                .as_ref()
                .and_then(|p| p.engine_last_seen_at)
                .map(pts),
            server_builds_enabled: hooks.server_builds_enabled(),
            engine_id: presence.map(|p| p.engine_id).unwrap_or_default(),
            duplicates_24h: hooks.duplicates_24h(),
            rejected_24h: hooks
                .deps
                .store
                .rejected_since(now - 86_400)
                .unwrap_or_default(),
            builds_queued: hooks.builds_queued(),
        }))
    }

    async fn list_server_builds(
        &self,
        request: Request<ListServerBuildsRequest>,
    ) -> Result<Response<ListServerBuildsResponse>, Status> {
        let request = request.into_inner();
        let subject = project_filter(&request.project_id)?;
        let (builds, page) = seq_page::<ServerBuild>(
            &self.hooks.deps.ops,
            RecordKind::ServerBuild,
            subject,
            &request.statuses,
            request.range.as_ref(),
            request.page.as_ref(),
            |_| true,
        )?;
        Ok(Response::new(ListServerBuildsResponse {
            builds,
            page: Some(page),
        }))
    }

    async fn get_server_build(
        &self,
        request: Request<GetServerBuildRequest>,
    ) -> Result<Response<ServerBuild>, Status> {
        let id = request.into_inner().build_id;
        if !text::uuid7(&id) {
            return Err(Status::invalid_argument("build_id is not a UUIDv7"));
        }
        self.hooks
            .build(&id)
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such build"))
    }
}
