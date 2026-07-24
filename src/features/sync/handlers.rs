use std::convert::Infallible;
use std::time::Duration;

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::stream::{self, Stream};
use tokio_stream::StreamExt;

use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::middleware::AuthenticatedUser;

/// SSE endpoint for realtime metadata sync.
pub async fn sync_stream(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    let rx = state.sse_channel(user.user_id).subscribe();

    let stream = stream::unfold(rx, move |mut rx| async move {
        match rx.recv().await {
            Ok(event) => {
                let sse_event = Event::default()
                    .event(format!("{}.{}", event.resource_type, event.event_type))
                    .json_data(serde_json::json!({
                        "resource_type": event.resource_type,
                        "resource_id": event.resource_id,
                        "payload": event.payload,
                        "timestamp": event.timestamp,
                    }))
                    .ok();

                Some((Ok(sse_event.unwrap_or(Event::default())), rx))
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                let event = Event::default()
                    .event("lagged")
                    .data(format!("{{\"missed\": {}}}", n));
                Some((Ok(event), rx))
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
        }
    });

    let init_event = Event::default().event("connected").data(
        serde_json::json!({
            "user_id": user.user_id,
            "device_id": user.device_id,
            "server_time": chrono::Utc::now(),
        })
        .to_string(),
    );

    let stream =
        futures_util::stream::once(async { Ok::<_, Infallible>(init_event) }).chain(stream);

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    ))
}
