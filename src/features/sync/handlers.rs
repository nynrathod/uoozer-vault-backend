use std::convert::Infallible;
use std::time::Duration;

use axum::response::IntoResponse;
use axum::response::sse::{Event, Sse};
use tokio_stream::StreamExt;

use crate::app_state::AppState;
use crate::core::middleware::AuthenticatedUser;

pub async fn sync_stream(
    state: axum::extract::State<AppState>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let mut rx = state.sse_channel(user.user_id).subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let sse_event = Event::default()
                        .event(format!("{}.{}", event.resource_type, event.event_type))
                        .json_data(serde_json::json!({
                            "seq": event.seq,
                            "resource_id": event.resource_id,
                            "payload": event.payload
                        }));
                    yield Ok::<_, Infallible>(sse_event.unwrap_or(Event::default()));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let event = Event::default()
                        .event("lagged")
                        .data(format!("{{\"missed\": {}}}", n));
                    yield Ok(event);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    let init_event = Event::default()
        .event("connected")
        .data(serde_json::json!({ "status": "connected" }).to_string());

    let stream =
        futures_util::stream::once(async { Ok::<_, Infallible>(init_event) }).chain(stream);

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}
