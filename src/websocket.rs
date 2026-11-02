use crate::state::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::{sync::atomic::Ordering, time::Duration};

pub async fn upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !crate::api::same_origin(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "Cross-origin WebSockets are not allowed",
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| stream(socket, state))
}
async fn stream(mut socket: WebSocket, state: AppState) {
    let mut receiver = state.events.subscribe();
    let mut shutdown_check = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = shutdown_check.tick() => {
                if state.shutdown.load(Ordering::Relaxed) {
                    let _ = tokio::time::timeout(Duration::from_secs(1), socket.send(Message::Close(None))).await;
                    break;
                }
            },
            event = receiver.recv() => match event {
                Ok(event) => {
                    if let Ok(data) = serde_json::to_string(&event) {
                        if !matches!(tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Text(data.into()))).await, Ok(Ok(()))) { break; }
                    }
                },
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {},
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::state::Event;
    #[test]
    fn event_uses_the_public_type_and_data_shape() {
        let event = Event {
            kind: "stats".into(),
            data: serde_json::json!({"packets_captured": 42}),
        };
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["type"], "stats");
        assert_eq!(value["data"]["packets_captured"], 42);
        assert!(value.get("kind").is_none());
    }
}
