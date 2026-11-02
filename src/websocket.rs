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
    #[tokio::test]
    async fn websocket_delivers_status_broadcast() {
        use crate::state::{AppState, Status};
        use std::future::IntoFuture;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let state = AppState::new(Status {
            capture_running: false,
            ai_status: "disabled".into(),
            interface: "test".into(),
            mode: "live".into(),
            ai_enabled: false,
            last_error: None,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server =
            tokio::spawn(axum::serve(listener, crate::api::router(state.clone())).into_future());
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(format!("GET /ws HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        loop {
            let mut byte = [0];
            client.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8(response)
            .unwrap()
            .contains("101 Switching Protocols"));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while state.events.receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        state.emit("status", &serde_json::json!({"capture_running":true}));
        let mut header = [0; 2];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0] & 0x0f, 1);
        let length = usize::from(header[1] & 0x7f);
        assert!(length < 126);
        let mut payload = vec![0; length];
        client.read_exact(&mut payload).await.unwrap();
        let event: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(event["type"], "status");
        assert_eq!(event["data"]["capture_running"], true);
        server.abort();
    }
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
