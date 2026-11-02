//! Cloudflare Clef typed decisions. Only explicitly selected flow metadata is sent.
use crate::flow::Flow;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChoiceAnswer {
    #[serde(rename = "type")]
    pub kind: String,
    pub choice: String,
    pub confidence: f64,
    pub probabilities: BTreeMap<String, f64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreAnswer {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: f64,
    pub confidence: f64,
    pub legend: BTreeMap<String, String>,
    pub probabilities: BTreeMap<String, f64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClefAnswers {
    pub traffic_type: ChoiceAnswer,
    pub evidence_strength: ScoreAnswer,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClefResult {
    pub model: String,
    pub answers: ClefAnswers,
    #[serde(default)]
    pub usage: Option<Value>,
}
#[derive(Deserialize)]
struct Envelope {
    success: bool,
    result: Option<ClefResult>,
}

/// A stable allowlist makes cloud sharing auditable; raw payloads never enter this function.
pub fn build_request(flow: &Flow, model: &str, share_identity: bool) -> Value {
    let packets = flow.packets_sent.saturating_add(flow.packets_received);
    let mut state = json!({
        "transport": format!("{:?}", flow.protocol).to_lowercase(),
        "destination_port": flow.dst.port(),
        "duration_ms": flow.duration_ms(),
        "packets_sent": flow.packets_sent,
        "packets_received": flow.packets_received,
        "bytes_sent": flow.bytes_sent,
        "bytes_received": flow.bytes_received,
        "mean_packet_size": if packets > 0 { flow.packet_size_sum as f64 / packets as f64 } else { 0.0 },
        "min_packet_size": flow.packet_size_min,
        "max_packet_size": flow.packet_size_max,
        "mean_inter_arrival_ms": if flow.inter_arrival_count > 0 { flow.inter_arrival_sum_ms as f64 / flow.inter_arrival_count as f64 } else { 0.0 },
        "tcp_syn_observed": flow.tcp_syn,
        "tcp_syn_ack_observed": flow.tcp_syn_ack,
        "tcp_ack_observed": flow.tcp_ack,
        "handshake_observed": flow.tls.is_some(),
        "tls_highest_offered_version": flow.tls.as_ref().and_then(|tls| tls.version.as_deref()),
        "tls_fingerprint": flow.tls.as_ref().and_then(|tls| tls.ja3.as_deref()),
        "alpn": flow.tls.as_ref().map(|tls| tls.alpn.iter().filter(|name| matches!(name.as_str(), "h2" | "http/1.1" | "h3")).collect::<Vec<_>>()),
    });
    if share_identity {
        let obj = state.as_object_mut().expect("state is an object");
        obj.insert("source_ip".into(), json!(flow.src.ip()));
        obj.insert("destination_ip".into(), json!(flow.dst.ip()));
        obj.insert(
            "sni".into(),
            json!(flow.tls.as_ref().and_then(|tls| tls.sni.as_deref())),
        );
    }
    json!({
        "model": model,
        "state": state,
        "questions": {
            "traffic_type": {
                "type": "choice",
                "instructions": "Classify this encrypted network flow using only the supplied observable evidence. Select unknown when the evidence cannot reliably distinguish ordinary TLS from a disguised tunnel.",
                "criteria": {
                    "ordinary_tls": "Consistent with ordinary TLS traffic",
                    "suspected_reality": "Potentially consistent with a VLESS REALITY encrypted tunnel",
                    "other_tunnel": "Potentially consistent with another encrypted tunnel",
                    "unknown": "Insufficient information for reliable classification"
                }
            },
            "evidence_strength": {
                "type": "score",
                "instructions": "Evaluate the strength of the observable evidence for the selected traffic class.",
                "criteria": ["No meaningful evidence", "Weak evidence", "Moderate evidence", "Strong evidence"]
            }
        }
    })
}

fn valid_probability(p: f64) -> bool {
    p.is_finite() && (0.0..=1.0).contains(&p)
}

pub fn parse_response(body: &[u8]) -> Result<ClefResult, String> {
    let envelope: Envelope = serde_json::from_slice(body)
        .map_err(|_| "Invalid Cloudflare response schema".to_string())?;
    if !envelope.success {
        return Err("Cloudflare reported an unsuccessful request".into());
    }
    let result = envelope
        .result
        .ok_or_else(|| "Cloudflare response has no result".to_string())?;
    let choice = &result.answers.traffic_type;
    let strength = &result.answers.evidence_strength;
    if choice.kind != "choice"
        || strength.kind != "score"
        || ![
            "ordinary_tls",
            "suspected_reality",
            "other_tunnel",
            "unknown",
        ]
        .contains(&choice.choice.as_str())
        || !choice.probabilities.contains_key(&choice.choice)
        || !valid_probability(choice.confidence)
        || !valid_probability(strength.confidence)
        || !strength.score.is_finite()
        || !(0.0..=3.0).contains(&strength.score)
        || choice
            .probabilities
            .values()
            .chain(strength.probabilities.values())
            .any(|p| !valid_probability(*p))
        || choice.probabilities.len() != 4
        || strength.probabilities.len() != 4
    {
        return Err("Invalid Clef typed answers".into());
    }
    Ok(result)
}

#[derive(Clone)]
pub struct ClefClient {
    client: reqwest::Client,
    endpoint: String,
    token: String,
    model: String,
    share_identity: bool,
    spacing: Duration,
    next_request: Arc<Mutex<Instant>>,
}

impl ClefClient {
    /// Returns None when credentials are unavailable. Credentials are never serialized.
    pub fn from_env() -> Result<Option<Self>, String> {
        let account = std::env::var("CLOUDFLARE_ACCOUNT_ID").unwrap_or_default();
        let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
        if account.trim().is_empty() || token.trim().is_empty() {
            return Ok(None);
        }
        if !account.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("Invalid Cloudflare account ID".into());
        }
        let model = std::env::var("AXION_AI_MODEL").unwrap_or_else(|_| "clef-flash".into());
        if model != "clef-flash" && model != "clef" {
            return Err("AXION_AI_MODEL must be clef-flash or clef".into());
        }
        let rpm = std::env::var("AXION_AI_MAX_REQUESTS_PER_MINUTE")
            .ok()
            .and_then(|x| x.parse::<u32>().ok())
            .unwrap_or(30)
            .clamp(1, 600);
        let share = std::env::var("AXION_AI_SHARE_IDENTITY")
            .unwrap_or_default()
            .eq_ignore_ascii_case("true");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| "Could not initialize Cloudflare HTTP client".to_string())?;
        Ok(Some(Self {
            client, endpoint: format!("https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/@cf/cloudflare/{model}"), token, model, share_identity: share,
            spacing: Duration::from_secs_f64(60.0 / f64::from(rpm)), next_request: Arc::new(Mutex::new(Instant::now())),
        }))
    }

    async fn wait_for_slot(&self) {
        let mut next = self.next_request.lock().await;
        let now = Instant::now();
        if *next > now {
            sleep(*next - now).await;
        }
        *next = Instant::now() + self.spacing;
    }

    /// Attempts transient errors up to three times, without blocking the packet capture loop.
    pub async fn classify(&self, flow: &Flow) -> Result<ClefResult, String> {
        let body = build_request(flow, &self.model, self.share_identity);
        let mut last_error = "Cloudflare request failed".to_string();
        for attempt in 0..3_u32 {
            self.wait_for_slot().await;
            match self
                .client
                .post(&self.endpoint)
                .bearer_auth(&self.token)
                .json(&body)
                .send()
                .await
            {
                Ok(mut response) => {
                    let status = response.status();
                    if status.is_success() {
                        // Cap the accepted response before deserializing it.
                        if response.content_length().is_some_and(|size| size > 65_536) {
                            return Err("Cloudflare response too large".into());
                        }
                        let mut bytes = Vec::new();
                        while let Some(chunk) = response
                            .chunk()
                            .await
                            .map_err(|_| "Cloudflare response read failed".to_string())?
                        {
                            if bytes.len().saturating_add(chunk.len()) > 65_536 {
                                return Err("Cloudflare response too large".into());
                            }
                            bytes.extend_from_slice(&chunk);
                        }
                        return parse_response(&bytes);
                    }
                    last_error = format!("Cloudflare HTTP {status}");
                    if status.as_u16() != 429 && !status.is_server_error() {
                        return Err(last_error);
                    }
                }
                Err(error) => {
                    last_error = if error.is_timeout() {
                        "Cloudflare request timed out"
                    } else {
                        "Cloudflare request failed"
                    }
                    .into();
                }
            }
            if attempt < 2 {
                sleep(Duration::from_secs(1 << attempt)).await;
            }
        }
        Err(last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_typed_cloudflare_envelope() {
        let body = br#"{"success":true,"result":{"model":"clef-flash","answers":{"traffic_type":{"type":"choice","choice":"unknown","confidence":0.7,"probabilities":{"ordinary_tls":0.1,"suspected_reality":0.1,"other_tunnel":0.1,"unknown":0.7}},"evidence_strength":{"type":"score","score":0.4,"confidence":0.7,"legend":{"0":"None","1":"Weak","2":"Moderate","3":"Strong"},"probabilities":{"0":0.7,"1":0.2,"2":0.1,"3":0.0}}}}}"#;
        let result = parse_response(body).unwrap();
        assert_eq!(result.answers.traffic_type.choice, "unknown");
        assert_eq!(result.answers.evidence_strength.probabilities["0"], 0.7);
    }
    #[test]
    fn rejects_failed_and_malformed_envelopes() {
        assert!(parse_response(br#"{"success":false,"result":null}"#).is_err());
        assert!(parse_response(br#"{"success":true,"result":{}}"#).is_err());
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use crate::{
        flow::FlowTable,
        packet::{Packet, Protocol},
        tls::TlsInfo,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    fn sample() -> Flow {
        let p = Packet {
            timestamp_ms: 1,
            src: "192.0.2.1:30000".parse().unwrap(),
            dst: "198.51.100.1:443".parse().unwrap(),
            protocol: Protocol::Tcp,
            wire_len: 100,
            tcp_seq: Some(1),
            tcp_flags: 2,
            payload: vec![],
        };
        let mut f = FlowTable::new(10, 1000).ingest(p);
        f.tls = Some(TlsInfo {
            sni: Some("sensitive.example".into()),
            ..Default::default()
        });
        f
    }
    fn client(endpoint: String, timeout: Duration) -> ClefClient {
        ClefClient {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(timeout)
                .build()
                .unwrap(),
            endpoint,
            token: "test".into(),
            model: "clef-flash".into(),
            share_identity: false,
            spacing: Duration::from_millis(1),
            next_request: Arc::new(Mutex::new(Instant::now())),
        }
    }
    #[test]
    fn request_uses_typed_questions_and_omits_identity_by_default() {
        let body = build_request(&sample(), "clef-flash", false);
        let serialized = body.to_string();
        assert!(!serialized.contains("192.0.2.1"));
        assert!(!serialized.contains("198.51.100.1"));
        assert!(!serialized.contains("sensitive.example"));
        assert_eq!(body["questions"]["traffic_type"]["type"], "choice");
        assert_eq!(body["questions"]["evidence_strength"]["type"], "score");
        assert!(build_request(&sample(), "clef-flash", true)
            .to_string()
            .contains("sensitive.example"));
    }
    #[tokio::test]
    async fn non_retryable_http_error_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            socket
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let err = client(format!("http://{addr}"), Duration::from_secs(2))
            .classify(&sample())
            .await
            .unwrap_err();
        assert!(err.contains("401"));
    }
    #[tokio::test]
    async fn timed_out_request_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _socket = socket;
                    sleep(Duration::from_millis(200)).await;
                });
            }
        });
        let err = client(format!("http://{addr}"), Duration::from_millis(30))
            .classify(&sample())
            .await
            .unwrap_err();
        assert_eq!(err, "Cloudflare request timed out");
    }
}
