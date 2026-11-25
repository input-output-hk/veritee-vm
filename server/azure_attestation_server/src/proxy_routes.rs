//! Phase 3 of the attested channel (issue #15): the decrypt-and-forward
//! `POST /proxy` record layer.
//!
//! Once a session is `Established` (see `POST /session[/complete]`), the client
//! tunnels application traffic through the enclave as AEAD records:
//!
//! - the client seals a request with its `c2s` key and posts the ciphertext;
//! - the enclave **decrypts in-VM**, forwards the plaintext to the DApp over the
//!   local hop, then **re-encrypts** the DApp's response with the `s2c` key.
//!
//! The plaintext never leaves the TEE in the clear on the untrusted network:
//! confidentiality/integrity ride on the record keys derived during the
//! attested handshake, so a network attacker (incl. a TLS-terminating proxy)
//! sees only ciphertext bound to `sid`.
//!
//! ## Outer wire format
//!
//! Request `{ "sid": b64, "ciphertext": b64 }` → Response `{ "ciphertext": b64 }`.
//! The AEAD associated data is the raw `sid`, matching the client. The record
//! layer's directional nonces (`dir ‖ seq`) provide ordering / anti-replay, so a
//! session processes its records strictly in order.
//!
//! ## Encrypted tunnel format
//!
//! The decrypted client record is a versioned HTTP tunnel request:
//!
//! `{ "version": 1, "request": { "method", "path", "query", "headers", "body" } }`.
//!
//! The encrypted server response is:
//!
//! `{ "version": 1, "response": { "status", "headers", "body" } }`.
//!
//! Normal DApp 4xx/5xx responses stay inside that encrypted response and do not
//! drop the attested session. Transport/protocol/AEAD failures still drop it.
//!
//! ## Concurrency
//!
//! Open → upstream await → seal must not interleave for the same `sid` (that
//! would desynchronise c2s/s2c sequence counters). [`ProxyGates`] holds a
//! per-`sid` async mutex across the whole round-trip; the session-store lock is
//! still only held inside brief `with_records` calls (never across the await).
//! Distinct sessions remain fully concurrent.
//!
//! ## Failure handling
//!
//! Any per-record failure (unknown/expired `sid`, AEAD open failure, or an
//! upstream error after the request counter has already advanced) leaves the
//! record streams desynchronised, so the session is **dropped** and the client
//! must re-establish. This is deliberately coarse — a peer cannot probe failure
//! sub-cases to mount a padding-oracle-style attack.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};

use akx::{SessionError, SessionStore};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};

const MAX_PROXY_PATHS: usize = 64;
const MAX_PROXY_PATH_BYTES: usize = 1024;
const MAX_PROXY_POLICY_BYTES: u64 = 65536;

/// Per-`sid` single-flight gates for [`post_proxy`].
///
/// Keeps one `tokio::sync::Mutex` per session id so concurrent `/proxy` calls
/// for the same session serialize. Idle gates are dropped when the last waiter
/// finishes (`Arc` strong-count check) so the map does not grow without bound.
#[derive(Default)]
pub struct ProxyGates {
    inner: Mutex<HashMap<Vec<u8>, Arc<tokio::sync::Mutex<()>>>>,
}

impl ProxyGates {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the flight lock for `sid`, creating it if needed.
    fn gate_for(&self, sid: &[u8]) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.inner.lock().expect("proxy gates poisoned");
        map.entry(sid.to_vec())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Remove the gate when nothing else holds a clone (no in-flight / waiter).
    fn forget_if_idle(&self, sid: &[u8]) {
        let mut map = self.inner.lock().expect("proxy gates poisoned");
        let idle = map
            .get(sid)
            .map(|gate| Arc::strong_count(gate) == 1)
            .unwrap_or(false);
        if idle {
            map.remove(sid);
        }
    }
}

/// The DApp endpoint the enclave forwards decrypted requests to.
///
/// Cloneable (holds a connection-pooling [`reqwest::Client`]) so it can live in
/// the shared Axum state. The exact hop (loopback-published `app` port vs. the
/// Caddy `api` endpoint) is a deployment detail resolved in Phase 5; it is
/// configured via the `DAPP_UPSTREAM_URL` env var.
#[derive(Clone)]
pub struct DappUpstream {
    client: reqwest::Client,
    base_url: Url,
    allowed_paths: HashSet<String>,
}

impl DappUpstream {
    pub fn new(base_url: impl AsRef<str>) -> anyhow::Result<Self> {
        let base_url = parse_base_url(base_url.as_ref())?;
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(120))
                .build()?,
            base_url,
            allowed_paths: HashSet::new(),
        })
    }

    /// Read the fixed origin and measured policy file installed by guest setup.
    /// A configured file is authoritative, including when it is absent: never
    /// fall back to environment routes after a failed measured setup.
    pub fn from_env() -> anyhow::Result<Self> {
        let base_url = std::env::var("DAPP_UPSTREAM_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let policy_file = std::env::var_os("DAPP_PROXY_POLICY_FILE");
        Self::from_configuration(
            &base_url,
            policy_file.as_deref().map(Path::new),
            std::env::var("DAPP_PROXY_ALLOWED_PATHS").ok(),
        )
    }

    fn from_configuration(
        base_url: &str,
        policy_file: Option<&Path>,
        environment_paths: Option<String>,
    ) -> anyhow::Result<Self> {
        let mut upstream = Self::new(base_url)?;
        upstream.allowed_paths = match policy_file {
            Some(path) => load_route_policy(path)?,
            None => parse_allowed_paths(environment_paths)?,
        };
        Ok(upstream)
    }

    /// Forward the decrypted HTTP tunnel request to the DApp and return the
    /// response envelope. Non-2xx DApp responses are normal application
    /// responses and intentionally do not become proxy transport errors.
    async fn forward(&self, request: TunnelRequest) -> Result<TunnelResponse, ProxyError> {
        let method = parse_method(&request.method)?;
        let url = self.target_url(&request.path, &request.query)?;
        let headers = request_headers(&request.headers)?;

        let resp = self
            .client
            .request(method, url)
            .headers(headers)
            .body(request.body)
            .send()
            .await
            .map_err(|_| ProxyError::Upstream)?;

        let status = resp.status().as_u16();
        let headers = response_headers(resp.headers());
        let body = resp
            .bytes()
            .await
            .map_err(|_| ProxyError::Upstream)?
            .to_vec();

        Ok(TunnelResponse {
            status,
            headers,
            body,
        })
    }

    fn target_url(&self, path: &str, query: &[QueryPair]) -> Result<Url, ProxyError> {
        validate_path(path)?;
        if !self.allowed_paths.contains(path) {
            return Err(ProxyError::ForbiddenPath);
        }

        let mut url = self.base_url.clone();
        url.set_path(path);
        url.set_query(None);
        {
            let mut pairs = url.query_pairs_mut();
            for pair in query {
                validate_query_component(&pair.0)?;
                validate_query_component(&pair.1)?;
                pairs.append_pair(&pair.0, &pair.1);
            }
        }
        Ok(url)
    }
}

type QueryPair = (String, String);

#[derive(Deserialize)]
pub struct TunnelEnvelope {
    version: u8,
    request: TunnelRequest,
}

#[derive(Deserialize)]
pub struct TunnelRequest {
    method: String,
    path: String,
    #[serde(default)]
    query: Vec<QueryPair>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default, with = "crate::base64")]
    body: Vec<u8>,
}

#[derive(Serialize)]
pub struct TunnelResponseEnvelope {
    version: u8,
    response: TunnelResponse,
}

#[derive(Serialize)]
pub struct TunnelResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    #[serde(with = "crate::base64")]
    body: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRequest {
    #[serde(with = "crate::base64")]
    sid: Vec<u8>,
    #[serde(with = "crate::base64")]
    ciphertext: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyResponse {
    #[serde(with = "crate::base64")]
    ciphertext: Vec<u8>,
}

/// `POST /proxy` — decrypt a client record, forward to the DApp, re-encrypt the
/// response.
pub async fn post_proxy(
    State(sessions): State<Arc<SessionStore>>,
    State(upstream): State<DappUpstream>,
    State(gates): State<Arc<ProxyGates>>,
    Json(req): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ProxyError> {
    let sid = req.sid;

    // Reject before allocating a flight lock for unknown / pending sids.
    sessions.ensure_established(&sid)?;

    let gate = gates.gate_for(&sid);
    // Async block so early `return Err` still runs cleanup below.
    let result: Result<Json<ProxyResponse>, ProxyError> = async {
        // Serialize open → upstream → seal for this sid only.
        let _flight = gate.lock().await;

        // 1. Decrypt the client -> server record in-VM (aad = sid).
        let plaintext =
            match sessions.with_records(&sid, |c2s, _s2c| c2s.open(&sid, &req.ciphertext)) {
                Ok(Ok(pt)) => pt,
                Ok(Err(_aead)) => {
                    sessions.remove(&sid);
                    return Err(ProxyError::BadRecord);
                }
                Err(e) => return Err(ProxyError::from(e)),
            };

        let request = match decode_tunnel_request(&plaintext) {
            Ok(request) => request,
            Err(err) => {
                sessions.remove(&sid);
                return Err(err);
            }
        };

        // 2. Forward plaintext; session-store lock is *not* held across await.
        let response = match upstream.forward(request).await {
            Ok(response) => response,
            Err(err) if err.is_transport() => {
                // The c2s counter already advanced; the stream is unrecoverable.
                sessions.remove(&sid);
                return Err(err);
            }
            Err(err) => {
                sessions.remove(&sid);
                return Err(err);
            }
        };

        let response_body = match serde_json::to_vec(&TunnelResponseEnvelope {
            version: 1,
            response,
        }) {
            Ok(body) => body,
            Err(_e) => {
                sessions.remove(&sid);
                return Err(ProxyError::BadTunnel);
            }
        };

        // 3. Seal the server -> client response (aad = sid).
        match sessions.with_records(&sid, |_c2s, s2c| s2c.seal(&sid, &response_body)) {
            Ok(Ok(ct)) => Ok(Json(ProxyResponse { ciphertext: ct })),
            Ok(Err(_aead)) => {
                sessions.remove(&sid);
                Err(ProxyError::BadRecord)
            }
            Err(e) => Err(ProxyError::from(e)),
        }
    }
    .await;

    // Drop our Arc clone, then scrub the map entry if no other waiter remains.
    drop(gate);
    gates.forget_if_idle(&sid);

    result
}

/// Errors surfaced by `POST /proxy`, mapped to HTTP status codes.
#[derive(Debug)]
pub enum ProxyError {
    /// Session absent/expired.
    NotFound,
    /// Session exists but the handshake is not complete.
    NotEstablished,
    /// AEAD open/seal failure (tampered/replayed/desynchronised record).
    BadRecord,
    /// Decrypted tunnel request was malformed.
    BadTunnel,
    /// Tunnel path is valid syntax but not allowed by route policy.
    ForbiddenPath,
    /// The DApp hop failed at the transport layer.
    Upstream,
}

impl From<SessionError> for ProxyError {
    fn from(err: SessionError) -> Self {
        match err {
            SessionError::NotFound => ProxyError::NotFound,
            SessionError::WrongState => ProxyError::NotEstablished,
            _ => ProxyError::BadRecord,
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ProxyError::NotFound => (StatusCode::NOT_FOUND, "unknown or expired session"),
            ProxyError::NotEstablished => (StatusCode::CONFLICT, "session handshake not complete"),
            ProxyError::BadRecord => (StatusCode::BAD_REQUEST, "record authentication failed"),
            ProxyError::BadTunnel => (StatusCode::BAD_REQUEST, "malformed tunnel request"),
            ProxyError::ForbiddenPath => (StatusCode::FORBIDDEN, "tunnel path is not allowed"),
            ProxyError::Upstream => (StatusCode::BAD_GATEWAY, "upstream DApp transport error"),
        };
        (status, msg).into_response()
    }
}

impl ProxyError {
    fn is_transport(&self) -> bool {
        matches!(self, ProxyError::Upstream)
    }
}

fn decode_tunnel_request(plaintext: &[u8]) -> Result<TunnelRequest, ProxyError> {
    let envelope: TunnelEnvelope =
        serde_json::from_slice(plaintext).map_err(|_| ProxyError::BadTunnel)?;
    if envelope.version != 1 {
        return Err(ProxyError::BadTunnel);
    }
    Ok(envelope.request)
}

fn parse_base_url(value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    match url.scheme() {
        "http" | "https" => {}
        _ => anyhow::bail!("DAPP_UPSTREAM_URL must use http or https"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("DAPP_UPSTREAM_URL must not include credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("DAPP_UPSTREAM_URL must not include a query or fragment");
    }
    if !matches!(url.path(), "" | "/") {
        anyhow::bail!("DAPP_UPSTREAM_URL must be an origin/base URL, not a route");
    }
    Ok(url)
}

fn parse_allowed_paths(value: Option<String>) -> anyhow::Result<HashSet<String>> {
    let paths = value
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect();
    validate_allowed_paths(paths)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutePolicy {
    version: u32,
    allowed_paths: Vec<String>,
}

fn load_route_policy(path: &Path) -> anyhow::Result<HashSet<String>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(_) => anyhow::bail!("could not read measured DApp proxy policy"),
    };
    let mut bytes = Vec::new();
    file.take(MAX_PROXY_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROXY_POLICY_BYTES {
        anyhow::bail!("measured DApp proxy policy exceeds size limit");
    }
    let policy: RoutePolicy = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid measured DApp proxy policy"))?;
    if policy.version != 1 {
        anyhow::bail!("unsupported measured DApp proxy policy version");
    }
    validate_allowed_paths(policy.allowed_paths)
}

fn validate_allowed_paths(paths: Vec<String>) -> anyhow::Result<HashSet<String>> {
    if paths.len() > MAX_PROXY_PATHS {
        anyhow::bail!("too many DApp proxy paths");
    }
    let mut allowed = HashSet::new();
    for path in paths {
        validate_path(&path).map_err(|_| anyhow::anyhow!("invalid DApp proxy path"))?;
        if !allowed.insert(path) {
            anyhow::bail!("duplicate DApp proxy path");
        }
    }
    Ok(allowed)
}

fn parse_method(value: &str) -> Result<Method, ProxyError> {
    let method = Method::from_bytes(value.as_bytes()).map_err(|_| ProxyError::BadTunnel)?;
    if method == Method::GET
        || method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
    {
        Ok(method)
    } else {
        Err(ProxyError::BadTunnel)
    }
}

fn request_headers(headers: &BTreeMap<String, String>) -> Result<HeaderMap, ProxyError> {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-type") {
            return Err(ProxyError::BadTunnel);
        }
        let header_name = HeaderName::from_lowercase(name.to_ascii_lowercase().as_bytes())
            .map_err(|_| ProxyError::BadTunnel)?;
        let header_value = HeaderValue::from_str(value).map_err(|_| ProxyError::BadTunnel)?;
        out.insert(header_name, header_value);
    }
    Ok(out)
}

fn response_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(value) = headers.get(CONTENT_TYPE) {
        if let Ok(value) = value.to_str() {
            out.insert("content-type".to_string(), value.to_string());
        }
    }
    out
}

fn validate_path(path: &str) -> Result<(), ProxyError> {
    if path.is_empty()
        || path.len() > MAX_PROXY_PATH_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
        || path.contains("://")
        || path.chars().any(char::is_control)
    {
        return Err(ProxyError::BadTunnel);
    }

    for segment in path.split('/') {
        let decoded = percent_decode(segment)?;
        if decoded == b"."
            || decoded == b".."
            || decoded.contains(&b'/')
            || decoded.contains(&b'\\')
        {
            return Err(ProxyError::BadTunnel);
        }
    }
    Ok(())
}

fn validate_query_component(value: &str) -> Result<(), ProxyError> {
    if value.chars().any(char::is_control) {
        return Err(ProxyError::BadTunnel);
    }
    Ok(())
}

fn percent_decode(value: &str) -> Result<Vec<u8>, ProxyError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ProxyError::BadTunnel);
            }
            let hi = hex_value(bytes[i + 1])?;
            let lo = hex_value(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, ProxyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ProxyError::BadTunnel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn upstream_with_paths(base_url: impl AsRef<str>, paths: &[&str]) -> DappUpstream {
        let mut upstream = DappUpstream::new(base_url).unwrap();
        upstream.allowed_paths = paths.iter().map(|path| path.to_string()).collect();
        upstream
    }

    fn established_session() -> (Arc<SessionStore>, Vec<u8>, akx::RecordKey, akx::RecordKey) {
        let epoch = akx::EpochManager::new(&akx::FakeAttester, 1).unwrap();
        let sid = b"proxy-routing-test".to_vec();
        let nonce = b"client-nonce";
        let (pending, handshake) = epoch.begin_session(&sid, nonce);
        let (enc, c2s, s2c) =
            akx::client_establish(&epoch.epoch_public(), &sid, nonce, &handshake).unwrap();
        let sessions = Arc::new(SessionStore::new(akx::SessionConfig::default()));
        sessions.insert_pending(sid.clone(), pending).unwrap();
        sessions.complete(&sid, &enc).unwrap();
        (sessions, sid, c2s, s2c)
    }

    #[tokio::test]
    async fn encrypted_check_and_prove_preserve_routes_and_survive_application_errors() {
        let app = axum::Router::new()
            .route("/check", axum::routing::get(|| async { "checked" }))
            .route(
                "/prove",
                axum::routing::post(
                    |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                        assert_eq!(headers[CONTENT_TYPE], "application/octet-stream");
                        assert_eq!(body.as_ref(), &[0, 255, 1, 128]);
                        vec![0, 254, 2, 129]
                    },
                ),
            )
            .route(
                "/error",
                axum::routing::post(|| async { (StatusCode::BAD_REQUEST, "invalid proof input") }),
            )
            .route(
                "/redirect",
                axum::routing::get(|| async {
                    axum::response::Redirect::temporary("http://127.0.0.1:1/must-not-follow")
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let upstream = upstream_with_paths(
            format!("http://{address}"),
            &["/check", "/prove", "/error", "/redirect"],
        );
        let gates = Arc::new(ProxyGates::new());
        let (sessions, sid, mut c2s, mut s2c) = established_session();

        for (method, path, expected_status, expected_body) in [
            ("GET", "/check", 200, b"checked".as_slice()),
            ("POST", "/error", 400, b"invalid proof input".as_slice()),
            ("POST", "/prove", 200, [0, 254, 2, 129].as_slice()),
            ("GET", "/redirect", 307, b"".as_slice()),
            ("GET", "/check", 200, b"checked".as_slice()),
        ] {
            let plaintext = serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "request": {"method": method, "path": path,
                    "headers": {"content-type": "application/octet-stream"},
                    "body": "AP8BgA=="}
            }))
            .unwrap();
            let ciphertext = c2s.seal(&sid, &plaintext).unwrap();
            let response = post_proxy(
                State(sessions.clone()),
                State(upstream.clone()),
                State(gates.clone()),
                Json(ProxyRequest {
                    sid: sid.clone(),
                    ciphertext,
                }),
            )
            .await
            .unwrap()
            .0;
            let decrypted = s2c.open(&sid, &response.ciphertext).unwrap();
            let decoded: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
            assert_eq!(decoded["version"], 1);
            assert_eq!(decoded["response"]["status"], expected_status);
            use crate::b64::prelude::{Engine as _, BASE64_STANDARD};
            let body = BASE64_STANDARD
                .decode(decoded["response"]["body"].as_str().unwrap())
                .unwrap();
            assert_eq!(body, expected_body);
            sessions.ensure_established(&sid).unwrap();
        }
        server.abort();
        assert!(gates.inner.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn transport_failure_drops_the_encrypted_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let upstream = upstream_with_paths(format!("http://{address}"), &["/check"]);
        let (sessions, sid, mut c2s, _) = established_session();
        let ciphertext = c2s
            .seal(
                &sid,
                br#"{"version":1,"request":{"method":"GET","path":"/check","body":""}}"#,
            )
            .unwrap();
        let response = post_proxy(
            State(sessions.clone()),
            State(upstream),
            State(Arc::new(ProxyGates::new())),
            Json(ProxyRequest {
                sid: sid.clone(),
                ciphertext,
            }),
        )
        .await;
        assert!(matches!(response, Err(ProxyError::Upstream)));
        assert!(sessions.ensure_established(&sid).is_err());
    }

    #[test]
    fn target_url_keeps_fixed_origin_and_encoded_query_values() {
        let upstream = upstream_with_paths("http://127.0.0.1:8080", &["/check"]);
        let url = upstream
            .target_url("/check", &[("value".into(), "a&b=#c".into())])
            .unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/check");
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![("value".into(), "a&b=#c".into())]
        );
    }

    #[test]
    fn missing_or_empty_allowlist_denies_all_routes() {
        for configured in [None, Some(String::new()), Some(" , ".into())] {
            let mut upstream = upstream_with_paths("http://127.0.0.1:8080", &[]);
            upstream.allowed_paths = parse_allowed_paths(configured).unwrap();
            for path in ["/check", "/prove", "/admin"] {
                assert!(matches!(
                    upstream.target_url(path, &[]),
                    Err(ProxyError::ForbiddenPath)
                ));
            }
        }
    }

    #[test]
    fn explicit_allowlist_exposes_only_exact_configured_routes() {
        let mut upstream = upstream_with_paths("http://127.0.0.1:8080", &[]);
        upstream.allowed_paths = parse_allowed_paths(Some(" /check, /prove ".into())).unwrap();
        for path in ["/check", "/prove"] {
            assert!(upstream.target_url(path, &[]).is_ok());
        }
        for path in ["/admin", "/prove/admin", "/check/"] {
            assert!(matches!(
                upstream.target_url(path, &[]),
                Err(ProxyError::ForbiddenPath)
            ));
        }
        assert!(parse_allowed_paths(Some("/check,/%2e%2e/admin".into())).is_err());
    }

    #[tokio::test]
    async fn measured_proof_metadata_configures_policy_and_forwarding() {
        let app = axum::Router::new()
            .route("/check", axum::routing::post(|| async { "checked" }))
            .route("/prove", axum::routing::post(|| async { "proof" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("dapp-proxy.json");
        // Execute the exact pure-Python helper installed by both OS targets,
        // using the preprod project's measured metadata.
        let status = std::process::Command::new("python3")
            .arg("-c")
            .arg(concat!(
                "import json, sys\n",
                "from pathlib import Path\n",
                "sys.path.insert(0, sys.argv[1])\n",
                "from proxy_policy import install_proxy_policy\n",
                "install_proxy_policy(json.loads(Path(sys.argv[2]).read_text()), Path(sys.argv[3]))\n"
            ))
            .arg(repo.join("cli/veritee"))
            .arg(repo.join("projects/proof_server_preprod/metadata.json"))
            .arg(&policy_path)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "measured policy installation failed for the preprod test project"
        );
        let upstream = DappUpstream::from_configuration(
            &format!("http://{address}"),
            Some(&policy_path),
            Some("/admin".into()),
        )
        .unwrap();
        for (path, expected) in [("/check", b"checked".as_slice()), ("/prove", b"proof")] {
            let response = upstream
                .forward(TunnelRequest {
                    method: "POST".into(),
                    path: path.into(),
                    query: vec![],
                    headers: BTreeMap::new(),
                    body: vec![],
                })
                .await
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, expected);
        }
        for path in ["/admin", "/check/", "/prove/admin"] {
            assert!(matches!(
                upstream.target_url(path, &[]),
                Err(ProxyError::ForbiddenPath)
            ));
        }
        server.abort();
    }

    #[test]
    fn missing_or_empty_measured_policy_never_falls_back_to_environment_routes() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("policy.json");
        for content in [None, Some(r#"{"version":1,"allowed_paths":[]}"#)] {
            if let Some(content) = content {
                std::fs::write(&policy_path, content).unwrap();
            }
            let upstream = DappUpstream::from_configuration(
                "http://127.0.0.1:8080",
                Some(&policy_path),
                Some("/check,/prove".into()),
            )
            .unwrap();
            for path in ["/check", "/prove", "/admin"] {
                assert!(matches!(
                    upstream.target_url(path, &[]),
                    Err(ProxyError::ForbiddenPath)
                ));
            }
        }
    }

    #[test]
    fn invalid_measured_policy_rejects_startup() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("policy.json");
        for content in [
            "".to_string(),
            r#"{"version":2,"allowed_paths":["/prove"]}"#.into(),
            r#"{"version":1,"allowed_paths":["/prove"],"other":true}"#.into(),
            r#"{"version":1,"allowed_paths":null}"#.into(),
            r#"{"version":1,"allowed_paths":["/prove"],"allowed_paths":[]}"#.into(),
            r#"{"version":1,"allowed_paths":["/check","/check"]}"#.into(),
            r#"{"version":1,"allowed_paths":["/%2e%2e/admin"]}"#.into(),
            " ".repeat(MAX_PROXY_POLICY_BYTES as usize + 1),
            serde_json::json!({"version": 1, "allowed_paths": vec!["/check"; MAX_PROXY_PATHS + 1]})
                .to_string(),
        ] {
            std::fs::write(&policy_path, content).unwrap();
            assert!(DappUpstream::from_configuration(
                "http://127.0.0.1:8080",
                Some(&policy_path),
                Some("/prove".into())
            )
            .is_err());
        }
    }

    #[test]
    fn base_url_rejects_fixed_routes_credentials_and_query_strings() {
        for url in [
            "http://127.0.0.1:8080/prove",
            "http://user:secret@127.0.0.1:8080",
            "http://127.0.0.1:8080/?token=secret",
            "http://127.0.0.1:8080/#fragment",
        ] {
            assert!(parse_base_url(url).is_err());
        }
    }

    #[tokio::test]
    async fn proxy_gates_serialize_same_sid() {
        let gates = Arc::new(ProxyGates::new());
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let mut joins = Vec::new();
        for _ in 0..8 {
            let gates = gates.clone();
            let concurrent = concurrent.clone();
            let max_seen = max_seen.clone();
            joins.push(tokio::spawn(async move {
                let sid = b"same";
                let gate = gates.gate_for(sid);
                let _flight = gate.lock().await;
                let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                concurrent.fetch_sub(1, Ordering::SeqCst);
                drop(_flight);
                drop(gate);
                gates.forget_if_idle(sid);
            }));
        }
        for j in joins {
            j.await.unwrap();
        }
        assert_eq!(max_seen.load(Ordering::SeqCst), 1);
        assert!(gates.inner.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn proxy_gates_allow_distinct_sids() {
        let gates = Arc::new(ProxyGates::new());
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let mut joins = Vec::new();
        for i in 0..4u8 {
            let gates = gates.clone();
            let concurrent = concurrent.clone();
            let max_seen = max_seen.clone();
            joins.push(tokio::spawn(async move {
                let sid = vec![i];
                let gate = gates.gate_for(&sid);
                let _flight = gate.lock().await;
                let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                concurrent.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for j in joins {
            j.await.unwrap();
        }
        assert!(max_seen.load(Ordering::SeqCst) > 1);
    }

    #[test]
    fn validate_path_accepts_absolute_path_form() {
        validate_path("/prove").unwrap();
        validate_path("/l2/cardano-eutxo/transactions").unwrap();
    }

    #[test]
    fn validate_path_rejects_absolute_destinations_and_traversal() {
        for path in [
            "",
            "prove",
            "//evil.example/prove",
            "/http://evil.example/prove",
            "/../secret",
            "/%2e%2e/secret",
            "/safe/%2f/secret",
            "/safe\\secret",
            "/prove?x=1",
            "/prove#frag",
        ] {
            assert!(validate_path(path).is_err(), "{path} should be rejected");
        }
    }

    #[test]
    fn decode_tunnel_request_requires_supported_version() {
        let good = br#"{"version":1,"request":{"method":"GET","path":"/check","body":""}}"#;
        assert!(decode_tunnel_request(good).is_ok());

        let bad = br#"{"version":2,"request":{"method":"GET","path":"/check","body":""}}"#;
        assert!(decode_tunnel_request(bad).is_err());
    }
}
