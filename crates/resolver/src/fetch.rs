use async_trait::async_trait;
use futures_util::StreamExt;
use http::HeaderMap;
use reqwest::redirect::Policy;
use std::{
    net::IpAddr,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use url::Url;
use web_bot_auth_protocol::DIRECTORY_PATH;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressMode {
    Direct,
    Proxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchErrorKind {
    BadRequest,
    Dns,
    UnsafeAddress,
    RateLimited,
    Overloaded,
    CircuitOpen,
    Timeout,
    Transport,
    HttpStatus,
    MediaType,
    ContentEncoding,
    BodyTooLarge,
    InvalidResource,
}

impl FetchErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Dns => "dns",
            Self::UnsafeAddress => "unsafe_address",
            Self::RateLimited => "rate_limited",
            Self::Overloaded => "overloaded",
            Self::CircuitOpen => "circuit_open",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::HttpStatus => "http_status",
            Self::MediaType => "media_type",
            Self::ContentEncoding => "content_encoding",
            Self::BodyTooLarge => "body_too_large",
            Self::InvalidResource => "invalid_resource",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    Permanent,
    LoadShed,
    Transient,
    CircuitOpen,
}

#[derive(Clone, Debug)]
pub struct FetchError {
    pub kind: FetchErrorKind,
    pub status: Option<http::StatusCode>,
    pub retry_after: Option<Duration>,
}

impl FetchError {
    pub(crate) const fn new(kind: FetchErrorKind) -> Self {
        Self {
            kind,
            status: None,
            retry_after: None,
        }
    }

    pub(crate) fn class(&self) -> FailureClass {
        match self.kind {
            FetchErrorKind::Dns | FetchErrorKind::Timeout | FetchErrorKind::Transport => {
                FailureClass::Transient
            }
            FetchErrorKind::HttpStatus
                if self.status.is_some_and(|status| {
                    matches!(status.as_u16(), 408 | 425 | 429) || status.is_server_error()
                }) =>
            {
                FailureClass::Transient
            }
            FetchErrorKind::CircuitOpen => FailureClass::CircuitOpen,
            FetchErrorKind::RateLimited | FetchErrorKind::Overloaded => FailureClass::LoadShed,
            FetchErrorKind::BadRequest
            | FetchErrorKind::UnsafeAddress
            | FetchErrorKind::HttpStatus
            | FetchErrorKind::MediaType
            | FetchErrorKind::ContentEncoding
            | FetchErrorKind::BodyTooLarge
            | FetchErrorKind::InvalidResource => FailureClass::Permanent,
        }
    }

    pub(crate) fn allows_stale(&self) -> bool {
        matches!(
            self.class(),
            FailureClass::Transient | FailureClass::CircuitOpen
        )
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ResourceKind {
    Jwks,
    Cimd,
}

impl ResourceKind {
    pub(crate) fn accept(self, url: &Url) -> &'static str {
        match self {
            Self::Jwks if is_directory_url(url) => {
                "application/http-message-signatures-directory+json"
            }
            Self::Jwks => "application/jwk-set+json, application/json",
            Self::Cimd => "application/json",
        }
    }

    fn accepts_content_type(self, url: &Url, content_type: Option<&str>) -> bool {
        let Some(essence) = content_type.and_then(|value| value.split(';').next()) else {
            return false;
        };
        let essence = essence.trim().to_ascii_lowercase();
        match self {
            Self::Jwks if is_directory_url(url) => {
                essence == "application/http-message-signatures-directory+json"
            }
            Self::Jwks => matches!(
                essence.as_str(),
                "application/jwk-set+json" | "application/json"
            ),
            Self::Cimd => {
                essence == "application/json"
                    || (essence.starts_with("application/") && essence.ends_with("+json"))
            }
        }
    }
}

pub(super) fn is_directory_url(url: &Url) -> bool {
    url.path() == DIRECTORY_PATH && url.query().is_none() && url.fragment().is_none()
}

#[derive(Clone, Debug)]
pub struct FetchRequest {
    pub url: Url,
    pub kind: ResourceKind,
    pub headers: HeaderMap,
    pub selected_ip: IpAddr,
}

#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub status: http::StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, FetchError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionDns;

#[async_trait]
impl DnsResolver for ProductionDns {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, FetchError> {
        tokio::net::lookup_host((host, port))
            .await
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .map_err(|_| FetchError::new(FetchErrorKind::Dns))
    }
}

#[async_trait]
pub trait HttpFetcher: Send + Sync {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError>;
}

#[derive(Clone)]
pub struct ReqwestFetcher {
    mode: EgressMode,
    proxy: Option<reqwest::Proxy>,
    timeout: Duration,
    #[cfg(test)]
    // Test-only trust injection for local self-signed TLS fixtures. Production
    // construction has no custom CA path or equivalent configuration.
    test_roots: Vec<reqwest::Certificate>,
}

impl ReqwestFetcher {
    pub fn direct(timeout: Duration) -> Self {
        Self {
            mode: EgressMode::Direct,
            proxy: None,
            timeout,
            #[cfg(test)]
            test_roots: Vec::new(),
        }
    }

    pub fn proxy(proxy_url: &str, timeout: Duration) -> Result<Self, &'static str> {
        let proxy = reqwest::Proxy::all(proxy_url).map_err(|_| "invalid HTTPS_PROXY")?;
        Ok(Self {
            mode: EgressMode::Proxy,
            proxy: Some(proxy),
            timeout,
            #[cfg(test)]
            test_roots: Vec::new(),
        })
    }

    #[cfg(test)]
    // This helper never exists in production builds.
    fn with_test_root(mut self, der: &[u8]) -> Self {
        self.test_roots
            .push(reqwest::Certificate::from_der(der).expect("test certificate DER is valid"));
        self
    }

    fn client(&self, request: &FetchRequest) -> Result<reqwest::Client, FetchError> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            // A redirect can change the checked destination.
            .redirect(Policy::none())
            .timeout(self.timeout);
        #[cfg(test)]
        for root in &self.test_roots {
            builder = builder.add_root_certificate(root.clone());
        }
        match self.mode {
            EgressMode::Direct => {
                let host = request
                    .url
                    .host_str()
                    .ok_or_else(|| FetchError::new(FetchErrorKind::Transport))?;
                let port = request
                    .url
                    .port_or_known_default()
                    .ok_or_else(|| FetchError::new(FetchErrorKind::Transport))?;
                // Connect to the checked address, not a later DNS answer.
                builder = builder.resolve(host, SocketAddr::new(request.selected_ip, port));
            }
            EgressMode::Proxy => {
                // Use one explicit proxy. Automatic proxy rules stay off.
                builder = builder.proxy(
                    self.proxy
                        .clone()
                        .ok_or_else(|| FetchError::new(FetchErrorKind::Transport))?,
                );
            }
        }
        builder
            .build()
            .map_err(|_| FetchError::new(FetchErrorKind::Transport))
    }
}

#[async_trait]
impl HttpFetcher for ReqwestFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let client = self.client(&request)?;
        let response = client
            .get(request.url.clone())
            .headers(request.headers.clone())
            .header(http::header::ACCEPT, request.kind.accept(&request.url))
            .header(http::header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|error| {
                FetchError::new(if error.is_timeout() {
                    FetchErrorKind::Timeout
                } else {
                    FetchErrorKind::Transport
                })
            })?;

        let status = response.status();
        let headers = response.headers().clone();
        if !matches!(status.as_u16(), 200 | 304) {
            let retry_after = headers
                .get(http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| parse_retry_after(value, SystemTime::now()));
            return Err(FetchError {
                kind: FetchErrorKind::HttpStatus,
                status: Some(status),
                retry_after,
            });
        }
        if status == http::StatusCode::OK
            && !request.kind.accepts_content_type(
                &request.url,
                headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
            )
        {
            return Err(FetchError::new(FetchErrorKind::MediaType));
        }
        // Compressed data can bypass the body size limit after expansion.
        if headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
        {
            return Err(FetchError::new(FetchErrorKind::ContentEncoding));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(FetchError::new(FetchErrorKind::BodyTooLarge));
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| FetchError::new(FetchErrorKind::Transport))?;
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(FetchError::new(FetchErrorKind::BodyTooLarge));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchResponse {
            status,
            headers,
            body,
        })
    }
}

fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let delay = value
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .and_then(|until| until.duration_since(now).ok())
        })?;
    Some(delay.min(Duration::from_secs(300)))
}

pub(crate) type SharedDns = Arc<dyn DnsResolver>;
pub(crate) type SharedFetcher = Arc<dyn HttpFetcher>;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Mutex,
        task::JoinHandle,
    };
    use tokio_rustls::{TlsAcceptor, rustls};

    #[test]
    fn discovery_media_types_are_specific() {
        let directory =
            Url::parse("https://agent.example/.well-known/http-message-signatures-directory")
                .unwrap();
        let jwks = Url::parse("https://agent.example/keys").unwrap();
        assert_eq!(
            ResourceKind::Jwks.accept(&directory),
            "application/http-message-signatures-directory+json"
        );
        assert!(ResourceKind::Jwks.accepts_content_type(
            &directory,
            Some("application/http-message-signatures-directory+json; charset=utf-8")
        ));
        assert!(!ResourceKind::Jwks.accepts_content_type(&directory, Some("application/json")));
        assert!(ResourceKind::Jwks.accepts_content_type(&jwks, Some("application/jwk-set+json")));
        assert_eq!(ResourceKind::Cimd.accept(&jwks), "application/json");
        assert!(ResourceKind::Cimd.accepts_content_type(
            &jwks,
            Some("application/example-client-metadata+json; charset=utf-8")
        ));
        assert!(!ResourceKind::Cimd.accepts_content_type(&jwks, Some("text/json")));
    }

    #[test]
    fn retry_after_accepts_delta_and_http_date() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(parse_retry_after("10", now), Some(Duration::from_secs(10)));
        assert_eq!(
            parse_retry_after("Thu, 01 Jan 1970 00:21:40 GMT", now),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            parse_retry_after("Thu, 01 Jan 1970 00:16:50 GMT", now),
            Some(Duration::from_secs(10))
        );
        assert_eq!(parse_retry_after("invalid", now), None);
    }

    #[test]
    fn only_remote_failures_are_stale_eligible() {
        assert!(FetchError::new(FetchErrorKind::Transport).allows_stale());
        assert!(FetchError::new(FetchErrorKind::CircuitOpen).allows_stale());
        assert!(!FetchError::new(FetchErrorKind::UnsafeAddress).allows_stale());
        assert!(!FetchError::new(FetchErrorKind::Overloaded).allows_stale());
        assert!(!FetchError::new(FetchErrorKind::InvalidResource).allows_stale());
    }

    #[test]
    fn only_retryable_http_statuses_use_transient_policy() {
        let retryable = FetchError {
            kind: FetchErrorKind::HttpStatus,
            status: Some(http::StatusCode::TOO_MANY_REQUESTS),
            retry_after: None,
        };
        assert_eq!(retryable.class(), FailureClass::Transient);

        let permanent = FetchError {
            kind: FetchErrorKind::HttpStatus,
            status: Some(http::StatusCode::NOT_FOUND),
            retry_after: None,
        };
        assert_eq!(permanent.class(), FailureClass::Permanent);
    }

    fn request_for(url: Url) -> FetchRequest {
        FetchRequest {
            url,
            kind: ResourceKind::Jwks,
            headers: HeaderMap::new(),
            selected_ip: "127.0.0.1".parse().unwrap(),
        }
    }

    fn response_bytes(
        status: u16,
        reason: &str,
        content_type: Option<&str>,
        content_encoding: Option<&str>,
        body: &[u8],
    ) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(content_type) = content_type {
            response.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        if let Some(content_encoding) = content_encoding {
            response.push_str(&format!("Content-Encoding: {content_encoding}\r\n"));
        }
        response.push_str("\r\n");
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    struct TlsOrigin {
        address: SocketAddr,
        certificate: Vec<u8>,
        task: JoinHandle<()>,
    }

    impl Drop for TlsOrigin {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn tls_origin(response: Vec<u8>, delay: Option<Duration>) -> TlsOrigin {
        // Reqwest and the test server enable both rustls providers through
        // different dependency paths, so choose one explicitly for tests.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["origin.test".to_owned()])
            .expect("test certificate generation succeeds");
        let certificate = certified.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()),
        );
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(certificate.clone())],
                key,
            )
            .expect("test server certificate is usable");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test TLS listener binds");
        let address = listener.local_addr().expect("test listener has address");
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let _ = stream.write_all(&response).await;
        });
        TlsOrigin {
            address,
            certificate,
            task,
        }
    }

    struct HttpProxy {
        address: SocketAddr,
        target: Arc<Mutex<Option<String>>>,
        task: JoinHandle<()>,
    }

    impl Drop for HttpProxy {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn http_connect_proxy(origin: SocketAddr) -> HttpProxy {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test proxy listener binds");
        let address = listener.local_addr().expect("test proxy has address");
        let target = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&target);
        let task = tokio::spawn(async move {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let Ok(read) = client.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.len() > 8192 {
                    return;
                }
            }
            let first_line = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            *recorded.lock().await = first_line.split_whitespace().nth(1).map(str::to_owned);
            let Ok(mut upstream) = TcpStream::connect(origin).await else {
                return;
            };
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });
        HttpProxy {
            address,
            target,
            task,
        }
    }

    #[tokio::test]
    #[ignore = "requires local TCP sockets"]
    async fn direct_mode_pins_the_selected_address_and_validates_tls() {
        let body = br#"{"keys":[]}"#;
        let origin = tls_origin(
            response_bytes(200, "OK", Some("application/jwk-set+json"), None, body),
            None,
        )
        .await;
        let url = Url::parse(&format!(
            "https://origin.test:{}/keys",
            origin.address.port()
        ))
        .unwrap();
        let fetcher =
            ReqwestFetcher::direct(Duration::from_secs(2)).with_test_root(&origin.certificate);
        let response = fetcher.fetch(request_for(url)).await.unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.body, body);
    }

    #[tokio::test]
    #[ignore = "requires local TCP sockets"]
    async fn explicit_proxy_has_no_direct_fallback() {
        let body = br#"{"keys":[]}"#;
        let origin = tls_origin(
            response_bytes(200, "OK", Some("application/jwk-set+json"), None, body),
            None,
        )
        .await;
        let proxy = http_connect_proxy(origin.address).await;
        let url = Url::parse(&format!(
            "https://origin.test:{}/keys",
            origin.address.port()
        ))
        .unwrap();
        let fetcher =
            ReqwestFetcher::proxy(&format!("http://{}", proxy.address), Duration::from_secs(2))
                .unwrap()
                .with_test_root(&origin.certificate);
        let response = fetcher.fetch(request_for(url.clone())).await.unwrap();
        assert_eq!(response.body, body);
        let expected_target = format!("origin.test:{}", origin.address.port());
        assert_eq!(
            proxy.target.lock().await.as_deref(),
            Some(expected_target.as_str())
        );
        drop(proxy);
        let error = fetcher.fetch(request_for(url)).await.unwrap_err();
        assert!(matches!(
            error.kind,
            FetchErrorKind::Transport | FetchErrorKind::Timeout
        ));
    }

    #[tokio::test]
    #[ignore = "requires local TCP sockets"]
    async fn transport_enforces_status_media_encoding_and_size_policies() {
        let cases = [
            (
                response_bytes(302, "Found", None, None, b""),
                FetchErrorKind::HttpStatus,
            ),
            (
                response_bytes(200, "OK", Some("text/plain"), None, b"{}"),
                FetchErrorKind::MediaType,
            ),
            (
                response_bytes(
                    200,
                    "OK",
                    Some("application/jwk-set+json"),
                    Some("gzip"),
                    b"{}",
                ),
                FetchErrorKind::ContentEncoding,
            ),
            (
                response_bytes(
                    200,
                    "OK",
                    Some("application/jwk-set+json"),
                    None,
                    &vec![b'x'; MAX_RESPONSE_BYTES + 1],
                ),
                FetchErrorKind::BodyTooLarge,
            ),
        ];
        for (response, expected) in cases {
            let origin = tls_origin(response, None).await;
            let url = Url::parse(&format!(
                "https://origin.test:{}/keys",
                origin.address.port()
            ))
            .unwrap();
            let fetcher =
                ReqwestFetcher::direct(Duration::from_secs(2)).with_test_root(&origin.certificate);
            assert_eq!(
                fetcher.fetch(request_for(url)).await.unwrap_err().kind,
                expected
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires local TCP sockets"]
    async fn transport_maps_tls_timeout_to_bounded_error() {
        let origin = tls_origin(
            response_bytes(
                200,
                "OK",
                Some("application/jwk-set+json"),
                None,
                br#"{"keys":[]}"#,
            ),
            Some(Duration::from_millis(100)),
        )
        .await;
        let url = Url::parse(&format!(
            "https://origin.test:{}/keys",
            origin.address.port()
        ))
        .unwrap();
        let fetcher =
            ReqwestFetcher::direct(Duration::from_millis(10)).with_test_root(&origin.certificate);
        assert_eq!(
            fetcher.fetch(request_for(url)).await.unwrap_err().kind,
            FetchErrorKind::Timeout
        );
    }
}
