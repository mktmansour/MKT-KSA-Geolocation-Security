/*!
Arabic: وحدة الويب هوك صفر تبعيات مع واجهات قياسية ومحولات اختيارية.

English: Zero-deps webhook module with standard traits and optional adapters.
*/

/// نقطة دخول/خروج ويب هوك موحّدة.
/// Unified webhook endpoint abstraction.
pub trait WebhookEndpoint: Send + Sync {
    /// يستقبل حمولة JSON كسلسلة ويعيد حالة نجاح/فشل.
    /// Receives JSON payload as string and returns success/failure.
    fn receive(&self, json_payload: &str) -> Result<(), WebhookError>;
}

/// عميل إرسال ويب هوك.
/// Webhook sender client abstraction.
pub trait WebhookClient: Send + Sync {
    /// يرسل JSON إلى عنوان.
    /// Sends JSON to a URL.
    fn send(&self, url: &str, json_payload: &str) -> Result<(), WebhookError>;
}

pub mod guards;

/// أخطاء ويب هوك يدوية بلا تبعيات.
/// Manual zero-deps webhook errors.
#[derive(Debug, Clone)]
pub enum WebhookError {
    InvalidUrl,
    Transport(String),
    Handler(String),
}

impl core::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidUrl => write!(f, "Invalid URL"),
            Self::Transport(e) => write!(f, "Transport error: {e}"),
            Self::Handler(e) => write!(f, "Handler error: {e}"),
        }
    }
}

impl std::error::Error for WebhookError {}

/// تنفيذ افتراضي مستلم يعتمد على دالة يمررها المستخدم.
/// Default receiver backed by a user-provided function.
pub struct FnWebhookEndpoint<F>
where
    F: Fn(&str) -> Result<(), WebhookError> + Send + Sync + 'static,
{
    handler: F,
}

impl<F> FnWebhookEndpoint<F>
where
    F: Fn(&str) -> Result<(), WebhookError> + Send + Sync + 'static,
{
    pub fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F> WebhookEndpoint for FnWebhookEndpoint<F>
where
    F: Fn(&str) -> Result<(), WebhookError> + Send + Sync + 'static,
{
    fn receive(&self, json_payload: &str) -> Result<(), WebhookError> {
        (self.handler)(json_payload)
    }
}

/// تنفيذ افتراضي مرسل يستخدم std فقط (Placeholder): يُرجِع خطأ نقل.
/// Default sender using std only (placeholder): returns a transport error.
pub struct StdWebhookClient;

impl WebhookClient for StdWebhookClient {
    fn send(&self, _url: &str, _json_payload: &str) -> Result<(), WebhookError> {
        Err(WebhookError::Transport(
            "No HTTP client enabled (egress_reqwest feature)".into(),
        ))
    }
}

/// مُرسل ويب هوك محمي بسياسة خروج باستخدام العميل الداخلي.
/// Guarded webhook sender using std egress client with guard policy.
#[cfg(all(feature = "egress", feature = "egress_http_std"))]
pub struct GuardedStdWebhookSender {
    pub client: crate::security::egress_guard::http_client::std_impl::StdClient,
    pub policy: crate::security::egress_guard::policy::EgressPolicy,
}

#[cfg(all(feature = "egress", feature = "egress_http_std"))]
impl WebhookClient for GuardedStdWebhookSender {
    fn send(&self, url: &str, json_payload: &str) -> Result<(), WebhookError> {
        let _ = crate::security::egress_guard::resolver::preflight(&self.policy, url)
            .map_err(|e| WebhookError::Transport(format!("egress blocked: {e}")))?;
        use std::io::Write;
        use std::net::TcpStream;
        // Very minimal http POST
        let (host, port, path) = parse_http_url(url).map_err(WebhookError::Transport)?;
        let mut stream = TcpStream::connect((host.as_str(), port))
            .map_err(|e| WebhookError::Transport(e.to_string()))?;
        let body = json_payload.as_bytes();
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path, host, body.len()
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| WebhookError::Transport(e.to_string()))?;
        stream
            .write_all(body)
            .map_err(|e| WebhookError::Transport(e.to_string()))?;
        Ok(())
    }
}

#[cfg(all(feature = "egress", feature = "egress_http_std"))]
pub fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") {
        return Err("Only http:// supported in std sender".into());
    }
    let rest = &url[7..];
    let mut host_port = rest;
    let mut path = "/".to_string();
    if let Some(slash) = rest.find('/') {
        host_port = &rest[..slash];
        path = rest[slash..].to_string();
    }
    let (host, port) = if let Some(colon) = host_port.rfind(':') {
        let h = &host_port[..colon];
        let p = host_port[colon + 1..]
            .parse::<u16>()
            .map_err(|_| "Invalid port")?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), 80)
    };
    Ok((host, port, path))
}

#[cfg(feature = "webhook_out")]
mod reqwest_client {
    pub struct ReqwestWebhookClient;
    impl crate::webhook::WebhookClient for ReqwestWebhookClient {
        fn send(&self, url: &str, json_payload: &str) -> Result<(), crate::webhook::WebhookError> {
            let client = reqwest::blocking::Client::new();
            let res = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(json_payload.to_string())
                .send()
                .map_err(|e| crate::webhook::WebhookError::Transport(e.to_string()))?;
            if res.status().is_success() {
                Ok(())
            } else {
                Err(crate::webhook::WebhookError::Transport(format!(
                    "HTTP {}",
                    res.status()
                )))
            }
        }
    }
    pub use ReqwestWebhookClient as DefaultWebhookClient;
}

#[cfg(not(feature = "webhook_out"))]
pub use StdWebhookClient as DefaultWebhookClient;
