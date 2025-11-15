// Arabic: أنواع الطلب/الاستجابة والمعالج لخادم std_http (صفر تبعية)
// English: Request/Response types and handler alias for std_http (zero-deps)

use std::sync::Arc;

pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub fingerprint_hex: Option<String>,
    /// Arabic: رؤوس استجابة إضافية (مثل Location لإعادة التوجيه)
    /// English: Additional response headers (e.g., Location for redirects)
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.as_bytes().to_vec(),
            fingerprint_hex: None,
            headers: Vec::new(),
        }
    }
}
