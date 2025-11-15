/*!
Arabic: محلل URL بسيط صفر تبعيات للاستخدام مع الحارس عند تعطيل `url`.
English: Simple zero‑deps URL parser for egress guard when `url` crate is disabled.
*/

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleUrl {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Scheme,
    Host,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Scheme => write!(f, "invalid or unsupported scheme"),
            ParseError::Host => write!(f, "missing host"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Arabic: يحلل `http[s]://host[:port]` فقط.
/// English: Parses only `http[s]://host[:port]`.
pub fn parse(input: &str) -> Result<SimpleUrl, ParseError> {
    let lower = input.trim();
    let (scheme, rest) = if let Some(r) = lower.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = lower.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(ParseError::Scheme);
    };

    let mut host_port = rest;
    if let Some(pos) = host_port.find('/') {
        host_port = &host_port[..pos];
    }
    if host_port.is_empty() {
        return Err(ParseError::Host);
    }

    let (host, port) = if let Some(colon) = host_port.rfind(':') {
        let (h, p) = host_port.split_at(colon);
        let p = &p[1..];
        if p.is_empty() {
            (h.to_string(), None)
        } else if let Ok(v) = p.parse::<u16>() {
            (h.to_string(), Some(v))
        } else {
            (host_port.to_string(), None)
        }
    } else {
        (host_port.to_string(), None)
    };

    Ok(SimpleUrl {
        scheme: scheme.to_string(),
        host: host.to_ascii_lowercase(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_https() {
        let u = parse("https://api.example.com:8443/path?q=1").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "api.example.com");
        assert_eq!(u.port, Some(8443));
    }

    #[test]
    fn parse_basic_http_default_port_none() {
        let u = parse("http://example.com").unwrap();
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, None);
    }
}
