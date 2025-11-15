/// Arabic: واجهة عميل HTTP بلا تبعيات
/// English: Zero‑deps HTTP client trait
pub trait HttpClient {
    type Response;
    type Error;
    fn get(&self, url: &str) -> Result<Self::Response, Self::Error>;
}

#[cfg(feature = "egress_reqwest")]
pub mod reqwest_impl {
    use super::HttpClient;
    use reqwest::blocking::Client;

    pub struct ReqwestClient(pub Client);
    impl HttpClient for ReqwestClient {
        type Response = reqwest::blocking::Response;
        type Error = reqwest::Error;
        fn get(&self, url: &str) -> Result<Self::Response, Self::Error> {
            self.0.get(url).send()
        }
    }
}

#[cfg(feature = "egress_http_std")]
pub mod std_impl {
    use super::HttpClient;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    pub struct StdClient;

    impl HttpClient for StdClient {
        type Response = String;
        type Error = String;

        fn get(&self, url: &str) -> Result<Self::Response, Self::Error> {
            // Very minimal HTTP/1.1 GET client supporting only http://host:port/path
            let (host, port, path) = parse_http_url(url)?;
            let mut stream =
                TcpStream::connect((host.as_str(), port)).map_err(|e| e.to_string())?;
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                path, host
            );
            stream
                .write_all(req.as_bytes())
                .map_err(|e| e.to_string())?;
            let mut buf = String::new();
            stream.read_to_string(&mut buf).map_err(|e| e.to_string())?;
            Ok(buf)
        }
    }

    fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
        // Very naive parser: only supports http://host[:port]/path
        let lower = url.to_ascii_lowercase();
        if !lower.starts_with("http://") {
            return Err("Only http:// scheme supported in egress_http_std".into());
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
}

#[cfg(all(feature = "egress", feature = "egress_http_std"))]
pub mod guarded_std_client {
    use super::HttpClient;
    use crate::security::egress_guard::{policy::EgressPolicy, resolver};

    pub struct GuardedStdClient<C> {
        pub client: C,
        pub policy: EgressPolicy,
    }

    impl<C: HttpClient<Error = String, Response = String>> HttpClient for GuardedStdClient<C> {
        type Response = String;
        type Error = String;
        fn get(&self, url: &str) -> Result<Self::Response, Self::Error> {
            let _ = resolver::preflight(&self.policy, url)
                .map_err(|e| format!("egress blocked: {e}"))?;
            self.client.get(url)
        }
    }
}
