use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressError {
    UrlParse,
    Scheme,
    HostMissing,
    HostNotAllowed,
    DnsFailed,
    IpNotPublic,
    PortNotAllowed,
}

impl Display for EgressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            EgressError::UrlParse => "url-parse-failed",
            EgressError::Scheme => "scheme-not-allowed",
            EgressError::HostMissing => "host-missing",
            EgressError::HostNotAllowed => "host-not-allowed",
            EgressError::DnsFailed => "dns-lookup-failed",
            EgressError::IpNotPublic => "ip-not-public",
            EgressError::PortNotAllowed => "port-not-allowed",
        };
        write!(f, "{}", msg)
    }
}

impl Error for EgressError {}
