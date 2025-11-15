use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::errors::EgressError;
use super::policy::EgressPolicy;
#[cfg(feature = "egress_url")]
use url::Url;

/// Arabic: فحص أن المضيف ضمن allowlist وأن IP عام ومنافذ مسموحة
/// English: Check host against allowlist, ensure public IP and allowed port
#[cfg(feature = "egress_url")]
pub fn preflight(policy: &EgressPolicy, url: &str) -> Result<(Url, Vec<SocketAddr>), EgressError> {
    let u = Url::parse(url).map_err(|_| EgressError::UrlParse)?;
    let scheme = u.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(EgressError::Scheme);
    }
    let host = u
        .host_str()
        .ok_or(EgressError::HostMissing)?
        .to_ascii_lowercase();
    let port = u.port_or_known_default().unwrap_or(443);

    if policy
        .denylist
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    {
        return Err(EgressError::HostNotAllowed);
    }
    if !policy
        .allowlist
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    {
        return Err(EgressError::HostNotAllowed);
    }
    if !policy.allowed_ports.contains(&port) {
        return Err(EgressError::PortNotAllowed);
    }

    // NOTE: نستخدم resolver النظامي عبر std::net::ToSocketAddrs (بلا تبعيات)
    let addrs_iter = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| EgressError::DnsFailed)?;
    let addrs: Vec<SocketAddr> = addrs_iter.filter(|sa| is_public_ip(&sa.ip())).collect();
    if addrs.is_empty() {
        return Err(EgressError::IpNotPublic);
    }
    Ok((u, addrs))
}

#[cfg(not(feature = "egress_url"))]
pub fn preflight(
    policy: &EgressPolicy,
    url: &str,
) -> Result<
    (
        crate::security::egress_guard::parser::SimpleUrl,
        Vec<SocketAddr>,
    ),
    EgressError,
> {
    let u = crate::security::egress_guard::parser::parse(url).map_err(|_| EgressError::UrlParse)?;
    if u.scheme != "https" && u.scheme != "http" {
        return Err(EgressError::Scheme);
    }
    let host = u.host.clone();
    let port = u.port.unwrap_or(if u.scheme == "https" { 443 } else { 80 });

    if policy
        .denylist
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    {
        return Err(EgressError::HostNotAllowed);
    }
    if !policy
        .allowlist
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    {
        return Err(EgressError::HostNotAllowed);
    }
    if !policy.allowed_ports.contains(&port) {
        return Err(EgressError::PortNotAllowed);
    }

    let addrs_iter = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| EgressError::DnsFailed)?;
    let addrs: Vec<SocketAddr> = addrs_iter.filter(|sa| is_public_ip(&sa.ip())).collect();
    if addrs.is_empty() {
        return Err(EgressError::IpNotPublic);
    }
    Ok((u, addrs))
}

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || *v4 == Ipv4Addr::UNSPECIFIED)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback() || v6.is_unique_local() || v6.is_unspecified() || v6.is_multicast())
        }
    }
}

use std::net::ToSocketAddrs;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_public_ip_basic() {
        // Private IPv4 should be rejected
        assert_eq!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), false);
        // Loopback IPv6 should be rejected
        assert_eq!(is_public_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)), false);
        // A common public IPv4 example range (TEST-NET-3 203.0.113.0/24) is not special-cased here,
        // but treat as public for the purpose of the filter logic
        assert_eq!(
            is_public_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            true
        );
    }

    #[test]
    fn test_preflight_host_not_allowed() {
        let mut allowlist: HashSet<String> = HashSet::new();
        allowlist.insert("api.example.com".into());
        let mut allowed_ports: HashSet<u16> = HashSet::new();
        allowed_ports.insert(443);
        let policy = EgressPolicy {
            allowlist,
            denylist: HashSet::new(),
            allowed_ports,
            max_redirects: 0,
            timeout_ms: 5000,
            max_response_bytes: 2_000_000,
        };
        let err = preflight(&policy, "https://not-allowed.example/path").unwrap_err();
        matches!(err, EgressError::HostNotAllowed);
    }

    #[test]
    fn test_preflight_blocks_localhost_private_ip() {
        // Allow localhost and port 80 so allow/port checks pass, then it should fail on public IP filter
        let mut allowlist: HashSet<String> = HashSet::new();
        allowlist.insert("localhost".into());
        let mut allowed_ports: HashSet<u16> = HashSet::new();
        allowed_ports.insert(80);
        let policy = EgressPolicy {
            allowlist,
            denylist: HashSet::new(),
            allowed_ports,
            max_redirects: 0,
            timeout_ms: 5000,
            max_response_bytes: 2_000_000,
        };
        let err = preflight(&policy, "http://localhost:80/").unwrap_err();
        matches!(err, EgressError::IpNotPublic);
    }
}
