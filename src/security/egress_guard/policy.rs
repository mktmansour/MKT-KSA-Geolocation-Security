use std::collections::HashSet;

/// Arabic: سياسة الحارس (نطاقات/منافذ/مهلات/تحويلات)
/// English: Guard policy (domains/ports/timeouts/redirects)
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub allowlist: HashSet<String>,
    pub denylist: HashSet<String>,
    pub allowed_ports: HashSet<u16>,
    pub max_redirects: u8,
    pub timeout_ms: u64,
    pub max_response_bytes: u64,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        let mut ports = HashSet::new();
        ports.insert(80);
        ports.insert(443);
        Self {
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            allowed_ports: ports,
            max_redirects: 0,
            timeout_ms: 5000,
            max_response_bytes: 2_000_000,
        }
    }
}
