use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct AiGuardConfig {
    pub block_threshold: u8,
    pub max_payload_bytes: usize,
    pub reputation_decay_seconds: u64,
    pub base_block_seconds: u64,
    pub max_block_seconds: u64,
    pub max_tracked_ips: usize,
    pub burst_window_seconds: u64,
    pub burst_soft_limit: u16,
    pub burst_hard_limit: u16,
}

impl Default for AiGuardConfig {
    fn default() -> Self {
        Self {
            block_threshold: 70,
            max_payload_bytes: 64 * 1024,
            reputation_decay_seconds: 300,
            base_block_seconds: 20,
            max_block_seconds: 900,
            max_tracked_ips: 20_000,
            burst_window_seconds: 10,
            burst_soft_limit: 24,
            burst_hard_limit: 60,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiRiskAssessment {
    pub score: u8,
    pub reasons: Vec<&'static str>,
}

impl AiRiskAssessment {
    #[must_use]
    pub fn is_blocked(&self, threshold: u8) -> bool {
        self.score >= threshold
    }
}

#[derive(Debug, Clone)]
pub struct AiRiskDecision {
    pub assessment: AiRiskAssessment,
    pub blocked: bool,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
struct IpRiskState {
    reputation: u16,
    offense_count: u8,
    last_seen: Instant,
    blocked_until: Option<Instant>,
    burst_count: u16,
    burst_window_start: Instant,
}

impl IpRiskState {
    fn new(now: Instant) -> Self {
        Self {
            reputation: 0,
            offense_count: 0,
            last_seen: now,
            blocked_until: None,
            burst_count: 0,
            burst_window_start: now,
        }
    }
}

#[derive(Debug)]
pub struct RequestAiGuard {
    config: AiGuardConfig,
    ip_state: RwLock<HashMap<IpAddr, IpRiskState>>,
}

impl RequestAiGuard {
    #[must_use]
    pub fn new(config: AiGuardConfig) -> Self {
        Self {
            config,
            ip_state: RwLock::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn assess(&self, path: &str, user_agent: Option<&str>, payload: &[u8]) -> AiRiskAssessment {
        let mut score: u8 = 0;
        let mut reasons = Vec::new();

        if payload.len() > self.config.max_payload_bytes {
            score = score.saturating_add(35);
            reasons.push("payload_too_large");
        }

        if user_agent.is_none() {
            score = score.saturating_add(8);
            reasons.push("missing_user_agent");
        }

        if path.contains("alerts/trigger") {
            score = score.saturating_add(5);
            reasons.push("high_impact_route");
        }

        if path.contains("smart_access/verify") {
            score = score.saturating_add(8);
            reasons.push("sensitive_access_route");
        }

        let maybe_text: Cow<'_, str> = String::from_utf8_lossy(payload);
        let text = maybe_text.to_ascii_lowercase();
        let indicators = [
            ("<script", 35_u8, "xss_pattern"),
            ("union select", 35_u8, "sqli_pattern"),
            ("drop table", 35_u8, "sqli_pattern"),
            (" or 1=1", 28_u8, "sqli_pattern"),
            ("'--", 24_u8, "sqli_comment_pattern"),
            ("../", 20_u8, "path_traversal_pattern"),
            ("${jndi:", 45_u8, "jndi_pattern"),
            ("sleep(", 20_u8, "timing_attack_pattern"),
        ];

        for (needle, weight, reason) in indicators {
            if text.contains(needle) {
                score = score.saturating_add(weight);
                reasons.push(reason);
            }
        }

        if path.contains("smart_access/verify") {
            let smart_route_indicators = [
                ("\"is_vpn\":true", 14_u8, "vpn_indicator"),
                ("tor", 18_u8, "tor_indicator"),
                ("proxy", 10_u8, "proxy_indicator"),
                ("unknown device", 14_u8, "unknown_device_indicator"),
                ("rapid-switch", 12_u8, "velocity_anomaly_indicator"),
            ];
            for (needle, weight, reason) in smart_route_indicators {
                if text.contains(needle) {
                    score = score.saturating_add(weight);
                    reasons.push(reason);
                }
            }
        }

        let non_printable = payload
            .iter()
            .filter(|b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
            .count();
        if !payload.is_empty() {
            let ratio = non_printable as f32 / payload.len() as f32;
            if ratio > 0.25 {
                score = score.saturating_add(20);
                reasons.push("binary_like_payload");
            }
        }

        AiRiskAssessment { score, reasons }
    }

    pub async fn evaluate_request(
        &self,
        ip: IpAddr,
        path: &str,
        user_agent: Option<&str>,
        payload: &[u8],
    ) -> AiRiskDecision {
        let now = Instant::now();
        let mut map = self.ip_state.write().await;
        self.prune_if_needed(&mut map, now);

        let state = map.entry(ip).or_insert_with(|| IpRiskState::new(now));
        self.apply_decay(state, now);
        let burst_count = self.bump_burst_counter(state, now);

        if let Some(until) = state.blocked_until {
            if until > now {
                let retry_after = (until - now).as_secs().max(1);
                let mut assessment = self.assess(path, user_agent, payload);
                assessment.reasons.push("temporary_ip_block_active");
                assessment.score = assessment.score.max(self.config.block_threshold);
                return AiRiskDecision {
                    assessment,
                    blocked: true,
                    retry_after_seconds: Some(retry_after),
                };
            }
            state.blocked_until = None;
        }

        let mut assessment = self.assess(path, user_agent, payload);
        let reputation_boost = (state.reputation / 10).min(30) as u8;
        if reputation_boost > 0 {
            assessment.score = assessment.score.saturating_add(reputation_boost).min(100);
            assessment.reasons.push("ip_reputation_risk");
        }
        let pre_burst_score = assessment.score;

        if burst_count > self.config.burst_soft_limit {
            let extra = burst_count.saturating_sub(self.config.burst_soft_limit);
            let burst_penalty = ((extra / 2) as u8).min(22);
            assessment.score = assessment.score.saturating_add(burst_penalty).min(100);
            assessment.reasons.push("burst_traffic_anomaly");
        }

        let adaptive_threshold = self.adaptive_block_threshold(state, burst_count);
        if burst_count >= self.config.burst_hard_limit {
            assessment.reasons.push("burst_hard_limit_exceeded");
            if pre_burst_score >= 20 {
                assessment.score = assessment.score.max(adaptive_threshold);
            } else {
                assessment.score = assessment.score.saturating_add(8);
            }
        }
        if adaptive_threshold < self.config.block_threshold {
            assessment.reasons.push("adaptive_threshold_lowered");
        }

        let blocked = assessment.is_blocked(adaptive_threshold);
        state.last_seen = now;

        if blocked {
            state.offense_count = state.offense_count.saturating_add(1);
            state.reputation = state.reputation.saturating_add(assessment.score as u16);

            let burst_pressure =
                u64::from(burst_count.saturating_sub(self.config.burst_soft_limit));
            let burst_multiplier = 1 + (burst_pressure / 10).min(10);
            let multiplier = u64::from(state.offense_count).min(10) * burst_multiplier;
            let block_seconds = (self.config.base_block_seconds * multiplier)
                .min(self.config.max_block_seconds)
                .max(self.config.base_block_seconds);
            state.blocked_until = Some(now + Duration::from_secs(block_seconds));

            return AiRiskDecision {
                assessment,
                blocked: true,
                retry_after_seconds: Some(block_seconds),
            };
        }

        if burst_count <= self.config.burst_soft_limit {
            state.offense_count = state.offense_count.saturating_sub(1);
        }
        state.reputation = state.reputation.saturating_sub(3);

        AiRiskDecision {
            assessment,
            blocked: false,
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub fn block_threshold(&self) -> u8 {
        self.config.block_threshold
    }

    fn apply_decay(&self, state: &mut IpRiskState, now: Instant) {
        let elapsed = now.saturating_duration_since(state.last_seen).as_secs();
        if elapsed < self.config.reputation_decay_seconds
            || self.config.reputation_decay_seconds == 0
        {
            return;
        }

        let windows = elapsed / self.config.reputation_decay_seconds;
        for _ in 0..windows.min(8) {
            state.reputation /= 2;
            state.offense_count = state.offense_count.saturating_sub(1);
        }
    }

    fn bump_burst_counter(&self, state: &mut IpRiskState, now: Instant) -> u16 {
        let window_seconds = self.config.burst_window_seconds.max(1);
        if now
            .saturating_duration_since(state.burst_window_start)
            .as_secs()
            >= window_seconds
        {
            state.burst_count = 0;
            state.burst_window_start = now;
        }
        state.burst_count = state.burst_count.saturating_add(1);
        state.burst_count
    }

    fn adaptive_block_threshold(&self, state: &IpRiskState, burst_count: u16) -> u8 {
        let reputation_penalty = (state.reputation / 30).min(20) as u8;
        let offense_penalty = state.offense_count.min(8) * 2;
        let burst_penalty = if burst_count > self.config.burst_soft_limit {
            ((burst_count - self.config.burst_soft_limit) / 8).min(12) as u8
        } else {
            0
        };

        let reduction = reputation_penalty
            .saturating_add(offense_penalty)
            .saturating_add(burst_penalty);
        self.config
            .block_threshold
            .saturating_sub(reduction)
            .max(35)
    }

    fn prune_if_needed(&self, map: &mut HashMap<IpAddr, IpRiskState>, now: Instant) {
        if map.len() < self.config.max_tracked_ips {
            return;
        }

        let stale_after = self
            .config
            .reputation_decay_seconds
            .saturating_mul(12)
            .max(300);

        map.retain(|_, state| {
            now.saturating_duration_since(state.last_seen).as_secs() < stale_after
        });
    }
}

impl Default for RequestAiGuard {
    fn default() -> Self {
        Self::new(AiGuardConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hostile_payload_is_blocked() {
        let guard = RequestAiGuard::new(AiGuardConfig {
            block_threshold: 60,
            ..AiGuardConfig::default()
        });

        let decision = guard
            .evaluate_request(
                "203.0.113.10".parse().expect("valid test ip"),
                "/api/alerts/trigger",
                Some("integration-test"),
                b"<script>alert(1)</script> union select * from users",
            )
            .await;

        assert!(decision.blocked);
        assert!(decision.retry_after_seconds.is_some());
        assert!(decision.assessment.reasons.contains(&"xss_pattern"));
    }

    #[tokio::test]
    async fn repeated_offense_triggers_temporary_lock() {
        let guard = RequestAiGuard::new(AiGuardConfig {
            block_threshold: 30,
            base_block_seconds: 1,
            max_block_seconds: 5,
            ..AiGuardConfig::default()
        });

        let ip: IpAddr = "203.0.113.20".parse().expect("valid test ip");
        let first = guard
            .evaluate_request(
                ip,
                "/api/alerts/trigger",
                Some("ua"),
                b"<script>bad</script>",
            )
            .await;
        assert!(first.blocked);

        let second = guard
            .evaluate_request(ip, "/api/alerts/trigger", Some("ua"), b"{}")
            .await;
        assert!(second.blocked);
        assert!(second
            .assessment
            .reasons
            .contains(&"temporary_ip_block_active"));
    }

    #[tokio::test]
    async fn reputation_decay_reduces_score_over_time() {
        let guard = RequestAiGuard::new(AiGuardConfig {
            block_threshold: 70,
            reputation_decay_seconds: 1,
            base_block_seconds: 1,
            max_block_seconds: 2,
            ..AiGuardConfig::default()
        });

        let ip: IpAddr = "203.0.113.30".parse().expect("valid test ip");
        let first = guard
            .evaluate_request(
                ip,
                "/api/alerts/trigger",
                Some("ua"),
                b"union select drop table",
            )
            .await;
        assert!(first.blocked);

        tokio::time::sleep(Duration::from_secs(2)).await;

        let later = guard
            .evaluate_request(ip, "/api/behavior/analyze", Some("ua"), b"normal payload")
            .await;

        // We assert the path no longer hard-blocks for benign traffic after decay window.
        assert!(!later.blocked);
    }

    #[tokio::test]
    async fn burst_hard_limit_blocks_when_payload_is_suspicious() {
        let guard = RequestAiGuard::new(AiGuardConfig {
            block_threshold: 85,
            burst_window_seconds: 60,
            burst_soft_limit: 2,
            burst_hard_limit: 3,
            base_block_seconds: 1,
            max_block_seconds: 5,
            ..AiGuardConfig::default()
        });

        let ip: IpAddr = "203.0.113.44".parse().expect("valid test ip");

        let _ = guard
            .evaluate_request(ip, "/api/device/resolve", Some("ua"), b"{}")
            .await;
        let _ = guard
            .evaluate_request(ip, "/api/device/resolve", Some("ua"), b"{}")
            .await;
        let blocked = guard
            .evaluate_request(ip, "/api/device/resolve", Some("ua"), b"../etc/passwd")
            .await;

        assert!(blocked.blocked);
        assert!(blocked
            .assessment
            .reasons
            .contains(&"burst_hard_limit_exceeded"));
    }

    #[tokio::test]
    async fn smart_access_vpn_risk_is_elevated() {
        let guard = RequestAiGuard::new(AiGuardConfig {
            block_threshold: 45,
            ..AiGuardConfig::default()
        });

        let decision = guard
            .evaluate_request(
                "203.0.113.55".parse().expect("valid test ip"),
                "/api/smart_access/verify",
                Some("ua"),
                br#"{"network_info":{"is_vpn":true},"env":"tor proxy unknown device rapid-switch"}"#,
            )
            .await;

        assert!(decision.blocked);
        assert!(decision
            .assessment
            .reasons
            .contains(&"sensitive_access_route"));
    }

    #[tokio::test]
    async fn stale_ip_state_is_pruned_when_capacity_is_reached() {
        let guard = RequestAiGuard::new(AiGuardConfig {
            max_tracked_ips: 2,
            reputation_decay_seconds: 1,
            ..AiGuardConfig::default()
        });

        let stale_seen = Instant::now() - Duration::from_secs(400);
        let stale_ip_one: IpAddr = "203.0.113.61".parse().expect("valid test ip");
        let stale_ip_two: IpAddr = "203.0.113.62".parse().expect("valid test ip");

        {
            let mut map = guard.ip_state.write().await;
            let mut stale_state_one = IpRiskState::new(stale_seen);
            stale_state_one.last_seen = stale_seen;
            let mut stale_state_two = IpRiskState::new(stale_seen);
            stale_state_two.last_seen = stale_seen;
            map.insert(stale_ip_one, stale_state_one);
            map.insert(stale_ip_two, stale_state_two);
        }

        let fresh_ip: IpAddr = "203.0.113.63".parse().expect("valid test ip");
        let _ = guard
            .evaluate_request(fresh_ip, "/api/behavior/analyze", Some("ua"), b"{}")
            .await;

        let map = guard.ip_state.read().await;
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&fresh_ip));
        assert!(!map.contains_key(&stale_ip_one));
        assert!(!map.contains_key(&stale_ip_two));
    }
}
