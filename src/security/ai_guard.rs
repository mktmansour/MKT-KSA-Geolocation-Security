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
}

impl IpRiskState {
    fn new(now: Instant) -> Self {
        Self {
            reputation: 0,
            offense_count: 0,
            last_seen: now,
            blocked_until: None,
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

        let blocked = assessment.is_blocked(self.config.block_threshold);
        state.last_seen = now;

        if blocked {
            state.offense_count = state.offense_count.saturating_add(1);
            state.reputation = state.reputation.saturating_add(assessment.score as u16);

            let multiplier = u64::from(state.offense_count).min(10);
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

        state.reputation = state.reputation.saturating_sub(2);

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
}
