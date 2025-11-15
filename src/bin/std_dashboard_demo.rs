/*! Arabic: برنامج تجريبي لخادم std_http مع لوحة معلومات وويب هوك ومخاطر (صفر تبعية)
English: Demo for std_http server with dashboard, webhook, and risk (zero‑deps) */

#[cfg(feature = "api_std_http")]
fn main() {
    use std::sync::Arc;
    mkt_ksa_geo_sec::telemetry::init();

    // حُرّاس افتراضية لكل المسارات الحساسة (يتطلب توقيع HMAC للوارد)
    mkt_ksa_geo_sec::webhook::guards::register_builtins();

    // إعداد مفتاح auth_hmac من متغيّر بيئي (للاختبارات) أو إنشاؤه تلقائيًا إن لم يوجد
    let mgr = mkt_ksa_geo_sec::crypto::key_rotation::key_manager();
    if let Ok(hex) = std::env::var("MKT_AUTH_HMAC_HEX") {
        struct DevRng {
            seed: Vec<u8>,
        }
        impl mkt_ksa_geo_sec::security::crypto_smart::traits::CryptoRngProvider for DevRng {
            fn random(
                &self,
                len: usize,
            ) -> Result<Vec<u8>, mkt_ksa_geo_sec::security::crypto_smart::traits::CryptoStrictError>
            {
                if self.seed.is_empty() {
                    return Ok(vec![0u8; len]);
                }
                let mut out = Vec::with_capacity(len);
                while out.len() < len {
                    let take = (len - out.len()).min(self.seed.len());
                    out.extend_from_slice(&self.seed[..take]);
                }
                Ok(out)
            }
        }
        #[allow(clippy::manual_is_multiple_of)]
        fn from_hex(s: &str) -> Option<Vec<u8>> {
            let b = s.as_bytes();
            if b.len() % 2 != 0 {
                return None;
            }
            let mut out = Vec::with_capacity(b.len() / 2);
            let to_n = |c: u8| -> Option<u8> { (c as char).to_digit(16).map(|v| v as u8) };
            for i in (0..b.len()).step_by(2) {
                let hi = to_n(b[i])?;
                let lo = to_n(b[i + 1])?;
                out.push((hi << 4) | lo);
            }
            Some(out)
        }
        if let Some(seed) = from_hex(&hex) {
            use std::sync::Arc;
            mgr.set_rng_provider(Arc::new(DevRng { seed: seed.clone() }));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Some(meta) = mgr.get_meta("auth_hmac") {
                let _ = mgr.rotate_key(
                    "auth_hmac",
                    meta.version.saturating_add(1),
                    seed.len().max(16),
                    now,
                );
                println!(
                    "[DEV] auth_hmac rotated from ENV-seeded RNG (len={})",
                    seed.len()
                );
            } else {
                let _ = mgr.create_key("auth_hmac", 1, seed.len().max(16), None, now);
                println!(
                    "[DEV] auth_hmac created from ENV-seeded RNG (len={})",
                    seed.len()
                );
            }
        } else {
            eprintln!(
                "[WARN] MKT_AUTH_HMAC_HEX is not valid hex; falling back to auto-generated key"
            );
            if mgr.get("auth_hmac").is_err() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let _ = mgr.create_key("auth_hmac", 1, 32, None, now);
                println!("[DEV] Created bootstrap key: id=auth_hmac ver=1 len=32");
            }
        }
    } else if mgr.get("auth_hmac").is_err() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let _ = mgr.create_key("auth_hmac", 1, 32, None, now);
        println!("[DEV] Created bootstrap key: id=auth_hmac ver=1 len=32");
    }

    // Bootstrap: تسجيل عميل OAuth2 تجريبي للاختبارات التشغيلية
    {
        use mkt_ksa_geo_sec::oauth2::clients::{
            get_client_manager, ClientAuthMethod, ClientSecurityPolicy, ClientType,
        };
        use mkt_ksa_geo_sec::oauth2::core::{GrantType, ResponseType};

        let cm = get_client_manager();
        if cm.get_client("demo_client").is_none() {
            let _ = cm.register_client(
                "demo_client".to_string(),
                "Demo Client".to_string(),
                ClientType::Web,
                ClientAuthMethod::None,
            );
            // سياسة عميل تجريبية مُهيّأة دفعة واحدة (تجنّب إعادة الإسناد بعد default)
            let policy = ClientSecurityPolicy {
                allowed_scopes: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "openid".to_string(),
                    "profile".to_string(),
                    "offline_access".to_string(),
                ],
                allowed_grant_types: vec![
                    GrantType::AuthorizationCode,
                    GrantType::ClientCredentials,
                    GrantType::RefreshToken,
                ],
                allowed_response_types: vec![ResponseType::Code],
                allowed_redirect_uris: vec!["https://example.com/callback".to_string()],
                ..ClientSecurityPolicy::default()
            };
            let _ = cm.update_client_security_policy("demo_client", policy);
            println!("[DEV] OAuth2 demo client registered: client_id=demo_client");
        } else {
            println!("[DEV] OAuth2 demo client already exists: client_id=demo_client");
        }
    }

    // Webhook endpoint: يسجل ويزيد المخاطر عند كلمات خطرة
    struct Ep;
    impl mkt_ksa_geo_sec::webhook::WebhookEndpoint for Ep {
        fn receive(
            &self,
            json_payload: &str,
        ) -> Result<(), mkt_ksa_geo_sec::webhook::WebhookError> {
            mkt_ksa_geo_sec::telemetry::record_event("webhook_in", json_payload);
            if json_payload.contains("attack") || json_payload.contains("inject") {
                mkt_ksa_geo_sec::telemetry::set_risk(80);
            }
            Ok(())
        }
    }

    // ضبط الويب هوك
    mkt_ksa_geo_sec::api::std_http::set_webhook_endpoint(Arc::new(Ep));

    // سياسة افتراضية للوارد
    let policy = mkt_ksa_geo_sec::security::inspection_policy::InboundPolicy::default();

    // معالج افتراضي: يعرض مساعدة بسيطة
    let handler = Arc::new(|_req: &mkt_ksa_geo_sec::api::std_http::Request| -> mkt_ksa_geo_sec::api::std_http::Response {
        mkt_ksa_geo_sec::api::std_http::Response::json(200, "{\"ok\":true,\"endpoints\":[\"/metrics\",\"/events.ndjson\",\"/toggle?compression=on|off\",\"/risk\"]}")
    });

    // تشغيل الخادم
    println!("🚀 Starting std_http at http://127.0.0.1:8080");
    match mkt_ksa_geo_sec::api::std_http::run_with_policy("127.0.0.1:8080", policy, handler) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("❌ Server failed to start: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "api_std_http"))]
fn main() {
    println!("Enable feature api_std_http to run this demo.");
}
