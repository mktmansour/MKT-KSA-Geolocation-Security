# 04. API Guide

This page provides a practical API-level reference for consumers and integrators.

## 1. Request Contract Basics

Recommended headers:

- X-API-Key
- Authorization: Bearer <token>
- X-Request-ID
- Content-Type: application/json

## 2. Endpoint Groups

| Domain | Example Route | Purpose |
|---|---|---|
| User/Auth | /api/users/{id} | User retrieval and authorization checks |
| Geo | /api/verify_geo | Geographic consistency and trust |
| Device | /api/verify_device | Device fingerprint trust |
| Behavior | /api/analyze_behavior | Behavioral anomaly analysis |
| Network | /api/analyze_network | Proxy/VPN and network risk |
| Sensors | /api/analyze_sensors | Sensor integrity anomaly checks |
| Weather | /api/verify_weather | Context consistency signal |
| Smart Access | /api/smart_access_verify | Composite trust decision |
| Alerts | /api/alerts/trigger | Security event and alert workflow |

## 3. Error Model

The API returns structured security-aware responses for authentication, authorization, and risk-deny paths.

Core practices:

- Use stable error codes in clients.
- Propagate request id across all tiers.
- Treat retry guidance as policy signal.

## 4. API Invocation Example

```bash
curl -sS -X POST http://127.0.0.1:8080/api/alerts/trigger \
  -H "X-API-Key: ${API_KEY}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: wiki-alert-001" \
  -d '{"entity_id":"00000000-0000-0000-0000-000000000000","entity_type":"user","alert_type":"intrusion","severity":"high","details":{"source":"wiki"}}'
```

## 5. Client Integration Guidance

- Implement centralized HTTP client wrappers.
- Capture response codes, error codes, and request id.
- Add retry policy only where explicitly allowed.
- Monitor latency and deny-rate trends per endpoint.

## 6. Next Step

Continue to [05. Deployment and Operations](05-Deployment-and-Operations.md).

## Search Keywords

Rust security API reference, geolocation verification endpoint, smart access API, Actix Web secure headers.
