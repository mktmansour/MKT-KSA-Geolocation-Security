#!/usr/bin/env python3
"""10-minute split test: isolate legitimate vs hostile traffic from separate IP ranges."""

from __future__ import annotations

import random
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional, Tuple

from common import (
    build_parser,
    make_token,
    print_common,
    random_ip,
    request_json,
    runtime_from_args,
    summarize_latencies,
)

DEFENSE_STATUSES = {400, 401, 403, 422, 429}


def main() -> None:
    parser = build_parser(
        "10-minute split test (legitimate vs hostile)",
        default_duration=600,
        default_workers=24,
    )
    parser.add_argument("--legit-share", type=float, default=0.45, help="Legitimate traffic share (0.0..1.0)")
    args = parser.parse_args()
    rt = runtime_from_args(args)

    legit_share = max(0.05, min(0.95, float(args.legit_share)))

    admin_token = make_token(rt.jwt_secret, role="admin")
    user_token = make_token(rt.jwt_secret, role="user")
    invalid_token = "invalid.jwt.token"

    payload_device = {
        "os": "Android 14",
        "device_info": "Pixel 8",
        "environment_data": "office-gate",
    }

    payload_smart_legit = {
        "geo_input": None,
        "behavior_input": {
            "entity_id": "split-legit",
            "timestamp": "2026-03-19T03:00:00Z",
            "location": [24.7136, 46.6753],
            "network_info": {
                "ip_address": "8.8.8.8",
                "is_vpn": False,
                "connection_type": "5G",
            },
            "device_fingerprint": "fp-split-legit",
        },
        "os_info": "Android 14",
        "device_details": "Pixel 8",
        "env_context": "office-gate",
    }

    payload_smart_hostile = {
        "geo_input": ["198.18.0.66", [40.7128, -74.0060, 5, 2500.0]],
        "behavior_input": {
            "entity_id": "split-hostile",
            "timestamp": "2026-03-19T03:00:30Z",
            "location": [40.7128, -74.0060],
            "network_info": {
                "ip_address": "198.18.0.66",
                "is_vpn": True,
                "connection_type": "TOR",
            },
            "device_fingerprint": "fp-split-hostile",
        },
        "os_info": "Android 14",
        "device_details": "Unknown Device",
        "env_context": "tor-exit-vpn",
    }

    legit_status_counts: Counter[int] = Counter()
    attack_status_counts: Counter[int] = Counter()
    legit_outcomes: Counter[str] = Counter()
    attack_outcomes: Counter[str] = Counter()
    latencies_ms: list[float] = []

    start = time.time()
    end = start + rt.duration_sec

    def pick_legit_scenario() -> Tuple[str, str, str, Optional[Dict], Dict[str, str], set[int]]:
        kind = random.choice(["device", "smart", "user"])
        if kind == "device":
            return (
                "legit_device",
                "POST",
                "/api/device/resolve",
                payload_device,
                {
                    "X-Forwarded-For": random_ip("203.0.113"),
                    "X-API-Key": rt.api_key,
                    "Authorization": f"Bearer {admin_token}",
                },
                {200, 429, 403},
            )
        if kind == "smart":
            return (
                "legit_smart_access",
                "POST",
                "/api/smart_access/verify",
                payload_smart_legit,
                {
                    "X-Forwarded-For": random_ip("203.0.113"),
                    "X-API-Key": rt.api_key,
                    "Authorization": f"Bearer {admin_token}",
                },
                {200, 403, 429},
            )
        uid = str(uuid.uuid4())
        return (
            "legit_user_path",
            "GET",
            f"/api/users/{uid}",
            None,
            {
                "X-Forwarded-For": random_ip("203.0.113"),
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {user_token}",
            },
            {403, 404, 429},
        )

    def pick_attack_scenario() -> Tuple[str, str, str, Optional[Dict], Dict[str, str], set[int]]:
        kind = random.choice(["bad_key", "bad_token", "high_risk", "burst"])
        if kind == "bad_key":
            return (
                "attack_bad_api_key",
                "POST",
                "/api/device/resolve",
                payload_device,
                {
                    "X-Forwarded-For": random_ip("198.51.100"),
                    "X-API-Key": "bad-key",
                    "Authorization": f"Bearer {admin_token}",
                },
                {401},
            )
        if kind == "bad_token":
            return (
                "attack_invalid_token",
                "POST",
                "/api/device/resolve",
                payload_device,
                {
                    "X-Forwarded-For": random_ip("198.51.100"),
                    "X-API-Key": rt.api_key,
                    "Authorization": f"Bearer {invalid_token}",
                },
                {401},
            )
        if kind == "high_risk":
            return (
                "attack_high_risk_smart",
                "POST",
                "/api/smart_access/verify",
                payload_smart_hostile,
                {
                    "X-Forwarded-For": "198.18.0.66",
                    "X-API-Key": rt.api_key,
                    "Authorization": f"Bearer {admin_token}",
                },
                {200, 403, 422, 429},
            )
        return (
            "attack_burst_same_ip",
            "POST",
            "/api/device/resolve",
            payload_device,
            {
                "X-Forwarded-For": "198.18.0.66",
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {admin_token}",
            },
            {200, 429, 403},
        )

    def worker() -> list[Tuple[bool, str, Optional[int], set[int], float]]:
        rows = []
        while time.time() < end:
            is_legit = random.random() < legit_share
            if is_legit:
                scenario, method, path, body, headers, expected = pick_legit_scenario()
            else:
                scenario, method, path, body, headers, expected = pick_attack_scenario()

            t0 = time.perf_counter()
            status, _, _ = request_json(
                rt.base_url,
                method,
                path,
                body=body,
                headers=headers,
                timeout_sec=rt.timeout_sec,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            rows.append((is_legit, scenario, status, expected, elapsed_ms))
        return rows

    with ThreadPoolExecutor(max_workers=rt.workers) as pool:
        futures = [pool.submit(worker) for _ in range(rt.workers)]
        all_rows = []
        for fut in as_completed(futures):
            all_rows.extend(fut.result())

    for is_legit, scenario, status, expected, elapsed_ms in all_rows:
        latencies_ms.append(elapsed_ms)

        if is_legit:
            legit_outcomes["total"] += 1
        else:
            attack_outcomes["total"] += 1

        if status is None:
            if is_legit:
                legit_outcomes["network_exception"] += 1
            else:
                attack_outcomes["network_exception"] += 1
            continue

        if is_legit:
            legit_status_counts[status] += 1
            if status in expected:
                legit_outcomes["expected"] += 1
            else:
                legit_outcomes["unexpected"] += 1
            if status == 429:
                legit_outcomes["throttled"] += 1
            if status >= 500:
                legit_outcomes["status_5xx"] += 1
        else:
            attack_status_counts[status] += 1
            if status in expected:
                attack_outcomes["expected"] += 1
            else:
                attack_outcomes["unexpected"] += 1
            if status in DEFENSE_STATUSES:
                attack_outcomes["defended"] += 1
            if status >= 500:
                attack_outcomes["status_5xx"] += 1

    elapsed = time.time() - start
    total_requests = len(all_rows)
    legit_total = legit_outcomes.get("total", 0)
    attack_total = attack_outcomes.get("total", 0)

    legit_expected_rate = (legit_outcomes.get("expected", 0) / legit_total * 100.0) if legit_total else 0.0
    legit_throttle_rate = (legit_outcomes.get("throttled", 0) / legit_total * 100.0) if legit_total else 0.0
    attack_defense_rate = (attack_outcomes.get("defended", 0) / attack_total * 100.0) if attack_total else 0.0

    summary = {
        "phase": "10M_SPLIT",
        "total_requests": total_requests,
        "elapsed_sec": round(elapsed, 2),
        "rps": round(total_requests / elapsed, 2) if elapsed > 0 else 0,
        "traffic_split": {
            "legitimate_percent": round(legit_share * 100.0, 2),
            "attack_percent": round((1.0 - legit_share) * 100.0, 2),
        },
        "legitimate": {
            "total": legit_total,
            "expected_rate_percent": round(legit_expected_rate, 2),
            "throttled_rate_percent": round(legit_throttle_rate, 2),
            "network_exceptions": int(legit_outcomes.get("network_exception", 0)),
            "status_5xx": int(legit_outcomes.get("status_5xx", 0)),
            "status_counts": dict(legit_status_counts),
        },
        "attack": {
            "total": attack_total,
            "defense_rate_percent": round(attack_defense_rate, 2),
            "unexpected": int(attack_outcomes.get("unexpected", 0)),
            "network_exceptions": int(attack_outcomes.get("network_exception", 0)),
            "status_5xx": int(attack_outcomes.get("status_5xx", 0)),
            "status_counts": dict(attack_status_counts),
        },
        "latency_ms": summarize_latencies(latencies_ms),
    }

    print_common(summary, "PHASE_10M_SPLIT")


if __name__ == "__main__":
    main()
