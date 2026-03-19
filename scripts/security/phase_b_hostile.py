#!/usr/bin/env python3
"""Phase-B: advanced hostile pressure test against live API defenses."""

from __future__ import annotations

import random
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional, Tuple

from common import (
    build_parser,
    make_token,
    print_common,
    random_ip,
    request_json,
    request_raw,
    runtime_from_args,
    summarize_latencies,
)

DEFENSE_STATUSES = {400, 401, 403, 422, 429}


def main() -> None:
    parser = build_parser("Phase-B hostile live test", default_duration=180, default_workers=16)
    args = parser.parse_args()
    rt = runtime_from_args(args)

    admin_token = make_token(rt.jwt_secret, role="admin")
    invalid_token = "invalid.jwt.token"

    payload_device = {
        "os": "Android 14",
        "device_info": "Pixel 8",
        "environment_data": "office-gate",
    }

    payload_smart_high_risk = {
        "geo_input": ["198.18.0.66", [40.7128, -74.0060, 5, 2500.0]],
        "behavior_input": {
            "entity_id": "phase-b-risk",
            "timestamp": "2026-03-19T02:21:00Z",
            "location": [40.7128, -74.0060],
            "network_info": {
                "ip_address": "198.18.0.66",
                "is_vpn": True,
                "connection_type": "TOR",
            },
            "device_fingerprint": "fp-risk-rapid-switch",
        },
        "os_info": "Android 14",
        "device_details": "Unknown Device",
        "env_context": "tor-exit-vpn",
    }

    attack_ip = "198.18.0.66"

    def s_bad_api_key(_: int):
        headers = {
            "X-Forwarded-For": random_ip("198.51.100"),
            "X-API-Key": "bad-key",
            "Authorization": f"Bearer {admin_token}",
        }
        return "bad_api_key", True, "json", "POST", "/api/device/resolve", payload_device, headers, {401}

    def s_invalid_token(_: int):
        headers = {
            "X-Forwarded-For": random_ip("198.51.100"),
            "X-API-Key": rt.api_key,
            "Authorization": f"Bearer {invalid_token}",
        }
        return "invalid_token", True, "json", "POST", "/api/device/resolve", payload_device, headers, {401}

    def s_missing_bearer(_: int):
        headers = {
            "X-Forwarded-For": random_ip("198.51.100"),
            "X-API-Key": rt.api_key,
        }
        return "missing_bearer", True, "json", "POST", "/api/device/resolve", payload_device, headers, {401}

    def s_malformed_json(_: int):
        headers = {
            "X-Forwarded-For": random_ip("198.51.100"),
            "X-API-Key": rt.api_key,
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        }
        return "malformed_json", True, "raw", "POST", "/api/device/resolve", b'{"os":"x",', headers, {400, 422}

    def s_high_risk_smart(_: int):
        headers = {
            "X-Forwarded-For": attack_ip,
            "X-API-Key": rt.api_key,
            "Authorization": f"Bearer {admin_token}",
        }
        return (
            "high_risk_smart",
            True,
            "json",
            "POST",
            "/api/smart_access/verify",
            payload_smart_high_risk,
            headers,
            {200, 403, 422, 429},
        )

    def s_burst_same_ip_valid(_: int):
        headers = {
            "X-Forwarded-For": attack_ip,
            "X-API-Key": rt.api_key,
            "Authorization": f"Bearer {admin_token}",
        }
        return "burst_same_ip_valid", True, "json", "POST", "/api/device/resolve", payload_device, headers, {200, 429, 403}

    def s_control_valid(_: int):
        headers = {
            "X-Forwarded-For": random_ip("203.0.113"),
            "X-API-Key": rt.api_key,
            "Authorization": f"Bearer {admin_token}",
        }
        return "control_valid", False, "json", "POST", "/api/device/resolve", payload_device, headers, {200, 429, 403}

    scenarios = [
        ("bad_api_key", s_bad_api_key, 25),
        ("invalid_token", s_invalid_token, 20),
        ("missing_bearer", s_missing_bearer, 10),
        ("malformed_json", s_malformed_json, 10),
        ("high_risk_smart", s_high_risk_smart, 15),
        ("burst_same_ip_valid", s_burst_same_ip_valid, 10),
        ("control_valid", s_control_valid, 10),
    ]

    scenario_names = [s[0] for s in scenarios]
    scenario_weights = [s[2] for s in scenarios]
    scenario_funcs = {s[0]: s[1] for s in scenarios}

    status_counts: Counter[int] = Counter()
    scenario_counts: Counter[str] = Counter()
    scenario_unexpected: Counter[str] = Counter()
    attack_counts: Counter[str] = Counter()
    attack_defended: Counter[str] = Counter()
    latencies_ms: list[float] = []
    errors: Counter[str] = Counter()

    start = time.time()
    end = start + rt.duration_sec

    def worker() -> list[Tuple[str, bool, Optional[int], set[int], float]]:
        rows = []
        iteration = 0
        while time.time() < end:
            iteration += 1
            name = random.choices(scenario_names, weights=scenario_weights, k=1)[0]
            sname, is_attack, mode, method, path, payload, headers, ok_statuses = scenario_funcs[name](iteration)

            t0 = time.perf_counter()
            if mode == "raw":
                status, _, _ = request_raw(
                    rt.base_url,
                    method,
                    path,
                    payload,
                    headers=headers,
                    timeout_sec=rt.timeout_sec,
                )
            else:
                status, _, _ = request_json(
                    rt.base_url,
                    method,
                    path,
                    body=payload,
                    headers=headers,
                    timeout_sec=rt.timeout_sec,
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            rows.append((sname, is_attack, status, ok_statuses, elapsed_ms))
        return rows

    with ThreadPoolExecutor(max_workers=rt.workers) as pool:
        futures = [pool.submit(worker) for _ in range(rt.workers)]
        all_rows = []
        for fut in as_completed(futures):
            all_rows.extend(fut.result())

    for sname, is_attack, status, ok_statuses, elapsed_ms in all_rows:
        scenario_counts[sname] += 1
        latencies_ms.append(elapsed_ms)

        if status is None:
            errors["network_exception"] += 1
            scenario_unexpected[sname] += 1
            if is_attack:
                attack_counts[sname] += 1
            continue

        status_counts[status] += 1
        if status not in ok_statuses:
            scenario_unexpected[sname] += 1

        if is_attack:
            attack_counts[sname] += 1
            if status in DEFENSE_STATUSES:
                attack_defended[sname] += 1

    elapsed = time.time() - start
    total_requests = sum(scenario_counts.values())
    total_unexpected = sum(scenario_unexpected.values())
    pass_rate = ((total_requests - total_unexpected) / total_requests * 100.0) if total_requests else 0.0

    status_5xx = sum(v for k, v in status_counts.items() if k >= 500)
    defense_total = sum(v for k, v in status_counts.items() if k in DEFENSE_STATUSES)
    defense_ratio = (defense_total / total_requests * 100.0) if total_requests else 0.0

    attack_total = sum(attack_counts.values())
    attack_def_total = sum(attack_defended.values())
    attack_def_ratio = (attack_def_total / attack_total * 100.0) if attack_total else 0.0

    summary = {
        "phase": "B",
        "total_requests": total_requests,
        "elapsed_sec": round(elapsed, 2),
        "rps": round(total_requests / elapsed, 2) if elapsed > 0 else 0,
        "pass_rate_percent": round(pass_rate, 2),
        "unexpected_responses": int(total_unexpected),
        "status_5xx": int(status_5xx),
        "network_exceptions": int(errors.get("network_exception", 0)),
        "defense_ratio_percent": round(defense_ratio, 2),
        "attack_defense_ratio_percent": round(attack_def_ratio, 2),
        "latency_ms": summarize_latencies(latencies_ms),
        "status_counts": dict(status_counts),
        "scenario_unexpected": dict(scenario_unexpected),
        "attack_counts": dict(attack_counts),
        "attack_defended": dict(attack_defended),
    }

    print_common(summary, "PHASE_B")


if __name__ == "__main__":
    main()
