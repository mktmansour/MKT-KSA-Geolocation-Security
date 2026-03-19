#!/usr/bin/env python3
"""Phase-A: strict functional and security-aware mixed load test."""

from __future__ import annotations

import json
import random
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional, Tuple

from common import (
    build_parser,
    has_code,
    make_token,
    print_common,
    random_ip,
    request_json,
    runtime_from_args,
    summarize_latencies,
)


def make_behavior(entity: str = "phase-a-entity") -> Dict[str, Any]:
    return {
        "entity_id": entity,
        "timestamp": "2026-03-19T01:55:00Z",
        "location": [24.7136, 46.6753],
        "network_info": {
            "ip_address": "8.8.8.8",
            "is_vpn": False,
            "connection_type": "5G",
        },
        "device_fingerprint": "fp-phase-a",
    }


def check_extra(rule: str, status: Optional[int], headers: Dict[str, str], body: str) -> bool:
    if rule == "authorized_device":
        if status != 200:
            return False
        try:
            payload = json.loads(body)
            return isinstance(payload, dict) and isinstance(payload.get("trace_id"), str)
        except Exception:  # noqa: BLE001
            return False

    if rule == "request_id_echo":
        req_id = headers.get("X-Request-ID") or headers.get("x-request-id")
        return status == 200 and bool(req_id) and req_id.startswith("phase-a-rid-")

    return True


def main() -> None:
    parser = build_parser("Phase-A strict live test", default_duration=180, default_workers=10)
    args = parser.parse_args()
    rt = runtime_from_args(args)

    admin_token = make_token(rt.jwt_secret, role="admin")
    user_token = make_token(rt.jwt_secret, role="user")

    payload_device = {
        "os": "Android 14",
        "device_info": "Pixel 8",
        "environment_data": "office-gate",
    }
    payload_geo = {
        "ip_address": "8.8.8.8",
        "gps_data": [24.7136, 46.6753, 95, 20.0],
        "os_info": "Android 14",
        "device_details": "Pixel 8",
        "environment_context": "office-gate",
        "behavior_input": make_behavior(),
    }
    payload_smart = {
        "geo_input": None,
        "behavior_input": make_behavior(),
        "os_info": "Android 14",
        "device_details": "Pixel 8",
        "env_context": "office-gate",
    }

    def scenario_authorized_device(i: int):
        return (
            "authorized_device",
            "POST",
            "/api/device/resolve",
            payload_device,
            {
                "X-Forwarded-For": random_ip("203.0.113"),
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {admin_token}",
            },
            {200},
            None,
        )

    def scenario_request_id_echo(i: int):
        rid = f"phase-a-rid-{i}-{random.randint(1000, 9999)}"
        return (
            "request_id_echo",
            "POST",
            "/api/device/resolve",
            payload_device,
            {
                "X-Forwarded-For": random_ip("203.0.113"),
                "X-Request-ID": rid,
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {admin_token}",
            },
            {200},
            None,
        )

    def scenario_geo(_: int):
        return (
            "geo_resolve",
            "POST",
            "/api/geo/resolve",
            payload_geo,
            {
                "X-Forwarded-For": random_ip("198.51.100"),
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {admin_token}",
            },
            {200, 422},
            None,
        )

    def scenario_smart(_: int):
        return (
            "smart_access",
            "POST",
            "/api/smart_access/verify",
            payload_smart,
            {
                "X-Forwarded-For": random_ip("198.51.100"),
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {admin_token}",
            },
            {200, 403},
            None,
        )

    def scenario_users_admin(_: int):
        uid = str(uuid.uuid4())
        return (
            "users_admin",
            "GET",
            f"/api/users/{uid}",
            None,
            {
                "X-Forwarded-For": random_ip("192.0.2"),
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {admin_token}",
            },
            {200, 404},
            None,
        )

    def scenario_users_non_admin(_: int):
        uid = str(uuid.uuid4())
        return (
            "users_non_admin",
            "GET",
            f"/api/users/{uid}",
            None,
            {
                "X-Forwarded-For": random_ip("192.0.2"),
                "X-API-Key": rt.api_key,
                "Authorization": f"Bearer {user_token}",
            },
            {403},
            "INSUFFICIENT_PERMISSIONS",
        )

    def scenario_missing_api(_: int):
        return (
            "missing_api_key",
            "POST",
            "/api/device/resolve",
            payload_device,
            {"X-Forwarded-For": random_ip("198.51.100")},
            {401},
            "MISSING_API_KEY",
        )

    def scenario_invalid_api(_: int):
        return (
            "invalid_api_key",
            "POST",
            "/api/device/resolve",
            payload_device,
            {
                "X-Forwarded-For": random_ip("198.51.100"),
                "X-API-Key": "bad",
                "Authorization": f"Bearer {admin_token}",
            },
            {401},
            "INVALID_API_KEY",
        )

    def scenario_missing_bearer(_: int):
        return (
            "missing_bearer",
            "POST",
            "/api/device/resolve",
            payload_device,
            {
                "X-Forwarded-For": random_ip("198.51.100"),
                "X-API-Key": rt.api_key,
            },
            {401},
            "MISSING_BEARER_TOKEN",
        )

    def scenario_invalid_token(_: int):
        return (
            "invalid_token",
            "POST",
            "/api/device/resolve",
            payload_device,
            {
                "X-Forwarded-For": random_ip("198.51.100"),
                "X-API-Key": rt.api_key,
                "Authorization": "Bearer invalid.jwt",
            },
            {401},
            "INVALID_OR_EXPIRED_TOKEN",
        )

    scenarios = [
        ("authorized_device", scenario_authorized_device, 30),
        ("request_id_echo", scenario_request_id_echo, 6),
        ("geo_resolve", scenario_geo, 15),
        ("smart_access", scenario_smart, 10),
        ("users_admin", scenario_users_admin, 8),
        ("users_non_admin", scenario_users_non_admin, 7),
        ("missing_api_key", scenario_missing_api, 7),
        ("invalid_api_key", scenario_invalid_api, 5),
        ("missing_bearer", scenario_missing_bearer, 6),
        ("invalid_token", scenario_invalid_token, 6),
    ]

    scenario_names = [s[0] for s in scenarios]
    scenario_weights = [s[2] for s in scenarios]
    scenario_funcs = {s[0]: s[1] for s in scenarios}

    status_counts: Counter[int] = Counter()
    scenario_counts: Counter[str] = Counter()
    scenario_unexpected: Counter[str] = Counter()
    latencies_ms: list[float] = []
    errors: Counter[str] = Counter()

    start = time.time()
    end = start + rt.duration_sec

    def worker() -> list[Tuple[str, Optional[int], Dict[str, str], str, set[int], Optional[str], float]]:
        rows = []
        iteration = 0
        while time.time() < end:
            iteration += 1
            name = random.choices(scenario_names, weights=scenario_weights, k=1)[0]
            sname, method, path, body, headers, ok_statuses, ok_code = scenario_funcs[name](iteration)
            t0 = time.perf_counter()
            status, resp_headers, resp_body = request_json(
                rt.base_url,
                method,
                path,
                body=body,
                headers=headers,
                timeout_sec=rt.timeout_sec,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            rows.append((sname, status, resp_headers, resp_body, ok_statuses, ok_code, elapsed_ms))
        return rows

    with ThreadPoolExecutor(max_workers=rt.workers) as pool:
        futures = [pool.submit(worker) for _ in range(rt.workers)]
        all_rows = []
        for fut in as_completed(futures):
            all_rows.extend(fut.result())

    for sname, status, resp_headers, resp_body, ok_statuses, ok_code, elapsed_ms in all_rows:
        scenario_counts[sname] += 1
        latencies_ms.append(elapsed_ms)

        if status is None:
            errors["network_exception"] += 1
            scenario_unexpected[sname] += 1
            continue

        status_counts[status] += 1
        ok = (status in ok_statuses) and has_code(resp_body, ok_code) and check_extra(
            sname, status, resp_headers, resp_body
        )
        if not ok:
            scenario_unexpected[sname] += 1

    elapsed = time.time() - start
    total_requests = sum(scenario_counts.values())
    total_unexpected = sum(scenario_unexpected.values())
    pass_rate = ((total_requests - total_unexpected) / total_requests * 100.0) if total_requests else 0.0

    summary = {
        "phase": "A",
        "total_requests": total_requests,
        "elapsed_sec": round(elapsed, 2),
        "rps": round(total_requests / elapsed, 2) if elapsed > 0 else 0,
        "pass_rate_percent": round(pass_rate, 2),
        "unexpected_responses": int(total_unexpected),
        "status_5xx": int(sum(v for k, v in status_counts.items() if k >= 500)),
        "network_exceptions": int(errors.get("network_exception", 0)),
        "latency_ms": summarize_latencies(latencies_ms),
        "status_counts": dict(status_counts),
        "scenario_counts": dict(scenario_counts),
        "scenario_unexpected": dict(scenario_unexpected),
    }

    print_common(summary, "PHASE_A")


if __name__ == "__main__":
    main()
