#!/usr/bin/env python3
"""Shared helpers for live security performance scripts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import statistics
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib import error, request


@dataclass
class RuntimeConfig:
    base_url: str
    api_key: str
    jwt_secret: bytes
    duration_sec: int
    workers: int
    timeout_sec: float


def build_parser(description: str, default_duration: int, default_workers: int) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--base-url", default=os.getenv("SECURITY_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--api-key", default=os.getenv("API_KEY"))
    parser.add_argument("--jwt-secret", default=os.getenv("JWT_SECRET"))
    parser.add_argument("--duration-sec", type=int, default=default_duration)
    parser.add_argument("--workers", type=int, default=default_workers)
    parser.add_argument("--timeout-sec", type=float, default=float(os.getenv("SECURITY_HTTP_TIMEOUT_SEC", "8")))
    return parser


def runtime_from_args(args: argparse.Namespace) -> RuntimeConfig:
    if not args.api_key:
        raise SystemExit("API key is required. Pass --api-key or set API_KEY.")
    if not args.jwt_secret:
        raise SystemExit("JWT secret is required. Pass --jwt-secret or set JWT_SECRET.")

    return RuntimeConfig(
        base_url=args.base_url.rstrip("/"),
        api_key=args.api_key,
        jwt_secret=args.jwt_secret.encode("utf-8"),
        duration_sec=max(1, int(args.duration_sec)),
        workers=max(1, int(args.workers)),
        timeout_sec=max(0.1, float(args.timeout_sec)),
    )


def b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def make_token(secret: bytes, role: str = "admin", exp_seconds: int = 3600) -> str:
    now = int(time.time())
    header = {"alg": "HS512", "typ": "JWT"}
    payload = {
        "sub": str(uuid.uuid4()),
        "roles": [role],
        "exp": now + max(10, exp_seconds),
        "iat": now,
        "iss": "mkt_ksa_geo_sec",
        "aud": "api_clients",
    }
    msg = b64(json.dumps(header, separators=(",", ":")).encode("utf-8")) + b"." + b64(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    sig = hmac.new(secret, msg, hashlib.sha512).digest()
    return (msg + b"." + b64(sig)).decode("utf-8")


def request_json(
    base_url: str,
    method: str,
    path: str,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout_sec: float = 8.0,
) -> Tuple[Optional[int], Dict[str, str], str]:
    final_headers = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")

    req = request.Request(base_url + path, data=data, headers=final_headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout_sec) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode(errors="replace")
    except error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read().decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        return None, {}, str(exc)


def request_raw(
    base_url: str,
    method: str,
    path: str,
    raw_data: bytes,
    headers: Optional[Dict[str, str]] = None,
    timeout_sec: float = 8.0,
) -> Tuple[Optional[int], Dict[str, str], str]:
    final_headers = dict(headers or {})
    req = request.Request(base_url + path, data=raw_data, headers=final_headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout_sec) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode(errors="replace")
    except error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read().decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        return None, {}, str(exc)


def percentile(values: list[float], p: int) -> Optional[float]:
    if not values:
        return None
    sorted_vals = sorted(values)
    idx = int(round((p / 100.0) * (len(sorted_vals) - 1)))
    return sorted_vals[idx]


def summarize_latencies(latencies: list[float]) -> Dict[str, Optional[float]]:
    if not latencies:
        return {"avg": None, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "avg": round(statistics.mean(latencies), 2),
        "p50": round(percentile(latencies, 50) or 0.0, 2),
        "p95": round(percentile(latencies, 95) or 0.0, 2),
        "p99": round(percentile(latencies, 99) or 0.0, 2),
        "max": round(max(latencies), 2),
    }


def has_code(body_text: str, expected: Optional[str]) -> bool:
    if expected is None:
        return True
    try:
        payload = json.loads(body_text)
        if isinstance(payload, dict):
            return payload.get("code") == expected
    except Exception:  # noqa: BLE001
        pass
    return expected in body_text


def random_ip(prefix: str) -> str:
    return f"{prefix}.{random.randint(1, 240)}"


def write_summary_artifact(script_name: str, summary: Dict[str, Any]) -> Path:
    out_dir = Path("artifacts/security")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    out_file = out_dir / f"{script_name}_{stamp}.json"
    out_file.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return out_file


def print_common(summary: Dict[str, Any], prefix: str) -> None:
    artifact = write_summary_artifact(prefix.lower(), summary)
    print(f"{prefix}_SUMMARY|" + json.dumps(summary, separators=(",", ":")))
    print(f"{prefix}_ARTIFACT|{artifact}")


def new_counters() -> Tuple[Counter, Counter, Counter, Counter, list[float], Counter]:
    return Counter(), Counter(), Counter(), Counter(), [], Counter()
