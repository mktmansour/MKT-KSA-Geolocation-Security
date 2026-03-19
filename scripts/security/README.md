# Security Performance Scripts

Deterministic live security load scripts for periodic hardening checks.

## Prerequisites

- Running API server (default `http://127.0.0.1:8080`)
- `API_KEY` and `JWT_SECRET` exported in the shell
- Python 3.10+

## Scripts

- `phase_a_strict.py`: mixed functional/security strict validation
- `phase_b_hostile.py`: adversarial pressure and defense effectiveness test
- `phase_10m_split.py`: 10-minute split traffic test (legitimate vs hostile)
- `run_security_cycle.sh`: runs Phase-A, Phase-B, then 10m split in sequence

## Examples

```bash
export API_KEY='change_me'
export JWT_SECRET='replace_with_a_long_secret_32_chars_min'
export SECURITY_BASE_URL='http://127.0.0.1:8080'

python3 scripts/security/phase_a_strict.py --duration-sec 180 --workers 10
python3 scripts/security/phase_b_hostile.py --duration-sec 180 --workers 16
python3 scripts/security/phase_10m_split.py --duration-sec 600 --workers 24 --legit-share 0.45
```

Full cycle:

```bash
bash scripts/security/run_security_cycle.sh
```

Each script prints `*_SUMMARY|{...}` and stores a JSON artifact in `artifacts/security/`.
