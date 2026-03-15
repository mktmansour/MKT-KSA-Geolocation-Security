#!/usr/bin/env bash
set -euo pipefail

# Keep CI workspace deterministic and avoid stale advisory-db residue.
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$PWD}"
git submodule deinit -f --all || true
rm -rf .git/modules/cargo-home/advisory-db || true
rm -rf cargo-home/advisory-db || true
rm -rf .cargo-home/advisory-db || true
