#!/usr/bin/env bash
set -euo pipefail

# Keep CI workspace deterministic and avoid stale advisory-db residue.
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$PWD}"
git submodule deinit -f --all || true
rm -rf .git/modules/cargo-home/advisory-db || true
rm -rf cargo-home/advisory-db || true
rm -rf .cargo-home/advisory-db || true

# Remove transient artifacts that can pollute CI/local workspaces.
find . -type f \
	\( -name '*.tmp' -o -name '*.temp' -o -name '*.bak' -o -name '*.orig' -o -name '*~' \
		 -o -name '.DS_Store' -o -name '*.rej' -o -name '*.swp' -o -name '*.swo' \) \
	-not -path './.git/*' \
	-delete || true

# Remove package staging artifacts from previous packaging runs.
rm -rf target/package || true
