#!/usr/bin/env bash
# Fails if any shipped dependency uses a license that is not compatible with AGPL-3.0-only.
# Only production dependencies are checked: dev tooling is never distributed.
set -euo pipefail

cd "$(dirname "$0")/.."

ALLOWED_GO="Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MIT,MPL-2.0,Unlicense,0BSD,AGPL-3.0"
ALLOWED_NPM="MIT;ISC;Apache-2.0;BSD-2-Clause;BSD-3-Clause;0BSD;MPL-2.0;OFL-1.1;Unlicense;CC0-1.0;BlueOak-1.0.0"

echo "==> Go (server)"
go run github.com/google/go-licenses/v2@v2.0.1 check ./server/... \
  --allowed_licenses="${ALLOWED_GO}" \
  --ignore github.com/Shaalan15/central

echo "==> npm (web, production dependencies)"
(cd web && npx --yes license-checker-rseidelsohn@5.0.1 --production --excludePrivatePackages \
  --onlyAllow "${ALLOWED_NPM}" --summary)

echo "All dependency licenses are AGPL-3.0 compatible."
