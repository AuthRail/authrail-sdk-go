#!/bin/sh
set -eu
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/authrail-sdk-sidecar.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
cat > "$scratch/go.work" <<EOF
go 1.26.0
use (
  $repository
  $repository/../authrail-sidecar
)
EOF
cd "$repository/../authrail-sdk-node"
npm run build
cd "$repository"
GOWORK="$scratch/go.work" go run scripts/sidecar-check.go
