#!/bin/sh
set -eu
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/authrail-go-package.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
mkdir "$scratch/module" "$scratch/consumer"
# Check the committed release candidate, without ignored files or workspace replacements.
git -C "$repository" archive HEAD | tar -x -C "$scratch/module"
cd "$scratch/consumer"
export GOWORK=off
go mod init example.com/authrail-consumer
go mod edit -require=github.com/AuthRail/authrail-sdk-go@v0.0.0
go mod edit "-replace=github.com/AuthRail/authrail-sdk-go=$scratch/module"
cat > main.go <<'GO'
package main

import authrail "github.com/AuthRail/authrail-sdk-go"

func main() {
	_ = authrail.NewClient
	_ = authrail.Discover
	_ = authrail.LookupCustomerFact
	_ = authrail.NewOpenAIDecisionsExtractor
	_ = authrail.Config{}
	_ = authrail.Operation{}
}
GO
go mod tidy
go build ./...
printf '%s\n' 'Independent consumer compiles against the committed Go source archive.'
