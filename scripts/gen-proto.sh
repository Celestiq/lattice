#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# protoc-gen-go is installed via `go install` into GOPATH/bin.
export PATH="$(go env GOPATH)/bin:$PATH"

cd "$REPO_ROOT"

protoc \
  --go_out=. \
  --go_opt=paths=source_relative \
  proto/frames.proto \
  proto/schemas.proto \
  proto/events.proto
