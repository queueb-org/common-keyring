#!/usr/bin/env bash

set -euo pipefail

repository_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repository_dir"

GOWORK=off go test -tags=integration \
	./secure/... \
	./internal/backend/dbus \
	./internal/backend/fs \
	"$@"
