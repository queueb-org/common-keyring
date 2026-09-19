#!/usr/bin/env bash

set -euo pipefail

repository_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
host_goos=$(go env GOOS)

if [[ "$host_goos" != windows ]]; then
	if [[ "$host_goos" != linux ]] || ! grep -Eiq '(microsoft|wsl)' /proc/sys/kernel/osrelease; then
		printf 'Windows integration tests require Windows or WSL with Windows interop\n' >&2
		exit 1
	fi
fi

cd -- "$repository_dir"

GOWORK=off GOOS=windows GOARCH=$(go env GOARCH) \
	go test -tags=integration ./internal/backend/windows "$@"
