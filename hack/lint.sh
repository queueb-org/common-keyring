#!/usr/bin/env bash

set -euo pipefail

if (( $# != 0 )); then
  echo "Usage: $0" >&2
  exit 2
fi

repository_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# Enforce isolated module resolution.
export GOWORK=off

required_tools=(ineffassign staticcheck govulncheck)
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing %s; run ./hack/install-dev-tools.sh\n' "$tool" >&2
    exit 1
  fi
done

lint_module() {
  local module_dir=$1

  printf 'Linting %s\n' "$module_dir"
  cd -- "$module_dir"

  # Format locally; verify.sh separately rejects unformatted sources first.
  go fmt ./...

  # Report dependency changes, but leave go.mod and go.sum untouched.
  go mod tidy -diff
  go mod verify

  go vet ./...
  ineffassign ./...
  staticcheck ./...
  govulncheck -show verbose ./...
  GOOS=windows govulncheck -show verbose ./...
}

lint_module "$repository_dir"
lint_module "$repository_dir/examples/keyring-cli"
