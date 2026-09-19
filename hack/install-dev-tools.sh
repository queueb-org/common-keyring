#!/usr/bin/env bash

set -euo pipefail

if (( $# != 0 )); then
  echo "Usage: $0" >&2
  exit 2
fi

dev_tools=(
  github.com/fzipp/gocyclo/cmd/gocyclo@latest
  github.com/gordonklaus/ineffassign@latest
  honnef.co/go/tools/cmd/staticcheck@latest
  golang.org/x/vuln/cmd/govulncheck@latest
)

for tool in "${dev_tools[@]}"; do
  printf 'Installing %s\n' "$tool"
  go install "$tool"
done

printf 'Development tools installed\n'
