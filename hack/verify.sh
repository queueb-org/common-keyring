#!/usr/bin/env bash

set -euo pipefail

repository_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
main_coverage=$(mktemp /tmp/keyring-coverage.XXXXXX)
example_coverage=$(mktemp /tmp/keyring-example-coverage.XXXXXX)
unformatted=$(gofmt -l "$repository_dir")

if [[ -n "$unformatted" ]]; then
	printf 'files require gofmt:\n%s\n' "$unformatted" >&2
	exit 1
fi

cleanup() {
	rm -f -- "$main_coverage" "$example_coverage"
}
trap cleanup EXIT

verify_module() {
	local module_dir=$1
	local coverage_file=$2
	local coverage_report
	local incomplete

	cd -- "$module_dir"
	GOWORK=off go test -coverprofile="$coverage_file" ./...
	coverage_report=$(GOWORK=off go tool cover -func="$coverage_file")
	printf '%s\n' "$coverage_report"
	incomplete=$(printf '%s\n' "$coverage_report" | awk '$NF != "100.0%"')
	if [[ -n "$incomplete" ]]; then
		printf 'statement coverage below 100%%:\n%s\n' "$incomplete" >&2
		return 1
	fi

	CGO_ENABLED=1 GOWORK=off go test -race ./...
}

"$repository_dir/hack/lint.sh"
verify_module "$repository_dir" "$main_coverage"
verify_module "$repository_dir/examples/keyring-cli" "$example_coverage"
