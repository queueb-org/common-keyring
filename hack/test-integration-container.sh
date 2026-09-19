#!/usr/bin/env bash

set -euo pipefail

if (( $# < 1 )); then
	printf 'Usage: %s allowed|denied|unavailable [go-test-arguments...]\n' "$0" >&2
	exit 2
fi

mode=$1
shift
repository_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_binary=$(mktemp /tmp/keyring-container-test.XXXXXX)
trap 'rm -f -- "$test_binary"' EXIT

expected_error=
security_options=()
case "$mode" in
	allowed)
		security_options=(--security-opt seccomp=unconfined)
		;;
	denied)
		expected_error=permission
		;;
	unavailable)
		expected_error=unavailable
		security_options=(
			--security-opt "seccomp=$repository_dir/hack/seccomp/keyctl-unavailable.json"
		)
		;;
	*)
		printf 'unknown container integration mode %q\n' "$mode" >&2
		exit 2
		;;
esac

cd -- "$repository_dir"
CGO_ENABLED=0 GOWORK=off go test -c -tags=integration \
	-o "$test_binary" ./secure

docker run --rm --read-only --network none \
	"${security_options[@]}" \
	-e KEYRING_TEST_EXPECT_KEYCTL_ERROR="$expected_error" \
	-v "$test_binary:/keyring.test:ro" \
	alpine:latest \
	/keyring.test -test.run '^TestLinuxKeyringIntegration$' "$@"
