//go:build !windows

package windows

import (
	"errors"
	"testing"

	"common.queueb.org/keyring/internal/contract"
)

func TestUnsupportedPlatformOperations(t *testing.T) {
	value, err := nativeReadCredential("target")
	if value != nil || !errors.Is(err, contract.ErrUnsupported) {
		t.Fatalf("nativeReadCredential() = %v, %v", value, err)
	}
	if err := nativeWriteCredential("target", "key", nil); !errors.Is(err, contract.ErrUnsupported) {
		t.Fatalf("nativeWriteCredential() = %v", err)
	}
	if err := nativeDeleteCredential("target"); !errors.Is(err, contract.ErrUnsupported) {
		t.Fatalf("nativeDeleteCredential() = %v", err)
	}
}
