package fs

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestLayout(t *testing.T) {
	t.Parallel()

	layout := newLayout("example")
	if layout.serviceID != "1040e4d063233769773d25c38ba16e0df02de87916911b60a419fc3064fa25f8" {
		t.Fatalf("unexpected service identifier: %q", layout.serviceID)
	}

	servicePath := filepath.Join(layoutVersion, layout.serviceID)
	if layout.servicePath() != servicePath {
		t.Fatalf("unexpected service path: %q", layout.servicePath())
	}

	const keyID = "00c73cf4f915f7bae6bc9d2e62a0d0b4516ca6f12b91dedd34b720bc14f44d93"
	if keyPath := layout.keyPath("token"); keyPath != filepath.Join(servicePath, keyID) {
		t.Fatalf("unexpected key path: %q", keyPath)
	}
}

func TestIdentifierDomainSeparation(t *testing.T) {
	t.Parallel()

	if identifier(serviceDomain, "same") == identifier(keyDomain, "same") {
		t.Fatal("service and key identifiers must use separate domains")
	}
}

func FuzzLayoutKeyPath(f *testing.F) {
	for _, key := range []string{
		"",
		"token",
		"..",
		"../outside",
		"/absolute",
		`C:\absolute`,
		"directory/key",
		"ключ/秘密",
		strings.Repeat("long-key", 1024),
	} {
		f.Add(key)
	}

	layout := newLayout("service/../with/path/syntax")
	servicePath := layout.servicePath()
	f.Fuzz(func(t *testing.T, key string) {
		keyPath := layout.keyPath(key)
		if filepath.IsAbs(keyPath) {
			t.Fatalf("key path is absolute: %q", keyPath)
		}
		if filepath.Dir(keyPath) != servicePath {
			t.Fatalf("key path escaped service directory: %q", keyPath)
		}

		keyID := filepath.Base(keyPath)
		if len(keyID) != sha256HexLength {
			t.Fatalf("unexpected key identifier length: %d", len(keyID))
		}
		if _, err := hex.DecodeString(keyID); err != nil {
			t.Fatalf("key identifier is not hexadecimal: %q", keyID)
		}
	})
}

const sha256HexLength = 64
