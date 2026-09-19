//go:build linux

package fs

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestKeyring(t *testing.T) {
	if _, err := Open("", "service"); err == nil {
		t.Fatal("Open() error = nil")
	}

	rootDir := t.TempDir()
	if err := os.Chmod(rootDir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	keyring, err := Open(rootDir, "service")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	ctx := context.Background()
	want := []byte("secret")
	if err := keyring.Set(ctx, "key", want); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := keyring.Get(ctx, "key")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get() = %q, %v, want %q, nil", got, err, want)
	}
	if err := keyring.Delete(ctx, "key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}
