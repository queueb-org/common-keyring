//go:build windows && integration

package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"common.queueb.org/keyring/internal/contract"
)

func TestLiveCredentialManagerCRUD(t *testing.T) {
	identifierBytes := make([]byte, 16)
	if _, err := rand.Read(identifierBytes); err != nil {
		t.Fatalf("generate identifier: %v", err)
	}

	ctx := context.Background()
	service := "common.queueb.org/keyring/integration"
	key := hex.EncodeToString(identifierBytes)
	want := []byte{0, 1, 2, 127, 128, 254, 255}

	if err := Set(ctx, service, key, want); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	t.Cleanup(func() {
		if err := Delete(ctx, service, key); err != nil && !errors.Is(err, contract.ErrNotFound) {
			t.Errorf("cleanup Delete() error = %v", err)
		}
	})

	got, err := Get(ctx, service, key)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get() = %v, %v, want %v, nil", got, err, want)
	}
	if err := Delete(ctx, service, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := Get(ctx, service, key); !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("Get() after Delete error = %v, want %v", err, contract.ErrNotFound)
	}
}
