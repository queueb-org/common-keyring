//go:build linux && integration

package dbus

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"common.queueb.org/keyring/internal/contract"
)

func TestIntegrationUnavailableSessionBus(t *testing.T) {
	t.Setenv(
		"DBUS_SESSION_BUS_ADDRESS",
		"unix:path="+filepath.Join(t.TempDir(), "missing-session-bus"),
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	started := time.Now()
	err := Probe(ctx)
	if !errors.Is(err, contract.ErrBackendUnavailable) {
		t.Fatalf("Probe() error = %v, want %v", err, contract.ErrBackendUnavailable)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("Probe() took %s, want less than 1s", elapsed)
	}
}

func TestIntegrationUnavailableSecretService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := Probe(ctx)
	if err == nil {
		t.Skip("Secret Service is available in this session")
	}
	if !errors.Is(err, contract.ErrBackendUnavailable) {
		t.Fatalf("Probe() error = %v, want %v", err, contract.ErrBackendUnavailable)
	}
}
