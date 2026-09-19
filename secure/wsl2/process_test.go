//go:build linux

package wsl2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := run(context.Background(), testScript(t, "printf response\n"), []byte("request"))
		if result.err != nil || result.exitCode != 0 || string(result.output) != "response" {
			t.Fatalf("run() = %+v", result)
		}
	})

	t.Run("exit error", func(t *testing.T) {
		result := run(context.Background(), testScript(t, "printf failure\nexit 7\n"), nil)
		if result.err != nil || result.exitCode != 7 || string(result.output) != "failure" {
			t.Fatalf("run() = %+v", result)
		}
	})

	t.Run("execution error", func(t *testing.T) {
		result := run(context.Background(), filepath.Join(t.TempDir(), "missing"), nil)
		if result.err == nil || result.exitCode != -1 {
			t.Fatalf("run() = %+v", result)
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		body := "printf '%s' '" + strings.Repeat("x", maxMessageBytes+1) + "'\n"
		result := run(context.Background(), testScript(t, body), nil)
		if !errors.Is(result.err, ErrProtocol) || result.exitCode != -1 {
			t.Fatalf("run() = %+v, want %v", result, ErrProtocol)
		}
	})
}

func testScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return path
}
