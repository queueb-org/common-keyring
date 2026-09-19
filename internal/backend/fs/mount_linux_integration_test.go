//go:build linux && integration

package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"common.queueb.org/keyring/internal/contract"
)

func TestIntegrationDrvFSMountRejected(t *testing.T) {
	mountInfo, err := os.Open(mountInfoPath)
	if err != nil {
		t.Fatalf("open mount metadata: %v", err)
	}
	defer mountInfo.Close()

	mounts, err := parseMountInfo(mountInfo)
	if err != nil {
		t.Fatalf("parse mount metadata: %v", err)
	}
	for _, mount := range mounts {
		if !mount.isDrvFS() {
			continue
		}
		rootPath := filepath.Join(mount.point, fmt.Sprintf(".keyring-fs-drvfs-test-%d", os.Getpid()))
		if _, err := os.Lstat(rootPath); !errors.Is(err, os.ErrNotExist) {
			t.Skipf("DrvFS test path %q is not available", rootPath)
		}
		t.Cleanup(func() { _ = os.RemoveAll(rootPath) })

		if _, err := Open(rootPath, "integration-test"); !errors.Is(err, contract.ErrInsecureFallback) {
			t.Fatalf("Open on DrvFS mount %q: got %v, want %v", mount.point, err, contract.ErrInsecureFallback)
		}
		if _, err := os.Lstat(rootPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Open wrote to rejected DrvFS path %q", rootPath)
		}
		return
	}
	t.Skip("no DrvFS mount is visible")
}
