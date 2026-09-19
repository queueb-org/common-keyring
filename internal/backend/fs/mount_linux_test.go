//go:build linux

package fs

import (
	"errors"
	"io"
	iofs "io/fs"
	"path/filepath"
	"strings"
	"testing"

	"common.queueb.org/keyring/internal/contract"

	"golang.org/x/sys/unix"
)

func TestValidateMount(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "missing", "fallback")
	if err := validateMount(rootPath); err != nil {
		t.Fatalf("validate current filesystem: %v", err)
	}
}

func TestValidateMountWithEnvironment(t *testing.T) {
	t.Parallel()

	const mountInfo = "1 0 8:1 / / rw - ext4 /dev/root rw\n"
	tests := []struct {
		name        string
		environment fakeMountEnvironment
	}{
		{
			name: "absolute path",
			environment: fakeMountEnvironment{
				absoluteErr: errors.New("absolute failed"),
			},
		},
		{
			name: "stat path",
			environment: fakeMountEnvironment{
				absolutePath: "/fallback",
				statErr:      errors.New("stat failed"),
			},
		},
		{
			name: "missing root",
			environment: fakeMountEnvironment{
				absolutePath: "/",
				statErr:      iofs.ErrNotExist,
			},
		},
		{
			name: "symlink evaluation",
			environment: fakeMountEnvironment{
				absolutePath: "/fallback",
				evaluateErr:  errors.New("evaluation failed"),
			},
		},
		{
			name: "mount metadata",
			environment: fakeMountEnvironment{
				absolutePath: "/fallback",
				mountInfoErr: errors.New("open failed"),
			},
		},
		{
			name: "mount metadata parse",
			environment: fakeMountEnvironment{
				absolutePath: "/fallback",
				mountInfo:    "invalid\n",
			},
		},
		{
			name: "mount selection",
			environment: fakeMountEnvironment{
				absolutePath: "/fallback",
				mountInfo:    "1 0 8:2 / / rw - ext4 /dev/root rw\n",
			},
		},
		{
			name: "DrvFS",
			environment: fakeMountEnvironment{
				absolutePath: "/mnt/c/fallback",
				device:       mountDevice{major: 0, minor: 70},
				mountInfo:    "1 0 0:70 / /mnt/c rw - 9p C:\\134 rw,metadata,aname=drvfs;path=C:\\134\n",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			environment := test.environment
			if environment.mountInfo == "" && environment.mountInfoErr == nil {
				environment.mountInfo = mountInfo
			}
			if err := validateMountWithEnvironment("fallback", environment); !errors.Is(err, contract.ErrInsecureFallback) {
				t.Fatalf("expected insecure fallback error, got %v", err)
			}
		})
	}
}

func TestNearestExistingPath(t *testing.T) {
	t.Parallel()

	environment := fakeMountEnvironment{
		absolutePath:  "/existing/missing/fallback",
		existingPath:  "/existing",
		evaluatedPath: "/resolved",
		device:        mountDevice{major: 8, minor: 1},
	}
	path, device, err := nearestExistingPath("fallback", environment)
	if err != nil {
		t.Fatalf("find nearest existing path: %v", err)
	}
	if path != environment.evaluatedPath {
		t.Fatalf("unexpected resolved path: %q", path)
	}
	if device != environment.device {
		t.Fatalf("unexpected device: %+v", device)
	}
}

func TestParseMountInfo(t *testing.T) {
	t.Parallel()

	contents := strings.Join([]string{
		"1 0 8:1 / / rw shared:1 - ext4 /dev/root rw",
		`2 1 0:70 / /mnt/with\040space rw - 9p C:\134 rw,aname=drvfs;path=C:\134`,
	}, "\n")
	mounts, err := parseMountInfo(strings.NewReader(contents))
	if err != nil {
		t.Fatalf("parse mountinfo: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("unexpected mount count: %d", len(mounts))
	}
	if mounts[1].point != "/mnt/with space" || mounts[1].source != `C:\` {
		t.Fatalf("unexpected decoded mount: %+v", mounts[1])
	}
}

func TestParseMountInfoErrors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		contents string
	}{
		{name: "missing separator", contents: "1 0 8:1 / / rw ext4 /dev/root rw"},
		{name: "short suffix", contents: "1 0 8:1 / / rw - ext4"},
		{name: "device separator", contents: "1 0 invalid / / rw - ext4 /dev/root rw"},
		{name: "device major", contents: "1 0 x:1 / / rw - ext4 /dev/root rw"},
		{name: "device minor", contents: "1 0 8:x / / rw - ext4 /dev/root rw"},
		{name: "mount escape", contents: `1 0 8:1 / /mnt/invalid\999 rw - ext4 /dev/root rw`},
		{name: "source escape", contents: `1 0 8:1 / / rw - ext4 /dev/invalid\999 rw`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseMountInfo(strings.NewReader(test.contents)); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}

	if _, err := parseMountInfo(errorReader{}); err == nil {
		t.Fatal("expected reader error")
	}
}

func TestUnescapeMountField(t *testing.T) {
	t.Parallel()

	decoded, err := unescapeMountField(`a\011b\012c\040d\134e`)
	if err != nil {
		t.Fatalf("unescape field: %v", err)
	}
	if decoded != "a\tb\nc d\\e" {
		t.Fatalf("unexpected decoded field: %q", decoded)
	}
	if _, err := unescapeMountField(`truncated\`); err == nil {
		t.Fatal("expected truncated escape error")
	}
}

func TestSelectMount(t *testing.T) {
	t.Parallel()

	device := mountDevice{major: 8, minor: 1}
	mounts := []mount{
		{device: device, point: "/", filesystem: "ext4"},
		{device: mountDevice{major: 8, minor: 2}, point: "/home", filesystem: "other"},
		{device: device, point: "/home", filesystem: "ext4"},
		{device: device, point: "/home/user", filesystem: "bind"},
	}
	selected, err := selectMount(mounts, "/home/user/secrets", device)
	if err != nil {
		t.Fatalf("select mount: %v", err)
	}
	if selected.point != "/home/user" {
		t.Fatalf("unexpected selected mount: %+v", selected)
	}
	if _, err := selectMount(mounts, "/outside", mountDevice{major: 1, minor: 1}); err == nil {
		t.Fatal("expected missing mount error")
	}
}

func TestPathWithinMount(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		path       string
		mountPoint string
		expected   bool
	}{
		{path: "/", mountPoint: "/", expected: true},
		{path: "/home/user", mountPoint: "/home", expected: true},
		{path: "/home-other", mountPoint: "/home", expected: false},
		{path: "/home", mountPoint: "relative", expected: false},
	} {
		if actual := pathWithinMount(test.path, test.mountPoint); actual != test.expected {
			t.Fatalf("pathWithinMount(%q, %q) = %t", test.path, test.mountPoint, actual)
		}
	}
}

func TestMountIsDrvFS(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		mount    mount
		expected bool
	}{
		{name: "filesystem", mount: mount{filesystem: "DrvFS"}, expected: true},
		{name: "source", mount: mount{source: "DRVFS"}, expected: true},
		{name: "9p option", mount: mount{filesystem: "9p", superOptions: "rw,ANAME=DRVFS;path=C:"}, expected: true},
		{name: "other 9p", mount: mount{filesystem: "9p", superOptions: "rw,aname=drivers"}, expected: false},
		{name: "similar 9p option", mount: mount{filesystem: "9p", superOptions: "rw,aname=drvfs2"}, expected: false},
		{name: "ext4 option", mount: mount{filesystem: "ext4", superOptions: "aname=drvfs"}, expected: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if actual := test.mount.isDrvFS(); actual != test.expected {
				t.Fatalf("isDrvFS() = %t", actual)
			}
		})
	}
}

type fakeMountEnvironment struct {
	absolutePath  string
	absoluteErr   error
	existingPath  string
	evaluatedPath string
	evaluateErr   error
	statErr       error
	device        mountDevice
	mountInfo     string
	mountInfoErr  error
}

func (e fakeMountEnvironment) absolute(string) (string, error) {
	return e.absolutePath, e.absoluteErr
}

func (e fakeMountEnvironment) stat(path string, status *unix.Stat_t) error {
	if e.statErr != nil {
		return e.statErr
	}
	if e.existingPath != "" && path != e.existingPath {
		return iofs.ErrNotExist
	}
	status.Dev = unix.Mkdev(e.device.major, e.device.minor)
	return nil
}

func (e fakeMountEnvironment) evaluateSymlinks(path string) (string, error) {
	if e.evaluateErr != nil {
		return "", e.evaluateErr
	}
	if e.evaluatedPath != "" {
		return e.evaluatedPath, nil
	}
	return path, nil
}

func (e fakeMountEnvironment) openMountInfo() (io.ReadCloser, error) {
	if e.mountInfoErr != nil {
		return nil, e.mountInfoErr
	}
	return io.NopCloser(strings.NewReader(e.mountInfo)), nil
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}
