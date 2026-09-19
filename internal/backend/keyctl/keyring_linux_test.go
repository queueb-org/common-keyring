//go:build linux

package keyctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"common.queueb.org/keyring/internal/contract"

	"golang.org/x/sys/unix"
)

type searchFunc func(int, string, string, int) (int, error)
type addFunc func(string, string, []byte, int) (int, error)
type readFunc func(int) ([]byte, error)
type controlFunc func(int, int, int, int, int) (int, error)

// withKeyOperations overrides keyctl operations for one test and restores
// them during cleanup. It mutates package state and must not be used by
// parallel tests.
func withKeyOperations(
	t *testing.T,
	search searchFunc,
	add addFunc,
	read readFunc,
	control controlFunc,
) {
	t.Helper()
	originalSearch := searchKey
	originalAdd := addKey
	originalRead := getKeyContents
	originalControl := keyctlInt
	searchKey = search
	addKey = add
	getKeyContents = read
	keyctlInt = control
	t.Cleanup(func() {
		searchKey = originalSearch
		addKey = originalAdd
		getKeyContents = originalRead
		keyctlInt = originalControl
	})
}

func unusedSearch(int, string, string, int) (int, error) { return 0, nil }
func unusedAdd(string, string, []byte, int) (int, error) { return 0, nil }
func unusedRead(int) ([]byte, error)                     { return nil, nil }
func unusedControl(int, int, int, int, int) (int, error) { return 0, nil }

func TestOpen(t *testing.T) {
	original := getKeyringID
	t.Cleanup(func() { getKeyringID = original })

	getKeyringID = func(id int, create bool) (int, error) {
		if id != unix.KEY_SPEC_USER_SESSION_KEYRING || !create {
			t.Fatalf("KeyctlGetKeyringID() = %d, %v", id, create)
		}
		return 23, nil
	}
	keyring, err := Open("service")
	if err != nil || keyring.session != 23 || keyring.service != "service" {
		t.Fatalf("Open() = %#v, %v", keyring, err)
	}

	getKeyringID = func(int, bool) (int, error) { return 0, unix.ENOSYS }
	if _, err := Open("service"); !errors.Is(err, contract.ErrBackendUnavailable) {
		t.Fatalf("Open() error = %v, want %v", err, contract.ErrBackendUnavailable)
	}
}

func TestKeyName(t *testing.T) {
	keyring := &Keyring{service: "service"}
	if got := keyring.key("account"); got != keyName("service", "account") {
		t.Fatalf("key() = %q", got)
	}
	if keyName("a-b", "c") == keyName("a", "b-c") {
		t.Fatal("keyName() collided for ambiguous service/key pairs")
	}
	if got := keyName("service", "account"); len(got) != len("keyring:v1:")+sha256.Size*2 {
		t.Fatalf("keyName() length = %d", len(got))
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		withKeyOperations(t,
			func(ring int, keyType, name string, destination int) (int, error) {
				if ring != 23 || keyType != "user" ||
					name != keyName("service", "account") || destination != 0 {
					t.Fatalf("KeyctlSearch() = %d, %q, %q, %d", ring, keyType, name, destination)
				}
				return 42, nil
			},
			unusedAdd,
			func(key int) ([]byte, error) {
				if key != 42 {
					t.Fatalf("read key = %d", key)
				}
				return []byte("secret"), nil
			},
			unusedControl,
		)
		got, err := (&Keyring{session: 23, service: "service"}).Get(ctx, "account")
		if err != nil || !bytes.Equal(got, []byte("secret")) {
			t.Fatalf("Get() = %q, %v", got, err)
		}
	})

	t.Run("search error", func(t *testing.T) {
		withKeyOperations(t,
			func(int, string, string, int) (int, error) { return 0, unix.ENOKEY },
			unusedAdd,
			unusedRead,
			unusedControl,
		)
		if _, err := (&Keyring{}).Get(ctx, "missing"); !errors.Is(err, contract.ErrNotFound) {
			t.Fatalf("Get() error = %v", err)
		}
	})

	t.Run("payload error", func(t *testing.T) {
		withKeyOperations(t,
			func(int, string, string, int) (int, error) { return 42, nil },
			unusedAdd,
			func(int) ([]byte, error) { return nil, errors.New("payload") },
			unusedControl,
		)
		if _, err := (&Keyring{}).Get(ctx, "key"); !errors.Is(err, contract.ErrBackendFailure) {
			t.Fatalf("Get() error = %v", err)
		}
	})
}

func TestSet(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		withKeyOperations(t,
			unusedSearch,
			func(keyType, name string, value []byte, ring int) (int, error) {
				if keyType != "user" || name != keyName("service", "account") ||
					!bytes.Equal(value, []byte("secret")) || ring != 23 {
					t.Fatalf("AddKey() = %q, %q, %q, %d", keyType, name, value, ring)
				}
				return 42, nil
			},
			unusedRead,
			unusedControl,
		)
		if err := (&Keyring{session: 23, service: "service"}).Set(ctx, "account", []byte("secret")); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		err := (&Keyring{}).Set(ctx, "key", make([]byte, userKeyPayloadLimit+1))
		if !errors.Is(err, contract.ErrValueTooLarge) {
			t.Fatalf("Set() error = %v, want %v", err, contract.ErrValueTooLarge)
		}
	})

	t.Run("failure", func(t *testing.T) {
		withKeyOperations(t,
			unusedSearch,
			func(string, string, []byte, int) (int, error) { return 0, unix.EPERM },
			unusedRead,
			unusedControl,
		)
		if err := (&Keyring{}).Set(ctx, "key", nil); !errors.Is(err, contract.ErrPermissionDenied) {
			t.Fatalf("Set() error = %v", err)
		}
	})
}

func TestDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		withKeyOperations(t,
			func(int, string, string, int) (int, error) { return 42, nil },
			unusedAdd,
			unusedRead,
			func(command, key, ring, arg4, arg5 int) (int, error) {
				if command != unix.KEYCTL_UNLINK || key != 42 || ring != 23 || arg4 != 0 || arg5 != 0 {
					t.Fatalf("KeyctlInt() = %d, %d, %d, %d, %d", command, key, ring, arg4, arg5)
				}
				return 0, nil
			},
		)
		if err := (&Keyring{session: 23}).Delete(ctx, "key"); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}
	})

	t.Run("search error", func(t *testing.T) {
		withKeyOperations(t,
			func(int, string, string, int) (int, error) { return 0, unix.ENOKEY },
			unusedAdd,
			unusedRead,
			unusedControl,
		)
		if err := (&Keyring{}).Delete(ctx, "key"); !errors.Is(err, contract.ErrNotFound) {
			t.Fatalf("Delete() error = %v", err)
		}
	})

	t.Run("unlink error", func(t *testing.T) {
		withKeyOperations(t,
			func(int, string, string, int) (int, error) { return 42, nil },
			unusedAdd,
			unusedRead,
			func(int, int, int, int, int) (int, error) { return 0, errors.New("unlink") },
		)
		if err := (&Keyring{}).Delete(ctx, "key"); !errors.Is(err, contract.ErrBackendFailure) {
			t.Fatalf("Delete() error = %v", err)
		}
	})
}

func TestReadKeyContents(t *testing.T) {
	original := keyctlBuffer
	t.Cleanup(func() { keyctlBuffer = original })

	t.Run("size error", func(t *testing.T) {
		want := errors.New("size")
		keyctlBuffer = func(int, int, []byte, int) (int, error) { return 0, want }
		if _, err := readKeyContents(42); !errors.Is(err, want) {
			t.Fatalf("readKeyContents() error = %v, want %v", err, want)
		}
	})

	t.Run("read error", func(t *testing.T) {
		want := errors.New("read")
		calls := 0
		keyctlBuffer = func(command, key int, value []byte, arg5 int) (int, error) {
			if command != unix.KEYCTL_READ || key != 42 || arg5 != 0 {
				t.Fatalf("KeyctlBuffer() = %d, %d, %d", command, key, arg5)
			}
			calls++
			if calls == 1 {
				return 6, nil
			}
			return 0, want
		}
		if _, err := readKeyContents(42); !errors.Is(err, want) {
			t.Fatalf("readKeyContents() error = %v, want %v", err, want)
		}
	})

	t.Run("payload grows", func(t *testing.T) {
		calls := 0
		keyctlBuffer = func(_ int, _ int, value []byte, _ int) (int, error) {
			calls++
			switch calls {
			case 1:
				return 2, nil
			case 2:
				return 6, nil
			default:
				copy(value, "secret")
				return 6, nil
			}
		}
		got, err := readKeyContents(42)
		if err != nil || !bytes.Equal(got, []byte("secret")) || calls != 3 {
			t.Fatalf("readKeyContents() = %q, %v after %d calls", got, err, calls)
		}
	})
}

func TestContext(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	keyring := &Keyring{}
	if _, err := keyring.Get(canceled, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get() error = %v", err)
	}
	if err := keyring.Set(canceled, "key", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Set() error = %v", err)
	}
	if err := keyring.Delete(canceled, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestOperationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "nil"},
		{name: "not found", err: unix.ENOKEY, want: contract.ErrNotFound},
		{name: "expired", err: unix.EKEYEXPIRED, want: contract.ErrNotFound},
		{name: "revoked", err: unix.EKEYREVOKED, want: contract.ErrNotFound},
		{name: "permission", err: unix.EPERM, want: contract.ErrPermissionDenied},
		{name: "unavailable", err: unix.ENOSYS, want: contract.ErrBackendUnavailable},
		{name: "failure", err: errors.New("failure"), want: contract.ErrBackendFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := operationError("operation", test.err)
			if !errors.Is(err, test.want) || test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("operationError() = %v, want %v and %v", err, test.want, test.err)
			}
		})
	}
}

func TestProbeError(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "permission", err: unix.EPERM, want: contract.ErrPermissionDenied},
		{name: "unavailable", err: unix.ENOSYS, want: contract.ErrBackendUnavailable},
		{name: "failure", err: errors.New("failure"), want: contract.ErrBackendFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := probeError(test.err)
			if !errors.Is(err, test.err) || !errors.Is(err, test.want) {
				t.Fatalf("probeError() = %v, want %v and %v", err, test.err, test.want)
			}
		})
	}
}
