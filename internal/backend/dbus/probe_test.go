package dbus

import (
	"context"
	"errors"
	"testing"
	"time"

	"common.queueb.org/keyring/internal/contract"

	godbus "github.com/godbus/dbus/v5"
)

type probeBusObject struct {
	call *godbus.Call
}

func (o *probeBusObject) Call(string, godbus.Flags, ...any) *godbus.Call { return o.call }
func (o *probeBusObject) CallWithContext(context.Context, string, godbus.Flags, ...any) *godbus.Call {
	return o.call
}
func (o *probeBusObject) Go(string, godbus.Flags, chan *godbus.Call, ...any) *godbus.Call {
	return o.call
}
func (o *probeBusObject) GoWithContext(context.Context, string, godbus.Flags, chan *godbus.Call, ...any) *godbus.Call {
	return o.call
}
func (o *probeBusObject) AddMatchSignal(string, string, ...godbus.MatchOption) *godbus.Call {
	return o.call
}
func (o *probeBusObject) RemoveMatchSignal(string, string, ...godbus.MatchOption) *godbus.Call {
	return o.call
}
func (*probeBusObject) GetProperty(string) (godbus.Variant, error) { return godbus.Variant{}, nil }
func (*probeBusObject) StoreProperty(string, any) error            { return nil }
func (*probeBusObject) SetProperty(string, any) error              { return nil }
func (*probeBusObject) Destination() string                        { return serviceName }
func (*probeBusObject) Path() godbus.ObjectPath                    { return servicePath }

type probeObjectProvider struct {
	object godbus.BusObject
	err    error
}

func (p probeObjectProvider) Object(string, godbus.ObjectPath) godbus.BusObject { return p.object }
func (p probeObjectProvider) Close() error                                      { return p.err }
func (probeObjectProvider) AddMatchSignalContext(context.Context, ...godbus.MatchOption) error {
	return nil
}
func (probeObjectProvider) RemoveMatchSignalContext(context.Context, ...godbus.MatchOption) error {
	return nil
}
func (probeObjectProvider) Signal(chan<- *godbus.Signal)       {}
func (probeObjectProvider) RemoveSignal(chan<- *godbus.Signal) {}

type probeConnector struct {
	connection connection
	err        error
	called     *bool
}

func (c probeConnector) Connect(context.Context) (connection, error) {
	if c.called != nil {
		*c.called = true
	}
	return c.connection, c.err
}

func TestProbeContext(t *testing.T) {
	//lint:ignore SA1012, for test purposes
	if err := Probe(nil); !errors.Is(err, contract.ErrInvalidArgument) {
		t.Fatalf("Probe(nil) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe() error = %v", err)
	}
}

func TestProbe(t *testing.T) {
	ctx := context.Background()
	constructorErr := errors.New("constructor")
	openErr := errors.New("open")
	closeSessionErr := errors.New("close session")
	closeConnectionErr := errors.New("close connection")

	tests := []struct {
		name               string
		constructorErr     error
		openErr            error
		closeSessionErr    error
		closeConnectionErr error
		want               error
	}{
		{name: "success"},
		{name: "constructor", constructorErr: constructorErr, want: contract.ErrBackendFailure},
		{name: "open", openErr: openErr, want: contract.ErrBackendFailure},
		{name: "close session", closeSessionErr: closeSessionErr, want: contract.ErrBackendFailure},
		{name: "close connection", closeConnectionErr: closeConnectionErr, want: contract.ErrBackendFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constructed := false
			opened := false
			sessionClosed := false
			connectionClosed := false
			err := probe(ctx,
				probeConnector{
					connection: probeObjectProvider{},
					err:        test.constructorErr,
					called:     &constructed,
				},
				func(context.Context, connection) (godbus.BusObject, error) {
					opened = true
					return nil, test.openErr
				},
				func(context.Context, godbus.BusObject) error {
					sessionClosed = true
					return test.closeSessionErr
				},
				func(connection) error {
					connectionClosed = true
					return test.closeConnectionErr
				},
			)
			if !constructed {
				t.Fatal("connector was not called")
			}
			if test.want == nil {
				if err != nil {
					t.Fatalf("probe() error = %v", err)
				}
			} else if !errors.Is(err, test.want) {
				t.Fatalf("probe() error = %v, want %v", err, test.want)
			}
			if opened != (test.constructorErr == nil) ||
				sessionClosed != (test.constructorErr == nil && test.openErr == nil) ||
				connectionClosed != (test.constructorErr == nil) {
				t.Fatalf("calls = construct:%t open:%t session:%t connection:%t",
					constructed, opened, sessionClosed, connectionClosed)
			}
		})
	}
}

func TestSessionBusConnector(t *testing.T) {
	expected := errors.New("connect")
	connector := sessionBusConnector{
		connect: func(...godbus.ConnOption) (*godbus.Conn, error) { return nil, expected },
	}
	if _, err := connector.Connect(context.Background()); !errors.Is(err, expected) {
		t.Fatalf("Connect() error = %v", err)
	}
}

// withSessionBusStages overrides private D-Bus connection stages for one test
// and restores them during cleanup. It mutates package state and must not be
// used by parallel tests.
func withSessionBusStages(
	t *testing.T,
	dial func(...godbus.ConnOption) (*godbus.Conn, error),
	auth func(*godbus.Conn, []godbus.Auth) error,
	hello func(*godbus.Conn) error,
	close func(*godbus.Conn) error,
) {
	t.Helper()
	originalDial := dialSessionBus
	originalAuth := authSessionBus
	originalHello := helloSessionBus
	originalClose := closeSessionBus
	dialSessionBus = dial
	authSessionBus = auth
	helloSessionBus = hello
	closeSessionBus = close
	t.Cleanup(func() {
		dialSessionBus = originalDial
		authSessionBus = originalAuth
		helloSessionBus = originalHello
		closeSessionBus = originalClose
	})
}

func TestConnectSessionBus(t *testing.T) {
	dialErr := errors.New("dial")
	authErr := errors.New("auth")
	helloErr := errors.New("hello")
	closeErr := errors.New("close")

	tests := []struct {
		name       string
		dialErr    error
		authErr    error
		helloErr   error
		closeErr   error
		want       error
		category   error
		wantClosed bool
	}{
		{name: "success"},
		{name: "dial", dialErr: dialErr, want: dialErr, category: contract.ErrBackendUnavailable},
		{name: "auth", authErr: authErr, want: authErr, category: contract.ErrPermissionDenied, wantClosed: true},
		{name: "hello", helloErr: helloErr, want: helloErr, category: contract.ErrBackendFailure, wantClosed: true},
		{name: "cleanup", authErr: authErr, closeErr: closeErr, want: closeErr, category: contract.ErrPermissionDenied, wantClosed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := new(godbus.Conn)
			closed := false
			withSessionBusStages(t,
				func(options ...godbus.ConnOption) (*godbus.Conn, error) {
					if len(options) != 1 {
						t.Fatalf("dial options = %d, want 1", len(options))
					}
					return connection, test.dialErr
				},
				func(got *godbus.Conn, methods []godbus.Auth) error {
					if got != connection || methods != nil {
						t.Fatalf("Auth() = %p, %#v", got, methods)
					}
					return test.authErr
				},
				func(got *godbus.Conn) error {
					if got != connection {
						t.Fatalf("Hello() connection = %p", got)
					}
					return test.helloErr
				},
				func(got *godbus.Conn) error {
					if got != connection {
						t.Fatalf("Close() connection = %p", got)
					}
					closed = true
					return test.closeErr
				},
			)

			got, err := connectSessionBus(godbus.WithContext(context.Background()))
			if !errors.Is(err, test.want) {
				t.Fatalf("connectSessionBus() error = %v, want %v", err, test.want)
			}
			if !errors.Is(err, test.category) {
				t.Fatalf("connectSessionBus() error = %v, want category %v", err, test.category)
			}
			if (got == connection) != (test.want == nil) || closed != test.wantClosed {
				t.Fatalf("connectSessionBus() = %p, closed %t", got, closed)
			}
			if test.closeErr != nil && !errors.Is(err, test.authErr) {
				t.Fatalf("connectSessionBus() error = %v, want operation cause %v", err, test.authErr)
			}
		})
	}
}

func TestProbeSessionOperations(t *testing.T) {
	ctx := context.Background()
	t.Run("open", func(t *testing.T) {
		object := &probeBusObject{call: &godbus.Call{Body: []any{
			godbus.MakeVariant(""), godbus.ObjectPath("/session"),
		}}}
		session, err := openProbeSession(ctx, probeObjectProvider{object: object})
		if err != nil || session != object {
			t.Fatalf("openProbeSession() = %T, %v", session, err)
		}
	})

	t.Run("open error", func(t *testing.T) {
		expected := errors.New("open")
		object := &probeBusObject{call: &godbus.Call{Err: expected}}
		if _, err := openProbeSession(ctx, probeObjectProvider{object: object}); !errors.Is(err, expected) {
			t.Fatalf("openProbeSession() error = %v", err)
		}
	})

	t.Run("close session", func(t *testing.T) {
		expected := errors.New("close")
		object := &probeBusObject{call: &godbus.Call{Err: expected}}
		if err := closeProbeSession(ctx, object); !errors.Is(err, expected) {
			t.Fatalf("closeProbeSession() error = %v", err)
		}
	})

	t.Run("close connection", func(t *testing.T) {
		expected := errors.New("close")
		if err := closeConnection(probeObjectProvider{err: expected}); !errors.Is(err, expected) {
			t.Fatalf("closeConnection() error = %v", err)
		}
	})
}

func TestBackendError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "unavailable", err: godbus.Error{Name: "org.freedesktop.DBus.Error.ServiceUnknown"}, want: contract.ErrBackendUnavailable},
		{name: "no owner", err: godbus.Error{Name: "org.freedesktop.DBus.Error.NameHasNoOwner"}, want: contract.ErrBackendUnavailable},
		{name: "denied", err: godbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"}, want: contract.ErrPermissionDenied},
		{name: "authentication", err: godbus.Error{Name: "org.freedesktop.DBus.Error.AuthFailed"}, want: contract.ErrPermissionDenied},
		{name: "no reply", err: godbus.Error{Name: "org.freedesktop.DBus.Error.NoReply"}, want: contract.ErrTimeout},
		{name: "timeout", err: godbus.Error{Name: "org.freedesktop.DBus.Error.Timeout"}, want: contract.ErrTimeout},
		{name: "locked", err: godbus.Error{Name: "org.freedesktop.Secret.Error.IsLocked"}, want: contract.ErrBackendLocked},
		{name: "missing", err: godbus.Error{Name: "org.freedesktop.Secret.Error.NoSuchObject"}, want: contract.ErrNotFound},
		{name: "interaction", err: godbus.Error{Name: "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"}, want: contract.ErrInteractionRequired},
		{name: "limit", err: godbus.Error{Name: "org.freedesktop.DBus.Error.LimitsExceeded"}, want: contract.ErrValueTooLarge},
		{name: "categorized", err: errors.Join(contract.ErrPermissionDenied, errors.New("cause")), want: contract.ErrPermissionDenied},
		{name: "unknown dbus", err: godbus.Error{Name: "unknown"}, want: contract.ErrBackendFailure},
		{name: "plain", err: errors.New("plain"), want: contract.ErrBackendFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := backendError(context.Background(), "probe", test.err)
			if !errors.Is(err, test.want) {
				t.Fatalf("backendError() = %v, want %v", err, test.want)
			}
			var dbusErr godbus.Error
			if _, ok := test.err.(godbus.Error); ok && !errors.As(err, &dbusErr) {
				t.Fatalf("backendError() did not preserve %T", test.err)
			}
			if _, ok := test.err.(godbus.Error); !ok && !errors.Is(err, test.err) {
				t.Fatalf("backendError() did not preserve %v", test.err)
			}
		})
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := backendError(ctx, "probe", errors.New("ignored")); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, contract.ErrTimeout) {
		t.Fatalf("backendError() = %v", err)
	}
}
