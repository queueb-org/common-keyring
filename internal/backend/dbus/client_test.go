package dbus

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"common.queueb.org/keyring/internal/contract"

	godbus "github.com/godbus/dbus/v5"
)

type testBusObject struct {
	connection *testConnection
	path       godbus.ObjectPath
}

func (o *testBusObject) Call(method string, flags godbus.Flags, args ...any) *godbus.Call {
	return o.CallWithContext(context.Background(), method, flags, args...)
}

func (o *testBusObject) CallWithContext(
	ctx context.Context,
	method string,
	_ godbus.Flags,
	args ...any,
) *godbus.Call {
	return o.connection.call(ctx, o.path, method, args...)
}

func (o *testBusObject) Go(method string, flags godbus.Flags, ch chan *godbus.Call, args ...any) *godbus.Call {
	call := o.Call(method, flags, args...)
	ch <- call
	return call
}

func (o *testBusObject) GoWithContext(
	ctx context.Context,
	method string,
	flags godbus.Flags,
	ch chan *godbus.Call,
	args ...any,
) *godbus.Call {
	call := o.CallWithContext(ctx, method, flags, args...)
	ch <- call
	return call
}

func (o *testBusObject) AddMatchSignal(string, string, ...godbus.MatchOption) *godbus.Call {
	return &godbus.Call{}
}

func (o *testBusObject) RemoveMatchSignal(string, string, ...godbus.MatchOption) *godbus.Call {
	return &godbus.Call{}
}

func (*testBusObject) GetProperty(string) (godbus.Variant, error) { return godbus.Variant{}, nil }
func (*testBusObject) StoreProperty(string, any) error            { return nil }
func (*testBusObject) SetProperty(string, any) error              { return nil }
func (*testBusObject) Destination() string                        { return serviceName }
func (o *testBusObject) Path() godbus.ObjectPath                  { return o.path }

type testConnection struct {
	callOverride   func(context.Context, godbus.ObjectPath, string, ...any) *godbus.Call
	callErrors     map[string]error
	callErrorAt    map[string]int
	callCounts     map[string]int
	promptPaths    map[string]godbus.ObjectPath
	storedValue    []byte
	foundItems     []godbus.ObjectPath
	unlockedPaths  []godbus.ObjectPath
	closeErr       error
	addMatchErr    error
	removeMatchErr error
	promptSignal   *godbus.Signal
	signalChannel  chan<- *godbus.Signal
	closed         bool
	removedSignal  bool
	removedMatch   bool
	createdSecret  secretValue
	setProperties  map[string]godbus.Variant
}

func newTestConnection() *testConnection {
	return &testConnection{
		callErrors:  make(map[string]error),
		callErrorAt: make(map[string]int),
		callCounts:  make(map[string]int),
		promptPaths: map[string]godbus.ObjectPath{
			serviceInterface + ".Unlock":        "/",
			collectionInterface + ".CreateItem": "/",
			itemInterface + ".Delete":           "/",
		},
		storedValue:   []byte("secret\x00value"),
		foundItems:    []godbus.ObjectPath{"/item"},
		unlockedPaths: []godbus.ObjectPath{godbus.ObjectPath(defaultCollectionPath)},
	}
}

func (c *testConnection) Object(_ string, path godbus.ObjectPath) godbus.BusObject {
	return &testBusObject{connection: c, path: path}
}

func (c *testConnection) Close() error {
	c.closed = true
	return c.closeErr
}

func (c *testConnection) AddMatchSignalContext(context.Context, ...godbus.MatchOption) error {
	return c.addMatchErr
}

func (c *testConnection) RemoveMatchSignalContext(context.Context, ...godbus.MatchOption) error {
	c.removedMatch = true
	return c.removeMatchErr
}

func (c *testConnection) Signal(ch chan<- *godbus.Signal) { c.signalChannel = ch }

func (c *testConnection) RemoveSignal(chan<- *godbus.Signal) {
	c.removedSignal = true
	c.signalChannel = nil
}

func (c *testConnection) call(
	ctx context.Context,
	path godbus.ObjectPath,
	method string,
	args ...any,
) *godbus.Call {
	if c.callOverride != nil {
		return c.callOverride(ctx, path, method, args...)
	}
	c.callCounts[method]++
	if c.callErrorAt[method] == c.callCounts[method] {
		return &godbus.Call{Err: c.callErrors[method]}
	}
	if err := c.callErrors[method]; err != nil && c.callErrorAt[method] == 0 {
		return &godbus.Call{Err: err}
	}
	switch method {
	case serviceInterface + ".Unlock":
		return &godbus.Call{Body: []any{c.unlockedPaths, c.promptPaths[method]}}
	case collectionInterface + ".SearchItems":
		return &godbus.Call{Body: []any{c.foundItems}}
	case serviceInterface + ".OpenSession":
		return &godbus.Call{Body: []any{godbus.MakeVariant(""), godbus.ObjectPath("/session")}}
	case itemInterface + ".GetSecret":
		return &godbus.Call{Body: []any{secretValue{Value: c.storedValue}}}
	case collectionInterface + ".CreateItem":
		c.setProperties = args[0].(map[string]godbus.Variant)
		c.createdSecret = args[1].(secretValue)
		return &godbus.Call{Body: []any{godbus.ObjectPath("/item"), c.promptPaths[method]}}
	case itemInterface + ".Delete":
		return &godbus.Call{Body: []any{c.promptPaths[method]}}
	case promptInterface + ".Prompt":
		if c.promptSignal != nil {
			c.signalChannel <- c.promptSignal
		}
		return &godbus.Call{}
	case sessionInterface + ".Close":
		return &godbus.Call{}
	default:
		return &godbus.Call{Err: errors.New("unexpected method: " + method)}
	}
}

type testConnector struct {
	connection connection
	err        error
}

func (c testConnector) Connect(context.Context) (connection, error) {
	return c.connection, c.err
}

// WithConnector overrides the production connector for one test and restores
// it during cleanup. It mutates package state and must not be used by parallel
// tests.
func WithConnector(
	t *testing.T,
	factory func() connector,
) {
	t.Helper()
	original := newConnector
	newConnector = factory
	t.Cleanup(func() { newConnector = original })
}

func TestCredentialOperations(t *testing.T) {
	ctx := context.Background()
	if _, ok := newConnector().(sessionBusConnector); !ok {
		t.Fatalf("default connector = %T", newConnector())
	}
	connections := make([]*testConnection, 0, 6)
	WithConnector(t, func() connector {
		connection := newTestConnection()
		connections = append(connections, connection)
		return testConnector{connection: connection}
	})

	value := []byte("new\x00secret")
	if err := Set(ctx, "service", "key", value); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := Get(ctx, "service", "key")
	if err != nil || !bytes.Equal(got, []byte("secret\x00value")) {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	if err := Delete(ctx, "service", "key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	for index, connection := range connections {
		if !connection.closed {
			t.Fatalf("connection %d was not closed", index)
		}
	}
	setConnection := connections[0]
	if !bytes.Equal(setConnection.createdSecret.Value, value) ||
		setConnection.createdSecret.Session != "/session" ||
		setConnection.createdSecret.ContentType != "application/octet-stream" {
		t.Fatalf("CreateItem secret = %#v", setConnection.createdSecret)
	}
	attributes := setConnection.setProperties[itemInterface+".Attributes"].Value()
	wantAttributes := map[string]string{"service": "service", "username": "key"}
	if !reflect.DeepEqual(attributes, wantAttributes) {
		t.Fatalf("CreateItem attributes = %#v", attributes)
	}
}

func TestConnect(t *testing.T) {
	t.Run("context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := connect(ctx, testConnector{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("connect() error = %v", err)
		}
	})

	t.Run("connector", func(t *testing.T) {
		expected := errors.New("connect")
		_, err := connect(
			context.Background(),
			testConnector{err: expected},
		)
		if !errors.Is(err, expected) || !errors.Is(err, contract.ErrBackendFailure) {
			t.Fatalf("connect() error = %v", err)
		}
	})
}

func TestOperationFailures(t *testing.T) {
	ctx := context.Background()
	expected := errors.New("operation")

	tests := []struct {
		name   string
		method string
		call   func(connector) error
		want   error
	}{
		{
			name:   "get unlock",
			method: serviceInterface + ".Unlock",
			call: func(connector connector) error {
				_, err := get(ctx, "service", "key", connector)
				return err
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "get search",
			method: collectionInterface + ".SearchItems",
			call: func(connector connector) error {
				_, err := get(ctx, "service", "key", connector)
				return err
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "get open session",
			method: serviceInterface + ".OpenSession",
			call: func(connector connector) error {
				_, err := get(ctx, "service", "key", connector)
				return err
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "get secret",
			method: itemInterface + ".GetSecret",
			call: func(connector connector) error {
				_, err := get(ctx, "service", "key", connector)
				return err
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "set open session",
			method: serviceInterface + ".OpenSession",
			call: func(connector connector) error {
				return set(ctx, "service", "key", nil, connector)
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "set unlock",
			method: serviceInterface + ".Unlock",
			call: func(connector connector) error {
				return set(ctx, "service", "key", nil, connector)
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "set create",
			method: collectionInterface + ".CreateItem",
			call: func(connector connector) error {
				return set(ctx, "service", "key", nil, connector)
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "delete unlock",
			method: serviceInterface + ".Unlock",
			call: func(connector connector) error {
				return remove(ctx, "service", "key", connector)
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "delete search",
			method: collectionInterface + ".SearchItems",
			call: func(connector connector) error {
				return remove(ctx, "service", "key", connector)
			},
			want: contract.ErrBackendFailure,
		},
		{
			name:   "delete item",
			method: itemInterface + ".Delete",
			call: func(connector connector) error {
				return remove(ctx, "service", "key", connector)
			},
			want: contract.ErrBackendFailure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := newTestConnection()
			connection.callErrors[test.method] = expected
			err := test.call(testConnector{connection: connection})
			if !errors.Is(err, expected) || !errors.Is(err, test.want) || !connection.closed {
				t.Fatalf("operation error = %v, closed = %t", err, connection.closed)
			}
		})
	}

	t.Run("connect", func(t *testing.T) {
		err := set(ctx, "service", "key", nil, testConnector{err: expected})
		if !errors.Is(err, expected) {
			t.Fatalf("set() error = %v", err)
		}
		if _, err := get(ctx, "service", "key", testConnector{err: expected}); !errors.Is(err, expected) {
			t.Fatalf("get() error = %v", err)
		}
		if err := remove(ctx, "service", "key", testConnector{err: expected}); !errors.Is(err, expected) {
			t.Fatalf("remove() error = %v", err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		connection := newTestConnection()
		connection.foundItems = nil
		_, err := get(ctx, "service", "key", testConnector{connection: connection})
		if !errors.Is(err, contract.ErrNotFound) {
			t.Fatalf("get() error = %v", err)
		}
	})

	for _, test := range []struct {
		name string
		call func(connector) error
	}{
		{
			name: "get item unlock",
			call: func(connector connector) error {
				_, err := get(ctx, "service", "key", connector)
				return err
			},
		},
		{
			name: "delete item unlock",
			call: func(connector connector) error {
				return remove(ctx, "service", "key", connector)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := newTestConnection()
			method := serviceInterface + ".Unlock"
			connection.callErrors[method] = expected
			connection.callErrorAt[method] = 2
			err := test.call(testConnector{connection: connection})
			if !errors.Is(err, expected) {
				t.Fatalf("operation error = %v", err)
			}
		})
	}

	t.Run("locked", func(t *testing.T) {
		connection := newTestConnection()
		connection.callErrors[itemInterface+".Delete"] = godbus.Error{
			Name: "org.freedesktop.Secret.Error.IsLocked",
		}
		err := remove(ctx, "service", "key", testConnector{connection: connection})
		if !errors.Is(err, contract.ErrBackendLocked) {
			t.Fatalf("remove() error = %v", err)
		}
	})

	t.Run("session cleanup", func(t *testing.T) {
		connection := newTestConnection()
		connection.callErrors[sessionInterface+".Close"] = expected
		err := set(ctx, "service", "key", nil, testConnector{connection: connection})
		if !errors.Is(err, expected) || !errors.Is(err, contract.ErrBackendFailure) {
			t.Fatalf("set() error = %v", err)
		}
	})

	t.Run("canceled session cleanup", func(t *testing.T) {
		connection := newTestConnection()
		client := &client{connection: connection}
		resultErr := error(context.Canceled)
		client.closeSession("/session", &resultErr)
		if connection.callCounts[sessionInterface+".Close"] != 0 || !errors.Is(resultErr, context.Canceled) {
			t.Fatalf("closeSession() calls = %d, error = %v",
				connection.callCounts[sessionInterface+".Close"], resultErr)
		}
	})

	t.Run("connection cleanup", func(t *testing.T) {
		connection := newTestConnection()
		connection.closeErr = expected
		err := remove(ctx, "service", "key", testConnector{connection: connection})
		if !errors.Is(err, expected) || !errors.Is(err, contract.ErrBackendFailure) {
			t.Fatalf("remove() error = %v", err)
		}
	})
}

func TestPrompt(t *testing.T) {
	ctx := context.Background()
	prompt := godbus.ObjectPath("/prompt")

	t.Run("none", func(t *testing.T) {
		client := &client{connection: newTestConnection()}
		if err := client.handlePrompt(ctx, "/"); err != nil {
			t.Fatalf("handlePrompt() error = %v", err)
		}
	})

	t.Run("completed", func(t *testing.T) {
		connection := newTestConnection()
		connection.promptSignal = &godbus.Signal{
			Name: promptInterface + ".Completed",
			Body: []any{false, godbus.MakeVariant("")},
		}
		client := &client{connection: connection}
		if err := client.handlePrompt(ctx, prompt); err != nil {
			t.Fatalf("handlePrompt() error = %v", err)
		}
		if !connection.removedSignal || !connection.removedMatch {
			t.Fatalf("prompt cleanup = signal:%t match:%t", connection.removedSignal, connection.removedMatch)
		}
	})

	for _, test := range []struct {
		name      string
		configure func(*testConnection) context.Context
		want      error
	}{
		{
			name: "subscribe",
			configure: func(connection *testConnection) context.Context {
				connection.addMatchErr = errors.New("subscribe")
				return ctx
			},
			want: contract.ErrBackendFailure,
		},
		{
			name: "show",
			configure: func(connection *testConnection) context.Context {
				connection.callErrors[promptInterface+".Prompt"] = errors.New("show")
				return ctx
			},
			want: contract.ErrBackendFailure,
		},
		{
			name: "canceled",
			configure: func(*testConnection) context.Context {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				return canceled
			},
			want: context.Canceled,
		},
		{
			name: "invalid signal",
			configure: func(connection *testConnection) context.Context {
				connection.promptSignal = &godbus.Signal{Name: "invalid"}
				return ctx
			},
			want: contract.ErrBackendFailure,
		},
		{
			name: "closed signal channel",
			configure: func(connection *testConnection) context.Context {
				connection.callOverride = func(
					_ context.Context,
					_ godbus.ObjectPath,
					_ string,
					_ ...any,
				) *godbus.Call {
					close(connection.signalChannel)
					return &godbus.Call{}
				}
				return ctx
			},
			want: contract.ErrBackendFailure,
		},
		{
			name: "invalid dismissed",
			configure: func(connection *testConnection) context.Context {
				connection.promptSignal = &godbus.Signal{
					Name: promptInterface + ".Completed",
					Body: []any{string("false"), godbus.MakeVariant("")},
				}
				return ctx
			},
			want: contract.ErrBackendFailure,
		},
		{
			name: "dismissed",
			configure: func(connection *testConnection) context.Context {
				connection.promptSignal = &godbus.Signal{
					Name: promptInterface + ".Completed",
					Body: []any{true, godbus.MakeVariant("")},
				}
				return ctx
			},
			want: contract.ErrInteractionRequired,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := newTestConnection()
			operationCtx := test.configure(connection)
			client := &client{connection: connection}
			err := client.handlePrompt(operationCtx, prompt)
			if !errors.Is(err, test.want) {
				t.Fatalf("handlePrompt() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOperationPromptPaths(t *testing.T) {
	ctx := context.Background()
	methods := []struct {
		name   string
		method string
		call   func(connector) error
	}{
		{
			name:   "unlock",
			method: serviceInterface + ".Unlock",
			call: func(connector connector) error {
				return remove(ctx, "service", "key", connector)
			},
		},
		{
			name:   "create",
			method: collectionInterface + ".CreateItem",
			call: func(connector connector) error {
				return set(ctx, "service", "key", nil, connector)
			},
		},
		{
			name:   "delete",
			method: itemInterface + ".Delete",
			call: func(connector connector) error {
				return remove(ctx, "service", "key", connector)
			},
		},
	}
	for _, test := range methods {
		t.Run(test.name, func(t *testing.T) {
			connection := newTestConnection()
			connection.promptPaths[test.method] = "/prompt"
			connection.promptSignal = &godbus.Signal{
				Name: promptInterface + ".Completed",
				Body: []any{false, godbus.MakeVariant("")},
			}
			if err := test.call(testConnector{connection: connection}); err != nil {
				t.Fatalf("operation error = %v", err)
			}
		})
	}
}

func TestPromptChannelError(t *testing.T) {
	if err := promptChannelError(context.Background()); !errors.Is(err, contract.ErrBackendFailure) {
		t.Fatalf("promptChannelError() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := promptChannelError(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("promptChannelError() error = %v", err)
	}
}
