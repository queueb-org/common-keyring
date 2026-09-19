package dbus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"common.queueb.org/keyring/internal/contract"

	godbus "github.com/godbus/dbus/v5"
)

const (
	probeTimeout     = 5 * time.Second
	serviceName      = "org.freedesktop.secrets"
	servicePath      = "/org/freedesktop/secrets"
	serviceInterface = "org.freedesktop.Secret.Service"
	sessionInterface = "org.freedesktop.Secret.Session"
)

type connection interface {
	Object(string, godbus.ObjectPath) godbus.BusObject
	Close() error
	AddMatchSignalContext(context.Context, ...godbus.MatchOption) error
	RemoveMatchSignalContext(context.Context, ...godbus.MatchOption) error
	Signal(chan<- *godbus.Signal)
	RemoveSignal(chan<- *godbus.Signal)
}
type connector interface {
	Connect(context.Context) (connection, error)
}
type sessionBusConnector struct {
	connect func(...godbus.ConnOption) (*godbus.Conn, error)
}
type sessionOpener func(context.Context, connection) (godbus.BusObject, error)
type sessionCloser func(context.Context, godbus.BusObject) error
type connectionCloser func(connection) error

// Probe performs a bounded, side-effect-free Secret Service availability
// check and closes both its temporary session and D-Bus connection.
func Probe(ctx context.Context) error {
	return probe(
		ctx,
		sessionBusConnector{connect: connectSessionBus},
		openProbeSession,
		closeProbeSession,
		closeConnection,
	)
}

func probe(
	ctx context.Context,
	bus connector,
	opener sessionOpener,
	closeSession sessionCloser,
	closeConnection connectionCloser,
) (resultErr error) {
	if err := contextError(ctx); err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	service, err := bus.Connect(probeCtx)
	if err != nil {
		return backendError(probeCtx, "connect to session bus", err)
	}
	defer func() {
		if err := closeConnection(service); err != nil && resultErr == nil {
			resultErr = fmt.Errorf("%w: close session bus: %w", contract.ErrBackendFailure, err)
		}
	}()

	session, err := opener(probeCtx, service)
	if err != nil {
		return backendError(probeCtx, "open probe session", err)
	}
	if err := closeSession(probeCtx, session); err != nil {
		return backendError(probeCtx, "close probe session", err)
	}
	return nil
}

func (c sessionBusConnector) Connect(ctx context.Context) (connection, error) {
	return c.connect(godbus.WithContext(ctx))
}

// Keep the private session-bus stages behind variables intentionally so unit
// tests can exercise authentication and cleanup without a live D-Bus daemon.
var (
	dialSessionBus  = godbus.SessionBusPrivateNoAutoStartup
	authSessionBus  = (*godbus.Conn).Auth
	helloSessionBus = (*godbus.Conn).Hello
	closeSessionBus = (*godbus.Conn).Close
)

func connectSessionBus(options ...godbus.ConnOption) (*godbus.Conn, error) {
	connection, err := dialSessionBus(options...)
	if err != nil {
		return nil, fmt.Errorf("%w: dial session bus: %w", contract.ErrBackendUnavailable, err)
	}
	if err := authSessionBus(connection, nil); err != nil {
		return nil, closeFailedSessionBus(connection, fmt.Errorf(
			"%w: authenticate session bus: %w",
			contract.ErrPermissionDenied,
			err,
		))
	}
	if err := helloSessionBus(connection); err != nil {
		return nil, closeFailedSessionBus(connection, fmt.Errorf(
			"%w: initialize session bus: %w",
			contract.ErrBackendFailure,
			err,
		))
	}
	return connection, nil
}

func closeFailedSessionBus(connection *godbus.Conn, operationErr error) error {
	if err := closeSessionBus(connection); err != nil {
		return errors.Join(
			operationErr,
			fmt.Errorf("%w: close session bus: %w", contract.ErrBackendFailure, err),
		)
	}
	return operationErr
}

func openProbeSession(
	ctx context.Context,
	service connection,
) (godbus.BusObject, error) {
	var ignored godbus.Variant
	var sessionPath godbus.ObjectPath
	object := service.Object(serviceName, godbus.ObjectPath(servicePath))
	err := object.CallWithContext(
		ctx,
		serviceInterface+".OpenSession",
		0,
		"plain",
		godbus.MakeVariant(""),
	).Store(&ignored, &sessionPath)
	if err != nil {
		return nil, err
	}
	return service.Object(serviceName, sessionPath), nil
}

func closeProbeSession(ctx context.Context, session godbus.BusObject) error {
	return session.CallWithContext(ctx, sessionInterface+".Close", 0).Err
}

func closeConnection(connection connection) error {
	return connection.Close()
}
