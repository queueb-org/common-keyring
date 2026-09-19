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
	defaultCollectionPath = "/org/freedesktop/secrets/aliases/default"
	collectionInterface   = "org.freedesktop.Secret.Collection"
	itemInterface         = "org.freedesktop.Secret.Item"
	promptInterface       = "org.freedesktop.Secret.Prompt"
	cleanupTimeout        = time.Second
	itemLabelPrefix       = "common.queueb.org/keyring"
	keyAttribute          = "username"
	serviceAttribute      = "service"
)

type secretValue struct {
	Session     godbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string `dbus:"content_type"`
}

type client struct {
	connection connection
	service    godbus.BusObject
	collection godbus.BusObject
}

var newConnector = func() connector {
	return sessionBusConnector{connect: connectSessionBus}
}

// Get returns a value from the default Secret Service collection.
func Get(ctx context.Context, service, key string) ([]byte, error) {
	return get(
		ctx,
		service,
		key,
		newConnector(),
	)
}

// Set stores a value in the default Secret Service collection.
func Set(ctx context.Context, service, key string, value []byte) error {
	return set(
		ctx,
		service,
		key,
		value,
		newConnector(),
	)
}

// Delete deletes a value from the default Secret Service collection.
func Delete(ctx context.Context, service, key string) error {
	return remove(
		ctx,
		service,
		key,
		newConnector(),
	)
}

func connect(
	ctx context.Context,
	bus connector,
) (*client, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	connection, err := bus.Connect(ctx)
	if err != nil {
		return nil, backendError(ctx, "connect to session bus", err)
	}
	return &client{
		connection: connection,
		service: connection.Object(
			serviceName,
			godbus.ObjectPath(servicePath),
		),
		collection: connection.Object(
			serviceName,
			godbus.ObjectPath(defaultCollectionPath),
		),
	}, nil
}

func get(
	ctx context.Context,
	service string,
	key string,
	bus connector,
) (value []byte, resultErr error) {
	client, err := connect(ctx, bus)
	if err != nil {
		return nil, err
	}
	defer client.close(&resultErr)

	if err := client.unlock(ctx, godbus.ObjectPath(defaultCollectionPath)); err != nil {
		return nil, err
	}
	item, err := client.find(ctx, service, key)
	if err != nil {
		return nil, err
	}
	if err := client.unlock(ctx, item); err != nil {
		return nil, err
	}
	session, err := client.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer client.closeSession(session, &resultErr)

	var valueSecret secretValue
	err = client.connection.Object(serviceName, item).CallWithContext(
		ctx,
		itemInterface+".GetSecret",
		0,
		session,
	).Store(&valueSecret)
	if err != nil {
		return nil, backendError(ctx, "get credential", err)
	}
	return append([]byte(nil), valueSecret.Value...), nil
}

func set(
	ctx context.Context,
	service string,
	key string,
	value []byte,
	bus connector,
) (resultErr error) {
	client, err := connect(ctx, bus)
	if err != nil {
		return err
	}
	defer client.close(&resultErr)

	session, err := client.openSession(ctx)
	if err != nil {
		return err
	}
	defer client.closeSession(session, &resultErr)
	if err := client.unlock(ctx, godbus.ObjectPath(defaultCollectionPath)); err != nil {
		return err
	}

	attributes := map[string]string{
		keyAttribute:     key,
		serviceAttribute: service,
	}
	valueSecret := secretValue{
		Session:     session,
		Parameters:  []byte{},
		Value:       append([]byte(nil), value...),
		ContentType: "application/octet-stream",
	}
	var item godbus.ObjectPath
	var prompt godbus.ObjectPath
	err = client.collection.CallWithContext(
		ctx,
		collectionInterface+".CreateItem",
		0,
		map[string]godbus.Variant{
			itemInterface + ".Label":      godbus.MakeVariant(fmt.Sprintf("%s: %s", itemLabelPrefix, key)),
			itemInterface + ".Attributes": godbus.MakeVariant(attributes),
		},
		valueSecret,
		true,
	).Store(&item, &prompt)
	if err != nil {
		return backendError(ctx, "set credential", err)
	}
	return client.handlePrompt(ctx, prompt)
}

func remove(
	ctx context.Context,
	service string,
	key string,
	bus connector,
) (resultErr error) {
	client, err := connect(ctx, bus)
	if err != nil {
		return err
	}
	defer client.close(&resultErr)

	if err := client.unlock(ctx, godbus.ObjectPath(defaultCollectionPath)); err != nil {
		return err
	}
	item, err := client.find(ctx, service, key)
	if err != nil {
		return err
	}
	if err := client.unlock(ctx, item); err != nil {
		return err
	}
	var prompt godbus.ObjectPath
	err = client.connection.Object(serviceName, item).CallWithContext(
		ctx,
		itemInterface+".Delete",
		0,
	).Store(&prompt)
	if err != nil {
		return backendError(ctx, "delete credential", err)
	}
	return client.handlePrompt(ctx, prompt)
}

func (c *client) unlock(ctx context.Context, object godbus.ObjectPath) error {
	var unlocked []godbus.ObjectPath
	var prompt godbus.ObjectPath
	err := c.service.CallWithContext(
		ctx,
		serviceInterface+".Unlock",
		0,
		[]godbus.ObjectPath{object},
	).Store(&unlocked, &prompt)
	if err != nil {
		return backendError(ctx, "unlock credential store object", err)
	}
	return c.handlePrompt(ctx, prompt)
}

func (c *client) find(
	ctx context.Context,
	service string,
	key string,
) (godbus.ObjectPath, error) {
	var items []godbus.ObjectPath
	err := c.collection.CallWithContext(
		ctx,
		collectionInterface+".SearchItems",
		0,
		map[string]string{
			keyAttribute:     key,
			serviceAttribute: service,
		},
	).Store(&items)
	if err != nil {
		return "", backendError(ctx, "find credential", err)
	}
	if len(items) == 0 {
		return "", fmt.Errorf("%w: find credential", contract.ErrNotFound)
	}
	return items[0], nil
}

func (c *client) openSession(ctx context.Context) (godbus.ObjectPath, error) {
	var ignored godbus.Variant
	var session godbus.ObjectPath
	err := c.service.CallWithContext(
		ctx,
		serviceInterface+".OpenSession",
		0,
		"plain",
		godbus.MakeVariant(""),
	).Store(&ignored, &session)
	if err != nil {
		return "", backendError(ctx, "open operation session", err)
	}
	return session, nil
}

func (c *client) handlePrompt(ctx context.Context, prompt godbus.ObjectPath) error {
	if prompt == godbus.ObjectPath("/") {
		return nil
	}

	signals := make(chan *godbus.Signal, 1)
	c.connection.Signal(signals)
	defer c.connection.RemoveSignal(signals)
	match := []godbus.MatchOption{
		godbus.WithMatchObjectPath(prompt),
		godbus.WithMatchInterface(promptInterface),
		godbus.WithMatchMember("Completed"),
	}
	if err := c.connection.AddMatchSignalContext(ctx, match...); err != nil {
		return backendError(ctx, "subscribe to prompt", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		_ = c.connection.RemoveMatchSignalContext(cleanupCtx, match...)
	}()

	err := c.connection.Object(serviceName, prompt).CallWithContext(
		ctx,
		promptInterface+".Prompt",
		0,
		"",
	).Err
	if err != nil {
		return backendError(ctx, "show prompt", err)
	}

	for {
		select {
		case <-ctx.Done():
			return contextError(ctx)
		case signal, ok := <-signals:
			if !ok || signal == nil {
				return promptChannelError(ctx)
			}
			if signal.Name != promptInterface+".Completed" || len(signal.Body) < 2 {
				return fmt.Errorf("%w: invalid prompt completion", contract.ErrBackendFailure)
			}
			dismissed, ok := signal.Body[0].(bool)
			if !ok {
				return fmt.Errorf("%w: invalid prompt completion", contract.ErrBackendFailure)
			}
			if dismissed {
				return fmt.Errorf("%w: Secret Service prompt was dismissed", contract.ErrInteractionRequired)
			}
			return nil
		}
	}
}

func promptChannelError(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return fmt.Errorf("%w: prompt signal channel closed", contract.ErrBackendFailure)
}

func (c *client) closeSession(
	session godbus.ObjectPath,
	resultErr *error,
) {
	if errors.Is(*resultErr, context.Canceled) || errors.Is(*resultErr, context.DeadlineExceeded) {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	err := c.connection.Object(serviceName, session).CallWithContext(
		cleanupCtx,
		sessionInterface+".Close",
		0,
	).Err
	if err != nil {
		*resultErr = errors.Join(*resultErr, backendError(cleanupCtx, "close operation session", err))
	}
}

func (c *client) close(resultErr *error) {
	if err := c.connection.Close(); err != nil {
		*resultErr = errors.Join(
			*resultErr,
			fmt.Errorf("%w: close session bus: %w", contract.ErrBackendFailure, err),
		)
	}
}
