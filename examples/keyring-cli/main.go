package main

import (
	"context"
	"fmt"
	"io"
	"os"

	api "common.queueb.org/keyring"
	keyring "common.queueb.org/keyring/secure"

	"github.com/spf13/cobra"
)

type initializer func(
	context.Context,
	...*keyring.Option,
) (api.Keyringer, api.Info, error)

var exitProcess = os.Exit

type application struct {
	initialize initializer
	service    string
	keyring    api.Keyringer
}

func main() {
	command := newRootCommand(keyring.Open)
	if err := command.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		exitProcess(1)
	}
}

func newRootCommand(initialize initializer) *cobra.Command {
	app := &application{initialize: initialize}
	command := &cobra.Command{
		Use:           "keyring-example",
		Short:         "Store secrets using common.queueb.org/keyring",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(command *cobra.Command, _ []string) error {
			storage, _, err := app.initialize(
				command.Context(),
				&keyring.Option{Service: app.service},
			)
			if err != nil {
				return fmt.Errorf("initialize keyring: %w", err)
			}
			app.keyring = storage
			return nil
		},
	}
	command.PersistentFlags().StringVar(
		&app.service,
		"service",
		"keyring-example",
		"service name used to namespace secrets",
	)
	command.AddCommand(
		app.newCreateCommand(),
		app.newGetCommand(),
		app.newDeleteCommand(),
	)
	return command
}

func (a *application) newCreateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "create <key>",
		Short: "Read a secret from stdin and store it",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			secret, err := io.ReadAll(command.InOrStdin())
			if err != nil {
				return fmt.Errorf("read secret: %w", err)
			}
			if err := a.keyring.Set(command.Context(), args[0], secret); err != nil {
				return fmt.Errorf("create secret: %w", err)
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), "secret created")
			return err
		},
	}
}

func (a *application) newGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Write a secret to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			secret, err := a.keyring.Get(command.Context(), args[0])
			if err != nil {
				return fmt.Errorf("get secret: %w", err)
			}
			_, err = command.OutOrStdout().Write(secret)
			return err
		},
	}
}

func (a *application) newDeleteCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <key>",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if err := a.keyring.Delete(command.Context(), args[0]); err != nil {
				return fmt.Errorf("delete secret: %w", err)
			}
			_, err := fmt.Fprintln(command.OutOrStdout(), "secret deleted")
			return err
		},
	}
}
