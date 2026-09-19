package keyring_test

import (
	"context"
	"errors"
	"fmt"

	"common.queueb.org/keyring"
	"common.queueb.org/keyring/secure/fake"
)

func ExampleOpen() {
	ctx := context.Background()
	storage, info, err := keyring.Open(ctx, &keyring.Option{
		Keyringer: &fake.Keyring{Service: "example.application"},
	})
	if err != nil {
		panic(err)
	}

	if err := storage.Set(ctx, "api-token", []byte("secret")); err != nil {
		panic(err)
	}
	value, err := storage.Get(ctx, "api-token")
	if err != nil {
		panic(err)
	}
	fmt.Println(info.Backend, string(value))

	if err := storage.Delete(ctx, "api-token"); err != nil {
		panic(err)
	}
	_, err = storage.Get(ctx, "api-token")
	fmt.Println(errors.Is(err, keyring.ErrNotFound))

	// Output:
	// custom secret
	// true
}
