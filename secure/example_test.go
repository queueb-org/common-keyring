package keyring_test

import (
	"context"
	"fmt"

	api "common.queueb.org/keyring"
	securekeyring "common.queueb.org/keyring/secure"
	"common.queueb.org/keyring/secure/fake"
)

func ExampleOpen() {
	storage, info, err := securekeyring.Open(
		context.Background(),
		&securekeyring.Option{Keyringer: &fake.Keyring{}},
	)
	if err != nil {
		panic(err)
	}
	if info.Backend != api.BackendCustom {
		panic("unexpected backend")
	}
	fmt.Println(info.Backend, storage != nil)

	// Output:
	// custom true
}
