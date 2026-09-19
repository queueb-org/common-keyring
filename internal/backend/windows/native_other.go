//go:build !windows

package windows

import "common.queueb.org/keyring/internal/contract"

func nativeReadCredential(string) ([]byte, error) {
	return nil, contract.ErrUnsupported
}

func nativeWriteCredential(string, string, []byte) error {
	return contract.ErrUnsupported
}

func nativeDeleteCredential(string) error {
	return contract.ErrUnsupported
}
