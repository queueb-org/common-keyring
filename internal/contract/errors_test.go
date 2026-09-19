package contract

import "testing"

func TestError(t *testing.T) {
	if got := ErrNotFound.Error(); got != "credential not found" {
		t.Fatalf("ErrNotFound.Error() = %q", got)
	}
}
