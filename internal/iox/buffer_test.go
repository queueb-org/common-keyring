package iox

import "testing"

func TestLimitedBuffer(t *testing.T) {
	t.Run("negative limit", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("NewLimitedBuffer() did not panic")
			}
		}()
		NewLimitedBuffer(-1)
	})

	t.Run("within limit", func(t *testing.T) {
		buffer := NewLimitedBuffer(8)
		if _, err := buffer.Write([]byte("response")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if got := string(buffer.Bytes()); got != "response" {
			t.Fatalf("Bytes() = %q, want response", got)
		}
		if buffer.Overflow() {
			t.Fatal("Overflow() = true")
		}
	})

	t.Run("overflow", func(t *testing.T) {
		buffer := NewLimitedBuffer(4)
		contents := []byte("response")
		written, err := buffer.Write(contents)
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if written != len(contents) {
			t.Fatalf("Write() = %d, want %d", written, len(contents))
		}
		if !buffer.Overflow() {
			t.Fatal("Overflow() = false")
		}
		if got := string(buffer.Bytes()); got != "resp" {
			t.Fatalf("Bytes() = %q, want resp", got)
		}

		written, err = buffer.Write([]byte("discarded"))
		if err != nil || written != len("discarded") {
			t.Fatalf("Write() = %d, %v", written, err)
		}
		if got := string(buffer.Bytes()); got != "resp" {
			t.Fatalf("Bytes() after overflow = %q, want resp", got)
		}
	})
}
