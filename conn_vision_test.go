package tls

import (
	"bytes"
	"net"
	"testing"
)

func TestDetachVisionReadPreservesBufferedByteOrder(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	c := &Conn{conn: left}
	c.isHandshakeComplete.Store(true)
	c.input.Reset([]byte("plaintext"))
	_, _ = c.rawInput.Write([]byte("raw-read-ahead"))

	raw, buffered, err := c.DetachVisionRead()
	if err != nil {
		t.Fatalf("detach: %v", err)
	}
	if raw != left {
		t.Fatal("detach returned a different raw connection")
	}
	if want := []byte("plaintextraw-read-ahead"); !bytes.Equal(buffered, want) {
		t.Fatalf("buffered = %q, want %q", buffered, want)
	}
	if c.input.Len() != 0 || c.rawInput.Len() != 0 {
		t.Fatal("detach retained internal buffered bytes")
	}
	if _, _, err := c.DetachVisionRead(); err == nil {
		t.Fatal("second read detach succeeded")
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("TLS Read succeeded after Vision detach")
	}
}

func TestDetachVisionWriteIsIrreversible(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	c := &Conn{conn: left}
	c.isHandshakeComplete.Store(true)
	raw, err := c.DetachVisionWrite()
	if err != nil {
		t.Fatalf("detach: %v", err)
	}
	if raw != left {
		t.Fatal("detach returned a different raw connection")
	}
	if _, err := c.DetachVisionWrite(); err == nil {
		t.Fatal("second write detach succeeded")
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("TLS Write succeeded after Vision detach")
	}
}
