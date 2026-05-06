package smb

import (
	"errors"
	"net"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestIsIgnorableCloseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "net err closed", err: net.ErrClosed, want: true},
		{name: "closed network connection", err: errors.New("write tcp 127.0.0.1:445->127.0.0.1:40000: use of closed network connection"), want: true},
		{name: "already closed", err: errors.New("connection already closed"), want: true},
		{name: "real error", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isIgnorableCloseError(tt.err); got != tt.want {
				t.Fatalf("isIgnorableCloseError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsTimeoutError(t *testing.T) {
	t.Parallel()

	if !IsTimeoutError(timeoutErr{}) {
		t.Fatal("expected net timeout error to be detected")
	}
	if !IsTimeoutError(errors.New("read tcp 10.0.0.5:445: i/o timeout")) {
		t.Fatal("expected i/o timeout string to be detected")
	}
	if IsTimeoutError(contextDeadlineErr{}) {
		t.Fatal("did not expect non-network deadline wording to be treated as an SMB timeout")
	}
	if IsTimeoutError(errors.New("permission denied")) {
		t.Fatal("did not expect ordinary errors to be treated as timeouts")
	}
}

type contextDeadlineErr struct{}

func (contextDeadlineErr) Error() string { return "context deadline exceeded" }
