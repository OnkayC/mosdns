package coremain

import (
	"net/http"
	"testing"
)

func TestNewAPIServerHasDefensiveTimeouts(t *testing.T) {
	server := newAPIServer("127.0.0.1:0", http.NewServeMux())
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout must be positive")
	}
	if server.ReadTimeout <= 0 {
		t.Fatal("ReadTimeout must be positive")
	}
	if server.WriteTimeout <= 0 {
		t.Fatal("WriteTimeout must be positive")
	}
	if server.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout must be positive")
	}
}
