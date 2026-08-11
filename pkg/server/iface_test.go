package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
)

func TestQueryMetaFieldLayoutCompatibility(t *testing.T) {
	meta := QueryMeta{false, netip.Addr{}, "", ""}
	if meta.FromUDP || meta.ClientAddr.IsValid() || meta.ServerName != "" || meta.UrlPath != "" {
		t.Fatalf("unexpected query metadata: %#v", meta)
	}
}

func TestQueryTransportContext(t *testing.T) {
	if got := QueryTransportFromContext(nil); got != "" {
		t.Fatalf("nil context transport = %q, want empty", got)
	}
	ctx := WithQueryTransport(context.Background(), "doh")
	if got := QueryTransportFromContext(ctx); got != "doh" {
		t.Fatalf("transport = %q, want doh", got)
	}
}

func TestTCPTransportLabelsTLSAsDoT(t *testing.T) {
	plainClient, plainServer := net.Pipe()
	defer plainClient.Close()
	defer plainServer.Close()
	if got := tcpTransport(plainServer); got != "tcp" {
		t.Fatalf("plain transport = %q, want tcp", got)
	}

	tlsClient, tlsServer := net.Pipe()
	defer tlsClient.Close()
	defer tlsServer.Close()
	if got := tcpTransport(tls.Server(tlsServer, &tls.Config{})); got != "dot" {
		t.Fatalf("TLS transport = %q, want dot", got)
	}
}
