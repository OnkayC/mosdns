package server

import (
	"context"
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
