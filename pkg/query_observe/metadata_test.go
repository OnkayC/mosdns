package query_observe

import (
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func newTestContext() *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return query_context.NewContext(q)
}

func TestGetEmptyMetadata(t *testing.T) {
	got := Get(newTestContext())
	if got != (Metadata{}) {
		t.Fatalf("unexpected metadata: %#v", got)
	}
	if got := Get(nil); got != (Metadata{}) {
		t.Fatalf("nil context metadata = %#v", got)
	}
}

func TestSetEachMetadataField(t *testing.T) {
	qCtx := newTestContext()
	SetEntry(qCtx, "main")
	if got := Get(qCtx).Entry; got != "main" {
		t.Fatalf("entry = %q, want main", got)
	}

	SetRoute(qCtx, "foreign")
	if got := Get(qCtx).Route; got != "foreign" {
		t.Fatalf("route = %q, want foreign", got)
	}

	SetUpstream(qCtx, "cloudflare")
	if got := Get(qCtx).Upstream; got != "cloudflare" {
		t.Fatalf("upstream = %q, want cloudflare", got)
	}

	SetCacheStatus(qCtx, "hit")
	if got := Get(qCtx).CacheStatus; got != "hit" {
		t.Fatalf("cache status = %q, want hit", got)
	}

	SetInternal(qCtx)
	if got := Get(qCtx).Internal; !got {
		t.Fatal("internal metadata = false, want true")
	}
}

func TestCumulativeMetadataAndEmptySetters(t *testing.T) {
	qCtx := newTestContext()
	SetEntry(qCtx, "apple")
	SetRoute(qCtx, "direct")
	SetUpstream(qCtx, "alidns")
	SetCacheStatus(qCtx, "miss")

	SetEntry(qCtx, "")
	SetRoute(qCtx, "")
	SetUpstream(qCtx, "")
	SetCacheStatus(qCtx, "")

	want := Metadata{
		Entry:       "apple",
		Route:       "direct",
		Upstream:    "alidns",
		CacheStatus: "miss",
	}
	if got := Get(qCtx); got != want {
		t.Fatalf("metadata = %#v, want %#v", got, want)
	}
}
