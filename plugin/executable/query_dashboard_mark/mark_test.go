package query_dashboard_mark

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_observe"
	"github.com/miekg/dns"
)

func newTestContext() *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return query_context.NewContext(q)
}

func TestMarkerExecStoresMetadata(t *testing.T) {
	m := &Marker{args: Args{Entry: "main", Route: "direct", Upstream: "alidns"}}
	qCtx := newTestContext()
	if err := m.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	got := query_observe.Get(qCtx)
	want := query_observe.Metadata{Entry: "main", Route: "direct", Upstream: "alidns"}
	if got != want {
		t.Fatalf("metadata = %#v, want %#v", got, want)
	}
}

func TestInitBuildsMarker(t *testing.T) {
	plugin, err := Init(nil, &Args{Entry: "main", Route: "foreign", Upstream: "cf"})
	if err != nil {
		t.Fatal(err)
	}
	m := plugin.(*Marker)
	if m.args != (Args{Entry: "main", Route: "foreign", Upstream: "cf"}) {
		t.Fatalf("args = %#v", m.args)
	}
}

func TestQuickSetupParsesKeyValueTokens(t *testing.T) {
	plugin, err := quickSetup(nil, "entry=apple route=apple upstream=quad9")
	if err != nil {
		t.Fatal(err)
	}
	m := plugin.(*Marker)
	if m.args != (Args{Entry: "apple", Route: "apple", Upstream: "quad9"}) {
		t.Fatalf("args = %#v", m.args)
	}
}

func TestQuickSetupRejectsBadTokens(t *testing.T) {
	for _, input := range []string{"bad", "bad=value", "=value"} {
		if _, err := quickSetup(nil, input); err == nil {
			t.Fatalf("quickSetup(%q) succeeded, want error", input)
		}
	}
}
