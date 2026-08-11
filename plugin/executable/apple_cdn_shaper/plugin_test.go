package apple_cdn_shaper

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestNewLoadsOnlyValidGeneratedPrefixPolicy(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.txt")
	if err := os.WriteFile(valid, []byte(APPLE_ASN_IPV6_CIDR+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin, err := New(&Args{PrefixFile: valid})
	if err != nil {
		t.Fatalf("New(valid): %v", err)
	}
	if got := plugin.prefix.String(); got != APPLE_ASN_IPV6_CIDR {
		t.Fatalf("prefix = %s", got)
	}

	invalid := filepath.Join(dir, "invalid.txt")
	if err := os.WriteFile(invalid, []byte("2403:300::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(&Args{PrefixFile: invalid}); err == nil {
		t.Fatal("New(invalid) succeeded")
	}
	if _, err := New(&Args{}); err == nil {
		t.Fatal("New(empty path) succeeded")
	}
}

func TestPluginShapesResolverAndCachedResponses(t *testing.T) {
	plugin := &Plugin{prefix: requiredPrefix}
	query := new(dns.Msg)
	query.SetQuestion("cdn.example.", dns.TypeAAAA)
	response := func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetReply(query)
		msg.Answer = []dns.RR{
			mustRR(t, "cdn.example. 60 IN AAAA 2403:300:a04::10"),
			mustRR(t, "cdn.example. 60 IN AAAA 2001:db8::10"),
		}
		return msg
	}

	resolved := query_context.NewContext(query.Copy())
	resolverCalled := false
	next := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		resolverCalled = true
		qCtx.SetResponse(response())
		return nil
	})}}, nil)
	if err := plugin.Exec(context.Background(), resolved, next); err != nil {
		t.Fatal(err)
	}
	if !resolverCalled || len(resolved.R().Answer) != 1 {
		t.Fatalf("resolver path called=%v answers=%d", resolverCalled, len(resolved.R().Answer))
	}

	cached := query_context.NewContext(query.Copy())
	cached.SetResponse(response())
	next = sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, _ *query_context.Context) error {
		t.Fatal("cached response continued to resolver")
		return nil
	})}}, nil)
	if err := plugin.Exec(context.Background(), cached, next); err != nil {
		t.Fatal(err)
	}
	if len(cached.R().Answer) != 1 {
		t.Fatalf("cached answers=%d, want 1", len(cached.R().Answer))
	}
}
