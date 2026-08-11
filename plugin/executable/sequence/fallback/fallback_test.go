package fallback

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_observe"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestFallbackPreservesWinningObservationMetadata(t *testing.T) {
	primary := sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		return errors.New("primary failed")
	})
	secondary := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		query_observe.SetRoute(qCtx, "fallback")
		query_observe.SetUpstream(qCtx, "quad9")
		r := new(dns.Msg)
		r.SetReply(qCtx.Q())
		qCtx.SetResponse(r)
		return nil
	})
	f := &fallback{
		logger:               zap.NewNop(),
		primary:              primary,
		secondary:            secondary,
		fastFallbackDuration: time.Millisecond,
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	if err := f.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	if qCtx.R() == nil {
		t.Fatal("fallback response is nil")
	}
	meta := query_observe.Get(qCtx)
	if meta.Route != "fallback" || meta.Upstream != "quad9" {
		t.Fatalf("observation metadata = %#v", meta)
	}
}
