package fastforward

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_observe"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type testErr string

func (e testErr) Error() string { return string(e) }

type fakeUpstream struct {
	response *dns.Msg
	err      error
	closed   bool
}

func (u *fakeUpstream) ExchangeContext(_ context.Context, _ []byte) (*[]byte, error) {
	if u.err != nil {
		return nil, u.err
	}
	payload, err := u.response.Pack()
	if err != nil {
		return nil, err
	}
	buf := pool.GetBuf(len(payload))
	copy(*buf, payload)
	return buf, nil
}

func (u *fakeUpstream) Close() error {
	u.closed = true
	return nil
}

func TestExchangeSetsWinningUpstreamMetadata(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(query)

	response := new(dns.Msg)
	response.SetReply(query)
	response.Rcode = dns.RcodeSuccess

	uw := newWrapper(0, UpstreamConfig{Tag: "test_upstream", Addr: "udp://192.0.2.53"}, "test_forward")
	uw.u = &fakeUpstream{response: response}
	f := &Forward{args: &Args{Concurrent: 1}, logger: zap.NewNop()}

	got, err := f.exchange(context.Background(), qCtx, []*upstreamWrapper{uw})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Rcode != dns.RcodeSuccess {
		t.Fatalf("response = %#v", got)
	}
	if upstream := query_observe.Get(qCtx).Upstream; upstream != "test_upstream" {
		t.Fatalf("upstream metadata = %q, want test_upstream", upstream)
	}
}

func TestExchangeLeavesUpstreamEmptyWhenAllFail(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(query)

	uw := newWrapper(0, UpstreamConfig{Tag: "bad_upstream", Addr: "udp://192.0.2.53"}, "test_forward")
	uw.u = &fakeUpstream{err: testErr("upstream failed")}
	f := &Forward{args: &Args{Concurrent: 1}, logger: zap.NewNop()}

	if _, err := f.exchange(context.Background(), qCtx, []*upstreamWrapper{uw}); err == nil {
		t.Fatal("exchange succeeded, want error")
	}
	if upstream := query_observe.Get(qCtx).Upstream; upstream != "" {
		t.Fatalf("upstream metadata = %q, want empty", upstream)
	}
}
