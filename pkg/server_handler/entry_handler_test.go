package server_handler

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_observe"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestEntryHandlerTransfersQueryTransport(t *testing.T) {
	var transport string
	h := NewEntryHandler(EntryHandlerOpts{
		Entry: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			transport = query_observe.Get(qCtx).Transport
			response := new(dns.Msg)
			response.SetReply(qCtx.Q())
			qCtx.SetResponse(response)
			return nil
		}),
	})

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	payload := h.Handle(server.WithQueryTransport(context.Background(), "doq"), query, server.QueryMeta{}, func(response *dns.Msg) (*[]byte, error) {
		packed, err := response.Pack()
		return &packed, err
	})
	if payload == nil {
		t.Fatal("handler returned nil payload")
	}
	if transport != "doq" {
		t.Fatalf("transport = %q, want doq", transport)
	}
}
