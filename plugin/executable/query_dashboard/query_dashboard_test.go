package query_dashboard

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
	"net/netip"
)

func TestExecRecordsCompletedQuery(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10, ChannelSize: 1}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.ServerMeta.ClientAddr = netip.MustParseAddr("10.0.0.10")
	qCtx.ServerMeta.FromUDP = true

	next := sequence.NewChainWalker([]*sequence.ChainNode{{
		E: sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
			time.Sleep(time.Microsecond)
			query_observe.SetEntry(qCtx, "main")
			query_observe.SetRoute(qCtx, "direct")
			query_observe.SetCacheStatus(qCtx, "miss")
			query_observe.SetUpstream(qCtx, "alidns")
			r := new(dns.Msg)
			r.SetReply(qCtx.Q())
			r.Rcode = dns.RcodeSuccess
			qCtx.SetResponse(r)
			return nil
		}),
	}}, nil)

	if err := d.Exec(context.Background(), qCtx, next); err != nil {
		t.Fatal(err)
	}
	records := d.Recent(1, 0)
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	record := records[0]
	if record.Qname != "example.com." {
		t.Fatalf("qname = %q", record.Qname)
	}
	if record.Qtype != dns.TypeA {
		t.Fatalf("qtype = %d", record.Qtype)
	}
	if record.LatencyUs <= 0 {
		t.Fatalf("latency_us = %d, want > 0", record.LatencyUs)
	}
	if record.Transport != "udp" {
		t.Fatalf("transport = %q, want udp", record.Transport)
	}
	if record.Rcode == nil || *record.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %#v, want success", record.Rcode)
	}
	if record.Entry != "main" || record.Route != "direct" || record.CacheStatus != "miss" || record.Upstream != "alidns" {
		t.Fatalf("metadata = %#v", record)
	}
}

func TestRecordUsesConfiguredEntry(t *testing.T) {
	d, err := NewDashboard(&Args{Entry: "configured", RecentSize: 10}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	query_observe.SetEntry(qCtx, "metadata")
	record := d.Record(qCtx, time.Microsecond, nil)
	if record.Entry != "configured" {
		t.Fatalf("entry = %q, want configured", record.Entry)
	}
}

func TestRecordUsesExplicitTransport(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	query_observe.SetTransport(qCtx, "doq")
	record := d.Record(qCtx, time.Microsecond, nil)
	if record.Transport != "doq" {
		t.Fatalf("transport = %q, want doq", record.Transport)
	}
}

func TestExecSkipsInternalQuery(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	q := new(dns.Msg)
	q.SetQuestion("refresh.example.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	query_observe.SetInternal(qCtx)
	next := sequence.NewChainWalker([]*sequence.ChainNode{{
		E: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			return nil
		}),
	}}, nil)

	if err := d.Exec(context.Background(), qCtx, next); err != nil {
		t.Fatal(err)
	}
	if records := d.Recent(1, 0); len(records) != 0 {
		t.Fatalf("internal query records = %#v, want none", records)
	}
}

func TestRecordUsesClientVisibleResponseCode(t *testing.T) {
	tests := []struct {
		name    string
		setResp bool
		err     error
		want    int
	}{
		{name: "execution error overrides stale response", setResp: true, err: errors.New("upstream failed"), want: dns.RcodeServerFailure},
		{name: "missing response is refused", want: dns.RcodeRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDashboard(&Args{RecentSize: 1}, zap.NewNop(), "test")
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			qCtx := query_context.NewContext(q)
			if tt.setResp {
				r := new(dns.Msg)
				r.SetReply(q)
				qCtx.SetResponse(r)
			}
			record := d.Record(qCtx, time.Microsecond, tt.err)
			if record.Rcode == nil || *record.Rcode != tt.want {
				t.Fatalf("rcode = %#v, want %d", record.Rcode, tt.want)
			}
		})
	}
}
