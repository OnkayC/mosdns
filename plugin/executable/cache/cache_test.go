/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_observe"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func Test_cachePlugin_Dump(t *testing.T) {
	c := NewCache(&Args{Size: 16 * dumpBlockSize}, Opts{}) // Big enough to create dump fragments.

	resp := new(dns.Msg)
	resp.SetQuestion("test.", dns.TypeA)

	now := time.Now()
	hourLater := now.Add(time.Hour)
	v := &item{
		resp:           resp,
		storedTime:     now,
		expirationTime: hourLater,
	}

	// Fill the cache
	for i := 0; i < 32*dumpBlockSize; i++ {
		c.backend.Store(key(strconv.Itoa(i)), v, hourLater)
	}

	buf := new(bytes.Buffer)
	enw, err := c.writeDump(buf)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := c.readDump(buf)
	if err != nil {
		t.Fatal(err)
	}

	if enw != enr {
		t.Fatalf("read err, wrote %d entries, read %d", enw, enr)
	}
}

func TestCacheExecSetsSkipMetadata(t *testing.T) {
	c := NewCache(&Args{Size: 1024}, Opts{})
	defer c.Close()

	q := new(dns.Msg)
	q.SetQuestion("skip.example.", dns.TypeA)
	q.Response = true
	qCtx := query_context.NewContext(q)
	next := sequence.NewChainWalker(nil, nil)

	if err := c.Exec(context.Background(), qCtx, next); err != nil {
		t.Fatal(err)
	}
	if got := query_observe.Get(qCtx).CacheStatus; got != "skip" {
		t.Fatalf("cache status = %q, want skip", got)
	}
}

func TestCacheExecSetsMissThenHitMetadata(t *testing.T) {
	c := NewCache(&Args{Size: 1024}, Opts{})
	defer c.Close()

	first := newCacheTestContext("cache.example.")
	fillResponse := sequence.NewChainWalker([]*sequence.ChainNode{{
		E: sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
			r := new(dns.Msg)
			r.SetReply(qCtx.Q())
			r.Answer = []dns.RR{newARecord(t, "cache.example.")}
			qCtx.SetResponse(r)
			return nil
		}),
	}}, nil)
	if err := c.Exec(context.Background(), first, fillResponse); err != nil {
		t.Fatal(err)
	}
	if got := query_observe.Get(first).CacheStatus; got != "miss" {
		t.Fatalf("first cache status = %q, want miss", got)
	}

	second := newCacheTestContext("cache.example.")
	if err := c.Exec(context.Background(), second, sequence.NewChainWalker(nil, nil)); err != nil {
		t.Fatal(err)
	}
	if got := query_observe.Get(second).CacheStatus; got != "hit" {
		t.Fatalf("second cache status = %q, want hit", got)
	}
	if second.R() == nil {
		t.Fatal("second response is nil, want cached response")
	}
}

func TestLazyUpdateMarksInternalObservation(t *testing.T) {
	c := NewCache(&Args{Size: 16}, Opts{})
	defer c.Close()

	qCtx := newCacheTestContext("refresh.example.")
	internal := make(chan bool, 1)
	next := sequence.NewChainWalker([]*sequence.ChainNode{{
		E: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			internal <- query_observe.Get(qCtx).Internal
			return nil
		}),
	}}, nil)
	c.doLazyUpdate("refresh-key", qCtx, next)

	select {
	case got := <-internal:
		if !got {
			t.Fatal("lazy refresh internal metadata = false, want true")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lazy refresh")
	}
	if query_observe.Get(qCtx).Internal {
		t.Fatal("client query context was marked internal")
	}
}

func newCacheTestContext(qname string) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion(qname, dns.TypeA)
	return query_context.NewContext(q)
}

func newARecord(t *testing.T, qname string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(qname + " 60 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
