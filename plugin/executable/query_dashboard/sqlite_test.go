package query_dashboard

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestSQLiteStorePersistsAndQueriesRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query-dashboard.sqlite")
	store, err := newSQLiteStore(SQLiteArgs{
		Path:            path,
		BatchSize:       2,
		FlushIntervalMs: 60_000,
		RetentionHours:  168,
	}, 4, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	rcodeSuccess := 0
	rcodeNXDOMAIN := 3
	records := []QueryRecord{
		{
			Time:        now.Add(-2 * time.Minute),
			Uqid:        1,
			Entry:       "main",
			Route:       "foreign",
			Client:      "10.0.0.10",
			Transport:   "udp",
			Qname:       "alpha.example.",
			Qtype:       1,
			Qclass:      1,
			Rcode:       &rcodeSuccess,
			LatencyUs:   100,
			CacheStatus: "miss",
			Upstream:    "alidns",
		},
		{
			Time:        now.Add(-time.Minute),
			Uqid:        2,
			Entry:       "apple",
			Route:       "apple",
			Client:      "10.0.0.11",
			Transport:   "tcp",
			Qname:       "beta.example.",
			Qtype:       28,
			Qclass:      1,
			Rcode:       &rcodeNXDOMAIN,
			LatencyUs:   200,
			CacheStatus: "hit",
			Upstream:    "quad9",
			Error:       "upstream failed",
		},
		{
			Time:      now,
			Uqid:      3,
			Entry:     "main",
			Route:     "foreign",
			Client:    "10.0.0.10",
			Transport: "udp",
			Qname:     "alpha.example.",
			Qtype:     1,
			Qclass:    1,
			LatencyUs: 300,
			Upstream:  "cf",
		},
	}
	for _, record := range records {
		if !store.Enqueue(record) {
			t.Fatalf("failed to enqueue %#v", record)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = newSQLiteStore(SQLiteArgs{
		Path:            path,
		BatchSize:       2,
		FlushIntervalMs: 60_000,
		RetentionHours:  168,
	}, 4, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	search, err := store.Search("alpha", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(search) != 2 || search[0].Uqid != 3 || search[1].Uqid != 1 {
		t.Fatalf("search records = %#v", search)
	}
	if search[0].Rcode != nil {
		t.Fatalf("nil rcode record scanned with rcode %#v", *search[0].Rcode)
	}

	since, err := store.RecordsSince(now.Add(-90 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(since) != 2 || since[0].Uqid != 3 || since[1].Uqid != 2 {
		t.Fatalf("records since = %#v", since)
	}

	topDomains, err := store.TopDomains(now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(topDomains) < 2 || topDomains[0] != (TopDomainItem{Qname: "alpha.example.", Count: 2}) {
		t.Fatalf("top domains = %#v", topDomains)
	}

	topClients, err := store.TopClients(now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(topClients) < 2 || topClients[0] != (TopClientItem{Client: "10.0.0.10", Count: 2}) {
		t.Fatalf("top clients = %#v", topClients)
	}

	routes, err := store.Routes(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) < 2 || routes[0] != (RouteItem{Route: "foreign", Count: 2}) {
		t.Fatalf("routes = %#v", routes)
	}
}

func TestSQLiteSearchEscapesLikeWildcards(t *testing.T) {
	store, err := newSQLiteStore(SQLiteArgs{
		Path:            filepath.Join(t.TempDir(), "query-dashboard.sqlite"),
		BatchSize:       10,
		FlushIntervalMs: 60_000,
		RetentionHours:  1,
	}, 4, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	records := []QueryRecord{
		{Time: time.Now(), Uqid: 1, Qname: "_sip._tcp.example.", Qtype: 33, Qclass: 1, LatencyUs: 10},
		{Time: time.Now(), Uqid: 2, Qname: "xsipxtcp.example.", Qtype: 33, Qclass: 1, LatencyUs: 10},
		{Time: time.Now(), Uqid: 3, Qname: "100%match.example.", Qtype: 1, Qclass: 1, LatencyUs: 10},
		{Time: time.Now(), Uqid: 4, Qname: "100Xmatch.example.", Qtype: 1, Qclass: 1, LatencyUs: 10},
	}
	if err := store.writeBatch(records); err != nil {
		t.Fatal(err)
	}

	underscore, err := store.Search("_sip._tcp", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(underscore) != 1 || underscore[0].Uqid != 1 {
		t.Fatalf("underscore search = %#v, want only literal _sip._tcp", underscore)
	}

	percent, err := store.Search("100%", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(percent) != 1 || percent[0].Uqid != 3 {
		t.Fatalf("percent search = %#v, want only literal 100%%", percent)
	}
}

func TestSQLiteStatsAggregatesFullWindow(t *testing.T) {
	store, err := newSQLiteStore(SQLiteArgs{
		Path:            filepath.Join(t.TempDir(), "query-dashboard.sqlite"),
		BatchSize:       10,
		FlushIntervalMs: 60_000,
		RetentionHours:  1,
	}, 4, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now()
	rcodeOK := 0
	rcodeNX := 3
	records := []QueryRecord{
		{Time: now.Add(-time.Minute), Uqid: 1, Qname: "a.example.", Route: "foreign", CacheStatus: "miss", Rcode: &rcodeOK, LatencyUs: 10},
		{Time: now.Add(-30 * time.Second), Uqid: 2, Qname: "b.example.", Route: "foreign", CacheStatus: "hit", Rcode: &rcodeNX, LatencyUs: 20},
		{Time: now, Uqid: 3, Qname: "c.example.", Route: "apple", CacheStatus: "miss", Rcode: &rcodeOK, LatencyUs: 30},
	}
	if err := store.writeBatch(records); err != nil {
		t.Fatal(err)
	}

	stats, err := store.Stats(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 3 {
		t.Fatalf("total = %d, want 3", stats.Total)
	}
	if stats.RouteCounts["foreign"] != 2 || stats.RouteCounts["apple"] != 1 {
		t.Fatalf("route counts = %#v", stats.RouteCounts)
	}
	if stats.CacheStatusCounts["miss"] != 2 || stats.CacheStatusCounts["hit"] != 1 {
		t.Fatalf("cache counts = %#v", stats.CacheStatusCounts)
	}
	if stats.RcodeCounts["0"] != 2 || stats.RcodeCounts["3"] != 1 {
		t.Fatalf("rcode counts = %#v", stats.RcodeCounts)
	}
	if stats.LatencyUs.P50 != 20 || stats.LatencyUs.P95 != 30 || stats.LatencyUs.P99 != 30 {
		t.Fatalf("latency stats = %#v", stats.LatencyUs)
	}
}

func TestSQLiteStoreCloseAndWriteErrorCallback(t *testing.T) {
	var writeErrors int
	store, err := newSQLiteStore(SQLiteArgs{
		Path:            filepath.Join(t.TempDir(), "query-dashboard.sqlite"),
		BatchSize:       100,
		FlushIntervalMs: 60_000,
		RetentionHours:  1,
	}, 1, zap.NewNop(), func(error) { writeErrors++ })
	if err != nil {
		t.Fatal(err)
	}

	record := QueryRecord{Time: time.Now(), Uqid: 1, Qname: "close.example.", Qtype: 1, Qclass: 1, LatencyUs: 10}
	if !store.Enqueue(record) {
		t.Fatal("enqueue failed")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if store.Enqueue(record) {
		t.Fatal("enqueue after close succeeded")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store.reportWriteError(assertErr("synthetic write error"))
	if writeErrors != 1 {
		t.Fatalf("write error callback count = %d, want 1", writeErrors)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

func TestSQLitePrunesExpiredRowsOnStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query-dashboard.sqlite")
	args := SQLiteArgs{
		Path:            path,
		BatchSize:       10,
		FlushIntervalMs: 60_000,
		RetentionHours:  1,
	}
	store, err := newSQLiteStore(args, 4, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	oldRecord := QueryRecord{Time: time.Now().Add(-2 * time.Hour), Uqid: 1, Qname: "old.example.", Qtype: 1, Qclass: 1, LatencyUs: 10}
	newRecord := QueryRecord{Time: time.Now(), Uqid: 2, Qname: "new.example.", Qtype: 1, Qclass: 1, LatencyUs: 10}
	if err := store.writeBatch([]QueryRecord{oldRecord, newRecord}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = newSQLiteStore(args, 4, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	records, err := store.RecordsSince(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Qname != "new.example." {
		t.Fatalf("records after startup retention = %#v", records)
	}
}
