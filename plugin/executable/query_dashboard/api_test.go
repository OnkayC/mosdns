package query_dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"go.uber.org/zap"
)

func TestAPIQueryLogAndSearch(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rcode := 0
	d.ring.Add(QueryRecord{Time: time.Now(), Qname: "example.com.", Qtype: 1, Qclass: 1, Rcode: &rcode, LatencyUs: 12, Client: "10.0.0.10", Entry: "main", Route: "direct"})

	req := httptest.NewRequest(http.MethodGet, "/api/query-log?limit=1", nil)
	rr := httptest.NewRecorder()
	d.Api().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("query-log status = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp recordsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 || resp.Records[0].Qname != "example.com." {
		t.Fatalf("records = %#v", resp.Records)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/search?q=direct&limit=1", nil)
	rr = httptest.NewRecorder()
	d.Api().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("search status = %d, body %s", rr.Code, rr.Body.String())
	}
	resp = recordsResponse{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 || resp.Records[0].Route != "direct" {
		t.Fatalf("search records = %#v", resp.Records)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/search?q=missing&limit=1", nil)
	rr = httptest.NewRecorder()
	d.Api().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("empty search status = %d, body %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"records":[]`) {
		t.Fatalf("empty search body = %s, want records array", rr.Body.String())
	}
}

func TestAPIRejectsBadInputs(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cases := []string{
		"/api/query-log?offset=-1",
		"/api/search?q=",
		"/api/stats?window=not-a-duration",
		"/api/stats?window=-1s",
	}
	for _, path := range cases {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		d.Api().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", path, rr.Code)
		}
		if ct := rr.Header().Get("content-type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("%s content-type = %q", path, ct)
		}
	}
}

func TestAPIHealthAndIndex(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	d.Api().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health status = %d", rr.Code)
	}
	var health healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if !health.OK || health.RecentCapacity != 10 {
		t.Fatalf("health = %#v", health)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rr = httptest.NewRecorder()
	d.Api().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "mosdns query dashboard") {
		t.Fatalf("index body missing dashboard shell")
	}
	if !strings.Contains(body, `href="style.css"`) || !strings.Contains(body, `src="app.js"`) {
		t.Fatalf("index body missing prefix-preserving relative asset URLs: %s", body)
	}
	if strings.Contains(body, `href="/`) || strings.Contains(body, `src="/`) {
		t.Fatalf("index body contains root-relative asset URL: %s", body)
	}
	if !strings.Contains(body, `value="doh"`) || !strings.Contains(body, `value="doq"`) {
		t.Fatalf("index body missing DoH/DoQ transport filters: %s", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/style.css", nil)
	rr = httptest.NewRecorder()
	d.Api().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("style status = %d", rr.Code)
	}
	style := rr.Body.String()
	if !strings.Contains(style, ".path-bar-fill.doh") || !strings.Contains(style, ".path-bar-fill.doq") {
		t.Fatalf("style body missing DoH/DoQ chart colors")
	}
}

func TestDashboardAssetsUnderReverseProxyPrefix(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10}, zap.NewNop(), "custom")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	r := chi.NewRouter()
	r.Mount("/mosdns/plugins/custom", d.Api())
	for _, path := range []string{
		"/mosdns/plugins/custom/",
		"/mosdns/plugins/custom/app.js",
		"/mosdns/plugins/custom/style.css",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d body %s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestAPIAggregationsUseRingFallback(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 10}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rcodeOK := 0
	rcodeNX := 3
	d.ring.Add(QueryRecord{Time: time.Now().Add(-time.Minute), Qname: "alpha.example.", Client: "10.0.0.10", Route: "foreign", CacheStatus: "miss", Rcode: &rcodeOK, LatencyUs: 10})
	d.ring.Add(QueryRecord{Time: time.Now(), Qname: "alpha.example.", Client: "10.0.0.10", Route: "foreign", CacheStatus: "hit", Rcode: &rcodeNX, LatencyUs: 30})
	d.ring.Add(QueryRecord{Time: time.Now(), Qname: "beta.example.", Client: "10.0.0.11", Route: "apple", CacheStatus: "miss", Rcode: &rcodeOK, LatencyUs: 20})

	assertStatusOK := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		d.Api().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d body %s", path, rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}

	statsBody := assertStatusOK("/api/stats?window=5m")
	if !strings.Contains(statsBody, `"total":3`) || !strings.Contains(statsBody, `"foreign":2`) || !strings.Contains(statsBody, `"hit":1`) {
		t.Fatalf("unexpected stats body: %s", statsBody)
	}
	if body := assertStatusOK("/api/top-domains?since=1h&limit=5"); !strings.Contains(body, `"qname":"alpha.example."`) || !strings.Contains(body, `"count":2`) {
		t.Fatalf("unexpected top domains body: %s", body)
	}
	if body := assertStatusOK("/api/top-clients?since=1h&limit=5"); !strings.Contains(body, `"client":"10.0.0.10"`) || !strings.Contains(body, `"count":2`) {
		t.Fatalf("unexpected top clients body: %s", body)
	}
	if body := assertStatusOK("/api/routes?since=1h"); !strings.Contains(body, `"route":"foreign"`) || !strings.Contains(body, `"count":2`) {
		t.Fatalf("unexpected routes body: %s", body)
	}
}

func TestInMemoryAggregationsUseDeterministicTieBreakers(t *testing.T) {
	records := []QueryRecord{
		{Qname: "beta.example.", Client: "10.0.0.2", Route: "zeta"},
		{Qname: "alpha.example.", Client: "10.0.0.1", Route: "alpha"},
	}

	domains := topDomainsFromRecords(records, 10)
	if len(domains) != 2 || domains[0].Qname != "alpha.example." || domains[1].Qname != "beta.example." {
		t.Fatalf("top domains = %#v, want lexical order for tied counts", domains)
	}
	clients := topClientsFromRecords(records, 10)
	if len(clients) != 2 || clients[0].Client != "10.0.0.1" || clients[1].Client != "10.0.0.2" {
		t.Fatalf("top clients = %#v, want lexical order for tied counts", clients)
	}
	routes := routesFromRecords(records)
	if len(routes) != 2 || routes[0].Route != "alpha" || routes[1].Route != "zeta" {
		t.Fatalf("routes = %#v, want lexical order for tied counts", routes)
	}
}

func TestDashboardDefaultsAndDropCounter(t *testing.T) {
	d, err := NewDashboard(&Args{SQLite: SQLiteArgs{Enabled: true, Path: filepath.Join(t.TempDir(), "query-dashboard.sqlite"), BatchSize: 100, FlushIntervalMs: 60_000}}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.args.RecentSize != 20000 || d.args.ChannelSize != 4096 || d.args.SQLite.RetentionHours != 168 {
		t.Fatalf("defaults not applied: %#v", d.args)
	}
}
