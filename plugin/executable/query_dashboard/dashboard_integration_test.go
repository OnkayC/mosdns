package query_dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func newDashboardTestContext(qname string) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion(qname, dns.TypeA)
	return query_context.NewContext(q)
}
func TestInitRegistersAPIAndMetrics(t *testing.T) {
	m := coremain.NewTestMosdnsWithPlugins(nil)
	bp := coremain.NewBP("query_dashboard_test", m)
	plugin, err := Init(bp, &Args{RecentSize: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer plugin.(*Dashboard).Close()

	req := httptest.NewRequest(http.MethodGet, "/plugins/query_dashboard_test/health", nil)
	rr := httptest.NewRecorder()
	m.GetAPIRouter().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("mounted health status = %d body %s", rr.Code, rr.Body.String())
	}
}

func TestRegMetricsToRejectsDuplicateRegistration(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 1}, zap.NewNop(), "dup")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	reg := prometheus.NewRegistry()
	if err := d.RegMetricsTo(reg); err != nil {
		t.Fatal(err)
	}
	if err := d.RegMetricsTo(reg); err == nil {
		t.Fatal("second registration succeeded, want duplicate error")
	}
}

func TestRecordErrorAndSQLiteDropCounter(t *testing.T) {
	d, err := NewDashboard(&Args{
		RecentSize: 1,
		SQLite: SQLiteArgs{
			Enabled:         true,
			Path:            filepath.Join(t.TempDir(), "query-dashboard.sqlite"),
			BatchSize:       1000,
			FlushIntervalMs: 60_000,
		},
	}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	qCtx := newDashboardTestContext("error.example.")
	_ = d.sqlite.Close()
	record := d.Record(qCtx, time.Microsecond, errors.New("downstream failed"))
	if record.Error != "downstream failed" {
		t.Fatalf("record error = %q", record.Error)
	}
	if d.droppedCount.Load() != 1 {
		t.Fatalf("dropped count = %d, want 1", d.droppedCount.Load())
	}
	d.handleSQLiteWriteError(errors.New("write failed"))
	if d.sqliteErrorCount.Load() != 1 {
		t.Fatalf("sqlite error count = %d, want 1", d.sqliteErrorCount.Load())
	}
}

func TestAPIErrorBranchesAndStaticNotFound(t *testing.T) {
	d, err := NewDashboard(&Args{RecentSize: 1}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cases := []string{
		"/api/query-log?limit=not-int",
		"/api/top-domains?since=bad-duration",
		"/api/top-domains?limit=bad-limit",
		"/api/top-clients?since=bad-duration",
		"/api/routes?since=bad-duration",
	}
	for _, path := range cases {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		d.Api().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", path, rr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/missing.css", nil)
	rr := httptest.NewRecorder()
	d.Api().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing asset status = %d, want 404", rr.Code)
	}
}

func TestSQLiteBackedAPIAndReadErrors(t *testing.T) {
	d, err := NewDashboard(&Args{
		RecentSize: 1,
		SQLite: SQLiteArgs{
			Enabled:         true,
			Path:            filepath.Join(t.TempDir(), "query-dashboard.sqlite"),
			BatchSize:       10,
			FlushIntervalMs: 60_000,
		},
	}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	record := QueryRecord{Time: time.Now(), Uqid: 1, Qname: "sqlite.example.", Qtype: 1, Qclass: 1, Client: "10.0.0.10", Route: "sqlite", LatencyUs: 42}
	if err := d.sqlite.writeBatch([]QueryRecord{record}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/api/search?q=sqlite&limit=5", want: "sqlite.example."},
		{path: "/api/stats?window=1h", want: "sqlite"},
		{path: "/api/top-domains?since=1h", want: "sqlite.example."},
		{path: "/api/top-clients?since=1h", want: "10.0.0.10"},
		{path: "/api/routes?since=1h", want: "sqlite"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()
		d.Api().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), tc.want) {
			t.Fatalf("%s status/body = %d %s", tc.path, rr.Code, rr.Body.String())
		}
	}

	if err := d.sqlite.db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/search?q=sqlite&limit=5", "/api/stats?window=1h", "/api/top-domains?since=1h", "/api/top-clients?since=1h", "/api/routes?since=1h"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		d.Api().ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("%s status = %d, want 500", path, rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `"error":"internal server error"`) {
			t.Fatalf("%s body = %s, want generic internal error", path, body)
		}
		if strings.Contains(body, "database is closed") {
			t.Fatalf("%s exposed backend error: %s", path, body)
		}
	}
}
