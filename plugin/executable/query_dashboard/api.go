package query_dashboard

import (
	"embed"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

//go:embed web/*
var webFiles embed.FS

type recordsResponse struct {
	Records []QueryRecord `json:"records"`
}

type healthResponse struct {
	OK                     bool       `json:"ok"`
	RecentSize             int        `json:"recent_size"`
	RecentCapacity         int        `json:"recent_capacity"`
	DroppedTotal           uint64     `json:"dropped_total"`
	SQLiteEnabled          bool       `json:"sqlite_enabled"`
	SQLiteWriteErrorsTotal uint64     `json:"sqlite_write_errors_total"`
	OldestTime             *time.Time `json:"oldest_time"`
	NewestTime             *time.Time `json:"newest_time"`
}

type statsResponse struct {
	Total             int            `json:"total"`
	RcodeCounts       map[string]int `json:"rcode_counts"`
	CacheStatusCounts map[string]int `json:"cache_status_counts"`
	RouteCounts       map[string]int `json:"route_counts"`
	LatencyUs         latencyStats   `json:"latency_us"`
}

type latencyStats struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
}

type TopDomainItem struct {
	Qname string `json:"qname"`
	Count int    `json:"count"`
}

type TopClientItem struct {
	Client string `json:"client"`
	Count  int    `json:"count"`
}

type RouteItem struct {
	Route string `json:"route"`
	Count int    `json:"count"`
}

func (d *Dashboard) Api() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/", d.serveAsset("web/index.html", "text/html; charset=utf-8"))
	r.Get("/app.js", d.serveAsset("web/app.js", "application/javascript; charset=utf-8"))
	r.Get("/style.css", d.serveAsset("web/style.css", "text/css; charset=utf-8"))
	r.Get("/health", d.handleHealth)
	r.Get("/api/query-log", d.handleQueryLog)
	r.Get("/api/search", d.handleSearch)
	r.Get("/api/stats", d.handleStats)
	r.Get("/api/top-domains", d.handleTopDomains)
	r.Get("/api/top-clients", d.handleTopClients)
	r.Get("/api/routes", d.handleRoutes)
	return r
}

func (d *Dashboard) serveAsset(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		data, err := webFiles.ReadFile(path)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("content-type", contentType)
		_, _ = w.Write(data)
	}
}

func (d *Dashboard) handleHealth(w http.ResponseWriter, req *http.Request) {
	oldest, newest := d.ring.Bounds()
	writeJSON(w, http.StatusOK, healthResponse{
		OK:                     true,
		RecentSize:             d.ring.Len(),
		RecentCapacity:         d.ring.Capacity(),
		DroppedTotal:           d.droppedCount.Load(),
		SQLiteEnabled:          d.sqlite != nil,
		SQLiteWriteErrorsTotal: d.sqliteErrorCount.Load(),
		OldestTime:             oldest,
		NewestTime:             newest,
	})
}

func (d *Dashboard) handleQueryLog(w http.ResponseWriter, req *http.Request) {
	limit, err := parseLimit(req, "limit", defaultLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, err := parseOffset(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, recordsResponse{Records: recordsOrEmpty(d.Recent(limit, offset))})
}

func (d *Dashboard) handleSearch(w http.ResponseWriter, req *http.Request) {
	q := strings.TrimSpace(req.URL.Query().Get("q"))
	if q == "" {
		writeError(w, http.StatusBadRequest, errors.New("q is required"))
		return
	}
	limit, err := parseLimit(req, "limit", defaultLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	records, err := d.Search(q, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, recordsResponse{Records: recordsOrEmpty(records)})
}

func (d *Dashboard) handleStats(w http.ResponseWriter, req *http.Request) {
	window, err := parseDurationParam(req, "window", 5*time.Minute)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	stats, err := d.stats(time.Now().Add(-window))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (d *Dashboard) handleTopDomains(w http.ResponseWriter, req *http.Request) {
	since, limit, ok := parseSinceAndLimit(w, req)
	if !ok {
		return
	}
	items, err := d.topDomains(since, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]TopDomainItem{"items": topDomainItemsOrEmpty(items)})
}

func (d *Dashboard) handleTopClients(w http.ResponseWriter, req *http.Request) {
	since, limit, ok := parseSinceAndLimit(w, req)
	if !ok {
		return
	}
	items, err := d.topClients(since, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]TopClientItem{"items": topClientItemsOrEmpty(items)})
}

func (d *Dashboard) handleRoutes(w http.ResponseWriter, req *http.Request) {
	sinceDuration, err := parseDurationParam(req, "since", time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	items, err := d.routes(time.Now().Add(-sinceDuration))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]RouteItem{"items": routeItemsOrEmpty(items)})
}

func parseSinceAndLimit(w http.ResponseWriter, req *http.Request) (time.Time, int, bool) {
	sinceDuration, err := parseDurationParam(req, "since", time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return time.Time{}, 0, false
	}
	limit, err := parseLimit(req, "limit", 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return time.Time{}, 0, false
	}
	return time.Now().Add(-sinceDuration), limit, true
}

func parseLimit(req *http.Request, key string, fallback int) (int, error) {
	value := strings.TrimSpace(req.URL.Query().Get(key))
	if value == "" {
		return normalizeLimit(0, fallback), nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return normalizeLimit(limit, fallback), nil
}

func parseOffset(req *http.Request) (int, error) {
	value := strings.TrimSpace(req.URL.Query().Get("offset"))
	if value == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, errors.New("offset must be non-negative")
	}
	return offset, nil
}

func parseDurationParam(req *http.Request, key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(req.URL.Query().Get(key))
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func recordsOrEmpty(records []QueryRecord) []QueryRecord {
	if records == nil {
		return []QueryRecord{}
	}
	return records
}

func topDomainItemsOrEmpty(items []TopDomainItem) []TopDomainItem {
	if items == nil {
		return []TopDomainItem{}
	}
	return items
}

func topClientItemsOrEmpty(items []TopClientItem) []TopClientItem {
	if items == nil {
		return []TopClientItem{}
	}
	return items
}

func routeItemsOrEmpty(items []RouteItem) []RouteItem {
	if items == nil {
		return []RouteItem{}
	}
	return items
}

func statsFromRecords(records []QueryRecord) statsResponse {
	stats := statsResponse{
		Total:             len(records),
		RcodeCounts:       make(map[string]int),
		CacheStatusCounts: make(map[string]int),
		RouteCounts:       make(map[string]int),
	}
	latencies := make([]int64, 0, len(records))
	for _, record := range records {
		if record.Rcode != nil {
			stats.RcodeCounts[strconv.Itoa(*record.Rcode)]++
		}
		if record.CacheStatus != "" {
			stats.CacheStatusCounts[record.CacheStatus]++
		}
		if record.Route != "" {
			stats.RouteCounts[record.Route]++
		}
		latencies = append(latencies, record.LatencyUs)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	stats.LatencyUs = latencyStats{
		P50: percentile(latencies, 0.50),
		P95: percentile(latencies, 0.95),
		P99: percentile(latencies, 0.99),
	}
	return stats
}

func percentile(values []int64, p float64) int64 {
	if len(values) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(len(values))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}

func topDomainsFromRecords(records []QueryRecord, limit int) []TopDomainItem {
	counts := make(map[string]int)
	for _, record := range records {
		if record.Qname != "" {
			counts[record.Qname]++
		}
	}
	items := make([]TopDomainItem, 0, len(counts))
	for qname, count := range counts {
		items = append(items, TopDomainItem{Qname: qname, Count: count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func topClientsFromRecords(records []QueryRecord, limit int) []TopClientItem {
	counts := make(map[string]int)
	for _, record := range records {
		if record.Client != "" {
			counts[record.Client]++
		}
	}
	items := make([]TopClientItem, 0, len(counts))
	for client, count := range counts {
		items = append(items, TopClientItem{Client: client, Count: count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func routesFromRecords(records []QueryRecord) []RouteItem {
	counts := make(map[string]int)
	for _, record := range records {
		if record.Route != "" {
			counts[record.Route]++
		}
	}
	items := make([]RouteItem, 0, len(counts))
	for route, count := range counts {
		items = append(items, RouteItem{Route: route, Count: count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	return items
}
