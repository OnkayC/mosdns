package query_dashboard

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_observe"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const (
	PluginType                   = "query_dashboard"
	defaultSQLiteBatchSize       = 500
	defaultSQLiteFlushIntervalMs = 1000
	defaultSQLiteRetentionHours  = 168
)

type Args struct {
	Entry       string     `yaml:"entry"`
	RecentSize  int        `yaml:"recent_size"`
	ChannelSize int        `yaml:"channel_size"`
	SQLite      SQLiteArgs `yaml:"sqlite"`
}

type SQLiteArgs struct {
	Enabled         bool   `yaml:"enabled"`
	Path            string `yaml:"path"`
	BatchSize       int    `yaml:"batch_size"`
	FlushIntervalMs int    `yaml:"flush_interval_ms"`
	RetentionHours  int    `yaml:"retention_hours"`
}

type QueryRecord struct {
	Time        time.Time `json:"time"`
	Uqid        uint32    `json:"uqid"`
	Entry       string    `json:"entry,omitempty"`
	Route       string    `json:"route,omitempty"`
	Client      string    `json:"client,omitempty"`
	Transport   string    `json:"transport,omitempty"`
	Qname       string    `json:"qname"`
	Qtype       uint16    `json:"qtype"`
	Qclass      uint16    `json:"qclass"`
	Rcode       *int      `json:"rcode,omitempty"`
	LatencyUs   int64     `json:"latency_us"`
	CacheStatus string    `json:"cache_status,omitempty"`
	Upstream    string    `json:"upstream,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type Dashboard struct {
	args   Args
	logger *zap.Logger
	ring   *Ring
	sqlite *sqliteStore

	recordsTotal           prometheus.Counter
	droppedTotal           prometheus.Counter
	sqliteWriteErrorsTotal prometheus.Counter
	recentSize             prometheus.GaugeFunc

	recordsCount     atomic.Uint64
	droppedCount     atomic.Uint64
	sqliteErrorCount atomic.Uint64
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	d, err := NewDashboard(args.(*Args), bp.L(), bp.Tag())
	if err != nil {
		return nil, err
	}
	if err := d.RegMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("failed to register metrics, %w", err)
	}
	bp.RegAPI(d.Api())
	return d, nil
}

var _ sequence.RecursiveExecutable = (*Dashboard)(nil)

func NewDashboard(args *Args, logger *zap.Logger, metricsTag string) (*Dashboard, error) {
	if args == nil {
		args = new(Args)
	}
	cfg := *args
	cfg.setDefaults()
	if logger == nil {
		logger = zap.NewNop()
	}

	labels := prometheus.Labels{"tag": metricsTag}
	d := &Dashboard{
		args:   cfg,
		logger: logger,
		ring:   NewRing(cfg.RecentSize),
		recordsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "records_total",
			Help:        "The total number of query dashboard records accepted.",
			ConstLabels: labels,
		}),
		droppedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "dropped_total",
			Help:        "The total number of query dashboard records dropped before or during SQLite persistence.",
			ConstLabels: labels,
		}),
		sqliteWriteErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "sqlite_write_errors_total",
			Help:        "The total number of query dashboard SQLite write errors.",
			ConstLabels: labels,
		}),
	}
	d.recentSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "recent_size_current",
		Help:        "Current number of query records in the in-memory dashboard ring.",
		ConstLabels: labels,
	}, func() float64 {
		return float64(d.ring.Len())
	})

	if cfg.SQLite.Enabled {
		store, err := newSQLiteStore(cfg.SQLite, cfg.ChannelSize, logger, d.handleSQLiteWriteError, d.handleSQLiteDropped)
		if err != nil {
			return nil, err
		}
		d.sqlite = store
	}

	return d, nil
}

func (a *Args) setDefaults() {
	if a.RecentSize <= 0 {
		a.RecentSize = 20000
	}
	if a.ChannelSize <= 0 {
		a.ChannelSize = 4096
	}
	a.SQLite.setDefaults()
}

func (a *SQLiteArgs) setDefaults() {
	if a.Path == "" {
		a.Path = "./logs/query-dashboard.sqlite"
	}
	if a.BatchSize <= 0 {
		a.BatchSize = defaultSQLiteBatchSize
	}
	if a.FlushIntervalMs <= 0 {
		a.FlushIntervalMs = defaultSQLiteFlushIntervalMs
	}
	if a.RetentionHours <= 0 {
		a.RetentionHours = defaultSQLiteRetentionHours
	}
}

func (d *Dashboard) RegMetricsTo(r prometheus.Registerer) error {
	for _, collector := range [...]prometheus.Collector{d.recordsTotal, d.droppedTotal, d.sqliteWriteErrorsTotal, d.recentSize} {
		if err := r.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dashboard) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	start := time.Now()
	err := next.ExecNext(ctx, qCtx)
	if !query_observe.Get(qCtx).Internal {
		d.Record(qCtx, time.Since(start), err)
	}
	return err
}

func (d *Dashboard) Record(qCtx *query_context.Context, elapsed time.Duration, execErr error) QueryRecord {
	meta := query_observe.Get(qCtx)
	question := qCtx.QQuestion()
	entry := d.args.Entry
	if entry == "" {
		entry = meta.Entry
	}

	rcodeValue := clientVisibleRcode(qCtx, execErr)
	rcode := &rcodeValue

	client := ""
	if qCtx.ServerMeta.ClientAddr.IsValid() {
		client = qCtx.ServerMeta.ClientAddr.String()
	}
	transport := meta.Transport
	if transport == "" {
		if qCtx.ServerMeta.FromUDP {
			transport = "udp"
		} else {
			transport = "tcp"
		}
	}

	record := QueryRecord{
		Time:        qCtx.StartTime(),
		Uqid:        qCtx.Id(),
		Entry:       entry,
		Route:       meta.Route,
		Client:      client,
		Transport:   transport,
		Qname:       question.Name,
		Qtype:       question.Qtype,
		Qclass:      question.Qclass,
		Rcode:       rcode,
		LatencyUs:   elapsed.Microseconds(),
		CacheStatus: meta.CacheStatus,
		Upstream:    meta.Upstream,
	}
	if execErr != nil {
		record.Error = execErr.Error()
	}

	d.ring.Add(record)
	d.recordsCount.Add(1)
	d.recordsTotal.Inc()
	if d.sqlite != nil && !d.sqlite.Enqueue(record) {
		d.droppedCount.Add(1)
		d.droppedTotal.Inc()
	}
	return record
}

func (d *Dashboard) Close() error {
	if d.sqlite != nil {
		return d.sqlite.Close()
	}
	return nil
}

func clientVisibleRcode(qCtx *query_context.Context, execErr error) int {
	if execErr != nil {
		return dns.RcodeServerFailure
	}
	if response := qCtx.R(); response != nil {
		return response.Rcode
	}
	return dns.RcodeRefused
}

func (d *Dashboard) Recent(limit, offset int) []QueryRecord {
	return d.ring.Recent(limit, offset)
}

func (d *Dashboard) Search(ctx context.Context, q string, limit int) ([]QueryRecord, error) {
	if d.sqlite != nil {
		return d.sqlite.Search(ctx, q, normalizeLimit(limit, defaultLimit))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.ring.Search(q, limit), nil
}

func (d *Dashboard) recordsSince(ctx context.Context, since time.Time) ([]QueryRecord, error) {
	if d.sqlite != nil {
		return d.sqlite.RecordsSince(ctx, since)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records := d.ring.All()
	out := records[:0]
	for _, record := range records {
		if !record.Time.Before(since) {
			out = append(out, record)
		}
	}
	return out, nil
}

func (d *Dashboard) stats(ctx context.Context, since time.Time) (statsResponse, error) {
	if d.sqlite != nil {
		return d.sqlite.Stats(ctx, since)
	}
	records, err := d.recordsSince(ctx, since)
	if err != nil {
		return statsResponse{}, err
	}
	stats := statsFromRecords(records)
	stats.Partial = d.ring.TruncatedSince(since)
	return stats, nil
}

func (d *Dashboard) topDomains(ctx context.Context, since time.Time, limit int) (topDomainsResponse, error) {
	limit = normalizeLimit(limit, 50)
	if d.sqlite != nil {
		items, err := d.sqlite.TopDomains(ctx, since, limit)
		return topDomainsResponse{Items: items}, err
	}
	records, err := d.recordsSince(ctx, since)
	if err != nil {
		return topDomainsResponse{}, err
	}
	items := topDomainsFromRecords(records, limit)
	return topDomainsResponse{Items: items, Partial: d.ring.TruncatedSince(since)}, nil
}

func (d *Dashboard) topClients(ctx context.Context, since time.Time, limit int) (topClientsResponse, error) {
	limit = normalizeLimit(limit, 50)
	if d.sqlite != nil {
		items, err := d.sqlite.TopClients(ctx, since, limit)
		return topClientsResponse{Items: items}, err
	}
	records, err := d.recordsSince(ctx, since)
	if err != nil {
		return topClientsResponse{}, err
	}
	items := topClientsFromRecords(records, limit)
	return topClientsResponse{Items: items, Partial: d.ring.TruncatedSince(since)}, nil
}

func (d *Dashboard) routes(ctx context.Context, since time.Time) (routesResponse, error) {
	if d.sqlite != nil {
		items, err := d.sqlite.Routes(ctx, since)
		return routesResponse{Items: items}, err
	}
	records, err := d.recordsSince(ctx, since)
	if err != nil {
		return routesResponse{}, err
	}
	items := routesFromRecords(records)
	return routesResponse{Items: items, Partial: d.ring.TruncatedSince(since)}, nil
}

func (d *Dashboard) handleSQLiteWriteError(err error) {
	d.sqliteErrorCount.Add(1)
	d.sqliteWriteErrorsTotal.Inc()
}

func (d *Dashboard) handleSQLiteDropped(count int) {
	if count <= 0 {
		return
	}
	d.droppedCount.Add(uint64(count))
	d.droppedTotal.Add(float64(count))
}
