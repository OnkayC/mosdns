package query_dashboard

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

type sqliteStore struct {
	db            *sql.DB
	ch            chan QueryRecord
	batchSize     int
	flushInterval time.Duration
	retention     time.Duration
	logger        *zap.Logger
	onWriteError  func(error)

	mu     sync.RWMutex
	closed bool
	wg     sync.WaitGroup
}

func newSQLiteStore(args SQLiteArgs, channelSize int, logger *zap.Logger, onWriteError func(error)) (*sqliteStore, error) {
	if channelSize <= 0 {
		channelSize = 4096
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if err := os.MkdirAll(filepath.Dir(args.Path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite parent dir: %w", err)
	}
	db, err := sql.Open("sqlite", args.Path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	store := &sqliteStore{
		db:            db,
		ch:            make(chan QueryRecord, channelSize),
		batchSize:     args.BatchSize,
		flushInterval: time.Duration(args.FlushIntervalMs) * time.Millisecond,
		retention:     time.Duration(args.RetentionHours) * time.Hour,
		logger:        logger,
		onWriteError:  onWriteError,
	}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	store.wg.Add(1)
	go store.worker()
	return store, nil
}

func (s *sqliteStore) init() error {
	statements := [...]string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		`CREATE TABLE IF NOT EXISTS queries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_unix_nano INTEGER NOT NULL,
  uqid INTEGER NOT NULL,
  entry TEXT,
  route TEXT,
  client TEXT,
  transport TEXT,
  qname TEXT NOT NULL,
  qtype INTEGER NOT NULL,
  qclass INTEGER NOT NULL,
  rcode INTEGER,
  latency_us INTEGER NOT NULL,
  cache_status TEXT,
  upstream TEXT,
  error TEXT
);`,
		"CREATE INDEX IF NOT EXISTS queries_ts_idx ON queries(ts_unix_nano);",
		"CREATE INDEX IF NOT EXISTS queries_qname_idx ON queries(qname);",
		"CREATE INDEX IF NOT EXISTS queries_client_idx ON queries(client);",
		"CREATE INDEX IF NOT EXISTS queries_route_idx ON queries(route);",
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("init sqlite: %w", err)
		}
	}
	return nil
}

func (s *sqliteStore) Enqueue(record QueryRecord) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false
	}
	select {
	case s.ch <- cloneRecord(record):
		return true
	default:
		return false
	}
}

func (s *sqliteStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.ch)
	s.mu.Unlock()

	s.wg.Wait()
	return s.db.Close()
}

func (s *sqliteStore) worker() {
	defer s.wg.Done()

	flushTicker := time.NewTicker(s.flushInterval)
	defer flushTicker.Stop()
	retentionTicker := time.NewTicker(time.Hour)
	defer retentionTicker.Stop()

	batch := make([]QueryRecord, 0, s.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.writeBatch(batch); err != nil {
			s.reportWriteError(err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case record, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, record)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-flushTicker.C:
			flush()
		case <-retentionTicker.C:
			if err := s.deleteExpired(); err != nil {
				s.reportWriteError(err)
			}
		}
	}
}

func (s *sqliteStore) writeBatch(records []QueryRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO queries (
  ts_unix_nano, uqid, entry, route, client, transport, qname, qtype, qclass, rcode, latency_us, cache_status, upstream, error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, record := range records {
		var rcode any
		if record.Rcode != nil {
			rcode = *record.Rcode
		}
		if _, err := stmt.Exec(
			record.Time.UnixNano(),
			record.Uqid,
			nullString(record.Entry),
			nullString(record.Route),
			nullString(record.Client),
			nullString(record.Transport),
			record.Qname,
			record.Qtype,
			record.Qclass,
			rcode,
			record.LatencyUs,
			nullString(record.CacheStatus),
			nullString(record.Upstream),
			nullString(record.Error),
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *sqliteStore) deleteExpired() error {
	if s.retention <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-s.retention).UnixNano()
	_, err := s.db.Exec("DELETE FROM queries WHERE ts_unix_nano < ?", cutoff)
	return err
}

func (s *sqliteStore) reportWriteError(err error) {
	if s.onWriteError != nil {
		s.onWriteError(err)
	}
	s.logger.Error("query dashboard sqlite write failed", zap.Error(err))
}

func escapeLikePattern(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(s)
}

func (s *sqliteStore) Search(q string, limit int) ([]QueryRecord, error) {
	like := "%" + escapeLikePattern(strings.ToLower(strings.TrimSpace(q))) + "%"
	rows, err := s.db.Query(selectRecordSQL+` WHERE lower(qname) LIKE ? ESCAPE '\' OR lower(client) LIKE ? ESCAPE '\' OR lower(route) LIKE ? ESCAPE '\' OR lower(entry) LIKE ? ESCAPE '\' OR lower(upstream) LIKE ? ESCAPE '\' ORDER BY ts_unix_nano DESC LIMIT ?`, like, like, like, like, like, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

func (s *sqliteStore) RecordsSince(since time.Time) ([]QueryRecord, error) {
	rows, err := s.db.Query(selectRecordSQL+` WHERE ts_unix_nano >= ? ORDER BY ts_unix_nano DESC`, since.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

func (s *sqliteStore) Stats(since time.Time) (statsResponse, error) {
	stats := statsResponse{
		RcodeCounts:       make(map[string]int),
		CacheStatusCounts: make(map[string]int),
		RouteCounts:       make(map[string]int),
	}
	ts := since.UnixNano()

	if err := s.db.QueryRow(`SELECT COUNT(*) FROM queries WHERE ts_unix_nano >= ?`, ts).Scan(&stats.Total); err != nil {
		return statsResponse{}, err
	}

	rcodeRows, err := s.db.Query(`SELECT rcode, COUNT(*) FROM queries WHERE ts_unix_nano >= ? AND rcode IS NOT NULL GROUP BY rcode`, ts)
	if err != nil {
		return statsResponse{}, err
	}
	for rcodeRows.Next() {
		var rcode sql.NullInt64
		var count int
		if err := rcodeRows.Scan(&rcode, &count); err != nil {
			rcodeRows.Close()
			return statsResponse{}, err
		}
		if rcode.Valid {
			stats.RcodeCounts[strconv.FormatInt(rcode.Int64, 10)] = count
		}
	}
	if err := rcodeRows.Err(); err != nil {
		rcodeRows.Close()
		return statsResponse{}, err
	}
	rcodeRows.Close()

	cacheRows, err := s.db.Query(`SELECT cache_status, COUNT(*) FROM queries WHERE ts_unix_nano >= ? AND cache_status != '' GROUP BY cache_status`, ts)
	if err != nil {
		return statsResponse{}, err
	}
	for cacheRows.Next() {
		var status string
		var count int
		if err := cacheRows.Scan(&status, &count); err != nil {
			cacheRows.Close()
			return statsResponse{}, err
		}
		stats.CacheStatusCounts[status] = count
	}
	if err := cacheRows.Err(); err != nil {
		cacheRows.Close()
		return statsResponse{}, err
	}
	cacheRows.Close()

	routeRows, err := s.db.Query(`SELECT route, COUNT(*) FROM queries WHERE ts_unix_nano >= ? AND route != '' GROUP BY route`, ts)
	if err != nil {
		return statsResponse{}, err
	}
	for routeRows.Next() {
		var route string
		var count int
		if err := routeRows.Scan(&route, &count); err != nil {
			routeRows.Close()
			return statsResponse{}, err
		}
		stats.RouteCounts[route] = count
	}
	if err := routeRows.Err(); err != nil {
		routeRows.Close()
		return statsResponse{}, err
	}
	routeRows.Close()

	p50, err := s.latencyPercentile(ts, 0.50)
	if err != nil {
		return statsResponse{}, err
	}
	p95, err := s.latencyPercentile(ts, 0.95)
	if err != nil {
		return statsResponse{}, err
	}
	p99, err := s.latencyPercentile(ts, 0.99)
	if err != nil {
		return statsResponse{}, err
	}
	stats.LatencyUs = latencyStats{P50: p50, P95: p95, P99: p99}
	return stats, nil
}

func (s *sqliteStore) latencyPercentile(sinceUnixNano int64, p float64) (int64, error) {
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM queries WHERE ts_unix_nano >= ?`, sinceUnixNano).Scan(&total); err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, nil
	}
	// Match statsFromRecords: idx = ceil(n*p)-1
	idx := int(math.Ceil(float64(total)*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= total {
		idx = total - 1
	}
	var latency int64
	err := s.db.QueryRow(`SELECT latency_us FROM queries WHERE ts_unix_nano >= ? ORDER BY latency_us ASC LIMIT 1 OFFSET ?`, sinceUnixNano, idx).Scan(&latency)
	if err != nil {
		return 0, err
	}
	return latency, nil
}

func (s *sqliteStore) TopDomains(since time.Time, limit int) ([]TopDomainItem, error) {
	rows, err := s.db.Query(`SELECT qname, COUNT(*) FROM queries WHERE ts_unix_nano >= ? GROUP BY qname ORDER BY COUNT(*) DESC, qname ASC LIMIT ?`, since.UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []TopDomainItem
	for rows.Next() {
		var item TopDomainItem
		if err := rows.Scan(&item.Qname, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *sqliteStore) TopClients(since time.Time, limit int) ([]TopClientItem, error) {
	rows, err := s.db.Query(`SELECT client, COUNT(*) FROM queries WHERE ts_unix_nano >= ? AND client IS NOT NULL AND client != '' GROUP BY client ORDER BY COUNT(*) DESC, client ASC LIMIT ?`, since.UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []TopClientItem
	for rows.Next() {
		var item TopClientItem
		if err := rows.Scan(&item.Client, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *sqliteStore) Routes(since time.Time) ([]RouteItem, error) {
	rows, err := s.db.Query(`SELECT route, COUNT(*) FROM queries WHERE ts_unix_nano >= ? AND route IS NOT NULL AND route != '' GROUP BY route ORDER BY COUNT(*) DESC, route ASC LIMIT ?`, since.UnixNano(), maxLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []RouteItem
	for rows.Next() {
		var item RouteItem
		if err := rows.Scan(&item.Route, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const selectRecordSQL = `SELECT ts_unix_nano, uqid, entry, route, client, transport, qname, qtype, qclass, rcode, latency_us, cache_status, upstream, error FROM queries`

func scanRecords(rows *sql.Rows) ([]QueryRecord, error) {
	var records []QueryRecord
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func scanRecord(rows interface{ Scan(dest ...any) error }) (QueryRecord, error) {
	var (
		ts          int64
		uqid        int64
		entry       sql.NullString
		route       sql.NullString
		client      sql.NullString
		transport   sql.NullString
		qname       string
		qtype       int64
		qclass      int64
		rcode       sql.NullInt64
		latencyUs   int64
		cacheStatus sql.NullString
		upstream    sql.NullString
		errText     sql.NullString
	)
	if err := rows.Scan(&ts, &uqid, &entry, &route, &client, &transport, &qname, &qtype, &qclass, &rcode, &latencyUs, &cacheStatus, &upstream, &errText); err != nil {
		return QueryRecord{}, err
	}
	record := QueryRecord{
		Time:        time.Unix(0, ts),
		Uqid:        uint32(uqid),
		Entry:       entry.String,
		Route:       route.String,
		Client:      client.String,
		Transport:   transport.String,
		Qname:       qname,
		Qtype:       uint16(qtype),
		Qclass:      uint16(qclass),
		LatencyUs:   latencyUs,
		CacheStatus: cacheStatus.String,
		Upstream:    upstream.String,
		Error:       errText.String,
	}
	if rcode.Valid {
		v := int(rcode.Int64)
		record.Rcode = &v
	}
	return record, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
