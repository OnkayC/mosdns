package query_dashboard

import (
	"strings"
	"sync"
	"time"
)

const (
	defaultLimit = 200
	maxLimit     = 1000
)

type Ring struct {
	mu       sync.RWMutex
	records  []QueryRecord
	next     int
	capacity int
	full     bool
}

func NewRing(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{capacity: capacity}
}

func (r *Ring) Add(record QueryRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record = cloneRecord(record)
	if len(r.records) < r.capacity {
		r.records = append(r.records, record)
		r.next = len(r.records) % r.capacity
		if len(r.records) == r.capacity {
			r.full = true
		}
		return
	}

	r.records[r.next] = record
	r.next = (r.next + 1) % r.capacity
	r.full = true
}

func (r *Ring) Recent(limit, offset int) []QueryRecord {
	limit = normalizeLimit(limit, defaultLimit)
	if offset < 0 {
		offset = 0
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.recentLocked(limit, offset)
}

func (r *Ring) Search(substr string, limit int) []QueryRecord {
	limit = normalizeLimit(limit, defaultLimit)
	substr = strings.ToLower(strings.TrimSpace(substr))
	if substr == "" {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]QueryRecord, 0, min(limit, r.lenLocked()))
	for _, record := range r.allNewestLocked() {
		if recordMatches(record, substr) {
			out = append(out, cloneRecord(record))
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lenLocked()
}

func (r *Ring) Capacity() int {
	return r.capacity
}

func (r *Ring) All() []QueryRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	records := r.allNewestLocked()
	out := make([]QueryRecord, len(records))
	for i, record := range records {
		out[i] = cloneRecord(record)
	}
	return out
}

func (r *Ring) Bounds() (oldest *time.Time, newest *time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.lenLocked() == 0 {
		return nil, nil
	}
	oldestTime := r.records[r.oldestIndexLocked()].Time
	newestTime := r.records[r.newestIndexLocked()].Time
	return &oldestTime, &newestTime
}

func (r *Ring) recentLocked(limit, offset int) []QueryRecord {
	records := r.allNewestLocked()
	if offset >= len(records) {
		return nil
	}
	records = records[offset:]
	if len(records) > limit {
		records = records[:limit]
	}
	out := make([]QueryRecord, len(records))
	for i, record := range records {
		out[i] = cloneRecord(record)
	}
	return out
}

func (r *Ring) allNewestLocked() []QueryRecord {
	n := r.lenLocked()
	if n == 0 {
		return nil
	}
	out := make([]QueryRecord, 0, n)
	idx := r.newestIndexLocked()
	for i := 0; i < n; i++ {
		out = append(out, r.records[idx])
		idx--
		if idx < 0 {
			idx = n - 1
		}
	}
	return out
}

func (r *Ring) lenLocked() int {
	return len(r.records)
}

func (r *Ring) oldestIndexLocked() int {
	if !r.full {
		return 0
	}
	return r.next
}

func (r *Ring) newestIndexLocked() int {
	n := r.lenLocked()
	if n == 0 {
		return 0
	}
	if !r.full {
		return n - 1
	}
	idx := r.next - 1
	if idx < 0 {
		idx = n - 1
	}
	return idx
}

func normalizeLimit(limit, fallback int) int {
	if limit <= 0 {
		limit = fallback
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return limit
}

func recordMatches(record QueryRecord, substr string) bool {
	fields := [...]string{record.Qname, record.Client, record.Route, record.Entry, record.Upstream}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), substr) {
			return true
		}
	}
	return false
}

func cloneRecord(record QueryRecord) QueryRecord {
	if record.Rcode != nil {
		rcode := *record.Rcode
		record.Rcode = &rcode
	}
	return record
}
