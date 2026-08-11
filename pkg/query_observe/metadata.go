package query_observe

import "github.com/IrineSistiana/mosdns/v5/pkg/query_context"

type Metadata struct {
	Entry       string
	Route       string
	Upstream    string
	CacheStatus string
	Transport   string
	Internal    bool
}

var (
	entryKey       = query_context.RegKey()
	routeKey       = query_context.RegKey()
	upstreamKey    = query_context.RegKey()
	cacheStatusKey = query_context.RegKey()
	transportKey   = query_context.RegKey()
	internalKey    = query_context.RegKey()
)

func SetEntry(qCtx *query_context.Context, entry string) {
	storeString(qCtx, entryKey, entry)
}

func SetRoute(qCtx *query_context.Context, route string) {
	storeString(qCtx, routeKey, route)
}

func SetUpstream(qCtx *query_context.Context, upstream string) {
	storeString(qCtx, upstreamKey, upstream)
}

func SetCacheStatus(qCtx *query_context.Context, status string) {
	storeString(qCtx, cacheStatusKey, status)
}

func SetTransport(qCtx *query_context.Context, transport string) {
	storeString(qCtx, transportKey, transport)
}

func SetInternal(qCtx *query_context.Context) {
	if qCtx != nil {
		qCtx.StoreValue(internalKey, true)
	}
}

func Get(qCtx *query_context.Context) Metadata {
	if qCtx == nil {
		return Metadata{}
	}
	return Metadata{
		Entry:       getString(qCtx, entryKey),
		Route:       getString(qCtx, routeKey),
		Upstream:    getString(qCtx, upstreamKey),
		CacheStatus: getString(qCtx, cacheStatusKey),
		Transport:   getString(qCtx, transportKey),
		Internal:    getBool(qCtx, internalKey),
	}
}

// Copy replaces dst's observation metadata with src's metadata.
func Copy(dst, src *query_context.Context) {
	if dst == nil {
		return
	}
	for _, key := range [...]uint32{entryKey, routeKey, upstreamKey, cacheStatusKey, transportKey, internalKey} {
		value, ok := src.GetValue(key)
		if ok {
			dst.StoreValue(key, value)
		} else {
			dst.DeleteValue(key)
		}
	}
}

func storeString(qCtx *query_context.Context, key uint32, value string) {
	if qCtx == nil || value == "" {
		return
	}
	qCtx.StoreValue(key, value)
}

func getString(qCtx *query_context.Context, key uint32) string {
	v, ok := qCtx.GetValue(key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func getBool(qCtx *query_context.Context, key uint32) bool {
	v, ok := qCtx.GetValue(key)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}
