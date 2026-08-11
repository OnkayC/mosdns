package query_dashboard_mark

import (
	"context"
	"fmt"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_observe"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

const PluginType = "query_dashboard_mark"

type Args struct {
	Entry    string `yaml:"entry"`
	Route    string `yaml:"route"`
	Upstream string `yaml:"upstream"`
}

type Marker struct {
	args Args
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, quickSetup)
}

func Init(_ *coremain.BP, args any) (any, error) {
	return &Marker{args: *args.(*Args)}, nil
}

var _ sequence.Executable = (*Marker)(nil)

func (m *Marker) Exec(_ context.Context, qCtx *query_context.Context) error {
	query_observe.SetEntry(qCtx, m.args.Entry)
	query_observe.SetRoute(qCtx, m.args.Route)
	query_observe.SetUpstream(qCtx, m.args.Upstream)
	return nil
}

func quickSetup(_ sequence.BQ, s string) (any, error) {
	args := Args{}
	for _, token := range strings.Fields(s) {
		key, value, ok := strings.Cut(token, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid query_dashboard_mark token %q", token)
		}
		switch key {
		case "entry":
			args.Entry = value
		case "route":
			args.Route = value
		case "upstream":
			args.Upstream = value
		default:
			return nil, fmt.Errorf("unknown query_dashboard_mark key %q", key)
		}
	}
	return &Marker{args: args}, nil
}
