package apple_cdn_shaper

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

const PluginType = "apple_cdn_shaper"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	PrefixFile string `yaml:"prefix_file"`
}

type Plugin struct {
	prefix netip.Prefix
}

var _ sequence.RecursiveExecutable = (*Plugin)(nil)

func New(args *Args) (*Plugin, error) {
	if args.PrefixFile == "" {
		return nil, fmt.Errorf("prefix_file is required")
	}
	file, err := os.Open(args.PrefixFile)
	if err != nil {
		return nil, fmt.Errorf("open prefix policy: %w", err)
	}
	defer file.Close()

	prefix, err := ParsePrefixPolicy(file)
	if err != nil {
		return nil, err
	}
	return &Plugin{prefix: prefix}, nil
}

func Init(_ *coremain.BP, value any) (any, error) {
	return New(value.(*Args))
}

func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if qCtx.R() == nil {
		if err := next.ExecNext(ctx, qCtx); err != nil {
			return err
		}
	}
	response, changed := ShapeResponse(qCtx.R(), p.prefix)
	if changed {
		qCtx.SetResponse(response)
	}
	return nil
}
