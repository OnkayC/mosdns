package apple_cdn_shaper

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

const APPLE_ASN_IPV6_CIDR = "2403:300::/32"

var requiredPrefix = netip.MustParsePrefix(APPLE_ASN_IPV6_CIDR)

// ParsePrefixPolicy accepts the generated MosDNS prefix artifact and rejects
// empty, malformed, multiple, or divergent policy values.
func ParsePrefixPolicy(r io.Reader) (netip.Prefix, error) {
	scanner := bufio.NewScanner(r)
	var values []string
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line != "" {
			values = append(values, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return netip.Prefix{}, fmt.Errorf("read prefix policy: %w", err)
	}
	if len(values) != 1 {
		return netip.Prefix{}, fmt.Errorf("prefix policy must contain exactly one value, got %d", len(values))
	}

	prefix, err := netip.ParsePrefix(values[0])
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse prefix policy %q: %w", values[0], err)
	}
	if prefix != requiredPrefix {
		return netip.Prefix{}, fmt.Errorf("prefix policy must be %s, got %s", requiredPrefix, prefix)
	}
	return prefix, nil
}
