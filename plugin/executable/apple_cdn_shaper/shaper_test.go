package apple_cdn_shaper

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", text, err)
	}
	return rr
}

func TestShapeResponseFiltersEveryNonQualifyingAddressChoice(t *testing.T) {
	prefix := netip.MustParsePrefix("2403:300:a04::/48")
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess, AuthenticatedData: true},
		Answer: []dns.RR{
			mustRR(t, "cdn.example. 60 IN CNAME edge.example."),
			mustRR(t, "edge.example. 60 IN A 192.0.2.10"),
			mustRR(t, "edge.example. 60 IN AAAA 2403:300:a04::10"),
			mustRR(t, "edge.example. 60 IN AAAA 2001:db8::10"),
			mustRR(t, "edge.example. 60 IN HTTPS 1 . mandatory=alpn,ipv4hint,ipv6hint alpn=h2 ipv4hint=192.0.2.20 ipv6hint=2403:300:a04::20,2001:db8::20"),
			&dns.RRSIG{Hdr: dns.RR_Header{Name: "edge.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeAAAA},
		},
		Extra: []dns.RR{
			mustRR(t, "edge.example. 60 IN A 192.0.2.30"),
			mustRR(t, "edge.example. 60 IN AAAA 2403:300:a04::30"),
			mustRR(t, "edge.example. 60 IN AAAA 2001:db8::30"),
			mustRR(t, "edge.example. 60 IN SVCB 1 . mandatory=ipv4hint,ipv6hint ipv4hint=192.0.2.40 ipv6hint=2403:300:a04::40,2001:db8::40"),
		},
	}

	out, changed := ShapeResponse(msg, prefix)
	if !changed {
		t.Fatal("expected qualifying mixed response to be shaped")
	}
	if out == msg {
		t.Fatal("expected shaping to return a copy")
	}
	if len(msg.Answer) != 6 || len(msg.Extra) != 4 {
		t.Fatal("input message was mutated")
	}
	if out.AuthenticatedData {
		t.Fatal("shaped response retained authenticated-data flag")
	}

	var cnameCount, aCount, rrsigCount int
	var aaaa []net.IP
	var https *dns.HTTPS
	var svcb *dns.SVCB
	for _, rr := range append(append([]dns.RR{}, out.Answer...), out.Extra...) {
		switch value := rr.(type) {
		case *dns.CNAME:
			cnameCount++
		case *dns.A:
			aCount++
		case *dns.AAAA:
			aaaa = append(aaaa, value.AAAA)
		case *dns.HTTPS:
			https = value
		case *dns.SVCB:
			svcb = value
		case *dns.RRSIG:
			rrsigCount++
		}
	}
	if cnameCount != 1 {
		t.Fatalf("CNAME count = %d, want 1", cnameCount)
	}
	if aCount != 0 {
		t.Fatalf("A count = %d, want 0", aCount)
	}
	if rrsigCount != 0 {
		t.Fatalf("RRSIG count = %d, want 0", rrsigCount)
	}
	if len(aaaa) != 2 {
		t.Fatalf("AAAA count = %d, want 2", len(aaaa))
	}
	for _, ip := range aaaa {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !prefix.Contains(addr) {
			t.Fatalf("retained non-qualifying AAAA %v", ip)
		}
	}
	if https == nil || svcb == nil {
		t.Fatal("HTTPS or SVCB record was removed")
	}

	assertFilteredServiceBindingHints(t, https.Value, "2403:300:a04::20")
	assertFilteredServiceBindingHints(t, svcb.Value, "2403:300:a04::40")
}

func assertFilteredServiceBindingHints(t *testing.T, values []dns.SVCBKeyValue, expectedIPv6 string) {
	t.Helper()
	var mandatory *dns.SVCBMandatory
	var ipv4Hint *dns.SVCBIPv4Hint
	var ipv6Hint *dns.SVCBIPv6Hint
	for _, value := range values {
		switch hint := value.(type) {
		case *dns.SVCBMandatory:
			mandatory = hint
		case *dns.SVCBIPv4Hint:
			ipv4Hint = hint
		case *dns.SVCBIPv6Hint:
			ipv6Hint = hint
		}
	}
	if ipv4Hint != nil {
		t.Fatalf("retained IPv4 hint %v", ipv4Hint.Hint)
	}
	if ipv6Hint == nil || len(ipv6Hint.Hint) != 1 || ipv6Hint.Hint[0].String() != expectedIPv6 {
		t.Fatalf("IPv6 hints = %v, want %s", ipv6Hint, expectedIPv6)
	}
	if mandatory == nil {
		t.Fatal("mandatory parameter was removed")
	}
	for _, key := range mandatory.Code {
		if key == dns.SVCB_IPV4HINT {
			t.Fatal("mandatory still requires removed ipv4hint")
		}
	}
}

func TestShapeResponseAvoidsCopyWhenEveryAddressAlreadyQualifies(t *testing.T) {
	prefix := netip.MustParsePrefix("2403:300:a04::/48")
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{
			mustRR(t, "cdn.example. 60 IN CNAME edge.example."),
			mustRR(t, "edge.example. 60 IN AAAA 2403:300:a04::10"),
			mustRR(t, "edge.example. 60 IN HTTPS 1 . alpn=h2 ipv6hint=2403:300:a04::20"),
		},
	}

	out, changed := ShapeResponse(msg, prefix)
	if changed || out != msg {
		t.Fatal("already constrained response was copied")
	}
}

func TestShapeResponseLeavesNoPrefixResponseUnchanged(t *testing.T) {
	prefix := netip.MustParsePrefix("2403:300:a04::/48")
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{
			mustRR(t, "cdn.example. 60 IN CNAME edge.example."),
			mustRR(t, "edge.example. 60 IN A 192.0.2.10"),
			mustRR(t, "edge.example. 60 IN AAAA 2001:db8::10"),
		},
	}
	want := msg.String()

	out, changed := ShapeResponse(msg, prefix)
	if changed {
		t.Fatal("response without target prefix was shaped")
	}
	if out != msg {
		t.Fatal("response without target prefix did not preserve identity")
	}
	if out.String() != want {
		t.Fatalf("response changed:\n%s", out)
	}
}

func TestShapeResponseDoesNotSynthesizeOnFailures(t *testing.T) {
	prefix := netip.MustParsePrefix("2403:300:a04::/48")
	for name, msg := range map[string]*dns.Msg{
		"nil":      nil,
		"empty":    {MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}},
		"servfail": {MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeServerFailure}},
	} {
		t.Run(name, func(t *testing.T) {
			out, changed := ShapeResponse(msg, prefix)
			if changed || out != msg {
				t.Fatalf("ShapeResponse() = (%v, %v), want unchanged", out, changed)
			}
		})
	}
}

func TestParsePrefixPolicyRequiresExactSinglePrefix(t *testing.T) {
	prefix, err := ParsePrefixPolicy(strings.NewReader("# generated\n2403:300:a04::/48\n"))
	if err != nil {
		t.Fatalf("ParsePrefixPolicy(valid): %v", err)
	}
	if got := prefix.String(); got != "2403:300:a04::/48" {
		t.Fatalf("prefix = %s", got)
	}

	for name, policy := range map[string]string{
		"empty":     "# only a comment\n",
		"malformed": "not-a-prefix\n",
		"divergent": "2403:300::/32\n",
		"multiple":  "2403:300:a04::/48\n2403:300:a04::/48\n",
		"ipv4":      "192.0.2.0/24\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePrefixPolicy(strings.NewReader(policy)); err == nil {
				t.Fatal("ParsePrefixPolicy() succeeded, want error")
			}
		})
	}
}
