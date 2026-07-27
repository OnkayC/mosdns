package apple_cdn_shaper

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// ShapeResponse returns a filtered copy only when the response contains both
// an address in prefix and another selectable address outside the contract.
// Responses without a qualifying address, and responses already constrained
// to prefix, are returned unchanged.
func ShapeResponse(msg *dns.Msg, prefix netip.Prefix) (*dns.Msg, bool) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || !prefix.IsValid() || !prefix.Addr().Is6() {
		return msg, false
	}
	prefix = prefix.Masked()

	state := addressChoiceState{}
	state.inspectRecords(msg.Answer, prefix)
	state.inspectRecords(msg.Extra, prefix)
	if !state.qualifying || !state.conflicting {
		return msg, false
	}

	out := msg.Copy()
	out.AuthenticatedData = false
	out.Answer = filterRecords(out.Answer, prefix)
	out.Ns = removeSignatures(out.Ns)
	out.Extra = filterRecords(out.Extra, prefix)
	return out, true
}

type addressChoiceState struct {
	qualifying  bool
	conflicting bool
}

func (s *addressChoiceState) inspectRecords(records []dns.RR, prefix netip.Prefix) {
	for _, rr := range records {
		switch value := rr.(type) {
		case *dns.A:
			s.conflicting = true
		case *dns.AAAA:
			s.inspectIP(value.AAAA, prefix)
		case *dns.SVCB:
			s.inspectServiceBinding(value.Value, prefix)
		case *dns.HTTPS:
			s.inspectServiceBinding(value.Value, prefix)
		}
	}
}

func (s *addressChoiceState) inspectServiceBinding(values []dns.SVCBKeyValue, prefix netip.Prefix) {
	for _, value := range values {
		switch hint := value.(type) {
		case *dns.SVCBIPv4Hint:
			if len(hint.Hint) > 0 {
				s.conflicting = true
			}
		case *dns.SVCBIPv6Hint:
			for _, ip := range hint.Hint {
				s.inspectIP(ip, prefix)
			}
		}
	}
}

func (s *addressChoiceState) inspectIP(ip net.IP, prefix netip.Prefix) {
	if containsIP(prefix, ip) {
		s.qualifying = true
	} else {
		s.conflicting = true
	}
}

func containsIP(prefix netip.Prefix, ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && prefix.Contains(addr)
}

func filterRecords(records []dns.RR, prefix netip.Prefix) []dns.RR {
	filtered := records[:0]
	for _, rr := range records {
		switch value := rr.(type) {
		case *dns.A, *dns.RRSIG:
			continue
		case *dns.AAAA:
			if !containsIP(prefix, value.AAAA) {
				continue
			}
		case *dns.SVCB:
			value.Value = filterSVCBValues(value.Value, prefix)
		case *dns.HTTPS:
			value.Value = filterSVCBValues(value.Value, prefix)
		}
		filtered = append(filtered, rr)
	}
	return filtered
}

func removeSignatures(records []dns.RR) []dns.RR {
	filtered := records[:0]
	for _, rr := range records {
		if _, ok := rr.(*dns.RRSIG); !ok {
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

func filterSVCBValues(values []dns.SVCBKeyValue, prefix netip.Prefix) []dns.SVCBKeyValue {
	removedIPv4Hint := false
	removedIPv6Hint := false
	for _, value := range values {
		switch hint := value.(type) {
		case *dns.SVCBIPv4Hint:
			removedIPv4Hint = true
		case *dns.SVCBIPv6Hint:
			qualifying := hint.Hint[:0]
			for _, ip := range hint.Hint {
				if containsIP(prefix, ip) {
					qualifying = append(qualifying, ip)
				}
			}
			hint.Hint = qualifying
			removedIPv6Hint = len(qualifying) == 0
		}
	}

	filtered := values[:0]
	for _, value := range values {
		switch item := value.(type) {
		case *dns.SVCBMandatory:
			codes := item.Code[:0]
			for _, code := range item.Code {
				if (code == dns.SVCB_IPV4HINT && removedIPv4Hint) || (code == dns.SVCB_IPV6HINT && removedIPv6Hint) {
					continue
				}
				codes = append(codes, code)
			}
			if len(codes) == 0 {
				continue
			}
			item.Code = codes
		case *dns.SVCBIPv4Hint:
			continue
		case *dns.SVCBIPv6Hint:
			if len(item.Hint) == 0 {
				continue
			}
		}
		filtered = append(filtered, value)
	}
	return filtered
}
