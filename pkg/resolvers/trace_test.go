package resolvers

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type traceCall struct {
	Network string
	Server  string
	Host    string
	Name    string
	Qtype   uint16
	RD      bool
	ID      uint16
}

type traceHarness struct {
	t       *testing.T
	respond func(traceCall) (*dns.Msg, time.Duration, error)
	calls   []traceCall
}

func installTraceExchange(t *testing.T, fn func(traceCall) (*dns.Msg, time.Duration, error)) *traceHarness {
	t.Helper()
	h := &traceHarness{t: t, respond: fn}
	old := traceExchange
	traceExchange = h.exchange
	t.Cleanup(func() { traceExchange = old })
	return h
}

func (h *traceHarness) exchange(_ context.Context, network, server string, msg *dns.Msg, _ string, _ time.Duration) (*dns.Msg, time.Duration, error) {
	h.t.Helper()
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		h.t.Fatalf("server %q: %v", server, err)
	}
	if net.ParseIP(host) == nil {
		h.t.Fatalf("server host %q is not an IP literal", host)
	}
	if len(msg.Question) != 1 {
		h.t.Fatalf("expected one question, got %d", len(msg.Question))
	}
	if msg.RecursionDesired {
		h.t.Fatalf("authoritative query to %s unexpectedly had RD=1", server)
	}
	if msg.Question[0].Qclass != dns.ClassINET {
		h.t.Fatalf("authoritative query to %s used non-IN class %d", server, msg.Question[0].Qclass)
	}

	call := traceCall{
		Network: network,
		Server:  server,
		Host:    host,
		Name:    msg.Question[0].Name,
		Qtype:   msg.Question[0].Qtype,
		RD:      msg.RecursionDesired,
		ID:      msg.Id,
	}
	h.calls = append(h.calls, call)
	if h.respond == nil {
		h.t.Fatalf("unexpected authoritative exchange: %+v", call)
	}
	return h.respond(call)
}

type bootstrapResolver struct {
	t         *testing.T
	calls     []dns.Question
	responses []Response
	err       error
}

func (b *bootstrapResolver) Address() string { return "bootstrap" }

func (b *bootstrapResolver) Lookup(_ context.Context, questions []dns.Question, _ QueryFlags) ([]Response, error) {
	b.t.Helper()
	b.calls = append(b.calls, questions...)
	return b.responses, b.err
}

func replyFor(req *dns.Msg, rcode int, aa, tc bool, answers, authorities, additional []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = rcode
	m.Authoritative = aa
	m.Truncated = tc
	m.Answer = answers
	m.Ns = authorities
	m.Extra = additional
	return m
}

func aRR(name, ip string) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: canonicalName(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}
}

func aaaaRR(name, ip string) dns.RR {
	return &dns.AAAA{Hdr: dns.RR_Header{Name: canonicalName(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP(ip)}
}

func nsRR(owner, target string) dns.RR {
	return &dns.NS{Hdr: dns.RR_Header{Name: canonicalName(owner), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: canonicalName(target)}
}

func cnameRR(owner, target string) dns.RR {
	return &dns.CNAME{Hdr: dns.RR_Header{Name: canonicalName(owner), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: canonicalName(target)}
}

func soaRR(owner string) dns.RR {
	owner = canonicalName(owner)
	base := strings.TrimSuffix(owner, ".")
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: owner, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns." + base + ".",
		Mbox:    "hostmaster." + base + ".",
		Serial:  1,
		Refresh: 2,
		Retry:   3,
		Expire:  4,
		Minttl:  5,
	}
}

func runTrace(t *testing.T, q dns.Question, opts TraceOptions) (TraceResult, error) {
	t.Helper()
	res, err := Trace(context.Background(), q, opts)
	return res, err
}
func TestTraceRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		q    dns.Question
		opts TraceOptions
		want string
	}{
		{
			name: "ANY question",
			q:    dns.Question{Name: "example.com.", Qtype: dns.TypeANY, Qclass: dns.ClassINET},
			want: "query type ANY",
		},
		{
			name: "invalid source",
			q:    dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			opts: TraceOptions{SourceAddr: "not-an-ip"},
			want: "invalid source address",
		},
		{
			name: "source family mismatch",
			q:    dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			opts: TraceOptions{UseIPv4: true, SourceAddr: "::1"},
			want: "does not match IPv4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := runTrace(t, tc.q, tc.opts)
			if !errors.Is(err, ErrInvalidTraceConfig) {
				t.Fatalf("Trace() error = %v, want ErrInvalidTraceConfig", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Trace() error = %q, want it to mention %q", err, tc.want)
			}
			if res.Status != TraceStatusFailed || res.Error == nil || res.Error.Code != "invalid_config" {
				t.Fatalf("result = %+v, want failed invalid_config", res)
			}
			if len(res.Hops) != 0 {
				t.Fatalf("len(Hops) = %d, want 0", len(res.Hops))
			}
		})
	}
}

func TestTraceHierarchyAndAuthoritySemantics(t *testing.T) {
	h := installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
		switch {
		case call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Server != "192.0.2.10:53" && call.Server != "192.0.2.20:53":
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("example.com.", "ns.example.com.")}, []dns.RR{aRR("ns.example.com.", "192.0.2.20")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.20:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
				[]dns.RR{aRR("www.example.com.", "93.184.216.34")}, nil, nil), 1 * time.Millisecond, nil
		default:
			t.Fatalf("unexpected exchange: %+v", call)
		}
		return nil, 0, nil
	})

	res, err := runTrace(t, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{UseIPv4: true})
	if err != nil {
		t.Fatalf("Trace() error = %v", err)
	}
	if res.SchemaVersion != TraceSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", res.SchemaVersion, TraceSchemaVersion)
	}
	if res.Status != TraceStatusComplete || res.Verdict != TraceVerdictAnswer {
		t.Fatalf("status/verdict = %s/%s, want complete/answer", res.Status, res.Verdict)
	}
	if got := len(res.Hops); got != 3 {
		t.Fatalf("len(Hops) = %d, want 3", got)
	}
	if res.Hops[0].Role != TraceRoleRoot || res.Hops[0].Outcome != TraceOutcomeReferral || res.Hops[0].Zone != "." {
		t.Fatalf("root hop = %+v", res.Hops[0])
	}
	if res.Hops[1].Role != TraceRoleDelegation || res.Hops[1].Outcome != TraceOutcomeReferral || res.Hops[1].Zone != "com." {
		t.Fatalf("TLD hop = %+v", res.Hops[1])
	}
	if res.Hops[2].Role != TraceRoleAuthoritative || res.Hops[2].Outcome != TraceOutcomeAnswer || res.Hops[2].Zone != "example.com." {
		t.Fatalf("zone hop = %+v", res.Hops[2])
	}
	if len(res.Hops[2].Answers) != 1 || res.Hops[2].Answers[0].Data != "93.184.216.34" {
		t.Fatalf("final answer = %+v", res.Hops[2].Answers)
	}
	if len(h.calls) != 3 {
		t.Fatalf("traceExchange calls = %d, want 3", len(h.calls))
	}
	for _, call := range h.calls {
		if call.RD {
			t.Fatalf("call had RD=1: %+v", call)
		}
		if net.ParseIP(call.Host) == nil {
			t.Fatalf("call host is not IP literal: %+v", call)
		}
	}
}

func TestTraceFailoverAndTcpRetry(t *testing.T) {
	t.Run("dead_first_failover", func(t *testing.T) {
		h := installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			switch {
			case call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Server != "192.0.2.10:53" && call.Server != "192.0.2.20:53" && call.Server != "192.0.2.21:53":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("example.com.", "a.example.com."), nsRR("example.com.", "b.example.com.")},
					[]dns.RR{aRR("a.example.com.", "192.0.2.20"), aRR("b.example.com.", "192.0.2.21")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.20:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return nil, 0, context.DeadlineExceeded
			case call.Server == "192.0.2.21:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
					[]dns.RR{aRR("www.example.com.", "93.184.216.34")}, nil, nil), 1 * time.Millisecond, nil
			default:
				t.Fatalf("unexpected exchange: %+v", call)
			}
			return nil, 0, nil
		})

		res, err := runTrace(t, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{UseIPv4: true})
		if err != nil {
			t.Fatalf("Trace() error = %v", err)
		}
		if got := len(res.Hops); got != 3 {
			t.Fatalf("len(Hops) = %d, want 3", got)
		}
		if got := len(res.Hops[2].Attempts); got != 2 {
			t.Fatalf("final hop attempts = %d, want 2", got)
		}
		if res.Hops[2].Attempts[0].Error == nil || res.Hops[2].Attempts[0].Error.Code != "timeout" {
			t.Fatalf("first attempt error = %+v, want timeout", res.Hops[2].Attempts[0].Error)
		}
		if res.Hops[2].Attempts[1].IP != "192.0.2.21" {
			t.Fatalf("second attempt IP = %q, want 192.0.2.21", res.Hops[2].Attempts[1].IP)
		}
		if len(h.calls) != 4 {
			t.Fatalf("traceExchange calls = %d, want 4", len(h.calls))
		}
	})

	t.Run("truncation_tcp_retry", func(t *testing.T) {
		h := installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			switch {
			case call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Server != "192.0.2.10:53" && call.Server != "192.0.2.20:53":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("example.com.", "ns.example.com.")}, []dns.RR{aRR("ns.example.com.", "192.0.2.20")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.20:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Network == "udp4":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, true, nil, nil, nil), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.20:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Network == "tcp4":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
					[]dns.RR{aRR("www.example.com.", "93.184.216.34")}, nil, nil), 1 * time.Millisecond, nil
			default:
				t.Fatalf("unexpected exchange: %+v", call)
			}
			return nil, 0, nil
		})

		res, err := runTrace(t, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{UseIPv4: true})
		if err != nil {
			t.Fatalf("Trace() error = %v", err)
		}
		if got := len(res.Hops[2].Attempts); got != 2 {
			t.Fatalf("final hop attempts = %d, want 2", got)
		}
		if res.Hops[2].Attempts[0].Protocol != "udp" || res.Hops[2].Attempts[1].Protocol != "tcp" {
			t.Fatalf("attempt protocols = %q/%q, want udp/tcp", res.Hops[2].Attempts[0].Protocol, res.Hops[2].Attempts[1].Protocol)
		}
		if res.Hops[2].Attempts[0].RCode != "NOERROR" || !res.Hops[2].Attempts[0].Truncated {
			t.Fatalf("UDP attempt = %+v, want NOERROR with truncated=true", res.Hops[2].Attempts[0])
		}
		if h.calls[2].ID != h.calls[3].ID {
			t.Fatalf("UDP/TCP retry IDs differ: %d vs %d", h.calls[2].ID, h.calls[3].ID)
		}
	})
}

func TestTraceIterativeAddressResolutionWithoutGlue(t *testing.T) {
	h := installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
		switch {
		case call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Server != "192.0.2.10:53" && call.Server != "192.0.2.20:53" && call.Server != "192.0.2.30:53":
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
			// The parent includes an out-of-bailiwick address. It must not be
			// trusted as glue; the tracer resolves ns.example.net iteratively.
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("example.com.", "ns.example.net.")}, []dns.RR{aRR("ns.example.net.", "192.0.2.99")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.99:53":
			t.Fatalf("tracer dialed untrusted out-of-bailiwick Additional data: %+v", call)
		case call.Name == "ns.example.net." && call.Qtype == dns.TypeA && call.Server != "192.0.2.30:53":
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
				nil, []dns.RR{nsRR("net.", "ns.net.")}, []dns.RR{aRR("ns.net.", "192.0.2.30")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.30:53" && call.Name == "ns.example.net." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
				[]dns.RR{aRR("ns.example.net.", "192.0.2.30")}, nil, nil), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.30:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
				[]dns.RR{aRR("www.example.com.", "93.184.216.34")}, nil, nil), 1 * time.Millisecond, nil
		default:
			t.Fatalf("unexpected exchange: %+v", call)
		}
		return nil, 0, nil
	})

	res, err := runTrace(t, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{UseIPv4: true})
	if err != nil {
		t.Fatalf("Trace() error = %v", err)
	}
	if len(h.calls) != 5 {
		t.Fatalf("traceExchange calls = %d, want 5", len(h.calls))
	}
	if h.calls[2].Name != "ns.example.net." || h.calls[2].Qtype != dns.TypeA {
		t.Fatalf("internal address-resolution call = %+v, want ns.example.net. A", h.calls[2])
	}
	if got := res.Hops[1].Delegation.Nameservers[0].Addresses; !reflect.DeepEqual(got, []string{"192.0.2.30"}) {
		t.Fatalf("delegation addresses = %#v, want [192.0.2.30]", got)
	}
	if res.Hops[2].Answers[0].Data != "93.184.216.34" {
		t.Fatalf("final answer = %+v", res.Hops[2].Answers)
	}
}

func TestTraceTerminalNegatives(t *testing.T) {
	t.Run("nxdomain", func(t *testing.T) {
		installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			switch {
			case call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Server != "192.0.2.10:53" && call.Server != "192.0.2.20:53":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("example.com.", "ns.example.com.")}, []dns.RR{aRR("ns.example.com.", "192.0.2.20")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.20:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeNameError, true, false,
					nil, []dns.RR{soaRR("example.com.")}, nil), 1 * time.Millisecond, nil
			default:
				t.Fatalf("unexpected exchange: %+v", call)
			}
			return nil, 0, nil
		})

		res, err := runTrace(t, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{UseIPv4: true})
		if err != nil {
			t.Fatalf("Trace() error = %v", err)
		}
		if res.Status != TraceStatusComplete || res.Verdict != TraceVerdictNXDOMAIN {
			t.Fatalf("status/verdict = %s/%s, want complete/nxdomain", res.Status, res.Verdict)
		}
		if res.Error != nil {
			t.Fatalf("unexpected trace error: %+v", res.Error)
		}
	})

	t.Run("nodata", func(t *testing.T) {
		installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			switch {
			case call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Server != "192.0.2.10:53" && call.Server != "192.0.2.20:53":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("example.com.", "ns.example.com.")}, []dns.RR{aRR("ns.example.com.", "192.0.2.20")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.20:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
					nil, []dns.RR{soaRR("example.com.")}, nil), 1 * time.Millisecond, nil
			default:
				t.Fatalf("unexpected exchange: %+v", call)
			}
			return nil, 0, nil
		})

		res, err := runTrace(t, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{UseIPv4: true})
		if err != nil {
			t.Fatalf("Trace() error = %v", err)
		}
		if res.Status != TraceStatusComplete || res.Verdict != TraceVerdictNODATA {
			t.Fatalf("status/verdict = %s/%s, want complete/nodata", res.Status, res.Verdict)
		}
		if res.Error != nil {
			t.Fatalf("unexpected trace error: %+v", res.Error)
		}
	})
}

func TestTraceCNAMERestart(t *testing.T) {
	h := installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
		switch {
		case call.Name == "www.example.com." && call.Qtype == dns.TypeA && call.Server != "192.0.2.10:53" && call.Server != "192.0.2.20:53" && call.Server != "192.0.2.30:53" && call.Server != "192.0.2.40:53":
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("example.com.", "ns.example.com.")}, []dns.RR{aRR("ns.example.com.", "192.0.2.20")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.20:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
				[]dns.RR{cnameRR("www.example.com.", "target.example.net.")}, nil, nil), 1 * time.Millisecond, nil
		case call.Name == "target.example.net." && call.Qtype == dns.TypeA && call.Server != "192.0.2.30:53" && call.Server != "192.0.2.40:53":
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("net.", "ns.net.")}, []dns.RR{aRR("ns.net.", "192.0.2.30")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.30:53" && call.Name == "target.example.net." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("example.net.", "ns.example.net.")}, []dns.RR{aRR("ns.example.net.", "192.0.2.40")}), 1 * time.Millisecond, nil
		case call.Server == "192.0.2.40:53" && call.Name == "target.example.net." && call.Qtype == dns.TypeA:
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
				[]dns.RR{aRR("target.example.net.", "203.0.113.42")}, nil, nil), 1 * time.Millisecond, nil
		default:
			t.Fatalf("unexpected exchange: %+v", call)
		}
		return nil, 0, nil
	})

	res, err := runTrace(t, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{UseIPv4: true})
	if err != nil {
		t.Fatalf("Trace() error = %v", err)
	}
	if got := len(res.Hops); got != 6 {
		t.Fatalf("len(Hops) = %d, want 6", got)
	}
	if res.Hops[2].Outcome != TraceOutcomeCNAME || len(res.Hops[2].Answers) != 1 || res.Hops[2].Answers[0].Type != "CNAME" {
		t.Fatalf("CNAME hop = %+v", res.Hops[2])
	}
	if res.Hops[3].Zone != "." || res.Hops[4].Zone != "net." || res.Hops[5].Zone != "example.net." {
		t.Fatalf("post-CNAME restart hops = %+v %+v %+v", res.Hops[3], res.Hops[4], res.Hops[5])
	}
	if res.Hops[5].Answers[0].Data != "203.0.113.42" {
		t.Fatalf("final answer = %+v", res.Hops[5].Answers)
	}
	if len(h.calls) != 6 {
		t.Fatalf("traceExchange calls = %d, want 6", len(h.calls))
	}
}

func TestTraceReferralErrors(t *testing.T) {
	t.Run("non_authoritative_answer_is_not_terminal", func(t *testing.T) {
		boot := &bootstrapResolver{
			t: t,
			responses: []Response{{
				Answers:    []Answer{{Name: ".", Type: "NS", Address: "a.root-servers.net."}},
				Additional: []Answer{{Name: "a.root-servers.net.", Address: "203.0.113.10"}},
			}},
		}
		installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				[]dns.RR{aRR("www.example.com.", "203.0.113.42")}, nil, nil), time.Millisecond, nil
		})

		res, err := Trace(context.Background(), dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{Bootstrap: boot, UseIPv4: true})
		if err == nil {
			t.Fatal("Trace() accepted a non-authoritative cached answer")
		}
		var terr *TraceError
		if !errors.As(err, &terr) || terr.Code != "lame_delegation" {
			t.Fatalf("err = %v, want lame_delegation", err)
		}
		if res.Status != TraceStatusPartial || res.Verdict != TraceVerdictError {
			t.Fatalf("result status/verdict = %s/%s, want partial/error", res.Status, res.Verdict)
		}
	})

	t.Run("malformed_referral", func(t *testing.T) {
		boot := &bootstrapResolver{
			t: t,
			responses: []Response{{
				Answers:    []Answer{{Name: ".", Type: "NS", Address: "a.root-servers.net."}},
				Additional: []Answer{{Name: "a.root-servers.net.", Address: "203.0.113.10"}},
			}},
		}
		installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			if call.Server != "203.0.113.10:53" {
				t.Fatalf("unexpected server: %+v", call)
			}
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
				nil, []dns.RR{nsRR("example.org.", "ns.example.org.")}, nil), 1 * time.Millisecond, nil
		})

		res, err := Trace(context.Background(), dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{Bootstrap: boot, UseIPv4: true})
		if err == nil {
			t.Fatal("Trace() error = nil, want malformed_referral")
		}
		var terr *TraceError
		if !errors.As(err, &terr) || terr.Code != "malformed_referral" {
			t.Fatalf("err = %v, want malformed_referral", err)
		}
		if res.Status != TraceStatusPartial || res.Error == nil || res.Error.Code != "malformed_referral" {
			t.Fatalf("result = %+v", res)
		}
	})

	t.Run("lame_delegation", func(t *testing.T) {
		boot := &bootstrapResolver{
			t: t,
			responses: []Response{{
				Answers:    []Answer{{Name: ".", Type: "NS", Address: "a.root-servers.net."}},
				Additional: []Answer{{Name: "a.root-servers.net.", Address: "203.0.113.10"}},
			}},
		}
		installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			if call.Server != "203.0.113.10:53" {
				t.Fatalf("unexpected server: %+v", call)
			}
			return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false, nil, nil, nil), 1 * time.Millisecond, nil
		})

		res, err := Trace(context.Background(), dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{Bootstrap: boot, UseIPv4: true})
		if err == nil {
			t.Fatal("Trace() error = nil, want lame_delegation")
		}
		var terr *TraceError
		if !errors.As(err, &terr) || terr.Code != "lame_delegation" {
			t.Fatalf("err = %v, want lame_delegation", err)
		}
		if res.Status != TraceStatusPartial || res.Error == nil || res.Error.Code != "lame_delegation" {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestTraceBootstrapAndAddressFamilyFiltering(t *testing.T) {
	t.Run("bootstrap_custom_root_address", func(t *testing.T) {
		boot := &bootstrapResolver{
			t: t,
			responses: []Response{{
				Answers:    []Answer{{Name: ".", Type: "NS", Address: "a.root-servers.net."}},
				Additional: []Answer{{Name: "a.root-servers.net.", Address: "203.0.113.99"}},
			}},
		}
		h := installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			switch {
			case call.Server == "203.0.113.99:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.10:53" && call.Name == "www.example.com." && call.Qtype == dns.TypeA:
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
					[]dns.RR{aRR("www.example.com.", "93.184.216.34")}, nil, nil), 1 * time.Millisecond, nil
			default:
				t.Fatalf("unexpected exchange: %+v", call)
			}
			return nil, 0, nil
		})

		res, err := Trace(context.Background(), dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{Bootstrap: boot, UseIPv4: true})
		if err != nil {
			t.Fatalf("Trace() error = %v", err)
		}
		if len(boot.calls) != 1 || boot.calls[0].Name != "." || boot.calls[0].Qtype != dns.TypeNS {
			t.Fatalf("bootstrap lookup = %+v", boot.calls)
		}
		if len(h.calls) == 0 || h.calls[0].Host != "203.0.113.99" {
			t.Fatalf("first authoritative call = %+v", h.calls)
		}
		if res.Hops[0].Attempts[0].IP != "203.0.113.99" {
			t.Fatalf("root hop = %+v", res.Hops[0].Attempts)
		}
	})

	t.Run("ipv4_filter", func(t *testing.T) {
		boot := &bootstrapResolver{
			t: t,
			responses: []Response{{
				Answers:    []Answer{{Name: ".", Type: "NS", Address: "a.root-servers.net."}},
				Additional: []Answer{{Name: "a.root-servers.net.", Address: "198.41.0.4"}, {Name: "a.root-servers.net.", Address: "2001:503:ba3e::2:30"}},
			}},
		}
		installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			if call.Network != "udp4" {
				t.Fatalf("expected udp4 network, got %+v", call)
			}
			switch {
			case call.Name == "www.example.com." && call.Server != "192.0.2.10:53":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10"), aaaaRR("ns.com.", "2001:db8::10")}), 1 * time.Millisecond, nil
			case call.Server == "192.0.2.10:53" && call.Name == "www.example.com.":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
					[]dns.RR{aRR("www.example.com.", "93.184.216.34")}, nil, nil), 1 * time.Millisecond, nil
			default:
				t.Fatalf("unexpected exchange: %+v", call)
			}
			return nil, 0, nil
		})

		res, err := Trace(context.Background(), dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{Bootstrap: boot, UseIPv4: true})
		if err != nil {
			t.Fatalf("Trace() error = %v", err)
		}
		if got := res.Hops[0].Delegation.Nameservers[0].Addresses; !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
			t.Fatalf("delegation addresses = %#v, want [192.0.2.10]", got)
		}
		if res.Hops[1].Attempts[0].IP != "192.0.2.10" {
			t.Fatalf("second hop attempts = %+v", res.Hops[1].Attempts)
		}
	})

	t.Run("ipv6_filter", func(t *testing.T) {
		boot := &bootstrapResolver{
			t: t,
			responses: []Response{{
				Answers:    []Answer{{Name: ".", Type: "NS", Address: "a.root-servers.net."}},
				Additional: []Answer{{Name: "a.root-servers.net.", Address: "198.41.0.4"}, {Name: "a.root-servers.net.", Address: "2001:503:ba3e::2:30"}},
			}},
		}
		installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			if call.Network != "udp6" {
				t.Fatalf("expected udp6 network, got %+v", call)
			}
			switch {
			case call.Name == "www.example.com." && call.Server != "[2001:db8::10]:53":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, false, false,
					nil, []dns.RR{nsRR("com.", "ns.com.")}, []dns.RR{aRR("ns.com.", "192.0.2.10"), aaaaRR("ns.com.", "2001:db8::10")}), 1 * time.Millisecond, nil
			case call.Server == "[2001:db8::10]:53" && call.Name == "www.example.com.":
				return replyFor(&dns.Msg{Question: []dns.Question{{Name: call.Name, Qtype: call.Qtype, Qclass: dns.ClassINET}}}, dns.RcodeSuccess, true, false,
					[]dns.RR{aRR("www.example.com.", "93.184.216.34")}, nil, nil), 1 * time.Millisecond, nil
			default:
				t.Fatalf("unexpected exchange: %+v", call)
			}
			return nil, 0, nil
		})

		res, err := Trace(context.Background(), dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{Bootstrap: boot, UseIPv6: true})
		if err != nil {
			t.Fatalf("Trace() error = %v", err)
		}
		if got := res.Hops[0].Delegation.Nameservers[0].Addresses; !reflect.DeepEqual(got, []string{"2001:db8::10"}) {
			t.Fatalf("delegation addresses = %#v, want [2001:db8::10]", got)
		}
		if res.Hops[1].Attempts[0].IP != "2001:db8::10" {
			t.Fatalf("second hop attempts = %+v", res.Hops[1].Attempts)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		boot := &bootstrapResolver{
			t: t,
			responses: []Response{{
				Answers:    []Answer{{Name: ".", Type: "NS", Address: "a.root-servers.net."}},
				Additional: []Answer{{Name: "a.root-servers.net.", Address: "203.0.113.10"}},
			}},
		}
		h := installTraceExchange(t, func(call traceCall) (*dns.Msg, time.Duration, error) {
			if call.Server != "203.0.113.10:53" {
				t.Fatalf("unexpected server: %+v", call)
			}
			return nil, 0, context.DeadlineExceeded
		})

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		res, err := Trace(ctx, dns.Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, TraceOptions{Bootstrap: boot, UseIPv4: true})
		if err == nil {
			t.Fatal("Trace() error = nil, want timeout")
		}
		var terr *TraceError
		if !errors.As(err, &terr) || terr.Code != "timeout" {
			t.Fatalf("err = %v, want timeout", err)
		}
		if res.Status != TraceStatusPartial || res.Error == nil || res.Error.Code != "timeout" {
			t.Fatalf("result = %+v", res)
		}
		if len(h.calls) != 1 {
			t.Fatalf("traceExchange calls = %d, want 1", len(h.calls))
		}
	})
}
