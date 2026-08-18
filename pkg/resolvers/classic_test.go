package resolvers

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestClassicResolverTruncatedRetryWithSource exercises the truncated-UDP to
// TCP fallback together with a bound source address: the retry must switch
// the client to TCP and rebuild the source dialer so its local address type
// matches the dialed network.
func TestClassicResolverTruncatedRetryWithSource(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			m.Truncated = true // force the TCP fallback
		} else {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 99),
			}}
		}
		_ = w.WriteMsg(m)
	})

	// Serve UDP and TCP on the same loopback port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := l.Addr().String()
	_, port, err := net.SplitHostPort(server)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}

	usrv := &dns.Server{PacketConn: pc, Handler: handler}
	tsrv := &dns.Server{Listener: l, Handler: handler}
	go func() { _ = usrv.ActivateAndServe() }()
	go func() { _ = tsrv.ActivateAndServe() }()
	defer usrv.Shutdown()
	defer tsrv.Shutdown()

	rslvr, err := NewClassicResolver(server, ClassicResolverOpts{}, Options{
		Timeout:    2 * time.Second,
		Logger:     discardLogger(),
		SourceAddr: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	rsp, err := rslvr.Lookup(context.Background(), []dns.Question{
		{Name: "retry.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}, QueryFlags{})
	if err != nil {
		t.Fatalf("query with source + truncation retry failed: %v", err)
	}
	if len(rsp) == 0 || len(rsp[0].Answers) == 0 {
		t.Fatal("expected answers from the TCP retry")
	}
}
