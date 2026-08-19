package resolvers

import (
	"context"
	"crypto/tls"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mr-karan/doggo/pkg/models"
)

// ClassicResolver represents the config options for setting up a Resolver.
type ClassicResolver struct {
	client          *dns.Client
	server          string
	resolverOptions Options
}

// ClassicResolverOpts holds options for setting up a Classic resolver.
type ClassicResolverOpts struct {
	UseTLS bool
	UseTCP bool
}

// NewClassicResolver accepts a list of nameservers and configures a DNS resolver.
func NewClassicResolver(server string, classicOpts ClassicResolverOpts, resolverOpts Options) (Resolver, error) {
	net := "udp"
	client := &dns.Client{
		Timeout: resolverOpts.Timeout,
		Net:     "udp",
		// Size the local UDP receive buffer independently of EDNS0: without
		// this, replies larger than 512 bytes to plain (non-EDNS) queries are
		// OS-truncated and fail to unpack on Unix, and fail with WSAEMSGSIZE
		// on Windows (issue #251). This only sizes the receive buffer; it adds
		// no OPT record and changes nothing on the wire.
		UDPSize: dns.DefaultMsgSize,
	}

	if classicOpts.UseTCP {
		net = "tcp"
	}

	if resolverOpts.UseIPv4 {
		net = net + "4"
	}
	if resolverOpts.UseIPv6 {
		net = net + "6"
	}

	if classicOpts.UseTLS {
		net = net + "-tls"
		// Provide extra TLS config for doing/skipping hostname verification.
		client.TLSConfig = &tls.Config{
			ServerName:         resolverOpts.TLSHostname,
			InsecureSkipVerify: resolverOpts.InsecureSkipVerify,
		}
	}

	client.Net = net

	if resolverOpts.SourceAddr != "" {
		dialer, err := sourceDialer(net, resolverOpts.SourceAddr, resolverOpts.Timeout)
		if err != nil {
			return nil, err
		}
		client.Dialer = dialer
	}

	return &ClassicResolver{
		client:          client,
		server:          server,
		resolverOptions: resolverOpts,
	}, nil
}

// query takes a dns.Question and sends them to DNS Server.
// It parses the Response from the server in a custom output format.
func (r *ClassicResolver) query(ctx context.Context, question dns.Question, flags QueryFlags) (Response, error) {
	var (
		rsp      Response
		messages = prepareMessages(question, flags, r.resolverOptions.Ndots, r.resolverOptions.SearchList)
	)
	// Several questions run concurrently against this resolver and all of
	// them share r.client, so work on a per-call copy: the truncated
	// response retry below changes the protocol (and the source dialer)
	// and must not be observed by, or race with, other questions.
	client := *r.client
	for _, msg := range messages {
		r.resolverOptions.Logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", r.resolverOptions.Ndots,
			"nameserver", r.server,
		)

		// Since the library doesn't include tcp.Dial time,
		// it's better to not rely on `rtt` provided here and calculate it ourselves.
		now := time.Now()

		in, _, err := client.ExchangeContext(ctx, &msg, r.server)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return rsp, err
			}
			return rsp, err
		}

		// In case the response size exceeds 512 bytes (can happen with lot of TXT records),
		// fallback to TCP as with UDP the response is truncated. Fallback mechanism is in-line with `dig`.
		if in.Truncated && strings.HasPrefix(client.Net, "udp") {
			// Retry the same message on a copy of the client switched to TCP.
			// The source-address dialer is typed to the original (UDP) network,
			// so rebuild it or the local address type would no longer match the
			// dialed network.
			retry := client
			switch retry.Net {
			case "udp":
				retry.Net = "tcp"
			case "udp4":
				retry.Net = "tcp4"
			case "udp6":
				retry.Net = "tcp6"
			}
			if retry.Dialer != nil {
				dialer, err := sourceDialer(retry.Net, r.resolverOptions.SourceAddr, r.resolverOptions.Timeout)
				if err != nil {
					return rsp, err
				}
				retry.Dialer = dialer
			}
			r.resolverOptions.Logger.Debug("Response truncated; retrying now", "protocol", retry.Net)
			in, _, err = retry.ExchangeContext(ctx, &msg, r.server)
			if err != nil {
				return rsp, err
			}
		}

		// Pack questions in output.
		for _, q := range msg.Question {
			ques := Question{
				Name:  q.Name,
				Class: dns.ClassToString[q.Qclass],
				Type:  models.RecordTypeString(q.Qtype),
			}
			rsp.Questions = append(rsp.Questions, ques)
		}
		rtt := time.Since(now)

		// Get the authorities and answers.
		output := parseMessage(in, rtt, r.server)
		rsp.Authorities = output.Authorities
		rsp.Answers = output.Answers
		rsp.Additional = output.Additional
		rsp.Edns = mergeEdnsInfo(rsp.Edns, output.Edns)

		if len(output.Answers) > 0 || in.Rcode == dns.RcodeSuccess {
			// Stop iterating the searchlist.
			break
		}

		// Check if context is done after each iteration
		select {
		case <-ctx.Done():
			return rsp, ctx.Err()
		default:
			// Continue to next iteration
		}
	}
	return rsp, nil
}

// Address implements the Resolver interface.
func (r *ClassicResolver) Address() string {
	return r.server
}

// Lookup implements the Resolver interface
func (r *ClassicResolver) Lookup(ctx context.Context, questions []dns.Question, flags QueryFlags) ([]Response, error) {
	return ConcurrentLookup(ctx, questions, flags, r.query, r.resolverOptions.Logger)
}
