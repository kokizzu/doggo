package resolvers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mr-karan/doggo/pkg/models"
)

const (
	TraceSchemaVersion = 1

	maxTraceHops      = 32
	maxTraceExchanges = 64
	maxTraceCNAMEs    = 8
	defaultTracePort  = "53"
	defaultTraceWait  = 5 * time.Second
)

// ErrInvalidTraceConfig identifies trace questions and options that are
// rejected before any DNS exchange.
var ErrInvalidTraceConfig = errors.New("invalid trace configuration")

type TraceStatus string

type TraceVerdict string

type TraceOutcome string

type TraceRole string

const (
	TraceStatusComplete TraceStatus = "complete"
	TraceStatusPartial  TraceStatus = "partial"
	TraceStatusFailed   TraceStatus = "failed"
)

const (
	TraceVerdictAnswer   TraceVerdict = "answer"
	TraceVerdictNXDOMAIN TraceVerdict = "nxdomain"
	TraceVerdictNODATA   TraceVerdict = "nodata"
	TraceVerdictError    TraceVerdict = "error"
)

const (
	TraceOutcomeReferral TraceOutcome = "referral"
	TraceOutcomeAnswer   TraceOutcome = "answer"
	TraceOutcomeCNAME    TraceOutcome = "cname"
	TraceOutcomeNXDOMAIN TraceOutcome = "nxdomain"
	TraceOutcomeNODATA   TraceOutcome = "nodata"
	TraceOutcomeError    TraceOutcome = "error"
)

const (
	TraceRoleRoot          TraceRole = "root"
	TraceRoleDelegation    TraceRole = "delegation"
	TraceRoleAuthoritative TraceRole = "authoritative"
)

type TraceOptions struct {
	Bootstrap  Resolver
	Flags      QueryFlags
	UseIPv4    bool
	UseIPv6    bool
	SourceAddr string
	Timeout    time.Duration
}

type TraceResult struct {
	SchemaVersion int           `json:"schema_version"`
	Query         TraceQuestion `json:"query"`
	Status        TraceStatus   `json:"status"`
	Verdict       TraceVerdict  `json:"verdict"`
	Hops          []TraceHop    `json:"hops,omitempty"`
	Summary       TraceSummary  `json:"summary"`
	Error         *TraceError   `json:"error,omitempty"`
}

type TraceQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type TraceSummary struct {
	HopCount   int   `json:"hop_count"`
	TotalRTTMS int64 `json:"total_rtt_ms"`
}

type TraceHop struct {
	Number      int              `json:"number"`
	Zone        string           `json:"zone"`
	Role        TraceRole        `json:"role"`
	Attempts    []TraceAttempt   `json:"attempts,omitempty"`
	Delegation  *TraceDelegation `json:"delegation,omitempty"`
	Answers     []TraceRecord    `json:"answers,omitempty"`
	Authorities []TraceRecord    `json:"authorities,omitempty"`
	Additional  []TraceRecord    `json:"additional,omitempty"`
	Outcome     TraceOutcome     `json:"outcome"`
}

type TraceAttempt struct {
	Nameserver string      `json:"nameserver,omitempty"`
	IP         string      `json:"ip,omitempty"`
	Protocol   string      `json:"protocol,omitempty"`
	RTTMS      int64       `json:"rtt_ms"`
	RCode      string      `json:"rcode,omitempty"`
	Truncated  bool        `json:"truncated,omitempty"`
	Error      *TraceError `json:"error,omitempty"`
}

type TraceDelegation struct {
	Child       string            `json:"child"`
	Nameservers []TraceNameserver `json:"nameservers,omitempty"`
}

type TraceNameserver struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses,omitempty"`
}

type TraceRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

type TraceError struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

func (e *TraceError) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

type traceNameserverState struct {
	name  string
	addrs []netip.Addr
	view  *TraceNameserver
}

type traceStep struct {
	Attempts    []TraceAttempt
	Answers     []TraceRecord
	Authorities []TraceRecord
	Additional  []TraceRecord
	Outcome     TraceOutcome
	Delegation  *TraceDelegation
	NextZone    string
	NextNS      []traceNameserverState
	AliasTarget string
	AnswerIPs   []netip.Addr
}

type tracer struct {
	opts        TraceOptions
	question    dns.Question
	result      TraceResult
	timeout     time.Duration
	source      netip.Addr
	zoneCache   map[string][]traceNameserverState
	resolvingNS map[string]bool
	exchanges   int
	aliases     int
	aliasSeen   map[string]bool
}

var traceExchange = defaultTraceExchange

func Trace(ctx context.Context, question dns.Question, opts TraceOptions) (TraceResult, error) {
	tr, err := newTracer(question, opts)
	if err != nil {
		return traceFailureResult(question, err), err
	}

	roots, terr := tr.primeRoots(ctx)
	if terr != nil {
		return tr.finish(terr), terr
	}
	tr.zoneCache["."] = roots

	if terr := tr.resolveVisible(ctx); terr != nil {
		return tr.finish(terr), terr
	}
	return tr.finish(nil), nil
}

func newTracer(question dns.Question, opts TraceOptions) (*tracer, error) {
	q, err := normalizeTraceQuestion(question)
	if err != nil {
		return nil, err
	}
	if opts.UseIPv4 && opts.UseIPv6 {
		return nil, fmt.Errorf("%w: trace supports at most one address-family filter", ErrInvalidTraceConfig)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTraceWait
	}

	source, err := parseSourceAddr(opts.SourceAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTraceConfig, err)
	}
	if source.IsValid() {
		source = source.Unmap()
		if opts.UseIPv4 && !source.Is4() {
			return nil, fmt.Errorf("%w: source address family does not match IPv4 trace filter", ErrInvalidTraceConfig)
		}
		if opts.UseIPv6 && !source.Is6() {
			return nil, fmt.Errorf("%w: source address family does not match IPv6 trace filter", ErrInvalidTraceConfig)
		}
	}

	tr := &tracer{
		opts:        opts,
		question:    q,
		timeout:     timeout,
		source:      source,
		zoneCache:   make(map[string][]traceNameserverState),
		resolvingNS: make(map[string]bool),
		aliasSeen:   map[string]bool{canonicalName(q.Name): true},
		result: TraceResult{
			SchemaVersion: TraceSchemaVersion,
			Query: TraceQuestion{
				Name:  q.Name,
				Type:  models.RecordTypeString(q.Qtype),
				Class: dns.Class(q.Qclass).String(),
			},
			Verdict: TraceVerdictError,
			Status:  TraceStatusFailed,
		},
	}
	return tr, nil
}

func traceFailureResult(question dns.Question, err error) TraceResult {
	q := dns.Question{Name: canonicalName(question.Name), Qtype: question.Qtype, Qclass: question.Qclass}
	if q.Qclass == 0 {
		q.Qclass = dns.ClassINET
	}
	return TraceResult{
		SchemaVersion: TraceSchemaVersion,
		Query: TraceQuestion{
			Name:  canonicalName(q.Name),
			Type:  models.RecordTypeString(q.Qtype),
			Class: dns.Class(q.Qclass).String(),
		},
		Status:  TraceStatusFailed,
		Verdict: TraceVerdictError,
		Error:   asTraceError(err, "network"),
		Summary: TraceSummary{},
	}
}

func normalizeTraceQuestion(q dns.Question) (dns.Question, error) {
	if q.Qclass == 0 {
		q.Qclass = dns.ClassINET
	}
	if q.Qclass != dns.ClassINET {
		return dns.Question{}, fmt.Errorf("%w: trace supports only class IN", ErrInvalidTraceConfig)
	}
	if q.Qtype == 0 {
		q.Qtype = dns.TypeA
	}
	if q.Qtype == dns.TypeANY {
		return dns.Question{}, fmt.Errorf("%w: trace does not support query type ANY", ErrInvalidTraceConfig)
	}
	q.Name = canonicalName(q.Name)
	return q, nil
}

func (t *tracer) finish(err error) TraceResult {
	t.result.Summary.HopCount = len(t.result.Hops)
	var totalRTT int64
	for _, hop := range t.result.Hops {
		for _, attempt := range hop.Attempts {
			totalRTT += attempt.RTTMS
		}
	}
	t.result.Summary.TotalRTTMS = totalRTT

	if err == nil {
		t.result.Status = TraceStatusComplete
		if t.result.Verdict == "" {
			t.result.Verdict = TraceVerdictAnswer
		}
		t.result.Error = nil
		return t.result
	}

	terr := asTraceError(err, "network")
	t.result.Error = terr
	t.result.Verdict = TraceVerdictError
	if len(t.result.Hops) > 0 {
		t.result.Status = TraceStatusPartial
	} else {
		t.result.Status = TraceStatusFailed
	}
	return t.result
}

func (t *tracer) resolveVisible(ctx context.Context) *TraceError {
	current := t.question
	zone := "."
	ns := t.zoneCache[zone]
	visitedZones := map[string]bool{zone: true}

	for {
		if len(t.result.Hops) >= maxTraceHops {
			return traceErr("max_hops", fmt.Sprintf("trace exceeded %d visible hops", maxTraceHops))
		}

		step, terr := t.step(ctx, zone, ns, current)
		hop := TraceHop{
			Number:      len(t.result.Hops) + 1,
			Zone:        zone,
			Role:        traceRoleFor(zone, step.Outcome),
			Attempts:    step.Attempts,
			Delegation:  step.Delegation,
			Answers:     step.Answers,
			Authorities: step.Authorities,
			Additional:  step.Additional,
			Outcome:     step.Outcome,
		}
		if hop.Role == "" {
			hop.Role = traceRoleFor(zone, TraceOutcomeError)
		}
		t.result.Hops = append(t.result.Hops, hop)

		if terr != nil {
			return terr
		}

		switch step.Outcome {
		case TraceOutcomeReferral:
			if step.NextZone == "" {
				return traceErr("malformed_referral", "referral missing child zone")
			}
			if visitedZones[step.NextZone] {
				return traceErr("referral_loop", fmt.Sprintf("referral loop detected at %s", step.NextZone))
			}
			visitedZones[step.NextZone] = true
			zone = step.NextZone
			ns = step.NextNS
		case TraceOutcomeAnswer:
			t.result.Verdict = TraceVerdictAnswer
			return nil
		case TraceOutcomeNXDOMAIN:
			t.result.Verdict = TraceVerdictNXDOMAIN
			return nil
		case TraceOutcomeNODATA:
			t.result.Verdict = TraceVerdictNODATA
			return nil
		case TraceOutcomeCNAME:
			if step.AliasTarget == "" {
				return traceErr("cname_loop", "alias response missing target")
			}
			if t.aliasSeen[step.AliasTarget] {
				return traceErr("cname_loop", fmt.Sprintf("alias cycle detected at %s", step.AliasTarget))
			}
			t.aliases++
			if t.aliases > maxTraceCNAMEs {
				return traceErr("cname_loop", fmt.Sprintf("trace exceeded %d aliases", maxTraceCNAMEs))
			}
			t.aliasSeen[step.AliasTarget] = true
			current.Name = step.AliasTarget
			if dns.IsSubDomain(zone, step.AliasTarget) {
				continue
			}
			zone, ns = t.closestCachedZone(step.AliasTarget)
			visitedZones = map[string]bool{zone: true}
		default:
			return traceErr("network", "trace ended without a terminal result")
		}
	}
}

func traceRoleFor(zone string, outcome TraceOutcome) TraceRole {
	if zone == "." {
		return TraceRoleRoot
	}
	if outcome == TraceOutcomeReferral || outcome == TraceOutcomeError {
		return TraceRoleDelegation
	}
	return TraceRoleAuthoritative
}

func (t *tracer) step(ctx context.Context, zone string, nameservers []traceNameserverState, question dns.Question) (traceStep, *TraceError) {
	step := traceStep{Outcome: TraceOutcomeError}
	if len(nameservers) == 0 {
		return step, traceErr("no_nameserver_address", fmt.Sprintf("no authoritative servers for %s", zone))
	}

	var lastErr *TraceError
	for i := range nameservers {
		ns := &nameservers[i]
		if len(ns.addrs) == 0 {
			addrs, terr := t.resolveNameserverAddresses(ctx, ns.name)
			if terr != nil {
				lastErr = terr
				continue
			}
			setTraceNSAddresses(ns, addrs)
		}

		for _, addr := range ns.addrs {
			msg := t.buildAuthoritativeMessage(question)
			udpAttempt, response, terr := t.exchangeAttempt(ctx, ns.name, addr, "udp", msg)
			step.Attempts = append(step.Attempts, udpAttempt)
			if terr != nil {
				lastErr = terr
				continue
			}

			final := response
			if response.Truncated {
				tcpMsg := t.buildAuthoritativeMessage(question)
				tcpMsg.Id = msg.Id
				tcpAttempt, tcpResponse, tcpErr := t.exchangeAttempt(ctx, ns.name, addr, "tcp", tcpMsg)
				step.Attempts = append(step.Attempts, tcpAttempt)
				if tcpErr != nil {
					lastErr = tcpErr
					continue
				}
				final = tcpResponse
			}

			classified, terr := t.classifyResponse(zone, question, final)
			if terr != nil {
				step.Answers = classified.Answers
				step.Authorities = classified.Authorities
				step.Additional = classified.Additional
				step.Attempts[len(step.Attempts)-1].Error = terr
				lastErr = terr
				continue
			}
			classified.Attempts = append(classified.Attempts, step.Attempts...)
			return classified, nil
		}
	}

	if lastErr == nil {
		lastErr = traceErr("no_nameserver_address", fmt.Sprintf("no usable nameserver address for %s", zone))
	}
	return step, lastErr
}

func (t *tracer) exchangeAttempt(ctx context.Context, nsName string, addr netip.Addr, protocol string, msg *dns.Msg) (TraceAttempt, *dns.Msg, *TraceError) {
	attempt := TraceAttempt{
		Nameserver: nsName,
		IP:         addr.String(),
		Protocol:   protocol,
	}
	if t.exchanges >= maxTraceExchanges {
		terr := traceErr("query_budget", fmt.Sprintf("trace exceeded %d exchanges", maxTraceExchanges))
		attempt.Error = terr
		return attempt, nil, terr
	}
	t.exchanges++

	server := net.JoinHostPort(addr.String(), defaultTracePort)
	started := time.Now()
	response, rtt, err := traceExchange(ctx, networkFor(protocol, addr), server, msg, t.opts.SourceAddr, t.timeout)
	if rtt <= 0 {
		rtt = time.Since(started)
	}
	attempt.RTTMS = rtt.Milliseconds()
	if err != nil {
		attempt.Error = transportTraceError(err)
		return attempt, nil, attempt.Error
	}
	if response == nil {
		attempt.Error = traceErr("network", "authoritative server returned an empty response")
		return attempt, nil, attempt.Error
	}
	if !response.Response || len(response.Question) != 1 ||
		canonicalName(response.Question[0].Name) != canonicalName(msg.Question[0].Name) ||
		response.Question[0].Qtype != msg.Question[0].Qtype ||
		response.Question[0].Qclass != msg.Question[0].Qclass {
		attempt.Error = traceErr("network", "authoritative server returned a mismatched response")
		return attempt, nil, attempt.Error
	}
	attempt.RCode = dns.RcodeToString[response.Rcode]
	attempt.Truncated = response.Truncated
	return attempt, response, nil
}

func (t *tracer) classifyResponse(zone string, question dns.Question, msg *dns.Msg) (traceStep, *TraceError) {
	step := traceStep{
		Answers:     traceRecords(msg.Answer),
		Authorities: traceRecords(msg.Ns),
		Additional:  traceRecords(msg.Extra),
	}

	switch msg.Rcode {
	case dns.RcodeRefused:
		return step, traceErr("refused", "authoritative server refused the query")
	case dns.RcodeServerFailure:
		return step, traceErr("servfail", "authoritative server returned SERVFAIL")
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return step, traceErr("network", fmt.Sprintf("authoritative server returned %s", dns.RcodeToString[msg.Rcode]))
	}

	// Iterative traces accept terminal data only from a server that claims
	// authority for it. Without this guard, a mixed recursive/authoritative
	// server could satisfy an RD=0 query from cache and make the trace stop at
	// a non-authoritative answer.
	if msg.Authoritative {
		if outcome, aliasTarget, answerIPs, ok := classifyAnswer(msg, question); ok {
			step.Outcome = outcome
			step.AliasTarget = aliasTarget
			step.AnswerIPs = answerIPs
			return step, nil
		}
	}

	if msg.Rcode == dns.RcodeNameError && msg.Authoritative && hasSOA(msg.Ns) {
		step.Outcome = TraceOutcomeNXDOMAIN
		return step, nil
	}

	if msg.Rcode == dns.RcodeSuccess && msg.Authoritative && hasSOA(msg.Ns) {
		step.Outcome = TraceOutcomeNODATA
		return step, nil
	}

	delegation, nextNS, terr := t.extractReferral(zone, question.Name, msg)
	if terr == nil && delegation != nil {
		step.Outcome = TraceOutcomeReferral
		step.Delegation = delegation
		step.NextZone = delegation.Child
		step.NextNS = nextNS
		t.zoneCache[delegation.Child] = nextNS
		return step, nil
	}
	if terr != nil {
		return step, terr
	}

	return step, traceErr("lame_delegation", fmt.Sprintf("no usable referral or terminal answer from %s", zone))
}

func classifyAnswer(msg *dns.Msg, question dns.Question) (TraceOutcome, string, []netip.Addr, bool) {
	qname := canonicalName(question.Name)
	if hasDirectAnswer(msg.Answer, qname, question.Qtype) {
		return TraceOutcomeAnswer, "", extractAnswerIPs(msg.Answer, qname, question.Qtype), true
	}
	if question.Qtype == dns.TypeCNAME {
		if _, ok := firstCNAME(msg.Answer, qname); ok {
			return TraceOutcomeAnswer, "", nil, true
		}
	}

	current := qname
	seen := map[string]bool{current: true}
	for i := 0; i < 16; i++ {
		if hasDirectAnswer(msg.Answer, current, question.Qtype) {
			return TraceOutcomeAnswer, "", extractAnswerIPs(msg.Answer, current, question.Qtype), true
		}
		if target, ok := firstCNAME(msg.Answer, current); ok {
			target = canonicalName(target)
			if seen[target] {
				return TraceOutcomeCNAME, target, nil, true
			}
			seen[target] = true
			current = target
			continue
		}
		if target, ok := rewriteDNAME(msg.Answer, current); ok {
			target = canonicalName(target)
			if seen[target] {
				return TraceOutcomeCNAME, target, nil, true
			}
			seen[target] = true
			current = target
			continue
		}
		break
	}
	if current != qname {
		return TraceOutcomeCNAME, current, nil, true
	}
	return "", "", nil, false
}

func hasDirectAnswer(rrs []dns.RR, owner string, qtype uint16) bool {
	for _, rr := range rrs {
		h := rr.Header()
		if canonicalName(h.Name) == owner && h.Rrtype == qtype {
			return true
		}
	}
	return false
}

func firstCNAME(rrs []dns.RR, owner string) (string, bool) {
	for _, rr := range rrs {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		if canonicalName(cname.Hdr.Name) == owner {
			return cname.Target, true
		}
	}
	return "", false
}

func rewriteDNAME(rrs []dns.RR, name string) (string, bool) {
	var best *dns.DNAME
	for _, rr := range rrs {
		dname, ok := rr.(*dns.DNAME)
		if !ok {
			continue
		}
		owner := canonicalName(dname.Hdr.Name)
		if owner == name || !dns.IsSubDomain(owner, name) {
			continue
		}
		if best == nil || dns.CountLabel(owner) > dns.CountLabel(canonicalName(best.Hdr.Name)) {
			best = dname
		}
	}
	if best == nil {
		return "", false
	}
	owner := canonicalName(best.Hdr.Name)
	target := canonicalName(best.Target)
	trimmedName := strings.TrimSuffix(name, ".")
	trimmedOwner := strings.TrimSuffix(owner, ".")
	trimmedTarget := strings.TrimSuffix(target, ".")
	prefix := strings.TrimSuffix(trimmedName, "."+trimmedOwner)
	prefix = strings.TrimSuffix(prefix, ".")
	if prefix == "" {
		return target, true
	}
	return canonicalName(prefix + "." + trimmedTarget), true
}

func extractAnswerIPs(rrs []dns.RR, owner string, qtype uint16) []netip.Addr {
	var out []netip.Addr
	seen := map[string]bool{}
	for _, rr := range rrs {
		h := rr.Header()
		if canonicalName(h.Name) != owner || h.Rrtype != qtype {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			if addr, ok := netip.AddrFromSlice(v.A.To4()); ok {
				key := addr.String()
				if !seen[key] {
					seen[key] = true
					out = append(out, addr)
				}
			}
		case *dns.AAAA:
			if addr, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
				addr = addr.Unmap()
				key := addr.String()
				if !seen[key] {
					seen[key] = true
					out = append(out, addr)
				}
			}
		}
	}
	sortAddrs(out)
	return out
}

func (t *tracer) extractReferral(zone, qname string, msg *dns.Msg) (*TraceDelegation, []traceNameserverState, *TraceError) {
	var (
		bestOwner string
		hadNS     bool
		targets   = make(map[string]*traceNameserverState)
	)
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		hadNS = true
		owner := canonicalName(ns.Hdr.Name)
		if owner == zone || !dns.IsSubDomain(zone, owner) || !dns.IsSubDomain(owner, qname) {
			continue
		}
		if bestOwner == "" || dns.CountLabel(owner) > dns.CountLabel(bestOwner) {
			bestOwner = owner
			targets = make(map[string]*traceNameserverState)
		}
		if owner != bestOwner {
			continue
		}
		name := canonicalName(ns.Ns)
		if _, ok := targets[name]; !ok {
			targets[name] = &traceNameserverState{name: name}
		}
	}

	if bestOwner == "" {
		if hadNS {
			return nil, nil, traceErr("malformed_referral", fmt.Sprintf("response from %s did not contain a descending referral", zone))
		}
		return nil, nil, nil
	}

	for _, rr := range msg.Extra {
		// Parent-side glue is usable only when the NS name is within the
		// responding server's current zone. This admits necessary sibling glue
		// (for example, root referrals to .com servers under .net) while
		// ignoring Additional data outside the server's bailiwick.
		if !dns.IsSubDomain(zone, canonicalName(rr.Header().Name)) {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			name := canonicalName(v.Hdr.Name)
			target, ok := targets[name]
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(v.A.To4()); ok && t.allowAddr(addr) {
				target.addrs = appendIfMissingAddr(target.addrs, addr)
			}
		case *dns.AAAA:
			name := canonicalName(v.Hdr.Name)
			target, ok := targets[name]
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
				addr = addr.Unmap()
				if t.allowAddr(addr) {
					target.addrs = appendIfMissingAddr(target.addrs, addr)
				}
			}
		}
	}

	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)

	delegation := &TraceDelegation{Child: bestOwner}
	modelTargets := make([]TraceNameserver, 0, len(names))
	states := make([]traceNameserverState, 0, len(names))
	for _, name := range names {
		state := *targets[name]
		sortAddrs(state.addrs)
		modelTargets = append(modelTargets, TraceNameserver{Name: name, Addresses: addrStrings(state.addrs)})
		states = append(states, state)
	}
	for i := range states {
		states[i].view = &modelTargets[i]
	}
	delegation.Nameservers = modelTargets
	sort.SliceStable(states, func(i, j int) bool {
		leftBailiwick := dns.IsSubDomain(bestOwner, states[i].name)
		rightBailiwick := dns.IsSubDomain(bestOwner, states[j].name)
		if leftBailiwick != rightBailiwick {
			return leftBailiwick
		}
		leftGlue := len(states[i].addrs) > 0
		rightGlue := len(states[j].addrs) > 0
		if leftGlue != rightGlue {
			return leftGlue
		}
		return states[i].name < states[j].name
	})
	return delegation, states, nil
}

func (t *tracer) resolveNameserverAddresses(ctx context.Context, name string) ([]netip.Addr, *TraceError) {
	name = canonicalName(name)
	if t.resolvingNS[name] {
		return nil, traceErr("no_nameserver_address", fmt.Sprintf("dependency cycle while resolving %s", name))
	}
	t.resolvingNS[name] = true
	defer delete(t.resolvingNS, name)

	var (
		addrs   []netip.Addr
		lastErr *TraceError
	)
	if t.wantIPv4() {
		ips, terr := t.resolveAddressQuery(ctx, dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if terr != nil {
			if terr.Code == "query_budget" {
				return nil, terr
			}
			lastErr = terr
		}
		addrs = append(addrs, ips...)
	}
	if t.wantIPv6() {
		ips, terr := t.resolveAddressQuery(ctx, dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
		if terr != nil {
			if terr.Code == "query_budget" {
				return nil, terr
			}
			lastErr = terr
		}
		addrs = append(addrs, ips...)
	}
	addrs = uniqueSortedAddrs(addrs)
	if len(addrs) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, traceErr("no_nameserver_address", fmt.Sprintf("no usable address records found for %s", name))
	}
	return addrs, nil
}

func (t *tracer) resolveAddressQuery(ctx context.Context, question dns.Question) ([]netip.Addr, *TraceError) {
	current := question
	zone, ns := t.closestCachedZone(question.Name)
	visitedZones := map[string]bool{zone: true}
	localAliases := 0
	seenAliases := map[string]bool{canonicalName(question.Name): true}

	for {
		step, terr := t.step(ctx, zone, ns, current)
		if terr != nil {
			return nil, terr
		}
		switch step.Outcome {
		case TraceOutcomeReferral:
			if visitedZones[step.NextZone] {
				return nil, traceErr("referral_loop", fmt.Sprintf("referral loop detected at %s", step.NextZone))
			}
			visitedZones[step.NextZone] = true
			zone = step.NextZone
			ns = step.NextNS
		case TraceOutcomeAnswer:
			return filterAllowedAddrs(step.AnswerIPs, t.allowAddr), nil
		case TraceOutcomeNXDOMAIN, TraceOutcomeNODATA:
			return nil, nil
		case TraceOutcomeCNAME:
			if step.AliasTarget == "" || seenAliases[step.AliasTarget] {
				return nil, traceErr("cname_loop", fmt.Sprintf("alias cycle detected at %s", step.AliasTarget))
			}
			localAliases++
			if localAliases > maxTraceCNAMEs {
				return nil, traceErr("cname_loop", fmt.Sprintf("trace exceeded %d aliases", maxTraceCNAMEs))
			}
			seenAliases[step.AliasTarget] = true
			current.Name = step.AliasTarget
			if dns.IsSubDomain(zone, step.AliasTarget) {
				continue
			}
			zone, ns = t.closestCachedZone(step.AliasTarget)
			visitedZones = map[string]bool{zone: true}
		default:
			return nil, traceErr("no_nameserver_address", fmt.Sprintf("could not resolve address records for %s", question.Name))
		}
	}
}

func (t *tracer) closestCachedZone(name string) (string, []traceNameserverState) {
	for candidate := canonicalName(name); ; candidate = parentZone(candidate) {
		if ns, ok := t.zoneCache[candidate]; ok {
			return candidate, ns
		}
		if candidate == "." {
			break
		}
	}
	return ".", nil
}

func parentZone(name string) string {
	name = canonicalName(name)
	if name == "." {
		return "."
	}
	trimmed := strings.TrimSuffix(name, ".")
	idx := strings.IndexByte(trimmed, '.')
	if idx < 0 {
		return "."
	}
	return trimmed[idx+1:] + "."
}

func (t *tracer) primeRoots(ctx context.Context) ([]traceNameserverState, *TraceError) {
	if t.opts.Bootstrap == nil {
		roots := filterHintStates(rootHintStates(), t.allowAddr)
		if len(roots) == 0 {
			return nil, traceErr("bootstrap", "no usable built-in root hints for the selected address family")
		}
		return roots, nil
	}

	responses, err := t.opts.Bootstrap.Lookup(ctx, []dns.Question{{Name: ".", Qtype: dns.TypeNS, Qclass: dns.ClassINET}}, t.opts.Flags)
	rootSet := make(map[string]traceNameserverState)
	for _, response := range responses {
		for _, answer := range response.Answers {
			if strings.ToUpper(answer.Type) != "NS" || canonicalName(answer.Name) != "." {
				continue
			}
			name := canonicalName(answer.Address)
			if _, ok := rootHintsByName[name]; !ok {
				continue
			}
			state := rootSet[name]
			state.name = name
			rootSet[name] = state
		}
		for _, extra := range response.Additional {
			name := canonicalName(extra.Name)
			state, ok := rootSet[name]
			if !ok {
				continue
			}
			addr, parseErr := netip.ParseAddr(strings.TrimSpace(extra.Address))
			if parseErr != nil {
				continue
			}
			addr = addr.Unmap()
			if t.allowAddr(addr) {
				state.addrs = appendIfMissingAddr(state.addrs, addr)
				rootSet[name] = state
			}
		}
	}

	for name, state := range rootSet {
		if len(state.addrs) == 0 {
			if hint, ok := rootHintsByName[name]; ok {
				for _, addr := range hint {
					if t.allowAddr(addr) {
						state.addrs = appendIfMissingAddr(state.addrs, addr)
					}
				}
				rootSet[name] = state
			}
		}
	}

	roots := make([]traceNameserverState, 0, len(rootSet))
	for _, state := range rootSet {
		state.addrs = uniqueSortedAddrs(state.addrs)
		if len(state.addrs) > 0 {
			roots = append(roots, state)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].name < roots[j].name })
	if len(roots) > 0 {
		return roots, nil
	}
	if err != nil {
		return nil, traceErr("bootstrap", err.Error())
	}
	return nil, traceErr("bootstrap", "bootstrap resolver did not return usable root NS records")
}

func (t *tracer) buildAuthoritativeMessage(question dns.Question) *dns.Msg {
	msg := &dns.Msg{}
	msg.Id = dns.Id()
	msg.RecursionDesired = false
	msg.AuthenticatedData = t.opts.Flags.AD
	msg.CheckingDisabled = t.opts.Flags.CD
	msg.Authoritative = t.opts.Flags.AA
	msg.Zero = t.opts.Flags.Z
	msg.Question = []dns.Question{{
		Name:   canonicalName(question.Name),
		Qtype:  question.Qtype,
		Qclass: question.Qclass,
	}}

	flags := t.opts.Flags
	if flags.DO || flags.NSID || flags.Cookie || flags.Padding || flags.EDE || flags.Bufsize > 0 {
		bufsize := flags.Bufsize
		if bufsize == 0 {
			bufsize = 1232
		}
		msg.SetEdns0(bufsize, flags.DO)
		if opt := msg.IsEdns0(); opt != nil {
			if flags.NSID {
				opt.Option = append(opt.Option, &dns.EDNS0_NSID{})
			}
			if flags.Cookie {
				opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{})
			}
			if flags.Padding {
				opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 128)})
			}
		}
	}
	return msg
}

func (t *tracer) wantIPv4() bool {
	if t.opts.UseIPv4 {
		return true
	}
	if t.opts.UseIPv6 {
		return false
	}
	if t.source.IsValid() {
		return t.source.Is4()
	}
	return true
}

func (t *tracer) wantIPv6() bool {
	if t.opts.UseIPv6 {
		return true
	}
	if t.opts.UseIPv4 {
		return false
	}
	if t.source.IsValid() {
		return t.source.Is6()
	}
	return true
}

func (t *tracer) allowAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if t.source.IsValid() {
		if t.source.Is4() && !addr.Is4() {
			return false
		}
		if t.source.Is6() && !addr.Is6() {
			return false
		}
	}
	if t.opts.UseIPv4 {
		return addr.Is4()
	}
	if t.opts.UseIPv6 {
		return addr.Is6()
	}
	return addr.Is4() || addr.Is6()
}

func filterAllowedAddrs(addrs []netip.Addr, allow func(netip.Addr) bool) []netip.Addr {
	var out []netip.Addr
	for _, addr := range addrs {
		if allow(addr) {
			out = append(out, addr.Unmap())
		}
	}
	return uniqueSortedAddrs(out)
}

func transportTraceError(err error) *TraceError {
	if errors.Is(err, context.DeadlineExceeded) {
		return traceErr("timeout", err.Error())
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return traceErr("timeout", err.Error())
	}
	return traceErr("network", err.Error())
}

func asTraceError(err error, fallback string) *TraceError {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInvalidTraceConfig) {
		return traceErr("invalid_config", err.Error())
	}
	var terr *TraceError
	if errors.As(err, &terr) {
		return terr
	}
	return traceErr(fallback, err.Error())
}

func traceErr(code, detail string) *TraceError {
	return &TraceError{Code: code, Detail: detail}
}

func networkFor(protocol string, addr netip.Addr) string {
	if addr.Unmap().Is4() {
		return protocol + "4"
	}
	return protocol + "6"
}

func canonicalName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "."
	}
	return dns.CanonicalName(dns.Fqdn(name))
}

func hasSOA(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

func traceRecords(rrs []dns.RR) []TraceRecord {
	if len(rrs) == 0 {
		return nil
	}
	records := make([]TraceRecord, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		records = append(records, TraceRecord{
			Name:  canonicalName(rr.Header().Name),
			Type:  models.RecordTypeString(rr.Header().Rrtype),
			Class: dns.Class(rr.Header().Class).String(),
			TTL:   rr.Header().Ttl,
			Data:  traceRecordData(rr),
		})
	}
	if len(records) == 0 {
		return nil
	}
	return records
}

func traceRecordData(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.NS:
		return canonicalName(v.Ns)
	case *dns.CNAME:
		return canonicalName(v.Target)
	case *dns.DNAME:
		return canonicalName(v.Target)
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, canonicalName(v.Mx))
	case *dns.PTR:
		return canonicalName(v.Ptr)
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", canonicalName(v.Ns), canonicalName(v.Mbox), v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, canonicalName(v.Target))
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	default:
		parts := strings.Fields(rr.String())
		if len(parts) <= 4 {
			return ""
		}
		return strings.Join(parts[4:], " ")
	}
}

func appendIfMissingAddr(addrs []netip.Addr, addr netip.Addr) []netip.Addr {
	addr = addr.Unmap()
	for _, existing := range addrs {
		if existing == addr {
			return addrs
		}
	}
	return append(addrs, addr)
}

func uniqueSortedAddrs(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		key := addr.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	sortAddrs(out)
	return out
}

func sortAddrs(addrs []netip.Addr) {
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
}

func addrStrings(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}
	return out
}

func setTraceNSAddresses(ns *traceNameserverState, addrs []netip.Addr) {
	ns.addrs = uniqueSortedAddrs(addrs)
	if ns.view != nil {
		ns.view.Addresses = addrStrings(ns.addrs)
	}
}

func filterHintStates(states []traceNameserverState, allow func(netip.Addr) bool) []traceNameserverState {
	filtered := make([]traceNameserverState, 0, len(states))
	for _, state := range states {
		state.addrs = filterAllowedAddrs(state.addrs, allow)
		if len(state.addrs) == 0 {
			continue
		}
		filtered = append(filtered, state)
	}
	return filtered
}

func rootHintStates() []traceNameserverState {
	states := make([]traceNameserverState, 0, len(rootHintOrder))
	for _, name := range rootHintOrder {
		states = append(states, traceNameserverState{name: name, addrs: append([]netip.Addr(nil), rootHintsByName[name]...)})
	}
	return states
}

func mustAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr.Unmap()
}

var rootHintOrder = []string{
	"a.root-servers.net.",
	"b.root-servers.net.",
	"c.root-servers.net.",
	"d.root-servers.net.",
	"e.root-servers.net.",
	"f.root-servers.net.",
	"g.root-servers.net.",
	"h.root-servers.net.",
	"i.root-servers.net.",
	"j.root-servers.net.",
	"k.root-servers.net.",
	"l.root-servers.net.",
	"m.root-servers.net.",
}

var rootHintsByName = map[string][]netip.Addr{
	"a.root-servers.net.": {mustAddr("198.41.0.4"), mustAddr("2001:503:ba3e::2:30")},
	"b.root-servers.net.": {mustAddr("170.247.170.2"), mustAddr("2801:1b8:10::b")},
	"c.root-servers.net.": {mustAddr("192.33.4.12"), mustAddr("2001:500:2::c")},
	"d.root-servers.net.": {mustAddr("199.7.91.13"), mustAddr("2001:500:2d::d")},
	"e.root-servers.net.": {mustAddr("192.203.230.10"), mustAddr("2001:500:a8::e")},
	"f.root-servers.net.": {mustAddr("192.5.5.241"), mustAddr("2001:500:2f::f")},
	"g.root-servers.net.": {mustAddr("192.112.36.4"), mustAddr("2001:500:12::d0d")},
	"h.root-servers.net.": {mustAddr("198.97.190.53"), mustAddr("2001:500:1::53")},
	"i.root-servers.net.": {mustAddr("192.36.148.17"), mustAddr("2001:7fe::53")},
	"j.root-servers.net.": {mustAddr("192.58.128.30"), mustAddr("2001:503:c27::2:30")},
	"k.root-servers.net.": {mustAddr("193.0.14.129"), mustAddr("2001:7fd::1")},
	"l.root-servers.net.": {mustAddr("199.7.83.42"), mustAddr("2001:500:9f::42")},
	"m.root-servers.net.": {mustAddr("202.12.27.33"), mustAddr("2001:dc3::35")},
}

func defaultTraceExchange(ctx context.Context, network, server string, msg *dns.Msg, sourceAddr string, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, 0, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, 0, fmt.Errorf("direct authoritative dial target must be an IP literal: %s", server)
	}
	client := &dns.Client{
		Net:     network,
		Timeout: timeout,
		UDPSize: dns.DefaultMsgSize,
	}
	if sourceAddr != "" {
		dialer, err := sourceDialer(network, sourceAddr, timeout)
		if err != nil {
			return nil, 0, err
		}
		client.Dialer = dialer
	}
	return client.ExchangeContext(ctx, msg, server)
}
