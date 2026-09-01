# DNS delegation trace design

Status: implementation specification

## Goal

Add an iterative DNS delegation trace to doggo that is easier to understand than
`dig +trace`, while remaining deterministic and scriptable. A trace must show
which zone delegated the query, which authoritative server was contacted, every
failed/retried attempt, each round-trip time, and the terminal DNS result.

The implementation targets the CLI first. It is not exposed through the web API
in this release.

## CLI contract

```console
doggo example.com --trace
doggo example.com AAAA --trace
doggo example.com --trace @1.1.1.1
doggo example.com --trace --json
doggo example.com --trace --short
```

- `--trace` is a mode flag, not a subcommand. This preserves doggo's existing
  free-form query syntax and avoids making `trace` unusable as a queried label.
- Exactly one effective name, type, and class is accepted.
- The default trace question is `A IN` (unlike a regular lookup, which defaults
  to both A and AAAA).
- Reverse/PTR traces are supported after the existing `--reverse` conversion.
- Only class IN is supported because delegation server discovery depends on
  A/AAAA glue.
- `--nameserver` / positional `@server` affects only root priming. All later
  hops are sent directly to authoritative servers over classic DNS.
- Without an explicit server, doggo starts from a compiled IANA root-hints set.
- `--ipv4`, `--ipv6`, `--source`, `--timeout`, DNS header flags, EDNS flags,
  output flags, and `--debug` apply. Authoritative-hop queries always force
  `RD=0`; ECS is not forwarded to authoritative servers.
- Reject `--trace` with `--any`, `--authoritative`, `--gp-from`, multiple
  questions, a non-IN class, or both `--ipv4` and `--ipv6`.
- Encrypted resolver options apply only to an explicit bootstrap resolver.

`trace` is a valid config key and has the `DOGGO_TRACE` environment equivalent,
consistent with other long flags.

## Resolution algorithm

### Root priming

The tracer contains the 13 IANA root server names and their published IPv4 and
IPv6 addresses. With no explicit bootstrap resolver, these hints are used
immediately. If a bootstrap resolver is supplied, doggo queries `NS .` through
one configured resolver, uses returned root NS/glue that matches the root NS
set, and fills missing addresses from the built-in hints. If priming fails,
return a bootstrap error rather than silently changing what the user asked.
The bootstrap lookup is not rendered as a delegation hop.

### Iteration

For each current zone/server set:

1. Query the current name/type/class with `RD=0` and a fresh message ID.
2. Use UDP first. Retry a truncated response over TCP to the same IP.
3. Record every attempt, including network failures and retry protocol.
4. Try alternative addresses/nameservers deterministically after timeout,
   REFUSED, SERVFAIL, malformed, or lame responses.
5. Classify a valid response as:
   - referral: a deeper NS owner that is an ancestor of the current qname;
   - answer: relevant answer records (including CNAME/DNAME);
   - NXDOMAIN: authoritative name error;
   - NODATA: authoritative NOERROR with SOA and no answer;
   - lame/malformed: no valid forward referral or terminal result.
6. Follow referrals until a terminal result or a safety limit is reached.

Referral zones must strictly descend from the current zone and remain suffixes
of the query name. Track visited zones to reject referral loops. Limits are 32
visible hops, 64 total exchanges, and 8 CNAME redirects.

### Glue and nameserver addresses

- Use A/AAAA Additional records only when their owner matches a referred NS
  within the responding parent's zone. Additional data outside that bailiwick
  is not trusted; sibling glue inside the parent zone remains usable.
- Respect the selected address family.
- Missing and out-of-bailiwick addresses are resolved with the same iterative tracer, never with
  `net.Lookup*` or by dialing an NS hostname. Internal address-resolution
  queries share the query budget and have a dependency-cycle guard.
- Every direct authoritative dial target must be an IP literal plus port.
- Sort NS names and addresses for stable behavior and tests.

### Aliases and terminal negatives

If a response contains a CNAME/DNAME without the requested final type, record
it and continue with the alias target. Restart from the closest cached ancestor
(or root) when the target leaves the current zone. Stop after eight aliases or
on a cycle.

An authoritative NXDOMAIN or NODATA is a completed trace with a corresponding
verdict, not a transport failure.

### DNSSEC

`--do` requests DNSSEC records and the output may report DS/RRSIG presence.
This feature does not validate the chain of trust and must never label data as
validated/authenticated.

## Data model and JSON

The resolver package owns transport-neutral trace models:

- `TraceResult`: schema version, question, status, verdict, ordered hops,
  summary, and optional structured terminal error.
- `TraceHop`: number, zone, role, ordered attempts, optional delegation,
  answers/authorities/additional records, and outcome.
- `TraceAttempt`: NS name, IP, protocol, RTT in milliseconds, RCODE, truncation
  state, and stable error code/detail.
- `TraceDelegation`: child zone and sorted NS targets with discovered addresses.

JSON is emitted as:

```json
{
  "schema_version": 1,
  "trace": {
    "query": {"name":"example.com.","type":"A","class":"IN"},
    "status": "complete",
    "verdict": "answer",
    "hops": [],
    "summary": {"hop_count":3,"total_rtt_ms":42}
  }
}
```

Stable enums:

- status: `complete`, `partial`, `failed`
- verdict: `answer`, `nxdomain`, `nodata`, `error`
- outcome: `referral`, `answer`, `cname`, `nxdomain`, `nodata`, `error`
- error codes include `timeout`, `network`, `refused`, `servfail`,
  `malformed_referral`, `lame_delegation`, `no_nameserver_address`,
  `referral_loop`, `cname_loop`, `max_hops`, and `query_budget`.

Fields may be added compatibly. Incompatible JSON changes require a schema
version bump.

## Human output

Use a dedicated renderer rather than flattening hops into the normal response
table. Each hop is a vertical block:

```text
TRACE  example.com.  A  IN

 1  .                                      root
    -> a.root-servers.net. (198.41.0.4)     18ms  NOERROR
    delegates com. to a.gtld-servers.net. + 12 more

 2  com.                                    delegation
    -> a.gtld-servers.net. (192.5.6.30)      9ms  NOERROR
    delegates example.com. to a.iana-servers.net., b.iana-servers.net.

 3  example.com.                            authoritative [ok]
    -> a.iana-servers.net. (199.43.135.53)  14ms  NOERROR

    ANSWER
    example.com.  A  300s  93.184.216.34

-- 3 hops · 41ms total · answer from a.iana-servers.net. --
```

Color is decorative only. Text always carries status and outcome. ASCII
symbols are used so redirected output and assistive tools remain predictable.
`--color=false`, `NO_COLOR`, and non-TTY behavior continue to use fatih/color.

`--short` prints one tab-separated path line per successful hop followed by
final answer values. JSON is always color-free.

## Exit behavior

- `0`: completed trace, including authoritative NXDOMAIN/NODATA.
- `1`: invalid invocation/configuration before tracing.
- `2`: one or more hops were collected but the trace ended in an operational
  error; partial output is still printed.
- `9`: no usable trace hop was produced.

Recovered failed attempts do not make an otherwise completed trace exit 2;
they remain visible in `attempts`.

## Code organization

- `pkg/resolvers/trace.go`: iterative algorithm, root hints, trace models,
  exchange/factory seams, and raw-message classification.
- `pkg/resolvers/trace_test.go`: deterministic scripted transport tests.
- `internal/app/output_trace.go`: terminal, short, and JSON renderers.
- `cmd/doggo/cli.go`: flag, validation, trace mode dispatch, cleanup, exits.
- help/completions/config sample/docs: discoverability and stable contract.

Normal resolver behavior and its existing JSON schema remain unchanged.

## Acceptance criteria

1. A local fake hierarchy can trace root -> TLD -> zone -> answer without
   internet access.
2. Dead-first/live-second failover, UDP truncation/TCP retry, missing glue,
   NXDOMAIN, NODATA, CNAME, and loop/budget cases have deterministic tests.
3. No authoritative NS hostname is ever passed to a network dialer.
4. Partial traces are rendered and serialized before the CLI exits 2.
5. `go test ./...`, trace-sensitive `go test -race`, formatting, and vet pass.
6. Existing non-trace output and JSON tests remain unchanged and green.
