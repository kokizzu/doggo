---
title: Delegation Trace
description: Follow an iterative DNS delegation trace with Doggo
---

`doggo --trace` follows the delegation chain directly, showing which zone delegated the query, which authoritative server answered, and every retry or failure along the way. It is a CLI-only feature.

## Syntax

```bash
doggo example.com --trace
doggo example.com AAAA --trace
doggo --reverse 8.8.8.8 --trace
doggo example.com --trace @1.1.1.1
doggo example.com --trace --json
doggo example.com --trace --short
```

- `--trace` is a mode flag, not a subcommand.
- Trace mode accepts exactly one effective question and defaults to `A IN`.
- `--reverse` rewrites the query to PTR form first, then traces that lookup.
- Only class `IN` is supported.

## Bootstrap and hop behavior

- With no explicit resolver, Doggo starts from a built-in IANA root-hints set.
- `@server` or `--nameserver` changes only root priming.
- With an explicit bootstrap resolver, Doggo asks for `NS .`, keeps matching root servers, and fills missing root addresses from the built-in hints.
- If root priming fails, the trace ends with a bootstrap error instead of silently switching resolvers.
- After priming, every hop is sent directly to authoritative servers over classic DNS on port 53.
- Hop queries always use `RD=0`.
- Authoritative hops try UDP first and retry truncated responses over TCP.
- `--ipv4`, `--ipv6`, `--source`, `--timeout`, DNS header flags, EDNS flags, output flags, and `--debug` still apply.
- Encrypted resolver settings only affect an explicit bootstrap resolver.
- ECS is never forwarded to authoritative servers.

## Readable output

The default renderer prints one block per visible hop:

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

Each hop keeps retries, transport fallbacks, and failures visible. `--short` prints one tab-separated path line per successful hop, then the final answer values. `--json` is always color-free.

If `--do` is enabled, Doggo may show DNSSEC-related records such as `DS` or `RRSIG`, but it does **not** validate the chain of trust.

## JSON fields

Trace JSON has two top-level fields: `schema_version` (currently `1`) and
`trace`. The nested `trace` object includes:

- `query`
- `status`: `complete`, `partial`, `failed`
- `verdict`: `answer`, `nxdomain`, `nodata`, `error`
- `hops`
- `summary`
- optional `error`

Each hop includes `number`, `zone`, `role`, `outcome`, `attempts`, optional `delegation`, and any captured `answers`, `authorities`, or `additional` records.

Each attempt includes `nameserver`, `ip`, `protocol`, `rtt_ms`, `rcode`, an optional `truncated` marker, and an optional structured `error` with `code` and `detail`.

Stable outcomes are `referral`, `answer`, `cname`, `nxdomain`, `nodata`, and `error`. Stable error codes include `bootstrap`, `timeout`, `network`, `refused`, `servfail`, `malformed_referral`, `lame_delegation`, `no_nameserver_address`, `referral_loop`, `cname_loop`, `max_hops`, and `query_budget`.

## Incompatible flags

`--trace` cannot be combined with:

- `--any`
- `--authoritative`
- `--gp-from`
- multiple effective questions
- non-`IN` classes
- both `--ipv4` and `--ipv6`

## Partial results and exit codes

Doggo prints collected hops before exiting on operational failures.

- `0`: completed trace, including authoritative `NXDOMAIN` and `NODATA`
- `1`: invalid invocation or configuration
- `2`: one or more hops were collected, but the trace ended with an operational error
- `9`: no usable trace hop was produced

Recovered failed attempts remain visible inside `attempts`; they do not turn an otherwise completed trace into exit code `2`.
