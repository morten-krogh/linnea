# Audit Report 127

Audited commit `c0d520d` (`audit 126: The authority parser rejects valid IPvFuture literals`), 2026-08-28.

This pass followed the shared authority parser after its IPvFuture addition.
It found that its `reg-name` branch deliberately excludes percent-encoding,
even though percent-encoded octets are part of the `uri-host` grammar used by
HTTP `Host` and `:authority`. No source, test, or configuration file was
changed in this audit; only this report was added.

## Finding 1 — Percent-encoded reg-names are rejected as invalid authorities

**Severity:** Low  
**Confidence:** High  
**Status:** Open

[`linnea_http_authority_host`](../src/server/linnea_hpack.asm#L1901) parses an
unbracketed host one byte at a time and calls
[`.ah_regname_ok`](../src/server/linnea_hpack.asm#L2072). Its bitmap expressly
excludes `%` ([line 55](../src/server/linnea_hpack.asm#L55)), so every
percent-encoded octet takes `.ah_bad` and is rejected before vhost selection.
The same function is used by HTTP/1.1 `Host`, HTTP/2 `:authority`, HTTP/3
`:authority`, and the HTTP/1.1 CONNECT authority-form path.

That omits a grammar alternative that an authority must accept. HTTP defines
`Host` as `uri-host` ([RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2))
and uses the same URI host grammar for `:authority`
([RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1)).
The referenced `reg-name` production includes `pct-encoded`, where each
occurrence is `%` followed by two hexadecimal digits
([RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2)).
`alpha%2Etest` and `alpha%41.test` are therefore well-formed registered names;
`alpha%ZZ.test` is the malformed control.

### Reproduction

From the repository root, start the cleartext authority fixture. The first
request is an ordinary host control. The next two differ only by valid
percent-encoding in the registered name; the final line is deliberately
malformed percent-encoding.

```sh
d=$(mktemp -d /tmp/linnea-audit-127-XXXXXX)
./bin/linnea --config test/configs/authority-vhosts.json >"$d/out" 2>"$d/err" & server=$!
trap 'kill "$server" 2>/dev/null; wait "$server" 2>/dev/null' EXIT
sleep 0.3
python3 - <<'PY'
import socket

for host in (b'alpha.test', b'alpha%2Etest', b'alpha%41.test', b'alpha%ZZ.test'):
    sock = socket.create_connection(('127.0.0.1', 61466))
    sock.sendall(b'GET / HTTP/1.1\r\nHost: ' + host +
                 b'\r\nConnection: close\r\n\r\n')
    print(host, b'->', sock.recv(256).split(b'\r\n', 1)[0])
    sock.close()
PY
```

Observed output:

```
b'alpha.test' b'->' b'HTTP/1.1 200 OK'
b'alpha%2Etest' b'->' b'HTTP/1.1 400 Bad Request'
b'alpha%41.test' b'->' b'HTTP/1.1 400 Bad Request'
b'alpha%ZZ.test' b'->' b'HTTP/1.1 400 Bad Request'
```

The ordinary control proves that the listener and request are otherwise valid.
The two valid spellings are indistinguishable from the malformed control to
Linnea: all three are rejected at the same authority-validation step.

### Impact

Clients or intermediaries that send a legal percent-encoded registered name
cannot reach a vhost at all; Linnea reports malformed HTTP instead of applying
normal authority handling. The fault affects all three HTTP versions because
they share this function. Percent-encoding should still be parsed strictly:
accepting a bare `%` or non-hex digits would merely replace this false rejection
with acceptance of malformed authorities.

### Recommended fix

Extend the unbracketed `reg-name` scan to recognize `%` as exactly one
`pct-encoded` unit: require two following hexadecimal digits and advance past
all three bytes. Keep the existing bitmap for the remaining unreserved and
sub-delimiter bytes. Normalize percent-encoded unreserved characters before
vhost comparison (or compare them equivalently), so `alpha%2Etest` does not
silently select a different vhost than its normalized host spelling. Add paired
HTTP/1, HTTP/2, and HTTP/3 authority tests: valid `alpha%2Etest` and
`alpha%41.test` must be accepted, while `alpha%`, `alpha%2`, and
`alpha%ZZ.test` must remain 400.

## Resolution (2026-08-28)

**CONFIRMED; no code change was made in this audit.** The reproduction above
was run against `c0d520d` and produced the four status lines shown. The source
comment and bitmap identify the cause directly: percent-encoding is explicitly
unsupported, rather than being parsed and then rejected for a malformed escape.

---

## Resolution

**CONFIRMED and fixed — but only half the recommendation. Percent-encoded
reg-names are now accepted; the recommended normalization before vhost
selection is DECLINED, with the measurement below.**

### Reproduced first

The report's fixture was run verbatim against `c0d520d` and produced the four
status lines it claims, so the finding is real and not a mis-attribution:

```
alpha.test    -> 200 OK        beta.test     -> 200 OK
alpha%2Etest  -> 400           alpha%41.test -> 400        alpha%ZZ.test -> 400
```

The extra spellings confirm the cause is the missing grammar alternative and
not something narrower: `alpha%2.test`, `alpha%`, `alpha%2`, `alpha%2Ftest`,
`alpha%00test` and `beta%2Etest:8080` were all 400 as well — every byte after
`%` was irrelevant because the `%` itself took `.ah_bad`.

### Two independent oracles, asked rather than assumed

`nginx 1.30.4` (already an interop oracle in `tls/80-nginx-interop.sh`),
configured with `alpha.test`, `beta.test` and a `default_server`, and curl's
RFC 3986 URL parser. Ours is the post-fix build.

| Host | nginx | curl URL parser | linnea (before) | linnea (after) |
|---|---|---|---|---|
| `alpha.test` | 200 ALPHA | ok | 200 | 200 |
| `alpha%2Etest` | 200 **DEFAULT** | ok → `alpha.test` | **400** | 200, default vhost |
| `alpha%41.test` | 200 **DEFAULT** | ok → `alphaA.test` | **400** | 200, default vhost |
| `alpha%2etest` | 200 DEFAULT | ok → `alpha.test` | 400 | 200, default vhost |
| `alpha%ZZ.test` | **200** DEFAULT | malformed (exit 3) | 400 | 400 |
| `alpha%2` | **200** DEFAULT | malformed (exit 3) | 400 | 400 |
| `alpha%` | **200** DEFAULT | malformed (exit 3) | 400 | 400 |
| `alpha%2Ftest` | 200 DEFAULT | **malformed (exit 3)** | 400 | **200**, default vhost |
| `alpha%00test` | 200 DEFAULT | **malformed (exit 3)** | 400 | **200**, default vhost |

Both oracles agree with the report that `alpha%2Etest` and `alpha%41.test` are
well formed, so the 400 was a false rejection — the outcome this workflow rates
worst. Two disagreements are worth stating rather than hiding:

* **nginx is laxer than both us and curl.** It validates no percent-encoding at
  all: `alpha%`, `alpha%2` and `alpha%ZZ.test` are just opaque bytes to it. We
  follow curl and the ABNF here — `pct-encoded = "%" HEXDIG HEXDIG` (RFC 3986
  2.1), both digits present and both hex — because the report is right that
  accepting a bare `%` would replace a false rejection with a false acceptance.
* **curl is stricter than the ABNF on `%2F` and `%00`.** It decodes the host to
  hand to a resolver and re-validates the result, so an escape that decodes to
  a byte reg-name forbids literally is refused. That is a *resolver* rule, not
  the grammar: RFC 3986 3.2.2 admits any `pct-encoded` octet in `reg-name`, and
  percent-encoding exists precisely to carry bytes that may not appear raw. We
  never decode, so `%2F` stays three inert bytes; it becomes a `/` nowhere, and
  it matches no configured hostname. Accepting it is the grammar's answer, and
  rejecting it would be a second false rejection of the kind this report is
  about.

### The fix

`.ah_u_scan` in `src/server/linnea_hpack.asm` now branches on `%` to
`.ah_u_pct`, which demands two in-bounds hex digits (`.ah_hexdig_ok`, new) and
advances the cursor by three. The `ah_regname_tab` bitmap is **deliberately
unchanged**: `%` is not a byte class but a three-byte unit, and the same table
is shared with the IPvFuture value scan, whose production
(`unreserved / sub-delims / ":"`) has no `pct-encoded` alternative. Setting the
bit would have silently legalised `[v1.a%20b]`, which report 126's test asserts
is 400 — and it still is.

One parser serves h1 `Host`, h1 CONNECT authority-form, h2 `:authority` and h3
`:authority`, so all four moved together. Nothing else changed: the port is
still one to five digits in 0..65535 after a percent-encoded name
(`alpha%2Etest:99999` is still 400), and brackets are untouched.

### Declined: normalizing before vhost selection

The report also asks that percent-encoded unreserved characters be normalized
(or compared equivalently) before vhost selection. That is not implemented, on
three grounds, the first of them measured:

1. **nginx does not do it.** Measured above: with `server_name alpha.test`
   configured, `Host: alpha%2Etest` is answered by the **default** server, not
   by `alpha.test`'s. Normalizing would make Linnea route a request somewhere
   nginx does not, which is precisely the divergence an interop oracle is here
   to prevent. RFC 3986 6.2.2.2 puts percent-encoding normalization on a
   *comparison ladder* ("may"), not in the grammar.
2. **It would change what "unknown name" means.** Every name we do not host —
   `[::1]`, `[v1.fe80]`, an alias, an IP — already falls through to the default
   vhost, and h3 answers 421 only for a name the connection's certificate does
   not cover. Decoding turns a spelling into a *different vhost's* name, so
   `%6Cocalhost` would start drawing a 421 on h3 where today it is served
   locally. That is a routing decision made by a transformation the operator
   never wrote down, and the access log would still show the encoded form.
3. **The contract has nowhere to put the decoded bytes.** The parser returns an
   offset and a length into the caller's buffer. A decoded host is shorter than
   its input and cannot be expressed that way, so normalizing means a scratch
   buffer and a bound on every one of the four call sites — and then a
   re-validation pass, because `%2F` decodes to a byte `reg-name` forbids.
   curl's exit-3 on `%2F` and `%00` is exactly that re-validation; it is the
   cost of decoding, not a reason to decode.

Making it normalize later is a contained change if that trade is ever wanted.
It is stated in the code so it can be found.

### Coverage, and the A/B that proves it

Every rejection is paired with an acceptance, and the pairing was proved by
running the new tests against the **pre-fix** binary and watching them fail:

* `test/shards/h1/24-authority.sh` — 6 new acceptance checks (`alpha%2Etest`,
  `alpha%41.test`, lower-case `%2e`, with a port, and the non-decoding control)
  and 7 new rejections (`%ZZ`, `%2.`, `%2`, `%`, a bare `%` authority,
  `alpha%2:8080` — the escape may not be completed by the port delimiter — and
  `alpha%2Etest:99999`). **Pre-fix: 195 passed / 11 failed. Post-fix: 201
  passed / 5 failed**, the 5 being partial-run artifacts that need state from
  `h1/20-serving.sh` and are green in the full-directory run below.
* The non-decoding control is the load-bearing one: `Host: beta%2Etest` must
  serve the **default** vhost's page, not `beta.test`'s `sub index`. A build
  that decoded would pass every other line in the block and fail that one.
* `test/tls/h2_authority_grammar.py` — 3 acceptances, 7 rejections. Pre-fix it
  fails at `assert served(b"alpha%2Etest")`; post-fix it prints `ok`.
* `test/quic/h3_authority_test.py` — 2 acceptances, 2 rejections, and the
  sharpest non-decoding control available anywhere in the tree: `%6Cocalhost`
  is `localhost` with one letter escaped, and `localhost` is a vhost this
  connection's certificate does not cover, so **a build that normalized would
  answer 421 here**. Pre-fix it fails at the pct-encoded acceptance; post-fix
  `ok`.
* `test/shards/h1/25-http-semantics.sh` — the fourth call site: `CONNECT
  alpha%2Etest:443` is 405 (well formed, we tunnel nothing) while
  `alpha%ZZ.test:443` and `alpha%2:443` stay 400. The point of the finding is
  that those two answers stopped being distinguishable.

A build that simply added `%` to the byte table passes all 11 acceptance lines
and fails all 16 rejection lines; a build that rejects everything fails the
reverse. Neither can pass this set.

### Found along the way: an h3 test 8% from timing out

`h3_authority_test.py` waits a full five seconds per malformed authority for a
response its reset stream never sends, so its runtime is set by how many
rejections it checks. Measured: **83s against `timeout 90`** before this report
touched it. Adding the six near-misses h1 and h2 carry took it to **113s** and
the shard check failed *on the timeout, not on the server* — a failure that
would have read as a regression in the parser. Resolved by carrying two
rejections on h3 rather than six (**93s**) and raising the budget to `timeout
150`, with the reasoning in the shard file so the next person adding a line
there knows what it costs.

### What was run — the full suite was NOT run

Deliberately targeted, per the operator's instruction:

| Run | Result |
|---|---|
| `run.sh h1/00-setup.sh h1/24-authority.sh h1/25-http-semantics.sh` (pre-fix) | 195 passed, 11 failed — the A/B |
| same (post-fix) | 201 passed, 5 failed (partial-run artifacts) |
| `run.sh tls/20-e2e.sh tls/40-http2.sh` — 72s | **108 passed, 0 failed**, 5 slow-run skips |
| `run.sh tls/60-sni-coalesce.sh` — 93s | **12 passed, 0 failed** |
| `run.sh h1` (the one full-directory acceptance control) — 143s | **477 passed, 0 failed**, 7 slow-run skips |
| `h2_authority_grammar.py` / `h3_authority_test.py` standalone, pre-fix binary | both fail at their pct-encoded acceptance |
| `test/configs/doc_claims_test.py` | **191 claims, "all claims hold", before and after** — the count is unchanged, so no block stopped executing |
| `test/tls/prod_cert_check.sh` | exit 0 before and after: the real 3-cert chain at `/etc/linnea/certs/linnea.amberbio.com/fullchain.pem` still parses |

**The full suite was not run, and `LINNEA_SUITE=full` was not run.** This change
touches no certificate, PEM or DER code — `prod_cert_check.sh` was run anyway,
and is unchanged at exit 0 — but the tls shard's other six files, the quic
shard and the base shard were not exercised, and neither was the h1 shard's
slow set. A deploy still needs the full run.
