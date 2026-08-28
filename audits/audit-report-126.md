# Audit Report 126

Audited commit `e3f87c2` (`audit 125: HTTP/1.1 rejects a valid CONNECT authority-form as 400`), 2026-08-28.

This pass followed the new HTTP/1.1 CONNECT authority-form path into the shared
authority parser. It found that the parser implements bracketed IPv6 literals
but rejects the other grammar alternative for an IP literal, IPvFuture. No
production code, test, or configuration was changed in this audit; only this
report was added.

## Finding 1 — The authority parser rejects valid IPvFuture literals

**Severity:** Low
**Confidence:** High
**Status:** Open

[`linnea_http_handle`](../src/server/linnea_http.asm#L1024) now gives a
CONNECT target to the shared
[`linnea_http_authority_host`](../src/server/linnea_hpack.asm#L1901) parser.
For a bracketed target, the parser scans to `]` and then unconditionally copies
the contents to `ah_ip6_lit` and calls
[`linnea_network_parse_ipv6`](../src/server/linnea_hpack.asm#L1979). A failed
IPv6 parse takes `.ah_bad`; there is no IPvFuture branch.

That is narrower than `uri-host`. HTTP defines `uri-host` by reference to the
URI `host` grammar ([RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1)), and HTTP/1.1 defines CONNECT authority-form as `uri-host ":"
port` ([RFC 9112 §3.2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3)).
The referenced URI grammar defines an IP-literal as either an IPv6 address or
an IPvFuture value; `v1.fe80` and `vF.a:b-c` both satisfy its IPvFuture
production ([RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2)).

### Reproduction

From the repository root, start the cleartext authority fixture and send one
ordinary IPv6 literal control followed by two valid IPvFuture CONNECT targets.
The server does not implement CONNECT, so each syntactically valid target
should reach its 405 response; only the literal syntax changes.

```sh
d=$(mktemp -d /tmp/linnea-audit-126-XXXXXX)
./bin/linnea --config test/configs/authority-vhosts.json >"$d/out" 2>"$d/err" & server=$!
trap 'kill "$server" 2>/dev/null; wait "$server" 2>/dev/null' EXIT
sleep 0.3
python3 - <<'PY'
import socket

for target in (b'[::1]:443', b'[v1.fe80]:443', b'[vF.a:b-c]:65535'):
    sock = socket.create_connection(('127.0.0.1', 61466))
    sock.sendall(b'CONNECT ' + target + b' HTTP/1.1\r\n'
                 b'Host: alpha.test\r\n\r\n')
    print(target, b'->', sock.recv(256).split(b'\r\n', 1)[0])
    sock.close()
PY
```

Observed output:

```
b'[::1]:443' b'->' b'HTTP/1.1 405 Method Not Allowed'
b'[v1.fe80]:443' b'->' b'HTTP/1.1 400 Bad Request'
b'[vF.a:b-c]:65535' b'->' b'HTTP/1.1 400 Bad Request'
```

The IPv6 line is the acceptance control for the bracketed-literal and port
paths. The two following targets are valid authority-form by the same grammar,
but are rejected before normal method classification. They therefore receive
the syntax-error response rather than the unsupported-method response that the
control receives.

### Impact

Valid HTTP/1.1 CONNECT requests using an IPvFuture literal cannot reach
Linnea's declared unsupported-method handling. Because the same parser is used
for `Host` and HTTP/2/HTTP/3 `:authority`, the narrower grammar also rejects
that legal authority spelling on the other request paths. This is currently an
interoperability and protocol-classification error; it would become a direct
connectivity failure if CONNECT or a vhost using a future literal were later
implemented.

### Recommended fix

Keep the existing IPv6 validation, but add the RFC 3986 IPvFuture alternative
to the bracketed-literal branch: case-insensitive `v`, one or more hexadecimal
digits, `.`, then one or more `unreserved`, `sub-delims`, or `:` bytes. It
should return the existing bracket-stripped host slice without calling the IPv6
parser. Add paired h1 CONNECT tests for `[::1]:443` and `[v1.fe80]:443`, both
expecting 405, plus malformed near-misses such as `[v.fe80]:443` and
`[v1.]:443` expecting 400. Exercise the shared grammar through h2 and h3 as
well so the fix does not make their authority handling diverge.

## Resolution (2026-08-28)

**CONFIRMED, and the recommendation is accepted and implemented.** The report's
own reproduction script, run unchanged at `e3f87c2`, printed its three lines
exactly: `[::1]:443` → 405, `[v1.fe80]:443` → 400, `[vF.a:b-c]:65535` → 400.

### The fix

`linnea_http_authority_host` now implements both alternatives of RFC 3986
3.2.2's `IP-literal`, not one. The branch is taken on the first byte inside the
brackets: an IPvFuture opens with the version flag `v`, `v` is not a hex digit,
so the choice is made outright with nothing to backtrack. The IPv6 path is
byte-for-byte what it was — same length cap, same copy, same
`linnea_network_parse_ipv6` — and the new path validates
`"v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )` in place and returns the
same bracket-stripped slice. The port check after the `]` was given a label and
is now reached from both, so there is one port rule and not two.

The version flag is matched case-insensitively (`or al, 0x20`): ABNF string
literals are case-insensitive by RFC 5234 2.3, and 3986 says so again in prose.

No `LINNEA_MAX_IP6_LIT` cap on the new path, deliberately: that constant exists
because the IPv6 branch copies into a 64-byte `.bss` buffer to NUL-terminate for
the parser. The IPvFuture branch copies nothing — it returns an offset and a
length into the caller's buffer, exactly as the already-unbounded reg-name path
does. Checked the four call sites (`linnea_http.asm` x3, `linnea_http2.asm` x2,
`linnea_quic_server.asm`) before relying on that: every one of them consumes the
result as ptr/len, and none copies it into a fixed buffer.

### What three independent oracles say

`openssl` has no verdict to give here — this is URI grammar, not certificates —
so the oracles are the implementations that also parse this text. The
disagreements are the interesting part, and all three are explainable:

| authority | linnea (after) | nginx 1.30.4 | python `urlsplit` | node/WHATWG | curl 8.15 |
|---|---|---|---|---|---|
| `[::1]:443` | accept | accept | accept | accept | accept |
| `[v1.fe80]:443` | accept | accept | accept | reject | reject |
| `[vF.a:b-c]:65535` | accept | accept | accept | reject | reject |
| `[V9.x]` | accept | accept | **reject** | reject | reject |
| `[v.fe80]`, `[v1.]`, `[v1]`, `[vg.x]` | reject | **accept** | reject | reject | reject |
| `[v1.a%20b]` | reject | reject | **accept** | reject | reject |
| `[deadbeef]`, `[gggg::1]` | reject | **accept** | reject | reject | reject |

- **nginx accepts almost everything between brackets.** Asked
  `Host: [deadbeef]`, `[v1.]`, `[v1]`, `[vg.x]`, `[V9.x]` and `[gggg::1]` it
  answers 200 to all six; only bytes that are not authority bytes at all (`%`,
  `/`) draw a 400. So it is a useful oracle for the acceptance half and no
  oracle at all for the rejection half, and it is not a reason to loosen ours:
  linnea has refused `[deadbeef]` since report 3 and still does.
- **python refuses `[V9.x]`.** That is python's bug, not a real constraint —
  `IPvFuture = "v" 1*HEXDIG ...` is an ABNF string literal and therefore
  case-insensitive, and 3986 3.2.2's prose says "starts with `v`
  (case-insensitive)" in as many words. We accept it.
- **python accepts `[v1.a%20b]`.** `pct-encoded` is in `reg-name` and is *not*
  in `IPvFuture`; python is simply lenient. We reject it — and so, for once,
  does nginx (400), which is the one bracketed input in this table it refuses
  besides `/`.

nginx, asked the report's three CONNECT lines, answers 405/405/405 — the same
verdicts this build now gives.

### One thing declined, with the measurement

I did **not** change the empty-port rule. `[v1.x]:`, `[::1]:` and `plain.test:`
are all 400; RFC 3986's `port = *DIGIT` does permit an empty port, and python
accepts all three. Measured on both binaries: those three answer 400 before the
fix and 400 after it. It is one uniform pre-existing policy across all three
host forms, it is asserted by name in `h2_authority_grammar.py` and
`h3_authority_test.py`, and loosening it is a separate decision about a
different production. Widening one alternative of `IP-literal` is not licence to
also widen `authority`.

### Where the parser moved, and where it did not

A 33-case differential over the `Host` header, both binaries, same fixture. The
**only** cells that changed are the seven well-formed IPvFuture spellings,
400 → 200. `[::1]`, `[::1]:443`, `[::ffff:1.2.3.4]` stayed 200; `[deadbeef]`,
`[gggg::1]`, `[::1`, `[::1]x`, `[]`, `beta.test:garbage` stayed 400; vhost
routing (`alpha.test` → main root, `beta.test` → `www/sub`) is unchanged. That
last part is the point of the exercise — tightening or loosening a shared parser
is how a server starts serving the wrong site.

### Coverage, and the A/B that proves it

Every acceptance is paired with a near-miss one byte away, because a build that
stopped validating bracket contents would pass every acceptance line on its own.

- `test/shards/h1/24-authority.sh` — 12 checks: four acceptances
  (`[v1.fe80]:443`, `[v1.fe80]`, `[vF.a:b-c]:65535`, `[V9.x]`), eight rejections
  (`[v.fe80]`, `[v1.]`, `[v1]`, `[vg.x]`, `[v1.a/b]`, `[v1.a%20b]`,
  `[v1.fe80]:65536`, `[v1.fe80]x`).
- `test/shards/h1/25-http-semantics.sh` — 5 CONNECT checks: 405 for
  `[v1.fe80]:443` and `[V9.x]:80`, 400 for `[v.fe80]:443`, `[v1.]:443` and the
  portless `[v1.fe80]`.
- `test/tls/h2_authority_grammar.py` — 2 new acceptances, 5 new malformed cases.
- `test/quic/h3_authority_test.py` — 1 new acceptance, 5 new malformed cases.

h2 and h3 are not decoration: the report is right that this is one shared
parser, and an authority spelling legal on one protocol and not another is the
divergence those two files exist to catch.

**A/B against the pre-fix binary, kept aside before rebuilding:**

| | pre-fix | post-fix |
|---|---|---|
| `run.sh h1/00-setup h1/24-authority h1/25-http-semantics h1/50-teardown` (25s) | 180 passed, **11 failed** | 186 passed, 5 failed |
| `h2_authority_grammar.py` | **fails**: `valid IPvFuture :authority was not served over h2` | `ok` |
| `h3_authority_test.py` | **fails**: `IPvFuture authority not served locally` | `ok` |

Six of the eleven pre-fix failures are the new acceptance lines; the other five
(`range vs 304`, three `if-range`, `request log 404`) fail identically on both
binaries and are an artefact of naming files rather than the directory — they
need `h1/20-serving.sh`'s state, and all five pass in the full shard run below.
The new **rejection** lines pass on the pre-fix binary, as they must: that build
rejected everything bracketed-and-not-IPv6. Only the acceptance half can tell
the two builds apart, which is exactly why it is there.

### What was run

- The report's reproduction script, verbatim, at `e3f87c2`.
- A 33-case `Host` differential and a 12-case CONNECT differential, each against
  both binaries, compared cell by cell against `urllib.parse` and against
  nginx 1.30.4 driven from the same script.
- **Acceptance control first:** all 63 `test/configs/*.json` under
  `./bin/linnea --test`, both binaries — `--test` verdicts **identical**,
  no config that loaded before stopped loading.
- `test/tls/prod_cert_check.sh` → `rc=0`, the real 3-certificate
  `linnea.amberbio.com` chain parsed. This change touches no certificate, PEM or
  DER code, so it was not required; it is cheap and it is the step this tree
  learned the hard way.
- `test/configs/doc_claims_test.py`: **191 claims** pre-fix, **191** post-fix,
  "all claims hold" both times. The count is the check, not the sentence.
- Targeted single-file h1 runs for the edit loop (25s each) and the two protocol
  scripts run directly against `tls-h2.json` and `tls-sni.json` servers, so that
  h2 and h3 could be exercised without paying the 486s tls shard.
- **One directory run, at the end:** `./test/shards/run.sh base h1` →
  **528 passed, 0 failed, 7 SKIPPED**, 2m40s, saved to `/tmp/final126.log` and
  read from the file thereafter. All 17 new h1 checks pass inside it.

**The full suite was not run.** `LINNEA_SUITE=full` and the tls and quic shards
were deliberately not run in this loop; they belong to the separate pre-deploy
run. The h2 and h3 evidence above is from running those two scripts directly,
which is narrower than `run.sh tls` and is stated as such.
