# Audit Report 140

Audited commit `e49f3dc` (`audit 139: require Upgrade on proxied 101`), 2026-08-29.

This pass examined configuration-provided response-field construction, HTTP/1 request-header and framing controls, TLS encrypted-record buffering, and HTTP/2 SETTINGS/window state. The HTTP/1 controls reject DEL received from a client, and the TLS and HTTP/2 paths came back clean on source review: the TLS drain bounds each complete record against its input buffer, and the HTTP/2 window paths retain signed-window and 31-bit overflow checks. It found one configuration/output-boundary defect: the JSON string parser accepts DEL in values which are emitted verbatim as HTTP response field values. No source, test, or configuration file was changed in this audit; only this report was added.

## Finding 1 — Configuration permits DEL in response header values

**Severity:** Low  
**Confidence:** High  
**Status:** Open

`linnea_parse_string` rejects bytes below `0x20`, but accepts `0x7f` ([`linnea_config_parse.asm`](../src/server/linnea_config_parse.asm#L1897)). That is valid enough for its small JSON subset, but it is not valid in an HTTP field value: RFC 9110 defines `field-vchar` as `VCHAR` (`0x21`–`0x7e`) or `obs-text`, excluding DEL ([RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)).

The parser uses this unchecked string form for `cache_control` and `hsts`. The HTTP/1 serving path writes both values without validation ([`linnea_http.asm`](../src/server/linnea_http.asm#L3566), [`linnea_http.asm`](../src/server/linnea_http.asm#L3605)); HTTP/2 and HTTP/3 encode the same configured bytes as field values. A redirect target has the same issue when used to construct `Location`.

### Reproduction

From the repository root, copy the existing cleartext fixture outside the tree, add one DEL byte to its configured `Cache-Control` value, start Linnea, and make a direct request.

```sh
cfg=$(mktemp /tmp/linnea-140-XXXX.json)
cp test/configs/listen.json "$cfg"
perl -0777 -i -pe 's/"max-age=60"/"max-age=60\x7f"/' "$cfg"
./bin/linnea --config "$cfg" >/tmp/linnea-140.out 2>/tmp/linnea-140.err & pid=$!
trap 'kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -f "$cfg"' EXIT
sleep 0.3
python3 - <<'PY'
import socket

s = socket.create_connection(('127.0.0.1', 61080))
s.sendall(b'GET / HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')
b = bytearray()
while part := s.recv(8192):
    b.extend(part)
print(repr(bytes(b).split(b'\r\n\r\n')[0]))
PY
```

Observed output (excerpt):

```
b'...\\r\\nCache-Control: max-age=60\\x7f\\r\\nConnection: close'
```

Linnea accepts the configuration and sends the prohibited byte in a response field value. In contrast, the normal HTTP/1 request parser deliberately refuses DEL in received field values, so the server's configuration and its wire parser disagree about the syntax of the same HTTP construct.

### Impact

An operator can deploy a configuration that makes Linnea author malformed HTTP/1, HTTP/2, and HTTP/3 response fields. Strict clients, intermediaries, or downstream protocol translators can reject such responses or handle them inconsistently. This requires configuration-write access, so it is a correctness and deployment-reliability defect rather than a remote header-injection primitive.

### Recommended fix

Add a shared validation helper for configuration strings that will become HTTP field values, accepting only `0x21`–`0x7e` and `0x80`–`0xff` (with OWS only where that particular field deliberately permits it). Apply it to `cache_control`, `hsts`, and the configured portion of redirect `Location`. Keep URL/scheme validation separate from field-value validation. Add paired startup tests: a conventional `Cache-Control`/HSTS/redirect value must still load and be emitted, while otherwise identical values containing DEL must be rejected before the listener starts.

---

## Resolution (fix pass)

**Finding 1: FIXED.** The report is right, and its reproduction is exact.

### Reproduced first

The report's script, verbatim, against `e49f3dc`:

```
b'HTTP/1.1 200 OK\r\n...\r\nCache-Control: max-age=60\x7f\r\nConnection: close'
```

DEL reached the wire in a response field value, from a configuration the
server had just accepted.

### The oracle: one of three parsers refuses the response outright

`openssl` is not an oracle for HTTP field grammar, so I asked the parsers that
are. All three were pointed at the pre-fix binary serving the DEL:

| parser | verdict |
|---|---|
| node v22.22.2 / llhttp | **`HPE_INVALID_HEADER_TOKEN`: "Invalid header value char"** — the whole response is discarded |
| curl 8.15.0 (libcurl/8.15.0) | accepts, prints `Cache-Control: max-age=60^?` |
| python3 `http.client` | accepts, `getheader('Cache-Control') == 'max-age=60\x7f'` |

So the report's impact claim is neither theoretical nor universal: a
widely-deployed parser drops the entire response, while two lenient ones pass
the byte through. That spread — some recipients fine, one silently losing every
response — is the worst shape this defect could take.

And linnea's own request parser was measured beside them, on the same byte in a
*request* field value:

```
GET / HTTP/1.1 ... X-Probe: a\x7fb   ->   HTTP/1.1 400 Bad Request
```

The server refused on receipt what it authored on send. That disagreement was
the finding.

### Acceptance controls, run before anything was tightened

Every config in `test/configs/`, generated through `genports.py` exactly as the
suite does, plus both shipped configs — 65 files — run through `--test` on the
pre-fix binary, recorded, then re-run after the change:

```
diff prefix.txt postfix.txt   ->   empty
ACCEPTANCE: all 63 test/configs verdicts identical
config/linnea.json      | pre: (accepted) | post: (accepted)
config/linnea-tls.json  | pre: spill_dir is not an existing directory | post: (same)
```

Not a sample, and not just the exit codes: the first line of output too, so a
config that started failing for a *different* reason would show up.

### The fix

`field_value_ok` in `src/server/linnea_config.asm`, called from
`linnea_config_validate` — which both startup and `--test` run before any
listener is opened, so a configuration that would author a malformed response
never serves one. It accepts `field-vchar` (`0x21`–`0x7e`, `0x80`–`0xff`), and
optionally SP/HTAB strictly *between* two of those. Applied to `hsts`
(server), `cache_control` (location), and the `redirect` target after its
existing scheme check.

### Where I did not follow the recommendation, and the measurement why

The recommended rule was "accepting only `0x21`–`0x7e` and `0x80`–`0xff` (with
OWS only where that particular field deliberately permits it)". Read literally,
whitespace is opt-in per field. I measured what that would refuse before
choosing:

```
test/configs/tls-h3-canned.json:  "cache_control": "public, max-age=600"
test/configs/tls-h3-maxhdr.json:  "hsts": "max-age=31536000; includeSubDomains; preload; ..."
test/configs/tls-h3-proxy.json    "hsts": "max-age=31536000"
docs/config.md worked example:    "cache_control": "public, max-age=604800"
```

An interior space is not a concession to those fields, it is what RFC 9110 §5.5
`field-content` *is*: `field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]`.
So `hsts` and `cache_control` permit it between two field-vchars, and the rule
is the RFC's rather than a per-key allowance. `redirect` takes none at all —
it is the head of a `Location` URL, which cannot carry whitespace — and that is
the one place a per-field difference is real.

Two smaller calls, both stated because they are tightenings:

- **Leading and trailing whitespace are refused** on all three. RFC 9110 §5.5:
  "A field value does not include leading or trailing whitespace." Every
  recipient would OWS-strip it, so this is the one change here that could
  refuse something that used to work. Measured: no config in `test/configs/`,
  in `config/`, or in `docs/config.md` has one.
- **HTAB is unreachable from a config today** — the JSON string parser refuses
  every byte below `0x20`, so `"a\tb"` dies at parse with "control character in
  string" (measured). The branch is kept so `field_value_ok` is a correct
  field-value predicate for the next caller rather than one that happens to
  work here.

### Coverage, proved by A/B against the pre-fix binary

Five checks in `test/shards/base/10-config.sh`, with the fixtures built in the
script rather than checked in — the byte that matters is invisible in a
fixture, and worse than a fixture nobody can read is one a stray reformat
silently repairs.

```
pre-fix   43 passed, 4 failed   FAIL: cache_control with DEL (exit=124, wanted 1)
                                FAIL: hsts with DEL
                                FAIL: redirect with DEL
                                FAIL: redirect with a space
                                PASS: spaces and obs-text load
post-fix  47 passed, 0 failed
```

`exit=124` is the tell: pre-fix the server did not reject the config, it
*started serving* and had to be timed out. The paired acceptance control —
`"public, max-age=600, immutable, x=<obs-text>"` with
`"max-age=31536000; includeSubDomains; preload"` — passes on **both** binaries,
so no blanket-reject implementation can satisfy this set.

`docs/config.md` gained the rule (a "Values that become response headers"
section plus the three table rows), and `doc_claims_test.py` gained nine
matching claims: **191 claims before, 200 after, all hold**. Same A/B there:
on the pre-fix binary exactly the five rejection claims fail and the four
acceptance claims (interior spaces ×2, obs-text, conventional redirect) pass.

### What was run

Deliberately narrow — this change is config-load only.

| run | result |
|---|---|
| `run.sh base/10-config.sh` (iteration, then A/B) | 47 passed, 0 failed (PARTIAL) |
| `run.sh h1/00-setup.sh h1/20-serving.sh` | 83 passed, 0 failed (PARTIAL) — `cache-control from config`, `304 repeats cache-control` |
| `run.sh tls/20-e2e.sh tls/50-e2e-teardown.sh` | 28 passed, 0 failed (PARTIAL) — `hsts header (h1)`, `hsts on a 404`, `hsts on a proxy 502` |
| `run.sh base` (the one full-directory control, 16s) | 71 passed, 0 failed |
| `test/tls/prod_cert_check.sh` | rc 0 — `/etc/linnea/certs/linnea.amberbio.com/fullchain.pem (3 certs): the whole chain parsed` |

The two file runs exist because rejecting is only half of it: `Cache-Control`
and `Strict-Transport-Security` still have to *reach the wire*, and those are
the checks that say so.

`prod_cert_check.sh` was run although this change touches no certificate, PEM
or DER code — it is in the base shard regardless, and it is cheaper to run it
than to argue that it was not needed.

**The full suite was not run**, and neither was `LINNEA_SUITE=full`. The four
runs above are the whole of it. The last full suite predates reports 107-140.
