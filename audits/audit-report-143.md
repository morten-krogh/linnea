# Audit Report 143

Audited commit `433f60e` (`audit 142: no issues found`), 2026-08-29.

This pass examined configuration parsing and its numeric/path bounds, HTTP/1
chunked request-body capture and spill-file lifecycle, TLS record framing and
backend-TLS handshake buffering, and HTTP/3 QPACK response construction plus
proxy response delivery. The configuration, spill, and TLS areas came back
clean on source review: configuration values are range-checked before their
fixed-size destinations are written; chunked capture checks the decoded total,
trailer grammar, and pipelined suffix capacity; and the TLS record consumers
bound their declared fragments before buffering or decrypting them. The HTTP/3
response path has the confirmed field-section-limit defect below. No source,
test, or configuration file was changed in this audit; only this report was
added.

## Finding 1 — HTTP/3 responses do not enforce SETTINGS_MAX_FIELD_SECTION_SIZE

**Severity:** Medium

**Status:** Confirmed on the audited binary.

`SETTINGS_MAX_FIELD_SECTION_SIZE` is a limit a peer advertises for response
field sections it will accept. The normal HTTP/3 response builder stores the
setting in `linnea_qpack_max_fss`, but the proxy builder never consults it:
`linnea_h3_proxy_deliver` calls `linnea_qpack_encode_proxy` and immediately
frames the result with `.dl_put_headers`. A proxied response therefore reaches
clients even when its field section exceeds their advertised limit.

The adjacent static path is incomplete for the same setting: it compares the
encoded QPACK byte count to the limit. HTTP/3 defines the limit using the
uncompressed field-section size (name length + value length + 32 per field),
so an encoded section below the setting can still be one the peer refuses.
For example, the configured static `hello.txt` response has status,
content-type, content-length, validators, cache policy, HSTS, nosniff, date,
and server fields; its uncompressed size is well over 200 bytes even though
the encoder's compact QPACK representation is below 200.

### Reproduction

From the repository root, run this without changing any tracked file. It
starts the existing proxy fixture and server, then streams the existing HTTP/3
SETTINGS probe through `sed` so its request targets the proxy route instead of
the static file:

```sh
set -e
logdir=$(mktemp -d /tmp/linnea-audit-143.XXXXXX)
python3 test/proxy_backend.py >"$logdir/backend.log" 2>&1 &
backend_pid=$!
./bin/linnea --config test/configs/tls-h3-proxy.json >"$logdir/server.log" 2>&1 &
server_pid=$!
cleanup() { kill "$server_pid" "$backend_pid" 2>/dev/null || true; wait "$server_pid" "$backend_pid" 2>/dev/null || true; }
trap cleanup EXIT
sleep 0.5
sed 's/def h3_request(path=b"\/hello.txt")/def h3_request(path=b"\/api\/simple")/' \
  test/quic/h3_settings_validation.py | python3 /dev/stdin 61462
```

The probe injects a valid client control stream carrying
`SETTINGS_MAX_FIELD_SECTION_SIZE = 50`, then sends a GET on stream 0. The
expected handling is `RESET_STREAM` for that request with
`H3_INTERNAL_ERROR` (`0x0102`), because even the small proxied response has
more than 50 bytes of fields. Observed output on `433f60e`:

```text
ok   truncated large SETTINGS (close=0x0106, want close 0x0106)
ok   oversized SETTINGS (close=0x0107, want close 0x0107)
ok   duplicate after 33 identifiers (close=0x0109, want close 0x0109)
ok   valid empty SETTINGS accepted (stayed open)
FAIL tiny MAX_FIELD_SECTION_SIZE resets the stream (close=0x0005, want reset 0x0102)
ok   generous MAX_FIELD_SECTION_SIZE serves (fss_reset=False)
FAIL (1)
```

The unrelated `close=0x0005` is the probe's documented follow-up
stream-initiator error; the distinguishing result is the absence of the
required stream reset, which the probe captures directly.

### Impact

An HTTP/3 client that advertises a small but valid field-section limit can be
sent a proxied response it declared it cannot process, producing an
interoperability failure for every matching request. Static responses can also
exceed the same limit whenever QPACK compression hides their uncompressed
field size. This is especially likely with security and cache headers, where
the server adds many fields itself.

### Recommended fix

Compute the HTTP/3 field-section size using the RFC 9114 accounting rule while
encoding (each field's name length, value length, and 32-byte overhead), and
apply the same check to both `linnea_qpack_encode_response` and
`linnea_qpack_encode_proxy`, including interim proxy heads. Before any bytes
are sent, route an over-limit response through the existing stream-reset path;
do not use the encoded QPACK length as a substitute for the peer's limit.

## Resolution (fix pass)

**Finding 1: FIXED.** Both halves reproduced on `433f60e`, and both are fixed.

### What was measured before touching anything

The report's own reproduction, run verbatim on the audited binary, against
`test/configs/tls-h3-proxy.json` and `test/proxy_backend.py`:

```text
FAIL tiny MAX_FIELD_SECTION_SIZE resets the stream (close=0x0005, want reset 0x0102)
```

and, with a probe of my own that only advertises a limit and reports whether the
stream came back reset with `H3_INTERNAL_ERROR`:

```text
pre-fix   /api/simple  limit=50:     reset=False      <- (a) proxy: never checked
pre-fix   /hello.txt   limit=50:     reset=True
pre-fix   /hello.txt   limit=200:    reset=False      <- (b) static: encoded length compared
pre-fix   /hello.txt   limit=100000: reset=False
```

Row 3 is the whole of the second half of the report: 200 is above what QPACK
encodes that response to and below what RFC 9114 4.2.2 says it measures.

### The independent oracle

`curl --http3` (8.15.0, ngtcp2/nghttp3 — a stack that is not ours) fetched the
same three resources, and the RFC 9114 4.2.2 rule was applied to the fields it
reported, name + value + 32 each:

```text
/hello.txt     626   (:status, content-type, content-length, accept-ranges,
                      vary, etag, last-modified, nosniff, HSTS, date, server)
/api/simple    378   (:status, content-length, via, HSTS, nosniff, date, server)
/api/bigearly  six interim sections of 1670, then a 377 final:
               largest section 1670, sum 10397
```

Those numbers are the acceptance criterion, not an estimate. After the fix the
server's own boundary lands on them **to the byte**:

```text
post-fix  /hello.txt    limit=625:  reset=True     limit=626:  reset=False
post-fix  /api/simple   limit=377:  reset=True     limit=378:  reset=False
post-fix  /api/bigearly limit=1669: reset=True     limit=1670: reset=False
                        limit=2000: reset=False    (the 10397 sum does not count)
```

Nothing about certificates, PEM or DER was touched; `test/tls/prod_cert_check.sh`
was run anyway and exits 0 (`/etc/linnea/certs/linnea.amberbio.com/fullchain.pem`,
3 certs, whole chain parsed).

### What was changed

`linnea_qpack.asm` now accumulates the RFC 9114 4.2.2 size — name length + value
length + 32 per field, **uncompressed** — into `linnea_qpack_fss_size` as it
encodes, in both `linnea_qpack_encode_response` and `linnea_qpack_encode_proxy`
(macro `QFSS`, sitting beside the existing `QROOM` bound checks). The encoded
QPACK length is no longer used as a proxy for it anywhere.

`linnea_http3.asm` compares that size, not `rbp`, with `linnea_qpack_max_fss`.

The proxy half needed one thing the report's recommendation does not mention, and
it is the reason the check could not simply be copied into the second encoder: a
proxied response is encoded on an **upstream completion**, long after the
per-request globals stopped describing the connection that asked for it —
`linnea_qpack_max_fss` at that moment holds whatever limit the last h3 request on
this worker advertised, which may be another connection entirely, or none. So the
size travels with the response instead: `linnea_h3_proxy_deliver` records the
largest section it encoded (interim heads included, each measured separately) in
the new `linnea_h3d_fss` parameter, and `linnea_quic_h3_deliver` — which has
already identified the owning connection and validated its generation — compares
it against that connection's own `max_fss_peer`, resetting the stream with
`H3_INTERNAL_ERROR` and freeing the slot exactly as `.serve_fss_over` does on the
static path. The canned 502/503/504 path (`linnea_h3_proxy_fail`) carries its
size the same way, so it cannot inherit a stale one.

Per **section**, not per response: RFC 9114 4.2.2 bounds a field section, and an
interim chain is several. `/api/bigearly` with a limit of 2000 serves (largest
section 1670) though its sections sum to 10397 — an implementation that added
them up would refuse a response the client accepts, which is the failure mode
worth more than the one being fixed.

### Coverage, and the A/B that proves it

`test/quic/h3_fss_limit.py` (new), wired into `test/shards/tls/30-h3-proxy.sh`
beside the other h3 proxy checks. Seven rows, every rejection paired with an
acceptance above the same response's measured size:

```text
                                                   pre-fix   post-fix
proxied response over the peer's limit is reset      FAIL       ok
proxied response under it is served                   ok        ok
proxied response with no limit advertised is served   ok        ok
static response over the peer's limit is reset       FAIL       ok
static response under it is served                    ok        ok
an interim head over the limit resets the stream     FAIL       ok
an interim chain whose sum exceeds the limit serves    ok        ok
```

The pre-fix column is a real run against a binary rebuilt from `git stash` of
this change, not a prediction. The acceptance rows are what a fix that reset
every stream carrying a limit — or that summed the interim sections — fails.

### What was run

* `./test/shards/run.sh base` — **before** the change, 71 passed / 0 failed, and
  again after: byte-identical PASS list. That is the acceptance control the
  workflow asks for first: every config in `test/configs/` still loads, and the
  qpack encoder's own bound test (`qpack-encode 6/6`) still holds.
* `test/configs/doc_claims_test.py` — 200 claims, "all claims hold", on the
  pre-fix binary and the post-fix one. The count is stated because "all claims
  hold" prints either way.
* `./test/shards/run.sh tls/20-e2e.sh tls/30-h3-proxy.sh` — the targeted file run
  for the changed proxy path: **100 passed, 0 failed, 2 SKIPPED** (98 before this
  report; the new check and its skip line are the two). Announces PARTIAL RUN.
* `./test/shards/run.sh quic` — one full-directory run, at the end, as the
  acceptance control for the static h3 path: **98 passed, 0 failed, 13 SKIPPED**
  (the skips are the `extensive`-gated ones a fast run always skips).
* `test/quic/h3_settings_validation.py` directly against `tls-h3.json`, because
  the quic shard skips it in a fast run and it is the check this finding
  supersedes: all six rows ok, including "tiny ... resets" and "generous ...
  serves".
* The report's own reproduction, verbatim, post-fix: the row that read `FAIL` on
  `433f60e` now reads `ok tiny MAX_FIELD_SECTION_SIZE resets the stream
  (reset=0x0102, want reset 0x0102)`.

**The full suite was not run.** No `LINNEA_SUITE=full`, no `./test/run_shards.sh`
over everything: base, the two named tls files, and the quic shard are the whole
of it, plus the standalone probes named above. h1 and the rest of tls were not
run — the change is confined to the HTTP/3 response builders and the h3 delivery
path, and touches no h1, h2 or TLS code.
