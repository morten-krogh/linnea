# Audit Report 122

Audited commit `5a218b5` (`http: refuse DEL in an HTTP/1 field value (report 121)`), 2026-08-28.

This pass examined the HTTP/2-to-HTTP/1 proxy translation left open by report
121. It found that a DEL (`0x7f`) in an HTTP/2 field value is copied verbatim
into the HTTP/1.1 request head sent to a backend. No production code, test, or
configuration was changed in this audit; only this report was added.

## Finding 1 — HTTP/2 proxy translates DEL into an invalid HTTP/1 field value

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`emit_field`](../src/server/linnea_hpack.asm#L393) rejects only CR, LF, and
NUL while scanning an HTTP/2 field value. That is correct for an HTTP/2 peer:
RFC 9113 prohibits those three bytes, not DEL. But the proxy rebuild at
[line 769](../src/server/linnea_hpack.asm#L769) appends every ordinary field,
and [`h2_proxy_request`](../src/server/linnea_http2.asm#L2337) copies the
result straight into an HTTP/1.1 request head. DEL is not `field-vchar` in the
HTTP field grammar: RFC 9110 defines that set as `0x21`--`0x7e` or
`0x80`--`0xff`, excluding `0x7f` ([RFC 9110
§5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)).

Thus a legal HTTP/2 request is translated into an invalid HTTP/1.1 request.
The bundled backend is deliberately permissive, which makes the byte visible;
a stricter backend, WAF, or logging parser can reject or interpret the request
differently after Linnea has already routed it.

### Reproduction

Starting at the repository root, run the fixture backend and TLS server, then
send one normal HTTP/2 field and one with literal DEL. The small HPACK encoder
uses only literal, unindexed fields, so the byte sent is explicit.

```sh
d=$(mktemp -d /tmp/linnea-audit-122-XXXXXX)
LINNEA_TEST_RUNDIR="$d" python3 test/proxy_backend.py >"$d/backend.log" 2>&1 & backend=$!
./bin/linnea --config test/configs/tls.json >"$d/linnea.out" 2>"$d/linnea.err" & server=$!
trap 'kill "$server" "$backend" 2>/dev/null; wait "$server" "$backend" 2>/dev/null' EXIT
sleep 0.3
python3 - test/tls/server.crt 61443 <<'PY'
import socket, ssl, sys

ca, port = sys.argv[1], int(sys.argv[2])
def frame(kind, flags, stream, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes((kind, flags))
            + stream.to_bytes(4, "big") + payload)
def literal(name, value):
    return b"\0" + bytes((len(name),)) + name + bytes((len(value),)) + value
def request(value):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    fields = b"".join((literal(b":method", b"GET"),
                        literal(b":scheme", b"https"),
                        literal(b":authority", b"localhost"),
                        literal(b":path", b"/api/headers"),
                        literal(b"x-test", value)))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0)
              + frame(1, 5, 1, fields))
    s.settimeout(3)
    data = b""
    try:
        while True:
            head = s.recv(9)
            if not head:
                break
            while len(head) < 9:
                head += s.recv(9 - len(head))
            length = int.from_bytes(head[:3], "big")
            payload = b""
            while len(payload) < length:
                payload += s.recv(length - len(payload))
            if head[3] == 0 and int.from_bytes(head[5:], "big") == 1:
                data += payload
            if head[3] == 0 and head[4] & 1:
                break
    except OSError:
        pass
    s.close()
    return data

for label, value in (("ordinary", b"before-after"),
                     ("DEL", b"before\x7fafter")):
    body = request(value)
    print(f"{label}: DATA={bool(body)}, backend echo="
          f"{b'x-test: ' + value in body}")
PY
```

Observed output:

```
ordinary: DATA=True, backend echo=True
DEL: DATA=True, backend echo=True
```

The ordinary request is the acceptance control. The DEL request's backend echo
proves that the raw `0x7f` crossed the HTTP/2-to-HTTP/1 boundary, rather than
being rejected or normalised before the proxy connected it to the backend.

### Impact

An HTTP/2 client can make Linnea send an HTTP/1.1 request that is outside the
HTTP/1 field-value grammar. That creates a parser differential at a trust
boundary: downstream components may reject the request, omit the byte while
recording it, or apply a different validation rule than Linnea did.

### Recommended fix

At the HTTP/1 rebuild boundary, reject or safely normalise bytes that cannot
appear in an HTTP/1 field value, including DEL. Keep the existing HTTP/2 input
rule separate: DEL is allowed on an HTTP/2-only request, so the restriction
belongs specifically to a path that emits HTTP/1.1.

Add a raw HTTP/2 proxy test with `x-test: before\x7fafter`, asserting that the
stream is refused (or that the backend receives no request), paired with the
ordinary control above. The negative backend assertion is essential: a 4xx
alone would not prove the invalid h1 head stopped at Linnea.

## Resolution (2026-08-28)

**CONFIRMED and FIXED — and it was larger than the report's one door.**
Reproduced before believing, with the report's own script run verbatim against
`5a218b5`:

```
ordinary: DATA=True, backend echo=True      <- acceptance control
DEL: DATA=True, backend echo=True           <- the raw 0x7f reached the backend
```

After the fix, the same script:

```
ordinary: DATA=True, backend echo=True
DEL: DATA=True, backend echo=False
```

`DATA=True` still holds on the second line because the 400 has a body; the line
that matters is `backend echo=False`. A refusal that answered the client and
still opened the upstream socket would have fixed nothing.

### Three things measured that the report did not claim

**HTTP/3 has the identical defect.** `emit_field` is shared: HPACK calls it for
h2 and QPACK calls it for h3 (`linnea_qpack.asm:231`), and both arm the head
rebuild unconditionally. Measured on the pre-fix binary, same matrix:
`h3 DEL status=200 backend echo=True`. Fixing only h2 would have left the byte
crossing the same boundary from the newer protocol.

**The Cookie join is a second way into the same head.** RFC 9113 8.2.3 lets a
client split Cookie, so those values never become a rebuilt line at all — they
are joined with `"; "` into `ck_buf` and emitted as one h1 `Cookie:` line later.
A check placed only at `.rebuild` leaves it open. Measured before:
`cookie: sid=a<DEL>bc` -> 200, echoed by the backend. After: 400, not echoed.

**`:path` was already closed, and the request line was never at risk.**
`GET /api/headers<DEL>` over h2 is answered with RST_STREAM on the *pre-fix*
binary. Stated because "reject bytes that cannot appear in an HTTP/1 field
value" could have been read as covering the request line too, and that work was
already done. The finding is exactly field values, and nothing wider.

Also checked and found closed: h2 **request** trailers are decoded only to keep
the HPACK table in sync and are never forwarded (`linnea_http2.asm:.trailer_block`,
"Nothing here reaches the request"), so they are not a third door. And
`proxy_h2` does not escape the rule either — a backend spoken to over HTTP/2 is
fed from the same normalised h1 head, which `linnea_h2_client.asm` re-parses
into HPACK, so the h1 grammar is the pivot for both upstream modes.

### The check is deliberately NOT in emit_field

The rebuild block looks like the right place and is not. `.hb_start` is armed
for **every** h2 and h3 request, proxied or not (`linnea_http2.asm:1208`,
`linnea_quic_server.asm:3596`), so the rebuild is where the byte is written but
not where we know it will be sent. Refusing there would refuse a static h2
request that RFC 9113 8.2.1 calls well-formed — the report asked for that
separation and it is right.

So `emit_field` only **records** (`.h1_unsafe`, set by `h1_unsafe_scan` at the
two places a value crosses into h1 text: the rebuilt line and the Cookie join),
and the two proxy entries refuse: `h2_serve.serve_proxy` before the upstream
slot is claimed, and `linnea_h3_proxy_start` before a leg is allocated. Neither
has spoken to a backend at that point, which is what makes the negative
assertion true rather than merely likely.

The control that holds this line is `static-DEL`: the same byte, on a static
location, is still served **200** on h2 and h3. Every other new case would pass
a blanket "refuse DEL everywhere" implementation; that one would not.

### The oracle disagreed, and was asked rather than assumed

nginx 1.30.4 configured as an HTTP/2 front end with `proxy_pass` to an HTTP/1
backend, given the same request:

```
nginx ordinary: backend saw  x-test: before-after
nginx DEL     : backend saw  x-test: before<0x7f>after     (200, forwarded verbatim)
```

nginx translates DEL from h2 straight into the h1 request head, exactly as
linnea did. Refusing is therefore a **deliberate departure**, not conformance
catch-up — the same trade report 121 made at the h1 door, for the same reasons
(RFC 9110 5.5 puts 0x7f in neither `field-vchar` nor `obs-text`; the RFC's
permission to retain an invalid CTL is conditioned on a context "not processed
by any downstream HTTP parser", which a forwarding proxy is the opposite of; no
legal client emits it, so the refusal cannot cost a real request).

One argument here that report 121 did not have: after 121, **the same byte to
the same backend was refused on h1 and forwarded on h2/h3**. The trust boundary
depended on which protocol the client happened to speak, which is the one shape
no reading of the RFCs defends.

### Coverage

`test/proxy_del_field.py` — one matrix, three protocols x six cases, run from
`test/shards/tls/30-h3-proxy.sh` beside the other h1/h2/h3 proxy matrices:

| case | h1 | h2 | h3 |
|---|---|---|---|
| `x-test: before-after` (control) | 200, echoed | 200, echoed | 200, echoed |
| `x-test: a<0x7e>b<0x80>c` (control) | 200, echoed | 200, echoed | 200, echoed |
| `x-test: before<DEL>after` | 400, not echoed | 400, not echoed | 400, not echoed |
| `cookie: sid=abc` (control) | 200, echoed | 200, echoed | 200, echoed |
| `cookie: sid=a<DEL>bc` | 400, not echoed | 400, not echoed | 400, not echoed |
| `x-test: <DEL>`, static route (control) | 400 | **200** | **200** |

Every rejection is paired: the status *and* the backend's echo of the head it
received, so "we changed our mind about the status" cannot pass for "the
invalid h1 request was never sent". The obs-text control is the one most likely
to catch a bad fix — `0x7e` closes VCHAR and `0x80` opens obs-text, so an
implementation clamping at "anything above `0x7e`" would refuse a legal value
and nothing else here would notice. The static row is the one that keeps the
refusal from becoming over-refusal.

**A/B against the pre-fix binary**: it fails exactly four of the eighteen —
`h2 DEL`, `h2 cookie-DEL`, `h3 DEL`, `h3 cookie-DEL` — each with
`status=200 backend echo=True`, and passes the fourteen controls. The fixed
binary passes 18/18. A test never seen failing is not known to test anything;
this one was watched failing, on the four cases it is about and no others.

### What was run, and what was not

- `./test/shards/run.sh tls` — **600 passed, 0 failed, 7 skipped**, against a
  baseline of **599 passed, 0 failed, 7 skipped** measured on `5a218b5` *before*
  any edit. One more check, no regressions. This is the shard that owns both
  changed paths (`40-http2.sh`, `30-h3-proxy.sh`).
- Acceptance control on the loader: every config in `test/configs/` under
  `--test`, on both binaries — 39 accepted and 24 refused (the `bad-*` fixtures)
  in each case, identical. The change adds a field to `linnea_h2_req`, whose
  size drives a stack frame and two `rep stos` counts, so "still parses and
  still starts" is not a formality.
- `test/configs/doc_claims_test.py`: **191 claims pass** before and after. The
  count is what proves no block stopped executing; "all claims hold" alone would
  not.
- `test/tls/prod_cert_check.sh`: `ok /etc/linnea/certs/linnea.amberbio.com/fullchain.pem
  (3 certs): the whole chain parsed`. No certificate, PEM or DER code was
  touched here, so this is a control rather than a requirement — it is recorded
  because report 114 shipped past a green suite.

**THE FULL SUITE WAS NOT RUN.** `LINNEA_SUITE=full` is what gates a deploy and
it has not been run for this change; only the `tls` shard and the checks listed
above were. It must be run before deploying, together with the shards this loop
did not touch.
