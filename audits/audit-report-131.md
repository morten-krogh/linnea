# Audit Report 131

Audited commit `e3781c0` (`audit 130: A proxy sends chunked transfer coding to HTTP/1.0 clients`), 2026-08-28.

This pass examined HTTP request parsing and static-response framing, with a
focus on numeric boundaries shared by HTTP/1, HTTP/2, and HTTP/3. It found one
range-parser overflow: an oversized decimal byte position can wrap into a
small in-file value. No source, test, or configuration file was changed in
this audit; only this report was added.

## Finding 1 — An overflowing byte-range position wraps to the start of a file

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`linnea_http_range_parse`](../src/server/linnea_static.asm#L1018) accumulates
the decimal first-byte and last-byte positions with `imul` and `add`, then
compares the already-wrapped 64-bit result with its `2^62` saturation limit
([lines 1028–1033](../src/server/linnea_static.asm#L1028) and
[1050–1055](../src/server/linnea_static.asm#L1050)). A multiplication that
wraps below that limit bypasses the saturation check. The parser subsequently
treats the wrapped number as an ordinary range position.

For example, `18446744073709551616` is larger than any possible file offset.
As a range start it is valid syntax but unsatisfiable, so the server should
return `416 Range Not Satisfiable`; as an end position it should be clamped to
the end of the representation. Instead both positions wrap to zero. RFC 9110
defines byte-range positions as non-negative decimal integers and requires a
416 response when none of the requested ranges are satisfiable
([RFC 9110 §14.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1)).

### Reproduction

From the repository root, start the existing cleartext fixture and issue three
requests to its 18-byte static file:

```sh
d=$(mktemp -d /tmp/linnea-audit-131-XXXXXX)
./bin/linnea --config test/configs/listen.json >"$d/server.out" 2>"$d/server.err" & server=$!
trap 'kill "$server" 2>/dev/null; wait "$server" 2>/dev/null; rm -rf "$d"' EXIT
sleep 0.3
python3 - <<'PY'
import socket

for value in (b'bytes=18446744073709551616-',
              b'bytes=18446744073709551616-0',
              b'bytes=0-18446744073709551616'):
    client = socket.create_connection(('127.0.0.1', 61080))
    client.sendall(b'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nRange: ' +
                   value + b'\r\nConnection: close\r\n\r\n')
    response = b''
    while True:
        chunk = client.recv(8192)
        if not chunk:
            break
        response += chunk
    lines = response.split(b'\r\n')
    print(value.decode(), lines[0].decode())
    for line in lines:
        if line.lower().startswith((b'content-range:', b'content-length:')):
            print(' ', line.decode())
    client.close()
PY
```

Observed output:

```
bytes=18446744073709551616- HTTP/1.1 206 Partial Content
  Content-Length: 18
  Content-Range: bytes 0-17/18
bytes=18446744073709551616-0 HTTP/1.1 206 Partial Content
  Content-Length: 1
  Content-Range: bytes 0-0/18
bytes=0-18446744073709551616 HTTP/1.1 206 Partial Content
  Content-Length: 1
  Content-Range: bytes 0-0/18
```

The first two requests name a start position beyond the end of an 18-byte
file, yet receive data from byte zero. The third names byte zero through an
end position beyond the file; it should cover the entire file after clamping,
but instead returns only byte zero.

### Impact

Range clients can receive the wrong slice of a representation. In particular,
a resumable-download client asking for an out-of-range offset can be given the
beginning of the file as a `206`, and a client requesting `0` through a huge
end can receive a one-byte partial response. The incorrect `Content-Range`
makes ordinary recovery logic trust the corrupt result. The routine is shared
by the HTTP/1, HTTP/2, and HTTP/3 static-serving paths.

### Recommended fix

Detect overflow before each multiply/addition, or make saturation sticky once
the value reaches the sentinel; never perform another arithmetic accumulation
on the sentinel. Add paired boundary tests for oversized first and last
positions: an oversized first position must return 416, while an oversized
last position with a valid first position must return the complete suffix to
EOF. Include ordinary in-range controls so rejecting every Range field cannot
pass.

## Resolution (2026-08-28)

**CONFIRMED; no code change was made in this audit.** The reproduction above
was run against `e3781c0` and produced the three incorrect `206` responses
shown. The bug is in the shared range helper rather than the HTTP/1 response
writer, so the same arithmetic defect is reachable through its HTTP/2 and
HTTP/3 callers as well.

## Resolution (fix pass, 2026-08-28)

**Finding 1: FIXED** — reproduced byte for byte at `e3781c0`, then fixed in
[`linnea_http_range_parse`](../src/server/linnea_static.asm#L1018). The three
requests in the report returned exactly the three wrong `206`s it prints. A
fourth case the report did not list is wrong the other way: `bytes=-<2^64>`
answered `416` where `bytes=-9999` answers the whole file.

### What the defect actually is

The report names the cause correctly but describes the check as merely
"already-wrapped". It is narrower and worth stating precisely, because it
decides the shape of the fix: the saturation compare ran **after** the
multiply, and `2^62 * 10 = 2^63` **modulo 2^64**, which is still above the
`2^62` limit. So saturation was self-sustaining once reached, and the only way
in was a value that had never saturated. `1844674407370955161` is under `2^62`,
so it passed every check; one more digit made `18446744073709551616 ≡ 0`.
`18446744073709551615` — the digit below the wrap — was always handled
correctly. That is the size boundary `WORKFLOW.md §4` asks a fixture to cross,
and it is one decimal digit wide.

The fix decides saturation **before** each multiply: if the accumulator already
exceeds `2^62 / 10`, another digit cannot leave it under the limit, so it is
set to `2^62` without any arithmetic. Saturation is then genuinely sticky and
no product is ever formed that can wrap. Applied to all three accumulators —
first, last, **and suffix**; the report only reached the first two.

### Measured, before and after (18-byte `hello.txt`)

| Range | before | after |
|---|---|---|
| `bytes=18446744073709551616-` | 206 `bytes 0-17/18` | **416** `bytes */18` |
| `bytes=18446744073709551616-0` | 206 `bytes 0-0/18` | **200**, whole file |
| `bytes=0-18446744073709551616` | 206 `bytes 0-0/18` | **206 `bytes 0-17/18`** |
| `bytes=-18446744073709551616` | 416 | **206 `bytes 0-17/18`** |
| `bytes=18446744073709551615-` | 416 | 416 (unchanged control) |
| `bytes=0-4` / `-7` / `6-9999` / `-9999` / `99-` / `-0` / `5-2` | correct | unchanged |

A 32-digit variant (`99999999999999999999999999999999`) gives the same answers
as `2^64`, confirming the stickiness rather than a fix tuned to one length.

### One deviation from the report's expectation, deliberate

The report asks for `416` on `bytes=18446744073709551616-0`. It gets **200**
(header ignored, full body). After the fix the huge number is `2^62`, so the
spec is `first > last`, which RFC 9110 §14.1.2 makes an *invalid* range-spec,
not an unsatisfiable one — and linnea already answers `200` for `bytes=5-2` and
`bytes=99-0`. Giving the oversized form a `416` would make an overflowing
number the one number in the parser with special semantics, which is the class
of bug being fixed. The report's own principle — a wrapped value must be
treated as an ordinary large value — is what produces the `200`.

### Independent oracle: nginx 

`openssl` has no verdict on Range semantics, so the oracle was **nginx**
(system nginx, an 18-byte file, same eight requests). It agrees where it
matters and its two disagreements are both explained:

| Range | nginx | linnea after fix |
|---|---|---|
| `bytes=4611686018427387904-` (2^62) | 416 | 416 — **same limit, independently** |
| `bytes=18446744073709551616-` | 416 | 416 ✓ |
| `bytes=0-4611686018427387904` | 206 `0-17/18` | 206 `0-17/18` ✓ |
| `bytes=0-18446744073709551616` | 416 | 206 `0-17/18` |
| `bytes=18446744073709551616-0` | 416 | 200 |
| `bytes=5-2`, `bytes=abc` | **416** | 200 |

The last row is the point: nginx answers `416` for *every* malformed Range,
including `bytes=abc`. Its `416` on the two disagreeing rows is house style for
"I did not like this header", not a semantic claim about overflow — so it is
not evidence against ignoring an invalid spec. Where nginx does express a
semantic opinion, on a large-but-representable last position
(`0-4611686018427387904`), it clamps to EOF exactly as linnea now does, which
is also what RFC 9110 §14.1.1 requires. nginx's `416` on `0-<2^64>` is its own
`off_t` overflow guard; linnea's clamp is the RFC answer, and the report agrees
("it should cover the entire file after clamping").

### Coverage, and the A/B

Ten checks added to `test/shards/h1/25-http-semantics.sh`. Run against the
**pre-fix** binary (rebuilt from `git checkout` of the source, tests kept),
5 of them fail:

```
FAIL: overflow first 416          FAIL: overflow backwards 200
FAIL: overflow last to EOF        FAIL: overflow backwards full
FAIL: overflow suffix all
253 passed, 5 failed
```

and after the fix, `258 passed, 0 failed`. The other five are the pairing the
workflow asks for, and they passed *before* the fix too, which is the proof
they are controls and not more of the same assertion: `2^64-1` and the 32-digit
first position must still be `416` (so "refuse every long number" is not a
passing strategy), `bytes=2-5` must still slice `2-5/18` (so "ignore every
Range" is not either), and the pre-existing `bytes=6-9999` / `-9999` / `99-` /
`-0` / `5-2` checks sit directly above them unchanged.

### What was run

- `run.sh h1/00-setup.sh h1/20-serving.sh h1/25-http-semantics.sh h1/50-teardown.sh` — the A/B pair, PARTIAL, 253/5 before and 258/0 after.
- `run.sh h1` — the acceptance control, once, at the end: **489 passed, 0 failed, 7 SKIPPED**. The 7 skips are the pre-existing fast-run skips (proxy sweeps, slowloris), unrelated.
- `test/configs/doc_claims_test.py` — **191 claims before, 191 after**, "all claims hold" both times.
- `test/tls/prod_cert_check.sh` — `ok /etc/linnea/certs/linnea.amberbio.com/fullchain.pem (3 certs)`, exit 0. Not required (no certificate, PEM or DER code was touched) but run as a control.
- nginx as the range oracle, above.

The h2 and h3 static paths call the same helper with no arithmetic of their
own, so the h1 run covers the changed code; the tls shard was not run for this
change.

**The full suite was not run.** `LINNEA_SUITE=full` and the other shards
(`base`, `quic`, `tls`) were deliberately not run — this pass was scoped to the
changed path, and the full suite is run separately before a deploy.
