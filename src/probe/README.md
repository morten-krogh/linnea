# linnea-probe

A standalone HTTP compliance prober. Point it at a live server and it runs a
battery of conformance checks — valid requests, malformed requests, dynamic
header-table encoding, slow/dribbled connections — across HTTP/1.1, HTTP/2 and
HTTP/3, and reports where the server deviates from the specs. Because it drives
its own QUIC and TLS 1.3 stack, the HTTP/3 battery reaches into transport- and
handshake-level conformance too — flow control, connection-id rotation, and
ClientHello validation — the kind of thing off-the-shelf HTTP clients can't probe.

It is the client-side sibling of the Linnea server: the same world of `nasm` +
`ld`, no libc, no third-party code. It brings up TCP, TLS 1.3, and a from-scratch
QUIC/HTTP-3 stack itself, reusing only the crypto and protocol primitives in
`src/lib/`.

## Synopsis

```
linnea-probe <url> <protocol> [--host <name>]
linnea-probe --version
```

- `<url>` — `http[s]://<host-or-ipv4>[:port][/path]`. Hostnames are resolved
  over DNS; bare IPv4 and `localhost` are used directly.
- `<protocol>` — `h1`, `h2`, or `h3`. **`h2` and `h3` require `https://`**
  (they are negotiated by TLS ALPN / QUIC). `h1` runs over either scheme.
- `--host <name>` — override the `Host:` header (h1/h2) or `:authority` (h2/h3)
  independently of the connection target. Useful for exercising virtual-host
  routing and cross-certificate misdirection.
- `--big <path>` — a large resource (default `/`) for the HTTP/3 **urgency**
  probe, which needs two sizeable concurrent responses to observe scheduling
  order. Point it at a big asset the server actually has (e.g. a JS bundle or
  image); if the resource is small or absent, that probe reports `[info]`
  (inconclusive — it cannot schedule tiny responses) rather than a deviation.
- `--version` — print the version and exit 0.

The **exit code is the number of deviations** found (capped at 255), so the tool
drops straight into a CI gate:

```sh
linnea-probe https://example.com/ h2 || echo "non-compliant"
```

## Verdicts

Each probe prints one line:

| Tag      | Meaning                                                              |
|----------|---------------------------------------------------------------------|
| `[ OK ]` | The server behaved as the spec requires.                            |
| `[DEV!]` | A deviation: it **accepted invalid input** (a 2xx/3xx to a malformed request) or **dropped a valid request**. Counts toward the exit code. |
| `[info]` | A defensible-but-notable choice — e.g. a rejection with a different status than expected, or a terse connection-close instead of a status. Not a deviation. |

The distinction is deliberate: only *accepting* bad input or *losing* good input
is a compliance failure. A server that rejects malformed input in its own way is
reported as `[info]`, not penalised.

## What it checks

**HTTP/1.1 (19 probes)** — valid GET; keep-alive reuse; missing `Host`;
duplicate `Host`; whitespace before the header colon; a colon-less header; a
version-less request line; an unknown method (→ 501); a known-but-declined method
(`DELETE` → 405 with `Allow`); a field name containing a delimiter (→ 400);
`HTTP/1.0`; a bogus version; an over-long request target (→ 414); bare-LF line
endings; an absolute-form target; that an error response carries `Date`; that
`Expect: 100-continue` draws an interim `100 Continue`; that `close` anywhere in a
`Connection` list closes the socket; and a slowloris drip that watches whether the
server times the request head out.

**HTTP/2 (9 probes)** — a valid GET (→ 200); **HPACK dynamic-table indexing**
(one request inserts `:authority` with incremental indexing, the next references
it by dynamic index); a request with no `:path` (→ `RST_STREAM`); an undecodable
HPACK block (→ `GOAWAY`); a wrong-length `WINDOW_UPDATE` (→ `GOAWAY(FRAME_SIZE_ERROR)`,
i.e. the RFC's code, not a blanket `PROTOCOL_ERROR`); a zero `WINDOW_UPDATE`
increment (→ `RST_STREAM`, the connection surviving); a `PING` bearing a stream id
(→ `PROTOCOL_ERROR`); a wrong-length `RST_STREAM` (→ `FRAME_SIZE_ERROR`); and a
`CONNECT` (→ 405, not a reset).

**HTTP/3 (15 probes)** — the full QUIC/TLS 1.3 handshake in three verified stages
(Initial + Handshake keys; server flight / server Finished decrypted; client
Finished → 1-RTT keys), then a real GET over 1-RTT with a QPACK-encoded request
(→ `:status 200`). Request-stream compliance: no `:path` (→ `RESET_STREAM`); an
undecodable QPACK field section, a negative QPACK Base, and a frame after the
trailer section (→ `CONNECTION_CLOSE`); a control-stream frame with a bad length
(→ connection error); and **urgency scheduling** (`u=07` is *low* priority, not
high — needs `--big`, see above).

Because it drives its own QUIC stack, it also exercises transport- and
TLS-handshake-level behaviour that most HTTP probers can't reach: the server
grants connection flow-control credit (`MAX_DATA`); it issues a `NEW_CONNECTION_ID`
and the probe **rotates its connection id onto it** and confirms the server still
routes it; and the QUIC `ClientHello` is refused when it omits
`signature_algorithms`, doesn't offer TLS 1.3, or offers no cipher the server
implements — each verified by an explicit `CONNECTION_CLOSE`, not a silent drop.

## Building

Built from the repository root alongside the server:

```sh
make            # builds bin/linnea and bin/linnea-probe
make probe      # builds only bin/linnea-probe
sudo make install   # installs both to /usr/local/bin
```

No dependencies beyond `nasm` and `ld`.

## Examples

```sh
# All three protocols against a live server
linnea-probe https://example.com/ h1
linnea-probe https://example.com/ h2
linnea-probe https://example.com/ h3

# Cleartext HTTP/1.1 against a local listener
linnea-probe http://127.0.0.1:8080/ h1

# Exercise vhost routing: connect to one address, claim another authority
linnea-probe https://example.com/ h2 --host other.example.com
```

## Notes

- The prober is a fully independent QUIC/TLS/HTTP client — it does not link the
  Linnea server, only the shared crypto and protocol codecs in `src/lib/`.
- It has been validated at 0 deviations against the Linnea server both locally
  and over the public internet. Deviations reported against other servers are
  the point of the tool, not a defect in it — though genuine prober bugs are of
  course possible; when in doubt, cross-check against a second implementation.
- Source: `src/probe/linnea_probe.asm`.
