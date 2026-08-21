# linnea-probe

`linnea-probe` is a standalone HTTP/1.1, HTTP/2 and HTTP/3 **compliance prober**.
It opens connections to a live server and runs a battery of probes — valid
requests, malformed ones, bad framing, slow drips — reporting for each what the
server did and whether it matches what the RFCs require.

It is a **diagnostic, not a unit test**: every probe prints a line, and the exit
code is the number of outright deviations, so it reads well by eye *and* can gate
CI. It can be pointed at **any** server, not just linnea — that is the point of
having an independent implementation of the same protocols.

Like the server, it is zero-dependency: `nasm` and `ld`, its own `_start`, no
libc, its own TLS 1.3 and QUIC clients. It is built by `make` and installed by
`make install` alongside `linnea`.

## Usage

```
linnea-probe <url> <protocol> [--host <name>] [--big <path>]
linnea-probe --version
```

- `<url>` — the server to probe. `h1` accepts `http://` or `https://`; `h2` and
  `h3` require `https://`.
- `<protocol>` — `h1`, `h2` or `h3`.
- `--host <name>` — the SNI / `Host` name to send, when it differs from the URL
  host (e.g. probing an IP but presenting a virtual-host name).
- `--big <path>` — a large resource for the HTTP/3 urgency/priority probe
  (default `/`).
- `--version` — print the version and exit.

## Output and exit code

Each probe prints one line, prefixed by its verdict:

- `[ OK ]` — the server did what the RFC requires.
- `[DEV!]` — a **deviation**: an invalid request was accepted, or no answer came
  where one was due. These are what the exit code counts.
- `[info]` — the request was handled, but with a different status than expected;
  reported, not counted as a failure.

Each protocol battery ends with a summary line, e.g.:

```
== HTTP/1.1 compliance probes -> 19 probes, 0 deviation(s)
```

**The exit code is the total number of deviations** — `0` when the server is
fully compliant with what the battery checks, non-zero otherwise. That makes it
usable directly in CI:

```sh
linnea-probe https://example.com h2 || echo "compliance deviations found"
```

## Examples

Probe a local server over each protocol:

```sh
linnea-probe http://127.0.0.1:8080 h1
linnea-probe https://127.0.0.1 h2 --host example.com
linnea-probe https://127.0.0.1 h3 --host example.com
```

Probe the live demo (see [the README](../README.md#see-it-live)) over HTTP/3:

```sh
linnea-probe https://linnea.amberbio.com h3
```

## What it checks, and what it does not

The batteries cover request validity and rejection, header and framing rules,
chunked and content-length bodies, slow/partial input, the TLS 1.3 handshake,
HTTP/2 stream and HPACK behaviour, and the HTTP/3 / QUIC transport and QPACK
behaviour — the same surface linnea's own test suite exercises, but driven by a
separate client. It is a compliance probe, not a load generator or a fuzzer, and
a clean run is evidence of conformance on the cases it checks, not a proof of
correctness on every input. See [`security.md`](security.md) on what a passing
battery can and cannot tell you.
