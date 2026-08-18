# Configuring linnea

linnea takes exactly one argument: the path to a JSON configuration file.

```
linnea --config /etc/linnea/linnea.json
```

The full option list:

```
  -c, --config <path>  read the configuration from <path>
  -t, --test           check the configuration and certificates, then exit
  -b, --bpf-probe      check that BPF reuseport steering loads, then exit
  -h, --help           print this and exit
```

**A configuration that does not parse, or that breaks one of the rules below,
is refused and the server does not start** — it never runs on a
partly-understood file. Errors go to stderr and name the line and column:

```
$ linnea --test --config linnea.json
linnea: parse error at line 3, column 15: timeout must be between 1 and 3600
$ echo $?
1
```

`--test` parses the file, applies every rule below, and loads the certificates
and keys — then exits 0 without binding anything. Run it before you apply a
change.

> **The one thing `--test` cannot check** is whether the port is actually
> bindable — that needs a real bind, and something else may hold it. Everything
> else a cold start would reject, `--test` rejects: the `host` must be an IPv4
> or IPv6 literal, and the `root` and `log` directories must exist.

---

## The JSON dialect

linnea reads a deliberately small subset of JSON. Everything it rejects, it
rejects loudly rather than guessing.

| | |
|---|---|
| Strings | double quotes only. **No escape sequences** — `\n`, `\"`, `\\` and `\uXXXX` are all errors. A path or header value that needs one cannot be expressed. |
| Numbers | non-negative integers only. No `-`, no `.`, no exponent. |
| Comments | not supported, in any form. |
| Trailing commas | not supported. |
| Duplicate keys | an error, not last-one-wins. |
| Control bytes | an error inside a string. |
| Unknown keys | an error. A typo will not be silently ignored. |

That last pair is worth relying on: if linnea starts, every key you wrote was
understood, and none of them was written twice.

---

## The three levels

Settings live at one of three levels, and **a key is only valid at its own
level**. This is the single easiest thing to get wrong: putting `max_body` on a
server, or `hsts` at the top, is an "unknown key" error rather than a silent
no-op — which is the behaviour you want, but it does mean the error message
tells you the key is unknown when what you really did was put it in the wrong
place.

```
{                             ← GLOBAL: process-wide settings
  "log": "...",
  "workers": 4,
  "servers": [
    {                         ← SERVER: one host:port + hostname (vhost)
      "host": "0.0.0.0",
      "port": 443,
      "hostname": "example.com",
      "locations": [
        {                     ← LOCATION: one path prefix
          "prefix": "/",
          "root": "/var/www"
        }
      ]
    }
  ]
}
```

At most **16 servers**, and at most **8 locations per server**.

---

## Global settings

Written at the top level of the object. Only `log` and `servers` are required;
every other global has a working default.

| Key | Type | Default | Range | What it does |
|---|---|---|---|---|
| `log` | string | — **required** | ≤ 255 | Path to the access log — and to everything else, unless `error_log` names a second file. Its directory must exist; the file itself is created. |
| `error_log` | string | none | ≤ 255 | Path for the **diagnostics**: the connection lifecycle, handshake failures, capture faults — everything that is not a request record. Unset means one file for both, exactly as before this key existed. Reopened alongside `log` on SIGHUP, so a rotation does not leave diagnostics writing into a renamed inode. |
| `servers` | array | — **required** | 1–16 | The virtual servers. At least one. |
| `timeout` | integer | `5` | 1–3600 | Seconds an idle **client** connection is held before closing. |
| `proxy_timeout` | integer | the value of `timeout` | 1–3600 | Seconds an **upstream** exchange may go without progress before the request is failed with 504. Covers the connect, the request send and the response read. Unset means it follows `timeout`, which is what one knob did for both before this key existed — set it when the two want different numbers, which they usually do: a browser may idle for a minute between requests, while a backend that has not answered in five seconds is holding an upstream slot for nothing. |
| `tunnel_timeout` | integer | the value of `timeout` | 1–86400 | Seconds an **upgraded** connection (a WebSocket tunnel) may go without traffic. A tunnel is not a request and should not inherit the request's deadline — an idle WebSocket is normal, and silence cannot tell a quiet peer from a vanished one. Detecting a peer that has gone is the job of RFC 6455 Ping/Pong, which `linnea-ws` does; this is the backstop for a tunnelled backend that does not. HAProxy draws the same distinction with `timeout tunnel`. |
| `head_timeout` | integer | `10` | 1–3600 | Seconds a client has to finish sending a request head. Slow-loris bound. |
| `drain_timeout` | integer | `30` | 1–3600 | Seconds a **reload's** old workers may take to finish what they hold before dropping it ([shutdown.md](shutdown.md)). A stop ignores this — it is immediate. Raise it if you serve long downloads and would rather a reload waited for them; lower it if you would rather old workers went quickly. |
| `max_connections` | integer | `1024` | 1–65536 | Concurrent client connections **per worker** — each worker allocates a pool of this size, so the whole server's ceiling is this times `workers`. (It said "across all workers" until 2026-08-14; measured at 4 concurrent with `max_connections: 2` and `workers: 2`.) |
| `max_per_ip` | integer | `64` | 1–65536 | Concurrent connections from one source address, so one host cannot take the pool. This is the **connection** control; see `rate_limit` for the request one. |
| `rate_limit` | integer | `0` (off) | 0–1000000 | Requests per second one source address may make, across h1, h2 and h3 alike; over it the request is refused with **429**. The bucket holds one second's worth, so a client that has been quiet may spend a second's allowance at once and is then held to the rate.<br><br>Distinct from `max_per_ip`, and on a multiplexed protocol very distinct: h2 and h3 each allow 100 concurrent streams, so the default 64 connections is 6400 requests in flight from one address without breaking any rule.<br><br>**Per worker**, like every pool here — a client whose connections land on several workers is metered by each, so the effective ceiling is this times `workers`. Addresses are keyed exactly as `max_per_ip` keys them: IPv4 in full, native IPv6 on the /64, mapped and loopback addresses in full. |
| `max_upstream` | integer | `256` | 1–65536 | Concurrent connections to proxy backends. |
| `max_body` | integer | `67108864` (64 MiB) | 1–18446744073709551615 | Largest request body accepted, on h1, h2 and h3 alike. A larger upload is refused with 413 before the bytes land. There is deliberately no ceiling below what a 64-bit count holds: this key is meant to BE the limit. |
| `workers` | integer | `0` | 0–256 | Worker processes. **`0` means one per online CPU**, which is the default.<br><br>HTTP/3 steers each connection to its worker by a one-byte index in the connection id, through a BPF reuseport map. That one byte bounds the scheme: **cold-start migration steering works for the whole range (up to 256 workers)**, but a **lossless hot reload keeps at most 128 workers** — the two coexisting generations each need their own half of the 256-entry index space. Above 128, a reload may reset the draining generation's h3 connections (a wider index would be a redesign). Without the BPF program (no `CAP_BPF`), h3 falls back to the kernel's 4-tuple hash, which steers a non-migrating client correctly but neither survives migration nor a reload. |
| `http2` | integer | `1` | 0 or 1 | Offer HTTP/2 via ALPN on TLS listeners. |
| `spill_dir` | string | `/tmp` | ≤ 255 | Directory whose **filesystem** holds request-body capture files. Must exist and support `O_TMPFILE`; no directory entry is ever created in it. **Put this on a real disk.** |
| `port_file` | string | none | ≤ 255 | Path to write the ports actually bound, one line per server: `<hostname> <host> <port>`. Written once, after every listener is up and before any worker is forked. Unset means no file. Mainly for `"port": 0`, where the config cannot say what the port will be. |

> **`"port": 0` and `port_file` go together.** With `0`, the kernel picks a free
> port at bind time and the answer is written back everywhere the configured
> number would have been read: the `listening on host:port` log line, `Alt-Svc`,
> and `port_file`. Every worker's listener binds the *same* chosen port, so the
> `SO_REUSEPORT` set stays a set. Two servers that both say `0` get two
> different ports and two listeners — sharing one listener between vhosts needs
> a real number they can agree on. Across a hot upgrade the inherited socket
> keeps its port, so a reload does not move it.
>
> `port_file` is written through a temporary file and `rename(2)`, so a reader
> polling for it sees either nothing or the finished contents, never a
> half-written line. If it cannot be written the server stops, with the errno —
> silently starting would leave whoever is waiting on the file to time out.
>
> **`spill_dir` decides whether an upload costs RAM or disk.** An upload is
> captured whole before it goes upstream — on HTTP/1.1, HTTP/2 and HTTP/3 alike
> — so the capture is as large as the body, up to `max_body`. The default,
> `/tmp`, is tmpfs on most systems and *always* is under systemd's
> `PrivateTmp`, which makes that capture plain anonymous memory: nothing is
> written back, nothing can be reclaimed, and enough concurrent uploads exhaust
> RAM rather than disk. Point it at a directory on a local disk. The startup
> line names the directory and appends `(tmpfs: uploads are held in RAM, not
> written back)` when it is not one, so you can tell at a glance which you have.
>
> HTTP/2 used to be the exception, streaming the body upstream as it arrived
> and capturing nothing, so an h2 upload cost its flow-control window rather
> than its size. It no longer is: streaming held a backend connection open for
> as long as the client took to upload, which on a slow uplink queued every
> other request to that backend behind it.

---

## Server settings

Each entry of `servers` describes one virtual host: an address to bind, a port,
and the name it answers to. Listeners are dual-stack by default: `"::"` and
`"0.0.0.0"` both accept IPv6 *and* IPv4 clients (the latter as `::ffff:a.b.c.d`).
A specific IPv4 literal binds just that address; a specific IPv6 literal binds
just that address (IPv6 only); and `"v6only": true` makes a `"::"` listener
IPv6-only. Several servers may share one `host`/`port` pair and be told apart by
`hostname` (SNI on TLS, the `Host` header on plaintext).

Servers share a listener by their **effective endpoint**, not the host text:
`"::"` and `"0.0.0.0"` (both `in6addr_any`), and equivalent IPv6 spellings,
name one listener with one vhost table — not two that would split a hostname
between them. Two servers on one effective `address`/`port` must agree on
`v6only`, or the config is rejected.

| Key | Type | Default | Limit | What it does |
|---|---|---|---|---|
| `host` | string | — **required** | ≤ 63 | Bind address: **an IPv4 or IPv6 literal**. `"0.0.0.0"` and `"::"` are the dual-stack wildcard; a specific IPv4 (`"192.0.2.1"`) or IPv6 (`"2001:db8::1"`, `"::1"`) binds that one address. Names are not resolved — `"localhost"` is refused, and a zone id (`"fe80::1%eth0"`) is not accepted. |
| `v6only` | integer | `0` | `0` or `1` | `1` sets `IPV6_V6ONLY`, so a `"::"` host binds **IPv6-only** instead of dual-stack. Meaningful only with `"::"` — a specific IPv4 or IPv6 literal is already single-family. |
| `port` | integer | — **required** | `0`, or 1–65535 | Bind port. **`0` means "let the kernel choose a free one"** — see below. The key itself is still required, so a random port is always something the config asked for. |
| `hostname` | string | — **required** | ≤ 255 | The name this server answers to. Not empty. |
| `locations` | array | — **required** | 1–8 | Path routing. At least one. |
| `cert` | string | none | ≤ 255 | Path to a PEM certificate chain. Enables TLS. |
| `key` | string | none | ≤ 255 | Path to the PEM PKCS#8 private key. |
| `hsts` | **string** | none | ≤ 255 | **The `Strict-Transport-Security` header value**, sent verbatim — e.g. `"max-age=31536000"`. Not a flag. |
| `nosniff` | integer | `0` | 0 or 1 | Send `X-Content-Type-Options: nosniff`. |

> **`hsts` is a string and `nosniff` is a flag.** They sit next to each other
> and behave differently, so `"hsts": 1` is easy to write by mistake. It is
> refused with a message that tells you the shape to use rather than a bare
> quoting complaint.

### Rules across servers

- **`cert` and `key` go together.** One without the other is
  *"server needs both cert and key, or neither"*.
- **A listener is all-TLS or all-plaintext.** Every server sharing one
  `host`/`port` must either all set `cert`/`key` or none of them:
  *"servers sharing a listener must all set TLS or none"*. TLS and cleartext
  cannot share a socket.
- HTTP/3 is offered automatically on a TLS listener whose servers can express
  it, including servers with a `redirect` location: those are served over h3
  like any other, with `Location` emitted from QPACK's static table (RFC 9204
  index 12). They used to be kept off h3 entirely on the premise that QPACK had
  no `Location` to emit, which was never true; the cost was not the redirect
  but that one such location took the whole vhost's QUIC listener with it.
- **HTTP/3 binds one QUIC socket per distinct host on a port**, so a specific
  IPv6 literal beside a wildcard (or two specific hosts) each answer h3 on their
  own address. It used to bind only the first eligible host's, leaving the
  others with h1/h2 and no h3 -- silently, since their TCP still answered. A
  handful of distinct hosts per port is supported; past that the excess serve
  TCP only and the worker logs it.

---

## Location settings

Each entry of `locations` routes one path prefix. **The longest matching prefix
wins**, regardless of the order you write them in — so `/api` and `/` can
coexist and `/api/x` goes to `/api`.

| Key | Type | Default | Limit | What it does |
|---|---|---|---|---|
| `prefix` | string | — **required** | ≤ 255 | Path prefix. **Must start with `/`.** |
| `root` | string | one of three | ≤ 255 | Serve static files from this directory. Must exist. |
| `proxy` | string | one of three | ≤ 255 | Forward to an HTTP/1.1 backend. **`IPv4:port` only**, e.g. `"127.0.0.1:8080"`. |
| `redirect` | string | one of three | ≤ 255 | Reply 301 to this URL prefix. **Must start with `http://` or `https://`.** |
| `cache_control` | string | none | ≤ 255 | `Cache-Control` value for static responses. Only meaningful with `root`. |

> **Exactly one of `root`, `proxy` or `redirect`.** Zero is an error and so are
> two: *"location requires prefix and exactly one of root, proxy or redirect"*.

---

## A complete example

A TLS site with static content, an API proxied to a local backend, a legacy
path redirected away, and a plaintext listener that does nothing but redirect
to HTTPS and serve ACME challenges.

```json
{
  "log": "/var/log/linnea/access.log",
  "workers": 4,
  "timeout": 30,
  "head_timeout": 10,
  "drain_timeout": 30,
  "max_connections": 4096,
  "max_per_ip": 64,
  "max_upstream": 256,
  "max_body": 8388608,
  "http2": 1,

  "servers": [
    {
      "host": "0.0.0.0",
      "port": 443,
      "hostname": "example.com",
      "cert": "/etc/letsencrypt/live/example.com/fullchain.pem",
      "key": "/etc/letsencrypt/live/example.com/privkey.pem",
      "hsts": "max-age=31536000; includeSubDomains",
      "nosniff": 1,
      "locations": [
        { "prefix": "/api",    "proxy": "127.0.0.1:8080" },
        { "prefix": "/static", "root": "/srv/example/static",
          "cache_control": "public, max-age=604800" },
        { "prefix": "/old",    "redirect": "https://example.com/new" },
        { "prefix": "/",       "root": "/srv/example/www" }
      ]
    },
    {
      "host": "0.0.0.0",
      "port": 80,
      "hostname": "example.com",
      "locations": [
        { "prefix": "/.well-known/acme-challenge", "root": "/srv/acme" },
        { "prefix": "/", "redirect": "https://example.com" }
      ]
    }
  ]
}
```

Reading it back: uploads are capped at 8 MiB rather than the 64 MiB default;
`/api/anything` reaches the backend because `/api` is a longer match than `/`;
`/static/...` is served with a week of caching; port 80 carries no `cert`, so
that listener is plaintext, which is allowed because *no* server on port 80
sets TLS.

---

## Applying a change

Check it first, then reload:

```
linnea --test --config /etc/linnea/linnea.json    # exits 0, or says why not
sudo systemctl reload linnea
```

`systemctl reload` sends **SIGUSR2**, which is a zero-downtime re-exec: the
master runs the new binary in `--test` mode first and **refuses the reload if
the configuration is bad, leaving the old generation serving**. So a typo
cannot take the site down. It picks up a new binary at the same time, since it
re-execs — there is no config-only reload.

> **Adding or removing a server needs a restart, not a reload.** A hot upgrade
> hands the listening sockets to the new binary and matches them against the
> configured servers, so it can only work when that set is unchanged. Change
> it and the re-exec'd binary refuses — *"hot upgrade needs an unchanged
> listener set; use restart"* — and **exits**, leaving systemd's
> `Restart=always` to bring the server back. It comes back, but as a
> restart: connections are dropped, and the message goes to the journal, not
> to the access log. Editing values inside existing servers, adding or
> removing *locations*, and changing globals are all fine to reload.

Two things that catch people out:

- **A value read at startup needs two reloads to take visible effect.**
  `drain_timeout` is the clear case: the first reload only loads the new value
  into the generation it starts, and the second is when that generation
  retires under it.
- **Adding a key ties the configuration to the binary.** Unknown keys are an
  error, so a binary older than a key refuses a file that uses it. A reload
  survives that — the master checks first and keeps serving — but a cold start
  does not. Rolling a binary back means removing the newer keys too.

**SIGHUP is not a config reload.** It tells every process to reopen its log
file, which is what a log rotation needs and nothing more:

```
kill -HUP $MAINPID        # reopen the log after rotating it
```

Both signals can be sent without root when the unit runs as the `linnea` user.

For what a stop, a reload and a restart each do to open connections, and what
the drain writes to the log, see **[shutdown.md](shutdown.md)**.
