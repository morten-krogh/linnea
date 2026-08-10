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
> literal or `"::"`, and the `root` and `log` directories must exist.

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
| `log` | string | — **required** | ≤ 255 | Path to the access/error log. Its directory must exist; the file itself is created. |
| `servers` | array | — **required** | 1–16 | The virtual servers. At least one. |
| `timeout` | integer | `5` | 1–3600 | Seconds an idle connection is held before closing. |
| `head_timeout` | integer | `10` | 1–3600 | Seconds a client has to finish sending a request head. Slow-loris bound. |
| `drain_timeout` | integer | `30` | 1–3600 | Seconds a **reload's** old workers may take to finish what they hold before dropping it ([shutdown.md](shutdown.md)). A stop ignores this — it is immediate. Raise it if you serve long downloads and would rather a reload waited for them; lower it if you would rather old workers went quickly. |
| `max_connections` | integer | `1024` | 1–65536 | Concurrent client connections, across all workers. |
| `max_per_ip` | integer | `64` | 1–65536 | Concurrent connections from one source address, so one host cannot take the pool. |
| `max_upstream` | integer | `256` | 1–65536 | Concurrent connections to proxy backends. |
| `max_body` | integer | `67108864` (64 MiB) | 1–68719476736 | Largest request body accepted, on h1, h2 and h3 alike. A larger upload is refused with 413 before the bytes land. |
| `workers` | integer | `0` | 0–256 | Worker processes. **`0` means one per online CPU**, which is the default. |
| `http2` | integer | `1` | 0 or 1 | Offer HTTP/2 via ALPN on TLS listeners. |

---

## Server settings

Each entry of `servers` describes one virtual host: an address to bind, a port,
and the name it answers to. Listeners are dual-stack: `"::"` and `"0.0.0.0"`
both accept IPv6 *and* IPv4 clients (the latter as `::ffff:a.b.c.d`), and a
specific IPv4 literal binds just that address. Several servers may share one `host`/`port` pair
and be told apart by `hostname` (SNI on TLS, the `Host` header on plaintext).

| Key | Type | Default | Limit | What it does |
|---|---|---|---|---|
| `host` | string | — **required** | ≤ 63 | Bind address: **an IPv4 literal, or `"::"`**. Names are not resolved — `"localhost"` and `"::1"` are both refused. |
| `port` | integer | — **required** | 1–65535 | Bind port. |
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
  it. A server with a `redirect` location is kept off h3 (QPACK has no
  `Location` header to emit) and keeps h1/h2.

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
