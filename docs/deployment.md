# Deployment

Running linnea in production. The `config/` directory holds the systemd units,
an example configuration, a log-rotation snippet and a certbot hook that
together describe a real deployment — the one that serves the project's live
site. This document explains each piece so you can adapt it.

For what a stop, a reload and a restart do to open connections, see
[`shutdown.md`](shutdown.md); for the configuration itself, [`config.md`](config.md).

## The service, and its own identity

Linnea runs under a dedicated system user, **`linnea-svc`** — not a login user.
The point is isolation: a stray signal aimed at a development binary running as
your account cannot reach production, because a different UID owns it. The unit
(`config/linnea.service`) sets `User=` and `Group=linnea-svc`.

Install:

```sh
make                                 # build as yourself
sudo make install                    # copies binaries to /usr/local/bin
sudo cp config/linnea.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linnea
```

Configuration lives in `/etc/linnea/` (the unit points `--config` at
`/etc/linnea/linnea-tls.json`). Keep it readable by `linnea-svc` and its group;
keep the private key readable by the group and no wider.

## Capabilities, not root

The unit grants exactly three ambient capabilities and nothing else:

- `CAP_NET_BIND_SERVICE` — to bind ports below 1024 (443, 80).
- `CAP_BPF` and `CAP_NET_ADMIN` — to install the BPF reuseport map that steers
  HTTP/3 connections to their worker. Without them, h3 falls back to the
  kernel's 4-tuple hash, which cannot survive connection migration or a reload;
  everything else still works.

It also runs with the usual hardening — `ProtectSystem`, `ProtectHome`,
`NoNewPrivileges`, a private `/tmp`, and a restricted capability bounding set.

## Reload, restart, and the config check

`ExecReload` sends **SIGUSR2**, which is the zero-downtime re-exec:

```sh
sudo systemctl reload linnea    # apply a new config and/or a new binary, no dropped connections
```

The master runs the new binary in `--test` mode first and **refuses the reload
if the configuration or certificates are bad**, leaving the old generation
serving — a typo cannot take the site down. Always check first anyway:

```sh
linnea --test --config /etc/linnea/linnea-tls.json
```

`Restart=always` (not `on-failure`) is deliberate: systemd counts a `SIGTERM`
exit as clean, so `on-failure` would not bring the server back after one. Some
changes — adding or removing a whole server — need a real restart rather than a
reload; [`config.md`](config.md#applying-a-change) says which.

## TLS certificates

Point `cert` at a PEM chain and `key` at a PKCS#8 private key
([`config.md`](config.md) has the rules). With Let's Encrypt/certbot, the
included `config/certbot-deploy-hook.sh` runs after each renewal: it installs the
new chain and **reloads** linnea (never restarts, so a renewal drops nothing).

The hook also trims the certificate chain to the shortest form that still
verifies. This matters for HTTP/3 specifically: QUIC may send only a few times
what it has received before it has validated the client's address, and a
too-long certificate chain does not fit in that budget, costing an extra round
trip on every cold h3 handshake. A shorter chain that still chains to a trusted
root avoids it. Keep the reload-not-restart behaviour if you write your own hook.

## Logs

`LogsDirectory=linnea` gives the service `/var/log/linnea`. Linnea writes an
access log and, if `error_log` is set, a separate diagnostics log. Both are
reopened on **SIGHUP**, which is what a rotation needs:

```sh
kill -HUP $MAINPID    # reopen the logs after rotating them
```

`config/linnea.logrotate` is a rotation snippet that does exactly that. A new
log file (a new `error_log`, say) needs a new line in it — rotation does not
discover files on its own.

## Upload spill

`spill_dir` is where request bodies are captured before they go upstream. Under
systemd's `PrivateTmp`, the default `/tmp` is anonymous memory, so a large or
concurrent upload costs RAM, not disk. Point `spill_dir` at a real directory —
the reference deployment uses a `StateDirectory` under `/var/lib/linnea`. The
startup line tells you which you have (it appends a note when the directory is
tmpfs).

## The demo backends

`config/linnea-api.service`, `config/linnea-api2.service` and
`config/linnea-ws.service` run the demonstration backends behind `/api` and
`/ws`. They are examples of what sits behind the proxy, not part of the server;
a real deployment proxies to whatever services it actually runs. If you do run
two instances of a backend for restart failover (see
[`proxying.md`](proxying.md)), restart them one at a time.

## Checklist

- Binaries installed to `/usr/local/bin`, unit installed and enabled.
- Config in `/etc/linnea/`, valid under `linnea --test`, readable by the service
  user; private key not world-readable.
- `spill_dir` on a real disk.
- Certificate renewal reloads (does not restart) and keeps the chain short.
- Log rotation sends SIGHUP and covers every log file.
