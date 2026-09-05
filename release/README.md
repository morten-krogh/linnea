# Linnea — release package

**Linnea** is a from-scratch HTTP/1.1, HTTP/2 and HTTP/3 web server and reverse
proxy, written in x86-64 assembly with its own TLS 1.3 and no dependencies.
Whether you cloned the repo (you are in `release/`) or unpacked the download
tarball, this directory has everything you need to run it.

Source, full documentation, and how it is built (mostly by Claude, with some
contributions and audits by Codex) are at
<https://github.com/morten-krogh/linnea>.

## What's in here

| File | What it is |
|---|---|
| `VERSION` | The release version this directory holds (e.g. `1.1.0`). |
| `linnea` | The server. A statically linked binary — copy it and run it. |
| `linnea-probe` | A standalone HTTP/1/2/3 compliance prober. Point it at any server. |
| `linnea-minimal.json` | The smallest working config: serve static files over plain HTTP. |
| `linnea.example.json` | A complete config: TLS, static files, an API proxy, and redirects. |
| `SHA256SUMS` | Binary checksums — in the download tarball; from the repo, verify by rebuilding (see "Verify"). |

## Requirements

- **Linux 5.19 or newer**, on an **x86-64** CPU.

That is all. There is nothing to install: the binary is statically linked and
uses only the Linux syscall interface. (HTTP/3 connection steering uses BPF and
wants the `CAP_BPF` capability; without it, HTTP/3 still works via the kernel's
connection hash.)

## Run it

Serve static files over plain HTTP — no root, no setup:

```sh
chmod +x linnea
mkdir -p /tmp/linnea-www
echo '<h1>hello from linnea</h1>' > /tmp/linnea-www/index.html

./linnea --config linnea-minimal.json
```

Then visit <http://127.0.0.1:8080/>.

For a real site — TLS on 443, static content, an API proxied to a local backend,
and HTTP-to-HTTPS redirects — edit `linnea.example.json`: change `example.com` to
your hostname, point `cert`/`key` at your certificate and key, and set the
`root`/`proxy` paths to yours. Then:

```sh
./linnea --test --config linnea.example.json   # checks the config and certs, exits
sudo ./linnea --config linnea.example.json     # 443/80 need privilege to bind
```

`--test` validates a configuration (and loads its certificates) without binding
anything — run it before you apply a change. The configuration format, every key
and every rule, is documented at
<https://github.com/morten-krogh/linnea/blob/master/docs/config.md>. Note that
the config is strict JSON with **no comments**, so this README, not the file, is
where the explanation lives.

## Check compliance

`linnea-probe` runs a battery of HTTP/1, HTTP/2 or HTTP/3 compliance probes
against a running server and exits with the number of deviations found:

```sh
./linnea-probe http://127.0.0.1:8080 h1
./linnea-probe https://linnea.amberbio.com h3    # the live demo
```

## Verify the binaries

Confirm the download matches the published checksums:

```sh
sha256sum -c SHA256SUMS
```

Because linnea is `nasm` + `ld` with no libraries and no optimizer, the shipped
binaries are **byte-for-byte reproducible** — build from source, strip, and
compare:

```sh
git clone https://github.com/morten-krogh/linnea && cd linnea
git checkout v1.2.0
make
strip bin/linnea bin/linnea-probe
sha256sum bin/linnea bin/linnea-probe   # match the entries in SHA256SUMS
```

The `strip` matters: the default build carries DWARF debug info (`-g`) that
embeds the absolute build path, so the *unstripped* file hash varies by where you
built it. The release ships the **stripped** binaries, which carry no such info
and hash identically in every build environment.

## More

- Full documentation: <https://github.com/morten-krogh/linnea/tree/master/docs>
- Report a vulnerability privately: see
  <https://github.com/morten-krogh/linnea/blob/master/SECURITY.md>
- License: MIT.
