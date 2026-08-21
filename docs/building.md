# Building linnea

Linnea has no build-time or runtime dependencies beyond an assembler, a linker,
and the Linux kernel. There is nothing to fetch, vendor or pin.

## Requirements

- **Linux on x86-64**, with a kernel new enough for `io_uring` (roughly 5.6+;
  newer is better, and some QUIC receive-side features use later additions).
- **`nasm`** (the Netwide Assembler).
- **`ld`** (GNU binutils, or any ELF linker).

For running the test suite as well, you also need **`python3`** (the test
fixtures and backends are Python) and **`curl`**. A few HTTP/3 tests need an
HTTP/3-capable `curl` and the Python `aioquic`/`pylsqpack` packages; tests that
need them are skipped when they are absent rather than failed.

## Build

```sh
make
```

That assembles every `.asm` under `src/` and links the products. There are no
flags to set and nothing to configure. The build is expected to be
**warning-free** — a new assembler warning is treated as a real signal (a
truncated immediate, a suspicious size), so `make 2>&1 | grep -i warning`
returning nothing is part of a healthy build.

`make` produces four binaries in `bin/`:

| Binary | What it is |
|---|---|
| `bin/linnea` | The server — the product. |
| `bin/linnea-probe` | A standalone HTTP/1/2/3 compliance prober, shipped in its own right. Point it at any server. |
| `bin/linnea-api` | A tiny demo backend (upload checksum + random number) used to exercise the reverse proxy. |
| `bin/linnea-ws` | A tiny demo WebSocket backend. |

`linnea-api` and `linnea-ws` are **demonstration backends** for the proxy, not
part of the product; the product is `linnea` (and `linnea-probe` alongside it).

## Running

```sh
linnea --config <path>     # run with a configuration file
linnea --test --config <path>   # check the config and certificates, then exit
linnea --bpf-probe         # check that BPF reuseport steering loads, then exit
linnea --help
```

The [Quick start](../README.md#quick-start) in the README has a minimal static
configuration; [`config.md`](config.md) is the full reference.

## Installing

```sh
make                # build first, as yourself
sudo make install   # copies the binaries to /usr/local/bin
```

`make install` **only copies** — it refuses to build — so that a `sudo make
install` never leaves root-owned object files in your tree. Build as yourself,
then install. It copies `linnea`, `linnea-probe`, `linnea-api` and `linnea-ws`
to `/usr/local/bin`. The systemd units and configuration are handled separately;
see [`deployment.md`](deployment.md).

## Testing

```sh
make test                                  # the fast suite
LINNEA_SUITE=full ./test/run_shards.sh     # the full, deploy-gating suite
```

`run_shards.sh` runs the suite as several concurrent jobs, each with its own
port base, and prints a single pass/fail total. The fast suite is for quick
iteration; the full suite is what must pass before anything is deployed.

`bin/linnea-probe` is a separate, dependency-free way to check conformance — it
speaks HTTP/1, HTTP/2 and HTTP/3 and can be aimed at any server, including a
live one, to test it against an independent implementation of the same
protocols.

## Layout

```
src/lib/      shared library: crypto, TLS/QUIC primitives, utilities
src/server/   the server (its own _start)
src/probe/    linnea-probe (its own _start)
include/      shared .inc headers (struct layouts, syscall numbers, constants)
test/         the suite: shard scripts, protocol fixtures, demo backends
config/       systemd units and example configuration (see deployment.md)
docs/         this documentation
```

How the pieces fit at runtime is [`architecture.md`](architecture.md).
