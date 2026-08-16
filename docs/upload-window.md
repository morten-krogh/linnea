# The h3 upload receive window — design notes

Status: the window work through `2b08e76` is done and deployed except that last
commit. What follows is **designed and agreed, not implemented**.

The goal is not a faster upload on one link. It is that linnea serves a gigabit
client and a phone from the same build without either being tuned for, and keeps
doing so as networks get faster.

## The governing formula

A peer sending a body stalls at each DATA frame boundary for

    max(0, rtt - buffer / rate)

because the server cannot invite a byte it has nowhere to put. It has nowhere to
put it because it cannot tell framing from body until it has parsed the stream
**in order**, and a peer sends in order, so the next frame's header cannot arrive
before this frame's last byte. That is why pipelining the next region ahead was
designed and discarded: it changes where the ceiling sits *after* the grant, not
when the header arrives.

**So the runway is the buffer, and the buffer must cover the bandwidth-delay
product.** Measured 36.7 ms against 33 ms predicted at 128 KiB, 19 MB/s, 40 ms.

## Why not a constant, and why not a plain config key

BDP is a property of the client and spans four orders of magnitude:

| client | rate | rtt | BDP |
|---|---|---|---|
| phone | 300 kB/s | 80 ms | 24 KB |
| the link this was found on | 2.8 MB/s | 120 ms | 336 KB |
| gigabit, regional | 125 MB/s | 30 ms | 3.75 MB |
| gigabit, intercontinental | 125 MB/s | 100 ms | 12.5 MB |

No constant is right for all of them, and sizing for the worst reserves 12.5 MB
for the phone.

A config key looks like the answer and is not. An operator knows how much RAM
the box has; they cannot know a given client's BDP, and that is the number the
per-stream size has to match. **Exposing the per-stream size asks the operator to
guess on behalf of every future client — the same mistake as hard-coding it,
relocated.**

`LINNEA_QUIC_RA_BIG` also cannot usefully be raised past 4 MiB on its own:
`LINNEA_QUIC_RA_WINDOW` (in-flight cap inside a payload) and
`LINNEA_QUIC_FC_WINDOW` (connection level) both sit there. They move as a set.

## What other implementations do

Auto-tune against measured BDP under a configured cap. Linux TCP is the
canonical form — `tcp_rmem` is *min, default, max* and the kernel grows each
connection toward the max. quic-go exposes `MaxStreamReceiveWindow` and tunes
beneath it; Chromium's QUIC does the same. nginx and Apache are the older
static-directive style. (Check their current defaults before quoting them.)

## The design

**Config exposes the ceiling and the budget, never the per-stream size:**

    upload_buffer_max     per-stream ceiling the tuner may grow to
    upload_buffer_pool    per-worker byte budget for all borrowed buffers

Both numeric, both documented in `docs/config.md` with scope/default/range and
asserted against the binary by `test/configs/doc_claims_test.py`.

**Growth rule.** Start a body at a small borrow (256 KiB). Double, capped by
`upload_buffer_max`, when either:

- STREAM_DATA_BLOCKED arrives for the stream — the peer stating that we are the
  constraint, which is unambiguous and needs no heuristic; or
- the stream consumed its whole window inside one measured RTT — the same fact
  inferred before the peer has to say it.

Never shrink a live stream. The buffer returns to the pool at `ra_release`.

**Three pieces already exist, which is what makes this tractable:**

1. `ra_buf_borrow` already swaps a buffer and carries the live window across,
   bounded by the *current* size. Growing is borrowing a bigger one.
2. RTT is measured per connection (`081967c`), so BDP is computable.
3. `linnea_quic_flow_blocked` is already set from STREAM_DATA_BLOCKED (0x15).
   Chrome sent five of them in the netlog that started this work and nothing
   read them.

**The trap it must not repeat.** `50eefaa` fixed a regression where the borrow
was keyed on a DATA frame's *size*: Chrome frames a body in 371 KB pieces and
Firefox in small ones, so one rule gave 2.9 MB/s and 440 kB/s. **Key growth on
BDP and on the peer's blocked signal — never on how the peer chopped its body
up.** The suite guards this on both protocols (`--expect-borrow` on h3,
`--max-grants` at two framings on h2).

## Do the CPU work first

Measured 2026-08-16, 32 MB over h3, worker utime+stime from `/proc`:

    RAM path, before 2b08e76    9.7-10.0 ns/byte   100-103 MB/s per core
    RAM path, after  2b08e76    7.2- 7.8 ns/byte   128-139 MB/s per core
    capture-file path           5.9      ns/byte   168        MB/s per core

**128 MB/s per core is about 1 Gbit/s**, and the box runs two workers. One
gigabit client already saturates a worker on the receive path alone, before flow
control enters into it. A bigger window without more receive throughput moves the
stall out of flow control — where the peer announces it with
STREAM_DATA_BLOCKED and it is visible — and into the CPU, where the client
simply goes slower and nothing says why.

`2b08e76` took the first 28% by keeping the arrival bitmap a byte at a time
instead of a bit.

## Push more traffic onto the capture-file path

**The file path is cheaper than buffering in RAM** — 5.9 against 7.2 ns/byte —
which inverts the usual intuition and is the clearest remaining win. It tracks
arrivals as ranges rather than a bitmap and writes straight through, so it does
no per-byte work at all; the RAM path copies (`rep movsb` into `.buf`) and
maintains a bit per byte on top of the same file write.

Today a payload takes the file path only when `frame_rem >= .cap`, and `.cap` is
1 MiB once a body has borrowed. So essentially all browser traffic — Chrome's
371 KB frames, Firefox's small ones — stays on the *more expensive* path. The
threshold is backwards for the workload it meets.

Proposal: open a region for any DATA payload above a small fixed threshold,
independent of the borrowed buffer's size. Points to settle by measurement, not
argument:

- **Where the crossover actually is.** A region costs a `ra_body_migrate`, a
  slide and a range-list entry; below some frame size that exceeds what the
  bitmap would have cost. Measure ns/byte across frame sizes to find it rather
  than picking a number.
- **`LINNEA_QUIC_RA_RANGES` is 32.** Out-of-order arrival within a region is
  tracked as ranges and a peer that fragments past that has its stream refused.
  More, smaller regions means more streams meeting that bound.
- **This does not remove the need for window headroom.** The boundary runway is
  still `base + .cap`; the file path changes what the *payload* costs, not what
  crossing a frame boundary costs. The two changes are complementary and neither
  substitutes for the other.

## Order of work

1. Measure the region/RAM crossover and lower the threshold accordingly.
2. Any further per-byte cost in the RAM path that survives (the copy is next).
3. Then auto-tuning and the two config keys, with the ceiling raised to match.

Raising windows before (1) and (2) buys a stall the peer cannot report.
