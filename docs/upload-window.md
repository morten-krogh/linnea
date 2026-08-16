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

## Push more traffic onto the capture-file path — DONE

**The file path is cheaper than buffering in RAM**, which inverts the usual
intuition and was the clearest remaining win. It tracks arrivals as ranges
rather than a bitmap and writes straight through, so it does no per-byte work at
all; the RAM path copies (`rep movsb` into `.buf`) and maintains a bit per byte
on top of the same file write.

A payload used to take the file path only when `frame_rem >= .cap`, and `.cap`
is 1 MiB once a body has borrowed. So essentially all browser traffic — Chrome's
371 KB frames, Firefox's small ones — stayed on the *more expensive* path. The
threshold was backwards for the workload it meets, and is now
`LINNEA_QUIC_RA_REGION_MIN`, 4096, independent of the borrowed buffer's size.

### What was measured

Both builds up at once on separate ports, differing only in the gate; 32 MiB per
point; worker CPU from `/proc/PID/schedstat` (nanoseconds — `utime`/`stime`
quantise at 10 ms against a ~250 ms signal). ns/byte, lower is better:

| frame | buffer path | file path | | frame | buffer path | file path |
|---|---|---|---|---|---|---|
| 2 KiB | 8.15 | 8.27 | | 262 KiB | 7.86 | 6.32 |
| 4 KiB | 8.24 | 7.54 | | 371 KiB | 7.92 | 6.57 |
| 8 KiB | 7.79 | 6.67 | | 1 MiB | 7.89 | 6.28 |
| 32 KiB | 7.85 | 6.50 | | **2 MiB** | **6.18** | **6.23** |
| 64 KiB | 7.91 | 6.49 | | **4 MiB** | **6.48** | **6.14** |

The last two rows are the control: past ~2 MiB *both* builds open a region, so
they must agree, and they do within 1%. That row is what makes the rest of the
table evidence rather than two numbers that happen to differ — and it had to be
put there deliberately, because the first attempt at a control used 1 MiB frames
and did not fire. **The gate tests what REMAINS of a payload after the walk has
consumed what already arrived**, so a 1 MiB frame reaches it with less than
1 MiB left and stays on the buffer path. The same arithmetic is why the
threshold is 4096 and not lower: a threshold of T catches frames comfortably
above T, not frames of T, and by 2 KiB there is nothing left to win.

### Found underneath: a grant per DATA frame

Opening a region per frame rather than per megabyte reaches the "last step up to
the cap" exception on the first evaluation of every region. Credit is normally
handed out in steps of half the stream's buffer — ~66 grants for a 32 MiB body
however it is framed — and it became **one MAX_STREAM_DATA per frame: 4120 of
them, and the widest ceiling step collapsed from 524480 to 8195.**

Nothing stalled, because the ceiling each grant carries is still a whole buffer
past the payload. But a peer re-granted a frame at a time is the exact shape the
borrow assertion in `h3_upload_frames.py` reads as *no buffer was lent at all*,
so lowering the gate alone turns that check red — and on a real network it is a
packet per frame on the reverse path.

The exception exists for a peer stranded a few bytes short of a body whose
length it has already declared. **A peer already holding this payload's end plus
half a buffer beyond it is not that peer**, and the step is now suppressed for
it. Measured at 8 KiB framing: 6.67 → 6.38 ns/byte, 4120 grants → 68. At 371 KB
framing it is neutral (6.27 → 6.25), which is what it should be — there is one
region per 371 KB either way. `--max-grants` on the suite's small-framed upload
holds it.

### What this does not do

- **It does not remove the need for window headroom.** The boundary runway is
  still `base + .cap`; the file path changes what the *payload* costs, not what
  crossing a frame boundary costs. The two are complementary.
- **`LINNEA_QUIC_RA_RANGES` is 32.** Out-of-order arrival inside a region is
  tracked as ranges and a peer that fragments past that has its stream refused.
  More, smaller regions means more streams meeting that bound; nothing in the
  reorder checks moved, but the margin is thinner than it was.
- **The region's fixed cost is not the grant.** Suppressing the grant bought
  0.29 ns/byte of the ~1.3 the region costs at 8 KiB framing. The rest is the
  migrate, the slide, and one `pwrite` per arrival where the buffer path
  accumulates and writes a contiguous run. That last one is now done, below.

## The capture stage — DONE

Writing each arrival straight through meant **one `pwrite` per QUIC packet**:
32,934 of them for a 33,554,432-byte body, mean 1019 bytes, counted with
`strace` rather than reasoned about. The syscall costs more than a copy of the
same bytes, so contiguous runs are now gathered in a 64 KiB per-worker stage
(`LINNEA_QUIC_CAP_STAGE`) and written when the run breaks, when the stage fills,
or when the region closes.

    frame      before   after
     8 KiB       6.82    5.66      ns/byte, worker cpu, 32 MiB per point
    64 KiB       6.31    5.20
    371 KiB      6.45    5.06      Chrome's framing
      4 MiB      6.21    4.96

17-21% at every framing, and **with the gate change ahead of it, Chrome's
framing went 7.92 -> 5.06 ns/byte: 126 -> 198 MB/s per core.**

**One stage per worker is safe for a specific reason**, not by luck: a region is
only ever filled from the arrival path, and *the walk is never fed while a
region is open* — so the sink and the stage can never hold bytes for the same
file at once. Two uploads in flight simply alternate, and each one's first
arrival flushes the other's span.

The flush points are the whole correctness surface, and there are three: the
region's close (the one that matters — from there the walk can finish the
request and hand the descriptor upstream without ever coming back), a run that
does not continue the staged span, and `ra_release`. The last one writes rather
than discards, deliberately: if the close ever stops flushing, that turns a
silent truncation into a slow one.

**It did not reach one write per body**, and the remainder says where the next
one is. 8193 writes remain for 4096 frames — one per region, which is optimal,
plus **one per frame from the SINK**: the walk consumes the ~1100 bytes that
arrive alongside each DATA frame header before the gate is even evaluated, and
those go out on their own. Staging them too would need a flush at the request
handoff instead of at the region's close, which widens the surface to every
request rather than every region, and is worth about 3%.

## Order of work

1. ~~Measure the region/RAM crossover and lower the threshold accordingly.~~
   Done: `LINNEA_QUIC_RA_REGION_MIN` = 4096, plus the grant suppression above.
2. Any further per-byte cost that survives. ~~The per-arrival `pwrite` on the
   file path~~ done, above. What is left: the `rep movsb` into `.buf` on the
   buffer path, and the sink's write per DATA frame.
3. Then auto-tuning and the two config keys, with the ceiling raised to match.

Raising windows before (2) buys a stall the peer cannot report. **That argument
is now weaker than it was** — the receive path went from ~100 MB/s per core to
~198 at Chrome's framing, so a gigabit client no longer saturates a worker on
receive alone, and step 3 has more room than the numbers at the top of this file
suggest. Re-measure the ceiling before sizing anything against it.
