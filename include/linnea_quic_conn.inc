; QUIC connection state and the connection pool.
;
; A QUIC connection is identified by the connection ID the peer puts in the
; Destination Connection ID field, which is the ID *we* chose and advertised as
; our Source Connection ID during the handshake. We pick that ID, so we encode
; routing into its first two bytes and fill the rest with randomness:
;
;     scid = [ worker index(8) ][ pool index(8) ][ 6 random bytes ]
;
; The worker index is the first byte so the BPF reuseport program can read it
; and steer the connection's packets back to the worker that owns it, even after
; the client migrates to a new address (see src/linnea_bpf.asm). The pool index
; demultiplexes to the slot within that worker: O(1), no map — read the index,
; bounds-check it, and confirm the slot's full ID matches (the random tail makes
; the ID unguessable, so a wrong or spoofed ID fails the compare).
;
; Requires linnea_quic.inc (linnea_quic_keys_size, LINNEA_QUIC_MAX_CID).

; Connections per worker. The pool index is byte 1 of every connection ID we
; issue (byte 0 is the worker, for the BPF steering), so 256 is the most this
; ID layout can address — anything larger needs a wider ID. A slot is large
; (mostly its LINNEA_QUIC_TXSTREAMS response-stream slots), but the pool is
; .bss and faulted lazily, so an unused slot costs address space, not memory.
; A browser holds one QUIC connection open for a whole page load, so this is
; the ceiling on concurrent h3 clients per worker.
LINNEA_QUIC_MAX_CONNS equ 256       ; connections per worker
LINNEA_QUIC_RXBUF_SIZE equ 2048     ; linnea_quic_rxbuf, ONE datagram
; The socket reads into linnea_quic_rxbatch, not into rxbuf, and UDP_GRO may
; fill it with many datagrams from one flow; each is copied down to rxbuf and
; processed there.
;
; The two are deliberately NOT one constant. RXBUF_SIZE is the bound the h3
; proxy's unchecked .up_append rests on -- "a datagram is at most
; LINNEA_QUIC_RXBUF_SIZE", arithmetic that comment calls out as written down
; nowhere and the only thing between that copy and the next connection in the
; pool. Growing it to fit a GRO batch would have quietly multiplied that bound
; by 32 while every test still passed, so the batch got its own name instead and
; the per-datagram bound never moved. The copy out of the batch is clamped to it.
LINNEA_QUIC_RXBATCH_SIZE equ 65536
; strm_pay: one 1-RTT packet's payload — ACK, the STREAM header, and an inline
; HTTP/3 response. Named so the serve path can check against it rather than
; against a literal that drifts from the buffer it is meant to describe.
LINNEA_QUIC_STRM_PAY   equ 4096
LINNEA_QUIC_SCID_LEN  equ 8         ; every connection ID we issue is 8 bytes
LINNEA_QUIC_IDLE_SECS equ 30        ; reclaim a slot after this long with no packet
; A handshake that has stalled is reclaimed far sooner than an established
; connection: a peer that has not finished in this long is either gone or never
; existed (a spoofed Initial), and holding its slot for the full idle window is
; what lets a trickle of forged packets keep the pool occupied.
LINNEA_QUIC_HS_IDLE_SECS equ 3

; Address validation (RFC 9000 8.1). An Initial packet costs a connection slot, a
; key exchange and a signature, and its source address is unverifiable — UDP has no
; handshake — so a flood of forged Initials would otherwise fill the pool and lock
; real clients out (measured: ~300 abandoned Initials, and no browser could open
; h3 until the sweep caught up). Once this many slots are held by peers that have
; not yet proved their address, a new Initial without a token is answered with a
; Retry instead: the client must echo the token from an address that really
; receives our packets before any state is created. Below the threshold nothing
; changes, so the common case keeps its 1-RTT (and 0-RTT) handshake.
LINNEA_QUIC_UNVALIDATED_MAX equ 16
LINNEA_QUIC_RETRY_TOKEN_LEN equ 46  ; version(1) ts(8) odcid_len(1) odcid(20) mac(16)
LINNEA_QUIC_RETRY_WINDOW_MS equ 10000  ; a token older than this is refused

; A ClientHello too large for one Initial packet (a browser offering a
; post-quantum key share runs to ~1.6 KB, well over the ~1200-byte Initial) is
; split across several Initial packets, each carrying a CRYPTO frame at an
; increasing offset. The fragments are reassembled here, keyed on the client's
; original DCID so every Initial of one handshake lands on the same slot.
LINNEA_QUIC_CH_BUF    equ 4096       ; largest ClientHello we reassemble

; The server handshake flight carries the whole certificate chain in CRYPTO
; frames, which for a real chain far exceeds one datagram. QUIC forbids IP
; fragmentation (packets set don't-fragment), so a flight larger than the path
; MTU must be split: the CRYPTO byte stream is chopped into chunks, each carried
; by its own Handshake packet (increasing packet number, increasing CRYPTO
; offset) in its own datagram. This chunk size keeps a datagram — even the first,
; which coalesces the Initial ahead of the Handshake packet — WITHIN the
; 1200-byte size every QUIC endpoint must accept (RFC 9000 s14.1), so no
; datagram of ours depends on a path that carries more.
; 14.1 also runs the other way, which this once had backwards: a datagram
; carrying an ack-eliciting Initial must be EXPANDED to 1200. That is how the
; path is shown to carry the size QUIC requires before the handshake commits to
; it, and it bounds what an unvalidated address can reflect. .send_flight pads
; the datagram that coalesces the Initial up to this.
LINNEA_QUIC_CRYPTO_CHUNK equ 960    ; max CRYPTO payload per Handshake packet
LINNEA_QUIC_MIN_INITIAL_DGRAM equ 1200 ; RFC 9000 14.1 floor for an Initial datagram
LINNEA_QUIC_HS_FLIGHT_MAX equ 8192  ; largest flight the shared hsmsg scratch assembles
LINNEA_QUIC_FLIGHT_TAIL   equ 320   ; per-conn EE || CertVerify || Finished kept for resume

; Handshake progress, so a packet can be checked against the connection's stage.
LINNEA_QUIC_ST_NEW       equ 0      ; allocated, nothing processed yet
LINNEA_QUIC_ST_HANDSHAKE equ 1      ; server flight sent, awaiting the client
LINNEA_QUIC_ST_CONNECTED equ 2      ; client Finished verified, 1-RTT keys live
; Closing (RFC 9000 10.2.1): we have sent a CONNECTION_CLOSE and keep the slot
; for a short while so the peer's still-in-flight packets draw the close again —
; and so the peer learns the actual error we sent instead of a stateless reset
; (which is what a freed slot's connection id produces). The slot is reclaimed
; by the retransmission sweep once the closing period is up.
LINNEA_QUIC_ST_CLOSING   equ 3
LINNEA_QUIC_CLOSING_MS   equ 3000   ; >= 3x the initial PTO (RFC 9000 10.2)

; Loss recovery for the small-reply / control 1-RTT space. Every ack-eliciting
; packet we send here is kept until the peer acknowledges it, so a lost copy can
; be resent — under a fresh packet number, since QUIC forbids reusing one (RFC
; 9002 A.5). The frames are stored, not the protected bytes, so a retransmission
; is re-encrypted with a new number. Bulk response bodies are tracked separately
; in the in-flight table below; this ring only holds the handshake completion,
; control-stream setup and small inline responses, which are few.
LINNEA_QUIC_RTX_SLOTS   equ 8       ; outstanding small-reply packets per conn
; Recent 1-RTT packet numbers kept purely for round-trip measurement. The peer's
; largest acknowledged is by nature one of the last packets we sent, so a short
; ring covers it; anything older falls back to no sample, which is what the
; whole path did before.
LINNEA_QUIC_PNRING_SLOTS equ 16
LINNEA_QUIC_RTX_PAYLOAD equ 1500    ; frame bytes kept per packet
LINNEA_QUIC_ACK_MAXR    equ 16      ; ACK ranges decoded from one incoming frame

; Probe timeout: a buffered packet unacknowledged for this long is resent, under
; a fresh number. The threshold doubles per attempt (a lost reply on a slow or
; congested path is not lost again just because the first probe was early) up to
; a cap, and after a maximum number of attempts the packet is abandoned — a peer
; that has vanished should not be probed until the idle sweep reclaims it.
; Loss-recovery timing (RFC 9002 5, 6.2). The probe timeout used to be the flat
; LINNEA_QUIC_PTO_MS below with no RTT measured anywhere, which meant any path
; slower than a quarter second retransmitted everything spuriously and halved its
; congestion window each time — a collapse on exactly the links least able to
; absorb one. It is now derived per connection from measured round trips.
LINNEA_QUIC_INITIAL_RTT equ 333     ; kInitialRtt, used until the first sample
LINNEA_QUIC_TIMER_GRAN  equ 1       ; kGranularity, milliseconds
LINNEA_QUIC_MAX_ACK_DELAY equ 25    ; the peer's default when it advertises none
LINNEA_QUIC_PTO_FLOOR   equ 20      ; never probe faster than this
LINNEA_QUIC_PTO_CEIL    equ 8000    ; nor slower, before backoff
LINNEA_QUIC_PTO_MS      equ 250     ; base probe timeout, milliseconds
LINNEA_QUIC_PTO_CAP     equ 4       ; largest backoff shift (250ms << 4 = 4s)
LINNEA_QUIC_PTO_MAX     equ 6       ; attempts before a packet is given up on
; Response-body chunks are given up on far later than a small control reply. Stream
; data is reliable by contract: a chunk we stop retransmitting is data the peer will
; never have, which both truncates the response and strands the connection-level flow
; control credit it consumed (the peer counts the largest offset it received, we count
; the largest we sent, and only a RESET_STREAM's final size can close that gap). With
; the backoff capped at 4 s, 16 attempts span ~50 s — longer than the idle timeout, so
; in practice a chunk is retransmitted until it lands or the connection is reclaimed.
; Six attempts (~8 s) is far too few on a path with real loss: a client that drops
; half our packets, as one does when its receive buffer overflows, hits it routinely.
LINNEA_QUIC_TX_PTO_MAX  equ 16      ; attempts before a response chunk is given up on
; ACK-based loss detection (RFC 9002 6.1.1): a response chunk left at least this
; many packet numbers behind the largest acknowledged is treated as lost and
; retransmitted at once, rather than waiting out the growing PTO — prompt recovery
; under loss/reordering. 3 is the RFC's kPacketThreshold (tolerates 3-deep reorder).
LINNEA_QUIC_LOSS_THRESH equ 3

; PRIORITY_UPDATE (RFC 9218 7.2) on the control stream. The payload is a varint
; element id plus a priority field value, so a real one is well under 32 bytes;
; the buffer is generous and anything past it is treated as not a priority frame.
; PU_PEND is how many updates for not-yet-open response streams are remembered.
LINNEA_QUIC_PU_BUF  equ 64
LINNEA_QUIC_PU_PEND equ 8

; A request whose frames span several packets is reassembled in a per-connection
; buffer: each frame is placed at its offset (out-of-order frames are buffered,
; not dropped), a parallel byte-map records which bytes have arrived, and the
; contiguous prefix length advances as gaps fill. The request is served once the
; stream is complete (FIN seen and the prefix covers it). A whole request in a
; single packet (the common case) still takes a copy-free fast path. Several
; requests reassemble at once (LINNEA_QUIC_RA_CTXS contexts): under a burst,
; frames from different streams interleave in one flight, and a single context
; would drop all but one (the packet is already acknowledged, so the dropped
; request is never retransmitted — it is lost, and the page stalls). Requests
; larger than the buffer, or a burst deeper than the contexts, are still dropped.
; It is also the RUNWAY a client gets across every DATA frame boundary, and that
; is what sets its size. The ceiling is base + RA_BUF, and a gap past it might
; hide the next frame header, so it is genuinely all we can invite -- a client
; whose bandwidth x RTT exceeds it stalls there while a fresh grant makes a
; round trip.
;
; 32 KiB was under it for an ordinary browser on an ordinary link. Measured from
; a Chrome netlog of one 1 MB upload: THREE DATA frames of 371,712 bytes -- 11x
; the window -- and five STREAM_DATA_BLOCKED frames, one per boundary, ~390 ms
; of a 3.1 s upload spent stalled on us before counting the congestion-window
; recovery each stall costs. That client's bandwidth-delay product was 37 KB
; against 32 KiB of runway: short by a hair, every single frame.
;
; 128 KiB clears that by 3.5x and covers ~1 MB/s at 120 ms. The cost is address
; space rather than memory -- the pool is a private anonymous mapping, faulted
; on touch -- but state it plainly: RA_CTXS(6) * (buf + its arrival bitmap) is
; 864 KB per connection, so 226 MB per worker in the pathological case where all
; 256 connections run six concurrent uploads each. It was 57 MB at 32 KiB.
;
; It buys a round trip per boundary rather than all of them. A peer used to pay
; TWO at each one -- base did not move to the payload's end until the payload was
; whole, so the runway did not even begin until then -- and now the window is
; there in advance and it pays one. Buying that last one means RA_BUF exceeding
; bandwidth x RTT, which is the memory above against somebody's link, so it is
; not a constant that can be chosen once and be right.
LINNEA_QUIC_RA_BUF      equ 131072  ; reassembly capacity for one request stream,
                                    ; and the credit a client crosses a frame
                                    ; boundary on
; Receive-side connection flow control (quic-9). We advertise INITIAL_MAX_DATA and
; keep the ceiling FC_WINDOW ahead of what the peer has sent, re-granting via
; MAX_DATA whenever a fresh grant would advance the ceiling by >= FC_GRANT_MIN.
; Over-granting is safe: a stream is still capped at RA_BUF, so no extra is buffered.
LINNEA_QUIC_INITIAL_MAX_DATA equ 1048576   ; must match initial_max_data in the TP
LINNEA_QUIC_FC_WINDOW        equ 0x400000   ; 4 MiB ahead of received
LINNEA_QUIC_FC_GRANT_MIN     equ 0x40000    ; 256 KiB minimum grant step
LINNEA_QUIC_CTRL_RO     equ 512     ; reordered control-stream bytes held (h3-6)
LINNEA_QUIC_RA_CTXS     equ 6       ; requests that can reassemble concurrently
LINNEA_QUIC_RA_WALK     equ 8288    ; room for one linnea_h3_walk (asserted)
; How far the request-stream window may slide before the peer is told. Half the
; buffer: grant sooner and it is a packet per datagram, later and the client
; stalls waiting on credit it has already earned.
LINNEA_QUIC_RA_GRANT    equ LINNEA_QUIC_RA_BUF / 2
; --- direct-to-file body (the upload window) -------------------------------
; RA_BUF bounds how much UNCONSUMED stream we can hold, and because the window
; we advertise had to equal it, it also bounded the upload RATE: a client may
; have at most one window unacknowledged, so throughput was 32 KiB per ROUND
; TRIP however fast the link. 2.4 MB/s at a 13.5 ms client, against h2's
; 4 MiB window, which is why the same file uploaded far faster over h2.
;
; A DATA frame's payload does not need to pass through RAM at all. Its bytes
; are going to the capture file regardless, and a QUIC STREAM frame states its
; own offset — so once the payload's extent is known, every byte in it has a
; known file offset and can be pwritten straight there, in order or not. The
; file is sparse; a hole costs nothing and a later write fills it.
;
; What makes this safe is that every invited byte has somewhere to go. Inside
; the payload that is the file, bounded only by how much we are willing to have
; in flight at once (this constant, measured from what has LANDED). Past the
; payload it is the buffer, so the ceiling runs one RA_BUF beyond the frame and
; no further: a gap out there might hide the next frame header, and we would not
; know whether a byte is body or framing.
;
; That last RA_BUF is not a detail. The window used to stop dead at the payload's
; end, because .base stayed at the payload's START while it was being written and
; nothing past the payload could be placed at all -- so a peer ran out of credit
; on the boundary itself, once per DATA frame, and waited for the grant that only
; went out after the payload's last byte landed. .base moves to the payload's END
; when the region opens instead, which puts the buffer where the NEXT frame is
; and leaves the payload below it, reached through a split in the arrival path.
LINNEA_QUIC_RA_WINDOW   equ 0x400000   ; 4 MiB: most we invite in flight on one
                                       ; request stream, matching h2's window
; Out-of-order arrivals to track while filling a payload. Real reordering
; makes a handful of large ranges; a peer that deliberately fragments into
; more than this has its stream refused rather than being allowed to cost
; unbounded bookkeeping. Duplicates are free -- the same bytes rewritten at
; the same offset -- so this only has to answer "is the region whole yet".
LINNEA_QUIC_RA_RANGES   equ 32
; How long a request stream may go without a single frame before its context is
; considered abandoned and may be taken from it (see linnea_quic_ra.act_ms). An
; upload in progress is ack-clocked, so frames arrive every round trip; five
; seconds of silence is a client that has gone away, not a slow one — even a
; path bad enough to have doubled its PTO several times is well inside it.
LINNEA_QUIC_RA_STALE_MS equ 5000

; 0-RTT (early data): a resuming client can send its request in a 0-RTT packet
; coalesced with the ClientHello, before the handshake completes. The decrypted
; early frames are buffered here and served once the 1-RTT keys are up. Small: a
; 0-RTT request is a single GET (a large early body is neither expected nor kept).
LINNEA_QUIC_EARLY_BUF   equ 1024

; A response too large for one packet is sent as a sequence of STREAM-frame
; chunks, each in its own 1-RTT packet, each datagram under the 1200-byte floor
; every QUIC path must carry (RFC 9000 s14.1): short header (11) + chunk + the
; STREAM header and a leading ACK (~30) + AEAD tag (16) stays comfortably under.
; The stream's first bytes are the HTTP/3 HEADERS frame and the DATA frame
; header, kept per stream in its slot's hdr; the body bytes come straight from
; the file mapping. Up to LINNEA_QUIC_TXSTREAMS responses stream at once (a
; browser page load fires many large requests concurrently — a page of ten 0.6 MB
; images plus a chunked HTML and favicon is a dozen at once), interleaved chunk by
; chunk by the pump over the shared congestion window. The slot count matches the
; initial_max_streams_bidi we advertise (linnea_quic.asm), so a client can never
; open more request streams than we have response slots — a large response is
; therefore never refused for lack of a slot. Slots cost only fixed memory (they
; share one congestion window), not bandwidth.
LINNEA_QUIC_TX_CHUNK    equ 1100    ; stream bytes per 1-RTT packet
; HEADERS frame + DATA frame header prefix cap. Sized from the LARGEST head the
; documented config can produce, not from a typical one: hsts and cache_control
; are each up to 255 bytes (docs/config.md), which is 510 of the old 512 on
; their own, so a vhost setting both at their documented maxima could not serve
; any file over LINNEA_H3_INLINE_MAX at all — the head failed this check and the
; stream was RESET, silently, while h1 and h2 served the same file. Worst case
; now: 2 prefix + 5 status + 32 content-type + 22 content-length + 95
; content-range + 3 accept-ranges/vary/content-encoding + 50 etag + 31
; last-modified + 259 cache-control + 31 date + 8 server + 1 nosniff + 259 hsts
; + 12 framing = 810.
LINNEA_QUIC_TX_HDR      equ 1024
LINNEA_QUIC_TXSTREAMS   equ 100     ; = advertised initial_max_streams_bidi
LINNEA_QUIC_RST_SEEN    equ 32      ; cancelled stream ids remembered per connection
; Bidi-stream flow control (RFC 9000 4.6). We advertise this many streams up front,
; then raise the peer's limit with MAX_STREAMS as it opens streams, so a long-lived
; (reused) connection never runs out — without this a browser that refreshes enough
; times exhausts the limit, can open no more request streams (images stop loading),
; and falls back to h2 after ~30 s. Grant a fresh window once within THRESH of it.
LINNEA_QUIC_MS_INIT     equ 100     ; initial_max_streams_bidi we advertise
; initial_max_streams_uni we advertise. Unlike the bidirectional limit this one
; is never raised — a client needs three uni streams for HTTP/3 (control and the
; two QPACK streams) and opens no more — so the value the transport parameter
; carries is also the value linnea_quic_stream_limit enforces. Both now read
; this constant, so the granted limit and the enforced one cannot drift apart.
LINNEA_QUIC_MSU_INIT    equ 100
LINNEA_QUIC_MS_WINDOW   equ 128     ; streams granted ahead of the peer's highest
LINNEA_QUIC_MS_THRESH   equ 64      ; regrant when the peer is within this of the limit

; Congestion control (RFC 9002 NewReno). The response is ack-clocked, but by a
; congestion window that GROWS rather than the fixed 8-packet loss ring — without
; this a bulk transfer is pinned at ~8.8 KB per round trip (600 KB took ~1 s on a
; 15 ms path vs ~68 ms over TCP/h2). cwnd is in bytes; sending is allowed while
; bytes_in_flight < cwnd. In slow start (cwnd < ssthresh) cwnd grows by the bytes
; acknowledged (doubling per round trip); in congestion avoidance it grows about
; one packet per round trip; a loss (a chunk given up to the PTO) halves it.
; The window can't exceed what the in-flight table can track, so it is capped at
; the table size. The table is lightweight — a stream chunk is rebuilt from the
; file on retransmission, so only {pn, offset, length} is kept, not the bytes.
LINNEA_QUIC_TXINFL_SLOTS equ 256    ; stream chunks trackable in flight at once
LINNEA_QUIC_INIT_CWND    equ 11000  ; ~10 packets (RFC 9002 initial window)
LINNEA_QUIC_MIN_CWND     equ 2200   ; 2 packets, the floor after a loss
LINNEA_QUIC_MAX_CWND     equ LINNEA_QUIC_TXINFL_SLOTS * LINNEA_QUIC_TX_CHUNK

struc linnea_quic_txchunk
    .in_use:   resq 1
    .pn:       resq 1               ; packet number it LAST went out under
    .pn0:      resq 1               ; packet number it FIRST went out under. A QUIC
                                    ; ACK carries cumulative ranges, so a peer keeps
                                    ; acking a delivered packet in every ACK. If the
                                    ; original was delivered but its ack was lost or
                                    ; delayed past our PTO, we resend under a new pn
                                    ; and .pn moves on; a later cumulative ack still
                                    ; covers the original, so we must match .pn0 too
                                    ; or the chunk never frees and pins the window.
    .sent_ms:  resq 1               ; CLOCK_MONOTONIC ms when (re)sent, for the PTO
    .first_ms: resq 1               ; ...and when it FIRST went out, never overwritten:
                                    ; the time twin of .pn0. A resend moves .sent_ms,
                                    ; so after a few of them every outstanding chunk
                                    ; looks freshly sent and the SPAN of a loss episode
                                    ; collapses to nothing -- which is the one thing
                                    ; RFC 9002 7.6 has to measure.
    .off:      resq 1               ; the chunk's stream offset (to rebuild it)
    .len:      resq 1               ; chunk length (stream bytes; for bytes_in_flight)
    .tries:    resq 1               ; retransmissions so far
    .ctx:      resq 1               ; which response stream (index into tx_streams)
endstruc

; One open response stream. A body too large for one packet stays mmap'd here and
; is sent as STREAM-frame chunks. Stream byte i is hdr[i] while i < hlen (the
; HTTP/3 HEADERS frame and DATA frame header), and file byte foff + (i - hlen)
; after that; the stream carries hlen + flen bytes in all (flen < size for a 206).
; fc_max is the client's per-stream window (initial_max_stream_data, grown by
; MAX_STREAM_DATA); inflight is this stream's own unacknowledged chunk bytes, so
; its mapping is released the moment it is both fully sent and fully acknowledged.
struc linnea_quic_txstream
    .active:   resq 1
    ; The slot is claimed but has no response in it yet: the request went to a
    ; proxy upstream and the answer arrives on a later io_uring completion. It
    ; is claimed at once for two reasons. A retransmitted request finds it and
    ; is acknowledged rather than served a second time — otherwise a loss burst
    ; starts two upstream exchanges and answers one stream twice. And the peer
    ; cancelling the stream frees it through the ordinary reset path, so the
    ; response is dropped when it finally turns up. Nothing else may touch it:
    ; the pump skips it (it has no bytes to send) and, without this flag, the
    ; reaper would see a fully-sent unacknowledged-free stream and free it.
    .pending:  resq 1
    .sid:      resq 1               ; the request stream being answered
    .base:     resq 1               ; the response file's mapping (munmap wants
    .size:     resq 1               ; base/size — always the WHOLE mapping)
    .foff:     resq 1               ; body start within the mapping (a 206's
    .flen:     resq 1               ; range offset, 0 otherwise) and body length
    .hlen:     resq 1               ; stream bytes held in hdr
    .off:      resq 1               ; next stream offset to send
    .fc_max:   resq 1               ; max stream offset the client will accept
    .inflight: resq 1               ; this stream's unacknowledged chunk bytes
    ; RFC 9218 priority the client signalled (priority header): the pump serves
    ; lower urgency first; within one urgency, non-incremental streams run to
    ; completion in arrival order while incremental ones share the window.
    .urgency:     resq 1            ; 0 (highest) .. 7 (lowest), default 3
    .incremental: resq 1            ; 1 = deliver progressively (share the window)
    .hdr:      resb LINNEA_QUIC_TX_HDR
endstruc

; One in-progress request-stream reassembly (see LINNEA_QUIC_RA_CTXS). A frame's
; bytes go to buf at their stream offset, seen[i] marks byte i arrived, len is the
; contiguous prefix from 0, hi the high-water of seen, and once fin is set final is
; the total. The request is served when fin && len >= final.
struc linnea_quic_ra
    .active:   resq 1               ; 1 while this context is buffering a stream
    .sid:      resq 1               ; the stream id it is reassembling
    ; The frame walk over this stream, carried across datagrams. The stream is
    ; parsed as it arrives rather than once it is whole, which is what lets the
    ; bytes stop having to all be here at the same time. It holds its field
    ; section rather than decoding it (linnea_h3_walk.defer), so the decoder's
    ; output stays shared instead of costing every stream its own copy.
    ;
    ; Reserved by size rather than by struct: this header is included by files
    ; that have no reason to know about HTTP/3 at all, and the .inc files carry
    ; no include guards. linnea_quic_server.asm sees both and asserts the two
    ; agree, so the number cannot drift away from the thing it holds.
    .walk:     resb LINNEA_QUIC_RA_WALK
    .fed:      resq 1               ; bytes of the contiguous prefix already
                                    ; handed to the walk
    ; The request body, captured as it arrives. It cannot stay in .buf: the
    ; buffer is reused the moment this datagram is done with, and an upstream
    ; leg does not send until its connect completes. O_TMPFILE, so it has no
    ; name, nothing else can see it, and the kernel reclaims it when the fd
    ; closes -- including if we are killed mid-upload.
    .spill_fd:  resq 1              ; -1 = none opened
    .spill_len: resq 1
    ; The window slides. .base is the stream offset buf[0] holds, so .len and
    ; .hi are measured from there rather than from the start of the stream, and
    ; a request is bounded by how much of it is UNCONSUMED at once rather than
    ; by how long it is. .fc_adv is the ceiling last granted to the peer
    ; (base + the buffer); a fresh MAX_STREAM_DATA goes out as it advances, or
    ; the client stops at the window it was told about at the handshake.
    .base:      resq 1
    .fc_adv:    resq 1
    ; CLOCK_MONOTONIC ms when a frame last arrived for this stream. A context is
    ; held until its stream completes or faults, and a client that opens a
    ; request stream and walks away completes neither — so without this the slot
    ; is gone for the life of the connection, and RA_CTXS abandoned streams stop
    ; every later multi-frame request on it dead. The allocator reclaims the
    ; least recently active context once it has been silent for RA_STALE_MS.
    .act_ms:    resq 1
    .len:      resq 1               ; contiguous bytes received from offset 0
    .hi:       resq 1               ; highest offset+len seen (extent of the seen set)
    .fin:      resq 1               ; the FIN has been seen
    .final:    resq 1               ; the stream's total size (valid once fin)
    ; Direct-to-file body. .body_to == 0 means not in it; while it is set, the
    ; payload of the DATA frame the walk is waiting on is being written
    ; straight to the capture file and .buf holds none of it.
    .body_from: resq 1              ; absolute stream offset of the payload
    .body_to:   resq 1              ; ...and one past its end (0 = inactive)
    .body_file: resq 1              ; file offset .body_from maps to
    .body_hi:   resq 1              ; contiguous bytes placed from .body_from
    .body_nr:   resq 1              ; ranges in use
    .body_rng:  resq LINNEA_QUIC_RA_RANGES * 2   ; [start, end) absolute pairs
    .buf:      resb LINNEA_QUIC_RA_BUF
    ; bit i = 1 once stream byte i has arrived. A bit, not a byte: at one byte
    ; per byte this array alone was half the size of a connection, and there
    ; are LINNEA_QUIC_RA_CTXS of them in every one.
    .seen:     resb (LINNEA_QUIC_RA_BUF + 7) / 8
endstruc

struc linnea_quic_sent
    .in_use:   resq 1
    .pn:       resq 1               ; packet number it last went out under
    .sent_ms:  resq 1               ; CLOCK_MONOTONIC ms when (re)sent, for the PTO
    .len:      resq 1               ; frame-payload length
    .tries:    resq 1               ; retransmissions so far (0 = first send)
    .payload:  resb LINNEA_QUIC_RTX_PAYLOAD
    .pad:      resb 4               ; round the record to a multiple of 8
endstruc

struc linnea_quic_conn
    .in_use:     resq 1
    .dcid_len:   resq 1              ; length of the peer's connection ID
    .peer_len:   resq 1              ; sockaddr length
    .state:      resq 1
    .ctrl_id:    resq 1              ; the peer's control stream id, 0 until seen
    ; The peer's QPACK stream ids, 0 until seen. Recorded only so that a
    ; RESET_STREAM or STOP_SENDING naming one can be recognised: RFC 9114 6.2
    ; forbids closing a critical stream by any means, and a reset is a closure.
    ; Their contents still carry nothing we read (our table capacity is 0), which
    ; is why the ids were not tracked before.
    .qpack_enc_id: resq 1
    .qpack_dec_id: resq 1
    ; The control stream's frame walk (RFC 9114 6.2.1). It carries a frame
    ; sequence like any other stream, but it never ends and arrives spread over
    ; STREAM frames, so it is walked as it streams rather than reassembled:
    ; .ctrl_off is the next stream offset the walk can consume, .ctrl_skip the
    ; payload bytes of the frame in progress still to be discarded, and
    ; .ctrl_hdr holds a frame header split across a STREAM-frame boundary (two
    ; varints, so at most 16 bytes). .ctrl_settings records that the opening
    ; SETTINGS has been seen — the first frame must be one and no later frame may
    ; be. Zero-initialised with the slot, which is exactly the starting state.
    .ctrl_off:   resq 1
    .ctrl_skip:  resq 1
    .ctrl_hlen:  resq 1
    .ctrl_settings: resq 1
    .ctrl_hdr:   resb 16
    ; PRIORITY_UPDATE is the one control-stream frame whose payload we read
    ; rather than skip, so it alone is captured as it streams past: .ctrl_pucap
    ; is 0 while skipping, or the frame type while collecting into .ctrl_pu.
    ; A payload longer than the buffer is not captured at all — a priority field
    ; value is a few bytes ("u=1, i"), so anything near this size is not one.
    .ctrl_pucap: resq 1
    .ctrl_pulen: resq 1
    .ctrl_pu:    resb LINNEA_QUIC_PU_BUF
    ; Control-stream bytes that arrived ahead of the contiguous prefix. The
    ; walk consumes only in-order bytes, but a reordered datagram is delivered
    ; (and acked) exactly once — dropping its bytes left a permanent hole, and
    ; rule enforcement on the control stream quietly ended there for the life
    ; of the connection (h3-6). One bounded segment is held and merged as
    ; neighbours arrive; .ctrl_ro_sid is the uni stream it belongs to (0 =
    ; empty), which may be a stream not yet typed — its offset-0 frame naming
    ; it the control stream may itself be the late one. A hole wider than the
    ; buffer falls back to stopping the walk, which only a peer manufacturing
    ; the gap would ever see: real control-stream traffic is a few bytes.
    .ctrl_ro_sid:   resq 1
    .ctrl_ro_start: resq 1
    .ctrl_ro_len:   resq 1
    .ctrl_ro_buf:   resb LINNEA_QUIC_CTRL_RO
    ; A PRIORITY_UPDATE may name a request stream whose response has not opened
    ; yet: the control stream and the request stream are separate, so the update
    ; can overtake the request that it reprioritises. RFC 9218 7 says to keep the
    ; signal rather than drop it, so the most recent value per stream waits here
    ; and is applied when the response slot is filled. A small ring: the oldest
    ; entry is evicted, which costs at most a missed reprioritisation.
    .pu_sid:     resq LINNEA_QUIC_PU_PEND    ; stream id + 1 (0 = empty)
    .pu_val:     resq LINNEA_QUIC_PU_PEND    ; urgency | incremental << 8
    .pu_next:    resq 1                      ; write cursor
    .h3_goaway_id: resq 1            ; lowest request stream a drain would reject
    .ms_bidi_max:  resq 1            ; bidi stream count granted to the peer (MAX_STREAMS)
    .vhost:        resq 1            ; index into the vhost table, chosen by the SNI:
                                     ; selects the cert, signing key and document root
    .is_v2:      resq 1              ; 1 if this connection negotiated QUIC v2 (RFC 9369):
                                     ; selects the Initial salt, packet-protection HKDF
                                     ; labels and long-header packet-type codes
    .pn_1rtt:    resq 1              ; next 1-RTT packet number we send
    .last_active: resq 1             ; CLOCK_MONOTONIC seconds of the last packet
    ; The closing state (RFC 9000 10.2.1). When we send a CONNECTION_CLOSE the
    ; frame is kept here so a packet arriving afterwards can be answered with the
    ; same close rather than a stateless reset; .close_deadline (CLOCK_MONOTONIC
    ; ms) is when the sweep may free the slot. Our closes are at most 4 bytes
    ; (transport: type, code, frame-type, empty reason), so 24 is ample headroom.
    .close_len:      resq 1
    .close_deadline: resq 1
    .close_frame:    resb 24
    ; acknowledgement state for the 1-RTT space (see linnea_quic_ack_record):
    ; these three must stay adjacent and in this order.
    .rx_have:    resq 1
    .rx_largest: resq 1
    .rx_mask:    resq 1
    .scid:       resb LINNEA_QUIC_SCID_LEN   ; ours (index || random)
    ; an alternate connection id we issue via NEW_CONNECTION_ID (quic-7): same
    ; worker/pool bytes so it routes to this slot, fresh random tail. Lets the peer
    ; rotate its DCID (migration, unlinkability) without losing the connection.
    .cid1:       resb LINNEA_QUIC_SCID_LEN
    .cid1_active: resq 1                      ; 1 once cid1 is routable
    .dcid:       resb LINNEA_QUIC_MAX_CID    ; the peer's, our DCID when sending
    .peer:       resb 28                     ; sockaddr_in6 of the client (IPv4 as ::ffff:x)
    .hs_sec:     resb 96             ; c_hs || s_hs || handshake_secret
    .th_cfin:    resb 32             ; H(CH..server Finished)
    ; Session resumption (RFC 8446 4.6.1): the PSK a NewSessionTicket will carry,
    ; derived at ClientHello time (while the transcript inputs are still in scratch)
    ; and sealed into the ticket at handshake completion — a later datagram, by when
    ; that scratch is gone. sni_hash ties the ticket to the server_name it was
    ; issued under, matched on resumption.
    .resumption_psk: resb 32
    .sni_hash:   resb 8
    ; 0-RTT: the early-data keys and the buffered early request (served at completion)
    .zrtt_ckeys: resb linnea_quic_keys_size
    .early_len:  resq 1              ; bytes of buffered early-data frames (0 = none)
    .early_buf:  resb LINNEA_QUIC_EARLY_BUF
    .ini_client: resb linnea_quic_keys_size
    .ini_server: resb linnea_quic_keys_size
    .hs_ckeys:   resb linnea_quic_keys_size
    .hs_skeys:   resb linnea_quic_keys_size
    .ap_ckeys:   resb linnea_quic_keys_size
    .ap_skeys:   resb linnea_quic_keys_size
    ; 1-RTT key update (RFC 9001 6). The peer may flip the key-phase bit and switch
    ; to next-generation keys at any time; we must follow. Keep the CURRENT client
    ; and server application traffic secrets so the next generation can be derived
    ; (secret_next = HKDF-Expand-Label(secret, "quic ku", "", 32)), plus the phase we
    ; are currently on. The header-protection key is NOT rotated by an update, so the
    ; keys' .hp is preserved across a rekey — only .key and .iv change.
    .ap_csecret: resb 32
    .ap_ssecret: resb 32
    .key_phase:  resq 1
    .sent:       resb LINNEA_QUIC_RTX_SLOTS * linnea_quic_sent_size ; loss-recovery ring
    ; anti-amplification (RFC 9000 s8.1) and the resumable handshake flight. Until
    ; the peer proves its address, we may send at most 3x the bytes it sent us, so
    ; a spoofed Initial cannot make us flood a third party. A large certificate
    ; chain overflows that budget on the first round trip, so the flight tail is
    ; released once the peer's first Handshake packet validates the address (only a
    ; client that received our flight can produce it). The flight is EE ||
    ; Certificate || CertVerify || Finished; the Certificate is identical for every
    ; connection, so only the per-connection edge (EE, the randomized CertVerify,
    ; and Finished) is kept here — the flight is recomposed into the shared hsmsg
    ; scratch from this tail plus the shared certificate list when resuming.
    .amp_credit: resq 1             ; bytes we may still send pre-validation (3xrecv - sent)
    .amp_valid:  resq 1             ; 1 once the peer's address is validated
    .flight_len: resq 1             ; total handshake-flight (CRYPTO) bytes
    .flight_off: resq 1             ; bytes of the flight already sent
    .flight_pn:  resq 1             ; packet number of the next Handshake packet
    .flight_ee_len: resq 1          ; EncryptedExtensions length (Certificate follows it)
    .flight_cv_len: resq 1          ; CertificateVerify length (Finished's 36 follow it)
    .flight_tail: resb LINNEA_QUIC_FLIGHT_TAIL   ; EE || CertVerify || Finished
    ; What a retransmission of the server's first flight needs (RFC 9000 13.3,
    ; RFC 9002 6.2). The Handshake half recomposes from the fields above, but the
    ; ServerHello lived only in per-datagram scratch, so the Initial carrying it
    ; could not be rebuilt — and losing that one ~1150-byte datagram, the most
    ; drop-prone of the connection, killed the handshake outright.
    .sh_len:     resq 1              ; 90 fresh, 96 with the PSK extension
    .sh_msg:     resb 128
    .pn_ini:     resq 1              ; next Initial packet number we send; a
                                     ; retransmission MUST NOT reuse one (12.3)
    .flight_ms:  resq 1              ; CLOCK_MONOTONIC ms the flight last went
                                     ; out; 0 = nothing outstanding to probe
    .flight_tries: resq 1            ; PTO backoff for the flight
    ; Round-trip estimate (RFC 9002 5). All milliseconds; srtt == 0 means no
    ; sample has been taken yet and the kInitialRtt defaults apply.
    .rtt_have:   resq 1              ; 1 once a sample exists. A separate flag
                                     ; because 0 ms is a REAL measurement on
                                     ; loopback and fast LANs, so srtt == 0
                                     ; cannot double as "not measured yet"
    .srtt:       resq 1              ; smoothed_rtt
    .rttvar:     resq 1              ; rttvar
    .min_rtt:    resq 1              ; the smallest round trip seen
    ; Send times for recent 1-RTT packets, so an ACK naming ANY of them can be
    ; turned into a round trip. Before this the only send times kept were those
    ; of packets we might RETRANSMIT -- small replies and response chunks -- and
    ; the packet a peer names as its largest acknowledged is almost always the
    ; most recent one we sent, which is usually a standalone ACK. Those are
    ; emitted untracked, so the lookup missed, the sample was discarded, and
    ; rtt_have stayed 0 for the life of every connection. Measured: zero samples
    ; across a handshake, three requests and an upload.
    .pn_ring:    resb LINNEA_QUIC_PNRING_SLOTS * 16   ; {pn, sent_ms} pairs
    .pn_ring_at: resq 1              ; next slot to overwrite
    ; largest acknowledged + 1 (0 = none yet). RFC 9002 5.1 takes a sample only
    ; when the largest is NEWLY acknowledged; the old code got that for free
    ; because an acked packet was freed from its table, and a ring that never
    ; frees has to say so explicitly or every duplicate ACK resamples.
    .largest_ack_p1: resq 1
    ; request-stream reassembly: LINNEA_QUIC_RA_CTXS streams reassemble at once
    ; Stream ids the peer has cancelled (RESET_STREAM / STOP_SENDING), as a
    ; small ring. A cancel can arrive before the request that produced it has
    ; finished arriving — a retransmitted or reordered STREAM frame then
    ; opens a response for a stream the peer has stopped, and that response
    ; can never drain: the peer will never raise its stream window, so the
    ; slot stays active with its file mapped for the life of the connection
    ; until concurrent requests are refused with a 503.
    .rst_ids:    resq LINNEA_QUIC_RST_SEEN
    .rst_cursor: resq 1
    .ra_ctx:     resb LINNEA_QUIC_RA_CTXS * linnea_quic_ra_size
    ; the open response streams (up to LINNEA_QUIC_TXSTREAMS at once): each slot
    ; holds one large response's mapping, head and progress; the pump interleaves
    ; their chunks over the shared congestion window and in-flight table below.
    .tx_streams: resb LINNEA_QUIC_TXSTREAMS * linnea_quic_txstream_size
    ; Flow control (RFC 9000 s4). The client caps how much stream data we may send:
    ; per stream by initial_max_stream_data_bidi_local (grown by MAX_STREAM_DATA,
    ; held per slot in .fc_max); per connection by initial_max_data, grown by
    ; MAX_DATA. We send only up to those limits and wait for the client to raise
    ; them as it consumes — so a response larger than the initial window streams
    ; within it rather than being refused. fc_stream_init is the per-stream initial
    ; applied to each new slot; fc_conn_sent is the running total sent conn-wide.
    .fc_stream_init: resq 1         ; the initial per-stream window (new slots start here)
    ; How many unidirectional streams the client's transport parameters let us
    ; open (initial_max_streams_uni). HTTP/3 wants three — control, QPACK encoder
    ; and decoder — and RFC 9000 4.6 forbids opening more than the peer allows,
    ; so a client that grants fewer gets none of them rather than a violation.
    .ms_uni_peer:   resq 1
    ; The peer's ack_delay_exponent and max_ack_delay. Both describe the ACKs it
    ; SENDS us (RFC 9000 19.3 / RFC 9002 5.3), so both belong to the connection
    ; rather than being assumed from our own defaults.
    .ack_exp_peer:  resq 1
    .max_ack_peer:  resq 1
    ; The effective idle window for THIS connection, in seconds. RFC 9000 10.1:
    ; "the effective value ... is computed as the minimum of the two advertised
    ; values", so a client that says it will forget us sooner than our own
    ; LINNEA_QUIC_IDLE_SECS gets its slot reclaimed at its number, not ours. Set
    ; to our default at allocation and narrowed once the client's transport
    ; parameters are read; a peer that omits the parameter (or sends 0) imposes
    ; no limit of its own and leaves ours standing.
    .idle_secs:     resq 1
    .fc_conn_max:   resq 1          ; max total data the client will accept
    .fc_conn_sent:  resq 1          ; response-stream bytes sent against fc_conn_max
    ; receive side (quic-9): the peer is flow-controlled by initial_max_data, which
    ; we must raise with MAX_DATA as it sends, or it stalls once it hits the ceiling.
    .fc_recv:       resq 1          ; cumulative client->server STREAM bytes (loose)
    .fc_adv:        resq 1          ; connection-level ceiling we have advertised
    .fc_pending:    resq 1          ; 1 = a MAX_DATA grant is queued for the next send
    ; congestion control shared by the open response streams (RFC 9002 NewReno):
    ; one packet-number space and one path, so one window over all of them.
    .cwnd:       resq 1             ; congestion window in bytes (0 = uninitialised)
    .ssthresh:   resq 1             ; slow-start threshold in bytes
    .bytes_in_flight: resq 1        ; unacknowledged stream-chunk bytes across all streams
    .cc_recovery_pn: resq 1         ; largest pn when recovery began (loss dedup)
    .tx_rr:      resq 1             ; round-robin cursor: the slot the pump starts at
                                    ; next, so a small (loss-shrunk) window is shared
                                    ; fairly rather than starving the higher slots
    .tx_infl:    resb LINNEA_QUIC_TXINFL_SLOTS * linnea_quic_txchunk_size
    ; ClientHello reassembly (RFC 9000 7.5): the client's original DCID identifies
    ; the handshake before we have issued our own connection id, so every Initial
    ; of one handshake — including the later packets of a ClientHello too large
    ; for one Initial — routes here by it. The CRYPTO fragments are folded into
    ; ch_buf in offset order; ch_total is learned from the TLS handshake length in
    ; the offset-0 fragment, and the ClientHello is parsed once ch_len reaches it.
    .odcid:      resb LINNEA_QUIC_MAX_CID   ; the client's original DCID
    .odcid_len:  resq 1
    ; What to advertise as original_destination_connection_id (RFC 9000 7.3). It is
    ; normally .odcid, but after a Retry the client's Initials carry the id WE chose,
    ; so the parameter must still name the id it first used — recovered from the
    ; token, since we kept no state for it. A client checks both this and
    ; retry_source_connection_id and aborts the handshake if either is wrong.
    .tp_odcid:     resb LINNEA_QUIC_MAX_CID
    .tp_odcid_pad: resb 4                    ; keep the struct 8-byte aligned
    .tp_odcid_len: resq 1
    .via_retry:    resq 1              ; 1 if this connection came through a Retry
    .ch_len:     resq 1              ; contiguous ClientHello bytes reassembled
    .ch_total:   resq 1              ; full ClientHello size, 0 until the header lands
    .ch_hi:      resq 1              ; highest offset+len seen (extent of ch_seen)
    .ch_maxpn:   resq 1              ; largest Initial packet number seen (for the ACK)
    .ch_minpn:   resq 1              ; smallest Initial packet number seen. A client may
                                     ; start its Initials above 0 (Chrome starts at 1 to
                                     ; resist ossification), so the ACK must cover the
                                     ; real [min,max] range, not assume it begins at 0 —
                                     ; acking a packet the peer never sent is invalid.
    .ch_buf:     resb LINNEA_QUIC_CH_BUF
    ; A CRYPTO fragment can arrive out of order (ngtcp2 does this), so each is
    ; placed at its offset and its bytes marked here; the contiguous prefix
    ; (ch_len) advances as gaps fill, exactly like the request-stream reassembly.
    .ch_seen:    resb LINNEA_QUIC_CH_BUF
    .pad:        resb 4              ; keep the size a multiple of 8
endstruc

; linnea_quic_conn_lookup(rdi=dcid ptr, rsi=dcid len) -> rax = conn* or 0.
;   Marks the slot active, so a connection in use never falls to the sweep.
; linnea_quic_conn_alloc(rdi=peer ptr, rsi=peer len) -> rax = conn* or 0.
;   Sweeps idle slots first, then zeroes one, assigns a fresh connection ID and
;   records the peer. Returns 0 only when the pool is genuinely full of live
;   connections.
; linnea_quic_conn_free(rdi=conn) — return the slot to the pool. A client that
;   closes cleanly frees its slot at once; the sweep is the backstop for those
;   that simply vanish.
; linnea_quic_conn_sweep(rdi=now seconds, rsi=idle seconds) -> rax = slots freed.
;   Exposed with an explicit clock so it can be tested without waiting.
; linnea_quic_conn_active() -> rax = slots currently in use.
;
; linnea_quic_conn_free_hook — a function pointer (0 = none) called with
;   rdi = conn on every path that returns a slot to the pool (explicit free and
;   the idle sweep), before the slot is reused. The QUIC server registers a hook
;   that unmaps an open response stream's file, so a connection reclaimed
;   mid-transfer cannot leak the mapping. The pool itself knows nothing of mmap.
