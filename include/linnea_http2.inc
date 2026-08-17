; HTTP/2 (RFC 9113) constants. M15: connection bring-up — preface,
; SETTINGS, PING, GOAWAY. Streams (HEADERS/DATA) come in later
; milestones; until then a request frame draws a graceful GOAWAY.

; conn.h2_state
LINNEA_H2_PREFACE   equ 0     ; awaiting the 24-byte client preface
LINNEA_H2_RUNNING   equ 1     ; preface seen; processing frames
LINNEA_H2_CLOSING   equ 2     ; a GOAWAY is queued; close once it is sent
LINNEA_H2_DRAINING  equ 3     ; worker draining: GOAWAY sent, finish open
                              ; streams then close, refuse new ones

; linnea_h2_handle return codes (dispatched by the io_uring loop)
LINNEA_H2_MORE      equ 0     ; need more bytes: arm a recv
LINNEA_H2_SEND      equ 1     ; out_ptr/out_rem set: send, then resume
LINNEA_H2_CLOSE     equ 2     ; tear the connection down

; frame types
LINNEA_H2_FT_DATA          equ 0
LINNEA_H2_FT_HEADERS       equ 1
LINNEA_H2_FT_PRIORITY      equ 2
LINNEA_H2_FT_RST_STREAM    equ 3
LINNEA_H2_FT_SETTINGS      equ 4
LINNEA_H2_FT_PUSH_PROMISE  equ 5
LINNEA_H2_FT_PING          equ 6
LINNEA_H2_FT_GOAWAY        equ 7
LINNEA_H2_FT_WINDOW_UPDATE equ 8
LINNEA_H2_FT_CONTINUATION  equ 9

; frame flags
LINNEA_H2_FLAG_ACK         equ 0x01   ; SETTINGS / PING
LINNEA_H2_FLAG_END_STREAM  equ 0x01   ; DATA / HEADERS
LINNEA_H2_FLAG_END_HEADERS equ 0x04   ; HEADERS / CONTINUATION
LINNEA_H2_FLAG_PADDED      equ 0x08   ; DATA / HEADERS
LINNEA_H2_FLAG_PRIORITY    equ 0x20   ; HEADERS

; SETTINGS identifiers we emit / honour
LINNEA_H2_SETTINGS_HEADER_TABLE_SIZE      equ 0x01
LINNEA_H2_SETTINGS_MAX_CONCURRENT_STREAMS equ 0x03
LINNEA_H2_SETTINGS_ENABLE_PUSH            equ 0x02
LINNEA_H2_SETTINGS_INITIAL_WINDOW_SIZE    equ 0x04
LINNEA_H2_SETTINGS_MAX_FRAME_SIZE         equ 0x05
LINNEA_H2_SETTINGS_MAX_HEADER_LIST        equ 0x06

; error codes (RFC 9113 7) for RST_STREAM / GOAWAY
LINNEA_H2_NO_ERROR         equ 0
LINNEA_H2_PROTOCOL_ERROR   equ 1
LINNEA_H2_INTERNAL_ERROR   equ 2
LINNEA_H2_FLOW_CONTROL_ERR equ 3
LINNEA_H2_FRAME_SIZE_ERROR equ 6
LINNEA_H2_COMPRESSION_ERR  equ 9
LINNEA_H2_REFUSED_STREAM   equ 7
LINNEA_H2_ENHANCE_CALM     equ 11

; Flow control / framing defaults (RFC 9113 6.5.2 / 6.9).
LINNEA_H2_INIT_WINDOW  equ 65535   ; initial connection + stream send window
LINNEA_H2_MAX_FRAME    equ 16384    ; DATA payload we cap each frame at

; --- Multiplexing (M18) --------------------------------------------------
; Concurrent response bodies are tracked in a bounded per-connection stream
; pool overlaid on up_buf. HEADERS responses are emitted in order as they are
; decoded (they are small); only a body that must stream as DATA holds a slot,
; so a slot is pure body-send bookkeeping. A round-robin scheduler emits one
; DATA frame per send, interleaving streams at frame granularity.
; Concurrent streaming bodies, and what we advertise as
; SETTINGS_MAX_CONCURRENT_STREAMS — the two are the same number by
; construction (see h2_settings_be32 below), because a server that advertises
; more than it can hold invites REFUSED_STREAM and one that advertises less
; makes the client queue for nothing.
;
; RFC 9113 6.5.2 recommends no smaller than 100 "so as not to unnecessarily
; limit parallelism", and 16 was below that: the site's own page asks for 14
; sub-resources at once, so the video's Range requests queued behind the
; gallery and Firefox showed them Blocked. 100 matches both the RFC and the
; initial_max_streams_bidi HTTP/3 already advertises, so the same page gets
; the same parallelism whichever protocol the browser picked.
;
; The pool is overlaid on up_buf, which is 8448 bytes: 100 slots at 80 bytes
; is 8000, so it fits with room and nothing else claims that space once the
; TLS handshake state it shares has been consumed. The rapid-reset budget
; below is rate-based and does not scale with this, so raising it does not
; widen CVE-2023-44487.
LINNEA_H2_MAX_STREAMS  equ 100
; ...as a big-endian u32 for the SETTINGS frame, so the wire value cannot
; drift from the pool size.
%define LINNEA_H2_BE32(x) ((((x) & 0xff) << 24) | ((((x) >> 8) & 0xff) << 16) | \
                           ((((x) >> 16) & 0xff) << 8) | (((x) >> 24) & 0xff))
LINNEA_H2_RST_LIMIT    equ 200      ; RST_STREAMs before GOAWAY (rapid-reset,
                                    ; CVE-2023-44487)

struc linnea_h2_stream
    .id:        resq 1   ; client stream id; 0 = free slot
    .swnd:      resq 1   ; per-stream send window (signed)
    .file_base: resq 1   ; mmap base for munmap on completion (0 = rodata body)
    .file_size: resq 1   ; mmap length
    .body_ptr:  resq 1   ; next unframed body byte
    .body_rem:  resq 1   ; body bytes not yet framed
    .flags:     resq 1   ; bit 0 = set END_STREAM on the final DATA frame
    .up:        resq 1   ; proxied stream: upstream slot index + 1 (0 = static)
    ; RFC 9218 priority, taken from the request's `priority` field at slot
    ; allocation (default urgency 3, non-incremental). The scheduler serves the
    ; lowest urgency first; within one urgency a non-incremental response runs
    ; to completion in arrival order and incremental ones share the connection
    ; window in turn — the same policy h3's pump applies, so the two protocols
    ; schedule concurrent responses alike.
    .urgency:     resq 1   ; 0 (highest) .. 7 (lowest), default 3
    .incremental: resq 1   ; 1 = deliver progressively, sharing the window
endstruc

LINNEA_H2_STREAM_END    equ 1       ; .flags bit 0
LINNEA_H2_STREAM_UPDONE equ 4       ; proxied: END_STREAM emitted, reap the slot

; up_buf overlay: [stream pool] (the header-block assembly and its decode
; scratch once followed here; they moved to the lazily-mapped h2_hb_pool so a
; big cookie load no longer has to fit in up_buf's corner — see below)
LINNEA_H2_POOL_OFF     equ 0
LINNEA_H2_POOL_BYTES   equ linnea_h2_stream_size * LINNEA_H2_MAX_STREAMS

; Static file path assembly (M17): the normalized path is built at
; LINNEA_HTTP2_PATH_ROOT so a matched location's root can be prepended in
; place ahead of it (mirrors the HTTP/1.1 handler's path_buf).
LINNEA_HTTP2_PATH_ROOT equ LINNEA_MAX_ROOT + 1
LINNEA_HTTP2_PATH_BUF  equ LINNEA_HTTP2_PATH_ROOT + 2560
LINNEA_HTTP2_MAX_PATH  equ 2048     ; bound on the decoded :path length

; Request assembly (M16, rehomed Q121): the reassembled header block and the
; HPACK decode scratch live in h2_hb_pool — one lazily-mapped area per
; connection, like the upload buffers — because the 3072 bytes they used to
; get in up_buf meant a browser with a big cookie load killed its whole
; connection. The scratch is double the block: Huffman expands at most 8/5,
; so a block that fits can always decode into it. The DECODED list is bounded
; separately by LINNEA_HPACK_MAX_LISTSIZE (8192), which is what we advertise
; as SETTINGS_MAX_HEADER_LIST_SIZE; overrunning either the block cap or the
; list bound answers that stream 431 — the connection lives on.
LINNEA_H2_HB_ASM       equ 8192   ; max reassembled header-block bytes
LINNEA_H2_HB_SCRATCH   equ 16384  ; decoded-literal arena (2x: Huffman <= 8/5)
LINNEA_H2_HB_AREA      equ LINNEA_H2_HB_ASM + LINNEA_H2_HB_SCRATCH
LINNEA_H2_MAX_CONT     equ 16     ; CONTINUATION frames per HEADERS (flood guard)

; h2_build_request outcomes (negative sentinels vs a byte count)
LINNEA_H2_REQ_MORE   equ -1      ; header block not fully buffered yet
LINNEA_H2_REQ_ERR    equ -2      ; connection error; the code to report is
                                 ; left in h2_goaway_code by the failing site

; --- proxy-over-h2 (Q86) --------------------------------------------------
; A stream routed to a proxy location runs an h1 exchange with the upstream
; (fresh connection, Connection: close) through a bounded per-connection pool
; of upstream slots. Each slot owns a buffer that holds the rewritten request
; (head + a bounded body) and is then reused for the upstream response. The
; slots live in one global mmap indexed by connection pool index, so a slot
; is addressable from an io_uring completion that carries only indices.
; Concurrent upstream exchanges per connection. Sized for real browser
; parallelism (six in-flight API calls is common) so a page's requests are
; not refused and retried; also the most the 3-bit slot field in an op's
; user_data can address. The buffers are mmap'd lazily, so an idle
; connection's slots cost address space, not memory.
LINNEA_H2P_SLOTS      equ 8
LINNEA_H2P_BUF        equ 16384   ; slot buffer
LINNEA_H2P_HEAD_MAX   equ 8192    ; rewritten request head cap (buf[0..) )
LINNEA_H2P_BODY_OFF   equ 8192    ; request body collects at buf[BODY_OFF..)
LINNEA_H2P_BODY_MAX   equ 8192    ; request body cap (h1's in_buf caps ~8K too)
LINNEA_H2P_RHEAD_MAX  equ 6144    ; upstream response head cap (502 beyond)
; out_buf room a translated response HEADERS frame may need: the upstream
; head, plus HPACK's per-field length prefixes, plus the fields we add
; ourselves. Reserved before emitting one — a short reservation spilled the
; frame into up_buf, whose first bytes are the stream pool, which turned
; into refused streams on a healthy connection.
LINNEA_H2P_HEAD_ROOM  equ 7680
; And the room h2_serve's own responses need at the frame loop's cursor: the
; largest is a redirect, whose Location carries a URL prefix plus the request
; target (bounded at 2048 where it is built).
LINNEA_H2_RESP_ROOM   equ 3072
; SETTINGS_INITIAL_WINDOW_SIZE: the per-stream receive window we advertise.
;
; It used to be two things at once — the window AND the size of the-one-
; streaming-upload-per-connection FIFO the body was appended to — held equal on
; purpose, because the FIFO could not overflow only while a client was barred
; from sending past its window. Bodies are captured to a file now, so there is
; no FIFO to overflow and nothing left for the window to be equal TO: this is
; a flow-control number and only that. The buffer it was married to is gone,
; and with it max_connections * 4 MiB of address space per worker (4 GiB at the
; default 1024) that existed solely to hold one upload per connection.
;
; 64 KiB — the RFC default, rounded up — used to be the whole upload
; pipeline, and credit was returned as bytes drained to the backend, one
; 16 KiB frame at a time. Steady-state upload throughput was therefore
; 16 KiB per ROUND TRIP: invisible on loopback, where every upload test runs
; and passes, but 546 KB/s at a laptop's 30 ms and a quarter of a minute for
; an 8 MiB upload.
;
; The window IS the upload rate a client can reach: it may have at most this
; much unacknowledged, so throughput is bounded by WINDOW / RTT no matter how
; fast the link is. 1 MiB served a 13.5 ms client at 78 MB/s (621 Mbit/s),
; which is short of a symmetric gigabit line; 4 MiB carries that to 310 MB/s
; and keeps a 100 ms client above 10 MB/s. h3 grants 1 MiB
; (LINNEA_QUIC_INITIAL_MAX_DATA) with a 4 MiB ceiling (FC_WINDOW), so h2 is
; no longer the narrower of the two whichever protocol the browser picks.
;
; Cost is now only what a window costs: bytes a client may have in flight
; before we credit them back, held in the capture file rather than in RAM.
LINNEA_H2_INITIAL_WINDOW equ 4194304
%if LINNEA_H2_INITIAL_WINDOW > 0x7fffffff
  %error "SETTINGS_INITIAL_WINDOW_SIZE is capped at 2^31-1 (RFC 9113 6.5.2)"
%endif
; The batching step for credit that is owed back only once bytes have drained
; UPSTREAM. That was the streaming path's accounting, and no path takes it any
; more: a collected body is credited where it is consumed, in the DATA handler,
; which is both prompter and simpler. The step and the block in h2p_service
; that uses it are kept because rq_credit is still zeroed and tested on every
; pass, so the machinery stays coherent — it is simply never armed now. Removing
; the accounting outright is a separate change: it is entangled with rq_owed and
; the aborted-upload connection credit, which is not this commit's subject.
LINNEA_H2P_GRANT_MIN  equ 262144
%if LINNEA_H2P_GRANT_MIN >= LINNEA_H2_INITIAL_WINDOW
  %error "the h2 upload grant step must stay below the window, or a body smaller than one step can stall"
%endif
; SETTINGS_INITIAL_WINDOW_SIZE governs STREAM windows only. The CONNECTION
; window starts at 65535 by RFC 9113 6.9.2 and moves only on a WINDOW_UPDATE,
; so bring-up sends one; without it the connection window is the binding
; constraint and a bigger stream window buys nothing at all.
;
; The VALUE is unchanged, but what it is derived from no longer describes
; anything: it used to be "one streaming upload plus the bounded collect
; bodies", which was every body a connection could hold at once. Now every body
; collects and any of the LINNEA_H2P_SLOTS can be doing it. This stays the
; opening grant rather than the ceiling — the DATA handler credits the
; connection window back for every payload it consumes, so sustained throughput
; comes from that replenishment and not from this number. Whether a burst grant
; sized for one upload is still the right opening move for eight concurrent
; ones is a flow-control question worth MEASURING, and deliberately not
; answered by changing the arithmetic here unmeasured.
LINNEA_H2_CONN_WINDOW_INC equ LINNEA_H2_INITIAL_WINDOW + LINNEA_H2P_SLOTS * LINNEA_H2P_BODY_MAX
; The request-body clock (h1 streaming relay and h2 uploads): the head deadline
; keeps running through the body, and every received byte buys this much more
; time. 2 ms/byte = a 500 B/s floor — any real uploader outruns it thousands of
; times over, while a trickler holding an upstream slot falls behind and is cut
; roughly head_timeout after its last honest burst.
LINNEA_BODY_NS_PER_BYTE equ 2000000

; slot states
LINNEA_H2P_FREE       equ 0
LINNEA_H2P_COLLECT    equ 1       ; buffering the request body (awaiting END_STREAM)
LINNEA_H2P_CONNECTING equ 2       ; connect() to the upstream in flight / wanted
LINNEA_H2P_SENDING    equ 3       ; sending the rewritten request
LINNEA_H2P_HEAD       equ 4       ; reading the upstream response head
LINNEA_H2P_RELAY      equ 5       ; head parsed; body decoding and streaming
LINNEA_H2P_FAILED     equ 6       ; answer .status (502/504) or RST, then free
LINNEA_H2P_ZOMBIE     equ 7       ; conn/stream died with an op in flight; the
                                  ; completion frees the slot

; slot flags
LINNEA_H2P_F_HEAD_SENT equ 1      ; response HEADERS frame emitted
LINNEA_H2P_F_EOF       equ 2      ; upstream closed (or exchange complete)
LINNEA_H2P_F_IS_HEAD   equ 4      ; the client request was HEAD
LINNEA_H2P_F_HEAD_RDY  equ 8      ; head parsed, HEADERS frame not yet emitted
LINNEA_H2P_F_WANT_CONN equ 16     ; the loop should arm: connect
LINNEA_H2P_F_WANT_SEND equ 32     ; ... send of the unsent request bytes
LINNEA_H2P_F_WANT_RECV equ 64     ; ... recv into the response buffer
LINNEA_H2P_F_INFLIGHT  equ 128    ; an upstream op is in flight
LINNEA_H2P_F_BODY_DONE equ 256    ; response body fully received/decoded
LINNEA_H2P_F_NO_BODY   equ 512    ; bodiless response (HEAD/204/304)
LINNEA_H2P_F_RST       equ 1024   ; failure after HEAD_SENT: emit RST_STREAM
LINNEA_H2P_F_REAP      equ 2048   ; fully framed: free once no send is reading
                                  ; the slot buffer (the last DATA frame sends
                                  ; straight out of it)
; 4096 was LINNEA_H2P_F_REQ_STREAM — the request body streams upstream as it
; arrives instead of being collected whole. Nothing streams a request body any
; more; the bit is left unallocated rather than reused, so that a stale flags
; word from an older build cannot mean something new.
LINNEA_H2P_F_REQ_DONE  equ 8192   ; every request-body byte has been forwarded
; The request body was captured to a file and is sent upstream from a mapping
; of it, the way h1 and h3 already do — and, since uploads stopped streaming,
; the way EVERY proxied h2 body with more than LINNEA_H2P_BODY_MAX in it goes.
; The collecting path buffers into the slot up to that and spills past it, so
; any body runs to max_body instead of being refused at 8 KiB. Head from the
; slot buffer, then body from rq_buf. Two things about the mapping matter: it
; must not be slid down (there is no window to make room in), and its bytes
; were credited back to the client as they were captured, not as they go
; upstream.
LINNEA_H2P_F_REQ_FILE  equ 16384
LINNEA_H2P_F_DEC_ERR   equ 32768   ; the response body decode hit malformed framing
                                   ; (a bad chunk); the exchange must fail, not
                                   ; complete with a clean END_STREAM
LINNEA_H2P_F_HEAD_INTERIM equ 65536 ; the parsed head is a 1xx informational
                                    ; response (RFC 9113 8.8.5): relay it without
                                    ; END_STREAM and keep reading for the final head

struc linnea_h2p
    .state:     resq 1
    .fd:        resd 1            ; upstream socket, -1 = none
    .fdpad:     resd 1
    .sid:       resq 1            ; the client stream id
    .gen:       resq 1            ; the connection incarnation this belongs to
    .location:  resq 1            ; matched location* (connect addr, log)
    .srv:       resq 1            ; the vhost that matched, for its headers
    .req_len:   resq 1            ; rewritten request bytes (head, then body)
    .sent:      resq 1            ; upstream send progress
    .len:       resq 1            ; response bytes received into buf
    .rd:        resq 1            ; decode cursor (raw bytes consumed)
    .wr:        resq 1            ; decoded-body write cursor (wr <= rd)
    .off:       resq 1            ; decoded-body bytes already framed to the client
    .body_rem:  resq 1            ; body bytes still expected; -1 = until close
    .chunked:   resq 1            ; de-chunk phase: 0 = not chunked (see h2p_decode)
    .chunk_rem: resq 1            ; data bytes left in the current chunk
    .status:    resq 1            ; upstream status (or our 502/504)
    .flags:     resq 1            ; LINNEA_H2P_F_*
    ; The request body on its way upstream: a mapping of the file it was
    ; captured to, walked by rq_rd/rq_wr. These three were the streaming
    ; FIFO's cursors, which is why they read like a ring buffer's; the capture
    ; path took them over unchanged, and is all that is left using them.
    .rq_buf:    resq 1            ; the mapping (0 = nothing captured)
    .rq_rd:     resq 1            ; next body byte to send upstream
    .rq_wr:     resq 1            ; append point
    .rq_rem:    resq 1            ; body bytes still expected from the client
    .rq_credit: resq 1            ; forwarded bytes owed back as WINDOW_UPDATE
    .rq_start:  resq 1            ; the body clock: stamped at the claim, paid
                                  ; forward LINNEA_BODY_NS_PER_BYTE per received
                                  ; byte (capped at now), failed 408 when it
                                  ; falls head_timeout behind
    ; Connection-level credit left behind when the slot was freed with body
    ; bytes still uncredited (the client reset the stream, or the upstream
    ; failed, mid-upload). The stream is gone, so this can only go out on
    ; stream 0 — and it must, or the connection window never recovers. It
    ; outlives the slot's tenancy and is cleared per connection.
    .rq_owed:   resq 1
    ; The content-length the client declared, or -1 when it declared none.
    ; RFC 9113 8.1.1 makes a body whose DATA payloads do not sum to it
    ; malformed, and that has to be judged at END_STREAM — the streaming path
    ; already refuses a body that overruns the declared length, but a body that
    ; stops SHORT was simply never completed, and the request sat until the body
    ; clock timed it out. The collecting path did not know the declared length
    ; at all: it measured what arrived and forwarded that.
    .rq_declared: resq 1
    ; The capture file for a collected body that outgrew the slot buffer, and
    ; the mapping of it that the send reads. O_TMPFILE, so closing the fd IS
    ; the delete and a crash leaves nothing behind. -1/0 when unused, which is
    ; every request that fits in the slot.
    .rq_fd:     resd 1
    .rq_fdpad:  resd 1
    .rq_map:    resq 1            ; mmap base (0 = none); rq_buf points at it
    .rq_maplen: resq 1            ; its length, for munmap
    .lg_bytes:  resq 1            ; body bytes framed to the client, for the
                                  ; access line (.off gets rebased by the
                                  ; buffer compaction, so it cannot serve)
    ; the access line's method and target, copied at the claim: the rewritten
    ; request head in buf is overwritten by the response long before the
    ; status is known. One length byte, then the (truncated) text.
    .lg_meth:   resb 16
    .lg_tgt:    resb 104
    .buf:       resb LINNEA_H2P_BUF
endstruc
