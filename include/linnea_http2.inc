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
LINNEA_H2_SETTINGS_INITIAL_WINDOW_SIZE    equ 0x04
LINNEA_H2_SETTINGS_MAX_HEADER_LIST        equ 0x06

; error codes (RFC 9113 7) for RST_STREAM / GOAWAY
LINNEA_H2_NO_ERROR         equ 0
LINNEA_H2_PROTOCOL_ERROR   equ 1
LINNEA_H2_INTERNAL_ERROR   equ 2
LINNEA_H2_FLOW_CONTROL_ERR equ 3
LINNEA_H2_FRAME_SIZE_ERROR equ 6
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
LINNEA_H2_MAX_STREAMS  equ 16       ; concurrent streaming bodies (= advertised
                                    ; SETTINGS_MAX_CONCURRENT_STREAMS)
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
LINNEA_H2_REQ_ERR    equ -2      ; malformed: connection error, GOAWAY

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
; One streaming upload per connection gets this buffer (the h2 default
; receive window, rounded up). Mapped lazily, so a connection that never
; uploads never touches it; a second concurrent upload on the same
; connection falls back to the bounded collect path.
LINNEA_H2P_UPLOAD_BUF equ 65536
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
LINNEA_H2P_F_REQ_STREAM equ 4096  ; the request body streams upstream as it
                                  ; arrives instead of being collected whole
LINNEA_H2P_F_REQ_DONE  equ 8192   ; every request-body byte has been forwarded

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
    ; Streaming request body: a FIFO in the connection's upload buffer. A
    ; client may have a full receive window in flight before it has even
    ; processed our SETTINGS, so the FIFO is sized for the protocol default
    ; (65535) rather than anything we could advertise; the window is credited
    ; back only as bytes go upstream, which paces everything after that.
    .rq_buf:    resq 1            ; the FIFO (0 = collecting, not streaming)
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
