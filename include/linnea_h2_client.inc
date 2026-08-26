; ============================================================================
; linnea_h2_client.inc — backend HTTP/2 client leg (roadmap #1 Tier 1).
;
; Single-stream (id 1) h2 client: an h1<->h2 translator. It parses the proxy's
; already-normalized h1 request head into an HPACK HEADERS block (+ DATA from the
; captured body), and synthesizes an h1 response head from the decoded h2
; response — so the whole client-facing relay (h1/h2/h3) stays unchanged. See
; docs/design/backend-h2-plan.md.
; ============================================================================

%include "linnea_hpack.inc"          ; linnea_h2_req (scratch carrier), linnea_hpack_dyn

; Frame types (RFC 9113 6).
LINNEA_H2C_FT_DATA       equ 0x00
LINNEA_H2C_FT_HEADERS    equ 0x01
LINNEA_H2C_FT_PUSH       equ 0x05
LINNEA_H2C_FT_RST        equ 0x03
LINNEA_H2C_FT_SETTINGS   equ 0x04
LINNEA_H2C_FT_PING       equ 0x06
LINNEA_H2C_FT_GOAWAY     equ 0x07
LINNEA_H2C_FT_WINDOW     equ 0x08
LINNEA_H2C_FT_CONT       equ 0x09

; Frame flags.
LINNEA_H2C_FL_ACK        equ 0x01     ; SETTINGS/PING
LINNEA_H2C_FL_END_STREAM equ 0x01     ; DATA/HEADERS
LINNEA_H2C_FL_END_HEADERS equ 0x04    ; HEADERS/CONTINUATION
LINNEA_H2C_FL_PADDED     equ 0x08     ; DATA/HEADERS
LINNEA_H2C_FL_PRIORITY   equ 0x20     ; HEADERS

; SETTINGS identifiers (RFC 9113 6.5.2).
LINNEA_H2C_SET_HDRTAB    equ 0x01
LINNEA_H2C_SET_PUSH      equ 0x02     ; SETTINGS_ENABLE_PUSH
LINNEA_H2C_SET_INITWIN   equ 0x04
LINNEA_H2C_SET_MAXFRAME  equ 0x05
LINNEA_H2C_SET_MAXHDRS   equ 0x06     ; SETTINGS_MAX_HEADER_LIST_SIZE

; The largest frame payload we let a BACKEND send us (RFC 9113 4.2). Our client
; SETTINGS carries no SETTINGS_MAX_FRAME_SIZE, so the protocol default stands
; and this is that default. It is OUR limit on the peer, and it is not the
; backend's own MAX_FRAME_SIZE -- that one describes what the backend is willing
; to RECEIVE and cannot enlarge what we accept.
LINNEA_H2C_RX_FRAME_MAX equ 16384
;
; It was the receive BUFFERS that bounded this before: 20471 in the blocking
; reader and 65527 in the resumable one, so a 16385-byte DATA frame the peer was
; never allowed to send fitted in memory and was relayed (audit-report-52). A
; buffer is not a protocol limit. If a MAX_FRAME_SIZE is ever advertised on this
; leg, this must move with it rather than with the buffers.

; Scheme selector for the request :scheme pseudo-header.
LINNEA_H2C_SCHEME_HTTP   equ 0
LINNEA_H2C_SCHEME_HTTPS  equ 1

; Buffer sizing (blocking leg; the proxy leg reuses per-connection arenas).
LINNEA_H2C_OUT_CAP      equ 65536    ; outbound staging (preface+SETTINGS+HEADERS, DATA)
LINNEA_H2C_HDRBLK_CAP   equ 32768    ; assembled response HEADERS/CONTINUATION block
LINNEA_H2C_SCRATCH_CAP  equ 32768    ; hpack scratch (Huffman expansion + dyn copies)
                                     ; -- kept equal to HDRBLK_CAP: a single
                                     ; literal may be as long as the block that
                                     ; carries it, and must still expand
; The response body either path will buffer. ONE policy for both, so the
; blocking oracle and the resumable driver cannot disagree about what fits.
LINNEA_H2C_D_BODY_CAP   equ 1048576  ; buffered response body (v1; stream later)

; The largest synthesized response HEAD: a status line, every relayed field
; line (bounded by HDRBLK_CAP), our own content-length, and the blank line.
LINNEA_H2C_HEAD_MAX     equ LINNEA_H2C_HDRBLK_CAP + 128

; The one-buffer response output. It must hold a MAXIMUM BODY *plus* a head:
; the body cap admits exactly 1 MiB and the composers then wrote the head in
; front of it, so a legal 1 MiB response returned 1048646 bytes from a 1048576
; byte buffer -- 70 bytes past the end, into whatever .bss followed
; (audit-report-67). Sized by construction now, asserted in
; linnea_h2_client.asm, and the composers check as well.
LINNEA_H2C_RESP_CAP     equ LINNEA_H2C_D_BODY_CAP + LINNEA_H2C_HEAD_MAX
LINNEA_H2C_RXCHUNK      equ 65536    ; per recv() request size

; Exchange result sentinels (rax from linnea_h2c_exchange).
LINNEA_H2C_ERR          equ -1       ; wire/decode failure -> caller 502
LINNEA_H2C_RST          equ -2       ; backend RST_STREAM  -> caller 502
LINNEA_H2C_GOAWAY       equ -3       ; backend GOAWAY       -> caller 502


; The client's advertised receive window: exactly what we can actually TAKE.
;
; It was 4 MiB while the response body buffer held 1 MiB, so a backend that
; believed us and sent 2 MiB -- well inside the window we had granted -- was cut
; off with a 502 after spending the bandwidth. That is the same defect as the
; MAX_HEADER_LIST_SIZE one recorded immediately below, one field over: an
; advertisement the buffers do not honour. This is tied to the cap rather than
; written out, so the two cannot drift, and linnea_h2_client.asm asserts the
; relationship at assembly time.
;
; It stays large enough that inbound WINDOW_UPDATE for a response body is rare,
; which is what the old value was reaching for.
LINNEA_H2C_INITWIN      equ LINNEA_H2C_D_BODY_CAP
; What we tell a backend we will accept as a response header list. Its DEFAULT
; when unsent is UNLIMITED (RFC 9113 6.5.2), so staying silent said "any size"
; while the buffers quietly enforced far less -- and nginx, entitled to believe
; us, sent an 18188-byte block and was refused.
;
; NOT HDRBLK_CAP. Accepting a block is only half the journey: the decoded head
; is then written into the buffer the client's protocol reads from, and the
; smallest of those (up_buf, 8448, for an h1 or h3 client) binds before
; HDRBLK_CAP ever does. Advertising the block cap would promise four times what
; the narrowest path can deliver -- the same dishonesty as advertising nothing,
; wearing a number. So this is the smallest head we can render on ANY path,
; rounded down, and it is the figure docs/config.md states.
; 6144: LINNEA_H2P_RHEAD_MAX, the h2-client path's own cap on an upstream
; response head, and the tightest of the four a head must pass. Advertising
; anything larger promises what that path cannot render.
LINNEA_H2C_MAXHDRS      equ 6144

; Resumable driver states (linnea_h2c.state).
LINNEA_H2C_ST_SEND_INIT equ 0   ; preface+SETTINGS+HEADERS staged, sending
LINNEA_H2C_ST_SETTLE    equ 1   ; awaiting the server SETTINGS before body
LINNEA_H2C_ST_SEND_BODY equ 2   ; streaming request DATA under flow control
LINNEA_H2C_ST_RESP      equ 3   ; reading the response
LINNEA_H2C_ST_DONE      equ 4
LINNEA_H2C_ST_FAILED    equ 5

; Driver step verdicts (rax from start / on_sent / on_recv).
LINNEA_H2C_WANT_SEND    equ 0   ; arm a send of out_buf[out_sent .. out_len]
LINNEA_H2C_WANT_RECV    equ 1   ; arm a recv, feed the bytes to on_recv
LINNEA_H2C_DRV_DONE     equ 2   ; response complete; compose + relay
LINNEA_H2C_DRV_FAIL     equ 3   ; wire/decode failure -> 502
LINNEA_H2C_DRV_RST      equ 4   ; backend RST_STREAM -> 502
LINNEA_H2C_DRV_GOAWAY   equ 5   ; backend GOAWAY -> 502

; Per-leg driver buffer caps. Kept modest (per-leg arena, one per proxied conn).
; IN_CAP must hold a retained partial frame (<= one max frame, ~16 KiB) plus a
; whole fresh read; callers feed on_recv <= 32 KiB at a time.
LINNEA_H2C_D_IN_CAP     equ 65536    ; recv accumulation (partial frame + a read)
LINNEA_H2C_D_OUT_CAP    equ 32768    ; outbound staging

; The resumable driver's per-leg context. Only CROSS-STEP state lives here; each
; driver step is atomic on the worker, so the global scratch/carrier/decoder are
; reused WITHIN a step (the header block is copied into the global decoder and
; the results copied back), which reuses the whole tested h2c_decode unchanged.
; The dynamic table persists here (it must survive across a header block, and any
; trailer block). [h2c_ctx] points at the current leg before each driver entry.
struc linnea_h2c
    .state:        resq 1
    .scheme:       resq 1
    .stream_win:   resq 1        ; our stream-1 SEND window
    .conn_win:     resq 1        ; connection SEND window
    .status:       resq 1        ; decoded response :status
    .hdrblk_len:   resq 1        ; reassembled response header block length
    .hdrlines_len: resq 1        ; synthesized "name: value\r\n" bytes
    .body_len:     resq 1        ; response body accumulated
    ; request cursor (resumable body send)
    .req_body:     resq 1
    .req_body_len: resq 1
    .body_sent:    resq 1
    ; io staging
    .out_len:      resq 1        ; bytes staged in .out_buf
    .out_sent:     resq 1        ; bytes of .out_buf already sent
    .in_len:       resq 1        ; bytes buffered in .in_buf awaiting a full frame
    ; flags
    .settled:      resq 1        ; server SETTINGS applied
    ; The response's own content-length, kept so it can be checked against the
    ; DATA bytes at END_STREAM (RFC 9113 8.1.1). Committed from the final head's
    ; block, like .status -- the emitter's globals belong to whichever leg is
    ; decoding right now, and this leg's answer must survive the gap between two
    ; on_recv calls.
    .cl_seen:      resq 1
    .cl_val:       resq 1
    .is_head:      resq 1        ; the REQUEST was HEAD: a length, and no body
    .hdr_es:       resq 1        ; END_STREAM seen on the response HEADERS
    .hdr_done:     resq 1        ; response header block decoded
    ; A header block is OPEN: a HEADERS/CONTINUATION arrived without END_HEADERS,
    ; so the only frame that may follow is its CONTINUATION on the same stream
    ; (RFC 9113 6.10). Without this the driver had no notion of a block being in
    ; progress, so a CONTINUATION out of nowhere read as a response head.
    .hdr_open:     resq 1
    ; the response header block outgrew HDRBLK_CAP: OUR limit, not a backend
    ; fault, so the failure is logged and counted differently
    .hdr_big:      resq 1
    ; The peer's last advertised INITIAL_WINDOW_SIZE. RFC 9113 6.9.2 makes a
    ; change to it a DELTA applied to every open stream's current window, not a
    ; new absolute window -- so the old value has to be remembered to compute
    ; the difference. Starts at 65535, the protocol default, which makes the
    ; first SETTINGS behave exactly as the old assignment did.
    .peer_init_win: resq 1
    ; embedded buffers + the decoder's persistent dynamic table
    .dyn:          resb linnea_hpack_dyn_size
    .hdrblk:       resb LINNEA_H2C_HDRBLK_CAP
    .hdrlines:     resb LINNEA_H2C_HDRBLK_CAP
    .body_buf:     resb LINNEA_H2C_D_BODY_CAP
    .out_buf:      resb LINNEA_H2C_D_OUT_CAP
    .in_buf:       resb LINNEA_H2C_D_IN_CAP
endstruc
