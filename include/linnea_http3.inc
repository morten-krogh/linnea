; HTTP/3 (RFC 9114) framing constants and interfaces.
;
; On a request stream the client sends a sequence of HTTP/3 frames, each a
; varint Type, a varint Length, and that many payload bytes (7.1). The request
; is a HEADERS frame whose payload is a QPACK-encoded field section, optionally
; followed by DATA frames. Unknown frame types are skipped (9). We reuse the
; QUIC varint decoder for the frame header and the QPACK decoder for HEADERS.

LINNEA_H3_FRAME_DATA        equ 0x00
LINNEA_H3_FRAME_HEADERS     equ 0x01
LINNEA_H3_FRAME_CANCEL_PUSH equ 0x03
LINNEA_H3_FRAME_SETTINGS    equ 0x04
LINNEA_H3_FRAME_PUSH_PROMISE equ 0x05
LINNEA_H3_FRAME_GOAWAY      equ 0x07
LINNEA_H3_FRAME_MAX_PUSH_ID equ 0x0d
; PRIORITY_UPDATE (RFC 9218 7.2), the only extension frame we read. Its payload
; is varint(prioritized element id) followed by the same RFC 8941 dictionary the
; `priority` header field carries. Two types: one for a request stream, one for a
; pushed one. Both belong on the control stream and nowhere else.
LINNEA_H3_FRAME_PRIORITY_UPDATE      equ 0xF0700
LINNEA_H3_FRAME_PRIORITY_UPDATE_PUSH equ 0xF0701

; Unidirectional stream types (the first varint on a client uni stream).
LINNEA_H3_STREAM_CONTROL    equ 0x00
LINNEA_H3_STREAM_PUSH       equ 0x01   ; only a server may open one (6.2.2)
LINNEA_H3_STREAM_QPACK_ENC  equ 0x02
LINNEA_H3_STREAM_QPACK_DEC  equ 0x03

; HTTP/3 error codes (RFC 9114 8.1), sent in an application CONNECTION_CLOSE
; when a peer breaks a control-stream rule.
LINNEA_H3_ERR_NO_ERROR         equ 0x0100  ; orderly close (the drain's goodbye)
LINNEA_H3_ERR_STREAM_CREATION  equ 0x0103  ; a second control stream
LINNEA_H3_ERR_CLOSED_CRITICAL  equ 0x0104  ; a critical stream (control/QPACK) closed
LINNEA_H3_ERR_FRAME_UNEXPECTED equ 0x0105  ; a frame illegal in the stream it arrived on
LINNEA_H3_ERR_FRAME            equ 0x0106  ; a frame's payload does not match its length
LINNEA_H3_ERR_ID               equ 0x0108  ; an id a frame named cannot exist
LINNEA_H3_ERR_SETTINGS         equ 0x0109  ; a reserved or repeated setting identifier
LINNEA_H3_ERR_MISSING_SETTINGS equ 0x010a  ; control stream opened without SETTINGS
LINNEA_H3_ERR_REQ_REJECTED     equ 0x010b  ; not processed — safe to retry elsewhere
LINNEA_H3_ERR_REQ_INCOMPLETE   equ 0x010d  ; the stream ended before a whole message
LINNEA_H3_ERR_MESSAGE          equ 0x010e  ; the message decoded but breaks a rule
LINNEA_H3_ERR_QPACK_DECOMP     equ 0x0200  ; QPACK could not decode a field section
LINNEA_H3_ERR_QPACK_ENC_STREAM equ 0x0201  ; an encoder instruction we cannot honour

; linnea_h3_read_headers(rdi=stream ptr, rsi=stream len, rdx=req *linnea_h2_req)
;   -> rax = 0 on success (a HEADERS frame was found and QPACK-decoded),
;      negative on error. Walks the request-stream frames, skips DATA/unknown
;      frames, and decodes the first HEADERS frame. The caller zeroes the req
;      and sets .scratch / .scratch_end (as for linnea_qpack_decode).
LINNEA_H3_ERR          equ 1      ; malformed/truncated frame
LINNEA_H3_ERR_NOHEADERS equ 2     ; no HEADERS frame in the stream data
; A field section that QPACK could not decode. Kept distinct from the frame
; errors above because RFC 9204 2.2.1 requires it to end the CONNECTION with
; QPACK_DECOMPRESSION_FAILED: once a field section is undecodable the peer's
; encoder state and ours have diverged, so no later request could be read
; either. (Our zero-capacity table means a compliant client never gets here —
; QPACK's capacity starts at 0 and may only rise to what we advertise.)
LINNEA_H3_ERR_QPACK    equ 3
; The field section decoded fine but is larger than we will hold. That is our
; own resource limit, not the peer's encoder going wrong, so it must not be
; reported as a decompression failure: RFC 9114 4.2.2 wants a 431 or a stream
; reset, and killing the connection would take every other request with it.
LINNEA_H3_ERR_TOOLARGE equ 4
; A frame that must not appear on a request stream (RFC 9114 7.2): the reserved
; HTTP/2 types, or a control/push frame. Unlike the malformed-request sentinels
; above, this ends the CONNECTION with H3_FRAME_UNEXPECTED, not the stream.
LINNEA_H3_ERR_UNEXPECTED equ 5
; The last frame on the stream was cut short — a frame header that runs off the
; end, or a declared payload longer than the bytes that arrived. RFC 9114 7.1 is
; explicit that when a stream terminates cleanly and its last frame was
; truncated, that is a CONNECTION error of type H3_FRAME_ERROR. Kept apart from
; the malformed-request sentinel above because that one fails only the stream.
LINNEA_H3_ERR_TRUNCATED equ 6
; The body could not be written where it was going — the capture file. Ours to
; own, not the peer's: nothing about the request was wrong, so it earns a 500
; rather than a stream reset that would tell the client to blame itself.
LINNEA_H3_ERR_SINK equ 7

; --- the request-stream frame walk -----------------------------------------
; A request stream is a sequence of frames, and until now it was walked in one
; pass over a stream that had been reassembled whole. That is what bounds an
; HTTP/3 request to the reassembly buffer, and so bounds an upload to 8 KB: the
; window advertised for a client's request stream cannot exceed what we can
; hold, or a body between the two overflows reassembly, is dropped WITHOUT an
; ack, and the client retransmits it forever.
;
; This walk carries its position across STREAM frames instead, so the stream
; can be consumed as it arrives. Same shape as the control stream's walk
; (linnea_quic_server.asm), including the buffer for a frame header split
; across a boundary — a type and a length varint, so 16 bytes covers it.
LINNEA_H3_W_HEADER  equ 0    ; accumulating a frame header
LINNEA_H3_W_FIELDS  equ 1    ; inside a HEADERS payload
LINNEA_H3_W_DATA    equ 2    ; inside a DATA payload
LINNEA_H3_W_SKIP    equ 3    ; inside a payload we do not read
LINNEA_H3_W_DONE    equ 4    ; finished, or failed and not to be resumed
; The field section must be decoded whole, so a section split across STREAM
; frames is accumulated here first. Bounded by the decoded-list limit QPACK
; already enforces: an encoding cannot be larger than the list it decodes to,
; since RFC 7541 4.1 charges 32 bytes per field on top of its bytes.
LINNEA_H3_WALK_FS   equ LINNEA_HPACK_MAX_LISTSIZE

struc linnea_h3_walk
    ; Where runs of body go: sink(rdi = this state, rsi = bytes, rdx = length)
    ; -> rax = 0 or -1. Zero means join them in place instead, which needs the
    ; caller to be feeding slices of one buffer and is how a whole stream that
    ; arrived at once is still handled. .sink_ctx is the sink's to use.
    .sink:      resq 1
    .sink_ctx:  resq 1
    .phase:     resq 1
    .frame_rem: resq 1       ; payload bytes still to consume in this frame
    ; Where the walk is in the frame SEQUENCE (RFC 9114 4.1): 0 = nothing yet,
    ; 1 = the request headers are in, 2 = the trailer section has been and gone.
    .seq:       resq 1
    .hdr_len:   resq 1       ; bytes of a split frame header held in .hdr
    .fs_have:   resq 1       ; field-section bytes accumulated in .fs
    .body_ptr:  resq 1       ; the request body, joined as one run
    .body_len:  resq 1
    .hdr:       resb 16
    .fs:        resb LINNEA_H3_WALK_FS
endstruc
; Everything before the accumulator is reset per request; .fs needs no clearing
; because .fs_have says how much of it is live.
LINNEA_H3_WALK_RESET equ linnea_h3_walk.fs

; A response body up to this size is written into the response packet directly
; (one packet, as ever). A larger body is not copied at all: linnea_h3_serve
; hands back the file mapping and writes only the stream's head — the HEADERS
; frame and the DATA frame header — and the QUIC layer sends the body as
; STREAM-frame chunks straight from the mapping.
LINNEA_H3_INLINE_MAX   equ 1024
; Upper bound on that head (status, content-type, content-length, the
; validators, date and server QPACK fields plus framing come to well under
; this). Must not exceed the per-connection head buffer it is copied into
; (LINNEA_QUIC_TX_HDR in linnea_quic_conn.inc).
LINNEA_H3_HEAD_MAX     equ 512
LINNEA_H3_PATH_ROOT equ LINNEA_MAX_ROOT + 1   ; room for the root in front of the path
LINNEA_H3_HDRS_BUF equ 8192      ; proxy header rebuild for an h3 request

; --- proxying to an HTTP/1.1 upstream (linnea_h3_proxy.asm) ---------------
; The upstream response head we will re-encode, capped exactly where HTTP/2
; caps it (LINNEA_H2P_RHEAD_MAX): the same backend answer must not be relayed
; over one protocol and refused over the other.
LINNEA_H3_PROXY_RHEAD_MAX equ 6144
; The response's own head (HEADERS frame + DATA frame header) does NOT fit the
; fixed hdr of a response-stream slot once a backend's fields are in it, and
; growing that hdr costs LINNEA_QUIC_TXSTREAMS x LINNEA_QUIC_MAX_CONNS times
; whatever it grows by. So the head is written into the capture file IN FRONT
; of the body instead: the capture starts this far into the file, leaving a
; hole the head is written back into once its length is known, and the slot
; streams head and body as one run out of the mapping (its hdr goes unused).
; The reserve therefore bounds the encoded head, and comfortably exceeds what
; a 6144-byte upstream head can encode to.
LINNEA_H3_PROXY_RESERVE   equ 8192
; Where a parked request's access-line text sits in the leg's in_buf, and how
; much of each is kept. Long enough for any real method, target or host; a
; longer one is truncated, since this is a log line and not a decision.
LINNEA_H3_LG_METH_MAX     equ 32
LINNEA_H3_LG_TGT          equ 32
LINNEA_H3_LG_TGT_MAX      equ 1024
LINNEA_H3_LG_HOST         equ 1056
LINNEA_H3_LG_HOST_MAX     equ 256
