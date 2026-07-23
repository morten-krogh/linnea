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

; Unidirectional stream types (the first varint on a client uni stream).
LINNEA_H3_STREAM_CONTROL    equ 0x00
LINNEA_H3_STREAM_QPACK_ENC  equ 0x02
LINNEA_H3_STREAM_QPACK_DEC  equ 0x03

; HTTP/3 error codes (RFC 9114 8.1), sent in an application CONNECTION_CLOSE
; when a peer breaks a control-stream rule.
LINNEA_H3_ERR_MISSING_SETTINGS equ 0x0105  ; control stream opened without SETTINGS
LINNEA_H3_ERR_STREAM_CREATION  equ 0x0103  ; a second control stream
LINNEA_H3_ERR_CLOSED_CRITICAL  equ 0x0104  ; a critical stream (control/QPACK) closed

; linnea_h3_read_headers(rdi=stream ptr, rsi=stream len, rdx=req *linnea_h2_req)
;   -> rax = 0 on success (a HEADERS frame was found and QPACK-decoded),
;      negative on error. Walks the request-stream frames, skips DATA/unknown
;      frames, and decodes the first HEADERS frame. The caller zeroes the req
;      and sets .scratch / .scratch_end (as for linnea_qpack_decode).
LINNEA_H3_ERR          equ 1      ; malformed/truncated frame
LINNEA_H3_ERR_NOHEADERS equ 2     ; no HEADERS frame in the stream data

; Largest POST body echoed back inline; a larger one (whose echo would not fit
; one response packet) gets a small receipt — its length and a hash — instead.
LINNEA_H3_ECHO_MAX     equ 1024

; A response body up to this size is written into the response packet directly
; (one packet, as ever). A larger body is not copied at all: linnea_h3_serve
; hands back the file mapping and writes only the stream's head — the HEADERS
; frame and the DATA frame header — and the QUIC layer sends the body as
; STREAM-frame chunks straight from the mapping.
LINNEA_H3_INLINE_MAX   equ 1024
; Upper bound on that head (status + content-type + content-length QPACK fields
; plus framing come to well under half this). Must not exceed the per-connection
; head buffer it is copied into (LINNEA_QUIC_TX_HDR in linnea_quic_conn.inc).
LINNEA_H3_HEAD_MAX     equ 128
