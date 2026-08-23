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
LINNEA_H2_FT_DATA       equ 0x00
LINNEA_H2_FT_HEADERS    equ 0x01
LINNEA_H2_FT_RST        equ 0x03
LINNEA_H2_FT_SETTINGS   equ 0x04
LINNEA_H2_FT_PING       equ 0x06
LINNEA_H2_FT_GOAWAY     equ 0x07
LINNEA_H2_FT_WINDOW     equ 0x08
LINNEA_H2_FT_CONT       equ 0x09

; Frame flags.
LINNEA_H2_FL_ACK        equ 0x01     ; SETTINGS/PING
LINNEA_H2_FL_END_STREAM equ 0x01     ; DATA/HEADERS
LINNEA_H2_FL_END_HEADERS equ 0x04    ; HEADERS/CONTINUATION
LINNEA_H2_FL_PADDED     equ 0x08     ; DATA/HEADERS
LINNEA_H2_FL_PRIORITY   equ 0x20     ; HEADERS

; SETTINGS identifiers (RFC 9113 6.5.2).
LINNEA_H2_SET_HDRTAB    equ 0x01
LINNEA_H2_SET_INITWIN   equ 0x04
LINNEA_H2_SET_MAXFRAME  equ 0x05

; Scheme selector for the request :scheme pseudo-header.
LINNEA_H2_SCHEME_HTTP   equ 0
LINNEA_H2_SCHEME_HTTPS  equ 1

; Buffer sizing (blocking leg; the proxy leg reuses per-connection arenas).
LINNEA_H2C_OUT_CAP      equ 65536    ; outbound staging (preface+SETTINGS+HEADERS, DATA)
LINNEA_H2C_HDRBLK_CAP   equ 16384    ; assembled response HEADERS/CONTINUATION block
LINNEA_H2C_SCRATCH_CAP  equ 16384    ; hpack scratch (Huffman expansion + dyn copies)
LINNEA_H2C_RESP_CAP     equ 1048576  ; synthesized h1 response (head + body)
LINNEA_H2C_RXCHUNK      equ 65536    ; per recv() request size

; Exchange result sentinels (rax from linnea_h2c_exchange).
LINNEA_H2C_ERR          equ -1       ; wire/decode failure -> caller 502
LINNEA_H2C_RST          equ -2       ; backend RST_STREAM  -> caller 502
LINNEA_H2C_GOAWAY       equ -3       ; backend GOAWAY       -> caller 502

; The client's advertised receive windows: large, like the server's, so inbound
; WINDOW_UPDATE for the response body is rare.
LINNEA_H2C_INITWIN      equ 4194304
