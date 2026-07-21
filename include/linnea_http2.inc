; HTTP/2 (RFC 9113) constants. M15: connection bring-up — preface,
; SETTINGS, PING, GOAWAY. Streams (HEADERS/DATA) come in later
; milestones; until then a request frame draws a graceful GOAWAY.

; conn.h2_state
LINNEA_H2_PREFACE   equ 0     ; awaiting the 24-byte client preface
LINNEA_H2_RUNNING   equ 1     ; preface seen; processing frames
LINNEA_H2_CLOSING   equ 2     ; a GOAWAY is queued; close once it is sent

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

; error codes (RFC 9113 7) for RST_STREAM / GOAWAY
LINNEA_H2_NO_ERROR         equ 0
LINNEA_H2_PROTOCOL_ERROR   equ 1
LINNEA_H2_INTERNAL_ERROR   equ 2
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
    .rsv:       resq 1
endstruc

LINNEA_H2_STREAM_END  equ 1         ; .flags bit 0

; up_buf overlay: [stream pool][header assembly][Huffman scratch]
LINNEA_H2_POOL_OFF     equ 0
LINNEA_H2_POOL_BYTES   equ linnea_h2_stream_size * LINNEA_H2_MAX_STREAMS

; Static file path assembly (M17): the normalized path is built at
; LINNEA_HTTP2_PATH_ROOT so a matched location's root can be prepended in
; place ahead of it (mirrors the HTTP/1.1 handler's path_buf).
LINNEA_HTTP2_PATH_ROOT equ LINNEA_MAX_ROOT + 1
LINNEA_HTTP2_PATH_BUF  equ LINNEA_HTTP2_PATH_ROOT + 2560
LINNEA_HTTP2_MAX_PATH  equ 2048     ; bound on the decoded :path length

; request assembly (M16): the reassembled header block and the Huffman
; decode scratch live in up_buf after the stream pool (pool 1024, assembly
; 3072, scratch 3072 all fit in up_buf's 8448 bytes).
LINNEA_H2_HBLOCK_MAX   equ 3072   ; max reassembled header-block bytes
LINNEA_H2_ASSEMBLY_OFF equ LINNEA_H2_POOL_BYTES               ; up_buf + this
LINNEA_H2_SCRATCH_OFF  equ LINNEA_H2_ASSEMBLY_OFF + LINNEA_H2_HBLOCK_MAX
LINNEA_H2_MAX_CONT     equ 16     ; CONTINUATION frames per HEADERS (flood guard)

; h2_build_request outcomes (negative sentinels vs a byte count)
LINNEA_H2_REQ_MORE   equ -1      ; header block not fully buffered yet
LINNEA_H2_REQ_ERR    equ -2      ; malformed: connection error, GOAWAY
