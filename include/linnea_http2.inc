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
LINNEA_H2_SETTINGS_HEADER_TABLE_SIZE equ 0x01

; request assembly (M16): the reassembled header block and the Huffman
; decode scratch both live in the connection's up_buf (unused under h2,
; which does not proxy yet). 4096 each fits in up_buf (8448 bytes).
LINNEA_H2_HBLOCK_MAX  equ 4096   ; max reassembled header-block bytes
LINNEA_H2_SCRATCH_OFF equ 4096   ; Huffman decode region: up_buf + this
LINNEA_H2_MAX_CONT    equ 16     ; CONTINUATION frames per HEADERS (flood guard)
LINNEA_H2_ECHO_MAX    equ 512    ; bound on the M16 echo response body

; h2_build_request outcomes (negative sentinels vs a byte count)
LINNEA_H2_REQ_MORE   equ -1      ; header block not fully buffered yet
LINNEA_H2_REQ_ERR    equ -2      ; malformed: connection error, GOAWAY
