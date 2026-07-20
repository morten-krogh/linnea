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

LINNEA_H2_FLAG_ACK  equ 0x01
