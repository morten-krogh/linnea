; Config limits and in-memory layout.

LINNEA_MAX_SERVERS      equ 16
LINNEA_MAX_HOST         equ 63       ; max host string length (buffer +1 for NUL)
LINNEA_MAX_HOSTNAME     equ 255      ; max hostname string length (DNS limit)
LINNEA_MAX_CONFIG_FILE  equ 1 << 20  ; sanity cap on config file size

struc linnea_config_server
    .host:          resb LINNEA_MAX_HOST + 1      ; NUL-terminated bind address
    .host_len:      resq 1                        ; length excluding NUL
    .hostname:      resb LINNEA_MAX_HOSTNAME + 1  ; NUL-terminated server name
    .hostname_len:  resq 1
    .port:          resw 1                        ; u16, host byte order
    .reserved:      resb 6                        ; pad to 8-byte multiple
endstruc

struc linnea_config
    .server_count:  resq 1
    .servers:       resb linnea_config_server_size * LINNEA_MAX_SERVERS
endstruc

; Parser cursor over the mmap'd config file. pos lives in memory so
; parse errors can always report the exact byte offset.
struc linnea_parser
    .base:  resq 1   ; mmap'd buffer start
    .size:  resq 1   ; file size
    .pos:   resq 1   ; current byte offset
endstruc
