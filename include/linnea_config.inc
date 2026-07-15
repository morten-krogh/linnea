; Config limits and in-memory layout.

LINNEA_MAX_SERVERS      equ 16
LINNEA_MAX_HOST         equ 63       ; max host string length (buffer +1 for NUL)
LINNEA_MAX_HOSTNAME     equ 255      ; max hostname string length (DNS limit)
LINNEA_MAX_ROOT         equ 255      ; max document root path length
LINNEA_MAX_LOG          equ 255      ; max log file path length
LINNEA_MAX_CONFIG_FILE  equ 1 << 20  ; sanity cap on config file size

; defaults for the optional top-level config keys
LINNEA_DEFAULT_TIMEOUT          equ 5     ; idle timeout, seconds
LINNEA_DEFAULT_MAX_CONNECTIONS  equ 1024

struc linnea_config_server
    .host:          resb LINNEA_MAX_HOST + 1      ; NUL-terminated bind address
    .host_len:      resq 1                        ; length excluding NUL
    .hostname:      resb LINNEA_MAX_HOSTNAME + 1  ; NUL-terminated server name
    .hostname_len:  resq 1
    .port:          resw 1                        ; u16, host byte order
    .pad:           resw 1
    .listen_fd:     resd 1                        ; listening socket, set by linnea_network
    .root:          resb LINNEA_MAX_ROOT + 1      ; NUL-terminated document root
    .root_len:      resq 1
    .listener_owner: resd 1                       ; 1 = this server bound the socket;
    .pad2:          resd 1                        ; 0 = shares a prior server's listener
endstruc

struc linnea_config
    .server_count:  resq 1
    .timeout:       resq 1                        ; idle timeout, seconds
    .max_connections: resq 1                      ; connection pool size
    .log:           resb LINNEA_MAX_LOG + 1       ; NUL-terminated log file path
    .log_len:       resq 1
    .servers:       resb linnea_config_server_size * LINNEA_MAX_SERVERS
endstruc

; Parser cursor over the mmap'd config file. pos lives in memory so
; parse errors can always report the exact byte offset.
struc linnea_parser
    .base:  resq 1   ; mmap'd buffer start
    .size:  resq 1   ; file size
    .pos:   resq 1   ; current byte offset
endstruc
