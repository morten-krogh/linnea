; Config limits and in-memory layout.

LINNEA_MAX_SERVERS      equ 16
LINNEA_MAX_LOCATIONS    equ 8        ; locations per server
LINNEA_MAX_HOST         equ 63       ; max host string length (buffer +1 for NUL)
LINNEA_MAX_HOSTNAME     equ 255      ; max hostname string length (DNS limit)
LINNEA_MAX_PREFIX       equ 255      ; max location prefix length
LINNEA_MAX_ROOT         equ 255      ; max document root path length
LINNEA_MAX_PROXY_STR    equ 63       ; max proxy "ip:port" string length
LINNEA_MAX_LOG          equ 255      ; max log file path length
LINNEA_MAX_CONFIG_FILE  equ 1 << 20  ; sanity cap on config file size

; defaults for the optional top-level config keys
LINNEA_DEFAULT_TIMEOUT          equ 5     ; idle timeout, seconds
LINNEA_DEFAULT_MAX_CONNECTIONS  equ 1024

; what a location routes to
LINNEA_LOC_KIND_ROOT    equ 0        ; serve files from .root
LINNEA_LOC_KIND_PROXY   equ 1        ; forward to the upstream in .proxy_addr

; One routing entry: requests whose normalized path starts with .prefix are
; served from .root or proxied to .proxy_addr; the longest prefix wins.
struc linnea_config_location
    .prefix:        resb LINNEA_MAX_PREFIX + 1    ; NUL-terminated path prefix
    .prefix_len:    resq 1
    .kind:          resq 1                        ; LINNEA_LOC_KIND_*
    .root:          resb LINNEA_MAX_ROOT + 1      ; NUL-terminated document root
    .root_len:      resq 1
    .proxy_addr:    resb 16                       ; upstream sockaddr_in, prebuilt at
                                                  ; parse time (static: safe SQE addr)
    .proxy_str:     resb LINNEA_MAX_PROXY_STR + 1 ; upstream "ip:port" for dump/log
    .proxy_str_len: resq 1
endstruc

struc linnea_config_server
    .host:          resb LINNEA_MAX_HOST + 1      ; NUL-terminated bind address
    .host_len:      resq 1                        ; length excluding NUL
    .hostname:      resb LINNEA_MAX_HOSTNAME + 1  ; NUL-terminated server name
    .hostname_len:  resq 1
    .port:          resw 1                        ; u16, host byte order
    .pad:           resw 1
    .listen_fd:     resd 1                        ; listening socket, set by linnea_network
    .listener_owner: resd 1                       ; 1 = this server bound the socket;
    .pad2:          resd 1                        ; 0 = shares a prior server's listener
    ; --- TLS (optional; "cert" and "key" are both-or-neither) --------
    .tls:           resd 1                        ; 1 = this server serves TLS
    .pad3:          resd 1
    .cert_path:     resb LINNEA_MAX_ROOT + 1      ; PEM cert chain path
    .cert_path_len: resq 1
    .key_path:      resb LINNEA_MAX_ROOT + 1      ; PEM PKCS#8 key path
    .key_path_len:  resq 1
    .cert_der:      resq 1                        ; loaded DER (startup), or 0
    .cert_der_len:  resq 1
    .key_priv:      resq 1                        ; P-256 private scalar ptr (startup)
    .location_count: resq 1
    .locations:     resb linnea_config_location_size * LINNEA_MAX_LOCATIONS
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
