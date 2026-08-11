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
; A connection may hold a slot only so long without completing a request head.
; The idle timeout alone cannot bound this: it is armed per operation and any
; progress rearms it, so a client dribbling one byte per timeout period holds a
; slot for as long as it likes (measured: 6x the timeout and still holding, for
; eight small writes). This is the total the head gets, however slowly it arrives.
LINNEA_DEFAULT_HEAD_TIMEOUT     equ 10    ; seconds to finish a request head
; How long a retiring generation gets to finish what it holds during a hot
; upgrade. Only a reload drains (SIGQUIT); a stop exits at once, so this never
; delays one. It exists because a WebSocket tunnel never finishes on its own —
; without a deadline one open tab pins an old worker for as long as the tab
; lives, and every reload leaves another behind.
LINNEA_DEFAULT_DRAIN_TIMEOUT    equ 30    ; seconds a reload's drain may take
; Connections one source address may hold at once, per worker. Without it a
; single host can take every slot in the pool — with well-formed traffic, no
; trickery needed — and everyone else is refused.
LINNEA_DEFAULT_MAX_PER_IP       equ 64
; Upstream (backend) connections in flight at once, per worker. Past this a
; proxied request is answered 503 rather than opening one more: the backend is
; usually far smaller than the flood that can reach us, and refusing here is
; what keeps it alive.
LINNEA_DEFAULT_MAX_UPSTREAM     equ 256
; A proxied upload is captured on disk before it is forwarded, so the cap is
; what stands between one client and the filesystem. 64 MB by default; the
; ceiling is a sanity bound on the config value, not a promise of disk.
LINNEA_DEFAULT_MAX_BODY         equ 67108864
LINNEA_MAX_BODY_CEILING         equ 68719476736
LINNEA_DEFAULT_MAX_CONNECTIONS  equ 1024
LINNEA_DEFAULT_WORKERS          equ 0     ; 0 = one worker per online CPU
LINNEA_MAX_WORKERS              equ 256

; what a location routes to
LINNEA_LOC_KIND_ROOT     equ 0       ; serve files from .root
LINNEA_LOC_KIND_PROXY    equ 1       ; forward to the upstream in .proxy_addr
LINNEA_LOC_KIND_REDIRECT equ 2      ; 301 to .redirect + the request target

; One routing entry: requests whose normalized path starts with .prefix are
; served from .root, proxied to .proxy_addr, or answered with a 301 to
; .redirect; the longest prefix wins.
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
    .redirect:      resb LINNEA_MAX_ROOT + 1      ; URL prefix the 301 points at
    .redirect_len:  resq 1
    .cache_control: resb LINNEA_MAX_ROOT + 1      ; Cache-Control value for static
    .cache_control_len: resq 1                    ; responses (0 = header not sent)
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
    ; Optional security headers, sent on the responses this server builds.
    ; HSTS is only meaningful over TLS (RFC 6797 7.2: a UA ignores it on a
    ; plain connection), so it is configured per server, next to the cert.
    .hsts:          resb LINNEA_MAX_ROOT + 1      ; Strict-Transport-Security
    .hsts_len:      resq 1                        ; value (0 = not sent)
    .nosniff:       resq 1                        ; 1 = X-Content-Type-Options
    .key_path:      resb LINNEA_MAX_ROOT + 1      ; PEM PKCS#8 key path
    .key_path_len:  resq 1
    .cert_list:     resq 1                        ; TLS certificate_list, pre-framed
    .cert_list_len: resq 1                        ; at startup, or 0
    .key_priv:      resq 1                        ; P-256 private scalar ptr (startup)
    .location_count: resq 1
    .locations:     resb linnea_config_location_size * LINNEA_MAX_LOCATIONS
endstruc

struc linnea_config
    .server_count:  resq 1
    .timeout:       resq 1                        ; idle timeout, seconds
    .max_connections: resq 1                      ; connection pool size, per worker
    .head_timeout:  resq 1                        ; seconds to complete a request head
    .drain_timeout: resq 1                        ; seconds a reload's drain may take
    .max_per_ip:    resq 1                        ; connections one address may hold
    .max_upstream:  resq 1                        ; upstream connections in flight
    .max_body:      resq 1                        ; largest request body accepted
    .workers:       resq 1                        ; worker processes; 0 until the
                                                  ; auto count is resolved at startup
    .http2:         resq 1                        ; 1 = offer HTTP/2 via ALPN
    .log:           resb LINNEA_MAX_LOG + 1       ; NUL-terminated log file path
    .log_len:       resq 1
    ; Where a request body is captured before it goes upstream — one O_TMPFILE
    ; per upload, on h1, h2 and h3 alike. It only supplies the FILESYSTEM;
    ; O_TMPFILE creates no directory entry. This is a config key rather than a
    ; constant because the right answer is deployment-specific and the wrong
    ; answer is expensive: the default of /tmp is tmpfs on most systems (and
    ; always so under systemd's PrivateTmp), which makes a "spill" plain
    ; anonymous memory — an upload then costs its own size in RAM, up to
    ; max_body, with no writeback and no way for the kernel to reclaim it.
    .spill_dir:     resb LINNEA_MAX_ROOT + 1
    .spill_dir_len: resq 1
    .servers:       resb linnea_config_server_size * LINNEA_MAX_SERVERS
endstruc

; Parser cursor over the mmap'd config file. pos lives in memory so
; parse errors can always report the exact byte offset.
struc linnea_parser
    .base:  resq 1   ; mmap'd buffer start
    .size:  resq 1   ; file size
    .pos:   resq 1   ; current byte offset
endstruc
