; Config limits and in-memory layout.

LINNEA_MAX_SERVERS      equ 16
LINNEA_MAX_LOCATIONS    equ 8        ; locations per server
LINNEA_MAX_HOST         equ 63       ; max host string length (buffer +1 for NUL)
LINNEA_MAX_HOSTNAME     equ 255      ; max hostname string length (DNS limit)
LINNEA_MAX_PREFIX       equ 255      ; max location prefix length
LINNEA_MAX_ROOT         equ 255      ; max document root path length
LINNEA_MAX_PROXY_STR    equ 63       ; max proxy "ip:port" string length
; Backends one proxy location may name. A location used to hold exactly one
; upstream; naming several is what lets a dead one be stepped over instead of
; answered with a 502. Eight is generous for this server's shape and costs
; ~66 KB of .bss across every location of every server, against a 238 MB total.
LINNEA_MAX_BACKENDS     equ 8
LINNEA_MAX_SNI          equ 255      ; max backend SNI hostname length
LINNEA_MAX_LOG          equ 255      ; max log file path length
LINNEA_MAX_CONFIG_FILE  equ 1 << 20  ; sanity cap on config file size

; defaults for the optional top-level config keys
LINNEA_DEFAULT_TIMEOUT          equ 5     ; idle timeout, seconds
; 0 = follow `timeout`. Resolved at the end of parsing, so the default is
; "whatever timeout is" and existing configs behave exactly as before.
LINNEA_DEFAULT_PROXY_TIMEOUT    equ 0
LINNEA_DEFAULT_TUNNEL_TIMEOUT   equ 0     ; 0 = follow `timeout`
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
LINNEA_DEFAULT_RATE_LIMIT       equ 0     ; 0 = no request-rate limit
; Upstream (backend) connections in flight at once, per worker. Past this a
; proxied request is answered 503 rather than opening one more: the backend is
; usually far smaller than the flood that can reach us, and refusing here is
; what keeps it alive.
LINNEA_DEFAULT_MAX_UPSTREAM     equ 256
; A proxied upload is captured on disk before it is forwarded, so the cap is
; what stands between one client and the filesystem. 64 MB by default; the
; ceiling is a sanity bound on the config value, not a promise of disk.
LINNEA_DEFAULT_MAX_BODY         equ 67108864
LINNEA_DEFAULT_MAX_CONNECTIONS  equ 1024
LINNEA_DEFAULT_WORKERS          equ 0     ; 0 = one worker per online CPU
LINNEA_MAX_WORKERS              equ 256
; QUIC BPF CID-steering index space. The steering index is ONE byte of the
; connection id (0..255), so the reuseport map holds 2 * HALF == 256 entries and
; each hot-upgrade generation stamps from its own HALF (base 0 or HALF) -- two
; generations of up to HALF workers each coexist without colliding. Lossless h3
; reload therefore supports up to HALF workers; a cold start's migration steering
; works up to 2 * HALF (the whole map). Beyond HALF the two generations cannot
; both fit one byte -- a wider CID index would be a redesign.
LINNEA_BPF_STEER_HALF           equ 128

; The longest response field NAME this proxy will relay. Not an HTTP limit --
; RFC 9110 5.1 makes a field name a token of any length, and requires a proxy to
; forward unrecognized fields -- but an implementation must bound its lowercase
; scratch buffers somewhere. What matters is that the bound is ONE number,
; enforced at the shared gate so every protocol answers the same way. It used to
; be the SIZE of two encoder buffers, 64 bytes, enforced nowhere and applied only
; by h2 and h3: a 65-byte extension field reached HTTP/1 clients and vanished for
; everyone else (audit-report-12 Finding 2). Generous against the real world,
; where the longest names in use are well under 50 bytes.
LINNEA_HTTP_MAX_FIELD_NAME      equ 256

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
    ; --- upstreams: .proxy_count of them, in selection order -------------
    ; Each sockaddr_in is prebuilt at parse time and lives in the parsed config,
    ; so it outlives any SQE that points at it.
    .proxy_count:   resq 1                        ; 1..LINNEA_MAX_BACKENDS
    .proxy_addr:    resb 16 * LINNEA_MAX_BACKENDS ; upstream sockaddr_in[]
    .proxy_str:     resb (LINNEA_MAX_PROXY_STR + 1) * LINNEA_MAX_BACKENDS
    .proxy_str_len: resq LINNEA_MAX_BACKENDS      ; "ip:port" each, for dump/log
    ; --- backend TLS (roadmap #1 Tier 0): connect to the backends over TLS 1.3
    ; and authenticate them by PINNING the certificate's SPKI. Per-location: all
    ; of a location's backends are https or none are. proxy_tls=1 requires a pin.
    .proxy_tls:     resq 1                        ; 1 = backends are https
    .proxy_pin:     resb 32                       ; pinned SHA-256(SPKI)
    .proxy_pin_set: resq 1                        ; 1 = a pin was configured
    .proxy_sni:     resb LINNEA_MAX_SNI + 1       ; SNI to send (NUL-terminated)
    .proxy_sni_len: resq 1
    .proxy_h2:      resq 1                        ; 1 = offer only ALPN h2 to the
                                                  ; backend and speak HTTP/2 to it
                                                  ; (Tier 1; requires proxy_tls)
    ; --- per-worker upstream state, NOT configuration --------------------
    ; Workers are forked, so these live in a copy-on-write page and are private
    ; to each worker without a separate table. They are deliberately not part of
    ; the config dump: a --test run has no workers and nothing to report.
    .bk_dead_at:    resq LINNEA_MAX_BACKENDS      ; monotonic s it was failed out
                                                  ; (0 = healthy)
    .bk_fails:      resq LINNEA_MAX_BACKENDS      ; consecutive failures
    .rr_cursor:     resq 1                        ; round-robin position
    ; 1 = upstream connections to this location's backends may be kept and
    ; reused. OFF by default and deliberately opt-in, like nginx's
    ; proxy_http_version 1.1 + keepalive: sending "Connection: close" upstream
    ; is what currently GUARANTEES a close-delimited response terminates, and a
    ; backend that sends neither Content-Length nor chunked would hang without
    ; it. Turning this on is the operator asserting their backend delimits its
    ; responses, which HTTP/1.1 requires but does not enforce.
    .proxy_keepalive: resq 1
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
    ; 1 = set IPV6_V6ONLY on the listener, so a "::" host binds IPv6-only instead
    ; of dual-stack. 0 (default) keeps the dual-stack behaviour. Meaningful only for
    ; "::": a specific IPv6 or IPv4 literal is already single-family.
    .v6only:        resq 1
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
    ; How long an UPSTREAM exchange may go without progress, separately from
    ; the client idle timeout above. One knob governed both until now, so a
    ; deployment could not say "clients may idle for a minute, but a backend
    ; that has not answered in five seconds is wedged" — and the two want very
    ; different numbers: prod holds client connections for 60s, which is 60s of
    ; an upstream slot held by a backend that will never reply. 0 means "follow
    ; timeout", which is exactly what every config did before the key existed;
    ; it is resolved to the real value once, at the end of parsing, so nothing
    ; downstream has to know about the sentinel.
    .proxy_timeout: resq 1                        ; upstream deadline, seconds
    ; How long an upgraded connection — a WebSocket tunnel — may go without
    ; traffic. A tunnel is not a request and should not inherit the request's
    ; deadline: an idle WebSocket is a normal, healthy thing, and reaping it on
    ; silence cannot tell a quiet peer from a vanished one. HAProxy draws the
    ; same distinction with `timeout tunnel`. 0 means "follow timeout", which is
    ; what one knob did for both before this key existed; resolved at the end of
    ; parsing so nothing downstream sees the sentinel.
    .tunnel_timeout: resq 1
    .max_connections: resq 1                      ; connection pool size, per worker
    .head_timeout:  resq 1                        ; seconds to complete a request head
    .drain_timeout: resq 1                        ; seconds a reload's drain may take
    .max_per_ip:    resq 1                        ; connections one address may hold
    .max_upstream:  resq 1                        ; upstream connections in flight
    .max_body:      resq 1                        ; largest request body accepted
    .workers:       resq 1                        ; worker processes; 0 until the
                                                  ; auto count is resolved at startup
    .http2:         resq 1                        ; 1 = offer HTTP/2 via ALPN
    ; Requests per second one source address may make, 0 = unlimited. The
    ; REQUEST control; max_per_ip is the CONNECTION control, and on h2/h3 the
    ; two are far apart — 64 connections x 100 streams is 6400 requests in
    ; flight from one address without breaking a single rule.
    .rate_limit:    resq 1
    .log:           resb LINNEA_MAX_LOG + 1       ; NUL-terminated log file path
    .log_len:       resq 1
    ; Where the diagnostics go, when they are to be kept apart from the request
    ; record: the connection lifecycle, handshake failures, capture faults —
    ; nginx's split, and the one that matters when something is wrong at three
    ; in the morning and the access log is thousands of lines an hour. Unset
    ; (len 0) means one file for both, exactly as before the key existed.
    .error_log:     resb LINNEA_MAX_LOG + 1
    .error_log_len: resq 1
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
    ; Where to report the ports actually bound, one line per server:
    ;   <hostname> <host> <port>
    ; Written once, after every listener is up and before any worker is forked,
    ; through a temporary file and rename(2) — so a reader sees either nothing
    ; or the whole thing, never a half-written line. Only useful together with
    ; "port": 0, where the config cannot say what the port will be; unset means
    ; no file is written.
    .port_file:     resb LINNEA_MAX_ROOT + 1
    .port_file_len: resq 1
    .servers:       resb linnea_config_server_size * LINNEA_MAX_SERVERS
endstruc

; Parser cursor over the mmap'd config file. pos lives in memory so
; parse errors can always report the exact byte offset.
struc linnea_parser
    .base:  resq 1   ; mmap'd buffer start
    .size:  resq 1   ; file size
    .pos:   resq 1   ; current byte offset
endstruc
