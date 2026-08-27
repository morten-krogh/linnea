; linnea_http.asm — HTTP/1.1 request parsing, routing, and static serving.
;
; Supported subset:
; - Methods: GET and HEAD on static locations; anything else gets 405.
; - Request line: METHOD SP TARGET SP "HTTP/1.1" CRLF; single spaces;
;   METHOD 1-32 bytes, TARGET 1-2048 bytes, printable ASCII (0x21-0x7E).
;   Other HTTP/x versions get 505, malformed lines 400.
; - Header lines: NAME ":" OWS VALUE CRLF; the head must end with
;   CRLF CRLF within the input buffer, else 431.
; - Keep-alive: on by default (HTTP/1.1); disabled by "Connection: close"
;   and by error responses.
; - Bodies: head + body must fit the input buffer together, else 413; the
;   response waits until the whole body has arrived, then the body is
;   discarded with the head so keep-alive works. Transfer-Encoding: 501.
;   Duplicate or malformed Content-Length: 400.
; - Routing: the query string is stripped, then the target is
;   percent-decoded (%XX; bad escapes and %00 give 400). The decoded path
;   must be absolute; it is normalized segment by segment (empty and "."
;   segments drop, ".." pops — checked after decoding so encoded dots
;   cannot slip through; popping above the root gives 400). The result is
;   matched against the vhost's location prefixes, longest prefix first;
;   no match gives 404. Prefixes are not stripped: a static location maps
;   path = location root + normalized path, a proxy location forwards the
;   whole target upstream.
; - Static locations: a directory result maps to its index.html.
;   Missing/non-regular files: 404.
;   The access log records the raw, undecoded target.
; - Pre-compressed files: a variant sitting beside the file is the whole
;   opt-in. When the client's Accept-Encoding allows it, "<path>.br" is
;   tried, then "<path>.gz", then the file itself; the first one that is
;   there is served with the matching Content-Encoding. Everything else —
;   Content-Type, Content-Length, the validators — describes the variant
;   actually sent, except the type, which still comes from the name before
;   the suffix. Static responses carry Vary: Accept-Encoding so a cache
;   cannot hand a variant to a client that cannot read it. A variant with
;   no plain file beside it answers whoever takes the encoding and 404s
;   everyone else — shipping both files is the deployer's job.
; - Caching: every static 200 carries an ETag built from the file's mtime
;   and size, plus Last-Modified. A request whose If-None-Match matches
;   (weak comparison, "*" and comma-separated lists included), or whose
;   If-Modified-Since is at or after the file's mtime, gets a 304 instead
;   — one that keeps the connection alive, since a revalidation that cost
;   a new connection each time would defeat the point. If-None-Match wins
;   when both are present; an If-Modified-Since we cannot parse is
;   ignored, which costs a needless 200 and nothing worse.
; - Files are served from a read-only mmap queued behind the header send
;   (conn.file_*); the event loop munmaps after the send completes.
; - Ranges: a single "bytes=" range on a GET gets a 206 slice of the
;   mmap (Content-Range names it; static 200s advertise Accept-Ranges).
;   If-Range holds the range back unless its validator strong-matches.
;   Anything not understood — other units, several ranges, bad syntax —
;   is ignored in favor of the full 200, which is always safe; a range
;   that misses the file entirely is a 416 naming the actual length.
; - Proxy locations: a fresh upstream connection per request. The request
;   is rewritten into conn.up_buf (raw target, client headers except
;   Connection, then "Connection: close") and the buffered body is queued
;   behind it; the event loop connects, sends, then reads the response
;   head back into up_buf. The head is rewritten into conn.out_buf: the
;   status line and headers pass through except Connection, which we set
;   from the client's own keep-alive wish. Client keep-alive survives only
;   when the body length is known (Content-Length, or no body at all for
;   HEAD/204/304); a chunked or close-delimited response is relayed until
;   the upstream closes and forces Connection: close. Upstream failures
;   map to 502, upstream timeouts to 504. Proxied requests are logged on
;   completion, with the upstream status and the relayed byte count.
; - Upgrades (websockets etc.): when the client's Connection header lists
;   the upgrade token and an Upgrade header is present, the wish is
;   forwarded ("Connection: upgrade" instead of close; Upgrade and the
;   Sec-WebSocket-* headers pass through anyway). A 101 answer switches
;   the connection to a blind full-duplex byte tunnel, driven by the
;   event loop; any other answer is a normal proxied response. A 101
;   the client never asked for is a 502.

default rel

extern linnea_h3_altsvc
extern linnea_h3_altsvc_len
extern linnea_h3_server
extern linnea_h3_advert
%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_connection.inc"
%include "linnea_http.inc"
%include "linnea_time.inc"

global linnea_http_handle
global linnea_http_proxy_error
global linnea_http_request_timeout
global linnea_http_upstream_head_valid
global linnea_http_status_no_clen
extern linnea_http_status_no_content
extern linnea_http_head_conn_named
global linnea_http_proxy_head
extern linnea_http_authority_host
global linnea_http_proxy_log

LINNEA_HTTP_MAX_METHOD  equ 32
LINNEA_HTTP_MAX_TARGET  equ 2048
; The decoded path is built at LINNEA_HTTP_PATH_ROOT so a matched
; location's root can be prepended in place, without moving the path:
; root (255) + target (2048) + "/index.html" + NUL always fits.
LINNEA_HTTP_PATH_ROOT   equ LINNEA_MAX_ROOT + 1
LINNEA_HTTP_PATH_BUF    equ 2560

extern linnea_config_instance
extern linnea_config_match_location
extern linnea_string_from_u64
extern linnea_string_to_u64
extern linnea_string_from_hex_u64
extern linnea_string_equal
extern linnea_string_is_token
extern linnea_string_is_tchar
extern linnea_string_trim_ows
extern linnea_chunk_ext_step
extern linnea_spill_chunked
extern linnea_string_iequal
extern linnea_string_has_token
extern linnea_time_http_date
extern linnea_time_parse_http_date
extern linnea_time_http_now
; request-evaluation helpers shared with the h2/h3 serve paths; they live in
; linnea_static.asm so the h3 test binaries link without this file's deps
extern linnea_http_identity_refused
extern linnea_http_coding_ok
extern linnea_static_variant_fresh
extern linnea_static_mtime_of
extern linnea_http_inm_match
extern linnea_http_etag_match
extern linnea_http_ifrange_match
extern linnea_http_range_parse
extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp
extern linnea_log_access_begin

extern linnea_upstream_count
extern linnea_upstream_open
extern linnea_ratelimit_take
extern linnea_ratelimit_on
extern linnea_uring_now
extern linnea_upstream_closed
extern linnea_upstream_pick
extern linnea_upstream_take
extern linnea_upstream_reap_one
extern linnea_upstream_limit

section .rodata


resp_400:       db "HTTP/1.1 400 Bad Request", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_400_len    equ $ - resp_400
resp_404:       db "HTTP/1.1 404 Not Found", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_404_len    equ $ - resp_404
; The same 404 for a static path, which is content-negotiated even when it
; misses: a ".br" with no plain file beside it is served to whoever takes the
; encoding and 404s everyone else, so without Vary a shared cache stores this
; 404 under the bare URL and then hands it to the very clients the variant was
; for (h1-15). The negotiated 200 already carries the header; the miss has to
; agree with it or the two responses are not interchangeable to a cache.
resp_404_vary:  db "HTTP/1.1 404 Not Found", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Vary: Accept-Encoding", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_404_vary_len equ $ - resp_404_vary
; "OPTIONS *": what this server supports, as a whole. Bodiless, like every
; other canned response.
;
; It says "Connection: close" because it DOES close: every blob goes through
; .resp_static, which clears keep_alive unconditionally. The comment here used
; to claim the opposite — "it keeps the connection (nothing went wrong)" — and
; RFC 9112 9.6 requires a server that will close to send the close option, so
; the two disagreeing left a client waiting on a socket already on its way out.
slash_target:   db "/"
resp_options:   db "HTTP/1.1 200 OK", 13, 10
                db "Allow: GET, HEAD, OPTIONS", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_options_len equ $ - resp_options
resp_405:       db "HTTP/1.1 405 Method Not Allowed", 13, 10
                db "Allow: GET, HEAD", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_405_len    equ $ - resp_405
resp_413:       db "HTTP/1.1 413 Content Too Large", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_413_len    equ $ - resp_413
; RFC 9110 15.5.18: an expectation this server cannot meet. Only 100-continue
; is defined, and only a proxy location can pass another one on for a backend
; to judge; where we ARE the origin, serving the resource anyway would tell the
; client its expectation was met (audit-report-33).
; RFC 9110 15.5.7 with 12.5.3: the client excluded the unencoded form with
; identity;q=0 and no coded variant it named is available, so there is no
; representation left that it will take.
; The 406 is the one status that exists ONLY because of Accept-Encoding, so it
; carries Vary unconditionally where the 404 needs a separate blob for the
; static path alone (resp_404_vary above). Added with the status itself in
; 4185ddf and missed there: the header three lines up states the rule, and the
; new status walked straight past it (audit-report-37).
resp_406:       db "HTTP/1.1 406 Not Acceptable", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Vary: Accept-Encoding", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_406_len    equ $ - resp_406
resp_417:       db "HTTP/1.1 417 Expectation Failed", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_417_len    equ $ - resp_417
resp_414:       db "HTTP/1.1 414 URI Too Long", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_414_len    equ $ - resp_414
; RFC 9110 15.5.9: the client did not finish the request in time. Sent where
; the connection used to be dropped in silence -- a client whose body stalled
; got no status at all and could not tell a server that gave up from a network
; that ate the connection. "Connection: close" is the SHOULD in 15.5.9.
resp_408:       db "HTTP/1.1 408 Request Timeout", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_408_len    equ $ - resp_408
; RFC 6585 4. Connection: close on purpose — a client being metered should not
; hold the connection open waiting to spend the next bucket on it.
resp_429:       db "HTTP/1.1 429 Too Many Requests", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_429_len    equ $ - resp_429
resp_431:       db "HTTP/1.1 431 Request Header Fields Too Large", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_431_len    equ $ - resp_431
resp_501:       db "HTTP/1.1 501 Not Implemented", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_501_len    equ $ - resp_501
; Bodiless, like every other canned response: .resp_static appends the vhost's
; security headers by copying the blob without its terminating blank line (the
; "- 4"), which silently cut into a trailing body instead — the appended
; headers landed inside it and Content-Length then covered the wrong bytes.
resp_503:       db "HTTP/1.1 503 Service Unavailable", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_503_len    equ $ - resp_503
resp_502:       db "HTTP/1.1 502 Bad Gateway", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_502_len    equ $ - resp_502
resp_504:       db "HTTP/1.1 504 Gateway Timeout", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_504_len    equ $ - resp_504
resp_505:       db "HTTP/1.1 505 HTTP Version Not Supported", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_505_len    equ $ - resp_505

status_200:     db "HTTP/1.1 200 OK", 13, 10, "Content-Type: "
status_200_len  equ $ - status_200
status_301:     db "HTTP/1.1 301 Moved Permanently", 13, 10, "Location: "
status_301_len  equ $ - status_301
hdr_301_tail:   db 13, 10, "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
hdr_301_tail_len equ $ - hdr_301_tail
status_206:     db "HTTP/1.1 206 Partial Content", 13, 10, "Content-Type: "
status_206_len  equ $ - status_206
status_412:     db "HTTP/1.1 412 Precondition Failed"
status_412_len  equ $ - status_412
status_304:     db "HTTP/1.1 304 Not Modified"
status_304_len  equ $ - status_304
status_416:     db "HTTP/1.1 416 Range Not Satisfiable", 13, 10
                db "Content-Range: bytes */"
status_416_len  equ $ - status_416
hdr_length:     db 13, 10, "Content-Length: "
hdr_length_len  equ $ - hdr_length
hdr_etag:       db 13, 10, "ETag: "
hdr_etag_len    equ $ - hdr_etag
hdr_last_mod:   db 13, 10, "Last-Modified: "
hdr_last_mod_len equ $ - hdr_last_mod
hdr_content_enc: db 13, 10, "Content-Encoding: "
hdr_content_enc_len equ $ - hdr_content_enc
hdr_vary:       db 13, 10, "Vary: Accept-Encoding"
hdr_vary_len    equ $ - hdr_vary
hdr_altsvc:     db 13, 10, "Alt-Svc: "
hdr_altsvc_len  equ $ - hdr_altsvc
hdr_accept_ranges: db 13, 10, "Accept-Ranges: bytes"
hdr_accept_ranges_len equ $ - hdr_accept_ranges
hdr_server:     db 13, 10, "Server: linnea"
hdr_server_len  equ $ - hdr_server
hdr_cache_control: db 13, 10, "Cache-Control: "
hdr_cache_control_len equ $ - hdr_cache_control
hdr_hsts:       db 13, 10, "Strict-Transport-Security: "
hdr_hsts_len    equ $ - hdr_hsts
hdr_nosniff:    db 13, 10, "X-Content-Type-Options: nosniff"
hdr_nosniff_len equ $ - hdr_nosniff
; The same two policies in the PROXY head's style. The generated-head constants
; above lead with CRLF because that builder appends pieces before one final
; terminator; the proxy rewriter appends complete lines. Same policy, two framing
; conventions, so the bytes differ and the VALUE does not.
hdr_p_hsts:     db "Strict-Transport-Security: "
hdr_p_hsts_len  equ $ - hdr_p_hsts
hdr_p_nosniff:  db "X-Content-Type-Options: nosniff", 13, 10
hdr_p_nosniff_len equ $ - hdr_p_nosniff
hn_sts:         db "strict-transport-security"
hn_sts_len      equ $ - hn_sts
hn_xcto:        db "x-content-type-options"
hn_xcto_len     equ $ - hn_xcto
hdr_date:       db 13, 10, "Date: "
hdr_date_len    equ $ - hdr_date
hdr_content_range: db 13, 10, "Content-Range: bytes "
hdr_content_range_len equ $ - hdr_content_range

enc_br:         db "br"
enc_br_len      equ $ - enc_br
enc_gzip:       db "gzip"
enc_gzip_len    equ $ - enc_gzip
hdr_keepalive:  db 13, 10, "Connection: keep-alive", 13, 10, 13, 10
hdr_keepalive_len equ $ - hdr_keepalive
hdr_close:      db 13, 10, "Connection: close", 13, 10, 13, 10
hdr_close_len   equ $ - hdr_close

; Rewritten heads end their last copied header line with CRLF, so these
; carry no leading CRLF of their own.
; RFC 9110 7.6.3 MUST: an intermediary adds a Via entry naming the protocol it
; received the message over and a name for itself. Without it a request that
; crosses this proxy is indistinguishable from one that reached the backend
; directly, which is what the field exists to prevent (loop detection, and
; knowing which hop to blame). Via is list-valued, so emitting our own line
; alongside any the client already sent is the same thing as appending to it
; (5.3) and needs no splicing.
;
; The received-protocol is exact rather than assumed: this handler admits only
; HTTP/1.1 requests, and an upstream response is HTTP/1.1 by the time the
; rewriter has accepted it.
hdr_via_11:     db "Via: 1.1 linnea", 13, 10
hdr_via_11_len  equ $ - hdr_via_11
qmark_lit:      db "?"
hdr_host_up:    db "Host: "
hdr_host_up_len equ $ - hdr_host_up
hdr_cl_up:      db "Content-Length: "
hdr_cl_up_len   equ $ - hdr_cl_up
hdr_crlf_up:    db 13, 10
hdr_up_close:   db "Connection: close", 13, 10, 13, 10
hdr_up_close_len equ $ - hdr_up_close
; Said explicitly rather than by omission. HTTP/1.1 defaults to keep-alive, so
; the field is not required -- but a backend behind an intermediary that
; downgrades reads the absence differently from the word, and the word costs 24
; bytes once per request.
hdr_up_keep:    db "Connection: keep-alive", 13, 10, 13, 10
hdr_up_keep_len equ $ - hdr_up_keep
hdr_up_keepalive: db "Connection: keep-alive", 13, 10, 13, 10
hdr_up_keepalive_len equ $ - hdr_up_keepalive
hdr_up_upgrade: db "Connection: upgrade", 13, 10, 13, 10
hdr_up_upgrade_len equ $ - hdr_up_upgrade
req_version:    db " HTTP/1.1", 13, 10
req_version_len equ $ - req_version
version_11_sp:  db "HTTP/1.1 "
version_11_sp_len equ $ - version_11_sp

version_11:     db "HTTP/1.1"          ; 8 bytes, compared as one qword
version_1x:     db "HTTP/1."           ; the 7-byte prefix, minor digit free
                db 0                   ; the 8th byte of the qword read above
version_10:     db "HTTP/1.0"          ; accepted from an upstream, rewritten
crlf:           db 13, 10
crlfcrlf:       db 13, 10, 13, 10
; The methods RFC 9110 defines, plus PATCH (RFC 5789). A method in this list is
; one we recognise but do not serve here, which is 405 with an Allow header; one
; that is not is 501, because 15.6.2 makes that "the appropriate response when
; the server does not recognize the request method". Answering 405 to both told
; a client that FROB is a real method simply not allowed on this resource.
; Length-prefixed and contiguous, terminated by a zero length. Case-sensitive:
; RFC 9110 9.1 makes the method case-sensitive, so "get" is not GET.
known_methods:  db 4, "POST"
                db 3, "PUT"
                db 6, "DELETE"
                db 7, "CONNECT"
                db 7, "OPTIONS"
                db 5, "TRACE"
                db 5, "PATCH"
                db 0
method_trace:   db "TRACE"
method_options: db "OPTIONS"
method_get:     db "GET"
method_head:    db "HEAD"
index_html:     db "index.html"
index_html_len  equ $ - index_html

log_req:        db "request "
log_req_len     equ $ - log_req
log_from:       db " from "
log_from_len    equ $ - log_from
log_quote:      db ' "'
log_endq:       db '" '
; the protocol closes the quoted request, as the Common Log Format has it. It
; is written from the request line, not from a constant: the version check
; admits 1.0 and 1.2-1.9 as well as 1.1, and 505 exists precisely to answer a
; version this server does not implement -- so a constant made the log silent
; about the one field the status was about.
log_dash:       db "-"
log_sp:         db " "
log_nl:         db 10

val_close_h1:   db "close"
hn_connection:  db "connection"
hn_content_len: db "content-length"
hn_transfer_enc: db "transfer-encoding"
hn_host:        db "host"
hn_expect:      db "expect"
hn_max_forwards: db "max-forwards"
hdr_max_forwards: db "Max-Forwards: "
hdr_max_forwards_len equ $ - hdr_max_forwards
hv_100_continue: db "100-continue"
resp_100:       db "HTTP/1.1 100 Continue", 13, 10, 13, 10
resp_100_len    equ $ - resp_100
hn_if_none_match: db "if-none-match"
hn_if_mod_since: db "if-modified-since"
hn_accept_enc:  db "accept-encoding"
hn_upgrade:     db "upgrade"       ; the header name and the Connection token
hn_range:       db "range"
hn_if_range:    db "if-range"
hn_if_match:    db "if-match"
hn_if_unmod:    db "if-unmodified-since"
; Fields that are hop-by-hop in themselves, whatever Connection says. RFC 9110
; 7.6.1 makes an intermediary drop the fields a Connection value NAMES — that is
; linnea_http_head_conn_named — but these are connection-specific on their own and
; must not be forwarded even when the peer never lists them. A client that sends
; `Keep-Alive: timeout=5` or `TE: gzip` without naming it in Connection had it
; relayed to the backend verbatim, which is the same smuggling surface 7.6.1
; exists to close: the backend reads framing or connection instructions that were
; meant for the hop it never shared.
;
; Length-prefixed and contiguous so the walk needs no pointer table. Terminated
; by a zero length.
;
; Upgrade is deliberately NOT here, in either direction: this proxy tunnels
; websockets, and the 101 path emits only "Connection: upgrade", so the backend's
; own Upgrade header has to reach the client through the copy loop for the
; handshake to complete. Connection and Transfer-Encoding are absent too — both
; are already handled where the rewriters replace them.
; RFC 9110 gives each of these a single-value grammar, so a second line is a
; message that contradicts itself. One byte of length, one of bit, then the
; name -- the bit avoids a variable shift, which would want cl and the line
; cursor lives in rcx.
hv_singletons:
    db 12, 0x01, "content-type"
    db  8, 0x02, "location"
    db  4, 0x04, "etag"
    db 13, 0x08, "last-modified"
    db  7, 0x10, "expires"
    db  3, 0x20, "age"
    db 11, 0x40, "retry-after"
    db 13, 0x80, "content-range"
    db  0, 0
hop_by_hop_names:
    db 10, "keep-alive"
    db  2, "te"
    db  7, "trailer"
    db 16, "proxy-connection"
    db 18, "proxy-authenticate"
    db 19, "proxy-authorization"
    db  0
hdr_te_chunked: db "Transfer-Encoding: chunked", 13, 10
hdr_te_chunked_len equ $ - hdr_te_chunked
hv_close:       db "close"
hv_keepalive:   db "keep-alive"
hv_chunked:     db "chunked"
slash_ch:       db "/"
zero_ch:        db "0"

; MIME types by file extension; default is application/octet-stream.
mime_html:      db "text/html; charset=utf-8"
mime_html_len   equ $ - mime_html
mime_css:       db "text/css; charset=utf-8"
mime_css_len    equ $ - mime_css
mime_js:        db "text/javascript; charset=utf-8"
mime_js_len     equ $ - mime_js
mime_json:      db "application/json"
mime_json_len   equ $ - mime_json
mime_txt:       db "text/plain; charset=utf-8"
mime_txt_len    equ $ - mime_txt
mime_htm: db "text/html; charset=utf-8"
mime_htm_len equ $ - mime_htm
mime_mjs: db "text/javascript; charset=utf-8"
mime_mjs_len equ $ - mime_mjs
mime_wasm: db "application/wasm"
mime_wasm_len equ $ - mime_wasm
mime_webp: db "image/webp"
mime_webp_len equ $ - mime_webp
mime_avif: db "image/avif"
mime_avif_len equ $ - mime_avif
mime_woff2: db "font/woff2"
mime_woff2_len equ $ - mime_woff2
mime_woff: db "font/woff"
mime_woff_len equ $ - mime_woff
mime_ttf: db "font/ttf"
mime_ttf_len equ $ - mime_ttf
mime_otf: db "font/otf"
mime_otf_len equ $ - mime_otf
mime_mp3: db "audio/mpeg"
mime_mp3_len equ $ - mime_mp3
mime_ogg: db "audio/ogg"
mime_ogg_len equ $ - mime_ogg
mime_wav: db "audio/wav"
mime_wav_len equ $ - mime_wav
mime_m4a: db "audio/mp4"
mime_m4a_len equ $ - mime_m4a
mime_aac: db "audio/aac"
mime_aac_len equ $ - mime_aac
mime_flac: db "audio/flac"
mime_flac_len equ $ - mime_flac
mime_pdf: db "application/pdf"
mime_pdf_len equ $ - mime_pdf
mime_xml: db "application/xml"
mime_xml_len equ $ - mime_xml
mime_csv: db "text/csv; charset=utf-8"
mime_csv_len equ $ - mime_csv
mime_md: db "text/markdown; charset=utf-8"
mime_md_len equ $ - mime_md
mime_zip: db "application/zip"
mime_zip_len equ $ - mime_zip
mime_gz: db "application/gzip"
mime_gz_len equ $ - mime_gz
mime_map: db "application/json"
mime_map_len equ $ - mime_map
mime_wmanifest: db "application/manifest+json"
mime_wmanifest_len equ $ - mime_wmanifest
mime_mp4:       db "video/mp4"
mime_mp4_len    equ $ - mime_mp4
mime_webm:      db "video/webm"
mime_webm_len   equ $ - mime_webm
mime_ogv:       db "video/ogg"
mime_ogv_len    equ $ - mime_ogv
mime_png:       db "image/png"
mime_png_len    equ $ - mime_png
mime_jpeg:      db "image/jpeg"
mime_jpeg_len   equ $ - mime_jpeg
mime_gif:       db "image/gif"
mime_gif_len    equ $ - mime_gif
mime_svg:       db "image/svg+xml"
mime_svg_len    equ $ - mime_svg
mime_ico:       db "image/x-icon"
mime_ico_len    equ $ - mime_ico
mime_default:   db "application/octet-stream"
mime_default_len equ $ - mime_default

ext_html:       db "html"
ext_css:        db "css"
ext_js:         db "js"
ext_json:       db "json"
ext_txt:        db "txt"
ext_png:        db "png"
ext_jpg:        db "jpg"
ext_jpeg:       db "jpeg"
ext_gif:        db "gif"
ext_svg:        db "svg"
ext_ico:        db "ico"
ext_mp4:        db "mp4"
ext_webm:       db "webm"
ext_ogv:        db "ogv"
ext_htm: db "htm"
ext_mjs: db "mjs"
ext_wasm: db "wasm"
ext_webp: db "webp"
ext_avif: db "avif"
ext_woff2: db "woff2"
ext_woff: db "woff"
ext_ttf: db "ttf"
ext_otf: db "otf"
ext_mp3: db "mp3"
ext_ogg: db "ogg"
ext_wav: db "wav"
ext_m4a: db "m4a"
ext_aac: db "aac"
ext_flac: db "flac"
ext_pdf: db "pdf"
ext_xml: db "xml"
ext_csv: db "csv"
ext_md: db "md"
ext_zip: db "zip"
ext_gz: db "gz"
ext_map: db "map"
ext_wmanifest: db "webmanifest"

; entries: ext ptr, ext len, mime ptr, mime len; terminated by a 0 ptr
mime_table:
    dq ext_html, 4, mime_html, mime_html_len
    dq ext_css,  3, mime_css,  mime_css_len
    dq ext_js,   2, mime_js,   mime_js_len
    dq ext_json, 4, mime_json, mime_json_len
    dq ext_txt,  3, mime_txt,  mime_txt_len
    dq ext_png,  3, mime_png,  mime_png_len
    dq ext_jpg,  3, mime_jpeg, mime_jpeg_len
    dq ext_jpeg, 4, mime_jpeg, mime_jpeg_len
    dq ext_gif,  3, mime_gif,  mime_gif_len
    dq ext_svg,  3, mime_svg,  mime_svg_len
    dq ext_ico,  3, mime_ico,  mime_ico_len
    dq ext_mp4,  3, mime_mp4,  mime_mp4_len
    dq ext_webm, 4, mime_webm, mime_webm_len
    dq ext_ogv,  3, mime_ogv,  mime_ogv_len
    dq ext_htm, 3, mime_htm, mime_htm_len
    dq ext_mjs, 3, mime_mjs, mime_mjs_len
    dq ext_wasm, 4, mime_wasm, mime_wasm_len
    dq ext_webp, 4, mime_webp, mime_webp_len
    dq ext_avif, 4, mime_avif, mime_avif_len
    dq ext_woff2, 5, mime_woff2, mime_woff2_len
    dq ext_woff, 4, mime_woff, mime_woff_len
    dq ext_ttf, 3, mime_ttf, mime_ttf_len
    dq ext_otf, 3, mime_otf, mime_otf_len
    dq ext_mp3, 3, mime_mp3, mime_mp3_len
    dq ext_ogg, 3, mime_ogg, mime_ogg_len
    dq ext_wav, 3, mime_wav, mime_wav_len
    dq ext_m4a, 3, mime_m4a, mime_m4a_len
    dq ext_aac, 3, mime_aac, mime_aac_len
    dq ext_flac, 4, mime_flac, mime_flac_len
    dq ext_pdf, 3, mime_pdf, mime_pdf_len
    dq ext_xml, 3, mime_xml, mime_xml_len
    dq ext_csv, 3, mime_csv, mime_csv_len
    dq ext_md, 2, mime_md, mime_md_len
    dq ext_zip, 3, mime_zip, mime_zip_len
    dq ext_gz, 2, mime_gz, mime_gz_len
    dq ext_map, 3, mime_map, mime_map_len
    dq ext_wmanifest, 11, mime_wmanifest, mime_wmanifest_len
    dq 0

section .bss

num_buf:        resb 20
; '"' + 16 hex mtime digits + '-' + 16 hex size digits + '"', with room for
; the hex formatter's 16-byte scratch past each write cursor
etag_buf:       resb 48
etag_len:       resq 1
date_buf:       resb LINNEA_HTTP_DATE_LEN
path_buf:       resb LINNEA_HTTP_PATH_BUF
statbuf:        resb LINNEA_STAT_SIZE

section .text

; linnea_http_handle(rdi=connection*) -> rax
;   LINNEA_HTTP_NEED_MORE: incomplete head, arm another recv
;   LINNEA_HTTP_RESPOND:   out/file fields set; send, then consult
;                          conn.keep_alive
;
; Stack locals:
;   [rsp+0]  is_head        [rsp+8]  target ptr   [rsp+16] target len
;   [rsp+24] keep_alive     [rsp+32] file size    [rsp+40] mime ptr
;   [rsp+48] mime len       [rsp+56] name ptr / open fd / vhost scratch
;   [rsp+64] name len       [rsp+72] value ptr    [rsp+80] value len
;   [rsp+88] Host value ptr (0 = absent)          [rsp+96] Host value len
;   [rsp+104] method len    [rsp+112] status      [rsp+120] server* (for log)
;   [rsp+128] Content-Length value                [rsp+136] flags: 1=CL, 2=TE
;   [rsp+144] raw target len, query included (the target len at [rsp+16]
;             is truncated at '?' for routing)  [rsp+152] location*
;   [rsp+160] best prefix len (location match scratch)
;   [rsp+168] directory flag (r9 does not survive the match loop's calls)
;   [rsp+176] If-None-Match ptr (0 = absent)     [rsp+184] its len
;   [rsp+192] If-Modified-Since ptr (0 = absent) [rsp+200] its len
;   [rsp+208] Accept-Encoding ptr (0 = absent)   [rsp+216] its len
;   [rsp+224] encoding served: 0 none, 1 gzip, 2 br
;   [rsp+232] upgrade flags: 1 = Connection lists the upgrade token,
;             2 = an Upgrade header is present; 3 = forward the wish
;   [rsp+240] Range ptr (0 = absent)             [rsp+248] its len
;   [rsp+256] If-Range ptr (0 = absent)          [rsp+264] its len
;   [rsp+272] body offset   [rsp+280] body length (the whole file, or the
;             satisfiable range of a 206)
;   [rsp+296] Host field lines seen (RFC 9112 3.2 wants exactly one)
;   [rsp+312] If-Match ptr (0 = absent)          [rsp+320] its len
;   [rsp+328] If-Unmodified-Since ptr (0 = absent) [rsp+336] its len
;   [rsp+352] Accept-Encoding spans (3 x 16 bytes, ending at 399)
;   [rsp+400] the source file's mtime, for the precompressed-variant staleness
;             test -- the slot immediately after that array
;   [rsp+304] asterisk-form: the target was "*", so the request is about the
;             server itself rather than any resource (OPTIONS *)

; http_hop_by_hop(rdi = field name, rsi = name length) -> rax = 1 if the field
; must not cross this hop, whatever Connection says. See hop_by_hop_names.
;
; Touches neither r10 nor r13 — the two rewriters keep their colon offset in
; those across the comparisons, and linnea_string_iequal leaves them alone.
; proxy_abs_authority(rdi = head base, rsi = method length)
;   -> rdx = authority length (0 when the target is not absolute-form),
;      rax = authority pointer.
;
; RFC 9112 3.2.2: with an absolute-form request-target, a proxy MUST ignore the
; received Host and forward the target's authority instead. The parser already
; ROUTES on that authority, but its routing slot holds the host with the PORT
; STRIPPED -- correct for vhost selection, wrong for a Host line -- so this
; re-reads the authority from the original request line, which is still intact
; in the head buffer (audit-report-75; the first attempt reused the routing slot
; and quietly dropped ":8080" from every proxied request).
;
; Touches rax/rcx/rdx/r8/r9 only.
proxy_abs_authority:
    lea r8, [rdi + rsi + 1]           ; the target, past "METHOD "
    xor edx, edx
    movzx eax, byte [r8]
    or al, 0x20
    cmp al, 'h'
    jne .paa_no
    movzx eax, byte [r8+1]
    or al, 0x20
    cmp al, 't'
    jne .paa_no
    movzx eax, byte [r8+2]
    or al, 0x20
    cmp al, 't'
    jne .paa_no
    movzx eax, byte [r8+3]
    or al, 0x20
    cmp al, 'p'
    jne .paa_no
    lea r9, [r8+4]                    ; after "http"
    movzx eax, byte [r9]
    or al, 0x20
    cmp al, 's'
    jne .paa_colon
    inc r9                            ; "https"
.paa_colon:
    cmp byte [r9], ':'
    jne .paa_no
    cmp byte [r9+1], '/'
    jne .paa_no
    cmp byte [r9+2], '/'
    jne .paa_no
    add r9, 3                         ; the authority starts here
    mov rax, r9
.paa_scan:
    movzx ecx, byte [r9]
    cmp cl, '/'
    je .paa_end
    cmp cl, '?'
    je .paa_end
    cmp cl, '#'
    je .paa_end
    cmp cl, ' '
    je .paa_end
    cmp cl, 13
    je .paa_end
    inc r9
    jmp .paa_scan
.paa_end:
    mov rdx, r9
    sub rdx, rax                      ; authority length, port included
    ret
.paa_no:
    xor edx, edx
    ret


http_hop_by_hop:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8                 ; 4 pushes + the return address: re-align to 16
    mov r12, rdi
    mov r13, rsi
    lea rbx, [hop_by_hop_names]
.hb_loop:
    movzx r14d, byte [rbx]     ; this entry's name length
    test r14d, r14d
    jz .hb_no                  ; the zero terminator: nothing matched
    cmp r13, r14
    jne .hb_next               ; lengths differ, so the names cannot match
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rbx + 1]
    mov ecx, r14d
    call linnea_string_iequal
    test eax, eax
    jnz .hb_yes
.hb_next:
    lea rbx, [rbx + r14 + 1]
    jmp .hb_loop
.hb_yes:
    mov eax, 1
    jmp .hb_ret
.hb_no:
    xor eax, eax
.hb_ret:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


linnea_http_handle:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 560               ; +32 for the two precondition fields, +64 for the
                               ; Accept-Encoding span array (h1-14): [352] holds
                               ; three (ptr,len) pairs, [400] the scan index, and
                               ; [416]/[424] the version token as the client wrote
                               ; it, for the access log, [432] and [480] three
                               ; (ptr,len) spans each for If-None-Match and
                               ; If-Match, counted at [176] and [312], and
                               ; [528] the Max-Forwards value (bit 64 of the
                               ; framing flags says whether one was sent), and
                               ; [536]/[544] an absolute-form empty path's query
                               ; (audit-report-76)
    ; Cleared per request: this frame is reused for every request on a
    ; keep-alive connection, and a stale query would be appended to the next
    ; request's target. Only the absolute-form branch below ever sets them.
    mov qword [rsp + 536], 0
    mov qword [rsp + 544], 0
    mov rbx, rdi
    lea r14, [rbx + linnea_connection.in_buf]
    mov r12, [rbx + linnea_connection.in_len]
    mov qword [rsp + 8], 0     ; no target yet
    mov qword [rsp + 16], 0
    mov qword [rsp + 24], 1    ; keep_alive default on
    mov qword [rsp + 32], 0    ; response bytes
    mov qword [rsp + 88], 0    ; no Host header yet
    mov qword [rsp + 96], 0
    mov qword [rsp + 296], 0   ; and none counted
    mov qword [rsp + 104], 0   ; no method yet
    mov qword [rsp + 128], 0   ; no body
    mov qword [rsp + 136], 0   ; no Content-Length/Transfer-Encoding seen
    mov qword [rsp + 144], 0   ; no raw target yet
    mov qword [rsp + 416], 0   ; ...and no version token yet
    mov qword [rsp + 176], 0   ; no If-None-Match lines yet (a count)
    mov qword [rsp + 192], 0   ; no If-Modified-Since yet
    mov qword [rsp + 208], 0   ; no Accept-Encoding lines yet (a count, h1-14)
    mov qword [rsp + 224], 0   ; nothing negotiated
    mov qword [rsp + 232], 0   ; no upgrade asked
    mov qword [rsp + 240], 0   ; no Range yet
    mov qword [rsp + 256], 0   ; no If-Range yet
    mov ecx, [rbx + linnea_connection.server]
    imul rcx, rcx, linnea_config_server_size
    lea rax, [linnea_config_instance]
    lea rax, [rax + rcx + linnea_config.servers]
    mov [rsp + 120], rax       ; default server, until a vhost matches

    ; find the CRLF CRLF terminator
    xor r13d, r13d
.scan:
    lea rax, [r13 + 4]
    cmp rax, r12
    ja .no_terminator
    cmp dword [r14 + r13], 0x0A0D0A0D    ; "\r\n\r\n"
    je .found
    inc r13
    jmp .scan
.no_terminator:
    cmp r12, LINNEA_CONN_IN_BUF
    jae .resp_431
    mov eax, LINNEA_HTTP_NEED_MORE
    jmp .ret

.found:
    ; One complete head is one request — which on a keep-alive connection is a
    ; very different count from max_per_ip's. Checked before the method is read,
    ; so a refused request costs the parse of nothing.
    cmp qword [linnea_ratelimit_on], 0
    je .rl_ok
    push r13
    push r12
    call linnea_uring_now            ; the clock FIRST: it takes rdi/rsi for its
    mov rdx, rax                     ; syscall and would destroy the address
    lea rdi, [rbx + linnea_connection.peer_ip]
    mov rsi, [rbx + linnea_connection.peer_ip_len]
    call linnea_ratelimit_take
    pop r12
    pop r13
    test eax, eax
    jnz .resp_429
.rl_ok:
    ; whole head = terminator offset + 4 bytes; lines end strictly
    ; before r13 + 2 (the terminating empty line's CRLF).
    lea rax, [r13 + 4]
    mov [rbx + linnea_connection.head_len], rax
    add r13, 2                 ; head limit
    xor r15d, r15d             ; cursor

    ; --- method ---------------------------------------------------
.method_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ' '
    je .method_done
    cmp al, 0x21
    jb .resp_400
    cmp al, 0x7e
    ja .resp_400
    inc r15
    jmp .method_loop
.method_done:
    test r15, r15
    jz .resp_400
    cmp r15, LINNEA_HTTP_MAX_METHOD
    ja .resp_400
    ; The loop above only bounded the method to printable ASCII, which admits
    ; every delimiter — so a method could carry a double quote, and the access
    ; line writes the method inside quotes, splitting its own field. A method is
    ; a token (RFC 9110 9.1), so hold it to one.
    mov rdi, r14               ; the method bytes, at in_buf[0]
    mov rsi, r15
    call linnea_string_is_token
    test eax, eax
    jz .resp_400
    mov [rsp + 104], r15       ; method = in_buf[0 .. len)
    ; GET, HEAD, or 405 (checked after the head parses cleanly)
    mov qword [rsp], -1
    cmp r15, 3
    jne .try_head
    cmp word [r14], 'GE'
    jne .method_known
    cmp byte [r14 + 2], 'T'
    jne .method_known
    mov qword [rsp], 0         ; GET
    jmp .method_known
.try_head:
    cmp r15, 4
    jne .method_known
    cmp dword [r14], 'HEAD'
    jne .method_known
    mov qword [rsp], 1         ; HEAD
.method_known:
    cmp qword [rsp], -1
    jne .method_classified     ; GET or HEAD: nothing to look up
    ; not GET or HEAD: recognised (405) or not (501)? r14/r15 are the method
    ; bytes and length, and both are callee-saved, so only the walk's own
    ; cursor needs saving across the compare — which keeps the pushes even and
    ; the stack aligned for it.
    lea r9, [known_methods]
.km_loop:
    movzx ecx, byte [r9]
    test ecx, ecx
    jz .km_unknown
    cmp rcx, r15
    jne .km_next
    push r9
    push rcx
    mov rdi, r14
    mov rsi, r15
    lea rdx, [r9 + 1]
    call linnea_string_equal   ; case-sensitive: a method is (9.1)
    pop rcx
    pop r9
    test eax, eax
    jnz .method_classified     ; a method we know: the 405 already set stands
.km_next:
    lea r9, [r9 + rcx + 1]
    jmp .km_loop
.km_unknown:
    mov qword [rsp], -2        ; unrecognised: 501
.method_classified:
    inc r15                    ; skip the SP

    ; --- target ---------------------------------------------------
    lea rax, [r14 + r15]
    mov [rsp + 8], rax
    mov rcx, r15
.target_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ' '
    je .target_done
    cmp al, 0x21
    jb .resp_400
    cmp al, 0x7e
    ja .resp_400
    inc r15
    jmp .target_loop
.target_done:
    mov rax, r15
    sub rax, rcx
    mov [rsp + 16], rax
    mov [rsp + 144], rax       ; raw length, kept when the query is stripped
    test rax, rax
    jz .resp_400
    ; RFC 9112 3.2: "A server that receives a request-target longer than any
    ; URI it wishes to parse MUST respond with a 414 (URI Too Long)." This said
    ; 400, which tells the client its request was malformed — so it stops rather
    ; than shortening the URL, and a long signed URL looks like a client bug.
    ; The 414 blob was already here, reachable only from the redirect-overflow
    ; guard further down.
    ;
    ; The cap itself stays at 2048. RFC 9112 3 RECOMMENDS supporting at least
    ; 8000, and raising it here is cheap (path_buf is one per worker and in_buf
    ; is 17408), but h2 bounds :path at 2048 and h3's bound is implicit in
    ; linnea_static_normalize's buffer — so lifting only h1 would mean a URL
    ; that works over one protocol and not another. Left together, deliberately.
    cmp rax, LINNEA_HTTP_MAX_TARGET
    ja .resp_414
    inc r15                    ; skip the SP

    ; --- request-target forms (RFC 9112 3.2) ----------------------
    ; Only origin-form ("/path") used to survive: everything else reached the
    ; path normalizer and came back 400. absolute-form is one a server MUST
    ; accept, and asterisk-form is how OPTIONS asks about the server itself.
    ; Both are recognised here, before the target is used for anything.
    mov qword [rsp + 304], 0   ; not an OPTIONS * request
    mov qword [rsp + 312], 0   ; ...and no If-Match lines (also a count)
    mov qword [rsp + 328], 0   ; If-Unmodified-Since absent
    mov rax, [rsp + 8]
    cmp qword [rsp + 16], 1
    jne .not_asterisk
    cmp byte [rax], '*'
    jne .not_asterisk
    mov qword [rsp + 304], 1   ; asterisk-form: the server itself
    jmp .target_form_done
.not_asterisk:
    push r13
    push r15
    mov rdi, [rsp + 16 + 8]    ; target ptr (two pushes above the frame)
    mov rsi, [rsp + 16 + 16]   ; target len
    call target_absolute       ; rax = path ptr / 0, rdx = path len,
                               ; rcx = authority ptr, r8 = authority len
    pop r15
    pop r13
    test rax, rax
    jz .target_form_done
    ; absolute-form: the target carries its own authority, and RFC 9112 3.2
    ; says THAT is what identifies the resource — a Host header, which an
    ; HTTP/1.1 client must still send, is ignored rather than obeyed.
    mov [rsp + 8], rax
    mov [rsp + 16], rdx
    mov [rsp + 144], rdx
    mov [rsp + 88], rcx        ; routing follows the target's authority
    mov [rsp + 96], r8
    mov [rsp + 536], r10       ; an empty path's query, appended by the proxy
    mov [rsp + 544], r11       ; rewrite; zero for every other target form
.target_form_done:

    ; --- version: HTTP/1.x CRLF -----------------------------------
    ; 1.1 is the common case and stays a single qword compare. Anything else
    ; with major version 1 is handled per RFC 9112 2.5 rather than refused:
    ;   1.0 -> served in 1.0 mode (see the four differences below)
    ;   1.2+ -> "process the message as if it were in the highest minor version
    ;           within that major version", i.e. exactly as 1.1
    ; Only a major version we do not implement is 505, which is what RFC 9110
    ; 15.6.6 actually defines that code for -- it was being answered to 1.0 and
    ; 1.2 as well, neither of which is a major-version problem.
    lea rax, [r15 + 8]
    cmp rax, r13
    ja .resp_400
    ; Keep the token for the access log before anything is decided about it.
    ; That log wrote a fixed " HTTP/1.1" for every HTTP/1 request, so a 1.0
    ; request was recorded as 1.1 and -- worse -- the one status that IS about
    ; the version said nothing about it: an HTTP/2 connection preface,
    ; "PRI * HTTP/2.0", is correctly answered 505 and was logged as
    ; `"PRI * HTTP/1.1" 505`, a line this server cannot produce, since that
    ; literal request is a 400. Found from a production 5xx alert where the
    ; logged line was the only evidence and it described a message nobody sent.
    ;
    ; Eight bytes because every version this grammar admits is exactly
    ; "HTTP/x.y". A longer one fails the CRLF check below and is a 400 whose
    ; logged version is its first eight bytes.
    lea rcx, [r14 + r15]
    mov [rsp + 416], rcx
    mov qword [rsp + 424], 8
    mov rax, [r14 + r15]
    mov rcx, [version_11]
    cmp rax, rcx
    je .version_done
    ; not 1.1: is it "HTTP/1." with some other minor digit?
    mov rdx, rax
    mov rcx, 0x00ffffffffffffff       ; the low 7 bytes, "HTTP/1."
    and rdx, rcx
    ; ...and the stored text is masked with the copy already in rcx. Written a
    ; second time as an immediate, the constant truncates to a sign-extended
    ; imm32 and the mask does nothing -- it assembled with a warning. Harmless
    ; as it stood, but only because version_1x carries an explicit zero byte.
    and rcx, [version_1x]
    cmp rdx, rcx
    jne .version_other
    mov rcx, rax
    shr rcx, 56                       ; the minor digit
    cmp cl, '0'
    je .version_10
    cmp cl, '1'
    jb .resp_400                      ; "HTTP/1.-" and the like: malformed
    cmp cl, '9'
    ja .resp_400
    jmp .version_done                 ; 1.2..1.9 -> treat as 1.1 (2.5)
.version_10:
    or qword [rsp + 136], 8           ; this request is HTTP/1.0
    ; 1.0 has no persistent connections unless the client asks for one, so the
    ; default flips: close, and the "keep-alive" token below turns it back on.
    mov qword [rsp + 24], 0
.version_done:
    add r15, 8
    cmp word [r14 + r15], 0x0A0D         ; CRLF
    jne .resp_400
    add r15, 2

    ; --- header lines ---------------------------------------------
.header_loop:
    cmp r15, r13
    jae .parsed
    mov rcx, r15               ; name start
.name_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ':'
    je .name_done
    cmp al, 0x21
    jb .resp_400
    cmp al, 0x7e
    ja .resp_400
    inc r15
    jmp .name_loop
.name_done:
    mov r8, r15
    sub r8, rcx                ; name len
    test r8, r8
    jz .resp_400
    ; A field name is a token (RFC 9110 5.1, 5.6.2). The loop above admits every
    ; printable byte but ':', so the delimiters ( ) , " / [ ] { } @ \ = all
    ; passed — and a name carrying one is copied verbatim to the upstream when
    ; proxying, which is the classic parser-differential setup: two hops
    ; disagreeing about where a field name ends. The method has been checked with
    ; this same helper all along; field names were not.
    push rcx
    push r8
    lea rdi, [r14 + rcx]
    mov rsi, r8
    call linnea_string_is_token
    pop r8
    pop rcx
    test eax, eax
    jz .resp_400
    inc r15                    ; skip ':'
.ows_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ' '
    je .ows_skip
    cmp al, 9
    je .ows_skip
    jmp .value_start
.ows_skip:
    inc r15
    jmp .ows_loop
.value_start:
    mov r9, r15                ; value start
.value_loop:
    movzx eax, byte [r14 + r15]
    cmp al, 13
    je .value_done
    cmp al, 9
    je .value_ok
    cmp al, 0x20
    jb .resp_400
.value_ok:
    inc r15
    cmp r15, r13
    jae .resp_400
    jmp .value_loop
.value_done:
    cmp byte [r14 + r15 + 1], 10
    jne .resp_400
    ; trim trailing OWS: value = [r9, r10)
    mov r10, r15
.trim:
    cmp r10, r9
    jbe .trimmed
    movzx eax, byte [r14 + r10 - 1]
    cmp al, ' '
    je .trim_dec
    cmp al, 9
    je .trim_dec
    jmp .trimmed
.trimmed:
    ; stash name and value for the iequal calls below
    lea rax, [r14 + rcx]
    mov [rsp + 56], rax
    mov [rsp + 64], r8
    lea rax, [r14 + r9]
    mov [rsp + 72], rax
    mov rax, r10
    sub rax, r9
    mov [rsp + 80], rax
    ; Connection: "close", or a token list that may ask to upgrade
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_connection]
    mov ecx, 10
    call linnea_string_iequal
    test eax, eax
    jz .try_content_len
    ; A value that is entirely "close" used to be short-circuited here, and the
    ; shortcut cleared keep-alive WITHOUT the "close is final" flag the token
    ; loop sets -- so a later `Connection: keep-alive` line put persistence back
    ; on and the socket was held against the wish of the client that had already
    ; said close. The token loop below handles a lone "close" correctly and has
    ; since report 10; the special case only existed to skip it. Found beside
    ; audit-report-29, and the same defect: a rule applied per LINE to a field
    ; whose lines are one list.
.conn_tokens:
    ; scan the comma-separated list for the "upgrade" token; the name
    ; scratch at [rsp+56/64] is free once the name has matched
    mov rax, [rsp + 72]
    mov [rsp + 56], rax        ; token cursor
    add rax, [rsp + 80]
    mov [rsp + 64], rax        ; value end
.conn_tok_start:
    mov rax, [rsp + 56]
    cmp rax, [rsp + 64]
    jae .header_next
    movzx ecx, byte [rax]
    cmp cl, ','
    je .conn_tok_skip
    cmp cl, ' '
    je .conn_tok_skip
    cmp cl, 9
    je .conn_tok_skip
    mov rdx, rax               ; token start; find its end
.conn_tok_end:
    cmp rdx, [rsp + 64]
    jae .conn_tok_have
    movzx ecx, byte [rdx]
    cmp cl, ','
    je .conn_tok_have
    cmp cl, ' '
    je .conn_tok_have
    cmp cl, 9
    je .conn_tok_have
    inc rdx
    jmp .conn_tok_end
.conn_tok_have:
    ; The token has to survive the comparisons: linnea_string_iequal returns in
    ; rax and clobbers the registers holding the bounds, so both ends are
    ; spilled before the first call and re-derived for the second.
    mov [rsp + 344], rax       ; token start
    mov [rsp + 56], rdx        ; token end, and where the scan resumes
    mov rdi, rax
    mov rsi, rdx
    sub rsi, rax               ; token length
    lea rdx, [hn_upgrade]
    mov ecx, 7
    call linnea_string_iequal
    test eax, eax
    jz .conn_tok_close
    or qword [rsp + 232], 1    ; the client asks to upgrade
    jmp .conn_tok_start
.conn_tok_close:
    ; "close" is a connection option like any other (RFC 9112 9.1), so it can
    ; sit anywhere in the list. Only a value that was ENTIRELY "close" used to
    ; count, and this loop — which was already walking the tokens — tested for
    ; nothing but "upgrade". So `Connection: keep-alive, close` was answered
    ; `Connection: keep-alive` and the socket was held to the idle timeout,
    ; against the explicit wish of the client that sent it.
    mov rdi, [rsp + 344]
    mov rsi, [rsp + 56]
    sub rsi, rdi               ; token length
    lea rdx, [hv_close]
    mov ecx, 5
    call linnea_string_iequal
    test eax, eax
    jz .conn_tok_ka
    mov qword [rsp + 24], 0    ; the client asked to close
    or qword [rsp + 136], 16   ; ...and that is final, see below
    jmp .conn_tok_start
.conn_tok_ka:
    ; "keep-alive" is how an HTTP/1.0 client asks for the persistence 1.1 gives
    ; by default (RFC 9112 9.3). For a 1.1 request it changes nothing, since the
    ; default is already on.
    ;
    ; "close" wins wherever it sits in the list, which is NOT what applying the
    ; tokens in order gives you: `Connection: close, keep-alive` would end on
    ; keep-alive and hold a socket the client said it was done with. 9.1 makes
    ; close an instruction about the connection, not a vote, so it is sticky.
    test qword [rsp + 136], 16
    jnz .conn_tok_start
    mov rdi, [rsp + 344]
    mov rsi, [rsp + 56]
    sub rsi, rdi               ; token length
    lea rdx, [hv_keepalive]
    mov ecx, 10
    call linnea_string_iequal
    test eax, eax
    jz .conn_tok_start
    mov qword [rsp + 24], 1
    jmp .conn_tok_start
.conn_tok_skip:
    inc qword [rsp + 56]
    jmp .conn_tok_start
.try_content_len:
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_content_len]
    mov ecx, 14
    call linnea_string_iequal
    test eax, eax
    jnz .cl_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_transfer_enc]
    mov ecx, 17
    call linnea_string_iequal
    test eax, eax
    jnz .te_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_if_none_match]
    mov ecx, 13
    call linnea_string_iequal
    test eax, eax
    jnz .inm_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_if_mod_since]
    mov ecx, 17
    call linnea_string_iequal
    test eax, eax
    jnz .ims_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_accept_enc]
    mov ecx, 15
    call linnea_string_iequal
    test eax, eax
    jnz .ae_header
    ; Upgrade? only its presence matters; the value passes through verbatim
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_upgrade]
    mov ecx, 7
    call linnea_string_iequal
    test eax, eax
    jz .try_range
    or qword [rsp + 232], 2
    jmp .header_next
.try_range:
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_range]
    mov ecx, 5
    call linnea_string_iequal
    test eax, eax
    jnz .range_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_if_range]
    mov ecx, 8
    call linnea_string_iequal
    test eax, eax
    jnz .ifr_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_expect]
    mov ecx, 6
    call linnea_string_iequal
    test eax, eax
    jnz .expect_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_max_forwards]
    mov ecx, 12
    call linnea_string_iequal
    test eax, eax
    jnz .mf_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_if_match]
    mov ecx, 8
    call linnea_string_iequal
    test eax, eax
    jnz .ifm_header
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_if_unmod]
    mov ecx, 19
    call linnea_string_iequal
    test eax, eax
    jnz .ius_header
.try_host:
    ; Host? Counted, not just captured: a second Host field line is a request
    ; smuggling primitive (an intermediary may route on the other one), so
    ; every occurrence must be seen even though the first supplies the value.
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_host]
    mov ecx, 4
    call linnea_string_iequal
    test eax, eax
    jz .header_next
    inc qword [rsp + 296]
    cmp qword [rsp + 88], 0
    jne .header_next           ; keep the first value; the count rejects it below
    mov rax, [rsp + 72]
    mov [rsp + 88], rax
    mov rax, [rsp + 80]
    mov [rsp + 96], rax
    jmp .header_next
.mf_header:
    ; RFC 9110 7.6.2: Max-Forwards limits how many intermediaries an OPTIONS or
    ; TRACE may cross. At zero we are the final recipient and MUST answer
    ; ourselves rather than forward; above zero we MUST forward a value one
    ; lower. Neither happened -- the field was copied upstream untouched, so a
    ; chain of proxies would circulate a request whose whole purpose is to stop
    ; at a chosen hop. TRACE is refused outright now, so OPTIONS is the method
    ; this serves (audit-report-33 follow-up).
    ;
    ; 1*DIGIT and nothing else, so a value that is not a number is a bad
    ; request rather than a field to ignore: it asks for a hop count we cannot
    ; work out. A SECOND line is refused for the same reason and by the same
    ; rule as the singleton conditionals beside it (audit-report-32): the field
    ; is one count, not a list, so two of them are two answers to one question.
    ; Keeping the last let a client decide by field ORDER whether the request
    ; was forwarded at all -- "0 then 1" went upstream and "1 then 0" was
    ; answered here -- and HTTP/1 forwarded a decremented line per original
    ; occurrence while h2 and h3 emitted one (audit-report-34).
    test qword [rsp + 136], 64
    jnz .resp_400
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    call linnea_string_to_u64  ; -> rax = value, edx = 0 ok / 1 syntax / 2 range
    test edx, edx
    jnz .resp_400
    mov [rsp + 528], rax
    or qword [rsp + 136], 64   ; a Max-Forwards was sent
    jmp .header_next
.expect_header:
    ; 100-continue is the only expectation defined, and the only one this server
    ; can meet. Another one used to fall through to ordinary processing, which
    ; served the resource and told the client by omission that its expectation
    ; had been honoured. Recorded here and answered 417 at the static branch;
    ; a PROXY location still forwards it, because there the backend is the one
    ; being asked and it may well be able to meet it (audit-report-33).
    ;
    ; The whole value is compared, so a list -- "100-continue, feature-x" -- is
    ; an unsupported expectation, not a recognised one with something extra:
    ; a value we do not understand in full is one we cannot promise to meet.
    ; h2 and h3 compare the same way, which is what keeps the three agreeing.
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    lea rdx, [hv_100_continue]
    mov ecx, 12
    call linnea_string_iequal
    test eax, eax
    jnz .expect_100_seen
    or qword [rsp + 232], 8    ; an expectation we cannot meet (2 is Upgrade's)
    jmp .header_next
.expect_100_seen:
    ; RFC 9110 10.1.1: a server "MUST NOT send a 100 (Continue) response to an
    ; HTTP/1.0 client", which has no way to understand it -- the interim status
    ; would be read as the final one and the response as garbage. A 1.0 client
    ; sending Expect is already confused; answering it would make things worse.
    test qword [rsp + 136], 8
    jnz .header_next
    or qword [rsp + 232], 4    ; the client is waiting for permission
    jmp .header_next
.ifm_header:
    ; RFC 9110 5.3 once more: If-Match carries an entity-tag LIST, so repeated
    ; lines are the comma-joined value. The Host rule was applied instead --
    ; first occurrence wins -- which is a rule for a field that may not repeat
    ; at all, and it changed the meaning of a legal request: `If-Match: "miss"`
    ; followed by `If-Match: <current>` was 412 where the one-line spelling
    ; passed. Recorded as spans and tried in turn, exactly as Accept-Encoding is
    ; (audit-report-30).
    ; Three spans is far more than any client sends, but a FOURTH must not be
    ; dropped on the floor: discarding a legal list member changes the answer
    ; to a conditional request, and does it silently -- a matching tag on the
    ; fourth line became a 200 where a 304 was due, or a 412 on a request that
    ; had to pass (audit-report-31). What cannot be combined is refused instead,
    ; and refused the same way on all three protocols: none of them can re-walk
    ; a decoded field section, so the policy is set by the one that cannot
    ; rather than split between them.
    mov rcx, [rsp + 312]       ; spans recorded so far
    cmp rcx, 3
    jae .too_many_etags
    shl rcx, 4                 ; -> byte offset of this span in the array
    lea rax, [rsp + 480]
    add rax, rcx
    mov rdx, [rsp + 72]        ; value ptr
    mov [rax], rdx
    mov rdx, [rsp + 80]        ; value len
    mov [rax + 8], rdx
    inc qword [rsp + 312]
    jmp .header_next
.ius_header:
    ; A SECOND occurrence is refused, not resolved. These four each define one
    ; date, validator or range -- not a list -- so two of them are a request
    ; that says two different things, and "first occurrence wins" quietly picked
    ; one. It picked the opposite one from h2 and h3, which kept the last, so
    ; the same request was 200 here and 304 there and swapping the client's two
    ; lines swapped which was which; a doubled Range served byte 0 on HTTP/1 and
    ; byte 10 on the other two (audit-report-32). Refusing is what Host and
    ; Content-Length have always done with a repeat, and for the same reason.
    cmp qword [rsp + 328], 0
    jne .resp_400              ; a second one: the request says two things
    mov rax, [rsp + 72]
    mov [rsp + 328], rax
    mov rax, [rsp + 80]
    mov [rsp + 336], rax
    jmp .header_next
.inm_header:                   ; a list too, and recorded the same way
    mov rcx, [rsp + 176]
    cmp rcx, 3
    jae .too_many_etags
    shl rcx, 4
    lea rax, [rsp + 432]
    add rax, rcx
    mov rdx, [rsp + 72]
    mov [rax], rdx
    mov rdx, [rsp + 80]
    mov [rax + 8], rdx
    inc qword [rsp + 176]
    jmp .header_next
.ims_header:
    cmp qword [rsp + 192], 0
    jne .resp_400              ; a second one: the request says two things
    mov rax, [rsp + 72]
    mov [rsp + 192], rax
    mov rax, [rsp + 80]
    mov [rsp + 200], rax
    jmp .header_next
.ae_header:
    ; RFC 9110 5.3: repeated field lines of a list-based field are equivalent to
    ; the comma-joined value, so a client may split its codings over several
    ; Accept-Encoding lines. Keeping only the first one (h1-14) silently dropped
    ; every coding after it — "Accept-Encoding: identity" then ".. : br" served
    ; the plain file. Record each line as its own (ptr,len) span instead; the
    ; negotiation below tries them all, which is the same answer as joining them
    ; without having to copy the values anywhere. Three spans is far more than a
    ; real client sends, and a FOURTH is refused rather than ignored: a list
    ; member can be a prohibition -- `identity;q=0` says the unencoded form is
    ; unacceptable -- so dropping one can turn a refusal into permission, and
    ; even for ordinary preferences the same legal request served a different
    ; representation depending only on which line carried `br`
    ; (audit-report-35; the reasoning that let it be ignored was mine, in 32).
    mov rcx, [rsp + 208]       ; spans recorded so far
    cmp rcx, 3
    jae .resp_431
    shl rcx, 4                 ; -> byte offset of this span in the array
    lea rax, [rsp + 352]
    add rax, rcx
    mov rdx, [rsp + 72]        ; value ptr
    mov [rax], rdx
    mov rdx, [rsp + 80]        ; value len
    mov [rax + 8], rdx
    inc qword [rsp + 208]
    jmp .header_next
.range_header:
    cmp qword [rsp + 240], 0
    jne .resp_400              ; a second one: the request says two things
    mov rax, [rsp + 72]
    mov [rsp + 240], rax
    mov rax, [rsp + 80]
    mov [rsp + 248], rax
    jmp .header_next
.ifr_header:
    cmp qword [rsp + 256], 0
    jne .resp_400              ; a second one: the request says two things
    mov rax, [rsp + 72]
    mov [rsp + 256], rax
    mov rax, [rsp + 80]
    mov [rsp + 264], rax
    jmp .header_next
.cl_header:
    test qword [rsp + 136], 1
    jnz .resp_400              ; duplicate Content-Length
    or qword [rsp + 136], 1
    ; The guard here is against OVERFLOW, not against size. It used to stop at
    ; 1 << 32, which made 4 GiB a hard ceiling on h1 no matter what max_body
    ; said — a 6 GiB upload was refused instantly with 413 while the same body
    ; went through h2 at full speed, because h2's parser guarded the multiply
    ; instead of capping the value. What may be accepted is max_body's decision
    ; and is made below; all this has to do is not wrap.
    ;
    ; This was one of only two of the five hand-rolled decimal parsers here
    ; that got the bound right, and it is now the shared one they all call
    ; (audit-report-5 Finding 1). h1 keeps its own split of the verdict: "not a
    ; number" is a bad request, "more than 2^64-1" is a body we could never
    ; accept whatever max_body says, which is what 413 means.
    mov rdi, [rsp + 72]        ; value must be all digits
    mov rsi, [rsp + 80]
    call linnea_string_to_u64  ; -> rax = value, edx = 0 ok / 1 syntax / 2 range
    cmp edx, 1
    je .resp_400
    cmp edx, 2
    je .resp_413
    mov [rsp + 128], rax
    jmp .header_next
.te_header:
    ; "chunked" is the one coding we implement (RFC 9112 7.1 makes receiving it
    ; a MUST); anything else still earns a 501. Bit 2 is "a coding we cannot
    ; do", bit 4 is "chunked", bit 32 is "chunked more than once".
    ;
    ; The value is walked as a LIST because that is what it is. Repeated field
    ; lines are one comma-separated list in order (RFC 9110 5.3), so two
    ; "Transfer-Encoding: chunked" lines say "chunked, chunked" -- which RFC
    ; 9112 6.1 forbids, chunked being applicable at most once. Comparing the
    ; whole value against "chunked" made the two spellings of one message
    ; disagree with each other: written on one line it was 501, written on two
    ; it was 200 and the body was decoded and routed (audit-report-28).
    mov r10, [rsp + 72]        ; element cursor
    mov r11, [rsp + 80]        ; bytes left in the list
.te_elem:
    test r11, r11
    jz .header_next
    xor rcx, rcx               ; the element runs to the next comma
.te_scan:
    cmp rcx, r11
    jae .te_elem_end
    cmp byte [r10 + rcx], ','
    je .te_elem_end
    inc rcx
    jmp .te_scan
.te_elem_end:
    push r10                   ; nothing below may touch an rsp-relative local
    push r11                   ; until these are popped
    push rcx
    mov rdi, r10
    mov rsi, rcx
    call linnea_string_trim_ows       ; -> rax = ptr, rdx = length
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [hv_chunked]
    mov ecx, 7
    call linnea_string_iequal
    pop rcx
    pop r11
    pop r10
    test eax, eax
    jz .te_elem_other
    test qword [rsp + 136], 4
    jnz .te_elem_again
    or qword [rsp + 136], 4
    jmp .te_elem_next
.te_elem_again:
    or qword [rsp + 136], 32   ; twice, which is not a coding but a malformed one
    jmp .te_elem_next
.te_elem_other:
    or qword [rsp + 136], 2
.te_elem_next:
    cmp rcx, r11
    jae .header_next           ; that was the last element
    inc rcx                    ; step over the comma
    add r10, rcx
    sub r11, rcx
    jmp .te_elem
.too_many_etags:
    jmp .resp_431              ; more entity-tag lines than can be combined
.header_next:
    add r15, 2                 ; past the CRLF
    jmp .header_loop
.trim_dec:
    dec r10
    jmp .trim

.version_other:
    ; "HTTP/" followed by an unsupported version -> 505, else 400
    mov eax, [r14 + r15]
    cmp eax, 'HTTP'
    jne .resp_400
    cmp byte [r14 + r15 + 4], '/'
    jne .resp_400
    jmp .resp_505

    ; --- serve the file ---------------------------------------------
.parsed:
    ; Host (RFC 9112 3.2): exactly one field line, and a value that could be
    ; an authority. For HTTP/1.1 the header is mandatory — a missing or repeated
    ; one is how a request gets routed one way here and another way at an
    ; intermediary. This runs before the asterisk-form branch below: "OPTIONS *"
    ; carries no authority of its own, so it is exactly the request whose Host an
    ; intermediary would read differently, and the rule is not waived for it.
    ;
    ; HTTP/1.0 predates Host and 9112 3.2 does not require it there, so an absent
    ; one is served by the accepting server's default vhost — the same fallback an
    ; unrecognised name gets. MORE THAN ONE is still 400 whatever the version:
    ; the ambiguity that rule exists to prevent does not depend on the version.
    cmp qword [rsp + 296], 1
    ja .resp_400               ; two or more: ambiguous, always
    je .host_present
    test qword [rsp + 136], 8
    jz .resp_400               ; 1.1 with no Host
    jmp .host_done             ; 1.0 without one: the default vhost serves it
.host_present:
    mov rcx, [rsp + 96]
    test rcx, rcx
    jz .resp_400               ; "Host:" with no authority at all
    ; Validate the authority as a STRUCTURE, not just byte by byte: a reg-name
    ; or a bracketed IPv6 literal, then an optional one-to-five-digit port and
    ; nothing else. "three.test:garbage" and "[::1" are 400 now, exactly as a
    ; control byte in the authority always was.
    mov rdi, [rsp + 88]
    mov rsi, rcx
    call linnea_http_authority_host
    cmp rax, -1
    je .resp_400
.host_done:
    test qword [rsp + 136], 2
    jnz .resp_501                      ; a coding we do not implement
    ; ...and chunked applied more than once is not an unimplemented coding but
    ; an invalid message, so it is a 400 and it is judged after the 501: a list
    ; carrying both an unknown coding and a repeated chunked is still answered
    ; for the coding we cannot do.
    test qword [rsp + 136], 32
    jnz .resp_400
    ; Transfer-Encoding and Content-Length together is the classic smuggling
    ; setup: RFC 9112 6.1 says the message framing is invalid, answer 400 and
    ; close. It used to fall out as a 501 because any TE at all was refused.
    mov rax, [rsp + 136]
    and rax, 5
    cmp rax, 5
    je .resp_400
    ; "OPTIONS *" asks about the server, not about a resource (RFC 9112
    ; 3.2.4): there is no path to route, so answer it here. Any other method
    ; with an asterisk target is nonsense and stays a 400.
    cmp qword [rsp + 304], 0
    je .not_options_star
    cmp qword [rsp + 104], 7           ; the method text sits at in_buf[0)
    jne .resp_400
    lea rax, [rbx + linnea_connection.in_buf]
    cmp dword [rax], 'OPTI'
    jne .resp_400
    cmp dword [rax + 3], 'IONS'
    jne .resp_400
    jmp .resp_options
.not_options_star:
    ; an unknown method is only an error on a static location (405 below);
    ; proxy locations forward whatever the client sent
    ; A body that fits is buffered whole with the head, so both can be
    ; dropped together and keep-alive stays safe. One that does not fit is
    ; only servable by a proxy location, which streams it upstream as it
    ; arrives — the routing below sends anything else to a 413.
    mov qword [rsp + 288], 0   ; streaming the request body?
    mov qword [rbx + linnea_connection.req_body_rem], 0
    test qword [rsp + 136], 4
    jz .not_chunked
    cmp qword [rbx + linnea_connection.capture_done], 0
    jne .chunked_captured
    ; --- chunked: decode it in place, then carry on as any other body -------
    ; Afterwards the buffer holds the body exactly as though the client had
    ; declared a Content-Length, so nothing downstream needs to know this
    ; happened. The decoded form is always shorter than the encoded one, so it
    ; cannot overflow what has already been received.
    lea rdi, [rbx + linnea_connection.in_buf]
    add rdi, [rbx + linnea_connection.head_len]
    mov rsi, [rbx + linnea_connection.in_len]
    sub rsi, [rbx + linnea_connection.head_len]
    call chunked_decode              ; rax = decoded, rdx = encoded
    cmp rax, -2
    je .resp_400                     ; malformed framing
    cmp rax, -1
    jne .chunked_done
    ; not all here yet. If the buffer is already full it never will be: this
    ; body is larger than we buffer, and only a proxy could have streamed it —
    ; which the chunked path does not do yet.
    mov rcx, [rbx + linnea_connection.in_len]
    cmp rcx, LINNEA_CONN_IN_BUF
    jae .chunked_capture
    test qword [rsp + 232], 4        ; waiting on our permission to send it?
    jz .chunked_wait
    mov rdi, rbx
    call http_send_continue
.chunked_wait:
    mov eax, LINNEA_HTTP_NEED_MORE
    jmp .ret
.chunked_done:
    ; slide anything pipelined behind it down over the framing we removed
    push rax
    push rdx
    mov rcx, [rbx + linnea_connection.in_len]
    sub rcx, [rbx + linnea_connection.head_len]
    sub rcx, rdx                     ; bytes sitting after the encoded body
    jz .chunked_compacted
    lea rdi, [rbx + linnea_connection.in_buf]
    add rdi, [rbx + linnea_connection.head_len]
    add rdi, rax                     ; just past the decoded body
    lea rsi, [rbx + linnea_connection.in_buf]
    add rsi, [rbx + linnea_connection.head_len]
    add rsi, rdx                     ; just past the encoded body
    rep movsb
.chunked_compacted:
    pop rdx
    pop rax
    mov rcx, rdx
    sub rcx, rax                     ; framing bytes that have gone
    sub [rbx + linnea_connection.in_len], rcx
    mov [rsp + 128], rax             ; the decoded length IS the Content-Length
    and qword [rsp + 136], ~4        ; and it is an ordinary body from here on
    or qword [rsp + 136], 8          ; ...but the proxy still owes it a length
    jmp .not_chunked                 ; the two capture arms below are not ours
.chunked_capture:
    ; The buffer is full and the body is not finished, so it never will fit:
    ; it is captured — and decoded — as it arrives instead. Whether that is
    ; allowed is routing's call, exactly as for a counted body: [rsp+288]
    ; sends every location that cannot consume a body this large to a 413.
    ; Nothing is queued behind the head; the whole body goes to the capture.
    mov qword [rsp + 288], 2
    mov qword [rsp + 128], 0
    mov rax, [rbx + linnea_connection.head_len]
    jmp .body_ready
.chunked_captured:
    ; The second pass over the same head, once the capture is complete. The
    ; body is decoded and mapped rather than sitting in in_buf, so nothing is
    ; queued behind the head and the length the backend is told comes from
    ; spill_len (below). It is an ordinary counted request from here on — the
    ; same shape a chunked body small enough to buffer has always been given.
    mov qword [rsp + 128], 0
    and qword [rsp + 136], ~4
    or qword [rsp + 136], 8          ; and the proxy owes it a length
    mov rax, [rbx + linnea_connection.in_len]
    jmp .body_ready
.not_chunked:
    ; max_body applies to EVERY counted body, not only one too large to buffer
    ; (Finding 3). The cap check used to live in .body_stream alone, which is
    ; reached only when head+body overflows in_buf; a body that FIT in in_buf
    ; slipped past a max_body set below the buffer size, so the documented limit
    ; behaved differently for small and large bodies and a proxy forwarded a
    ; body the config said it would refuse. Checked here on the declared (or, for
    ; a chunked body decoded in place, the decoded) length, before the
    ; buffered/streamed split, so both paths honour it. [rsp+128] is the body
    ; length; 0 (no body) never exceeds a nonzero max_body.
    lea rax, [linnea_config_instance]
    mov rax, [rax + linnea_config.max_body]
    cmp [rsp + 128], rax
    ja .body_toolarge
    mov rax, [rbx + linnea_connection.head_len]
    add rax, [rsp + 128]
    cmp rax, LINNEA_CONN_IN_BUF
    ja .body_stream
    cmp rax, [rbx + linnea_connection.in_len]
    jbe .body_ready
    test qword [rsp + 232], 4        ; waiting on our permission to send it?
    jz .body_wait
    mov rdi, rbx
    call http_send_continue
.body_wait:
    mov eax, LINNEA_HTTP_NEED_MORE
    jmp .ret
.body_toolarge:
    ; the client has not been told to hold back (no 100-continue was answered),
    ; so it is about to send a body nobody will read: linger over the refusal
    mov qword [rbx + linnea_connection.answer_linger], 1
    jmp .resp_413
.body_stream:
    ; Too large to hold with the head, so it will be captured on disk. max_body
    ; was already applied above on the declared length, so the bytes never land.
.body_capture_ok:
    ; keep the head consumed and hand the routing whatever body bytes have
    ; already arrived; the rest is captured as it comes
    mov qword [rsp + 288], 1
    mov rcx, [rbx + linnea_connection.in_len]
    sub rcx, [rbx + linnea_connection.head_len]      ; body bytes in hand
    mov rax, [rsp + 128]
    sub rax, rcx                                     ; still to come
    mov [rbx + linnea_connection.req_body_rem], rax
    mov [rsp + 128], rcx       ; what .proxy_start queues behind the head
    mov rax, [rbx + linnea_connection.in_len]
.body_ready:
    ; the body is in hand, so this request wants no further permission. Cleared
    ; here rather than per handler call: the head is re-parsed on every recv
    ; while a body is still arriving, and clearing there would send a fresh 100
    ; on each one. Cleared at all, rather than never, so the SECOND request on a
    ; keep-alive connection still gets its own.
    mov qword [rbx + linnea_connection.continue_sent], 0
    mov [rbx + linnea_connection.head_len], rax
    ; strip the query string for routing; [rsp+144] keeps the raw length
    ; for proxying and the access log
    mov rsi, [rsp + 8]
    mov rcx, [rsp + 16]
    xor edx, edx
.query_scan:
    cmp rdx, rcx
    jae .query_done
    cmp byte [rsi + rdx], '?'
    je .query_found
    inc rdx
    jmp .query_scan
.query_found:
    mov rcx, rdx
.query_done:
    mov [rsp + 16], rcx
    test rcx, rcx
    jz .resp_400
    ; absolute-path and ".." checks run on the decoded target below
    ; default server = the one whose listener accepted the connection
    mov ecx, [rbx + linnea_connection.server]
    imul rcx, rcx, linnea_config_server_size
    lea rax, [linnea_config_instance]
    lea r12, [rax + rcx + linnea_config.servers]   ; server*
    ; vhost selection: match the Host header (port stripped) against the
    ; hostnames of all servers sharing this listener; no match = default
    mov rcx, [rsp + 96]
    test rcx, rcx
    jz .server_chosen
    ; the host to match is the parser's host slice -- past a leading '[' and
    ; short of the ']' or ':port' -- not "everything before the first colon",
    ; which for "[::1]:443" was just "[". A malformed authority was already
    ; rejected with 400 above, so -1 here only means "use the default".
    mov rdi, [rsp + 88]
    mov rsi, rcx
    call linnea_http_authority_host        ; rax = host len, rdx = host offset
    cmp rax, -1
    je .server_chosen
    add rdx, [rsp + 88]
    mov [rsp + 88], rdx                     ; host ptr, past any '['
    mov [rsp + 96], rax                     ; host len, port and brackets removed
    test rax, rax
    jz .server_chosen
    lea rax, [linnea_config_instance]
    mov r13, [rax + linnea_config.server_count]
    xor r15d, r15d             ; candidate index
.vhost_loop:
    cmp r15, r13
    jae .server_chosen
    imul rdx, r15, linnea_config_server_size
    lea rax, [linnea_config_instance]
    lea rdx, [rax + rdx + linnea_config.servers]
    mov eax, [rdx + linnea_config_server.listen_fd]
    cmp eax, [r12 + linnea_config_server.listen_fd]
    jne .vhost_next
    mov [rsp + 56], rdx        ; candidate server*
    mov rcx, [rdx + linnea_config_server.hostname_len]
    lea rdx, [rdx + linnea_config_server.hostname]
    mov rdi, [rsp + 88]
    mov rsi, [rsp + 96]
    call linnea_string_iequal
    test eax, eax
    jz .vhost_next
    mov r12, [rsp + 56]        ; matched vhost
    jmp .server_chosen
.vhost_next:
    inc r15
    jmp .vhost_loop
.server_chosen:
    mov [rsp + 120], r12       ; the server that will handle the request
    ; decode the target into path_buf, leaving room ahead of it for a
    ; matched location's root to be prepended in place
    lea rdi, [path_buf + LINNEA_HTTP_PATH_ROOT]
    mov rsi, [rsp + 8]         ; raw target
    mov rcx, [rsp + 16]
    mov r13, rdi               ; start of the decoded target
    xor edx, edx
.decode_loop:
    cmp rdx, rcx
    jae .decode_done
    movzx eax, byte [rsi + rdx]
    cmp al, '%'
    je .decode_pct
    mov [rdi], al
    inc rdi
    inc rdx
    jmp .decode_loop
.decode_pct:
    lea rax, [rdx + 3]
    cmp rax, rcx
    ja .resp_400
    movzx eax, byte [rsi + rdx + 1]
    call .hex_nibble
    test eax, eax
    js .resp_400
    mov r9d, eax
    movzx eax, byte [rsi + rdx + 2]
    call .hex_nibble
    test eax, eax
    js .resp_400
    shl r9d, 4
    or eax, r9d
    jz .resp_400               ; %00 would truncate the path
    mov [rdi], al
    inc rdi
    add rdx, 3
    jmp .decode_loop
.decode_done:
    ; normalize the decoded path in place, segment by segment:
    ; "" and "." drop, ".." pops (above the root: 400); r9 tracks whether
    ; the path names a directory (trailing "/", "/." or "/..")
    cmp byte [r13], '/'
    jne .resp_400
    mov rsi, r13               ; read cursor, at a '/'
    mov rcx, rdi               ; end of the decoded input
    mov rdi, r13               ; write cursor
    xor r9d, r9d               ; directory flag
.norm_loop:
    cmp rsi, rcx
    jae .norm_done
    inc rsi                    ; past the '/'; segment = [rsi, rdx)
    mov rdx, rsi
.norm_seg_end:
    cmp rdx, rcx
    jae .norm_have_seg
    cmp byte [rdx], '/'
    je .norm_have_seg
    inc rdx
    jmp .norm_seg_end
.norm_have_seg:
    mov rax, rdx
    sub rax, rsi               ; segment length
    test rax, rax
    jz .norm_skip
    cmp rax, 1
    jne .norm_not_dot
    cmp byte [rsi], '.'
    je .norm_skip
    jmp .norm_copy
.norm_not_dot:
    cmp rax, 2
    jne .norm_copy
    cmp word [rsi], '..'
    jne .norm_copy
    cmp rdi, r13               ; pop the previous segment
    jbe .resp_400              ; ".." above the root
    dec rdi
.norm_pop:
    cmp rdi, r13
    jbe .norm_skip
    cmp byte [rdi], '/'
    je .norm_skip
    dec rdi
    jmp .norm_pop
.norm_skip:                    ; "", "." and ".." leave a directory if final
    cmp rdx, rcx
    jb .norm_next
    mov r9d, 1
    jmp .norm_next
.norm_copy:
    mov byte [rdi], '/'
    inc rdi
.norm_copy_loop:
    cmp rsi, rdx
    jae .norm_copied
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    jmp .norm_copy_loop
.norm_copied:
    xor r9d, r9d
.norm_next:
    mov rsi, rdx               ; at the next '/' or the end
    jmp .norm_loop
.norm_done:
    cmp rdi, r13               ; everything normalized away = the root
    jne .norm_matched
    mov byte [rdi], '/'        ; materialize "/" so a "/" prefix matches
    inc rdi
    mov r9d, 1
.norm_matched:
    ; --- location match: longest prefix wins ------------------------
    ; path = [r13, rdi); prefixes are matched byte for byte and are not
    ; stripped — the whole path is appended to the root / sent upstream
    mov r15, rdi               ; path end
    mov r8, rdi
    sub r8, r13                ; path len
    mov [rsp + 168], r9        ; the matcher clobbers r9
    mov rdi, r12               ; server*
    mov rsi, r13               ; path
    mov rdx, r8                ; path length
    call linnea_config_match_location
    mov [rsp + 152], rax       ; five places downstream re-read the match here
    test rax, rax
    jz .resp_404               ; no location claims this path
    ; TRACE reflects the request it received back to whoever sent it. At an
    ; origin that is a curiosity; through a PROXY it hands the caller whatever
    ; the request carried by the time it arrived -- its own credentials among
    ; it, and any header an intermediary added. A static location has always
    ; answered it 405 as a method it does not serve; a proxy location forwarded
    ; it to a backend that might implement it. Refused here instead, before the
    ; kinds diverge, so the answer no longer depends on which location matched.
    ; It also settles Max-Forwards for TRACE: there is no hop to count to.
    mov rdi, r14               ; the method text sits at in_buf[0)
    mov rsi, [rsp + 104]
    lea rdx, [method_trace]
    mov ecx, 5
    call linnea_string_equal   ; case-sensitive: a method is (RFC 9110 9.1)
    test eax, eax
    jnz .resp_405
    mov rax, [rsp + 152]       ; linnea_string_equal took rax
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    je .proxy_max_forwards
    ; Past the proxy branch every answer is ours to make -- a file, a redirect,
    ; an error -- so an expectation we cannot meet is refused rather than
    ; ignored: serving the resource would tell the client by omission that it
    ; had been honoured. A PROXY location has already branched away above and
    ; forwards it, because there the backend is the one being asked
    ; (audit-report-33).
    test qword [rsp + 232], 8
    jnz .resp_417
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    je .redirect_check

    ; --- static location ---------------------------------------------
    cmp qword [rsp + 288], 0
    jne .resp_413              ; only a proxy streams a body this large
    cmp qword [rsp], -2
    je .resp_501               ; a method we do not recognise at all (15.6.2)
    cmp qword [rsp], -1
    je .resp_405               ; a method we know, but files are GET/HEAD only
    ; A static location serves a file: it has no use for request content, and
    ; content on GET or HEAD has no defined semantics anyway (RFC 9110 9.3.1).
    ; Serving the file regardless means silently discarding bytes the client
    ; announced -- the request-smuggling shape 9.3.1 names. h1 already refused
    ; the half of this it happened to notice: a body too big to sit in in_buf
    ; streams, and .resp_413 four lines up turns that into a refusal. A body
    ; that FIT was ignored and the file served, so the same request was refused
    ; or served depending on how it compared with a buffer size nobody
    ; configured -- the shape Finding 3 had on max_body. [rsp+128] is the body
    ; length (declared, or decoded for a chunked one), so both are refused now.
    cmp qword [rsp + 128], 0
    jne .resp_400
    mov rdi, r15               ; path end, from the match above
    mov r9, [rsp + 168]        ; directory flag
    test r9d, r9d
    jz .path_ready
    cmp byte [rdi - 1], '/'    ; a directory maps to its index.html
    je .append_index
    mov byte [rdi], '/'
    inc rdi
.append_index:
    lea rsi, [index_html]
    mov ecx, index_html_len
    rep movsb
.path_ready:
    mov byte [rdi], 0
    mov r15, rdi               ; path end, for the extension scan
    ; prepend the location root, ending where the decoded path starts
    mov rax, [rsp + 152]
    mov rcx, [rax + linnea_config_location.root_len]
    lea r13, [path_buf + LINNEA_HTTP_PATH_ROOT]
    sub r13, rcx               ; start of the joined path
    mov rdi, r13
    lea rsi, [rax + linnea_config_location.root]
    rep movsb
    ; A pre-compressed file sitting beside this one is the whole opt-in:
    ; if the client takes the encoding and the variant is there, serve it.
    ; br goes first — it compresses better than gzip. The suffix is written
    ; at r15, so the name before it stays intact for the MIME lookup.
    cmp qword [rsp + 208], 0
    je .open_plain             ; no Accept-Encoding: nothing to negotiate
    ; Each Accept-Encoding line is its own span (h1-14) and the whole rule --
    ; the named entry, then the wildcard, then the default -- lives in
    ; linnea_http_coding_ok, which h2 and h3 reach through
    ; linnea_static_open_enc. This used to walk the spans here with its own
    ; loop, which is how h1 came to answer the wildcard differently from
    ; nothing at all (audit-report-36).
    ; the source's mtime, once, for the staleness test each variant faces
    mov byte [r15], 0
    mov rdi, r13
    call linnea_static_mtime_of
    mov [rsp + 400], rax
    lea rdi, [rsp + 352]
    mov rsi, [rsp + 208]
    lea rdx, [enc_br]
    mov ecx, enc_br_len
    call linnea_http_coding_ok
    test eax, eax
    jz .try_gzip
    mov dword [r15], '.br'     ; three bytes and the NUL
    ; A variant older than its source is stale, and serving it hands this
    ; client a different body from the one an identity client gets -- each with
    ; its own self-consistent ETag, so nothing ever revalidates into agreement.
    mov rdi, r13
    mov rsi, [rsp + 400]
    call linnea_static_variant_fresh
    test eax, eax
    jz .try_gzip
    mov rdi, r13
    call .open_regular
    test eax, eax
    js .try_gzip
    mov qword [rsp + 224], 2
    jmp .have_file
.try_gzip:
    lea rdi, [rsp + 352]
    mov rsi, [rsp + 208]
    lea rdx, [enc_gzip]
    mov ecx, enc_gzip_len
    call linnea_http_coding_ok
    test eax, eax
    jz .open_plain
    mov dword [r15], '.gz'
    mov rdi, r13
    mov rsi, [rsp + 400]
    call linnea_static_variant_fresh
    test eax, eax
    jz .open_plain
    mov rdi, r13
    call .open_regular
    test eax, eax
    js .open_plain
    mov qword [rsp + 224], 1
    jmp .have_file
.open_plain:
    ; The fallback is the unencoded form. identity;q=0 forbids it (RFC 9110
    ; 12.5.3), and nothing coded was acceptable or it would have been served
    ; above -- so there is no representation left that this client will take
    ; (audit-report-35). Only asked when an Accept-Encoding was actually sent:
    ; absent, every coding including identity is acceptable.
    cmp qword [rsp + 208], 0
    je .open_plain_go
    lea rdi, [rsp + 352]
    mov rsi, [rsp + 208]
    call linnea_http_identity_refused
    test eax, eax
    jnz .resp_406
.open_plain_go:
    mov byte [r15], 0          ; drop whichever suffix was tried
    mov qword [rsp + 224], 0
    mov rdi, r13
    call .open_regular
    test eax, eax
    js .resp_404_vary          ; a negotiated miss: the 404 carries Vary (h1-15)
.have_file:
    mov [rsp + 56], rax        ; fd; statbuf describes the file we opened
    mov rax, [statbuf + LINNEA_STAT_ST_SIZE]
    mov [rsp + 32], rax        ; file size
    ; --- validators: ETag "<hex mtime>-<hex size>" and Last-Modified ---
    ; the number formatters clobber rdi/rsi/rcx, so the write cursor waits
    ; on the stack across each call
    lea rax, [etag_buf]
    mov byte [rax], '"'
    mov rdi, [statbuf + LINNEA_STAT_ST_MTIME]
    lea rsi, [etag_buf + 1]
    call linnea_string_from_hex_u64
    lea rcx, [etag_buf + 1]
    add rcx, rax
    mov byte [rcx], '-'
    inc rcx
    mov [rsp + 64], rcx
    mov rdi, [rsp + 32]        ; file size
    mov rsi, rcx
    call linnea_string_from_hex_u64
    mov rcx, [rsp + 64]
    add rcx, rax
    mov byte [rcx], '"'
    inc rcx
    lea rax, [etag_buf]
    sub rcx, rax
    mov [etag_len], rcx
    mov rdi, [statbuf + LINNEA_STAT_ST_MTIME]
    lea rsi, [date_buf]
    call linnea_time_http_date
    ; --- conditional request: If-None-Match wins over If-Modified-Since -
    ; RFC 9110 13.2.2 evaluates the preconditions in order, and If-Match comes
    ; first: it asks "only if the representation is still the one I hold", so a
    ; mismatch is 412 and nothing further is considered. If-Unmodified-Since is
    ; the same question asked with a date, and is consulted only when If-Match
    ; is absent. Neither was read at all — a conditional PUT-style request was
    ; answered as though it carried no condition, which is exactly the lost
    ; update the fields exist to prevent.
    cmp qword [rsp + 312], 0
    je .check_ius
    ; any line may carry the matching tag, which is what joining them would say
    mov qword [rsp + 408], 0
.ifm_span:
    mov rcx, [rsp + 408]
    cmp rcx, [rsp + 312]
    jae .resp_412              ; no line matched
    shl rcx, 4
    lea rax, [rsp + 480]
    add rax, rcx
    mov rdi, [rax]
    mov rsi, [rax + 8]
    lea rdx, [etag_buf]
    mov rcx, [etag_len]
    mov r8d, 1                 ; If-Match compares strongly (13.1.1)
    call linnea_http_etag_match
    inc qword [rsp + 408]
    test eax, eax
    jz .ifm_span
    jmp .check_inm             ; If-Match present: If-Unmodified-Since is skipped
.check_ius:
    cmp qword [rsp + 328], 0
    je .check_inm
    mov rdi, [rsp + 328]
    mov rsi, [rsp + 336]
    call linnea_time_parse_http_date
    cmp rax, -1
    je .check_inm              ; unparseable: ignored, as for the other dates
    cmp [statbuf + LINNEA_STAT_ST_MTIME], rax
    ja .resp_412               ; modified since: the client's assumption is stale
.check_inm:
    cmp qword [rsp + 176], 0
    je .check_ims
    mov qword [rsp + 408], 0
.inm_span:
    mov rcx, [rsp + 408]
    cmp rcx, [rsp + 176]
    jae .send_full             ; no line matched, and that overrides If-Modified-Since
    shl rcx, 4
    lea rax, [rsp + 432]
    add rax, rcx
    mov rdi, [rax]
    mov rsi, [rax + 8]
    lea rdx, [etag_buf]
    mov rcx, [etag_len]
    call linnea_http_inm_match
    inc qword [rsp + 408]
    test eax, eax
    jz .inm_span
    jmp .resp_304
.check_ims:
    cmp qword [rsp + 192], 0
    je .send_full
    mov rdi, [rsp + 192]
    mov rsi, [rsp + 200]
    call linnea_time_parse_http_date
    cmp rax, -1
    je .send_full              ; unparseable: the RFC says ignore it
    cmp [statbuf + LINNEA_STAT_ST_MTIME], rax
    jbe .resp_304              ; not modified since the client's copy
.send_full:
    ; --- Range: a single bytes=... range, applied to GETs only --------
    ; Ignoring the header (a full 200) is always safe, so anything not
    ; understood — another unit, several ranges, bad syntax — serves the
    ; whole file; only a syntactically valid but unsatisfiable range
    ; earns a 416. Evaluated after the conditionals, as RFC 9110 orders.
    mov qword [rsp + 112], 200
    mov qword [rsp + 272], 0   ; body offset
    mov rax, [rsp + 32]
    mov [rsp + 280], rax       ; body length: the whole file until a
    cmp qword [rsp], 0         ; range narrows it
    jne .range_done            ; Range is defined for GET alone
    cmp qword [rsp + 240], 0
    je .range_done
    ; If-Range: the range only applies if the representation is the one
    ; the client already holds — a STRONG validator match (RFC 9110
    ; 13.1.5), else the whole file, since patching a stale copy with
    ; fresh bytes would corrupt it
    cmp qword [rsp + 256], 0
    je .range_eval
    mov rdi, [rsp + 256]
    mov rsi, [rsp + 264]
    lea rdx, [etag_buf]
    mov rcx, [etag_len]
    mov r8, [statbuf + LINNEA_STAT_ST_MTIME]
    call linnea_http_ifrange_match
    test eax, eax
    jz .range_done
.range_eval:
    mov rdi, [rsp + 240]
    mov rsi, [rsp + 248]
    mov rdx, [rsp + 32]
    call linnea_http_range_parse
    cmp rax, -1
    je .range_done
    cmp rax, -2
    je .resp_416
    mov [rsp + 272], rax
    mov [rsp + 280], rdx
    mov qword [rsp + 112], 206
.range_done:
    ; GET with content: map the file and queue it behind the headers
    cmp qword [rsp], 0
    jne .no_map                ; HEAD: headers only
    mov rax, [rsp + 32]        ; file size
    test rax, rax
    jz .no_map                 ; empty file
    mov rsi, rax
    xor edi, edi
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8, [rsp + 56]
    xor r9d, r9d
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .close_404
    mov [rbx + linnea_connection.file_base], rax
    mov rcx, [rsp + 32]        ; munmap needs the whole mapping
    mov [rbx + linnea_connection.file_size], rcx
    add rax, [rsp + 272]       ; the requested slice, or the whole file
    mov [rbx + linnea_connection.file_ptr], rax
    mov rcx, [rsp + 280]
    mov [rbx + linnea_connection.file_rem], rcx
.no_map:
    mov rdi, [rsp + 56]
    mov eax, LINNEA_SYS_CLOSE
    syscall                    ; the mapping outlives the fd

    ; MIME type from the extension (joined path start .. r15)
    mov rdx, r13
    mov rcx, r15               ; scan backwards for '.' before any '/'
.ext_scan:
    cmp rcx, rdx
    jbe .ext_none
    movzx eax, byte [rcx - 1]
    cmp al, '.'
    je .ext_found
    cmp al, '/'
    je .ext_none
    dec rcx
    jmp .ext_scan
.ext_found:
    mov [rsp + 72], rcx        ; ext ptr
    mov rax, r15
    sub rax, rcx
    mov [rsp + 80], rax        ; ext len
    lea r12, [mime_table]
.mime_loop:
    mov rdx, [r12]
    test rdx, rdx
    jz .ext_none
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    mov rcx, [r12 + 8]
    call linnea_string_iequal
    test eax, eax
    jnz .mime_found
    add r12, 32
    jmp .mime_loop
.mime_found:
    mov rax, [r12 + 16]
    mov [rsp + 40], rax
    mov rax, [r12 + 24]
    mov [rsp + 48], rax
    jmp .build_headers
.ext_none:
    lea rax, [mime_default]
    mov [rsp + 40], rax
    mov qword [rsp + 48], mime_default_len

    ; --- 200/206 response headers -------------------------------------
.build_headers:
    mov rax, [rsp + 24]
    mov [rbx + linnea_connection.keep_alive], rax
    lea r15, [rbx + linnea_connection.out_buf]
    cmp qword [rsp + 112], 206
    je .status_partial
    lea rdi, [status_200]
    mov esi, status_200_len
    jmp .status_emit
.status_partial:
    lea rdi, [status_206]
    mov esi, status_206_len
.status_emit:
    call .append
    mov rdi, [rsp + 40]
    mov rsi, [rsp + 48]
    call .append
    lea rdi, [hdr_length]
    mov esi, hdr_length_len
    call .append
    mov rdi, [rsp + 280]       ; the range's length, or the whole file's
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
    cmp qword [rsp + 112], 206
    jne .no_content_range
    ; Content-Range: bytes first-last/size
    lea rdi, [hdr_content_range]
    mov esi, hdr_content_range_len
    call .append
    mov rdi, [rsp + 272]
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
    lea rdi, [log_dash]
    mov esi, 1
    call .append
    mov rdi, [rsp + 272]
    add rdi, [rsp + 280]
    dec rdi                    ; last = first + length - 1
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
    lea rdi, [slash_ch]
    mov esi, 1
    call .append
    mov rdi, [rsp + 32]
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
.no_content_range:
    cmp qword [rsp + 224], 0
    je .no_enc_hdr
    lea rdi, [hdr_content_enc]
    mov esi, hdr_content_enc_len
    call .append
    cmp qword [rsp + 224], 2
    je .enc_is_br
    lea rdi, [enc_gzip]
    mov esi, enc_gzip_len
    jmp .enc_emit
.enc_is_br:
    lea rdi, [enc_br]
    mov esi, enc_br_len
.enc_emit:
    call .append
.no_enc_hdr:
    lea rdi, [hdr_vary]
    mov esi, hdr_vary_len
    call .append
    lea rdi, [hdr_accept_ranges]
    mov esi, hdr_accept_ranges_len
    call .append
    call .append_validators
    mov rdi, [rsp + 120]       ; the serving vhost
    call .append_server_date
    mov rdi, [rsp + 152]       ; the matched location's Cache-Control, if set
    call .append_cache_control
    ; Alt-Svc, when a QUIC listener is up: tells the client it can reach this
    ; origin over HTTP/3 next time.
    cmp qword [linnea_h3_altsvc_len], 0
    je .no_altsvc
    mov eax, [rbx + linnea_connection.server]
    cmp byte [linnea_h3_advert + rax], 0
    je .no_altsvc                 ; this origin has no h3 vhost: nothing to advertise
    lea rdi, [hdr_altsvc]
    mov esi, hdr_altsvc_len
    call .append
    lea rdi, [linnea_h3_altsvc]
    mov rsi, [linnea_h3_altsvc_len]
    call .append
.no_altsvc:
    cmp qword [rsp + 24], 0
    je .conn_close_hdr
    lea rdi, [hdr_keepalive]
    mov esi, hdr_keepalive_len
    jmp .conn_hdr
.conn_close_hdr:
    lea rdi, [hdr_close]
    mov esi, hdr_close_len
.conn_hdr:
    call .append
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov rax, [rsp + 280]       ; the log's byte count: what the body holds
    mov [rsp + 32], rax
    jmp .log_request

.redirect_check:
    cmp qword [rsp + 288], 0
    jne .resp_413              ; a redirect cannot consume the body either
    jmp .redirect_start

; --- redirect location: 301, Location = target + the raw request -------
; The original percent-encoded target (query included) is appended to the
; configured URL verbatim: the redirect points at the same resource on
; the other origin, encoding untouched.
.redirect_start:
    mov rax, [rsp + 152]       ; the matched location
    ; the head is assembled unchecked into out_buf, so bound it first: a
    ; target near in_buf's size plus a long redirect URL can exceed it
    mov rcx, [rax + linnea_config_location.redirect_len]
    add rcx, [rsp + 144]       ; raw target length
    add rcx, status_301_len + hdr_301_tail_len + hdr_server_len + hdr_date_len + LINNEA_HTTP_DATE_LEN
    add rcx, hdr_hsts_len + LINNEA_MAX_ROOT + hdr_nosniff_len
    cmp rcx, LINNEA_CONN_OUT_BUF
    ja .resp_414
    lea r15, [rbx + linnea_connection.out_buf]
    lea rdi, [status_301]
    mov esi, status_301_len
    call .append
    mov rax, [rsp + 152]
    lea rdi, [rax + linnea_config_location.redirect]
    mov rsi, [rax + linnea_config_location.redirect_len]
    call .append
    mov rdi, [rsp + 8]         ; the raw request target, query included
    mov rsi, [rsp + 144]
    call .append
    mov rdi, [rsp + 120]       ; the serving vhost
    call .append_server_date
    lea rdi, [hdr_301_tail]
    mov esi, hdr_301_tail_len
    call .append
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rbx + linnea_connection.keep_alive], 0
    mov qword [rbx + linnea_connection.file_rem], 0
    mov qword [rsp + 112], 301
    mov qword [rsp + 32], 0    ; no body
    jmp .log_request

; --- 304: the validators, no body, and the connection stays up ---------
.resp_304:
    mov rdi, [rsp + 56]        ; the file is not going to be read
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov rax, [rsp + 24]
    mov [rbx + linnea_connection.keep_alive], rax
    mov qword [rbx + linnea_connection.file_rem], 0
    lea r15, [rbx + linnea_connection.out_buf]
    lea rdi, [status_304]
    mov esi, status_304_len
    call .append
    lea rdi, [hdr_vary]        ; a 304 must carry the Vary of its 200; the
    mov esi, hdr_vary_len      ; encoding itself is metadata it should not
    call .append               ; restate
    call .append_validators
    mov rdi, [rsp + 120]       ; the serving vhost
    call .append_server_date
    mov rdi, [rsp + 152]       ; the matched location's Cache-Control, if set
    call .append_cache_control
    cmp qword [rsp + 24], 0
    je .conn_close_304
    lea rdi, [hdr_keepalive]
    mov esi, hdr_keepalive_len
    jmp .conn_hdr_304
.conn_close_304:
    lea rdi, [hdr_close]
    mov esi, hdr_close_len
.conn_hdr_304:
    call .append
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rsp + 112], 304
    mov qword [rsp + 32], 0    ; a 304 carries no body
    jmp .log_request

; --- 412: a precondition the client set was not met --------------------
; Modelled on the 304 above: the file is closed unread, the connection is
; kept, and no body is sent. RFC 9110 15.5.13 wants the validators too — a
; client that guessed wrong should be able to see what the current
; representation actually is without a second round trip.
.resp_412:
    mov rdi, [rsp + 56]        ; the file is not going to be read
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov rax, [rsp + 24]
    mov [rbx + linnea_connection.keep_alive], rax
    mov qword [rbx + linnea_connection.file_rem], 0
    lea r15, [rbx + linnea_connection.out_buf]
    lea rdi, [status_412]
    mov esi, status_412_len
    call .append
    call .append_validators
    mov rdi, [rsp + 120]       ; the serving vhost
    call .append_server_date
    cmp qword [rsp + 24], 0
    je .conn_close_412
    lea rdi, [hdr_keepalive]
    mov esi, hdr_keepalive_len
    jmp .conn_hdr_412
.conn_close_412:
    lea rdi, [hdr_close]
    mov esi, hdr_close_len
.conn_hdr_412:
    call .append
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rsp + 112], 412
    mov qword [rsp + 32], 0    ; no body
    jmp .log_request

; --- 416: the range misses the file entirely ---------------------------
; Built dynamically because it must name the actual length ("Content-
; Range: bytes */N") so the client can retry sensibly — and, like the
; 304, so it can preserve keep-alive.
.resp_416:
    mov rdi, [rsp + 56]        ; the file is not going to be read
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov rax, [rsp + 24]
    mov [rbx + linnea_connection.keep_alive], rax
    mov qword [rbx + linnea_connection.file_rem], 0
    lea r15, [rbx + linnea_connection.out_buf]
    lea rdi, [status_416]      ; ends with "Content-Range: bytes */"
    mov esi, status_416_len
    call .append
    mov rdi, [rsp + 32]
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
    lea rdi, [hdr_length]
    mov esi, hdr_length_len
    call .append
    lea rdi, [zero_ch]
    mov esi, 1
    call .append
    mov rdi, [rsp + 120]       ; the serving vhost
    call .append_server_date
    cmp qword [rsp + 24], 0
    je .conn_close_416
    lea rdi, [hdr_keepalive]
    mov esi, hdr_keepalive_len
    jmp .conn_hdr_416
.conn_close_416:
    lea rdi, [hdr_close]
    mov esi, hdr_close_len
.conn_hdr_416:
    call .append
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rsp + 112], 416
    mov qword [rsp + 32], 0    ; no body
    jmp .log_request

; --- proxy location: rewrite the request and open the upstream socket ---
; The event loop takes it from here (connect, send, read the head back).
.proxy_max_forwards:
    ; RFC 9110 7.6.2: an OPTIONS carrying Max-Forwards: 0 has reached its final
    ; recipient -- us -- and MUST NOT be forwarded. Above zero it goes on with a
    ; value one lower, which the rewriter emits. Only OPTIONS reaches this with
    ; the field meaning anything: TRACE is already refused above, and 7.6.2
    ; leaves every other method free to ignore it.
    test qword [rsp + 136], 64
    jz .proxy_start            ; no Max-Forwards: nothing to count
    mov rdi, r14
    mov rsi, [rsp + 104]
    lea rdx, [method_options]
    mov ecx, 7
    call linnea_string_equal
    mov r11d, eax              ; .proxy_build takes the matched LOCATION from
    mov rax, [rsp + 152]       ; rax, and the compare above returned into it
    test r11d, r11d
    jz .proxy_start            ; not OPTIONS: the field is not ours to act on
    cmp qword [rsp + 528], 0
    je .resp_options           ; zero hops left: we are the final recipient
.proxy_start:
    ; A chunked body still arriving: capture it before anything is built or
    ; connected. The head cannot be rewritten yet — its Content-Length is the
    ; decoded length, which is not known until the last chunk — so the caller
    ; captures and then calls us again over the same head.
    cmp qword [rsp + 288], 2
    jne .proxy_build
    ; The vhost has to be recorded even though the head is not built yet: a
    ; capture that fails is answered with a canned response, and both that
    ; response's security headers and its log line are the vhost's. A pool slot
    ; carries the last connection's vhost otherwise, which is a stale pointer.
    mov rcx, [rsp + 120]
    mov [rbx + linnea_connection.vhost], rcx
    mov [rbx + linnea_connection.location], rax
    mov eax, LINNEA_HTTP_CAPTURE
    jmp .ret
.proxy_build:
    mov [rbx + linnea_connection.location], rax
    ; The client head is rewritten into up_buf. up_buf is smaller than in_buf
    ; and .append is an unchecked rep movsb, so this one bound guards the whole
    ; rewrite: a head that fits in_buf but not up_buf would otherwise overrun
    ; the slot into the next connection. head_len here spans the buffered body
    ; too (set at .body_ready), so subtract it — the pure head is what gets
    ; copied, exactly as the copy loop computes its limit.
    ;
    ; What the rewrite writes, measured against that pure head, because the
    ; budget below has to cover ALL of it and named only some of it:
    ;
    ;   request line   a wash. "method SP target" + req_version (" HTTP/1.1"
    ;                  CRLF, 11) is exactly as long as the "method SP target SP
    ;                  HTTP/1.x CRLF" it replaces — an HTTP-version token is
    ;                  always eight characters. req_version_len below is
    ;                  therefore pure surplus, not payment for this.
    ;   headers        never more than the pure head's: Connection, Expect and
    ;                  Transfer-Encoding are skipped by name, then the
    ;                  hop-by-hop list and everything Connection itself names.
    ;   Via            +17, ALWAYS, and nothing in the budget was named for it.
    ;   Content-Length +16 plus digits plus CRLF, but ONLY when bit 8 is set,
    ;                  which means the body arrived chunked — so the pure head
    ;                  carried a Transfer-Encoding line (>= 27) that the copy
    ;                  loop dropped. Longest we can emit is 11 digits, since
    ;                  the captured length is bounded by max_body's 64 GiB
    ;                  ceiling, giving 29. Net over the dropped line: +2.
    ;   Connection     +23 at most (upgrade; close is 21).
    ;
    ; Worst case is therefore 17 + 2 + 23 = 42 over the pure head, against a
    ; budget of 23 + 11 + 32 = 66. The 24 bytes between them are the margin any
    ; new line added here spends — lengthening Via is enough to start eating
    ; it. h1_upbuf_test.py walks a proxied head across this boundary in both
    ; framings and expects every size to be forwarded or refused 431.
    mov rcx, [rbx + linnea_connection.head_len]
    sub rcx, [rsp + 128]             ; buffered body bytes queued behind the head
    add rcx, hdr_up_upgrade_len
    add rcx, req_version_len + 32
    cmp rcx, LINNEA_CONN_UP_BUF
    ja .resp_431
    mov rcx, [rsp + 120]
    mov [rbx + linnea_connection.vhost], rcx   ; the log fires on completion
    mov rcx, [rsp + 24]
    mov [rbx + linnea_connection.keep_alive], rcx
    xor ecx, ecx
    cmp qword [rsp], 1
    sete cl
    mov [rbx + linnea_connection.is_head], rcx ; a HEAD response has no body
    mov qword [rbx + linnea_connection.up_status], 0
    mov qword [rbx + linnea_connection.relayed], 0
    ; Per-REQUEST upstream state, cleared per request. Connection slots are
    ; reused, and these three are written from one request and read by the next
    ; stage of another: a stale up_no_reuse (set because some earlier backend
    ; said close) silently vetoed every later reuse on that slot, which is how
    ; keep-alive appeared to work on a fresh server and stop working afterwards.
    mov qword [rbx + linnea_connection.up_reusable], 0
    mov qword [rbx + linnea_connection.up_no_reuse], 0
    mov qword [rbx + linnea_connection.up_pooled], 0
    mov qword [rbx + linnea_connection.up_len], 0
    mov qword [rbx + linnea_connection.body_rem], 0
    xor ecx, ecx               ; upgrade only when Connection lists the
    mov rax, [rsp + 232]       ; token AND an Upgrade header names a
    and rax, 3                 ; protocol to switch to
    cmp rax, 3
    sete cl
    mov [rbx + linnea_connection.upgrade], rcx
    ; request line: the method and raw target as the client sent them
    lea r15, [rbx + linnea_connection.up_buf]  ; append cursor
    mov rdi, r14
    mov rsi, [rsp + 104]
    call .append
    lea rdi, [log_sp]
    mov esi, 1
    call .append
    mov rdi, [rsp + 8]
    mov rsi, [rsp + 144]
    call .append
    ; An absolute-form target with an EMPTY path carries its query separately:
    ; "/?x=1" is not contiguous in the head buffer, so the target above is the
    ; canned "/" and the query is appended here (audit-report-76). Dropping it
    ; would turn a 400 into a successful request for the WRONG resource.
    cmp qword [rsp + 536], 0   ; the POINTER, not the length: "http://host?"
    je .proxy_no_qs            ; is an empty query, which is not no query
    lea rdi, [qmark_lit]
    mov esi, 1
    call .append
    mov rdi, [rsp + 536]
    mov rsi, [rsp + 544]
    call .append
.proxy_no_qs:
    lea rdi, [req_version]
    mov esi, req_version_len
    call .append
    ; RFC 9112 3.2.2: an absolute-form target's authority REPLACES the received
    ; Host. The parser routes on it already; the rewrite forwarded the client's
    ; Host line verbatim, so a request that selected this vhost as target.test
    ; reached the backend as other.test -- and on the proxy_h2 leg that field
    ; becomes the sole :authority (audit-report-75).
    mov rdi, r14
    mov rsi, [rsp + 104]
    call proxy_abs_authority          ; rdx = 0 unless absolute-form
    test rdx, rdx
    jz .proxy_no_host_repl
    push rax
    push rdx
    lea rdi, [hdr_host_up]
    mov esi, hdr_host_up_len
    call .append
    pop rsi
    pop rdi
    call .append
    lea rdi, [hdr_crlf_up]
    mov esi, 2
    call .append
.proxy_no_host_repl:
    ; header lines, verbatim except Connection (we send our own)
    mov r13, [rbx + linnea_connection.head_len]
    sub r13, [rsp + 128]       ; head_len covers the body too
    sub r13, 2                 ; lines end before the terminating CRLF
    xor ecx, ecx
.proxy_rl_scan:
    cmp byte [r14 + rcx], 13   ; the head is known to hold CRLF CRLF
    je .proxy_rl_found
    inc rcx
    jmp .proxy_rl_scan
.proxy_rl_found:
    add rcx, 2
    mov [rsp + 56], rcx        ; line cursor
.proxy_hdr_loop:
    mov rcx, [rsp + 56]
    cmp rcx, r13
    jae .proxy_hdr_done
    mov rdx, rcx
.proxy_eol_scan:
    cmp byte [r14 + rdx], 13
    je .proxy_eol_found
    inc rdx
    jmp .proxy_eol_scan
.proxy_eol_found:
    mov [rsp + 64], rdx        ; CR offset
    mov r8, rcx
.proxy_colon_scan:
    cmp r8, rdx
    jae .proxy_copy_line
    cmp byte [r14 + r8], ':'
    je .proxy_colon_found
    inc r8
    jmp .proxy_colon_scan
.proxy_colon_found:
    ; Keep the colon offset in r10. iequal clobbers r8 — which the old comment
    ; here noted — but it clobbers r9 as well, and only sometimes: it writes r9b
    ; solely once the two lengths it was given match, returning untouched when
    ; they differ. So r9 survived most comparisons and was quietly destroyed by
    ; the ones that got as far as comparing bytes, which is why a field name of
    ; exactly 10 characters (the length of "connection") reached the Expect test
    ; with a garbage length. r10 is one of the two registers iequal never uses.
    mov r10, r8                ; colon offset, safe across the comparisons below
    mov r9, r8
    mov rax, r8
    sub rax, rcx               ; header name length
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_connection]
    mov ecx, 10
    call linnea_string_iequal
    test eax, eax
    jnz .proxy_next_line       ; ours replaces it
    ; Max-Forwards goes on with one hop taken off it (RFC 9110 7.6.2), and only
    ; for the method it counts for: OPTIONS. The zero case never reaches here --
    ; it was answered before the upstream was chosen -- so the value is at least
    ; one and the subtraction cannot wrap.
    test qword [rsp + 136], 64
    jz .not_max_forwards
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_max_forwards]
    mov ecx, 12
    call linnea_string_iequal
    test eax, eax
    jz .not_max_forwards
    push r10
    mov rdi, r14
    mov rsi, [rsp + 104 + 8]
    lea rdx, [method_options]
    mov ecx, 7
    call linnea_string_equal
    pop r10
    test eax, eax
    jz .proxy_copy_line        ; another method: forwarded untouched
    lea rdi, [hdr_max_forwards]
    mov esi, hdr_max_forwards_len
    call .append
    mov rdi, [rsp + 528]
    dec rdi                    ; one hop taken; the zero case never gets here
    lea rsi, [num_buf]
    call linnea_string_from_u64   ; -> rax = digits written
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
    lea rdi, [crlf]
    mov esi, 2
    call .append
    jmp .proxy_next_line
.not_max_forwards:
    ; The whole body is already buffered, so there is nothing left for the
    ; upstream to authorize: forwarding a 100-continue expectation would only
    ; invite a 100 Continue, which this exchange has no way to handle. That is
    ; true of 100-continue and of nothing else -- an expectation we do not know
    ; is the BACKEND's to refuse, with the 417 RFC 9110 10.1.1 defines, and
    ; dropping every Expect made HTTP/1 the only protocol that never gave it the
    ; chance: h2 and h3 forward it (found sweeping the collectors after
    ; audit-report-32). The value decides, so it is read here rather than the
    ; name alone; r10 is the colon offset and the checks below still need it.
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_expect]
    mov ecx, 6
    call linnea_string_iequal
    test eax, eax
    jz .not_expect_line
    push r10
    lea rdi, [r14 + r10 + 1]         ; past the colon
    mov rsi, [rsp + 64 + 8]          ; line end (one push deep)
    sub rsi, r10
    dec rsi
    call linnea_string_trim_ows      ; -> rax = ptr, rdx = length
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [hv_100_continue]
    mov ecx, 12
    call linnea_string_iequal
    pop r10
    test eax, eax
    jnz .proxy_next_line             ; ours to answer: not forwarded
    jmp .proxy_copy_line             ; any other expectation goes upstream
.not_expect_line:
    ; the received Host, when it has been replaced above
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_host]
    mov ecx, 4
    call linnea_string_iequal
    test eax, eax
    jz .proxy_not_host
    push r10
    mov rdi, r14
    mov rsi, [rsp + 104 + 8]
    call proxy_abs_authority
    pop r10
    test rdx, rdx
    jnz .proxy_next_line              ; absolute-form: ours replaced it
.proxy_not_host:
    ; Transfer-Encoding never goes upstream: the body was decoded on the way in,
    ; so forwarding the header would promise the backend a framing that is no
    ; longer there. A Content-Length describing the decoded body is emitted with
    ; the Connection header below instead.
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_transfer_enc]
    mov ecx, 17
    call linnea_string_iequal
    test eax, eax
    jnz .proxy_next_line
    ; fields that are hop-by-hop in themselves, named in Connection or not
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    call http_hop_by_hop
    test eax, eax
    jnz .proxy_next_line
    ; and every field ANY of the client's Connection values names (RFC 9110
    ; 7.6.1). The whole head is re-walked per field rather than one value being
    ; kept as a span: Connection is list-valued, repeated field lines are one
    ; list in order (RFC 9110 5.3), and the span held only the LAST line. So
    ;     Connection: X-Auth-Bypass
    ;     Connection: keep-alive
    ;     X-Auth-Bypass: 1
    ; nominated the field hop-by-hop and forwarded it to the backend anyway,
    ; while the same request with the lines swapped removed it (audit-report-29).
    ; The response direction has walked the head since report 10, and its
    ; comment already claimed the request direction "has had the real rule" --
    ; which is what a claim in a comment is worth.
    ;
    ; One field is exempt, and only while one condition holds: `Upgrade`, when
    ; the client itself asked to upgrade. `Connection: upgrade` names Upgrade
    ; hop-by-hop like any other token, but there the server is a PARTICIPANT
    ; rather than a bystander -- it re-emits Connection: upgrade of its own and
    ; needs the client's Upgrade to reach the backend, or the tunnel it is
    ; setting up cannot be agreed. Written as "this field, given that wish"
    ; rather than as a name the matcher never matches: the response direction
    ; had it the second way and leaked `Upgrade: websocket` out of an ordinary
    ; 200 (audit-report-11).
    test qword [rsp + 232], 1         ; did the client ask to upgrade?
    jz .proxy_conn_named
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_upgrade]
    mov ecx, 7
    call linnea_string_iequal
    test eax, eax
    jnz .proxy_copy_line              ; the tunnel needs it forwarded
.proxy_conn_named:
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdx, [r14 + rcx]              ; the field name being considered
    mov rcx, rax
    mov rdi, r14                      ; ...against this whole request head
    mov rsi, [rbx + linnea_connection.head_len]
    call linnea_http_head_conn_named
    test eax, eax
    jnz .proxy_next_line              ; hop-by-hop: it stops here
.proxy_copy_line:
    mov rcx, [rsp + 56]
    mov rdx, [rsp + 64]
    lea rdi, [r14 + rcx]
    mov rsi, rdx
    sub rsi, rcx
    add rsi, 2                 ; include the CRLF
    call .append
.proxy_next_line:
    mov rdx, [rsp + 64]
    add rdx, 2
    mov [rsp + 56], rdx
    jmp .proxy_hdr_loop
.proxy_hdr_done:
    ; A body that arrived chunked has been decoded, and its Transfer-Encoding
    ; was dropped above — so the backend needs a length, and the client sent no
    ; Content-Length header for the copy loop to forward.
    test qword [rsp + 136], 8
    jz .proxy_no_clen
    lea rdi, [hdr_cl_up]
    mov esi, hdr_cl_up_len
    call .append
    mov rdi, [rsp + 128]             ; the decoded length
    cmp qword [rbx + linnea_connection.capture_done], 0
    je .proxy_clen_digits
    mov rdi, [rbx + linnea_connection.spill_len]   ; captured, not buffered
.proxy_clen_digits:
    lea rsi, [num_buf]
    call linnea_string_from_u64      ; rax = digits written
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
    lea rdi, [hdr_crlf_up]
    mov esi, 2
    call .append
.proxy_no_clen:
    lea rdi, [hdr_via_11]            ; we forwarded this hop (RFC 9110 7.6.3)
    mov esi, hdr_via_11_len
    call .append
    cmp qword [rbx + linnea_connection.upgrade], 0
    jne .proxy_conn_upgrade
    ; "Connection: close" is what makes a close-delimited response terminate, so
    ; it goes unless this location opted into keep-alive AND the method is one
    ; that may be sent again. Reuse is confined to safe methods because a pooled
    ; socket can always lose a race with the backend's own idle timeout, and the
    ; only sound answer to that race is to be able to repeat the request.
    ; [rsp] is 0 for GET and 1 for HEAD; -1/-2 for everything else, which the
    ; unsigned compare excludes.
    mov rcx, [rsp + 152]              ; the matched location
    test rcx, rcx
    jz .proxy_conn_close
    cmp qword [rcx + linnea_config_location.proxy_keepalive], 0
    je .proxy_conn_close
    cmp qword [rsp], 1
    ja .proxy_conn_close
    mov qword [rbx + linnea_connection.up_reusable], 1
    lea rdi, [hdr_up_keep]
    mov esi, hdr_up_keep_len
    jmp .proxy_conn_emit
.proxy_conn_close:
    lea rdi, [hdr_up_close]    ; one request per upstream connection
    mov esi, hdr_up_close_len
    jmp .proxy_conn_emit
.proxy_conn_upgrade:
    lea rdi, [hdr_up_upgrade]  ; forward the client's upgrade wish
    mov esi, hdr_up_upgrade_len
.proxy_conn_emit:
    call .append
    ; send window: the rewritten head, then the buffered body behind it
    lea rax, [rbx + linnea_connection.up_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov rcx, [rsp + 128]       ; Content-Length (0 = no body queued)
    mov [rbx + linnea_connection.file_rem], rcx
    mov rax, [rbx + linnea_connection.head_len]
    sub rax, rcx               ; the body sits right after the head
    lea rdx, [rbx + linnea_connection.in_buf]
    add rax, rdx
    mov [rbx + linnea_connection.file_ptr], rax
    ; the backend gets no more connections than it was sized for: past the
    ; ceiling the request is refused here rather than passed on
    ; choose which backend this request starts on, and begin its attempt count.
    ; First, because a parked connection belongs to ONE backend and there is
    ; nothing to look for until we know which.
    mov rdi, [rbx + linnea_connection.location]
    call linnea_upstream_pick
    mov [rbx + linnea_connection.up_backend], rax
    mov qword [rbx + linnea_connection.up_tries], 1
    mov qword [rbx + linnea_connection.up_pooled], 0
    ; A TLS backend leg is never pooled: a parked kTLS socket carries kernel
    ; crypto state the pool does not track, and the plaintext-head retry would
    ; write cleartext onto a socket expecting records. Force a fresh connect
    ; (hence a fresh handshake) every time, and never park it.
    mov rax, [rbx + linnea_connection.location]
    cmp qword [rax + linnea_config_location.proxy_tls], 0
    je .up_pool_ok
    mov qword [rbx + linnea_connection.up_reusable], 0
    jmp .up_fresh
.up_pool_ok:
    ; A reusable leg looks in the pool BEFORE the ceiling is consulted: a parked
    ; connection is already counted against it, so making a request wait for
    ; headroom it does not need would be the ceiling refusing its own inventory.
    cmp qword [rbx + linnea_connection.up_reusable], 0
    je .up_fresh
    mov rdi, [rbx + linnea_connection.location]
    mov rsi, [rbx + linnea_connection.up_backend]
    call linnea_upstream_take
    cmp eax, -1
    je .up_fresh
    mov [rbx + linnea_connection.up_fd], eax
    mov qword [rbx + linnea_connection.up_pooled], 1
    ; snapshot the request head so a dead parked socket can be retried on a
    ; fresh connection (out_rem is up_buf..head-end here; GET/HEAD has no body)
    mov rcx, [rbx + linnea_connection.out_rem]
    mov [rbx + linnea_connection.up_head_len], rcx
    mov qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_SENDING
    mov eax, LINNEA_HTTP_PROXY
    jmp .ret
.up_fresh:
    call linnea_upstream_count
    cmp rax, [linnea_upstream_limit]
    jb .up_fresh_room
    call linnea_upstream_reap_one     ; an idle parked socket yields to a request
    test eax, eax
    jnz .up_fresh                      ; freed one: re-check the ceiling
    jmp .resp_503                      ; genuinely at capacity with live requests
.up_fresh_room:
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .resp_502
    mov [rbx + linnea_connection.up_fd], eax
    call linnea_upstream_open
    mov qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_CONNECTING
    mov eax, LINNEA_HTTP_PROXY
    jmp .ret

.close_404:
    mov rdi, [rsp + 56]
    mov eax, LINNEA_SYS_CLOSE
    syscall
.resp_404_vary:
    ; a static path that missed: negotiated, so it must carry Vary (h1-15)
    lea rax, [resp_404_vary]
    mov ecx, resp_404_vary_len
    mov qword [rsp + 112], 404
    jmp .resp_static
.resp_404:
    lea rax, [resp_404]
    mov ecx, resp_404_len
    mov qword [rsp + 112], 404
    jmp .resp_static
.resp_400:
    lea rax, [resp_400]
    mov ecx, resp_400_len
    mov qword [rsp + 112], 400
    jmp .resp_static
.resp_options:
    lea rax, [resp_options]
    mov ecx, resp_options_len
    mov qword [rsp + 112], 200
    jmp .resp_static
.resp_405:
    lea rax, [resp_405]
    mov ecx, resp_405_len
    mov qword [rsp + 112], 405
    jmp .resp_static
.resp_429:
    lea rax, [resp_429]
    mov ecx, resp_429_len
    mov qword [rsp + 112], 429
    jmp .resp_static
.resp_413:
    lea rax, [resp_413]
    mov ecx, resp_413_len
    mov qword [rsp + 112], 413
    jmp .resp_static
.resp_406:
    lea rax, [resp_406]
    mov ecx, resp_406_len
    mov qword [rsp + 112], 406
    jmp .resp_static
.resp_417:
    lea rax, [resp_417]
    mov ecx, resp_417_len
    mov qword [rsp + 112], 417
    jmp .resp_static
.resp_414:
    lea rax, [resp_414]
    mov ecx, resp_414_len
    mov qword [rsp + 112], 414
    jmp .resp_static
.resp_431:
    lea rax, [resp_431]
    mov ecx, resp_431_len
    mov qword [rsp + 112], 431
    jmp .resp_static
.resp_501:
    lea rax, [resp_501]
    mov ecx, resp_501_len
    mov qword [rsp + 112], 501
    jmp .resp_static
.resp_502:
    lea rax, [resp_502]
    mov ecx, resp_502_len
    mov qword [rsp + 112], 502
    jmp .resp_static
.resp_503:
    lea rax, [resp_503]
    mov ecx, resp_503_len
    mov qword [rsp + 112], 503
    jmp .resp_static
.resp_505:
    lea rax, [resp_505]
    mov ecx, resp_505_len
    mov qword [rsp + 112], 505
.resp_static:
    ; The canned error responses are sent straight from rodata. When the
    ; vhost configures security headers they have to appear here too — a
    ; browser whose first request 404s should still learn the policy — so
    ; the blob is copied into out_buf without its blank line, the headers
    ; are appended, and the blank line is put back. Every blob ends with
    ; "Connection: close" CRLF CRLF, which is what the 4 accounts for.
    mov rdi, rbx
    mov rsi, rax               ; the blob
    mov rdx, rcx               ; and its length
    mov rcx, [rsp + 120]       ; the serving vhost (a default until matched)
    call http_error_blob       ; -> rax = ptr, rdx = length
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rdx
    mov qword [rbx + linnea_connection.keep_alive], 0
    mov qword [rbx + linnea_connection.file_rem], 0  ; drop anything queued
    mov qword [rsp + 32], 0    ; error responses carry no body
    ; fall through to .log_request

; access log: 'request <hostname> "<METHOD> <TARGET>" <status> <bytes>'
.log_request:
    call linnea_log_access_begin   ; marks the stream AND writes "request "
    mov rax, [rsp + 120]
    lea rdi, [rax + linnea_config_server.hostname]
    mov rsi, [rax + linnea_config_server.hostname_len]
    call linnea_log_write
    lea rdi, [log_from]
    mov esi, log_from_len
    call linnea_log_write
    lea rdi, [rbx + linnea_connection.peer]
    mov rsi, [rbx + linnea_connection.peer_len]
    call linnea_log_write
    lea rdi, [log_quote]
    mov esi, 2
    call linnea_log_write
    mov rdi, r14               ; method text sits at the buffer start
    mov rsi, [rsp + 104]
    test rsi, rsi
    jnz .log_method
    lea rdi, [log_dash]
    mov esi, 1
.log_method:
    call linnea_log_write
    lea rdi, [log_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [rsp + 8]
    mov rsi, [rsp + 144]       ; the raw target, query included
    test rdi, rdi
    jnz .log_target
    lea rdi, [log_dash]
    mov esi, 1
.log_target:
    call linnea_log_write
    lea rdi, [log_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [rsp + 416]
    mov rsi, [rsp + 424]
    test rdi, rdi
    jnz .log_version
    lea rdi, [log_dash]        ; the line never got as far as a version
    mov esi, 1
.log_version:
    call linnea_log_write
    lea rdi, [log_endq]
    mov esi, 2
    call linnea_log_write
    mov rdi, [rsp + 112]
    call linnea_log_u64
    lea rdi, [log_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [rsp + 32]
    call linnea_log_u64
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    mov eax, LINNEA_HTTP_RESPOND
    jmp .ret

.ret:
    add rsp, 560
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .open_regular(rdi=path cstr) -> rax = fd, or -1 if it is missing or is
; not a regular file. statbuf describes the file on success. Probing for a
; variant must not be able to open a directory named "foo.br".
.open_regular:
    push rbx
    xor esi, esi               ; O_RDONLY
    xor edx, edx
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .open_missing
    mov rbx, rax               ; fd
    mov rdi, rax
    lea rsi, [statbuf]
    mov eax, LINNEA_SYS_FSTAT
    syscall
    cmp rax, -4095
    jae .open_reject
    mov eax, [statbuf + LINNEA_STAT_ST_MODE]
    and eax, LINNEA_S_IFMT
    cmp eax, LINNEA_S_IFREG
    jne .open_reject
    mov rax, rbx
    pop rbx
    ret
.open_reject:
    mov edi, ebx
    mov eax, LINNEA_SYS_CLOSE
    syscall
.open_missing:
    mov rax, -1
    pop rbx
    ret


; .append_validators() — the ETag and Last-Modified lines, from the
; buffers filled after the fstat. Shared by the 200 and 304 paths so a
; revalidating client always gets back exactly what it will compare next.
.append_validators:
    lea rdi, [hdr_etag]
    mov esi, hdr_etag_len
    call .append
    lea rdi, [etag_buf]
    mov rsi, [etag_len]
    call .append
    lea rdi, [hdr_last_mod]
    mov esi, hdr_last_mod_len
    call .append
    lea rdi, [date_buf]
    mov esi, LINNEA_HTTP_DATE_LEN
    jmp .append

; .append_cache_control(rdi=location*, may be 0) — the location's configured
; Cache-Control line, when there is one. A 304 carries it too: like Vary, it
; is metadata the client's cache must refresh on revalidation.
.append_cache_control:
    test rdi, rdi
    jz .acc_done
    cmp qword [rdi + linnea_config_location.cache_control_len], 0
    je .acc_done
    mov r8, rdi                ; the location, across .append (which keeps r8)
    lea rdi, [hdr_cache_control]
    mov esi, hdr_cache_control_len
    call .append
    lea rdi, [r8 + linnea_config_location.cache_control]
    mov rsi, [r8 + linnea_config_location.cache_control_len]
    jmp .append
.acc_done:
    ret

; .append_server_date(rdi = the serving vhost, may be 0) — the Server line, a
; Date line naming the current time (RFC 9110 6.6.1), and whatever security
; headers that vhost configures. Shared by every dynamically assembled head.
; The vhost comes in as an argument rather than off the caller's frame: a
; call has already pushed the return address, so the frame offsets differ
; here from every other line in this handler.
.append_server_date:
    push rdi                   ; the vhost, across the appends
    lea rdi, [hdr_server]
    mov esi, hdr_server_len
    call .append
    lea rdi, [hdr_date]
    mov esi, hdr_date_len
    call .append
    call linnea_time_http_now
    mov rdi, rax
    mov esi, LINNEA_HTTP_DATE_LEN
    call .append
    pop rdi                    ; the serving vhost
    ; fall through to the security headers

; .append_security(rdi = the serving vhost, may be 0) — the Strict-Transport
; -Security and X-Content-Type-Options lines this vhost configures, if any.
.append_security:
    test rdi, rdi
    jz .asd_done
    mov r8, rdi
    cmp qword [r8 + linnea_config_server.hsts_len], 0
    je .asd_nosniff
    push r8
    lea rdi, [hdr_hsts]
    mov esi, hdr_hsts_len
    call .append
    pop r8
    push r8
    lea rdi, [r8 + linnea_config_server.hsts]
    mov rsi, [r8 + linnea_config_server.hsts_len]
    call .append
    pop r8
.asd_nosniff:
    cmp qword [r8 + linnea_config_server.nosniff], 0
    je .asd_done
    lea rdi, [hdr_nosniff]
    mov esi, hdr_nosniff_len
    jmp .append
.asd_done:
    ret

; .append(rdi=ptr, rsi=len) — local helper; r15 is the write cursor.
; The 200 header line lengths are bounded well under LINNEA_CONN_OUT_BUF.
.append:
    mov rcx, rsi
    mov rsi, rdi
    mov rdi, r15
    rep movsb
    mov r15, rdi
    ret

; .hex_nibble(eax=char) -> eax = 0-15, or -1 for a non-hex character
.hex_nibble:
    mov r8d, eax
    sub r8d, '0'
    cmp r8d, 9
    jbe .hex_digit
    or eax, 0x20               ; ASCII lowercase
    sub eax, 'a'
    cmp eax, 5
    ja .hex_bad
    add eax, 10
    ret
.hex_digit:
    mov eax, r8d
    ret
.hex_bad:
    mov eax, -1
    ret




; http_send_continue(rdi = conn*) — send the 100 (Continue) interim response,
; once per request.
;
; RFC 9110 10.1.1: a server receiving a 100-continue expectation MUST answer
; either 100 or a final status. This answered neither — the field was never
; inspected, and hn_expect existed only so the proxy rewriter could strip it —
; so the server sat waiting for a body the client was deliberately withholding
; while the client sat waiting for permission to send it. curl breaks that with
; its own one-second timeout, which is a second added to every such request;
; a client without that fallback gets nothing until the connection dies.
;
; Written straight to the socket rather than through out_buf: this is an INTERIM
; response, and the response machinery is built around one final head per
; request. It is safe here because nothing else is in flight — the loop is
; reading the request, so no send is armed — and a TLS connection is in kTLS by
; the time a request is being parsed, so the socket write is an encrypted record
; like any other. MSG_NOSIGNAL because a dead peer must not kill the worker,
; which is the lesson Q174 paid for.
;
; A failure here costs nothing: the client falls back to the behaviour it had
; before this existed, which is to send the body after its own timeout.
http_send_continue:
    cmp qword [rdi + linnea_connection.continue_sent], 0
    jne .sc_done
    mov qword [rdi + linnea_connection.continue_sent], 1
    push rdi
    mov edi, [rdi + linnea_connection.fd]
    lea rsi, [resp_100]
    mov edx, resp_100_len
    mov r10d, LINNEA_MSG_DONTWAIT | LINNEA_MSG_NOSIGNAL
    xor r8d, r8d
    xor r9d, r9d
    mov eax, LINNEA_SYS_SENDTO
    syscall
    pop rdi
.sc_done:
    ret

; http_error_blob(rdi=conn*, rsi=blob, rdx=blob len, rcx=server* or 0)
;   -> rax = response ptr, rdx = response length
; A canned error response carrying the vhost's security headers. A browser
; whose first request fails should still learn the policy, and that includes
; the ones a proxy failure produces — a 502 from a dead upstream is often the
; very first thing a client sees. The blob is copied into out_buf without its
; terminating blank line, the headers are appended, and the blank line is put
; back; every blob ends with "Connection: close" CRLF CRLF, which is what the
; 4 accounts for, and each header literal carries its own leading CRLF. With
; no headers configured the blob is returned untouched, straight from rodata.
http_error_blob:
    ; Always assembled, never returned straight from rodata: RFC 9110 6.6.1
    ; makes Date mandatory on everything a server with a clock sends outside
    ; 1xx and 5xx, and a date is not something a constant can carry. The blobs
    ; shipped without one — 400, 404, 405, 413, 414, 431 and the OPTIONS * 200
    ; — while every dynamically built response had it right, so the gap was
    ; exactly the responses assembled ahead of time.
.heb_copy:
    push rbx
    push r12
    push r15
    mov rbx, rcx                     ; server*, or 0 before one is matched
    mov r12, rdi                     ; conn*
    lea r15, [rdi + linnea_connection.out_buf]
    mov rdi, r15                     ; the blob without its blank line
    mov rcx, rdx
    sub rcx, 4
    rep movsb
    mov r15, rdi
    test rbx, rbx
    jz .heb_blank                    ; no vhost yet: Date, and nothing else
    cmp qword [rbx + linnea_config_server.hsts_len], 0
    je .heb_nosniff
    lea rsi, [hdr_hsts]
    mov rcx, hdr_hsts_len
    rep movsb
    lea rsi, [rbx + linnea_config_server.hsts]
    mov rcx, [rbx + linnea_config_server.hsts_len]
    rep movsb
    mov r15, rdi
.heb_nosniff:
    cmp qword [rbx + linnea_config_server.nosniff], 0
    je .heb_blank
    mov rdi, r15
    lea rsi, [hdr_nosniff]
    mov rcx, hdr_nosniff_len
    rep movsb
    mov r15, rdi
.heb_blank:
    mov rdi, r15
    lea rsi, [hdr_date]              ; carries its own leading CRLF
    mov ecx, hdr_date_len
    rep movsb
    mov r15, rdi
    call linnea_time_http_now        ; -> rax = the cached IMF-fixdate
    mov rdi, r15
    mov rsi, rax
    mov ecx, LINNEA_HTTP_DATE_LEN
    rep movsb
    mov r15, rdi
    lea rsi, [crlfcrlf]
    mov ecx, 4
    rep movsb
    lea rax, [r12 + linnea_connection.out_buf]
    mov rdx, rdi
    sub rdx, rax
    pop r15
    pop r12
    pop rbx
    ret

; target_absolute(rdi = target ptr, rsi = target length)
;   -> rax = path ptr (0 when the target is not absolute-form), rdx = path
;      length, rcx = authority ptr, r8 = authority length.
; RFC 9112 3.2.2: "scheme://authority/path". A server MUST accept it, and the
; authority it carries — not the Host header — identifies the resource. The
; path returned is the part from the '/' that ends the authority; a target
; with no such '/' ("http://host") means the root. Only http and https are
; recognised, case-insensitively, since the scheme is case-insensitive.
target_absolute:
    push rbx
    mov rbx, rdi
    cmp rsi, 8                       ; the shortest is "http://x"
    jb .ta_no
    ; scheme: "http" then optional "s", then "://"
    mov eax, [rbx]
    or eax, 0x20202020               ; fold to lowercase
    cmp eax, 'http'
    jne .ta_no
    lea rdi, [rbx + 4]
    movzx eax, byte [rdi]
    or al, 0x20
    cmp al, 's'
    jne .ta_sep
    inc rdi
.ta_sep:
    mov eax, [rdi]
    and eax, 0x00ffffff
    cmp eax, '://'
    jne .ta_no
    add rdi, 3                       ; the authority starts here
    mov rcx, rdi                     ; authority ptr
    lea r9, [rbx + rsi]              ; target end
    mov r8, rdi
.ta_auth:
    cmp r8, r9
    jae .ta_root                     ; no path at all: the root
    cmp byte [r8], '/'
    je .ta_path
    cmp byte [r8], '?'
    je .ta_query                     ; an empty path, then a query
    inc r8
    jmp .ta_auth
.ta_path:
    xor r10d, r10d               ; no query of its own
    xor r11d, r11d
    mov rax, r8                      ; the path begins at that '/'
    mov rdx, r9
    sub rdx, r8                      ; its length
    sub r8, rcx                      ; authority length
    test r8, r8
    jz .ta_no                        ; "http:///path" names nothing
    pop rbx
    ret
.ta_query:
    ; RFC 9110 4.2.1: http-URI is authority path-abempty [ "?" query ], so an
    ; EMPTY path may be followed by a query -- "http://host?x=1" is authority
    ; "host", path "", query "x=1". Scanning only for '/' swallowed the query
    ; into the authority, which the authority validator then rejected: a valid
    ; request was answered 400, and a query CONTAINING a slash split at that
    ; slash instead (audit-report-76).
    ;
    ; The path normalises to "/" and the query comes back separately in
    ; r10/r11, because "/?x=1" does not exist contiguously in the head buffer;
    ; the caller keeps it and the proxy rewrite appends it behind the target.
    mov r10, r8                      ; at the '?'
    inc r10                          ; the query itself
    mov r11, r9
    sub r11, r10                     ; its length
    sub r8, rcx                      ; authority length
    test r8, r8
    jz .ta_no
    lea rax, [slash_target]
    mov rdx, 1
    pop rbx
    ret
.ta_root:
    xor r10d, r10d               ; no query of its own
    xor r11d, r11d
    sub r8, rcx                      ; authority length
    test r8, r8
    jz .ta_no
    lea rax, [slash_target]          ; the root, since the target gave no path
    mov rdx, 1
    pop rbx
    ret
.ta_no:
    xor r10d, r10d               ; no query of its own
    xor r11d, r11d
    xor eax, eax
    pop rbx
    ret

; --- proxying ----------------------------------------------------------

; linnea_http_authority_host(rdi = authority ptr, rsi = authority len)
;   -> rax = host length, rdx = host offset from ptr (0, or 1 for a bracketed
;      literal); or rax = -1 when the authority is malformed.
;
; The single authority parser for all three protocols. An authority is
;   reg-name-or-IPv4 [ ":" port ]   or   "[" IPv6 "]" [ ":" port ]
; and a bare split at the first ':' mis-handles both ends of the grammar: it
; turned "[::1]:443" into the host "[" (the first ':' sits inside the literal),
; and it accepted "three.test:garbage" and "three.test:80:bad" because whatever
; followed the first ':' was never looked at. Here the bracket form is parsed to
; its closing ']', and a port -- in either form -- is accepted only as one to
; five decimal digits with nothing after it. The host character rule matches
; what the h1 Host and h2/h3 :authority validators already enforced (printable,
; no space, no DEL); it is not tightened here, only the STRUCTURE is. A well
; formed name that is not a configured vhost still simply falls through to the
; default -- rejecting is for malformed structure, not for unknown names.


; linnea_http_log_conn(rdi=conn*, rsi=status, rdx=bytes)
; The access log line for a proxied request, emitted once the exchange is
; over. The method and target are re-derived from in_buf: proxying arms no
; client recv, so the request head is still intact, and the head is only
; dropped afterwards by the event loop's keep-alive compaction.
linnea_http_log_conn:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48                ; [32]/[40]: the version token, scanned like the
                               ; method and target rather than assumed
    mov rbx, rdi
    mov [rsp], rsi             ; status
    mov [rsp + 8], rdx         ; body bytes
    lea r14, [rbx + linnea_connection.in_buf]
    xor r12d, r12d
.method_scan:
    cmp r12, [rbx + linnea_connection.in_len]
    jae .method_done
    cmp byte [r14 + r12], ' '
    je .method_done
    inc r12
    jmp .method_scan
.method_done:
    mov [rsp + 16], r12        ; method len
    lea r13, [r12 + 1]         ; target start
    mov r15, r13
.target_scan:
    cmp r15, [rbx + linnea_connection.in_len]
    jae .target_done
    cmp byte [r14 + r15], ' '
    je .target_done
    inc r15
    jmp .target_scan
.target_done:
    ; The version is the rest of the line, and it is re-derived here for the
    ; same reason the method and target are: this logger writes what arrived.
    ; It used to write a constant, which made every version but 1.1 a fiction.
    mov qword [rsp + 32], 0    ; no version on the line
    lea rax, [r15 + 1]
    cmp rax, [rbx + linnea_connection.in_len]
    jae .no_version            ; the line ended at the target
    lea rcx, [r14 + rax]
    mov [rsp + 32], rcx        ; version ptr
    mov rcx, rax               ; ...and it runs to the CR, or to what arrived
.version_scan:
    cmp rcx, [rbx + linnea_connection.in_len]
    jae .version_end
    cmp byte [r14 + rcx], 13
    je .version_end
    inc rcx
    jmp .version_scan
.version_end:
    sub rcx, rax
    mov [rsp + 40], rcx        ; version len
.no_version:
    sub r15, r13
    mov [rsp + 24], r15        ; target len
    add r13, r14               ; target ptr
    call linnea_log_access_begin   ; marks the stream AND writes "request "
    ; The vhost can be ABSENT. Every caller here until now logged a request that
    ; had routed, so the name was always there and this read was unguarded -- and
    ; the first caller that logs a request which never routed (the 408 for a body
    ; that stalled: h1 waits for a declared body BEFORE choosing a vhost) took a
    ; SIGSEGV on a null dereference at +0x148, killing the worker. Guarded here
    ; rather than at that one call site, because "which vhost served this" is a
    ; question a request can legitimately fail to have an answer to, and the next
    ; caller to log one would find the same hole. "-" is the access-log
    ; convention for a field with no value.
    mov rax, [rbx + linnea_connection.vhost]
    test rax, rax
    jz .lc_no_vhost
    lea rdi, [rax + linnea_config_server.hostname]
    mov rsi, [rax + linnea_config_server.hostname_len]
    jmp .lc_name
.lc_no_vhost:
    lea rdi, [log_dash]
    mov esi, 1
.lc_name:
    call linnea_log_write
    lea rdi, [log_from]
    mov esi, log_from_len
    call linnea_log_write
    lea rdi, [rbx + linnea_connection.peer]
    mov rsi, [rbx + linnea_connection.peer_len]
    call linnea_log_write
    lea rdi, [log_quote]
    mov esi, 2
    call linnea_log_write
    mov rdi, r14
    mov rsi, [rsp + 16]
    call linnea_log_write
    lea rdi, [log_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, r13
    mov rsi, [rsp + 24]
    call linnea_log_write
    lea rdi, [log_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [rsp + 32]
    mov rsi, [rsp + 40]
    test rdi, rdi
    jnz .lc_version
    lea rdi, [log_dash]
    mov esi, 1
.lc_version:
    call linnea_log_write
    lea rdi, [log_endq]
    mov esi, 2
    call linnea_log_write
    mov rdi, [rsp]
    call linnea_log_u64
    lea rdi, [log_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [rsp + 8]
    call linnea_log_u64
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_http_proxy_error(rdi=conn*, rsi=502 or 504)
; Abandons the upstream exchange and answers the client with a static
; error instead. Only valid before any response byte has been sent, which
; is every failure up to and including the response head.
linnea_http_proxy_error:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rdi
    mov r12, rsi
    mov edi, [rbx + linnea_connection.up_fd]
    cmp edi, -1
    je .no_up
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed   ; release the ceiling slot, or a 502/504
                                  ; storm permanently wedges proxying at 503
    mov dword [rbx + linnea_connection.up_fd], -1
.no_up:
    mov qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_IDLE
    cmp r12, 504
    je .gateway_timeout
    cmp r12, 400
    je .bad_request            ; a captured body whose framing did not hold up
    cmp r12, 413
    je .too_large              ; ...or which ran past max_body
    lea rax, [resp_502]
    mov ecx, resp_502_len
    jmp .set
.bad_request:
    lea rax, [resp_400]
    mov ecx, resp_400_len
    jmp .set
.too_large:
    lea rax, [resp_413]
    mov ecx, resp_413_len
    jmp .set
.gateway_timeout:
    lea rax, [resp_504]
    mov ecx, resp_504_len
.set:
    mov rdi, rbx               ; the vhost's security headers ride this too
    mov rsi, rax
    mov rdx, rcx
    mov rcx, [rbx + linnea_connection.vhost]
    call http_error_blob       ; -> rax = ptr, rdx = length
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rdx
    mov qword [rbx + linnea_connection.keep_alive], 0
    mov qword [rbx + linnea_connection.file_rem], 0   ; drop the queued body
    mov rdi, rbx
    mov rsi, r12
    xor edx, edx
    call linnea_http_log_conn
    add rsp, 8
    pop r12
    pop rbx
    ret

; linnea_http_request_timeout(rdi=conn*) — answer 408 and stop keeping the
; connection alive (RFC 9110 15.5.9). Called from the io_uring loop when the
; idle clock fires on an HTTP/1 connection with a request PARTLY received: a
; head that stopped mid-line, or -- the case that made this visible -- a body
; that declared N bytes and sent fewer. h1 waits for a declared body before it
; routes, and a short body is indistinguishable from a slow one on a byte
; stream, so waiting is right and the timeout is the only possible answer. What
; was wrong is that there was no answer: the connection was closed with the log
; line "idle timeout" and nothing went to the client at all.
;
; Only for a request in progress. req_start is zero between requests, so an
; idle keep-alive connection -- legitimate, and possibly long -- still closes in
; silence rather than being told it timed out.
;
; The caller must set answer_linger before arming the send, as the capture
; refusals do: the client is still sending, and closing on top of the answer
; would RST away the very bytes that explain the refusal.
linnea_http_request_timeout:
    push rbx
    sub rsp, 8
    mov rbx, rdi
    lea rsi, [resp_408]
    mov edx, resp_408_len
    mov rcx, [rbx + linnea_connection.vhost]   ; its security headers ride this
    call http_error_blob                       ; -> rax = ptr, rdx = length
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rdx
    mov qword [rbx + linnea_connection.keep_alive], 0
    mov qword [rbx + linnea_connection.file_rem], 0   ; drop any queued body
    mov rdi, rbx
    mov esi, 408
    xor edx, edx
    call linnea_http_log_conn
    add rsp, 8
    pop rbx
    ret

; linnea_http_proxy_log(rdi=conn*) — the completion log line for a proxied
; request: the upstream's status and the body bytes actually relayed.
linnea_http_proxy_log:
    mov rsi, [rdi + linnea_connection.up_status]
    mov rdx, [rdi + linnea_connection.relayed]
    jmp linnea_http_log_conn

; linnea_http_status_no_clen(edi = status) -> eax = 1 when a response with
; this status must not carry Content-Length.
; RFC 9110 8.6: a server MUST NOT send Content-Length on a 1xx or a 204. On
; those two the field is not merely surplus, it is a framing lie -- an interim
; head has no body at all, so a client that believes the length reads the next
; response's first bytes as this one's content. The HEAD and 304 cases named in
; the same section are the opposite: there the length describes a representation
; the client is not being sent, and it must survive. The rule lives here, once,
; because the three translators that emit a response head have each already
; drifted apart on questions this small.
linnea_http_status_no_clen:
    xor eax, eax
    cmp edi, 100
    jb .nc_ret
    cmp edi, 199
    jbe .nc_yes
    cmp edi, 204
    jne .nc_ret
.nc_yes:
    mov eax, 1
.nc_ret:
    ret

; linnea_http_upstream_head_valid(rdi = head buf, rsi = head length)
;   -> eax = 1 valid, 0 not.
; One gate on an upstream HTTP/1 response head, for every protocol that relays
; one (audit-report-6 Finding 1). The head must not carry anything the
; downstream message cannot legally hold (RFC 9110 5.5/5.6.2, RFC 9112 5, RFC
; 9110 8.6): every field line needs a token name and a colon, its value may hold
; no control byte but HTAB, no line may be an obsolete fold, and a repeated
; Content-Length must name the same length. The status line is checked here
; too: version, three-digit code, reason-phrase bytes and the CRLF that ends
; it (audit-report-8 Finding 1, audit-report-9 Finding 1).
;
; It began as h2p_head_validate with HTTP/2 as its only caller, and the other
; two protocols each answered these responses differently -- which is how the
; audit found it. A backend line "Bad Name: x" was 502 on h2, relayed VERBATIM
; to the client on h1, and QPACK-encoded onto the wire as a field name
; containing a SPACE on h3. "Content-Length: 5" then "Content-Length: 7" was 502
; on h1 and h2, but h3 took the first value, captured five bytes and re-issued
; the contradiction as a clean 200. It lives in the HTTP/1 module because an
; upstream response head IS an HTTP/1 message, whichever protocol relays it.
linnea_http_upstream_head_valid:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 56                       ; [rsp]=cl seen flag, [rsp+8]=cl value,
                                      ; [rsp+16]=status, [rsp+24]=TE line count,
                                      ; [rsp+32]=singleton fields seen (bitmask),
                                      ; [rsp+40]=the line cursor across that scan
    mov r12, rdi                      ; head buf
    mov r13, rsi                      ; head length
    mov qword [rsp], 0                ; no Content-Length seen yet
    mov qword [rsp + 16], 0
    mov qword [rsp + 24], 0
    mov qword [rsp + 32], 0           ; no singleton field seen yet
    xor rcx, rcx                      ; cursor
    ; --- the status line itself ------------------------------------------
    ; This used to be skipped outright, and only HTTP/1 checked it afterwards
    ; with a policy of its own -- so "HTTP/x.y 200 OK" was a 502 there and a
    ; perfectly ordinary 200 over h2 and h3, which manufactured a downstream
    ; status from the three digits and never looked at the version bytes
    ; (audit-report-8 Finding 1). RFC 9112 2.3 makes HTTP-version
    ; HTTP-name "/" DIGIT "." DIGIT, so those bytes are part of the grammar,
    ; not decoration; and a proxy that will only speak 1.0 or 1.1 upstream has
    ; no business relaying a response claiming anything else. Checked here, in
    ; the one gate every protocol already calls, rather than three times.
    cmp r13, 13                       ; "HTTP/1.1 200" + CR at the very least
    jb .hv_bad
    mov rax, [r12]
    lea rcx, [version_11]
    cmp rax, [rcx]
    je .hv_ver_ok
    lea rcx, [version_10]
    cmp rax, [rcx]
    jne .hv_bad
.hv_ver_ok:
    cmp byte [r12 + 8], ' '           ; exactly one SP before the code
    jne .hv_bad
    xor ecx, ecx
.hv_code:
    cmp ecx, 3
    jae .hv_code_done
    movzx eax, byte [r12 + rcx + 9]
    sub eax, '0'
    cmp eax, 9
    ja .hv_bad                        ; the status code is three DIGITS
    imul edx, [rsp + 16], 10          ; keep the value: the 205 rule below is
    add edx, eax                      ; the first thing here to need it
    mov [rsp + 16], rdx
    inc ecx
    jmp .hv_code
.hv_code_done:
    ; RFC 9110 15: a status code is a three-digit integer in 100..599. Three
    ; DIGITS is necessary and not sufficient, and the difference is not
    ; cosmetic: h1 classified anything at or below 199 as an interim response,
    ; so an upstream "099" selected the interim loop -- a lifecycle decision
    ; about when a response is complete and which fields become visible before
    ; the real answer -- while h2 and h3 refused it, and nothing anywhere
    ; checked the upper bound, so 600..999 was reissued downstream, including as
    ; an HTTP/2 and HTTP/3 :status (audit-report-13 Finding 1).
    ;
    ; The range belongs here rather than in the translators' own lower-bound
    ; checks: those run after the shared decision, h1 has none, and none of them
    ; looks upward. An in-range but unregistered status such as 299 must still
    ; be forwarded -- this is a range, not an allowlist.
    mov rax, [rsp + 16]
    cmp rax, 100
    jb .hv_bad
    cmp rax, 599
    ja .hv_bad
    ; ...and the code is delimited: either the line ends, or a reason phrase
    ; follows behind its own space. "HTTP/1.1 2000" is not a status line.
    movzx eax, byte [r12 + 12]
    cmp al, 13
    je .hv_status
    cmp al, ' '
    jne .hv_bad
    xor rcx, rcx
.hv_status:                           ; the reason phrase, to its CRLF
    cmp rcx, r13
    jae .hv_bad                       ; a status line with no CRLF is not one
    movzx eax, byte [r12 + rcx]
    cmp al, 13
    je .hv_status_eol
    ; reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ), RFC 9112 4. A byte
    ; outside that set is not a reason phrase, and HTTP/1 relays these bytes
    ; verbatim -- which is how a NUL or a bare LF would reach the client.
    cmp al, 9
    je .hv_status_next
    cmp al, 32
    jb .hv_bad
    cmp al, 127
    je .hv_bad
.hv_status_next:
    inc rcx
    jmp .hv_status
.hv_status_eol:
    ; A CR ends an HTTP/1 line only when an LF follows it (RFC 9112 2.2). This
    ; used to step over the CR unconditionally, so the byte behind a BARE one
    ; became the first byte of a "field name": "HTTP/1.1 200\rX-Fold: accepted"
    ; walked straight through this gate and was normalised into an ordinary 200
    ; on all three protocols -- h1 even replacing the bare CR with a CRLF of its
    ; own on the way out (audit-report-9 Finding 1). The field lines below have
    ; always demanded the LF; the line naming the status now does too.
    lea rax, [rcx + 1]
    cmp rax, r13
    jae .hv_bad
    cmp byte [r12 + rax], 10
    jne .hv_bad
    add rcx, 2                        ; past CRLF
.hv_line:
    cmp rcx, r13
    jae .hv_ok
    cmp byte [r12 + rcx], 13
    je .hv_ok                         ; the terminating empty line: done
    movzx eax, byte [r12 + rcx]
    cmp al, ' '
    je .hv_bad                        ; a line beginning with SP/HTAB is an
    cmp al, 9                         ; obsolete fold -- reject, do not relay
    je .hv_bad
    mov r14, rcx                      ; field name start
.hv_name:
    cmp rcx, r13
    jae .hv_bad
    movzx eax, byte [r12 + rcx]
    cmp al, ':'
    je .hv_name_done
    cmp al, 13
    je .hv_bad                        ; CR before any colon: no name/value split
    inc rcx
    jmp .hv_name
.hv_name_done:
    mov r15, rcx                      ; colon offset
    mov rbp, rcx
    sub rbp, r14                      ; name length
    jz .hv_bad                        ; empty name (colon at line start)
    cmp rbp, LINNEA_HTTP_MAX_FIELD_NAME
    ja .hv_bad                        ; longer than anything we will relay --
                                      ; refused HERE so h1, h2 and h3 agree,
                                      ; rather than being silently erased by
                                      ; whichever encoder has a small buffer
    lea rdi, [r12 + r14]
    mov rsi, rbp
    call linnea_string_is_token       ; token name?
    test eax, eax
    jz .hv_bad
    ; the value: skip the colon and any OWS, then run to the CR
    lea rcx, [r15 + 1]
.hv_ows:
    cmp rcx, r13
    jae .hv_bad
    movzx eax, byte [r12 + rcx]
    cmp al, ' '
    je .hv_ows_next
    cmp al, 9
    je .hv_ows_next
    jmp .hv_valstart
.hv_ows_next:
    inc rcx
    jmp .hv_ows
.hv_valstart:
    mov r14, rcx                      ; value start (name start no longer needed)
.hv_value:
    cmp rcx, r13
    jae .hv_bad
    movzx eax, byte [r12 + rcx]
    cmp al, 13
    je .hv_value_end
    cmp al, 9
    je .hv_value_next                 ; HTAB is allowed
    cmp al, 0x20
    jb .hv_bad                        ; a control byte in the value
    cmp al, 0x7F
    je .hv_bad                        ; DEL
    ja .hv_value_next                 ; 0x80-0xFF obs-text is tolerated
.hv_value_next:
    inc rcx
    jmp .hv_value
.hv_value_end:
    ; --- fields that may appear at most once -----------------------------
    ; Each of these defines ONE value: a media type, a target, a validator, a
    ; date. Two of them are a message that says two different things, and this
    ; gate relayed both onward -- a 302 carrying `Location: /one` and
    ; `Location: /two` reached the client with both, and clients disagree about
    ; which to follow, so a cache and a browser can end up at different URLs.
    ; The duplicate Content-Length beside them has been refused since report 6;
    ; nothing else was. Found by sweeping repeated RESPONSE fields after the
    ; request-side sweep that produced reports 28-32.
    ;
    ; Content-Length is deliberately absent from the table: two identical
    ; lengths describe the same body and are reconciled below, which is a
    ; different rule from "this field cannot repeat".
    mov [rsp + 40], rcx               ; iequal does not promise the cursor
    lea rbx, [hv_singletons]
.hv_sing_loop:
    movzx eax, byte [rbx]
    test eax, eax
    jz .hv_sing_done
    cmp rax, rbp
    jne .hv_sing_next
    push rbx
    lea rdi, [r12 + r15]
    sub rdi, rbp                      ; the field name
    mov rsi, rbp
    lea rdx, [rbx + 2]
    mov ecx, eax
    call linnea_string_iequal
    pop rbx
    test eax, eax
    jnz .hv_sing_hit
.hv_sing_next:
    movzx eax, byte [rbx]
    lea rbx, [rbx + rax + 2]
    jmp .hv_sing_loop
.hv_sing_hit:
    movzx eax, byte [rbx + 1]         ; this field's bit, so no shift is needed
    test [rsp + 32], rax              ; ...and the cursor in rcx stays put
    jnz .hv_bad                       ; a second one: two answers to one question
    or [rsp + 32], rax
.hv_sing_done:
    mov rcx, [rsp + 40]
    ; a Transfer-Encoding line, noted only so the 205 rule below can see it
    cmp rbp, 17
    jne .hv_not_te
    lea rdi, [r12 + r15]
    sub rdi, rbp
    mov rsi, rbp
    lea rdx, [hn_transfer_enc]
    mov ecx, 17
    call linnea_string_iequal
    test eax, eax
    jz .hv_not_te
    ; Repeated list-valued field lines COMBINE, in order, so two of these state
    ; "chunked, chunked" -- two chunk layers, which RFC 9112 6.1 forbids and
    ; which one layer of chunks does not satisfy. Each line was being validated
    ; in isolation, so both passed: h1 relayed both fields with a single-layer
    ; body, while h2 and h3 de-chunked once and dropped the fields into an
    ; ordinary-looking success (audit-report-13 Finding 2).
    ;
    ; This is NOT the duplicate Content-Length of report 6, which is reconciled
    ; rather than refused: two identical lengths describe the same body, whereas
    ; a second `chunked` describes a second transformation that does not exist.
    ; A count is enough because the policy is already "exactly one chunked and
    ; nothing else"; the value check below rejects any comma list on its own.
    inc qword [rsp + 24]
    cmp qword [rsp + 24], 1
    ja .hv_bad
    ; ...and the coding list must be exactly `chunked`. RFC 9112 6.1 makes
    ; Transfer-Encoding the sequence of codings applied to form the HTTP/1
    ; message body, and its own example is `gzip, chunked`: content compressed
    ; and THEN chunk-framed. Removing the chunk framing does not undo the gzip,
    ; so a proxy that de-chunks and calls the result identity content hands the
    ; client bytes that are not the response. That is what HTTP/3 did with
    ; `gzip, chunked` and what HTTP/2 did with a bare `gzip` -- and HTTP/1
    ; relayed the coding to a client that never offered TE, which RFC 9112 6.1
    ; forbids in as many words (audit-report-11 Finding 2).
    ;
    ; It is refused here, once, rather than in each translator: the audit found
    ; THREE different wrong answers to the same upstream message, which is what
    ; a rule kept in three places does. `chunked` is the one coding this proxy
    ; actually removes; anything else is a transformation it cannot express
    ; downstream, and inventing a length for bytes it did not decode is worse
    ; than refusing.
    ;
    ; The value's leading OWS is already skipped; trim the trailing OWS and the
    ; whole list must be that one token. /api/tepad ("  Chunked ") is the
    ; control that keeps this from becoming "refuse anything unfamiliar".
    ; rcx is not the CR any more -- linnea_string_iequal takes its length in
    ; ecx -- so re-find it from the value start, exactly as the Content-Length
    ; path below does. Missing this made every chunked response a 502, which
    ; the /api/chunked control caught on the first run.
    mov rcx, r14
.hv_te_scan:
    cmp byte [r12 + rcx], 13
    je .hv_te_eol
    inc rcx
    jmp .hv_te_scan
.hv_te_eol:
    mov rdi, rcx                      ; the CR: walk back over trailing OWS
.hv_te_trim:
    cmp rdi, r14
    jbe .hv_bad                       ; an empty coding list
    movzx eax, byte [r12 + rdi - 1]
    cmp al, ' '
    je .hv_te_step
    cmp al, 9
    jne .hv_te_have
.hv_te_step:
    dec rdi
    jmp .hv_te_trim
.hv_te_have:
    sub rdi, r14                      ; the trimmed list's length
    cmp rdi, 7
    jne .hv_bad
    push rcx
    lea rdi, [r12 + r14]
    mov rsi, 7
    lea rdx, [hv_chunked]
    mov ecx, 7
    call linnea_string_iequal
    pop rcx
    test eax, eax
    jz .hv_bad                        ; a coding we do not remove
    jmp .hv_next_line
.hv_not_te:
    ; a Content-Length line: its value must agree with any earlier one
    cmp rbp, 14
    jne .hv_next_line
    lea rdi, [r12 + r15]
    sub rdi, rbp                      ; name start = colon - name length
    mov rsi, rbp
    lea rdx, [hn_content_len]
    mov rcx, 14
    call linnea_string_iequal
    test eax, eax
    jz .hv_next_line                  ; some other 14-char name
    ; the value is [r14, CR); re-find its CR to measure it
    mov rcx, r14
.hv_cl_scan:
    cmp byte [r12 + rcx], 13
    je .hv_cl_have
    inc rcx
    jmp .hv_cl_scan
.hv_cl_have:
    sub rcx, r14                      ; value length, TRAILING OWS included
    lea rdi, [r12 + r14]              ; value start (past the leading OWS)
    ; RFC 9112 5 puts OWS on BOTH sides of a field value. The leading half is
    ; skipped where the value starts, above; the trailing half was not, so
    ; "Content-Length:   5  " reached the number parser as "5  " and was refused
    ; as a non-number -- a 502 for a response that is perfectly legal. It went
    ; unnoticed while HTTP/2 was the only caller, because nothing pointed the
    ; /api/clpad fixture at h2; HTTP/1 had its own parser that trimmed both
    ; sides and served it, so sharing this validator is what surfaced it.
.hv_cl_trim:
    test rcx, rcx
    jz .hv_cl_measured                ; all whitespace: let the parser call it
    movzx eax, byte [rdi + rcx - 1]
    cmp al, ' '
    je .hv_cl_untrim
    cmp al, 9                         ; HTAB
    jne .hv_cl_measured
.hv_cl_untrim:
    dec rcx
    jmp .hv_cl_trim
.hv_cl_measured:
    mov rsi, rcx
    call linnea_string_to_u64         ; -> rax = value, edx = 0 ok / 1 / 2
    test edx, edx
    jnz .hv_bad                       ; a malformed or unrepresentable length
    cmp qword [rsp], 0
    je .hv_cl_first
    cmp rax, [rsp + 8]
    jne .hv_bad                       ; two Content-Lengths that disagree
    jmp .hv_next_line
.hv_cl_first:
    mov qword [rsp], 1
    mov [rsp + 8], rax
.hv_next_line:
    ; rcx is not the line cursor any more; re-find the CR from the value start
    mov rcx, r14
.hv_eol_scan:
    cmp byte [r12 + rcx], 13
    je .hv_eol_have
    inc rcx
    jmp .hv_eol_scan
.hv_eol_have:
    lea rax, [rcx + 2]
    cmp rax, r13
    ja .hv_bad
    cmp byte [r12 + rcx + 1], 10
    jne .hv_bad
    add rcx, 2
    jmp .hv_line
.hv_ok:
    ; --- Transfer-Encoding is forbidden outright on 1xx and 204 ---------
    ; RFC 9112 6.1, and an absolute prohibition rather than 205's conditional
    ; one: those statuses are terminated at the first empty line and cannot
    ; carry a body whatever the fields say, so the field can only mislead.
    ; Refused here so all three protocols answer the same way BEFORE any of
    ; them emits a head -- h1 used to emit an invalid 204 carrying the field
    ; while h2 and h3 scrubbed it into a clean success, and on an interim head
    ; h2 relayed a sanitised 103 and only then discovered the error, telling a
    ; client that early metadata was valid when the response was malformed
    ; (audit-report-12 Finding 1).
    cmp qword [rsp + 24], 0
    je .hv_te_status_ok               ; no Transfer-Encoding: nothing to judge
    mov rax, [rsp + 16]
    cmp rax, 204
    je .hv_bad
    cmp rax, 100
    jb .hv_te_status_ok
    cmp rax, 199
    jbe .hv_bad
.hv_te_status_ok:
    ; --- a 205 must not frame content -----------------------------------
    ; RFC 9110 15.3.6: a 205 implies no content and a server MUST NOT generate
    ; any. It differs from 204 in being ALLOWED a Content-Length -- to say zero
    ; -- so this is a contradiction test, not report 9's "no such field" rule.
    ; It is refused rather than normalised, and the reason is framing: dropping
    ; the body while relaying "Content-Length: 4" gives the client a different
    ; error, and dropping both leaves four bytes in the upstream buffer that the
    ; next response on a kept-alive connection would be read out of. A backend
    ; that contradicts itself is a bad gateway.
    ;
    ; Refusing Transfer-Encoding here is deliberately stricter than the letter,
    ; which permits an empty chunked section: we cannot know it is empty without
    ; reading it, and the alternative is relaying content on a status that must
    ; have none. Written down so it stays a decision.
    cmp qword [rsp + 16], 205
    jne .hv_ok_go
    cmp qword [rsp + 24], 0
    jne .hv_bad                       ; 205 + Transfer-Encoding
    cmp qword [rsp], 0
    je .hv_ok_go                      ; no Content-Length at all: no content
    cmp qword [rsp + 8], 0
    jne .hv_bad                       ; 205 announcing content
.hv_ok_go:
    mov eax, 1
    jmp .hv_ret
.hv_bad:
    xor eax, eax
.hv_ret:
    add rsp, 56
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_http_proxy_head(rdi=conn*) -> rax
;   LINNEA_HTTP_HEAD_MORE  (0): the head is not complete yet
;   LINNEA_HTTP_HEAD_READY (1): out_buf holds the rewritten head, the send
;                               window and body framing are set, state RELAY
;   LINNEA_HTTP_HEAD_BAD  (-1): malformed head; the caller answers 502
; The head passes through except Connection, which is replaced with the
; client's own keep-alive wish — and that wish only survives if the body
; length is known, since a close-delimited body is the only frame left.
; Locals:
;   [rsp+0] head end   [rsp+8] Content-Length   [rsp+16] flags: 1=CL, 2=TE
;   [rsp+24] line cursor  [rsp+32] CR offset    [rsp+40] header lines end
linnea_http_proxy_head:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64
    mov rbx, rdi
    lea r14, [rbx + linnea_connection.up_buf]
    mov r12, [rbx + linnea_connection.up_len]
    lea r15, [rbx + linnea_connection.out_buf]   ; out cursor, across every head
    ; Nothing is being relayed as chunked until this head says so. Cleared on
    ; every call, including the ones that return MORE, so a keep-alive
    ; connection cannot inherit the last response's answer.
    mov qword [rbx + linnea_connection.resp_chunked], 0
.head_start:
    ; r14 points at THIS head's first byte and r12 counts the bytes behind it.
    ; An interim head is relayed and stepped over, and the loop comes back here
    ; with both moved on. Every call re-parses from the very beginning, which is
    ; what lets an incomplete head return MORE and be handed the same bytes
    ; again without emitting the interim heads twice.
    mov qword [rsp + 8], 0
    mov qword [rsp + 16], 0
    mov qword [rsp + 48], 0    ; not an interim head until proven one
    mov qword [rsp + 56], 0    ; ...and nothing yet forbids a Content-Length
    ; the head ends at the first CRLF CRLF
    xor r13d, r13d
.scan:
    lea rax, [r13 + 4]
    cmp rax, r12
    ja .need_more
    cmp dword [r14 + r13], 0x0A0D0A0D
    je .found
    inc r13
    jmp .scan
.need_more:
    mov eax, LINNEA_HTTP_HEAD_MORE
    jmp .ret
.found:
    lea rax, [r13 + 4]
    mov [rsp], rax             ; head end
    add r13, 2
    mov [rsp + 40], r13        ; header lines end before the empty line's CRLF
    ; The whole field section is checked before any of it is rewritten toward
    ; the client (audit-report-6 Finding 1). h1 used to check only what it
    ; happened to parse for framing, so a backend line whose NAME was not a
    ; token -- "Bad Name: x" -- was relayed to the client verbatim, and a NUL
    ; in a value went with it. h2 had refused both since Finding 34; this is
    ; the same gate, now shared. r14 is the head buffer and [rsp] its length;
    ; the validator preserves r12/r13/r14 and the frame.
    push r13
    mov rdi, r14
    mov rsi, [rsp + 8]         ; head end (the push above moved the frame by 8)
    call linnea_http_upstream_head_valid
    pop r13
    test eax, eax
    jz .bad

    ; --- status line: "HTTP/1.x SSS ..." ----------------------------
    cmp qword [rsp], 13        ; "HTTP/1.1 200" + CRLF at the very least
    jb .bad
    mov rax, [r14]
    lea rcx, [version_11]
    cmp rax, [rcx]
    je .version_ok
    lea rcx, [version_10]
    cmp rax, [rcx]
    jne .bad
.version_ok:
    cmp byte [r14 + 8], ' '
    jne .bad
    xor eax, eax
    xor ecx, ecx
.status_loop:
    cmp ecx, 3
    jae .status_done
    movzx edx, byte [r14 + rcx + 9]
    sub edx, '0'
    cmp edx, 9
    ja .bad
    imul eax, eax, 10
    add eax, edx
    inc ecx
    jmp .status_loop
.status_done:
    ; A 1xx head is interim: forward it and keep reading for the response that
    ; matters -- RFC 9110 15.2 requires a proxy to forward 1xx. 101 is 1xx by
    ; number only; it ends HTTP on this connection and has its own path below.
    mov [rsp + 56], rax        ; the status, across the call
    mov edi, eax
    call linnea_http_status_no_clen
    mov rdx, [rsp + 56]
    mov [rsp + 56], rax        ; [56] now answers "must this carry no length?"
    cmp rdx, 199
    ja .head_final
    cmp rdx, 101
    je .head_final
    mov qword [rsp + 48], 1
    jmp .status_emit
.head_final:
    mov [rbx + linnea_connection.up_status], rdx
.status_emit:
    ; rewrite the version, then pass the rest of the line through
    lea rdi, [version_11_sp]
    mov esi, version_11_sp_len
    call .append
    mov rcx, 9
.status_eol_scan:
    cmp rcx, r13
    jae .bad
    cmp byte [r14 + rcx], 13
    je .status_eol_found
    inc rcx
    jmp .status_eol_scan
.status_eol_found:
    mov [rsp + 32], rcx
    lea rdi, [r14 + 9]
    mov rsi, rcx
    sub rsi, 9
    call .append
    lea rdi, [crlf]
    mov esi, 2
    call .append
    mov rcx, [rsp + 32]
    add rcx, 2
    mov [rsp + 24], rcx        ; first header line

    ; --- header lines ------------------------------------------------
.header_loop:
    mov rcx, [rsp + 24]
    cmp rcx, [rsp + 40]
    jae .header_done
    mov rdx, rcx
.eol_scan:
    cmp rdx, [rsp + 40]
    jae .bad                   ; the terminator guarantees a CR before here
    cmp byte [r14 + rdx], 13
    je .eol_found
    inc rdx
    jmp .eol_scan
.eol_found:
    mov [rsp + 32], rdx
    mov r8, rcx
.colon_scan:
    cmp r8, rdx
    jae .copy_line             ; no colon: pass it through untouched
    cmp byte [r14 + r8], ':'
    je .colon_found
    inc r8
    jmp .colon_scan
.colon_found:
    mov r13, r8                ; colon offset, for the value scan
    ; --- FRAMING FIRST: what delimits the message we RECEIVED -------------
    ; This used to come after the forwarding filters, and that ordering was a
    ; defect with a High severity attached to it. `Connection` says which fields
    ; are specific to this hop -- it does NOT unsay what they mean ON this hop,
    ; and RFC 9110 7.6.1 lists Transfer-Encoding among the fields an
    ; intermediary removes AFTER applying their semantics. So an upstream
    ; sending
    ;       Connection: Transfer-Encoding
    ;       Transfer-Encoding: chunked
    ; had the field correctly kept out of the downstream head and incorrectly
    ; kept out of our own framing decision: no flag was set, the response became
    ; close-delimited, and h1 relayed the chunk sizes and terminator to the
    ; client as content while h2 and h3 de-chunked the same response properly
    ; (audit-report-14 Finding 1).
    ;
    ; Removing a field from the message sent onward must happen after that field
    ; has delimited the message received. Both fields are read here; whether
    ; either is COPIED is decided at .fwd below, so a nominated Content-Length
    ; still frames this hop and still does not travel.
    mov rcx, [rsp + 24]
    mov rax, r13
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_content_len]
    mov ecx, 14
    call linnea_string_iequal
    test eax, eax
    jnz .content_len
    mov rcx, [rsp + 24]
    mov rax, r13
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_transfer_enc]
    mov ecx, 17
    call linnea_string_iequal
    test eax, eax
    jz .fwd
    ; Chunked. The flag is this hop's framing; the upstream's FIELD is never
    ; copied onward, because Transfer-Encoding describes one hop and the hop it
    ; describes downstream is ours. We state our own at .until_eof, exactly as
    ; Connection is replaced rather than relayed -- which also means a
    ; Connection-nominated Transfer-Encoding still frames this hop and still
    ; does not travel, instead of the framing being lost with the field
    ; (audit-report-14 Finding 1).
    or qword [rsp + 16], 2
    jmp .next_line
.fwd:
    ; --- and only now, what we FORWARD ------------------------------------
    ; The name comes from the FRAME, not from whatever r8 and rcx happen to
    ; hold. They used to be right because this ran first; the framing block now
    ; runs ahead of it and leaves neither intact -- linnea_string_iequal takes
    ; its length in ecx, and .content_len repurposes r8 as the value cursor. The
    ; Connection field therefore stopped being recognised and was FORWARDED,
    ; except when it happened to be the first field, where the stale ecx of 17
    ; coincided with the offset after "HTTP/1.1 200 OK" (audit-report-16).
    ;
    ; Beside report 15 that is a policy bypass, not just untidiness: the
    ; upstream names our own field in Connection, we correctly replace the
    ; discarded backend value with the configured one, and then hand the client
    ; the instruction to throw that replacement away. The two checks below have
    ; always reloaded from the frame; this one now does too.
    mov rcx, [rsp + 24]        ; this line's start
    mov rax, r13               ; ...and its colon, saved at .colon_found
    sub rax, rcx               ; header name length
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_connection]
    mov ecx, 10
    call linnea_string_iequal
    test eax, eax
    jz .not_conn_field
    ; Ours replaces it -- but read it first. A backend that says "close" is
    ; about to go, and parking that socket would hand the next request a race
    ; with its FIN. Connection is a #rule (RFC 9110 7.6.1), so the token matcher
    ; decides it, not a substring: "closed-loop" is not "close".
    mov rdi, r14
    add rdi, r13
    inc rdi                    ; just past the colon
    mov rsi, [rsp + 32]        ; end of line
    sub rsi, r13
    dec rsi
    lea rdx, [val_close_h1]
    mov ecx, 5
    call linnea_string_has_token     ; the #rule matcher every protocol shares
    test eax, eax
    jz .next_line
    mov qword [rbx + linnea_connection.up_no_reuse], 1
    jmp .next_line
.not_conn_field:
    ; The response side leaked these just as the request side did: a backend
    ; answering `Keep-Alive: timeout=5` had it relayed to a client whose
    ; connection to us has nothing to do with ours to the backend.
    mov rcx, [rsp + 24]
    mov rax, r13
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    call http_hop_by_hop
    test eax, eax
    jnz .next_line
    ; ...and every field THIS head's own Connection value names (RFC 9110
    ; 7.6.1). The fixed table above is only the half of the rule that was known
    ; when it was written; the value is the other half (audit-report-10
    ; Finding 2). Interim heads come through here too, on the same loop.
    mov rax, [rsp + 24]
    mov rcx, r13
    sub rcx, rax               ; name length
    lea rdx, [r14 + rax]       ; name pointer
    ; The one exception, and it is exactly as wide as its reason: on a 101 the
    ; backend's Upgrade line has to reach the client or the tunnel never
    ; completes -- there this proxy is a participant, not a bystander. It used
    ; to be a global exception inside the helper, which also let an ORDINARY
    ; 200 export Upgrade after we had replaced Connection with our own value
    ; (audit-report-11 Finding 1). up_status is already parsed here, and an
    ; interim head never reaches this with 101 in it.
    cmp qword [rbx + linnea_connection.up_status], 101
    jne .cn_ask
    cmp rcx, 7
    jne .cn_ask
    push rdx
    push rcx
    mov rdi, rdx
    mov rsi, rcx
    lea rdx, [hn_upgrade]
    mov ecx, 7
    call linnea_string_iequal
    pop rcx
    pop rdx
    test eax, eax
    jnz .copy_line             ; the tunnel's own Upgrade: forward it
.cn_ask:
    mov rdi, r14               ; the head it came from...
    mov rsi, [rsp]             ; ...and that head's length
    call linnea_http_head_conn_named
    test eax, eax
    jnz .next_line
    ; It travels -- so now it counts as the backend having set a policy. A
    ; field the backend nominated in Connection was dropped above and must NOT
    ; count, or naming your own Strict-Transport-Security silently turns the
    ; origin's off (audit-report-15 Finding 2).
    mov rax, [rsp + 24]
    mov rcx, r13
    sub rcx, rax               ; name length
    lea rdx, [r14 + rax]       ; name pointer
    cmp rcx, hn_sts_len
    jne .sec_try_sniff
    push rdx
    push rcx
    mov rdi, rdx
    mov rsi, rcx
    lea rdx, [hn_sts]
    mov ecx, hn_sts_len
    call linnea_string_iequal
    pop rcx
    pop rdx
    test eax, eax
    jz .sec_noted
    or qword [rsp + 16], 4
    jmp .sec_noted
.sec_try_sniff:
    cmp rcx, hn_xcto_len
    jne .sec_noted
    mov rdi, rdx
    mov rsi, rcx
    lea rdx, [hn_xcto]
    mov ecx, hn_xcto_len
    call linnea_string_iequal
    test eax, eax
    jz .sec_noted
    or qword [rsp + 16], 8
.sec_noted:
    jmp .copy_line             ; nothing forbade it: it travels. Without this
                               ; jump every surviving field fell into the
                               ; Content-Length parser below -- the framing
                               ; block used to sit here, and moving it left the
                               ; fall-through behind.
.content_len:
    ; A REPEATED Content-Length is no longer refused here. The shared validator
    ; at .found has already parsed every occurrence and rejected the head unless
    ; they all name the same length (RFC 9110 8.6), so by this point a repeat is
    ; a repeat of the same number and re-reading it is harmless. Refusing it
    ; here as well made h1 answer 502 where h2 and h3 answered 200 for the very
    ; same backend response -- the /api/cldupe fixture, which h2 has a test
    ; asserting is served (audit-report-6 Finding 1). The bit is still SET,
    ; because .header_done reads it as "a Content-Length was present at all".
    or qword [rsp + 16], 1
    ; value = [colon+1, CR), OWS-trimmed, digits only
    lea rcx, [r13 + 1]
    mov rdx, [rsp + 32]
.cl_ows:
    cmp rcx, rdx
    jae .bad
    movzx eax, byte [r14 + rcx]
    cmp al, ' '
    je .cl_ows_next
    cmp al, 9
    jne .cl_digits
.cl_ows_next:
    inc rcx
    jmp .cl_ows
.cl_digits:
    mov r8, rcx                ; first byte of the value, past the leading OWS
.cl_scan:
    cmp rcx, rdx
    jae .cl_parse
    movzx eax, byte [r14 + rcx]
    cmp al, ' '
    je .cl_parse
    cmp al, 9
    je .cl_parse
    inc rcx
    jmp .cl_scan
.cl_parse:
    ; [r8, rcx) is the value with its optional surrounding whitespace trimmed.
    ; The shared parser (audit-report-5 Finding 1) refuses an empty run, a byte
    ; that is not a digit, and a number past 2^64-1 -- all of them a bad gateway
    ; here, so the verdict it splits does not need splitting again. This loop
    ; had the bound right; it is converted anyway, because the point of the
    ; finding is that five copies of six instructions drifted apart and three
    ; ended up wrong. rcx and rdx are the line cursor and its end and the parser
    ; uses both, so they ride the stack across the call.
    push rcx
    push rdx
    lea rdi, [r14 + r8]
    mov rsi, rcx
    sub rsi, r8
    call linnea_string_to_u64
    mov r9d, edx               ; the verdict, BEFORE the pop puts the line end
    pop rdx                    ; back into rdx and takes edx with it
    pop rcx
    test r9d, r9d
    jnz .bad
    cmp rax, -1
    je .bad                    ; body_rem's -1 means "read until the upstream
                               ; closes"; a backend declaring exactly 2^64-1
                               ; bytes would turn a counted body into a
                               ; close-delimited one, as h2 and h3 also refuse
    mov [rsp + 8], rax
.cl_trail:
    ; only trailing whitespace may follow the digits: a value like
    ; "12 34" would frame the body as 12 while the client reads the
    ; header we copied verbatim and disagrees
    cmp rcx, rdx
    jae .cl_done
    movzx eax, byte [r14 + rcx]
    cmp al, ' '
    je .cl_trail_next
    cmp al, 9
    jne .bad
.cl_trail_next:
    inc rcx
    jmp .cl_trail
.cl_done:
    ; The value is parsed and stored either way -- a 204 naming a length that is
    ; not a number is still a bad gateway -- but on the two statuses where HTTP
    ; forbids the field it stops here instead of being copied out (RFC 9110 8.6,
    ; audit-report-9 Finding 2). It is dropped, not rewritten to 0: "no length"
    ; and "a length of zero" are different answers, and 204 means the first.
    cmp qword [rsp + 56], 0
    jne .next_line
    jmp .fwd                   ; framed; whether it travels is decided there
.copy_line:
    mov rcx, [rsp + 24]
    mov rdx, [rsp + 32]
    lea rdi, [r14 + rcx]
    mov rsi, rdx
    sub rsi, rcx
    add rsi, 2                 ; include the CRLF
    call .append
.next_line:
    mov rdx, [rsp + 32]
    add rdx, 2
    mov [rsp + 24], rdx
    jmp .header_loop

    ; --- an interim head: relay it, then go round for the next --------
    ; A 1xx is a complete message that frames no body, so it ends at its own
    ; blank line. h2 has relayed interim heads since Finding 30 and h3 since
    ; report 7; h1 did not, and took the first head it saw as THE response. A
    ; backend answering "103 Early Hints" with a Content-Length therefore had
    ; that length believed: the client got the interim as its final answer, with
    ; the first bytes of the real response consumed as the interim's body
    ; (audit-report-9 Finding 2). Nothing is appended per interim head beyond
    ; what the upstream sent, so out_buf's 64 bytes of slack over up_buf still
    ; covers the Via and Connection added to the final head, however many
    ; interim heads come before it.
.interim_done:
    test qword [rsp + 16], 2
    jnz .bad                   ; Transfer-Encoding on a bodiless head: refuse
    lea rdi, [crlf]
    mov esi, 2
    call .append               ; the blank line that ends it
    mov rax, [rsp]             ; this head's length
    add r14, rax               ; the next head begins where this one ended
    sub r12, rax
    jmp .head_start

    ; --- body framing and our own Connection header -------------------
.header_done:
    cmp qword [rsp + 48], 0
    jne .interim_done
    cmp qword [rbx + linnea_connection.up_status], 101
    je .upgrade_head
    ; Transfer-Encoding and Content-Length together contradict each other
    ; (RFC 9112 6.3: TE wins, and forwarding both is a response-splitting
    ; vector). Refuse the response rather than pick a side.
    mov rax, [rsp + 16]
    and rax, 3
    cmp rax, 3
    je .bad
    cmp qword [rbx + linnea_connection.is_head], 0
    jne .no_body               ; a HEAD response is head-only, whatever it claims
    ; 1xx, 204, 205 and 304 carry no content, whatever the head says. 205 was
    ; missing from all three of these lists (audit-report-10 Finding 1); the
    ; rule is one predicate now so they cannot disagree again.
    mov edi, [rbx + linnea_connection.up_status]
    call linnea_http_status_no_content
    test eax, eax
    jnz .no_body
    test qword [rsp + 16], 1
    jz .until_eof              ; no Content-Length: chunked or close-delimited
    mov rax, [rsp + 8]
    mov [rbx + linnea_connection.body_rem], rax
    jmp .conn_hdr
.no_body:
    mov qword [rbx + linnea_connection.body_rem], 0
    jmp .conn_hdr
.until_eof:
    mov qword [rbx + linnea_connection.body_rem], -1
    mov qword [rbx + linnea_connection.keep_alive], 0
    ; ...and if what we are relaying IS chunked, say so ourselves. Only here:
    ; a HEAD, a 304 or any other bodiless answer reaches .no_body instead and
    ; must not claim a framing it is not sending.
    test qword [rsp + 16], 2
    jz .conn_hdr
    lea rdi, [hdr_te_chunked]
    mov esi, hdr_te_chunked_len
    call .append
    ; ...and the relay is told, so it can run the chunk grammar over the bytes
    ; it forwards. HTTP/1 relays this body verbatim -- it has already sent this
    ; head -- so it cannot answer 502 the way h2 and h3 do. What it can do is
    ; refuse to finish: a malformed extension or trailer used to reach the
    ; client as a clean, complete 200 while the same upstream bytes were 502 on
    ; both binary protocols (audit-report-24). The state block is opened here,
    ; on the response whose framing it describes.
    mov qword [rbx + linnea_connection.resp_chunked], 1
    mov qword [rbx + linnea_connection.resp_chunk_state], LINNEA_CHUNK_SIZE
    mov qword [rbx + linnea_connection.resp_chunk_rem], 0
    mov qword [rbx + linnea_connection.resp_chunk_digits], 0
    mov qword [rbx + linnea_connection.resp_chunk_ext], LINNEA_CHUNK_EXT_START
    mov qword [rbx + linnea_connection.resp_chunk_raw], 0
.conn_hdr:
    lea rdi, [hdr_via_11]            ; and this one, on the way back
    mov esi, hdr_via_11_len
    call .append
    ; The vhost's configured policy rides a PROXIED response too: it describes
    ; the origin, not the backend. h2 and h3 have added it to proxied responses
    ; all along, and h1 added it to static heads and to its own error heads --
    ; but not to a successful proxied one, so the same origin's HSTS and nosniff
    ; were present or absent depending on which protocol the client negotiated
    ; (audit-report-15 Finding 1). A backend field that SURVIVED filtering still
    ; wins; one it nominated in Connection does not, because it never arrives.
    mov r8, [rbx + linnea_connection.vhost]
    test r8, r8
    jz .sec_done
    test qword [rsp + 16], 4
    jnz .sec_sniff
    cmp qword [r8 + linnea_config_server.hsts_len], 0
    je .sec_sniff
    lea rdi, [hdr_p_hsts]
    mov esi, hdr_p_hsts_len
    call .append
    mov r8, [rbx + linnea_connection.vhost]
    lea rdi, [r8 + linnea_config_server.hsts]
    mov rsi, [r8 + linnea_config_server.hsts_len]
    call .append
    lea rdi, [crlf]
    mov esi, 2
    call .append
    mov r8, [rbx + linnea_connection.vhost]
.sec_sniff:
    test qword [rsp + 16], 8
    jnz .sec_done
    cmp qword [r8 + linnea_config_server.nosniff], 0
    je .sec_done
    lea rdi, [hdr_p_nosniff]
    mov esi, hdr_p_nosniff_len
    call .append
.sec_done:
    cmp qword [rbx + linnea_connection.keep_alive], 0
    je .close_hdr
    lea rdi, [hdr_up_keepalive]
    mov esi, hdr_up_keepalive_len
    jmp .emit_conn
.close_hdr:
    lea rdi, [hdr_up_close]
    mov esi, hdr_up_close_len
.emit_conn:
    call .append

    ; body bytes that arrived with the head go out behind it. r12 counts from
    ; r14, so this is what followed THIS head -- not what followed any interim
    ; head already relayed.
    mov rax, r12
    sub rax, [rsp]             ; leftover
    mov rcx, [rbx + linnea_connection.body_rem]
    cmp rcx, -1
    je .leftover_set           ; until EOF: relay everything buffered
    cmp rax, rcx
    jbe .leftover_count
    mov rax, rcx               ; upstream overshot its Content-Length
.leftover_count:
    sub [rbx + linnea_connection.body_rem], rax
.leftover_set:
    mov [rbx + linnea_connection.file_rem], rax
    add [rbx + linnea_connection.relayed], rax
    mov rcx, [rsp]
    lea rdx, [r14 + rcx]
    mov [rbx + linnea_connection.file_ptr], rdx
    ; A chunked body is judged before it is forwarded, and this first piece is
    ; judged while the head is still sitting unsent in out_buf -- so a backend
    ; that writes its head and body in one go (which is most of them) gets the
    ; same 502 from HTTP/1 that h2 and h3 give. Only a malformation that arrives
    ; in a LATER read cannot be answered, and the relay closes on that one
    ; instead (audit-report-24). Read back from the connection rather than kept
    ; in registers: linnea_spill_chunked preserves the callee-saved ones this
    ; function is using, and nothing else here is worth carrying across a call.
    cmp qword [rbx + linnea_connection.resp_chunked], 0
    je .leftover_ok
    mov rdx, [rbx + linnea_connection.file_rem]
    test rdx, rdx
    jz .leftover_ok
    mov rdi, rbx
    mov rsi, [rbx + linnea_connection.file_ptr]
    lea rcx, [rbx + linnea_connection.resp_chunk_state]
    mov r8d, LINNEA_CHUNK_VALIDATE
    call linnea_spill_chunked
    cmp eax, -1
    je .bad                    ; malformed framing: 502, head not yet sent
.leftover_ok:
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_RELAY
    mov eax, LINNEA_HTTP_HEAD_READY
    jmp .ret

    ; --- 101: the upstream agreed to switch protocols ------------------
    ; Only meaningful when the client's upgrade wish was forwarded, and a
    ; 101 has no body, so any framing header on it is nonsense. The head
    ; goes out with our own "Connection: upgrade"; the Upgrade header has
    ; already passed through verbatim. Bytes past the head are the
    ; server's first tunnel bytes and are queued behind the head send.
    ; When it drains, the event loop switches to the full-duplex tunnel.
.upgrade_head:
    cmp qword [rbx + linnea_connection.upgrade], 0
    je .bad
    cmp qword [rsp + 16], 0    ; CL/TE flags
    jne .bad
    lea rdi, [hdr_up_upgrade]
    mov esi, hdr_up_upgrade_len
    call .append
    mov qword [rbx + linnea_connection.keep_alive], 0
    mov qword [rbx + linnea_connection.body_rem], 0
    mov rax, r12
    sub rax, [rsp]             ; leftover tunnel bytes, relayed verbatim
    mov [rbx + linnea_connection.file_rem], rax
    add [rbx + linnea_connection.relayed], rax
    mov rcx, [rsp]
    lea rdx, [r14 + rcx]
    mov [rbx + linnea_connection.file_ptr], rdx
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_UPGRADE
    mov eax, LINNEA_HTTP_HEAD_READY
    jmp .ret
.bad:
    mov eax, LINNEA_HTTP_HEAD_BAD
.ret:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .append(rdi=ptr, rsi=len) — r15 is the write cursor. out_buf carries
; enough slack over up_buf to hold the rewritten head (see the .inc).
.append:
    mov rcx, rsi
    mov rsi, rdi
    mov rdi, r15
    rep movsb
    mov r15, rdi
    ret

; ===================================================================
; chunked_decode(rdi = body start, rsi = bytes available)
;   -> rax = decoded length, rdx = encoded bytes the body occupied
;      rax = -1  the body is not complete yet: ask for more
;      rax = -2  malformed framing
;
; RFC 9112 7.1 MUST: "A server MUST be able to receive and decode the chunked
; transfer coding." Nothing here could: any Transfer-Encoding at all was
; answered 501, so every client that sends a body of unknown length up front —
; curl -T -, fetch() with a ReadableStream, most libraries handed a stream —
; was refused outright.
;
; Two passes, and the first one MUST NOT write. A body arrives across as many
; reads as the network feels like, and the caller re-parses from the start of
; the body each time more turns up; a walk that slid chunks down as it went
; would leave the buffer half-decoded, and the retry would parse the wreckage
; and call it malformed. So the first pass only measures, and nothing moves
; until the terminating chunk has actually been seen.
;
; Every length off the wire is checked against the bytes remaining BEFORE it is
; added to a cursor: a chunk size is up to 16 hex digits, and add-then-compare
; would wrap past the end and read on.
chunked_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov r12, rdi                      ; body start
    lea r13, [rdi + rsi]              ; end of what has arrived
    xor ebp, ebp                      ; pass: 0 = measure, 1 = move
.cd_pass:
    mov r14, r12                      ; read cursor
    mov r15, r12                      ; write cursor
.cd_chunk:
    xor ebx, ebx                      ; chunk size
    xor ecx, ecx                      ; hex digits seen
.cd_size:
    cmp r14, r13
    jae .cd_more
    movzx eax, byte [r14]
    cmp al, '0'
    jb .cd_size_done
    cmp al, '9'
    jbe .cd_digit
    or al, 0x20                       ; fold A-F to a-f
    cmp al, 'a'
    jb .cd_size_done
    cmp al, 'f'
    ja .cd_size_done
    sub al, 'a' - 10
    jmp .cd_accum
.cd_digit:
    sub al, '0'
.cd_accum:
    ; The bound goes through a register because 0x0fffffffffffffff does not fit
    ; in the sign-extended imm32 a "cmp r64, imm" carries: nasm truncated it to
    ; 0xff and both compares became "above 2^64-1", which nothing is. The two
    ; other chunk decoders load it into a register and so were never affected,
    ; which is why a 17-digit size was 400 the moment the body grew past in_buf
    ; and accepted below it. It assembled with a warning for as long as it has
    ; existed; `make 2>&1 | grep warning` is now silent, so the next one shows.
    mov r8, 0x0fffffffffffffff
    cmp rbx, r8
    ja .cd_bad                        ; a size no body could ever have
    shl rbx, 4
    movzx eax, al
    or rbx, rax
    cmp rbx, r8                       ; ...and after the shift too: the test
    ja .cd_bad                        ; above only stops the shift overflowing
    inc rcx
    inc r14
    jmp .cd_size
.cd_size_done:
    test rcx, rcx
    jz .cd_bad                        ; no digits: not a chunk header
    ; chunk = chunk-size [ chunk-ext ] CRLF, and everything between the digits
    ; and the CR is judged by linnea_chunk_ext_step -- the one place the
    ; extension grammar lives, because it has to hold identically in the two
    ; decoders that split at LINNEA_CONN_IN_BUF and in h2's. This scanned a
    ; byte CLASS instead: first anything but LF (so "4 ", "4g" and "4\0" were a
    ; size of four, audit-report-22), then anything printable (so "4;=bad" and
    ; "4;a=\"unterminated" were well-formed chunk headers, audit-report-23).
    mov r9d, LINNEA_CHUNK_EXT_START   ; at a component boundary
.cd_ext:
    cmp r14, r13
    jae .cd_more
    movzx esi, byte [r14]
    mov rdi, r9
    call linnea_chunk_ext_step
    cmp rax, -2
    je .cd_size_crlf                  ; the CR that ends the size line
    cmp rax, -1
    je .cd_bad
    mov r9, rax
    inc r14
    jmp .cd_ext
.cd_size_crlf:
    lea rax, [r14 + 2]
    cmp rax, r13
    ja .cd_more
    cmp byte [r14 + 1], 10
    jne .cd_bad
    add r14, 2
    test rbx, rbx
    jz .cd_last                       ; a zero-size chunk ends the body
    mov rax, r13
    sub rax, r14                      ; bytes actually here
    cmp rbx, rax
    ja .cd_more                       ; the data has not all arrived
    test ebp, ebp
    jz .cd_skip_data                  ; measuring: touch nothing
    mov rcx, rbx
    mov rdi, r15
    mov rsi, r14
    rep movsb                         ; slide it down over its header
    mov r15, rdi
    jmp .cd_after_data
.cd_skip_data:
    add r15, rbx
.cd_after_data:
    add r14, rbx
    lea rax, [r14 + 2]
    cmp rax, r13
    ja .cd_more
    cmp byte [r14], 13
    jne .cd_bad
    cmp byte [r14 + 1], 10
    jne .cd_bad
    add r14, 2
    jmp .cd_chunk
.cd_last:
    ; the trailer section: field lines until an empty one. They are dropped — a
    ; trailer that reached the request could change the answer to it, the same
    ; rule HTTP/2 and HTTP/3 follow for theirs.
.cd_trailer:
    cmp r14, r13
    jae .cd_more
    cmp byte [r14], ':'
    je .cd_bad                        ; a field line with an empty name
    cmp byte [r14], 13
    je .cd_trailer_end
.cd_trailer_line:
    ; A trailer section is made of HTTP field LINES. Rejecting a bare LF made
    ; the DELIMITERS right without making the line a field, so a colonless line
    ; or a NUL in a value still completed the message (audit-report-21). This
    ; decoder re-parses from the body start on every call, so the name/value
    ; split needs no persistent state -- unlike the h2 and h3 state machines,
    ; which gained a state each for the same rule.
    cmp r14, r13
    jae .cd_more
    cmp byte [r14], ':'
    je .cd_trailer_val
    cmp byte [r14], 13
    je .cd_bad                        ; no colon: not a field line
    cmp byte [r14], 10
    je .cd_bad
    movzx edi, byte [r14]
    call linnea_string_is_tchar
    test eax, eax
    jz .cd_bad
    inc r14
    jmp .cd_trailer_line
.cd_trailer_val:
    inc r14
.cd_trailer_val_scan:
    cmp r14, r13
    jae .cd_more
    cmp byte [r14], 13
    je .cd_trailer_crlf
    cmp byte [r14], 10
    je .cd_bad
    cmp byte [r14], 9
    je .cd_trailer_val_next           ; HTAB is legal in a value
    cmp byte [r14], 0x20
    jb .cd_bad                        ; any other control byte is not
    cmp byte [r14], 0x7f
    je .cd_bad                        ; DEL
.cd_trailer_val_next:
    inc r14
    jmp .cd_trailer_val_scan
.cd_trailer_crlf:
    lea rax, [r14 + 2]
    cmp rax, r13
    ja .cd_more
    cmp byte [r14 + 1], 10
    jne .cd_bad
    add r14, 2
    jmp .cd_trailer
.cd_trailer_end:
    lea rax, [r14 + 2]
    cmp rax, r13
    ja .cd_more
    cmp byte [r14 + 1], 10
    jne .cd_bad
    add r14, 2
    ; the body is whole. On the measuring pass, go round again and move it.
    test ebp, ebp
    jnz .cd_done
    mov ebp, 1
    jmp .cd_pass
.cd_done:
    mov rax, r15
    sub rax, r12                      ; decoded length
    mov rdx, r14
    sub rdx, r12                      ; what the encoded body occupied
    jmp .cd_ret
.cd_more:
    mov rax, -1
    xor edx, edx
    jmp .cd_ret
.cd_bad:
    mov rax, -2
    xor edx, edx
.cd_ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
