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
global linnea_http_proxy_head
global linnea_http_proxy_log

LINNEA_HTTP_MAX_METHOD  equ 32
LINNEA_HTTP_MAX_TARGET  equ 2048
; The decoded path is built at LINNEA_HTTP_PATH_ROOT so a matched
; location's root can be prepended in place, without moving the path:
; root (255) + target (2048) + "/index.html" + NUL always fits.
LINNEA_HTTP_PATH_ROOT   equ LINNEA_MAX_ROOT + 1
LINNEA_HTTP_PATH_BUF    equ 2560

extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_from_hex_u64
extern linnea_string_equal
extern linnea_string_is_token
extern linnea_string_iequal
extern linnea_time_http_date
extern linnea_time_parse_http_date
extern linnea_time_http_now
; request-evaluation helpers shared with the h2/h3 serve paths; they live in
; linnea_static.asm so the h3 test binaries link without this file's deps
extern linnea_http_ae_accepts
extern linnea_http_inm_match
extern linnea_http_etag_match
extern linnea_http_ifrange_match
extern linnea_http_range_parse
extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp

extern linnea_upstream_count
extern linnea_upstream_open
extern linnea_upstream_closed
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
; "OPTIONS *": what this server supports, as a whole. Bodiless, like every
; other canned response, and it keeps the connection (nothing went wrong).
slash_target:   db "/"
resp_options:   db "HTTP/1.1 200 OK", 13, 10
                db "Allow: GET, HEAD, OPTIONS", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10, 13, 10
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
resp_414:       db "HTTP/1.1 414 URI Too Long", 13, 10
                db "Server: linnea", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_414_len    equ $ - resp_414
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
hdr_cl_up:      db "Content-Length: "
hdr_cl_up_len   equ $ - hdr_cl_up
hdr_crlf_up:    db 13, 10
hdr_up_close:   db "Connection: close", 13, 10, 13, 10
hdr_up_close_len equ $ - hdr_up_close
hdr_up_keepalive: db "Connection: keep-alive", 13, 10, 13, 10
hdr_up_keepalive_len equ $ - hdr_up_keepalive
hdr_up_upgrade: db "Connection: upgrade", 13, 10, 13, 10
hdr_up_upgrade_len equ $ - hdr_up_upgrade
req_version:    db " HTTP/1.1", 13, 10
req_version_len equ $ - req_version
version_11_sp:  db "HTTP/1.1 "
version_11_sp_len equ $ - version_11_sp

version_11:     db "HTTP/1.1"          ; 8 bytes, compared as one qword
version_10:     db "HTTP/1.0"          ; accepted from an upstream, rewritten
crlf:           db 13, 10
crlfcrlf:       db 13, 10, 13, 10
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
; the protocol closes the quoted request, as the Common Log Format has it.
; Every request this handler accepts is HTTP/1.1 — the version check admits
; nothing else — so it is a constant here.
log_proto11:    db " HTTP/1.1"
log_proto11_len equ $ - log_proto11
log_dash:       db "-"
log_sp:         db " "
log_nl:         db 10

hn_connection:  db "connection"
hn_content_len: db "content-length"
hn_transfer_enc: db "transfer-encoding"
hn_host:        db "host"
hn_expect:      db "expect"
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
; http_conn_option_named — but these are connection-specific on their own and
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
hop_by_hop_names:
    db 10, "keep-alive"
    db  2, "te"
    db  7, "trailer"
    db 16, "proxy-connection"
    db 18, "proxy-authenticate"
    db 19, "proxy-authorization"
    db  0
hv_close:       db "close"
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
;   [rsp+304] asterisk-form: the target was "*", so the request is about the
;             server itself rather than any resource (OPTIONS *)

; http_hop_by_hop(rdi = field name, rsi = name length) -> rax = 1 if the field
; must not cross this hop, whatever Connection says. See hop_by_hop_names.
;
; Touches neither r10 nor r13 — the two rewriters keep their colon offset in
; those across the comparisons, and linnea_string_iequal leaves them alone.
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

; http_conn_option_named(rdi = field name, rsi = name length, rbx = connection)
;   -> eax = 1 when the client's Connection field lists this name.
;
; RFC 9110 7.6.1 MUST: an intermediary parses Connection before forwarding and
; removes every field the value names, then Connection itself. Only Connection
; and Expect were being dropped, so a client sending
;     Connection: X-Auth-Bypass
;     X-Auth-Bypass: 1
; had X-Auth-Bypass delivered to the backend as an ordinary end-to-end field.
; That is the header-smuggling shape the requirement exists to close: the client
; marks a field hop-by-hop, we forward it anyway, and the backend cannot tell it
; was never meant to arrive.
;
; `upgrade` is deliberately not matched. The upgrade path re-emits Connection:
; upgrade itself and relies on the client's Upgrade field being forwarded, so
; treating that one token as a removal instruction would break the tunnel the
; server is setting up — there the intermediary is a participant, not a
; bystander.
;
; Everything the loop needs lives in callee-saved registers, so no value has to
; be pushed across the comparison calls and the stack parity the caller left is
; untouched.
http_conn_option_named:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                      ; the name we are asking about
    mov r13, rsi
    mov r14, [rbx + linnea_connection.conn_opts]
    test r14, r14
    jz .cn_no                         ; no Connection field at all
    mov r15, r14
    add r15, [rbx + linnea_connection.conn_opts_len]   ; value end
.cn_tok:
    cmp r14, r15
    jae .cn_no
    movzx ecx, byte [r14]
    cmp cl, ','
    je .cn_step
    cmp cl, ' '
    je .cn_step
    cmp cl, 9
    je .cn_step
    mov rbp, r14                      ; token start; find its end
.cn_end:
    cmp rbp, r15
    jae .cn_have
    movzx ecx, byte [rbp]
    cmp cl, ','
    je .cn_have
    cmp cl, ' '
    je .cn_have
    cmp cl, 9
    je .cn_have
    inc rbp
    jmp .cn_end
.cn_have:
    mov rcx, rbp
    sub rcx, r14                      ; token length
    cmp rcx, r13
    jne .cn_next                      ; lengths differ: cannot match
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    call linnea_string_iequal
    test eax, eax
    jz .cn_next
    ; a match — unless it is `upgrade`, which this server forwards on purpose
    mov rdi, r14
    mov rsi, rbp
    sub rsi, r14
    lea rdx, [hn_upgrade]
    mov ecx, 7
    call linnea_string_iequal
    test eax, eax
    jnz .cn_no                        ; the upgrade token names a field we keep
    mov eax, 1
    jmp .cn_ret
.cn_next:
    mov r14, rbp                      ; resume after this token
    jmp .cn_tok
.cn_step:
    inc r14
    jmp .cn_tok
.cn_no:
    xor eax, eax
.cn_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


linnea_http_handle:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 352               ; +32 for the two precondition fields
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
    mov qword [rsp + 176], 0   ; no If-None-Match yet
    mov qword [rsp + 192], 0   ; no If-Modified-Since yet
    mov qword [rsp + 208], 0   ; no Accept-Encoding yet
    mov qword [rsp + 224], 0   ; nothing negotiated
    mov qword [rsp + 232], 0   ; no upgrade asked
    mov qword [rbx + linnea_connection.conn_opts], 0      ; no Connection field yet
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
    cmp rax, LINNEA_HTTP_MAX_TARGET
    ja .resp_400
    inc r15                    ; skip the SP

    ; --- request-target forms (RFC 9112 3.2) ----------------------
    ; Only origin-form ("/path") used to survive: everything else reached the
    ; path normalizer and came back 400. absolute-form is one a server MUST
    ; accept, and asterisk-form is how OPTIONS asks about the server itself.
    ; Both are recognised here, before the target is used for anything.
    mov qword [rsp + 304], 0   ; not an OPTIONS * request
    mov qword [rsp + 312], 0   ; If-Match absent
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
.target_form_done:

    ; --- version: exactly "HTTP/1.1" CRLF -------------------------
    lea rax, [r15 + 8]
    cmp rax, r13
    ja .resp_400
    mov rax, [r14 + r15]
    mov rcx, [version_11]
    cmp rax, rcx
    jne .version_other
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
    ; keep the value: every token in it names a field the proxy must not forward
    mov rax, [rsp + 72]
    mov [rbx + linnea_connection.conn_opts], rax
    mov rax, [rsp + 80]
    mov [rbx + linnea_connection.conn_opts_len], rax
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    lea rdx, [hv_close]
    mov ecx, 5
    call linnea_string_iequal
    test eax, eax
    jz .conn_tokens
    mov qword [rsp + 24], 0
    jmp .header_next
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
    mov rdi, rax
    mov rsi, rdx
    sub rsi, rax               ; token length
    mov [rsp + 56], rdx        ; resume after this token
    lea rdx, [hn_upgrade]
    mov ecx, 7
    call linnea_string_iequal
    test eax, eax
    jz .conn_tok_start
    or qword [rsp + 232], 1    ; the client asks to upgrade
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
.ifm_header:                   ; first occurrence wins, as for Host
    cmp qword [rsp + 312], 0
    jne .header_next
    mov rax, [rsp + 72]
    mov [rsp + 312], rax
    mov rax, [rsp + 80]
    mov [rsp + 320], rax
    jmp .header_next
.ius_header:
    cmp qword [rsp + 328], 0
    jne .header_next
    mov rax, [rsp + 72]
    mov [rsp + 328], rax
    mov rax, [rsp + 80]
    mov [rsp + 336], rax
    jmp .header_next
.inm_header:                   ; first occurrence wins, as for Host
    cmp qword [rsp + 176], 0
    jne .header_next
    mov rax, [rsp + 72]
    mov [rsp + 176], rax
    mov rax, [rsp + 80]
    mov [rsp + 184], rax
    jmp .header_next
.ims_header:
    cmp qword [rsp + 192], 0
    jne .header_next
    mov rax, [rsp + 72]
    mov [rsp + 192], rax
    mov rax, [rsp + 80]
    mov [rsp + 200], rax
    jmp .header_next
.ae_header:
    cmp qword [rsp + 208], 0
    jne .header_next
    mov rax, [rsp + 72]
    mov [rsp + 208], rax
    mov rax, [rsp + 80]
    mov [rsp + 216], rax
    jmp .header_next
.range_header:                 ; first occurrence wins, as for Host
    cmp qword [rsp + 240], 0
    jne .header_next
    mov rax, [rsp + 72]
    mov [rsp + 240], rax
    mov rax, [rsp + 80]
    mov [rsp + 248], rax
    jmp .header_next
.ifr_header:
    cmp qword [rsp + 256], 0
    jne .header_next
    mov rax, [rsp + 72]
    mov [rsp + 256], rax
    mov rax, [rsp + 80]
    mov [rsp + 264], rax
    jmp .header_next
.cl_header:
    test qword [rsp + 136], 1
    jnz .resp_400              ; duplicate Content-Length
    or qword [rsp + 136], 1
    mov rsi, [rsp + 72]        ; value must be all digits
    mov rcx, [rsp + 80]
    test rcx, rcx
    jz .resp_400
    mov r9, 1 << 32
    xor eax, eax
    xor edx, edx
.cl_digits:
    cmp rdx, rcx
    jae .cl_done
    movzx r8d, byte [rsi + rdx]
    sub r8d, '0'
    cmp r8d, 9
    ja .resp_400
    imul rax, rax, 10
    add rax, r8
    cmp rax, r9
    ja .resp_413
    inc rdx
    jmp .cl_digits
.cl_done:
    mov [rsp + 128], rax
    jmp .header_next
.te_header:
    ; "chunked" is the one coding we implement (RFC 9112 7.1 makes receiving it
    ; a MUST); anything else still earns a 501. Bit 2 is "a coding we cannot
    ; do", bit 4 is "chunked".
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    lea rdx, [hv_chunked]
    mov ecx, 7
    call linnea_string_iequal
    test eax, eax
    jz .te_unsupported
    or qword [rsp + 136], 4
    jmp .header_next
.te_unsupported:
    or qword [rsp + 136], 2
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
    ; an authority. Every request we accept is HTTP/1.1 (the version check
    ; above admits nothing else), so the header is mandatory — and a missing
    ; or repeated one is how a request gets routed one way here and another
    ; way at an intermediary. This runs before the asterisk-form branch below:
    ; "OPTIONS *" carries no authority of its own, so it is exactly the request
    ; whose Host an intermediary would read differently, and the rule is not
    ; waived for it.
    cmp qword [rsp + 296], 1
    jne .resp_400
    mov rcx, [rsp + 96]
    test rcx, rcx
    jz .resp_400               ; "Host:" with no authority at all
    mov rdx, [rsp + 88]
.host_char:
    movzx eax, byte [rdx]
    cmp al, 0x20
    jbe .resp_400              ; space or control byte inside the authority
    cmp al, 0x7f
    je .resp_400
    inc rdx
    dec rcx
    jnz .host_char
    test qword [rsp + 136], 2
    jnz .resp_501                      ; a coding we do not implement
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
    jae .resp_413
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
.not_chunked:
    mov rax, [rbx + linnea_connection.head_len]
    add rax, [rsp + 128]
    cmp rax, LINNEA_CONN_IN_BUF
    ja .body_stream
    cmp rax, [rbx + linnea_connection.in_len]
    jbe .body_ready
    mov eax, LINNEA_HTTP_NEED_MORE
    jmp .ret
.body_stream:
    ; keep the head consumed and hand the routing whatever body bytes have
    ; already arrived; the rest follows through the same buffer
    mov qword [rsp + 288], 1
    mov rcx, [rbx + linnea_connection.in_len]
    sub rcx, [rbx + linnea_connection.head_len]      ; body bytes in hand
    mov rax, [rsp + 128]
    sub rax, rcx                                     ; still to come
    mov [rbx + linnea_connection.req_body_rem], rax
    mov [rsp + 128], rcx       ; what .proxy_start queues behind the head
    mov rax, [rbx + linnea_connection.in_len]
.body_ready:
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
    mov rsi, [rsp + 88]
    xor edx, edx
.host_port_scan:
    cmp rdx, rcx
    jae .host_port_done
    cmp byte [rsi + rdx], ':'
    je .host_port_found
    inc rdx
    jmp .host_port_scan
.host_port_found:
    mov rcx, rdx
.host_port_done:
    mov [rsp + 96], rcx
    test rcx, rcx
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
    mov [rsp + 168], r9        ; the compares below clobber r9
    mov qword [rsp + 152], 0   ; best location*
    mov qword [rsp + 160], 0   ; best prefix len
    mov r10, [r12 + linnea_config_server.location_count]
    xor r11d, r11d             ; location index
.loc_loop:
    cmp r11, r10
    jae .loc_done
    imul rax, r11, linnea_config_location_size
    lea rax, [r12 + rax + linnea_config_server.locations]
    mov rcx, [rax + linnea_config_location.prefix_len]
    cmp rcx, r8
    ja .loc_next               ; prefix longer than the path
    cmp rcx, [rsp + 160]
    jbe .loc_next              ; not longer than the best match so far
    ; compare the first prefix_len bytes of the path
    mov [rsp + 56], rax        ; candidate location*
    mov [rsp + 64], r8
    mov [rsp + 72], r10
    mov [rsp + 80], r11
    mov rdi, r13
    mov rsi, rcx
    lea rdx, [rax + linnea_config_location.prefix]
    call linnea_string_equal
    mov r11, [rsp + 80]
    mov r10, [rsp + 72]
    mov r8, [rsp + 64]
    test eax, eax
    jz .loc_next
    mov rax, [rsp + 56]
    mov [rsp + 152], rax
    mov rcx, [rax + linnea_config_location.prefix_len]
    mov [rsp + 160], rcx
.loc_next:
    inc r11
    jmp .loc_loop
.loc_done:
    mov rax, [rsp + 152]
    test rax, rax
    jz .resp_404               ; no location claims this path
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    je .proxy_start
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    je .redirect_check

    ; --- static location ---------------------------------------------
    cmp qword [rsp + 288], 0
    jne .resp_413              ; only a proxy streams a body this large
    cmp qword [rsp], -1
    je .resp_405               ; files are GET/HEAD only
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
    mov rdi, [rsp + 208]
    mov rsi, [rsp + 216]
    lea rdx, [enc_br]
    mov ecx, enc_br_len
    call linnea_http_ae_accepts
    test eax, eax
    jz .try_gzip
    mov dword [r15], '.br'     ; three bytes and the NUL
    mov rdi, r13
    call .open_regular
    test eax, eax
    js .try_gzip
    mov qword [rsp + 224], 2
    jmp .have_file
.try_gzip:
    mov rdi, [rsp + 208]
    mov rsi, [rsp + 216]
    lea rdx, [enc_gzip]
    mov ecx, enc_gzip_len
    call linnea_http_ae_accepts
    test eax, eax
    jz .open_plain
    mov dword [r15], '.gz'
    mov rdi, r13
    call .open_regular
    test eax, eax
    js .open_plain
    mov qword [rsp + 224], 1
    jmp .have_file
.open_plain:
    mov byte [r15], 0          ; drop whichever suffix was tried
    mov qword [rsp + 224], 0
    mov rdi, r13
    call .open_regular
    test eax, eax
    js .resp_404
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
    mov rdi, [rsp + 312]
    mov rsi, [rsp + 320]
    lea rdx, [etag_buf]
    mov rcx, [etag_len]
    mov r8d, 1                 ; If-Match compares strongly (13.1.1)
    call linnea_http_etag_match
    test eax, eax
    jz .resp_412
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
    mov rdi, [rsp + 176]
    mov rsi, [rsp + 184]
    lea rdx, [etag_buf]
    mov rcx, [etag_len]
    call linnea_http_inm_match
    test eax, eax
    jnz .resp_304
    jmp .send_full             ; a mismatch overrides any If-Modified-Since
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
.proxy_start:
    mov [rbx + linnea_connection.location], rax
    ; the client head is rewritten into up_buf (method + target + our version
    ; and Connection lines + every client header verbatim). up_buf is smaller
    ; than in_buf, and .append is an unchecked rep movsb, so bound the head
    ; first: a head that fits in_buf but not up_buf would otherwise overrun the
    ; slot into the next connection. head_len here spans the buffered body too
    ; (set at .body_ready), so subtract it — the pure head is what gets copied,
    ; exactly as the copy loop computes its limit. Upper bound = pure head + the
    ; longest Connection line we add + the request-line rewrite slack.
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
    lea rdi, [req_version]
    mov esi, req_version_len
    call .append
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
    ; The whole body is already buffered, so there is nothing left for the
    ; upstream to authorize: forwarding Expect would only invite a 100
    ; Continue, which this exchange has no way to handle.
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_expect]
    mov ecx, 6
    call linnea_string_iequal
    test eax, eax
    jnz .proxy_next_line
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
    ; and every field the client's own Connection value names (RFC 9110 7.6.1)
    mov rcx, [rsp + 56]
    mov rax, r10
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    call http_conn_option_named
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
    call linnea_upstream_count
    cmp rax, [linnea_upstream_limit]
    jae .resp_503
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
.resp_413:
    lea rax, [resp_413]
    mov ecx, resp_413_len
    mov qword [rsp + 112], 413
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
    call linnea_log_stamp
    lea rdi, [log_req]
    mov esi, log_req_len
    call linnea_log_write
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
    lea rdi, [log_proto11]
    mov esi, log_proto11_len
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
    add rsp, 352
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
    test rcx, rcx
    jz .heb_asis
    cmp qword [rcx + linnea_config_server.hsts_len], 0
    jne .heb_copy
    cmp qword [rcx + linnea_config_server.nosniff], 0
    jne .heb_copy
.heb_asis:
    mov rax, rsi
    ret
.heb_copy:
    push rbx
    push r12
    push r15
    mov rbx, rcx                     ; server*
    mov r12, rdi                     ; conn*
    lea r15, [rdi + linnea_connection.out_buf]
    mov rdi, r15                     ; the blob without its blank line
    mov rcx, rdx
    sub rcx, 4
    rep movsb
    mov r15, rdi
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
    inc r8
    jmp .ta_auth
.ta_path:
    mov rax, r8                      ; the path begins at that '/'
    mov rdx, r9
    sub rdx, r8                      ; its length
    sub r8, rcx                      ; authority length
    test r8, r8
    jz .ta_no                        ; "http:///path" names nothing
    pop rbx
    ret
.ta_root:
    sub r8, rcx                      ; authority length
    test r8, r8
    jz .ta_no
    lea rax, [slash_target]          ; the root, since the target gave no path
    mov rdx, 1
    pop rbx
    ret
.ta_no:
    xor eax, eax
    pop rbx
    ret

; --- proxying ----------------------------------------------------------

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
    sub rsp, 32
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
    sub r15, r13
    mov [rsp + 24], r15        ; target len
    add r13, r14               ; target ptr
    call linnea_log_stamp
    lea rdi, [log_req]
    mov esi, log_req_len
    call linnea_log_write
    mov rax, [rbx + linnea_connection.vhost]
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
    mov rdi, r14
    mov rsi, [rsp + 16]
    call linnea_log_write
    lea rdi, [log_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, r13
    mov rsi, [rsp + 24]
    call linnea_log_write
    lea rdi, [log_proto11]
    mov esi, log_proto11_len
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
    add rsp, 32
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
    lea rax, [resp_502]
    mov ecx, resp_502_len
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

; linnea_http_proxy_log(rdi=conn*) — the completion log line for a proxied
; request: the upstream's status and the body bytes actually relayed.
linnea_http_proxy_log:
    mov rsi, [rdi + linnea_connection.up_status]
    mov rdx, [rdi + linnea_connection.relayed]
    jmp linnea_http_log_conn

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
    sub rsp, 48
    mov rbx, rdi
    lea r14, [rbx + linnea_connection.up_buf]
    mov r12, [rbx + linnea_connection.up_len]
    mov qword [rsp + 8], 0
    mov qword [rsp + 16], 0
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
    mov [rbx + linnea_connection.up_status], rax
    ; rewrite the version, then pass the rest of the line through
    lea r15, [rbx + linnea_connection.out_buf]
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
    mov rax, r8
    sub rax, rcx               ; header name length
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_connection]
    mov ecx, 10
    call linnea_string_iequal
    test eax, eax
    jnz .next_line             ; ours replaces it
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
    jz .copy_line
    or qword [rsp + 16], 2     ; chunked: the framing is the upstream's
    jmp .copy_line
.content_len:
    test qword [rsp + 16], 1
    jnz .bad                   ; duplicate Content-Length
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
    xor r8d, r8d               ; value
    xor r9d, r9d               ; digit count
.cl_loop:
    cmp rcx, rdx
    jae .cl_done
    movzx eax, byte [r14 + rcx]
    cmp al, ' '
    je .cl_trail
    cmp al, 9
    je .cl_trail
    sub eax, '0'
    cmp eax, 9
    ja .bad
    imul r8, r8, 10
    add r8, rax
    mov r10, 1 << 32
    cmp r8, r10
    ja .bad
    inc r9d
    inc rcx
    jmp .cl_loop
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
    test r9d, r9d
    jz .bad                    ; empty value
    mov [rsp + 8], r8
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

    ; --- body framing and our own Connection header -------------------
.header_done:
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
    mov rax, [rbx + linnea_connection.up_status]
    cmp rax, 204
    je .no_body
    cmp rax, 304
    je .no_body
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
.conn_hdr:
    lea rdi, [hdr_via_11]            ; and this one, on the way back
    mov esi, hdr_via_11_len
    call .append
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

    ; body bytes that arrived with the head go out behind it
    mov rax, [rbx + linnea_connection.up_len]
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
    mov rax, [rbx + linnea_connection.up_len]
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
    add rsp, 48
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
    cmp rbx, 0x0fffffffffffffff
    ja .cd_bad                        ; a size no body could ever have
    shl rbx, 4
    movzx eax, al
    or rbx, rax
    inc rcx
    inc r14
    jmp .cd_size
.cd_size_done:
    test rcx, rcx
    jz .cd_bad                        ; no digits: not a chunk header
.cd_ext:                              ; chunk-ext runs to the CRLF, ignored
    cmp r14, r13
    jae .cd_more
    cmp byte [r14], 13
    je .cd_size_crlf
    cmp byte [r14], 10
    je .cd_bad                        ; a bare LF is not a line ending here
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
    cmp byte [r14], 13
    je .cd_trailer_end
.cd_trailer_line:
    cmp r14, r13
    jae .cd_more
    cmp byte [r14], 13
    je .cd_trailer_crlf
    inc r14
    jmp .cd_trailer_line
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
