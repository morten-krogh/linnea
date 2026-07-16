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
extern linnea_string_iequal
extern linnea_time_http_date
extern linnea_time_parse_http_date
extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp

section .rodata

resp_400:       db "HTTP/1.1 400 Bad Request", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_400_len    equ $ - resp_400
resp_404:       db "HTTP/1.1 404 Not Found", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_404_len    equ $ - resp_404
resp_405:       db "HTTP/1.1 405 Method Not Allowed", 13, 10
                db "Allow: GET, HEAD", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_405_len    equ $ - resp_405
resp_413:       db "HTTP/1.1 413 Content Too Large", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_413_len    equ $ - resp_413
resp_431:       db "HTTP/1.1 431 Request Header Fields Too Large", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_431_len    equ $ - resp_431
resp_501:       db "HTTP/1.1 501 Not Implemented", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_501_len    equ $ - resp_501
resp_502:       db "HTTP/1.1 502 Bad Gateway", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_502_len    equ $ - resp_502
resp_504:       db "HTTP/1.1 504 Gateway Timeout", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_504_len    equ $ - resp_504
resp_505:       db "HTTP/1.1 505 HTTP Version Not Supported", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_505_len    equ $ - resp_505

status_200:     db "HTTP/1.1 200 OK", 13, 10, "Content-Type: "
status_200_len  equ $ - status_200
status_206:     db "HTTP/1.1 206 Partial Content", 13, 10, "Content-Type: "
status_206_len  equ $ - status_206
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
hdr_accept_ranges: db 13, 10, "Accept-Ranges: bytes"
hdr_accept_ranges_len equ $ - hdr_accept_ranges
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
hv_close:       db "close"
slash_ch:       db "/"
zero_ch:        db "0"

; MIME types by file extension; default is application/octet-stream.
mime_html:      db "text/html"
mime_html_len   equ $ - mime_html
mime_css:       db "text/css"
mime_css_len    equ $ - mime_css
mime_js:        db "application/javascript"
mime_js_len     equ $ - mime_js
mime_json:      db "application/json"
mime_json_len   equ $ - mime_json
mime_txt:       db "text/plain"
mime_txt_len    equ $ - mime_txt
mime_png:       db "image/png"
mime_png_len    equ $ - mime_png
mime_jpeg:      db "image/jpeg"
mime_jpeg_len   equ $ - mime_jpeg
mime_gif:       db "image/gif"
mime_gif_len    equ $ - mime_gif
mime_svg:       db "image/svg+xml"
mime_svg_len    equ $ - mime_svg
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
linnea_http_handle:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 288
    mov rbx, rdi
    lea r14, [rbx + linnea_connection.in_buf]
    mov r12, [rbx + linnea_connection.in_len]
    mov qword [rsp + 8], 0     ; no target yet
    mov qword [rsp + 16], 0
    mov qword [rsp + 24], 1    ; keep_alive default on
    mov qword [rsp + 32], 0    ; response bytes
    mov qword [rsp + 88], 0    ; no Host header yet
    mov qword [rsp + 96], 0
    mov qword [rsp + 104], 0   ; no method yet
    mov qword [rsp + 128], 0   ; no body
    mov qword [rsp + 136], 0   ; no Content-Length/Transfer-Encoding seen
    mov qword [rsp + 144], 0   ; no raw target yet
    mov qword [rsp + 176], 0   ; no If-None-Match yet
    mov qword [rsp + 192], 0   ; no If-Modified-Since yet
    mov qword [rsp + 208], 0   ; no Accept-Encoding yet
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
.try_host:
    ; Host? (first occurrence wins, used for vhost selection)
    cmp qword [rsp + 88], 0
    jne .header_next
    mov rdi, [rsp + 56]
    mov rsi, [rsp + 64]
    lea rdx, [hn_host]
    mov ecx, 4
    call linnea_string_iequal
    test eax, eax
    jz .header_next
    mov rax, [rsp + 72]
    mov [rsp + 88], rax
    mov rax, [rsp + 80]
    mov [rsp + 96], rax
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
    or qword [rsp + 136], 2    ; chunked etc. are not implemented
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
    test qword [rsp + 136], 2
    jnz .resp_501
    ; an unknown method is only an error on a static location (405 below);
    ; proxy locations forward whatever the client sent
    ; the whole body must be buffered so it can be discarded with the
    ; head; only then is keep-alive safe
    mov rax, [rbx + linnea_connection.head_len]
    add rax, [rsp + 128]
    cmp rax, LINNEA_CONN_IN_BUF
    ja .resp_413
    cmp rax, [rbx + linnea_connection.in_len]
    jbe .body_ready
    mov eax, LINNEA_HTTP_NEED_MORE
    jmp .ret
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

    ; --- static location ---------------------------------------------
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
    test rsi, rsi
    jz .range_done
    movzx eax, byte [rdi]
    cmp al, '"'
    je .range_ifr_etag
    cmp al, 'W'                ; "W/..." is a weak tag, which can never
    jne .range_ifr_date        ; strong-match — but "Wed, ..." is a date
    cmp rsi, 2
    jb .range_done
    cmp byte [rdi + 1], '/'
    je .range_done
.range_ifr_date:
    call linnea_time_parse_http_date
    cmp rax, -1
    je .range_done             ; unparseable: not a match
    cmp [statbuf + LINNEA_STAT_ST_MTIME], rax
    jne .range_done            ; strong: the exact instant only
    jmp .range_eval
.range_ifr_etag:
    lea rdx, [etag_buf]
    mov rcx, [etag_len]
    call linnea_string_equal   ; strong: byte-identical, case included
    test eax, eax
    jz .range_done
.range_eval:
    mov rdi, [rsp + 240]
    mov rsi, [rsp + 248]
    mov rdx, [rsp + 32]
    call .range_parse
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
    mov r9, r8                 ; colon offset; iequal clobbers r8
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
    mov rax, r9
    sub rax, rcx
    lea rdi, [r14 + rcx]
    mov rsi, rax
    lea rdx, [hn_expect]
    mov ecx, 6
    call linnea_string_iequal
    test eax, eax
    jnz .proxy_next_line
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
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .resp_502
    mov [rbx + linnea_connection.up_fd], eax
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
.resp_505:
    lea rax, [resp_505]
    mov ecx, resp_505_len
    mov qword [rsp + 112], 505
.resp_static:
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rcx
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
    add rsp, 288
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

; .range_parse(rdi=value, rsi=len, rdx=file size) -> rax, rdx
; Parses a Range value holding a single byte range: "bytes=first-last",
; "bytes=first-" or "bytes=-suffix". Returns the byte offset in rax and
; the count in rdx, or rax = -1 when the header should be ignored
; (another unit, several ranges, malformed) or -2 when the single range
; is valid but unsatisfiable (a 416). Absurdly long numbers saturate at
; 2^62, far past any file size, and fall out as unsatisfiable or as a
; last clamped to the end. No calls, caller-saved registers only.
.range_parse:
    mov r10, rdx               ; file size
    cmp rsi, 7                 ; "bytes=" and at least one spec byte
    jb .rp_ignore
    mov r8d, [rdi]
    or r8d, 0x20202020         ; ASCII lowercase
    cmp r8d, 'byte'
    jne .rp_ignore
    movzx r8d, byte [rdi + 4]
    or r8d, 0x20
    cmp r8b, 's'
    jne .rp_ignore
    cmp byte [rdi + 5], '='
    jne .rp_ignore
    add rdi, 6
    sub rsi, 6
    xor ecx, ecx               ; cursor
    cmp byte [rdi], '-'
    je .rp_suffix
    ; ---- first, digits up to '-' -------------------------------------
    xor eax, eax
.rp_first_loop:
    cmp rcx, rsi
    jae .rp_ignore             ; no '-' at all
    movzx r8d, byte [rdi + rcx]
    cmp r8b, '-'
    je .rp_first_done
    sub r8d, '0'
    cmp r8d, 9
    ja .rp_ignore
    imul rax, rax, 10
    add rax, r8
    mov r11, 1 << 62
    cmp rax, r11
    jbe .rp_first_next
    mov rax, r11               ; saturate
.rp_first_next:
    inc rcx
    jmp .rp_first_loop
.rp_first_done:
    inc rcx                    ; past the '-'
    cmp rcx, rsi
    jae .rp_open_end           ; "first-": everything from first on
    ; ---- last, digits to the end -------------------------------------
    xor r9d, r9d
.rp_last_loop:
    cmp rcx, rsi
    jae .rp_have_last
    movzx r8d, byte [rdi + rcx]
    sub r8d, '0'
    cmp r8d, 9
    ja .rp_ignore              ; a ',' (several ranges) lands here too
    imul r9, r9, 10
    add r9, r8
    mov r11, 1 << 62
    cmp r9, r11
    jbe .rp_last_next
    mov r9, r11                ; saturate
.rp_last_next:
    inc rcx
    jmp .rp_last_loop
.rp_have_last:
    cmp rax, r9
    ja .rp_ignore              ; first > last is not a range
    cmp rax, r10
    jae .rp_unsat              ; starts at or past the end
    lea r8, [r10 - 1]
    cmp r9, r8
    jbe .rp_last_fits
    mov r9, r8                 ; a long last means "to the end"
.rp_last_fits:
    mov rdx, r9
    sub rdx, rax
    inc rdx                    ; count = last - first + 1
    ret
.rp_open_end:
    cmp rax, r10
    jae .rp_unsat
    mov rdx, r10
    sub rdx, rax               ; to the end of the file
    ret
    ; ---- "-suffix": the last N bytes ----------------------------------
.rp_suffix:
    mov ecx, 1                 ; past the '-'
    xor eax, eax
    xor r9d, r9d               ; digit count
.rp_suffix_loop:
    cmp rcx, rsi
    jae .rp_suffix_done
    movzx r8d, byte [rdi + rcx]
    sub r8d, '0'
    cmp r8d, 9
    ja .rp_ignore
    imul rax, rax, 10
    add rax, r8
    mov r11, 1 << 62
    cmp rax, r11
    jbe .rp_suffix_next
    mov rax, r11               ; saturate
.rp_suffix_next:
    inc r9d
    inc rcx
    jmp .rp_suffix_loop
.rp_suffix_done:
    test r9d, r9d
    jz .rp_ignore              ; bare "-"
    test rax, rax
    jz .rp_unsat               ; "-0" selects nothing
    test r10, r10
    jz .rp_unsat               ; nothing to take a suffix of
    cmp rax, r10
    jbe .rp_suffix_fits
    mov rax, r10               ; longer than the file: all of it
.rp_suffix_fits:
    mov rdx, rax               ; count
    mov rax, r10
    sub rax, rdx               ; offset = size - count
    ret
.rp_ignore:
    mov rax, -1
    ret
.rp_unsat:
    mov rax, -2
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

; linnea_http_ae_accepts(rdi=value, rsi=len, rdx=token, rcx=token len) -> rax
; 1 when an Accept-Encoding names this coding and does not refuse it with
; q=0. Relative q values are not compared: linnea has exactly two variants
; and its own preference between them (br first), so all it needs to know
; is whether a coding is allowed at all. "*" is not honoured — it would
; mean guessing which coding the client meant.
; Locals: [rsp+0] token end (linnea_string_iequal clobbers rcx)
linnea_http_ae_accepts:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov rbx, rdi               ; value
    mov r12, rsi               ; value len
    mov r13, rdx               ; token
    mov r14, rcx               ; token len
    xor r15d, r15d             ; cursor
.element:
    cmp r15, r12
    jae .no
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .element_skip
    cmp al, 9
    je .element_skip
    cmp al, ','
    je .element_skip
    jmp .token_start
.element_skip:
    inc r15
    jmp .element
.token_start:
    mov rcx, r15
.token_scan:
    cmp rcx, r12
    jae .token_end
    movzx eax, byte [rbx + rcx]
    cmp al, ','
    je .token_end
    cmp al, ';'
    je .token_end
    cmp al, ' '
    je .token_end
    cmp al, 9
    je .token_end
    inc rcx
    jmp .token_scan
.token_end:
    mov [rsp], rcx
    mov rax, rcx
    sub rax, r15               ; candidate length
    lea rdi, [rbx + r15]
    mov rsi, rax
    mov rdx, r13
    mov rcx, r14
    call linnea_string_iequal
    mov rcx, [rsp]
    test eax, eax
    jnz .matched
.to_comma:                     ; some other coding: skip the whole element
    cmp rcx, r12
    jae .no
    cmp byte [rbx + rcx], ','
    je .comma
    inc rcx
    jmp .to_comma
.comma:
    lea r15, [rcx + 1]
    jmp .element
.matched:
    mov r15, rcx               ; parameters may still refuse it
.param_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .param_ws_next
    cmp al, 9
    je .param_ws_next
    jmp .param
.param_ws_next:
    inc r15
    jmp .param_ws
.param:
    cmp al, ';'
    jne .yes                   ; end of the element: no q at all
    inc r15
.q_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .q_ws_next
    cmp al, 9
    je .q_ws_next
    jmp .q_name
.q_ws_next:
    inc r15
    jmp .q_ws
.q_name:
    or al, 0x20                ; ASCII lowercase
    cmp al, 'q'
    jne .yes                   ; some other parameter: leave it accepted
    inc r15
.eq_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .eq_ws_next
    cmp al, 9
    je .eq_ws_next
    jmp .eq
.eq_ws_next:
    inc r15
    jmp .eq_ws
.eq:
    cmp al, '='
    jne .yes
    inc r15
.value_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .value_ws_next
    cmp al, 9
    je .value_ws_next
    jmp .value
.value_ws_next:
    inc r15
    jmp .value_ws
.value:
    cmp al, '0'                ; only q=0, in its various spellings, refuses
    jne .yes
    inc r15
    cmp r15, r12
    jae .no                    ; bare "0"
    cmp byte [rbx + r15], '.'
    jne .no                    ; "0" then a separator
    inc r15
.fraction:
    cmp r15, r12
    jae .no                    ; "0." and zeros all the way
    movzx eax, byte [rbx + r15]
    cmp al, '0'
    je .fraction_next
    sub eax, '1'
    cmp eax, 8
    jbe .yes                   ; a nonzero digit: 0.001 still allows it
    jmp .no                    ; the value ended: every digit was zero
.fraction_next:
    inc r15
    jmp .fraction
.yes:
    mov eax, 1
    jmp .ret
.no:
    xor eax, eax
.ret:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_http_inm_match(rdi=value, rsi=len, rdx=etag, rcx=etag len) -> rax
; 1 if an If-None-Match value matches our entity-tag. The value is "*", or
; a comma-separated list of entity-tags, each optionally weak ("W/"). The
; comparison is weak (RFC 9110 13.1.2): the W/ prefix does not affect a
; match, so it is simply skipped. The etag we are handed carries its
; quotes, and so does each candidate.
; Locals: [rsp+0] closing-quote offset (linnea_string_equal clobbers rcx)
linnea_http_inm_match:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov rbx, rdi               ; value
    mov r12, rsi               ; value len
    mov r13, rdx               ; our etag
    mov r14, rcx               ; our etag len
    xor r15d, r15d             ; cursor
.next:
    cmp r15, r12
    jae .no
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .skip
    cmp al, 9
    je .skip
    cmp al, ','
    je .skip
    jmp .candidate
.skip:
    inc r15
    jmp .next
.candidate:
    cmp al, '*'
    je .yes                    ; matches any representation, and we have one
    cmp al, 'W'
    jne .quoted
    lea rax, [r15 + 1]
    cmp rax, r12
    jae .no
    cmp byte [rbx + rax], '/'
    jne .no
    add r15, 2
.quoted:
    cmp r15, r12
    jae .no
    cmp byte [rbx + r15], '"'
    jne .no                    ; not an entity-tag: nothing here can match
    lea rcx, [r15 + 1]
.find_close:
    cmp rcx, r12
    jae .no                    ; unterminated
    cmp byte [rbx + rcx], '"'
    je .close_found
    inc rcx
    jmp .find_close
.close_found:
    mov [rsp], rcx
    mov rax, rcx
    sub rax, r15
    inc rax                    ; candidate length, quotes included
    lea rdi, [rbx + r15]
    mov rsi, rax
    mov rdx, r13
    mov rcx, r14
    call linnea_string_equal
    test eax, eax
    jnz .yes
    mov r15, [rsp]
    inc r15                    ; past the closing quote, on to the next tag
    jmp .next
.yes:
    mov eax, 1
    jmp .ret
.no:
    xor eax, eax
.ret:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
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
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rcx
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
