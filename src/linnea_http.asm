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
; - Files are served from a read-only mmap queued behind the header send
;   (conn.file_*); the event loop munmaps after the send completes.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_connection.inc"

global linnea_http_handle

; linnea_http_handle return values
LINNEA_HTTP_NEED_MORE   equ 0
LINNEA_HTTP_RESPOND     equ 1

LINNEA_HTTP_MAX_METHOD  equ 32
LINNEA_HTTP_MAX_TARGET  equ 2048
; The decoded path is built at LINNEA_HTTP_PATH_ROOT so a matched
; location's root can be prepended in place, without moving the path:
; root (255) + target (2048) + "/index.html" + NUL always fits.
LINNEA_HTTP_PATH_ROOT   equ LINNEA_MAX_ROOT + 1
LINNEA_HTTP_PATH_BUF    equ 2560

extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_equal
extern linnea_string_iequal
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
resp_505:       db "HTTP/1.1 505 HTTP Version Not Supported", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_505_len    equ $ - resp_505

status_200:     db "HTTP/1.1 200 OK", 13, 10, "Content-Type: "
status_200_len  equ $ - status_200
hdr_length:     db 13, 10, "Content-Length: "
hdr_length_len  equ $ - hdr_length
hdr_keepalive:  db 13, 10, "Connection: keep-alive", 13, 10, 13, 10
hdr_keepalive_len equ $ - hdr_keepalive
hdr_close:      db 13, 10, "Connection: close", 13, 10, 13, 10
hdr_close_len   equ $ - hdr_close

version_11:     db "HTTP/1.1"          ; 8 bytes, compared as one qword
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
hv_close:       db "close"

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
linnea_http_handle:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 176
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
    ; Connection: close?
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
    jz .header_next
    mov qword [rsp + 24], 0
    jmp .header_next
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
    je .resp_501               ; proxying arrives with the next milestone

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
    ; open + fstat, must be a regular file
    mov rdi, r13
    xor esi, esi               ; O_RDONLY
    xor edx, edx
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .resp_404
    mov [rsp + 56], rax        ; fd
    mov rdi, rax
    lea rsi, [statbuf]
    mov eax, LINNEA_SYS_FSTAT
    syscall
    cmp rax, -4095
    jae .close_404
    mov eax, [statbuf + LINNEA_STAT_ST_MODE]
    and eax, LINNEA_S_IFMT
    cmp eax, LINNEA_S_IFREG
    jne .close_404
    mov rax, [statbuf + LINNEA_STAT_ST_SIZE]
    mov [rsp + 32], rax        ; file size
    ; GET with content: map the file and queue it behind the headers
    cmp qword [rsp], 0
    jne .no_map                ; HEAD: headers only
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
    mov [rbx + linnea_connection.file_ptr], rax
    mov rcx, [rsp + 32]
    mov [rbx + linnea_connection.file_size], rcx
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

    ; --- 200 response headers ----------------------------------------
.build_headers:
    mov rax, [rsp + 24]
    mov [rbx + linnea_connection.keep_alive], rax
    lea r15, [rbx + linnea_connection.out_buf]
    lea rdi, [status_200]
    mov esi, status_200_len
    call .append
    mov rdi, [rsp + 40]
    mov rsi, [rsp + 48]
    call .append
    lea rdi, [hdr_length]
    mov esi, hdr_length_len
    call .append
    mov rdi, [rsp + 32]
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
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
    mov qword [rsp + 112], 200
    jmp .log_request

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
.resp_505:
    lea rax, [resp_505]
    mov ecx, resp_505_len
    mov qword [rsp + 112], 505
.resp_static:
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rbx + linnea_connection.keep_alive], 0
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
    add rsp, 176
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
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
