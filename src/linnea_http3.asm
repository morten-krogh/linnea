; linnea_http3.asm — HTTP/3 (RFC 9114) request-stream framing. For now this
; parses the frame layer on a client request stream and decodes the HEADERS
; frame with QPACK. The response path and stream demux come later.

default rel

%include "linnea_http3.inc"
%include "linnea_hpack.inc"
%include "linnea_syscall.inc"

global linnea_h3_read_headers
global linnea_h3_build_response
global linnea_h3_build_431
global linnea_h3_build_421
global linnea_h3_build_response_head
global linnea_h3_serve
global linnea_h3_tx_cap

extern linnea_hpack_req_check
extern linnea_quic_varint_decode
extern linnea_quic_varint_encode
extern linnea_log_access
extern linnea_log_acc_peer
extern linnea_log_acc_proto
extern linnea_log_acc_proto_len
extern linnea_log_acc_status
extern linnea_log_acc_bytes
extern linnea_qpack_decode
extern linnea_qpack_encode_response
extern linnea_qpack_send_validators
extern linnea_qpack_crange_ptr
extern linnea_qpack_crange_len
extern linnea_qpack_cenc
; static-file resolution, shared with the HTTP/2 serve path
extern linnea_static_normalize
extern linnea_static_open
extern linnea_static_open_enc
extern linnea_static_mime
extern linnea_static_validators
extern linnea_static_mtime
extern linnea_static_etag
extern linnea_static_etag_len
extern linnea_http_inm_match
extern linnea_http_range_parse
extern linnea_http_ifrange_match
extern linnea_time_parse_http_date

global linnea_h3_body_off
global linnea_h3_body_len

section .rodata
idx_name:      db "index.html"
idx_name_len   equ $ - idx_name
txt_plain:     db "text/plain; charset=utf-8"
txt_plain_len  equ $ - txt_plain
body_404:      db "404 Not Found", 10
body_404_len   equ $ - body_404
body_400:      db "400 Bad Request", 10
body_400_len   equ $ - body_400
proto_h3: db "HTTP/3"
proto_h3_len equ $ - proto_h3
body_421: db "421 Misdirected Request", 10
body_421_len equ $ - body_421
body_431:      db "431 Request Header Fields Too Large", 10
body_431_len   equ $ - body_431
body_503:      db "503 Service Unavailable", 10
body_503_len   equ $ - body_503

section .bss
fs_buf:   resb 768                    ; encoded response field section
clen_buf: resb 20                     ; content-length as decimal ASCII
h3_path_buf: resb 4096                ; root ++ decoded path ++ NUL
post_receipt: resb 64                 ; "<len> <hash>" for a large POST body
; The caller's flow-control allowance for one chunked response: the most stream
; bytes (head + body) the requesting client can accept, set by the QUIC server
; per request before linnea_h3_serve — 0 while another chunked response is in
; flight on the connection. A body that will not fit is refused with a 503
; rather than overrun the client's window (a flow-control violation kills the
; connection; a 503 is retryable).
linnea_h3_tx_cap: resq 1
; For a chunked (large-body) response: where the body starts within the file
; mapping linnea_h3_serve hands back, and how many bytes of it to stream — a
; 206's range slice, or 0 / the whole size. The caller copies these into the
; response-stream slot beside the mapping.
linnea_h3_body_off: resq 1
linnea_h3_body_len: resq 1
h3_crange_buf: resb 80                ; "bytes first-last/size" / "bytes */size"

section .text

; linnea_h3_read_headers(rdi=stream, rsi=len, rdx=req)
;   -> rax = 0 | -err, and on success r8 = request-body ptr, r9 = body length
;   (0 if none). Each frame is varint(type) varint(length) payload. Decode the
;   first HEADERS frame's field section into req via QPACK, and capture the first
;   DATA frame after it as the body (r8/r9 point into the stream — the body is
;   not copied). DATA before HEADERS, and any other frame type, are skipped. Only
;   a single DATA frame within these stream bytes is captured: a body split
;   across DATA frames or QUIC packets is not reassembled.
; Body ptr/len live in stack locals [rsp]/[rsp+8] during the walk (all callee-
; saved registers are already in use) and move to r8/r9 at return.
linnea_h3_read_headers:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 24                      ; [rsp]=body ptr, [rsp+8]=body len (16-aligned)
    mov r14, rdx                     ; req
    mov r12, rdi                     ; cursor
    lea r13, [rdi + rsi]             ; end
    xor r15d, r15d                   ; HEADERS seen yet?
    mov qword [rsp], 0               ; body ptr
    mov qword [rsp + 8], 0           ; body len
.frame:
    cmp r12, r13
    jae .done
    ; frame type (varint_decode takes rdi=cursor, rsi=end)
    mov rdi, r12
    mov rsi, r13
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .err
    mov rbx, rax                     ; frame type
    add r12, rdx
    ; frame length
    mov rdi, r12
    mov rsi, r13
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .err
    add r12, rdx                     ; -> payload
    ; the payload must fit in the remaining stream bytes
    mov rcx, r13
    sub rcx, r12
    cmp rax, rcx
    ja .err
    cmp rbx, LINNEA_H3_FRAME_HEADERS
    je .headers
    cmp rbx, LINNEA_H3_FRAME_DATA
    je .data
    ; Neither HEADERS nor DATA. A request stream carries only those two; the
    ; reserved HTTP/2 types (0x02/0x06/0x08/0x09, RFC 9114 7.2.8) and the
    ; control/push frames — CANCEL_PUSH/SETTINGS/PUSH_PROMISE/GOAWAY (0x03..0x07)
    ; and MAX_PUSH_ID (0x0d) — are a connection error H3_FRAME_UNEXPECTED here.
    ; GREASE (0x1f*N+0x21) and any other unknown type MUST be ignored (7.2, 9).
    cmp rbx, 0x0d
    je .frame_unexpected
    mov rcx, rbx
    sub rcx, 2
    cmp rcx, 7                        ; original type in 0x02..0x09
    jbe .frame_unexpected
    add r12, rax                     ; grease / unknown: skip its payload
    jmp .frame
.headers:
    ; A HEADERS after the first is a trailer section (RFC 9114 4.1). We serve
    ; from the request headers, not trailers, and must NOT let a trailer merge
    ; into the request struct: a trailing `range`/`if-none-match`/etc. would
    ; otherwise change the response the client never asked to change. Skip it
    ; unread; the request was already parsed from the first HEADERS.
    test r15d, r15d
    jnz .trailer_skip
    mov rdi, r12                     ; QPACK field section
    mov rsi, rax
    mov rdx, r14
    mov rbp, rax                     ; keep the field-section length
    call linnea_qpack_decode         ; returns 0 | -err
    test rax, rax
    jns .decoded
    ; a request that broke a semantic rule decoded fine — the QPACK state is
    ; intact, so RFC 9114 4.1.2 fails the STREAM, which -LINNEA_H3_ERR does
    cmp qword [r14 + linnea_h2_req.malformed], 0
    jne .err
    ; a header list past our bound is a resource limit, answerable on the
    ; stream; only a genuine decode failure is a connection error
    cmp rax, -LINNEA_HPACK_ERR_LIMIT
    jne .qpack_broken
    mov rax, -LINNEA_H3_ERR_TOOLARGE
    jmp .ret
.qpack_broken:
    mov rax, -LINNEA_H3_ERR_QPACK    ; the caller ends the connection with it
    jmp .ret
.decoded:
    ; the whole-request rules (an agreeing, plausible authority from one
    ; source or the other) — shared with HTTP/2
    mov rdi, r14
    call linnea_hpack_req_check
    test rax, rax
    js .err
    mov r15d, 1                      ; HEADERS decoded
    add r12, rbp                     ; past the field section
    jmp .frame
.data:
    ; capture the first DATA frame after HEADERS as the request body
    test r15d, r15d
    jz .frame_unexpected             ; DATA before HEADERS (RFC 9114 4.1)
    cmp qword [rsp], 0
    jne .data_skip                   ; a body is already captured
    mov [rsp], r12                   ; body ptr
    mov [rsp + 8], rax               ; body len
.data_skip:
    add r12, rax
    jmp .frame
.trailer_skip:                       ; a dead-end reached only by the jump in
    add r12, rax                     ; .headers: advance past the trailer's
    jmp .frame                       ; field section without decoding it
.frame_unexpected:                   ; a dead-end reached only by explicit jumps
    mov rax, -LINNEA_H3_ERR_UNEXPECTED
    jmp .ret
.done:
    test r15d, r15d
    jz .noheaders
    xor eax, eax                     ; a complete request
    jmp .ret
.noheaders:
    mov rax, -LINNEA_H3_ERR_NOHEADERS
    jmp .ret
.err:
    mov rax, -LINNEA_H3_ERR
.ret:
    mov r8, [rsp]                    ; body ptr / len out (0 if none)
    mov r9, [rsp + 8]
    add rsp, 24
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_build_headers(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=content_length) -> rax = length written.
; Emits only the HEADERS frame (0x01) wrapping the QPACK-encoded response
; fields — :status, content-type, content-length (both omitted for a 304),
; plus whatever linnea_qpack_encode_response adds (validators when armed,
; then date and server). A HEAD response is exactly this — no DATA frame
; follows — and it is the first half of a full response head.
linnea_h3_build_headers:
    push rbx
    push r14
    push r15
    push rbp
    ; The access line: every HTTP/3 response of any shape passes through here,
    ; and the server parked the who-and-what (peer, host, method, target) in
    ; the log's parameter block before serving. Only the outcome is added. A
    ; zero peer means no context was set (a bare test driver): log nothing.
    cmp qword [linnea_log_acc_peer], 0
    je .no_acc
    mov eax, esi
    mov [linnea_log_acc_status], rax
    mov [linnea_log_acc_bytes], r8
    lea rax, [proto_h3]                 ; this builder is HTTP/3-only
    mov [linnea_log_acc_proto], rax
    mov qword [linnea_log_acc_proto_len], proto_h3_len
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    call linnea_log_access
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
.no_acc:
    mov rbx, rdi                     ; out start
    mov r14, rdi                     ; out cursor
    mov r15d, esi                    ; status
    ; content-length text = decimal(content_length)
    push rdx
    push rcx
    lea rdi, [clen_buf]
    mov rax, r8
    call u64_to_dec                  ; rax = digit count
    pop rcx
    pop rdx
    mov rbp, rax                     ; content-length text length
    ; QPACK-encode the response fields into fs_buf
    lea rdi, [fs_buf]
    mov esi, r15d
    ; rdx = ct_ptr, rcx = ct_len already
    lea r8, [clen_buf]
    mov r9, rbp
    cmp r15d, 304                    ; a 304 restates only the validators, not
    jne .enc                         ; the representation's type or length
    xor edx, edx
    xor r8d, r8d
.enc:
    call linnea_qpack_encode_response ; rax = field-section length
    mov rbp, rax                     ; field-section length
    ; HEADERS frame: type 0x01, length varint, field section
    mov byte [r14], LINNEA_H3_FRAME_HEADERS
    inc r14
    mov rdi, r14
    mov rsi, rbp
    call linnea_quic_varint_encode
    add r14, rax
    lea rsi, [fs_buf]
    mov rdi, r14
    mov rcx, rbp
    rep movsb
    mov r14, rdi
    mov rax, r14
    sub rax, rbx                     ; headers length
    pop rbp
    pop r15
    pop r14
    pop rbx
    ret

; linnea_h3_build_response_head(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=body_len) -> rax = length written.
; The HEADERS frame (content-length = body_len) followed by the DATA frame's
; type and length varint — everything of the response that precedes the body
; bytes. A caller that inlines the body appends it right after; a chunked
; response keeps this head per connection and streams the body from its file
; mapping, so the head and body never share a buffer.
linnea_h3_build_response_head:
    push rbx
    push r13
    push r14
    mov rbx, rdi                     ; out start
    mov r13, r8                      ; body len
    call linnea_h3_build_headers     ; rax = headers length (args unchanged)
    lea r14, [rbx + rax]             ; cursor after the HEADERS frame
    mov byte [r14], LINNEA_H3_FRAME_DATA
    inc r14
    mov rdi, r14
    mov rsi, r13
    call linnea_quic_varint_encode
    add r14, rax
    mov rax, r14
    sub rax, rbx                     ; total head length
    pop r14
    pop r13
    pop rbx
    ret

; linnea_h3_build_421(rdi=out) -> rax = length written.
; The whole response for a request whose authority this connection is not
; authoritative for (its certificate covers a different site). A client that
; coalesced onto this connection retries on a fresh one, where the right
; certificate is presented; nothing else recovers as cleanly.
linnea_h3_build_421:
    mov esi, 421
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_421]
    mov r9d, body_421_len
    jmp linnea_h3_build_response

; linnea_h3_build_431(rdi=out) -> rax = length written.
; The whole response for a request whose header section we will not hold: the
; request never parsed, so there is no path, method or vhost to serve from —
; only a status the client can act on, which beats resetting the stream and
; leaving it to guess why.
linnea_h3_build_431:
    mov esi, 431
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_431]
    mov r9d, body_431_len
    jmp linnea_h3_build_response

; linnea_h3_build_response(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=body_ptr, r9=body_len) -> rax = total length written.
; The head (HEADERS frame + DATA frame header) followed by the body bytes.
; The out buffer must hold the field section + body + framing.
linnea_h3_build_response:
    push r12
    push r13
    push r14
    mov r12, r8                      ; body ptr
    mov r13, r9                      ; body len
    mov r14, rdi                     ; out
    mov r8, r9                       ; the head takes the body's length
    call linnea_h3_build_response_head
    lea rdi, [r14 + rax]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    add rax, r13                     ; head + body
    pop r14
    pop r13
    pop r12
    ret

; linnea_h3_serve(rdi=req, rsi=root ptr, rdx=root len, rcx=out, r8=body ptr,
;   r9=body len) -> rax = response length written to out, and r8/r9 = the
; response file's mapping base/size when the body was too large to inline
; (r9 = 0 otherwise: out holds the complete response, nothing stays mapped).
; A POST echoes its request body (200 text/plain). Otherwise resolves the
; request's :path under root and serves that file with its MIME type, or a
; 404 / 400 response. The path normalizer, opener and MIME table are the shared
; ones, so h3 and h2 resolve and reject paths identically.
; A body over LINNEA_H3_INLINE_MAX is not copied: out receives only the head
; (HEADERS frame + DATA frame header), the file stays mapped, and the caller
; streams the body as chunks — unless head + body exceeds the caller's
; flow-control allowance (linnea_h3_tx_cap), which is refused with a 503: the
; client's window cannot take the response, and overrunning it would kill the
; connection instead of the request.
linnea_h3_serve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 40                      ; [0/8] mime ptr/len, [16/24] range
    ;                                ; offset/length, [32] ranged flag
    mov rbx, rdi                     ; req
    mov r12, rcx                     ; out
    ; no validators or content-range until a file is opened and the request's
    ; conditionals and range are evaluated
    mov qword [linnea_qpack_send_validators], 0
    mov qword [linnea_qpack_crange_ptr], 0
    mov qword [linnea_qpack_cenc], 0
    ; a POST echoes its request body back (r8/r9) — the observable proof that
    ; DATA frames are captured. GET/HEAD (and other methods) fall through to the
    ; static file path, which ignores any body.
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    cmp qword [rbx + linnea_h2_req.method_len], 4
    jne .not_post
    cmp dword [rdi], 0x54534f50      ; "POST", little-endian
    jne .not_post
    cmp r9, LINNEA_H3_ECHO_MAX
    ja .post_receipt                 ; too large to echo in one packet: a receipt
    mov rdi, r12                     ; echo: 200 text/plain, body = r8/r9 (unchanged)
    mov esi, 200
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    call linnea_h3_build_response
    jmp .sret
.post_receipt:
    ; The echo would overflow one response packet, so reply with a receipt: the
    ; body's length and a position-sensitive rolling hash (h = h*31 + byte). Both
    ; require every byte, in order — proof the multi-packet stream reassembled to
    ; exactly what was sent, in a response that fits one packet.
    mov rsi, r8                      ; body ptr
    mov rcx, r9                      ; body len
    mov r14, r9                      ; keep the length
    xor eax, eax                     ; hash accumulator
    test rcx, rcx
    jz .pr_hashed
.pr_hash:
    imul eax, eax, 31
    movzx edx, byte [rsi]
    add eax, edx
    inc rsi
    dec rcx
    jnz .pr_hash
.pr_hashed:
    mov r13d, eax                    ; keep the hash (u64_to_dec clobbers r8/r9)
    lea rdi, [post_receipt]
    mov rax, r14                     ; length as decimal
    call u64_to_dec
    mov byte [rdi], ' '
    inc rdi
    mov eax, r13d                    ; hash as decimal
    call u64_to_dec
    lea rax, [post_receipt]
    sub rdi, rax                     ; receipt length
    mov r9, rdi
    mov rdi, r12
    mov esi, 200
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [post_receipt]
    call linnea_h3_build_response
    jmp .sret
.not_post:
    ; path buffer = root ++ (decoded path)
    lea rdi, [h3_path_buf]
    mov rcx, rdx                     ; root length (rsi = root ptr)
    rep movsb
    mov r13, rdi                     ; where the decoded path starts
    mov rsi, [rbx + linnea_h2_req.path_ptr]
    test rsi, rsi
    jz .bad                          ; no :path in the request
    mov rdx, [rbx + linnea_h2_req.path_len]
    mov rdi, r13
    call linnea_static_normalize     ; rax = end ptr (0 = reject), r9 = dir flag
    test rax, rax
    jz .bad
    mov r14, rax                     ; end of the resolved path
    test r9, r9
    jz .noindex
    mov rdi, r14                     ; a directory: serve index.html from it
    cmp byte [rdi - 1], '/'          ; normalize consumed the trailing slash on
    je .append_index                 ; every directory but "/", so put it back
    mov byte [rdi], '/'
    inc rdi
.append_index:
    lea rsi, [idx_name]
    mov ecx, idx_name_len
    rep movsb
    mov r14, rdi
.noindex:
    ; open the file — negotiating a pre-compressed variant when the client's
    ; Accept-Encoding allows one (open_enc writes the suffix and NUL at r14;
    ; the MIME lookup below keeps using the name before it)
    lea rdi, [h3_path_buf]
    mov rsi, r14
    mov rdx, [rbx + linnea_h2_req.ae_ptr]
    mov rcx, [rbx + linnea_h2_req.ae_len]
    call linnea_static_open_enc      ; rax = base (0 = missing), rdx = size,
    mov [linnea_qpack_cenc], r8      ; r8 = the coding served
    test rax, rax
    jz .notfound
    mov r15, rax                     ; mapped body base (1 = empty file)
    mov rbp, rdx                     ; body size
    ; validators for this file, then the request's conditionals: If-None-Match
    ; wins over If-Modified-Since, and an INM mismatch answers 200 whatever
    ; If-Modified-Since says (RFC 9110 13.2.2)
    mov rdi, [linnea_static_mtime]
    mov rsi, rbp
    call linnea_static_validators
    mov qword [linnea_qpack_send_validators], 1
    mov rdi, [rbx + linnea_h2_req.inm_ptr]
    test rdi, rdi
    jz .chk_ims
    mov rsi, [rbx + linnea_h2_req.inm_len]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    call linnea_http_inm_match
    test eax, eax
    jnz .h3_304
    jmp .cond_done
.chk_ims:
    mov rdi, [rbx + linnea_h2_req.ims_ptr]
    test rdi, rdi
    jz .cond_done
    mov rsi, [rbx + linnea_h2_req.ims_len]
    call linnea_time_parse_http_date
    cmp rax, -1
    je .cond_done                    ; unparseable: the RFC says ignore it
    cmp [linnea_static_mtime], rax
    jbe .h3_304                      ; not modified since the client's copy
.cond_done:
    lea rdi, [h3_path_buf]
    mov rsi, r14
    sub rsi, rdi                     ; resolved path length
    call linnea_static_mime          ; rax = mime ptr, rdx = mime len
    mov [rsp], rax                   ; keep the MIME across the range work
    mov [rsp + 8], rdx
    mov qword [rsp + 16], 0          ; whole file until a range narrows it
    mov [rsp + 24], rbp
    mov qword [rsp + 32], 0          ; not a 206
    ; --- Range: a single bytes= range on a GET, evaluated after the
    ; conditionals as RFC 9110 orders and gated by If-Range (strong match
    ; only). Anything not understood serves the full 200, which is always
    ; safe; a valid but unsatisfiable range earns the 416.
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    cmp qword [rbx + linnea_h2_req.method_len], 4
    jne .range_chk
    cmp dword [rdi], 0x44414548      ; "HEAD": ranges apply to GET alone
    je .range_done
.range_chk:
    mov rdi, [rbx + linnea_h2_req.rng_ptr]
    test rdi, rdi
    jz .range_done
    mov rdi, [rbx + linnea_h2_req.ifr_ptr]
    test rdi, rdi
    jz .range_eval
    mov rsi, [rbx + linnea_h2_req.ifr_len]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    mov r8, [linnea_static_mtime]
    call linnea_http_ifrange_match
    test eax, eax
    jz .range_done                   ; stale validator: the whole file
.range_eval:
    mov rdi, [rbx + linnea_h2_req.rng_ptr]
    mov rsi, [rbx + linnea_h2_req.rng_len]
    mov rdx, rbp
    call linnea_http_range_parse     ; rax = offset, rdx = count | -1 | -2
    cmp rax, -1
    je .range_done
    cmp rax, -2
    je .h3_416
    mov [rsp + 16], rax
    mov [rsp + 24], rdx
    mov qword [rsp + 32], 1
    ; content-range value: "bytes first-last/size"
    lea rdi, [h3_crange_buf]
    mov dword [rdi], 'byte'
    mov word [rdi + 4], 's '
    add rdi, 6
    mov rax, [rsp + 16]              ; first
    call u64_to_dec
    mov byte [rdi], '-'
    inc rdi
    mov rax, [rsp + 16]
    add rax, [rsp + 24]
    dec rax                          ; last = first + count - 1
    call u64_to_dec
    mov byte [rdi], '/'
    inc rdi
    mov rax, rbp                     ; the representation's whole size
    call u64_to_dec
    lea rax, [h3_crange_buf]
    sub rdi, rax
    mov [linnea_qpack_crange_len], rdi
    mov [linnea_qpack_crange_ptr], rax
.range_done:
    ; a HEAD request: emit only the headers (content-length = the file size) and
    ; no body — whatever the size. A bodiless response is not flow-controlled.
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    cmp qword [rbx + linnea_h2_req.method_len], 4
    jne .body_serve
    cmp dword [rdi], 0x44414548      ; "HEAD", little-endian
    jne .body_serve
    mov rdi, r12                     ; out
    mov esi, 200
    mov rdx, [rsp]                   ; mime ptr / len
    mov rcx, [rsp + 8]
    mov r8, rbp                      ; content-length = file size
    call linnea_h3_build_headers     ; rax = response length (headers only)
    cmp r15, 1
    jbe .sret                        ; empty-file sentinel: nothing was mapped
    push rax
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    pop rax
    jmp .sret
.body_serve:
    mov esi, 200                     ; 206 when a range narrowed the body
    cmp qword [rsp + 32], 0
    je .st_sel
    mov esi, 206
.st_sel:
    mov rdx, [rsp]                   ; mime ptr / len
    mov rcx, [rsp + 8]
    mov rax, [rsp + 24]              ; body length: the slice's
    cmp rax, LINNEA_H3_INLINE_MAX
    ja .large                        ; too big for one packet: stream it
    mov r8, r15
    add r8, [rsp + 16]               ; the slice, or the whole file
    mov r9, [rsp + 24]
    cmp r15, 1                       ; empty-file sentinel: found, nothing mapped
    jne .havebody
    xor r8d, r8d
    xor r9d, r9d
.havebody:
    mov rdi, r12
    call linnea_h3_build_response    ; rax = response length
    cmp r15, 1
    jbe .sret                        ; nothing was mapped
    push rax
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    pop rax
    jmp .sret
.large:
    ; may we start a chunked response? Only one is in flight at a time; a
    ; concurrent large request is refused (503). The body itself streams within
    ; the client's flow-control window, enforced by the pump, so its size is not
    ; checked here. (esi = status, rdx/rcx = MIME, kept live.)
    cmp qword [linnea_h3_tx_cap], 0
    je .refuse
    mov rdi, r12
    mov r8, [rsp + 24]               ; body length (for content-length + DATA len)
    call linnea_h3_build_response_head ; rax = head length written to out
    mov rcx, [rsp + 16]              ; where the body starts in the mapping,
    mov [linnea_h3_body_off], rcx    ; and how much of it the pump streams
    mov rcx, [rsp + 24]
    mov [linnea_h3_body_len], rcx
    mov r8, r15                      ; the mapping is the caller's to stream + unmap
    mov r9, rbp
    jmp .sret_large
.h3_416:
    ; the single range is valid but unsatisfiable: unmap the file and answer
    ; a bodiless 416 whose Content-Range names the actual length ("bytes
    ; */size") so the client can retry sensibly. It describes no
    ; representation, so the validators are dropped again.
    cmp r15, 1
    jbe .h3_416_nomap                ; empty-file sentinel: nothing was mapped
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h3_416_nomap:
    mov qword [linnea_qpack_send_validators], 0
    lea rdi, [h3_crange_buf]         ; content-range value: "bytes */size"
    mov dword [rdi], 'byte'
    mov dword [rdi + 4], 's */'
    add rdi, 8
    mov rax, rbp
    call u64_to_dec
    lea rax, [h3_crange_buf]
    sub rdi, rax
    mov [linnea_qpack_crange_len], rdi
    mov [linnea_qpack_crange_ptr], rax
    mov rdi, r12                     ; out
    mov esi, 416
    xor edx, edx                     ; no content-type
    xor r8d, r8d                     ; content-length: 0, and no DATA frame
    call linnea_h3_build_headers     ; rax = response length (headers only)
    jmp .sret

.h3_304:
    ; the client's copy is current: unmap the file and answer a bodiless 304
    ; carrying the validators it will compare next time. Like a HEAD response,
    ; a 304 is headers-only and so never flow-controlled.
    cmp r15, 1
    jbe .h3_304_nomap                ; empty-file sentinel: nothing was mapped
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h3_304_nomap:
    mov rdi, r12                     ; out
    mov esi, 304
    xor r8d, r8d                     ; no content-length (none is encoded)
    call linnea_h3_build_headers     ; rax = response length (headers only)
    jmp .sret

.refuse:
    ; unmap the file and answer 503: refused, not broken — the client may retry
    ; (e.g. once the connection's open response stream finishes). The 503
    ; describes no file: drop the validators computed for the mapping.
    mov qword [linnea_qpack_send_validators], 0
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov rdi, r12
    mov esi, 503
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_503]
    mov r9d, body_503_len
    call linnea_h3_build_response
    jmp .sret
.notfound:
    mov rdi, r12
    mov esi, 404
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_404]
    mov r9d, body_404_len
    call linnea_h3_build_response
    jmp .sret
.bad:
    mov rdi, r12
    mov esi, 400
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_400]
    mov r9d, body_400_len
    call linnea_h3_build_response
.sret:
    xor r8d, r8d                     ; complete response in out, nothing mapped
    xor r9d, r9d
.sret_large:
    add rsp, 40
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; u64_to_dec(rdi=out, rax=value) -> rax = number of digits written (no NUL).
u64_to_dec:
    sub rsp, 24
    lea r8, [rsp + 24]               ; one past the temp end
    mov r9, r8                       ; write digits backwards
    mov r10, 10
    test rax, rax
    jnz .d1
    dec r9
    mov byte [r9], '0'
    jmp .d2
.d1:
    dec r9
    xor edx, edx
    div r10
    add dl, '0'
    mov [r9], dl
    test rax, rax
    jnz .d1
.d2:
    mov rcx, r8
    sub rcx, r9                      ; digit count
    mov rax, rcx
    mov rsi, r9
    rep movsb                        ; copy to out (rdi)
    add rsp, 24
    ret
