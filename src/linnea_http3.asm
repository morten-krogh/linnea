; linnea_http3.asm — HTTP/3 (RFC 9114) request-stream framing. For now this
; parses the frame layer on a client request stream and decodes the HEADERS
; frame with QPACK. The response path and stream demux come later.

default rel

%include "linnea_http3.inc"
%include "linnea_hpack.inc"
%include "linnea_syscall.inc"

global linnea_h3_read_headers
global linnea_h3_build_response
global linnea_h3_build_response_head
global linnea_h3_serve
global linnea_h3_tx_cap

extern linnea_quic_varint_decode
extern linnea_quic_varint_encode
extern linnea_qpack_decode
extern linnea_qpack_encode_response
; static-file resolution, shared with the HTTP/2 serve path
extern linnea_static_normalize
extern linnea_static_open
extern linnea_static_mime

section .rodata
idx_name:      db "index.html"
idx_name_len   equ $ - idx_name
txt_plain:     db "text/plain"
txt_plain_len  equ $ - txt_plain
body_404:      db "404 Not Found", 10
body_404_len   equ $ - body_404
body_400:      db "400 Bad Request", 10
body_400_len   equ $ - body_400
body_503:      db "503 Service Unavailable", 10
body_503_len   equ $ - body_503

section .bss
fs_buf:   resb 512                    ; encoded response field section
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
    add r12, rax                     ; skip any other frame's payload
    jmp .frame
.headers:
    mov rdi, r12                     ; QPACK field section
    mov rsi, rax
    mov rdx, r14
    mov rbp, rax                     ; keep the field-section length
    call linnea_qpack_decode         ; returns 0 | -err
    test rax, rax
    js .ret                          ; propagate a decode error
    mov r15d, 1                      ; HEADERS decoded
    add r12, rbp                     ; past the field section
    jmp .frame
.data:
    ; capture the first DATA frame after HEADERS as the request body
    test r15d, r15d
    jz .data_skip                    ; DATA before HEADERS: not a body, skip it
    cmp qword [rsp], 0
    jne .data_skip                   ; a body is already captured
    mov [rsp], r12                   ; body ptr
    mov [rsp + 8], rax               ; body len
.data_skip:
    add r12, rax
    jmp .frame
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

; linnea_h3_build_response_head(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=body_len) -> rax = length written.
; Emits a HEADERS frame (0x01) wrapping the QPACK-encoded response fields
; (:status, content-type, content-length = body_len) then the DATA frame's
; type and length varint — everything of the response that precedes the body
; bytes. A caller that inlines the body appends it right after; a chunked
; response keeps this head per connection and streams the body from its file
; mapping, so the head and body never share a buffer.
linnea_h3_build_response_head:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8                       ; keep rsp 16-aligned for the calls
    mov rbx, rdi                     ; out start
    mov r14, rdi                     ; out cursor
    mov r15d, esi                    ; status
    mov r13, r8                      ; body len
    ; content-length text = decimal(body_len)
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
    ; DATA frame: type 0x00 and its length varint (the body is the caller's)
    mov byte [r14], LINNEA_H3_FRAME_DATA
    inc r14
    mov rdi, r14
    mov rsi, r13
    call linnea_quic_varint_encode
    add r14, rax
    mov rax, r14
    sub rax, rbx                     ; head length
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

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
    sub rsp, 8                       ; keep rsp 16-aligned for the calls
    mov rbx, rdi                     ; req
    mov r12, rcx                     ; out
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
    lea rsi, [idx_name]
    mov ecx, idx_name_len
    rep movsb
    mov r14, rdi
.noindex:
    mov byte [r14], 0                ; NUL-terminate for open()
    lea rdi, [h3_path_buf]
    call linnea_static_open          ; rax = base (0 = missing), rdx = size
    test rax, rax
    jz .notfound
    mov r15, rax                     ; mapped body base (1 = empty file)
    mov rbp, rdx                     ; body size
    lea rdi, [h3_path_buf]
    mov rsi, r14
    sub rsi, rdi                     ; resolved path length
    call linnea_static_mime          ; rax = mime ptr, rdx = mime len
    mov rcx, rdx                     ; mime len
    mov rdx, rax                     ; mime ptr
    cmp rbp, LINNEA_H3_INLINE_MAX
    ja .large                        ; too big for one packet: stream it
    mov r8, r15
    mov r9, rbp
    cmp r15, 1                       ; empty-file sentinel: found, nothing mapped
    jne .havebody
    xor r8d, r8d
    xor r9d, r9d
.havebody:
    mov rdi, r12
    mov esi, 200
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
    ; will head + body fit the client's allowance? (rdx/rcx = MIME, kept live)
    mov rax, [linnea_h3_tx_cap]
    sub rax, LINNEA_H3_HEAD_MAX      ; the head's worst case
    jb .refuse                       ; no allowance at all
    cmp rbp, rax
    ja .refuse                       ; the body alone would overrun the window
    mov rdi, r12
    mov esi, 200
    mov r8, rbp                      ; body length (for content-length + DATA len)
    call linnea_h3_build_response_head ; rax = head length written to out
    mov r8, r15                      ; the mapping is the caller's to stream + unmap
    mov r9, rbp
    jmp .sret_large
.refuse:
    ; unmap the file and answer 503: refused, not broken — the client may retry
    ; (e.g. once the connection's open response stream finishes)
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
    add rsp, 8
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
