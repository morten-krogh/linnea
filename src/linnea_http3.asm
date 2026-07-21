; linnea_http3.asm — HTTP/3 (RFC 9114) request-stream framing. For now this
; parses the frame layer on a client request stream and decodes the HEADERS
; frame with QPACK. The response path and stream demux come later.

default rel

%include "linnea_http3.inc"
%include "linnea_hpack.inc"
%include "linnea_syscall.inc"

global linnea_h3_read_headers
global linnea_h3_build_response
global linnea_h3_serve

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

section .bss
fs_buf:   resb 512                    ; encoded response field section
clen_buf: resb 20                     ; content-length as decimal ASCII
h3_path_buf: resb 4096                ; root ++ decoded path ++ NUL

section .text

; linnea_h3_read_headers(rdi=stream, rsi=len, rdx=req) -> rax = 0 | -err.
; Each frame is varint(type) varint(length) payload. Skip DATA and unknown
; frames; decode the first HEADERS frame's field section into req via QPACK.
linnea_h3_read_headers:
    push rbx
    push r12
    push r13
    push r14
    push r15                         ; alignment (unused)
    mov r14, rdx                     ; req
    mov r12, rdi                     ; cursor
    lea r13, [rdi + rsi]             ; end
.frame:
    cmp r12, r13
    jae .noheaders
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
    add r12, rax                     ; skip this frame's payload
    jmp .frame
.headers:
    mov rdi, r12                     ; QPACK field section
    mov rsi, rax
    mov rdx, r14
    call linnea_qpack_decode         ; returns 0 | -err
    jmp .ret
.noheaders:
    mov rax, -LINNEA_H3_ERR_NOHEADERS
    jmp .ret
.err:
    mov rax, -LINNEA_H3_ERR
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_build_response(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=body_ptr, r9=body_len) -> rax = total length written.
; Emits a HEADERS frame (0x01) wrapping the QPACK-encoded response fields
; (:status, content-type, content-length = body_len) then a DATA frame (0x00)
; carrying the body. The out buffer must hold the field section + body + framing.
linnea_h3_build_response:
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
    mov r12, r8                      ; body ptr
    mov r13, r9                      ; body len
    ; content-length text = decimal(body_len)
    push rdx
    push rcx
    lea rdi, [clen_buf]
    mov rax, r9
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
    ; DATA frame: type 0x00, length varint, body
    mov byte [r14], LINNEA_H3_FRAME_DATA
    inc r14
    mov rdi, r14
    mov rsi, r13
    call linnea_quic_varint_encode
    add r14, rax
    mov rsi, r12
    mov rdi, r14
    mov rcx, r13
    rep movsb
    mov r14, rdi
    mov rax, r14
    sub rax, rbx                     ; total length
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_serve(rdi=req, rsi=root ptr, rdx=root len, rcx=out)
;   -> rax = response length written to out.
; Resolves the request's :path under root and serves that file with its MIME
; type, or a 404 / 400 response. The path normalizer, opener and MIME table are
; the shared ones, so h3 and h2 resolve and reject paths identically.
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
