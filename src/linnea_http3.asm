; linnea_http3.asm — HTTP/3 (RFC 9114) request-stream framing. For now this
; parses the frame layer on a client request stream and decodes the HEADERS
; frame with QPACK. The response path and stream demux come later.

default rel

%include "linnea_http3.inc"

global linnea_h3_read_headers

extern linnea_quic_varint_decode
extern linnea_qpack_decode

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
