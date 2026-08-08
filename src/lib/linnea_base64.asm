; linnea_base64.asm — base64 encoding.
;
; The decoder lives in linnea_pem.asm, where it reads a certificate; this is
; the other direction, and it exists for the WebSocket handshake, whose
; Sec-WebSocket-Accept is base64 over a 20-byte digest (RFC 6455 4.2.2).
; Standard alphabet, '=' padded — RFC 4648 4, not the URL-safe variant.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 are preserved.

default rel

global linnea_base64_encode

section .rodata
b64_alpha: db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

section .text

; linnea_base64_encode(rdi = in, rsi = inlen, rdx = out) -> rax = bytes written.
; The output is 4 * ceil(inlen / 3) bytes and is NOT NUL-terminated; the caller
; sizes the buffer.
linnea_base64_encode:
    push rbx
    push r12
    mov rbx, rdi                     ; input cursor
    mov r12, rsi                     ; bytes left
    mov r8, rdx                      ; output cursor
    mov r9, rdx                      ; where it started, to measure at the end
    lea r10, [b64_alpha]
.group:
    cmp r12, 3
    jb .remainder
    movzx eax, byte [rbx]            ; three bytes -> one 24-bit group
    shl eax, 16
    movzx ecx, byte [rbx + 1]
    shl ecx, 8
    or eax, ecx
    movzx ecx, byte [rbx + 2]
    or eax, ecx
    add rbx, 3
    sub r12, 3
    mov edx, eax                     ; ...emitted six bits at a time
    shr edx, 18
    and edx, 63
    movzx edx, byte [r10 + rdx]
    mov [r8], dl
    mov edx, eax
    shr edx, 12
    and edx, 63
    movzx edx, byte [r10 + rdx]
    mov [r8 + 1], dl
    mov edx, eax
    shr edx, 6
    and edx, 63
    movzx edx, byte [r10 + rdx]
    mov [r8 + 2], dl
    mov edx, eax
    and edx, 63
    movzx edx, byte [r10 + rdx]
    mov [r8 + 3], dl
    add r8, 4
    jmp .group
.remainder:
    test r12, r12
    jz .done
    ; One or two bytes left. The group is padded with zero bits to the next
    ; six-bit boundary and the output to four characters with '='.
    movzx eax, byte [rbx]
    shl eax, 16
    cmp r12, 2
    jb .one
    movzx ecx, byte [rbx + 1]
    shl ecx, 8
    or eax, ecx
.one:
    mov edx, eax                     ; first character
    shr edx, 18
    and edx, 63
    movzx edx, byte [r10 + rdx]
    mov [r8], dl
    mov edx, eax                     ; second
    shr edx, 12
    and edx, 63
    movzx edx, byte [r10 + rdx]
    mov [r8 + 1], dl
    cmp r12, 2
    jb .pad2
    mov edx, eax                     ; third, when two bytes were left
    shr edx, 6
    and edx, 63
    movzx edx, byte [r10 + rdx]
    mov [r8 + 2], dl
    mov byte [r8 + 3], '='
    add r8, 4
    jmp .done
.pad2:
    mov word [r8 + 2], '=='
    add r8, 4
.done:
    mov rax, r8
    sub rax, r9
    pop r12
    pop rbx
    ret
