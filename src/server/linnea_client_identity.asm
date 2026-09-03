; A canonical, versioned client address for private authenticated backends.
; The header is not authentication: the backend must authenticate Linnea's
; transport before trusting it. Public request fields with this reserved name
; are stripped by every proxy rewrite before this function appends its value.

default rel

%include "linnea_config.inc"

global linnea_client_identity_append

section .rodata
prefix4: db "Linnea-Client-Identity: v1;ip4="
prefix4_len equ $ - prefix4
prefix6: db "Linnea-Client-Identity: v1;ip6="
prefix6_len equ $ - prefix6
hex: db "0123456789abcdef"

section .text

; linnea_client_identity_append(rdi=destination, rsi=location*,
;   rdx=raw network-order address, rcx=4 or 16) -> rax=new destination.
; Returns the unchanged destination when the location did not opt in, and zero
; when it did but the kernel-derived address is unavailable. IPv4-mapped IPv6
; is normalized to IPv4 so TCP and QUIC give one client one key.
linnea_client_identity_append:
    cmp qword [rsi + linnea_config_location.proxy_client_identity], 0
    je .off
    cmp rcx, 4
    je .ip4
    cmp rcx, 16
    jne .bad
    cmp qword [rdx], 0
    jne .ip6
    cmp word [rdx + 8], 0
    jne .ip6
    cmp word [rdx + 10], 0xffff
    jne .ip6
    add rdx, 12
.ip4:
    mov r8, rdx
    mov r9d, 4
    lea rsi, [prefix4]
    mov ecx, prefix4_len
    rep movsb
    jmp .digits
.ip6:
    mov r8, rdx
    mov r9d, 16
    lea rsi, [prefix6]
    mov ecx, prefix6_len
    rep movsb
.digits:
    lea r10, [hex]
.byte:
    movzx r11d, byte [r8]
    mov eax, r11d
    shr eax, 4
    mov al, [r10 + rax]
    mov [rdi], al
    and r11d, 15
    mov al, [r10 + r11]
    mov [rdi + 1], al
    add rdi, 2
    inc r8
    dec r9
    jnz .byte
    mov word [rdi], 0x0a0d
    add rdi, 2
.off:
    mov rax, rdi
    ret
.bad:
    xor eax, eax
    ret
