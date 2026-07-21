; linnea_quic.asm — QUIC (RFC 9000) transport helpers. Starts with the
; variable-length integer encoding (16): the top two bits of the first byte
; give the length (1/2/4/8 bytes) and the rest is a big-endian value.

default rel

global linnea_quic_varint_decode
global linnea_quic_varint_encode

section .text

; linnea_quic_varint_decode(rdi=ptr, rsi=end) -> rax = value, rdx = bytes
; consumed (0 on truncation/error, so a valid decode always advances).
linnea_quic_varint_decode:
    cmp rdi, rsi
    jae .err
    movzx eax, byte [rdi]
    mov ecx, eax
    shr ecx, 6                       ; length code 0..3
    mov edx, 1
    shl edx, cl                      ; nbytes = 1 << code
    lea r8, [rdi + rdx]
    cmp r8, rsi
    ja .err                          ; not enough bytes
    and eax, 0x3f                    ; drop the length bits from the first byte
    cmp edx, 1
    je .done
    mov r8d, edx
    dec r8d                          ; remaining bytes to fold in
    lea r9, [rdi + 1]
.fold:
    shl rax, 8
    movzx ecx, byte [r9]
    or rax, rcx
    inc r9
    dec r8d
    jnz .fold
.done:
    ret
.err:
    xor eax, eax
    xor edx, edx
    ret

; linnea_quic_varint_encode(rdi=dst, rsi=value) -> rax = bytes written.
; The value must fit in 62 bits (RFC 9000 16); larger values are not encodable.
linnea_quic_varint_encode:
    cmp rsi, 0x3f
    jbe .b1
    cmp rsi, 0x3fff
    jbe .b2
    cmp rsi, 0x3fffffff
    jbe .b4
.b8:
    mov rax, 0xc000000000000000
    or rax, rsi
    bswap rax
    mov [rdi], rax
    mov eax, 8
    ret
.b4:
    mov eax, esi
    or eax, 0x80000000
    bswap eax
    mov [rdi], eax
    mov eax, 4
    ret
.b2:
    mov eax, esi
    or eax, 0x4000
    xchg al, ah                      ; 2-byte big-endian
    mov [rdi], ax
    mov eax, 2
    ret
.b1:
    mov [rdi], sil
    mov eax, 1
    ret
