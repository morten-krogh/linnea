; linnea_string.asm — string and number utilities.

default rel

global linnea_string_length
global linnea_string_equal
global linnea_string_copy
global linnea_string_from_u64

section .text

; linnea_string_length(rdi=cstr) -> rax=len
linnea_string_length:
    xor eax, eax
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret

; linnea_string_equal(rdi=ptr1, rsi=len1, rdx=ptr2, rcx=len2) -> rax=1/0
linnea_string_equal:
    cmp rsi, rcx
    jne .no
    xor eax, eax
.loop:
    cmp rax, rsi
    jae .yes
    mov r8b, [rdi + rax]
    cmp r8b, [rdx + rax]
    jne .no
    inc rax
    jmp .loop
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; linnea_string_copy(rdi=dst, rsi=src, rdx=len) — copies len bytes, NUL-terminates.
; Caller must ensure dst has room for len + 1 bytes.
linnea_string_copy:
    mov rcx, rdx
    rep movsb
    mov byte [rdi], 0
    ret

; linnea_string_from_u64(rdi=value, rsi=buf) -> rax=len
; Formats value as decimal digits at the start of buf. buf must be >= 20 bytes.
linnea_string_from_u64:
    mov rax, rdi
    lea r8, [rsi + 20]         ; end of buf
    mov r9, r8                 ; write cursor, moves down
    mov r10, 10
.digit:
    xor edx, edx
    div r10
    add dl, '0'
    dec r9
    mov [r9], dl
    test rax, rax
    jnz .digit
    mov rcx, r8
    sub rcx, r9                ; len
    mov rax, rcx
    mov rdi, rsi               ; dst = start of buf
    mov rsi, r9                ; src = first digit
    rep movsb
    ret
