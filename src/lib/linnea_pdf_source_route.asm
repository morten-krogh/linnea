; Exact method/path predicate for the proposed Vefruna source body rule.
; rdi=method bytes, rsi=length, rdx=normalized path bytes, rcx=length
; Returns eax=1 only for POST /projects/project_<26 encoded chars>/source.
; This is a pure predicate; callers must still select and enforce a cap.

default rel

global linnea_pdf_source_route

section .rodata
method_post: db "POST"
path_prefix: db "/projects/project_"
path_suffix: db "/source"
alphabet: db "0123456789abcdefghjkmnpqrstvwxyz"

section .text
linnea_pdf_source_route:
    xor eax, eax
    cmp rsi, 4
    jne .done
    cmp rcx, 51
    jne .done
    cmp dword [rdi], 0x54534f50      ; POST, little endian
    jne .done
    xor r8d, r8d
.prefix:
    cmp r8, 18
    jae .first_digit
    mov r9b, [rdx + r8]
    cmp r9b, [path_prefix + r8]
    jne .done
    inc r8
    jmp .prefix
.first_digit:
    mov r9b, [rdx + 18]
    cmp r9b, '0'
    jb .done
    cmp r9b, '7'
    ja .done
    mov r8d, 19
    movzx r11d, r9b               ; nonzero digit seen
    sub r11d, '0'
.digits:
    cmp r8, 44
    jae .suffix
    mov r9b, [rdx + r8]
    xor r10d, r10d
.alphabet:
    cmp r9b, [alphabet + r10]
    je .valid_digit
    inc r10
    cmp r10, 32
    jb .alphabet
    jmp .done
.valid_digit:
    or r11d, r10d
    inc r8
    jmp .digits
.suffix:
    test r11d, r11d
    jz .done
    xor r8d, r8d
.suffix_loop:
    cmp r8, 7
    jae .match
    mov r9b, [rdx + r8 + 44]
    cmp r9b, [path_suffix + r8]
    jne .done
    inc r8
    jmp .suffix_loop
.match:
    mov eax, 1
.done:
    ret
