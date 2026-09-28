; Exact method/path predicate for the proposed Vefruna source body rule.
; rdi=method bytes, rsi=length, rdx=normalized path bytes, rcx=length
; Returns eax=1 only for POST /projects/project_<26 encoded chars>/source.
; This is a pure predicate; callers must still select and enforce a cap.

default rel

global linnea_pdf_source_route
global linnea_pdf_confirmation_route
global linnea_package_route

section .rodata
method_post: db "POST"
path_prefix: db "/projects/project_"
path_suffix: db "/source"
confirmation_suffix: db "/pdf-candidate-confirmations"
confirmation_suffix_len equ $ - confirmation_suffix
package_suffix: db "/pattern-package"
package_suffix_len equ $ - package_suffix
alphabet: db "0123456789abcdefghjkmnpqrstvwxyz"

section .text
linnea_pdf_source_route:
    push r12
    push r13
    lea r12, [path_suffix]
    mov r13d, 7
    call pdf_route_common
    pop r13
    pop r12
    ret

linnea_pdf_confirmation_route:
    push r12
    push r13
    lea r12, [confirmation_suffix]
    mov r13d, confirmation_suffix_len
    call pdf_route_common
    pop r13
    pop r12
    ret

linnea_package_route:
    push r12
    push r13
    lea r12, [package_suffix]
    mov r13d, package_suffix_len
    call pdf_route_common
    pop r13
    pop r12
    ret

pdf_route_common:
    xor eax, eax
    cmp rsi, 4
    jne .done
    mov r10, r13
    add r10, 44
    cmp rcx, r10
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
    cmp r8, r13
    jae .match
    mov r9b, [rdx + r8 + 44]
    cmp r9b, [r12 + r8]
    jne .done
    inc r8
    jmp .suffix_loop
.match:
    mov eax, 1
.done:
    ret
