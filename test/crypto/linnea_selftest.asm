; linnea_selftest.asm — standalone crypto self-test binary.
;
; Default: run every embedded known-answer table (SHA-256, HMAC, HKDF)
; and print "<name> <pass>/<total>" per category; exit 1 if any failed.
; The vectors come from test/crypto/gen_vectors.py (hashlib/hmac are the
; reference); this binary checks the assembly against them.
;
; "sha256-stdin" mode: read length-prefixed frames from stdin
; (4-byte LE length, then the bytes), emit each 32-byte digest to stdout,
; loop to EOF. One process then serves a million-input differential
; driver (test/crypto/diff_sha256.py) without per-input fork overhead.

default rel

%include "linnea_syscall.inc"
%include "linnea_sha256.inc"
%include "sha256_vectors.inc"

global _start

extern linnea_print_stdout
extern linnea_print_u64_stdout
extern linnea_sha256
extern linnea_hmac_sha256
extern linnea_hkdf_extract
extern linnea_hkdf_expand

section .rodata

mode_stdin:  db "sha256-stdin", 0
lbl_sha:     db "sha256 "
lbl_sha_len  equ $ - lbl_sha
lbl_hmac:    db "hmac "
lbl_hmac_len equ $ - lbl_hmac
lbl_ext:     db "hkdf-extract "
lbl_ext_len  equ $ - lbl_ext
lbl_exp:     db "hkdf-expand "
lbl_exp_len  equ $ - lbl_exp
sep_slash:   db "/"
nl:          db 10

section .bss

outbuf:      resb 128           ; digest / OKM scratch
lenbuf:      resb 8
inbuf:       resb 1 << 20       ; stdin-mode input frame

section .text

_start:
    mov rax, [rsp]              ; argc
    cmp rax, 2
    jl .vectors
    mov rdi, [rsp + 16]         ; argv[1]
    lea rsi, [mode_stdin]
    call streq
    test eax, eax
    jnz .stdin

; ---- known-answer tables --------------------------------------------
.vectors:
    xor r15d, r15d             ; total failures across categories

    ; SHA-256
    lea rbx, [sha256_tests]
    xor r12d, r12d
    xor r13d, r13d
.sha_loop:
    cmp r12, sha256_test_count
    jae .sha_done
    imul rax, r12, 24
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]
    mov rsi, [r14 + 8]
    lea rdx, [outbuf]
    call linnea_sha256
    lea rdi, [outbuf]
    mov rsi, [r14 + 16]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .sha_loop
.sha_done:
    lea rdi, [lbl_sha]
    mov rsi, lbl_sha_len
    mov rdx, r13
    mov rcx, sha256_test_count
    call report
    add r15, sha256_test_count
    sub r15, r13               ; += (total - pass); the count is a constant,
                               ; rcx was clobbered by report's print calls

    ; HMAC
    lea rbx, [hmac_tests]
    xor r12d, r12d
    xor r13d, r13d
.hmac_loop:
    cmp r12, hmac_test_count
    jae .hmac_done
    imul rax, r12, 40
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; key
    mov rsi, [r14 + 8]         ; keylen
    mov rdx, [r14 + 16]        ; msg
    mov rcx, [r14 + 24]        ; msglen
    lea r8, [outbuf]
    call linnea_hmac_sha256
    lea rdi, [outbuf]
    mov rsi, [r14 + 32]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .hmac_loop
.hmac_done:
    lea rdi, [lbl_hmac]
    mov rsi, lbl_hmac_len
    mov rdx, r13
    mov rcx, hmac_test_count
    call report
    add r15, hmac_test_count
    sub r15, r13

    ; HKDF-Extract
    lea rbx, [hkdf_extract_tests]
    xor r12d, r12d
    xor r13d, r13d
.ext_loop:
    cmp r12, hkdf_extract_test_count
    jae .ext_done
    imul rax, r12, 40
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; salt
    mov rsi, [r14 + 8]         ; saltlen
    mov rdx, [r14 + 16]        ; ikm
    mov rcx, [r14 + 24]        ; ikmlen
    lea r8, [outbuf]
    call linnea_hkdf_extract
    lea rdi, [outbuf]
    mov rsi, [r14 + 32]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .ext_loop
.ext_done:
    lea rdi, [lbl_ext]
    mov rsi, lbl_ext_len
    mov rdx, r13
    mov rcx, hkdf_extract_test_count
    call report
    add r15, hkdf_extract_test_count
    sub r15, r13

    ; HKDF-Expand
    lea rbx, [hkdf_expand_tests]
    xor r12d, r12d
    xor r13d, r13d
.exp_loop:
    cmp r12, hkdf_expand_test_count
    jae .exp_done
    imul rax, r12, 48
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; prk
    mov rsi, [r14 + 8]         ; prklen
    mov rdx, [r14 + 16]        ; info
    mov rcx, [r14 + 24]        ; infolen
    lea r8, [outbuf]
    mov r9, [r14 + 40]         ; outlen
    call linnea_hkdf_expand
    lea rdi, [outbuf]
    mov rsi, [r14 + 32]
    mov rcx, [r14 + 40]
    call memeq
    add r13, rax
    inc r12
    jmp .exp_loop
.exp_done:
    lea rdi, [lbl_exp]
    mov rsi, lbl_exp_len
    mov rdx, r13
    mov rcx, hkdf_expand_test_count
    call report
    add r15, hkdf_expand_test_count
    sub r15, r13

    ; exit 1 if anything failed
    mov edi, 1
    test r15, r15
    jnz .exit
    xor edi, edi
.exit:
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- sha256-stdin differential mode ---------------------------------
.stdin:
    lea rdi, [lenbuf]
    mov rsi, 4
    call read_full
    cmp eax, 4
    jne .stdin_done
    mov ecx, [lenbuf]          ; frame length, little-endian
    lea rdi, [inbuf]
    mov rsi, rcx
    call read_full
    lea rdi, [inbuf]
    mov esi, [lenbuf]
    lea rdx, [outbuf]
    call linnea_sha256
    lea rdi, [outbuf]
    mov rsi, 32
    call linnea_print_stdout
    jmp .stdin
.stdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; report(rdi=label, rsi=labellen, rdx=pass, rcx=total) — "<label><p>/<t>\n"
report:
    push rbx
    push r12
    push r13
    mov rbx, rdx               ; pass
    mov r12, rcx               ; total
    call linnea_print_stdout   ; label (rdi/rsi already set)
    mov rdi, rbx
    call linnea_print_u64_stdout
    lea rdi, [sep_slash]
    mov rsi, 1
    call linnea_print_stdout
    mov rdi, r12
    call linnea_print_u64_stdout
    lea rdi, [nl]
    mov rsi, 1
    call linnea_print_stdout
    pop r13
    pop r12
    pop rbx
    ret

; memeq(rdi=a, rsi=b, rcx=n) -> eax = 1 if the n bytes match, else 0.
memeq:
    xor eax, eax
.loop:
    test rcx, rcx
    jz .equal
    mov dl, [rdi]
    cmp dl, [rsi]
    jne .done
    inc rdi
    inc rsi
    dec rcx
    jmp .loop
.equal:
    mov eax, 1
.done:
    ret

; read_full(rdi=buf, rsi=count) -> eax = bytes actually read (== count, or
; fewer at EOF). Loops over short reads.
read_full:
    push rbx
    push r12
    push r13
    mov rbx, rdi               ; buf cursor
    mov r12, rsi               ; remaining
    xor r13d, r13d             ; total read
.loop:
    test r12, r12
    jz .done
    xor eax, eax               ; SYS_READ
    xor edi, edi               ; stdin
    mov rsi, rbx
    mov rdx, r12
    syscall
    test rax, rax
    jle .done                  ; 0 = EOF, <0 = error
    add rbx, rax
    sub r12, rax
    add r13, rax
    jmp .loop
.done:
    mov rax, r13
    pop r13
    pop r12
    pop rbx
    ret

; streq(rdi=a, rsi=b) -> eax = 1 if the NUL-terminated strings are equal.
streq:
    xor eax, eax
.loop:
    mov dl, [rdi]
    cmp dl, [rsi]
    jne .done
    test dl, dl
    jz .equal
    inc rdi
    inc rsi
    jmp .loop
.equal:
    mov eax, 1
.done:
    ret
