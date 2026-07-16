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
extern linnea_x25519

section .rodata

mode_stdin:  db "sha256-stdin", 0
mode_xstdin: db "x25519-stdin", 0
mode_xiter:  db "x25519-iter", 0
lbl_sha:     db "sha256 "
lbl_sha_len  equ $ - lbl_sha
lbl_hmac:    db "hmac "
lbl_hmac_len equ $ - lbl_hmac
lbl_ext:     db "hkdf-extract "
lbl_ext_len  equ $ - lbl_ext
lbl_exp:     db "hkdf-expand "
lbl_exp_len  equ $ - lbl_exp
lbl_x:       db "x25519 "
lbl_x_len    equ $ - lbl_x
lbl_xi:      db "x25519-iter "
lbl_xi_len   equ $ - lbl_xi
sep_slash:   db "/"
nl:          db 10

section .bss

outbuf:      resb 128           ; digest / OKM scratch
lenbuf:      resb 8
inbuf:       resb 1 << 20       ; stdin-mode input frame
iter_k:      resb 32            ; X25519 iterated-test working values
iter_u:      resb 32
iter_r:      resb 32

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
    mov rdi, [rsp + 16]
    lea rsi, [mode_xstdin]
    call streq
    test eax, eax
    jnz .xstdin
    mov rdi, [rsp + 16]
    lea rsi, [mode_xiter]
    call streq
    test eax, eax
    jnz .xiter

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

    ; X25519 single-shot
    lea rbx, [x25519_tests]
    xor r12d, r12d
    xor r13d, r13d
.x_loop:
    cmp r12, x25519_test_count
    jae .x_done
    imul rax, r12, 24
    lea r14, [rbx + rax]
    lea rdi, [outbuf]
    mov rsi, [r14 + 0]         ; scalar
    mov rdx, [r14 + 8]         ; u
    call linnea_x25519
    lea rdi, [outbuf]
    mov rsi, [r14 + 16]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .x_loop
.x_done:
    lea rdi, [lbl_x]
    mov rsi, lbl_x_len
    mov rdx, r13
    mov rcx, x25519_test_count
    call report
    add r15, x25519_test_count
    sub r15, r13

    ; X25519 iterated (k = u = 9, RFC recurrence)
    lea rbx, [x25519_iter_tests]
    xor r12d, r12d
    xor r13d, r13d
.xi_loop:
    cmp r12, x25519_iter_test_count
    jae .xi_done
    imul rax, r12, 16
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; iteration count
    lea rsi, [outbuf]
    call run_iter
    lea rdi, [outbuf]
    mov rsi, [r14 + 8]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .xi_loop
.xi_done:
    lea rdi, [lbl_xi]
    mov rsi, lbl_xi_len
    mov rdx, r13
    mov rcx, x25519_iter_test_count
    call report
    add r15, x25519_iter_test_count
    sub r15, r13

    ; exit 1 if anything failed
    mov edi, 1
    test r15, r15
    jnz .exit
    xor edi, edi
.exit:
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- x25519-stdin differential mode (64-byte scalar||u frames) ------
.xstdin:
    lea rdi, [inbuf]
    mov rsi, 64
    call read_full
    cmp eax, 64
    jne .xstdin_done
    lea rdi, [outbuf]
    lea rsi, [inbuf]
    lea rdx, [inbuf + 32]
    call linnea_x25519
    lea rdi, [outbuf]
    mov rsi, 32
    call linnea_print_stdout
    jmp .xstdin
.xstdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- x25519-iter mode: argv[2] rounds, raw 32-byte result to stdout -
.xiter:
    mov rax, [rsp + 8]         ; argc
    cmp rax, 3
    jl .xiter_bad
    mov rdi, [rsp + 24]        ; argv[2]
    call parse_u64
    mov rdi, rax
    lea rsi, [outbuf]
    call run_iter
    lea rdi, [outbuf]
    mov rsi, 32
    call linnea_print_stdout
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.xiter_bad:
    mov edi, 1
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

; run_iter(rdi=n, rsi=out32) — the RFC 7748 recurrence: k = u = 9, then
; n times (r = X25519(k,u); u = k; k = r); write the final k to out.
run_iter:
    push rbx
    push r12
    push r13
    mov rbx, rdi               ; n
    mov r12, rsi               ; out
    lea rdi, [iter_k]
    call zero32
    lea rdi, [iter_u]
    call zero32
    mov byte [iter_k], 9
    mov byte [iter_u], 9
.loop:
    test rbx, rbx
    jz .done
    lea rdi, [iter_r]
    lea rsi, [iter_k]
    lea rdx, [iter_u]
    call linnea_x25519
    lea rdi, [iter_u]
    lea rsi, [iter_k]
    call copy32
    lea rdi, [iter_k]
    lea rsi, [iter_r]
    call copy32
    dec rbx
    jmp .loop
.done:
    mov rdi, r12
    lea rsi, [iter_k]
    call copy32
    pop r13
    pop r12
    pop rbx
    ret

; copy32(rdi=dst, rsi=src) — copy 32 bytes.
copy32:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    ret

; zero32(rdi=dst) — clear 32 bytes.
zero32:
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    ret

; parse_u64(rdi=cstr) -> rax — decimal, no validation (test tooling).
parse_u64:
    xor eax, eax
.loop:
    movzx ecx, byte [rdi]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul rax, rax, 10
    add rax, rcx
    inc rdi
    jmp .loop
.done:
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
