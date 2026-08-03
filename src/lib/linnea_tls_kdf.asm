; linnea_tls_kdf.asm — the TLS 1.3 key-schedule KDF (RFC 8446 7.1).
;
; HKDF-Expand-Label builds the HkdfLabel info structure
;   uint16 length || opaque label<7..255> = "tls13 " + label
;                 || opaque context<0..255>
; on the stack and runs HKDF-Expand over it; Derive-Secret is the
; 32-byte case with a transcript hash as context. Secrets are always
; SHA-256-sized here (the only suite linnea speaks), output lengths are
; at most 255 (TLS never asks for more from one expansion).
;
; ABI: System V; callee-saved preserved.

default rel

global linnea_tls_hkdf_expand_label
global linnea_tls_derive_secret

extern linnea_hkdf_expand

section .rodata

tls13_prefix: db "tls13 "

section .text

; linnea_tls_hkdf_expand_label(rdi=secret32, rsi=label, rdx=labellen,
;                              rcx=context, r8=ctxlen, r9=out,
;                              [stack]=outlen)
; The label is the bare RFC name ("key", "c hs traffic", ...) — the
; "tls13 " prefix is added here.
linnea_tls_hkdf_expand_label:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72                ; the HkdfLabel info (<= 56 bytes used)
    mov rbp, rdi               ; secret
    mov rbx, r9                ; out
    mov r12, [rsp + 128]       ; outlen (72 + 48 pushed + 8 return)
    mov r14, rcx               ; context
    mov r15, r8                ; ctxlen

    mov byte [rsp], 0          ; uint16 length, big-endian (outlen <= 255)
    mov rax, r12
    mov [rsp + 1], al
    lea eax, [edx + 6]         ; label length byte incl. "tls13 "
    mov [rsp + 2], al
    mov eax, [tls13_prefix]
    mov [rsp + 3], eax
    mov ax, [tls13_prefix + 4]
    mov [rsp + 7], ax
    lea rdi, [rsp + 9]         ; label follows the prefix
    mov rcx, rdx               ; rsi = label already
    rep movsb
    mov rax, r15               ; context length byte
    mov [rdi], al
    inc rdi
    mov rsi, r14
    mov rcx, r15
    rep movsb

    mov rcx, rdi               ; infolen = cursor - start
    sub rcx, rsp
    mov rdi, rbp               ; prk
    mov rsi, 32
    mov rdx, rsp               ; info
    mov r8, rbx                ; out
    mov r9, r12                ; outlen
    call linnea_hkdf_expand

    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; linnea_tls_derive_secret(rdi=secret32, rsi=label, rdx=labellen,
;                          rcx=transcript_hash32, r8=out)
; = HKDF-Expand-Label(secret, label, hash, 32)
linnea_tls_derive_secret:
    mov r9, r8                 ; out
    mov r8, 32                 ; ctxlen: a SHA-256 transcript hash
    sub rsp, 8
    mov qword [rsp], 32        ; outlen
    call linnea_tls_hkdf_expand_label
    add rsp, 8
    ret
