; linnea_pem.asm — minimal PEM decoding for the cert chain and key.
;
; linnea_pem_decode finds a "-----BEGIN <name>-----" / "-----END-----"
; block and base64-decodes its body (skipping any whitespace) into the
; caller's buffer. linnea_pem_cert_list decodes every CERTIFICATE block
; in a file — leaf first, then the chain, the order PEM chain files are
; written in — into a pre-framed TLS 1.3 certificate_list.
; linnea_pem_p256_key decodes a PKCS#8 "PRIVATE KEY" block and walks its
; DER to the 32-byte P-256 private scalar.
;
; Deliberately not a general PEM/DER parser: linnea only ever loads its
; own operator-supplied files, one cert chain and one key. Errors are -1
; (no matching BEGIN block) or -2 (a block that is malformed or overflows
; the buffer); the caller turns both into a startup error_exit.
;
; ABI: System V; callee-saved preserved.

default rel

global linnea_pem_decode
global linnea_pem_cert_list
global linnea_pem_p256_key

section .rodata

begin_pfx:  db "-----BEGIN "
begin_len   equ $ - begin_pfx
end_pfx:    db "-----END "
end_len     equ $ - end_pfx
dashes5:    db "-----"

section .bss

alignb 8
b64_table:  resb 256          ; ASCII -> 6-bit value, 0xff for non-alphabet
key_buf:    resb 256          ; decoded PKCS#8 EC key; the real thing is
key_buf_cap equ 256           ; ~138 bytes with the optional public key

section .text

; ---- linnea_pem_decode(rdi=src, rsi=srclen, rdx=name, rcx=namelen,
;      r8=out, r9=outcap) -> rax = DER length, or -1 when no BEGIN <name>
;      block exists, -2 when a block is malformed or outgrows outcap.
;      On success rdx points just past the decoded body (at or before its
;      END line): the resume point for scanning a multi-block file. -----
linnea_pem_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rdi              ; src cursor
    lea r13, [rdi + rsi]      ; src end
    mov r14, rdx              ; name
    mov r15, rcx              ; namelen
    mov rbp, r8               ; out
    mov r12, r9               ; outcap

    ; find "-----BEGIN <name>-----"
    lea rdi, [begin_pfx]
    mov rsi, begin_len
    call find_bytes
    test rax, rax
    js .nofind
    add rbx, begin_len
    mov rdi, rbx             ; the name must follow immediately
    mov rsi, r14
    mov rcx, r15
    call bytes_eq
    test eax, eax
    jz .bad
    add rbx, r15
    mov rdi, rbx             ; ...and then the closing dashes
    lea rsi, [dashes5]
    mov rcx, 5
    call bytes_eq
    test eax, eax
    jz .bad
    add rbx, 5

    call build_b64_table

    ; base64-decode until "-----END", accumulating bits
    xor r8d, r8d             ; bit accumulator
    xor r9d, r9d             ; bits held
    xor r10d, r10d           ; output length
.loop:
    cmp rbx, r13
    jae .bad                 ; ran out before the END marker
    ; is this the start of the END line? (only meaningful at column-ish
    ; positions, but '-' never appears in base64 so a plain check is safe)
    cmp byte [rbx], '-'
    jne .decode
    mov rdi, rbx
    lea rsi, [end_pfx]
    mov rcx, end_len
    call bytes_eq
    test eax, eax
    jnz .done
.decode:
    movzx eax, byte [rbx]
    inc rbx
    cmp al, '='
    je .done                 ; padding: the data is complete
    movzx eax, byte [b64_table + rax]
    cmp al, 0xff
    je .loop                 ; whitespace / newline
    shl r8d, 6
    or r8d, eax
    add r9d, 6
    cmp r9d, 8
    jb .loop
    sub r9d, 8
    mov ecx, r9d
    mov eax, r8d
    shr eax, cl              ; take the top 8 completed bits
    cmp r10, r12
    jae .bad                 ; would overflow the caller's buffer
    mov [rbp + r10], al
    inc r10
    jmp .loop
.done:
    mov rax, r10
    mov rdx, rbx             ; resume point for the next block
    jmp .ret
.nofind:
    mov rax, -1
    jmp .ret
.bad:
    mov rax, -2
.ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- linnea_pem_cert_list(rdi=src, rsi=srclen, rdx=out, rcx=outcap)
;      -> rax = certificate_list length, or -1 / -2 as linnea_pem_decode.
;
;      Decodes every CERTIFICATE block and emits each as a TLS 1.3
;      CertificateEntry (RFC 8446 4.4.2): u24 DER length, the DER, and an
;      empty (u16 0) extensions block. The result is the certificate_list
;      body, copied verbatim into the Certificate handshake message. At
;      least one block is required; the file's order (leaf first, then
;      the chain) is the order the wire wants. --------------------------
linnea_pem_cert_list:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi              ; src cursor
    lea r13, [rdi + rsi]      ; src end
    mov r14, rdx              ; out
    mov r15, rcx              ; outcap
    xor ebx, ebx              ; list length so far
.next:
    lea rax, [rbx + 5]        ; this entry's framing: u24 length + u16 ext
    cmp rax, r15
    ja .bad
    mov rdi, r12
    mov rsi, r13
    sub rsi, r12              ; source bytes left
    lea rdx, [cert_name]
    mov ecx, cert_name_len
    lea r8, [r14 + rbx + 3]   ; the DER lands after its u24 length
    mov r9, r15
    sub r9, rax               ; room left after the framing
    call linnea_pem_decode
    test rax, rax
    js .no_more
    jz .bad                   ; an empty CERTIFICATE block: malformed (-2)
    mov r12, rdx              ; resume past this block
    mov ecx, eax              ; u24 DER length, big-endian
    shr ecx, 16
    mov [r14 + rbx], cl
    mov ecx, eax
    shr ecx, 8
    mov [r14 + rbx + 1], cl
    mov [r14 + rbx + 2], al
    lea rcx, [r14 + rbx]
    mov word [rcx + rax + 3], 0    ; per-certificate extensions: none
    lea rbx, [rbx + rax + 5]
    jmp .next
.no_more:
    cmp rax, -2
    je .ret                   ; a malformed block: propagate
    test rbx, rbx
    jz .ret                   ; no CERTIFICATE block at all: rax = -1
    mov rax, rbx
    jmp .ret
.bad:
    mov rax, -2
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

section .rodata
cert_name:    db "CERTIFICATE"
cert_name_len equ $ - cert_name
section .text

; ---- p256_der_open(rdi=p, rsi=end, edx=tag) -> rax = content ptr or -1,
;      rcx = content length. Checks the tag, decodes the length, and
;      verifies the content fits within end.
;
;      Short form and the 0x81 long form only. A P-256 PKCS#8 key is about
;      140 bytes, so a length that needs two or more bytes is malformed
;      rather than merely unsupported, and a 0x81 carrying a value below 128
;      is non-minimal DER. Both are rejected. ------------------------------
p256_der_open:
    push rbx
    mov rbx, rsi
    sub rbx, rdi
    cmp rbx, 2
    jb .bad
    movzx eax, byte [rdi]
    cmp eax, edx
    jne .bad
    movzx ecx, byte [rdi + 1]
    lea rax, [rdi + 2]
    cmp ecx, 0x80
    jb .have                  ; short form: the byte is the length
    cmp ecx, 0x81
    jne .bad
    cmp rbx, 3
    jb .bad
    movzx ecx, byte [rdi + 2]
    cmp ecx, 0x80
    jb .bad                   ; 0x81 with a short value: not minimal
    lea rax, [rdi + 3]
.have:
    mov rbx, rsi
    sub rbx, rax
    cmp rbx, rcx              ; content must fit inside end
    jb .bad
    pop rbx
    ret
.bad:
    mov rax, -1
    xor ecx, ecx
    pop rbx
    ret

; ---- linnea_pem_p256_key(rdi=src, rsi=srclen) -> rax = pointer to the
;      32-byte private scalar, or -1. The pointer is into a static buffer.
;
;      Walks the PKCS#8 structure rather than comparing a fixed prefix: an
;      EC key's inner SEC1 ECPrivateKey carries an OPTIONAL [1] public key,
;      and whether the generator emits it shifts every length byte before the
;      scalar. A prefix compare would accept keys from `openssl genpkey` and
;      reject otherwise valid ones that omit it.
;
;        SEQUENCE                          PrivateKeyInfo
;          INTEGER 0                       version
;          SEQUENCE                        AlgorithmIdentifier
;            OID id-ecPublicKey, OID prime256v1
;          OCTET STRING                    privateKey, wrapping:
;            SEQUENCE                      SEC1 ECPrivateKey
;              INTEGER 1                   version
;              OCTET STRING (32)           <- the scalar
;              [1] BIT STRING              publicKey, optional, ignored
;
;      The curve is pinned by the AlgorithmIdentifier compare: a P-384 or
;      secp256k1 key is refused here rather than being silently misused. ---
linnea_pem_p256_key:
    push rbx
    push r12
    push r13
    lea rdx, [pk_name]
    mov rcx, pk_name_len
    lea r8, [key_buf]
    mov r9, key_buf_cap
    call linnea_pem_decode
    cmp rax, 0
    jl .fail

    lea rbx, [key_buf]
    lea r13, [key_buf + rax]

    mov rdi, rbx                    ; SEQUENCE PrivateKeyInfo
    mov rsi, r13
    mov edx, 0x30
    call p256_der_open
    cmp rax, -1
    je .fail
    mov rbx, rax
    lea r13, [rax + rcx]

    mov rdi, rbx                    ; INTEGER 0
    mov rsi, r13
    mov edx, 0x02
    call p256_der_open
    cmp rax, -1
    je .fail
    cmp rcx, 1
    jne .fail
    cmp byte [rax], 0
    jne .fail
    lea rbx, [rax + rcx]

    mov rdi, rbx                    ; SEQUENCE AlgorithmIdentifier
    mov rsi, r13
    mov edx, 0x30
    call p256_der_open
    cmp rax, -1
    je .fail
    lea r12, [rax + rcx]            ; where the next element begins
    cmp rcx, alg_ec_len
    jne .fail
    mov rdi, rax
    lea rsi, [alg_ec]
    mov rcx, alg_ec_len
    call bytes_eq
    test eax, eax
    jz .fail
    mov rbx, r12

    mov rdi, rbx                    ; OCTET STRING privateKey
    mov rsi, r13
    mov edx, 0x04
    call p256_der_open
    cmp rax, -1
    je .fail
    mov rbx, rax
    lea r13, [rax + rcx]

    mov rdi, rbx                    ; SEQUENCE ECPrivateKey
    mov rsi, r13
    mov edx, 0x30
    call p256_der_open
    cmp rax, -1
    je .fail
    mov rbx, rax
    lea r13, [rax + rcx]

    mov rdi, rbx                    ; INTEGER 1
    mov rsi, r13
    mov edx, 0x02
    call p256_der_open
    cmp rax, -1
    je .fail
    cmp rcx, 1
    jne .fail
    cmp byte [rax], 1
    jne .fail
    lea rbx, [rax + rcx]

    mov rdi, rbx                    ; OCTET STRING, the scalar
    mov rsi, r13
    mov edx, 0x04
    call p256_der_open
    cmp rax, -1
    je .fail
    cmp rcx, 32                     ; SEC1 fixes this at ceil(log2 n / 8)
    jne .fail
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

section .rodata
; The AlgorithmIdentifier content for a prime256v1 key: OID id-ecPublicKey
; (1.2.840.10045.2.1) then OID prime256v1 (1.2.840.10045.3.1.7).
alg_ec:     db 0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01
            db 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07
alg_ec_len  equ $ - alg_ec
section .text

section .rodata
pk_name:    db "PRIVATE KEY"
pk_name_len equ $ - pk_name
section .text

; find_bytes(rdi=needle, rsi=needlelen, needle stays, rcx from bytes_eq) —
; scan [rbx, r13) for the needle; on success rbx points at the match and
; rax = 0, else rax = -1. Clobbers rax, rcx, r11 (not rbx on failure path
; leaves rbx at end).
find_bytes:
    mov r11, rsi             ; needlelen
.scan:
    mov rax, r13
    sub rax, rbx
    cmp rax, r11
    jb .miss
    push rdi
    push rsi
    mov rsi, rdi             ; needle
    mov rdi, rbx             ; haystack cursor
    mov rcx, r11
    call bytes_eq
    pop rsi
    pop rdi
    test eax, eax
    jnz .hit
    inc rbx
    jmp .scan
.hit:
    xor eax, eax
    ret
.miss:
    mov rax, -1
    ret

; bytes_eq(rdi=a, rsi=b, rcx=n) -> eax = 1 if equal. Preserves rdi/rsi.
bytes_eq:
    push rdi
    push rsi
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
    pop rsi
    pop rdi
    ret

; build_b64_table — fill b64_table: A-Z/a-z/0-9/+/ -> 0..63, else 0xff.
build_b64_table:
    lea rdi, [b64_table]
    mov eax, 0xff
    mov ecx, 256
    rep stosb
    lea rdi, [b64_table]
    xor ecx, ecx             ; value 0..63
.az:
    cmp ecx, 26
    jae .after_az
    mov byte [rdi + rcx + 'A'], cl
    inc ecx
    jmp .az
.after_az:
    xor ecx, ecx
.a_z:
    cmp ecx, 26
    jae .after_a_z
    lea eax, [ecx + 26]
    mov [rdi + rcx + 'a'], al
    inc ecx
    jmp .a_z
.after_a_z:
    xor ecx, ecx
.d09:
    cmp ecx, 10
    jae .after_09
    lea eax, [ecx + 52]
    mov [rdi + rcx + '0'], al
    inc ecx
    jmp .d09
.after_09:
    mov byte [b64_table + '+'], 62
    mov byte [b64_table + '/'], 63
    ret
