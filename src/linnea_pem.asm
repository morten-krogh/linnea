; linnea_pem.asm — minimal PEM decoding for the cert chain and key.
;
; linnea_pem_decode finds a "-----BEGIN <name>-----" / "-----END-----"
; block and base64-decodes its body (skipping any whitespace) into the
; caller's buffer. linnea_pem_ed25519_seed decodes a PKCS#8
; "PRIVATE KEY" block and returns the 32-byte Ed25519 seed, checking the
; one fixed DER prefix RFC 8410 mandates for this key type.
;
; Deliberately not a general PEM/DER parser: linnea only ever loads its
; own operator-supplied files, one leaf certificate and one key. Errors
; return -1; the caller turns that into a startup error_exit.
;
; ABI: System V; callee-saved preserved.

default rel

global linnea_pem_decode
global linnea_pem_ed25519_seed

section .rodata

begin_pfx:  db "-----BEGIN "
begin_len   equ $ - begin_pfx
end_pfx:    db "-----END "
end_len     equ $ - end_pfx
dashes5:    db "-----"

; PKCS#8 / RFC 8410 header for an Ed25519 private key: SEQUENCE, version
; 0, AlgorithmIdentifier {1.3.101.112}, then OCTET STRING wrapping the
; 32-byte CurvePrivateKey OCTET STRING.
pkcs8_ed:   db 0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06
            db 0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20
pkcs8_len   equ $ - pkcs8_ed

section .bss

alignb 8
b64_table:  resb 256          ; ASCII -> 6-bit value, 0xff for non-alphabet
seed_buf:   resb 48           ; decoded PKCS#8 key (16 prefix + 32 seed)

section .text

; ---- linnea_pem_decode(rdi=src, rsi=srclen, rdx=name, rcx=namelen,
;                        r8=out, r9=outcap) -> rax = DER length or -1 ---
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
    js .fail
    add rbx, begin_len
    mov rdi, rbx             ; the name must follow immediately
    mov rsi, r14
    mov rcx, r15
    call bytes_eq
    test eax, eax
    jz .fail
    add rbx, r15
    mov rdi, rbx             ; ...and then the closing dashes
    lea rsi, [dashes5]
    mov rcx, 5
    call bytes_eq
    test eax, eax
    jz .fail
    add rbx, 5

    call build_b64_table

    ; base64-decode until "-----END", accumulating bits
    xor r8d, r8d             ; bit accumulator
    xor r9d, r9d             ; bits held
    xor r10d, r10d           ; output length
.loop:
    cmp rbx, r13
    jae .fail                ; ran out before the END marker
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
    jae .fail                ; would overflow the caller's buffer
    mov [rbp + r10], al
    inc r10
    jmp .loop
.done:
    mov rax, r10
    jmp .ret
.fail:
    mov rax, -1
.ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- linnea_pem_ed25519_seed(rdi=src, rsi=srclen) -> rax = seed ptr or
;      -1. The returned pointer is a static 32-byte buffer. ------------
linnea_pem_ed25519_seed:
    push rbx
    lea rdx, [pk_name]
    mov rcx, pk_name_len
    lea r8, [seed_buf]
    mov r9, 48
    call linnea_pem_decode
    cmp rax, 48              ; PKCS#8 Ed25519 is exactly 48 bytes
    jne .fail
    lea rdi, [seed_buf]      ; verify the fixed 16-byte prefix
    lea rsi, [pkcs8_ed]
    mov rcx, pkcs8_len
    call bytes_eq
    test eax, eax
    jz .fail
    lea rax, [seed_buf + 16]
    pop rbx
    ret
.fail:
    mov rax, -1
    pop rbx
    ret

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
