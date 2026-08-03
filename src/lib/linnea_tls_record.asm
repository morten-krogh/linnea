; linnea_tls_record.asm — TLS 1.3 record protection (RFC 8446 5.2/5.3).
;
; One linnea_tls_keys per direction: AES-128-GCM schedule, static IV,
; and the record sequence number. The per-record nonce is the IV with
; the big-endian sequence number xored into its low 8 bytes. The AAD is
; the 5-byte record header. TLSInnerPlaintext is content || type ||
; zero padding; open strips the padding and rejects a padding-only
; record. Seal writes the payload into out+5 and encrypts it in place
; (linnea_aesgcm seal/open both support in-place operation).
;
; Sequence numbers advance on every seal and on successfully opened
; records only — a failed open kills the connection anyway.
;
; ABI: System V; callee-saved preserved.

default rel

%include "linnea_tls.inc"

global linnea_tls_keys_init
global linnea_tls_seal
global linnea_tls_open

extern linnea_tls_hkdf_expand_label
extern linnea_aesgcm_init
extern linnea_aesgcm_seal
extern linnea_aesgcm_open

section .rodata

lbl_key: db "key"
lbl_iv:  db "iv"

section .text

; rec_nonce — write the nonce for the keys' current sequence number.
; rdi = keys, rsi = 12-byte destination. Clobbers rax, rcx.
rec_nonce:
    mov rax, [rdi + linnea_tls_keys.seq]
    bswap rax
    mov ecx, [rdi + linnea_tls_keys.iv]
    mov [rsi], ecx
    mov rcx, [rdi + linnea_tls_keys.iv + 4]
    xor rcx, rax
    mov [rsi + 4], rcx
    ret

; ---- linnea_tls_keys_init(rdi=keys, rsi=secret32) --------------------
; Derive the traffic key and IV from a traffic secret and reset the
; sequence number.
linnea_tls_keys_init:
    push rbp
    push rbx
    sub rsp, 24
    mov rbp, rdi
    mov rbx, rsi

    mov rdi, rbx               ; key = HKDF-Expand-Label(secret, "key", 16)
    lea rsi, [lbl_key]
    mov edx, 3
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp + 8]
    mov qword [rsp], 16
    call linnea_tls_hkdf_expand_label
    lea rdi, [rbp + linnea_tls_keys.aes]
    lea rsi, [rsp + 8]
    call linnea_aesgcm_init

    mov rdi, rbx               ; iv = HKDF-Expand-Label(secret, "iv", 12)
    lea rsi, [lbl_iv]
    mov edx, 2
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rbp + linnea_tls_keys.iv]
    mov qword [rsp], 12
    call linnea_tls_hkdf_expand_label

    mov qword [rbp + linnea_tls_keys.seq], 0
    add rsp, 24
    pop rbx
    pop rbp
    ret

; ---- linnea_tls_seal(rdi=keys, esi=inner type, rdx=payload, rcx=len,
;                      r8=out) -> rax = total record length (len + 22) --
; out receives header || AES-GCM(payload || type) || tag. No padding is
; ever inserted. len must leave the record within 2^14 bytes (callers
; fragment; handshake flights and echoed app data are already bounded).
linnea_tls_seal:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40                ; [rsp] arg7, [rsp+16] nonce
    mov rbp, rdi               ; keys
    mov ebx, esi               ; inner type
    mov r12, rdx               ; payload
    mov r13, rcx               ; len
    mov r14, r8                ; out

    mov byte [r14], LINNEA_TLS_CT_APPDATA
    mov word [r14 + 1], 0x0303
    lea rax, [r13 + 17]        ; ciphertext length: len + type + tag
    xchg al, ah
    mov [r14 + 3], ax

    lea rdi, [r14 + 5]         ; payload || type into the record body
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov [rdi], bl

    mov rdi, rbp
    lea rsi, [rsp + 16]
    call rec_nonce
    inc qword [rbp + linnea_tls_keys.seq]

    lea rdi, [rbp + linnea_tls_keys.aes]
    lea rsi, [rsp + 16]
    mov rdx, r14               ; AAD = the record header
    mov ecx, 5
    lea r8, [r14 + 5]
    lea r9, [r13 + 1]
    lea rax, [r14 + 5]
    mov [rsp], rax             ; in-place seal
    call linnea_aesgcm_seal

    lea rax, [r13 + 22]
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ---- linnea_tls_open(rdi=keys, rsi=record, rdx=reclen, rcx=out) ------
; Opens one complete encrypted record (header included in record/reclen).
; Returns rax = content length and rdx = inner content type, or
; rax = -1 (bad type byte, bad tag, or padding-only plaintext; out is
; zeroed by the AEAD on a tag failure).
linnea_tls_open:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov rbp, rdi
    mov rbx, rsi               ; record
    mov r12, rdx               ; reclen
    mov r13, rcx               ; out

    cmp r12, 22                ; header + tag + at least the type byte
    jb .fail
    cmp byte [rbx], LINNEA_TLS_CT_APPDATA
    jne .fail

    mov rdi, rbp
    lea rsi, [rsp + 16]
    call rec_nonce             ; seq bumps only on success
    lea rdi, [rbp + linnea_tls_keys.aes]
    lea rsi, [rsp + 16]
    mov rdx, rbx               ; AAD = the record header
    mov ecx, 5
    lea r8, [rbx + 5]
    lea r9, [r12 - 5]
    mov [rsp], r13
    call linnea_aesgcm_open
    test rax, rax
    jnz .fail

    lea rcx, [r12 - 21]        ; plaintext length (type byte included)
.scan:                         ; strip the zero padding from the end
    test rcx, rcx
    jz .fail                   ; nothing but padding: no content type
    movzx edx, byte [r13 + rcx - 1]
    test dl, dl
    jnz .found
    dec rcx
    jmp .scan
.found:
    inc qword [rbp + linnea_tls_keys.seq]
    lea rax, [rcx - 1]         ; content length excludes the type byte
    jmp .done
.fail:
    mov rax, -1
    xor edx, edx
.done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
