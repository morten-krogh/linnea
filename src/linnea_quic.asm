; linnea_quic.asm — QUIC (RFC 9000) transport helpers. Starts with the
; variable-length integer encoding (16): the top two bits of the first byte
; give the length (1/2/4/8 bytes) and the rest is a big-endian value.

default rel

%include "linnea_quic.inc"
%include "linnea_aesgcm.inc"

global linnea_quic_varint_decode
global linnea_quic_varint_encode
global linnea_quic_initial_dcid
global linnea_quic_unprotect
global linnea_quic_crypto_frame
global linnea_quic_recv_initial

extern linnea_quic_hp_mask
extern linnea_quic_initial_secrets
extern linnea_aesgcm_init
extern linnea_aesgcm_open

section .text

; linnea_quic_initial_dcid(rdi=packet, rsi=len) -> rax = DCID ptr, rdx = DCID
; len; rax = 0 on a malformed/short long-header packet. RFC 9000 17.2.
linnea_quic_initial_dcid:
    cmp rsi, 7                       ; b0 + version(4) + dcidlen + 1
    jb .bad
    test byte [rdi], 0x80            ; long header?
    jz .bad
    movzx edx, byte [rdi + 5]        ; DCID length
    cmp rdx, LINNEA_QUIC_MAX_CID
    ja .bad
    lea rax, [rdi + 6 + rdx]         ; end of DCID
    sub rax, rdi
    cmp rax, rsi
    ja .bad                          ; DCID runs past the datagram
    lea rax, [rdi + 6]
    ret
.bad:
    xor eax, eax
    xor edx, edx
    ret

; linnea_quic_unprotect(rdi=packet, rsi=len, rdx=keys, rcx=out)
;   -> rax = plaintext length, or -1 on a parse/AEAD failure.
; Removes header protection and AEAD-opens an Initial (long-header) packet,
; writing the frame bytes to out. RFC 9001 5.3 / 5.4.
%define U_AAD    0        ; unprotected header (AAD), <= 64 bytes
%define U_NONCE  64       ; 12-byte AEAD nonce
%define U_MASK   80       ; 5-byte header-protection mask (8 reserved)
%define U_HLEN   88       ; header length (= AAD length)
%define U_PNLEN  96       ; packet-number length
%define U_PN     104      ; decoded packet number
%define U_CTX    112      ; AES-GCM context (192 bytes)
linnea_quic_unprotect:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 312                     ; frame (keeps rsp 16-aligned for calls)
    mov rbx, rdi                     ; packet
    mov rbp, rsi                     ; packet length
    mov r12, rdx                     ; keys
    mov r13, rcx                     ; out
    ; --- parse the long header to the packet-number offset ---
    ; rdi is the cursor (varint_decode preserves rdi and rsi).
    movzx eax, byte [rbx + 5]        ; DCID length
    lea rdi, [rbx + 6]
    add rdi, rax                     ; -> SCID length
    movzx eax, byte [rdi]            ; SCID length
    inc rdi
    add rdi, rax                     ; -> token-length varint
    lea rsi, [rbx + rbp]             ; datagram end
    call linnea_quic_varint_decode   ; token length
    test rdx, rdx
    jz .err
    add rdi, rdx
    add rdi, rax                     ; skip the token
    call linnea_quic_varint_decode   ; length (pn + payload + tag)
    test rdx, rdx
    jz .err
    mov r15, rax                     ; length value
    add rdi, rdx                     ; -> packet number
    mov r14, rdi
    sub r14, rbx                     ; r14 = pn offset
    ; --- header protection: sample 16 bytes at pn_offset + 4 ---
    lea rdx, [r14 + 20]
    cmp rdx, rbp
    ja .err                          ; sample runs past the datagram
    lea rdi, [r12 + linnea_quic_keys.hp]
    lea rsi, [rbx + r14 + 4]
    lea rdx, [rsp + U_MASK]
    call linnea_quic_hp_mask
    ; unprotect the first byte (low 4 bits for a long header)
    movzx eax, byte [rbx]
    movzx edx, byte [rsp + U_MASK]
    and edx, 0x0f
    xor eax, edx
    mov r8d, eax                     ; unprotected b0
    mov ecx, eax
    and ecx, 3
    inc ecx                          ; pn length (1..4)
    mov [rsp + U_PNLEN], rcx
    lea rax, [r14 + rcx]             ; header length = pn_offset + pn_len
    mov [rsp + U_HLEN], rax
    ; --- copy the header into the AAD scratch, then unmask b0 + pn ---
    lea rsi, [rbx]
    lea rdi, [rsp + U_AAD]
    mov rcx, rax                     ; header length
    rep movsb
    mov [rsp + U_AAD], r8b           ; AAD[0] = unprotected first byte
    mov rcx, [rsp + U_PNLEN]
    lea rdi, [rsp + U_AAD + r14]     ; the pn bytes inside the AAD
    lea rsi, [rsp + U_MASK + 1]      ; mask[1..]
    xor edx, edx
.pn_unmask:
    mov al, [rdi + rdx]
    xor al, [rsi + rdx]
    mov [rdi + rdx], al
    inc edx
    cmp edx, ecx
    jb .pn_unmask
    ; decode the (truncated) packet number, big-endian
    xor eax, eax
    xor edx, edx
.pn_decode:
    shl rax, 8
    movzx r9d, byte [rdi + rdx]
    or rax, r9
    inc edx
    cmp edx, ecx
    jb .pn_decode
    mov [rsp + U_PN], rax
    ; --- nonce = iv XOR pn (right-aligned, big-endian) ---
    lea rsi, [r12 + linnea_quic_keys.iv]
    lea rdi, [rsp + U_NONCE]
    mov ecx, 12
    rep movsb
    mov rax, [rsp + U_PN]
    lea rdi, [rsp + U_NONCE + 11]
    mov ecx, 8
.nonce_xor:
    mov dl, al
    xor [rdi], dl
    dec rdi
    shr rax, 8
    dec ecx
    jnz .nonce_xor
    ; --- AEAD-open ---
    lea rdi, [rsp + U_CTX]
    lea rsi, [r12 + linnea_quic_keys.key]
    call linnea_aesgcm_init
    ; ct = packet + pn_offset + pn_len ; ctlen = length_value - pn_len
    mov r9, r15
    sub r9, [rsp + U_PNLEN]          ; ctlen (payload incl. 16-byte tag)
    lea r8, [rbx + r14]
    add r8, [rsp + U_PNLEN]          ; ct pointer
    ; bounds: pn_offset + length_value <= packet_len
    lea rax, [r14 + r15]
    cmp rax, rbp
    ja .err
    lea rdi, [rsp + U_CTX]
    lea rsi, [rsp + U_NONCE]
    lea rdx, [rsp + U_AAD]
    mov rcx, [rsp + U_HLEN]
    sub rsp, 16
    mov [rsp], r13                   ; out
    call linnea_aesgcm_open
    add rsp, 16
    test rax, rax
    js .err
    mov rax, r15
    sub rax, [rsp + U_PNLEN]
    sub rax, 16                      ; plaintext length = ctlen - tag
    jmp .done
.err:
    mov rax, -1
.done:
    add rsp, 312
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_crypto_frame(rdi=frames, rsi=len) -> rax = CRYPTO data ptr,
; rdx = CRYPTO data length (rax = 0 if none). Skips PADDING/PING and returns
; the first CRYPTO frame's data (RFC 9000 19.6); ACK etc. end the scan.
linnea_quic_crypto_frame:
    lea rsi, [rdi + rsi]             ; end (rsi is preserved across varint calls)
.scan:
    cmp rdi, rsi
    jae .none
    movzx eax, byte [rdi]
    test al, al                      ; PADDING (0x00)
    jz .skip1
    cmp al, 0x01                     ; PING
    je .skip1
    cmp al, 0x06                     ; CRYPTO
    je .crypto
    jmp .none                        ; any other frame: stop
.skip1:
    inc rdi
    jmp .scan
.crypto:
    inc rdi                          ; past the type
    call linnea_quic_varint_decode   ; offset (rdi=cursor, rsi=end preserved)
    test rdx, rdx
    jz .none
    add rdi, rdx
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .none
    mov r8, rax                      ; CRYPTO data length
    add rdi, rdx                     ; rdi -> CRYPTO data
    mov rax, rdi
    mov rdx, r8
    ret
.none:
    xor eax, eax
    xor edx, edx
    ret

; linnea_quic_recv_initial(rdi=datagram, rsi=len, rdx=plaintext buf)
;   -> rax = ClientHello ptr (into the plaintext buf), rdx = length;
;      rax = 0 if the datagram is not an Initial we can decrypt.
; Derives the Initial keys from the packet's own DCID, unprotects it, and
; returns the first CRYPTO frame's data (the TLS ClientHello). Reusable by the
; real server once the UDP loop is wired in.
linnea_quic_recv_initial:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 120                     ; client keys [0], server keys [48]
    mov rbx, rdi                     ; datagram
    mov r12, rsi                     ; length
    mov r13, rdx                     ; plaintext buffer
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_initial_dcid    ; rax = DCID ptr, rdx = DCID len
    test rax, rax
    jz .fail
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [rsp]                   ; client keys
    lea rcx, [rsp + 48]              ; server keys
    call linnea_quic_initial_secrets
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rsp]                   ; the client encrypts with its Initial keys
    mov rcx, r13
    call linnea_quic_unprotect       ; rax = plaintext length
    test rax, rax
    js .fail
    mov rdi, r13
    mov rsi, rax
    call linnea_quic_crypto_frame    ; rax = CH ptr, rdx = CH len
    jmp .rdone
.fail:
    xor eax, eax
    xor edx, edx
.rdone:
    add rsp, 120
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

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
