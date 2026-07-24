; linnea_quic.asm — QUIC (RFC 9000) transport helpers. Starts with the
; variable-length integer encoding (16): the top two bits of the first byte
; give the length (1/2/4/8 bytes) and the rest is a big-endian value.

default rel

%include "linnea_quic.inc"
%include "linnea_aesgcm.inc"
%include "linnea_quic_conn.inc"   ; for LINNEA_QUIC_RA_BUF (transport-param bound)

global linnea_quic_varint_decode
global linnea_quic_varint_encode
global linnea_quic_initial_dcid
global linnea_quic_unprotect
global linnea_quic_unprotect_hs
global linnea_quic_unprotect_short
global linnea_quic_crypto_frame
global linnea_quic_stream_frame
global linnea_quic_close_frame
global linnea_quic_ack_record
global linnea_quic_build_ack
global linnea_quic_ack_ranges
global linnea_quic_recv_initial
global linnea_quic_protect
global linnea_quic_ch_parse
global linnea_quic_alpn_has
global linnea_quic_build_transport_params
global linnea_quic_tp_parse
global linnea_quic_flow_scan
global linnea_quic_parse_priority
global linnea_quic_reset_scan
global linnea_quic_build_sh
global linnea_quic_build_ee
global linnea_quic_build_cert
global linnea_quic_build_cert_verify
global linnea_quic_build_finished

extern linnea_quic_hp_mask
extern linnea_quic_initial_secrets
extern linnea_aesgcm_init
extern linnea_aesgcm_open
extern linnea_aesgcm_seal
extern linnea_sha256
extern linnea_hmac_sha256
extern linnea_quic_early_ok
extern linnea_p256_ecdsa_sign
extern linnea_tls_hkdf_expand_label

section .rodata
; CertificateVerify signed content prefix (RFC 8446 4.4.3): 64 spaces, the
; context string, and a 0x00 separator; the transcript hash follows at runtime.
cv_prefix:    times 64 db 0x20
              db "TLS 1.3, server CertificateVerify"
              db 0x00
cv_prefix_len equ $ - cv_prefix
lbl_finished: db "finished"

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
;   -> rax = plaintext length (or -1), rdx = the packet number.
; Removes header protection and AEAD-opens an Initial (long-header) packet,
; writing the frame bytes to out. RFC 9001 5.3 / 5.4.
%define U_AAD    0        ; unprotected header (AAD), <= 64 bytes
%define U_NONCE  64       ; 12-byte AEAD nonce
%define U_MASK   80       ; 5-byte header-protection mask (8 reserved)
%define U_HLEN   88       ; header length (= AAD length)
%define U_PNLEN  96       ; packet-number length
%define U_PN     104      ; decoded packet number
%define U_HASTOK 304      ; 1 for an Initial (has a token), 0 for a Handshake
%define U_CTX    112      ; AES-GCM context (192 bytes)
; Initial packets carry a token; Handshake packets do not. Both entry points
; share the body; U_HASTOK selects whether the token varint is skipped.
linnea_quic_unprotect_hs:
    xor r8d, r8d                     ; no token
    jmp unprotect_body
linnea_quic_unprotect:
    mov r8d, 1                       ; token present
unprotect_body:
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
    mov [rsp + U_HASTOK], r8         ; token-present flag
    ; --- parse the long header to the packet-number offset ---
    ; rdi is the cursor (varint_decode preserves rdi and rsi).
    movzx eax, byte [rbx + 5]        ; DCID length
    lea rdi, [rbx + 6]
    add rdi, rax                     ; -> SCID length
    movzx eax, byte [rdi]            ; SCID length
    inc rdi
    add rdi, rax                     ; -> token-length varint (Initial) or length
    lea rsi, [rbx + rbp]             ; datagram end
    cmp qword [rsp + U_HASTOK], 0
    je .no_token
    call linnea_quic_varint_decode   ; token length
    test rdx, rdx
    jz .err
    add rdi, rdx
    add rdi, rax                     ; skip the token
.no_token:
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
    mov rdx, [rsp + U_PN]            ; and the packet number, for acknowledging
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

; linnea_quic_unprotect_short(rdi=packet, rsi=len, rdx=keys, rcx=out, r8=dcid_len,
;   r9=expected pn) -> rax = plaintext length (or -1), rdx = the packet number.
; Removes header protection and AEAD-opens a short-header (1-RTT) packet. The
; destination connection-id length must be supplied — short headers carry no
; length field for it. RFC 9001 5.3 / 5.4.
; The wire carries only the packet number's low bits, so the true number is
; recovered against r9 = the next number the caller expects from this peer
; (largest received + 1; 0 when nothing has been received). Without the
; expansion a peer whose number outgrows its truncation window would XOR the
; wrong value into the nonce and every later packet would fail to open.
%define S_AAD    0        ; unprotected header (AAD)
%define S_NONCE  64
%define S_MASK   80
%define S_HLEN   88
%define S_PNLEN  96
%define S_PN     104
%define S_CTX    112
%define S_EXP    312      ; expected packet number (r9 at entry)
%define S_PHASE  320      ; key-phase bit read after header protection (-1 if too short)
linnea_quic_unprotect_short:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 328
    mov [rsp + S_EXP], r9
    mov qword [rsp + S_PHASE], -1    ; until header protection is removed (below)
    mov rbx, rdi                     ; packet
    mov rbp, rsi                     ; packet length
    mov r12, rdx                     ; keys
    mov r13, rcx                     ; out
    lea r14, [r8 + 1]                ; pn offset = 1 (first byte) + DCID length
    ; --- header protection: sample 16 bytes at pn_offset + 4 ---
    lea rdx, [r14 + 20]
    cmp rdx, rbp
    ja .serr
    lea rdi, [r12 + linnea_quic_keys.hp]
    lea rsi, [rbx + r14 + 4]
    lea rdx, [rsp + S_MASK]
    call linnea_quic_hp_mask
    ; unprotect the first byte (low 5 bits for a short header)
    movzx eax, byte [rbx]
    movzx edx, byte [rsp + S_MASK]
    and edx, 0x1f
    xor eax, edx
    mov r8d, eax                     ; unprotected b0
    ; capture the key-phase bit (0x04) for the caller: a key update flips it, and
    ; it is only readable now that header protection has been removed.
    mov r9d, r8d
    and r9d, 0x04
    shr r9d, 2                       ; 0 or 1
    mov [rsp + S_PHASE], r9
    mov ecx, eax
    and ecx, 3
    inc ecx                          ; pn length (1..4)
    mov [rsp + S_PNLEN], rcx
    lea rax, [r14 + rcx]
    mov [rsp + S_HLEN], rax          ; header length = pn_offset + pn_len
    ; --- copy the header into the AAD scratch, then unmask b0 + pn ---
    lea rsi, [rbx]
    lea rdi, [rsp + S_AAD]
    mov rcx, rax
    rep movsb
    mov [rsp + S_AAD], r8b
    mov rcx, [rsp + S_PNLEN]
    lea rdi, [rsp + S_AAD + r14]
    lea rsi, [rsp + S_MASK + 1]
    xor edx, edx
.s_pnunmask:
    mov al, [rdi + rdx]
    xor al, [rsi + rdx]
    mov [rdi + rdx], al
    inc edx
    cmp edx, ecx
    jb .s_pnunmask
    ; decode the (truncated) packet number, big-endian
    xor eax, eax
    xor edx, edx
.s_pndecode:
    shl rax, 8
    movzx r9d, byte [rdi + rdx]
    or rax, r9
    inc edx
    cmp edx, ecx
    jb .s_pndecode
    ; expand against the expected number (RFC 9000 A.3): the true number is the
    ; candidate with these low bits closest to it. The expansion happens before
    ; the nonce is formed — the nonce takes the full number, not the wire bits.
    mov r9, [rsp + S_EXP]            ; expected
    mov ecx, [rsp + S_PNLEN]
    shl ecx, 3                       ; bits carried on the wire
    mov rdx, 1
    shl rdx, cl                      ; win  = 1 << bits
    mov r10, rdx
    shr r10, 1                       ; hwin = win / 2
    lea r11, [rdx - 1]               ; mask = win - 1
    not r11
    mov r8, r9
    and r8, r11                      ; expected & ~mask
    or r8, rax                       ; candidate
    lea rcx, [r8 + r10]
    cmp rcx, r9
    ja .s_pn_nolow
    add r8, rdx                      ; candidate <= expected - hwin: next window
    jmp .s_pn_expanded
.s_pn_nolow:
    lea rcx, [r9 + r10]
    cmp r8, rcx
    jbe .s_pn_expanded
    cmp r8, rdx
    jb .s_pn_expanded
    sub r8, rdx                      ; candidate > expected + hwin: previous window
.s_pn_expanded:
    mov rax, r8
    mov [rsp + S_PN], rax
    ; --- nonce = iv XOR pn (right-aligned) ---
    lea rsi, [r12 + linnea_quic_keys.iv]
    lea rdi, [rsp + S_NONCE]
    mov ecx, 12
    rep movsb
    mov rax, [rsp + S_PN]
    lea rdi, [rsp + S_NONCE + 11]
    mov ecx, 8
.s_nonce:
    mov dl, al
    xor [rdi], dl
    dec rdi
    shr rax, 8
    dec ecx
    jnz .s_nonce
    ; --- AEAD-open: ct = packet + header_len, ctlen = packet_len - header_len ---
    lea rdi, [rsp + S_CTX]
    lea rsi, [r12 + linnea_quic_keys.key]
    call linnea_aesgcm_init
    mov r9, rbp
    sub r9, [rsp + S_HLEN]           ; ctlen (payload incl. 16-byte tag)
    lea r8, [rbx]
    add r8, [rsp + S_HLEN]           ; ct pointer
    lea rdi, [rsp + S_CTX]
    lea rsi, [rsp + S_NONCE]
    lea rdx, [rsp + S_AAD]
    mov rcx, [rsp + S_HLEN]
    sub rsp, 16
    mov [rsp], r13                   ; out
    call linnea_aesgcm_open
    add rsp, 16
    test rax, rax
    js .serr
    mov rax, rbp
    sub rax, [rsp + S_HLEN]
    sub rax, 16                      ; plaintext length = ctlen - tag
    mov rdx, [rsp + S_PN]            ; and the packet number, for acknowledging
    jmp .sdone
.serr:
    mov rax, -1
.sdone:
    mov r8, [rsp + S_PHASE]          ; key-phase bit (or -1 if the packet was too short)
    add rsp, 328
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_stream_frame(rdi=frames, rsi=len) -> rax = STREAM data ptr,
; rdx = STREAM data length, r8 = stream id, r9 = first byte after this frame,
; r10 = the stream data offset (0 when no OFF field is present — a stream's type
; byte is only at offset 0), r11 = 1 if the FIN bit is set (the stream ends here).
; rax = 0 if none. Skips PADDING/PING/ACK and returns the first STREAM frame's
; data (RFC 9000 19.8). The type byte 0b00001XXX carries OFF (0x04), LEN (0x02)
; and FIN (0x01) flags. r9 lets the caller resume the scan, so a packet carrying
; several STREAM frames (requests on different streams) can be walked in full;
; a frame with no LEN runs to the end of the packet, so r9 is then the end.
linnea_quic_stream_frame:
    push rbx
    push r12
    push r13
    lea rsi, [rdi + rsi]             ; end (preserved across varint calls)
.ss_scan:
    cmp rdi, rsi
    jae .ss_none
    movzx ebx, byte [rdi]            ; frame type
    test bl, bl                      ; PADDING
    jz .ss_skip1
    cmp bl, 0x01                     ; PING
    je .ss_skip1
    cmp bl, 0x02                     ; ACK
    je .ss_ack
    cmp bl, 0x03                     ; ACK w/ ECN
    je .ss_ack
    mov eax, ebx
    and eax, 0xf8
    cmp eax, 0x08                    ; STREAM (0b00001xxx)
    je .ss_stream
    ; A STREAM frame can be coalesced after other frames (a peer commonly bundles
    ; NEW_CONNECTION_ID, flow-control or path frames ahead of stream data), so
    ; skip any known frame type rather than stopping (RFC 9000 19).
    cmp bl, 0x1e                     ; HANDSHAKE_DONE (no payload)
    je .ss_skip1
    cmp bl, 0x1a                     ; PATH_CHALLENGE (8 bytes)
    je .ss_skip8
    cmp bl, 0x1b                     ; PATH_RESPONSE (8 bytes)
    je .ss_skip8
    cmp bl, 0x18                     ; NEW_CONNECTION_ID
    je .ss_ncid
    cmp bl, 0x06                     ; CRYPTO (offset, length, data)
    je .ss_crypto
    cmp bl, 0x07                     ; NEW_TOKEN (length, token)
    je .ss_token
    cmp bl, 0x04                     ; RESET_STREAM (3 varints)
    je .ss_v3
    cmp bl, 0x05                     ; STOP_SENDING (2 varints)
    je .ss_v2
    cmp bl, 0x11                     ; MAX_STREAM_DATA (2 varints)
    je .ss_v2
    cmp bl, 0x15                     ; STREAM_DATA_BLOCKED (2 varints)
    je .ss_v2
    cmp bl, 0x10                     ; MAX_DATA (1 varint)
    je .ss_v1
    cmp bl, 0x12                     ; MAX_STREAMS bidi (1 varint)
    je .ss_v1
    cmp bl, 0x13                     ; MAX_STREAMS uni (1 varint)
    je .ss_v1
    cmp bl, 0x14                     ; DATA_BLOCKED (1 varint)
    je .ss_v1
    cmp bl, 0x16                     ; STREAMS_BLOCKED bidi (1 varint)
    je .ss_v1
    cmp bl, 0x17                     ; STREAMS_BLOCKED uni (1 varint)
    je .ss_v1
    cmp bl, 0x19                     ; RETIRE_CONNECTION_ID (1 varint)
    je .ss_v1
    jmp .ss_none                     ; a frame we do not recognise: stop
.ss_skip1:
    inc rdi
    jmp .ss_scan
.ss_skip8:
    add rdi, 9                       ; type byte + 8 fixed bytes
    jmp .ss_scan
.ss_v1:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    jmp .ss_scan
.ss_v2:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    jmp .ss_scan
.ss_v3:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    jmp .ss_scan
.ss_token:
    inc rdi
    call linnea_quic_varint_decode   ; token length
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    add rdi, rax                      ; skip the token bytes
    jmp .ss_scan
.ss_crypto:
    inc rdi
    call linnea_quic_varint_decode   ; offset
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    add rdi, rax                      ; skip the crypto data
    jmp .ss_scan
.ss_ncid:
    inc rdi
    call linnea_quic_varint_decode   ; sequence number
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; retire prior to
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    cmp rdi, rsi
    jae .ss_none
    movzx eax, byte [rdi]             ; connection id length
    add rdi, 1
    add rdi, rax                      ; skip the connection id
    add rdi, 16                       ; skip the stateless reset token
    jmp .ss_scan
.ss_ack:
    inc rdi
    call linnea_quic_varint_decode   ; Largest Acknowledged
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Delay
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Count
    test rdx, rdx
    jz .ss_none
    mov r12, rax
    add rdi, rdx
    call linnea_quic_varint_decode   ; First ACK Range
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
.ss_ackr:
    test r12, r12
    jz .ss_ackecn
    call linnea_quic_varint_decode   ; Gap
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Length
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    dec r12
    jmp .ss_ackr
.ss_ackecn:
    cmp bl, 0x03
    jne .ss_scan
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ss_none
    add rdi, rdx
    jmp .ss_scan
.ss_stream:
    inc rdi                          ; past the type
    call linnea_quic_varint_decode   ; stream id
    test rdx, rdx
    jz .ss_none
    mov r13, rax                     ; stream id
    add rdi, rdx
    xor r10d, r10d                   ; offset defaults to 0 (no OFF field)
    test bl, 0x04                    ; OFF flag: an offset field is present
    jz .ss_nooff
    call linnea_quic_varint_decode   ; offset
    test rdx, rdx
    jz .ss_none
    mov r10, rax                     ; stream data offset (survives the LEN decode)
    add rdi, rdx
.ss_nooff:
    test bl, 0x02                    ; LEN flag: an explicit length field
    jz .ss_tolen
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .ss_none
    mov r12, rax                     ; data length
    add rdi, rdx
    jmp .ss_have
.ss_tolen:
    mov r12, rsi                     ; no LEN: data runs to the frame's end
    sub r12, rdi
.ss_have:
    ; the declared data length must stay within the packet (RFC 9000 19.8): with an
    ; explicit LEN a peer can claim more bytes than the datagram holds, and the
    ; length is used as a copy/parse size downstream — reject the frame rather than
    ; read past the plaintext buffer. (The no-LEN branch above set r12 = end - rdi,
    ; so it lands exactly on the end and passes.)
    lea rax, [rdi + r12]
    cmp rax, rsi
    ja .ss_none
    mov rax, rdi                     ; data pointer
    mov rdx, r12                     ; data length
    mov r8, r13                      ; stream id
    lea r9, [rdi + r12]              ; resume point for the next frame
    mov r11d, ebx
    and r11d, 1                      ; FIN flag (bl bit 0) — bl still the type byte
    pop r13
    pop r12
    pop rbx
    ret
.ss_none:
    xor eax, eax
    xor edx, edx
    pop r13
    pop r12
    pop rbx
    ret

; Acknowledgement state for one packet-number space: three qwords —
;   [0] have  : 0 until the first packet arrives (0 is a real packet number)
;   [1] largest: the highest packet number seen
;   [2] mask  : bit i set = packet (largest - 1 - i) also arrived
; A 64-packet window behind the largest is plenty to describe what we hold
; while a peer has anything in flight, and it costs no allocation.

; linnea_quic_ack_record(rdi=state, rsi=packet number) — note a packet as
; received. Reordering is handled: a packet below the largest sets its bit, and
; a later packet shifts the window up.
linnea_quic_ack_record:
    cmp qword [rdi], 0
    jne .ar_have
    mov qword [rdi], 1               ; first packet in this space
    mov [rdi + 8], rsi
    mov qword [rdi + 16], 0
    ret
.ar_have:
    mov rax, [rdi + 8]               ; largest
    cmp rsi, rax
    ja .ar_newer
    je .ar_done                      ; duplicate
    ; older packet: set its bit if it still falls inside the window
    sub rax, rsi
    dec rax                          ; offset below largest
    cmp rax, 64
    jae .ar_done                     ; too old to describe
    mov rcx, rax
    mov rdx, 1
    shl rdx, cl
    or [rdi + 16], rdx
    ret
.ar_newer:
    mov rcx, rsi
    sub rcx, rax                     ; delta
    cmp rcx, 64
    jae .ar_reset                    ; the old window falls off entirely
    mov rdx, [rdi + 16]
    shl rdx, cl
    mov rax, 1
    dec rcx
    shl rax, cl                      ; the old largest is now delta-1 below
    or rdx, rax
    mov [rdi + 16], rdx
    mov [rdi + 8], rsi
    ret
.ar_reset:
    mov qword [rdi + 16], 0
    mov [rdi + 8], rsi
.ar_done:
    ret

; linnea_quic_build_ack(rdi=out, rsi=state) -> rax = bytes written (0 if
; nothing has been received yet). Emits one ACK frame covering the largest
; packet and the unbroken run below it (RFC 9000 19.3). Packets under a gap are
; left unacknowledged — acknowledging less than we hold is always safe, whereas
; claiming a packet we never saw would suppress a retransmission we need.
linnea_quic_build_ack:
    push rbx
    push r12
    push r13
    push r14
    cmp qword [rsi], 0
    je .ba_none
    mov r14, rdi                     ; out start
    mov rbx, rdi                     ; out cursor
    mov r12, [rsi + 8]               ; largest
    mov r13, [rsi + 16]              ; mask
    ; the unbroken run below the largest is the set bits from bit 0 up, which
    ; is where the first zero of the complement sits
    mov rax, r13
    not rax
    bsf rcx, rax
    jnz .ba_run
    mov ecx, 64                      ; every bit set: a full window
.ba_run:
    cmp rcx, r12
    jbe .ba_cap                      ; the run cannot reach below packet 0
    mov rcx, r12
.ba_cap:
    mov r13, rcx                     ; First ACK Range
    mov byte [rbx], 0x02             ; ACK, without ECN counts
    inc rbx
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_varint_encode   ; Largest Acknowledged
    add rbx, rax
    mov rdi, rbx
    xor esi, esi
    call linnea_quic_varint_encode   ; ACK Delay (we do not measure one)
    add rbx, rax
    mov rdi, rbx
    xor esi, esi
    call linnea_quic_varint_encode   ; ACK Range Count: only the first range
    add rbx, rax
    mov rdi, rbx
    mov rsi, r13
    call linnea_quic_varint_encode   ; First ACK Range
    add rbx, rax
    mov rax, rbx
    sub rax, r14                     ; bytes written
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.ba_none:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_ack_ranges(rdi=frames, rsi=len, rdx=out, rcx=max pairs)
;   -> rax = number of acknowledged [smallest, largest] pairs written to out
;   (0 if the packet carries no ACK frame, or on a malformed one). Each pair is
;   two qwords. The first ACK frame among the leading frames is decoded (PADDING
;   and PING are stepped over; any other frame ends the search) into its ranges
;   (RFC 9000 19.3): the caller frees the buffered packets each range covers.
;   A peer coalescing an ACK with stream data places the ACK first, so the
;   leading scan reaches it. ECN counts, if present, follow the ranges and need
;   not be read — we stop once the ranges are done.
linnea_quic_ack_ranges:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    lea rsi, [rdi + rsi]             ; end (preserved across varint calls)
    mov r14, rdx                     ; out cursor
    mov rbp, rcx                     ; max pairs
    xor r15d, r15d                   ; pairs written
.scan:
    cmp rdi, rsi
    jae .ret
    movzx eax, byte [rdi]
    test al, al                      ; PADDING
    jz .skip1
    cmp al, 0x01                     ; PING
    je .skip1
    cmp al, 0x02                     ; ACK
    je .ack
    cmp al, 0x03                     ; ACK with ECN counts
    je .ack
    ; A real peer coalesces its ACK BEHIND other frames (NEW_CONNECTION_ID, a
    ; MAX_DATA, a retransmitted STREAM, ...), not always first, so skip every known
    ; frame to reach it rather than giving up — a missed ACK never frees the buffered
    ; packets or the in-flight response chunks, and the transfer stalls with its
    ; congestion window full. Same complete walk as linnea_quic_stream_frame.
    mov edx, eax
    and edx, 0xf8
    cmp edx, 0x08                    ; STREAM (0x08-0x0f)
    je .astream
    cmp al, 0x1e                     ; HANDSHAKE_DONE (no payload)
    je .skip1
    cmp al, 0x1a                     ; PATH_CHALLENGE (8 bytes)
    je .askip8
    cmp al, 0x1b                     ; PATH_RESPONSE (8 bytes)
    je .askip8
    cmp al, 0x18                     ; NEW_CONNECTION_ID
    je .ancid
    cmp al, 0x06                     ; CRYPTO (offset, length, data)
    je .acrypto
    cmp al, 0x07                     ; NEW_TOKEN (length, token)
    je .atoken
    cmp al, 0x04                     ; RESET_STREAM (3 varints)
    je .av3
    cmp al, 0x05                     ; STOP_SENDING (2 varints)
    je .av2
    cmp al, 0x11                     ; MAX_STREAM_DATA (2 varints)
    je .av2
    cmp al, 0x15                     ; STREAM_DATA_BLOCKED (2 varints)
    je .av2
    cmp al, 0x10                     ; MAX_DATA (1 varint)
    je .av1
    cmp al, 0x12                     ; MAX_STREAMS bidi (1 varint)
    je .av1
    cmp al, 0x13                     ; MAX_STREAMS uni (1 varint)
    je .av1
    cmp al, 0x14                     ; DATA_BLOCKED (1 varint)
    je .av1
    cmp al, 0x16                     ; STREAMS_BLOCKED bidi (1 varint)
    je .av1
    cmp al, 0x17                     ; STREAMS_BLOCKED uni (1 varint)
    je .av1
    cmp al, 0x19                     ; RETIRE_CONNECTION_ID (1 varint)
    je .av1
    jmp .ret                         ; truly unknown (e.g. CONNECTION_CLOSE): stop
.skip1:
    inc rdi
    jmp .scan
.askip8:
    add rdi, 9                       ; type byte + 8 fixed bytes
    jmp .scan
.av1:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ret
    add rdi, rdx
    jmp .scan
.av2:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ret
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ret
    add rdi, rdx
    jmp .scan
.av3:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ret
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ret
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ret
    add rdi, rdx
    jmp .scan
.atoken:
    inc rdi
    call linnea_quic_varint_decode   ; token length
    test rdx, rdx
    jz .ret
    add rdi, rdx
    add rdi, rax                      ; skip the token bytes
    jmp .scan
.acrypto:
    inc rdi
    call linnea_quic_varint_decode   ; offset
    test rdx, rdx
    jz .ret
    add rdi, rdx
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .ret
    add rdi, rdx
    add rdi, rax                      ; skip the crypto data
    jmp .scan
.ancid:
    inc rdi
    call linnea_quic_varint_decode   ; sequence number
    test rdx, rdx
    jz .ret
    add rdi, rdx
    call linnea_quic_varint_decode   ; retire prior to
    test rdx, rdx
    jz .ret
    add rdi, rdx
    cmp rdi, rsi
    jae .ret
    movzx eax, byte [rdi]             ; connection id length
    add rdi, 1
    add rdi, rax                      ; skip the connection id
    add rdi, 16                       ; skip the stateless reset token
    jmp .scan
.astream:
    mov r12d, eax                    ; save the STREAM type bits (OFF/LEN/FIN)
    inc rdi
    call linnea_quic_varint_decode   ; stream id
    test rdx, rdx
    jz .ret
    add rdi, rdx
    test r12b, 0x04                  ; OFF present?
    jz .astream_len
    call linnea_quic_varint_decode   ; offset
    test rdx, rdx
    jz .ret
    add rdi, rdx
.astream_len:
    test r12b, 0x02                  ; LEN present?
    jz .ret                          ; no LEN: data runs to the packet end — stop
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .ret
    add rdi, rdx
    add rdi, rax                      ; skip the stream data
    jmp .scan
.ack:
    inc rdi                          ; past the type
    call linnea_quic_varint_decode   ; Largest Acknowledged
    test rdx, rdx
    jz .ret
    add rdi, rdx
    mov r12, rax                     ; largest of the current range
    call linnea_quic_varint_decode   ; ACK Delay
    test rdx, rdx
    jz .ret
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Count
    test rdx, rdx
    jz .ret
    add rdi, rdx
    mov r13, rax                     ; additional ranges to follow
    call linnea_quic_varint_decode   ; First ACK Range
    test rdx, rdx
    jz .ret
    add rdi, rdx
    ; first range: [largest - first, largest]
    mov r8, r12
    sub r8, rax                      ; smallest
    mov r9, r12                      ; largest
    mov rbx, r8                      ; remember the smallest for the next gap
    call .emit
.rloop:
    test r13, r13
    jz .ret
    call linnea_quic_varint_decode   ; Gap
    test rdx, rdx
    jz .ret
    add rdi, rdx
    mov r10, rax                     ; gap (r10 survives varint_decode)
    call linnea_quic_varint_decode   ; ACK Range Length
    test rdx, rdx
    jz .ret
    add rdi, rdx
    mov r11, rax                     ; length (r11 survives varint_decode)
    ; next range: largest = prev smallest - gap - 2, smallest = largest - length
    mov r9, rbx
    sub r9, r10
    sub r9, 2
    mov r8, r9
    sub r8, r11
    mov rbx, r8
    call .emit
    dec r13
    jmp .rloop
.ret:
    mov rax, r15
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; .emit(r8=smallest, r9=largest) — append one pair unless the caller's buffer is
; full. Preserves rdi/rsi (the frame cursor) and the range registers.
.emit:
    cmp r15, rbp
    jae .emit_ret                    ; buffer full: count no more
    mov [r14], r8
    mov [r14 + 8], r9
    add r14, 16
    inc r15
.emit_ret:
    ret

; linnea_quic_close_frame(rdi=frames, rsi=len) -> rax = 1 if the packet carries
; a CONNECTION_CLOSE (0x1c transport, 0x1d application), else 0. A peer closing
; down sends it alone or straight after an ACK, so the walk only needs to step
; over PADDING/PING/ACK; anything else ends the scan. Missing a close buried
; behind other frames costs nothing — the idle sweep still reclaims the slot.
linnea_quic_close_frame:
    push rbx
    push r12
    lea rsi, [rdi + rsi]             ; end
.cf_scan:
    cmp rdi, rsi
    jae .cf_none
    movzx ebx, byte [rdi]
    cmp bl, 0x1c
    je .cf_yes
    cmp bl, 0x1d
    je .cf_yes
    test bl, bl                      ; PADDING
    jz .cf_skip1
    cmp bl, 0x01                     ; PING
    je .cf_skip1
    cmp bl, 0x02                     ; ACK
    je .cf_ack
    cmp bl, 0x03                     ; ACK with ECN
    je .cf_ack
    jmp .cf_none
.cf_skip1:
    inc rdi
    jmp .cf_scan
.cf_ack:
    inc rdi
    call linnea_quic_varint_decode   ; Largest Acknowledged
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Delay
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Count
    test rdx, rdx
    jz .cf_none
    mov r12, rax
    add rdi, rdx
    call linnea_quic_varint_decode   ; First ACK Range
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
.cf_range:
    test r12, r12
    jz .cf_ecn
    call linnea_quic_varint_decode   ; Gap
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Length
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
    dec r12
    jmp .cf_range
.cf_ecn:
    cmp bl, 0x03
    jne .cf_scan
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .cf_none
    add rdi, rdx
    jmp .cf_scan
.cf_yes:
    mov eax, 1
    pop r12
    pop rbx
    ret
.cf_none:
    xor eax, eax
    pop r12
    pop rbx
    ret

; linnea_quic_crypto_frame(rdi=frames, rsi=len) -> rax = CRYPTO data ptr,
; rdx = CRYPTO data length, r8 = CRYPTO offset (rax = 0 if none). Skips
; PADDING/PING/ACK and returns the first CRYPTO frame's data (RFC 9000 19.6).
; ACK (0x02/0x03) is fully skipped so a Handshake packet that acks the server
; before its Finished still yields the CRYPTO data. Any other frame ends the
; scan. The offset lets the caller reassemble a CRYPTO stream (a ClientHello too
; large for one Initial packet) across packets.
linnea_quic_crypto_frame:
    push rbx
    push r12
    lea rsi, [rdi + rsi]             ; end (rsi preserved across varint calls)
.scan:
    cmp rdi, rsi
    jae .none
    movzx ebx, byte [rdi]            ; frame type (kept in bl across varints)
    test bl, bl                      ; PADDING (0x00)
    jz .skip1
    cmp bl, 0x01                     ; PING
    je .skip1
    cmp bl, 0x06                     ; CRYPTO
    je .crypto
    cmp bl, 0x02                     ; ACK
    je .ack
    cmp bl, 0x03                     ; ACK with ECN counts
    je .ack
    jmp .none                        ; any other frame: stop
.skip1:
    inc rdi
    jmp .scan
.ack:
    inc rdi                          ; past the type
    call linnea_quic_varint_decode   ; Largest Acknowledged
    test rdx, rdx
    jz .none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Delay
    test rdx, rdx
    jz .none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Count
    test rdx, rdx
    jz .none
    mov r12, rax                     ; number of additional ranges
    add rdi, rdx
    call linnea_quic_varint_decode   ; First ACK Range
    test rdx, rdx
    jz .none
    add rdi, rdx
.ack_range:
    test r12, r12
    jz .ack_ecn
    call linnea_quic_varint_decode   ; Gap
    test rdx, rdx
    jz .none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Length
    test rdx, rdx
    jz .none
    add rdi, rdx
    dec r12
    jmp .ack_range
.ack_ecn:
    cmp bl, 0x03                     ; only 0x03 carries the three ECN counts
    jne .scan
    call linnea_quic_varint_decode   ; ECT0
    test rdx, rdx
    jz .none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ECT1
    test rdx, rdx
    jz .none
    add rdi, rdx
    call linnea_quic_varint_decode   ; ECN-CE
    test rdx, rdx
    jz .none
    add rdi, rdx
    jmp .scan
.crypto:
    inc rdi                          ; past the type
    call linnea_quic_varint_decode   ; offset (rdi=cursor, rsi=end preserved)
    test rdx, rdx
    jz .none
    push rax                         ; keep the offset across the length varint
    add rdi, rdx
    call linnea_quic_varint_decode   ; length
    pop r8                           ; r8 = CRYPTO offset
    test rdx, rdx
    jz .none
    mov r12, rax                     ; CRYPTO data length
    add rdi, rdx                     ; rdi -> CRYPTO data
    ; the declared length must stay within the packet (RFC 9000 19.6): it is used
    ; as a copy size into the ClientHello reassembly buffer, so reject an
    ; overrunning frame rather than read past the plaintext.
    lea rax, [rdi + r12]
    cmp rax, rsi
    ja .none
    mov rax, rdi
    mov rdx, r12
    pop r12
    pop rbx
    ret
.none:
    xor eax, eax
    xor edx, edx
    xor r8d, r8d
    pop r12
    pop rbx
    ret

; linnea_quic_build_cert_verify(rdi=out, rsi=transcript hash H(CH..Cert),
;   rdx=P-256 private scalar) -> rax = CertificateVerify message length.
; ECDSA-P256 over 64 spaces || context || 0x00 || transcript hash (RFC 8446
; 4.4.3). Identical to TLS; reuses linnea's signer.
linnea_quic_build_cert_verify:
    push rbx
    push r12
    push r13
    sub rsp, 176                     ; [0..cv_prefix_len+32) content, [+32) digest
    mov rbx, rdi                     ; out
    mov r12, rsi                     ; transcript hash
    mov r13, rdx                     ; private key
    lea rdi, [rsp]                   ; content = cv_prefix || transcript hash
    lea rsi, [cv_prefix]
    mov rcx, cv_prefix_len
    rep movsb
    mov rsi, r12
    mov rcx, 32
    rep movsb
    lea rdi, [rsp]                   ; digest = SHA-256(content)
    mov esi, cv_prefix_len + 32
    lea rdx, [rsp + 130]
    call linnea_sha256
    lea rdi, [rbx + 8]               ; signature = ECDSA(digest, priv)
    lea rsi, [rsp + 130]
    mov rdx, r13
    call linnea_p256_ecdsa_sign      ; rax = DER signature length
    mov r12, rax
    mov byte [rbx], 0x0f             ; CertificateVerify
    lea rax, [r12 + 4]               ; body = scheme(2) + siglen(2) + sig
    mov [rbx + 3], al
    shr rax, 8
    mov [rbx + 2], al
    shr rax, 8
    mov [rbx + 1], al
    mov word [rbx + 4], 0x0304       ; ecdsa_secp256r1_sha256 (0x0403)
    mov rax, r12                     ; signature length (16-bit)
    mov [rbx + 7], al
    shr rax, 8
    mov [rbx + 6], al
    lea rax, [r12 + 8]
    add rsp, 176
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_build_finished(rdi=out, rsi=s_hs traffic secret, rdx=transcript
;   hash H(CH..CertVerify)) -> rax = Finished message length (36).
; verify_data = HMAC(HKDF-Expand-Label(s_hs, "finished"), transcript hash).
linnea_quic_build_finished:
    push rbx
    push r12
    push r13
    sub rsp, 48                      ; [0..32) finished key
    mov rbx, rdi                     ; out
    mov r12, rsi                     ; s_hs
    mov r13, rdx                     ; transcript hash
    mov rdi, r12                     ; finished_key = Expand-Label(s_hs,"finished")
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [rsp]                   ; verify_data = HMAC(finished_key, th)
    mov esi, 32
    mov rdx, r13
    mov ecx, 32
    lea r8, [rbx + 4]
    call linnea_hmac_sha256
    mov byte [rbx], 0x14             ; Finished
    mov byte [rbx + 1], 0
    mov byte [rbx + 2], 0
    mov byte [rbx + 3], 32
    mov eax, 36
    add rsp, 48
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_build_cert(rdi=out, rsi=cert_list, rdx=cert_list len)
;   -> rax = Certificate message length.
; Wraps a pre-framed certificate_list (from linnea_pem_cert_list) in the TLS
; Certificate handshake message (RFC 8446 4.4.2): an empty request context,
; the certificate_list length, then the list. Identical to TLS.
linnea_quic_build_cert:
    push rbx
    mov rbx, rdi                     ; message base
    mov byte [rbx], 0x0b             ; Certificate
    lea rax, [rdx + 4]               ; body length = ctx(1) + listlen(3) + list
    mov [rbx + 3], al
    shr rax, 8
    mov [rbx + 2], al
    shr rax, 8
    mov [rbx + 1], al
    mov byte [rbx + 4], 0            ; certificate_request_context length
    mov rax, rdx                     ; certificate_list length (24-bit)
    mov [rbx + 7], al
    shr rax, 8
    mov [rbx + 6], al
    shr rax, 8
    mov [rbx + 5], al
    lea rdi, [rbx + 8]               ; copy the certificate_list verbatim
    mov rcx, rdx
    rep movsb
    lea rax, [rdx + 8]               ; total message length
    pop rbx
    ret

; linnea_quic_build_ee(rdi=out, rsi=odcid, rdx=odcid len, rcx=scid,
;   r8=scid len) -> rax = EncryptedExtensions message length.
; Two extensions: ALPN echoing "h3", and the QUIC transport parameters
; (extension 0x39). The TLS EE builder knows neither, so QUIC has its own.
linnea_quic_build_ee:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi                     ; out base
    mov r13, rsi                     ; odcid
    mov r14, rdx                     ; odcid len
    mov r15, rcx                     ; scid
    mov rbp, r8                      ; scid len
    mov byte [rbx], 0x08             ; EncryptedExtensions (lengths later)
    lea r12, [rbx + 6]               ; extensions cursor (after type+len+extslen)
    ; ALPN extension echoing "h3"
    mov word [r12], 0x1000           ; type 0x0010
    mov word [r12 + 2], 0x0500       ; ext length 5
    mov word [r12 + 4], 0x0300       ; ProtocolNameList length 3
    mov byte [r12 + 6], 2            ; protocol name length
    mov word [r12 + 7], 0x3368       ; "h3"
    add r12, 9
    ; QUIC transport parameters extension (0x0039)
    mov word [r12], 0x3900
    lea rdi, [r12 + 4]               ; write the parameters after the ext header
    mov rsi, r13
    mov rdx, r14
    mov rcx, r15
    mov r8, rbp
    call linnea_quic_build_transport_params   ; rax = parameters length
    mov rcx, rax                     ; ext length (big-endian)
    mov [r12 + 3], cl
    shr rcx, 8
    mov [r12 + 2], cl
    lea r12, [r12 + 4 + rax]         ; end of extensions
    ; early_data extension (empty) accepts the client's 0-RTT (RFC 8446 4.2.10)
    cmp qword [linnea_quic_early_ok], 0
    je .ee_ext_done
    mov word [r12], 0x2a00           ; early_data (0x002a)
    mov word [r12 + 2], 0x0000       ; ext length 0
    add r12, 4
.ee_ext_done:
    ; extensions length = r12 - (out + 6)
    mov rcx, r12
    lea rdx, [rbx + 6]
    sub rcx, rdx
    mov [rbx + 5], cl
    shr rcx, 8
    mov [rbx + 4], cl
    ; handshake message length = total - 4
    mov rax, r12
    sub rax, rbx                     ; total message length
    lea rcx, [rax - 4]
    mov byte [rbx + 1], 0
    mov [rbx + 3], cl
    shr rcx, 8
    mov [rbx + 2], cl
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; linnea_quic_build_sh(rdi=out, rsi=server_pub32, rdx=server_random32)
;   -> rax = ServerHello message length (90). The QUIC ClientHello carries an
;   empty legacy_session_id, so the ServerHello echoes an empty one. Fixed
;   profile: TLS_AES_128_GCM_SHA256, x25519, TLS 1.3.
linnea_quic_build_sh:
    push rbx
    mov rbx, rdi                     ; message base
    mov byte [rbx], 0x02             ; server_hello (length filled at the end)
    mov word [rbx + 4], 0x0303       ; legacy_version
    lea rdi, [rbx + 6]               ; server random
    mov rcx, 32
    push rsi
    mov rsi, rdx
    rep movsb
    pop rsi                          ; server_pub
    mov byte [rbx + 38], 0           ; legacy_session_id length = 0
    mov word [rbx + 39], 0x0113      ; cipher_suite 0x1301 (big-endian bytes)
    mov byte [rbx + 41], 0           ; legacy_compression_method
    mov word [rbx + 42], 0x2e00      ; extensions length = 46
    mov word [rbx + 44], 0x3300      ; key_share (0x0033)
    mov word [rbx + 46], 0x2400      ; ext length 36
    mov word [rbx + 48], 0x1d00      ; group x25519 (0x001d)
    mov word [rbx + 50], 0x2000      ; key_exchange length 32
    lea rdi, [rbx + 52]
    mov rcx, 32
    rep movsb                        ; server public key share
    mov word [rbx + 84], 0x2b00      ; supported_versions (0x002b)
    mov word [rbx + 86], 0x0200      ; ext length 2
    mov word [rbx + 88], 0x0403      ; selected_version 0x0304
    mov byte [rbx + 1], 0            ; handshake length = 86
    mov byte [rbx + 2], 0
    mov byte [rbx + 3], 86
    mov eax, 90
    pop rbx
    ret

; tp_int(rdi=cursor, rsi=param id, rdx=integer value) -> rax = new cursor.
; Encodes one integer transport parameter: id, then the length of the value's
; varint, then the value varint (RFC 9000 18).
tp_int:
    push rbx
    push r12
    push r13
    push r14
    mov r14, rdi                     ; cursor
    mov r13, rsi                     ; id
    mov r12, rdx                     ; value
    mov rdi, r14
    mov rsi, r13
    call linnea_quic_varint_encode   ; id
    add r14, rax
    sub rsp, 16
    lea rdi, [rsp]                   ; measure the value varint
    mov rsi, r12
    call linnea_quic_varint_encode
    mov rbx, rax                     ; value byte length
    mov rdi, r14
    mov rsi, rbx
    call linnea_quic_varint_encode   ; length
    add r14, rax
    lea rsi, [rsp]                   ; copy the value bytes
    mov rdi, r14
    mov rcx, rbx
    rep movsb
    add r14, rbx
    add rsp, 16
    mov rax, r14
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; tp_bytes(rdi=cursor, rsi=param id, rdx=data, rcx=data len) -> rax=new cursor.
tp_bytes:
    push rbx
    push r13
    push r14
    push r15
    mov r14, rdi                     ; cursor
    mov r13, rsi                     ; id
    mov r15, rdx                     ; data
    mov rbx, rcx                     ; data length
    mov rdi, r14
    mov rsi, r13
    call linnea_quic_varint_encode   ; id
    add r14, rax
    mov rdi, r14
    mov rsi, rbx
    call linnea_quic_varint_encode   ; length
    add r14, rax
    mov rsi, r15                     ; data
    mov rdi, r14
    mov rcx, rbx
    rep movsb
    add r14, rbx
    mov rax, r14
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; linnea_quic_build_transport_params(rdi=out, rsi=odcid, rdx=odcid len,
;   rcx=scid, r8=scid len) -> rax = encoded length.
; Server transport parameters for EncryptedExtensions (RFC 9000 18.2).
linnea_quic_build_transport_params:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rdi                     ; out (base)
    mov r13, rsi                     ; odcid
    mov r14, rdx                     ; odcid len
    mov r15, rcx                     ; scid
    mov rbp, r8                      ; scid len
    mov r12, rbx                     ; cursor
    mov rdi, r12                     ; original_destination_connection_id (0x00)
    xor esi, esi
    mov rdx, r13
    mov rcx, r14
    call tp_bytes
    mov r12, rax
    mov rdi, r12                     ; initial_source_connection_id (0x0f)
    mov esi, 0x0f
    mov rdx, r15
    mov rcx, rbp
    call tp_bytes
    mov r12, rax
    mov rdi, r12                     ; max_idle_timeout (0x01) = 30000 ms
    mov esi, 0x01
    mov edx, 30000
    call tp_int
    mov r12, rax
    mov rdi, r12                     ; max_udp_payload_size (0x03)
    mov esi, 0x03
    mov edx, 1472
    call tp_int
    mov r12, rax
    mov rdi, r12                     ; initial_max_data (0x04)
    mov esi, 0x04
    mov edx, 1048576
    call tp_int
    mov r12, rax
    mov rdi, r12                     ; initial_max_stream_data_bidi_local (0x05)
    mov esi, 0x05
    mov edx, 262144
    call tp_int
    mov r12, rax
    mov rdi, r12                     ; initial_max_stream_data_bidi_remote (0x06):
    mov esi, 0x06                    ; the window for the client's REQUEST streams.
    ; It must not exceed the per-stream reassembly buffer: a request body between
    ; the buffer size and the advertised window overflows reassembly, is dropped
    ; WITHOUT an ack, and the client retransmits it forever (a permanent stall). Bind
    ; it to the buffer so the client is flow-controlled to what we can actually take.
    mov edx, LINNEA_QUIC_RA_BUF
    call tp_int
    mov r12, rax
    mov rdi, r12                     ; initial_max_stream_data_uni (0x07)
    mov esi, 0x07
    mov edx, 262144
    call tp_int
    mov r12, rax
    mov rdi, r12                     ; initial_max_streams_bidi (0x08)
    mov esi, 0x08
    mov edx, 100
    call tp_int
    mov r12, rax
    mov rdi, r12                     ; initial_max_streams_uni (0x09)
    mov esi, 0x09
    mov edx, 100
    call tp_int
    mov r12, rax
    mov rax, r12
    sub rax, rbx                     ; total length
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_tp_parse(rdi=params, rsi=len) -> rax = initial_max_data (0x04),
; rdx = initial_max_stream_data_bidi_local (0x05); zero when absent — which is
; also what RFC 9000 18.2 says an omitted parameter means. These two bound what
; we may send on a client-initiated bidirectional stream (its response), so the
; server reads them from the client's transport parameters before it commits to
; a chunked response. The parameters are a sequence of varint id, varint length,
; then that many bytes; both values are themselves varints. Anything malformed
; stops the walk with whatever was gathered.
linnea_quic_tp_parse:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8
    mov rbx, rdi                     ; cursor
    lea r12, [rdi + rsi]             ; end
    xor r13d, r13d                   ; initial_max_data
    xor r14d, r14d                   ; initial_max_stream_data_bidi_local
.tp_next:
    cmp rbx, r12
    jae .tp_done
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_varint_decode   ; parameter id
    test rdx, rdx
    jz .tp_done
    mov r15, rax
    add rbx, rdx
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_varint_decode   ; parameter length
    test rdx, rdx
    jz .tp_done
    add rbx, rdx
    mov rbp, rax                     ; parameter length
    mov rcx, r12
    sub rcx, rbx
    cmp rbp, rcx
    ja .tp_done                      ; runs past the extension
    cmp r15, 0x04
    je .tp_value
    cmp r15, 0x05
    je .tp_value
    add rbx, rbp                     ; not one we read: skip its payload
    jmp .tp_next
.tp_value:
    mov rdi, rbx
    lea rsi, [rbx + rbp]
    call linnea_quic_varint_decode   ; the value
    test rdx, rdx
    jz .tp_skip
    cmp r15, 0x04
    jne .tp_val05
    mov r13, rax
    jmp .tp_skip
.tp_val05:
    mov r14, rax
.tp_skip:
    add rbx, rbp
    jmp .tp_next
.tp_done:
    mov rax, r13
    mov rdx, r14
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_parse_priority(rdi = value ptr, rsi = value len)
;   -> rax = urgency (0-7), rdx = incremental (0/1).
; Parses an RFC 9218 priority field value, an RFC 8941 dictionary of members
; separated by commas, e.g. "u=1, i" or "u=5" or "i=?0". Recognises the two keys
; that matter: u=<0..7> (urgency; default 3) and i (incremental boolean; bare or
; "i=?1" is true, "i=?0" false; default false). Unknown members and malformed
; values are ignored, leaving the defaults — a request with no priority header
; (ptr callers pass len 0) gets urgency 3, non-incremental.
linnea_quic_parse_priority:
    mov r8d, 3                       ; default urgency
    xor r9d, r9d                     ; default incremental = false
    lea r10, [rdi + rsi]             ; end
.pp_member:
    cmp rdi, r10
    jae .pp_done
    movzx eax, byte [rdi]
    cmp al, ' '                      ; skip spaces and empty members
    je .pp_skip
    cmp al, ','
    je .pp_skip
    cmp al, 'u'
    je .pp_u
    cmp al, 'i'
    je .pp_i
    jmp .pp_adv                      ; unknown key: skip to the next member
.pp_skip:
    inc rdi
    jmp .pp_member
.pp_u:
    lea rcx, [rdi + 2]               ; need "u=" then a digit
    cmp rcx, r10
    ja .pp_adv
    cmp byte [rdi + 1], '='
    jne .pp_adv
    movzx eax, byte [rdi + 2]
    sub al, '0'
    cmp al, 7                        ; unsigned: rejects non-digits and >7
    ja .pp_adv
    mov r8d, eax
    jmp .pp_adv
.pp_i:
    ; bare 'i' (or 'i' ending the string) is true; only "i=?0" is false
    mov r9d, 1
    lea rcx, [rdi + 1]
    cmp rcx, r10
    jae .pp_adv                      ; 'i' at end: bare, true
    cmp byte [rdi + 1], '='
    jne .pp_adv                      ; 'i' then ',' or ' ': bare, true
    lea rcx, [rdi + 4]               ; "i=?0" needs 4 bytes
    cmp rcx, r10
    ja .pp_adv
    cmp byte [rdi + 3], '0'
    jne .pp_adv
    xor r9d, r9d                     ; i=?0 → false
.pp_adv:
    cmp rdi, r10                     ; advance to the next comma
    jae .pp_done
    cmp byte [rdi], ','
    je .pp_next
    inc rdi
    jmp .pp_adv
.pp_next:
    inc rdi
    jmp .pp_member
.pp_done:
    mov eax, r8d
    mov edx, r9d
    ret

; linnea_quic_flow_scan(rdi=frames, rsi=len, rdx=tx_sid, rcx=out) — record the
; largest MAX_DATA into out[0] and the largest MAX_STREAM_DATA for tx_sid into
; out[1] (the caller pre-zeroes out). A real browser bundles NEW_CONNECTION_ID,
; MAX_STREAMS, QPACK STREAM data and the like into the same 1-RTT packets as its
; flow-control credit, so this must SKIP every frame type it does not record —
; not stop at the first unrecognised one — or a MAX_DATA sitting behind such a
; frame is never absorbed and the response stalls when the window fills (the very
; bug that made a multi-image page stall over the real internet: one image fits a
; browser's large initial window, but ten exhaust it and depend on MAX_DATA). Same
; complete frame walk as linnea_quic_stream_frame; only truly unknown types stop.
linnea_quic_flow_scan:
    push rbx
    push r12
    push r13
    push r15
    lea rsi, [rdi + rsi]             ; end (preserved across varint_decode)
    mov r12, rdx                     ; tx_sid
    mov r13, rcx                     ; out
.fw_scan:
    cmp rdi, rsi
    jae .fw_done
    movzx ebx, byte [rdi]
    test bl, bl
    jz .fw_skip1                     ; PADDING
    cmp bl, 0x01
    je .fw_skip1                     ; PING
    cmp bl, 0x02
    je .fw_ack
    cmp bl, 0x03
    je .fw_ack
    cmp bl, 0x10
    je .fw_maxdata
    cmp bl, 0x11
    je .fw_maxstreamdata
    ; skip every other known frame so credit bundled behind it is still reached
    mov eax, ebx
    and eax, 0xf8
    cmp eax, 0x08                    ; STREAM (0x08-0x0f)
    je .fw_stream
    cmp bl, 0x1e                     ; HANDSHAKE_DONE (no payload)
    je .fw_skip1
    cmp bl, 0x1a                     ; PATH_CHALLENGE (8 bytes)
    je .fw_skip8
    cmp bl, 0x1b                     ; PATH_RESPONSE (8 bytes)
    je .fw_skip8
    cmp bl, 0x18                     ; NEW_CONNECTION_ID
    je .fw_ncid
    cmp bl, 0x06                     ; CRYPTO (offset, length, data)
    je .fw_crypto
    cmp bl, 0x07                     ; NEW_TOKEN (length, token)
    je .fw_token
    cmp bl, 0x04                     ; RESET_STREAM (3 varints)
    je .fw_v3
    cmp bl, 0x05                     ; STOP_SENDING (2 varints)
    je .fw_v2
    cmp bl, 0x15                     ; STREAM_DATA_BLOCKED (2 varints)
    je .fw_v2
    cmp bl, 0x12                     ; MAX_STREAMS bidi (1 varint)
    je .fw_v1
    cmp bl, 0x13                     ; MAX_STREAMS uni (1 varint)
    je .fw_v1
    cmp bl, 0x14                     ; DATA_BLOCKED (1 varint)
    je .fw_v1
    cmp bl, 0x16                     ; STREAMS_BLOCKED bidi (1 varint)
    je .fw_v1
    cmp bl, 0x17                     ; STREAMS_BLOCKED uni (1 varint)
    je .fw_v1
    cmp bl, 0x19                     ; RETIRE_CONNECTION_ID (1 varint)
    je .fw_v1
    jmp .fw_done                     ; unknown (e.g. CONNECTION_CLOSE): stop
.fw_skip1:
    inc rdi
    jmp .fw_scan
.fw_skip8:
    add rdi, 9                       ; type byte + 8 fixed bytes
    jmp .fw_scan
.fw_v1:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    jmp .fw_scan
.fw_v2:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    jmp .fw_scan
.fw_v3:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    jmp .fw_scan
.fw_token:
    inc rdi
    call linnea_quic_varint_decode   ; token length
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    add rdi, rax                      ; skip the token bytes
    jmp .fw_scan
.fw_crypto:
    inc rdi
    call linnea_quic_varint_decode   ; offset
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    add rdi, rax                      ; skip the crypto data
    jmp .fw_scan
.fw_ncid:
    inc rdi
    call linnea_quic_varint_decode   ; sequence number
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; retire prior to
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    cmp rdi, rsi
    jae .fw_done
    movzx eax, byte [rdi]             ; connection id length
    add rdi, 1
    add rdi, rax                      ; skip the connection id
    add rdi, 16                       ; skip the stateless reset token
    jmp .fw_scan
.fw_stream:
    mov r15d, ebx                    ; save the STREAM type bits (OFF/LEN/FIN)
    inc rdi
    call linnea_quic_varint_decode   ; stream id
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    test r15b, 0x04                  ; OFF present?
    jz .fw_stream_len
    call linnea_quic_varint_decode   ; offset
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
.fw_stream_len:
    test r15b, 0x02                  ; LEN present?
    jz .fw_done                      ; no LEN: data runs to the packet end — stop
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    add rdi, rax                      ; skip the stream data
    jmp .fw_scan
.fw_maxdata:
    inc rdi
    call linnea_quic_varint_decode   ; Maximum Data
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    cmp rax, [r13]
    jbe .fw_scan
    mov [r13], rax
    jmp .fw_scan
.fw_maxstreamdata:
    inc rdi
    call linnea_quic_varint_decode   ; Stream ID
    test rdx, rdx
    jz .fw_done
    mov rbx, rax
    add rdi, rdx
    call linnea_quic_varint_decode   ; Maximum Stream Data
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    cmp rbx, r12                     ; is it for our response stream?
    jne .fw_scan
    cmp rax, [r13 + 8]
    jbe .fw_scan
    mov [r13 + 8], rax
    jmp .fw_scan
.fw_ack:
    inc rdi
    call linnea_quic_varint_decode   ; Largest Acknowledged
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Delay
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Count
    test rdx, rdx
    jz .fw_done
    mov r15, rax                     ; additional ranges
    add rdi, rdx
    call linnea_quic_varint_decode   ; First ACK Range
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
.fw_ack_range:
    test r15, r15
    jz .fw_ack_ecn
    call linnea_quic_varint_decode   ; Gap
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Length
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    dec r15
    jmp .fw_ack_range
.fw_ack_ecn:
    cmp bl, 0x03                     ; only 0x03 carries the ECN counts
    jne .fw_scan
    call linnea_quic_varint_decode   ; ECT0
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ECT1
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ECN-CE
    test rdx, rdx
    jz .fw_done
    add rdi, rdx
    jmp .fw_scan
.fw_done:
    pop r15
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_reset_scan(rdi=frames, rsi=len, rdx=out, rcx=max) -> rax = count.
; Records the stream id of every STOP_SENDING (0x05) and RESET_STREAM (0x04) frame
; into out (one qword each, up to max). A peer sends these to cancel a stream — a
; browser does it to abandon a page's downloads on reload — and the caller must
; then tear that stream's response and reassembly down, or the abandoned chunks
; keep holding the congestion window and the connection stalls. Skips every other
; frame type (same complete walk as linnea_quic_stream_frame); stops at an unknown
; type or a malformed frame with whatever was gathered.
linnea_quic_reset_scan:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea rsi, [rdi + rsi]             ; end
    mov r13, rdx                     ; out cursor
    mov r14, rcx                     ; max
    xor r15d, r15d                   ; count
.rs_scan:
    cmp rdi, rsi
    jae .rs_done
    movzx ebx, byte [rdi]
    cmp bl, 0x04                     ; RESET_STREAM: stream id, app err, final size
    je .rs_reset
    cmp bl, 0x05                     ; STOP_SENDING: stream id, app err
    je .rs_stop
    test bl, bl                      ; PADDING
    jz .rs_skip1
    cmp bl, 0x01                     ; PING
    je .rs_skip1
    cmp bl, 0x02                     ; ACK
    je .rs_ack
    cmp bl, 0x03
    je .rs_ack
    mov eax, ebx
    and eax, 0xf8
    cmp eax, 0x08                    ; STREAM (0x08-0x0f)
    je .rs_stream
    cmp bl, 0x1e                     ; HANDSHAKE_DONE
    je .rs_skip1
    cmp bl, 0x1a                     ; PATH_CHALLENGE (8 bytes)
    je .rs_skip8
    cmp bl, 0x1b                     ; PATH_RESPONSE (8 bytes)
    je .rs_skip8
    cmp bl, 0x18                     ; NEW_CONNECTION_ID
    je .rs_ncid
    cmp bl, 0x06                     ; CRYPTO
    je .rs_crypto
    cmp bl, 0x07                     ; NEW_TOKEN
    je .rs_token
    cmp bl, 0x11                     ; MAX_STREAM_DATA (2 varints)
    je .rs_v2
    cmp bl, 0x15                     ; STREAM_DATA_BLOCKED (2 varints)
    je .rs_v2
    cmp bl, 0x10                     ; MAX_DATA (1 varint)
    je .rs_v1
    cmp bl, 0x12                     ; MAX_STREAMS bidi
    je .rs_v1
    cmp bl, 0x13                     ; MAX_STREAMS uni
    je .rs_v1
    cmp bl, 0x14                     ; DATA_BLOCKED
    je .rs_v1
    cmp bl, 0x16                     ; STREAMS_BLOCKED bidi
    je .rs_v1
    cmp bl, 0x17                     ; STREAMS_BLOCKED uni
    je .rs_v1
    cmp bl, 0x19                     ; RETIRE_CONNECTION_ID
    je .rs_v1
    jmp .rs_done                     ; unknown (e.g. CONNECTION_CLOSE): stop
.rs_skip1:
    inc rdi
    jmp .rs_scan
.rs_skip8:
    add rdi, 9
    jmp .rs_scan
.rs_v1:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    jmp .rs_scan
.rs_v2:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    jmp .rs_scan
.rs_token:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    add rdi, rax
    jmp .rs_scan
.rs_crypto:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    add rdi, rax
    jmp .rs_scan
.rs_ncid:
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    cmp rdi, rsi
    jae .rs_done
    movzx eax, byte [rdi]
    add rdi, 1
    add rdi, rax
    add rdi, 16
    jmp .rs_scan
.rs_stream:
    mov r12d, ebx                    ; STREAM type bits (OFF/LEN/FIN)
    inc rdi
    call linnea_quic_varint_decode   ; stream id
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    test r12b, 0x04                  ; OFF present?
    jz .rs_stream_len
    call linnea_quic_varint_decode   ; offset
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
.rs_stream_len:
    test r12b, 0x02                  ; LEN present?
    jz .rs_done                      ; no LEN: runs to the packet end — stop
    call linnea_quic_varint_decode   ; length
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    add rdi, rax
    jmp .rs_scan
.rs_ack:
    inc rdi
    call linnea_quic_varint_decode   ; Largest Acknowledged
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Delay
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Count
    test rdx, rdx
    jz .rs_done
    mov r12, rax
    add rdi, rdx
    call linnea_quic_varint_decode   ; First ACK Range
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
.rs_ack_range:
    test r12, r12
    jz .rs_ack_ecn
    call linnea_quic_varint_decode   ; Gap
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ACK Range Length
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    dec r12
    jmp .rs_ack_range
.rs_ack_ecn:
    cmp bl, 0x03
    jne .rs_scan
    call linnea_quic_varint_decode   ; ECT0
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ECT1
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; ECN-CE
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    jmp .rs_scan
.rs_stop:
    inc rdi
    call linnea_quic_varint_decode   ; stream id
    test rdx, rdx
    jz .rs_done
    mov r12, rax
    add rdi, rdx
    call linnea_quic_varint_decode   ; application error code
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    jmp .rs_record
.rs_reset:
    inc rdi
    call linnea_quic_varint_decode   ; stream id
    test rdx, rdx
    jz .rs_done
    mov r12, rax
    add rdi, rdx
    call linnea_quic_varint_decode   ; application error code
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
    call linnea_quic_varint_decode   ; final size
    test rdx, rdx
    jz .rs_done
    add rdi, rdx
.rs_record:
    cmp r15, r14
    jae .rs_scan                     ; out of room: skip, but keep walking
    mov [r13], r12
    add r13, 8
    inc r15
    jmp .rs_scan
.rs_done:
    mov rax, r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_ch_parse(rdi=ClientHello, rsi=len, rdx=out linnea_quic_ch)
; Walks the ClientHello extensions and records the server_name (SNI), the ALPN
; protocol list, and the QUIC transport parameters. Bounds-checked; missing
; fields are left zero.
linnea_quic_ch_parse:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdx                     ; out struct
    lea r12, [rdi + rsi]             ; ClientHello end
    mov r15, rdi                     ; save the ClientHello pointer
    mov rdi, rbx                     ; zero the out struct
    xor eax, eax
    mov ecx, linnea_quic_ch_size / 8
    rep stosq
    mov rdi, r15
    ; skip type(1)+len(3)+version(2)+random(32) = 38, to session_id length
    lea r13, [rdi + 38]
    cmp r13, r12
    jae .chp_done
    movzx eax, byte [r13]            ; session_id length
    lea r13, [r13 + 1 + rax]         ; -> cipher_suites length
    lea rax, [r13 + 2]
    cmp rax, r12
    ja .chp_done
    movzx eax, byte [r13]
    shl eax, 8
    movzx ecx, byte [r13 + 1]
    or eax, ecx                      ; cipher_suites length
    lea r13, [r13 + 2 + rax]         ; -> compression length
    cmp r13, r12
    jae .chp_done
    movzx eax, byte [r13]
    lea r13, [r13 + 1 + rax]         ; -> extensions length
    lea rax, [r13 + 2]
    cmp rax, r12
    ja .chp_done
    add r13, 2                       ; -> first extension
.chp_ext:
    lea rax, [r13 + 4]
    cmp rax, r12
    ja .chp_done                     ; no room for an extension header
    movzx eax, byte [r13]            ; extension type
    shl eax, 8
    movzx ecx, byte [r13 + 1]
    or eax, ecx
    movzx ecx, byte [r13 + 2]        ; extension length
    shl ecx, 8
    movzx edx, byte [r13 + 3]
    or ecx, edx
    lea r14, [r13 + 4]               ; extension data
    lea r15, [r14 + rcx]             ; extension end
    cmp r15, r12
    ja .chp_done
    test eax, eax
    jz .chp_sni                      ; server_name (0x0000)
    cmp eax, 0x10
    je .chp_alpn                     ; ALPN (0x0010)
    cmp eax, 0x39
    je .chp_tp                       ; QUIC transport parameters (0x0039)
    cmp eax, 0x33
    je .chp_ks                       ; key_share (0x0033)
    cmp eax, 0x2d
    je .chp_pskmodes                 ; psk_key_exchange_modes (0x002d)
    cmp eax, 0x29
    je .chp_psk                      ; pre_shared_key (0x0029)
    cmp eax, 0x2a
    je .chp_early                    ; early_data (0x002a)
.chp_next:
    mov r13, r15
    jmp .chp_ext
.chp_ks:
    ; client_shares length(2), then entries: group(2), len(2), key_exchange.
    ; find the x25519 share (group 0x001d) and record its 32-byte key.
    lea rax, [r14 + 2]
    cmp rax, r15
    ja .chp_next
    lea rsi, [r14 + 2]               ; first KeyShareEntry
.chp_ks_entry:
    lea rax, [rsi + 4]
    cmp rax, r15
    ja .chp_next
    movzx eax, byte [rsi]            ; group (16-bit)
    shl eax, 8
    movzx ecx, byte [rsi + 1]
    or eax, ecx
    movzx ecx, byte [rsi + 2]        ; key_exchange length
    shl ecx, 8
    movzx edx, byte [rsi + 3]
    or ecx, edx
    lea rdi, [rsi + 4 + rcx]         ; next entry
    cmp rdi, r15
    ja .chp_next
    cmp eax, 0x001d                  ; x25519?
    jne .chp_ks_skip
    cmp ecx, 32
    jne .chp_ks_skip
    lea rax, [rsi + 4]
    mov [rbx + linnea_quic_ch.ks_ptr], rax
    jmp .chp_next
.chp_ks_skip:
    mov rsi, rdi
    jmp .chp_ks_entry
.chp_sni:
    ; list_len(2), name_type(1), name_len(2), name — take the first host_name
    lea rax, [r14 + 5]
    cmp rax, r15
    ja .chp_next
    movzx eax, byte [r14 + 3]        ; name length
    shl eax, 8
    movzx ecx, byte [r14 + 4]
    or eax, ecx
    lea rdx, [r14 + 5]               ; name pointer
    lea rcx, [rdx + rax]
    cmp rcx, r15
    ja .chp_next
    mov [rbx + linnea_quic_ch.sni_ptr], rdx
    mov [rbx + linnea_quic_ch.sni_len], rax
    jmp .chp_next
.chp_alpn:
    lea rax, [r14 + 2]
    cmp rax, r15
    ja .chp_next
    movzx eax, byte [r14]            ; ProtocolNameList length
    shl eax, 8
    movzx ecx, byte [r14 + 1]
    or eax, ecx
    lea rdx, [r14 + 2]               ; the list itself
    mov [rbx + linnea_quic_ch.alpn_ptr], rdx
    mov [rbx + linnea_quic_ch.alpn_len], rax
    jmp .chp_next
.chp_tp:
    mov [rbx + linnea_quic_ch.tp_ptr], r14
    mov rax, r15
    sub rax, r14
    mov [rbx + linnea_quic_ch.tp_len], rax
    jmp .chp_next
.chp_early:
    ; early_data in a ClientHello is empty; its presence is the 0-RTT request.
    mov qword [rbx + linnea_quic_ch.early_data], 1
    jmp .chp_next
.chp_pskmodes:
    ; ke_modes<1..255>: 1-byte list length, then modes. We only do psk_dhe_ke (1).
    lea rax, [r14 + 1]
    cmp rax, r15
    ja .chp_next
    movzx ecx, byte [r14]            ; modes list length
    lea rsi, [r14 + 1]               ; first mode
    lea rdi, [rsi + rcx]             ; modes end
    cmp rdi, r15
    ja .chp_next
.chp_pm_loop:
    cmp rsi, rdi
    jae .chp_next
    cmp byte [rsi], 1               ; psk_dhe_ke
    jne .chp_pm_next
    mov qword [rbx + linnea_quic_ch.psk_dhe_ke], 1
    jmp .chp_next
.chp_pm_next:
    inc rsi
    jmp .chp_pm_loop
.chp_psk:
    ; OfferedPsks: identities<7..2^16-1> then binders<33..2^16-1>. Record the first
    ; identity (our ticket) and first binder, and where the binders length field
    ; sits — the truncated ClientHello the binder is computed over ends there.
    lea rax, [r14 + 2]
    cmp rax, r15
    ja .chp_next
    movzx eax, byte [r14]            ; identities list length
    shl eax, 8
    movzx ecx, byte [r14 + 1]
    or eax, ecx
    lea r10, [r14 + 2 + rax]         ; -> binders length field
    cmp r10, r15
    jae .chp_next
    ; first PskIdentity: identity<1..2^16-1> then uint32 obfuscated_ticket_age
    lea rax, [r14 + 4]
    cmp rax, r10
    ja .chp_next
    movzx ecx, byte [r14 + 2]        ; identity length
    shl ecx, 8
    movzx edx, byte [r14 + 3]
    or ecx, edx
    lea rax, [r14 + 4 + rcx]         ; end of identity bytes
    lea rdx, [rax + 4]               ; + obfuscated age
    cmp rdx, r10
    ja .chp_next
    lea rax, [r14 + 4]
    mov [rbx + linnea_quic_ch.psk_id_ptr], rax
    mov [rbx + linnea_quic_ch.psk_id_len], rcx
    mov [rbx + linnea_quic_ch.psk_binders_pos], r10
    ; first binder: 1-byte length (must be 32) then the 32 bytes
    lea rax, [r10 + 3]
    cmp rax, r15
    ja .chp_next
    cmp byte [r10 + 2], 32
    jne .chp_next
    lea rax, [r10 + 3]
    mov [rbx + linnea_quic_ch.psk_binder_ptr], rax
    jmp .chp_next
.chp_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_alpn_has(rdi=list, rsi=list len, rdx=proto, rcx=proto len)
;   -> rax = 1 if the ALPN protocol list contains proto, else 0.
; The list is a sequence of length-prefixed names (RFC 7301).
linnea_quic_alpn_has:
    lea r8, [rdi + rsi]              ; list end
.al_loop:
    cmp rdi, r8
    jae .al_no
    movzx r9d, byte [rdi]            ; this protocol's length
    inc rdi
    lea rax, [rdi + r9]
    cmp rax, r8
    ja .al_no
    cmp r9, rcx
    jne .al_skip
    ; compare r9 bytes at rdi vs proto
    push rsi
    push rdi
    push rcx
    mov rsi, rdx
    mov rcx, r9
    repe cmpsb
    pop rcx
    pop rdi
    pop rsi
    je .al_yes
.al_skip:
    add rdi, r9
    jmp .al_loop
.al_yes:
    mov eax, 1
    ret
.al_no:
    xor eax, eax
    ret

; linnea_quic_recv_initial(rdi=datagram, rsi=len, rdx=plaintext buf)
;   -> rax = ClientHello CRYPTO ptr (into the plaintext buf), rdx = length,
;      r8 = CRYPTO offset, r9 = the Initial packet number;
;      rax = 0 if the datagram is not an Initial we can decrypt.
; Derives the Initial keys from the packet's own DCID, unprotects it, and
; returns the first CRYPTO frame's data. The offset and packet number let the
; caller reassemble a ClientHello split across several Initial packets and
; acknowledge each Initial it received.
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
    call linnea_quic_unprotect       ; rax = plaintext length, rdx = packet number
    test rax, rax
    js .fail
    mov r14, rdx                     ; keep the Initial packet number
    mov rdi, r13
    mov rsi, rax
    call linnea_quic_crypto_frame    ; rax = CRYPTO ptr, rdx = len, r8 = offset
    mov r9, r14                      ; r9 = Initial packet number
    jmp .rdone
.fail:
    xor eax, eax
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
.rdone:
    add rsp, 120
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_protect(rdi=out, rsi=hdr, rdx=hdr_len, rcx=pn_len,
;                     r8=payload, r9=payload_len, [stack]=keys) -> rax=total
; The inverse of unprotect: AEAD-seals the payload (nonce = iv XOR pn, AAD =
; the unprotected header) after the header in out, copies the header, then
; applies header protection. hdr already contains the plaintext packet number.
; Works for long and short headers alike — the header-protection first-byte mask
; (4 vs 5 low bits) is chosen from the header form bit in hdr[0].
%define P_CTX    0
%define P_NONCE  192
%define P_MASK   208
%define P_PNOFF  216
%define P_PN     224
%define P_KEYS   248
linnea_quic_protect:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rax, [rsp + 56]              ; keys (caller's stack arg)
    mov r11, [rsp + 64]             ; full packet number (2nd stack arg), for the nonce
    sub rsp, 264
    mov [rsp + P_KEYS], rax
    ; The AEAD nonce uses the FULL packet number, NOT the value the header carries.
    ; The header truncates the pn to pn_len bytes (2 for 1-RTT), so it wraps at
    ; 65536; the peer reconstructs the full pn (RFC 9000 A.3) and builds its nonce
    ; from that. Deriving our nonce from the truncated header value matched only
    ; while pn < 65536 — past that every 1-RTT packet failed the peer's AEAD and the
    ; connection died at ~65536 packets (~72 MB). So take the full pn from the caller.
    mov [rsp + P_PN], r11
    mov rbx, rdi                     ; out
    mov rbp, rsi                     ; hdr
    mov r13, rdx                     ; hdr_len
    mov r14, rcx                     ; pn_len
    mov r12, r8                      ; payload
    mov r15, r9                      ; payload_len
    ; pn_offset = hdr_len - pn_len (for header protection; the pn value itself is
    ; the caller's full pn above, not re-read from the header)
    mov rax, r13
    sub rax, r14
    mov [rsp + P_PNOFF], rax
    ; copy the header into out
    mov rsi, rbp
    mov rdi, rbx
    mov rcx, r13
    rep movsb
    ; nonce = iv XOR pn (right-aligned)
    mov rax, [rsp + P_KEYS]
    lea rsi, [rax + linnea_quic_keys.iv]
    lea rdi, [rsp + P_NONCE]
    mov ecx, 12
    rep movsb
    mov rax, [rsp + P_PN]
    lea rdi, [rsp + P_NONCE + 11]
    mov ecx, 8
.p_nonce:
    mov dl, al
    xor [rdi], dl
    dec rdi
    shr rax, 8
    dec ecx
    jnz .p_nonce
    ; AEAD-seal the payload after the header
    mov rax, [rsp + P_KEYS]
    lea rdi, [rsp + P_CTX]
    lea rsi, [rax + linnea_quic_keys.key]
    call linnea_aesgcm_init
    lea rdi, [rsp + P_CTX]
    lea rsi, [rsp + P_NONCE]
    mov rdx, rbx                     ; AAD = the (unprotected) header in out
    mov rcx, r13
    mov r8, r12                      ; payload
    mov r9, r15
    lea rax, [rbx + r13]             ; seal destination = out + hdr_len
    sub rsp, 16
    mov [rsp], rax
    call linnea_aesgcm_seal
    add rsp, 16
    ; header protection: sample the ciphertext at pn_offset + 4
    mov rax, [rsp + P_PNOFF]
    lea rsi, [rbx + rax + 4]
    mov rax, [rsp + P_KEYS]
    lea rdi, [rax + linnea_quic_keys.hp]
    lea rdx, [rsp + P_MASK]
    call linnea_quic_hp_mask
    ; mask the first byte: 4 low bits for a long header, 5 for a short header
    movzx eax, byte [rbx]
    mov ecx, 0x0f
    test al, 0x80                    ; long-header form?
    jnz .p_b0
    mov ecx, 0x1f                    ; short header masks the 5 low bits
.p_b0:
    movzx edx, byte [rsp + P_MASK]
    and edx, ecx
    xor eax, edx
    mov [rbx], al
    ; mask the packet-number bytes
    mov rax, [rsp + P_PNOFF]
    lea rdi, [rbx + rax]
    lea rsi, [rsp + P_MASK + 1]
    xor edx, edx
.p_mask:
    mov al, [rdi + rdx]
    xor al, [rsi + rdx]
    mov [rdi + rdx], al
    inc edx
    cmp edx, r14d
    jb .p_mask
    ; total length = header + payload + 16-byte tag
    lea rax, [r13 + r15]
    add rax, 16
    add rsp, 264
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
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
