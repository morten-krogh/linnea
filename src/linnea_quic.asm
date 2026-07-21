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
global linnea_quic_protect
global linnea_quic_ch_parse
global linnea_quic_alpn_has
global linnea_quic_build_transport_params
global linnea_quic_build_sh
global linnea_quic_build_ee

extern linnea_quic_hp_mask
extern linnea_quic_initial_secrets
extern linnea_aesgcm_init
extern linnea_aesgcm_open
extern linnea_aesgcm_seal

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
    mov rdi, r12                     ; initial_max_stream_data_bidi_remote (0x06)
    mov esi, 0x06
    mov edx, 262144
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
    mov rdi, rbx                     ; zero the out struct (7 qwords)
    xor eax, eax
    mov ecx, 7
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

; linnea_quic_protect(rdi=out, rsi=hdr, rdx=hdr_len, rcx=pn_len,
;                     r8=payload, r9=payload_len, [stack]=keys) -> rax=total
; The inverse of unprotect: AEAD-seals the payload (nonce = iv XOR pn, AAD =
; the unprotected header) after the header in out, copies the header, then
; applies header protection. hdr already contains the plaintext packet number.
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
    sub rsp, 264
    mov [rsp + P_KEYS], rax
    mov rbx, rdi                     ; out
    mov rbp, rsi                     ; hdr
    mov r13, rdx                     ; hdr_len
    mov r14, rcx                     ; pn_len
    mov r12, r8                      ; payload
    mov r15, r9                      ; payload_len
    ; pn_offset = hdr_len - pn_len
    mov rax, r13
    sub rax, r14
    mov [rsp + P_PNOFF], rax
    ; read the plaintext packet number from the header (big-endian)
    lea rdi, [rbp + rax]
    xor rax, rax
    xor edx, edx
.rp_pn:
    shl rax, 8
    movzx ecx, byte [rdi + rdx]
    or rax, rcx
    inc edx
    cmp edx, r14d
    jb .rp_pn
    mov [rsp + P_PN], rax
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
    ; mask the first byte (low 4 bits for a long header)
    movzx eax, byte [rbx]
    movzx edx, byte [rsp + P_MASK]
    and edx, 0x0f
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
