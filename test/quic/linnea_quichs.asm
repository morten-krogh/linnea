; linnea_quichs.asm — test-only: a QUIC handshake responder that sends the full
; server flight. On a client Initial it replies with one datagram coalescing:
;   Initial packet   : ACK + CRYPTO(ServerHello)          [server Initial keys]
;   Handshake packet : CRYPTO(EE || Cert || CertVerify || Finished) [hs keys]
; A real client (aioquic) should decrypt both and complete the TLS handshake.
; When the client then sends its Handshake packet (client Finished), the server
; decrypts it with the client handshake keys, verifies the Finished MAC against
; the transcript through the server Finished, and prints "CFIN-OK" on success.
;
; Fixed server ephemeral key / random / connection id (deterministic test).
; The certificate chain and P-256 key are embedded. Binds 127.0.0.1:47501.

%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_sha256.inc"
%include "linnea_hpack.inc"

global _start

extern linnea_h3_read_headers
extern linnea_h3_serve
extern linnea_quic_initial_dcid
extern linnea_quic_initial_secrets
extern linnea_quic_recv_initial
extern linnea_quic_ch_parse
extern linnea_quic_build_sh
extern linnea_quic_build_ee
extern linnea_quic_build_cert
extern linnea_quic_build_cert_verify
extern linnea_quic_build_finished
extern linnea_quic_hs_secrets
extern linnea_quic_app_secrets
extern linnea_quic_protect
extern linnea_quic_unprotect_hs
extern linnea_quic_unprotect_short
extern linnea_quic_crypto_frame
extern linnea_quic_stream_frame
extern linnea_quic_varint_encode
extern linnea_quic_varint_decode
extern linnea_x25519
extern linnea_sha256_init
extern linnea_sha256_update
extern linnea_sha256_final
extern linnea_pem_cert_list
extern linnea_pem_p256_key

%define SOCK_DGRAM   2
%define SYS_RECVFROM 45
%define SYS_SENDTO   44

section .rodata
x25519_base:  db 9
              times 31 db 0
server_priv:  db 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
              db 0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
server_srand: db 0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f
              db 0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f
server_scid:  db 0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58
cert_pem:     incbin "test/tls/server.crt"
cert_pem_len  equ $ - cert_pem
key_pem:      incbin "test/tls/server.key"
key_pem_len   equ $ - key_pem
cfin_marker:  db "CFIN-OK", 10
cfin_marker_len equ $ - cfin_marker
docroot:      db "test/www/"
docroot_len   equ $ - docroot

section .bss
sa:          resb 16
salen:       resq 1
dgram:       resb 2048
plaintext:   resb 2048
ini_server:  resb linnea_quic_keys_size
ini_client:  resb linnea_quic_keys_size
hs_skeys:    resb linnea_quic_keys_size
hs_ckeys:    resb linnea_quic_keys_size
hs_sec:      resb 96                  ; c_hs || s_hs || handshake_secret
s_th_cfin:   resb 32                  ; H(CH..server Finished) for the client MAC
expfin:      resb 64                  ; expected client Finished message
ap_ckeys:    resb linnea_quic_keys_size
ap_skeys:    resb linnea_quic_keys_size
onertt_pay:  resb 32                  ; HANDSHAKE_DONE + PADDING
onertt_pkt:  resb 4096                ; the protected 1-RTT packet
strm_pay:    resb 4096                ; STREAM frame carrying the h3 response
req:         resb linnea_h2_req_size  ; decoded h3 request
h3scratch:   resb 2048                ; QPACK literal scratch
s_1rtt_pn:   resq 1                   ; server 1-RTT packet number
s_pl_ptr:    resq 1
s_pl_len:    resq 1
s_sid:       resq 1                   ; stream id of the request being served
s_sdata:     resq 1                   ; that stream's data pointer
s_slen:      resq 1                   ; and length
ch_out:      resb linnea_quic_ch_size
server_pub:  resb 32
sh_buf:      resb 128
th_buf:      resb 32
hsmsg:       resb 4096
cert_list:   resb 4096
shactx:      resb linnea_sha256_ctx_size
hdr:         resb 64
payload:     resb 256
hspay:       resb 4096
outpkt:      resb 8192
; per-request saves
s_ch_ptr:    resq 1
s_ch_len:    resq 1
s_odcid_ptr: resq 1
s_odcid_len: resq 1
s_cscid_ptr: resq 1
s_cscid_len: resq 1
s_cscid_buf: resb 20                  ; stable copy of the client SCID
s_cert_len:  resq 1
s_priv:      resq 1
s_ini_len:   resq 1
s_hsmsg_len: resq 1

section .text
_start:
    ; frame the certificate chain and load the private key once
    lea rdi, [cert_pem]
    mov esi, cert_pem_len
    lea rdx, [cert_list]
    mov ecx, 4096
    call linnea_pem_cert_list
    test rax, rax
    js .fail
    mov [s_cert_len], rax
    lea rdi, [key_pem]
    mov esi, key_pem_len
    call linnea_pem_p256_key
    test rax, rax
    js .fail
    mov [s_priv], rax
    ; udp socket + bind 127.0.0.1:47501
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, SOCK_DGRAM
    xor edx, edx
    syscall
    test eax, eax
    js .fail
    mov r12d, eax
    mov word [sa], LINNEA_AF_INET
    mov word [sa + 2], 0x8db9
    mov dword [sa + 4], 0x0100007f
    mov qword [sa + 8], 0
    mov eax, LINNEA_SYS_BIND
    mov edi, r12d
    lea rsi, [sa]
    mov edx, 16
    syscall
    test eax, eax
    js .fail
.loop:
    mov qword [salen], 16
    mov eax, SYS_RECVFROM
    mov edi, r12d
    lea rsi, [dgram]
    mov edx, 2048
    xor r10d, r10d
    lea r8, [sa]
    lea r9, [salen]
    syscall
    test rax, rax
    jle .loop
    mov r13, rax                     ; datagram length

    ; short-header (1-RTT) packets carry application data once the handshake is
    ; confirmed; long-header packets are the handshake flights.
    test byte [dgram], 0x80
    jz .onertt_in

    ; server Initial keys from the client DCID (also the odcid for transport params)
    lea rdi, [dgram]
    mov rsi, r13
    call linnea_quic_initial_dcid
    test rax, rax
    jz .loop
    mov [s_odcid_ptr], rax
    mov [s_odcid_len], rdx
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [ini_client]
    lea rcx, [ini_server]
    call linnea_quic_initial_secrets
    ; ClientHello + key_share
    lea rdi, [dgram]
    mov rsi, r13
    lea rdx, [plaintext]
    call linnea_quic_recv_initial
    test rax, rax
    jz .try_handshake                ; no ClientHello — maybe the client Finished
    mov [s_ch_ptr], rax
    mov [s_ch_len], rdx
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [ch_out]
    call linnea_quic_ch_parse
    ; the client's SCID sits after its DCID in the received header. Copy it to a
    ; stable buffer: we reuse it as the DCID of every packet we send back, but
    ; dgram is overwritten by each recvfrom.
    movzx eax, byte [dgram + 5]
    lea rsi, [dgram + 6 + rax]
    movzx ecx, byte [rsi]            ; SCID length
    inc rsi                          ; -> SCID bytes
    mov [s_cscid_len], rcx
    lea rdi, [s_cscid_buf]
    rep movsb                        ; copy the SCID out of dgram
    lea rax, [s_cscid_buf]
    mov [s_cscid_ptr], rax
    ; server ephemeral public + ServerHello
    lea rdi, [server_pub]
    lea rsi, [server_priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    lea rdi, [sh_buf]
    lea rsi, [server_pub]
    lea rdx, [server_srand]
    call linnea_quic_build_sh

    ; ===== Initial packet: ACK + CRYPTO(ServerHello) =====
    mov byte [payload], 0x02
    mov dword [payload + 1], 0
    mov byte [payload + 5], 0x06
    mov byte [payload + 6], 0x00
    mov word [payload + 7], 0x5a40   ; CRYPTO length varint(90)
    lea rdi, [payload + 9]
    lea rsi, [sh_buf]
    mov ecx, 90
    rep movsb                        ; payload length = 99
    call .build_initial_header       ; -> rcx = header length (uses s_cscid_*)
    sub rsp, 16
    lea rax, [ini_server]
    mov [rsp], rax
    lea rdi, [outpkt]
    lea rsi, [hdr]
    mov rdx, rcx
    mov ecx, 1
    lea r8, [payload]
    mov r9d, 99
    call linnea_quic_protect         ; rax = Initial packet length
    add rsp, 16
    mov [s_ini_len], rax

    ; ===== handshake keys and messages =====
    ; th = H(CH || SH)
    lea rsi, [sh_buf]
    mov edx, 90
    call .transcript                 ; th_buf = H(CH || saved-prefix)? see helper
    ; hs_secrets(client key_share, server_priv, th, hs_ckeys, hs_skeys, hs_sec)
    mov rdi, [ch_out + linnea_quic_ch.ks_ptr]
    lea rsi, [server_priv]
    lea rdx, [th_buf]
    lea rcx, [hs_ckeys]
    lea r8, [hs_skeys]
    lea r9, [hs_sec]
    call linnea_quic_hs_secrets
    ; EE || Cert || CertVerify || Finished into hsmsg
    lea rdi, [hsmsg]
    mov rsi, [s_odcid_ptr]
    mov rdx, [s_odcid_len]
    lea rcx, [server_scid]
    mov r8d, 8
    call linnea_quic_build_ee        ; rax = EE length
    mov r14, rax                     ; running hsmsg length
    lea rdi, [hsmsg + r14]
    lea rsi, [cert_list]
    mov rdx, [s_cert_len]
    call linnea_quic_build_cert
    add r14, rax
    ; th_cert = H(CH || SH || hsmsg[0..r14])
    lea rsi, [hsmsg]
    mov rdx, r14
    call .transcript
    lea rdi, [hsmsg + r14]
    lea rsi, [th_buf]
    mov rdx, [s_priv]
    call linnea_quic_build_cert_verify
    add r14, rax
    ; th_cv = H(CH || SH || hsmsg[0..r14])
    lea rsi, [hsmsg]
    mov rdx, r14
    call .transcript
    lea rdi, [hsmsg + r14]
    lea rsi, [hs_sec + 32]           ; s_hs traffic secret
    lea rdx, [th_buf]
    call linnea_quic_build_finished
    add r14, rax
    mov [s_hsmsg_len], r14

    ; ===== Handshake packet: CRYPTO(hsmsg) =====
    mov byte [hspay], 0x06           ; CRYPTO type
    mov byte [hspay + 1], 0x00       ; offset 0
    lea rdi, [hspay + 2]
    mov rsi, r14                     ; hsmsg length
    call linnea_quic_varint_encode   ; rax = varint bytes
    lea rdi, [hspay + 2 + rax]
    lea rsi, [hsmsg]
    mov rcx, r14
    push rax
    rep movsb                        ; copy hsmsg
    pop rax
    lea r15, [rax + 2]
    add r15, r14                     ; Handshake payload length
    call .build_hs_header            ; -> rcx = header length, uses r15 for length
    sub rsp, 16
    lea rax, [hs_skeys]
    mov [rsp], rax
    mov rdi, [s_ini_len]
    lea rdi, [outpkt + rdi]          ; coalesce after the Initial packet
    lea rsi, [hdr]
    mov rdx, rcx
    mov ecx, 1
    lea r8, [hspay]
    mov r9, r15
    call linnea_quic_protect         ; rax = Handshake packet length
    add rsp, 16
    ; send the coalesced datagram
    mov rdx, [s_ini_len]
    add rdx, rax                     ; total datagram length
    mov eax, SYS_SENDTO
    mov edi, r12d
    lea rsi, [outpkt]
    xor r10d, r10d
    lea r8, [sa]
    mov r9d, 16
    syscall
    ; save the transcript through the server Finished; the client's Finished
    ; MAC covers exactly this (H(CH || SH || EE || Cert || CertVerify || Fin)).
    lea rsi, [hsmsg]
    mov rdx, [s_hsmsg_len]
    call .transcript
    lea rsi, [th_buf]
    lea rdi, [s_th_cfin]
    mov ecx, 32
    rep movsb
    jmp .loop

; --- the datagram had no ClientHello: walk its coalesced packets looking for a
; Handshake packet (the client Finished). The client acks the server Initial in
; a leading Initial packet, then carries its Finished in a coalesced Handshake
; packet, so we must skip past the Initial to reach it.
.try_handshake:
    lea r15, [dgram]                 ; cursor over coalesced packets
.walk:
    lea rax, [dgram + r13]           ; datagram end
    cmp r15, rax
    jae .loop                        ; no Handshake packet in this datagram
    test byte [r15], 0x80
    jz .loop                         ; short header (1-RTT): stop
    movzx eax, byte [r15]
    and al, 0x30                     ; packet type (not header-protected)
    mov r10d, eax                    ; 0x00 Initial, 0x20 Handshake
    movzx eax, byte [r15 + 5]        ; DCID length
    lea rdi, [r15 + 6 + rax]         ; -> SCID length
    movzx eax, byte [rdi]
    lea rdi, [rdi + 1 + rax]         ; -> token-len (Initial) or length (Handshake)
    lea rsi, [dgram + r13]           ; datagram end (varint bound)
    cmp r10d, 0x20
    je .walk_len                     ; Handshake carries no token
    call linnea_quic_varint_decode   ; token length (Initial only)
    add rdi, rdx
    add rdi, rax                     ; skip the token
.walk_len:
    call linnea_quic_varint_decode   ; length (pn + payload + tag)
    lea rdi, [rdi + rdx]             ; -> packet number
    add rdi, rax                     ; -> next coalesced packet
    cmp r10d, 0x20
    je .do_cfin
    mov r15, rdi                     ; advance past this (Initial) packet
    jmp .walk
.do_cfin:
    ; a Handshake packet at [r15]: unprotect with the client handshake keys
    mov rdi, r15
    lea rsi, [dgram + r13]
    sub rsi, r15                     ; bytes from here to the datagram end
    lea rdx, [hs_ckeys]
    lea rcx, [plaintext]
    call linnea_quic_unprotect_hs
    test rax, rax
    js .loop
    lea rdi, [plaintext]
    mov rsi, rax
    call linnea_quic_crypto_frame    ; skips the ACK, returns the Finished
    test rax, rax
    jz .loop
    cmp rdx, 36
    jb .loop
    mov r14, rax                     ; received Finished message ptr
    ; expected = Finished(c_hs, H(CH..server Finished))
    lea rdi, [expfin]
    lea rsi, [hs_sec]                ; c_hs traffic secret (offset 0)
    lea rdx, [s_th_cfin]
    call linnea_quic_build_finished  ; rax = 36
    lea rsi, [expfin]
    mov rdi, r14
    mov ecx, 36
    repe cmpsb
    jne .loop
    ; the client authenticated. Derive the 1-RTT keys (the application traffic
    ; secrets use the same transcript through the server Finished) and confirm
    ; the handshake by sending HANDSHAKE_DONE in a short-header 1-RTT packet.
    lea rdi, [hs_sec + 64]           ; handshake secret
    lea rsi, [s_th_cfin]             ; H(CH..server Finished)
    lea rdx, [ap_ckeys]
    lea rcx, [ap_skeys]
    call linnea_quic_app_secrets
    ; payload: HANDSHAKE_DONE (0x1e), padded so the HP sample has room
    mov byte [onertt_pay], 0x1e
    lea rdi, [onertt_pay + 1]
    xor eax, eax
    mov ecx, 15
    rep stosb                        ; PADDING to 16 bytes
    lea rsi, [onertt_pay]
    mov edx, 16
    call .send_1rtt
    ; announce it
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [cfin_marker]
    mov edx, cfin_marker_len
    syscall
    jmp .loop

; --- 1-RTT (short-header) packet: HTTP/3 requests on QUIC streams ---
; One packet can carry several STREAM frames (requests on different streams),
; so walk them all and answer each on the stream it arrived on.
.onertt_in:
    lea rdi, [dgram]
    mov rsi, r13
    lea rdx, [ap_ckeys]              ; client 1-RTT keys (derived at .do_cfin)
    lea rcx, [plaintext]
    mov r8d, 8                       ; our DCID length = server_scid length
    call linnea_quic_unprotect_short
    test rax, rax
    js .loop
    lea r14, [plaintext]             ; scan cursor
    lea r15, [plaintext + rax]       ; end of the frames
.stream_scan:
    cmp r14, r15
    jae .loop
    mov rdi, r14
    mov rsi, r15
    sub rsi, r14
    call linnea_quic_stream_frame    ; rax=data, rdx=len, r8=stream id, r9=next
    test rax, rax
    jz .loop                         ; no further STREAM frames
    mov r14, r9                      ; resume point for the next frame
    mov [s_sid], r8
    mov [s_sdata], rax
    mov [s_slen], rdx
    test r8, 3
    jnz .stream_scan                 ; not a client-initiated bidi stream
    ; zero the request struct and point the QPACK scratch at h3scratch
    lea rdi, [req]
    xor eax, eax
    mov ecx, linnea_h2_req_size
    rep stosb
    lea rax, [h3scratch]
    mov [req + linnea_h2_req.scratch], rax
    lea rax, [h3scratch + 2048]
    mov [req + linnea_h2_req.scratch_end], rax
    ; parse the HTTP/3 request (HEADERS frame -> QPACK decode)
    mov rdi, [s_sdata]
    mov rsi, [s_slen]
    lea rdx, [req]
    call linnea_h3_read_headers
    test rax, rax
    jnz .stream_scan                 ; not a complete request on this stream
    ; response STREAM frame: type 0x09 (STREAM|FIN), this stream's id, then the
    ; HTTP/3 response. Each response rides its own 1-RTT packet, so the frame
    ; needs no LEN — its data runs to the end of the packet.
    mov byte [strm_pay], 0x09
    lea rdi, [strm_pay + 1]
    mov rsi, [s_sid]
    call linnea_quic_varint_encode   ; rax = stream-id varint length
    lea rbx, [rax + 1]               ; STREAM frame header length
    lea rcx, [strm_pay + rbx]
    lea rdi, [req]
    lea rsi, [docroot]
    mov edx, docroot_len
    call linnea_h3_serve             ; rax = h3 response length
    lea rdx, [rax + rbx]             ; STREAM frame length
    lea rsi, [strm_pay]
    call .send_1rtt
    jmp .stream_scan

; .send_1rtt(rsi = payload ptr, rdx = payload len) — build a short-header 1-RTT
; packet with the current server packet number, protect it with the server
; 1-RTT keys, send it to the client, and advance the packet number.
.send_1rtt:
    push rbx                          ; align the stack (and free reg)
    mov [s_pl_ptr], rsi
    mov [s_pl_len], rdx
    mov byte [hdr], 0x40              ; short header, 1-byte pn, key phase 0
    mov rcx, [s_cscid_len]
    lea rdi, [hdr + 1]
    mov rsi, [s_cscid_ptr]
    rep movsb                         ; DCID = client SCID
    mov rax, [s_1rtt_pn]
    mov [rdi], al                     ; packet number (1 byte)
    inc rdi
    mov rbx, [s_cscid_len]
    add rbx, 2                        ; header length = 1 + DCID + 1
    sub rsp, 16
    lea rax, [ap_skeys]
    mov [rsp], rax
    lea rdi, [onertt_pkt]
    lea rsi, [hdr]
    mov rdx, rbx
    mov ecx, 1
    mov r8, [s_pl_ptr]
    mov r9, [s_pl_len]
    call linnea_quic_protect          ; rax = packet length
    add rsp, 16
    mov rdx, rax
    mov eax, SYS_SENDTO
    mov edi, r12d
    lea rsi, [onertt_pkt]
    xor r10d, r10d
    lea r8, [sa]
    mov r9d, 16
    syscall
    inc qword [s_1rtt_pn]
    pop rbx
    ret

; .build_initial_header -> rcx = header length; DCID = client SCID, SCID = ours,
; length field = pn(1)+payload(99)+tag(16) = 116, packet number 0.
.build_initial_header:
    mov byte [hdr], 0xc0
    mov dword [hdr + 1], 0x01000000
    mov rcx, [s_cscid_len]
    mov [hdr + 5], cl
    lea rdi, [hdr + 6]
    mov rsi, [s_cscid_ptr]
    rep movsb
    mov byte [rdi], 8
    inc rdi
    lea rsi, [server_scid]
    mov ecx, 8
    rep movsb
    mov byte [rdi], 0x00             ; token length
    mov word [rdi + 1], 0x7440       ; length varint(116)
    mov byte [rdi + 3], 0x00         ; packet number 0
    lea rcx, [rdi + 4]
    lea rax, [hdr]
    sub rcx, rax                     ; header length
    ret

; .build_hs_header -> rcx = header length; type Handshake, no token; the length
; field = pn(1)+r15(payload)+tag(16), packet number 0.
.build_hs_header:
    mov byte [hdr], 0xe0             ; long, Handshake, 1-byte pn
    mov dword [hdr + 1], 0x01000000
    mov rcx, [s_cscid_len]
    mov [hdr + 5], cl
    lea rdi, [hdr + 6]
    mov rsi, [s_cscid_ptr]
    rep movsb
    mov byte [rdi], 8
    inc rdi
    lea rsi, [server_scid]
    mov ecx, 8
    rep movsb
    ; length varint = pn(1) + payload(r15) + tag(16)
    lea rsi, [r15 + 17]
    push rdi
    call linnea_quic_varint_encode   ; writes at rdi, rax = varint bytes
    pop rdi
    add rdi, rax                     ; past the length varint
    mov byte [rdi], 0x00             ; packet number 0
    lea rcx, [rdi + 1]
    lea rax, [hdr]
    sub rcx, rax
    ret

; .transcript(rsi=tail ptr, rdx=tail len) -> th_buf = SHA256(CH || tail).
; The ClientHello is always the transcript prefix; the tail is SH, or the
; growing SH..message run in hsmsg.
.transcript:
    push r14
    push r15
    sub rsp, 8                        ; keep the stack 16-aligned for the calls
    mov r14, rsi
    mov r15, rdx
    lea rdi, [shactx]
    call linnea_sha256_init
    lea rdi, [shactx]
    mov rsi, [s_ch_ptr]
    mov rdx, [s_ch_len]
    call linnea_sha256_update
    ; if the tail is not sh_buf itself, the SH must precede it
    lea rax, [sh_buf]
    cmp r14, rax
    je .tr_tail
    lea rdi, [shactx]
    lea rsi, [sh_buf]
    mov edx, 90
    call linnea_sha256_update
.tr_tail:
    lea rdi, [shactx]
    mov rsi, r14
    mov rdx, r15
    call linnea_sha256_update
    lea rdi, [shactx]
    lea rsi, [th_buf]
    call linnea_sha256_final
    add rsp, 8
    pop r15
    pop r14
    ret
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
