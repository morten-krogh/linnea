; linnea_quic_server.asm — the QUIC/HTTP/3 server datagram handler.
;
; Everything above the socket: demultiplex a datagram to its connection, run the
; handshake, and serve HTTP/3 requests. It owns the receive buffer and all
; per-datagram scratch, so a caller only has to read a datagram into
; linnea_quic_rxbuf and hand over the length and the sender's address. The same
; handler therefore serves a blocking recvfrom loop (the test driver) and the
; io_uring event loop.
;
; Replies go out with sendto(2) on the socket the caller passes. A UDP send hands
; the datagram straight to the kernel rather than waiting on a peer the way a
; stream write can, so it does not stall the loop; routing it through the ring
; would mean tracking an msghdr per in-flight reply for no real gain.

default rel

%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"
%include "linnea_sha256.inc"
%include "linnea_hpack.inc"
%include "linnea_http3.inc"

; Per-connection state lives in the pool slot cur_conn points at. CONNLEA loads
; the address of one of its fields; CONNGET loads a qword field's value. Both
; use only the destination register.
%macro CONNLEA 2                     ; CONNLEA reg, field -> reg = &conn.field
    mov %1, [cur_conn]
    add %1, linnea_quic_conn. %+ %2
%endmacro
%macro CONNGET 2                     ; CONNGET reg, field -> reg = conn.field
    mov %1, [cur_conn]
    mov %1, [%1 + linnea_quic_conn. %+ %2]
%endmacro

%define SYS_SENDTO   44

global linnea_quic_server_init
global linnea_quic_server_datagram
global linnea_quic_server_rtx_sweep
global linnea_quic_rxbuf
global linnea_quic_altsvc_set
global linnea_h3_altsvc
global linnea_h3_altsvc_len
global linnea_h3_server

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
extern linnea_quic_conn_lookup
extern linnea_quic_conn_alloc
extern linnea_quic_hs_secrets
extern linnea_quic_app_secrets
extern linnea_quic_protect
extern linnea_quic_unprotect_hs
extern linnea_quic_unprotect_short
extern linnea_quic_crypto_frame
extern linnea_quic_stream_frame
extern linnea_quic_close_frame
extern linnea_quic_ack_record
extern linnea_quic_build_ack
extern linnea_quic_ack_ranges
extern linnea_quic_rtx_record
extern linnea_quic_rtx_ack_range
extern linnea_quic_conn_slot
extern linnea_string_from_u64
extern linnea_quic_conn_free
extern linnea_quic_varint_encode
extern linnea_quic_varint_decode
extern linnea_x25519
extern linnea_sha256_init
extern linnea_sha256_update
extern linnea_sha256_final

section .rodata
altsvc_pre:  db 'h3=":'
altsvc_pre_len equ $ - altsvc_pre
altsvc_post: db '"; ma=86400'
altsvc_post_len equ $ - altsvc_post
x25519_base:  db 9
              times 31 db 0
server_priv:  db 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
              db 0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
server_srand: db 0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f
              db 0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f
cfin_marker:  db "CFIN-OK", 10
cfin_marker_len equ $ - cfin_marker
; The server's unidirectional streams, opened once the handshake completes.
; RFC 9114 6.2.1 requires each side to open a control stream and send SETTINGS as
; its first frame. Three LEN-prefixed STREAM frames on the fixed server-initiated
; uni stream ids 3, 7 and 11 (a server opens no others):
;   - stream 3, type 0x00 (control): a SETTINGS frame advertising
;     QPACK_MAX_TABLE_CAPACITY=0 and QPACK_BLOCKED_STREAMS=0 — we keep no dynamic
;     table, so the peer's encoder must not reference one;
;   - stream 7, type 0x02 (QPACK encoder) and stream 11, type 0x03 (QPACK
;     decoder): opened empty, since with a zero table neither ever carries data.
; This is a constant: the stream ids and settings are the same for every
; connection, so it is coalesced verbatim into the HANDSHAKE_DONE packet.
h3_uni_setup: db 0x0a, 0x03, 0x07, 0x00, 0x04, 0x04, 0x01, 0x00, 0x07, 0x00
              db 0x0a, 0x07, 0x01, 0x02
              db 0x0a, 0x0b, 0x01, 0x03
h3_uni_setup_len equ $ - h3_uni_setup

section .bss
sa:          resb 16
salen:       resq 1
linnea_quic_rxbuf: resb LINNEA_QUIC_RXBUF_SIZE
plaintext:   resb 2048
cur_conn:    resq 1                   ; connection this datagram belongs to
expfin:      resb 64                  ; expected client Finished message
onertt_pay:  resb 64                  ; ACK + HANDSHAKE_DONE + server uni streams
onertt_pkt:  resb 4096                ; the protected 1-RTT packet
strm_pay:    resb 4096                ; STREAM frame carrying the h3 response
req:         resb linnea_h2_req_size  ; decoded h3 request
h3scratch:   resb 2048                ; QPACK literal scratch
s_pl_ptr:    resq 1
s_pl_len:    resq 1
s_sid:       resq 1                   ; stream id of the request being served
s_sdata:     resq 1                   ; that stream's data pointer
s_slen:      resq 1                   ; and length
s_soff:      resq 1                   ; and offset (0 = the stream's first bytes)
cc_pay:      resb 16                  ; an application CONNECTION_CLOSE payload
ch_out:      resb linnea_quic_ch_size
server_pub:  resb 32
sh_buf:      resb 128
th_buf:      resb 32
hsmsg:       resb 4096
s_cert_list_ptr: resq 1
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
s_cert_len:  resq 1
s_priv:      resq 1
s_ini_len:   resq 1
s_hsmsg_len: resq 1
linnea_h3_altsvc:     resb 48    ; Alt-Svc value, e.g. h3=":443"; ma=86400
linnea_h3_altsvc_len: resq 1     ; 0 until a QUIC listener is bound
linnea_h3_server:     resq 1     ; index of the server that owns that listener
s_acklen:      resq 1
s_docroot_ptr: resq 1
s_docroot_len: resq 1
ack_ranges:    resb LINNEA_QUIC_ACK_MAXR * 16   ; decoded [smallest,largest] pairs

section .text

; linnea_quic_server_init(rdi=certificate_list, rsi=list len, rdx=P-256 private
;   scalar, rcx=document root, r8=root len) -> rax = 0.
; The chain and key are taken already framed/decoded — the config parser does
; that work for the TLS listeners, and the test driver frames its embedded PEM.
linnea_quic_server_init:
    mov [s_cert_list_ptr], rdi
    mov [s_cert_len], rsi
    mov [s_priv], rdx
    mov [s_docroot_ptr], rcx
    mov [s_docroot_len], r8
    xor eax, eax
    ret

; linnea_quic_altsvc_set(rdi=port) — build the Alt-Svc value advertising HTTP/3
; on this port. HTTP/1.1 and HTTP/2 responses carry it so a client that reached
; us over TCP learns it can use HTTP/3; without it browsers never try QUIC.
linnea_quic_altsvc_set:
    push rbx
    push r12
    mov r12, rdi                     ; port
    lea rbx, [linnea_h3_altsvc]
    lea rsi, [altsvc_pre]
    mov rdi, rbx
    mov ecx, altsvc_pre_len
    rep movsb
    mov rbx, rdi
    mov rdi, r12
    mov rsi, rbx
    call linnea_string_from_u64      ; port digits
    add rbx, rax
    lea rsi, [altsvc_post]
    mov rdi, rbx
    mov ecx, altsvc_post_len
    rep movsb
    lea rax, [linnea_h3_altsvc]
    sub rdi, rax
    mov [linnea_h3_altsvc_len], rdi
    pop r12
    pop rbx
    ret

; linnea_quic_server_datagram(rdi=length, rsi=peer sockaddr, rdx=peer len,
;   ecx=udp socket fd) — process one datagram already read into
; linnea_quic_rxbuf, sending any replies on that socket.
linnea_quic_server_datagram:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8                       ; keep rsp 16-aligned for the calls
    mov r13, rdi                     ; datagram length
    mov r12d, ecx                    ; udp socket
    ; record the sender: the pool allocator and .refresh_peer read it here
    cmp rdx, 16
    jbe .dg_plen
    mov edx, 16
.dg_plen:
    mov [salen], rdx
    mov rcx, rdx
    lea rdi, [sa]
    rep movsb                        ; rsi = peer sockaddr

    ; --- demultiplex: route the datagram to its connection ---
    ; The peer addresses us by the connection ID we issued, whose first two
    ; bytes hold the pool index, so the lookup is a bounds check and a compare.
    ; Short-header (1-RTT) packets carry application data once the handshake is
    ; confirmed; long-header packets are the handshake flights.
    test byte [linnea_quic_rxbuf], 0x80
    jz .demux_short
    movzx eax, byte [linnea_quic_rxbuf + 5]      ; long header: explicit DCID length
    cmp eax, LINNEA_QUIC_MAX_CID
    ja .done
    lea rdi, [linnea_quic_rxbuf + 6]
    mov esi, eax
    call linnea_quic_conn_lookup
    test rax, rax
    jnz .demux_found
    ; An id we never issued. Only a client's first flight may open a
    ; connection, and that always arrives in an Initial packet: the type bits
    ; sit in the first byte and are not header-protected. Anything else with an
    ; unknown id belongs to a connection we do not hold — another worker's, or
    ; one already gone — so it is dropped rather than mistaken for a new
    ; handshake. With several workers this is what keeps a datagram that landed
    ; on the wrong one from starting a bogus connection.
    movzx eax, byte [linnea_quic_rxbuf]
    and al, 0x30                     ; packet type: Initial is 0
    jnz .done
    lea rdi, [sa]
    mov rsi, [salen]
    call linnea_quic_conn_alloc
    test rax, rax
    jz .done                         ; pool exhausted: drop the datagram
    mov [cur_conn], rax
    jmp .long_in
.demux_short:
    lea rdi, [linnea_quic_rxbuf + 1]             ; short header: our ID, fixed length
    mov esi, LINNEA_QUIC_SCID_LEN
    call linnea_quic_conn_lookup
    test rax, rax
    jz .done                         ; unknown connection: drop
    call .refresh_peer
    jmp .onertt_in
.demux_found:
    call .refresh_peer
.long_in:

    ; server Initial keys from the client DCID (also the odcid for transport params)
    lea rdi, [linnea_quic_rxbuf]
    mov rsi, r13
    call linnea_quic_initial_dcid
    test rax, rax
    jz .done
    mov [s_odcid_ptr], rax
    mov [s_odcid_len], rdx
    mov rdi, rax
    mov rsi, rdx
    CONNLEA rdx, ini_client
    CONNLEA rcx, ini_server
    call linnea_quic_initial_secrets
    ; ClientHello + key_share
    lea rdi, [linnea_quic_rxbuf]
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
    movzx eax, byte [linnea_quic_rxbuf + 5]
    lea rsi, [linnea_quic_rxbuf + 6 + rax]
    movzx ecx, byte [rsi]            ; SCID length
    inc rsi                          ; -> SCID bytes
    mov rax, [cur_conn]
    mov [rax + linnea_quic_conn.dcid_len], rcx
    lea rdi, [rax + linnea_quic_conn.dcid]
    rep movsb                        ; copy the SCID out of dgram
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
    CONNLEA rax, ini_server
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
    CONNLEA rcx, hs_ckeys
    CONNLEA r8, hs_skeys
    CONNLEA r9, hs_sec
    call linnea_quic_hs_secrets
    ; EE || Cert || CertVerify || Finished into hsmsg
    lea rdi, [hsmsg]
    mov rsi, [s_odcid_ptr]
    mov rdx, [s_odcid_len]
    CONNLEA rcx, scid
    mov r8d, 8
    call linnea_quic_build_ee        ; rax = EE length
    mov r14, rax                     ; running hsmsg length
    lea rdi, [hsmsg + r14]
    mov rsi, [s_cert_list_ptr]
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
    CONNLEA rsi, hs_sec
    add rsi, 32                      ; s_hs traffic secret
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
    CONNLEA rax, hs_skeys
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
    CONNLEA r8, peer
    CONNGET r9, peer_len
    syscall
    ; save the transcript through the server Finished; the client's Finished
    ; MAC covers exactly this (H(CH || SH || EE || Cert || CertVerify || Fin)).
    lea rsi, [hsmsg]
    mov rdx, [s_hsmsg_len]
    call .transcript
    lea rsi, [th_buf]
    CONNLEA rdi, th_cfin
    mov ecx, 32
    rep movsb
    jmp .done

; --- the datagram had no ClientHello: walk its coalesced packets looking for a
; Handshake packet (the client Finished). The client acks the server Initial in
; a leading Initial packet, then carries its Finished in a coalesced Handshake
; packet, so we must skip past the Initial to reach it.
.try_handshake:
    lea r15, [linnea_quic_rxbuf]                 ; cursor over coalesced packets
.walk:
    lea rax, [linnea_quic_rxbuf + r13]           ; datagram end
    cmp r15, rax
    jae .done                        ; no Handshake packet in this datagram
    test byte [r15], 0x80
    jz .done                         ; short header (1-RTT): stop
    movzx eax, byte [r15]
    and al, 0x30                     ; packet type (not header-protected)
    mov r10d, eax                    ; 0x00 Initial, 0x20 Handshake
    movzx eax, byte [r15 + 5]        ; DCID length
    lea rdi, [r15 + 6 + rax]         ; -> SCID length
    movzx eax, byte [rdi]
    lea rdi, [rdi + 1 + rax]         ; -> token-len (Initial) or length (Handshake)
    lea rsi, [linnea_quic_rxbuf + r13]           ; datagram end (varint bound)
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
    lea rsi, [linnea_quic_rxbuf + r13]
    sub rsi, r15                     ; bytes from here to the datagram end
    CONNLEA rdx, hs_ckeys
    lea rcx, [plaintext]
    call linnea_quic_unprotect_hs
    test rax, rax
    js .done
    lea rdi, [plaintext]
    mov rsi, rax
    call linnea_quic_crypto_frame    ; skips the ACK, returns the Finished
    test rax, rax
    jz .done
    cmp rdx, 36
    jb .done
    mov r14, rax                     ; received Finished message ptr
    ; expected = Finished(c_hs, H(CH..server Finished))
    lea rdi, [expfin]
    CONNLEA rsi, hs_sec              ; c_hs traffic secret (offset 0)
    CONNLEA rdx, th_cfin
    call linnea_quic_build_finished  ; rax = 36
    lea rsi, [expfin]
    mov rdi, r14
    mov ecx, 36
    repe cmpsb
    jne .done
    ; the client authenticated. Complete the handshake exactly once: a repeated
    ; client Finished (its HANDSHAKE_DONE was lost) is left to the loss-recovery
    ; timer, which resends the packet below rather than rebuilding it here.
    mov rax, [cur_conn]
    cmp qword [rax + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    je .done
    mov qword [rax + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    ; derive the 1-RTT keys (the application traffic secrets use the same
    ; transcript through the server Finished).
    CONNLEA rdi, hs_sec
    add rdi, 64                      ; handshake secret
    CONNLEA rsi, th_cfin             ; H(CH..server Finished)
    CONNLEA rdx, ap_ckeys
    CONNLEA rcx, ap_skeys
    call linnea_quic_app_secrets
    ; confirm the handshake and open the server's HTTP/3 streams in one packet:
    ; ACK, HANDSHAKE_DONE (0x1e), then the control + QPACK stream setup. The
    ; STREAM frames are LEN-prefixed, so all three self-delimit within the packet.
    lea rdi, [onertt_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack       ; rax = ACK length (0 if nothing to ack yet)
    mov rcx, rax
    mov byte [onertt_pay + rcx], 0x1e   ; HANDSHAKE_DONE
    inc rcx
    lea rdi, [onertt_pay + rcx]
    lea rsi, [h3_uni_setup]
    push rcx
    mov ecx, h3_uni_setup_len
    rep movsb                        ; append the fixed control/QPACK stream setup
    pop rcx
    add rcx, h3_uni_setup_len
    lea rsi, [onertt_pay]
    mov rdx, rcx                     ; total payload length
    call .send_1rtt
    ; announce it
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [cfin_marker]
    mov edx, cfin_marker_len
    syscall
    jmp .done

; --- 1-RTT (short-header) packet: HTTP/3 requests on QUIC streams ---
; One packet can carry several STREAM frames (requests on different streams),
; so walk them all and answer each on the stream it arrived on.
.onertt_in:
    lea rdi, [linnea_quic_rxbuf]
    mov rsi, r13
    CONNLEA rdx, ap_ckeys            ; client 1-RTT keys (derived at .do_cfin)
    lea rcx, [plaintext]
    mov r8d, LINNEA_QUIC_SCID_LEN    ; the connection ID length we issue
    call linnea_quic_unprotect_short  ; rax = frame bytes, rdx = packet number
    test rax, rax
    js .done
    ; note it as received, so our next packet can acknowledge it — otherwise the
    ; peer keeps retransmitting a request we have already answered
    push rax
    mov rsi, rdx
    CONNLEA rdi, rx_have
    call linnea_quic_ack_record
    pop rax
    mov r14, rax                     ; frame bytes
    ; ingest the peer's ACK: release every buffered packet it acknowledges, so
    ; we stop holding (and, once the PTO timer exists, retransmitting) frames
    ; that have already arrived.
    lea rdi, [plaintext]
    mov rsi, r14
    lea rdx, [ack_ranges]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges      ; rax = pairs written into ack_ranges
    test rax, rax
    jz .acks_done
    lea rbx, [ack_ranges]
    mov rbp, rax                     ; pair count
.ack_free:
    mov rdi, [cur_conn]
    mov rsi, [rbx]                   ; smallest
    mov rdx, [rbx + 8]               ; largest
    call linnea_quic_rtx_ack_range
    add rbx, 16
    dec rbp
    jnz .ack_free
.acks_done:
    ; a peer that closes cleanly gets its slot back at once instead of waiting
    ; for the idle sweep — this is what keeps rapid connection churn from
    ; filling the pool.
    lea rdi, [plaintext]
    mov rsi, r14
    call linnea_quic_close_frame
    test rax, rax
    jnz .peer_closed
    lea r15, [plaintext + r14]       ; end of the frames
    lea r14, [plaintext]             ; scan cursor
.stream_scan:
    cmp r14, r15
    jae .done
    mov rdi, r14
    mov rsi, r15
    sub rsi, r14
    call linnea_quic_stream_frame    ; rax=data, rdx=len, r8=stream id, r9=next
    test rax, rax
    jz .done                         ; no further STREAM frames
    mov r14, r9                      ; resume point for the next frame
    mov [s_sid], r8
    mov [s_sdata], rax
    mov [s_slen], rdx
    mov [s_soff], r10                ; data offset, for typing a uni stream
    mov rax, r8
    and eax, 3
    jz .serve_bidi                   ; client bidi stream: an HTTP/3 request
    cmp eax, 2
    je .client_uni                   ; client uni stream: control / QPACK
    jmp .stream_scan                 ; a server-initiated id (never from a client)
.serve_bidi:
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
    ; acknowledge what we have received first: a STREAM frame carries no LEN,
    ; so its data runs to the end of the packet and it must come last.
    lea rdi, [strm_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack       ; rax = 0 if there is nothing to ack yet
    mov [s_acklen], rax
    mov rcx, rax
    mov byte [strm_pay + rcx], 0x09  ; STREAM | FIN
    lea rdi, [strm_pay + rcx + 1]
    mov rsi, [s_sid]
    call linnea_quic_varint_encode   ; rax = stream-id varint length
    mov rbx, [s_acklen]
    add rbx, rax
    inc rbx                          ; bytes before the HTTP/3 response
    lea rcx, [strm_pay + rbx]
    lea rdi, [req]
    mov rsi, [s_docroot_ptr]
    mov rdx, [s_docroot_len]
    call linnea_h3_serve             ; rax = h3 response length
    lea rdx, [rax + rbx]             ; STREAM frame length
    lea rsi, [strm_pay]
    call .send_1rtt
    jmp .stream_scan

; --- a client unidirectional stream: control, QPACK encoder/decoder or grease.
; A stream's type is the first varint, present only at offset 0, so a later
; frame (offset > 0) is a continuation we do not re-type. RFC 9114 6.2.1 requires
; the control stream to open with SETTINGS and forbids a second one; a violation
; ends the connection with the matching HTTP/3 error. QPACK and unknown streams
; are ignored — with a zero dynamic table their instruction streams carry nothing.
.client_uni:
    cmp qword [s_soff], 0
    jne .stream_scan                 ; a continuation: type already determined
    mov rsi, [s_slen]
    test rsi, rsi
    jz .stream_scan                  ; empty frame: nothing to type yet
    mov rax, [s_sdata]
    movzx ecx, byte [rax]            ; the stream type (1 byte for every h3 type)
    cmp cl, LINNEA_H3_STREAM_CONTROL
    jne .stream_scan                 ; QPACK/grease: not interpreted
    ; the client's control stream. Reject a second one on a different id.
    mov rdx, [cur_conn]
    mov rax, [rdx + linnea_quic_conn.ctrl_id]
    test rax, rax
    jz .uni_ctrl_first
    cmp rax, [s_sid]
    je .uni_ctrl_settings            ; the same control stream again
    mov edi, LINNEA_H3_ERR_STREAM_CREATION
    jmp .h3_close
.uni_ctrl_first:
    mov rax, [s_sid]
    mov [rdx + linnea_quic_conn.ctrl_id], rax
.uni_ctrl_settings:
    ; the first frame on the control stream must be SETTINGS. If only the type
    ; byte is present it may follow in a later frame, so do not reject that.
    cmp qword [s_slen], 2
    jb .stream_scan
    mov rax, [s_sdata]
    movzx ecx, byte [rax + 1]        ; first control-stream frame type (0x04 = SETTINGS)
    cmp cl, LINNEA_H3_FRAME_SETTINGS
    je .stream_scan                  ; SETTINGS first: accepted (its values ignored)
    mov edi, LINNEA_H3_ERR_MISSING_SETTINGS
    ; fall through to .h3_close

; .h3_close(edi = HTTP/3 error code) — end the connection with an application
; CONNECTION_CLOSE (frame 0x1d) carrying the code, then free the slot. Sent via
; emit_1rtt (no loss-recovery tracking): the connection is gone the moment this
; is queued, so a lost close is not worth resending.
.h3_close:
    mov byte [cc_pay], 0x1d          ; CONNECTION_CLOSE (application)
    mov rsi, rdi                     ; error code
    lea rdi, [cc_pay + 1]
    call linnea_quic_varint_encode   ; rax = error-code varint length
    mov byte [cc_pay + 1 + rax], 0x00   ; reason phrase length = 0
    lea rsi, [cc_pay]
    mov [s_pl_ptr], rsi
    lea rdx, [rax + 2]               ; payload = type(1) + code + reason-len(1)
    mov [s_pl_len], rdx
    call emit_1rtt
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done

; the peer said goodbye: release its slot and stop reading this datagram
.peer_closed:
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done

; .refresh_peer(rax = conn) — make it the current connection and record the
; address this datagram came from, so replies follow a peer that has migrated.
.refresh_peer:
    mov [cur_conn], rax
    mov rcx, [salen]
    cmp rcx, 16
    jbe .rp_len
    mov ecx, 16
.rp_len:
    mov [rax + linnea_quic_conn.peer_len], rcx
    lea rdi, [rax + linnea_quic_conn.peer]
    lea rsi, [sa]
    rep movsb
    ret

; .send_1rtt(rsi = payload ptr, rdx = payload len) — send a short-header 1-RTT
; packet carrying these frames (emit_1rtt) and buffer them for loss recovery, so
; a lost copy is resent under a fresh number by the sweep. r12d = the UDP socket.
.send_1rtt:
    push rbx
    mov [s_pl_ptr], rsi
    mov [s_pl_len], rdx
    call emit_1rtt                    ; rax = the packet number used
    mov rbx, rax
    call now_ms
    mov r8, rax
    mov rdi, [cur_conn]
    mov rsi, rbx
    mov rdx, [s_pl_ptr]
    mov rcx, [s_pl_len]
    call linnea_quic_rtx_record
    pop rbx
    ret

; .build_initial_header -> rcx = header length; DCID = client SCID, SCID = ours,
; length field = pn(1)+payload(99)+tag(16) = 116, packet number 0.
.build_initial_header:
    mov byte [hdr], 0xc0
    mov dword [hdr + 1], 0x01000000
    CONNGET rcx, dcid_len
    mov [hdr + 5], cl
    lea rdi, [hdr + 6]
    CONNLEA rsi, dcid
    rep movsb
    mov byte [rdi], LINNEA_QUIC_SCID_LEN
    inc rdi
    CONNLEA rsi, scid
    mov ecx, LINNEA_QUIC_SCID_LEN
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
    CONNGET rcx, dcid_len
    mov [hdr + 5], cl
    lea rdi, [hdr + 6]
    CONNLEA rsi, dcid
    rep movsb
    mov byte [rdi], LINNEA_QUIC_SCID_LEN
    inc rdi
    CONNLEA rsi, scid
    mov ecx, LINNEA_QUIC_SCID_LEN
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
.done:
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; now_ms -> rax = CLOCK_MONOTONIC milliseconds. Monotonic so the probe timeout
; cannot be thrown off by a wall-clock step. Standalone (not a datagram-local)
; because the retransmission sweep needs it too.
now_ms:
    sub rsp, 24
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    mov edi, LINNEA_CLOCK_MONOTONIC
    mov rsi, rsp
    syscall
    mov r8, [rsp]                     ; seconds
    imul r8, r8, 1000
    mov rax, [rsp + 8]                ; nanoseconds
    xor edx, edx
    mov rcx, 1000000
    div rcx                           ; rax = ns / 1e6
    add rax, r8
    add rsp, 24
    ret

; emit_1rtt() -> rax = the packet number the packet went out under.
; Builds a short-header 1-RTT packet carrying [s_pl_ptr, s_pl_len], protects it
; with the current connection's server 1-RTT keys, sends it on r12d, and advances
; the connection's packet number. cur_conn selects the connection, r12d is the
; UDP socket. Shared by the live reply path (.send_1rtt) and the retransmission
; sweep, which resends the stored frames under the fresh number this returns.
; Requires rsp 16-aligned at the call site (rsp % 16 == 8 on entry).
emit_1rtt:
    push rbx
    mov byte [hdr], 0x40              ; short header, 1-byte pn, key phase 0
    CONNGET rcx, dcid_len
    lea rdi, [hdr + 1]
    CONNLEA rsi, dcid
    rep movsb                         ; DCID = the peer's connection id
    CONNGET rax, pn_1rtt
    mov [rdi], al                     ; packet number (1 byte)
    inc rdi
    CONNGET rbx, dcid_len
    add rbx, 2                        ; header length = 1 + DCID + 1
    sub rsp, 16
    CONNLEA rax, ap_skeys
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
    CONNLEA r8, peer
    CONNGET r9, peer_len
    syscall
    mov rbx, [cur_conn]
    mov rax, [rbx + linnea_quic_conn.pn_1rtt]   ; the number just used
    inc qword [rbx + linnea_quic_conn.pn_1rtt]
    pop rbx
    ret

; linnea_quic_server_rtx_sweep(edi = UDP socket fd) — one probe-timeout pass over
; every live connection. Any buffered 1-RTT packet unacknowledged past its probe
; timeout is resent under a fresh packet number (the threshold doubles per
; attempt, up to a cap); one probed too many times is abandoned so a vanished
; peer is not chased until the idle sweep reclaims its slot. Driven by the event
; loop's periodic timer — the loop is single-threaded, so no datagram is being
; processed and the per-datagram send scratch is free to reuse.
linnea_quic_server_rtx_sweep:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                        ; align the call sites (rsp % 16 == 0)
    mov r12d, edi                     ; fd
    call now_ms
    mov r15, rax                      ; now, ms
    xor r13d, r13d                    ; connection index
.sw_conn:
    mov edi, r13d
    call linnea_quic_conn_slot        ; rax = conn* or 0
    test rax, rax
    jz .sw_conn_next
    mov rbx, rax                      ; connection
    lea r14, [rbx + linnea_quic_conn.sent]
    xor ebp, ebp                      ; slot
.sw_rec:
    cmp qword [r14 + linnea_quic_sent.in_use], 0
    je .sw_rec_next
    mov rax, r15
    sub rax, [r14 + linnea_quic_sent.sent_ms]      ; age in ms
    ; threshold = PTO_MS << min(tries, PTO_CAP)
    mov rcx, [r14 + linnea_quic_sent.tries]
    cmp rcx, LINNEA_QUIC_PTO_CAP
    jbe .sw_shift
    mov ecx, LINNEA_QUIC_PTO_CAP
.sw_shift:
    mov rdx, LINNEA_QUIC_PTO_MS
    shl rdx, cl
    cmp rax, rdx
    jb .sw_rec_next                   ; not yet due
    cmp qword [r14 + linnea_quic_sent.tries], LINNEA_QUIC_PTO_MAX
    jb .sw_resend
    mov qword [r14 + linnea_quic_sent.in_use], 0   ; given up on
    jmp .sw_rec_next
.sw_resend:
    mov [cur_conn], rbx
    lea rax, [r14 + linnea_quic_sent.payload]
    mov [s_pl_ptr], rax
    mov rax, [r14 + linnea_quic_sent.len]
    mov [s_pl_len], rax
    call emit_1rtt                    ; rax = the fresh packet number; r12d = fd
    mov [r14 + linnea_quic_sent.pn], rax
    mov [r14 + linnea_quic_sent.sent_ms], r15
    inc qword [r14 + linnea_quic_sent.tries]
.sw_rec_next:
    add r14, linnea_quic_sent_size
    inc ebp
    cmp ebp, LINNEA_QUIC_RTX_SLOTS
    jb .sw_rec
.sw_conn_next:
    inc r13d
    cmp r13d, LINNEA_QUIC_MAX_CONNS
    jb .sw_conn
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
