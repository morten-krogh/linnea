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
global linnea_quic_server_goaway_all
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
extern linnea_quic_conn_lookup_odcid
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
extern linnea_quic_rtx_record_ref
extern linnea_quic_rtx_ack_range
extern linnea_quic_rtx_inflight
extern linnea_quic_rtx_ref_count
extern linnea_quic_rtx_ref_clear
extern linnea_quic_tp_parse
extern linnea_quic_conn_free_hook
extern linnea_h3_tx_cap
extern linnea_quic_conn_slot
extern linnea_string_from_u64
extern linnea_quic_conn_free
extern linnea_quic_varint_encode
extern linnea_quic_varint_decode
extern linnea_x25519
extern linnea_sha256
extern linnea_sha256_init
extern linnea_sha256_update
extern linnea_sha256_final
extern linnea_quic_resumption_psk
extern linnea_quic_ticket_seal
extern linnea_quic_ticket_resume
extern linnea_quic_early_keys
extern linnea_quic_replay_check
extern linnea_quic_hs_psk
extern linnea_quic_early_ok
extern linnea_quic_resume_issued

section .rodata
altsvc_pre:  db 'h3=":'
altsvc_pre_len equ $ - altsvc_pre
altsvc_post: db '"; ma=86400'
altsvc_post_len equ $ - altsvc_post
x25519_base:  db 9
              times 31 db 0
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
; Bytes of control-stream data in h3_uni_setup (the 0x00 type + the 6-byte
; SETTINGS frame) — the offset at which a later GOAWAY continues that stream.
H3_CTRL_OFF equ 7

section .bss
sa:          resb 16
salen:       resq 1
linnea_quic_rxbuf: resb LINNEA_QUIC_RXBUF_SIZE
plaintext:   resb 2048
cur_conn:    resq 1                   ; connection this datagram belongs to
expfin:      resb 64                  ; expected client Finished message
onertt_pay:  resb 256                 ; ACK + HANDSHAKE_DONE + uni streams + NST CRYPTO
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
s_sfin:      resq 1                   ; and whether its FIN bit is set
s_body_ptr:  resq 1                   ; request body captured by read_headers
s_body_len:  resq 1
s_txc_pn:    resq 1                   ; packet number a chunk just went out under
cc_pay:      resb 16                  ; an application CONNECTION_CLOSE payload
goaway_pay:  resb 24                  ; a GOAWAY STREAM frame on the control stream
ch_out:      resb linnea_quic_ch_size
; Per-connection ephemeral X25519 private key and ServerHello random, refilled
; from getrandom(2) on every ClientHello. Constant values here would fix the
; server's key_share across all connections — breaking forward secrecy — and
; repeat the ServerHello random, so both are (re)generated per handshake. Kept
; adjacent and in this order so one getrandom32 pair fills them.
server_priv:  resb 32
server_srand: resb 32
server_pub:  resb 32
sh_buf:      resb 128
th_buf:      resb 32
hsmsg:       resb LINNEA_QUIC_HS_FLIGHT_MAX  ; shared scratch: the whole flight (EE..Finished)
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
s_hs_chunk:  resq 1              ; byte length of the flight chunk being framed
s_cv_off:    resq 1              ; hsmsg offset of CertVerify while staging the tail
s_fin_off:   resq 1              ; hsmsg offset of Finished while staging the tail
s_walk_next: resq 1              ; next coalesced packet, so the Finished walk can go on
linnea_h3_altsvc:     resb 48    ; Alt-Svc value, e.g. h3=":443"; ma=86400
linnea_h3_altsvc_len: resq 1     ; 0 until a QUIC listener is bound
linnea_h3_server:     resq 1     ; index of the server that owns that listener
s_acklen:      resq 1
s_docroot_ptr: resq 1
s_docroot_len: resq 1
ack_ranges:    resb LINNEA_QUIC_ACK_MAXR * 16   ; decoded [smallest,largest] pairs
; NewSessionTicket scratch (issued at handshake completion, see .append_nst)
s_pay_len:   resq 1              ; 1-RTT payload length saved across .append_nst
s_sh_len:    resq 1              ; ServerHello length (90 fresh, 96 with the PSK ext)
s_dgram_len: resq 1              ; this datagram's length (r13 may not survive to .early_walk)
s_now_sec:   resq 1              ; CLOCK_REALTIME seconds, for the 0-RTT replay window
s_resume_psk: resb 32           ; PSK recovered from an accepted resumption ticket
q_sni32:     resb 32             ; SHA-256(SNI), of which 8 bytes seed the ticket
q_nst_ts:    resb 16             ; timespec for the ticket's issued time
q_nst_pt:    resb 48             ; ticket plaintext: psk || issued || sni_hash
q_nst_msg:   resb 128            ; the NewSessionTicket handshake message

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
    ; a reclaimed connection may hold an open response stream's file mapping;
    ; the pool calls this back on every free so the mapping cannot leak
    lea rax, [quic_tx_free_hook]
    mov [linnea_quic_conn_free_hook], rax
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
    mov [s_dgram_len], r13           ; ...also saved: reloaded in the 0-RTT walk
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
    ; Not one of our issued ids. During the handshake the client still addresses
    ; us by the original DCID it chose — until it has our ServerHello it has no
    ; other id for us — so a further Initial of the same handshake (the rest of a
    ; ClientHello too large for one Initial, or a retransmission) must route to
    ; the slot the first Initial opened. Match it by that original DCID.
    movzx eax, byte [linnea_quic_rxbuf + 5]
    lea rdi, [linnea_quic_rxbuf + 6]
    mov esi, eax
    call linnea_quic_conn_lookup_odcid
    test rax, rax
    jz .demux_new
    mov [cur_conn], rax
    call .refresh_peer
    jmp .long_in
.demux_new:
    ; An id we never issued and no handshake in progress for it. Only a client's
    ; first flight may open a connection, and that always arrives in an Initial
    ; packet: the type bits sit in the first byte and are not header-protected.
    ; Anything else with an unknown id belongs to a connection we do not hold —
    ; another worker's, or one already gone — so it is dropped rather than
    ; mistaken for a new handshake. With several workers this is what keeps a
    ; datagram that landed on the wrong one from starting a bogus connection.
    movzx eax, byte [linnea_quic_rxbuf]
    and al, 0x30                     ; packet type: Initial is 0
    jnz .done
    lea rdi, [sa]
    mov rsi, [salen]
    call linnea_quic_conn_alloc
    test rax, rax
    jz .done                         ; pool exhausted: drop the datagram
    mov [cur_conn], rax
    ; record the client's original DCID so its later Initials find this slot
    movzx ecx, byte [linnea_quic_rxbuf + 5]
    mov [rax + linnea_quic_conn.odcid_len], rcx
    lea rdi, [rax + linnea_quic_conn.odcid]
    lea rsi, [linnea_quic_rxbuf + 6]
    rep movsb
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
    ; anti-amplification (RFC 9000 s8.1): credit 3x the bytes just received. Until
    ; the peer proves it is really at this address (by producing a Handshake
    ; packet, in .do_cfin below), we may send it no more than this, so a spoofed
    ; Initial cannot turn us into a reflector. Once validated the budget is moot.
    mov rax, [cur_conn]
    cmp qword [rax + linnea_quic_conn.amp_valid], 0
    jne .amp_credited
    lea rcx, [r13 + r13*2]                       ; 3 * datagram length
    add [rax + linnea_quic_conn.amp_credit], rcx
.amp_credited:
    ; A long-header packet on a connection that has already sent its flight is a
    ; retransmitted Initial (the client re-sent it before our flight's ACK
    ; reached it) or its Handshake flight. Rebuilding here would derive fresh
    ; keys and shatter the handshake in progress, so hand it to the Handshake
    ; walk (which may find the client Finished) rather than the ClientHello path.
    mov rcx, [cur_conn]
    cmp qword [rcx + linnea_quic_conn.state], LINNEA_QUIC_ST_NEW
    jne .try_handshake

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
    ; ClientHello CRYPTO fragment from this Initial
    lea rdi, [linnea_quic_rxbuf]
    mov rsi, r13
    lea rdx, [plaintext]
    call linnea_quic_recv_initial    ; rax=frag, rdx=len, r8=offset, r9=pn
    test rax, rax
    jz .try_handshake                ; no ClientHello CRYPTO — maybe the Finished
    ; fold the fragment into the connection's reassembly buffer; a ClientHello too
    ; large for one Initial completes only once its later packets arrive.
    call .ch_reassemble              ; rax = 1 if the ClientHello is now whole
    test rax, rax
    jz .done                         ; still partial: wait for the next Initial
    ; parse the reassembled ClientHello
    mov rcx, [cur_conn]
    lea rax, [rcx + linnea_quic_conn.ch_buf]
    mov [s_ch_ptr], rax
    mov rdx, [rcx + linnea_quic_conn.ch_total]
    mov [s_ch_len], rdx
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [ch_out]
    call linnea_quic_ch_parse
    ; A ClientHello with no usable x25519 key_share cannot key the ECDHE. Never
    ; hand a null share to x25519 (it would dereference address 0 and crash the
    ; worker); drop the datagram and reclaim the slot. This is the one client we
    ; cannot serve — every browser and QUIC library offers x25519.
    cmp qword [ch_out + linnea_quic_ch.ks_ptr], 0
    jne .ks_ok
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.ks_ok:
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
    ; SNI hash, computed once: it seeds any ticket we issue and (on a resumption
    ; offer) checks the presented ticket's server_name binding.
    mov rdi, [ch_out + linnea_quic_ch.sni_ptr]
    mov rsi, [ch_out + linnea_quic_ch.sni_len]
    lea rdx, [q_sni32]
    call linnea_sha256
    mov rax, [q_sni32]
    mov rbx, [cur_conn]
    mov [rbx + linnea_quic_conn.sni_hash], rax
    ; the client's flow-control allowance for a response stream, from its
    ; transport parameters: what it will accept on a connection (initial_max_data)
    ; and on one stream it opened (initial_max_stream_data_bidi_local). The lower
    ; bounds any chunked response; absent parameters mean zero (RFC 9000 18.2),
    ; so such a client is never sent a multi-packet body.
    mov qword [rbx + linnea_quic_conn.tx_limit], 0
    mov rdi, [ch_out + linnea_quic_ch.tp_ptr]
    test rdi, rdi
    jz .tp_recorded
    mov rsi, [ch_out + linnea_quic_ch.tp_len]
    call linnea_quic_tp_parse        ; rax = max_data, rdx = max_stream_data
    cmp rax, rdx
    cmovbe rdx, rax                  ; the smaller window governs
    mov rbx, [cur_conn]
    mov [rbx + linnea_quic_conn.tx_limit], rdx
.tp_recorded:
    ; --- session resumption: accept the client's PSK offer if it is well-formed
    ; (psk_dhe_ke, our ticket, matching SNI, verifying binder). linnea_quic_hs_psk
    ; then drives the ServerHello's pre_shared_key extension, the early secret in
    ; hs_secrets, and the EE-only flight below; 0 means a full handshake.
    mov qword [linnea_quic_hs_psk], 0
    mov qword [linnea_quic_early_ok], 0
    mov rbx, [cur_conn]
    mov qword [rbx + linnea_quic_conn.early_len], 0
    mov rdi, [ch_out + linnea_quic_ch.psk_id_ptr]
    test rdi, rdi
    jz .no_resume
    cmp qword [ch_out + linnea_quic_ch.psk_dhe_ke], 0
    je .no_resume
    cmp qword [ch_out + linnea_quic_ch.psk_binder_ptr], 0
    je .no_resume
    mov esi, [ch_out + linnea_quic_ch.psk_id_len]
    mov rdx, [s_ch_ptr]                       ; truncated-CH base
    mov rcx, [ch_out + linnea_quic_ch.psk_binders_pos]
    sub rcx, rdx                              ; truncated-CH length
    mov r8, [ch_out + linnea_quic_ch.psk_binder_ptr]
    lea r9, [q_sni32]                         ; current SNI hash
    sub rsp, 16
    lea rax, [s_resume_psk]
    mov [rsp], rax
    call linnea_quic_ticket_resume
    add rsp, 16
    test rax, rax
    jz .no_resume
    lea rax, [s_resume_psk]
    mov [linnea_quic_hs_psk], rax             ; resumed: seed the key schedule
    ; accept 0-RTT if the client also offered early_data. First defend against
    ; replay (RFC 9001 9.2): only within a freshness window (so the strike register
    ; need remember a binder for a bounded time), and reject a binder seen before.
    ; A rejection here still resumes — just without early data (1-RTT).
    cmp qword [ch_out + linnea_quic_ch.early_data], 0
    je .no_resume
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    xor edi, edi                             ; CLOCK_REALTIME
    lea rsi, [q_nst_ts]
    syscall
    mov rax, [q_nst_ts]                       ; now (seconds)
    mov [s_now_sec], rax
    sub rax, [linnea_quic_resume_issued]      ; ticket age
    cmp rax, LINNEA_QUIC_REPLAY_WINDOW
    ja .no_resume                             ; too old for 0-RTT (underflow -> huge -> reject)
    mov rdi, [ch_out + linnea_quic_ch.psk_binder_ptr]
    mov esi, [s_now_sec]
    call linnea_quic_replay_check
    test rax, rax
    jz .no_resume                             ; replayed binder or register full
    mov qword [linnea_quic_early_ok], 1
.no_resume:
    ; fresh ephemeral key + ServerHello random for this handshake. server_priv
    ; and server_srand are adjacent in .bss (32 bytes each), so two getrandom32
    ; calls refill both; a constant key_share would break forward secrecy.
    lea rdi, [server_priv]
    call .getrandom32
    lea rdi, [server_srand]
    call .getrandom32
    ; server ephemeral public + ServerHello
    lea rdi, [server_pub]
    lea rsi, [server_priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    lea rdi, [sh_buf]
    lea rsi, [server_pub]
    lea rdx, [server_srand]
    call linnea_quic_build_sh
    mov [s_sh_len], rax              ; 90 for a fresh handshake
    ; resumption: the ServerHello carries pre_shared_key with selected_identity 0,
    ; appended after supported_versions (RFC 8446 4.2.11). Grows the SH to 96.
    cmp qword [linnea_quic_hs_psk], 0
    je .sh_ready
    mov word [sh_buf + 90], 0x2900   ; pre_shared_key (0x0029)
    mov word [sh_buf + 92], 0x0200   ; ext length 2
    mov word [sh_buf + 94], 0x0000   ; selected_identity 0
    mov word [sh_buf + 42], 0x3400   ; extensions length 52 (was 46)
    mov byte [sh_buf + 3], 92        ; handshake length 92 (was 86)
    mov qword [s_sh_len], 96
.sh_ready:

    ; ===== Initial packet: ACK + CRYPTO(ServerHello) =====
    ; ACK the client's Initials: Largest Acknowledged and First ACK Range both the
    ; largest Initial packet number we received (they are 0..N contiguous — we
    ; needed every fragment). A single-packet ClientHello leaves this at 0. The
    ; number is tiny (one Initial per ClientHello fragment), so each varint is one
    ; byte and the ACK frame stays five bytes.
    mov byte [payload], 0x02
    mov dword [payload + 1], 0
    mov rax, [cur_conn]
    movzx ecx, byte [rax + linnea_quic_conn.ch_maxpn]
    mov [payload + 1], cl            ; Largest Acknowledged
    mov [payload + 4], cl            ; First ACK Range (covers 0..largest)
    mov byte [payload + 5], 0x06
    mov byte [payload + 6], 0x00
    mov eax, [s_sh_len]              ; CRYPTO length varint (2-byte: 0x4000 | len)
    shl eax, 8
    or eax, 0x40
    mov [payload + 7], ax
    lea rdi, [payload + 9]
    lea rsi, [sh_buf]
    mov ecx, [s_sh_len]
    rep movsb                        ; payload length = 9 + SH
    call .build_initial_header       ; -> rcx = header length (uses s_cscid_*)
    sub rsp, 16
    CONNLEA rax, ini_server
    mov [rsp], rax
    lea rdi, [outpkt]
    lea rsi, [hdr]
    mov rdx, rcx
    mov ecx, 1
    lea r8, [payload]
    mov r9d, [s_sh_len]
    add r9d, 9                        ; ACK(5) + CRYPTO header(4) + SH
    call linnea_quic_protect         ; rax = Initial packet length
    add rsp, 16
    mov [s_ini_len], rax

    ; ===== handshake keys and messages =====
    ; th = H(CH || SH)
    lea rsi, [sh_buf]
    mov edx, [s_sh_len]
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
    mov rcx, [cur_conn]
    mov [rcx + linnea_quic_conn.flight_ee_len], r14   ; Certificate follows EE
    ; resumption authenticates via the PSK, so the flight is EE || Finished — no
    ; Certificate, no CertificateVerify (RFC 8446 2.2). The tiny flight always fits
    ; the anti-amplification budget, so it never needs the cert-recompose resume path.
    cmp qword [linnea_quic_hs_psk], 0
    jne .flight_resumed
    lea rdi, [hsmsg + r14]
    mov rsi, [s_cert_list_ptr]
    mov rdx, [s_cert_len]
    call linnea_quic_build_cert
    add r14, rax
    ; th_cert = H(CH || SH || hsmsg[0..r14])
    lea rsi, [hsmsg]
    mov rdx, r14
    call .transcript
    mov [s_cv_off], r14              ; CertVerify starts here
    lea rdi, [hsmsg + r14]
    lea rsi, [th_buf]
    mov rdx, [s_priv]
    call linnea_quic_build_cert_verify
    mov rcx, [cur_conn]
    mov [rcx + linnea_quic_conn.flight_cv_len], rax   ; randomized: must be kept
    add r14, rax
    ; th_cv = H(CH || SH || hsmsg[0..r14])
    lea rsi, [hsmsg]
    mov rdx, r14
    call .transcript
    jmp .flight_finished
.flight_resumed:
    mov qword [rcx + linnea_quic_conn.flight_cv_len], 0
    ; th = H(CH || SH || EE)
    lea rsi, [hsmsg]
    mov rdx, r14
    call .transcript
.flight_finished:
    mov [s_fin_off], r14             ; Finished starts here
    lea rdi, [hsmsg + r14]
    CONNLEA rsi, hs_sec
    add rsi, 32                      ; s_hs traffic secret
    lea rdx, [th_buf]
    call linnea_quic_build_finished
    add r14, rax
    mov [s_hsmsg_len], r14

    ; ===== stage the handshake flight and send it under the amp budget =====
    ; hsmsg[0..s_hsmsg_len] is the handshake (EE || Cert || CertVerify ||
    ; Finished). .send_flight releases it in <=MTU Handshake packets up to what the
    ; budget allows; the tail waits for the client's address to be validated. Only
    ; the small per-connection edge is kept for that resume — the big Certificate
    ; is re-framed from the shared list in .recompose_flight, not stored per-conn.
    mov rbx, [cur_conn]
    lea rdi, [rbx + linnea_quic_conn.flight_tail]
    lea rsi, [hsmsg]                                  ; EncryptedExtensions
    mov rcx, [rbx + linnea_quic_conn.flight_ee_len]
    rep movsb                                         ; -> flight_tail + ee_len
    mov rsi, [s_cv_off]                               ; CertVerify
    lea rsi, [hsmsg + rsi]
    mov rcx, [rbx + linnea_quic_conn.flight_cv_len]
    rep movsb                                         ; -> flight_tail + ee_len + cv_len
    mov rsi, [s_fin_off]                              ; Finished (36 bytes)
    lea rsi, [hsmsg + rsi]
    mov ecx, 36
    rep movsb
    mov [rbx + linnea_quic_conn.flight_len], r14
    mov qword [rbx + linnea_quic_conn.flight_off], 0
    mov qword [rbx + linnea_quic_conn.flight_pn], 0
    call .send_flight                                 ; hsmsg is still the built flight
    ; save the transcript through the server Finished; the client's Finished
    ; MAC covers exactly this (H(CH || SH || EE || Cert || CertVerify || Fin)).
    lea rsi, [hsmsg]
    mov rdx, [s_hsmsg_len]
    call .transcript
    lea rsi, [th_buf]
    CONNLEA rdi, th_cfin
    mov ecx, 32
    rep movsb
    ; --- resumption: derive the ticket PSK now, while the transcript scratch is
    ; still fresh. The client's Finished is deterministic (HMAC(finished_key(c_hs),
    ; th_cfin)) so we build the same message, extend the transcript through it, and
    ; derive the resumption PSK. The NewSessionTicket that carries it goes out at
    ; handshake completion — a later datagram, by when sh_buf/hsmsg are overwritten,
    ; so the PSK (and the SNI hash binding the ticket) are stashed in the connection.
    mov rbx, [cur_conn]
    lea rdi, [expfin]                     ; expected client Finished (36 bytes)
    lea rsi, [rbx + linnea_quic_conn.hs_sec]           ; c_hs (offset 0)
    lea rdx, [rbx + linnea_quic_conn.th_cfin]
    call linnea_quic_build_finished
    lea rdi, [shactx]                     ; th_cfin_client = H(CH||SH||EE..Fin||cFin)
    call linnea_sha256_init
    lea rdi, [shactx]
    mov rsi, [s_ch_ptr]
    mov rdx, [s_ch_len]
    call linnea_sha256_update
    lea rdi, [shactx]
    lea rsi, [sh_buf]
    mov edx, [s_sh_len]
    call linnea_sha256_update
    lea rdi, [shactx]
    lea rsi, [hsmsg]
    mov rdx, [s_hsmsg_len]
    call linnea_sha256_update
    lea rdi, [shactx]
    lea rsi, [expfin]
    mov edx, 36
    call linnea_sha256_update
    lea rdi, [shactx]
    lea rsi, [th_buf]
    call linnea_sha256_final
    mov rbx, [cur_conn]
    lea rdi, [rbx + linnea_quic_conn.hs_sec]
    add rdi, 64                           ; handshake_secret
    lea rsi, [th_buf]
    lea rdx, [rbx + linnea_quic_conn.resumption_psk]
    call linnea_quic_resumption_psk       ; conn.sni_hash was set at CH time
    ; --- 0-RTT: if we accepted early data, derive the 0-RTT keys and decrypt the
    ; client's early request (coalesced with the ClientHello) so it can be served
    ; once the 1-RTT keys are up. Do this last — it reuses plaintext for the 0-RTT
    ; payload, and the ClientHello (still in plaintext) is no longer needed.
    cmp qword [linnea_quic_early_ok], 0
    je .early_done
    ; H(ClientHello) -> th_buf, then the 0-RTT keys from the recovered PSK
    mov rdi, [s_ch_ptr]
    mov rsi, [s_ch_len]
    lea rdx, [th_buf]
    call linnea_sha256
    lea rdi, [s_resume_psk]
    lea rsi, [th_buf]
    mov rbx, [cur_conn]
    lea rdx, [rbx + linnea_quic_conn.zrtt_ckeys]
    call linnea_quic_early_keys
    ; walk the datagram for the coalesced 0-RTT packet (long header, type 0x10)
    mov r13, [s_dgram_len]           ; r13 may have been clobbered building the flight
    lea r15, [linnea_quic_rxbuf]
.ew_loop:
    lea rax, [linnea_quic_rxbuf + r13]
    cmp r15, rax
    jae .early_done                  ; no 0-RTT packet in this datagram
    test byte [r15], 0x80
    jz .early_done                   ; short header — stop
    movzx eax, byte [r15]
    and al, 0x30
    mov r10d, eax                    ; 0x00 Initial, 0x10 0-RTT
    cmp r10d, 0x10
    je .ew_zrtt
    ; skip this long-header packet (an Initial ahead of the 0-RTT one)
    movzx eax, byte [r15 + 5]        ; DCID length
    lea rdi, [r15 + 6 + rax]
    movzx eax, byte [rdi]            ; SCID length
    lea rdi, [rdi + 1 + rax]         ; -> token length (Initial) / length
    lea rsi, [linnea_quic_rxbuf + r13]
    test r10d, r10d
    jnz .ew_len                      ; only an Initial carries a token
    call linnea_quic_varint_decode
    add rdi, rdx
    add rdi, rax                     ; skip the token
.ew_len:
    call linnea_quic_varint_decode   ; length (pn + payload + tag)
    lea rdi, [rdi + rdx]
    add rdi, rax
    mov r15, rdi
    jmp .ew_loop
.ew_zrtt:
    ; a 0-RTT packet: unprotect it with the early keys (long header, no token, so
    ; the Handshake-packet path applies) and buffer its frames for completion.
    mov rdi, r15
    lea rsi, [linnea_quic_rxbuf + r13]
    sub rsi, r15
    mov rbx, [cur_conn]
    lea rdx, [rbx + linnea_quic_conn.zrtt_ckeys]
    lea rcx, [plaintext]
    call linnea_quic_unprotect_hs    ; rax = frame bytes
    test rax, rax
    js .early_done
    cmp rax, LINNEA_QUIC_EARLY_BUF
    ja .early_done                   ; oversized early data: drop it (served fresh)
    mov rbx, [cur_conn]
    mov [rbx + linnea_quic_conn.early_len], rax
    lea rdi, [rbx + linnea_quic_conn.early_buf]
    lea rsi, [plaintext]
    mov rcx, rax
    rep movsb
.early_done:
    ; the flight is out: leave ST_NEW so a retransmitted ClientHello is recognized
    ; as a duplicate (above) rather than rebuilding the flight with fresh keys.
    mov rax, [cur_conn]
    mov qword [rax + linnea_quic_conn.state], LINNEA_QUIC_ST_HANDSHAKE
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
    ; a Handshake packet at [r15]: unprotect with the client handshake keys. Save
    ; where the next coalesced packet starts first — a datagram can carry an ACK
    ; and the Finished as two separate Handshake packets, so if this one holds no
    ; Finished we keep walking rather than give up (which stalled the handshake).
    mov [s_walk_next], rdi
    mov rdi, r15
    lea rsi, [linnea_quic_rxbuf + r13]
    sub rsi, r15                     ; bytes from here to the datagram end
    CONNLEA rdx, hs_ckeys
    lea rcx, [plaintext]
    call linnea_quic_unprotect_hs
    test rax, rax
    js .done
    ; a Handshake packet that decrypts means the peer holds the handshake keys,
    ; which it could only derive from our flight: its address is validated. On the
    ; first such packet, mark it and release any flight the amp budget held back
    ; (the client's ACK arrives here before it can send its Finished).
    mov rcx, [cur_conn]
    cmp qword [rcx + linnea_quic_conn.amp_valid], 0
    jne .cfin_finished               ; already validated/resumed on an earlier packet
    sub rsp, 16                      ; keep 16-aligned; save the CRYPTO-frame length
    mov [rsp], rax
    mov qword [rcx + linnea_quic_conn.amp_valid], 1
    ; only rebuild and release a flight the budget actually held back. A resumed
    ; handshake's flight (EE || Finished, no cert) always fit and was sent whole, so
    ; there is nothing to resume — and .recompose_flight assumes a certificate.
    mov rax, [rcx + linnea_quic_conn.flight_off]
    cmp rax, [rcx + linnea_quic_conn.flight_len]
    jae .cfin_sent
    call .recompose_flight           ; hsmsg is stale between datagrams; rebuild it
    call .send_flight
.cfin_sent:
    mov rax, [rsp]
    add rsp, 16
.cfin_finished:
    lea rdi, [plaintext]
    mov rsi, rax
    call linnea_quic_crypto_frame    ; skips the ACK, returns the Finished
    test rax, rax
    jz .cfin_next                    ; no Finished in this packet — try the next
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
    ; append a NewSessionTicket (post-handshake CRYPTO frame, RFC 9001 4.1.3) so
    ; the client can resume and, once 0-RTT lands, send early data next time.
    mov [s_pay_len], rcx
    lea rdi, [onertt_pay + rcx]
    call .append_nst                 ; rax = CRYPTO(NST) frame length
    mov rcx, [s_pay_len]
    add rcx, rax
    lea rsi, [onertt_pay]
    mov rdx, rcx                     ; total payload length
    call .send_1rtt
    ; announce it
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [cfin_marker]
    mov edx, cfin_marker_len
    syscall
    ; 0-RTT: now that the 1-RTT keys are up, serve any early request the client
    ; sent before the handshake completed. Its frames were buffered at CH time;
    ; replay them through the ordinary stream path (the response rides 1-RTT).
    mov rbx, [cur_conn]
    mov rax, [rbx + linnea_quic_conn.early_len]
    test rax, rax
    jz .done
    mov qword [rbx + linnea_quic_conn.early_len], 0   ; serve once
    lea rsi, [rbx + linnea_quic_conn.early_buf]
    lea rdi, [plaintext]
    mov rcx, rax
    rep movsb
    lea r15, [plaintext + rax]       ; frames end
    lea r14, [plaintext]             ; scan cursor
    jmp .stream_scan
    ; (.stream_scan serves the request(s) and jmps .done)

; --- 1-RTT (short-header) packet: HTTP/3 requests on QUIC streams ---
; One packet can carry several STREAM frames (requests on different streams),
; so walk them all and answer each on the stream it arrived on.
.onertt_in:
    ; the next packet number expected from the peer (largest received + 1, 0
    ; before anything arrives): the wire carries only the number's low bits,
    ; and unprotect expands them against this before forming the nonce
    mov rax, [cur_conn]
    xor r9d, r9d
    cmp qword [rax + linnea_quic_conn.rx_have], 0
    je .exp_pn_ready
    mov r9, [rax + linnea_quic_conn.rx_largest]
    inc r9
.exp_pn_ready:
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
    ; an open response stream is ack-clocked: the acknowledgements just ingested
    ; freed ring slots, so more chunks may go out (and a fully acknowledged
    ; stream is closed out — its mapping released)
    mov rax, [cur_conn]
    cmp qword [rax + linnea_quic_conn.tx_active], 0
    je .no_pump
    call tx_pump
.no_pump:
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
    mov [s_sfin], r11                ; FIN flag, for the critical-stream check
    mov rax, r8
    and eax, 3
    jz .client_bidi                  ; client bidi stream: an HTTP/3 request
    cmp eax, 2
    je .client_uni                   ; client uni stream: control / QPACK
    jmp .stream_scan                 ; a server-initiated id (never from a client)

; --- a client bidirectional stream: an HTTP/3 request ---
; A whole request in one STREAM frame (offset 0 with FIN) takes a copy-free fast
; path and is served straight from the packet. Anything else — a request whose
; frames span several packets — is reassembled in the connection's buffer, in
; offset order, and served only once the stream is complete.
.client_bidi:
    mov rax, [cur_conn]
    cmp qword [rax + linnea_quic_conn.ra_active], 0
    je .cb_fresh
    mov rdx, [rax + linnea_quic_conn.ra_sid]
    cmp rdx, [s_sid]
    je .ra_route                     ; a frame continuing this stream's reassembly
.cb_fresh:
    cmp qword [s_soff], 0
    jne .ra_route                    ; not at offset 0: earlier bytes came elsewhere
    cmp qword [s_sfin], 0
    je .ra_route                     ; no FIN: more frames follow
    jmp .serve_bidi                  ; the whole request is here: serve it directly

; reassemble the request stream into ra_buf, appending each frame at its offset.
.ra_route:
    mov rax, [cur_conn]
    cmp qword [rax + linnea_quic_conn.ra_active], 0
    je .ra_start
    mov rdx, [rax + linnea_quic_conn.ra_sid]
    cmp rdx, [s_sid]
    je .ra_have
    jmp .stream_scan                 ; another stream is mid-reassembly: one at a time
.ra_start:
    mov qword [rax + linnea_quic_conn.ra_active], 1
    mov rdx, [s_sid]
    mov [rax + linnea_quic_conn.ra_sid], rdx
    mov qword [rax + linnea_quic_conn.ra_len], 0
    mov qword [rax + linnea_quic_conn.ra_fin], 0
    ; clear the seen-map up to the previous run's high-water, then reset it
    mov rcx, [rax + linnea_quic_conn.ra_hi]
    lea rdi, [rax + linnea_quic_conn.ra_seen]
    xor al, al
    rep stosb
    mov rax, [cur_conn]
    mov qword [rax + linnea_quic_conn.ra_hi], 0
.ra_have:
    ; place the frame at its offset (out-of-order frames are buffered, not
    ; dropped) and record the bytes as seen; the contiguous prefix advances below.
    mov r9, [s_soff]                           ; offset
    mov r10, [s_slen]                          ; length
    mov r11, r9
    add r11, r10                               ; frame end = offset + len
    cmp r11, LINNEA_QUIC_RA_BUF
    ja .ra_drop                                ; past the buffer: request too large
    test r10, r10
    jz .ra_hi_upd                              ; empty frame (e.g. a lone FIN)
    lea rdi, [rax + linnea_quic_conn.ra_buf]
    add rdi, r9                                ; dest = ra_buf + offset
    mov rsi, [s_sdata]
    mov rcx, r10
    rep movsb                                  ; copy the frame's bytes
    lea rdi, [rax + linnea_quic_conn.ra_seen]
    add rdi, r9                                ; ra_seen + offset
    mov rcx, r10
    mov al, 1
    rep stosb                                  ; mark those bytes seen
    mov rax, [cur_conn]                        ; stosb wrote al; restore cur_conn
.ra_hi_upd:
    mov r10, [rax + linnea_quic_conn.ra_hi]
    cmp r11, r10
    jbe .ra_advance
    mov [rax + linnea_quic_conn.ra_hi], r11
    mov r10, r11                               ; r10 = ra_hi
.ra_advance:
    ; advance the contiguous prefix while the next byte has been seen
    mov r8, [rax + linnea_quic_conn.ra_len]
    lea rdi, [rax + linnea_quic_conn.ra_seen]
.ra_adv_loop:
    cmp r8, r10                                ; reached the high-water?
    jae .ra_adv_done
    cmp byte [rdi + r8], 0
    je .ra_adv_done                            ; a gap: stop here
    inc r8
    jmp .ra_adv_loop
.ra_adv_done:
    mov [rax + linnea_quic_conn.ra_len], r8
    cmp qword [s_sfin], 0
    je .ra_donecheck
    mov qword [rax + linnea_quic_conn.ra_fin], 1
    mov r10, [s_soff]
    add r10, [s_slen]
    mov [rax + linnea_quic_conn.ra_final], r10
.ra_donecheck:
    cmp qword [rax + linnea_quic_conn.ra_fin], 0
    je .ra_more
    mov r10, [rax + linnea_quic_conn.ra_len]
    cmp r10, [rax + linnea_quic_conn.ra_final]
    jb .ra_more                                ; a gap remains before the end
    ; complete: serve the reassembled request from ra_buf
    lea r10, [rax + linnea_quic_conn.ra_buf]
    mov [s_sdata], r10
    mov r10, [rax + linnea_quic_conn.ra_len]
    mov [s_slen], r10
    mov qword [rax + linnea_quic_conn.ra_active], 0
    jmp .serve_bidi
.ra_drop:
    mov qword [rax + linnea_quic_conn.ra_active], 0  ; too large: abandon the stream
    jmp .stream_scan                           ; do not ack data we cannot buffer
.ra_more:
    ; This packet was buffered without a reply, so nothing else acknowledges it.
    ; Send a bare ACK so the peer keeps sending the rest of the request rather
    ; than retransmitting what we already hold (emit_1rtt: an ACK is not tracked).
    lea rdi, [strm_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack
    test rax, rax
    jz .stream_scan
    lea rsi, [strm_pay]
    mov [s_pl_ptr], rsi
    mov [s_pl_len], rax
    call emit_1rtt
    jmp .stream_scan                           ; waiting for more frames
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
    call linnea_h3_read_headers      ; r8 = body ptr, r9 = body len on success
    test rax, rax
    jnz .stream_scan                 ; not a complete request on this stream
    mov [s_body_ptr], r8             ; keep the body across the response build
    mov [s_body_len], r9
    ; record it for a graceful GOAWAY: a drain rejects streams past this one, so
    ; the client knows exactly what it must retry elsewhere
    mov rax, [cur_conn]
    mov rdx, [s_sid]
    add rdx, 4                       ; the next client bidi stream id
    cmp rdx, [rax + linnea_quic_conn.h3_goaway_id]
    jbe .no_goaway_bump
    mov [rax + linnea_quic_conn.h3_goaway_id], rdx
.no_goaway_bump:
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
    mov r8, [s_body_ptr]             ; the request body, for a POST echo
    mov r9, [s_body_len]
    ; the client's allowance for a chunked response: zero while one is already
    ; in flight (one response stream at a time — a concurrent large request is
    ; refused with a 503 and can be retried), else what its transport
    ; parameters permit
    mov rax, [cur_conn]
    mov r11, [rax + linnea_quic_conn.tx_limit]
    cmp qword [rax + linnea_quic_conn.tx_active], 0
    je .tx_cap_set
    xor r11d, r11d
.tx_cap_set:
    mov [linnea_h3_tx_cap], r11
    call linnea_h3_serve             ; rax = h3 response length (or the head's);
                                     ; r9 != 0: chunked — r8/r9 = file mapping
    test r9, r9
    jnz .serve_large
    lea rdx, [rax + rbx]             ; STREAM frame length
    lea rsi, [strm_pay]
    call .send_1rtt
    jmp .stream_scan
.serve_large:
    ; the response is a stream, not a packet: keep its head and the file
    ; mapping on the connection and let the pump send it — chunk by chunk,
    ; ack-clocked by the loss ring. The head (HEADERS frame + DATA frame
    ; header, rax bytes at strm_pay + rbx) is bounded by LINNEA_H3_HEAD_MAX,
    ; which fits tx_hdr by construction.
    mov rcx, [cur_conn]
    mov [rcx + linnea_quic_conn.tx_base], r8
    mov [rcx + linnea_quic_conn.tx_size], r9
    mov [rcx + linnea_quic_conn.tx_hlen], rax
    mov rdx, [s_sid]
    mov [rcx + linnea_quic_conn.tx_sid], rdx
    mov qword [rcx + linnea_quic_conn.tx_off], 0
    mov qword [rcx + linnea_quic_conn.tx_active], 1
    lea rsi, [strm_pay + rbx]
    lea rdi, [rcx + linnea_quic_conn.tx_hdr]
    mov rcx, rax
    rep movsb
    call tx_pump
    jmp .stream_scan

; --- a client unidirectional stream: control, QPACK encoder/decoder or grease.
; A stream's type is the first varint, present only at offset 0, so a later frame
; (offset > 0) is a continuation we do not re-type. RFC 9114 6.2.1 / RFC 9204 4.2:
; the control and QPACK streams are critical — none may be closed (a FIN is
; H3_CLOSED_CRITICAL_STREAM), the control stream must open with SETTINGS, and a
; second control stream is H3_STREAM_CREATION_ERROR. Any violation ends the
; connection. QPACK streams otherwise carry nothing we read (zero table), and
; grease/unknown uni streams are ignored.
.client_uni:
    cmp qword [s_soff], 0
    jne .uni_cont                    ; a continuation: the type is already known
    mov rsi, [s_slen]
    test rsi, rsi
    jz .stream_scan                  ; empty first frame: nothing to type yet
    mov rax, [s_sdata]
    movzx ecx, byte [rax]            ; the stream type (1 byte for every h3 type)
    cmp cl, LINNEA_H3_STREAM_CONTROL
    je .uni_control
    cmp cl, LINNEA_H3_STREAM_QPACK_ENC
    je .uni_qpack
    cmp cl, LINNEA_H3_STREAM_QPACK_DEC
    je .uni_qpack
    jmp .stream_scan                 ; grease/unknown: not interpreted
.uni_qpack:
    cmp qword [s_sfin], 0
    jne .uni_critical_closed         ; a QPACK stream must not be closed
    jmp .stream_scan                 ; otherwise nothing to read (zero table)
.uni_cont:
    ; a continuation: only the control stream's closure is our concern here (we
    ; do not track QPACK stream ids, and their bodies carry nothing anyway).
    mov rdx, [cur_conn]
    mov rax, [rdx + linnea_quic_conn.ctrl_id]
    test rax, rax
    jz .stream_scan
    cmp rax, [s_sid]
    jne .stream_scan
    cmp qword [s_sfin], 0
    jne .uni_critical_closed
    jmp .stream_scan
.uni_control:
    ; closing the control stream is a critical-stream error, whatever it carries
    cmp qword [s_sfin], 0
    jne .uni_critical_closed
    ; reject a second control stream on a different id
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
    jmp .h3_close
.uni_critical_closed:
    mov edi, LINNEA_H3_ERR_CLOSED_CRITICAL
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

; .ch_reassemble(rax = CRYPTO fragment ptr, rdx = length, r8 = offset,
;   r9 = Initial packet number) -> rax = 1 once the ClientHello is complete, else
;   0. Folds one Initial's CRYPTO fragment into the connection's ch_buf in offset
; order: a fragment starting past the contiguous end is a gap and is left for the
; client to retransmit (Initial CRYPTO is normally in order). The full size is the
; TLS handshake length in the offset-0 fragment; completion is ch_len >= ch_total.
; The largest Initial packet number is tracked so the ServerHello can acknowledge
; every Initial received, not just packet 0. The connection is [cur_conn].
.ch_reassemble:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, [cur_conn]
    mov r12, rax                     ; fragment ptr
    mov r13, rdx                     ; fragment length
    mov r14, r8                      ; fragment offset
    ; track the largest Initial packet number, for the completion ACK
    cmp r9, [rbx + linnea_quic_conn.ch_maxpn]
    jbe .cr_pn_done
    mov [rbx + linnea_quic_conn.ch_maxpn], r9
.cr_pn_done:
    lea rax, [r14 + r13]             ; fragment end
    cmp rax, LINNEA_QUIC_CH_BUF
    ja .cr_incomplete                ; past the buffer: refuse (ClientHello too big)
    mov r15, [rbx + linnea_quic_conn.ch_len]
    cmp r14, r15
    ja .cr_incomplete                ; a gap before this fragment: wait for the filler
    test r13, r13
    jz .cr_extent                    ; empty fragment
    lea rdi, [rbx + linnea_quic_conn.ch_buf]
    add rdi, r14                     ; ch_buf + offset
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov rbx, [cur_conn]              ; rep movsb advanced rdi/rsi; rbx is untouched
.cr_extent:
    lea rax, [r14 + r13]             ; fragment end
    cmp rax, r15
    jbe .cr_haslen
    mov [rbx + linnea_quic_conn.ch_len], rax
    mov r15, rax                     ; new contiguous length
.cr_haslen:
    ; learn the full ClientHello size from the offset-0 fragment: the TLS
    ; handshake header is type(1) + length(3), so total = 4 + that length.
    cmp qword [rbx + linnea_quic_conn.ch_total], 0
    jne .cr_check
    cmp r15, 4
    jb .cr_incomplete                ; header not fully arrived yet
    lea rsi, [rbx + linnea_quic_conn.ch_buf]
    cmp byte [rsi], 0x01             ; ClientHello handshake type
    jne .cr_incomplete
    movzx eax, byte [rsi + 1]
    shl eax, 8
    movzx ecx, byte [rsi + 2]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [rsi + 3]
    or eax, ecx                      ; 24-bit handshake length
    add rax, 4
    mov [rbx + linnea_quic_conn.ch_total], rax
.cr_check:
    mov rax, [rbx + linnea_quic_conn.ch_total]
    test rax, rax
    jz .cr_incomplete
    cmp r15, rax
    jb .cr_incomplete
    mov eax, 1                        ; ch_len reached ch_total: complete
    jmp .cr_ret
.cr_incomplete:
    xor eax, eax
.cr_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
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

; .send_flight — release Handshake flight chunks from conn.flight_off up to
; conn.flight_len, each in its own <=MTU datagram (the first coalesced behind the
; Initial already staged in outpkt). Before the peer's address is validated it
; stops as soon as the next datagram would breach the amplification budget,
; leaving the tail for a later call once amp_valid is set. Advances flight_off /
; flight_pn and charges amp_credit as it goes. r12d = UDP socket; the connection
; is [cur_conn]. Clobbers caller-saved registers; preserves r13/r14/r15.
.send_flight:
    push r13
    push r14
    push r15
.sf_loop:
    mov r13, [cur_conn]
    mov r14, [r13 + linnea_quic_conn.flight_off]
    mov rcx, [r13 + linnea_quic_conn.flight_len]
    cmp r14, rcx
    jae .sf_done                     ; the whole flight has been sent
    sub rcx, r14                     ; remaining flight bytes
    cmp rcx, LINNEA_QUIC_CRYPTO_CHUNK
    jbe .sf_have
    mov ecx, LINNEA_QUIC_CRYPTO_CHUNK
.sf_have:
    mov [s_hs_chunk], rcx
    ; hspay = CRYPTO(0x06, offset r14, length chunk, hsmsg[r14..r14+chunk])
    mov byte [hspay], 0x06
    lea rdi, [hspay + 1]
    mov rsi, r14
    call linnea_quic_varint_encode   ; rax = offset-varint bytes
    mov r10, rax
    lea rdi, [hspay + 1 + r10]
    mov rsi, [s_hs_chunk]
    call linnea_quic_varint_encode   ; rax = length-varint bytes
    lea rdi, [hspay + 1 + r10]
    add rdi, rax                     ; -> CRYPTO data field
    ; Handshake payload r15 = type(1) + off-varint(r10) + len-varint(rax) + chunk
    lea r15, [r10 + rax]
    add r15, 1
    add r15, [s_hs_chunk]
    lea rsi, [hsmsg + r14]           ; chunk source: the recomposed flight in hsmsg
    mov rcx, [s_hs_chunk]
    rep movsb                        ; copy the chunk into hspay
    call .build_hs_header            ; rcx = header length; uses r15, conn.flight_pn
    sub rsp, 16
    CONNLEA rax, hs_skeys
    mov [rsp], rax
    test r14, r14                    ; the first chunk coalesces behind the Initial
    jnz .sf_alone
    mov rdi, [s_ini_len]
    lea rdi, [outpkt + rdi]
    jmp .sf_protect
.sf_alone:
    lea rdi, [outpkt]
.sf_protect:
    lea rsi, [hdr]
    mov rdx, rcx
    mov ecx, 1
    lea r8, [hspay]
    mov r9, r15
    call linnea_quic_protect         ; rax = protected packet length
    add rsp, 16
    test r14, r14                    ; datagram = Initial + packet for the first chunk
    jnz .sf_dglen
    add rax, [s_ini_len]
.sf_dglen:
    mov rdx, rax                     ; datagram length
    ; amplification gate: while unvalidated, never send past the 3x credit
    mov rcx, [cur_conn]
    cmp qword [rcx + linnea_quic_conn.amp_valid], 0
    jne .sf_send
    cmp [rcx + linnea_quic_conn.amp_credit], rdx
    jb .sf_done                      ; would breach the budget: hold the tail
.sf_send:
    mov eax, SYS_SENDTO
    mov edi, r12d
    lea rsi, [outpkt]
    xor r10d, r10d
    CONNLEA r8, peer
    CONNGET r9, peer_len
    syscall
    ; charge the datagram against the budget while still unvalidated
    mov rcx, [cur_conn]
    cmp qword [rcx + linnea_quic_conn.amp_valid], 0
    jne .sf_advance
    sub [rcx + linnea_quic_conn.amp_credit], rdx
.sf_advance:
    mov rcx, [cur_conn]
    mov rax, [s_hs_chunk]
    add [rcx + linnea_quic_conn.flight_off], rax
    inc qword [rcx + linnea_quic_conn.flight_pn]
    jmp .sf_loop
.sf_done:
    pop r15
    pop r14
    pop r13
    ret

; .recompose_flight — rebuild hsmsg = EE || Certificate || CertVerify || Finished
; from the per-connection tail and the shared certificate list. hsmsg is shared
; scratch, clobbered between datagrams, so before a resumed .send_flight can chunk
; it the flight has to be reassembled. build_cert is deterministic, so this is
; byte-identical to the original flight — the resumed chunks line up with the
; offsets the client already holds. The connection is [cur_conn].
.recompose_flight:
    ; EncryptedExtensions -> hsmsg[0]
    mov rax, [cur_conn]
    lea rsi, [rax + linnea_quic_conn.flight_tail]
    lea rdi, [hsmsg]
    mov rcx, [rax + linnea_quic_conn.flight_ee_len]
    rep movsb
    ; Certificate -> hsmsg[ee_len], re-framed from the shared list
    mov rax, [cur_conn]
    mov rdx, [rax + linnea_quic_conn.flight_ee_len]
    lea rdi, [hsmsg + rdx]
    mov rsi, [s_cert_list_ptr]
    mov rdx, [s_cert_len]
    call linnea_quic_build_cert       ; rax = Certificate message length
    ; CertVerify || Finished -> hsmsg[ee_len + cert_len], from the tail after EE
    mov rcx, [cur_conn]
    mov rdx, [rcx + linnea_quic_conn.flight_ee_len]
    add rdx, rax                      ; ee_len + cert_len
    lea rdi, [hsmsg + rdx]
    lea rsi, [rcx + linnea_quic_conn.flight_tail]
    add rsi, [rcx + linnea_quic_conn.flight_ee_len]
    mov rdx, [rcx + linnea_quic_conn.flight_cv_len]
    add rdx, 36                       ; CertVerify + Finished
    mov rcx, rdx
    rep movsb
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
    ; length varint = pn(1) + payload(9 + SH) + tag(16) = 26 + SH; a 2-byte varint
    mov eax, [s_sh_len]
    add eax, 26
    mov edx, eax
    shr edx, 8
    or edx, 0x40
    mov [rdi + 1], dl                ; 0x40 | (len >> 8)
    mov [rdi + 2], al                ; len & 0xff
    mov byte [rdi + 3], 0x00         ; packet number 0
    lea rcx, [rdi + 4]
    lea rax, [hdr]
    sub rcx, rax                     ; header length
    ret

; .build_hs_header -> rcx = header length; type Handshake, no token; the length
; field = pn(1)+r15(payload)+tag(16). The 1-byte packet number is conn.flight_pn
; (a flight never spans more than a handful of packets, so it never exceeds 0xff).
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
    mov r8, [cur_conn]
    mov al, [r8 + linnea_quic_conn.flight_pn]
    mov [rdi], al                    ; 1-byte packet number
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
    mov edx, [s_sh_len]
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
.cfin_next:
    mov r15, [s_walk_next]           ; resume the coalesced-packet walk
    jmp .walk
.done:
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .append_nst(rdi=dest) -> rax = bytes written. Seals the connection's resumption
; PSK into a stateless ticket, frames a NewSessionTicket (RFC 8446 4.6.1) carrying
; the QUIC early_data extension (max_early_data_size = 0xffffffff, the value QUIC
; requires — RFC 9001 4.6.1), and wraps it in a CRYPTO frame at offset 0. The
; message is a fixed 103 bytes (ticket 76 + early_data ext 8), so the frame header
; is constant too. The connection is [cur_conn].
.append_nst:
    push rbx
    push r12
    push r14
    mov r14, rdi                     ; dest
    mov rbx, [cur_conn]
    ; ticket plaintext = psk(32) || issued(8) || sni_hash(8)
    lea rdi, [q_nst_pt]
    lea rsi, [rbx + linnea_quic_conn.resumption_psk]
    mov ecx, 32
    rep movsb
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    xor edi, edi                     ; CLOCK_REALTIME
    lea rsi, [q_nst_ts]
    syscall
    mov rax, [q_nst_ts]              ; tv_sec
    mov [q_nst_pt + 32], rax
    mov rax, [rbx + linnea_quic_conn.sni_hash]
    mov [q_nst_pt + 40], rax
    ; ticket = nonce(12) || GCM-seal(plaintext48) -> NST body's ticket field
    lea rdi, [q_nst_pt]
    mov esi, 48
    lea rdx, [q_nst_msg + 17]
    call linnea_quic_ticket_seal     ; writes 76 bytes at q_nst_msg+17
    ; NewSessionTicket message fields
    mov byte [q_nst_msg], 0x04       ; type new_session_ticket
    mov byte [q_nst_msg + 1], 0
    mov word [q_nst_msg + 2], 0x6300 ; body length 99, big-endian
    mov eax, 86400                   ; ticket_lifetime seconds (1 day)
    bswap eax
    mov [q_nst_msg + 4], eax         ; ticket_lifetime, big-endian
    lea rdi, [q_nst_msg + 8]         ; ticket_age_add: 4 random bytes
    mov esi, 4
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    mov byte [q_nst_msg + 12], 2     ; ticket_nonce length
    mov word [q_nst_msg + 13], 0     ; the nonce {0,0}
    mov word [q_nst_msg + 15], 0x4c00   ; ticket length 76, big-endian
    ; ticket bytes already sealed into [17..92]
    mov word [q_nst_msg + 93], 0x0800   ; extensions length 8, big-endian
    mov word [q_nst_msg + 95], 0x2a00   ; extension early_data (0x002a), big-endian
    mov word [q_nst_msg + 97], 0x0400   ; extension length 4, big-endian
    mov dword [q_nst_msg + 99], 0xffffffff  ; max_early_data_size (QUIC: 0xffffffff)
    ; CRYPTO frame: type 0x06, offset varint(0), length varint(103), then the 103
    ; message bytes. 103 needs a 2-byte varint (0x4067).
    mov byte [r14], 0x06
    mov byte [r14 + 1], 0x00         ; offset 0
    mov word [r14 + 2], 0x6740       ; length varint(103) = bytes 0x40, 0x67
    lea rdi, [r14 + 4]
    lea rsi, [q_nst_msg]
    mov ecx, 103
    rep movsb
    mov eax, 107                     ; 4-byte frame header + 103-byte message
    pop r14
    pop r12
    pop rbx
    ret

; .getrandom32(rdi=dest) — fill 32 bytes from getrandom(2), retrying a short
; return. Aborts the process on error: startup entropy is assumed, and serving a
; handshake with a non-random ephemeral key would be worse than refusing it.
.getrandom32:
    push rbx
    push r12
    mov rbx, rdi
    xor r12d, r12d
.gr_loop:
    lea rdi, [rbx + r12]
    mov esi, 32
    sub rsi, r12                     ; bytes still to fill
    xor edx, edx                     ; flags
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    test rax, rax
    jle .gr_fail
    add r12, rax
    cmp r12, 32
    jb .gr_loop
    pop r12
    pop rbx
    ret
.gr_fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

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
    mov byte [hdr], 0x41              ; short header, 2-byte pn, key phase 0
    CONNGET rcx, dcid_len
    lea rdi, [hdr + 1]
    CONNLEA rsi, dcid
    rep movsb                         ; DCID = the peer's connection id
    ; two packet-number bytes: a chunked response spends numbers fast, and one
    ; byte capped a connection near 256 packets before the truncated number
    ; (which is also what the nonce takes) became ambiguous. Two carry 65536.
    CONNGET rax, pn_1rtt
    mov [rdi], ah                     ; packet number, big-endian
    mov [rdi + 1], al
    add rdi, 2
    CONNGET rbx, dcid_len
    add rbx, 3                        ; header length = 1 + DCID + 2
    sub rsp, 16
    CONNLEA rax, ap_skeys
    mov [rsp], rax
    lea rdi, [onertt_pkt]
    lea rsi, [hdr]
    mov rdx, rbx
    mov ecx, 2
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

; tx_emit_chunk(rdi=stream offset, rsi=length) -> rax = packet number used.
; Build and send one packet of the connection's open response stream: a leading
; ACK, then a STREAM frame (OFF always, no LEN — its data runs to the packet's
; end — and FIN on the chunk that ends the stream) whose bytes come from the
; head buffer below tx_hlen and the file mapping above it. Shared by the pump
; (first send) and the PTO sweep (retransmission): the stream bytes at an offset
; never change, so a rebuilt chunk is identical to the lost one.
; cur_conn is the connection, r12d the UDP socket.
tx_emit_chunk:
    push rbx
    push r13
    push r14
    push r15
    sub rsp, 8                        ; align the call sites
    mov rbx, [cur_conn]
    mov r13, rdi                      ; stream offset
    mov r14, rsi                      ; chunk length
    ; lead with the current ACK state — idempotent, and it keeps the peer's
    ; view of what we received fresh throughout a long transfer
    lea rdi, [strm_pay]
    lea rsi, [rbx + linnea_quic_conn.rx_have]
    call linnea_quic_build_ack        ; rax = ACK length (0 = nothing to ack)
    mov r15, rax                      ; write cursor into strm_pay
    ; STREAM frame type
    mov rcx, [rbx + linnea_quic_conn.tx_hlen]
    add rcx, [rbx + linnea_quic_conn.tx_size]   ; the stream's total length
    lea rdx, [r13 + r14]
    mov al, 0x0c                      ; STREAM | OFF
    cmp rdx, rcx
    jne .tc_typed
    or al, 0x01                       ; this chunk ends the stream: FIN
.tc_typed:
    mov [strm_pay + r15], al
    inc r15
    lea rdi, [strm_pay + r15]         ; stream id
    mov rsi, [rbx + linnea_quic_conn.tx_sid]
    call linnea_quic_varint_encode
    add r15, rax
    lea rdi, [strm_pay + r15]         ; stream offset
    mov rsi, r13
    call linnea_quic_varint_encode
    add r15, rax
    ; the chunk's bytes: stream byte i is tx_hdr[i] while i < tx_hlen, then
    ; file byte i - tx_hlen. A chunk can straddle the boundary.
    mov rax, [rbx + linnea_quic_conn.tx_hlen]
    mov rdx, r13                      ; running stream offset
    mov r9, r14                       ; bytes still to place
    cmp rdx, rax
    jae .tc_body
    mov r8, rax
    sub r8, rdx                       ; head bytes from here to tx_hlen
    cmp r8, r9
    jbe .tc_hcopy
    mov r8, r9
.tc_hcopy:
    lea rsi, [rbx + linnea_quic_conn.tx_hdr]
    add rsi, rdx
    lea rdi, [strm_pay + r15]
    mov rcx, r8
    rep movsb
    add r15, r8
    add rdx, r8
    sub r9, r8
.tc_body:
    test r9, r9
    jz .tc_send
    mov rsi, [rbx + linnea_quic_conn.tx_base]
    add rsi, rdx
    sub rsi, rax                      ; file bytes start at stream offset tx_hlen
    lea rdi, [strm_pay + r15]
    mov rcx, r9
    rep movsb
    add r15, r9
.tc_send:
    lea rsi, [strm_pay]
    mov [s_pl_ptr], rsi
    mov [s_pl_len], r15
    call emit_1rtt                    ; rax = the packet number used
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; tx_pump — advance the connection's open response stream: send chunks while
; the loss ring has a free slot to track them (the ring is the send window —
; acknowledgements free slots, so delivery is ack-clocked and the outstanding
; data stays bounded), and close the stream out once everything is sent AND
; acknowledged: unmap the file, tx_active = 0. The pump never sends what it
; cannot track — an untracked chunk would never be retransmitted, leaving a
; permanent hole in the stream. cur_conn is the connection, r12d the socket.
tx_pump:
    push rbx
    push r13
    push r14
    push r15
    sub rsp, 8                        ; align the call sites
    mov rbx, [cur_conn]
.tp_loop:
    cmp qword [rbx + linnea_quic_conn.tx_active], 0
    je .tp_ret
    mov r13, [rbx + linnea_quic_conn.tx_hlen]
    add r13, [rbx + linnea_quic_conn.tx_size]   ; stream total
    mov r14, [rbx + linnea_quic_conn.tx_off]
    cmp r14, r13
    jb .tp_more
    ; everything has been sent; delivered once nothing is still buffered
    mov rdi, rbx
    call linnea_quic_rtx_ref_count
    test rax, rax
    jnz .tp_ret                       ; chunks still awaiting acknowledgement
    mov rdi, [rbx + linnea_quic_conn.tx_base]
    mov rsi, [rbx + linnea_quic_conn.tx_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov qword [rbx + linnea_quic_conn.tx_active], 0
    jmp .tp_ret
.tp_more:
    mov rdi, rbx
    call linnea_quic_rtx_inflight
    cmp rax, LINNEA_QUIC_RTX_SLOTS
    jae .tp_ret                       ; window full: wait for acknowledgements
    mov r15, r13
    sub r15, r14                      ; stream bytes left
    cmp r15, LINNEA_QUIC_TX_CHUNK
    jbe .tp_len
    mov r15, LINNEA_QUIC_TX_CHUNK
.tp_len:
    mov rdi, r14
    mov rsi, r15
    call tx_emit_chunk                ; rax = the packet number it went out under
    mov [s_txc_pn], rax
    call now_ms
    mov r8, rax
    mov rdi, rbx
    mov rsi, [s_txc_pn]
    mov rdx, r14
    mov rcx, r15
    call linnea_quic_rtx_record_ref   ; cannot fail: a slot was free above
    add r14, r15
    mov [rbx + linnea_quic_conn.tx_off], r14
    jmp .tp_loop
.tp_ret:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; tx_abort(rdi=conn) — the response stream cannot continue (its peer stopped
; acknowledging, or the connection is being reclaimed): unmap the file, drop
; every buffered chunk reference — a surviving one would rebuild a chunk from
; memory that is no longer mapped — and close the stream. The peer never sees
; a FIN; an abandoned client re-requests, a vanished one is gone anyway.
tx_abort:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + linnea_quic_conn.tx_active], 0
    je .ta_ret
    mov rdi, [rbx + linnea_quic_conn.tx_base]
    mov rsi, [rbx + linnea_quic_conn.tx_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov qword [rbx + linnea_quic_conn.tx_active], 0
    mov rdi, rbx
    call linnea_quic_rtx_ref_clear
.ta_ret:
    pop rbx
    ret

; quic_tx_free_hook(rdi=conn) — registered as the pool's free hook: any path
; that reclaims a slot (clean close, idle sweep, handshake failure) releases an
; open response stream's mapping through tx_abort first.
quic_tx_free_hook:
    jmp tx_abort

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
    ; given up on. A stream-ref chunk cannot be dropped alone — the stream
    ; would keep a permanent hole — so its whole response is aborted (unmapped,
    ; every buffered chunk dropped); the idle sweep will reclaim the peer.
    cmp qword [r14 + linnea_quic_sent.kind], LINNEA_QUIC_KIND_STREAM_REF
    jne .sw_giveup
    mov rdi, rbx
    call tx_abort
    jmp .sw_rec_next
.sw_giveup:
    mov qword [r14 + linnea_quic_sent.in_use], 0
    jmp .sw_rec_next
.sw_resend:
    mov [cur_conn], rbx
    cmp qword [r14 + linnea_quic_sent.kind], LINNEA_QUIC_KIND_STREAM_REF
    je .sw_ref
    lea rax, [r14 + linnea_quic_sent.payload]
    mov [s_pl_ptr], rax
    mov rax, [r14 + linnea_quic_sent.len]
    mov [s_pl_len], rax
    call emit_1rtt                    ; rax = the fresh packet number; r12d = fd
    jmp .sw_sent
.sw_ref:
    ; rebuild the chunk from the connection's tx state (the stream bytes at an
    ; offset never change) and re-encrypt under a fresh number
    mov rdi, [r14 + linnea_quic_sent.s_off]
    mov rsi, [r14 + linnea_quic_sent.len]
    call tx_emit_chunk                ; rax = the fresh packet number
.sw_sent:
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

; linnea_quic_server_goaway_all(edi = UDP socket fd) — the worker is draining:
; tell every connected h3 peer we are going away with a GOAWAY frame on our
; control stream, so a client opens no new requests before we exit. The frame's
; stream id is the lowest request stream this connection would reject (one past
; the last it served), so the client knows precisely what to retry. Best-effort:
; sent once, not tracked for retransmission — we are about to exit.
linnea_quic_server_goaway_all:
    push rbx
    push r12
    push r13                         ; 3 pushes: the call sites are 16-aligned
    mov r12d, edi                    ; fd
    xor r13d, r13d                   ; connection index
.ga_conn:
    mov edi, r13d
    call linnea_quic_conn_slot       ; rax = conn* or 0
    test rax, rax
    jz .ga_next
    mov rbx, rax
    cmp qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    jne .ga_next                     ; no control stream before the handshake completes
    mov [cur_conn], rbx
    ; a STREAM frame on control stream 3 at offset H3_CTRL_OFF carrying a GOAWAY
    mov byte [goaway_pay], 0x0e      ; STREAM | OFF | LEN (no FIN — critical stream)
    mov byte [goaway_pay + 1], 0x03  ; the server control stream id
    mov byte [goaway_pay + 2], H3_CTRL_OFF
    mov byte [goaway_pay + 4], LINNEA_H3_FRAME_GOAWAY
    lea rdi, [goaway_pay + 6]
    mov rsi, [rbx + linnea_quic_conn.h3_goaway_id]
    call linnea_quic_varint_encode   ; rax = the id's varint length
    mov [goaway_pay + 5], al         ; GOAWAY frame length = the id varint length
    lea rcx, [rax + 2]
    mov [goaway_pay + 3], cl         ; STREAM data length = type(1) + len(1) + id
    lea rdx, [rax + 6]               ; total payload = STREAM header(4) + data
    lea rsi, [goaway_pay]
    mov [s_pl_ptr], rsi
    mov [s_pl_len], rdx
    call emit_1rtt
.ga_next:
    inc r13d
    cmp r13d, LINNEA_QUIC_MAX_CONNS
    jb .ga_conn
    pop r13
    pop r12
    pop rbx
    ret
