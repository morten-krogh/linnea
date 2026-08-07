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
%include "linnea_config.inc"

; A TLS virtual host reachable over HTTP/3: the ClientHello's SNI selects one, and
; the handshake serves its certificate, signs CertVerify with its key, and answers
; requests from its document root. All the TLS servers sharing the QUIC listener's
; address are registered (a page for one origin cannot be served under another's
; certificate). host_ptr/root_ptr point into the parsed config, which outlives us.
LINNEA_QUIC_MAX_VHOSTS equ 16
struc linnea_quic_vhost
    .host_ptr: resq 1
    .host_len: resq 1
    .cert_ptr: resq 1               ; framed certificate_list
    .cert_len: resq 1
    .priv:     resq 1               ; P-256 private scalar
    .root_ptr: resq 1               ; document root
    .root_len: resq 1
    .cc_ptr:   resq 1               ; the location's Cache-Control value
    .cc_len:   resq 1               ; (len 0 = none configured)
    .hsts_ptr: resq 1               ; the server's Strict-Transport-Security
    .hsts_len: resq 1               ; value (len 0 = not sent)
    .nosniff:  resq 1               ; 1 = send X-Content-Type-Options
    .srv:      resq 1               ; the config server*, so a request can be
                                    ; routed to a location rather than served
                                    ; under whichever root was registered
endstruc

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
global linnea_quic_add_vhost
global linnea_quic_server_datagram
global linnea_quic_server_rtx_sweep
global linnea_quic_server_goaway_all
global linnea_quic_server_drain_sweep
global linnea_quic_rxbuf
global linnea_quic_altsvc_set
global linnea_h3_altsvc
global linnea_h3_altsvc_len
global linnea_h3_server
global linnea_h3_advert
; delivering a proxied HTTP/3 response, which completes long after the datagram
; that carried the request: the parameter block and the entry point that reads
; it (see linnea_h3_proxy.asm)
global linnea_quic_h3_deliver
global linnea_h3d_qidx
global linnea_h3d_qgen
global linnea_h3d_sid
global linnea_h3d_hdr
global linnea_h3d_hlen
global linnea_h3d_base
global linnea_h3d_size
global linnea_h3d_foff
global linnea_h3d_flen

extern linnea_h3_build_431
extern linnea_h3_build_421
extern linnea_h3_read_headers
extern linnea_h3_serve
extern linnea_h3_srv
extern linnea_h3_owner_idx
extern linnea_h3_owner_gen
extern linnea_h3_owner_sid
extern h3_hdrs_buf
extern linnea_h3_body_off
extern linnea_h3_body_len
extern linnea_qpack_ccontrol_ptr
extern linnea_qpack_ccontrol_len
extern linnea_qpack_hsts_ptr
extern linnea_qpack_hsts_len
extern linnea_qpack_nosniff
extern linnea_quic_initial_dcid
extern linnea_quic_initial_secrets
extern linnea_quic_ch_parse
extern linnea_quic_build_sh
extern linnea_quic_build_ee
extern linnea_quic_build_cert
extern linnea_quic_build_cert_verify
extern linnea_quic_build_finished
extern linnea_quic_conn_lookup
extern linnea_quic_conn_lookup_odcid
extern linnea_quic_conn_alloc
extern linnea_quic_conn_unvalidated
extern linnea_quic_conn_sweep_now
extern linnea_quic_retry_scid
extern linnea_quic_retry_scid_len
extern linnea_aesgcm_init
extern linnea_aesgcm_seal
extern linnea_quic_retry_token_make
extern linnea_quic_retry_token_check
extern linnea_quic_hs_secrets
extern linnea_quic_app_secrets
extern linnea_quic_ku_next
extern linnea_quic_protect
extern linnea_quic_unprotect
extern linnea_quic_unprotect_hs
extern linnea_quic_unprotect_short
extern linnea_quic_crypto_frame
extern linnea_quic_stream_frame
extern linnea_quic_close_frame
extern linnea_quic_ack_record
extern linnea_quic_ack_seen
extern linnea_quic_frames_check
extern linnea_quic_stream_limit
extern linnea_quic_alpn_has
extern linnea_quic_frames_ack_eliciting
extern linnea_quic_rtt_sample
extern linnea_quic_pto_ms
extern linnea_quic_ack_delay
extern linnea_quic_ack_delay_ms
extern linnea_quic_tp_ack_exp
extern linnea_quic_tp_max_ack
extern linnea_quic_tp_idle_ms
extern linnea_quic_rtx_sent_ms
extern linnea_quic_build_ack
extern linnea_quic_ack_ranges
extern linnea_quic_rtx_record
extern linnea_quic_rtx_ack_range
extern linnea_quic_txchunk_room
extern linnea_quic_txchunk_record
extern linnea_quic_txchunk_ack
extern linnea_quic_txchunk_clear
extern linnea_quic_tp_parse
extern linnea_quic_tp_error
extern linnea_quic_tp_iscid
extern linnea_quic_tp_iscid_len
extern linnea_quic_flow_scan
extern linnea_quic_parse_priority
extern linnea_quic_reset_scan
extern linnea_quic_path_seen
extern linnea_quic_path_data
extern linnea_quic_reset_token
extern linnea_worker_index
extern linnea_network_addr_format
extern linnea_log_acc_host
extern linnea_log_acc_host_len
extern linnea_log_acc_peer
extern linnea_log_acc_peer_len
extern linnea_log_acc_meth
extern linnea_log_acc_meth_len
extern linnea_log_acc_tgt
extern linnea_log_acc_tgt_len
global linnea_quic_draining
extern quic_v2_active
extern linnea_quic_conn_free_hook
extern linnea_h3_tx_cap
extern linnea_quic_conn_slot
extern linnea_quic_dbg_tick
extern linnea_quic_dbg_conn
extern linnea_quic_dbg_rx
extern linnea_quic_dbg_serve
extern linnea_quic_dbg_reset
extern linnea_quic_dbg_chunk
extern linnea_quic_dbg_fc
extern linnea_quic_dbg_num
extern qdbg_pass
extern qdbg_on
extern linnea_string_from_u64
extern linnea_string_iequal
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
extern linnea_quic_early_fresh
extern linnea_quic_ticket_resume
extern linnea_quic_early_keys
extern linnea_quic_replay_check
extern linnea_quic_hs_psk
extern linnea_quic_early_ok
extern linnea_quic_resume_issued
extern linnea_quic_ticket_within_lifetime
section .rodata
quic_alpn_h3:   db "h3"        ; the one application protocol this server offers
; Retry integrity tag key and nonce, fixed by the RFC per QUIC version:
; v1 RFC 9001 5.8, v2 RFC 9369 3.3. They authenticate a Retry to any client
; without a shared secret — the tag proves only that the packet was not mangled,
; and its binding to the original connection id is what makes it useful.
retry_key_v1:   db 0xbe,0x0c,0x69,0x0b,0x9f,0x66,0x57,0x5a,0x1d,0x76,0x6b,0x54,0xe3,0x68,0xc8,0x4e
retry_nonce_v1: db 0x46,0x15,0x99,0xd3,0x5d,0x63,0x2b,0xf2,0x23,0x98,0x25,0xbb
retry_key_v2:   db 0x8f,0xb4,0xb0,0x1b,0x56,0xac,0x48,0xe2,0x60,0xfb,0xcb,0xce,0xad,0x7c,0xcc,0x92
retry_nonce_v2: db 0xd8,0x69,0x69,0xbc,0x2d,0x7c,0x6d,0x99,0x90,0xef,0xb0,0x4a
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
sa:          resb 28
salen:       resq 1
linnea_quic_rxbuf: resb LINNEA_QUIC_RXBUF_SIZE
plaintext:   resb 2048
cur_conn:    resq 1                   ; connection this datagram belongs to
expfin:      resb 64                  ; expected client Finished message
onertt_pay:  resb 512                 ; ACK + HANDSHAKE_DONE + NEW_CONNECTION_ID + uni + NST
onertt_pkt:  resb 4096                ; the protected 1-RTT packet
strm_pay:    resb 4096                ; STREAM frame carrying the h3 response
fc_grant_pay: resb 4096               ; MAX_DATA prepended to an outgoing payload (quic-9)
req:         resb linnea_h2_req_size  ; decoded h3 request
; QPACK literal scratch: every Huffman-decoded header value of one request goes
; here. At 2048 an ordinary request with a large cookie overflowed it, and the
; overflow was reported as a QPACK decompression failure — which killed the
; whole connection, taking every other request on it, for what is really our
; own resource limit. Sized to the header-list bound so that limit decides.
h3scratch:   resb LINNEA_HPACK_MAX_LISTSIZE
s_pl_ptr:    resq 1
s_pl_len:    resq 1
s_sid:       resq 1                   ; stream id of the request being served
s_serve_vhost: resq 1                 ; vhost answering it: the connection's,
                                      ; or another one its certificate covers
s_sdata:     resq 1                   ; that stream's data pointer
s_slen:      resq 1                   ; and length
s_soff:      resq 1                   ; and offset (0 = the stream's first bytes)
s_sfin:      resq 1                   ; and whether its FIN bit is set
s_rst_code:  resq 1                   ; app error code for the next RESET_STREAM
s_body_ptr:  resq 1                   ; request body captured by read_headers
s_body_len:  resq 1
s_txc_pn:    resq 1                   ; packet number a chunk just went out under
; 1-RTT key-update trial scratch (RFC 9001 6): next-generation client keys/secret
; are derived here and the packet is opened with them before anything is committed.
ku_ckeys:    resb linnea_quic_keys_size
ku_csecret:  resb 32
ku_ssecret:  resb 32
ku_exp:      resq 1                   ; expected packet number, held across the calls
s_tp_off:    resq 1                   ; a chunk's stream offset, held across the emit call
s_tp_len:    resq 1                   ; and its length, for the in-flight record
s_prio_u:    resq 1                   ; a request's parsed urgency (0-7)
s_prio_i:    resq 1                   ; and incremental flag (0/1), for the slot fill
; One proxied response, handed over from the upstream leg's completion (see
; linnea_quic_h3_deliver). Which connection and stream it answers, then the
; response itself: a head held here (a canned error), or a mapping whose
; foff/flen already span head and body together.
linnea_h3d_qidx: resq 1
linnea_h3d_qgen: resq 1               ; the connection ID that incarnation issued
linnea_h3d_sid:  resq 1
linnea_h3d_hdr:  resq 1
linnea_h3d_hlen: resq 1
linnea_h3d_base: resq 1
linnea_h3d_size: resq 1
linnea_h3d_foff: resq 1
linnea_h3d_flen: resq 1
s_ini_pn:    resq 1                   ; the Initial packet number being reassembled
s_ack_elicit: resq 1                  ; 1 when the 1-RTT packet in hand must be acked
s_pn_before:  resq 1                  ; conn.pn_1rtt before we processed it, so the
                                      ; exit can tell whether anything was sent
s_hs_type:   resq 1                   ; long-header Handshake type bits for this version
s_zrtt_type: resq 1                   ; ...and the 0-RTT and Initial ones, likewise
s_ini_type:  resq 1                   ; per-version (RFC 9369 shifts them all by one)
s_cc_acked:  resq 1                   ; response-stream bytes one incoming ACK freed
fc_scan:     resq 2                   ; [max_data, max_stream_data] from a flow scan
LINNEA_QUIC_RESET_MAX equ 16
reset_ids:   resq LINNEA_QUIC_RESET_MAX  ; stream ids the peer cancelled this packet
reset_pay:   resb 32                  ; a RESET_STREAM frame we send back on cancel
path_resp_pay: resb 16                ; a PATH_RESPONSE frame (0x1b + 8 echoed bytes)
LINNEA_QUIC_SRST_MAX equ 64           ; largest stateless reset we send
srst_buf:    resb LINNEA_QUIC_SRST_MAX ; the stateless-reset packet we build
srst_len:    resq 1
vneg_buf:    resb 64                   ; a Version Negotiation packet we build
cc_pay:      resb 16                  ; an application CONNECTION_CLOSE payload
acc_peer_buf: resb 64                  ; the peer's address text, for the access line
; 1 while the worker is draining (set by the event loop's stop path — the
; loop's own drain_flag lives in a module the standalone handshake test binary
; does not link). A draining worker opens no new connections.
linnea_quic_draining: resd 1
goaway_pay:  resb 24                  ; a GOAWAY STREAM frame on the control stream
maxstreams_pay: resb 16               ; a MAX_STREAMS frame raising the peer's limit
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
vhost_tab:   resb LINNEA_QUIC_MAX_VHOSTS * linnea_quic_vhost_size  ; SNI -> cert/key/root
vhost_count: resq 1
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
; the Initial that is opening a connection: its token (empty unless the client is
; answering a Retry), the client's source id (the Retry is addressed to it), and
; the original id recovered from a valid token
retry_ctx:   resb 256               ; AES-GCM context for the Retry integrity tag
s_tok_ptr:   resq 1
s_tok_len:   resq 1
s_cscid_ptr: resq 1
s_cscid_len: resq 1
s_tok_odcid: resb LINNEA_QUIC_MAX_CID
s_tok_odcid_len: resq 1
s_via_retry: resq 1
retry_buf:   resb 128                ; a Retry packet: header, ids, token, tag
retry_aad:   resb 160                ; the Retry pseudo-packet the tag covers
s_cert_len:  resq 1
s_priv:      resq 1
s_ini_len:   resq 1
s_ini_paylen: resq 1        ; Initial payload bytes (no pn, no tag)
s_hsmsg_len: resq 1
s_hs_chunk:  resq 1              ; byte length of the flight chunk being framed
s_cv_off:    resq 1              ; hsmsg offset of CertVerify while staging the tail
s_fin_off:   resq 1              ; hsmsg offset of Finished while staging the tail
s_walk_next: resq 1              ; next coalesced packet, so the Finished walk can go on
linnea_h3_altsvc:     resb 48    ; Alt-Svc value, e.g. h3=":443"; ma=86400
linnea_h3_altsvc_len: resq 1     ; 0 until a QUIC listener is bound
linnea_h3_server:     resq 1     ; index of the server that owns that listener
linnea_h3_advert:     resb LINNEA_MAX_SERVERS  ; byte[i]=1: server i advertises h3
                                 ; (every vhost on the QUIC port, so each origin
                                 ; tells clients it speaks h3 from its own responses)
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

; linnea_quic_server_init() -> rax = 0. Begin QUIC vhost registration: install the
; connection-free hook and clear the vhost table. linnea_quic_add_vhost is then
; called once per TLS server that shares the listener's address.
linnea_quic_server_init:
    ; a reclaimed connection may hold an open response stream's file mapping;
    ; the pool calls this back on every free so the mapping cannot leak
    lea rax, [quic_tx_free_hook]
    mov [linnea_quic_conn_free_hook], rax
    mov qword [vhost_count], 0
    xor eax, eax
    ret

; linnea_quic_add_vhost(rdi = config server, rsi = its root location) -> rax = 0.
; Register the server's hostname, certificate_list, key and document root as a QUIC
; vhost; the SNI matches one of these at handshake time. Extra vhosts past the
; table cap are ignored (the first, the default, is always kept).
linnea_quic_add_vhost:
    mov rax, [vhost_count]
    cmp rax, LINNEA_QUIC_MAX_VHOSTS
    jae .av_full
    imul rcx, rax, linnea_quic_vhost_size
    lea rdx, [vhost_tab + rcx]        ; the new slot
    lea r8, [rdi + linnea_config_server.hostname]
    mov [rdx + linnea_quic_vhost.host_ptr], r8
    mov r8, [rdi + linnea_config_server.hostname_len]
    mov [rdx + linnea_quic_vhost.host_len], r8
    mov r8, [rdi + linnea_config_server.cert_list]
    mov [rdx + linnea_quic_vhost.cert_ptr], r8
    mov r8, [rdi + linnea_config_server.cert_list_len]
    mov [rdx + linnea_quic_vhost.cert_len], r8
    mov r8, [rdi + linnea_config_server.key_priv]
    mov [rdx + linnea_quic_vhost.priv], r8
    lea r8, [rsi + linnea_config_location.root]
    mov [rdx + linnea_quic_vhost.root_ptr], r8
    mov r8, [rsi + linnea_config_location.root_len]
    mov [rdx + linnea_quic_vhost.root_len], r8
    lea r8, [rsi + linnea_config_location.cache_control]
    mov [rdx + linnea_quic_vhost.cc_ptr], r8
    mov r8, [rsi + linnea_config_location.cache_control_len]
    mov [rdx + linnea_quic_vhost.cc_len], r8
    lea r8, [rdi + linnea_config_server.hsts]
    mov [rdx + linnea_quic_vhost.hsts_ptr], r8
    mov r8, [rdi + linnea_config_server.hsts_len]
    mov [rdx + linnea_quic_vhost.hsts_len], r8
    mov r8, [rdi + linnea_config_server.nosniff]
    mov [rdx + linnea_quic_vhost.nosniff], r8
    mov [rdx + linnea_quic_vhost.srv], rdi
    inc qword [vhost_count]
.av_full:
    xor eax, eax
    ret

; select_vhost(rdi = SNI ptr, rsi = SNI len) -> rax = vhost index. The vhost whose
; hostname exactly matches the SNI, else 0 (the default) for an absent, unknown or
; malformed SNI. cur_conn is left pointing at the selected slot's fields elsewhere.
select_vhost:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                     ; SNI ptr
    mov r13, rsi                     ; SNI len
    test r13, r13
    jz .sv_default                   ; no SNI: default vhost
    xor r14d, r14d                   ; index
.sv_loop:
    cmp r14, [vhost_count]
    jae .sv_default
    imul rax, r14, linnea_quic_vhost_size
    lea rbx, [vhost_tab + rax]
    cmp r13, [rbx + linnea_quic_vhost.host_len]
    jne .sv_next                     ; length differs
    mov rsi, r12                     ; compare SNI to this vhost's hostname
    mov rdi, [rbx + linnea_quic_vhost.host_ptr]
    mov rcx, r13
    repe cmpsb
    jne .sv_next
    mov rax, r14                     ; matched
    jmp .sv_ret
.sv_next:
    inc r14
    jmp .sv_loop
.sv_default:
    xor eax, eax
.sv_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; vhost_slot(rax = vhost index) -> rax = &vhost_tab[index]. A tiny leaf used where
; the flight/serve paths need the connection's selected cert, key or root.
vhost_slot:
    imul rax, rax, linnea_quic_vhost_size
    lea rax, [vhost_tab + rax]
    ret

; authority_vhost(rdi = authority ptr, rsi = authority length) -> rax = vhost
; index, or -1 when no configured vhost carries that name. The port is cut
; first: ":authority" may carry one, a configured hostname never does.
authority_vhost:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    xor eax, eax
.av_port:
    cmp rax, r13
    jae .av_scan
    cmp byte [r12 + rax], ':'
    je .av_cut
    inc rax
    jmp .av_port
.av_cut:
    mov r13, rax
.av_scan:
    test r13, r13
    jz .av_none
    xor r14d, r14d
.av_loop:
    cmp r14, [vhost_count]
    jae .av_none
    mov rax, r14
    call vhost_slot
    mov r15, rax
    mov rdi, r12
    mov rsi, r13
    mov rdx, [r15 + linnea_quic_vhost.host_ptr]
    mov rcx, [r15 + linnea_quic_vhost.host_len]
    call linnea_string_iequal
    test eax, eax
    jnz .av_found
    inc r14
    jmp .av_loop
.av_found:
    mov rax, r14
    jmp .av_ret
.av_none:
    mov rax, -1
.av_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; vhost_same_cert(rdi = vhost index a, rsi = vhost index b) -> eax = 1 when
; both are served under the same certificate — which is what decides whether
; THIS connection is authoritative for another vhost's name. Comparing the
; certificate itself, not the index, is deliberate: one multi-SAN cert shared
; by several vhosts is exactly the case browsers coalesce onto one connection,
; and refusing those would cost a connection per origin for no security gain.
vhost_same_cert:
    push rbx
    push r12
    mov rax, rdi
    call vhost_slot
    mov rbx, rax
    mov rax, rsi
    call vhost_slot
    mov r12, rax
    mov rax, [rbx + linnea_quic_vhost.cert_len]
    cmp rax, [r12 + linnea_quic_vhost.cert_len]
    jne .vsc_no
    mov rdi, [rbx + linnea_quic_vhost.cert_ptr]
    mov rsi, [r12 + linnea_quic_vhost.cert_ptr]
    cmp rdi, rsi
    je .vsc_yes                      ; the same bytes, trivially
    mov rcx, rax
    repe cmpsb
    jne .vsc_no
.vsc_yes:
    mov eax, 1
    pop r12
    pop rbx
    ret
.vsc_no:
    xor eax, eax
    pop r12
    pop rbx
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
    ; record the sender: the pool allocator and the 1-RTT migration path read it here
    cmp rdx, 28
    jbe .dg_plen
    mov edx, 28
.dg_plen:
    mov [salen], rdx
    mov rcx, rdx
    lea rdi, [sa]
    rep movsb                        ; rsi = peer sockaddr

    ; opt-in receive trace: log every arriving datagram (target connection id +
    ; source), so a connection whose dump shows la frozen can be told apart —
    ; peer datagrams arriving but not matching, versus the peer truly silent.
    cmp byte [qdbg_on], 0
    je .no_rxlog
    lea rdi, [linnea_quic_rxbuf]
    mov rsi, r13
    lea rdx, [sa]
    call linnea_quic_dbg_rx
.no_rxlog:

    ; --- demultiplex: route the datagram to its connection ---
    ; The peer addresses us by the connection ID we issued, whose first two
    ; bytes hold the pool index, so the lookup is a bounds check and a compare.
    ; Short-header (1-RTT) packets carry application data once the handshake is
    ; confirmed; long-header packets are the handshake flights.
    test byte [linnea_quic_rxbuf], 0x80
    jz .demux_short
    ; A datagram must actually contain the header fields we are about to read.
    ; There was no length floor here at all, and rxbuf is reused between
    ; datagrams: a runt was demultiplexed on whatever the PREVIOUS datagram left
    ; behind, so it could be routed to an unrelated live connection and credit
    ; that connection's amplification budget with bytes received from somewhere
    ; else entirely. Nothing could be reflected by it — every reply path (Version
    ; Negotiation, the closing re-send, the stateless reset) carries its own
    ; length gate — but routing a packet on bytes that never arrived is not
    ; something to leave standing. A long header needs the first byte, the
    ; version, both connection-id length bytes and the DCID itself.
    cmp r13, 7
    jb .done
    movzx eax, byte [linnea_quic_rxbuf + 5]      ; long header: explicit DCID length
    cmp eax, LINNEA_QUIC_MAX_CID
    ja .done
    lea rax, [rax + 7]                           ; b0 + version(4) + len byte + DCID
    cmp r13, rax                                 ; + the SCID length byte
    jb .done
    movzx eax, byte [linnea_quic_rxbuf + 5]
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
    mov [cur_conn], rax              ; the address is NOT adopted here: see .long_in
    jmp .long_in
.demux_new:
    ; An unknown connection id with a long header. Check the version first: if it is
    ; not one we support, answer with a Version Negotiation packet (RFC 9000 6.1)
    ; listing our versions, so the client retries with one we speak rather than
    ; failing silently. A version of 0 is itself a VN packet — ignore it (a client
    ; never sends one to us; responding could loop). We do NOT require a large
    ; datagram here: version scanners and reachability probes send small unpadded
    ; packets, and our VN reply is tiny (~31 bytes), so the reflection factor stays
    ; under the RFC's 3x amplification bound. send_version_negotiation drops a
    ; datagram too short to even hold the connection ids.
    mov eax, [linnea_quic_rxbuf + 1]         ; version (little-endian read of the wire)
    cmp eax, 0x01000000                       ; QUIC v1  (wire 00 00 00 01)
    je .demux_known_ver
    cmp eax, 0xcf43336b                        ; QUIC v2  (wire 6b 33 43 cf, RFC 9369)
    je .demux_known_ver
    test eax, eax                             ; version 0 = a Version Negotiation packet
    jz .done
    call send_version_negotiation
    jmp .done
.demux_known_ver:
    ; Only a client's first flight may open a connection, and that always arrives in
    ; an Initial packet. The long-header packet type is in the first byte (not header
    ; protected); v1 encodes Initial as type bits 00, v2 remaps it to 01 (RFC 9369).
    ; Anything else with an unknown id belongs to a connection we do not hold, so it
    ; is dropped — with several workers this keeps a datagram that landed on the wrong
    ; one from starting a bogus handshake. (eax still holds the version.)
    movzx ecx, byte [linnea_quic_rxbuf]
    and cl, 0x30                              ; packet-type bits
    cmp eax, 0x01000000
    je .dn_want_v1_initial
    cmp cl, 0x10                              ; v2 Initial
    jne .done
    jmp .dn_alloc
.dn_want_v1_initial:
    test cl, cl                               ; v1 Initial = type 0
    jnz .done
.dn_alloc:
    ; draining: the GOAWAY told existing peers to move on, so a fresh Initial
    ; gets no reply — the client's retry lands on the replacement worker
    cmp dword [linnea_quic_draining], 0
    jne .done
    ; RFC 9000 14.1: a datagram carrying an Initial that opens a connection must
    ; be at least 1200 bytes. A client always pads it; enforcing the floor means a
    ; single small forged packet cannot buy a handshake, and keeps any reply we
    ; send well inside the 3x amplification bound. (The Version Negotiation path
    ; above deliberately answers small probes — its reply is tiny.)
    cmp r13, 1200
    jb .done
    lea rdi, [linnea_quic_rxbuf]
    mov rsi, r13
    call initial_token               ; rax = token ptr (0 = malformed header)
    test rax, rax
    jz .done
    mov [s_tok_ptr], rax
    mov [s_tok_len], rdx
    mov [s_cscid_ptr], r8
    mov [s_cscid_len], r9
    test rdx, rdx
    jnz .dn_token                    ; the client is answering a Retry
    ; No token. Open the connection straight away — the common case, and the one
    ; that keeps the handshake at one round trip — unless too many slots are
    ; already held by peers that have not proved their address, which is what a
    ; forged flood looks like. Then the client must come back with a token.
    call linnea_quic_conn_unvalidated
    cmp rax, LINNEA_QUIC_UNVALIDATED_MAX
    jb .dn_fresh
    call send_retry
    jmp .done
.dn_token:
    ; A token is only worth anything if we issued it, to this address, recently.
    ; An unusable one is dropped rather than answered: replying would hand a
    ; spoofer a packet, and a client whose token expired retransmits anyway.
    call now_ms
    mov rcx, rax
    lea rdi, [sa]
    mov rsi, [s_tok_ptr]
    mov rdx, [s_tok_len]
    lea r8, [s_tok_odcid]
    call linnea_quic_retry_token_check
    test rax, rax
    js .done
    mov [s_tok_odcid_len], rax
    mov qword [s_via_retry], 1
    jmp .dn_do_alloc
.dn_fresh:
    mov qword [s_via_retry], 0
.dn_do_alloc:
    lea rdi, [sa]
    mov rsi, [salen]
    call linnea_quic_conn_alloc
    test rax, rax
    jz .done                         ; pool exhausted: drop the datagram
    mov [cur_conn], rax
    mov qword [rax + linnea_quic_conn.ch_minpn], -1    ; sentinel: no Initial pn seen yet
    ; record the negotiated version (v2 = the only supported version that is not v1)
    mov qword [rax + linnea_quic_conn.is_v2], 0
    cmp dword [linnea_quic_rxbuf + 1], 0x01000000
    je .dn_odcid
    mov qword [rax + linnea_quic_conn.is_v2], 1
.dn_odcid:
    ; record the client's original DCID so its later Initials find this slot
    movzx ecx, byte [linnea_quic_rxbuf + 5]
    mov [rax + linnea_quic_conn.odcid_len], rcx
    lea rdi, [rax + linnea_quic_conn.odcid]
    lea rsi, [linnea_quic_rxbuf + 6]
    rep movsb
    ; original_destination_connection_id: normally the id this packet carries, but
    ; after a Retry the id the client used BEFORE it, which only the token knows.
    mov rax, [cur_conn]
    mov rcx, [s_via_retry]
    mov [rax + linnea_quic_conn.via_retry], rcx
    test rcx, rcx
    jnz .dn_tp_retry
    mov rcx, [rax + linnea_quic_conn.odcid_len]
    mov [rax + linnea_quic_conn.tp_odcid_len], rcx
    lea rdi, [rax + linnea_quic_conn.tp_odcid]
    lea rsi, [rax + linnea_quic_conn.odcid]
    rep movsb
    jmp .long_in
.dn_tp_retry:
    ; the token proves the peer receives packets at this address, so the 3x
    ; amplification limit has done its job and no longer applies (RFC 9000 8.1)
    mov qword [rax + linnea_quic_conn.amp_valid], 1
    mov rcx, [s_tok_odcid_len]
    mov [rax + linnea_quic_conn.tp_odcid_len], rcx
    lea rdi, [rax + linnea_quic_conn.tp_odcid]
    lea rsi, [s_tok_odcid]
    rep movsb
    jmp .long_in
.demux_short:
    ; the same floor for a short header: the id we look up is a fixed 8 bytes
    ; after the first, and reading it out of a shorter datagram means reading the
    ; previous one (see the long-header note above)
    cmp r13, 1 + LINNEA_QUIC_SCID_LEN
    jb .done
    lea rdi, [linnea_quic_rxbuf + 1]             ; short header: our ID, fixed length
    mov esi, LINNEA_QUIC_SCID_LEN
    call linnea_quic_conn_lookup
    test rax, rax
    jz .demux_short_reset            ; unknown connection: maybe a stateless reset
    cmp qword [rax + linnea_quic_conn.state], LINNEA_QUIC_ST_CLOSING
    je .closing_rx                   ; already closed: re-send the close, process nothing
    ; The 1-RTT keys do not exist until the client Finished is verified (.do_cfin
    ; sets ST_CONNECTED and derives ap_ckeys). Before that the key material is
    ; still the zeroed slot, and a zero AEAD/header-protection key is a KNOWN key:
    ; anyone could forge a packet that "opens", which would then adopt its source
    ; as the peer address and be served — a pre-auth reflection and hijack. So a
    ; short-header packet for a connection that has not completed its handshake is
    ; dropped; a legitimate client never sends 1-RTT before its own Finished, and
    ; a reordered one is recovered by the client's retransmission.
    cmp qword [rax + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    jne .done
    ; select the connection so we can decrypt, but do NOT adopt the source address
    ; yet: an unauthenticated (spoofed) 1-RTT packet carrying a valid connection id
    ; must not be able to redirect our sends. The address is committed only after
    ; the AEAD opens, in .onertt_in below.
    mov [cur_conn], rax
    jmp .onertt_in
.demux_short_reset:
    ; No state for this connection id. Only reset ids THIS worker issued — the first
    ; CID byte is the issuing worker's index. A packet mis-routed here for another
    ; worker's connection (the SO_REUSEPORT 4-tuple fallback, when the BPF CID
    ; steering is unavailable) must be dropped, not reset: resetting it would
    ; spuriously kill a connection another worker is serving and could storm resets
    ; between workers. In production the BPF steers each id to its worker, so a
    ; genuinely-stateless id (slot reclaimed) still reaches here and is reset.
    movzx eax, byte [linnea_quic_rxbuf + 1]   ; the DCID's worker byte
    cmp eax, [linnea_worker_index]
    jne .done
    ; If the packet is long enough to be a real 1-RTT packet, send a stateless reset
    ; (RFC 9000 10.3) so the peer tears down at once instead of idling out. Skip short
    ; packets (< 22B): the reset must be shorter than its trigger (no loop) yet >= 21.
    cmp r13, 22
    jb .done
    call send_stateless_reset
    jmp .done
.demux_found:
    cmp qword [rax + linnea_quic_conn.state], LINNEA_QUIC_ST_CLOSING
    je .closing_rx
    mov [cur_conn], rax
.long_in:
    ; Long-header packets are the handshake flights, and none of them authenticates
    ; its sender: Initial keys come from the connection id, which travels in the
    ; clear, so anyone who has seen a packet of this handshake can forge one. So the
    ; peer address is NOT adopted from a long-header packet — it stays the address
    ; the connection was opened from (recorded by the allocator, and validated by
    ; the Retry token when a Retry happened). Otherwise an attacker who had seen one
    ; datagram could replay it from an address of their choosing and our whole
    ; server flight would follow, both derailing the handshake and reflecting at
    ; whatever the amplification budget allows. RFC 9000 9 forbids migrating before
    ; the handshake is confirmed in any case; a real client stays put, and the
    ; address moves only after a 1-RTT packet authenticates, at .oi_ok.
    ; select this connection's QUIC version for every key derivation below (Initial,
    ; Handshake, 0-RTT, 1-RTT): v2 uses a different salt and different labels.
    mov rax, [cur_conn]
    mov al, [rax + linnea_quic_conn.is_v2]
    mov [quic_v2_active], al
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
    ; decrypt the Initial and fold every CRYPTO fragment it carries into the
    ; connection's reassembly buffer. A packet can hold several CRYPTO frames and
    ; a client (ngtcp2) may send them out of offset order, so we walk them all;
    ; a ClientHello too large for one Initial completes across several packets.
    lea rdi, [linnea_quic_rxbuf]
    mov rsi, r13
    CONNLEA rdx, ini_client
    lea rcx, [plaintext]
    call linnea_quic_unprotect       ; rax = plaintext length, rdx = pn
    cmp rax, -2
    je .ini_rsvd                     ; authentic, but its reserved bits are set
    test rax, rax
    js .try_handshake                ; not decryptable — maybe the client Finished
    mov [s_ini_pn], rdx
    lea r15, [plaintext]             ; walk cursor
    lea r14, [plaintext + rax]       ; frames end
.crypto_walk:
    mov rdi, r15
    mov rsi, r14
    sub rsi, r15
    jbe .crypto_none
    call linnea_quic_crypto_frame    ; rax=CRYPTO ptr, rdx=len, r8=offset
    test rax, rax
    jz .crypto_none                  ; no further CRYPTO frame
    lea r15, [rax + rdx]             ; resume past this frame's data
    mov r9, [s_ini_pn]
    call .ch_reassemble              ; rax = 1 once the ClientHello is whole
    test rax, rax
    jz .crypto_walk
    jmp .ch_complete
.crypto_none:
    jmp .done                        ; still partial: wait for the next Initial
.ch_complete:
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
    ; The client's SCID sits after its DCID in the received header. Copy it to a
    ; stable buffer: we reuse it as the DCID of every packet we send back, but
    ; dgram is overwritten by each recvfrom.
    ;
    ; This runs BEFORE the refusals below, not after them as it used to. A
    ; CONNECTION_CLOSE addressed with an empty DCID is a packet the client cannot
    ; match to any connection, so it discards it without a word and the refusal
    ; is silence all over again — which is exactly what the first cut of
    ; .initial_close did: 40 bytes on the wire, dropped on arrival. Nothing here
    ; depends on the ClientHello being acceptable; it is a property of the packet
    ; that carried it.
    movzx eax, byte [linnea_quic_rxbuf + 5]
    lea rsi, [linnea_quic_rxbuf + 6 + rax]
    movzx ecx, byte [rsi]            ; SCID length (raw wire byte, 0..255)
    ; conn.dcid is LINNEA_QUIC_MAX_CID bytes. This completing Initial's header
    ; was not size-checked by initial_token (that only guards a first packet),
    ; so bound the SCID before the copy or rep movsb overruns the field into
    ; the handshake secrets and reply-header builders that reuse dcid_len.
    cmp ecx, LINNEA_QUIC_MAX_CID
    ja .done                         ; malformed: drop, the conn times out
    inc rsi                          ; -> SCID bytes
    mov rax, [cur_conn]
    mov [rax + linnea_quic_conn.dcid_len], rcx
    lea rdi, [rax + linnea_quic_conn.dcid]
    rep movsb                        ; copy the SCID out of dgram
    ; A ClientHello with no usable x25519 key_share cannot key the ECDHE. Never
    ; hand a null share to x25519 (it would dereference address 0 and crash the
    ; worker). This is the one client we cannot serve — every browser and QUIC
    ; library offers x25519 — but it is now TOLD so, with the handshake_failure
    ; (40) that RFC 8446 4.1.1 names for "cannot negotiate an acceptable set of
    ; parameters", rather than left to time out against a silent server.
    ;
    ; The conformant answer for a client that supports x25519 and merely guessed
    ; a different group is a HelloRetryRequest, which the TCP path gained in
    ; Q159 and this one still lacks; QUIC's ClientHello parse does not read
    ; supported_groups, so the two cases are indistinguishable here exactly as
    ; they were on TCP before that fix.
    ; RFC 9001 8.4 MUST: QUIC forbids the TLS middlebox compatibility mode, so a
    ; ClientHello whose legacy_session_id is not empty "MUST be treated as a
    ; connection error of type PROTOCOL_VIOLATION". We always echoed an empty
    ; session id, which lands on the right outcome by accident -- such a client
    ; rejects our ServerHello -- but it learns nothing about why, and the refusal
    ; is properly ours to make.
    cmp qword [ch_out + linnea_quic_ch.sessid_len], 0
    jne .ini_rsvd                    ; the PROTOCOL_VIOLATION close
    cmp qword [ch_out + linnea_quic_ch.ks_ptr], 0
    jne .ks_ok
    mov edi, 0x0100 + 40             ; handshake_failure
    call .initial_close
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.tp_invalid:
    ; RFC 9000 7.4 MUST: a transport parameter carrying a value 18.2 declares
    ; invalid is a connection error of type TRANSPORT_PARAMETER_ERROR. Two are
    ; judged (linnea_quic_tp_parse): max_udp_payload_size below 1200, and
    ; active_connection_id_limit below 2. Both were read past in silence, so a
    ; peer could contradict itself — advertise a receive size no QUIC endpoint may
    ; use, or refuse to hold the second connection id we are about to issue it —
    ; and be served anyway. Refused in the Initial space, like the key_share and
    ; ALPN refusals, since that is where the ClientHello carrying them arrived.
    mov edi, 0x08                    ; TRANSPORT_PARAMETER_ERROR
    call .initial_close
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.ini_rsvd:
    ; RFC 9000 17.2 MUST: a long header's two reserved bits (mask 0x0c) set on a
    ; packet that authenticated is a connection error of type PROTOCOL_VIOLATION.
    ; The close goes in the Initial space — the one whose keys both ends certainly
    ; hold at this point — exactly as the key_share and ALPN refusals do, and the
    ; slot is released with it. A client that has already moved to the Handshake
    ; space has discarded its Initial keys (RFC 9001 4.9.1) and would not read
    ; this, so a Handshake packet carrying the bits is still only dropped; that
    ; space has no close builder of its own yet.
    mov edi, 0x0a                    ; PROTOCOL_VIOLATION
    call .initial_close
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.ks_ok:
    ; RFC 8446 9.2: a server authenticating with a certificate — which we always
    ; do — MUST abort a ClientHello that omits signature_algorithms, because it
    ; cannot know which schemes the client will accept for CertificateVerify. The
    ; TCP path enforces this; the QUIC ClientHello parse never read the extension
    ; (tls-5), so such a hello was served a certificate the client never said it
    ; could verify. The missing_extension alert (RFC 8446 6) rides an Initial
    ; CONNECTION_CLOSE exactly as the key_share/ALPN refusals do.
    cmp qword [ch_out + linnea_quic_ch.sigalg_seen], 0
    jne .sigalg_ok
    mov edi, 0x0100 + 109            ; missing_extension
    call .initial_close
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.sigalg_ok:
    ; QUIC mandates TLS 1.3 (RFC 9001 4.2), and we implement only
    ; TLS_AES_128_GCM_SHA256. A hello that offers neither must be refused with the
    ; matching alert (tls-5) rather than served a version/cipher it never offered —
    ; which a strict client would reject with illegal_parameter anyway. The QUIC
    ; ClientHello parse now records both.
    cmp qword [ch_out + linnea_quic_ch.tls13_seen], 0
    jne .tls13_ok
    mov edi, 0x0100 + 70             ; protocol_version
    call .initial_close
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.tls13_ok:
    cmp qword [ch_out + linnea_quic_ch.aes128_seen], 0
    jne .cipher_ok
    mov edi, 0x0100 + 40             ; handshake_failure
    call .initial_close
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.cipher_ok:
    ; The client must actually have offered h3. linnea_quic_build_ee wrote "h3"
    ; into EncryptedExtensions unconditionally, without ever looking at the
    ; list — so a client offering only hq-interop or doq was told h3 had been
    ; selected, which RFC 7301 3.2 forbids outright: a server must not name a
    ; protocol the client did not advertise. linnea_quic_alpn_has has existed
    ; all along and had no caller.
    ;
    ; RFC 9001 8.1 wants this refused with a no_application_protocol alert
    ; carried in a CONNECTION_CLOSE (QUIC error 0x0178), which .initial_close
    ; now sends: the Initial space is keyed off the client's own DCID, so it is
    ; writable even here.
    mov rdi, [ch_out + linnea_quic_ch.alpn_ptr]
    test rdi, rdi
    jz .alpn_bad                      ; no ALPN at all: h3 is not optional here
    mov rsi, [ch_out + linnea_quic_ch.alpn_len]
    lea rdx, [quic_alpn_h3]
    mov ecx, 2
    call linnea_quic_alpn_has
    test rax, rax
    jnz .alpn_ok
.alpn_bad:
    mov edi, 0x0100 + 120            ; no_application_protocol
    call .initial_close
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done
.alpn_ok:
    ; select the vhost by SNI — it fixes the certificate, signing key and document
    ; root this connection is served under, so a name gets its own origin's cert.
    mov rdi, [ch_out + linnea_quic_ch.sni_ptr]
    mov rsi, [ch_out + linnea_quic_ch.sni_len]
    call select_vhost
    mov rcx, [cur_conn]
    mov [rcx + linnea_quic_conn.vhost], rax
    ; SNI hash, computed once: it seeds any ticket we issue and (on a resumption
    ; offer) checks the presented ticket's server_name binding.
    mov rdi, [ch_out + linnea_quic_ch.sni_ptr]
    mov rsi, [ch_out + linnea_quic_ch.sni_len]
    lea rdx, [q_sni32]
    call linnea_sha256
    mov rax, [q_sni32]
    mov rbx, [cur_conn]
    mov [rbx + linnea_quic_conn.sni_hash], rax
    ; the client's initial flow-control limits from its transport parameters:
    ; how much data it will accept on a connection (initial_max_data) and on one
    ; stream it opened (initial_max_stream_data_bidi_local). These are only the
    ; starting windows — the client raises them with MAX_DATA / MAX_STREAM_DATA as
    ; it consumes, so a response larger than the initial window streams within it.
    ; Absent parameters mean zero (RFC 9000 18.2).
    mov qword [rbx + linnea_quic_conn.fc_stream_init], 0
    mov qword [rbx + linnea_quic_conn.ms_uni_peer], 0
    mov qword [rbx + linnea_quic_conn.ack_exp_peer], 3    ; RFC 9000 18.2 defaults
    mov qword [rbx + linnea_quic_conn.max_ack_peer], 25
    mov qword [rbx + linnea_quic_conn.fc_conn_max], 0
    mov qword [rbx + linnea_quic_conn.fc_conn_sent], 0
    ; receive-side flow control (quic-9): we advertised initial_max_data as the
    ; starting ceiling and have received nothing yet.
    mov qword [rbx + linnea_quic_conn.fc_recv], 0
    mov qword [rbx + linnea_quic_conn.fc_adv], LINNEA_QUIC_INITIAL_MAX_DATA
    mov qword [rbx + linnea_quic_conn.fc_pending], 0
    mov qword [rbx + linnea_quic_conn.ms_bidi_max], LINNEA_QUIC_MS_INIT
    mov rdi, [ch_out + linnea_quic_ch.tp_ptr]
    test rdi, rdi
    jz .tp_recorded
    mov rsi, [ch_out + linnea_quic_ch.tp_len]
    call linnea_quic_tp_parse        ; rax = max_data, rdx = max_stream_data,
                                     ; r8 = initial_max_streams_uni
    cmp qword [linnea_quic_tp_error], 0
    jne .tp_invalid                  ; a value RFC 9000 18.2 declares invalid
    mov rbx, [cur_conn]
    mov [rbx + linnea_quic_conn.fc_conn_max], rax
    mov [rbx + linnea_quic_conn.fc_stream_init], rdx   ; each new slot starts here
    mov [rbx + linnea_quic_conn.ms_uni_peer], r8
    ; ...and only NOW judge the connection ids. tp_parse returns three values in
    ; bare registers (rax, rdx, r8) and they are consumed by the three stores
    ; above; anything inserted between the call and them silently eats one. This
    ; check sat there and clobbered rax, so every connection ran with
    ; initial_max_data set to a connection-id length -- the handshake completed
    ; and small replies fitted, while any real response stalled on flow control.
    ;
    ; RFC 9000 7.3 MUST, both halves: the absence of initial_source_connection_id
    ; is a TRANSPORT_PARAMETER_ERROR, and so is a value that does not match the
    ; Source Connection ID of the peer's first Initial. The parameter binds the
    ; transport parameters to the packets that carried them: unchecked, an
    ; attacker who can rewrite Initials can swap connection ids on a handshake in
    ; flight and neither end notices. conn.dcid IS that Source Connection ID --
    ; it is what we address the peer by.
    mov rax, [linnea_quic_tp_iscid_len]
    cmp rax, -1
    je .tp_invalid                   ; the peer sent none
    cmp rax, [rbx + linnea_quic_conn.dcid_len]
    jne .tp_invalid                  ; a different length is already a mismatch
    test rax, rax
    jz .iscid_ok                     ; both empty: nothing to compare
    mov rcx, rax
    lea rdi, [linnea_quic_tp_iscid]
    lea rsi, [rbx + linnea_quic_conn.dcid]
    repe cmpsb
    jne .tp_invalid
.iscid_ok:
    mov rbx, [cur_conn]
    mov rax, [linnea_quic_tp_ack_exp]      ; the peer's ACK-delay encoding, which
    mov [rbx + linnea_quic_conn.ack_exp_peer], rax   ; is what decodes its ACKs
    mov rax, [linnea_quic_tp_max_ack]
    mov [rbx + linnea_quic_conn.max_ack_peer], rax
    ; RFC 9000 10.1: the effective idle timeout is the minimum of the two
    ; advertised values, and a peer that omits it (or sends 0) imposes none. We
    ; advertise LINNEA_QUIC_IDLE_SECS; a client that will forget us sooner gets
    ; its slot reclaimed at its number instead of ours. Round the peer's
    ; milliseconds up to whole seconds — the sweep's granularity — and never
    ; below one, so a tiny value cannot reclaim a connection the instant it is
    ; made.
    mov rax, [linnea_quic_tp_idle_ms]
    test rax, rax
    jz .idle_done                    ; absent or 0: ours stands
    add rax, 999
    xor edx, edx
    mov rcx, 1000
    div rcx                          ; -> seconds, rounded up
    test rax, rax
    jnz .idle_floor
    mov eax, 1
.idle_floor:
    cmp rax, LINNEA_QUIC_IDLE_SECS
    jae .idle_done                   ; longer than ours: the minimum is ours
    mov [rbx + linnea_quic_conn.idle_secs], rax
.idle_done:
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
    ; ticket lifetime (tls-7): the ticket verified, but a captured one must not
    ; resume past its advertised lifetime — the sealing key never rotates. The 0-RTT
    ; block below only gates EARLY data on the replay window; resumption itself was
    ; unbounded. Mirrors the TCP try_resume check.
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    xor edi, edi                             ; CLOCK_REALTIME
    lea rsi, [q_nst_ts]
    syscall
    mov rdi, [linnea_quic_resume_issued]
    mov rsi, [q_nst_ts]                       ; now (seconds)
    call linnea_quic_ticket_within_lifetime
    test rax, rax
    jz .no_resume                             ; expired / future-dated -> full handshake
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
    mov rdi, [linnea_quic_resume_issued]      ; from inside the SEALED ticket, so
    mov rsi, rax                              ; the client cannot move it
    call linnea_quic_early_fresh
    test rax, rax
    jz .no_resume                             ; outside the window: resume at 1-RTT
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
    ; ACK the Initials we received: Largest Acknowledged is the largest packet
    ; number, First ACK Range is (largest - smallest) so the range covers exactly
    ; [smallest, largest] — NOT [0, largest]. A client may start its Initials above 0
    ; (Chrome begins at 1), and acking a packet it never sent (e.g. 0) is an invalid
    ; ACK the client rejects (QUIC_INVALID_ACK_DATA). The numbers are tiny (a handful
    ; of Initials per ClientHello), so each varint is one byte and the ACK stays five.
    ; keep the ServerHello: a retransmission of this flight has to rebuild the
    ; Initial that carries it, and sh_buf is scratch clobbered between datagrams
    mov rax, [cur_conn]
    mov ecx, [s_sh_len]
    mov [rax + linnea_quic_conn.sh_len], rcx
    lea rdi, [rax + linnea_quic_conn.sh_msg]
    lea rsi, [sh_buf]
    rep movsb
    call .build_initial_packet       ; -> outpkt, s_ini_len; consumes conn.pn_ini

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
    ; retry_source_connection_id (RFC 9000 7.3): after a Retry the client checks
    ; that the id it has been talking to is the one our Retry chose. Empty length
    ; means no Retry happened and the parameter is omitted.
    mov rax, [cur_conn]
    mov qword [linnea_quic_retry_scid_len], 0
    cmp qword [rax + linnea_quic_conn.via_retry], 0
    je .hs_no_retry
    mov rcx, [rax + linnea_quic_conn.odcid_len]      ; = the id our Retry issued
    mov [linnea_quic_retry_scid_len], rcx
    lea rdi, [linnea_quic_retry_scid]
    lea rsi, [rax + linnea_quic_conn.odcid]
    rep movsb
.hs_no_retry:
    lea rdi, [hsmsg]
    mov rax, [cur_conn]
    lea rsi, [rax + linnea_quic_conn.tp_odcid]
    mov rdx, [rax + linnea_quic_conn.tp_odcid_len]
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
    mov rax, [cur_conn]
    mov rax, [rax + linnea_quic_conn.vhost]
    call vhost_slot                  ; the SNI-selected vhost's certificate and key
    mov rsi, [rax + linnea_quic_vhost.cert_ptr]
    mov rdx, [rax + linnea_quic_vhost.cert_len]
    call linnea_quic_build_cert
    add r14, rax
    ; th_cert = H(CH || SH || hsmsg[0..r14])
    lea rsi, [hsmsg]
    mov rdx, r14
    call .transcript
    mov [s_cv_off], r14              ; CertVerify starts here
    lea rdi, [hsmsg + r14]
    lea rsi, [th_buf]
    mov rax, [cur_conn]
    mov rax, [rax + linnea_quic_conn.vhost]
    call vhost_slot
    mov rdx, [rax + linnea_quic_vhost.priv]
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
    ; arm the probe timer: until the client's Finished arrives, this flight is
    ; unacknowledged and the sweep must be willing to send it again
    call now_ms
    mov rbx, [cur_conn]
    mov [rbx + linnea_quic_conn.flight_ms], rax
    mov qword [rbx + linnea_quic_conn.flight_tries], 0
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
    ; walk the datagram for the coalesced 0-RTT packet.
    ;
    ; RFC 9369 shifts every long-header packet type up by one for QUIC v2, so
    ; 0-RTT is 0x10 in v1 and 0x20 in v2, and Initial is 0x00 and 0x10. BOTH
    ; matter to this walk: the first is what it is hunting for, and the second is
    ; how it decides whether the packet it is stepping over carries a token to
    ; skip. Hardcoding the v1 values meant a v2 client's early data was looked
    ; for under a type it never sends -- the 0-RTT packet was silently ignored,
    ; the request went unanswered until the client resent it at 1-RTT, and the
    ; whole point of 0-RTT was lost. The Handshake walk below has computed its
    ; type per version all along (s_hs_type); this now does the same.
    mov r13, [s_dgram_len]           ; r13 may have been clobbered building the flight
    mov qword [s_zrtt_type], 0x10
    mov qword [s_ini_type], 0x00
    cmp byte [quic_v2_active], 0
    je .ew_types_set
    mov qword [s_zrtt_type], 0x20
    mov qword [s_ini_type], 0x10
.ew_types_set:
    lea r15, [linnea_quic_rxbuf]
.ew_loop:
    lea rax, [linnea_quic_rxbuf + r13]
    cmp r15, rax
    jae .early_done                  ; no 0-RTT packet in this datagram
    test byte [r15], 0x80
    jz .early_done                   ; short header — stop
    movzx eax, byte [r15]
    and al, 0x30
    mov r10d, eax                    ; this packet's type bits
    cmp r10, [s_zrtt_type]
    je .ew_zrtt
    ; skip this long-header packet (an Initial ahead of the 0-RTT one)
    movzx eax, byte [r15 + 5]        ; DCID length
    lea rdi, [r15 + 6 + rax]
    movzx eax, byte [rdi]            ; SCID length
    lea rdi, [rdi + 1 + rax]         ; -> token length (Initial) / length
    lea rsi, [linnea_quic_rxbuf + r13]
    cmp r10, [s_ini_type]
    jne .ew_len                      ; only an Initial carries a token
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
    call linnea_quic_unprotect_hs    ; rax = frame bytes, rdx = packet number
    test rax, rax
    js .early_done
    ; RFC 9000 13.2.1: this packet MUST be acknowledged. 0-RTT shares the
    ; Application packet number space with 1-RTT, so recording its number into
    ; rx_have is enough — the ACK rides the HANDSHAKE_DONE packet, whose ACK is
    ; built from rx_have at .do_cfin. The number used to be discarded, so the
    ; client declared its early request lost and re-sent it in 1-RTT, where it
    ; was served a SECOND time (harmless for the idempotent GET/HEAD that 0-RTT
    ; carries, but a needless duplicate and a MUST unmet).
    push rax                         ; frame count, across the record call
    mov rsi, rdx                     ; the 0-RTT packet number
    CONNLEA rdi, rx_have
    call linnea_quic_ack_record
    pop rax
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
    ; Once the handshake is confirmed the server has sent HANDSHAKE_DONE, and RFC
    ; 9001 4.9.1 then makes it discard its Handshake keys — after which it MUST NOT
    ; process a packet in that space. Initial keys went even earlier (4.9, on the
    ; first Handshake packet) and 0-RTT keys with them. Every long-header packet
    ; belongs to one of those three now-dead spaces, so a confirmed connection
    ; drops the whole datagram rather than AEAD-processing it under keys that are
    ; supposed to be gone. A conforming client stops sending them on HANDSHAKE_DONE;
    ; if that frame was lost the loss timer resends it as a 1-RTT packet, and the
    ; client's retransmitted Handshake/Initial here is simply discarded.
    mov rax, [cur_conn]
    cmp qword [rax + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    je .done
    ; the long-header type bits for a Handshake packet are 0x20 in v1, but v2 (RFC
    ; 9369) shifts every long-header type up by one, so 0x30. Compute the value for
    ; this connection's version once and match against it while walking the datagram.
    mov qword [s_hs_type], 0x20
    cmp byte [quic_v2_active], 0
    je .th_type_set
    mov qword [s_hs_type], 0x30
.th_type_set:
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
    cmp r10d, [s_hs_type]
    je .walk_len                     ; Handshake carries no token
    call linnea_quic_varint_decode   ; token length (Initial only)
    add rdi, rdx
    add rdi, rax                     ; skip the token
.walk_len:
    call linnea_quic_varint_decode   ; length (pn + payload + tag)
    lea rdi, [rdi + rdx]             ; -> packet number
    add rdi, rax                     ; -> next coalesced packet
    cmp r10d, [s_hs_type]
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
    ; The 4-byte handshake header is framing and compares plainly; the 32-byte
    ; verify_data is a MAC and gets the same constant-time compare the TCP path
    ; has always used. The packet carrying it is AEAD-authenticated, so the risk
    ; here is remote -- but there is no reason for the two paths to differ, and
    ; "it is protected anyway" is the argument that ages badly.
    lea rsi, [expfin]
    mov rdi, r14
    mov ecx, 4
    repe cmpsb
    jne .done
    lea rdi, [expfin + 4]
    lea rsi, [r14 + 4]
    call quic_ct_eq32
    test eax, eax
    jz .done
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
    CONNLEA r8, ap_csecret           ; keep the traffic secrets for key updates
    CONNLEA r9, ap_ssecret
    call linnea_quic_app_secrets
    mov rax, [cur_conn]
    mov qword [rax + linnea_quic_conn.key_phase], 0   ; start on key phase 0
    ; confirm the handshake and open the server's HTTP/3 streams in one packet:
    ; ACK, HANDSHAKE_DONE (0x1e), then the control + QPACK stream setup. The
    ; STREAM frames are LEN-prefixed, so all three self-delimit within the packet.
    lea rdi, [onertt_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack       ; rax = ACK length (0 if nothing to ack yet)
    mov rcx, rax
    mov byte [onertt_pay + rcx], 0x1e   ; HANDSHAKE_DONE
    inc rcx
    ; NEW_CONNECTION_ID (quic-7): hand the peer a spare routable CID and its reset
    ; token, so it can rotate its DCID without losing the connection.
    push rcx
    mov rbx, [cur_conn]
    lea rdi, [onertt_pay + rcx]
    mov byte [rdi], 0x18                 ; NEW_CONNECTION_ID
    mov byte [rdi + 1], 0x01            ; sequence number 1
    mov byte [rdi + 2], 0x00            ; retire prior to 0
    mov byte [rdi + 3], LINNEA_QUIC_SCID_LEN
    add rdi, 4
    lea rsi, [rbx + linnea_quic_conn.cid1]
    mov ecx, LINNEA_QUIC_SCID_LEN
    rep movsb                            ; the connection id
    mov rsi, rdi                         ; the 16-byte reset token follows
    lea rdi, [rbx + linnea_quic_conn.cid1]
    call linnea_quic_reset_token
    pop rcx
    add rcx, 4 + LINNEA_QUIC_SCID_LEN + 16   ; NEW_CONNECTION_ID frame length
    ; The control and QPACK streams are three unidirectional streams, and RFC
    ; 9000 4.6 is unconditional: "An endpoint MUST NOT open more streams than
    ; allowed by the current stream limit set by its peer". This blob used to go
    ; out for every connection without reading the client's
    ; initial_max_streams_uni at all (quic-12), so a client granting fewer than
    ; three got them anyway. A real HTTP/3 client grants far more, so this only
    ; bites a peer that has asked us not to — and such a peer cannot do HTTP/3 as
    ; RFC 9114 6.2.1 specifies either way; not opening them is the half that is
    ; ours to get right.
    cmp qword [rbx + linnea_quic_conn.ms_uni_peer], 3
    jb .no_h3_uni
    lea rdi, [onertt_pay + rcx]
    lea rsi, [h3_uni_setup]
    push rcx
    mov ecx, h3_uni_setup_len
    rep movsb                        ; append the fixed control/QPACK stream setup
    pop rcx
    add rcx, h3_uni_setup_len
.no_h3_uni:
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
    ; select this connection's QUIC version, so a 1-RTT key update (ku_next) derives
    ; the next generation with the right labels.
    mov rax, [cur_conn]
    mov al, [rax + linnea_quic_conn.is_v2]
    mov [quic_v2_active], al
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
    call linnea_quic_unprotect_short  ; rax = frame bytes, rdx = pn, r8 = key phase
    cmp rax, -2                       ; reserved bits set on an authentic packet:
    je .oi_rsvd                       ; a connection error, not a decrypt failure —
                                      ; and it must be caught BEFORE the key-update
                                      ; retry below, or a violating packet would
                                      ; provoke a pointless trial rekey instead
    test rax, rax
    jns .oi_ok
    ; Failed to open with the current keys. A peer-initiated key update (RFC 9001 6)
    ; flips the key-phase bit, so if this packet carries the OTHER phase, derive the
    ; next key generation and retry. r8 = -1 for a too-short packet never equals the
    ; other phase, so that just drops; and a spoofed phase flip cannot force a rekey
    ; because ku_try only commits when the AEAD actually opens.
    mov rcx, [cur_conn]
    mov r9, [rcx + linnea_quic_conn.key_phase]
    xor r9, 1
    cmp r8, r9
    jne .done
    mov rdi, rcx                     ; conn
    lea rsi, [linnea_quic_rxbuf]     ; packet
    mov rdx, r13                     ; len
    lea rcx, [plaintext]             ; out
    xor r8d, r8d                     ; expected pn = rx_largest + 1 (0 if none yet)
    cmp qword [rdi + linnea_quic_conn.rx_have], 0
    je .oi_ku_call
    mov r8, [rdi + linnea_quic_conn.rx_largest]
    inc r8
.oi_ku_call:
    call ku_try                      ; rax = frame bytes (or -1), rdx = pn
    cmp rax, -2
    je .oi_rsvd                      ; opened under the next key phase, bits still set
    test rax, rax
    js .done
    jmp .oi_ok
.oi_rsvd:
    ; RFC 9000 17.3.1 MUST: reserved bits set on a packet that authenticated is a
    ; connection error of type PROTOCOL_VIOLATION. No frame triggered it — the
    ; fault is in the header — and 19.19 defines the frame type 0 as exactly that
    ; case, "the value 0 is used when the frame type is unknown".
    mov edi, 0x0a                    ; PROTOCOL_VIOLATION
    xor esi, esi                     ; no frame type
    jmp .transport_close
.oi_ok:
    mov r10, rax                     ; hold the frame-byte count across the calls
    mov r11, rdx                     ; and the packet number
    ; The packet authenticated — but authentic is not the same as fresh. A 1-RTT
    ; datagram captured off the wire and replayed carries a valid AEAD tag, because
    ; it is a bit-for-bit copy of one that genuinely had one, so "only an
    ; authenticated peer can move the address" does not hold against replay. That
    ; was the whole bug: an attacker who had seen ONE datagram could resend it from
    ; a spoofed source and the connection followed them.
    ;
    ; RFC 9000 12.3: a packet number we have already processed MUST be discarded.
    ; A conforming peer never reuses a number — a retransmission carries the same
    ; frames under a new one — so this can only ever drop a duplicate or a replay,
    ; never a packet we still needed.
    CONNLEA rdi, rx_have
    mov rsi, r11
    call linnea_quic_ack_seen
    test rax, rax
    jnz .done
    ; Only the highest-numbered packet may move the peer address (RFC 9000 9.3),
    ; so a reordered older one cannot drag the connection back to an address the
    ; peer has already left. Judged BEFORE ack_record below raises the largest.
    mov rax, [cur_conn]
    cmp qword [rax + linnea_quic_conn.rx_have], 0
    je .oi_adopt                     ; the first packet is the highest there is
    mov rcx, [rax + linnea_quic_conn.rx_largest]
    cmp r11, rcx
    jbe .oi_addr_done
.oi_adopt:
    ; Only now adopt its source as the peer address, so a migrated client's replies
    ; follow it. Anti-amplification is deliberately NOT re-armed on a change: we run
    ; no PATH_CHALLENGE validation, so throttling a validated migration to 3x would
    ; wedge it. What makes that safe is freshness, checked above — not the AEAD tag
    ; alone, which a replay also satisfies.
    mov rcx, [salen]
    cmp rcx, 28
    jbe .oi_plen
    mov ecx, 28
.oi_plen:
    mov [rax + linnea_quic_conn.peer_len], rcx
    lea rdi, [rax + linnea_quic_conn.peer]
    lea rsi, [sa]
    rep movsb
.oi_addr_done:
    mov rax, r10                     ; frame-byte count
    ; note it as received, so our next packet can acknowledge it — otherwise the
    ; peer keeps retransmitting a request we have already answered
    push rax
    mov rsi, r11
    CONNLEA rdi, rx_have
    call linnea_quic_ack_record
    pop rax
    mov r14, rax                     ; frame bytes
    ; RFC 9000 12.4 MUST: a frame of unknown type is a connection error of type
    ; FRAME_ENCODING_ERROR. Judged once, here, rather than by each of the six
    ; scanners below — they disagreed about what "unknown" meant, and every one
    ; of them answered it by silently abandoning the rest of the packet.
    lea rdi, [plaintext]
    mov rsi, r14
    call linnea_quic_frames_check
    test rax, rax
    jz .frames_ok
    mov edi, 0x07                    ; FRAME_ENCODING_ERROR
    mov esi, edx                     ; the type we could not parse
    jmp .transport_close
.frames_ok:
    ; RFC 9000 4.6 MUST: a stream id past the limit we granted is a connection
    ; error of type STREAM_LIMIT_ERROR. Judged next to the frame walk above and
    ; for the same reason — once, on the whole packet, rather than by each of the
    ; scanners that go on to act on these frames. The bidirectional limit is the
    ; one this connection has been granted (it rises as streams open, see the
    ; MAX_STREAMS regrant), not the initial advertisement.
    lea rdi, [plaintext]
    mov rsi, r14
    mov rax, [cur_conn]
    mov rdx, [rax + linnea_quic_conn.ms_bidi_max]
    mov ecx, LINNEA_QUIC_MSU_INIT
    call linnea_quic_stream_limit
    test rax, rax
    jz .limits_ok
    mov edi, 0x04                    ; STREAM_LIMIT_ERROR
    mov esi, edx                     ; the frame that named the stream
    jmp .transport_close
.limits_ok:
    ; RFC 9000 13.2.1 MUST: an ack-eliciting packet has to be acknowledged. Note
    ; both whether this one is, and our packet number before any of it is acted
    ; on — comparing that number at the exit is how we tell whether anything we
    ; sent in reply already carried the acknowledgement.
    lea rdi, [plaintext]
    mov rsi, r14
    call linnea_quic_frames_ack_eliciting
    mov [s_ack_elicit], rax
    mov rax, [cur_conn]
    mov rax, [rax + linnea_quic_conn.pn_1rtt]
    mov [s_pn_before], rax
    ; ingest the peer's ACK: release every buffered packet it acknowledges, so
    ; we stop holding (and, once the PTO timer exists, retransmitting) frames
    ; that have already arrived.
    lea rdi, [plaintext]
    mov rsi, r14
    lea rdx, [ack_ranges]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges      ; rax = pairs written into ack_ranges
    test rax, rax
    js .ack_underflow                ; a range dropped below packet 0 (19.3.1)
    jz .acks_done
    ; RFC 9000 13.1: a peer must not acknowledge a packet number we have not
    ; sent. ack_ranges[8] is the largest acked; pn_1rtt is our NEXT number, so
    ; a valid largest is strictly below it. Without this a peer that acks, say,
    ; 2^62 makes tx_detect_loss below treat every in-flight chunk as lost and
    ; resend the whole table on each such ACK — a bandwidth burn that a spoofed
    ; source (the address is validated, but the ACK contents are the peer's)
    ; could aim at a third party.
    mov rcx, [cur_conn]
    mov rcx, [rcx + linnea_quic_conn.pn_1rtt]
    cmp [ack_ranges + 8], rcx
    jae .ack_violation
    ; --- round-trip measurement (RFC 9002 5.1), before anything is freed ---
    ; A sample comes only from a newly acknowledged largest: if we are still
    ; holding that packet number it has not been acknowledged before, and since a
    ; retransmission always goes out under a fresh number the measurement is
    ; unambiguous. Nothing was measured here at all until now — the probe timeout
    ; was a flat 250 ms, so any path slower than that retransmitted everything
    ; spuriously and halved its congestion window on each pass.
    push rax                          ; pair count
    push rbx                          ; ...and a second qword, so rsp stays
                                      ; 16-aligned across the calls below
    mov rdi, [cur_conn]
    mov rsi, [ack_ranges + 8]         ; largest acknowledged
    call linnea_quic_rtx_sent_ms      ; rax = when it went out, or 0
    test rax, rax
    jz .rtt_done                      ; already acked, or never ours
    mov rbx, rax
    call now_ms
    sub rax, rbx                      ; latest_rtt
    js .rtt_done                      ; a clock that went backwards: no sample
    ; The peer's Ack Delay is in units of 2^ack_delay_exponent microseconds, and
    ; RFC 9000 19.3 takes that exponent from whoever SENT the ACK — the client's
    ; advertised value, not ours (ours describes the ACKs we send). Assuming our
    ; own default 3 was right only when the client happened to default too.
    ; Subtract it only while that leaves the sample at or above the minimum seen,
    ; per RFC 9002 5.3 — a delay big enough to push it below is not credible.
    push rax                          ; latest_rtt, across the scaling call
    push rax
    mov rdi, [linnea_quic_ack_delay]
    mov rbx, [cur_conn]
    mov rsi, [rbx + linnea_quic_conn.ack_exp_peer]
    call linnea_quic_ack_delay_ms     ; rax = the peer's delay in ms
    mov rcx, rax
    pop rax
    pop rax
    mov rbx, [cur_conn]
    mov rdx, [rbx + linnea_quic_conn.max_ack_peer]
    cmp rcx, rdx
    jbe .rtt_delay_ok
    mov rcx, rdx                      ; 5.3: never more than the peer said it may delay
.rtt_delay_ok:
    mov rdi, [cur_conn]
    mov rdx, rax
    sub rdx, rcx
    js .rtt_sample                    ; would go negative: use the raw sample
    cmp rdx, [rdi + linnea_quic_conn.min_rtt]
    jb .rtt_sample
    mov rax, rdx                      ; adjusted sample
.rtt_sample:
    mov rsi, rax
    call linnea_quic_rtt_sample
.rtt_done:
    pop rbx
    pop rax                           ; pair count
    lea rbx, [ack_ranges]
    mov rbp, rax                     ; pair count
    mov qword [s_cc_acked], 0        ; response-stream bytes this ACK releases
.ack_free:
    mov rdi, [cur_conn]
    mov rsi, [rbx]                   ; smallest
    mov rdx, [rbx + 8]               ; largest
    call linnea_quic_rtx_ack_range   ; the small-reply / control loss ring
    mov rdi, [cur_conn]
    mov rsi, [rbx]
    mov rdx, [rbx + 8]
    call linnea_quic_txchunk_ack     ; the response-stream in-flight table
    add [s_cc_acked], rax
    add rbx, 16
    dec rbp
    jnz .ack_free
    ; grow the congestion window by the response-stream bytes just acknowledged
    mov rdi, [s_cc_acked]
    test rdi, rdi
    jz .ack_detect
    call cc_on_ack
    jmp .ack_detect
.ack_violation:
    mov edi, 0x0a                    ; PROTOCOL_VIOLATION (RFC 9000 20.1)
    mov esi, 0x02                    ; the ACK frame triggered it
    jmp .transport_close
.ack_underflow:
    mov edi, 0x07                    ; FRAME_ENCODING_ERROR (RFC 9000 19.3.1)
    mov esi, 0x02                    ; the malformed ACK frame
    jmp .transport_close
.ack_detect:
    ; then presume-lost and retransmit anything left far behind the largest acked
    ; (RFC 9002 6.1.1) — prompt recovery instead of waiting out the PTO backoff.
    mov rdi, [ack_ranges + 8]        ; largest acknowledged (pair 0 is the highest)
    call tx_detect_loss
.acks_done:
    ; a peer that closes cleanly gets its slot back at once instead of waiting
    ; for the idle sweep — this is what keeps rapid connection churn from
    ; filling the pool.
    lea rdi, [plaintext]
    mov rsi, r14
    call linnea_quic_close_frame
    test rax, rax
    jnz .peer_closed
    ; STOP_SENDING / RESET_STREAM: the peer cancelled streams (a browser abandons a
    ; page's downloads on reload). Tear each one down BEFORE the pump runs, so its
    ; abandoned chunks stop holding the shared congestion window — otherwise, after
    ; enough reloads, the window fills with dead chunks and the connection stalls.
    lea rdi, [plaintext]
    mov rsi, r14
    lea rdx, [reset_ids]
    mov ecx, LINNEA_QUIC_RESET_MAX
    call linnea_quic_reset_scan       ; rax = number of cancelled stream ids
    test rax, rax
    jz .no_resets
    mov rbx, rax                      ; count
    xor ebp, ebp                      ; index
.reset_loop:
    ; RFC 9114 6.2: a critical stream — the control stream and both QPACK
    ; streams — must not be closed, and a RESET_STREAM or STOP_SENDING naming
    ; one is a closure. Only a FIN was noticed, so a peer could reset the
    ; control stream and the connection carried on as though it still had one.
    mov rdi, [cur_conn]
    mov rsi, [reset_ids + rbp * 8]
    mov rax, [rdi + linnea_quic_conn.ctrl_id]
    test rax, rax
    jz .reset_chk_enc
    cmp rax, rsi
    je .reset_critical
.reset_chk_enc:
    mov rax, [rdi + linnea_quic_conn.qpack_enc_id]
    test rax, rax
    jz .reset_chk_dec
    cmp rax, rsi
    je .reset_critical
.reset_chk_dec:
    mov rax, [rdi + linnea_quic_conn.qpack_dec_id]
    test rax, rax
    jz .reset_ok
    cmp rax, rsi
    je .reset_critical
.reset_ok:
    call reset_teardown
    inc rbp
    cmp rbp, rbx
    jb .reset_loop
    jmp .reset_next
.reset_critical:
    mov edi, LINNEA_H3_ERR_CLOSED_CRITICAL
    jmp .h3_close
.reset_next:
.no_resets:
    ; PATH_CHALLENGE -> PATH_RESPONSE (RFC 9000 8.2): echo the 8 challenge bytes so a
    ; peer validating this path (e.g. after a migration) confirms our address. The
    ; peer is already committed (post-auth) to this packet's source, so it follows.
    cmp qword [linnea_quic_path_seen], 0
    je .no_pathresp
    mov byte [path_resp_pay], 0x1b
    mov rax, [linnea_quic_path_data]
    mov [path_resp_pay + 1], rax
    lea rsi, [path_resp_pay]
    mov [s_pl_ptr], rsi
    mov qword [s_pl_len], 9
    call emit_1rtt                    ; not rtx-tracked: a lost response is re-challenged
.no_pathresp:
    ; open response streams are ack-clocked and flow-controlled: the acks just
    ; ingested, plus any MAX_DATA / MAX_STREAM_DATA the peer sent as it consumed
    ; the responses, may let more chunks go out (and a fully acknowledged stream is
    ; closed out — its mapping released). Absorb the flow-control frames per active
    ; stream, then pump. Skip the walk entirely while nothing is streaming.
    ; Connection-level credit first, and unconditionally: MAX_DATA raises the window
    ; for the whole connection, and the peer sends each new value ONCE — the packet
    ; carrying it is acknowledged, so a value we fail to read is never repeated and
    ; our send window stays behind for the life of the connection. The per-stream walk
    ; below runs only while a response is open, which is exactly when a MAX_DATA can
    ; be missed: a browser reload cancels every stream, and the packets that follow
    ; carry the credit for what it just consumed with no stream left to walk. Miss
    ; enough of them and the window we believe we have is spent while the peer thinks
    ; it granted plenty — the connection then stalls with nothing in flight, and only
    ; a new connection recovers.
    mov qword [fc_scan], 0
    mov qword [fc_scan + 8], 0
    lea rdi, [plaintext]
    mov rsi, r14
    mov rdx, -1                       ; matches no stream id: MAX_STREAM_DATA is left
    lea rcx, [fc_scan]                ; to the per-stream walk, which owns the slots
    call linnea_quic_flow_scan
    mov rcx, [cur_conn]
    mov rdx, [fc_scan]                ; largest MAX_DATA in this packet
    test rdx, rdx
    jz .fc_conn_done
    mov r15, rdx                      ; dark trace: the credit and what it replaces
    mov rdi, rdx
    mov rsi, [rcx + linnea_quic_conn.fc_conn_max]
    call linnea_quic_dbg_fc
    mov rcx, [cur_conn]
    mov rdx, r15
    cmp rdx, [rcx + linnea_quic_conn.fc_conn_max]
    jbe .fc_conn_done
    mov [rcx + linnea_quic_conn.fc_conn_max], rdx
.fc_conn_done:
    mov rax, [cur_conn]
    lea rcx, [rax + linnea_quic_conn.tx_streams]
    mov edx, LINNEA_QUIC_TXSTREAMS
.fa_probe:
    cmp qword [rcx + linnea_quic_txstream.active], 0
    jne .fa_begin
    add rcx, linnea_quic_txstream_size
    dec edx
    jnz .fa_probe
    jmp .no_pump                      ; no stream active
.fa_begin:
    xor r15d, r15d                    ; stream index (preserved across flow_scan)
.fa_each:
    mov rax, [cur_conn]
    imul rdx, r15, linnea_quic_txstream_size
    lea rax, [rax + linnea_quic_conn.tx_streams]
    add rax, rdx                      ; rax = stream ctx ptr
    cmp qword [rax + linnea_quic_txstream.active], 0
    je .fa_next
    mov qword [fc_scan], 0
    mov qword [fc_scan + 8], 0
    mov rdx, [rax + linnea_quic_txstream.sid]
    lea rdi, [plaintext]
    mov rsi, r14
    lea rcx, [fc_scan]
    call linnea_quic_flow_scan
    mov rax, [cur_conn]               ; recompute ctx ptr (the call clobbered rax)
    imul rdx, r15, linnea_quic_txstream_size
    lea rax, [rax + linnea_quic_conn.tx_streams]
    add rax, rdx
    mov rcx, [cur_conn]
    mov rdx, [fc_scan]                ; largest MAX_DATA seen (connection-wide)
    cmp rdx, [rcx + linnea_quic_conn.fc_conn_max]
    jbe .fa_no_conn
    mov [rcx + linnea_quic_conn.fc_conn_max], rdx
.fa_no_conn:
    mov rdx, [fc_scan + 8]            ; largest MAX_STREAM_DATA for this stream
    cmp rdx, [rax + linnea_quic_txstream.fc_max]
    jbe .fa_next
    mov [rax + linnea_quic_txstream.fc_max], rdx
.fa_next:
    inc r15d
    cmp r15d, LINNEA_QUIC_TXSTREAMS
    jb .fa_each
    call tx_pump
.no_pump:
    lea r15, [plaintext + r14]       ; end of the frames
    lea r14, [plaintext]             ; scan cursor
.stream_scan:
    cmp r14, r15
    jae .rtt_finish
    mov rdi, r14
    mov rsi, r15
    sub rsi, r14
    call linnea_quic_stream_frame    ; rax=data, rdx=len, r8=stream id, r9=next
    test rax, rax
    jz .rtt_finish                   ; no further STREAM frames
    mov r14, r9                      ; resume point for the next frame
    mov [s_sid], r8
    mov [s_sdata], rax
    mov [s_slen], rdx
    mov [s_soff], r10                ; data offset, for typing a uni stream
    mov [s_sfin], r11                ; FIN flag, for the critical-stream check
    ; connection-level receive flow control (quic-9): count the bytes and, when a
    ; fresh grant would advance the ceiling by at least FC_GRANT_MIN, queue a
    ; MAX_DATA so the peer never stalls on initial_max_data. The count is loose
    ; (a retransmit is double-counted) but that only grants sooner, which is safe.
    mov rax, [cur_conn]
    add [rax + linnea_quic_conn.fc_recv], rdx
    mov rcx, [rax + linnea_quic_conn.fc_recv]
    add rcx, LINNEA_QUIC_FC_WINDOW
    sub rcx, [rax + linnea_quic_conn.fc_adv]
    cmp rcx, LINNEA_QUIC_FC_GRANT_MIN
    jb .fc_recv_done
    mov rcx, [rax + linnea_quic_conn.fc_recv]
    add rcx, LINNEA_QUIC_FC_WINDOW
    mov [rax + linnea_quic_conn.fc_adv], rcx
    mov qword [rax + linnea_quic_conn.fc_pending], 1
.fc_recv_done:
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
    ; find a context already reassembling this stream (a continuing frame)
    mov rax, [cur_conn]
    lea rax, [rax + linnea_quic_conn.ra_ctx]
    mov rdx, LINNEA_QUIC_RA_CTXS
    mov rcx, [s_sid]
.cb_find:
    cmp qword [rax + linnea_quic_ra.active], 0
    je .cb_find_next
    cmp qword [rax + linnea_quic_ra.sid], rcx
    je .ra_have                      ; rax = this stream's context: buffer into it
.cb_find_next:
    add rax, linnea_quic_ra_size
    dec rdx
    jnz .cb_find
    ; nothing is reassembling this stream. A whole request in one frame (offset 0
    ; with FIN) is served straight from the packet; anything else needs reassembly.
    cmp qword [s_soff], 0
    jne .ra_alloc                    ; not at offset 0: earlier bytes came elsewhere
    cmp qword [s_sfin], 0
    je .ra_alloc                     ; no FIN: more frames follow
    jmp .serve_bidi                  ; the whole request is here: serve it directly

; reassemble the request stream into a context's buffer, at each frame's offset.
.ra_alloc:
    mov rax, [cur_conn]
    lea rax, [rax + linnea_quic_conn.ra_ctx]
    mov rdx, LINNEA_QUIC_RA_CTXS
.ra_alloc_find:
    cmp qword [rax + linnea_quic_ra.active], 0
    je .ra_start                     ; rax = a free context
    add rax, linnea_quic_ra_size
    dec rdx
    jnz .ra_alloc_find
    jmp .stream_scan                 ; every context busy (a very deep burst): drop
.ra_start:
    mov qword [rax + linnea_quic_ra.active], 1
    mov rdx, [s_sid]
    mov [rax + linnea_quic_ra.sid], rdx
    mov qword [rax + linnea_quic_ra.len], 0
    mov qword [rax + linnea_quic_ra.fin], 0
    ; clear the seen-map up to the previous run's high-water, then reset it
    ; (one bit per stream byte, so round the high-water up to whole bytes)
    mov rcx, [rax + linnea_quic_ra.hi]
    add rcx, 7
    shr rcx, 3
    lea rdi, [rax + linnea_quic_ra.seen]
    push rax                                   ; xor al clobbers rax's low byte
    xor al, al
    rep stosb
    pop rax
    mov qword [rax + linnea_quic_ra.hi], 0
.ra_have:
    ; place the frame at its offset (out-of-order frames are buffered, not
    ; dropped) and record the bytes as seen; the contiguous prefix advances below.
    ; rax is this stream's reassembly context throughout.
    mov r9, [s_soff]                           ; offset
    mov r10, [s_slen]                          ; length
    mov r11, r9
    add r11, r10                               ; frame end = offset + len
    cmp r11, LINNEA_QUIC_RA_BUF
    ja .ra_drop                                ; past the buffer: request too large
    test r10, r10
    jz .ra_hi_upd                              ; empty frame (e.g. a lone FIN)
    lea rdi, [rax + linnea_quic_ra.buf]
    add rdi, r9                                ; dest = buf + offset
    mov rsi, [s_sdata]
    mov rcx, r10
    rep movsb                                  ; copy the frame's bytes (rax intact)
    lea rdi, [rax + linnea_quic_ra.seen]       ; mark those bytes seen. bts takes
    mov rsi, r9                                ; a bit offset that may run past the
    mov rcx, r10                               ; operand, so it addresses the whole
.ra_mark:                                      ; map from one base
    bts [rdi], rsi
    inc rsi
    dec rcx
    jnz .ra_mark
.ra_hi_upd:
    mov r10, [rax + linnea_quic_ra.hi]
    cmp r11, r10
    jbe .ra_advance
    mov [rax + linnea_quic_ra.hi], r11
    mov r10, r11                               ; r10 = hi
.ra_advance:
    ; advance the contiguous prefix while the next byte has been seen
    mov r8, [rax + linnea_quic_ra.len]
    lea rdi, [rax + linnea_quic_ra.seen]
.ra_adv_loop:
    cmp r8, r10                                ; reached the high-water?
    jae .ra_adv_done
    bt [rdi], r8
    jnc .ra_adv_done                           ; a gap: stop here
    inc r8
    jmp .ra_adv_loop
.ra_adv_done:
    mov [rax + linnea_quic_ra.len], r8
    cmp qword [s_sfin], 0
    je .ra_donecheck
    mov qword [rax + linnea_quic_ra.fin], 1
    mov r10, [s_soff]
    add r10, [s_slen]
    mov [rax + linnea_quic_ra.final], r10
.ra_donecheck:
    cmp qword [rax + linnea_quic_ra.fin], 0
    je .ra_more
    mov r10, [rax + linnea_quic_ra.len]
    cmp r10, [rax + linnea_quic_ra.final]
    jb .ra_more                                ; a gap remains before the end
    ; complete: serve the reassembled request from the context's buffer
    lea r10, [rax + linnea_quic_ra.buf]
    mov [s_sdata], r10
    mov r10, [rax + linnea_quic_ra.len]
    mov [s_slen], r10
    mov qword [rax + linnea_quic_ra.active], 0
    jmp .serve_bidi
.ra_drop:
    mov qword [rax + linnea_quic_ra.active], 0  ; abandon the over-long stream
    ; the peer sent more stream data than the window we advertised
    ; (initial_max_stream_data_bidi_remote == the reassembly buffer): a flow-control
    ; violation, so close the connection (RFC 9000 4.1: FLOW_CONTROL_ERROR = 0x03).
    mov edi, 0x03                               ; FLOW_CONTROL_ERROR
    mov esi, 0x08                               ; a STREAM frame triggered it
    jmp .transport_close
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
    ; Already answering this stream? Then this is a RETRANSMITTED request: the peer
    ; resent it because our ack of the original was lost (which happens exactly
    ; during a loss burst). Serving it again would open a second response slot for
    ; the same stream — a duplicate that resends the whole body and pins the shared
    ; congestion window, wedging the connection (observed with a real browser: the
    ; same sid held two slots, one stuck fully-sent-but-unacked). Instead ack it via
    ; the bare-ACK path so the peer stops retransmitting, and do not re-serve. The
    ; packet is already recorded in rx_have (at .exp_pn_ready), so the ack covers it.
    mov rax, [cur_conn]
    lea rax, [rax + linnea_quic_conn.tx_streams]
    mov rdx, LINNEA_QUIC_TXSTREAMS
    mov rcx, [s_sid]
.sb_dup:
    cmp qword [rax + linnea_quic_txstream.active], 0
    je .sb_dup_next
    cmp qword [rax + linnea_quic_txstream.sid], rcx
    je .ra_more                      ; a response is already open for this stream
.sb_dup_next:
    add rax, linnea_quic_txstream_size
    dec rdx
    jnz .sb_dup
    ; a stream the peer has cancelled gets no response: serving it would open
    ; a slot that can never drain (its window will never be raised)
    mov rax, [cur_conn]
    xor ecx, ecx
    mov rdx, [s_sid]
    inc rdx                           ; ids are stored as id + 1
.rst_seen_scan:
    cmp [rax + linnea_quic_conn.rst_ids + rcx * 8], rdx
    je .stream_scan
    inc ecx
    cmp ecx, LINNEA_QUIC_RST_SEEN
    jb .rst_seen_scan
    mov rdi, [s_sid]
    call linnea_quic_dbg_serve
    ; zero the request struct and point the QPACK scratch at h3scratch
    lea rdi, [req]
    xor eax, eax
    mov ecx, linnea_h2_req_size
    rep stosb
    lea rax, [h3scratch]
    mov [req + linnea_h2_req.scratch], rax
    lea rax, [h3scratch + LINNEA_HPACK_MAX_LISTSIZE]
    mov [req + linnea_h2_req.scratch_end], rax
    ; Arm the header rebuild emit_field already performs for h2: with hb_start
    ; set, every forwardable field is appended as an h1 "name: value" line,
    ; hop-by-hop and managed names stripped. h3 never set it, which is why a
    ; proxied h3 request had nowhere to keep a header the request struct has no
    ; field for -- an X-Filename or an Authorization simply had no way through.
    lea rax, [h3_hdrs_buf]
    mov [req + linnea_h2_req.hb_start], rax
    mov [req + linnea_h2_req.hb_cur], rax
    lea rax, [h3_hdrs_buf + LINNEA_H3_HDRS_BUF]
    mov [req + linnea_h2_req.hb_end], rax
    ; parse the HTTP/3 request (HEADERS frame -> QPACK decode)
    mov rdi, [s_sdata]
    mov rsi, [s_slen]
    lea rdx, [req]
    call linnea_h3_read_headers      ; r8 = body ptr, r9 = body len on success
    test rax, rax
    jz .req_ok
    ; An undecodable field section is a CONNECTION error (RFC 9204 2.2.1):
    ; the encoder's table state and ours have diverged, so every later
    ; request on this connection would fail too — say so instead of leaving
    ; the client waiting on a stream we silently dropped.
    cmp rax, -LINNEA_H3_ERR_TOOLARGE
    je .req_toolarge
    cmp rax, -LINNEA_H3_ERR_QPACK
    je .req_qpack_bad
    cmp rax, -LINNEA_H3_ERR_UNEXPECTED
    je .req_frame_unexpected
    ; the last frame on a cleanly terminated stream was cut short (7.1)
    cmp rax, -LINNEA_H3_ERR_TRUNCATED
    je .req_truncated
    ; the stream ended without a HEADERS frame at all, so there was never enough
    ; of a message to answer: 4.1 asks for H3_REQUEST_INCOMPLETE, which tells the
    ; client the request may be retried. H3_MESSAGE_ERROR — what this used to
    ; send — says the opposite, that the request itself was at fault.
    cmp rax, -LINNEA_H3_ERR_NOHEADERS
    je .req_incomplete
    ; Anything else is a malformed request: a truncated frame, or no HEADERS at
    ; all. Both entries to .serve_bidi require the FIN, so the stream is whole
    ; and nothing more is coming — dropping it here left the client waiting on
    ; a request that would never be answered. Reset the stream instead.
    ;
    ; Final Size is ours, not the peer's (RFC 9000 19.4): it is "the final size
    ; of the stream by the RESET_STREAM sender", and on a client-initiated
    ; bidirectional stream our RESET_STREAM ends only the server-to-client
    ; direction. This used to send the length of the CLIENT's request, on the
    ; reasoning that the reset settles the credit those bytes hold — but that is
    ; the receive direction, which a reset of our own sending direction does not
    ; touch. The peer then charged its connection-level window up to 8 KB for
    ; data it would never be sent, on every malformed request, and a client whose
    ; initial_max_stream_data_bidi_remote sits below that MUST close the
    ; connection with FLOW_CONTROL_ERROR (4.5). No response is open here — the
    ; duplicate guard above has already sent that case elsewhere — so nothing has
    ; gone out this way and the true final size is zero.
    mov rdi, [s_sid]
    xor esi, esi                     ; nothing was sent in the direction we reset
    mov edx, LINNEA_H3_ERR_MESSAGE   ; the request decoded but breaks a rule
    call tx_reset_stream_code
    jmp .stream_scan
.req_incomplete:
    mov rdi, [s_sid]
    xor esi, esi                     ; nothing was sent in the direction we reset
    mov edx, LINNEA_H3_ERR_REQ_INCOMPLETE
    call tx_reset_stream_code
    jmp .stream_scan
.req_truncated:
    mov edi, LINNEA_H3_ERR_FRAME
    jmp .h3_close
.req_qpack_bad:
    mov edi, LINNEA_H3_ERR_QPACK_DECOMP
    jmp .h3_close
.req_frame_unexpected:
    ; a frame illegal on a request stream — a connection error, not a stream one
    mov edi, LINNEA_H3_ERR_FRAME_UNEXPECTED
    jmp .h3_close
.misdirected:
    ; the access line names the vhost that DID answer — this connection's own,
    ; since the serve block that normally sets it is skipped below
    mov rax, [cur_conn]
    mov rax, [rax + linnea_quic_conn.vhost]
    call vhost_slot
    mov r10, [rax + linnea_quic_vhost.host_ptr]
    mov [linnea_log_acc_host], r10
    mov r10, [rax + linnea_quic_vhost.host_len]
    mov [linnea_log_acc_host_len], r10
    ; RFC 9110 7.4 / RFC 9114 4.3.1: this connection cannot speak for the
    ; authority the request names — its certificate covers a different site.
    ; 421 is the answer that tells the client to try a fresh connection,
    ; where the right certificate can be presented.
    lea rdi, [strm_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack       ; the ack must precede the STREAM frame
    mov [s_acklen], rax
    mov rcx, rax
    mov byte [strm_pay + rcx], 0x09  ; STREAM | FIN
    lea rdi, [strm_pay + rcx + 1]
    mov rsi, [s_sid]
    call linnea_quic_varint_encode
    mov rbx, [s_acklen]
    add rbx, rax
    inc rbx
    lea rdi, [strm_pay + rbx]
    call linnea_h3_build_421         ; rax = response length
    lea rdx, [rax + rbx]             ; STREAM frame length
    lea rsi, [strm_pay]
    call .send_1rtt
    jmp .stream_scan

.req_toolarge:
    ; The header section decoded but is bigger than we hold. That is our limit,
    ; not a protocol violation, so it is answered on this stream (RFC 9114
    ; 4.2.2) — a connection error here would take every other request with it,
    ; and a client waiting only on its own response would see nothing at all.
    ; The request never parsed, so there is no path or vhost: a bare 431.
    ; The access line still names the peer; method, target and host print "-".
    CONNLEA rdi, peer
    lea rsi, [acc_peer_buf]
    call linnea_network_addr_format
    mov [linnea_log_acc_peer_len], rax
    lea rax, [acc_peer_buf]
    mov [linnea_log_acc_peer], rax
    xor eax, eax
    mov [linnea_log_acc_meth], rax
    mov [linnea_log_acc_tgt], rax
    mov [linnea_log_acc_host], rax
    lea rdi, [strm_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack       ; the ack must precede the STREAM frame
    mov [s_acklen], rax
    mov rcx, rax
    mov byte [strm_pay + rcx], 0x09  ; STREAM | FIN
    lea rdi, [strm_pay + rcx + 1]
    mov rsi, [s_sid]
    call linnea_quic_varint_encode
    mov rbx, [s_acklen]
    add rbx, rax
    inc rbx                          ; bytes before the HTTP/3 response
    lea rdi, [strm_pay + rbx]
    call linnea_h3_build_431         ; rax = response length
    lea rdx, [rax + rbx]             ; STREAM frame length
    lea rsi, [strm_pay]
    call .send_1rtt
    jmp .stream_scan
.req_ok:
    ; Draining: the GOAWAY promised that streams at or above h3_goaway_id would
    ; not be processed (RFC 9114 5.2), so serving one anyway means the client
    ; may see the same request run twice — here and on the connection it retried
    ; on. Reject it with H3_REQUEST_REJECTED, the code 5.2 names as telling the
    ; client the request was not processed and may be retried. Below the id the
    ; request is one the GOAWAY promised TO finish, so it is served as ever.
    cmp dword [linnea_quic_draining], 0
    je .req_owned
    mov rax, [cur_conn]
    mov rdx, [s_sid]
    cmp rdx, [rax + linnea_quic_conn.h3_goaway_id]
    jb .req_owned
    mov rdi, [s_sid]
    xor esi, esi                     ; nothing was sent in the direction we reset
    mov edx, LINNEA_H3_ERR_REQ_REJECTED
    call tx_reset_stream_code
    jmp .stream_scan
.req_owned:
    mov [s_body_ptr], r8             ; keep the body across the response build
    mov [s_body_len], r9
    ; the access line's who-and-what: peer text, method, target. The vhost's
    ; name is set below with the other per-vhost fields; the status and byte
    ; count ride linnea_h3_build_headers, which every response passes through.
    CONNLEA rdi, peer
    lea rsi, [acc_peer_buf]
    call linnea_network_addr_format
    mov [linnea_log_acc_peer_len], rax
    lea rax, [acc_peer_buf]
    mov [linnea_log_acc_peer], rax
    mov rax, [req + linnea_h2_req.method_ptr]
    mov [linnea_log_acc_meth], rax
    mov rax, [req + linnea_h2_req.method_len]
    mov [linnea_log_acc_meth_len], rax
    mov rax, [req + linnea_h2_req.path_ptr]
    mov [linnea_log_acc_tgt], rax
    mov rax, [req + linnea_h2_req.path_len]
    mov [linnea_log_acc_tgt_len], rax
    ; record it for a graceful GOAWAY: a drain rejects streams past this one, so
    ; the client knows exactly what it must retry elsewhere
    mov rax, [cur_conn]
    mov rdx, [s_sid]
    add rdx, 4                       ; the next client bidi stream id
    cmp rdx, [rax + linnea_quic_conn.h3_goaway_id]
    jbe .no_goaway_bump
    mov [rax + linnea_quic_conn.h3_goaway_id], rdx
.no_goaway_bump:
    ; Raise the peer's bidi-stream limit as it opens streams (RFC 9000 19.11), so a
    ; reused connection never runs out. ordinal = the count of client bidi streams
    ; opened so far (client bidi ids are 0,4,8,... = 4*(n-1)); when it comes within
    ; MS_THRESH of what we have granted, grant a fresh window ahead and tell the
    ; peer with a MAX_STREAMS frame (sent reliably, ahead of the response packet).
    mov rax, [cur_conn]
    mov rdx, [s_sid]
    shr rdx, 2
    inc rdx                          ; ordinal (streams opened so far)
    mov rcx, rdx
    add rcx, LINNEA_QUIC_MS_THRESH
    cmp rcx, [rax + linnea_quic_conn.ms_bidi_max]
    jb .no_maxstreams
    add rdx, LINNEA_QUIC_MS_WINDOW    ; new granted limit
    mov [rax + linnea_quic_conn.ms_bidi_max], rdx
    mov byte [maxstreams_pay], 0x12   ; MAX_STREAMS (bidirectional)
    lea rdi, [maxstreams_pay + 1]
    mov rsi, rdx
    call linnea_quic_varint_encode    ; rax = varint length
    lea rsi, [maxstreams_pay]
    lea rdx, [rax + 1]                ; frame length = type byte + varint
    call .send_1rtt                   ; sent and buffered for loss recovery
.no_maxstreams:
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
    ; Which vhost serves this request? Until Q124 it was always the one the
    ; TLS SNI chose, so a request explicitly addressed to another site we host
    ; was silently answered with this one's content. Now :authority decides —
    ; but only among the names this connection's certificate actually covers.
    ; A name belonging to a vhost with a DIFFERENT certificate is not ours to
    ; answer on this connection: RFC 9114 4.3.1 / RFC 9110 7.4 make that a 421,
    ; which tells the client to open a new connection instead of failing. A
    ; name we do not host at all (an IP literal, an alias) keeps the old
    ; behaviour and is served by the connection's own vhost.
    mov r10, [cur_conn]
    mov r10, [r10 + linnea_quic_conn.vhost]
    mov [s_serve_vhost], r10
    push rcx
    push rdi
    mov rdi, [req + linnea_h2_req.auth_ptr]
    mov rsi, [req + linnea_h2_req.auth_len]
    call authority_vhost             ; rax = vhost index, or -1 if not ours
    pop rdi
    pop rcx
    cmp rax, -1
    je .h3_vhost_ready               ; a name we do not host: as before
    mov r10, [cur_conn]
    mov r10, [r10 + linnea_quic_conn.vhost]
    cmp rax, r10
    je .h3_vhost_ready               ; the connection's own vhost
    push rcx
    push rdi
    push rax
    mov rdi, rax
    mov rsi, r10
    call vhost_same_cert
    pop r10                          ; the requested vhost index
    pop rdi
    pop rcx
    test eax, eax
    jz .misdirected                  ; another site, another certificate: 421
    mov [s_serve_vhost], r10         ; same certificate: we are authoritative
.h3_vhost_ready:
    mov rax, [s_serve_vhost]
    call vhost_slot
    mov r10, [rax + linnea_quic_vhost.host_ptr]
    mov [linnea_log_acc_host], r10
    mov r10, [rax + linnea_quic_vhost.host_len]
    mov [linnea_log_acc_host_len], r10
    mov rsi, [rax + linnea_quic_vhost.root_ptr]
    mov rdx, [rax + linnea_quic_vhost.root_len]
    mov r10, [rax + linnea_quic_vhost.srv]   ; route this request on its own
    mov [linnea_h3_srv], r10                 ; vhost, not on the registered root
    ; this vhost's Cache-Control for the QPACK encoder (ptr 0 = none)
    mov r10, [rax + linnea_quic_vhost.cc_len]
    mov [linnea_qpack_ccontrol_len], r10
    mov r11, [rax + linnea_quic_vhost.cc_ptr]
    test r10, r10
    jnz .h3_cc_set
    xor r11d, r11d
.h3_cc_set:
    mov [linnea_qpack_ccontrol_ptr], r11
    ; this vhost's security headers, for the encoder
    mov r10, [rax + linnea_quic_vhost.hsts_len]
    mov [linnea_qpack_hsts_len], r10
    mov r11, [rax + linnea_quic_vhost.hsts_ptr]
    test r10, r10
    jnz .h3_hsts_set
    xor r11d, r11d
.h3_hsts_set:
    mov [linnea_qpack_hsts_ptr], r11
    mov r10, [rax + linnea_quic_vhost.nosniff]
    mov [linnea_qpack_nosniff], r10
    mov r8, [s_body_ptr]             ; the request body, for a POST echo
    mov r9, [s_body_len]
    ; may we start a chunked response? Yes while any of the LINNEA_QUIC_TXSTREAMS
    ; response-stream slots is free — they stream concurrently, interleaved by the
    ; pump. Only when every slot is busy is a large request refused with a 503
    ; (retryable). A large body otherwise streams within the client's flow-control
    ; window, which the pump enforces, growing it from MAX_STREAM_DATA / MAX_DATA.
    ; NB: rcx (head dest), rdx (docroot len), r8/r9 (body) are live arguments to
    ; linnea_h3_serve — scan for a free slot using only rax/r10/r11.
    mov r10, [cur_conn]
    lea r10, [r10 + linnea_quic_conn.tx_streams]
    mov eax, LINNEA_QUIC_TXSTREAMS
    xor r11d, r11d
.tx_cap_scan:
    cmp qword [r10 + linnea_quic_txstream.active], 0
    jne .tx_cap_busy
    mov r11d, 1                      ; a slot is free
    jmp .tx_cap_set
.tx_cap_busy:
    add r10, linnea_quic_txstream_size
    dec eax
    jnz .tx_cap_scan
.tx_cap_set:
    mov [linnea_h3_tx_cap], r11
    ; who the answer is owed to, for a request that turns out to be proxied:
    ; the connection's slot, the connection ID that authenticates this
    ; incarnation of it, and the stream
    mov r10, [cur_conn]
    mov r11, [r10 + linnea_quic_conn.scid]
    mov [linnea_h3_owner_gen], r11
    movzx r11d, byte [r10 + linnea_quic_conn.scid + 1]  ; the id carries the
    mov [linnea_h3_owner_idx], r11                      ; pool index in byte 1
    mov r11, [s_sid]
    mov [linnea_h3_owner_sid], r11
    call linnea_h3_serve             ; rax = h3 response length (or the head's);
                                     ; r9 != 0: chunked — r8/r9 = file mapping;
                                     ; rax = -1: proxied, and parked
    cmp rax, -1
    je .serve_parked
    test r9, r9
    jnz .serve_large
    lea rdx, [rax + rbx]             ; STREAM frame length
    lea rsi, [strm_pay]
    call .send_1rtt
    jmp .stream_scan
.serve_large:
    ; the response is a stream, not a packet: place its head and file mapping in a
    ; free response-stream slot and let the pump send it — chunk by chunk, shared
    ; congestion- and flow-controlled, scheduled against the other open streams by
    ; priority. The head (HEADERS frame + DATA frame header, rax bytes at strm_pay +
    ; rbx) is bounded by LINNEA_H3_HEAD_MAX, which fits the slot's hdr. tx_cap
    ; guaranteed a free slot when it let linnea_h3_serve return a chunked response.
    ; The head has to fit the slot's hdr, which is the struct's last field — an
    ; over-long one would run straight into the next slot's .active/.base/.size
    ; and have the pump read and later munmap attacker-influenced addresses. The
    ; buffers are sized for the worst response any legal config can produce, so
    ; this is a backstop: drop the mapping and reset the stream instead.
    cmp rax, LINNEA_QUIC_TX_HDR
    ja .sl_toolong
    ; First resolve the client's RFC 9218 priority (default urgency 3, non-
    ; incremental), before the serve registers are reused for the slot fill.
    mov qword [s_prio_u], 3
    mov qword [s_prio_i], 0
    mov r10, [req + linnea_h2_req.prio_ptr]
    test r10, r10
    jz .sl_prio_pending               ; no header, but an update may still await
    push rax                          ; head length
    push rbx                          ; head offset in strm_pay
    push r8                           ; file base
    push r9                           ; file size (4 pushes: 16-aligned for the call)
    mov rdi, r10
    mov rsi, [req + linnea_h2_req.prio_len]
    call linnea_quic_parse_priority   ; rax = urgency, rdx = incremental
    mov [s_prio_u], rax
    mov [s_prio_i], rdx
    pop r9
    pop r8
    pop rbx
    pop rax
.sl_prio_pending:
    call .pu_take
.sl_find:
    mov rcx, [cur_conn]
    lea rdx, [rcx + linnea_quic_conn.tx_streams]
    mov r10d, LINNEA_QUIC_TXSTREAMS
.sl_scan:
    cmp qword [rdx + linnea_quic_txstream.active], 0
    je .sl_found
    add rdx, linnea_quic_txstream_size
    dec r10d
    jnz .sl_scan
    jmp .stream_scan                 ; no free slot (unreachable: tx_cap ensured one)
.sl_found:
    mov [rdx + linnea_quic_txstream.base], r8
    mov [rdx + linnea_quic_txstream.size], r9
    mov r10, [linnea_h3_body_off]     ; the slice the serve chose (a 206's
    mov [rdx + linnea_quic_txstream.foff], r10   ; range, or 0 / the whole file)
    mov r10, [linnea_h3_body_len]
    mov [rdx + linnea_quic_txstream.flen], r10
    mov [rdx + linnea_quic_txstream.hlen], rax
    mov r10, [s_sid]
    mov [rdx + linnea_quic_txstream.sid], r10
    mov qword [rdx + linnea_quic_txstream.off], 0
    mov qword [rdx + linnea_quic_txstream.inflight], 0
    mov r10, [rcx + linnea_quic_conn.fc_stream_init]   ; this stream's own window
    mov [rdx + linnea_quic_txstream.fc_max], r10
    mov r10, [s_prio_u]                                 ; the client's priority signal
    mov [rdx + linnea_quic_txstream.urgency], r10
    mov r10, [s_prio_i]
    mov [rdx + linnea_quic_txstream.incremental], r10
    mov qword [rdx + linnea_quic_txstream.active], 1
    lea rsi, [strm_pay + rbx]
    lea rdi, [rdx + linnea_quic_txstream.hdr]
    mov rcx, rax
    rep movsb
    call tx_pump
    jmp .stream_scan
.sl_toolong:
    mov rdi, r8                       ; release the response's file mapping
    mov rsi, r9
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov rdi, [s_sid]
    xor esi, esi                      ; nothing of the body was sent
    call tx_reset_stream
    jmp .stream_scan

.serve_parked:
    ; The request went to a proxy upstream and its answer will arrive on an
    ; io_uring completion. Claim a response-stream slot for it NOW, marked
    ; pending: it is what a retransmitted request finds instead of being served
    ; a second time, what a cancel frees, and what the answer fills in when it
    ; comes. The priority the client signalled is resolved here too, while the
    ; request is still in hand, so the answer is scheduled against the
    ; connection's other streams the moment it arrives.
    mov qword [s_prio_u], 3           ; the RFC 9218 default: urgency 3,
    mov qword [s_prio_i], 0           ; non-incremental
    mov rdi, [req + linnea_h2_req.prio_ptr]
    test rdi, rdi
    jz .sp_prio_pending
    mov rsi, [req + linnea_h2_req.prio_len]
    call linnea_quic_parse_priority   ; rax = urgency, rdx = incremental
    mov [s_prio_u], rax
    mov [s_prio_i], rdx
.sp_prio_pending:
    call .pu_take
    mov rcx, [cur_conn]
    lea rdx, [rcx + linnea_quic_conn.tx_streams]
    mov r10d, LINNEA_QUIC_TXSTREAMS
.sp_scan:
    cmp qword [rdx + linnea_quic_txstream.active], 0
    je .sp_found
    add rdx, linnea_quic_txstream_size
    dec r10d
    jnz .sp_scan
    ; No slot, which tx_cap only fails to notice when every one is busy — the
    ; same condition a large static response answers 503 to. Nothing is parked,
    ; so the leg's answer will find no slot and be dropped; reset the stream so
    ; the client learns now rather than waiting for a response we cannot place.
    mov rdi, [s_sid]
    xor esi, esi
    mov edx, LINNEA_H3_ERR_REQ_REJECTED   ; not processed by us: safe to retry
    call tx_reset_stream_code
    jmp .stream_scan
.sp_found:
    mov qword [rdx + linnea_quic_txstream.base], 0
    mov qword [rdx + linnea_quic_txstream.size], 0
    mov qword [rdx + linnea_quic_txstream.foff], 0
    mov qword [rdx + linnea_quic_txstream.flen], 0
    mov qword [rdx + linnea_quic_txstream.hlen], 0
    mov r10, [s_sid]
    mov [rdx + linnea_quic_txstream.sid], r10
    mov qword [rdx + linnea_quic_txstream.off], 0
    mov qword [rdx + linnea_quic_txstream.inflight], 0
    mov r10, [rcx + linnea_quic_conn.fc_stream_init]
    mov [rdx + linnea_quic_txstream.fc_max], r10
    mov r10, [s_prio_u]
    mov [rdx + linnea_quic_txstream.urgency], r10
    mov r10, [s_prio_i]
    mov [rdx + linnea_quic_txstream.incremental], r10
    mov qword [rdx + linnea_quic_txstream.pending], 1
    mov qword [rdx + linnea_quic_txstream.active], 1
    ; Nothing goes out on this stream now, but the request packet still has to
    ; be acknowledged: the peer would otherwise retransmit it for as long as the
    ; backend takes to answer.
    lea rdi, [strm_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack
    test rax, rax
    jz .stream_scan
    lea rsi, [strm_pay]
    mov [s_pl_ptr], rsi
    mov [s_pl_len], rax
    call emit_1rtt
    jmp .stream_scan

; .pu_take — a PRIORITY_UPDATE that overtook the request on [s_sid] wins over
; the priority header it came with: the header is what the request was born
; with, the update is the client changing its mind afterwards (RFC 9218 7).
; Applies it to s_prio_u / s_prio_i and consumes the entry — it has done its
; job, and leaving it would re-apply to a later stream that happened to reuse
; the id, which cannot occur but costs nothing to rule out. Touches no register
; the two slot-filling paths keep live.
.pu_take:
    push rax
    push rcx
    push rdx
    push r10
    mov r10, [cur_conn]
    mov rdx, [s_sid]
    inc rdx                           ; stored as id + 1
    xor ecx, ecx
.pt_scan:
    cmp [r10 + linnea_quic_conn.pu_sid + rcx * 8], rdx
    je .pt_hit
    inc ecx
    cmp ecx, LINNEA_QUIC_PU_PEND
    jb .pt_scan
    jmp .pt_done
.pt_hit:
    mov qword [r10 + linnea_quic_conn.pu_sid + rcx * 8], 0
    mov rax, [r10 + linnea_quic_conn.pu_val + rcx * 8]
    mov rdx, rax
    and rdx, 0xff
    mov [s_prio_u], rdx
    shr rax, 8
    mov [s_prio_i], rax
.pt_done:
    pop r10
    pop rdx
    pop rcx
    pop rax
    ret

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
    cmp cl, LINNEA_H3_STREAM_PUSH
    je .uni_push                     ; a push stream, from a client
    call .uni_ro_drop                ; typed now, and not the control stream
    jmp .stream_scan                 ; grease/unknown: not interpreted
.uni_push:
    ; only a server pushes, so a client-opened push stream is a connection error
    ; H3_STREAM_CREATION_ERROR (RFC 9114 6.2.2). We never push at all.
    mov edi, LINNEA_H3_ERR_STREAM_CREATION
    jmp .h3_close
.uni_qpack:
    cmp qword [s_sfin], 0
    jne .uni_critical_closed         ; a QPACK stream must not be closed
    ; Remember which stream this is, so a reset of it can be recognised later.
    ; Nothing here reads the stream's contents — our QPACK capacity is 0, so a
    ; conforming encoder sends none — but 6.2 forbids closing it by any means,
    ; and a RESET_STREAM is a closure the FIN test above never sees.
    mov rdx, [cur_conn]
    mov rax, [s_sid]
    cmp cl, LINNEA_H3_STREAM_QPACK_ENC
    jne .uni_qpack_dec
    mov [rdx + linnea_quic_conn.qpack_enc_id], rax
    ; Police what the stream carries (h3-8): the instructions were never read,
    ; so an encoder inserting into — or sizing — the dynamic table we refused
    ; was told nothing, and its table state and ours silently diverged.
    call .qpack_enc_scan_all         ; this frame's bytes + any held segment
    mov ecx, eax                     ; the verdict, across the drop's clobbers
    call .uni_ro_drop                ; typed now, and not the control stream
    test ecx, ecx
    jnz .uni_qpack_enc_bad
    jmp .stream_scan
.uni_qpack_dec:
    mov [rdx + linnea_quic_conn.qpack_dec_id], rax
    call .uni_ro_drop                ; typed now, and not the control stream
    jmp .stream_scan                 ; otherwise nothing to read (zero table)
.uni_cont:
    ; a continuation: the control stream's closure and frame walk, the QPACK
    ; streams' closure and (encoder-side) instruction policing, and — when no
    ; control stream is known yet — bytes held for a stream whose type frame
    ; is the late one.
    mov rdx, [cur_conn]
    mov rax, [rdx + linnea_quic_conn.ctrl_id]
    test rax, rax
    jz .uni_cont_qpackq              ; no control stream yet: qpack, or untyped
    cmp rax, [s_sid]
    jne .uni_cont_qpackq
    cmp qword [s_sfin], 0
    jne .uni_critical_closed
    jmp .uni_ctrl_walk               ; more control-stream frames to walk
.uni_cont_qpackq:
    ; a QPACK stream's continuation: a FIN here closes a critical stream just
    ; as surely as one on the typing frame (RFC 9114 6.2 — "by any means"),
    ; and the encoder stream's bytes are judged wherever they land in the
    ; stream, since with a zero-capacity table position cannot change the
    ; verdict (see .qpack_enc_scan)
    mov rax, [rdx + linnea_quic_conn.qpack_enc_id]
    cmp rax, [s_sid]
    je .uni_cont_qpack_enc
    mov rax, [rdx + linnea_quic_conn.qpack_dec_id]
    cmp rax, [s_sid]
    je .uni_cont_qpack_dec
    ; neither control nor QPACK: a typed grease stream carries nothing we
    ; police, but with no control stream known this may be ITS bytes running
    ; ahead of their type frame — hold them (h3-6)
    cmp qword [rdx + linnea_quic_conn.ctrl_id], 0
    jne .stream_scan
    jmp .uni_cont_untyped
.uni_cont_qpack_dec:
    cmp qword [s_sfin], 0
    jne .uni_critical_closed
    jmp .stream_scan                 ; decoder-stream bodies carry nothing we act on
.uni_cont_qpack_enc:
    cmp qword [s_sfin], 0
    jne .uni_critical_closed
    mov rdi, [s_sdata]
    mov rsi, [s_slen]
    call .qpack_enc_scan
    test eax, eax
    jnz .uni_qpack_enc_bad
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
    je .uni_ctrl_walk                ; the same control stream again
    mov edi, LINNEA_H3_ERR_STREAM_CREATION
    jmp .h3_close
.uni_ctrl_first:
    mov rax, [s_sid]
    mov [rdx + linnea_quic_conn.ctrl_id], rax
    ; the walk starts after the stream-type byte this frame opened with
    mov qword [rdx + linnea_quic_conn.ctrl_off], 1
.uni_ctrl_walk:
    ; walk whatever frames these bytes complete. The first must be SETTINGS and
    ; no later one may be; DATA, HEADERS, PUSH_PROMISE and the types HTTP/2
    ; reserved end the connection; the rest are skipped by their length.
    call .ctrl_walk                  ; eax = 0, or the code to close with
    test eax, eax
    jz .stream_scan
    mov edi, eax
    jmp .h3_close
.uni_cont_untyped:
    ; No control stream is known yet, so this continuation cannot be typed —
    ; its offset-0 frame, the one naming the stream's type, may itself be the
    ; reordered-late one. If these bytes are the control stream's, dropping
    ; them would leave the frame walk a hole nothing ever fills (h3-6): hold
    ; them until the type arrives, and release them if the stream proves to
    ; be something else.
    call .ctrl_ro_capture
    jmp .stream_scan
.uni_critical_closed:
    mov edi, LINNEA_H3_ERR_CLOSED_CRITICAL
    jmp .h3_close

; .ctrl_walk() -> eax = 0 when the control-stream bytes in this STREAM frame are
; acceptable, else the HTTP/3 error code to close the connection with. Walks the
; frame sequence on the peer's control stream (RFC 9114 6.2.1, 7.2), carrying its
; position across STREAM frames in the connection: the payload of a frame we do
; not read is discarded by .ctrl_skip, and a frame header split across a frame
; boundary is accumulated in .ctrl_hdr.
;
; Only bytes that continue the contiguous prefix are walked. A STREAM frame that
; arrives ahead of .ctrl_off leaves a hole, and since a reordered (as opposed to
; lost) frame is delivered only once, those bytes may never come again — so the
; walk simply stops advancing rather than guessing. Enforcement then quietly ends
; for that connection, which is the right way round: these rules describe what a
; peer must not send, and none of them protects anything we would otherwise be
; exposed to, so a missed violation costs nothing while a wrong close would kill
; a conforming client. A genuine retransmission fills the hole and the walk
; resumes on its own.
; Uses [cur_conn] and the s_s* stream globals; clobbers only caller-saved
; registers plus rbx/r12/r13/r14/rbp, which it saves. Five pushes, so the calls
; below see a 16-aligned stack.
.ctrl_walk:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbx, [cur_conn]
    mov r12, [s_sdata]                ; cursor over this frame's new bytes
    mov r13, [s_slen]                 ; how many are left
    mov r14, [rbx + linnea_quic_conn.ctrl_off]
    mov rax, [s_soff]
    cmp rax, r14
    ja .cw_hole                       ; ahead of the prefix: hold, don't drop
    ; bytes below .ctrl_off were walked already — a retransmission overlapping
    ; what we have. Skip that prefix; if the whole frame is old there is nothing
    ; new to do.
    mov rcx, r14
    sub rcx, rax                      ; already-seen bytes at the front
    cmp rcx, r13
    jae .cw_ok
    add r12, rcx
    sub r13, rcx
.cw_loop:
    test r13, r13
    jz .cw_ok
    ; a frame whose payload we are discarding takes precedence over new headers
    mov rcx, [rbx + linnea_quic_conn.ctrl_skip]
    test rcx, rcx
    jz .cw_hdr
    cmp rcx, r13
    jbe .cw_skip_n
    mov rcx, r13
.cw_skip_n:
    sub [rbx + linnea_quic_conn.ctrl_skip], rcx
    ; a PRIORITY_UPDATE's payload is collected as it goes by, not discarded
    cmp qword [rbx + linnea_quic_conn.ctrl_pucap], 0
    je .cw_skip_move
    push rcx
    mov rdi, [rbx + linnea_quic_conn.ctrl_pulen]
    lea rdi, [rbx + linnea_quic_conn.ctrl_pu + rdi]
    mov rsi, r12
    add [rbx + linnea_quic_conn.ctrl_pulen], rcx
    rep movsb                         ; bounded: the length was checked at the header
    pop rcx
.cw_skip_move:
    add r12, rcx
    sub r13, rcx
    add r14, rcx
    ; the frame ends here: a captured frame is now whole, so act on it
    cmp qword [rbx + linnea_quic_conn.ctrl_skip], 0
    jne .cw_loop
    mov rax, [rbx + linnea_quic_conn.ctrl_pucap]
    test rax, rax
    jz .cw_loop
    cmp rax, LINNEA_H3_FRAME_SETTINGS
    je .cw_settings_apply
    cmp rax, LINNEA_H3_FRAME_PRIORITY_UPDATE
    jae .cw_pu_apply
    call .valen_apply                 ; CANCEL_PUSH / GOAWAY / MAX_PUSH_ID:
    jmp .cw_applied                   ; the payload must be one whole varint
.cw_settings_apply:
    call .settings_apply              ; eax = 0, or the code to close with
    jmp .cw_applied
.cw_pu_apply:
    call .pu_apply                    ; eax = 0, or the code to close with
.cw_applied:
    test eax, eax
    jnz .cw_ret_off
    jmp .cw_loop
.cw_hdr:
    ; feed the header one byte at a time and retry the decode: the two varints
    ; are 16 bytes at the very most, so the buffer can never fill without them
    ; both decoding, and a byte at a time is what lets a header split across
    ; STREAM frames resume exactly where it stopped
    mov rcx, [rbx + linnea_quic_conn.ctrl_hlen]
    cmp rcx, 16
    jae .cw_ok                        ; unreachable; never walk off the buffer
    movzx eax, byte [r12]
    mov [rbx + linnea_quic_conn.ctrl_hdr + rcx], al
    inc rcx
    mov [rbx + linnea_quic_conn.ctrl_hlen], rcx
    inc r12
    dec r13
    inc r14
    lea rdi, [rbx + linnea_quic_conn.ctrl_hdr]
    lea rbp, [rdi + rcx]              ; end of the buffered header bytes
    mov rsi, rbp
    call linnea_quic_varint_decode    ; frame type
    test rdx, rdx
    jz .cw_loop                       ; incomplete: take another byte
    lea rdi, [rbx + linnea_quic_conn.ctrl_hdr]
    add rdi, rdx                      ; the length varint follows the type
    mov rsi, rbp
    mov rbp, rax                      ; hold the type across the second decode
    call linnea_quic_varint_decode    ; frame length
    test rdx, rdx
    jz .cw_loop                       ; incomplete: take another byte
    ; a whole frame header: its payload is next, and the header buffer is spent
    mov qword [rbx + linnea_quic_conn.ctrl_hlen], 0
    mov [rbx + linnea_quic_conn.ctrl_skip], rax
    ; SETTINGS opens the control stream and appears exactly once (7.2.4)
    cmp qword [rbx + linnea_quic_conn.ctrl_settings], 0
    jne .cw_settings_seen
    cmp rbp, LINNEA_H3_FRAME_SETTINGS
    jne .cw_no_settings               ; the stream opened with something else
    mov qword [rbx + linnea_quic_conn.ctrl_settings], 1
    ; Capture the payload rather than skip it: the frame type was checked all
    ; along, but its CONTENTS never were, so a peer could send identifiers HTTP/3
    ; reserves — or the same one twice — and be told nothing was wrong.
    mov rcx, [rbx + linnea_quic_conn.ctrl_skip]
    test rcx, rcx
    jz .cw_loop                       ; an empty SETTINGS frame is perfectly legal
    cmp rcx, LINNEA_QUIC_PU_BUF
    ja .cw_loop                       ; more than we buffer: skip it, as the walk
                                      ; does with anything it cannot hold
    mov qword [rbx + linnea_quic_conn.ctrl_pucap], LINNEA_H3_FRAME_SETTINGS
    mov qword [rbx + linnea_quic_conn.ctrl_pulen], 0
    jmp .cw_loop
.cw_settings_seen:
    cmp rbp, LINNEA_H3_FRAME_SETTINGS
    je .cw_unexpected                 ; a second SETTINGS
    ; DATA and HEADERS belong to a request stream (7.2.1, 7.2.2), and a server
    ; may not receive PUSH_PROMISE at all (7.2.5)
    cmp rbp, LINNEA_H3_FRAME_DATA
    je .cw_unexpected
    cmp rbp, LINNEA_H3_FRAME_HEADERS
    je .cw_unexpected
    cmp rbp, LINNEA_H3_FRAME_PUSH_PROMISE
    je .cw_unexpected
    ; the frame types HTTP/2 used that HTTP/3 reserves (7.2.8)
    cmp rbp, 0x02
    je .cw_unexpected
    cmp rbp, 0x06
    je .cw_unexpected
    cmp rbp, 0x08
    je .cw_unexpected
    cmp rbp, 0x09
    je .cw_unexpected
    ; PRIORITY_UPDATE (RFC 9218 7.2) is the one extension frame we read: its
    ; payload is captured as it streams by and acted on once the frame ends.
    ; A payload too long to be a priority field value is left uncaptured and
    ; simply skipped, like any other frame we do not understand.
    cmp rbp, LINNEA_H3_FRAME_PRIORITY_UPDATE
    je .cw_prio
    cmp rbp, LINNEA_H3_FRAME_PRIORITY_UPDATE_PUSH
    je .cw_prio
    ; CANCEL_PUSH, GOAWAY and MAX_PUSH_ID belong here — and each carries
    ; exactly one varint (7.2.3/7.2.6/7.2.7), which was never checked (h3-4):
    ; the payload was skipped by length whatever it held, though 7.1 makes a
    ; payload longer or shorter than its fields H3_FRAME_ERROR.
    cmp rbp, LINNEA_H3_FRAME_CANCEL_PUSH
    je .cw_varint_frame
    cmp rbp, LINNEA_H3_FRAME_GOAWAY
    je .cw_varint_frame
    cmp rbp, LINNEA_H3_FRAME_MAX_PUSH_ID
    je .cw_varint_frame
    ; an unknown type — GREASE, or an extension we do not implement — must be
    ; ignored (9); its payload is discarded
    jmp .cw_loop
.cw_varint_frame:
    ; no varint at all, or more bytes than any varint has (8), is refusable at
    ; the header; an in-range payload is captured like SETTINGS and judged
    ; whole at the frame's end, wherever its bytes land
    mov rcx, [rbx + linnea_quic_conn.ctrl_skip]
    test rcx, rcx
    jz .cw_frame_err
    cmp rcx, 8
    ja .cw_frame_err
    mov [rbx + linnea_quic_conn.ctrl_pucap], rbp
    mov qword [rbx + linnea_quic_conn.ctrl_pulen], 0
    jmp .cw_loop
.cw_frame_err:
    mov eax, LINNEA_H3_ERR_FRAME
    jmp .cw_ret
.cw_prio:
    mov rcx, [rbx + linnea_quic_conn.ctrl_skip]      ; the declared payload length
    test rcx, rcx
    jz .cw_loop                       ; no element id can fit: not a priority frame
    cmp rcx, LINNEA_QUIC_PU_BUF
    ja .cw_loop                       ; far too long to be one either
    mov [rbx + linnea_quic_conn.ctrl_pucap], rbp     ; capture, remembering which type
    mov qword [rbx + linnea_quic_conn.ctrl_pulen], 0
    jmp .cw_loop
.cw_hole:
    ; A STREAM frame ahead of .ctrl_off: a reordered datagram is delivered (and
    ; acked) once, so dropping these bytes would leave a hole nothing ever
    ; fills, and the walk — with every rule it enforces — would end here for
    ; good (h3-6). Hold them instead; they are fed back in below the moment
    ; the in-order bytes catch up.
    call .ctrl_ro_capture
    jmp .cw_ok
.cw_ok:
    mov [rbx + linnea_quic_conn.ctrl_off], r14
    ; held ahead-bytes may now be contiguous with the prefix: walk them too
    mov rax, [rbx + linnea_quic_conn.ctrl_ro_sid]
    test rax, rax
    jz .cw_ok_done
    cmp rax, [rbx + linnea_quic_conn.ctrl_id]
    jne .cw_ok_done                   ; held for a stream not yet typed
    mov rax, [rbx + linnea_quic_conn.ctrl_ro_start]
    cmp rax, r14
    ja .cw_ok_done                    ; the hole is not filled yet
    mov rcx, [rbx + linnea_quic_conn.ctrl_ro_len]
    add rcx, rax                      ; the segment's end offset
    ; the segment is spent either way: walked now, or entirely stale
    mov qword [rbx + linnea_quic_conn.ctrl_ro_sid], 0
    mov qword [rbx + linnea_quic_conn.ctrl_ro_len], 0
    cmp rcx, r14
    jbe .cw_ok_done                   ; nothing beyond what was already walked
    mov rdx, r14
    sub rdx, rax                      ; already-walked prefix inside the segment
    lea r12, [rbx + linnea_quic_conn.ctrl_ro_buf + rdx]
    mov r13, rcx
    sub r13, r14                      ; the fresh bytes
    jmp .cw_loop
.cw_ok_done:
    xor eax, eax
    jmp .cw_ret
.cw_ret_off:                          ; an error, but the walk did consume bytes
    mov [rbx + linnea_quic_conn.ctrl_off], r14
    jmp .cw_ret
.cw_no_settings:
    mov eax, LINNEA_H3_ERR_MISSING_SETTINGS
    jmp .cw_ret
.cw_unexpected:
    mov eax, LINNEA_H3_ERR_FRAME_UNEXPECTED
.cw_ret:
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .valen_apply() -> eax = 0, or the H3 error code to close with. The captured
; frame — CANCEL_PUSH, GOAWAY or MAX_PUSH_ID — must be exactly one varint:
; its first byte declares the varint's length, and RFC 9114 7.1 makes a
; payload with bytes beyond its fields, or ending before them, H3_FRAME_ERROR
; (h3-4; Q182 checked SETTINGS alone). The VALUE is read and not acted on —
; we never promise a push, so there is no push state for any of the three to
; name. rbx = conn; clears the capture; preserves the walk's r12/r13/r14.
.valen_apply:
    mov qword [rbx + linnea_quic_conn.ctrl_pucap], 0
    movzx eax, byte [rbx + linnea_quic_conn.ctrl_pu]
    shr eax, 6
    mov ecx, eax
    mov eax, 1
    shl eax, cl                       ; the length the varint claims for itself
    cmp rax, [rbx + linnea_quic_conn.ctrl_pulen]
    jne .va_bad
    xor eax, eax
    ret
.va_bad:
    mov eax, LINNEA_H3_ERR_FRAME
    ret

; .ctrl_ro_capture() — the STREAM frame in the s_s* globals arrived ahead of
; the walked prefix of a (possible) control stream: hold its bytes so the walk
; can resume once the in-order bytes catch up (h3-6). One segment per
; connection, merged with whatever it touches; bytes disjoint from a held
; segment keep the lower-offset one (the first the walk will reach). A
; segment can belong to a stream whose offset-0 type frame has not arrived —
; .ctrl_walk's feed-in only consumes it once the stream proves to be the
; control stream, and .uni_ro_drop releases it if it proves otherwise.
; Reads cur_conn and the s_s* globals; no calls out, so alignment is free.
.ctrl_ro_capture:
    push rbx
    push r12
    push r13
    mov rbx, [cur_conn]
    mov r12, [s_sdata]
    mov r13, [s_slen]
    test r13, r13
    jz .rc_done
    mov rax, [s_soff]                 ; a: where the new bytes start
    mov rdx, [rbx + linnea_quic_conn.ctrl_ro_sid]
    test rdx, rdx
    jz .rc_fresh
    cmp rdx, [s_sid]
    jne .rc_done                      ; the buffer already serves another stream
    mov rsi, [rbx + linnea_quic_conn.ctrl_ro_start]
    mov rcx, [rbx + linnea_quic_conn.ctrl_ro_len]
    lea rdx, [rsi + rcx]              ; the held segment is [s, s+l)
    cmp rax, rdx
    ja .rc_done                       ; strictly after, a gap: drop the new bytes
    lea rdx, [rax + r13]
    cmp rdx, rsi
    jb .rc_fresh                      ; strictly before, a gap: keep the lower
    cmp rax, rsi
    jae .rc_tail
    ; the new bytes reach below the segment: shift the held data up so the
    ; segment can begin at the lower offset
    mov rdx, rsi
    sub rdx, rax                      ; the shift
    cmp rdx, LINNEA_QUIC_CTRL_RO
    jae .rc_fresh                     ; the held data would shift entirely out
    mov r8, LINNEA_QUIC_CTRL_RO
    sub r8, rdx
    cmp rcx, r8
    jbe .rc_shift
    mov rcx, r8                       ; what survives of the held data
.rc_shift:
    mov r9, rcx                       ; held bytes kept, across the copy
    lea rsi, [rbx + linnea_quic_conn.ctrl_ro_buf + r9 - 1]
    lea rdi, [rsi + rdx]
    std
    rep movsb                         ; overlapping right-shift: copy backward
    cld
    mov [rbx + linnea_quic_conn.ctrl_ro_start], rax
    lea rcx, [rdx + r9]               ; segment length after the shift
    mov [rbx + linnea_quic_conn.ctrl_ro_len], rcx
    jmp .rc_tail
.rc_fresh:
    mov rdx, [s_sid]
    mov [rbx + linnea_quic_conn.ctrl_ro_sid], rdx
    mov [rbx + linnea_quic_conn.ctrl_ro_start], rax
    mov qword [rbx + linnea_quic_conn.ctrl_ro_len], 0
.rc_tail:
    ; write the new bytes at their position in the segment (never past a gap:
    ; every path here has them touching or inside the held range)
    mov rsi, [rbx + linnea_quic_conn.ctrl_ro_start]
    mov rdx, rax
    sub rdx, rsi                      ; their position in the buffer
    cmp rdx, LINNEA_QUIC_CTRL_RO
    jae .rc_done                      ; starts past the buffer: nothing fits
    mov rcx, LINNEA_QUIC_CTRL_RO
    sub rcx, rdx                      ; room from there to the end
    cmp r13, rcx
    jbe .rc_write
    mov r13, rcx                      ; clamp: the tail beyond is dropped
.rc_write:
    lea rdi, [rbx + linnea_quic_conn.ctrl_ro_buf + rdx]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    add rdx, r13                      ; where the new bytes end, relative
    cmp rdx, [rbx + linnea_quic_conn.ctrl_ro_len]
    jbe .rc_done
    mov [rbx + linnea_quic_conn.ctrl_ro_len], rdx
.rc_done:
    pop r13
    pop r12
    pop rbx
    ret

; .uni_ro_drop() — the stream just typed itself as something other than the
; control stream: a segment held on its behalf will never be walked, so free
; the buffer for the stream that may yet need it.
.uni_ro_drop:
    mov rdx, [cur_conn]
    mov rax, [rdx + linnea_quic_conn.ctrl_ro_sid]
    cmp rax, [s_sid]
    jne .rd_done
    mov qword [rdx + linnea_quic_conn.ctrl_ro_sid], 0
    mov qword [rdx + linnea_quic_conn.ctrl_ro_len], 0
.rd_done:
    ret

; .qpack_enc_scan(rdi = bytes, rsi = count) -> eax = 0 fine, 1 violation.
; We advertise QPACK_MAX_TABLE_CAPACITY = 0, so the only instruction a
; conforming encoder can ever send is Set Dynamic Table Capacity to 0 — the
; single byte 0x20 (RFC 9204 4.3.1): any other capacity exceeds the maximum we
; set, and Insert or Duplicate have no table to land in. A one-byte instruction
; set makes the check position-independent, so each STREAM frame is judged as
; it arrives — reordering needs no reassembly, and a continuation byte of some
; would-be multi-byte instruction is preceded by a first byte that already
; fails. The violation is QPACK_ENCODER_STREAM_ERROR (4.1.3).
.qpack_enc_scan:
    xor eax, eax
    test rsi, rsi
    jz .qes_done
.qes_loop:
    cmp byte [rdi], 0x20
    jne .qes_bad
    inc rdi
    dec rsi
    jnz .qes_loop
    jmp .qes_done
.qes_bad:
    mov eax, 1
.qes_done:
    ret

; .qpack_enc_scan_all() -> eax as above, judging BOTH the typing frame's
; payload (the s_s* globals, past the stream-type byte) and any segment held
; for this stream while it was untyped — bytes that arrived ahead of the type
; frame would otherwise be dropped unjudged by .uni_ro_drop.
.qpack_enc_scan_all:
    mov rdi, [s_sdata]
    inc rdi
    mov rsi, [s_slen]
    dec rsi
    call .qpack_enc_scan
    test eax, eax
    jnz .qesa_done
    mov rdx, [cur_conn]
    mov rax, [rdx + linnea_quic_conn.ctrl_ro_sid]
    cmp rax, [s_sid]
    jne .qesa_ok
    lea rdi, [rdx + linnea_quic_conn.ctrl_ro_buf]
    mov rsi, [rdx + linnea_quic_conn.ctrl_ro_len]
    call .qpack_enc_scan
.qesa_done:
    ret
.qesa_ok:
    xor eax, eax
    ret

.uni_qpack_enc_bad:
    mov edi, LINNEA_H3_ERR_QPACK_ENC_STREAM
    jmp .h3_close

; .pu_apply() -> eax = 0, or the HTTP/3 error code to close with. Acts on the
; whole PRIORITY_UPDATE payload sitting in the connection's .ctrl_pu, and clears
; the capture. rbx = conn on entry; the walk's r12/r13/r14 are preserved.
;
; .settings_apply() -> eax = 0, or the H3 error code to close the connection
; with. Walks the captured SETTINGS payload as (identifier, value) varint pairs.
;
; The walk validated which FRAMES may appear on the control stream; the payload
; of the one frame that carries configuration was skipped whole. So a peer could
; send SETTINGS_MAX_CONCURRENT_STREAMS — an HTTP/2 identifier HTTP/3 reserves
; precisely so that an HTTP/2-shaped implementation is caught rather than
; silently misunderstood — and hear nothing back.
;
;   0x02..0x05   reserved (7.2.4.1): the HTTP/2 settings with no HTTP/3
;                equivalent. Receipt MUST be H3_SETTINGS_ERROR.
;   a repeat     the same identifier twice (7.2.4). A receiver MAY treat this
;                as H3_SETTINGS_ERROR, and we do.
;   truncated    an identifier with no value, or a varint running past the
;                frame: H3_FRAME_ERROR (7.1).
;   anything else is ignored, which is what GREASE requires (7.2.4.1).
;
; The values themselves are read and not acted on. The only one that would ask
; anything of us is MAX_FIELD_SECTION_SIZE, and 4.2.2 makes that a SHOULD on the
; sender: our response field sections run a few hundred bytes, far below any
; limit a client actually advertises, so there is nothing to enforce yet and a
; stored-but-unused field would only mislead.
;
; Five pushes plus the 256-byte seen-list keeps rsp 16-aligned for the calls.
.settings_apply:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    sub rsp, 256                      ; up to 32 identifiers already seen
    mov rbx, [cur_conn]
    mov qword [rbx + linnea_quic_conn.ctrl_pucap], 0   ; capture consumed
    lea r12, [rbx + linnea_quic_conn.ctrl_pu]
    mov r13, [rbx + linnea_quic_conn.ctrl_pulen]
    add r13, r12                      ; payload end
    xor r14d, r14d                    ; identifiers seen so far
.sa_loop:
    cmp r12, r13
    jae .sa_ok
    mov rdi, r12
    mov rsi, r13
    call linnea_quic_varint_decode    ; rax = identifier, rdx = bytes used
    test rdx, rdx
    jz .sa_frame_err                  ; a varint running past the frame
    add r12, rdx
    mov rbp, rax                      ; hold the identifier across the value
    cmp r12, r13
    jae .sa_frame_err                 ; an identifier with no value at all
    mov rdi, r12
    mov rsi, r13
    call linnea_quic_varint_decode    ; rax = value (read, not acted on)
    test rdx, rdx
    jz .sa_frame_err
    add r12, rdx
    ; the HTTP/2 identifiers HTTP/3 reserves (7.2.4.1). 0x01 and 0x06 are real
    ; HTTP/3 settings (QPACK capacity, max field section size), so the reserved
    ; run is exactly 0x02 through 0x05.
    cmp rbp, 0x02
    jb .sa_seen_scan
    cmp rbp, 0x05
    jbe .sa_settings_err
.sa_seen_scan:
    ; the same identifier twice
    xor ecx, ecx
.sa_seen_loop:
    cmp rcx, r14
    jae .sa_seen_add
    cmp [rsp + rcx * 8], rbp
    je .sa_settings_err
    inc rcx
    jmp .sa_seen_loop
.sa_seen_add:
    cmp r14, 32
    jae .sa_loop                      ; the list is full: stop recording, keep walking
    mov [rsp + r14 * 8], rbp
    inc r14
    jmp .sa_loop
.sa_frame_err:
    mov eax, LINNEA_H3_ERR_FRAME
    jmp .sa_ret
.sa_settings_err:
    mov eax, LINNEA_H3_ERR_SETTINGS
    jmp .sa_ret
.sa_ok:
    xor eax, eax
.sa_ret:
    add rsp, 256
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; The payload is varint(prioritized element id) then a priority field value in
; the same syntax the `priority` header uses, so the same parser reads it (RFC
; 9218 7.2). The update is applied to the response stream's open slot if it has
; one, and otherwise remembered: the control stream and the request stream are
; independent, so an update can overtake the request it reprioritises, and RFC
; 9218 7 asks that the signal be kept rather than dropped.
.pu_apply:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbx, [cur_conn]
    mov rbp, [rbx + linnea_quic_conn.ctrl_pucap]     ; which of the two types
    mov qword [rbx + linnea_quic_conn.ctrl_pucap], 0 ; capture consumed either way
    lea rdi, [rbx + linnea_quic_conn.ctrl_pu]
    mov rsi, [rbx + linnea_quic_conn.ctrl_pulen]
    add rsi, rdi
    call linnea_quic_varint_decode    ; rax = element id, rdx = its length
    test rdx, rdx
    jz .pu_ok                         ; a truncated id: nothing to act on
    mov r13, rax                      ; the element id
    ; the rest of the payload is the priority field value; an empty one is legal
    ; and simply means the defaults
    lea rdi, [rbx + linnea_quic_conn.ctrl_pu]
    add rdi, rdx
    mov rsi, [rbx + linnea_quic_conn.ctrl_pulen]
    sub rsi, rdx
    call linnea_quic_parse_priority   ; rax = urgency, rdx = incremental
    mov r14, rax
    shl rdx, 8
    or r14, rdx                       ; packed urgency | incremental << 8
    ; A push id can name nothing here: we never send PUSH_PROMISE, so no push has
    ; ever been promised on this connection and RFC 9218 7.2 makes any push id an
    ; H3_ID_ERROR. No conforming client can reach this.
    cmp rbp, LINNEA_H3_FRAME_PRIORITY_UPDATE_PUSH
    je .pu_id_error
    ; and a request id must be a client-initiated bidirectional stream (low two
    ; bits 00) — any other id does not name a request, whatever it names
    test r13, 3
    jnz .pu_id_error
    ; an open response slot for that stream takes the new values at once: the
    ; pump reads urgency and incremental afresh every time it picks a stream, so
    ; nothing else has to be resorted
    lea rax, [rbx + linnea_quic_conn.tx_streams]
    mov ecx, LINNEA_QUIC_TXSTREAMS
.pu_slot:
    cmp qword [rax + linnea_quic_txstream.active], 0
    je .pu_slot_next
    cmp [rax + linnea_quic_txstream.sid], r13
    je .pu_slot_hit
.pu_slot_next:
    add rax, linnea_quic_txstream_size
    dec ecx
    jnz .pu_slot
    jmp .pu_pend                      ; no slot open (yet): remember it
.pu_slot_hit:
    mov rdx, r14
    and rdx, 0xff
    mov [rax + linnea_quic_txstream.urgency], rdx
    mov rdx, r14
    shr rdx, 8
    mov [rax + linnea_quic_txstream.incremental], rdx
    jmp .pu_ok
.pu_pend:
    ; keep the most recent value per stream: overwrite this stream's entry if it
    ; already has one, else take the next ring slot (evicting the oldest)
    lea rax, [rbx + linnea_quic_conn.pu_sid]
    lea rdx, [r13 + 1]                ; ids are stored as id + 1, so 0 means empty
    xor ecx, ecx
.pu_pend_scan:
    cmp [rax + rcx * 8], rdx
    je .pu_pend_store
    inc ecx
    cmp ecx, LINNEA_QUIC_PU_PEND
    jb .pu_pend_scan
    mov rcx, [rbx + linnea_quic_conn.pu_next]
    lea r8, [rcx + 1]
    cmp r8, LINNEA_QUIC_PU_PEND
    jb .pu_pend_wrap
    xor r8d, r8d
.pu_pend_wrap:
    mov [rbx + linnea_quic_conn.pu_next], r8
.pu_pend_store:
    mov [rax + rcx * 8], rdx
    mov [rbx + linnea_quic_conn.pu_val + rcx * 8], r14
.pu_ok:
    xor eax, eax
    jmp .pu_ret
.pu_id_error:
    mov eax, LINNEA_H3_ERR_ID
.pu_ret:
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .h3_close(edi = HTTP/3 error code) — end the connection with an application
; CONNECTION_CLOSE (frame 0x1d) carrying the code, then enter the closing state.
; Sent via emit_1rtt (no loss-recovery tracking); the same frame is kept so the
; closing state can re-send it if the peer keeps talking.
.h3_close:
    call send_app_close              ; leaves the frame in cc_pay / s_pl_len
    lea rdi, [cc_pay]
    mov rsi, [s_pl_len]
    call .enter_closing
    jmp .done

; .transport_close(edi = transport error code, esi = triggering frame type) — end
; the connection with a TRANSPORT CONNECTION_CLOSE (frame 0x1c, RFC 9000 19.19):
; the error code, the frame type that caused it, and an empty reason phrase, then
; enter the closing state. Our transport error codes and frame types are all < 64,
; so each is a one-byte varint. Like .h3_close, sent via emit_1rtt with no loss
; tracking — the retained frame carries the reliability instead.
.transport_close:
    mov byte [cc_pay], 0x1c
    mov [cc_pay + 1], dil             ; transport error code
    mov [cc_pay + 2], sil             ; triggering frame type
    mov byte [cc_pay + 3], 0x00       ; reason phrase length = 0
    lea rsi, [cc_pay]
    mov [s_pl_ptr], rsi
    mov qword [s_pl_len], 4
    call emit_1rtt
    lea rdi, [cc_pay]
    mov esi, 4
    call .enter_closing
    jmp .done

; enter_closing(rdi = close-frame ptr, rsi = length) — keep cur_conn's slot in
; the closing state (RFC 9000 10.2) instead of freeing it now. The close frame is
; copied in so a later packet can be answered with it (at .closing_rx), and a
; deadline is set past which the retransmission sweep reclaims the slot. Holding
; the slot means the peer learns the real error we sent rather than the stateless
; reset a reused/freed connection id would draw. Uses cur_conn; preserves nothing
; the callers need past the jmp .done that follows.
.enter_closing:
    push rbx
    push r12
    push r13
    mov rbx, [cur_conn]
    mov r12, rdi                      ; src
    mov r13, rsi                      ; len
    cmp r13, 24
    jbe .ec_len_ok
    mov r13d, 24                      ; clamp to the buffer (our closes are <= 4 bytes)
.ec_len_ok:
    mov [rbx + linnea_quic_conn.close_len], r13
    lea rdi, [rbx + linnea_quic_conn.close_frame]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CLOSING
    call now_ms
    add rax, LINNEA_QUIC_CLOSING_MS
    mov [rbx + linnea_quic_conn.close_deadline], rax
    pop r13
    pop r12
    pop rbx
    ret

; the peer said goodbye: release its slot and stop reading this datagram. The
; peer is draining and will not read anything we send, so nothing is retained —
; a later stray packet from it drawing a stateless reset from us is harmless.
.peer_closed:
    mov rdi, [cur_conn]
    call linnea_quic_conn_free
    jmp .done

; .closing_rx(rax = the closing connection) — a packet arrived for a connection
; we have already closed. RFC 9000 10.2.1: re-send the CONNECTION_CLOSE we kept
; (so a lost close still reaches the peer, and it learns the real error rather
; than a stateless reset), process nothing else. Rate-limited to one per received
; packet, and only for a packet large enough that the reply cannot amplify —
; both as 10.2.1 asks.
.closing_rx:
    mov [cur_conn], rax
    cmp r13, 22                       ; the close is ~30B protected; never amplify
    jb .done
    lea rsi, [rax + linnea_quic_conn.close_frame]
    mov [s_pl_ptr], rsi
    mov rcx, [rax + linnea_quic_conn.close_len]
    mov [s_pl_len], rcx
    call emit_1rtt
    jmp .done

; .ch_reassemble(rax = CRYPTO fragment ptr, rdx = length, r8 = offset,
;   r9 = Initial packet number) -> rax = 1 once the ClientHello is complete, else
;   0. Places the fragment at its offset in ch_buf and marks its bytes in ch_seen;
; the contiguous prefix (ch_len) then advances as far as the seen-map allows, so
; fragments that arrive out of order (ngtcp2 sends the ClientHello's CRYPTO
; fragments in a different order than their offsets) are buffered, not dropped.
; The full size is the TLS handshake length in the offset-0 bytes; completion is
; ch_len >= ch_total. The largest Initial packet number is tracked so the
; ServerHello can acknowledge every Initial received. The connection is [cur_conn].
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
    ; track the smallest and largest Initial packet numbers, for the completion ACK
    ; (the range may start above 0 — Chrome's Initials begin at packet number 1)
    cmp r9, [rbx + linnea_quic_conn.ch_maxpn]
    jbe .cr_max_done
    mov [rbx + linnea_quic_conn.ch_maxpn], r9
.cr_max_done:
    cmp r9, [rbx + linnea_quic_conn.ch_minpn]
    jae .cr_pn_done
    mov [rbx + linnea_quic_conn.ch_minpn], r9
.cr_pn_done:
    lea rax, [r14 + r13]             ; fragment end
    cmp rax, LINNEA_QUIC_CH_BUF
    ja .cr_incomplete                ; past the buffer: refuse (ClientHello too big)
    test r13, r13
    jz .cr_hi                        ; empty fragment: nothing to place
    ; place the fragment at ch_buf[offset] and mark ch_seen[offset..+len]
    lea rdi, [rbx + linnea_quic_conn.ch_buf]
    add rdi, r14
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov rbx, [cur_conn]              ; rep movsb advanced rdi/rsi; rbx untouched
    lea rdi, [rbx + linnea_quic_conn.ch_seen]
    add rdi, r14
    mov rcx, r13
    mov al, 1
    rep stosb
    mov rbx, [cur_conn]
.cr_hi:
    ; extend the high-water mark to this fragment's end
    lea rax, [r14 + r13]
    cmp rax, [rbx + linnea_quic_conn.ch_hi]
    jbe .cr_adv
    mov [rbx + linnea_quic_conn.ch_hi], rax
.cr_adv:
    ; advance the contiguous prefix while the next byte has been seen
    mov r15, [rbx + linnea_quic_conn.ch_len]
    mov r10, [rbx + linnea_quic_conn.ch_hi]
    lea rdi, [rbx + linnea_quic_conn.ch_seen]
.cr_adv_loop:
    cmp r15, r10
    jae .cr_adv_done
    cmp byte [rdi + r15], 0
    je .cr_adv_done
    inc r15
    jmp .cr_adv_loop
.cr_adv_done:
    mov [rbx + linnea_quic_conn.ch_len], r15
    ; learn the full ClientHello size once the offset-0 header is contiguous: the
    ; TLS handshake header is type(1) + length(3), so total = 4 + that length.
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
    ; RFC 9000 14.1 MUST: a UDP datagram carrying an ack-eliciting Initial is
    ; expanded to 1200 bytes. That is this datagram — the Initial staged in
    ; outpkt coalesced with the first Handshake chunk — and ours ran short
    ; whenever the flight was small (a resumption flight is EE || Finished, a
    ; few hundred bytes). The padding goes in the LAST packet of the datagram as
    ; PADDING frames (type 0x00) inside the Handshake payload, so it is covered
    ; by that packet's Length and its AEAD; trailing bytes after the final packet
    ; would instead be read as a packet with the fixed bit clear and discarded.
    ; The header is built twice on purpose: its Length varint describes the
    ; payload, so the padded size has to be known before the header is final.
    test r14, r14
    jnz .sf_hdr                      ; only the first chunk shares the Initial's datagram
    call .build_hs_header
    mov rax, [s_ini_len]
    add rax, rcx                     ; + this packet's header
    add rax, r15                     ; + its payload
    add rax, 16                      ; + its AEAD tag
    cmp rax, LINNEA_QUIC_MIN_INITIAL_DGRAM
    jae .sf_hdr
    mov rdx, LINNEA_QUIC_MIN_INITIAL_DGRAM
    sub rdx, rax                     ; PADDING bytes wanted
    lea rdi, [hspay + r15]
    xor eax, eax
    mov rcx, rdx
    rep stosb
    add r15, rdx
.sf_hdr:
    call .build_hs_header            ; rcx = header length; uses r15, conn.flight_pn
    sub rsp, 16
    CONNLEA rax, hs_skeys
    mov [rsp], rax
    mov rax, [cur_conn]              ; full pn for the nonce = the flight packet number
    movzx eax, byte [rax + linnea_quic_conn.flight_pn]
    mov [rsp + 8], rax
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
    ; Certificate -> hsmsg[ee_len], re-framed from this vhost's list
    mov rax, [cur_conn]
    mov rdx, [rax + linnea_quic_conn.flight_ee_len]
    lea rdi, [hsmsg + rdx]
    mov rax, [cur_conn]
    mov rax, [rax + linnea_quic_conn.vhost]
    call vhost_slot
    mov rsi, [rax + linnea_quic_vhost.cert_ptr]
    mov rdx, [rax + linnea_quic_vhost.cert_len]
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

; .build_initial_packet — the Initial carrying ACK(client Initials) + CRYPTO
; (ServerHello), protected into outpkt with s_ini_len set. Expects the message in
; sh_buf with its length in s_sh_len. Takes its packet number from conn.pn_ini and
; advances it, so a retransmission never reuses one (RFC 9000 12.3).
.build_initial_packet:
    ; This block ran inline until it had to be shared with the retransmit path.
    ; Becoming a callee costs 8 bytes of stack for the return address, which left
    ; linnea_quic_protect — and the SSE it reaches — running one call deeper and
    ; misaligned. Put rsp back on a 16-byte boundary.
    sub rsp, 8
    mov byte [payload], 0x02
    mov dword [payload + 1], 0
    mov rax, [cur_conn]
    movzx ecx, byte [rax + linnea_quic_conn.ch_maxpn]
    mov [payload + 1], cl            ; Largest Acknowledged
    mov rdx, [rax + linnea_quic_conn.ch_maxpn]
    sub rdx, [rax + linnea_quic_conn.ch_minpn]
    mov [payload + 4], dl            ; First ACK Range = largest - smallest
    mov byte [payload + 5], 0x06
    mov byte [payload + 6], 0x00
    mov eax, [s_sh_len]              ; CRYPTO length varint (2-byte: 0x4000 | len)
    shl eax, 8
    or eax, 0x40
    mov [payload + 7], ax
    lea rdi, [payload + 9]
    lea rsi, [sh_buf]
    mov ecx, [s_sh_len]
    rep movsb
    mov rax, [s_sh_len]
    add rax, 9                       ; ACK(5) + CRYPTO header(4) + SH
    mov [s_ini_paylen], rax
    call .build_initial_header       ; -> rcx = header length
    sub rsp, 16
    CONNLEA rax, ini_server
    mov [rsp], rax
    mov rax, [cur_conn]              ; full pn for the nonce
    mov rax, [rax + linnea_quic_conn.pn_ini]
    mov [rsp + 8], rax
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
    mov rcx, [cur_conn]
    inc qword [rcx + linnea_quic_conn.pn_ini]
    add rsp, 8
    ret

; .initial_close(edi = QUIC error code) — end the handshake with something the
; peer can actually read.
;
; RFC 9001 4.8: a TLS alert raised during the handshake becomes a QUIC
; connection error of 0x0100 + the alert description. Every handshake-space
; refusal here used to just drop the connection and go silent, because the only
; close path was emit_1rtt and 1-RTT keys do not exist yet — so a client we had
; decided not to serve sat retransmitting its ClientHello until it gave up, with
; nothing anywhere to say why. Initial keys come from the client's own DCID, so
; this space can always be written, whatever else has failed.
;
; Frame type 0x1c, the transport form: 0x1d carries an application error and RFC
; 9000 12.5 forbids it in Initial and Handshake packets. cur_conn selects the
; connection, r12d is the UDP socket. The caller still frees the connection.
.initial_close:
    sub rsp, 8                       ; a callee: put rsp back on a 16-byte boundary
    mov byte [payload], 0x1c
    ; error code as a 2-byte varint — 0x0100+alert is 256..511, which never fits
    ; the 1-byte form and always fits the 2-byte one
    mov eax, edi
    mov edx, eax
    shr edx, 8
    or edx, 0x40
    mov [payload + 1], dl
    mov [payload + 2], al
    mov byte [payload + 3], 0x00     ; the frame type that triggered it: none
    mov byte [payload + 4], 0x00     ; reason phrase length
    mov qword [s_ini_paylen], 5
    call .build_initial_header       ; -> rcx = header length
    sub rsp, 16
    CONNLEA rax, ini_server
    mov [rsp], rax
    mov rax, [cur_conn]              ; full pn for the nonce
    mov rax, [rax + linnea_quic_conn.pn_ini]
    mov [rsp + 8], rax
    lea rdi, [outpkt]
    lea rsi, [hdr]
    mov rdx, rcx
    mov ecx, 1
    lea r8, [payload]
    mov r9d, 5
    call linnea_quic_protect         ; rax = Initial packet length
    add rsp, 16
    mov rdx, rax                     ; datagram length, before rax is the syscall
    mov eax, SYS_SENDTO
    mov edi, r12d
    lea rsi, [outpkt]
    xor r10d, r10d
    CONNLEA r8, peer
    CONNGET r9, peer_len
    syscall
    mov rcx, [cur_conn]
    inc qword [rcx + linnea_quic_conn.pn_ini]
    add rsp, 8
    ret

; .retx_hs_flight — resend the whole server flight after a PTO (RFC 9000 13.3,
; RFC 9002 6.2). There was no loss recovery for the Initial or Handshake spaces
; at all: .send_flight ran once when the flight was built and once when the
; amplification budget released its tail, and the sweep walked only the 1-RTT
; rings. So a lost first datagram simply ended the handshake — the client
; retransmitted its ClientHello until it gave up on HTTP/3 and fell back to TCP.
;
; Everything needed is connection state: the ServerHello above, and the Handshake
; half which .recompose_flight rebuilds from flight_tail plus the vhost's
; certificate. Both go out under fresh packet numbers. Expects rbx = conn,
; r12d = fd; clobbers freely.
.retx_hs_flight:
    ; This is a callee, so rsp arrives 8 off a 16-byte boundary; the builders it
    ; calls reach SSE, and .build_initial_packet re-aligns only for the depth of
    ; the first-flight path. Put rsp back before calling anything.
    sub rsp, 8
    mov [cur_conn], rbx
    mov al, [rbx + linnea_quic_conn.is_v2]
    mov [quic_v2_active], al          ; salt/labels/type codes for this connection
    mov rax, [rbx + linnea_quic_conn.sh_len]
    mov [s_sh_len], rax
    lea rdi, [sh_buf]
    lea rsi, [rbx + linnea_quic_conn.sh_msg]
    mov rcx, rax
    rep movsb
    call .build_initial_packet
    ; the builders owe us nothing, rbx included — reach the connection through
    ; cur_conn rather than assuming it survived
    mov rax, [cur_conn]
    mov qword [rax + linnea_quic_conn.flight_off], 0   ; resend the flight whole
    call .recompose_flight
    call .send_flight
    add rsp, 8
    ret

; .build_initial_header -> rcx = header length; DCID = client SCID, SCID = ours,
; length field = pn(1)+payload(99)+tag(16) = 116, packet number from conn.pn_ini.
.build_initial_header:
    mov byte [hdr], 0xc0             ; v1: long Initial (type bits 00, 1-byte pn),
    mov dword [hdr + 1], 0x01000000  ; version 0x00000001
    cmp byte [quic_v2_active], 0
    je .bih_ver
    mov byte [hdr], 0xd0             ; v2 (RFC 9369): Initial type bits 01,
    mov dword [hdr + 1], 0xcf43336b  ; version 0x6b3343cf (wire 6b 33 43 cf)
.bih_ver:
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
    ; length varint = pn(1) + payload + tag(16); a 2-byte varint. The payload
    ; length is a variable rather than "9 + SH" because the first flight is no
    ; longer the only thing sent in this space — .initial_close writes a
    ; CONNECTION_CLOSE here too.
    mov eax, [s_ini_paylen]
    add eax, 17
    mov edx, eax
    shr edx, 8
    or edx, 0x40
    mov [rdi + 1], dl                ; 0x40 | (len >> 8)
    mov [rdi + 2], al                ; len & 0xff
    mov rax, [cur_conn]              ; 1-byte packet number; a few retries at most
    mov rax, [rax + linnea_quic_conn.pn_ini]
    mov [rdi + 3], al
    lea rcx, [rdi + 4]
    lea rax, [hdr]
    sub rcx, rax                     ; header length
    ret

; .build_hs_header -> rcx = header length; type Handshake, no token; the length
; field = pn(1)+r15(payload)+tag(16). The 1-byte packet number is conn.flight_pn
; (a flight never spans more than a handful of packets, so it never exceeds 0xff).
.build_hs_header:
    mov byte [hdr], 0xe0             ; v1: long Handshake (type bits 10), 1-byte pn,
    mov dword [hdr + 1], 0x01000000  ; version 0x00000001
    cmp byte [quic_v2_active], 0
    je .bhh_ver
    mov byte [hdr], 0xf0             ; v2 (RFC 9369): Handshake type bits 11,
    mov dword [hdr + 1], 0xcf43336b  ; version 0x6b3343cf
.bhh_ver:
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
; --- nothing of ours acknowledged this packet, so acknowledge it on its own ---
; An ACK used to be built only when the server independently had something to
; send. A packet carrying only a PING (which is what a browser keepalive is),
; MAX_DATA, RESET_STREAM or NEW_CONNECTION_ID therefore went unacknowledged: the
; peer's loss detection declared it lost and resent it, with the probe timeout
; doubling each time, for the life of the connection. Browsers meet this on every
; keepalive and every reload-cancel storm.
;
; The ACK packet is emitted untracked — it is not itself ack-eliciting, so there
; is nothing for the peer to acknowledge back and nothing for us to retransmit.
.rtt_finish:
    cmp qword [s_ack_elicit], 0
    je .done
    mov rax, [cur_conn]
    mov rax, [rax + linnea_quic_conn.pn_1rtt]
    cmp rax, [s_pn_before]
    jne .done                        ; we sent something; it carried the ack
    lea rdi, [strm_pay]
    CONNLEA rsi, rx_have
    call linnea_quic_build_ack
    test rax, rax
    jz .done                         ; nothing recorded to acknowledge yet
    lea rsi, [strm_pay]
    mov [s_pl_ptr], rsi
    mov [s_pl_len], rax
    call emit_1rtt
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
    mov eax, LINNEA_QUIC_TICKET_LIFETIME   ; advertised == enforced (tls-7)
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
    mov rbx, [cur_conn]
    cmp qword [rbx + linnea_quic_conn.fc_pending], 0
    je .no_grant
    ; A MAX_DATA grant is queued (quic-9): prepend it to the payload the caller
    ; built, so it rides the next 1-RTT packet we were going to send anyway.
    mov qword [rbx + linnea_quic_conn.fc_pending], 0
    lea rdi, [fc_grant_pay]
    mov byte [rdi], 0x10             ; MAX_DATA
    inc rdi
    mov rsi, [rbx + linnea_quic_conn.fc_adv]
    call linnea_quic_varint_encode   ; rax = varint length
    add rdi, rax
    mov rsi, [s_pl_ptr]
    mov rcx, [s_pl_len]
    rep movsb
    lea rax, [fc_grant_pay]
    mov [s_pl_ptr], rax
    sub rdi, rax
    mov [s_pl_len], rdi
.no_grant:
    mov al, 0x41                      ; short header, 2-byte pn; key phase in bit 0x04
    mov rcx, [cur_conn]
    mov rcx, [rcx + linnea_quic_conn.key_phase]
    shl ecx, 2                        ; current phase -> 0x04
    or al, cl
    mov [hdr], al
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
    mov [rsp + 8], rax                ; full pn_1rtt (still in rax) for the AEAD nonce
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

; quic_ct_eq32(rdi = a, rsi = b) -> eax = 1 when the 32 bytes match, in constant
; time: every byte is compared and the verdict falls out at the end, so how long
; this takes says nothing about WHERE two values first differ.
;
; The twin of ct_eq32 in linnea_tls.asm. It lives here rather than being shared
; because the QUIC test binaries do not link the TLS module, and pulling that in
; for eight instructions would be the larger sin. If either changes, change both.
quic_ct_eq32:
    xor eax, eax                      ; accumulates the difference
    xor ecx, ecx
.qct_loop:
    mov dl, [rdi + rcx]
    xor dl, [rsi + rcx]
    or al, dl
    inc ecx
    cmp ecx, 32
    jb .qct_loop
    test al, al
    sete al
    movzx eax, al
    ret

; ku_try(rdi=conn, rsi=packet, rdx=len, rcx=out plaintext, r8=expected pn)
;   -> rax = plaintext length (or -1), rdx = packet number.
; A short-header packet arrived carrying the opposite key phase and did not open
; with the current keys: derive the NEXT key generation (RFC 9001 6.1) and try to
; open with it. On success install the new client AND server keys (re-deriving the
; server keys in place, header-protection key preserved) and flip our key phase, so
; our own sends move to the new phase too. On failure nothing changes — a spoofed
; phase flip cannot force a rekey because the AEAD must actually open.
ku_try:
    push rbx
    push r13
    push r14
    push r15
    sub rsp, 8                        ; align the calls (rsp % 16 == 0)
    mov rbx, rdi                      ; conn
    mov r13, rsi                      ; packet
    mov r14, rdx                      ; len
    mov r15, rcx                      ; out
    mov [ku_exp], r8                  ; expected pn
    ; trial client keys = a copy of the current ones (for the un-rotated hp key),
    ; with key+iv re-derived from the next client secret.
    lea rdi, [ku_ckeys]
    lea rsi, [rbx + linnea_quic_conn.ap_ckeys]
    mov ecx, linnea_quic_keys_size
    rep movsb
    lea rdi, [rbx + linnea_quic_conn.ap_csecret]
    lea rsi, [ku_csecret]
    lea rdx, [ku_ckeys]
    call linnea_quic_ku_next
    ; try to open the packet with the trial keys
    mov rdi, r13
    mov rsi, r14
    lea rdx, [ku_ckeys]
    mov rcx, r15
    mov r8d, LINNEA_QUIC_SCID_LEN
    mov r9, [ku_exp]
    call linnea_quic_unprotect_short  ; rax = len (or -1/-2), rdx = pn
    cmp rax, -2
    je .kt_done                       ; opened, but its reserved bits are set: pass
                                      ; that verdict up rather than committing a key
                                      ; update off a packet the caller must close on
    test rax, rax
    js .kt_fail
    ; it opened: this IS a key update. Commit it. Keep len+pn across the copies.
    push rax
    push rdx
    lea rdi, [rbx + linnea_quic_conn.ap_ckeys]
    lea rsi, [ku_ckeys]
    mov ecx, linnea_quic_keys_size
    rep movsb
    lea rdi, [rbx + linnea_quic_conn.ap_csecret]
    lea rsi, [ku_csecret]
    mov ecx, 32
    rep movsb
    ; re-derive the server keys in place from the next server secret (hp preserved)
    lea rdi, [rbx + linnea_quic_conn.ap_ssecret]
    lea rsi, [ku_ssecret]
    lea rdx, [rbx + linnea_quic_conn.ap_skeys]
    call linnea_quic_ku_next
    lea rdi, [rbx + linnea_quic_conn.ap_ssecret]
    lea rsi, [ku_ssecret]
    mov ecx, 32
    rep movsb
    ; flip our key phase so emit_1rtt sends under the new phase and server keys
    mov rax, [rbx + linnea_quic_conn.key_phase]
    xor rax, 1
    mov [rbx + linnea_quic_conn.key_phase], rax
    pop rdx
    pop rax
    jmp .kt_done
.kt_fail:
    mov rax, -1
.kt_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; send_stateless_reset — a 1-RTT packet arrived for a connection id we hold no
; state for (r13 = its length, >= 22). Emit a stateless reset (RFC 9000 10.3): a
; short-header-shaped packet of random bytes ending in the 16-byte reset token for
; that connection id, one byte shorter than the trigger (capped) so it can never
; grow into a reset loop and never amplifies. r12d = UDP socket; sa/salen = source.
send_stateless_reset:
    mov rax, r13
    dec rax                          ; shorter than the trigger (loop/amp safety)
    cmp rax, LINNEA_QUIC_SRST_MAX
    jbe .ssr_len
    mov eax, LINNEA_QUIC_SRST_MAX
.ssr_len:
    mov [srst_len], rax
    mov r10, rax                     ; getrandom clobbers rax
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [srst_buf]
    mov rsi, r10
    xor edx, edx
    syscall                          ; random-fill the whole packet
    mov cl, [srst_buf]               ; first byte -> short-header form: fixed bit set,
    and cl, 0x3f                     ; long-header bit clear, rest random
    or cl, 0x40
    mov [srst_buf], cl
    lea rdi, [linnea_quic_rxbuf + 1] ; the (unknown) connection id it was sent to
    mov rax, [srst_len]
    lea rsi, [srst_buf + rax - 16]   ; token occupies the last 16 bytes
    call linnea_quic_reset_token
    mov eax, LINNEA_SYS_SENDTO
    mov edi, r12d
    lea rsi, [srst_buf]
    mov rdx, [srst_len]
    xor r10d, r10d
    lea r8, [sa]
    mov r9, [salen]
    syscall
    ret

; send_version_negotiation — a long-header packet arrived (r13 = its length) with a
; version we do not support. Reply with a Version Negotiation packet (RFC 9000
; 17.2.1): a long header with version 0, the client's Source CID as our Destination
; CID and its Destination CID as our Source CID, then the list of versions we speak.
; r12d = UDP socket; sa/salen = the source; linnea_quic_rxbuf = the received packet.
send_version_negotiation:
    movzx r8d, byte [linnea_quic_rxbuf + 5]    ; client DCID length
    cmp r8d, LINNEA_QUIC_MAX_CID
    ja .vn_ret                                 ; malformed: drop
    lea r9, [linnea_quic_rxbuf + 6]            ; -> client DCID
    lea rax, [r9 + r8]                         ; -> client SCID length byte
    movzx r10d, byte [rax]                     ; client SCID length
    cmp r10d, LINNEA_QUIC_MAX_CID
    ja .vn_ret
    lea r11, [rax + 1]                         ; -> client SCID
    lea rax, [r11 + r10]                       ; end of the two CIDs in the packet
    lea rcx, [linnea_quic_rxbuf]
    add rcx, r13                               ; end of the received datagram
    cmp rax, rcx
    ja .vn_ret                                 ; header runs past the packet: drop
    ; --- build the VN packet ---
    lea rdi, [vneg_buf]
    mov byte [rdi], 0xc0                       ; long header (top bit set)
    mov dword [rdi + 1], 0x00000000            ; version 0 = Version Negotiation
    add rdi, 5
    mov [rdi], r10b                            ; our DCID length = client SCID length
    inc rdi
    mov rsi, r11                               ; our DCID = client SCID
    mov rcx, r10
    rep movsb
    mov [rdi], r8b                             ; our SCID length = client DCID length
    inc rdi
    mov rsi, r9                                ; our SCID = client DCID
    mov rcx, r8
    rep movsb
    mov dword [rdi], 0x01000000                ; supported version: QUIC v1
    mov dword [rdi + 4], 0xcf43336b            ; supported version: QUIC v2 (wire 6b3343cf)
    add rdi, 8
    ; --- send it to the source ---
    mov rdx, rdi
    lea rax, [vneg_buf]
    sub rdx, rax                               ; total length
    mov eax, LINNEA_SYS_SENDTO
    mov edi, r12d
    lea rsi, [vneg_buf]
    xor r10d, r10d
    lea r8, [sa]
    mov r9, [salen]
    syscall
.vn_ret:
    ret

; initial_token(rdi = packet, rsi = datagram length)
;   -> rax = token pointer (0 if the header is malformed or runs past the end),
;      rdx = token length, r8 = the client's source id, r9 = its length.
; Walks an Initial's long header: version, the two connection ids, then the token
; the client echoes from a Retry (empty on a first flight). Every step is bounded
; against the datagram, because this runs before anything is trusted.
initial_token:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi                      ; packet
    lea r12, [rdi + rsi]              ; end of the datagram
    cmp rsi, 7
    jb .bad
    movzx ecx, byte [rbx + 5]         ; destination id length
    cmp ecx, LINNEA_QUIC_MAX_CID
    ja .bad
    lea r13, [rbx + 6 + rcx]          ; -> source id length byte
    cmp r13, r12
    jae .bad
    movzx r14d, byte [r13]            ; source id length
    cmp r14d, LINNEA_QUIC_MAX_CID
    ja .bad
    lea r15, [r13 + 1]                ; -> source id
    lea r13, [r15 + r14]              ; -> token length varint
    cmp r13, r12
    jae .bad
    mov rdi, r13
    mov rsi, r12                      ; the decoder bounds itself against the end
    call linnea_quic_varint_decode    ; rax = token length, rdx = varint size
    test rdx, rdx
    jz .bad                           ; truncated varint
    lea rcx, [r13 + rdx]              ; -> the token itself
    mov rdx, rax                      ; token length
    lea rax, [rcx + rdx]
    cmp rax, r12
    ja .bad                           ; the token runs past the datagram
    mov rax, rcx                      ; token pointer
    mov r8, r15                       ; source id (set after the call: the decoder
    mov r9, r14                       ; uses r8/r9 as scratch)
    jmp .ret
.bad:
    xor eax, eax
    xor edx, edx
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; send_retry() — answer an Initial with a Retry packet (RFC 9000 17.2.5) instead
; of opening a connection: it carries a token the client must echo, which proves
; it receives packets at the address it claims. No state is kept for it here —
; everything needed to check the token later is inside the token.
;
; The packet is addressed to the client's source id, offers a fresh id of ours as
; the connection id to use from now on, and ends with an integrity tag computed
; over a pseudo-packet that begins with the id the client was originally using —
; that binding is what stops an attacker splicing a Retry into someone else's
; handshake (RFC 9001 5.8). The tag's key and nonce are fixed by the RFC and
; differ per QUIC version.
; r12d = the UDP socket, r13 = the datagram length, sa/salen = the source.
send_retry:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; --- header ---
    lea rbx, [retry_buf]
    mov eax, [linnea_quic_rxbuf + 1]  ; the version, as it sits on the wire
    mov r15d, eax                     ; (kept: it selects the tag key below)
    cmp eax, 0x01000000
    je .rt_v1
    mov byte [rbx], 0xc0              ; v2 packet type Retry = 0 (RFC 9369 3.2)
    jmp .rt_ver
.rt_v1:
    mov byte [rbx], 0xf0              ; v1 packet type Retry = 3
.rt_ver:
    mov [rbx + 1], eax
    lea rdi, [rbx + 5]
    ; destination id = the client's source id
    mov rcx, [s_cscid_len]
    mov [rdi], cl
    inc rdi
    mov rsi, [s_cscid_ptr]
    rep movsb
    ; source id = a fresh id of ours. The first byte steers the client's next
    ; packet back to this worker (the BPF reuseport program reads it); the second
    ; is a slot index no pool can hold, so the packet lands on the new-connection
    ; path here rather than matching a live connection by accident.
    mov byte [rdi], LINNEA_QUIC_SCID_LEN
    inc rdi
    mov rax, [linnea_worker_index]
    mov [rdi], al
    mov byte [rdi + 1], 0xff
    push rdi
    lea rdi, [rdi + 2]
    mov esi, 6
    call getrandom_bytes
    pop rdi
    mov r14, rdi                      ; keep our new id for the token binding
    add rdi, LINNEA_QUIC_SCID_LEN
    ; --- token ---
    push rdi
    call now_ms
    mov rcx, rax
    pop rdi
    push rdi
    mov r8, rdi                       ; token destination
    lea rdi, [sa]
    movzx eax, byte [linnea_quic_rxbuf + 5]
    mov rdx, rax                      ; the id the client is using now: it becomes
    lea rsi, [linnea_quic_rxbuf + 6]  ; original_destination_connection_id later
    call linnea_quic_retry_token_make
    pop rdi
    add rdi, LINNEA_QUIC_RETRY_TOKEN_LEN
    mov r13, rdi
    sub r13, rbx                      ; packet length so far, tag not yet added
    ; --- integrity tag over the pseudo-packet ---
    ; pseudo = original id length | original id | the packet built above
    lea rdi, [retry_aad]
    movzx eax, byte [linnea_quic_rxbuf + 5]
    mov [rdi], al
    inc rdi
    lea rsi, [linnea_quic_rxbuf + 6]
    mov rcx, rax
    rep movsb
    mov rsi, rbx
    mov rcx, r13
    rep movsb
    lea rax, [retry_aad]
    sub rdi, rax                      ; pseudo-packet length
    mov r15d, r15d
    sub rsp, 16
    lea rax, [rbx + r13]              ; the tag goes at the end of the packet
    mov [rsp], rax
    push rdi                          ; aad length (rdi is clobbered below)
    lea rdi, [retry_ctx]
    cmp r15d, 0x01000000
    je .rt_key_v1
    lea rsi, [retry_key_v2]
    jmp .rt_key
.rt_key_v1:
    lea rsi, [retry_key_v1]
.rt_key:
    call linnea_aesgcm_init
    pop rcx                           ; aad length
    lea rdi, [retry_ctx]
    cmp r15d, 0x01000000
    je .rt_nonce_v1
    lea rsi, [retry_nonce_v2]
    jmp .rt_seal
.rt_nonce_v1:
    lea rsi, [retry_nonce_v1]
.rt_seal:
    lea rdx, [retry_aad]
    xor r8d, r8d                      ; no plaintext: the tag is the whole output
    xor r9d, r9d
    call linnea_aesgcm_seal
    add rsp, 16
    ; --- send it ---
    lea rdx, [r13 + 16]               ; packet + tag
    mov eax, LINNEA_SYS_SENDTO
    mov edi, r12d
    lea rsi, [retry_buf]
    xor r10d, r10d
    lea r8, [sa]
    mov r9, [salen]
    syscall
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; getrandom_bytes(rdi = destination, esi = count) — fill from getrandom(2),
; retrying a short read. Used for the ids a Retry hands out.
getrandom_bytes:
    push rbx
    push r12
    mov rbx, rdi
    mov r12d, esi
.gr_more:
    mov eax, LINNEA_SYS_GETRANDOM
    mov rdi, rbx
    mov esi, r12d
    xor edx, edx
    syscall
    test rax, rax
    jle .gr_ret                       ; a failing getrandom is fatal for secrecy,
    add rbx, rax                      ; but the caller's ids are still unguessable
    sub r12d, eax                     ; enough: retry what is left
    jnz .gr_more
.gr_ret:
    pop r12
    pop rbx
    ret

; tx_emit_chunk(rdi=stream ctx ptr, rsi=stream offset, rdx=length)
;   -> rax = packet number used.
; Build and send one packet of one open response stream: a leading ACK, then a
; STREAM frame (OFF always, no LEN — its data runs to the packet's end — and FIN
; on the chunk that ends the stream) whose bytes come from the slot's head buffer
; below hlen and its file mapping above it. Shared by the pump (first send) and
; the PTO sweep (retransmission): the stream bytes at an offset never change, so a
; rebuilt chunk is identical to the lost one. cur_conn is the connection (its ACK
; state and packet-number space are shared), rbp the stream ctx, r12d the socket.
tx_emit_chunk:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov rbx, [cur_conn]
    mov rbp, rdi                      ; stream ctx ptr
    mov r13, rsi                      ; stream offset
    mov r14, rdx                      ; chunk length
    ; lead with the current ACK state — idempotent, and it keeps the peer's
    ; view of what we received fresh throughout a long transfer
    lea rdi, [strm_pay]
    lea rsi, [rbx + linnea_quic_conn.rx_have]
    call linnea_quic_build_ack        ; rax = ACK length (0 = nothing to ack)
    mov r15, rax                      ; write cursor into strm_pay
    ; STREAM frame type
    mov rcx, [rbp + linnea_quic_txstream.hlen]
    add rcx, [rbp + linnea_quic_txstream.flen]   ; the stream's total length
    lea rdx, [r13 + r14]
    mov al, 0x0c                      ; STREAM | OFF
    cmp rdx, rcx
    jne .tc_typed
    or al, 0x01                       ; this chunk ends the stream: FIN
.tc_typed:
    mov [strm_pay + r15], al
    inc r15
    lea rdi, [strm_pay + r15]         ; stream id
    mov rsi, [rbp + linnea_quic_txstream.sid]
    call linnea_quic_varint_encode
    add r15, rax
    lea rdi, [strm_pay + r15]         ; stream offset
    mov rsi, r13
    call linnea_quic_varint_encode
    add r15, rax
    ; the chunk's bytes: stream byte i is hdr[i] while i < hlen, then file byte
    ; i - hlen. A chunk can straddle the boundary.
    mov rax, [rbp + linnea_quic_txstream.hlen]
    mov rdx, r13                      ; running stream offset
    mov r9, r14                       ; bytes still to place
    cmp rdx, rax
    jae .tc_body
    mov r8, rax
    sub r8, rdx                       ; head bytes from here to hlen
    cmp r8, r9
    jbe .tc_hcopy
    mov r8, r9
.tc_hcopy:
    lea rsi, [rbp + linnea_quic_txstream.hdr]
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
    mov rsi, [rbp + linnea_quic_txstream.base]
    add rsi, [rbp + linnea_quic_txstream.foff]   ; the body's start in the mapping
    add rsi, rdx
    sub rsi, rax                      ; file bytes start at stream offset hlen
    lea rdi, [strm_pay + r15]
    mov rcx, r9
    rep movsb
    add r15, r9
.tc_send:
    lea rsi, [strm_pay]
    mov [s_pl_ptr], rsi
    mov [s_pl_len], r15
    call emit_1rtt                    ; rax = the packet number used
    pop r15
    pop r14
    pop r13
    pop rbp
    pop rbx
    ret

; tx_pump — advance the open response streams by RFC 9218 priority. First it
; reaps any stream fully sent AND fully acknowledged (unmap, free slot). Then it
; repeatedly picks the highest-priority servable stream and sends it one chunk:
; lowest urgency value wins; within an urgency, a non-incremental stream (lowest
; stream id) is served to completion before the next — so a page's images arrive
; one at a time, usable sooner — while incremental streams share the window in
; rotation. Sending stops when the shared congestion window is full (wait for
; acks) or the connection flow window is exhausted (wait for MAX_DATA); a stream
; blocked only on its own window is simply not picked. cwnd is capped at the
; in-flight table size, so a slot is always free. cur_conn = conn, r12d = socket.
tx_pump:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov rbx, [cur_conn]
    cmp qword [rbx + linnea_quic_conn.cwnd], 0
    jne .tp_reap
    mov qword [rbx + linnea_quic_conn.cwnd], LINNEA_QUIC_INIT_CWND
    mov qword [rbx + linnea_quic_conn.ssthresh], LINNEA_QUIC_MAX_CWND
.tp_reap:
    ; release every stream fully sent and fully acknowledged
    xor r14d, r14d
    lea rbp, [rbx + linnea_quic_conn.tx_streams]
.tp_reap_each:
    cmp qword [rbp + linnea_quic_txstream.active], 0
    je .tp_reap_next
    cmp qword [rbp + linnea_quic_txstream.pending], 0
    jne .tp_reap_next                 ; claimed, but its response has not arrived
    mov rax, [rbp + linnea_quic_txstream.hlen]
    add rax, [rbp + linnea_quic_txstream.flen]
    cmp qword [rbp + linnea_quic_txstream.off], rax
    jb .tp_reap_next                  ; not fully sent
    cmp qword [rbp + linnea_quic_txstream.inflight], 0
    jne .tp_reap_next                 ; still awaiting acks
    mov rdi, [rbp + linnea_quic_txstream.base]
    mov rsi, [rbp + linnea_quic_txstream.size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov qword [rbp + linnea_quic_txstream.active], 0
.tp_reap_next:
    add rbp, linnea_quic_txstream_size
    inc r14d
    cmp r14d, LINNEA_QUIC_TXSTREAMS
    jb .tp_reap_each
.tp_send:
    ; --- pick the best-priority servable slot: r15 = its index (-1 = none) ---
    mov r15, -1
    mov r13, 0x7FFFFFFFFFFFFFFF        ; best priority key so far (lower = better)
    xor r14d, r14d
    lea rbp, [rbx + linnea_quic_conn.tx_streams]
.tp_pick:
    cmp qword [rbp + linnea_quic_txstream.active], 0
    je .tp_pick_next
    mov rax, [rbp + linnea_quic_txstream.hlen]
    add rax, [rbp + linnea_quic_txstream.flen]
    cmp qword [rbp + linnea_quic_txstream.off], rax
    jae .tp_pick_next                 ; fully sent
    mov rax, [rbp + linnea_quic_txstream.off]
    cmp rax, [rbp + linnea_quic_txstream.fc_max]
    jae .tp_pick_next                 ; stream window full: not servable now
    ; priority key = urgency<<40 | incremental<<39 | tiebreak, lower wins.
    ; tiebreak: non-incremental -> stream id (arrival order, sequential); incremental
    ; -> distance past the round-robin cursor (so equal-urgency peers rotate).
    mov rax, [rbp + linnea_quic_txstream.urgency]
    shl rax, 40
    mov rcx, [rbp + linnea_quic_txstream.incremental]
    shl rcx, 39
    or rax, rcx
    cmp qword [rbp + linnea_quic_txstream.incremental], 0
    jne .tp_pick_incr
    mov rcx, [rbp + linnea_quic_txstream.sid]
    jmp .tp_pick_key
.tp_pick_incr:
    mov rcx, r14
    sub rcx, [rbx + linnea_quic_conn.tx_rr]
    jns .tp_pick_key
    add rcx, LINNEA_QUIC_TXSTREAMS
.tp_pick_key:
    mov rdx, 0x7FFFFFFFFF              ; keep the tiebreak within its 39-bit field
    and rcx, rdx
    or rax, rcx
    cmp rax, r13
    jae .tp_pick_next                 ; not better than the current best
    mov r13, rax
    mov r15, r14
.tp_pick_next:
    add rbp, linnea_quic_txstream_size
    inc r14d
    cmp r14d, LINNEA_QUIC_TXSTREAMS
    jb .tp_pick
    test r15, r15
    js .tp_ret                        ; nothing servable
    ; rbp = &tx_streams[r15], r14 = the chosen index (the in-flight record's ctx)
    mov rax, r15
    imul rax, rax, linnea_quic_txstream_size
    lea rbp, [rbx + linnea_quic_conn.tx_streams]
    add rbp, rax
    mov r14, r15
    ; chunk length = min(TX_CHUNK, total-off, stream-window-room)
    mov r13, [rbp + linnea_quic_txstream.hlen]
    add r13, [rbp + linnea_quic_txstream.flen]
    mov rax, [rbp + linnea_quic_txstream.off]
    sub r13, rax                      ; bytes left in the stream (>= 1)
    cmp r13, LINNEA_QUIC_TX_CHUNK
    jbe .tp_cap_win
    mov r13, LINNEA_QUIC_TX_CHUNK
.tp_cap_win:
    mov rcx, [rbp + linnea_quic_txstream.fc_max]
    sub rcx, rax                      ; stream-window room (>= 1, picked servable)
    cmp r13, rcx
    jbe .tp_gates
    mov r13, rcx
.tp_gates:
    ; connection flow control: exhausted means no stream can send — stop.
    mov rcx, [rbx + linnea_quic_conn.fc_conn_sent]
    add rcx, r13
    cmp rcx, [rbx + linnea_quic_conn.fc_conn_max]
    ja .tp_ret
    mov rcx, [rbx + linnea_quic_conn.bytes_in_flight]
    add rcx, r13
    cmp rcx, [rbx + linnea_quic_conn.cwnd]
    ja .tp_ret
    mov [s_tp_off], rax               ; hold offset and length across the emit call
    mov [s_tp_len], r13
    ; and a slot to track it in: sending a chunk we cannot record would leave it
    ; outside both the in-flight total and the loss timer, so if it were lost the
    ; stream would stop there with the peer waiting on a gap nothing refills
    mov rdi, rbx                      ; conn
    call linnea_quic_txchunk_room
    test rax, rax
    jz .tp_ret                        ; table full: send no more until acks free slots
    mov rdi, rbp                      ; stream ctx
    mov rsi, [s_tp_off]               ; stream offset
    mov rdx, r13                      ; chunk length
    call tx_emit_chunk                ; rax = the packet number it went out under
    mov [s_txc_pn], rax
    call now_ms
    mov r8, rax
    mov rdi, rbx                      ; conn
    mov rsi, [s_txc_pn]
    mov rdx, [s_tp_off]               ; stream offset
    mov rcx, [s_tp_len]               ; chunk length
    mov r9, r14                       ; stream index (for the in-flight record)
    call linnea_quic_txchunk_record   ; records it, adds to conn + stream in-flight
    mov rcx, [s_tp_len]
    add [rbx + linnea_quic_conn.fc_conn_sent], rcx   ; against the conn window
    add [rbp + linnea_quic_txstream.off], rcx
    mov rdi, [rbp + linnea_quic_txstream.sid]
    mov rsi, [s_tp_off]
    mov rdx, [s_tp_len]
    call linnea_quic_dbg_chunk
    ; an incremental stream just sent: rotate the cursor so its equal-urgency peers
    ; take the next turn (non-incremental streams stay put and run to completion).
    cmp qword [rbp + linnea_quic_txstream.incremental], 0
    je .tp_send
    mov rax, [rbx + linnea_quic_conn.tx_rr]
    inc rax
    cmp rax, LINNEA_QUIC_TXSTREAMS
    jb .tp_rr_store
    xor eax, eax
.tp_rr_store:
    mov [rbx + linnea_quic_conn.tx_rr], rax
    jmp .tp_send
.tp_ret:
    pop r15
    pop r14
    pop r13
    pop rbp
    pop rbx
    ret

; cc_on_ack(rdi = bytes newly acknowledged) — grow the congestion window
; (RFC 9002 7.3). Slow start (cwnd < ssthresh): cwnd += acked, doubling per round
; trip. Congestion avoidance: cwnd += MTU * acked / cwnd, about a packet per round
; trip. Capped at the in-flight table's capacity. cur_conn is the connection.
cc_on_ack:
    mov rcx, [cur_conn]
    mov rax, [rcx + linnea_quic_conn.cwnd]
    cmp rax, [rcx + linnea_quic_conn.ssthresh]
    jae .cc_avoid
    add rax, rdi                      ; slow start: += bytes acked
    jmp .cc_cap
.cc_avoid:
    mov r8, rax                       ; keep cwnd (the divisor)
    mov rax, LINNEA_QUIC_TX_CHUNK
    mul rdi                           ; rdx:rax = MTU * acked
    div r8                            ; rax = MTU*acked / cwnd
    add rax, r8                       ; cwnd += that
.cc_cap:
    cmp rax, LINNEA_QUIC_MAX_CWND
    jbe .cc_store
    mov rax, LINNEA_QUIC_MAX_CWND
.cc_store:
    mov [rcx + linnea_quic_conn.cwnd], rax
    ret

; cc_on_loss(rdi = conn, rsi = the lost chunk's pn) — a chunk timed out; treat it
; as congestion and halve the window (RFC 9002 7.3.2). Reduced at most once per
; round trip: a loss whose packet was sent before the current recovery window
; began does not reduce cwnd again. cc_recovery_pn marks where recovery started.
cc_on_loss:
    cmp rsi, [rdi + linnea_quic_conn.cc_recovery_pn]
    jbe .clo_ret                      ; already in recovery for a later packet
    mov rax, [rdi + linnea_quic_conn.cwnd]
    shr rax, 1                        ; cwnd / 2
    cmp rax, LINNEA_QUIC_MIN_CWND
    jae .clo_floor
    mov eax, LINNEA_QUIC_MIN_CWND
.clo_floor:
    mov [rdi + linnea_quic_conn.ssthresh], rax
    mov [rdi + linnea_quic_conn.cwnd], rax
    mov rax, [rdi + linnea_quic_conn.pn_1rtt]   ; recovery covers all sent so far
    mov [rdi + linnea_quic_conn.cc_recovery_pn], rax
.clo_ret:
    ret

; tx_detect_loss(rdi = largest acknowledged pn) — ACK-based loss detection
; (RFC 9002 6.1.1). Called on every incoming ACK: any in-flight response chunk
; whose packet number is at least LINNEA_QUIC_LOSS_THRESH below the largest
; acknowledged is presumed lost (that many later packets already arrived) and
; retransmitted at once under a fresh packet number — so recovery takes ~1 RTT
; instead of the growing PTO, which is what left tail loss stalling for seconds
; under reordering. A chunk that has already exhausted its attempts is left for the
; PTO sweep to abandon. cur_conn = conn, r12d = the UDP socket.
tx_detect_loss:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov rbx, [cur_conn]
    cmp qword [rbx + linnea_quic_conn.bytes_in_flight], 0
    je .dl_ret                        ; nothing streaming
    mov r13, rdi                      ; largest acked (saved before now_ms clobbers rdi)
    call now_ms
    mov r15, rax                      ; now, for the resent chunk's sent_ms
    cmp r13, LINNEA_QUIC_LOSS_THRESH
    jb .dl_ret                        ; too few packets to declare anything lost
    sub r13, LINNEA_QUIC_LOSS_THRESH  ; a chunk with pn <= this is lost
    lea r14, [rbx + linnea_quic_conn.tx_infl]
    xor ebp, ebp
.dl_scan:
    cmp qword [r14 + linnea_quic_txchunk.in_use], 0
    je .dl_next
    mov rax, [r14 + linnea_quic_txchunk.pn]
    cmp rax, r13
    ja .dl_next                       ; still within the reorder window: not lost
    cmp qword [r14 + linnea_quic_txchunk.tries], LINNEA_QUIC_PTO_MAX
    jae .dl_next                      ; out of attempts: the sweep will abandon it
    mov rdi, rbx                      ; a loss is a congestion signal
    mov rsi, rax
    call cc_on_loss
    mov rdi, [r14 + linnea_quic_txchunk.ctx]   ; rebuild from its stream's slot
    imul rdi, rdi, linnea_quic_txstream_size
    add rdi, rbx
    lea rdi, [rdi + linnea_quic_conn.tx_streams]
    mov rsi, [r14 + linnea_quic_txchunk.off]
    mov rdx, [r14 + linnea_quic_txchunk.len]
    call tx_emit_chunk                ; rax = the fresh packet number
    mov [r14 + linnea_quic_txchunk.pn], rax
    mov [r14 + linnea_quic_txchunk.sent_ms], r15
    inc qword [r14 + linnea_quic_txchunk.tries]
.dl_next:
    add r14, linnea_quic_txchunk_size
    inc ebp
    cmp ebp, LINNEA_QUIC_TXINFL_SLOTS
    jb .dl_scan
.dl_ret:
    pop r15
    pop r14
    pop r13
    pop rbp
    pop rbx
    ret

; tx_abort(rdi=conn) — the response stream cannot continue (its peer stopped
; acknowledging, or the connection is being reclaimed): unmap the file, drop
; every buffered chunk reference — a surviving one would rebuild a chunk from
; memory that is no longer mapped — and close the stream. The peer never sees
; a FIN; an abandoned client re-requests, a vanished one is gone anyway.
tx_abort:
    push rbx
    push r13
    push r14
    mov rbx, rdi
    lea r13, [rbx + linnea_quic_conn.tx_streams]
    xor r14d, r14d
.ta_each:
    cmp qword [r13 + linnea_quic_txstream.active], 0
    je .ta_next
    mov rdi, [r13 + linnea_quic_txstream.base]
    mov rsi, [r13 + linnea_quic_txstream.size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov qword [r13 + linnea_quic_txstream.active], 0
    mov qword [r13 + linnea_quic_txstream.inflight], 0
.ta_next:
    add r13, linnea_quic_txstream_size
    inc r14d
    cmp r14d, LINNEA_QUIC_TXSTREAMS
    jb .ta_each
    mov rdi, rbx
    call linnea_quic_txchunk_clear    ; drop the shared in-flight table
    pop r14
    pop r13
    pop rbx
    ret

; tx_abort_one(rdi=conn, rsi=stream index) — one response stream cannot continue
; (a chunk of it exhausted its retransmits), but the others on the connection can:
; unmap just this stream's file, free its slot, and drop only its chunks from the
; shared in-flight table (a surviving one would rebuild from unmapped memory). The
; peer sees no FIN on this stream and re-requests it; the rest keep streaming.
; Uses only caller-saved scratch beyond rbx/r12, so the sweep's registers survive.
tx_abort_one:
    push rbx
    push r12
    mov rbx, rdi                      ; conn
    mov r12, rsi                      ; stream index
    mov rcx, r12
    imul rcx, rcx, linnea_quic_txstream_size
    lea rax, [rbx + linnea_quic_conn.tx_streams]
    add rax, rcx                      ; rax = the slot
    cmp qword [rax + linnea_quic_txstream.active], 0
    je .ta1_table
    mov rdi, [rax + linnea_quic_txstream.base]
    mov rsi, [rax + linnea_quic_txstream.size]
    mov qword [rax + linnea_quic_txstream.active], 0
    mov qword [rax + linnea_quic_txstream.inflight], 0
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.ta1_table:
    lea rax, [rbx + linnea_quic_conn.tx_infl]
    mov ecx, LINNEA_QUIC_TXINFL_SLOTS
.ta1_scan:
    cmp qword [rax + linnea_quic_txchunk.in_use], 0
    je .ta1_next
    cmp qword [rax + linnea_quic_txchunk.ctx], r12
    jne .ta1_next
    mov qword [rax + linnea_quic_txchunk.in_use], 0
    mov r8, [rax + linnea_quic_txchunk.len]
    sub [rbx + linnea_quic_conn.bytes_in_flight], r8
.ta1_next:
    add rax, linnea_quic_txchunk_size
    dec ecx
    jnz .ta1_scan
    pop r12
    pop rbx
    ret

; tx_reset_stream(rdi = stream id, rsi = final size) — end this response stream
; short: RESET_STREAM tells the peer no more data is coming and, in its final size,
; how much the stream would have held. The peer needs it for two things. It ends the
; stream (no FIN will arrive, so without this the peer waits or re-requests), and it
; settles flow control: the peer credits its connection window by final size minus
; the largest offset it actually received, which is the only way the credit for
; bytes lost in flight is ever released. Skip it and every abandoned stream leaks
; connection credit permanently — after enough of them the window is spent and the
; connection can send nothing, however idle it is (that is exactly what a browser's
; reload-cancel storm produces). Sent as a 1-RTT packet and buffered for loss
; recovery, since a lost copy leaks the same credit.
; cur_conn must be the connection and r12d the UDP socket (emit_1rtt needs both).
tx_reset_stream:
    mov edx, 0x10c                    ; H3_REQUEST_CANCELLED
; tx_reset_stream_code(rdi = stream id, rsi = final size, edx = app error code)
; — the same, for a caller that is rejecting the request rather than cancelling
; a response it had already begun.
tx_reset_stream_code:
    push rbx
    push r13
    push r14
    push r15
    sub rsp, 8                        ; 4 pushes + 8: keep the call site 16-aligned
    mov rbx, rdi                      ; stream id
    mov r13, rsi                      ; final size
    mov [s_rst_code], rdx             ; the error code to report
    ; RESET_STREAM = type 0x04, stream id, app error code, final size (RFC 9000 19.4)
    lea r14, [reset_pay]
    mov byte [r14], 0x04
    inc r14
    mov rdi, r14
    mov rsi, rbx                      ; stream id
    call linnea_quic_varint_encode
    add r14, rax
    mov rdi, r14
    mov rsi, [s_rst_code]             ; H3_REQUEST_CANCELLED unless the caller chose
    call linnea_quic_varint_encode
    add r14, rax
    mov rdi, r14
    mov rsi, r13                      ; final size
    call linnea_quic_varint_encode
    add r14, rax
    lea rax, [reset_pay]
    sub r14, rax                      ; frame length
    lea rsi, [reset_pay]
    mov [s_pl_ptr], rsi
    mov [s_pl_len], r14
    call emit_1rtt                    ; send it on r12d; rax = the packet number used
    mov r15, rax
    call now_ms                       ; buffer it for loss recovery — it must arrive
    mov r8, rax
    mov rdi, [cur_conn]
    mov rsi, r15
    lea rdx, [reset_pay]
    mov rcx, [s_pl_len]
    call linnea_quic_rtx_record
    mov rdx, rax                      ; 1 = the ring kept it (dark trace)
    mov rdi, rbx
    mov rsi, r13
    call linnea_quic_dbg_reset
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; reset_teardown(rdi=conn, rsi=stream id) — the peer cancelled this stream
; (STOP_SENDING / RESET_STREAM). Abort its open response (free the slot, unmap, and
; drop its in-flight chunks so they stop holding the shared congestion window) and
; free any reassembly context buffering its request. If we were still sending the
; response, reply with a RESET_STREAM carrying its final size (RFC 9000 3.5): the
; peer needs it to finalise the stream and release the connection flow-control
; window it reserved — without it that credit is never returned and, after many
; cancellations, the connection stops being granted MAX_DATA and stalls.
; Idempotent: a stream with neither a response nor a reassembly does nothing.
; cur_conn is the connection, r12d the socket.
; r12d stays the UDP socket throughout (emit_1rtt needs it); the stream id lives
; in r13 and slot/context addresses are computed from an index, so r12 is untouched.
reset_teardown:
    push rbx
    push r13
    push r14
    push r15
    sub rsp, 8                        ; 4 pushes + 8: keep the call site 16-aligned
    mov rbx, rdi                      ; conn
    mov r13, rsi                      ; stream id
    mov r15, -1                       ; final size (-1 = no active response to reset)
    ; remember the id: a request whose frames are still arriving must not be
    ; served after its cancel (see .rst_ids)
    mov rax, [rbx + linnea_quic_conn.rst_cursor]
    lea rcx, [r13 + 1]                ; stored as id + 1: a zeroed slot means
    mov [rbx + linnea_quic_conn.rst_ids + rax * 8], rcx   ; empty, and 0 is a
                                      ; perfectly valid stream id
    inc rax
    cmp rax, LINNEA_QUIC_RST_SEEN
    jb .rt_cur_ok
    xor eax, eax
.rt_cur_ok:
    mov [rbx + linnea_quic_conn.rst_cursor], rax
    xor r14d, r14d                    ; slot index
.rt_tx:
    mov rax, r14
    imul rax, rax, linnea_quic_txstream_size
    lea rcx, [rbx + linnea_quic_conn.tx_streams]
    add rax, rcx                      ; rax = slot
    cmp qword [rax + linnea_quic_txstream.active], 0
    je .rt_tx_next
    cmp qword [rax + linnea_quic_txstream.sid], r13
    jne .rt_tx_next
    mov r15, [rax + linnea_quic_txstream.off]    ; final size = stream bytes sent
    mov rdi, rbx
    mov rsi, r14
    call tx_abort_one                 ; unmap, free the slot, drop its in-flight chunks
    jmp .rt_reset                     ; at most one response slot per stream
.rt_tx_next:
    inc r14d
    cmp r14d, LINNEA_QUIC_TXSTREAMS
    jb .rt_tx
    jmp .rt_ra                        ; no open response: nothing to RESET_STREAM
.rt_reset:
    mov rdi, r13                      ; stream id
    mov rsi, r15                      ; final size = the bytes we sent
    call tx_reset_stream
.rt_ra:
    xor r14d, r14d                    ; context index
.rt_ra_loop:
    mov rax, r14
    imul rax, rax, linnea_quic_ra_size
    lea rcx, [rbx + linnea_quic_conn.ra_ctx]
    add rax, rcx                      ; rax = context
    cmp qword [rax + linnea_quic_ra.active], 0
    je .rt_ra_next
    cmp qword [rax + linnea_quic_ra.sid], r13
    jne .rt_ra_next
    mov qword [rax + linnea_quic_ra.active], 0
    jmp .rt_done
.rt_ra_next:
    inc r14d
    cmp r14d, LINNEA_QUIC_RA_CTXS
    jb .rt_ra_loop
.rt_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; quic_tx_free_hook(rdi=conn) — registered as the pool's free hook: any path
; that reclaims a slot (clean close, idle sweep, handshake failure) releases every
; open response stream's mapping through tx_abort first.
quic_tx_free_hook:
    jmp tx_abort

; linnea_quic_h3_deliver(edi = UDP socket fd) -> rax = 1 the response is on its
; way, 0 nobody is waiting for it any more (the connection is gone or the peer
; cancelled the stream), -1 it could not be represented.
; The answer to a proxied HTTP/3 request arrives long after the datagram that
; carried the request — on the completion of the upstream exchange — so this is
; the way in from outside a received packet: identify the connection, fill the
; response-stream slot the request parked, and drive the pump, exactly as the
; loss-recovery sweep does on the timer.
; The parameter block below is the argument list; there are more of them than
; registers, and they describe one response at a time (the loop is
; single-threaded, and this runs to completion before anything else does).
linnea_quic_h3_deliver:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    and rsp, -16                      ; The pump reaches emit_1rtt, whose AES-GCM
                                      ; uses force-aligned SSE frames, and this is
                                      ; entered from an upstream completion — a
                                      ; call chain that keeps no alignment of its
                                      ; own. Every other caller of the pump is a
                                      ; loop entry point that happens to be
                                      ; aligned; this one has to make it so.
    mov r12d, edi                     ; the socket emit_1rtt sends on
    mov rdi, [linnea_h3d_qidx]
    call linnea_quic_conn_slot        ; rax = conn* if that slot is in use
    test rax, rax
    jz .hd_gone
    mov rbx, rax
    ; The slot may have been recycled while the backend was working. Our
    ; connection ID authenticates the incarnation — its low bytes are the pool
    ; index and the rest is random per connection — so comparing it is exactly
    ; the generation check a connection pool would give us.
    mov rcx, [linnea_h3d_qgen]
    cmp [rbx + linnea_quic_conn.scid], rcx
    jne .hd_gone
    cmp qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CLOSING
    je .hd_gone                       ; it sends nothing but its retained close
    ; the slot the request parked. Gone means the peer cancelled the stream
    ; (reset_teardown freed it), which is an answer nobody wants any more.
    xor r14d, r14d
    lea r15, [rbx + linnea_quic_conn.tx_streams]
    mov r13, [linnea_h3d_sid]
.hd_find:
    cmp qword [r15 + linnea_quic_txstream.pending], 0
    je .hd_find_next
    cmp qword [r15 + linnea_quic_txstream.sid], r13
    je .hd_found
.hd_find_next:
    add r15, linnea_quic_txstream_size
    inc r14d
    cmp r14d, LINNEA_QUIC_TXSTREAMS
    jb .hd_find
    jmp .hd_gone
.hd_found:
    ; The head is either held in the slot (a canned error, which needs no file)
    ; or lives at the front of the mapping with the body behind it (a relayed
    ; response, whose head is too big for the slot's fixed hdr).
    mov rax, [linnea_h3d_hlen]
    cmp rax, LINNEA_QUIC_TX_HDR
    ja .hd_toolong
    mov [r15 + linnea_quic_txstream.hlen], rax
    test rax, rax
    jz .hd_nohdr
    mov rcx, rax
    mov rsi, [linnea_h3d_hdr]
    lea rdi, [r15 + linnea_quic_txstream.hdr]
    rep movsb
.hd_nohdr:
    mov rax, [linnea_h3d_base]
    mov [r15 + linnea_quic_txstream.base], rax
    mov rax, [linnea_h3d_size]
    mov [r15 + linnea_quic_txstream.size], rax
    mov rax, [linnea_h3d_foff]
    mov [r15 + linnea_quic_txstream.foff], rax
    mov rax, [linnea_h3d_flen]
    mov [r15 + linnea_quic_txstream.flen], rax
    mov qword [r15 + linnea_quic_txstream.off], 0
    mov qword [r15 + linnea_quic_txstream.inflight], 0
    mov rax, [rbx + linnea_quic_conn.fc_stream_init]  ; this stream's own window
    mov [r15 + linnea_quic_txstream.fc_max], rax
    mov qword [r15 + linnea_quic_txstream.pending], 0 ; it is a response now
    mov [cur_conn], rbx
    call tx_pump
    mov eax, 1
    jmp .hd_ret
.hd_toolong:
    ; unreachable: the caller bounds the head before it gets here. Free the slot
    ; and end the stream rather than write past the slot's hdr into the next one.
    mov qword [r15 + linnea_quic_txstream.pending], 0
    mov qword [r15 + linnea_quic_txstream.active], 0
    mov [cur_conn], rbx
    mov rdi, r13
    xor esi, esi                      ; nothing of it was ever sent
    call tx_reset_stream
    mov eax, -1
    jmp .hd_ret
.hd_gone:
    xor eax, eax
.hd_ret:
    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
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
    ; reclaim connections that have gone quiet, including handshakes that stalled
    ; (a forged Initial never comes back) — see linnea_quic_conn_sweep_now
    call linnea_quic_conn_sweep_now
    call now_ms
    mov r15, rax                      ; now, ms
    call linnea_quic_dbg_tick         ; opt-in tracing: sets qdbg_pass for this pass
    xor r13d, r13d                    ; connection index
.sw_conn:
    mov edi, r13d
    call linnea_quic_conn_slot        ; rax = conn* or 0
    test rax, rax
    jz .sw_conn_next
    mov rbx, rax                      ; connection
    ; a connection in the closing state (RFC 9000 10.2.1) holds its slot only
    ; until the closing period is up; then the sweep reclaims it. Nothing else
    ; below applies to it — it sends nothing but the retained close, and only in
    ; response to a received packet (.closing_rx).
    cmp qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CLOSING
    jne .sw_not_closing
    mov rax, [rbx + linnea_quic_conn.close_deadline]
    cmp r15, rax
    jb .sw_conn_next                  ; still within the closing period
    mov rdi, rbx
    call linnea_quic_conn_free
    jmp .sw_conn_next
.sw_not_closing:
    cmp byte [qdbg_pass], 0           ; trace this live connection's state (dark unless
    je .sw_no_dbg                     ; the working-dir "linnea-qdbg" trigger file exists)
    mov rdi, rbx
    call linnea_quic_dbg_conn
.sw_no_dbg:
    ; --- the server's own handshake flight, while it is still unacknowledged ---
    ; A connection sitting in ST_HANDSHAKE has told the client everything it knows
    ; and heard nothing back. The 1-RTT rings below are empty for it, so without
    ; this it had no loss recovery whatsoever.
    cmp qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_HANDSHAKE
    jne .sw_hs_done
    mov rax, [rbx + linnea_quic_conn.flight_ms]
    test rax, rax
    jz .sw_hs_done                    ; nothing outstanding
    mov rcx, r15
    sub rcx, rax                      ; age in ms
    mov rdx, [rbx + linnea_quic_conn.flight_tries]
    cmp rdx, LINNEA_QUIC_PTO_CAP
    jbe .sw_hs_shift
    mov edx, LINNEA_QUIC_PTO_CAP
.sw_hs_shift:
    ; a peer may not delay acknowledging Initial or Handshake packets, so the
    ; max_ack_delay term of 6.2.1 does not apply to this flight
    push rcx
    push rdx
    mov rdi, rbx
    xor esi, esi
    call linnea_quic_pto_ms
    pop rdx
    pop rcx
    xchg rcx, rdx                     ; cl = backoff shift, rdx = age
    shl rax, cl
    cmp rdx, rax
    jb .sw_hs_done                    ; not yet due
    cmp qword [rbx + linnea_quic_conn.flight_tries], LINNEA_QUIC_PTO_MAX
    jae .sw_hs_give_up
    ; the flight rebuild reaches through vhost_slot and build_cert, neither of
    ; which owes this loop its registers — save what the sweep still needs
    push r12                          ; fd
    push r13                          ; connection index
    push r15                          ; now, ms
    push rbx
    ; the flight builders are locals of linnea_quic_server_datagram, so the sweep
    ; has to name the scope it is reaching into
    call linnea_quic_server_datagram.retx_hs_flight
    pop rbx
    pop r15
    pop r13
    pop r12
    mov [rbx + linnea_quic_conn.flight_ms], r15
    inc qword [rbx + linnea_quic_conn.flight_tries]
    jmp .sw_hs_done
.sw_hs_give_up:
    ; stop probing and let the idle sweep reclaim the slot; the peer is gone or
    ; the path is black-holing us, and more copies of a 1150-byte flight would
    ; only be an amplification gift
    mov qword [rbx + linnea_quic_conn.flight_ms], 0
.sw_hs_done:
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
    push rax                          ; age
    push rcx                          ; backoff shift
    mov rdi, rbx
    mov esi, 1                        ; application space: include max_ack_delay
    call linnea_quic_pto_ms
    mov rdx, rax
    pop rcx
    pop rax
    shl rdx, cl
    cmp rax, rdx
    jb .sw_rec_next                   ; not yet due
    cmp qword [r14 + linnea_quic_sent.tries], LINNEA_QUIC_PTO_MAX
    jb .sw_resend
    mov qword [r14 + linnea_quic_sent.in_use], 0    ; a small reply given up on
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
    ; --- the open response stream's chunks (the congestion-controlled table) ---
    cmp qword [rbx + linnea_quic_conn.bytes_in_flight], 0
    je .sw_pump                       ; nothing in flight: no chunks to probe, but the
                                      ; pump may still need to run (below)
    lea r14, [rbx + linnea_quic_conn.tx_infl]
    xor ebp, ebp
.sw_tc:
    cmp qword [r14 + linnea_quic_txchunk.in_use], 0
    je .sw_tc_next
    mov rax, r15
    sub rax, [r14 + linnea_quic_txchunk.sent_ms]      ; age in ms
    mov rcx, [r14 + linnea_quic_txchunk.tries]
    cmp rcx, LINNEA_QUIC_PTO_CAP
    jbe .sw_tc_shift
    mov ecx, LINNEA_QUIC_PTO_CAP
.sw_tc_shift:
    push rax
    push rcx
    mov rdi, rbx
    mov esi, 1
    call linnea_quic_pto_ms
    mov rdx, rax
    pop rcx
    pop rax
    shl rdx, cl
    cmp rax, rdx
    jb .sw_tc_next                    ; not yet due
    cmp qword [r14 + linnea_quic_txchunk.tries], LINNEA_QUIC_TX_PTO_MAX
    jb .sw_tc_resend
    ; given up on: drop just this stream, not the connection's other transfers, and
    ; tell the peer where the stream ends — it has neither these bytes nor a FIN, and
    ; only the final size releases the connection credit they consumed.
    mov rax, [r14 + linnea_quic_txchunk.ctx]
    imul rax, rax, linnea_quic_txstream_size
    lea rcx, [rbx + linnea_quic_conn.tx_streams]
    add rax, rcx                      ; the chunk's stream slot
    mov [cur_conn], rbx               ; emit_1rtt sends on this connection
    mov rdi, [rax + linnea_quic_txstream.sid]
    mov rsi, [rax + linnea_quic_txstream.off]      ; final size = the bytes we sent
    call tx_reset_stream
    mov rdi, rbx
    mov rsi, [r14 + linnea_quic_txchunk.ctx]
    call tx_abort_one
    jmp .sw_tc_next                   ; keep sweeping the remaining streams' chunks
.sw_tc_resend:
    mov [cur_conn], rbx
    mov rdi, rbx                      ; a timeout is a congestion signal
    mov rsi, [r14 + linnea_quic_txchunk.pn]
    call cc_on_loss
    ; rebuild from the file under a fresh pn — the ctx points at the stream slot
    ; the chunk belongs to (its mapping, head and stream id).
    mov rdi, [r14 + linnea_quic_txchunk.ctx]
    imul rdi, rdi, linnea_quic_txstream_size
    add rdi, rbx
    lea rdi, [rdi + linnea_quic_conn.tx_streams]   ; stream ctx ptr
    mov rsi, [r14 + linnea_quic_txchunk.off]
    mov rdx, [r14 + linnea_quic_txchunk.len]
    call tx_emit_chunk                ; rax = the fresh packet number
    mov [r14 + linnea_quic_txchunk.pn], rax
    mov [r14 + linnea_quic_txchunk.sent_ms], r15
    inc qword [r14 + linnea_quic_txchunk.tries]
.sw_tc_next:
    add r14, linnea_quic_txchunk_size
    inc ebp
    cmp ebp, LINNEA_QUIC_TXINFL_SLOTS
    jb .sw_tc
.sw_pump:
    ; drive the pump on the timer, not only on incoming acks. A response otherwise
    ; stalls whenever no ack will arrive to run it: after a stalled head is given up
    ; (tx_abort_one) nothing is in flight and the peer has nothing to ack, so the
    ; next queued stream would never start. The pump is congestion-window gated, so
    ; on a healthy connection it sends nothing here; on a stalled one it heals it.
    mov [cur_conn], rbx
    call tx_pump                      ; preserves rbx/rbp/r12/r13/r14/r15
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

; send_app_close(rdi = h3 error code) — queue an application CONNECTION_CLOSE
; (frame 0x1d) carrying the code on cur_conn, via emit_1rtt on the socket in
; r12d. Best-effort and untracked, like every close: the slot is freed the
; moment it is queued, so a lost close is not worth resending.
send_app_close:
    push rbx                         ; emit_1rtt wants a 16-aligned call site
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
    pop rbx
    ret

; linnea_quic_server_drain_sweep(edi = UDP socket fd) — one drain pass over the
; pool: every connected peer with nothing left in flight — no response stream
; open, no chunk unacknowledged, no request still reassembling — is told
; goodbye with CONNECTION_CLOSE(H3_NO_ERROR) and its slot freed. A connection
; still working is left alone; a later pass catches it once its last chunk is
; acknowledged. Handshakes in progress are not closed here (a 1-RTT close would
; not decrypt for them): the handshake idle sweep reclaims them within
; LINNEA_QUIC_HS_IDLE_SECS. Driven by the event loop's periodic timer, which
; keeps ticking during a drain exactly so this and the retransmission sweep can
; finish the in-flight responses the drain is waiting on.
linnea_quic_server_drain_sweep:
    push rbx
    push r12
    push r13                         ; 3 pushes: the call sites are 16-aligned
    mov r12d, edi                    ; fd, for emit_1rtt
    xor r13d, r13d                   ; connection index
.ds_conn:
    mov edi, r13d
    call linnea_quic_conn_slot       ; rax = conn* or 0
    test rax, rax
    jz .ds_next
    mov rbx, rax
    cmp qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    jne .ds_next
    cmp qword [rbx + linnea_quic_conn.bytes_in_flight], 0
    jne .ds_next
    lea rcx, [rbx + linnea_quic_conn.tx_streams]
    mov edx, LINNEA_QUIC_TXSTREAMS
.ds_tx:
    cmp qword [rcx + linnea_quic_txstream.active], 0
    jne .ds_next                     ; a response is still going out
    add rcx, linnea_quic_txstream_size
    dec edx
    jnz .ds_tx
    lea rcx, [rbx + linnea_quic_conn.ra_ctx]
    mov edx, LINNEA_QUIC_RA_CTXS
.ds_ra:
    cmp qword [rcx + linnea_quic_ra.active], 0
    jne .ds_next                     ; a request is still arriving
    add rcx, linnea_quic_ra_size
    dec edx
    jnz .ds_ra
    mov [cur_conn], rbx
    mov edi, LINNEA_H3_ERR_NO_ERROR
    call send_app_close
    mov rdi, rbx
    call linnea_quic_conn_free
.ds_next:
    inc r13d
    cmp r13d, LINNEA_QUIC_MAX_CONNS
    jb .ds_conn
    pop r13
    pop r12
    pop rbx
    ret
