; linnea_probe.asm — a standalone HTTP compliance prober.
;
;   linnea-probe <url> <protocol> [--host <name>]
;
; Opens connections to a live server and runs a battery of compliance probes —
; valid requests, malformed ones, bad framing, slow drips — reporting for each
; what the server did and whether it matches what the RFCs require. It is a
; diagnostic, not a unit test: every probe prints a line, and the exit code is
; the number of outright deviations (an invalid request ACCEPTED, or no answer
; where one was due), so it can gate CI as well as be read by eye.
;
; Phase 1 speaks HTTP/1.1 over cleartext TCP. The host in the URL must be an
; IPv4 literal or "localhost" (a DNS resolver and a TLS 1.3 client come with
; phase 2, which is also where HTTP/2 lands; HTTP/3 is phase 3). Zero
; dependencies, like the server: nasm + ld, no libc.

default rel

%include "linnea_syscall.inc"
%include "linnea_tls.inc"
%include "linnea_quic.inc"

global _start

extern linnea_print_stdout
extern linnea_print_stderr
extern linnea_string_from_u64
; --- reused crypto for the TLS 1.3 client ---
extern linnea_tls_hkdf_expand_label
extern linnea_tls_derive_secret
extern linnea_tls_keys_init
extern linnea_tls_seal
extern linnea_tls_open
extern linnea_x25519
extern linnea_sha256
extern linnea_hkdf_extract
extern linnea_hmac_sha256
; --- reused QUIC transport crypto for the HTTP/3 client ---
extern linnea_quic_initial_secrets
extern linnea_quic_protect
extern linnea_quic_unprotect
extern linnea_quic_unprotect_hs
extern linnea_quic_crypto_frame
extern linnea_quic_varint_encode
extern linnea_quic_varint_decode

; ---- kinds, for the per-probe report line -------------------------------
K_OK   equ 0            ; the server did what the RFC requires
K_DEV  equ 1            ; a deviation: invalid input accepted, or no answer due
K_INFO equ 2            ; rejected, but with a different status than expected

LINNEA_AF_INET_ equ 2
SOCK_STREAM_    equ 1
SOCK_DGRAM_     equ 2
O_RDONLY_       equ 0

RESP_CAP        equ 65536
REQ_CAP         equ 65536
HOSTBUF_CAP     equ 256
DNSBUF_CAP      equ 1024

section .rodata

usage_msg:  db "usage: linnea-probe <url> <protocol> [--host <name>]", 10
            db "  <url>       http://<ipv4-or-localhost>[:port][/path]", 10
            db "  <protocol>  h1 (h2/h3 not yet implemented)", 10
usage_len   equ $ - usage_msg

sch_http:   db "http://"
sch_http_len equ $ - sch_http
sch_https:  db "https://"
sch_https_len equ $ - sch_https

opt_host:   db "--host"
opt_host_len equ $ - opt_host

localhost_s: db "localhost"
localhost_len equ $ - localhost_s
localhost_addr equ 0x0100007f          ; 127.0.0.1 in network byte order

; report-line prefixes
pfx_ok:     db "[ OK ] "
pfx_ok_len  equ $ - pfx_ok
pfx_dev:    db "[DEV!] "
pfx_dev_len equ $ - pfx_dev
pfx_info:   db "[info] "
pfx_info_len equ $ - pfx_info

s_arrow:    db " -> "
s_arrow_len equ $ - s_arrow
s_status:   db "HTTP "
s_status_len equ $ - s_status
s_noresp:   db "(no response / connection closed)", 10
s_noresp_len equ $ - s_noresp
s_rst:      db "RST_STREAM (stream rejected)", 10
s_rst_len   equ $ - s_rst
s_goaway:   db "GOAWAY (connection error)", 10
s_goaway_len equ $ - s_goaway
s_want:     db "  (want "
s_want_len  equ $ - s_want
s_rparen_nl: db ")", 10
s_rparen_nl_len equ $ - s_rparen_nl
s_nl:       db 10

hdr_line:   db "== HTTP/1.1 compliance probes -> "
hdr_line_len equ $ - hdr_line
sum_head:   db 10, "== "
sum_head_len equ $ - sum_head
sum_probes: db " probes, "
sum_probes_len equ $ - sum_probes
sum_dev:    db " deviation(s)", 10
sum_dev_len equ $ - sum_dev
s_colon_sp: db ": "
s_colon_sp_len equ $ - s_colon_sp

err_scheme: db "error: url must start with http:// (https:// is phase 2)", 10
err_scheme_len equ $ - err_scheme
err_host:   db "error: host must be an IPv4 literal or localhost (DNS is phase 2)", 10
err_host_len equ $ - err_host
err_connect: db "error: could not connect to the server", 10
err_connect_len equ $ - err_connect
err_resolve: db "error: could not resolve the host (DNS)", 10
err_resolve_len equ $ - err_resolve
resolv_path: db "/etc/resolv.conf", 0
ns_kw:      db "nameserver"
ns_kw_len   equ $ - ns_kw
fallback_ns equ 0x3500007f              ; 127.0.0.53 (systemd-resolved), network order
proto_todo: db "error: protocol must be h1 or h2 (h3 coming)", 10
proto_todo_len equ $ - proto_todo
err_h2_tls: db "error: h2 requires https:// (h2 runs over TLS)", 10
err_h2_tls_len equ $ - err_h2_tls

; --- probe names (printed on each report line) ---
n_valid:    db "valid GET"
n_valid_len equ $ - n_valid
n_keepalive: db "keep-alive (two requests, one connection)"
n_keepalive_len equ $ - n_keepalive
n_nohost:   db "request with no Host header"
n_nohost_len equ $ - n_nohost
n_duphost:  db "request with two Host headers"
n_duphost_len equ $ - n_duphost
n_wsp:      db "whitespace before the header colon"
n_wsp_len   equ $ - n_wsp
n_nocolon:  db "header line with no colon"
n_nocolon_len equ $ - n_nocolon
n_badreqline: db "request line with no HTTP version"
n_badreqline_len equ $ - n_badreqline
n_unknownmeth: db "unknown method"
n_unknownmeth_len equ $ - n_unknownmeth
n_http10:   db "HTTP/1.0 request line"
n_http10_len equ $ - n_http10
n_badver:   db "bogus HTTP version (HTTP/9.9)"
n_badver_len equ $ - n_badver
n_longtarget: db "over-long request target (~9 KB)"
n_longtarget_len equ $ - n_longtarget
n_barelf:   db "bare-LF line endings"
n_barelf_len equ $ - n_barelf
n_absform:  db "absolute-form target"
n_absform_len equ $ - n_absform
n_slowloris: db "slow header drip (slowloris)"
n_slowloris_len equ $ - n_slowloris
s_closed_ok: db " (server closed the connection)", 10
s_closed_ok_len equ $ - s_closed_ok
s_stayed:   db " (server kept waiting through the drip window)", 10
s_stayed_len equ $ - s_stayed

; --- request fragments ---
f_get_sp:   db "GET "
f_get_sp_len equ $ - f_get_sp
f_sp_h11_crlf: db " HTTP/1.1", 13, 10
f_sp_h11_crlf_len equ $ - f_sp_h11_crlf
f_sp_h10_crlf: db " HTTP/1.0", 13, 10
f_sp_h10_crlf_len equ $ - f_sp_h10_crlf
f_sp_h99_crlf: db " HTTP/9.9", 13, 10
f_sp_h99_crlf_len equ $ - f_sp_h99_crlf
f_host:     db "Host: "
f_host_len  equ $ - f_host
f_crlf:     db 13, 10
f_crlf_len  equ $ - f_crlf
f_close_hdr: db "Connection: close", 13, 10
f_close_hdr_len equ $ - f_close_hdr
f_end:      db 13, 10                   ; the blank line ending the head
f_end_len   equ $ - f_end
f_dummy_host2: db "Host: other.example", 13, 10
f_dummy_host2_len equ $ - f_dummy_host2
f_wsp_hdr:  db "X-Probe : value", 13, 10
f_wsp_hdr_len equ $ - f_wsp_hdr
f_nocolon_hdr: db "ThisHeaderHasNoColon", 13, 10
f_nocolon_hdr_len equ $ - f_nocolon_hdr
f_frob_sp:  db "FROBNICATE "
f_frob_sp_len equ $ - f_frob_sp
f_get_lf:   db "GET "                   ; bare-LF variant reuses the target
f_get_lf_len equ $ - f_get_lf
f_sp_h11_lf: db " HTTP/1.1", 10
f_sp_h11_lf_len equ $ - f_sp_h11_lf
f_host_lf:  db "Host: "
f_host_lf_len equ $ - f_host_lf
f_lf:       db 10
f_end_lf:   db 10

; --- TLS 1.3 client constants ---
empty_hash: db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8
            db 0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
            db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55      ; SHA-256("")
zeros32_p:  times 32 db 0
x25519_base: db 9
             times 31 db 0
lbl_derived: db "derived"
lbl_c_hs:    db "c hs traffic"
lbl_s_hs:    db "s hs traffic"
lbl_c_ap:    db "c ap traffic"
lbl_s_ap:    db "s ap traffic"
lbl_finished: db "finished"
alpn_h11:    db "http/1.1"
alpn_h11_len equ $ - alpn_h11
; fixed middle of the ClientHello: cipher suites, compression (the parts with no
; variable content). cipher_suites len 2 = {0x1301}, compression len 1 = {0x00}.
ch_suites:  db 0x00, 0x02, 0x13, 0x01, 0x01, 0x00
ch_suites_len equ $ - ch_suites
err_tls:    db "error: TLS handshake failed", 10
err_tls_len equ $ - err_tls

; --- HTTP/2 ---
alpn_h2:    db "h2"
alpn_h2_len equ $ - alpn_h2
h2_preface: db "PRI * HTTP/2.0", 13, 10, 13, 10, "SM", 13, 10, 13, 10
h2_preface_len equ $ - h2_preface
h2_settings: db 0,0,0, 0x04, 0x00, 0,0,0,0          ; empty SETTINGS
h2_settings_len equ $ - h2_settings
h2_hdr_line: db "== HTTP/2 compliance probes -> "
h2_hdr_line_len equ $ - h2_hdr_line
; h2 probe names
n_h2_valid:  db "valid GET (h2)"
n_h2_valid_len equ $ - n_h2_valid
n_h2_multi:  db "two concurrent streams"
n_h2_multi_len equ $ - n_h2_multi
n_h2_dyn:    db "HPACK dynamic-table indexing (re-indexed :authority)"
n_h2_dyn_len equ $ - n_h2_dyn
n_h2_nopath: db "request with no :path (malformed)"
n_h2_nopath_len equ $ - n_h2_nopath
n_h2_badhdr: db "uppercase header name (malformed)"
n_h2_badhdr_len equ $ - n_h2_badhdr
n_h2_conn:   db "connection-specific header (Connection: keep-alive)"
n_h2_conn_len equ $ - n_h2_conn
n_h2_badhpack: db "undecodable HPACK (dynamic index into empty table)"
n_h2_badhpack_len equ $ - n_h2_badhpack
pseudo_status: db ":status"
; HPACK static-table status values for indices 8..14
h2_status_map: dw 200, 204, 206, 304, 400, 404, 500

; --- HTTP/3 / QUIC ---
alpn_h3:    db "h3"
alpn_h3_len equ $ - alpn_h3
h3_hdr_line: db "== HTTP/3 compliance probes -> "
h3_hdr_line_len equ $ - h3_hdr_line
n_h3_initial: db "QUIC Initial handshake (ServerHello received)"
n_h3_initial_len equ $ - n_h3_initial
err_h3_tls: db "error: h3 requires https:// (QUIC over UDP)", 10
err_h3_tls_len equ $ - err_h3_tls

section .bss
alignb 16
sa:         resb 16                     ; sockaddr_in
respbuf:    resb RESP_CAP
reqbuf:     resb REQ_CAP
hs_buf:     resb 4096                    ; ClientHello/Finished assembly (keeps reqbuf free)
numbuf:     resb 32
pollfd:     resb 8
timespec:   resb 16

conn_addr:  resd 1                      ; server address (network order), for connect
conn_port:  resd 1                      ; server port (host order)

urlhost:    resb HOSTBUF_CAP            ; the URL's host, NUL-terminated (for DNS)
urlhost_len: resq 1
dnsbuf:     resb DNSBUF_CAP             ; DNS query then response
ns_sa:      resb 16                     ; nameserver sockaddr_in
resolv_buf: resb 1024                   ; /etc/resolv.conf contents

host_ptr:   resq 1                      ; Host-header value ptr...
host_len:   resq 1                      ; ...and length (from the URL, or --host)
path_ptr:   resq 1                      ; request-target ptr...
path_len:   resq 1                      ; ...and length

req_cur:    resq 1                      ; request-assembly cursor into reqbuf
n_total:    resd 1
n_dev:      resd 1

; --- HTTP/2 client state ---
proto:      resq 1                      ; 1 = h1, 2 = h2
alpn_str:   resq 1                      ; ALPN protocol offered in the ClientHello
alpn_len:   resq 1
h2_block:   resb 4096                   ; HPACK header block being built
h2_block_len: resq 1                    ; its length
h2_sid:     resq 1                      ; next client stream id (odd)
h2_prefaced: resq 1                     ; 1 once the preface+SETTINGS have gone out

; --- TLS 1.3 client state (one connection at a time, so globals suffice) ---
use_tls:    resq 1                      ; 1 when the URL scheme is https
tls_priv:   resb 32                     ; our x25519 private key
tls_pub:    resb 32                     ; our x25519 public key
tls_srvpub: resb 32                     ; the server's key_share
tls_shared: resb 32                     ; ECDH shared secret
tls_random: resb 32                     ; client random
tls_sessid: resb 32                     ; legacy session id (middlebox compat)
tr_buf:     resb 16384                  ; handshake transcript (all HS messages)
tr_len:     resq 1
th_buf:     resb 32                     ; a transcript hash
sec_early:  resb 32
sec_derived: resb 32
sec_hs:     resb 32
sec_master: resb 32
sec_chs:    resb 32
sec_shs:    resb 32
sec_cap:    resb 32
sec_sap:    resb 32
fin_key:    resb 32
alignb 16
tls_wkeys:  resb linnea_tls_keys_size   ; client write direction
tls_rkeys:  resb linnea_tls_keys_size   ; client read direction
tls_rec:    resb 20480                  ; one incoming TLS record (header + payload)
hs_plain:   resb 20480                  ; decrypted server flight (handshake msgs)
hs_plain_len: resq 1
tls_pt:     resb 20480                  ; decrypted application record plaintext

; --- HTTP/3 / QUIC client state ---
udp_fd:     resq 1
q_dcid:     resb 8                      ; the DCID we pick (seeds the Initial keys)
q_scid:     resb 8                      ; our source connection id
alignb 16
qi_ckeys:   resb linnea_quic_keys_size  ; client Initial keys (we protect with these)
qi_skeys:   resb linnea_quic_keys_size  ; server Initial keys (we open with these)
qch:        resb 2048                   ; the QUIC ClientHello handshake message
qch_len:    resq 1
qtp:        resb 512                    ; encoded client transport parameters
qhdr:       resb 64                     ; a QUIC packet header being assembled
qpay:       resb 1500                   ; a QUIC packet payload being assembled
qpkt:       resb 1500                   ; the protected packet to send
qrx:        resb 2048                   ; a received datagram
qplain:     resb 2048                   ; decrypted QUIC frames
qvtmp:      resb 16                     ; varint scratch

section .text

; =======================================================================
; entry
; =======================================================================
_start:
    mov r15, [rsp]                      ; argc
    cmp r15, 3
    jl .usage

    ; --- protocol (argv[2]): "h1" or "h2" ---
    mov rsi, [rsp + 24]                 ; argv[2]
    movzx eax, byte [rsi]
    movzx ecx, byte [rsi + 1]
    cmp byte [rsi + 2], 0
    jne .proto_bad
    cmp al, 'h'
    jne .proto_bad
    cmp cl, '1'
    je .proto_h1
    cmp cl, '3'
    je .proto_h3
    cmp cl, '2'
    jne .proto_bad
    ; h2: TLS with ALPN "h2"
    mov qword [proto], 2
    lea rax, [alpn_h2]
    mov [alpn_str], rax
    mov qword [alpn_len], alpn_h2_len
    jmp .proto_set
.proto_h3:
    ; h3: QUIC/UDP with ALPN "h3"
    mov qword [proto], 3
    lea rax, [alpn_h3]
    mov [alpn_str], rax
    mov qword [alpn_len], alpn_h3_len
    jmp .proto_set
.proto_h1:
    mov qword [proto], 1
    lea rax, [alpn_h11]
    mov [alpn_str], rax
    mov qword [alpn_len], alpn_h11_len
.proto_set:

    ; --- optional --host override (scan argv[3..]) ---
    mov qword [host_ptr], 0
    mov rbx, 3                           ; arg index
.scan_opts:
    cmp rbx, r15
    jae .opts_done
    mov rdi, [rsp + 8 + rbx*8]           ; argv[rbx]
    lea rsi, [opt_host]
    mov edx, opt_host_len
    call streq_z                         ; rax=1 if argv[rbx] == "--host"
    test rax, rax
    jz .scan_next
    lea rcx, [rbx + 1]
    cmp rcx, r15
    jae .opts_done                       ; --host with no value: ignore
    mov rdi, [rsp + 8 + rcx*8]           ; the host value
    mov [host_ptr], rdi
    mov rsi, rdi
    call cstrlen
    mov [host_len], rax
    add rbx, 2
    jmp .scan_opts
.scan_next:
    inc rbx
    jmp .scan_opts
.opts_done:

    ; --- parse the URL (argv[1]) ---
    mov rdi, [rsp + 16]                  ; argv[1]
    call parse_url
    test rax, rax
    js .exit_err                         ; parse_url already printed the reason

    ; --- resolve the URL host to an address (IPv4 literal, localhost, or DNS) ---
    lea rdi, [urlhost]
    call dns_resolve
    cmp rax, -1
    je .exit_resolve
    mov [conn_addr], eax

    ; h2 and h3 require the https scheme (TLS/QUIC)
    cmp qword [proto], 1
    je .banner
    cmp qword [use_tls], 0
    je .proto_needs_tls
.banner:
    ; --- header banner (protocol-specific) ---
    lea rsi, [hdr_line]
    mov edx, hdr_line_len
    cmp qword [proto], 2
    jne .banner_try_h3
    lea rsi, [h2_hdr_line]
    mov edx, h2_hdr_line_len
    jmp .banner_put
.banner_try_h3:
    cmp qword [proto], 3
    jne .banner_put
    lea rsi, [h3_hdr_line]
    mov edx, h3_hdr_line_len
.banner_put:
    call puts
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call puts
    lea rsi, [s_nl]
    mov edx, 1
    call puts

    ; =================== the probe battery =======================
    cmp qword [proto], 2
    je .run_h2
    cmp qword [proto], 3
    je .run_h3
    call probe_valid
    call probe_keepalive
    call probe_nohost
    call probe_duphost
    call probe_wsp_colon
    call probe_nocolon
    call probe_badreqline
    call probe_unknown_method
    call probe_http10
    call probe_badver
    call probe_long_target
    call probe_bare_lf
    call probe_absform
    call probe_slowloris
    jmp .summary
.run_h2:
    call h2_battery
    jmp .summary
.run_h3:
    call h3_battery

.summary:
    ; =================== summary =================================
    lea rsi, [sum_head]
    mov edx, sum_head_len
    call puts
    mov edi, [n_total]
    call print_u32
    lea rsi, [sum_probes]
    mov edx, sum_probes_len
    call puts
    mov edi, [n_dev]
    call print_u32
    lea rsi, [sum_dev]
    mov edx, sum_dev_len
    call puts

    mov edi, [n_dev]
    cmp edi, 255
    jbe .exit_n
    mov edi, 255
.exit_n:
    jmp exit

.usage:
    lea rsi, [usage_msg]
    mov edx, usage_len
    call puts_err
    mov edi, 2
    jmp exit
.proto_bad:
    lea rsi, [proto_todo]
    mov edx, proto_todo_len
    call puts_err
    mov edi, 2
    jmp exit
.exit_err:
    mov edi, 2
    jmp exit
.exit_resolve:
    lea rsi, [err_resolve]
    mov edx, err_resolve_len
    call puts_err
    mov edi, 2
    jmp exit
.proto_needs_tls:
    lea rsi, [err_h2_tls]
    mov edx, err_h2_tls_len
    cmp qword [proto], 3
    jne .pnt_put
    lea rsi, [err_h3_tls]
    mov edx, err_h3_tls_len
.pnt_put:
    call puts_err
    mov edi, 2
    jmp exit

; =======================================================================
; probes
; =======================================================================
; Each probe: assemble a request in reqbuf, run one exchange, classify the
; observed status, and print a line. The "expected" status and whether a
; rejection is expected drive classify_and_report.

; a full, well-formed GET — the baseline: any HTTP status line is success.
probe_valid:
    push rbx
    call req_begin
    call add_get_target_h11
    call add_host
    call add_close
    call add_end
    call run_and_read                    ; rax = status (-1 none)
    ; baseline: OK if we got any status at all
    mov r8, rax                          ; observed
    mov dil, K_OK
    test rax, rax
    jns .ok
    mov dil, K_DEV
.ok:
    lea rsi, [n_valid]
    mov edx, n_valid_len
    mov rcx, r8
    mov r9d, -1                          ; no single "expected" code
    call report
    pop rbx
    ret

; two requests on one keep-alive connection, both must answer
probe_keepalive:
    push rbx
    push r12
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax                         ; fd
    ; request 1 (keep-alive: no Connection: close)
    call req_begin
    call add_get_target_h11
    call add_host
    call add_end
    mov edi, ebx
    call send_req
    mov edi, ebx
    call read_response
    call parse_status
    mov r12, rax                         ; status 1
    ; request 2 on the same fd
    call req_begin
    call add_get_target_h11
    call add_host
    call add_close
    call add_end
    mov edi, ebx
    call send_req
    mov edi, ebx
    call read_response
    mov edi, ebx
    call close_fd                         ; close BEFORE parse: parse reads the
    call parse_status                     ; buffer, and close would clobber rax
    ; OK only if BOTH answered
    mov dil, K_DEV
    test r12, r12
    js .report
    test rax, rax
    js .report
    mov dil, K_OK
.report:
    lea rsi, [n_keepalive]
    mov edx, n_keepalive_len
    mov rcx, rax                          ; show the 2nd status
    mov r9d, -1
    call report
    pop r12
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_keepalive]
    mov edx, n_keepalive_len
    mov rcx, -1
    mov r9d, -1
    call report
    pop r12
    pop rbx
    ret

; missing Host: RFC 9112 5.4 makes it a 400
probe_nohost:
    call req_begin
    call add_get_target_h11
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_nohost]
    mov edx, n_nohost_len
    mov r9d, 400
    call classify_reject
    ret

; two Host headers: 400
probe_duphost:
    call req_begin
    call add_get_target_h11
    call add_host
    lea rsi, [f_dummy_host2]
    mov edx, f_dummy_host2_len
    call req_add
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_duphost]
    mov edx, n_duphost_len
    mov r9d, 400
    call classify_reject
    ret

; whitespace before the colon (RFC 9112 5.1): 400
probe_wsp_colon:
    call req_begin
    call add_get_target_h11
    call add_host
    lea rsi, [f_wsp_hdr]
    mov edx, f_wsp_hdr_len
    call req_add
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_wsp]
    mov edx, n_wsp_len
    mov r9d, 400
    call classify_reject
    ret

; a header line with no colon: 400
probe_nocolon:
    call req_begin
    call add_get_target_h11
    call add_host
    lea rsi, [f_nocolon_hdr]
    mov edx, f_nocolon_hdr_len
    call req_add
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_nocolon]
    mov edx, n_nocolon_len
    mov r9d, 400
    call classify_reject
    ret

; request line with no HTTP version: 400
probe_badreqline:
    call req_begin
    lea rsi, [f_get_sp]
    mov edx, f_get_sp_len
    call req_add
    call add_target_only
    lea rsi, [f_crlf]                    ; end the line straight after the target
    mov edx, f_crlf_len
    call req_add
    call add_host
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_badreqline]
    mov edx, n_badreqline_len
    mov r9d, 400
    call classify_reject
    ret

; an unknown method: RFC 9110 15.6.2 points to 501
probe_unknown_method:
    call req_begin
    lea rsi, [f_frob_sp]
    mov edx, f_frob_sp_len
    call req_add
    call add_target_only
    lea rsi, [f_sp_h11_crlf]
    mov edx, f_sp_h11_crlf_len
    call req_add
    call add_host
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_unknownmeth]
    mov edx, n_unknownmeth_len
    mov r9d, 501
    call classify_reject
    ret

; an HTTP/1.0 request line — informational (behaviour varies by server)
probe_http10:
    call req_begin
    lea rsi, [f_get_sp]
    mov edx, f_get_sp_len
    call req_add
    call add_target_only
    lea rsi, [f_sp_h10_crlf]
    mov edx, f_sp_h10_crlf_len
    call req_add
    call add_host
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_http10]
    mov edx, n_http10_len
    call report_info
    ret

; a nonsense version — 505 or 400
probe_badver:
    call req_begin
    lea rsi, [f_get_sp]
    mov edx, f_get_sp_len
    call req_add
    call add_target_only
    lea rsi, [f_sp_h99_crlf]
    mov edx, f_sp_h99_crlf_len
    call req_add
    call add_host
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_badver]
    mov edx, n_badver_len
    mov r9d, 505
    call classify_reject
    ret

; an over-long request target: RFC 9112 3 -> 414
probe_long_target:
    call req_begin
    lea rsi, [f_get_sp]
    mov edx, f_get_sp_len
    call req_add
    ; a '/' then ~9000 'a'
    mov rdi, [req_cur]
    mov byte [rdi], '/'
    inc rdi
    mov ecx, 9000
    mov al, 'a'
    rep stosb
    mov [req_cur], rdi
    lea rsi, [f_sp_h11_crlf]
    mov edx, f_sp_h11_crlf_len
    call req_add
    call add_host
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_longtarget]
    mov edx, n_longtarget_len
    mov r9d, 414
    call classify_reject
    ret

; bare-LF line endings (no CR): RFC 9112 2.2 permits requiring CRLF -> 400
probe_bare_lf:
    call req_begin
    lea rsi, [f_get_lf]
    mov edx, f_get_lf_len
    call req_add
    call add_target_only
    lea rsi, [f_sp_h11_lf]
    mov edx, f_sp_h11_lf_len
    call req_add
    lea rsi, [f_host_lf]
    mov edx, f_host_lf_len
    call req_add
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call req_add
    lea rsi, [f_lf]
    mov edx, 1
    call req_add
    lea rsi, [f_end_lf]
    mov edx, 1
    call req_add
    call run_and_read
    mov rcx, rax
    lea rsi, [n_barelf]
    mov edx, n_barelf_len
    mov r9d, 400
    call classify_reject
    ret

; absolute-form target (RFC 9112 3.2.2): should still be served (2xx/3xx/404)
probe_absform:
    call req_begin
    lea rsi, [f_get_sp]
    mov edx, f_get_sp_len
    call req_add
    lea rsi, [sch_http]
    mov edx, sch_http_len
    call req_add
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call req_add
    mov rsi, [path_ptr]
    mov rdx, [path_len]
    call req_add
    lea rsi, [f_sp_h11_crlf]
    mov edx, f_sp_h11_crlf_len
    call req_add
    call add_host
    call add_close
    call add_end
    call run_and_read
    ; absolute-form is legal: OK if it did NOT 400
    mov r8, rax
    lea rsi, [n_absform]
    mov edx, n_absform_len
    mov dil, K_OK
    test rax, rax
    js .dev
    cmp rax, 400
    jne .ok
.dev:
    mov dil, K_DEV
.ok:
    mov rcx, r8
    mov r9d, -1
    call report
    ret

; slowloris: drip a partial request head, never finishing, and watch whether
; the server enforces a header deadline by closing on us within the window.
probe_slowloris:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax                         ; fd
    ; send the request line, then dribble a header a few bytes at a time with
    ; pauses, never sending the terminating blank line
    call req_begin
    call add_get_target_h11
    call req_flush_to_fd_ebx             ; sends what is buffered so far
    ; now drip "X-Drip: aaaa..." one small chunk at a time
    mov r12d, 20                          ; chunks
.drip:
    mov edi, ebx
    lea rsi, [f_crlf]                    ; harmless partial header bytes
    mov edx, 1                            ; one byte at a time (just a CR-less drip)
    call send_bytes
    test rax, rax
    js .closed                            ; server hung up on us: deadline enforced
    mov edi, ebx
    mov esi, 400                          ; check for a close between drips
    call wait_readable_or_closed
    cmp rax, 2                            ; 2 = peer closed
    je .closed
    dec r12d
    jnz .drip
    ; still open after the whole drip window: no deadline observed here
    mov edi, ebx
    call close_fd
    mov dil, K_INFO
    lea rsi, [n_slowloris]
    mov edx, n_slowloris_len
    lea r8, [s_stayed]
    mov r9d, s_stayed_len
    call report_tail
    pop rbx
    ret
.closed:
    mov edi, ebx
    call close_fd
    mov dil, K_OK
    lea rsi, [n_slowloris]
    mov edx, n_slowloris_len
    lea r8, [s_closed_ok]
    mov r9d, s_closed_ok_len
    call report_tail
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_slowloris]
    mov edx, n_slowloris_len
    mov rcx, -1
    mov r9d, -1
    call report
    pop rbx
    ret

; =======================================================================
; request assembly
; =======================================================================
; req_begin: reset the assembly cursor
req_begin:
    lea rax, [reqbuf]
    mov [req_cur], rax
    ret

; req_add(rsi=ptr, rdx=len): append bytes to the request buffer
req_add:
    mov rdi, [req_cur]
    mov rcx, rdx
    rep movsb
    mov [req_cur], rdi
    ret

; add "GET <target> HTTP/1.1\r\n"
add_get_target_h11:
    push rbx
    lea rsi, [f_get_sp]
    mov edx, f_get_sp_len
    call req_add
    call add_target_only
    lea rsi, [f_sp_h11_crlf]
    mov edx, f_sp_h11_crlf_len
    call req_add
    pop rbx
    ret

; append just the request target (path)
add_target_only:
    mov rsi, [path_ptr]
    mov rdx, [path_len]
    call req_add
    ret

; append "Host: <host>\r\n"
add_host:
    push rbx
    lea rsi, [f_host]
    mov edx, f_host_len
    call req_add
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call req_add
    lea rsi, [f_crlf]
    mov edx, f_crlf_len
    call req_add
    pop rbx
    ret

add_close:
    lea rsi, [f_close_hdr]
    mov edx, f_close_hdr_len
    call req_add
    ret

add_end:
    lea rsi, [f_end]
    mov edx, f_end_len
    call req_add
    ret

; =======================================================================
; one exchange: connect, send the assembled request, read, parse status
; =======================================================================
; run_and_read() -> rax = status code (-1 on no response / connect failure)
run_and_read:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    call send_req
    mov edi, ebx
    call read_response
    mov edi, ebx
    call close_fd
    call parse_status
    pop rbx
    ret
.fail:
    mov rax, -1
    pop rbx
    ret

; send_req(edi=fd): send the whole assembled request
send_req:
    push rbx
    mov ebx, edi
    lea rsi, [reqbuf]
    mov rdx, [req_cur]
    sub rdx, rsi                          ; length
    mov edi, ebx
    call send_bytes
    pop rbx
    ret

; req_flush_to_fd_ebx(): send whatever is in reqbuf on fd in ebx (slowloris)
req_flush_to_fd_ebx:
    lea rsi, [reqbuf]
    mov rdx, [req_cur]
    sub rdx, rsi
    mov edi, ebx
    jmp send_bytes                        ; tail-call: returns to our caller

; =======================================================================
; sockets
; =======================================================================
; tcp_connect() -> rax = fd, or -1. Reads conn_addr / conn_port.
tcp_connect:
    push rbx
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET_
    mov esi, SOCK_STREAM_
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov ebx, eax                          ; fd
    mov word [sa], LINNEA_AF_INET_
    mov eax, [conn_port]
    xchg al, ah                           ; port -> big-endian
    mov [sa + 2], ax
    mov eax, [conn_addr]
    mov [sa + 4], eax
    xor eax, eax
    mov [sa + 8], rax                     ; sin_zero
    mov eax, LINNEA_SYS_CONNECT
    mov edi, ebx
    lea rsi, [sa]
    mov edx, 16
    syscall
    test rax, rax
    js .fail_close
    ; on https, run the TLS handshake before handing the fd back
    cmp qword [use_tls], 0
    je .ok
    mov edi, ebx
    call tls_handshake
    test rax, rax
    js .fail_close
.ok:
    mov eax, ebx
    pop rbx
    ret
.fail_close:
    mov eax, LINNEA_SYS_CLOSE
    mov edi, ebx
    syscall
.fail:
    mov rax, -1
    pop rbx
    ret

; send_bytes(edi=fd, rsi=ptr, rdx=len) -> rax = 0 ok, -1 on error.
; The probes' sender: raw TCP, or one sealed TLS record over https.
send_bytes:
    cmp qword [use_tls], 0
    jne tls_app_send
    ; fall through to send_raw
; send_raw(edi=fd, rsi=ptr, rdx=len) -> rax = 0 ok, -1 on error (raw TCP)
send_raw:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .done
    mov eax, LINNEA_SYS_SENDTO
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    mov r10d, LINNEA_MSG_NOSIGNAL
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    js .err
    jz .err
    add r12, rax
    sub r13, rax
    jmp .loop
.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.err:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; wait_readable_or_closed(edi=fd, esi=timeout_ms)
;   -> rax = 1 readable(data), 0 timeout, 2 peer closed, -1 error
; After poll reports readability, a one-byte MSG_PEEK recv distinguishes real
; data (>0) from the EOF the peer's FIN produces (0).
MSG_PEEK_ equ 2
wait_readable_or_closed:
    push rbx
    push r12
    mov ebx, edi                          ; fd
    mov r12d, esi                          ; timeout ms (saved before poll clobbers esi)
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, r12d
    syscall
    test rax, rax
    js .err
    jz .timeout
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [respbuf]                     ; scratch for the peeked byte
    mov edx, 1
    mov r10d, MSG_PEEK_
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jz .closed
    js .err
    mov eax, 1
    jmp .done
.timeout:
    xor eax, eax
    jmp .done
.closed:
    mov eax, 2
    jmp .done
.err:
    mov rax, -1
.done:
    pop r12
    pop rbx
    ret

; =======================================================================
; response parsing
; =======================================================================
; read_response(edi=fd): read into respbuf until a quiet period or EOF.
;   -> rax = total bytes read (stored length in r-none; parse_status reads
;      respbuf and the length from resp_total)
read_response:
    cmp qword [use_tls], 0
    jne tls_app_recv                      ; https: read + decrypt TLS records
    push rbx
    push r12
    push r13
    mov ebx, edi
    xor r12d, r12d                        ; total
    mov r13d, 3000                        ; first-byte timeout ms
.loop:
    ; poll for readability
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, r13d
    syscall
    test rax, rax
    jle .done                             ; timeout or error: stop
    ; read
    mov eax, LINNEA_SYS_READ
    mov edi, ebx
    lea rsi, [respbuf]
    add rsi, r12
    mov edx, RESP_CAP
    sub edx, r12d
    syscall
    test rax, rax
    jle .done                             ; EOF or error
    add r12, rax
    cmp r12, RESP_CAP
    jae .done
    mov r13d, 400                          ; quiet timeout after first data
    jmp .loop
.done:
    mov [resp_total], r12
    mov rax, r12
    pop r13
    pop r12
    pop rbx
    ret

; parse_status() -> rax = status int, or -1. Reads respbuf / resp_total.
; Expects "HTTP/1.x SP DDD ...".
parse_status:
    mov rcx, [resp_total]
    cmp rcx, 12
    jb .none
    ; must start with "HTTP/"
    cmp dword [respbuf], 0x50545448        ; "HTTP" little-endian
    jne .none
    cmp byte [respbuf + 4], '/'
    jne .none
    ; find the first space (after the version token)
    lea rsi, [respbuf]
    mov rdx, rsi
    add rdx, rcx                           ; end
    add rsi, 5                             ; past "HTTP/"
.find_sp:
    cmp rsi, rdx
    jae .none
    cmp byte [rsi], ' '
    je .got_sp
    inc rsi
    jmp .find_sp
.got_sp:
    inc rsi                                ; first status digit
    lea rax, [rsi + 3]
    cmp rax, rdx
    ja .none
    ; three digits -> integer
    xor eax, eax
    mov ecx, 3
.digits:
    movzx r8d, byte [rsi]
    sub r8d, '0'
    cmp r8d, 9
    ja .none
    imul eax, eax, 10
    add eax, r8d
    inc rsi
    dec ecx
    jnz .digits
    ret
.none:
    mov rax, -1
    ret

; =======================================================================
; classification and reporting
; =======================================================================
; classify_reject(rsi=name, edx=namelen, rcx=observed, r9d=expected):
; an invalid request we expect the server to REJECT with status r9d.
;   observed == expected            -> OK
;   observed >= 400 (other reject)  -> INFO (rejected, different code)
;   observed 2xx/3xx (accepted!)    -> DEV
;   no response                     -> DEV
classify_reject:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rsi                          ; name
    mov r13d, edx                         ; namelen
    mov r14, rcx                          ; observed
    mov ebx, r9d                          ; expected
    ; decide kind in dil
    mov dil, K_DEV
    test r14, r14
    js .info                              ; closed with no status: a terse but
                                          ; legitimate rejection, not a deviation
    cmp r14d, ebx
    je .ok
    cmp r14d, 400
    jae .info
    jmp .emit                             ; accepted (<400) -> DEV
.ok:
    mov dil, K_OK
    jmp .emit
.info:
    mov dil, K_INFO
.emit:
    mov rsi, r12
    mov edx, r13d
    mov rcx, r14
    mov r9d, ebx
    call report
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; report_info(rsi=name, edx=namelen, rcx=observed): always INFO
report_info:
    mov dil, K_INFO
    mov r9d, -1
    jmp report

; report(dil=kind, rsi=name, edx=namelen, rcx=observed, r9d=expected(-1 none))
; prints "[kind] name -> HTTP NNN  (want MMM)\n", or "(no response)".
report:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                            ; align
    movzx ebx, dil                        ; kind
    mov r12, rsi                          ; name
    mov r13d, edx                         ; namelen
    mov r14, rcx                          ; observed
    mov r15d, r9d                         ; expected

    inc dword [n_total]
    cmp ebx, K_DEV
    jne .prefix
    inc dword [n_dev]
.prefix:
    ; prefix by kind
    cmp ebx, K_OK
    je .p_ok
    cmp ebx, K_DEV
    je .p_dev
    lea rsi, [pfx_info]
    mov edx, pfx_info_len
    jmp .pput
.p_ok:
    lea rsi, [pfx_ok]
    mov edx, pfx_ok_len
    jmp .pput
.p_dev:
    lea rsi, [pfx_dev]
    mov edx, pfx_dev_len
.pput:
    call puts
    ; name
    mov rsi, r12
    mov edx, r13d
    call puts
    ; " -> "
    lea rsi, [s_arrow]
    mov edx, s_arrow_len
    call puts
    ; observed
    test r14, r14
    js .noresp
    lea rsi, [s_status]
    mov edx, s_status_len
    call puts
    mov edi, r14d
    call print_u32
    ; want MMM ?
    cmp r15d, -1
    je .endline
    lea rsi, [s_want]
    mov edx, s_want_len
    call puts
    mov edi, r15d
    call print_u32
    lea rsi, [s_rparen_nl]
    mov edx, s_rparen_nl_len
    call puts
    jmp .ret
.endline:
    lea rsi, [s_nl]
    mov edx, 1
    call puts
    jmp .ret
.noresp:
    ; distinguish the h2 sentinels: -2 RST_STREAM, -3 GOAWAY, else no response
    cmp r14, -2
    je .rst
    cmp r14, -3
    je .goaway
    lea rsi, [s_noresp]
    mov edx, s_noresp_len
    call puts
    jmp .ret
.rst:
    lea rsi, [s_rst]
    mov edx, s_rst_len
    call puts
    jmp .ret
.goaway:
    lea rsi, [s_goaway]
    mov edx, s_goaway_len
    call puts
.ret:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; report_tail(dil=kind, rsi=name, edx=namelen, r8=tail ptr, r9d=tail len):
; like report but the detail is a literal string (used by slowloris).
report_tail:
    push rbx
    push r12
    push r13
    push r14
    push r15
    movzx ebx, dil
    mov r12, rsi
    mov r13d, edx
    mov r14, r8
    mov r15d, r9d
    inc dword [n_total]
    cmp ebx, K_DEV
    jne .prefix
    inc dword [n_dev]
.prefix:
    cmp ebx, K_OK
    je .p_ok
    cmp ebx, K_INFO
    je .p_info
    lea rsi, [pfx_dev]
    mov edx, pfx_dev_len
    jmp .pput
.p_ok:
    lea rsi, [pfx_ok]
    mov edx, pfx_ok_len
    jmp .pput
.p_info:
    lea rsi, [pfx_info]
    mov edx, pfx_info_len
.pput:
    call puts
    mov rsi, r12
    mov edx, r13d
    call puts
    mov rsi, r14
    mov edx, r15d
    call puts
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =======================================================================
; small helpers
; =======================================================================
; puts(rsi=ptr, rdx=len): the tool's internal print convention; shuffles to
; linnea_print_stdout's (rdi=ptr, rsi=len). puts_err writes to stderr.
puts:
    mov rdi, rsi
    mov rsi, rdx
    jmp linnea_print_stdout
puts_err:
    mov rdi, rsi
    mov rsi, rdx
    jmp linnea_print_stderr

; print_u32(edi=value): print the decimal number to stdout
print_u32:
    push rbx
    sub rsp, 8
    mov ecx, edi
    mov rdi, rcx
    lea rsi, [numbuf]
    call linnea_string_from_u64          ; rax = len
    lea rsi, [numbuf]
    mov rdx, rax
    call puts
    add rsp, 8
    pop rbx
    ret

; close_fd(edi=fd)
close_fd:
    mov eax, LINNEA_SYS_CLOSE
    syscall
    ret

; cstrlen(rsi=cstr) -> rax = length (NUL-terminated)
cstrlen:
    xor eax, eax
.l:
    cmp byte [rsi + rax], 0
    je .d
    inc rax
    jmp .l
.d:
    ret

; streq_z(rdi=cstr, rsi=fixed ptr, edx=fixed len) -> rax=1 if cstr equals the
; fixed string exactly (cstr must be NUL right after)
streq_z:
    xor eax, eax
    xor ecx, ecx
.l:
    cmp ecx, edx
    jae .tail
    mov r8b, [rdi + rcx]
    cmp r8b, [rsi + rcx]
    jne .no
    inc ecx
    jmp .l
.tail:
    cmp byte [rdi + rcx], 0
    jne .no
    mov eax, 1
.no:
    ret

; exit(edi=code)
exit:
    mov eax, LINNEA_SYS_EXIT
    syscall

; =======================================================================
; URL parsing
; =======================================================================
; parse_url(rdi=url cstr) -> rax = 0 ok / -1 error (prints its own message).
; Fills conn_addr, conn_port, path_ptr/len, and host_ptr/len (unless --host
; already set it). Accepts http://<ipv4-or-localhost>[:port][/path].
parse_url:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi                          ; cursor
    mov qword [use_tls], 0

    ; scheme: http:// or https://
    mov rsi, rbx
    lea rdi, [sch_https]
    mov edx, sch_https_len
    call memeq
    test rax, rax
    jz .try_http
    mov qword [use_tls], 1
    add rbx, sch_https_len
    jmp .scheme_ok
.try_http:
    mov rsi, rbx
    lea rdi, [sch_http]
    mov edx, sch_http_len
    call memeq
    test rax, rax
    jz .bad_scheme
    add rbx, sch_http_len
.scheme_ok:

    ; host runs until ':' or '/' or NUL
    mov r12, rbx                          ; host start
.host_scan:
    movzx eax, byte [rbx]
    test al, al
    je .host_end
    cmp al, ':'
    je .host_end
    cmp al, '/'
    je .host_end
    inc rbx
    jmp .host_scan
.host_end:
    mov r13, rbx
    sub r13, r12                          ; host length
    test r13, r13
    jz .bad_host                          ; empty host
    cmp r13, HOSTBUF_CAP - 1
    jae .bad_host
    ; copy the host into urlhost, NUL-terminated, for DNS and the Host header
    mov [urlhost_len], r13
    lea rdi, [urlhost]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov byte [rdi], 0
    ; default Host header = the URL host (unless --host overrode it)
    cmp qword [host_ptr], 0
    jne .host_set
    lea rax, [urlhost]
    mov [host_ptr], rax
    mov [host_len], r13
.host_set:

    ; optional :port
    mov dword [conn_port], 80             ; default for http
    cmp qword [use_tls], 0
    je .port_default_set
    mov dword [conn_port], 443            ; default for https
.port_default_set:
    movzx eax, byte [rbx]
    cmp al, ':'
    jne .port_done
    inc rbx
    xor r14d, r14d                         ; port accumulator
.port_scan:
    movzx eax, byte [rbx]
    cmp al, '0'
    jb .port_set
    cmp al, '9'
    ja .port_set
    imul r14d, r14d, 10
    sub eax, '0'
    add r14d, eax
    inc rbx
    jmp .port_scan
.port_set:
    test r14d, r14d
    jz .bad_host                           ; ":" with no digits
    mov [conn_port], r14d
.port_done:

    ; path = from '/' to NUL, or "/" if absent
    movzx eax, byte [rbx]
    cmp al, '/'
    je .have_path
    lea rax, [defslash]
    mov [path_ptr], rax
    mov qword [path_len], 1
    jmp .ok
.have_path:
    mov [path_ptr], rbx
    mov rsi, rbx
    call cstrlen
    mov [path_len], rax
.ok:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad_scheme:
    lea rsi, [err_scheme]
    mov edx, err_scheme_len
    call puts_err
    jmp .err
.bad_host:
    lea rsi, [err_host]
    mov edx, err_host_len
    call puts_err
.err:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; parse_ipv4_local(rdi=str) -> rax = address in network byte order, or -1.
; Reads four dotted decimal octets; stops at the first non-digit/non-dot, so a
; host followed by ':' '/' or NUL parses cleanly. Each octet 0..255.
parse_ipv4_local:
    xor r8d, r8d                          ; result (network order: octet i in byte i)
    xor r9d, r9d                          ; octet index
.octet:
    xor r11d, r11d                        ; octet value
    xor r10d, r10d                        ; digit count
.digit:
    movzx eax, byte [rdi]
    sub eax, '0'
    cmp eax, 9
    ja .end_digits
    imul r11d, r11d, 10
    add r11d, eax
    cmp r11d, 255
    ja .fail
    inc r10d
    inc rdi
    jmp .digit
.end_digits:
    test r10d, r10d
    jz .fail                              ; no digits in this octet
    mov ecx, r9d
    shl ecx, 3
    shl r11d, cl
    or r8d, r11d
    inc r9d
    movzx eax, byte [rdi]
    cmp r9d, 4
    je .last
    cmp al, '.'
    jne .fail
    inc rdi
    jmp .octet
.last:
    ; four octets read; the next byte must end the host token
    test al, al
    je .ok
    cmp al, ':'
    je .ok
    cmp al, '/'
    je .ok
    jmp .fail
.ok:
    mov eax, r8d
    ret
.fail:
    mov rax, -1
    ret

; =======================================================================
; DNS (A-record resolution over UDP)
; =======================================================================
; dns_resolve(rdi = hostname cstr) -> rax = IPv4 (network order) or -1.
; An IPv4 literal or "localhost" resolve without a query.
dns_resolve:
    push rbx
    mov rbx, rdi
    mov rdi, rbx
    call parse_ipv4_local
    cmp rax, -1
    jne .done                             ; a literal address
    mov rdi, rbx
    lea rsi, [localhost_s]
    mov edx, localhost_len
    call streq_z
    test rax, rax
    jz .dns
    mov eax, localhost_addr
    jmp .done
.dns:
    call nameserver_addr                  ; rax = nameserver (network order)
    mov esi, eax
    mov rdi, rbx
    call dns_query                        ; rax = address or -1
.done:
    pop rbx
    ret

; nameserver_addr() -> rax = the first nameserver in /etc/resolv.conf, or the
; systemd-resolved stub 127.0.0.53 if the file is missing or names none.
nameserver_addr:
    push rbx
    mov eax, LINNEA_SYS_OPEN
    lea rdi, [resolv_path]
    xor esi, esi                          ; O_RDONLY
    xor edx, edx
    syscall
    test rax, rax
    js .fallback
    mov ebx, eax                          ; fd
    mov eax, LINNEA_SYS_READ
    mov edi, ebx
    lea rsi, [resolv_buf]
    mov edx, 1023
    syscall
    mov r9, rax                           ; bytes read
    mov eax, LINNEA_SYS_CLOSE
    mov edi, ebx
    push r9
    syscall
    pop r9
    test r9, r9
    jle .fallback
    mov byte [resolv_buf + r9], 0         ; NUL-terminate
    lea rbx, [resolv_buf]                 ; line cursor
.line:
    cmp byte [rbx], 0
    je .fallback
    ; does this line start with "nameserver"?
    mov rsi, rbx
    lea rdi, [ns_kw]
    mov edx, ns_kw_len
    call memeq
    test rax, rax
    jz .next_line
    ; skip "nameserver" and any spaces/tabs
    lea rdi, [rbx + ns_kw_len]
.skip_ws:
    movzx eax, byte [rdi]
    cmp al, ' '
    je .adv_ws
    cmp al, 9
    jne .parse_ns
.adv_ws:
    inc rdi
    jmp .skip_ws
.parse_ns:
    call parse_ipv4_local                 ; rdi = the address text
    cmp rax, -1
    je .next_line
    pop rbx
    ret                                    ; rax = nameserver address
.next_line:
    ; advance to the start of the next line
.nl_scan:
    movzx eax, byte [rbx]
    test al, al
    je .fallback
    inc rbx
    cmp al, 10
    jne .nl_scan
    jmp .line
.fallback:
    mov eax, fallback_ns
    pop rbx
    ret

; dns_query(rdi = hostname cstr, esi = nameserver addr) -> rax = A record
; (network order) or -1. Builds a standard A query, sends it over UDP to
; nameserver:53, and walks the answer section for the first A record.
dns_query:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14, rdi                          ; hostname
    mov r15d, esi                         ; nameserver
    ; --- build the query in dnsbuf ---
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [dnsbuf]
    mov esi, 2                            ; a random 16-bit id
    xor edx, edx
    syscall
    mov byte [dnsbuf + 2], 0x01           ; flags: recursion desired
    mov byte [dnsbuf + 3], 0x00
    mov byte [dnsbuf + 4], 0x00           ; qdcount = 1
    mov byte [dnsbuf + 5], 0x01
    xor eax, eax
    mov [dnsbuf + 6], eax                 ; ancount = nscount = 0
    mov [dnsbuf + 8], eax                 ; nscount = arcount = 0
    mov word [dnsbuf + 10], 0
    ; QNAME: length-prefixed labels
    lea rdi, [dnsbuf + 12]                ; write cursor
    mov rsi, r14                          ; hostname read cursor
.qn_label:
    mov rbx, rdi                          ; remember the length-byte slot
    inc rdi                               ; leave room for the length
    xor ecx, ecx                          ; label length
.qn_char:
    movzx eax, byte [rsi]
    test al, al
    je .qn_end
    cmp al, '.'
    je .qn_dot
    mov [rdi], al
    inc rdi
    inc rsi
    inc ecx
    jmp .qn_char
.qn_dot:
    mov [rbx], cl                         ; fill in the label length
    inc rsi                               ; skip the '.'
    jmp .qn_label
.qn_end:
    mov [rbx], cl                         ; last label length
    mov byte [rdi], 0                     ; root label
    inc rdi
    mov word [rdi], 0x0100                ; QTYPE = A (0x0001, big-endian on wire)
    mov word [rdi + 2], 0x0100            ; QCLASS = IN
    add rdi, 4
    lea r13, [dnsbuf]
    sub rdi, r13                          ; r13d unused; rdi = query length
    mov r13, rdi                          ; query length
    ; --- send over UDP ---
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET_
    mov esi, SOCK_DGRAM_
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov ebx, eax                          ; udp fd
    mov word [ns_sa], LINNEA_AF_INET_
    mov word [ns_sa + 2], 0x3500          ; port 53, big-endian
    mov [ns_sa + 4], r15d                 ; nameserver address
    xor eax, eax
    mov [ns_sa + 8], rax
    mov eax, LINNEA_SYS_SENDTO
    mov edi, ebx
    lea rsi, [dnsbuf]
    mov rdx, r13
    xor r10d, r10d
    lea r8, [ns_sa]
    mov r9d, 16
    syscall
    test rax, rax
    js .fail_close
    ; wait up to 2s for the reply
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
    syscall
    test rax, rax
    jle .fail_close
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [dnsbuf]
    mov edx, DNSBUF_CAP
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    mov r13, rax                          ; response length
    push rax
    mov eax, LINNEA_SYS_CLOSE
    mov edi, ebx
    syscall
    pop r13
    cmp r13, 12
    jb .fail
    ; --- parse the answer section ---
    movzx r12d, byte [dnsbuf + 6]         ; ancount (big-endian)
    shl r12d, 8
    movzx eax, byte [dnsbuf + 7]
    or r12d, eax                          ; r12 = answer count
    lea rsi, [dnsbuf + 12]                ; cursor past the header
    lea rbx, [dnsbuf]
    add rbx, r13                          ; end of the response
    ; skip the question's QNAME (no compression) then QTYPE+QCLASS
.q_skip:
    cmp rsi, rbx
    jae .fail
    movzx eax, byte [rsi]
    test al, al
    je .q_skipped
    inc rsi
    add rsi, rax
    jmp .q_skip
.q_skipped:
    add rsi, 5                            ; the root 0, then QTYPE(2)+QCLASS(2)
    ; walk the answers
.ans:
    test r12d, r12d
    jz .fail
    cmp rsi, rbx
    jae .fail
    ; NAME: a compression pointer (11xxxxxx) is 2 bytes; else label sequence
    movzx eax, byte [rsi]
    mov ecx, eax
    and ecx, 0xc0
    cmp ecx, 0xc0
    je .name_ptr
.name_labels:
    movzx eax, byte [rsi]
    test al, al
    je .name_done_labels
    inc rsi
    add rsi, rax
    cmp rsi, rbx
    jae .fail
    jmp .name_labels
.name_done_labels:
    inc rsi                               ; the root 0
    jmp .rr_fixed
.name_ptr:
    add rsi, 2
.rr_fixed:
    lea rax, [rsi + 10]                   ; TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
    cmp rax, rbx
    ja .fail
    movzx eax, byte [rsi]                 ; TYPE high
    shl eax, 8
    movzx ecx, byte [rsi + 1]
    or eax, ecx                           ; TYPE
    movzx edx, byte [rsi + 8]             ; RDLENGTH high
    shl edx, 8
    movzx ecx, byte [rsi + 9]
    or edx, ecx                           ; RDLENGTH
    add rsi, 10                           ; -> RDATA
    cmp eax, 1                            ; A record?
    jne .rr_next
    cmp edx, 4
    jne .rr_next
    lea rax, [rsi + 4]
    cmp rax, rbx
    ja .fail
    mov eax, [rsi]                        ; the 4-byte address (already network order)
    jmp .ok
.rr_next:
    add rsi, rdx                          ; skip RDATA
    dec r12d
    jmp .ans
.ok:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fail_close:
    mov eax, LINNEA_SYS_CLOSE
    mov edi, ebx
    syscall
.fail:
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =======================================================================
; TLS 1.3 client (AES-128-GCM, x25519, no certificate verification)
; =======================================================================
; tr_add(rsi=ptr, rdx=len): append handshake bytes to the transcript buffer
tr_add:
    push rdi
    push rcx
    mov rdi, [tr_len]
    lea rdi, [tr_buf + rdi]
    mov rcx, rdx
    rep movsb
    add [tr_len], rdx
    pop rcx
    pop rdi
    ret

; read_full(edi=fd, rsi=buf, rdx=n) -> rax = 0 ok, -1 on EOF/error
read_full:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .ok
    mov eax, LINNEA_SYS_READ
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    jle .fail
    add r12, rax
    sub r13, rax
    jmp .loop
.ok:
    xor eax, eax
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

; read_tls_record(edi=fd) -> rax = outer content type (-1 on EOF/error).
; The whole record lands at tls_rec; rec_total gets header(5)+payload length.
read_tls_record:
    push rbx
    mov ebx, edi
    mov edi, ebx
    lea rsi, [tls_rec]
    mov edx, 5
    call read_full
    test rax, rax
    js .fail
    movzx eax, byte [tls_rec + 3]
    shl eax, 8
    movzx ecx, byte [tls_rec + 4]
    or eax, ecx                           ; payload length
    cmp eax, 20480 - 5
    ja .fail
    mov [rec_total], rax                  ; payload length (temporarily)
    test eax, eax
    jz .empty
    mov edi, ebx
    lea rsi, [tls_rec + 5]
    mov edx, [rec_total]
    call read_full
    test rax, rax
    js .fail
.empty:
    mov rax, [rec_total]
    add rax, 5
    mov [rec_total], rax
    movzx eax, byte [tls_rec]             ; outer content type
    pop rbx
    ret
.fail:
    mov rax, -1
    pop rbx
    ret

; tls_handshake(edi=fd) -> rax = 0 on success, -1 on failure.
; A full 1-RTT TLS 1.3 handshake with no certificate verification (this is a
; prober): x25519 key exchange, AES-128-GCM, ALPN http/1.1, SNI = urlhost.
tls_handshake:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16                          ; force 16-alignment for the SSE crypto
    mov r15d, edi                         ; fd

    ; --- x25519 keypair ---
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_priv]
    mov esi, 32
    xor edx, edx
    syscall
    and byte [tls_priv], 248              ; clamp
    and byte [tls_priv + 31], 127
    or byte [tls_priv + 31], 64
    lea rdi, [tls_pub]
    lea rsi, [tls_priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    ; client random + legacy session id
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_random]
    mov esi, 32
    xor edx, edx
    syscall
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_sessid]
    mov esi, 32
    xor edx, edx
    syscall
    mov qword [tr_len], 0

    ; --- build + send ClientHello ---
    call build_clienthello                ; rax = total record length
    mov edi, r15d
    lea rsi, [hs_buf]
    mov rdx, rax
    call send_raw
    test rax, rax
    js .fail

    ; --- ServerHello (plaintext handshake record) ---
    mov edi, r15d
    call read_tls_record
    cmp rax, 22
    jne .fail
    ; transcript += the ServerHello handshake bytes
    lea rsi, [tls_rec + 5]
    mov rdx, [rec_total]
    sub rdx, 5
    push rsi
    push rdx
    call tr_add
    pop rdx
    pop rsi
    call parse_serverhello                ; rsi=HS ptr, rdx=HS len -> tls_srvpub
    test rax, rax
    js .fail

    ; --- key schedule ---
    ; shared = x25519(priv, srvpub)
    lea rdi, [tls_shared]
    lea rsi, [tls_priv]
    lea rdx, [tls_srvpub]
    call linnea_x25519
    ; early = HKDF-Extract("", zeros)
    lea rdi, [zeros32_p]
    xor esi, esi
    lea rdx, [zeros32_p]
    mov ecx, 32
    lea r8, [sec_early]
    call linnea_hkdf_extract
    ; derived = Derive-Secret(early, "derived", H(""))
    lea rdi, [sec_early]
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [sec_derived]
    call linnea_tls_derive_secret
    ; hs = HKDF-Extract(derived, shared)
    lea rdi, [sec_derived]
    mov esi, 32
    lea rdx, [tls_shared]
    mov ecx, 32
    lea r8, [sec_hs]
    call linnea_hkdf_extract
    ; th = H(CH || SH)
    lea rdi, [tr_buf]
    mov rsi, [tr_len]
    lea rdx, [th_buf]
    call linnea_sha256
    ; c_hs, s_hs
    lea rdi, [sec_hs]
    lea rsi, [lbl_c_hs]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_chs]
    call linnea_tls_derive_secret
    lea rdi, [sec_hs]
    lea rsi, [lbl_s_hs]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_shs]
    call linnea_tls_derive_secret
    ; derived2, master
    lea rdi, [sec_hs]
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [sec_derived]                  ; reuse sec_derived as derived2
    call linnea_tls_derive_secret
    lea rdi, [sec_derived]
    mov esi, 32
    lea rdx, [zeros32_p]
    mov ecx, 32
    lea r8, [sec_master]
    call linnea_hkdf_extract
    ; handshake traffic keys: write = c_hs, read = s_hs
    lea rdi, [tls_wkeys]
    lea rsi, [sec_chs]
    call linnea_tls_keys_init
    lea rdi, [tls_rkeys]
    lea rsi, [sec_shs]
    call linnea_tls_keys_init

    ; --- read the encrypted server flight until Finished ---
    mov qword [hs_plain_len], 0
    mov qword [parse_off], 0
.flight_read:
    mov edi, r15d
    call read_tls_record
    test rax, rax
    js .fail
    cmp rax, 20
    je .flight_read                        ; ChangeCipherSpec: ignore
    cmp rax, 23
    jne .fail
    lea rdi, [tls_rkeys]
    lea rsi, [tls_rec]
    mov rdx, [rec_total]
    mov rcx, [hs_plain_len]
    lea rcx, [hs_plain + rcx]
    call linnea_tls_open                   ; rax = len, rdx = inner type
    test rax, rax
    js .fail
    cmp rdx, 22                            ; inner type must be handshake
    jne .fail
    add [hs_plain_len], rax
.walk:
    mov r12, [parse_off]
    mov r13, [hs_plain_len]
    lea rax, [r12 + 4]
    cmp rax, r13
    ja .flight_read                        ; need more bytes for a header
    movzx ecx, byte [hs_plain + r12 + 1]   ; msg length (24-bit)
    shl ecx, 8
    movzx eax, byte [hs_plain + r12 + 2]
    or ecx, eax
    shl ecx, 8
    movzx eax, byte [hs_plain + r12 + 3]
    or ecx, eax                            ; ecx = msg body length
    lea rax, [r12 + 4]
    add rax, rcx                           ; end of this message
    cmp rax, r13
    ja .flight_read                        ; message not fully arrived
    ; absorb this whole handshake message into the transcript
    lea rsi, [hs_plain + r12]
    lea rdx, [rcx + 4]
    push rcx
    call tr_add
    pop rcx
    movzx eax, byte [hs_plain + r12]       ; message type
    lea r12, [r12 + rcx + 4]
    mov [parse_off], r12
    cmp eax, 0x14                          ; Finished
    je .flight_done
    jmp .walk
.flight_done:

    ; --- application traffic secrets (th2 = H(CH..server Finished)) ---
    lea rdi, [tr_buf]
    mov rsi, [tr_len]
    lea rdx, [th_buf]
    call linnea_sha256
    lea rdi, [sec_master]
    lea rsi, [lbl_c_ap]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_cap]
    call linnea_tls_derive_secret
    lea rdi, [sec_master]
    lea rsi, [lbl_s_ap]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_sap]
    call linnea_tls_derive_secret

    ; --- client Finished (still under the handshake write keys) ---
    ; finished_key = HKDF-Expand-Label(c_hs, "finished", "", 32)
    lea rdi, [sec_chs]
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [fin_key]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; verify_data = HMAC(finished_key, th2) -> hs_buf+4 (after the 4-byte header)
    lea rdi, [fin_key]
    mov esi, 32
    lea rdx, [th_buf]
    mov ecx, 32
    lea r8, [hs_buf + 4]
    call linnea_hmac_sha256
    mov byte [hs_buf], 0x14                ; Finished
    mov byte [hs_buf + 1], 0
    mov byte [hs_buf + 2], 0
    mov byte [hs_buf + 3], 32
    ; seal (inner type 22) with the handshake write keys, send
    lea rdi, [tls_wkeys]
    mov esi, 22
    lea rdx, [hs_buf]
    mov ecx, 36
    lea r8, [tls_rec]
    call linnea_tls_seal                   ; rax = record length
    mov edi, r15d
    lea rsi, [tls_rec]
    mov rdx, rax
    call send_raw
    test rax, rax
    js .fail

    ; --- switch to application traffic keys ---
    lea rdi, [tls_wkeys]
    lea rsi, [sec_cap]
    call linnea_tls_keys_init
    lea rdi, [tls_rkeys]
    lea rsi, [sec_sap]
    call linnea_tls_keys_init

    xor eax, eax
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.fail:
    mov rax, -1
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; parse_serverhello(rsi=HS ptr, rdx=HS len) -> rax = 0 ok / -1.
; Extracts the server's x25519 key_share into tls_srvpub.
parse_serverhello:
    push rbx
    push r12
    mov rbx, rsi                           ; cursor
    lea r12, [rsi + rdx]                   ; end
    ; skip: type(1) len(3) legacy_version(2) random(32)
    add rbx, 4 + 2 + 32
    cmp rbx, r12
    jae .fail
    movzx eax, byte [rbx]                  ; session id length
    inc rbx
    add rbx, rax                           ; skip session id
    add rbx, 2 + 1                         ; cipher suite(2) + compression(1)
    cmp rbx, r12
    jae .fail
    ; extensions: total length (2), then ext entries
    add rbx, 2                             ; skip the extensions-length field
.ext:
    lea rax, [rbx + 4]
    cmp rax, r12
    ja .fail                               ; no key_share found
    movzx eax, byte [rbx]                  ; ext type high
    shl eax, 8
    movzx ecx, byte [rbx + 1]
    or eax, ecx                            ; ext type
    movzx edx, byte [rbx + 2]              ; ext data length
    shl edx, 8
    movzx ecx, byte [rbx + 3]
    or edx, ecx
    add rbx, 4                             ; -> ext data
    cmp eax, 0x0033                        ; key_share
    je .keyshare
    add rbx, rdx                           ; skip this extension
    jmp .ext
.keyshare:
    ; ext data: group(2) keylen(2) key[keylen]
    lea rax, [rbx + 4 + 32]
    cmp rax, r12
    ja .fail
    lea rdi, [tls_srvpub]
    lea rsi, [rbx + 4]                     ; skip group(2)+keylen(2)
    mov ecx, 32
    rep movsb
    xor eax, eax
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r12
    pop rbx
    ret

; build_clienthello() -> rax = total record length (record at hs_buf).
; Also appends the ClientHello handshake message to the transcript.
build_clienthello:
    push rbx
    push r12
    push r13
    mov r12, [urlhost_len]                 ; SNI host length
    lea rdi, [hs_buf + 5]                  ; write cursor (past record header)
    mov byte [rdi], 0x01                   ; ClientHello
    lea r13, [rdi + 1]                     ; hs length-24 slot
    add rdi, 4                             ; past type + len24
    ; body
    mov byte [rdi], 0x03                   ; legacy_version 0x0303
    mov byte [rdi + 1], 0x03
    add rdi, 2
    lea rsi, [tls_random]                  ; random[32]
    mov ecx, 32
    rep movsb                              ; rdi advanced by 32
    mov byte [rdi], 32                     ; session id length
    inc rdi
    lea rsi, [tls_sessid]
    mov ecx, 32
    rep movsb
    lea rsi, [ch_suites]                   ; suites + compression (6 bytes)
    mov ecx, ch_suites_len
    rep movsb
    ; extensions length slot
    mov rbx, rdi                           ; ext-length-16 slot
    add rdi, 2
    ; -- SNI --
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00               ; server_name
    lea rax, [r12 + 5]                     ; ext data len = 5 + hostlen
    mov [rdi + 2], ah
    mov [rdi + 3], al
    lea rax, [r12 + 3]                     ; server_name_list len = 3 + hostlen
    mov [rdi + 4], ah
    mov [rdi + 5], al
    mov byte [rdi + 6], 0x00               ; name type host_name
    mov rax, r12                           ; name length
    mov [rdi + 7], ah
    mov [rdi + 8], al
    add rdi, 9
    lea rsi, [urlhost]
    mov rcx, r12
    rep movsb
    ; -- supported_versions --
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x2b
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x03
    mov byte [rdi + 4], 0x02
    mov byte [rdi + 5], 0x03
    mov byte [rdi + 6], 0x04
    add rdi, 7
    ; -- supported_groups (x25519) --
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x0a
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x04
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x02
    mov byte [rdi + 6], 0x00
    mov byte [rdi + 7], 0x1d
    add rdi, 8
    ; -- signature_algorithms (ecdsa_secp256r1_sha256) --
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x0d
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x04
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x02
    mov byte [rdi + 6], 0x04
    mov byte [rdi + 7], 0x03
    add rdi, 8
    ; -- key_share --
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x33
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x26               ; ext data len = 38
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x24               ; client_shares len = 36
    mov byte [rdi + 6], 0x00
    mov byte [rdi + 7], 0x1d               ; group x25519
    mov byte [rdi + 8], 0x00
    mov byte [rdi + 9], 0x20               ; key length 32
    add rdi, 10
    lea rsi, [tls_pub]
    mov ecx, 32
    rep movsb
    ; -- ALPN (alpn_str/alpn_len: "http/1.1" or "h2") --
    mov r8, [alpn_len]                     ; protocol length
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x10
    lea rax, [r8 + 3]                      ; ext data len = 3 + protolen
    mov [rdi + 2], ah
    mov [rdi + 3], al
    lea rax, [r8 + 1]                      ; ALPN list len = 1 + protolen
    mov [rdi + 4], ah
    mov [rdi + 5], al
    mov [rdi + 6], r8b                     ; protocol name length
    add rdi, 7
    mov rsi, [alpn_str]
    mov rcx, r8
    rep movsb
    ; --- backpatch lengths ---
    ; extensions length = rdi - (rbx + 2)
    mov rax, rdi
    sub rax, rbx
    sub rax, 2
    mov [rbx], ah
    mov [rbx + 1], al
    ; handshake body length (24-bit) = rdi - (r13 + 3)
    mov rax, rdi
    sub rax, r13
    sub rax, 3
    mov byte [r13], 0                      ; high byte (always 0 here)
    mov ecx, eax
    shr ecx, 8
    mov [r13 + 1], cl
    mov [r13 + 2], al
    ; record header
    mov byte [hs_buf], 0x16
    mov byte [hs_buf + 1], 0x03
    mov byte [hs_buf + 2], 0x01
    mov rax, rdi
    lea rcx, [hs_buf + 5]
    sub rax, rcx                            ; record payload length
    mov [hs_buf + 3], ah
    mov [hs_buf + 4], al
    ; transcript += the ClientHello handshake message (hs_buf+5 .. rdi)
    lea rsi, [hs_buf + 5]
    mov rdx, rax
    push rax
    call tr_add
    pop rax
    add rax, 5                              ; total record length
    pop r13
    pop r12
    pop rbx
    ret

; tls_app_send(edi=fd, rsi=ptr, rdx=len) -> rax = 0 ok / -1
; Seals the payload as one application_data record and sends it.
tls_app_send:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16                          ; align for the SSE seal
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
    lea rdi, [tls_wkeys]
    mov esi, 23
    mov rdx, r12
    mov rcx, r13
    lea r8, [tls_rec]
    call linnea_tls_seal
    mov edi, ebx
    lea rsi, [tls_rec]
    mov rdx, rax
    call send_raw
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; tls_app_recv(edi=fd): read + decrypt application records into respbuf until a
; quiet period or close. Sets resp_total, like read_response.
tls_app_recv:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16                          ; align for the SSE open
    mov ebx, edi
    mov qword [resp_total], 0
    mov r13d, 3000
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, r13d
    syscall
    test rax, rax
    jle .done
    mov edi, ebx
    call read_tls_record
    test rax, rax
    js .done
    cmp rax, 20
    je .next                               ; CCS
    cmp rax, 23
    jne .done
    lea rdi, [tls_rkeys]
    lea rsi, [tls_rec]
    mov rdx, [rec_total]
    lea rcx, [tls_pt]
    call linnea_tls_open                   ; rax=len, rdx=inner type
    test rax, rax
    js .done
    cmp rdx, 21
    je .done                               ; alert (close_notify)
    cmp rdx, 23
    jne .next                              ; e.g. post-handshake NewSessionTicket
    ; append plaintext to respbuf
    mov rcx, [resp_total]
    lea rdi, [respbuf + rcx]
    lea rsi, [tls_pt]
    mov rcx, rax
    rep movsb
    add [resp_total], rax
.next:
    mov r13d, 400
    jmp .loop
.done:
    mov rax, [resp_total]
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =======================================================================
; HTTP/2 client (HPACK encode, minimal decode for :status)
; =======================================================================
; hp_enc_int(rdi=out, rax=value, cl=N prefix bits, r8b=flags) -> rdi advanced.
; Writes an HPACK prefix integer; flags occupy the top 8-N bits of byte 0.
hp_enc_int:
    mov edx, 1
    shl edx, cl
    dec edx                               ; mask = (1<<N)-1
    cmp rax, rdx
    jae .big
    or al, r8b
    mov [rdi], al
    inc rdi
    ret
.big:
    mov r9d, r8d
    or r9b, dl                            ; flags | mask
    mov [rdi], r9b
    inc rdi
    sub rax, rdx
.loop:
    cmp rax, 0x80
    jb .last
    mov r9, rax
    and r9d, 0x7f
    or r9d, 0x80
    mov [rdi], r9b
    inc rdi
    shr rax, 7
    jmp .loop
.last:
    mov [rdi], al
    inc rdi
    ret

; h2_enc_str(rdi=out, rsi=str, rdx=len) -> rdi advanced. Raw (H=0) string literal.
h2_enc_str:
    push rbx
    push r12
    mov rbx, rsi
    mov r12, rdx
    mov rax, r12                          ; length, 7-bit prefix, H=0
    mov cl, 7
    xor r8d, r8d
    call hp_enc_int
    mov rsi, rbx
    mov rcx, r12
    rep movsb
    pop r12
    pop rbx
    ret

; h2_enc_nameref(rdi=out, rax=name index, rsi=val, rdx=vlen) -> rdi advanced.
; Literal header, name by index (4-bit prefix, without indexing), raw value.
h2_enc_nameref:
    push rbx
    push r12
    mov rbx, rsi
    mov r12, rdx
    mov cl, 4
    xor r8d, r8d                          ; 0x00 = without indexing
    call hp_enc_int
    mov rsi, rbx
    mov rdx, r12
    call h2_enc_str
    pop r12
    pop rbx
    ret

; h2_build_get(): build a GET header block into h2_block, set h2_block_len.
h2_build_get:
    push rbx
    lea rbx, [h2_block]
    mov byte [rbx], 0x82                  ; :method GET  (static index 2)
    inc rbx
    mov byte [rbx], 0x87                  ; :scheme https (static index 7)
    inc rbx
    mov rdi, rbx                          ; :path (name index 4) = path
    mov rax, 4
    mov rsi, [path_ptr]
    mov rdx, [path_len]
    call h2_enc_nameref
    mov rbx, rdi
    mov rax, 1                            ; :authority (name index 1) = host
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call h2_enc_nameref
    lea rax, [h2_block]
    sub rdi, rax
    mov [h2_block_len], rdi
    pop rbx
    ret

; h2_enc_nameref_inc(rdi=out, rax=name index, rsi=val, rdx=vlen) -> rdi advanced.
; Literal header WITH incremental indexing (0x40, 6-bit prefix) — adds the field
; to both encoder and decoder dynamic tables.
h2_enc_nameref_inc:
    push rbx
    push r12
    mov rbx, rsi
    mov r12, rdx
    mov cl, 6
    mov r8d, 0x40
    call hp_enc_int
    mov rsi, rbx
    mov rdx, r12
    call h2_enc_str
    pop r12
    pop rbx
    ret

; h2_build_nopath(): a request missing :path (malformed, RFC 9113 8.3.1).
h2_build_nopath:
    push rbx
    lea rbx, [h2_block]
    mov byte [rbx], 0x82                  ; :method GET
    inc rbx
    mov byte [rbx], 0x87                  ; :scheme https
    inc rbx
    mov rdi, rbx
    mov rax, 1                            ; :authority (no :path at all)
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call h2_enc_nameref
    lea rax, [h2_block]
    sub rdi, rax
    mov [h2_block_len], rdi
    pop rbx
    ret

; h2_build_dyn1(): a GET whose :authority is added to the dynamic table
; (literal with incremental indexing) — becomes dynamic index 62.
h2_build_dyn1:
    push rbx
    lea rbx, [h2_block]
    mov byte [rbx], 0x82
    inc rbx
    mov byte [rbx], 0x87
    inc rbx
    mov rdi, rbx
    mov rax, 4                            ; :path (without indexing)
    mov rsi, [path_ptr]
    mov rdx, [path_len]
    call h2_enc_nameref
    mov rax, 1                            ; :authority WITH incremental indexing
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call h2_enc_nameref_inc
    lea rax, [h2_block]
    sub rdi, rax
    mov [h2_block_len], rdi
    pop rbx
    ret

; h2_build_dyn2(): the same GET but :authority is the dynamic index 62 added by
; dyn1 — proves the server's HPACK dynamic table decoded the first request.
h2_build_dyn2:
    push rbx
    lea rbx, [h2_block]
    mov byte [rbx], 0x82
    inc rbx
    mov byte [rbx], 0x87
    inc rbx
    mov rdi, rbx
    mov rax, 4                            ; :path (without indexing)
    mov rsi, [path_ptr]
    mov rdx, [path_len]
    call h2_enc_nameref
    mov byte [rdi], 0xbe                  ; indexed field, dynamic entry 62 (:authority)
    inc rdi
    lea rax, [h2_block]
    sub rdi, rax
    mov [h2_block_len], rdi
    pop rbx
    ret

; h2_build_badhpack(): a single indexed field for a dynamic entry that does not
; exist on a fresh connection — an HPACK decode error (RFC 9113 4.3).
h2_build_badhpack:
    mov byte [h2_block], 0xbe             ; indexed dynamic 62, empty table
    mov qword [h2_block_len], 1
    ret

; h2_exchange(edi=fd, esi=first, edx=stream id) -> rax = status (100..599), or
; -1 no response, -2 RST_STREAM (stream rejected), -3 GOAWAY (connection error).
; Sends the connection preface + SETTINGS when first=1, then a HEADERS frame
; carrying h2_block, and reads the response frames.
h2_exchange:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, edi                          ; fd
    mov r13d, edx                         ; stream id
    mov r14d, esi                         ; first?
    lea rdi, [reqbuf]                     ; assemble the outbound bytes
    test r14d, r14d
    jz .no_preface
    lea rsi, [h2_preface]
    mov rcx, h2_preface_len
    rep movsb
    lea rsi, [h2_settings]
    mov rcx, h2_settings_len
    rep movsb
.no_preface:
    mov r12, [h2_block_len]
    mov rax, r12                          ; HEADERS frame header
    shr rax, 16
    mov [rdi], al
    mov rax, r12
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], r12b
    mov byte [rdi + 3], 0x01              ; HEADERS
    mov byte [rdi + 4], 0x05              ; END_HEADERS | END_STREAM
    mov eax, r13d                         ; stream id, big-endian
    bswap eax
    mov [rdi + 5], eax
    add rdi, 9
    lea rsi, [h2_block]
    mov rcx, r12
    rep movsb
    lea rax, [reqbuf]
    mov rdx, rdi
    sub rdx, rax                          ; total length
    mov edi, ebx
    lea rsi, [reqbuf]
    call send_bytes
    test rax, rax
    js .fail
    mov edi, ebx
    call read_response                    ; fills respbuf / resp_total
    call h2_status_from_frames
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2_status_from_frames() -> rax = status, or -1. Walks respbuf as HTTP/2 frames
; and returns the :status from the first HEADERS frame.
h2_status_from_frames:
    push rbx
    push r12
    push r13
    lea r12, [respbuf]                    ; cursor
    mov r13, [resp_total]
    add r13, r12                          ; end
.frame:
    lea rax, [r12 + 9]
    cmp rax, r13
    ja .none                              ; no room for a frame header
    movzx eax, byte [r12]                 ; length (24-bit)
    shl eax, 8
    movzx ecx, byte [r12 + 1]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [r12 + 2]
    or eax, ecx
    mov rbx, rax                          ; frame length
    movzx ecx, byte [r12 + 3]             ; type
    lea rax, [r12 + 9]
    add rax, rbx                           ; end of this frame's payload
    cmp rax, r13
    ja .none                              ; frame not fully present
    cmp ecx, 0x03                         ; RST_STREAM -> stream rejected
    je .rst
    cmp ecx, 0x07                         ; GOAWAY -> connection error
    je .goaway
    cmp ecx, 0x01                         ; HEADERS?
    jne .skip
    ; found HEADERS: block starts at payload (assume no PADDED/PRIORITY on the
    ; response, which Linnea does not set)
    lea rdi, [r12 + 9]
    mov rsi, rbx
    call h2_find_status
    cmp rax, 0
    jg .done                              ; a real status
.skip:
    lea r12, [r12 + rbx + 9]
    jmp .frame
.rst:
    mov rax, -2
    jmp .done
.goaway:
    mov rax, -3
    jmp .done
.none:
    mov rax, -1
.done:
    pop r13
    pop r12
    pop rbx
    ret

; h2_read_rawstr(rsi=cur, rdi=end) -> rax=ptr, rdx=len, rsi advanced, CF on error
; (Huffman-flagged strings fail — Linnea encodes response values raw.)
h2_read_rawstr:
    cmp rsi, rdi
    jae .err
    test byte [rsi], 0x80                 ; Huffman bit
    jnz .err
    mov ecx, 7
    call hp_int                           ; rax=len, rsi past the length prefix
    jc .err
    mov rdx, rax
    mov rax, rsi
    add rsi, rdx                          ; advance past the raw bytes
    cmp rsi, rdi
    ja .err
    clc
    ret
.err:
    stc
    ret

; hp_int(rsi=cur, rdi=end, ecx=N prefix bits) -> rax=value, rsi advanced, CF err
hp_int:
    cmp rsi, rdi
    jae .err
    movzx eax, byte [rsi]
    inc rsi
    mov edx, 1
    shl edx, cl
    dec edx                               ; mask
    and eax, edx
    cmp eax, edx
    jne .done
    xor r8d, r8d                          ; shift
.cont:
    cmp rsi, rdi
    jae .err
    movzx r9d, byte [rsi]
    inc rsi
    mov r10, r9
    and r10, 0x7f
    mov ecx, r8d
    shl r10, cl
    add rax, r10
    add r8d, 7
    test r9b, 0x80
    jnz .cont
.done:
    clc
    ret
.err:
    stc
    ret

; h2_find_status(rdi=block, rsi=len) -> rax = status (100..599) or -1.
h2_find_status:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi                          ; cur
    lea r13, [rdi + rsi]                  ; end
.next:
    cmp r12, r13
    jae .none
    movzx eax, byte [r12]
    test al, 0x80
    jnz .indexed
    test al, 0x40
    jnz .lit6
    test al, 0x20
    jnz .sizeupd
    jmp .lit4                             ; 0x00 without / 0x10 never: 4-bit index
.indexed:
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hp_int
    jc .none
    mov r12, rsi
    cmp rax, 8
    jb .next
    cmp rax, 14
    ja .next
    lea rcx, [h2_status_map]
    sub rax, 8
    movzx eax, word [rcx + rax*2]
    jmp .done
.lit6:
    mov r14d, 6
    jmp .lit_common
.lit4:
    mov r14d, 4
.lit_common:
    mov rsi, r12
    mov rdi, r13
    mov ecx, r14d
    call hp_int
    jc .none
    mov r12, rsi
    mov rbx, rax                          ; name index (0 = literal name)
    test rbx, rbx
    jnz .have_name
    ; literal name: read it, mark whether it is :status
    mov rsi, r12
    mov rdi, r13
    call h2_read_rawstr
    jc .none
    mov r12, rsi                          ; advanced past the name
    ; compare (rax,rdx) to ":status"
    cmp rdx, 7
    jne .name_other
    mov rsi, rax
    lea rdi, [pseudo_status]
    mov edx, 7
    call memeq
    test rax, rax
    jz .name_other
    mov rbx, 8                            ; treat as :status
    jmp .have_name
.name_other:
    xor ebx, ebx                          ; some other name; skip its value
.have_name:
    mov rsi, r12
    mov rdi, r13
    call h2_read_rawstr                   ; value
    jc .none
    mov r12, rsi
    cmp rbx, 8                            ; was the name :status?
    jne .next
    ; parse the decimal value (rax=ptr, rdx=len)
    mov rsi, rax
    xor r8d, r8d
    xor ecx, ecx
.pd:
    cmp rcx, rdx
    jae .pd_done
    movzx r9d, byte [rsi + rcx]
    sub r9d, '0'
    cmp r9d, 9
    ja .none
    imul r8d, r8d, 10
    add r8d, r9d
    inc rcx
    jmp .pd
.pd_done:
    mov eax, r8d
    jmp .done
.sizeupd:
    mov rsi, r12
    mov rdi, r13
    mov ecx, 5
    call hp_int
    jc .none
    mov r12, rsi
    jmp .next
.none:
    mov rax, -1
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2_battery(): the HTTP/2 probe set.
h2_battery:
    call probe_h2_valid
    call probe_h2_dyn
    call probe_h2_nopath
    call probe_h2_badhpack
    ret

; probe_h2_valid: a well-formed GET over h2 — OK if any :status came back.
probe_h2_valid:
    push rbx
    call tcp_connect                      ; TLS handshake with ALPN h2
    test rax, rax
    js .fail
    mov ebx, eax
    call h2_build_get
    mov edi, ebx
    mov esi, 1                            ; first: send preface + SETTINGS
    mov edx, 1                            ; stream 1
    call h2_exchange                      ; rax = status
    push rax
    mov edi, ebx
    call close_fd
    pop rcx
    mov dil, K_OK
    test rcx, rcx
    jns .report                          ; a real status -> the server answered
    mov dil, K_DEV
.report:
    lea rsi, [n_h2_valid]
    mov edx, n_h2_valid_len
    mov r9d, -1
    call report
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_valid]
    mov edx, n_h2_valid_len
    mov rcx, -1
    mov r9d, -1
    call report
    pop rbx
    ret

; probe_h2_dyn: HPACK dynamic-table indexing — req1 adds :authority to the
; table, req2 references it by dynamic index. OK only if BOTH answer, which
; proves the server decoded the first request into its dynamic table.
probe_h2_dyn:
    push rbx
    push r12
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    call h2_build_dyn1
    mov edi, ebx
    mov esi, 1
    mov edx, 1
    call h2_exchange
    mov r12, rax                          ; status 1
    call h2_build_dyn2
    mov edi, ebx
    xor esi, esi                          ; not first
    mov edx, 3                            ; stream 3
    call h2_exchange
    push rax
    mov edi, ebx
    call close_fd
    pop rcx                               ; status 2
    mov dil, K_DEV
    test r12, r12
    js .report
    test rcx, rcx
    js .report
    mov dil, K_OK
.report:
    lea rsi, [n_h2_dyn]
    mov edx, n_h2_dyn_len
    mov r9d, -1
    call report
    pop r12
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_dyn]
    mov edx, n_h2_dyn_len
    mov rcx, -1
    mov r9d, -1
    call report
    pop r12
    pop rbx
    ret

; probe_h2_nopath: a request with no :path is malformed — the server should
; reject the STREAM (RST_STREAM) or answer 4xx, not serve it.
probe_h2_nopath:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    call h2_build_nopath
    mov edi, ebx
    mov esi, 1
    mov edx, 1
    call h2_exchange                      ; -2 = RST (good), 4xx (good), 2xx (bad)
    push rax
    mov edi, ebx
    call close_fd
    pop rcx
    ; OK unless the malformed request was actually SERVED (a 2xx/3xx status);
    ; RST/GOAWAY/no-response (all negative) and 4xx/5xx are correct rejections.
    mov dil, K_OK
    test rcx, rcx
    js .report                           ; RST/GOAWAY/no response -> rejected
    cmp rcx, 400
    jae .report                          ; 4xx/5xx -> rejected
    mov dil, K_DEV                        ; 2xx/3xx -> served malformed
.report:
    lea rsi, [n_h2_nopath]
    mov edx, n_h2_nopath_len
    mov r9d, -1
    call report
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_nopath]
    mov edx, n_h2_nopath_len
    mov rcx, -1
    mov r9d, -1
    call report
    pop rbx
    ret

; probe_h2_badhpack: an indexed field for a nonexistent dynamic entry is an
; HPACK decode failure — a CONNECTION error (GOAWAY/COMPRESSION_ERROR).
probe_h2_badhpack:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    call h2_build_badhpack
    mov edi, ebx
    mov esi, 1
    mov edx, 1
    call h2_exchange
    push rax
    mov edi, ebx
    call close_fd
    pop rcx
    ; OK if GOAWAY (-3); INFO if RST (-2) or no response; DEV if it served (>=100)
    mov dil, K_OK
    cmp rcx, -3
    je .report
    mov dil, K_INFO
    cmp rcx, -2
    je .report
    test rcx, rcx
    js .report                           ; no response: terse but not "served"
    mov dil, K_DEV                        ; a real status = bad HPACK was accepted
.report:
    lea rsi, [n_h2_badhpack]
    mov edx, n_h2_badhpack_len
    mov r9d, -1
    call report
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_badhpack]
    mov edx, n_h2_badhpack_len
    mov rcx, -1
    mov r9d, -1
    call report
    pop rbx
    ret

; =======================================================================
; HTTP/3 over QUIC (phase 3a: the Initial handshake exchange)
; =======================================================================
QINIT_HDRLEN equ 27                       ; byte0(1)+ver(4)+dcidlen(1)+dcid(8)
                                          ; +scidlen(1)+scid(8)+tok(1)+len(2)+pn(1)
QINIT_PAYLEN equ 1200 - QINIT_HDRLEN - 16 ; CRYPTO + PADDING, leaving room for the tag
QINIT_LENGTH equ 1 + QINIT_PAYLEN + 16    ; pn(1) + payload + tag, the "Length" field

; udp_connect() -> rax = fd or -1. A connected UDP socket to conn_addr:conn_port.
udp_connect:
    push rbx
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET_
    mov esi, SOCK_DGRAM_
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov ebx, eax
    mov word [sa], LINNEA_AF_INET_
    mov eax, [conn_port]
    xchg al, ah
    mov [sa + 2], ax
    mov eax, [conn_addr]
    mov [sa + 4], eax
    xor eax, eax
    mov [sa + 8], rax
    mov eax, LINNEA_SYS_CONNECT
    mov edi, ebx
    lea rsi, [sa]
    mov edx, 16
    syscall
    test rax, rax
    js .fail_close
    mov eax, ebx
    pop rbx
    ret
.fail_close:
    mov eax, LINNEA_SYS_CLOSE
    mov edi, ebx
    syscall
.fail:
    mov rax, -1
    pop rbx
    ret

; tp_int(rdi=cursor, rsi=id, rdx=value) -> rax = new cursor.
; Appends one integer transport parameter: varint(id) varint(len) varint(value).
tp_int:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi                          ; cursor
    mov r12, rsi                          ; id
    mov r13, rdx                          ; value
    lea rdi, [qvtmp]                      ; encode the value to size it
    mov rsi, r13
    call linnea_quic_varint_encode
    mov r14, rax                          ; value length
    mov rdi, rbx                          ; id
    mov rsi, r12
    call linnea_quic_varint_encode
    add rbx, rax
    mov rdi, rbx                          ; len
    mov rsi, r14
    call linnea_quic_varint_encode
    add rbx, rax
    lea rsi, [qvtmp]                      ; value bytes
    mov rdi, rbx
    mov rcx, r14
    rep movsb
    mov rax, rdi
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; quic_build_tp(rdi=out) -> rax = length. Client transport parameters.
quic_build_tp:
    push rbx
    mov rbx, rdi
    mov rdi, rbx
    mov esi, 0x01
    mov edx, 30000
    call tp_int                           ; max_idle_timeout
    mov rdi, rax
    mov esi, 0x03
    mov edx, 1472
    call tp_int                           ; max_udp_payload_size
    mov rdi, rax
    mov esi, 0x04
    mov edx, 1048576
    call tp_int                           ; initial_max_data
    mov rdi, rax
    mov esi, 0x05
    mov edx, 262144
    call tp_int                           ; bidi_local
    mov rdi, rax
    mov esi, 0x06
    mov edx, 262144
    call tp_int                           ; bidi_remote
    mov rdi, rax
    mov esi, 0x07
    mov edx, 262144
    call tp_int                           ; uni
    mov rdi, rax
    mov esi, 0x08
    mov edx, 100
    call tp_int                           ; max_streams_bidi
    mov rdi, rax
    mov esi, 0x09
    mov edx, 100
    call tp_int                           ; max_streams_uni
    mov rdi, rax
    mov esi, 0x0e
    mov edx, 2
    call tp_int                           ; active_connection_id_limit
    ; 0x0f initial_source_connection_id = our SCID (raw)
    mov byte [rax], 0x0f
    mov byte [rax + 1], 8                 ; length
    lea rdi, [rax + 2]
    lea rsi, [q_scid]
    mov ecx, 8
    rep movsb
    mov rax, rdi
    sub rax, rbx
    pop rbx
    ret

; quic_build_ch(rdi=out) -> rax = handshake message length. A bare TLS 1.3
; ClientHello (no record header) carrying quic_transport_parameters and ALPN h3.
quic_build_ch:
    push rbx
    push r12
    push r13
    mov r12, rdi                          ; message start
    mov byte [r12], 0x01                  ; ClientHello
    lea r13, [r12 + 1]                    ; length-24 slot
    lea rdi, [r12 + 4]                    ; body cursor
    mov byte [rdi], 0x03
    mov byte [rdi + 1], 0x03
    add rdi, 2
    lea rsi, [tls_random]
    mov ecx, 32
    rep movsb
    mov byte [rdi], 32
    inc rdi
    lea rsi, [tls_sessid]
    mov ecx, 32
    rep movsb
    lea rsi, [ch_suites]
    mov ecx, ch_suites_len
    rep movsb
    mov rbx, rdi                          ; ext-length-16 slot
    add rdi, 2
    ; SNI
    mov r8, [urlhost_len]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    lea rax, [r8 + 5]
    mov [rdi + 2], ah
    mov [rdi + 3], al
    lea rax, [r8 + 3]
    mov [rdi + 4], ah
    mov [rdi + 5], al
    mov byte [rdi + 6], 0x00
    mov rax, r8
    mov [rdi + 7], ah
    mov [rdi + 8], al
    add rdi, 9
    lea rsi, [urlhost]
    mov rcx, r8
    rep movsb
    ; supported_versions (TLS 1.3)
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x2b
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x03
    mov byte [rdi + 4], 0x02
    mov byte [rdi + 5], 0x03
    mov byte [rdi + 6], 0x04
    add rdi, 7
    ; supported_groups (x25519)
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x0a
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x04
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x02
    mov byte [rdi + 6], 0x00
    mov byte [rdi + 7], 0x1d
    add rdi, 8
    ; signature_algorithms (ecdsa_secp256r1_sha256)
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x0d
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x04
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x02
    mov byte [rdi + 6], 0x04
    mov byte [rdi + 7], 0x03
    add rdi, 8
    ; key_share (x25519)
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x33
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x26
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x24
    mov byte [rdi + 6], 0x00
    mov byte [rdi + 7], 0x1d
    mov byte [rdi + 8], 0x00
    mov byte [rdi + 9], 0x20
    add rdi, 10
    lea rsi, [tls_pub]
    mov ecx, 32
    rep movsb
    ; ALPN (alpn_str/alpn_len = h3)
    mov r8, [alpn_len]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x10
    lea rax, [r8 + 3]
    mov [rdi + 2], ah
    mov [rdi + 3], al
    lea rax, [r8 + 1]
    mov [rdi + 4], ah
    mov [rdi + 5], al
    mov [rdi + 6], r8b
    add rdi, 7
    mov rsi, [alpn_str]
    mov rcx, r8
    rep movsb
    ; quic_transport_parameters (0x0039)
    push rdi
    lea rdi, [qtp]
    call quic_build_tp                    ; rax = tp length
    pop rdi
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x39
    mov rcx, rax                          ; tp length
    mov [rdi + 2], ch
    mov [rdi + 3], cl
    add rdi, 4
    lea rsi, [qtp]
    rep movsb
    ; backpatch extensions length = rdi - (rbx + 2)
    mov rax, rdi
    sub rax, rbx
    sub rax, 2
    mov [rbx], ah
    mov [rbx + 1], al
    ; backpatch handshake body length (24-bit) = rdi - (r13 + 3)
    mov rax, rdi
    sub rax, r13
    sub rax, 3
    mov byte [r13], 0
    mov rcx, rax
    shr rcx, 8
    mov [r13 + 1], cl
    mov [r13 + 2], al
    mov rax, rdi
    sub rax, r12                          ; total handshake message length
    pop r13
    pop r12
    pop rbx
    ret

; quic_send_initial(edi=fd) -> rax = 0 ok / -1. Builds, protects and sends the
; client Initial (ClientHello in a CRYPTO frame, padded to 1200 bytes).
quic_send_initial:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16                          ; force alignment for the SSE crypto
    mov ebx, edi
    ; Initial keys from our chosen DCID
    lea rdi, [q_dcid]
    mov esi, 8
    lea rdx, [qi_ckeys]
    lea rcx, [qi_skeys]
    call linnea_quic_initial_secrets
    ; ClientHello
    lea rdi, [qch]
    call quic_build_ch
    mov [qch_len], rax
    ; payload: CRYPTO frame then PADDING
    lea rdi, [qpay]
    mov byte [rdi], 0x06                  ; CRYPTO
    mov byte [rdi + 1], 0x00              ; offset 0
    add rdi, 2
    mov rsi, [qch_len]
    call linnea_quic_varint_encode        ; length varint
    add rdi, rax
    lea rsi, [qch]
    mov rcx, [qch_len]
    rep movsb                             ; CRYPTO data
    ; PADDING up to QINIT_PAYLEN
    lea rax, [qpay]
    add rax, QINIT_PAYLEN
    sub rax, rdi                          ; bytes of padding
    mov rcx, rax
    xor al, al
    rep stosb
    ; header
    lea rdi, [qhdr]
    mov byte [rdi], 0xc0                  ; long | fixed | Initial | pnlen-1=0
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x00
    mov byte [rdi + 4], 0x01              ; version 1
    mov byte [rdi + 5], 8                 ; DCID length
    lea rax, [rdi + 6]
    lea rsi, [q_dcid]
    mov rdi, rax
    mov ecx, 8
    rep movsb
    mov byte [rdi], 8                     ; SCID length
    inc rdi
    lea rsi, [q_scid]
    mov ecx, 8
    rep movsb
    mov byte [rdi], 0                     ; token length 0
    inc rdi
    mov rsi, QINIT_LENGTH                 ; Length varint
    call linnea_quic_varint_encode
    add rdi, rax
    mov byte [rdi], 0                     ; packet number = 0 (1 byte)
    ; protect
    sub rsp, 16
    lea rax, [qi_ckeys]
    mov [rsp], rax
    mov qword [rsp + 8], 0                ; full packet number
    lea rdi, [qpkt]
    lea rsi, [qhdr]
    mov edx, QINIT_HDRLEN
    mov ecx, 1
    lea r8, [qpay]
    mov r9d, QINIT_PAYLEN
    call linnea_quic_protect              ; rax = total packet length
    add rsp, 16
    mov r12, rax
    ; send
    mov eax, LINNEA_SYS_SENDTO
    mov edi, ebx
    lea rsi, [qpkt]
    mov rdx, r12
    mov r10d, LINNEA_MSG_NOSIGNAL
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    js .fail
    xor eax, eax
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.fail:
    mov rax, -1
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; quic_recv_serverhello(edi=fd) -> rax = 1 if the server's Initial decrypted and
; carried a ServerHello, else 0. Waits up to 3s for the response datagram.
quic_recv_serverhello:
    push rbp
    mov rbp, rsp
    push rbx
    and rsp, -16                          ; force alignment for the SSE crypto
    mov ebx, edi
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 3000
    syscall
    test rax, rax
    jle .no
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .no
    ; unprotect the first (Initial) packet with the server Initial keys
    lea rdi, [qrx]
    mov rsi, rax
    lea rdx, [qi_skeys]
    lea rcx, [qplain]
    call linnea_quic_unprotect            ; rax = frame bytes, rdx = pn
    test rax, rax
    js .no
    ; a CRYPTO frame (the ServerHello) among the frames?
    lea rdi, [qplain]
    mov rsi, rax
    call linnea_quic_crypto_frame         ; rax = SH ptr (0 if none)
    test rax, rax
    jz .no
    mov eax, 1
    lea rsp, [rbp - 8]
    pop rbx
    pop rbp
    ret
.no:
    xor eax, eax
    lea rsp, [rbp - 8]
    pop rbx
    pop rbp
    ret

; h3_battery(): the HTTP/3 probe set (phase 3a: the Initial handshake).
h3_battery:
    call probe_h3_initial
    ret

; probe_h3_initial: send a QUIC Initial and confirm a ServerHello comes back.
probe_h3_initial:
    push rbx
    ; fresh x25519 keypair, client random, session id, DCID and SCID
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_priv]
    mov esi, 32
    xor edx, edx
    syscall
    and byte [tls_priv], 248
    and byte [tls_priv + 31], 127
    or byte [tls_priv + 31], 64
    lea rdi, [tls_pub]
    lea rsi, [tls_priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_random]
    mov esi, 32
    xor edx, edx
    syscall
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_sessid]
    mov esi, 32
    xor edx, edx
    syscall
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [q_dcid]
    mov esi, 8
    xor edx, edx
    syscall
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [q_scid]
    mov esi, 8
    xor edx, edx
    syscall
    call udp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    call quic_send_initial
    test rax, rax
    js .closefail
    mov edi, ebx
    call quic_recv_serverhello            ; rax = 1 on success
    push rax
    mov edi, ebx
    call close_fd
    pop rcx
    mov dil, K_OK
    test rcx, rcx
    jnz .report
    mov dil, K_DEV
.report:
    lea rsi, [n_h3_initial]
    mov edx, n_h3_initial_len
    mov rcx, -1
    mov r9d, -1
    call report_plain
    pop rbx
    ret
.closefail:
    mov edi, ebx
    call close_fd
.fail:
    mov dil, K_DEV
    lea rsi, [n_h3_initial]
    mov edx, n_h3_initial_len
    call report_plain
    pop rbx
    ret

; report_plain(dil=kind, rsi=name, edx=namelen): a report line with no status.
report_plain:
    push rbx
    push r12
    push r13
    movzx ebx, dil
    mov r12, rsi
    mov r13d, edx
    inc dword [n_total]
    cmp ebx, K_DEV
    jne .pfx
    inc dword [n_dev]
.pfx:
    cmp ebx, K_OK
    je .ok
    cmp ebx, K_INFO
    je .info
    lea rsi, [pfx_dev]
    mov edx, pfx_dev_len
    jmp .put
.ok:
    lea rsi, [pfx_ok]
    mov edx, pfx_ok_len
    jmp .put
.info:
    lea rsi, [pfx_info]
    mov edx, pfx_info_len
.put:
    call puts
    mov rsi, r12
    mov edx, r13d
    call puts
    lea rsi, [s_nl]
    mov edx, 1
    call puts
    pop r13
    pop r12
    pop rbx
    ret

; memeq(rsi=a, rdi=b, edx=len) -> rax=1 if the len bytes match
memeq:
    xor eax, eax
    xor ecx, ecx
.l:
    cmp ecx, edx
    jae .yes
    mov r8b, [rsi + rcx]
    cmp r8b, [rdi + rcx]
    jne .no
    inc ecx
    jmp .l
.yes:
    mov eax, 1
.no:
    ret

section .rodata
defslash:  db "/"

section .bss
resp_total: resq 1
parse_off:  resq 1                      ; handshake-message parse cursor
rec_total:  resq 1                      ; length of the last TLS record read
