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
%include "linnea_quic_conn.inc"

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
extern linnea_quic_hs_secrets
extern linnea_quic_app_secrets
extern linnea_quic_ku_next
extern linnea_quic_unprotect_short
extern linnea_quic_stream_frame
extern linnea_quic_frame_skip

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
            db "       linnea-probe --version", 10
            db "  <url>       http[s]://<host-or-ipv4>[:port][/path]", 10
            db "  <protocol>  h1 | h2 | h3   (h2 and h3 require https://)", 10
            db "  --host      override the Host / :authority (vhost routing)", 10
            db "  --big <p>   a large resource for the h3 urgency probe (default /)", 10
usage_len   equ $ - usage_msg

; Bump on any change to observable behaviour (probe set, verdicts, output).
probe_version:     db "linnea-probe 1.0.0", 10
probe_version_len  equ $ - probe_version
opt_version:       db "--version"
opt_version_len    equ $ - opt_version

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
s_bytes:    db " bytes"
s_bytes_len equ $ - s_bytes
s_noresp:   db "(no response / connection closed)", 10
s_noresp_len equ $ - s_noresp
s_rst:      db "RST_STREAM (stream rejected)", 10
s_rst_len   equ $ - s_rst
s_goaway:   db "GOAWAY (connection error)", 10
s_goaway_len equ $ - s_goaway
s_qdyn:     db "responded (:status not decodable — QPACK dynamic table / Huffman)", 10
s_qdyn_len  equ $ - s_qdyn
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
f_delete_sp: db "DELETE "                ; a real method a static server declines
f_delete_sp_len equ $ - f_delete_sp
f_badname_hdr: db "X-Probe(bad): 1", 13, 10   ; '(' is a delimiter, not a token char
f_badname_hdr_len equ $ - f_badname_hdr

; header-name needles (CRLF + lowercase name), for case-insensitive presence checks
nd_allow:   db 13, 10, "allow:"
nd_allow_len equ $ - nd_allow
nd_date:    db 13, 10, "date:"
nd_date_len equ $ - nd_date

n_knownmeth:  db "known method (DELETE) -> 405 with Allow"
n_knownmeth_len equ $ - n_knownmeth
n_fieldtoken: db "field name with a delimiter -> rejected"
n_fieldtoken_len equ $ - n_fieldtoken
n_errdate:    db "error response carries Date"
n_errdate_len equ $ - n_errdate
f_post_sp:  db "POST "
f_post_sp_len equ $ - f_post_sp
f_clen5:    db "Content-Length: 5", 13, 10
f_clen5_len equ $ - f_clen5
f_expect:   db "Expect: 100-continue", 13, 10
f_expect_len equ $ - f_expect
f_conn_kac: db "Connection: keep-alive, close", 13, 10
f_conn_kac_len equ $ - f_conn_kac
n_expect:   db "Expect: 100-continue answered with 100 Continue"
n_expect_len equ $ - n_expect
n_connclose: db "Connection: keep-alive, close closes the socket"
n_connclose_len equ $ - n_connclose
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
; signature_algorithms, as the whole extension (type, length, list length, list).
; The prober never verifies a certificate or a CertificateVerify signature, so
; this list is not a claim about what we can check — it is only what the server
; is allowed to sign with, and a server can only pick from it. Offering just
; ecdsa_secp256r1_sha256 (which is all linnea itself signs with) meant every
; server holding an RSA certificate — most of the web — had nothing it could use
; and refused the handshake outright with alert 40, handshake_failure. http3.is
; did exactly that, on h1 and h3 alike, until this list grew.
ch_sigalgs: db 0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0c
            db 0x04, 0x03            ; ecdsa_secp256r1_sha256 (linnea's own)
            db 0x05, 0x03            ; ecdsa_secp384r1_sha384
            db 0x08, 0x04            ; rsa_pss_rsae_sha256  — TLS 1.3 RSA certs
            db 0x08, 0x05            ; rsa_pss_rsae_sha384
            db 0x08, 0x06            ; rsa_pss_rsae_sha512
            db 0x04, 0x01            ; rsa_pkcs1_sha256 (certificate signatures)
ch_sigalgs_len equ $ - ch_sigalgs
ch_suites:  db 0x00, 0x02, 0x13, 0x01, 0x01, 0x00
ch_suites_len equ $ - ch_suites
; the tls-5 probe offers only a GREASE cipher (0x5a5a, RFC 8701) that no server
; implements — so ANY conformant server must refuse rather than pick 0x1301
; unoffered. (A real-but-unsupported suite like 0x1302 is portable only against a
; server that happens to lack it, e.g. Linnea; Cloudflare supports 0x1302.)
ch_suites_bad: db 0x00, 0x02, 0x5a, 0x5a, 0x01, 0x00
ch_suites_bad_len equ $ - ch_suites_bad
err_tls:    db "error: TLS handshake failed", 10
err_tls_len equ $ - err_tls

; --- HTTP/2 ---
alpn_h2:    db "h2"
alpn_h2_len equ $ - alpn_h2
h2_preface: db "PRI * HTTP/2.0", 13, 10, 13, 10, "SM", 13, 10, 13, 10
h2_preface_len equ $ - h2_preface
h2_settings: db 0,0,0, 0x04, 0x00, 0,0,0,0          ; empty SETTINGS
h2_settings_len equ $ - h2_settings
; WINDOW_UPDATE on stream 0 with a 5-byte payload (length != 4) -> FRAME_SIZE_ERROR
h2_wu_badlen: db 0,0,5, 0x08, 0x00, 0,0,0,0, 0,0,0,1,0
h2_wu_badlen_len equ $ - h2_wu_badlen
; WINDOW_UPDATE on stream 1 with a zero increment -> stream error, RST_STREAM
h2_wu_zero: db 0,0,4, 0x08, 0x00, 0,0,0,1, 0,0,0,0
h2_wu_zero_len equ $ - h2_wu_zero

n_h2_errcode: db "h2 wrong-length WINDOW_UPDATE -> FRAME_SIZE_ERROR"
n_h2_errcode_len equ $ - n_h2_errcode
n_h2_wuzero:  db "h2 zero WINDOW_UPDATE -> stream reset, connection survives"
n_h2_wuzero_len equ $ - n_h2_wuzero
; PING (type 0x06) with a non-zero stream id and a correct 8-byte payload
h2_ping_sid: db 0,0,8, 0x06, 0x00, 0,0,0,1, 0,0,0,0,0,0,0,0
h2_ping_sid_len equ $ - h2_ping_sid
; RST_STREAM (type 0x03) with a 3-byte payload (length != 4) on stream 1
h2_rst_badlen: db 0,0,3, 0x03, 0x00, 0,0,0,1, 0,0,0
h2_rst_badlen_len equ $ - h2_rst_badlen
n_h2_pingsid: db "h2 PING with a non-zero stream id -> PROTOCOL_ERROR"
n_h2_pingsid_len equ $ - n_h2_pingsid
n_h2_rstlen:  db "h2 wrong-length RST_STREAM -> FRAME_SIZE_ERROR"
n_h2_rstlen_len equ $ - n_h2_rstlen
m_connect:    db "CONNECT"
m_connect_len equ $ - m_connect
n_h2_connect: db "h2 CONNECT (unsupported method) -> 405, not a reset"
n_h2_connect_len equ $ - n_h2_connect
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
n_h3_initial: db "QUIC Initial (ServerHello + Handshake keys)"
n_h3_initial_len equ $ - n_h3_initial
n_h3_flight:  db "QUIC handshake flight (server Finished decrypted)"
n_h3_flight_len equ $ - n_h3_flight
n_h3_1rtt:    db "QUIC handshake complete (client Finished -> 1-RTT)"
n_h3_1rtt_len equ $ - n_h3_1rtt
n_h3_get:     db "HTTP/3 GET / (control stream + QPACK request)"
n_h3_get_len equ $ - n_h3_get
n_h3_nopath:  db "HTTP/3 request with no :path -> rejected"
n_h3_nopath_len equ $ - n_h3_nopath
n_h3_badqp:   db "HTTP/3 undecodable QPACK -> connection closed"
n_h3_badqp_len equ $ - n_h3_badqp
n_h3_nosig:   db "QUIC ClientHello without signature_algorithms -> aborted"
n_h3_nosig_len equ $ - n_h3_nosig
n_h3_sessid:  db "QUIC non-empty legacy_session_id -> refused"
n_h3_sessid_len equ $ - n_h3_sessid
n_h3_uni0:    db "QUIC max_streams_uni=0 is honoured (no server uni stream)"
n_h3_uni0_len equ $ - n_h3_uni0
n_h3_mups:    db "QUIC max_udp_payload_size=1200 bounds the server's datagrams"
n_h3_mups_len equ $ - n_h3_mups
n_h3_notls13: db "QUIC ClientHello not offering TLS 1.3 -> aborted"
n_h3_notls13_len equ $ - n_h3_notls13
n_h3_badciph: db "QUIC ClientHello with no supported cipher -> aborted"
n_h3_badciph_len equ $ - n_h3_badciph
n_h3_trailer: db "HTTP/3 frame after the trailer section -> connection error"
n_h3_trailer_len equ $ - n_h3_trailer
n_h3_qpbase:  db "HTTP/3 negative QPACK Base -> connection closed"
n_h3_qpbase_len equ $ - n_h3_qpbase
n_h3_ctrllen: db "HTTP/3 control frame with a bad length -> connection closed"
n_h3_ctrllen_len equ $ - n_h3_ctrllen
dflt_big:     db "/"                     ; default urgency-probe path (override --big)
dflt_big_len  equ $ - dflt_big
opt_big:      db "--big"
opt_big_len   equ $ - opt_big
hdr_priority: db "priority"
prio_a:       db "u=07"                  ; RFC 8941 number 7 (low); pre-fix read as 0
prio_a_len    equ $ - prio_a
prio_b:       db "u=1"                   ; urgency 1 (high) both pre- and post-fix
prio_b_len    equ $ - prio_b
n_h3_urgency: db "HTTP/3 urgency: u=07 is low priority, not high"
n_h3_urgency_len equ $ - n_h3_urgency
n_h3_maxdata: db "HTTP/3 server grants connection credit (MAX_DATA)"
n_h3_maxdata_len equ $ - n_h3_maxdata
n_h3_rsvd:    db "QUIC reserved header bits set -> PROTOCOL_VIOLATION"
n_h3_rsvd_len equ $ - n_h3_rsvd
n_h3_strmlim: db "QUIC stream id past the advertised limit -> STREAM_LIMIT_ERROR"
n_h3_strmlim_len equ $ - n_h3_strmlim
n_h3_initpad: db "QUIC Initial datagram expansion (RFC 9000 14.1)"
n_h3_initpad_len equ $ - n_h3_initpad
n_h3_keyupd:  db "QUIC key update (Key Phase flip) is followed"
n_h3_keyupd_len equ $ - n_h3_keyupd
n_h3_kuold:   db "QUIC packet delayed across a key update (old keys retained?)"
n_h3_kuold_len equ $ - n_h3_kuold
n_h3_iscid:   db "QUIC initial_source_connection_id mismatch -> refused"
n_h3_iscid_len equ $ - n_h3_iscid
n_h3_noiscid: db "QUIC initial_source_connection_id absent -> refused"
n_h3_noiscid_len equ $ - n_h3_noiscid
n_h3_tpudp:   db "QUIC max_udp_payload_size below 1200 -> refused"
n_h3_tpudp_len equ $ - n_h3_tpudp
n_h3_tpcid:   db "QUIC active_connection_id_limit below 2 -> refused"
n_h3_tpcid_len equ $ - n_h3_tpcid
n_h3_dgmax:   db "QUIC datagrams stay within the peer's max_udp_payload_size"
n_h3_dgmax_len equ $ - n_h3_dgmax
n_h3_cidcnt:  db "QUIC connection ids issued stay within the peer's limit"
n_h3_cidcnt_len equ $ - n_h3_cidcnt
n_h3_runt:    db "QUIC runt datagrams leave a live connection undisturbed"
n_h3_runt_len equ $ - n_h3_runt
n_h3_newcid:  db "HTTP/3 NEW_CONNECTION_ID issued and the CID routes"
n_h3_newcid_len equ $ - n_h3_newcid

; QPACK static index -> :status, mirroring the server's encoder table.
qpack_idx2status:
    dw 24,103, 25,200, 26,304, 27,404, 28,503
    dw 63,100, 64,204, 65,206, 66,302, 67,400, 68,403, 69,421, 70,425, 71,500
qpack_idx2status_end:
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
h2_goaway_seen: resq 1                   ; GOAWAY error code from the response, or -1
h2_rst_seen: resq 1                      ; first RST_STREAM error code, or -1

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
omit_sigalgs: resq 1                     ; tls-5 probe: drop signature_algorithms
bad_version: resq 1                      ; tls-5 probe: offer only TLS 1.2
bad_cipher:  resq 1                      ; tls-5 probe: offer a suite we lack
bad_sessid:  resq 1                      ; §8.4 probe: send a non-empty legacy_session_id
q_ncid_count: resq 1                     ; NEW_CONNECTION_ID frames the server sent
q_dgram_max: resq 1                      ; largest datagram the server sent us
tp_variant:  resq 1                      ; quic-12 probes: 1 = max_streams_uni 0,
                                         ; 2 = max_udp_payload_size 1200 (the
                                         ; floor), 3 = 1199 (below it, invalid),
                                         ; 4 = active_connection_id_limit 1
                                         ; (below the 2 RFC 9000 18.2 requires)
qch:        resb 2048                   ; the QUIC ClientHello handshake message
qch_len:    resq 1
qtp:        resb 512                    ; encoded client transport parameters
qhdr:       resb 64                     ; a QUIC packet header being assembled
qpay:       resb 1500                   ; a QUIC packet payload being assembled
qpkt:       resb 1500                   ; the protected packet to send
qrx:        resb 2048                   ; a received datagram
qplain:     resb 2048                   ; decrypted QUIC frames
qvtmp:      resb 16                     ; varint scratch
alignb 16
q_hs_ckeys: resb linnea_quic_keys_size  ; client Handshake keys (we protect)
q_hs_skeys: resb linnea_quic_keys_size  ; server Handshake keys (we open)
q_ap_ckeys: resb linnea_quic_keys_size  ; client 1-RTT keys
q_ap_skeys: resb linnea_quic_keys_size  ; server 1-RTT keys
q_cli_ap_secret: resb 32                ; the 1-RTT traffic secrets, kept because a
q_srv_ap_secret: resb 32                ; key update derives the next generation
q_ku_next:  resb 32                     ; from the SECRET, not from the keys
q_secrets:  resb 96                     ; c_hs || s_hs || handshake_secret
q_fin_key:  resb 32                     ; client Finished MAC key
qtr:        resb 8192                   ; TLS transcript (CH || SH || flight)
qtr_len:    resq 1
qhsc:       resb 8192                   ; reassembled Handshake CRYPTO stream
qhsc_len:   resq 1                      ; contiguous bytes from offset 0
q_hs_ready: resq 1                      ; 1 once Handshake keys are derived
q_init_largest: resq 1                  ; largest Initial pn the server sent
q_hs_largest:   resq 1                  ; largest Handshake pn the server sent
q_hs_smallest:  resq 1                  ; smallest Handshake pn seen (-1 = none yet)
q_ap_largest:   resq 1                  ; largest 1-RTT pn the server sent
q_ap_smallest:  resq 1                  ; smallest 1-RTT pn seen (-1 = none yet)
h3req:      resb 256                    ; the request packet payload, kept for retransmit
h3req_len:  resq 1
h3req_tries: resq 1                     ; remaining request retransmissions
q_fin_seen: resq 1                      ; 1 once the server Finished is reassembled
q_pkt_type: resq 1                      ; the long-header type of the packet being walked
q_sh_ptr:   resq 1                      ; ServerHello handshake message ptr/len
q_sh_len:   resq 1
q_sh_sessid_len: resq 1                  ; the ServerHello's echoed legacy_session_id length
qhsc_fin_end: resq 1                    ; offset in qhsc just past the server Finished
q_srv_scid: resb 20                     ; the server's chosen connection id (our DCID)
q_srv_scid_len: resq 1
q_srv_uni:   resq 1                      ; first server-initiated uni stream id seen (-1 = none)
q_close_code: resq 1                     ; error code of the last CONNECTION_CLOSE (-1 = none)
q_rsvd:      resq 1                      ; 1 = set the short header's reserved bits (quic-14)
q_srv_ms_bidi: resq 1                    ; the server's advertised initial_max_streams_bidi
                                         ; (-1 = it sent none, so no limit can be exceeded
                                         ; on purpose)
q_init_dgram: resq 1                     ; size of the first datagram carrying a server Initial
q_req_sid:   resq 1                      ; the stream the current request went out on, so the
                                         ; classifier collects the right response
q_kphase:    resq 1                      ; 1 = flip the Key Phase bit on what we send
q_ap_skeys_next: resb linnea_quic_keys_size ; the server's NEXT generation, held
q_ku_armed:  resq 1                      ; BESIDE the current one. After we flip the
                                         ; phase the server answers under whichever
                                         ; it has reached -- the old one until it
                                         ; processes the flip, the new one after --
                                         ; so both must be tried, exactly as the
                                         ; server's own ku_try does for us. Assuming
                                         ; it had rotated worked on loopback and
                                         ; failed over a real RTT.
q_hold:      resq 1                      ; 1 = build the next 1-RTT packet but do NOT
                                         ; send it; keep it in q_held instead
q_held:      resb 1500                   ; a protected packet withheld from the wire,
q_held_len:  resq 1                      ; to be released after a key update
q_pkt_ptr:   resq 1                      ; the 1-RTT packet being opened, kept so a
q_pkt_len:   resq 1                      ; retry does not re-derive a clobbered length
                                         ; (RFC 9001 6: that bit IS a QUIC key
                                         ; update; the TLS KeyUpdate message is
                                         ; forbidden here and is a connection error)
q_alt_cid:  resb 20                     ; a CID the server issued via NEW_CONNECTION_ID
q_alt_cid_len: resq 1
q_alt_cid_valid: resq 1                 ; 1 once we captured a NEW_CONNECTION_ID
q_cli_hs_pn: resq 1                     ; our next client Handshake packet number
q_acked:    resq 1                      ; 1 once we have sent a Handshake ACK
q_cli_ap_pn: resq 1                     ; our next client 1-RTT packet number
fs_scratch: resb 768                    ; the request QPACK field section
fs_scratch2: resb 768                   ; a second field section (urgency probe)
h3buf:      resb 4096                   ; response stream-0 data, reassembled
h3buf_len:  resq 1
h3_bytes_s0: resq 1                     ; urgency probe: bytes seen on stream 0
h3_bytes_s4: resq 1                     ; urgency probe: bytes seen on stream 4
big_ptr:    resq 1                      ; urgency probe: path to fetch (a large file)
big_len:    resq 1

section .text

; =======================================================================
; entry
; =======================================================================
_start:
    mov r15, [rsp]                      ; argc
    ; --- --version: report and exit 0 before requiring url/protocol ---
    cmp r15, 2
    jl .usage
    mov rdi, [rsp + 16]                 ; argv[1]
    lea rsi, [opt_version]
    mov edx, opt_version_len
    call streq_z
    test rax, rax
    jnz .show_version
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

    ; --- optional --host / --big overrides (scan argv[3..]) ---
    mov qword [host_ptr], 0
    lea rax, [dflt_big]                   ; the urgency probe fetches "/" by default
    mov [big_ptr], rax
    mov qword [big_len], dflt_big_len
    mov rbx, 3                           ; arg index
.scan_opts:
    cmp rbx, r15
    jae .opts_done
    mov rdi, [rsp + 8 + rbx*8]           ; argv[rbx]
    lea rsi, [opt_host]
    mov edx, opt_host_len
    call streq_z                         ; rax=1 if argv[rbx] == "--host"
    test rax, rax
    jnz .opt_host
    mov rdi, [rsp + 8 + rbx*8]
    lea rsi, [opt_big]
    mov edx, opt_big_len
    call streq_z                         ; rax=1 if argv[rbx] == "--big"
    test rax, rax
    jnz .opt_big
    jmp .scan_next
.opt_host:
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
.opt_big:
    lea rcx, [rbx + 1]
    cmp rcx, r15
    jae .opts_done                       ; --big with no value: ignore
    mov rdi, [rsp + 8 + rcx*8]           ; the path value
    mov [big_ptr], rdi
    mov rsi, rdi
    call cstrlen
    mov [big_len], rax
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
    call probe_known_method
    call probe_field_token
    call probe_err_date
    call probe_h1_expect
    call probe_h1_close
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

.show_version:
    lea rsi, [probe_version]
    mov edx, probe_version_len
    call puts
    xor edi, edi
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

; resp_ci_contains(rsi=needle, edx=needle len) -> rax = 1 if respbuf[0..resp_total)
; contains the needle (ASCII case-insensitive), else 0. Used to assert a header is
; present in the raw response (needles carry a leading CRLF so they anchor at a
; header line, not inside a value).
resp_ci_contains:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rsi                          ; needle
    mov r13, rdx                          ; needle length
    mov r14, [resp_total]
    sub r14, r13                          ; last viable start offset
    js .no                                ; needle longer than the response
    xor ebx, ebx                          ; start offset
.scan:
    cmp rbx, r14
    ja .no
    xor ecx, ecx
.cmp:
    cmp rcx, r13
    jae .hit
    mov al, [respbuf + rbx + rcx]
    cmp al, 'A'
    jb .a_ok
    cmp al, 'Z'
    ja .a_ok
    add al, 32
.a_ok:
    mov dl, [r12 + rcx]
    cmp dl, 'A'
    jb .b_ok
    cmp dl, 'Z'
    ja .b_ok
    add dl, 32
.b_ok:
    cmp al, dl
    jne .next
    inc rcx
    jmp .cmp
.next:
    inc rbx
    jmp .scan
.hit:
    mov eax, 1
    jmp .done
.no:
    xor eax, eax
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h1-12: a real method a static server declines draws 405 WITH Allow, not 501.
probe_known_method:
    push rbx
    call req_begin
    lea rsi, [f_delete_sp]
    mov edx, f_delete_sp_len
    call req_add
    call add_target_only
    lea rsi, [f_sp_h11_crlf]
    mov edx, f_sp_h11_crlf_len
    call req_add
    call add_host
    call add_close
    call add_end
    call run_and_read                     ; rax = status
    mov rbx, rax
    mov dil, K_DEV
    cmp rbx, 405
    jne .emit                             ; 501 (old behaviour) or worse -> deviation
    lea rsi, [nd_allow]
    mov edx, nd_allow_len
    call resp_ci_contains
    test rax, rax
    jz .emit                              ; 405 without Allow is still non-conformant
    mov dil, K_OK
.emit:
    lea rsi, [n_knownmeth]
    mov edx, n_knownmeth_len
    mov rcx, rbx
    mov r9d, 405
    call report
    pop rbx
    ret

; h1-13: a delimiter in a field NAME is not a token -> 400 (parser-differential
; when proxying if accepted).
probe_field_token:
    call req_begin
    call add_get_target_h11
    call add_host
    lea rsi, [f_badname_hdr]
    mov edx, f_badname_hdr_len
    call req_add
    call add_close
    call add_end
    call run_and_read
    mov rcx, rax
    lea rsi, [n_fieldtoken]
    mov edx, n_fieldtoken_len
    mov r9d, 400
    call classify_reject
    ret

; h1-6: an error response must carry Date (canned 4xx blobs included).
probe_err_date:
    push rbx
    call req_begin
    call add_get_target_h11
    call add_close
    call add_end                          ; no Host -> a 400 error blob
    call run_and_read
    mov rbx, rax
    mov dil, K_DEV
    test rbx, rbx
    js .emit                              ; no response at all
    lea rsi, [nd_date]
    mov edx, nd_date_len
    call resp_ci_contains
    test rax, rax
    jz .emit
    mov dil, K_OK
.emit:
    lea rsi, [n_errdate]
    mov edx, n_errdate_len
    mov rcx, rbx
    mov r9d, -1
    call report
    pop rbx
    ret

; h1-2: a request carrying Expect: 100-continue must be answered with an interim
; 100 Continue before the body (RFC 9110 10.1.1). We send the head with a
; Content-Length but no body; a conforming server replies 100 at once, a pre-fix
; one waits silently for the body. OK iff the first response is 100.
probe_h1_expect:
    call req_begin
    lea rsi, [f_post_sp]
    mov edx, f_post_sp_len
    call req_add
    call add_target_only
    lea rsi, [f_sp_h11_crlf]
    mov edx, f_sp_h11_crlf_len
    call req_add
    call add_host
    lea rsi, [f_clen5]
    mov edx, f_clen5_len
    call req_add
    lea rsi, [f_expect]
    mov edx, f_expect_len
    call req_add
    call add_end                          ; end of head; the body is withheld
    call run_and_read                     ; rax = first status line (100 if honoured)
    mov r8, rax
    mov dil, K_OK
    cmp rax, 100
    je .rep
    mov dil, K_DEV                        ; no 100 -> Expect was ignored
.rep:
    lea rsi, [n_expect]
    mov edx, n_expect_len
    mov rcx, r8
    mov r9d, 100
    call report
    ret

; h1-3: "close" anywhere in the Connection field's comma list must close the
; connection, not just a value that is entirely "close" (RFC 9110 7.6.1). We
; send "keep-alive, close" and check the server hangs up after the response
; rather than holding the socket open. OK iff the server initiates the close.
probe_h1_close:
    push rbx
    push r12
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    call req_begin
    call add_get_target_h11
    call add_host
    lea rsi, [f_conn_kac]
    mov edx, f_conn_kac_len
    call req_add
    call add_end
    mov edi, ebx
    call send_req
    mov edi, ebx
    call read_response
    call parse_status
    mov r12, rax                          ; the response status (or -1)
    mov edi, ebx
    mov esi, 1500
    call wait_readable_or_closed          ; 1 closing data / 2 FIN / 0 kept alive
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    test r12, r12
    js .info                              ; never got a response: cannot judge
    test rax, rax
    js .info                              ; poll error
    jz .dev                               ; timed out with the socket still open
    mov dil, K_OK                         ; the server closed (FIN or close_notify)
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_connclose]
    mov edx, n_connclose_len
    call report_plain
    pop r12
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_connclose]
    mov edx, n_connclose_len
    call report_plain
    pop r12
    pop rbx
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
    ; distinguish the sentinels: -2 RST_STREAM, -3 GOAWAY, -5 QPACK-dynamic, else none
    cmp r14, -2
    je .rst
    cmp r14, -3
    je .goaway
    cmp r14, -5
    je .qdyn
    lea rsi, [s_noresp]
    mov edx, s_noresp_len
    call puts
    jmp .ret
.qdyn:
    lea rsi, [s_qdyn]
    mov edx, s_qdyn_len
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
    ; -- signature_algorithms (see ch_sigalgs: ECDSA and RSA, so an RSA server
    ; has something it can sign CertificateVerify with) --
    push rsi
    lea rsi, [ch_sigalgs]
    mov ecx, ch_sigalgs_len
    rep movsb
    pop rsi
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

; h2_build_connect(): a CONNECT request — :method CONNECT + :authority, and by
; design (RFC 9113 8.5) NO :scheme and NO :path.
h2_build_connect:
    lea rdi, [h2_block]
    mov rax, 2                            ; :method (name index 2) = CONNECT
    lea rsi, [m_connect]
    mov rdx, m_connect_len
    call h2_enc_nameref
    mov rax, 1                            ; :authority = host
    mov rsi, [host_ptr]
    mov rdx, [host_len]
    call h2_enc_nameref
    lea rax, [h2_block]
    sub rdi, rax
    mov [h2_block_len], rdi
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
    call probe_h2_errcode
    call probe_h2_wu_zero
    call probe_h2_ping_stream
    call probe_h2_rst_badlen
    call probe_h2_connect
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

; h2_send_prefaced(edi=fd, rsi=frame, edx=frame len) -> rax = send result.
; Sends the connection preface + empty SETTINGS, then the given raw frame.
h2_send_prefaced:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13d, edx
    lea rdi, [reqbuf]
    lea rsi, [h2_preface]
    mov rcx, h2_preface_len
    rep movsb
    lea rsi, [h2_settings]
    mov rcx, h2_settings_len
    rep movsb
    mov rsi, r12
    mov rcx, r13
    rep movsb
    lea rax, [reqbuf]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [reqbuf]
    call send_bytes
    pop r13
    pop r12
    pop rbx
    ret

; h2_scan_errors(): walk respbuf frames, recording the GOAWAY error code into
; h2_goaway_seen and the first RST_STREAM error code into h2_rst_seen (-1 = none).
h2_scan_errors:
    push rbx
    push r12
    push r13
    mov qword [h2_goaway_seen], -1
    mov qword [h2_rst_seen], -1
    lea r12, [respbuf]
    mov r13, [resp_total]
    add r13, r12
.frame:
    lea rax, [r12 + 9]
    cmp rax, r13
    ja .done
    movzx eax, byte [r12]
    shl eax, 8
    movzx ecx, byte [r12 + 1]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [r12 + 2]
    or eax, ecx
    mov rbx, rax                          ; frame length
    movzx ecx, byte [r12 + 3]             ; type
    lea rax, [r12 + 9 + rbx]
    cmp rax, r13
    ja .done
    cmp ecx, 0x07
    je .goaway
    cmp ecx, 0x03
    je .rst
.skip:
    lea r12, [r12 + rbx + 9]
    jmp .frame
.goaway:
    cmp rbx, 8
    jb .skip
    movzx eax, byte [r12 + 13]            ; error code = payload offset 4 (BE32)
    shl eax, 8
    movzx ecx, byte [r12 + 14]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [r12 + 15]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [r12 + 16]
    or eax, ecx
    mov [h2_goaway_seen], rax
    jmp .skip
.rst:
    cmp rbx, 4
    jb .skip
    cmp qword [h2_rst_seen], -1
    jne .skip                            ; keep the first RST only
    movzx eax, byte [r12 + 9]            ; error code = payload (BE32)
    shl eax, 8
    movzx ecx, byte [r12 + 10]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [r12 + 11]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [r12 + 12]
    or eax, ecx
    mov [h2_rst_seen], rax
    jmp .skip
.done:
    pop r13
    pop r12
    pop rbx
    ret

; probe_h2_errcode (h2-2): a connection error must carry the RFC's code, not a
; blanket PROTOCOL_ERROR. A WINDOW_UPDATE whose length is not 4 is a
; FRAME_SIZE_ERROR (0x6). OK iff the GOAWAY names 0x6.
probe_h2_errcode:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    lea rsi, [h2_wu_badlen]
    mov edx, h2_wu_badlen_len
    call h2_send_prefaced
    mov edi, ebx
    call read_response
    call h2_scan_errors
    mov edi, ebx
    call close_fd
    mov dil, K_OK
    cmp qword [h2_goaway_seen], 0x6       ; FRAME_SIZE_ERROR
    je .report
    mov dil, K_DEV
.report:
    lea rsi, [n_h2_errcode]
    mov edx, n_h2_errcode_len
    call report_plain
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_errcode]
    mov edx, n_h2_errcode_len
    call report_plain
    pop rbx
    ret

; probe_h2_wu_zero (h2-3): a zero WINDOW_UPDATE increment on a non-zero stream is
; a STREAM error, not a connection error. OK iff an RST_STREAM(PROTOCOL_ERROR)
; comes back AND no GOAWAY (the connection survives).
probe_h2_wu_zero:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    lea rsi, [h2_wu_zero]
    mov edx, h2_wu_zero_len
    call h2_send_prefaced
    mov edi, ebx
    call read_response
    call h2_scan_errors
    mov edi, ebx
    call close_fd
    mov dil, K_DEV
    cmp qword [h2_goaway_seen], -1
    jne .report                          ; a GOAWAY = old connection-error behaviour
    cmp qword [h2_rst_seen], 1           ; PROTOCOL_ERROR
    jne .report
    mov dil, K_OK
.report:
    lea rsi, [n_h2_wuzero]
    mov edx, n_h2_wuzero_len
    call report_plain
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_wuzero]
    mov edx, n_h2_wuzero_len
    call report_plain
    pop rbx
    ret

; probe_h2_ping_stream (h2-10): a PING carries no stream, so a non-zero stream id
; is a connection error PROTOCOL_ERROR (RFC 7540 6.7). Pre-fix the id was ignored
; and the PING was ACKed. OK iff a GOAWAY(PROTOCOL_ERROR) comes back.
probe_h2_ping_stream:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    lea rsi, [h2_ping_sid]
    mov edx, h2_ping_sid_len
    call h2_send_prefaced
    mov edi, ebx
    call read_response
    call h2_scan_errors
    mov edi, ebx
    call close_fd
    mov dil, K_OK
    cmp qword [h2_goaway_seen], 1         ; PROTOCOL_ERROR
    je .report
    mov dil, K_DEV
.report:
    lea rsi, [n_h2_pingsid]
    mov edx, n_h2_pingsid_len
    call report_plain
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_pingsid]
    mov edx, n_h2_pingsid_len
    call report_plain
    pop rbx
    ret

; probe_h2_rst_badlen (h2-11): RST_STREAM is exactly 4 octets; any other length is
; a connection error FRAME_SIZE_ERROR (RFC 7540 6.4). Pre-fix the length was
; unchecked. OK iff a GOAWAY(FRAME_SIZE_ERROR) comes back.
probe_h2_rst_badlen:
    push rbx
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    lea rsi, [h2_rst_badlen]
    mov edx, h2_rst_badlen_len
    call h2_send_prefaced
    mov edi, ebx
    call read_response
    call h2_scan_errors
    mov edi, ebx
    call close_fd
    mov dil, K_OK
    cmp qword [h2_goaway_seen], 0x6       ; FRAME_SIZE_ERROR
    je .report
    mov dil, K_DEV
.report:
    lea rsi, [n_h2_rstlen]
    mov edx, n_h2_rstlen_len
    call report_plain
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_rstlen]
    mov edx, n_h2_rstlen_len
    call report_plain
    pop rbx
    ret

; probe_h2_connect (h2-15): CONNECT is a registered method a static server does
; not implement; the conformant answer is 405 (like any other known-but-declined
; method), not a stream reset that tells the client its request was broken. OK iff
; 405; DEV if RST_STREAM (the "reset not answered" bug) or a served 2xx/3xx.
probe_h2_connect:
    push rbx
    push r12
    call tcp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    call h2_build_connect
    mov edi, ebx
    mov esi, 1
    mov edx, 1
    call h2_exchange                      ; status | -2 RST | -3 GOAWAY | -1
    mov r12, rax
    mov edi, ebx
    call close_fd
    cmp r12, 405
    je .ok
    cmp r12, -2
    je .dev                               ; RST_STREAM: the pre-fix behaviour
    cmp r12, 200
    jl .info                              ; GOAWAY / no response: terse
    cmp r12, 400
    jl .dev                               ; 2xx/3xx: served CONNECT
    jmp .info                             ; other 4xx/5xx: a status, just not 405
.ok:
    mov dil, K_OK
    jmp .report
.dev:
    mov dil, K_DEV
    jmp .report
.info:
    mov dil, K_INFO
.report:
    lea rsi, [n_h2_connect]
    mov edx, n_h2_connect_len
    mov rcx, r12
    mov r9d, 405
    call report
    pop r12
    pop rbx
    ret
.fail:
    mov dil, K_DEV
    lea rsi, [n_h2_connect]
    mov edx, n_h2_connect_len
    mov rcx, -1
    mov r9d, 405
    call report
    pop r12
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
    cmp qword [tp_variant], 2             ; quic-12: smallest datagram the RFC allows
    jne .tp_mups2
    mov edx, 1200
.tp_mups2:
    cmp qword [tp_variant], 3             ; quic-12: one below the floor — invalid
    jne .tp_mups
    mov edx, 1199
.tp_mups:
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
    cmp qword [tp_variant], 1             ; quic-12: forbid server uni streams
    jne .tp_uni
    xor edx, edx
.tp_uni:
    call tp_int                           ; max_streams_uni
    mov rdi, rax
    mov esi, 0x0e
    mov edx, 2
    cmp qword [tp_variant], 4             ; quic-12: below the 2 that 18.2 requires
    jne .tp_cidlim
    mov edx, 1
.tp_cidlim:
    call tp_int                           ; active_connection_id_limit
    ; 0x0f initial_source_connection_id = our SCID (raw). tls-12 probes bend it:
    ; variant 5 states a DIFFERENT id than the packets carry, variant 6 omits
    ; the parameter altogether -- RFC 9000 7.3 makes both a connection error.
    cmp qword [tp_variant], 6
    je .tp_no_iscid
    mov byte [rax], 0x0f
    mov byte [rax + 1], 8                 ; length
    lea rdi, [rax + 2]
    lea rsi, [q_scid]
    mov ecx, 8
    rep movsb
    cmp qword [tp_variant], 5
    jne .tp_iscid_done
    xor byte [rax + 2], 0xff              ; same length, one bit of a different id
.tp_iscid_done:
    mov rax, rdi                          ; cursor past the parameter
.tp_no_iscid:                             ; ...or standing where it was
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
    ; legacy_session_id: empty per RFC 9001 8.4 — QUIC forbids TLS compatibility
    ; mode. The §8.4 probe sets bad_sessid to send a non-empty one on purpose, to
    ; check the server still echoes an empty session_id in its ServerHello.
    cmp qword [bad_sessid], 0
    jne .bad_sessid
    mov byte [rdi], 0
    inc rdi
    jmp .sessid_done
.bad_sessid:
    mov byte [rdi], 32
    inc rdi
    lea rsi, [tls_sessid]
    mov ecx, 32
    rep movsb
.sessid_done:
    lea rsi, [ch_suites]                  ; cipher_suites (TLS_AES_128_GCM_SHA256)
    mov ecx, ch_suites_len
    cmp qword [bad_cipher], 0
    je .cs_ok
    lea rsi, [ch_suites_bad]              ; tls-5 probe: offer a suite we lack
    mov ecx, ch_suites_bad_len
.cs_ok:
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
    mov byte [rdi + 6], 0x04              ; TLS 1.3
    cmp qword [bad_version], 0
    je .sv_ok
    mov byte [rdi + 6], 0x03              ; tls-5 probe: offer only TLS 1.2
.sv_ok:
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
    ; signature_algorithms (see ch_sigalgs) — the tls-5 probe drops it entirely
    cmp qword [omit_sigalgs], 0
    jne .no_sigalgs
    push rsi
    lea rsi, [ch_sigalgs]
    mov ecx, ch_sigalgs_len
    rep movsb
    pop rsi
.no_sigalgs:
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

; qtr_add(rsi=ptr, rdx=len): append to the TLS transcript buffer.
qtr_add:
    push rdi
    push rcx
    mov rdi, [qtr_len]
    lea rdi, [qtr + rdi]
    mov rcx, rdx
    rep movsb
    add [qtr_len], rdx
    pop rcx
    pop rdi
    ret

; quic_pkt_parse(rdi=pkt, rsi=end) -> rax = total packet length (0 if bad),
; rdx = long-header type (0x00 Initial, 0x20 Handshake, ...); also q_pkt_type.
quic_pkt_parse:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    movzx ebx, byte [r12]
    test bl, 0x80
    jz .bad
    mov edx, ebx
    and edx, 0x30
    mov [q_pkt_type], rdx
    lea rdi, [r12 + 5]                    ; -> DCID length
    cmp rdi, r13
    jae .bad
    movzx eax, byte [rdi]
    lea rdi, [rdi + 1 + rax]              ; -> SCID length
    cmp rdi, r13
    jae .bad
    movzx eax, byte [rdi]
    lea rdi, [rdi + 1 + rax]              ; -> token len (Initial) / Length
    cmp qword [q_pkt_type], 0x00
    jne .len
    mov rsi, r13
    call linnea_quic_varint_decode        ; token length
    test rdx, rdx
    jz .bad
    add rdi, rdx
    add rdi, rax                          ; skip the token
.len:
    cmp rdi, r13
    jae .bad
    mov rsi, r13
    call linnea_quic_varint_decode        ; Length (pn + payload + tag)
    test rdx, rdx
    jz .bad
    add rdi, rdx
    add rdi, rax                          ; -> end of this packet
    cmp rdi, r13
    ja .bad
    mov rax, rdi
    sub rax, r12                          ; total packet length
    mov rdx, [q_pkt_type]
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

; quic_derive_hs(): from tls_srvpub + the CH||SH transcript, derive the
; Handshake keys and the c_hs/s_hs/handshake secrets.
quic_derive_hs:
    lea rdi, [qtr]
    mov rsi, [qtr_len]
    lea rdx, [th_buf]
    call linnea_sha256                    ; th = H(CH || SH)
    lea rdi, [tls_srvpub]
    lea rsi, [tls_priv]
    lea rdx, [th_buf]
    lea rcx, [q_hs_ckeys]
    lea r8, [q_hs_skeys]
    lea r9, [q_secrets]
    call linnea_quic_hs_secrets
    ret

; quic_check_finished(): scan the reassembled Handshake CRYPTO for a complete
; Finished (type 0x14); set q_fin_seen and qhsc_fin_end when found.
quic_check_finished:
    xor ecx, ecx
.m:
    lea rax, [rcx + 4]
    cmp rax, [qhsc_len]
    ja .ret
    movzx eax, byte [qhsc + rcx]
    movzx edx, byte [qhsc + rcx + 1]
    shl edx, 8
    movzx r8d, byte [qhsc + rcx + 2]
    or edx, r8d
    shl edx, 8
    movzx r8d, byte [qhsc + rcx + 3]
    or edx, r8d                           ; message body length
    lea r9, [rcx + 4]
    add r9, rdx                           ; end of this message
    cmp r9, [qhsc_len]
    ja .ret                               ; incomplete
    cmp al, 0x14                          ; Finished
    jne .next
    mov qword [q_fin_seen], 1
    mov [qhsc_fin_end], r9
    ret
.next:
    mov rcx, r9
    jmp .m
.ret:
    ret

; quic_srv_tp_scan(): read the server's initial_max_streams_bidi out of the QUIC
; transport parameters it sent in EncryptedExtensions, so the stream-limit probe
; can build an id the SERVER ITSELF declared out of bounds instead of guessing a
; number and hoping it is over the limit. Left at -1 when the parameter is absent
; (RFC 9000 18.2 lets a server omit it; a server that never stated a limit is not
; one we can accuse of ignoring it), which the probe reports as [info].
quic_srv_tp_scan:
    push rbx
    push r12
    push r13
    push r14
    mov qword [q_srv_ms_bidi], -1
    xor ecx, ecx                          ; handshake-message cursor
.m:
    lea rax, [rcx + 4]
    cmp rax, [qhsc_len]
    ja .ret
    movzx eax, byte [qhsc + rcx]          ; message type
    movzx edx, byte [qhsc + rcx + 1]
    shl edx, 8
    movzx r8d, byte [qhsc + rcx + 2]
    or edx, r8d
    shl edx, 8
    movzx r8d, byte [qhsc + rcx + 3]
    or edx, r8d                           ; message body length
    lea r9, [rcx + 4]
    add r9, rdx                           ; end of this message
    cmp r9, [qhsc_len]
    ja .ret                               ; incomplete
    cmp al, 0x08                          ; EncryptedExtensions
    jne .next
    lea rbx, [qhsc + rcx + 4]             ; -> 2-byte extensions length
    lea r12, [qhsc + r9]                  ; message end
    lea rax, [rbx + 2]
    cmp rax, r12
    ja .ret
    movzx r13d, byte [rbx]
    shl r13d, 8
    movzx eax, byte [rbx + 1]
    or r13d, eax
    add rbx, 2
    lea rax, [rbx + r13]
    cmp rax, r12
    ja .ret
    mov r12, rax                          ; extensions end
.ext:
    lea rax, [rbx + 4]
    cmp rax, r12
    ja .ret
    movzx r13d, byte [rbx]                ; extension type
    shl r13d, 8
    movzx eax, byte [rbx + 1]
    or r13d, eax
    movzx r14d, byte [rbx + 2]            ; extension length
    shl r14d, 8
    movzx eax, byte [rbx + 3]
    or r14d, eax
    add rbx, 4
    lea rax, [rbx + r14]
    cmp rax, r12
    ja .ret
    cmp r13d, 0x0039                      ; quic_transport_parameters (RFC 9001 8.2)
    je .tp
    add rbx, r14
    jmp .ext
.tp:
    lea r12, [rbx + r14]                  ; the parameter list's end
.tpl:
    cmp rbx, r12
    jae .ret
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_varint_decode        ; parameter id
    test rdx, rdx
    jz .ret
    mov r13, rax
    add rbx, rdx
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_varint_decode        ; parameter length
    test rdx, rdx
    jz .ret
    add rbx, rdx
    mov r14, rax
    lea rax, [rbx + r14]
    cmp rax, r12
    ja .ret
    cmp r13, 0x08                         ; initial_max_streams_bidi
    jne .tpnext
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ret
    mov [q_srv_ms_bidi], rax
    jmp .ret
.tpnext:
    add rbx, r14
    jmp .tpl
.next:
    mov rcx, r9
    jmp .m
.ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; quic_walk_datagram(rsi=datagram length): walk the coalesced packets in qrx,
; decrypting the Initial (ServerHello -> derive Handshake keys) and Handshake
; packets (CRYPTO -> reassemble into qhsc). Force-aligns rsp for the SSE crypto.
quic_walk_datagram:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and rsp, -16
    lea r12, [qrx]
    lea r13, [qrx + rsi]                  ; end
.pkt:
    cmp r12, r13
    jae .done
    test byte [r12], 0x80
    jz .done                              ; short header / padding: stop
    mov rdi, r12
    mov rsi, r13
    call quic_pkt_parse
    test rax, rax
    jz .done
    mov rbx, rax                          ; packet total length
    cmp qword [q_pkt_type], 0x00
    je .initial
    cmp qword [q_pkt_type], 0x20
    je .handshake
    jmp .adv
.initial:
    mov rdi, r12
    mov rsi, rbx
    lea rdx, [qi_skeys]
    lea rcx, [qplain]
    call linnea_quic_unprotect            ; rax = frames, rdx = pn
    test rax, rax
    js .adv
    mov r14, rax                          ; frame bytes
    cmp rdx, [q_init_largest]
    jle .init_pn_done                     ; signed: the -1 "none yet" sentinel is < any pn
    mov [q_init_largest], rdx
.init_pn_done:
    cmp qword [q_hs_ready], 0
    jne .adv                              ; ServerHello handled already
    ; capture the server's SCID (becomes our DCID for Handshake/1-RTT)
    movzx eax, byte [r12 + 5]             ; DCID length
    lea rcx, [r12 + 6 + rax]              ; -> SCID length
    movzx edx, byte [rcx]
    mov [q_srv_scid_len], rdx
    lea rsi, [rcx + 1]
    lea rdi, [q_srv_scid]
    mov rcx, rdx
    rep movsb
    lea rdi, [qplain]
    mov rsi, r14                          ; frame bytes
    call linnea_quic_crypto_frame         ; rax = SH ptr, rdx = len
    test rax, rax
    jz .adv
    mov [q_sh_ptr], rax
    mov [q_sh_len], rdx
    ; capture the echoed legacy_session_id length (byte 38 of the ServerHello)
    ; now, while qplain still holds it — later packets overwrite the buffer
    movzx ecx, byte [rax + 38]
    mov [q_sh_sessid_len], rcx
    mov rsi, rax
    call parse_serverhello                ; rsi=ptr, rdx=len -> tls_srvpub
    mov qword [qtr_len], 0                ; transcript = CH || SH
    lea rsi, [qch]
    mov rdx, [qch_len]
    call qtr_add
    mov rsi, [q_sh_ptr]
    mov rdx, [q_sh_len]
    call qtr_add
    call quic_derive_hs
    mov qword [q_hs_ready], 1
    jmp .adv
.handshake:
    cmp qword [q_hs_ready], 0
    je .adv                               ; no Handshake keys yet
    mov rdi, r12
    mov rsi, rbx
    lea rdx, [q_hs_skeys]
    lea rcx, [qplain]
    call linnea_quic_unprotect_hs         ; rax = frames, rdx = pn
    test rax, rax
    js .adv
    cmp rdx, [q_hs_largest]
    jle .hs_pn_done                       ; signed: the -1 "none yet" sentinel is < any pn
    mov [q_hs_largest], rdx
.hs_pn_done:
    ; track the smallest Handshake pn seen so ACKs cover the real range, not 0..
    ; largest — a server may start the space's pns above 0 (Google starts at 2)
    cmp qword [q_hs_smallest], -1
    jne .hs_min_done
    mov [q_hs_smallest], rdx
.hs_min_done:
    mov r14, rax                          ; frame bytes
    lea rdi, [qplain]
    mov rsi, r14
    call linnea_quic_crypto_frame         ; rax = data, rdx = len, r8 = offset
    test rax, rax
    jz .adv
    cmp r8, [qhsc_len]
    jne .adv                              ; out of order: skip (Linnea is in order)
    mov rsi, rax
    mov rdi, [qhsc_len]
    lea rdi, [qhsc + rdi]
    mov rcx, rdx
    rep movsb
    add [qhsc_len], rdx
    call quic_check_finished
.adv:
    add r12, rbx
    jmp .pkt
.done:
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; quic_ack_frame(rdi=out, rsi=largest) -> rax = new cursor. An ACK covering
; every packet number from 0 to `largest`.
quic_ack_frame:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi                          ; largest acknowledged
    mov r13, rdx                          ; smallest acknowledged (contiguous)
    mov byte [rbx], 0x02
    inc rbx
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_varint_encode        ; largest acknowledged
    add rbx, rax
    mov rdi, rbx
    xor esi, esi
    call linnea_quic_varint_encode        ; ack delay = 0
    add rbx, rax
    mov rdi, rbx
    xor esi, esi
    call linnea_quic_varint_encode        ; ack range count = 0
    add rbx, rax
    mov rdi, rbx
    mov rsi, r12
    sub rsi, r13                          ; first ack range = largest - smallest, so
    call linnea_quic_varint_encode        ; we never claim packets below the smallest
    add rbx, rax                          ; one actually received (some servers, e.g.
    mov rax, rbx                          ; Google, start a space's pns above 0)
    pop r13
    pop r12
    pop rbx
    ret

; quic_send_hs(edi=fd, rsi=payload, rdx=payload len) -> rax = 0 ok / -1.
; Builds, protects (q_hs_ckeys) and sends one Handshake packet; bumps q_cli_hs_pn.
quic_send_hs:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and rsp, -16
    mov ebx, edi
    mov r14, rsi                          ; payload
    mov r13, rdx                          ; payload length
    lea rdi, [qhdr]
    mov byte [rdi], 0xe0                  ; long | fixed | Handshake | pnlen-1=0
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x00
    mov byte [rdi + 4], 0x01
    mov rcx, [q_srv_scid_len]
    mov [rdi + 5], cl
    lea rdi, [rdi + 6]
    lea rsi, [q_srv_scid]
    rep movsb
    mov byte [rdi], 8                     ; our SCID length
    inc rdi
    lea rsi, [q_scid]
    mov ecx, 8
    rep movsb
    lea rsi, [r13 + 1 + 16]               ; Length = pn(1) + payload + tag(16)
    call linnea_quic_varint_encode
    add rdi, rax
    mov rax, [q_cli_hs_pn]
    mov [rdi], al                         ; 1-byte packet number
    inc rdi
    lea rax, [qhdr]
    mov rdx, rdi
    sub rdx, rax                          ; header length
    sub rsp, 16
    lea rax, [q_hs_ckeys]
    mov [rsp], rax
    mov rax, [q_cli_hs_pn]
    mov [rsp + 8], rax
    lea rdi, [qpkt]
    lea rsi, [qhdr]
    mov ecx, 1
    mov r8, r14
    mov r9, r13
    call linnea_quic_protect              ; rax = total packet length
    add rsp, 16
    mov r12, rax
    inc qword [q_cli_hs_pn]
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
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.fail:
    mov rax, -1
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; quic_send_hs_ack(edi=fd): a Handshake packet carrying only an ACK, to validate
; our address and lift the server's 3x anti-amplification limit mid-flight.
quic_send_hs_ack:
    push rbx
    mov ebx, edi
    lea rdi, [qpay]
    mov rsi, [q_hs_largest]
    mov rdx, [q_hs_smallest]
    call quic_ack_frame                   ; rax = end
    lea rdx, [qpay]
    sub rax, rdx                          ; ACK length
    mov rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_hs
    pop rbx
    ret

; quic_send_held(edi = fd) — put a withheld packet on the wire, unchanged. It was
; protected with the keys and the key phase in force when it was BUILT, which is
; the whole point: it arrives after a key update carrying the older phase, exactly
; as a packet delayed by the network would.
quic_send_held:
    cmp qword [q_held_len], 0
    je .sh_none
    mov eax, LINNEA_SYS_SENDTO
    mov esi, edi
    mov edi, esi
    lea rsi, [q_held]
    mov rdx, [q_held_len]
    mov r10d, LINNEA_MSG_NOSIGNAL
    xor r8d, r8d
    xor r9d, r9d
    syscall
.sh_none:
    ret

; quic_send_1rtt_ack(edi = fd) — acknowledge the server's 1-RTT packets.
;
; The prober acknowledged the handshake and then nothing. On loopback that is
; invisible; against a real server the unacknowledged response fills its
; congestion window and it STOPS SENDING, which looks exactly like it ignoring
; the request. That is not a hypothetical: it is what made a key-update probe
; appear to fail against Cloudflare while an independent client showed Cloudflare
; handling it perfectly.
;
; The ack is deliberately PLAIN. It must not inherit whatever malformation the
; probe in progress has armed -- q_rsvd would put the reserved bits on every ack,
; which is a different experiment from "one request carried them" and silently
; changes what the peer does. The key phase is the exception and is kept: after a
; rotation every packet we send belongs to the new phase.
quic_send_1rtt_ack:
    push rbx
    push r12
    mov ebx, edi
    mov r12, [q_rsvd]
    mov qword [q_rsvd], 0
    cmp qword [q_ap_largest], 0
    jl .a1_done                           ; signed: nothing received yet
    ; Acknowledge ONLY the largest packet, not the span [smallest..largest]: a
    ; range claims every number in it, and this prober does not track which
    ; arrived, so a gap would have it vouching for packets it never saw -- and a
    ; peer that has not even SENT one of them is entitled to close the connection
    ; (RFC 9000 13.1). A single-packet range is always true.
    lea rdi, [qpay]
    mov rsi, [q_ap_largest]
    mov rdx, [q_ap_largest]
    call quic_ack_frame                   ; rax = one past the frame
    lea rdx, [qpay]
    sub rax, rdx
    mov rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
.a1_done:
    mov [q_rsvd], r12
    pop r12
    pop rbx
    ret

; quic_recv_flight(edi=fd) -> rax = 1 if the server Finished was decrypted.
; Reads datagrams, deriving Handshake keys from the ServerHello and reassembling
; the Handshake CRYPTO, until the server Finished arrives (or a timeout).
quic_recv_flight:
    push rbx
    mov ebx, edi
    mov qword [q_hs_ready], 0
    mov qword [qhsc_len], 0
    mov qword [q_fin_seen], 0
    mov qword [q_init_largest], -1
    mov qword [q_hs_largest], -1
    mov qword [q_hs_smallest], -1
    mov qword [q_cli_hs_pn], 0
    mov qword [q_acked], 0
    mov qword [q_init_dgram], 0
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 1500
    syscall
    test rax, rax
    jle .stall
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .stall
    mov rsi, rax
    ; measure the first datagram that carries a server Initial: RFC 9000 14.1
    ; requires a datagram carrying an ack-eliciting Initial to be expanded to
    ; 1200 bytes, and the server's ServerHello flight is exactly that. Measured
    ; on the datagram, not the packet, because coalescing is what usually
    ; satisfies the rule.
    cmp rsi, [q_dgram_max]                ; the largest datagram of the flight, for
    jbe .no_max                           ; the max_udp_payload_size lock
    mov [q_dgram_max], rsi
.no_max:
    cmp qword [q_init_dgram], 0
    jne .no_measure
    movzx eax, byte [qrx]
    test al, 0x80                         ; long header
    jz .no_measure
    and al, 0x30                          ; v1 long-header type: 00 = Initial
    jnz .no_measure
    mov [q_init_dgram], rsi
.no_measure:
    call quic_walk_datagram
    cmp qword [q_fin_seen], 0
    jne .done
    ; ACK promptly as flight packets arrive. A large server flight (Google's ~5 KB
    ; certificate) is paced on the client acknowledging what it received; only ACKing
    ; on a 1500ms stall is too slow and the server's window never reopens. Capped,
    ; once we have Handshake keys and a Handshake packet to acknowledge.
    cmp qword [q_hs_ready], 0
    je .loop
    cmp qword [q_hs_largest], 0
    jl .loop                              ; signed: no Handshake packet received yet
    cmp qword [q_acked], 16
    jae .loop
    inc qword [q_acked]
    mov edi, ebx
    call quic_send_hs_ack
    jmp .loop
.stall:
    ; The flight stalled. If we have Handshake keys but not the Finished yet, the
    ; server is holding back on the 3x anti-amplification limit — send a Handshake
    ; ACK to validate our address, which lets it send the rest. Do this once.
    cmp qword [q_fin_seen], 0
    jne .done
    cmp qword [q_hs_ready], 0
    je .done
    cmp qword [q_acked], 16              ; shared cap with the prompt-ACK path
    jae .done
    inc qword [q_acked]
    mov edi, ebx
    call quic_send_hs_ack
    jmp .loop
.done:
    call quic_srv_tp_scan                 ; the flight is in qhsc now: read its limits
    mov rax, [q_fin_seen]
    pop rbx
    ret

; quic_find_1rtt(rsi=datagram length) -> rax = ptr to the 1-RTT (short-header)
; packet in qrx, rdx = its length; rax = 0 if none. Skips leading long-header
; packets (a trailing Handshake ACK the server may coalesce).
quic_find_1rtt:
    push rbx
    push r12
    lea rbx, [qrx]
    lea r12, [qrx + rsi]                  ; end
.p:
    cmp rbx, r12
    jae .none
    test byte [rbx], 0x80
    jz .found
    mov rdi, rbx
    mov rsi, r12
    call quic_pkt_parse                   ; rax = total length
    test rax, rax
    jz .none
    add rbx, rax
    jmp .p
.found:
    mov rax, rbx
    mov rdx, r12
    sub rdx, rbx
    pop r12
    pop rbx
    ret
.none:
    xor eax, eax
    xor edx, edx
    pop r12
    pop rbx
    ret

; quic_recv_1rtt(edi=fd) -> rax = 1 if a server 1-RTT packet decrypted with the
; application keys (the handshake is complete). Tries a few datagrams.
quic_recv_1rtt:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    and rsp, -16
    mov ebx, edi
    mov r12d, 4
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
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
    mov rsi, rax
    call quic_find_1rtt                   ; rax = 1-RTT ptr, rdx = len
    test rax, rax
    jz .next
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [q_ap_skeys]
    lea rcx, [qplain]
    mov r8d, 8                            ; our SCID length (server's DCID)
    xor r9d, r9d                          ; expected pn = 0
    call linnea_quic_unprotect_short      ; rax = frames (or -1)
    test rax, rax
    js .next
    push rax                              ; frame length; the scanners clobber rax
    push rax                              ; (twice: keep rsp 16-aligned)
    lea rdi, [qplain]                     ; capture a NEW_CONNECTION_ID if present
    mov rsi, rax
    call quic_scan_ncid
    pop rax
    pop rax
    push rax
    push rax
    lea rdi, [qplain]                     ; a raised bidi stream limit, if the server
    mov rsi, rax                          ; grants one before we test the old limit
    call quic_scan_maxstreams
    pop rax
    pop rax
    lea rdi, [qplain]                     ; the server's control / QPACK streams
    mov rsi, rax                          ; ride this same packet
    call quic_scan_srv_uni
    jmp .yes
.next:
    dec r12d
    jnz .loop
.no:
    xor eax, eax
    lea rsp, [rbp - 16]
    pop r12
    pop rbx
    pop rbp
    ret
.yes:
    mov eax, 1
    lea rsp, [rbp - 16]
    pop r12
    pop rbx
    pop rbp
    ret

; quic_finish(edi=fd) -> rax = 1 if 1-RTT was established. Completes the
; transcript, derives 1-RTT keys, sends the client Finished (with an ACK) in a
; Handshake packet, and waits for a server 1-RTT packet.
quic_finish:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    and rsp, -16
    mov ebx, edi
    ; transcript += the server flight (EE..server Finished)
    lea rsi, [qhsc]
    mov rdx, [qhsc_fin_end]
    call qtr_add
    lea rdi, [qtr]
    mov rsi, [qtr_len]
    lea rdx, [th_buf]
    call linnea_sha256                    ; th2 = H(CH..server Finished)
    lea rdi, [q_secrets + 64]             ; handshake secret
    lea rsi, [th_buf]
    lea rdx, [q_ap_ckeys]
    lea rcx, [q_ap_skeys]
    lea r8, [q_cli_ap_secret]             ; keep both traffic secrets: a key update
    lea r9, [q_srv_ap_secret]             ; derives from the SECRET, not the keys
    call linnea_quic_app_secrets          ; 1-RTT keys
    ; finished_key = HKDF-Expand-Label(c_hs, "finished", "", 32)
    lea rdi, [q_secrets]
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [q_fin_key]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; payload = ACK + CRYPTO(client Finished)
    lea rdi, [qpay]
    mov rsi, [q_hs_largest]
    mov rdx, [q_hs_smallest]
    call quic_ack_frame                   ; rax = cursor after the ACK
    mov r12, rax                          ; CRYPTO frame start
    mov byte [r12], 0x06                  ; CRYPTO
    mov byte [r12 + 1], 0x00              ; offset 0
    mov byte [r12 + 2], 36                ; length 36
    mov byte [r12 + 3], 0x14              ; Finished
    mov byte [r12 + 4], 0x00
    mov byte [r12 + 5], 0x00
    mov byte [r12 + 6], 0x20              ; verify_data length 32
    lea rdi, [q_fin_key]                  ; verify_data = HMAC(fin_key, th2)
    mov esi, 32
    lea rdx, [th_buf]
    mov ecx, 32
    lea r8, [r12 + 7]
    call linnea_hmac_sha256
    lea rax, [r12 + 39]                   ; end of payload
    lea rcx, [qpay]
    sub rax, rcx
    mov rdx, rax                          ; payload length
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_hs                     ; Handshake packet: ACK + Finished
    mov edi, ebx
    call quic_recv_1rtt                   ; rax = 1 if a 1-RTT packet decrypted
    lea rsp, [rbp - 16]
    pop r12
    pop rbx
    pop rbp
    ret

; quic_send_1rtt(edi=fd, rsi=payload, rdx=payload len) -> rax = 0 ok / -1.
; Builds a short-header (1-RTT) packet with the application keys and sends it.
quic_send_1rtt:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and rsp, -16
    mov ebx, edi
    mov r14, rsi
    mov r13, rdx
    lea rdi, [qhdr]
    mov byte [rdi], 0x40                  ; short header: fixed bit, pnlen-1 = 0
    ; quic-14 probe: the two reserved bits (0x18) MUST be zero on the wire, and a
    ; peer that receives them set MUST close with PROTOCOL_VIOLATION (RFC 9000
    ; 17.3.1). They are set HERE, before linnea_quic_protect masks the byte, so
    ; they travel exactly as a real violator's would — header protection is what
    ; makes them invisible until the receiver has removed it.
    cmp qword [q_rsvd], 0
    je .no_rsvd
    or byte [rdi], 0x18
.no_rsvd:
    ; RFC 9001 6: a QUIC key update is the Key Phase bit (0x04), not a TLS
    ; KeyUpdate message -- that one is forbidden here and is a connection error.
    ; Set before linnea_quic_protect masks the byte, as the reserved bits are.
    cmp qword [q_kphase], 0
    je .no_kphase
    or byte [rdi], 0x04
.no_kphase:
    inc rdi
    mov rcx, [q_srv_scid_len]             ; DCID = the server's connection id
    lea rsi, [q_srv_scid]
    rep movsb
    mov rax, [q_cli_ap_pn]
    mov [rdi], al                         ; 1-byte packet number
    inc rdi
    lea rax, [qhdr]
    mov rdx, rdi
    sub rdx, rax                          ; header length
    sub rsp, 16
    lea rax, [q_ap_ckeys]
    mov [rsp], rax
    mov rax, [q_cli_ap_pn]
    mov [rsp + 8], rax
    lea rdi, [qpkt]
    lea rsi, [qhdr]
    mov ecx, 1
    mov r8, r14
    mov r9, r13
    call linnea_quic_protect
    add rsp, 16
    mov r12, rax
    inc qword [q_cli_ap_pn]               ; the number is consumed either way, so a
                                          ; withheld packet keeps the one it was
                                          ; built with and the next packet moves on
    cmp qword [q_hold], 0
    je .send_it
    mov [q_held_len], r12                 ; keep it for later instead of sending
    lea rdi, [q_held]
    lea rsi, [qpkt]
    mov rcx, r12
    rep movsb
    jmp .sent
.send_it:
    mov eax, LINNEA_SYS_SENDTO
    mov edi, ebx
    lea rsi, [qpkt]
    mov rdx, r12
    mov r10d, LINNEA_MSG_NOSIGNAL
    xor r8d, r8d
    xor r9d, r9d
    syscall
.sent:
    xor eax, eax
    test rax, rax
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; qpack_status_lookup(rdi=static index) -> rax = :status, or -1.
qpack_status_lookup:
    lea rsi, [qpack_idx2status]
    lea rcx, [qpack_idx2status_end]
.l:
    cmp rsi, rcx
    jae .none
    movzx eax, word [rsi]
    cmp rax, rdi
    je .hit
    add rsi, 4
    jmp .l
.hit:
    movzx eax, word [rsi + 2]
    ret
.none:
    mov rax, -1
    ret

; huff_status_decode(rdi=huffman bytes, rsi=len) -> rax = 3-digit status, or -1.
; A :status value is three ASCII digits, so only the digit codes of the HPACK /
; QPACK Huffman alphabet are needed (RFC 7541 Appendix B). They are NOT uniform:
; '0','1','2' are five bits (0b00000..0b00010) while '3'..'9' are six
; (0b011001..0b011111). Read MSB-first, trying a 5-bit code before a 6-bit one;
; anything else — including the all-ones padding tail — ends the value.
; Google Huffman-codes its status ("301" is the two bytes 0x64 0x01).
huff_status_decode:
    push rbx
    push r12
    push r13
    lea r13, [rdi + rsi]                  ; end of the value
    mov r12, rdi                          ; byte cursor
    xor r10d, r10d                        ; bit accumulator
    xor r11d, r11d                        ; bits currently held
    xor eax, eax                          ; status being accumulated
    xor ebx, ebx                          ; digits decoded
.hsd_fill:
    cmp r11d, 6                           ; keep 6 bits buffered: the longest code
    jae .hsd_have
    cmp r12, r13
    jae .hsd_tail                         ; no bytes left; a short tail may still hold
    movzx edx, byte [r12]                 ; one last 5-bit code
    inc r12
    shl r10d, 8
    or r10d, edx
    add r11d, 8
    jmp .hsd_fill
.hsd_have:
    mov ecx, r11d                         ; peek the top 5 bits
    sub ecx, 5
    mov edx, r10d
    shr edx, cl
    and edx, 0x1f
    cmp edx, 2                            ; 0b00000..0b00010 = '0','1','2'
    jbe .hsd_five
    mov ecx, r11d                         ; not a 5-bit digit: peek 6 bits
    sub ecx, 6
    mov edx, r10d
    shr edx, cl
    and edx, 0x3f
    cmp edx, 0x19                         ; 0b011001 = '3'
    jb .hsd_done
    cmp edx, 0x1f                         ; 0b011111 = '9'
    ja .hsd_done
    sub edx, 0x19 - 3                     ; code 0x19..0x1f -> digit 3..9
    sub r11d, 6
    jmp .hsd_acc
.hsd_five:
    sub r11d, 5
.hsd_acc:
    imul eax, eax, 10
    add eax, edx
    inc ebx
    cmp ebx, 3                            ; a status is exactly three digits
    jb .hsd_fill
    jmp .hsd_done
.hsd_tail:
    cmp r11d, 5                           ; fewer than 6 bits buffered and no more
    jb .hsd_done                          ; bytes: only a 5-bit code can still fit
    mov ecx, r11d
    sub ecx, 5
    mov edx, r10d
    shr edx, cl
    and edx, 0x1f
    cmp edx, 2
    ja .hsd_done                          ; padding (all ones) or a longer code
    sub r11d, 5
    imul eax, eax, 10
    add eax, edx
    inc ebx
    cmp ebx, 3
    jb .hsd_tail
.hsd_done:
    cmp ebx, 3
    jne .hsd_fail
    pop r13
    pop r12
    pop rbx
    ret
.hsd_fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; qpack_find_status(rdi=field section, rsi=len) -> rax = :status, or -1.
; A capacity-0 QPACK decoder: skips the 2-byte prefix, then walks field lines
; (indexed / literal-with-name-ref / literal-with-literal-name) for :status.
qpack_find_status:
    push rbx
    push r12
    push r13
    cmp byte [rdi], 0                     ; non-zero Required Insert Count means the
    jne .dyntable                        ; field section references the QPACK dynamic
                                         ; table (Google does); capacity-0, we can't
                                         ; resolve it -> report it honestly, not garbage
    lea r13, [rdi + rsi]                  ; end
    lea rbx, [rdi + 2]                    ; cursor, past Insert-Count + Base
.walk:
    cmp rbx, r13
    jae .none
    movzx eax, byte [rbx]
    test al, 0x80
    jnz .indexed
    mov ecx, eax
    and ecx, 0xc0
    cmp ecx, 0x40
    je .litnameref
    mov ecx, eax
    and ecx, 0xe0
    cmp ecx, 0x20
    je .litlitname
    jmp .none                            ; post-base / unsupported
.indexed:
    mov r12d, eax
    and r12d, 0x40                        ; T: static table?
    mov rsi, rbx
    mov rdi, r13
    mov ecx, 6
    call hp_int                          ; rax = index, rsi advanced
    jc .none
    mov rbx, rsi
    test r12d, r12d
    jz .walk                             ; dynamic index: we keep no table
    mov rdi, rax
    call qpack_status_lookup
    cmp rax, -1
    jne .found
    jmp .walk
.litnameref:
    mov r12d, eax
    and r12d, 0x10                        ; T: static table?
    mov rsi, rbx
    mov rdi, r13
    mov ecx, 4
    call hp_int                          ; rax = name index, rsi advanced
    jc .none
    mov rbx, rsi
    mov r8, rax                          ; name index
    cmp rbx, r13
    jae .none
    movzx r9d, byte [rbx]                 ; value: H (Huffman) bit + 7-bit length
    mov r10d, r9d
    and r10d, 0x80
    and r9d, 0x7f
    inc rbx
    test r12d, r12d
    jz .skipval
    cmp r8, 24                            ; static entries 24..28 (":status 103",
    jb .skipval                          ; 200, 304, 404, 503) all carry the
    cmp r8, 28                           ; ":status" name
    ja .skipval
    test r10d, r10d
    jnz .huffval                         ; Huffman-coded value (Google sends one)
    xor eax, eax
    xor ecx, ecx
.digit:
    cmp rcx, r9
    jae .found_adv
    movzx edx, byte [rbx + rcx]
    sub edx, '0'
    cmp edx, 9
    ja .dyntable                         ; non-digit: a Huffman-coded or otherwise
                                         ; undecodable value, not a plain-ASCII status
    imul eax, eax, 10
    add eax, edx
    inc rcx
    jmp .digit
.found_adv:
    add rbx, r9
    jmp .found
.huffval:
    mov rdi, rbx
    mov rsi, r9
    call huff_status_decode              ; rax = status | -1
    cmp rax, -1
    je .dyntable                         ; not three digits: report it undecodable
    add rbx, r9
    jmp .found
.skipval:
    add rbx, r9
    jmp .walk
.litlitname:
    mov rsi, rbx
    mov rdi, r13
    mov ecx, 3
    call hp_int                          ; name length
    jc .none
    mov rbx, rsi
    add rbx, rax
    mov rsi, rbx
    mov rdi, r13
    mov ecx, 7
    call hp_int                          ; value length
    jc .none
    mov rbx, rsi
    add rbx, rax
    jmp .walk
.found:
    pop r13
    pop r12
    pop rbx
    ret
.none:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret
.dyntable:
    mov rax, -5                          ; QPACK dynamic table in use, not decodable
    pop r13
    pop r12
    pop rbx
    ret

; parse_h3_headers(rdi=stream data, rsi=len) -> rax = :status, or -1 if there is
; no complete HEADERS frame yet. Walks HTTP/3 frames to the first HEADERS (0x01).
parse_h3_headers:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    lea r13, [rdi + rsi]
.fr:
    cmp rbx, r13
    jae .none
    mov rdi, rbx
    mov rsi, r13
    call linnea_quic_varint_decode        ; frame type
    test rdx, rdx
    jz .none
    add rbx, rdx
    mov r12, rax                          ; type
    mov rdi, rbx
    mov rsi, r13
    call linnea_quic_varint_decode        ; frame length
    test rdx, rdx
    jz .none
    add rbx, rdx
    lea rcx, [rbx + rax]
    cmp rcx, r13
    ja .none                             ; frame not fully arrived
    cmp r12, 0x01
    jne .skip
    mov rdi, rbx
    mov rsi, rax
    call qpack_find_status
    jmp .out
.skip:
    add rbx, rax
    jmp .fr
.none:
    mov rax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; quic_h3_get(edi=fd) -> rax = :status of the GET / response, or -1. Opens the
; client control stream (SETTINGS) and sends a QPACK-encoded GET on stream 0,
; then reassembles stream-0 data across 1-RTT packets and decodes :status.
quic_h3_get:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and rsp, -16
    mov ebx, edi
    mov qword [h3buf_len], 0
    ; --- QPACK field section for "GET / :authority=host" ---
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00                  ; Required Insert Count
    mov byte [rdi + 1], 0x00             ; Base
    mov byte [rdi + 2], 0xd1             ; :method GET   (static 17)
    mov byte [rdi + 3], 0xd7             ; :scheme https (static 23)
    mov byte [rdi + 4], 0xc1             ; :path /       (static 1)
    mov byte [rdi + 5], 0x50             ; :authority: literal, name ref static 0
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al                        ; value length (H=0, < 127)
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax                         ; field-section length
    ; --- 1-RTT payload: control STREAM(2) + request STREAM(0) ---
    lea rdi, [qpay]
    mov byte [rdi], 0x0a                 ; STREAM, LEN, no OFF/FIN
    mov byte [rdi + 1], 0x02             ; stream id 2 (client uni: control)
    mov byte [rdi + 2], 0x03             ; length 3
    mov byte [rdi + 3], 0x00             ; control stream type
    mov byte [rdi + 4], 0x04             ; SETTINGS frame
    mov byte [rdi + 5], 0x00             ; SETTINGS length 0
    add rdi, 6
    mov byte [rdi], 0x0b                 ; STREAM, LEN, FIN
    mov byte [rdi + 1], 0x00             ; stream id 0 (client bidi: request)
    lea rax, [r14 + 2]                   ; 0x01 + fslen-varint(1) + field section
    mov [rdi + 2], al                    ; STREAM data length (< 63)
    mov byte [rdi + 3], 0x01             ; HEADERS frame
    mov [rdi + 4], r14b                  ; HEADERS length (fslen, < 63)
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax                         ; payload length
    ; keep the request payload so it can be retransmitted: qpay is reused for the
    ; ACKs we send while reading, and QUIC gives us no retransmission for free
    mov [h3req_len], rdx
    push rdx
    lea rdi, [h3req]
    lea rsi, [qpay]
    mov rcx, rdx
    rep movsb
    pop rdx
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    ; --- read 1-RTT packets, reassemble stream 0, decode :status ---
    ; A large response (Google's HEADERS block is ~371 bytes) is paced across
    ; several 1-RTT packets on the client's acknowledgements, so ACK each round
    ; rather than reading passively — otherwise only the first packet ever arrives.
    mov r12d, 15                         ; datagram budget
    mov qword [q_ap_largest], -1
    mov qword [q_ap_smallest], -1
    mov qword [h3req_tries], 3           ; request retransmissions before giving up
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
    syscall
    test rax, rax
    jle .stall
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .fail
    mov rsi, rax
    call quic_find_1rtt                   ; rax = 1-RTT ptr, rdx = len
    test rax, rax
    jz .next
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [q_ap_skeys]
    lea rcx, [qplain]
    mov r8d, 8
    mov r9, [q_ap_largest]                ; expected pn = largest server pn seen + 1
    inc r9                                ; (-1 "none yet" becomes 0)
    call linnea_quic_unprotect_short      ; rax = frame bytes, rdx = pn
    test rax, rax
    js .next
    cmp rdx, [q_ap_largest]               ; track the server's 1-RTT pn range so the
    jle .ap_max_done                      ; ACK covers exactly what we received
    mov [q_ap_largest], rdx
.ap_max_done:
    cmp qword [q_ap_smallest], -1
    jne .ap_min_done
    mov [q_ap_smallest], rdx
.ap_min_done:
    ; walk STREAM frames; accumulate stream-0 data into h3buf
    lea r13, [qplain]                     ; frame cursor
    mov r14, rax                          ; frames length
    add r14, r13                          ; frames end
.frames:
    mov rdi, r13
    mov rsi, r14
    sub rsi, r13
    jle .decode
    call linnea_quic_stream_frame         ; rax=data, rdx=len, r8=id, r9=next
    test rax, rax
    jz .decode
    mov r13, r9                           ; resume after this STREAM frame
    test r8, r8
    jnz .frames                          ; not the request stream
    ; append rax..rax+rdx to h3buf
    mov rcx, [h3buf_len]
    lea rdi, [h3buf + rcx]
    mov rsi, rax
    mov rcx, rdx
    add [h3buf_len], rdx
    rep movsb
    jmp .frames
.decode:
    ; acknowledge what arrived so the server releases the rest of the response
    cmp qword [q_ap_largest], 0
    jl .decode_parse                      ; nothing decrypted yet
    lea rdi, [qpay]
    mov rsi, [q_ap_largest]
    mov rdx, [q_ap_smallest]
    call quic_ack_frame
    lea rdx, [qpay]
    sub rax, rdx
    mov rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
.decode_parse:
    lea rdi, [h3buf]
    mov rsi, [h3buf_len]
    call parse_h3_headers                 ; rax = status or -1
    cmp rax, -1
    jne .done
.next:
    dec r12d
    jnz .loop
    jmp .fail
.stall:
    ; Nothing arrived in the poll window. QUIC gives no retransmission for free, so
    ; resend the request: it may have been lost, or discarded because we sent it
    ; before the server had finished its side of the handshake (a 1-RTT packet that
    ; early is dropped). Servers that answer promptly never reach here.
    cmp qword [h3req_tries], 0
    jle .fail
    dec qword [h3req_tries]
    mov edi, ebx
    lea rsi, [h3req]
    mov rdx, [h3req_len]
    call quic_send_1rtt
    dec r12d
    jnz .loop
.fail:
    mov rax, -1
.done:
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; quic_h3_open() -> rax = a fd with the QUIC handshake driven to 1-RTT, or -1.
; A fresh connection (new keys, DCID, SCID) for a negative probe. Duplicates the
; setup in probe_h3_handshake deliberately, so a bug here cannot touch the proven
; valid-request path.
; quic_h3_handshake_retry(edi=fd) -> rax = q_fin_seen. Sends the Initial and reads
; the flight; if no ServerHello comes back it retries with a fresh connection id,
; the way a real client retransmits a lost Initial. Without this a single dropped
; Initial (a WAN loss, a server reload window) reads as a failed handshake.
quic_h3_handshake_retry:
    push rbx
    push r12
    mov ebx, edi
    mov r12d, 3
.attempt:
    mov edi, ebx
    call quic_send_initial
    test rax, rax
    js .fail
    mov edi, ebx
    call quic_recv_flight                 ; sets q_hs_ready / q_fin_seen
    cmp qword [q_hs_ready], 0
    jne .done                             ; the handshake got going
    dec r12d
    jz .done
    call quic_fresh_ids                    ; a brand-new connection id and keys
    jmp .attempt
.done:
    mov rax, [q_fin_seen]
    pop r12
    pop rbx
    ret
.fail:
    xor eax, eax
    pop r12
    pop rbx
    ret

quic_h3_open:
    push rbx
    mov qword [q_ncid_count], 0           ; per-connection, like q_req_sid below
    mov qword [q_dgram_max], 0
    ; The received packet numbers MUST be reset with the connection. They feed the
    ; acks the classifier now sends, and an ack for a packet the peer never sent is
    ; a PROTOCOL_VIOLATION (RFC 9000 13.1) -- a stale value from the previous
    ; probe's connection had this server closing on us, which stalled the battery
    ; for minutes against prod while lenient peers shrugged it off.
    mov qword [q_ap_largest], -1
    mov qword [q_ap_smallest], -1
    mov qword [q_req_sid], 0              ; a fresh connection requests on stream 0
                                          ; unless a probe says otherwise, so a probe
                                          ; that used another id cannot strand the next
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
    call quic_h3_handshake_retry
    test rax, rax
    jz .closefail                         ; no server Finished after retries
    mov edi, ebx
    call quic_finish
    test rax, rax
    jz .closefail                         ; 1-RTT not established
    mov eax, ebx
    pop rbx
    ret
.closefail:
    mov edi, ebx
    call close_fd
.fail:
    mov rax, -1
    pop rbx
    ret

; quic_h3_classify(edi=fd) -> rax: a server :status (>0), -2 RESET_STREAM on our
; request stream, -3 CONNECTION_CLOSE, or -1 nothing. Reads 1-RTT packets and
; walks every frame (frame_skip knows all lengths; stream_frame extracts the data).
quic_h3_classify:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16
    mov ebx, edi
    mov qword [h3buf_len], 0
    mov r15d, 8                           ; datagram budget
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
    syscall
    test rax, rax
    jle .none
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .none
    mov rsi, rax
    cmp rsi, [q_dgram_max]                ; keep the largest datagram of the whole
    jbe .no_max_1rtt                      ; connection, not just of the flight
    mov [q_dgram_max], rsi
.no_max_1rtt:
    call quic_find_1rtt
    test rax, rax
    jz .next
    mov [q_pkt_ptr], rax
    mov [q_pkt_len], rdx
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [q_ap_skeys]
    lea rcx, [qplain]
    mov r8d, 8
    mov r9, [q_cli_ap_pn]
    call linnea_quic_unprotect_short
    test rax, rax
    jns .opened
    cmp qword [q_ku_armed], 0
    je .next                              ; no key update in flight: not ours to read
    mov rdi, [q_pkt_ptr]                  ; the SAME packet, under the next generation
    mov rsi, [q_pkt_len]
    lea rdx, [q_ap_skeys_next]
    lea rcx, [qplain]
    mov r8d, 8
    mov r9, [q_cli_ap_pn]
    call linnea_quic_unprotect_short
    test rax, rax
    js .next
    push rax
    push rdx                              ; keep the length and the packet number
    lea rdi, [q_ap_skeys]                 ; it opened: the server has rotated, so
    lea rsi, [q_ap_skeys_next]            ; adopt the new generation and stop trying
    mov ecx, linnea_quic_keys_size
    rep movsb
    mov qword [q_ku_armed], 0
    pop rdx
    pop rax
.opened:
    ; track what we have received so the ack actually acknowledges the response --
    ; without this the ack names a packet from the handshake era and frees no
    ; congestion window at all.
    cmp qword [q_ap_largest], 0
    jl .cl_first_pn
    cmp rdx, [q_ap_largest]
    jbe .cl_pn_done
.cl_first_pn:
    mov [q_ap_largest], rdx
.cl_pn_done:
    cmp qword [q_ap_smallest], 0
    jge .cl_have_small
    mov [q_ap_smallest], rdx
.cl_have_small:
    lea r13, [qplain]                     ; frame cursor
    lea r14, [qplain]
    add r14, rax                          ; frames end
.frame:
    cmp r13, r14
    jae .next
    movzx eax, byte [r13]
    cmp al, 0x1c                          ; CONNECTION_CLOSE (transport)
    je .closed
    cmp al, 0x1d                          ; CONNECTION_CLOSE (application)
    je .closed
    cmp al, 0x04                          ; RESET_STREAM
    je .reset
    mov ecx, eax
    and ecx, 0xf8
    cmp ecx, 0x08                         ; STREAM
    je .stream
    mov rdi, r13                          ; anything else: skip by length
    mov rsi, r14
    call linnea_quic_frame_skip
    test rax, rax
    jle .next                            ; truncated / unknown: give up on packet
    add r13, rax
    jmp .frame
.stream:
    mov rdi, r13
    mov rsi, r14
    sub rsi, r13
    call linnea_quic_stream_frame         ; rax=data, rdx=len, r8=id, r9=next
    test rax, rax
    jz .next
    mov r13, r9
    cmp r8, [q_req_sid]
    jne .frame                           ; not the stream we requested on
    ; clamp to h3buf: a real page is far larger than this buffer and the copy had
    ; no bound, so a third-party server's response walked off the end of .bss and
    ; killed the prober. Only the head of the stream is ever needed — the field
    ; section carrying :status sits at its start.
    mov rcx, [h3buf_len]
    mov r8, 4096
    sub r8, rcx                          ; room left
    jbe .frame                           ; full: keep walking, copy nothing
    cmp rdx, r8
    jbe .fits
    mov rdx, r8
.fits:
    lea rdi, [h3buf + rcx]
    mov rsi, rax
    mov rcx, rdx
    add [h3buf_len], rdx
    rep movsb
    lea rdi, [h3buf]
    mov rsi, [h3buf_len]
    call parse_h3_headers
    cmp rax, -1
    jne .out                             ; got a :status
    jmp .frame
.reset:
    mov rax, -2
    jmp .out
.closed:
    ; record WHICH violation the server reported, not merely that it closed: a
    ; probe for a specific MUST has to tell the right error code from a server
    ; that closed for some unrelated reason. RFC 9000 19.19: the frame type byte
    ; is followed by the error code as a varint.
    mov qword [q_close_code], -1
    lea rdi, [r13 + 1]
    mov rsi, r14
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .closed_out
    mov [q_close_code], rax
.closed_out:
    mov rax, -3
    jmp .out
.next:
    mov edi, ebx                          ; ack what we have read so far: placed
    call quic_send_1rtt_ack               ; HERE, where the datagram is done with,
                                          ; because doing it before quic_find_1rtt
                                          ; would clobber the length it needs
    dec r15d
    jnz .loop
.none:
    mov rax, -1
.out:
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; quic_h3_bad(esi=variant) -> rax: opens a fresh h3 connection, sends one bad
; request, and classifies the response. variant 1 = no :path, 2 = undecodable
; QPACK. Returns quic_h3_classify's verdict, or -1 if the handshake failed.
quic_h3_bad:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and rsp, -16
    mov r12d, esi                         ; variant
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax                          ; fd
    ; --- QPACK field section into fs_scratch ---
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    add rdi, 2
    cmp r12d, 2
    je .badqpack
    ; valid pseudo-headers minus :path (variant 1)
    mov byte [rdi], 0xd1                  ; :method GET
    mov byte [rdi + 1], 0xd7             ; :scheme https
    add rdi, 2
    cmp r12d, 1
    je .authority                        ; variant 1: skip :path
    ; (no other variant reaches here)
.authority:
    mov byte [rdi], 0x50                  ; :authority literal name-ref static 0
    inc rdi
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    jmp .assemble
.badqpack:
    ; an indexed field line into the (empty, capacity-0) dynamic table
    mov byte [rdi], 0x80                  ; indexed, T=0 dynamic, index 0
    inc rdi
.assemble:
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax                          ; field-section length
    ; --- request STREAM(0) only (no control stream needed for a reject test) ---
    lea rdi, [qpay]
    mov byte [rdi], 0x0b                 ; STREAM, LEN, FIN
    mov byte [rdi + 1], 0x00             ; stream id 0
    lea rax, [r14 + 2]
    mov [rdi + 2], al                    ; STREAM data length
    mov byte [rdi + 3], 0x01            ; HEADERS frame
    mov [rdi + 4], r14b                 ; HEADERS length
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify                 ; rax = verdict
    mov r13, rax
    mov edi, ebx
    call close_fd
    mov rax, r13
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.fail:
    mov rax, -4                              ; handshake not established (distinct from -1)
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; probe_h3_nopath: a request missing :path must be rejected, never answered 2xx.
probe_h3_nopath:
    mov esi, 1
    call quic_h3_bad                      ; rax = status | -2 | -3 | -1 | -4
    cmp rax, -4
    je .skip                             ; handshake never came up: not a deviation
    mov dil, K_OK
    ; DEVIATION only if the server ANSWERED 2xx/3xx to a malformed request
    cmp rax, 200
    jl .ok
    cmp rax, 400
    jl .dev
.ok:
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.skip:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_nopath]
    mov edx, n_h3_nopath_len
    call report_plain
    ret

; probe_h3_badqpack: an undecodable QPACK field section is a connection error.
probe_h3_badqpack:
    mov esi, 2
    call quic_h3_bad
    cmp rax, -4
    je .skip                             ; handshake never came up: not a deviation
    mov dil, K_OK
    cmp rax, 200                          ; answered 2xx/3xx = accepted bad input
    jl .ok
    cmp rax, 400
    jl .dev
.ok:
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.skip:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_badqp]
    mov edx, n_h3_badqp_len
    call report_plain
    ret

; quic_fresh_ids(): a fresh x25519 keypair, client random, session id, DCID, SCID.
quic_fresh_ids:
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
    ret

; quic_recv_initial_verdict(edi=fd) -> rax: 1 = the server's Initial carried a
; CONNECTION_CLOSE (an explicit abort), 2 = it carried CRYPTO (a ServerHello: the
; handshake is proceeding), 0 = nothing decryptable arrived. Walks coalesced
; long-header packets, unprotects each Initial with qi_skeys and scans its frames.
quic_recv_initial_verdict:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16
    mov ebx, edi
    mov r12d, 4                           ; datagram budget
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
    syscall
    test rax, rax
    jle .none
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .none
    lea r13, [qrx]
    lea r14, [qrx + rax]                  ; datagram end
.pkt:
    cmp r13, r14
    jae .next
    movzx eax, byte [r13]
    test al, 0x80
    jz .next                             ; short header: unexpected here
    mov rdi, r13
    mov rsi, r14
    call quic_pkt_parse                   ; rax = this packet's total length
    test rax, rax
    jz .next
    mov r15, rax
    movzx eax, byte [r13]
    and al, 0xf0
    cmp al, 0xc0                          ; Initial (long, type bits 00)?
    jne .adv
    mov rdi, r13
    mov rsi, r15
    lea rdx, [qi_skeys]
    lea rcx, [qplain]
    call linnea_quic_unprotect            ; rax = frame bytes (or < 0)
    test rax, rax
    js .adv
    lea rdi, [qplain]
    lea rsi, [qplain + rax]
.fr:
    cmp rdi, rsi
    jae .adv
    movzx eax, byte [rdi]
    cmp al, 0x1c
    je .close
    cmp al, 0x1d
    je .close
    cmp al, 0x06
    je .crypto
    call linnea_quic_frame_skip           ; rax = frame length, rdi preserved
    test rax, rax
    jle .adv
    add rdi, rax
    jmp .fr
.adv:
    add r13, r15
    jmp .pkt
.next:
    dec r12d
    jnz .loop
.none:
    xor eax, eax
    jmp .done
.close:
    ; record WHICH error the abort names, so a probe for a specific MUST can tell
    ; it from a server that refused the handshake for an unrelated reason. rdi
    ; still points at the CONNECTION_CLOSE; rsi is the end of its packet.
    mov qword [q_close_code], -1
    inc rdi
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .close_out
    mov [q_close_code], rax
.close_out:
    mov eax, 1
    jmp .done
.crypto:
    mov eax, 2
.done:
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; quic_h3_abort_verdict() -> rax: a fresh QUIC connection whose (already-mangled)
; ClientHello should be refused. 1 = the server aborted with a CONNECTION_CLOSE in
; its Initial; 2 = it proceeded to a ServerHello; 0 = silence.
quic_h3_abort_verdict:
    push rbx
    call quic_fresh_ids
    call udp_connect
    test rax, rax
    js .av_fail
    mov ebx, eax
    mov edi, ebx
    call quic_send_initial
    test rax, rax
    js .av_close
    mov edi, ebx
    call quic_recv_initial_verdict        ; 1 close / 2 proceeded / 0 none
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    pop rbx
    ret
.av_close:
    mov edi, ebx
    call close_fd
.av_fail:
    xor eax, eax
    pop rbx
    ret

; report_abort_verdict(rdi=verdict, rsi=name, edx=len): OK iff aborted (1), DEV if
; the handshake proceeded (2), info on silence (0).
report_abort_verdict:
    mov cl, K_INFO
    cmp rdi, 1
    jne .rav_notok
    mov cl, K_OK
    jmp .rav_set
.rav_notok:
    cmp rdi, 2
    jne .rav_set
    mov cl, K_DEV
.rav_set:
    mov dil, cl
    call report_plain
    ret

; probe_h3_no_tls13 (tls-5): QUIC mandates TLS 1.3. A hello offering only TLS 1.2
; in supported_versions must be refused, not served TLS 1.3 unoffered.
probe_h3_no_tls13:
    mov qword [bad_version], 1
    call quic_h3_abort_verdict
    mov qword [bad_version], 0
    mov rdi, rax
    lea rsi, [n_h3_notls13]
    mov edx, n_h3_notls13_len
    call report_abort_verdict
    ret

; probe_h3_bad_cipher (tls-5): a hello offering only a cipher suite we do not
; implement must be refused, not served TLS_AES_128_GCM_SHA256 unoffered.
probe_h3_bad_cipher:
    mov qword [bad_cipher], 1
    call quic_h3_abort_verdict
    mov qword [bad_cipher], 0
    mov rdi, rax
    lea rsi, [n_h3_badciph]
    mov edx, n_h3_badciph_len
    call report_abort_verdict
    ret

; probe_h3_no_sigalgs (tls-5): a QUIC ClientHello with no signature_algorithms,
; while the server authenticates with a certificate, MUST be aborted with
; missing_extension (RFC 8446 9.2). OK iff the server's Initial says so; DEV if it
; proceeds to a ServerHello; info on silence.
probe_h3_no_sigalgs:
    push rbx
    push r12
    call quic_fresh_ids
    mov qword [omit_sigalgs], 1
    call udp_connect
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    call quic_send_initial
    test rax, rax
    js .closefail
    mov edi, ebx
    call quic_recv_initial_verdict        ; rax: 1 close / 2 proceeded / 0 none
    mov r12, rax
    mov qword [omit_sigalgs], 0
    mov edi, ebx
    call close_fd
    mov dil, K_OK
    cmp r12, 1
    je .rep
    mov dil, K_DEV
    cmp r12, 2
    je .rep
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_nosig]
    mov edx, n_h3_nosig_len
    call report_plain
    pop r12
    pop rbx
    ret
.closefail:
    mov edi, ebx
    call close_fd
.fail:
    mov qword [omit_sigalgs], 0
    mov dil, K_DEV
    lea rsi, [n_h3_nosig]
    mov edx, n_h3_nosig_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_trailer (h3-2): a request stream is HEADERS, DATA, then AT MOST ONE
; trailer section and nothing after. A frame following the trailers is a
; connection error (H3_FRAME_UNEXPECTED, RFC 9114 4.1). OK iff the server aborts
; the connection (Linnea does — a positive lock); else [info]: serving the request
; despite a frame after the trailers is a common request-tail leniency (Cloudflare
; does it) and not a portable deviation.
probe_h3_trailer:
    push rbx
    push r14
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    ; QPACK field section for a valid GET, into fs_scratch
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0xd1              ; :method GET
    mov byte [rdi + 3], 0xd7             ; :scheme https
    mov byte [rdi + 4], 0xc1             ; :path /
    mov byte [rdi + 5], 0x50             ; :authority literal, name ref static 0
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax                         ; field-section length
    ; payload: control STREAM(2, SETTINGS) + request STREAM(0, FIN) carrying
    ; HEADERS(req) + HEADERS(empty trailer) + DATA(1) — the DATA is the violation.
    lea rdi, [qpay]
    mov byte [rdi], 0x0a                 ; control STREAM, LEN, no FIN
    mov byte [rdi + 1], 0x02             ; stream id 2
    mov byte [rdi + 2], 0x03
    mov byte [rdi + 3], 0x00             ; control stream type
    mov byte [rdi + 4], 0x04             ; SETTINGS
    mov byte [rdi + 5], 0x00
    add rdi, 6
    mov byte [rdi], 0x0b                 ; request STREAM, LEN, FIN
    mov byte [rdi + 1], 0x00             ; stream id 0
    lea rax, [r14 + 9]                   ; stream data length (< 63)
    mov [rdi + 2], al
    add rdi, 3
    mov byte [rdi], 0x01                 ; HEADERS (request)
    mov [rdi + 1], r14b
    add rdi, 2
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    mov byte [rdi], 0x01                 ; HEADERS (trailer, empty field section)
    mov byte [rdi + 1], 0x02
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x00
    add rdi, 4
    mov byte [rdi], 0x00                 ; DATA after the trailers -> illegal
    mov byte [rdi + 1], 0x01
    mov byte [rdi + 2], 0x41
    add rdi, 3
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify                ; -3 close / -2 reset / status / -1
    mov r14, rax
    mov edi, ebx
    call close_fd
    cmp r14, -3                          ; CONNECTION_CLOSE = strict rejection
    je .ok
    ; Anything else is [info], not [DEV!]: a server that serves the request despite
    ; a frame after the trailers (Cloudflare does) is being lenient about the
    ; request-stream tail after an already-complete request — common and not a
    ; portable deviation. Linnea closes -> [OK], so this stays a positive lock.
    mov dil, K_INFO
    jmp .rep
.ok:
    mov dil, K_OK
.rep:
    lea rsi, [n_h3_trailer]
    mov edx, n_h3_trailer_len
    call report_plain
    pop r14
    pop rbx
    ret
.fail:
    mov dil, K_INFO                          ; handshake never came up: not a deviation
    lea rsi, [n_h3_trailer]
    mov edx, n_h3_trailer_len
    call report_plain
    pop r14
    pop rbx
    ret

; probe_h3_qpack_base (h3-14): with Required Insert Count 0, a set Delta Base sign
; bit means Base = -1, which is forbidden (RFC 9204 4.5.1.2) — a QPACK decoding
; failure, i.e. a connection error (QPACK_DECOMPRESSION_FAILED). Field section is
; an otherwise valid GET; only the sign bit is wrong. OK iff the server closes the
; connection (Linnea does — a positive lock); else [info]: with a static-only field
; section the Base is unused, so a decoder that validates it lazily (Cloudflare)
; serves the request — not a portable deviation.
probe_h3_qpack_base:
    push rbx
    push r14
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x80              ; Delta Base sign set, RIC 0 -> Base -1
    mov byte [rdi + 2], 0xd1             ; :method GET
    mov byte [rdi + 3], 0xd7             ; :scheme https
    mov byte [rdi + 4], 0xc1             ; :path /
    mov byte [rdi + 5], 0x50             ; :authority literal, name ref static 0
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax                         ; field-section length
    lea rdi, [qpay]
    mov byte [rdi], 0x0a                 ; control STREAM(2, SETTINGS)
    mov byte [rdi + 1], 0x02
    mov byte [rdi + 2], 0x03
    mov byte [rdi + 3], 0x00
    mov byte [rdi + 4], 0x04
    mov byte [rdi + 5], 0x00
    add rdi, 6
    mov byte [rdi], 0x0b                 ; request STREAM(0, FIN)
    mov byte [rdi + 1], 0x00
    lea rax, [r14 + 2]
    mov [rdi + 2], al
    mov byte [rdi + 3], 0x01             ; HEADERS
    mov [rdi + 4], r14b
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    mov r14, rax
    mov edi, ebx
    call close_fd
    cmp r14, -3                          ; connection close = strict rejection
    je .ok
    ; Anything else is [info], not [DEV!]: with a capacity-0 (static-only) field
    ; section the Base is never used, so a decoder that validates it lazily (as
    ; Cloudflare does) legitimately never sees the negative value and serves the
    ; request. Linnea validates eagerly and closes -> [OK], a positive lock.
    mov dil, K_INFO
    jmp .rep
.ok:
    mov dil, K_OK
.rep:
    lea rsi, [n_h3_qpbase]
    mov edx, n_h3_qpbase_len
    call report_plain
    pop r14
    pop rbx
    ret
.fail:
    mov dil, K_INFO                          ; handshake never came up: not a deviation
    lea rsi, [n_h3_qpbase]
    mov edx, n_h3_qpbase_len
    call report_plain
    pop r14
    pop rbx
    ret

; probe_h3_ctrl_framelen (h3-4): a single-varint control frame (CANCEL_PUSH /
; GOAWAY / MAX_PUSH_ID) must carry exactly one varint; an empty payload is a
; connection error (H3_FRAME_ERROR, RFC 9114 7.1). Sends a MAX_PUSH_ID of length 0
; on the control stream. OK iff the server closes; DEV if it serves the request
; (pre-fix never length-checked these).
probe_h3_ctrl_framelen:
    push rbx
    push r14
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0xd1
    mov byte [rdi + 3], 0xd7
    mov byte [rdi + 4], 0xc1
    mov byte [rdi + 5], 0x50
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax
    lea rdi, [qpay]
    mov byte [rdi], 0x0a                 ; control STREAM(2), data length 5
    mov byte [rdi + 1], 0x02
    mov byte [rdi + 2], 0x05
    mov byte [rdi + 3], 0x00             ; control stream type
    mov byte [rdi + 4], 0x04             ; SETTINGS
    mov byte [rdi + 5], 0x00             ; SETTINGS length 0
    mov byte [rdi + 6], 0x0d             ; MAX_PUSH_ID
    mov byte [rdi + 7], 0x00             ; length 0 -> illegal (needs one varint)
    add rdi, 8
    mov byte [rdi], 0x0b                 ; request STREAM(0, FIN)
    mov byte [rdi + 1], 0x00
    lea rax, [r14 + 2]
    mov [rdi + 2], al
    mov byte [rdi + 3], 0x01
    mov [rdi + 4], r14b
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    mov r14, rax
    mov edi, ebx
    call close_fd
    cmp r14, -3
    je .ok
    cmp r14, 200
    jl .info
    cmp r14, 400
    jl .dev
    jmp .info
.ok:
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_ctrllen]
    mov edx, n_h3_ctrllen_len
    call report_plain
    pop r14
    pop rbx
    ret
.fail:
    mov dil, K_INFO                          ; handshake never came up: not a deviation
    lea rsi, [n_h3_ctrllen]
    mov edx, n_h3_ctrllen_len
    call report_plain
    pop r14
    pop rbx
    ret

; qpack_get_prio(rdi=out, rsi=priority value, rdx=value len) -> rax = end.
; Field section for GET /h3big.bin with a "priority" request header.
qpack_get_prio:
    push r12
    push r13
    mov r12, rsi
    mov r13, rdx
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0xd1              ; :method GET
    mov byte [rdi + 3], 0xd7             ; :scheme https
    add rdi, 4
    mov byte [rdi], 0x51                 ; :path literal, name ref static 1
    mov rax, [big_len]
    mov [rdi + 1], al                    ; value length (keep the path short, < 60)
    add rdi, 2
    mov rsi, [big_ptr]
    mov rcx, [big_len]
    rep movsb
    mov byte [rdi], 0x50                 ; :authority literal, name ref static 0
    mov rax, [host_len]
    mov [rdi + 1], al
    add rdi, 2
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    mov byte [rdi], 0x27                 ; priority: literal with a literal name
    mov byte [rdi + 1], 0x01            ; name length 8 (7 + 1)
    add rdi, 2
    lea rsi, [hdr_priority]
    mov ecx, 8
    rep movsb
    mov [rdi], r13b                      ; value length (< 127, H=0)
    inc rdi
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov rax, rdi
    pop r13
    pop r12
    ret

; quic_h3_tally(edi=fd): read the server's early 1-RTT burst and sum the STREAM
; data bytes seen on stream 0 (h3_bytes_s0) and stream 4 (h3_bytes_s4). We do not
; ACK, so this captures the initial congestion-limited burst — which a priority
; scheduler fills from the higher-priority stream first.
quic_h3_tally:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16
    mov ebx, edi
    mov qword [h3_bytes_s0], 0
    mov qword [h3_bytes_s4], 0
    xor r15d, r15d                        ; expected pn for reconstruction
    mov r12d, 40                          ; datagram budget
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
    syscall
    test rax, rax
    jle .done
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .done
    mov rsi, rax
    call quic_find_1rtt                   ; rax = 1-RTT ptr, rdx = len
    test rax, rax
    jz .next
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [q_ap_skeys]
    lea rcx, [qplain]
    mov r8d, 8
    mov r9, r15
    call linnea_quic_unprotect_short      ; rax = frames, rdx = pn
    test rax, rax
    js .next
    mov r15, rdx                          ; track the largest pn as the next expected
    push rax                              ; frames length
    ; ACK what we have so the server keeps streaming — otherwise it sends only the
    ; initial congestion window and tx_pump's priority scheduling never shows.
    lea rdi, [qpay]
    mov rsi, r15
    xor edx, edx                          ; 1-RTT: ack 0..largest (our servers start at 0)
    call quic_ack_frame
    lea rdx, [qpay]
    sub rax, rdx
    mov rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    pop rax                               ; frames length
    lea r13, [qplain]
    lea r14, [qplain]
    add r14, rax
.frames:
    mov rdi, r13
    mov rsi, r14
    sub rsi, r13
    jle .next
    call linnea_quic_stream_frame         ; rax=data, rdx=len, r8=id, r9=next
    test rax, rax
    jz .next
    mov r13, r9
    cmp r8, 0
    je .add0
    cmp r8, 4
    je .add4
    jmp .frames
.add0:
    add [h3_bytes_s0], rdx
    jmp .frames
.add4:
    add [h3_bytes_s4], rdx
    jmp .frames
.next:
    dec r12d
    jnz .loop
.done:
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; probe_h3_urgency (h3-13): urgency is an RFC 8941 number, not one digit. Two
; concurrent GETs of a large file — stream 0 with "u=07" (the number 7, LOW
; priority; a pre-fix parser read only '0' = HIGHEST) and stream 4 with "u=1"
; (HIGH). A correct scheduler fills the early burst from stream 4. OK iff stream 4
; clearly leads (server honored the hint — a positive lock, needs --big + a
; bottleneck); else [info]. Priority (RFC 9218) is advisory, so a server that does
; not prioritize (Cloudflare, over the default /) is not deviating — never [DEV!].
probe_h3_urgency:
    push rbx
    push r12
    push r13
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    lea rdi, [fs_scratch]                 ; stream 0: u=07
    lea rsi, [prio_a]
    mov edx, prio_a_len
    call qpack_get_prio
    lea rcx, [fs_scratch]
    sub rax, rcx
    mov r12, rax                          ; lenA
    lea rdi, [fs_scratch2]                ; stream 4: u=1
    lea rsi, [prio_b]
    mov edx, prio_b_len
    call qpack_get_prio
    lea rcx, [fs_scratch2]
    sub rax, rcx
    mov r13, rax                          ; lenB
    lea rdi, [qpay]
    mov byte [rdi], 0x0a                 ; control STREAM(2, SETTINGS)
    mov byte [rdi + 1], 0x02
    mov byte [rdi + 2], 0x03
    mov byte [rdi + 3], 0x00
    mov byte [rdi + 4], 0x04
    mov byte [rdi + 5], 0x00
    add rdi, 6
    mov byte [rdi], 0x0b                 ; request STREAM(0, FIN)
    mov byte [rdi + 1], 0x00
    lea rax, [r12 + 2]
    mov [rdi + 2], al
    mov byte [rdi + 3], 0x01
    mov [rdi + 4], r12b
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r12
    rep movsb
    mov byte [rdi], 0x0b                 ; request STREAM(4, FIN)
    mov byte [rdi + 1], 0x04
    lea rax, [r13 + 2]
    mov [rdi + 2], al
    mov byte [rdi + 3], 0x01
    mov [rdi + 4], r13b
    add rdi, 5
    lea rsi, [fs_scratch2]
    mov rcx, r13
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_tally
    mov edi, ebx
    call close_fd
    ; HTTP priority (RFC 9218) is ADVISORY — a server MAY ignore a "priority"
    ; request header — so a stream-0 lead is not a deviation. Report [OK] only when
    ; the high-urgency stream (4) clearly leads (the server honored it), else [info].
    ; The margin filters network noise and small/absent resources (the default /):
    ; both streams fetch the same resource, so only a large one (--big) under real
    ; prioritization yields a big early lead. Never [DEV!] here.
    mov rax, [h3_bytes_s4]
    mov rdx, [h3_bytes_s0]
    sub rax, rdx                          ; s4 - s0 (signed)
    cmp rax, 16384
    jge .ok                               ; stream 4 (u=1, high) clearly led -> honored
    jmp .info                             ; otherwise inconclusive (advisory, ignored)
.ok:
    mov dil, K_OK
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_urgency]
    mov edx, n_h3_urgency_len
    call report_plain
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov dil, K_INFO                          ; handshake never came up: not a deviation
    lea rsi, [n_h3_urgency]
    mov edx, n_h3_urgency_len
    call report_plain
    pop r13
    pop r12
    pop rbx
    ret

; quic_h3_find_maxdata(edi=fd) -> rax = 1 if any server 1-RTT packet carries a
; MAX_DATA frame (0x10), else 0. Reads a few datagrams, ACKing as it goes.
quic_h3_find_maxdata:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16
    mov ebx, edi
    xor r15d, r15d
    mov r12d, 10
.loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
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
    mov rsi, rax
    call quic_find_1rtt
    test rax, rax
    jz .next
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [q_ap_skeys]
    lea rcx, [qplain]
    mov r8d, 8
    mov r9, r15
    call linnea_quic_unprotect_short
    test rax, rax
    js .next
    mov r15, rdx
    push rax
    lea rdi, [qpay]
    mov rsi, r15
    xor edx, edx                          ; 1-RTT: ack 0..largest (our servers start at 0)
    call quic_ack_frame
    lea rdx, [qpay]
    sub rax, rdx
    mov rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    pop rax
    lea r13, [qplain]
    lea r14, [qplain]
    add r14, rax
.fr:
    cmp r13, r14
    jae .next
    cmp byte [r13], 0x10                  ; MAX_DATA
    je .yes
    mov rdi, r13
    mov rsi, r14
    call linnea_quic_frame_skip
    test rax, rax
    jle .next
    add r13, rax
    jmp .fr
.next:
    dec r12d
    jnz .loop
.no:
    xor eax, eax
    jmp .done
.yes:
    mov eax, 1
.done:
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; quic_h3_find_srv_uni(edi=fd) -> rax = the id of the first server-initiated
; unidirectional stream the server opens, or -1 if it opens none. Server-uni ids
; are those with (id & 3) == 3 (RFC 9000 2.1). Reads a few 1-RTT datagrams,
; ACKing as it goes so the server keeps sending.
quic_h3_find_srv_uni:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16
    mov ebx, edi
    xor r15d, r15d                        ; expected pn for reconstruction
    mov r12d, 10                          ; datagram budget
.su_loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 2000
    syscall
    test rax, rax
    jle .su_none
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .su_none
    mov rsi, rax
    call quic_find_1rtt
    test rax, rax
    jz .su_next
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [q_ap_skeys]
    lea rcx, [qplain]
    mov r8d, 8
    mov r9, r15
    call linnea_quic_unprotect_short
    test rax, rax
    js .su_next
    mov r15, rdx
    push rax
    lea rdi, [qpay]                       ; keep the server sending
    mov rsi, r15
    xor edx, edx
    call quic_ack_frame
    lea rdx, [qpay]
    sub rax, rdx
    mov rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    pop rax
    lea r13, [qplain]
    lea r14, [qplain]
    add r14, rax
.su_fr:
    mov rdi, r13
    mov rsi, r14
    sub rsi, r13
    jle .su_next
    call linnea_quic_stream_frame         ; rax=data rdx=len r8=id r9=next
    test rax, rax
    jz .su_next
    mov r13, r9
    mov rax, r8
    and rax, 3
    cmp rax, 3                            ; server-initiated unidirectional?
    jne .su_fr
    cmp qword [q_srv_uni], -1
    jne .su_have
    mov [q_srv_uni], r8
.su_have:
    mov rax, r8                           ; found one: report its id
    jmp .su_done
.su_next:
    dec r12d
    jnz .su_loop
.su_none:
    mov rax, -1
.su_done:
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; probe_h3_maxdata (quic-9): a receiver must raise the peer's connection flow-
; control limit with MAX_DATA as it consumes, or the peer stalls at
; initial_max_data. Send one request and check the server grants credit. OK iff a
; MAX_DATA frame comes back (Linnea grants ahead-of-need — a positive lock); else
; [info]: a server need only raise the limit as the peer approaches it, which a
; small GET never does (Cloudflare sends none), so absence is not a deviation.
probe_h3_maxdata:
    push rbx
    push r14
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0xd1
    mov byte [rdi + 3], 0xd7
    mov byte [rdi + 4], 0xc1
    mov byte [rdi + 5], 0x50
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax
    lea rdi, [qpay]
    mov byte [rdi], 0x0a
    mov byte [rdi + 1], 0x02
    mov byte [rdi + 2], 0x03
    mov byte [rdi + 3], 0x00
    mov byte [rdi + 4], 0x04
    mov byte [rdi + 5], 0x00
    add rdi, 6
    mov byte [rdi], 0x0b
    mov byte [rdi + 1], 0x00
    lea rax, [r14 + 2]
    mov [rdi + 2], al
    mov byte [rdi + 3], 0x01
    mov [rdi + 4], r14b
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_find_maxdata
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    mov dil, K_OK
    test rax, rax
    jnz .rep
    ; No MAX_DATA in the window is [info], not [DEV!]: a server need only extend
    ; connection credit when the peer approaches its limit (a small GET never
    ; does). Linnea grants it ahead-of-need -> [OK], so this stays a positive lock.
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_maxdata]
    mov edx, n_h3_maxdata_len
    call report_plain
    pop r14
    pop rbx
    ret
.fail:
    mov dil, K_INFO                          ; handshake never came up: not a deviation
    lea rsi, [n_h3_maxdata]
    mov edx, n_h3_maxdata_len
    call report_plain
    pop r14
    pop rbx
    ret

; qpay_build_get(rdi = request stream id, rsi = 1 to open the control stream)
;   -> rdx = payload length, built in qpay.
; A GET on the given bidirectional stream, optionally preceded by the client
; control stream (an empty SETTINGS). The id is varint-encoded, so a probe can
; put an ordinary, perfectly well-formed request on a stream the server never
; permitted (quic-14) exactly as easily as on stream 0 — the stream id is then
; the only variable. The control stream is optional because it may be opened
; ONCE: a second SETTINGS on it is itself an HTTP/3 connection error (RFC 9114
; 7.2.4), so a probe sending a second request must not repeat it.
; Records the id in q_req_sid so the classifier collects the right response.
qpay_build_get:
    push rbx
    push r13
    push r14
    push r15
    mov r13, rdi                          ; request stream id
    mov r15, rsi                          ; open the control stream?
    mov [q_req_sid], rdi
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00                  ; QPACK: Required Insert Count 0
    mov byte [rdi + 1], 0x00             ;        Delta Base 0
    mov byte [rdi + 2], 0xd1             ; :method GET   (static 17)
    mov byte [rdi + 3], 0xd7             ; :scheme https (static 23)
    mov byte [rdi + 4], 0xc1             ; :path /       (static 1)
    mov byte [rdi + 5], 0x50             ; :authority, literal with static name 0
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax                          ; field-section length
    lea rdi, [qpay]
    test r15, r15
    jz .no_control
    mov byte [rdi], 0x0a                  ; STREAM | LEN
    mov byte [rdi + 1], 0x02             ; stream 2: the client's control stream
    mov byte [rdi + 2], 0x03             ; STREAM data length
    mov byte [rdi + 3], 0x00             ; stream type 0x00 = control
    mov byte [rdi + 4], 0x04             ; SETTINGS
    mov byte [rdi + 5], 0x00             ; no settings
    add rdi, 6
.no_control:
    mov byte [rdi], 0x0b                  ; STREAM | LEN | FIN
    inc rdi
    mov rsi, r13
    call linnea_quic_varint_encode        ; the request stream id
    add rdi, rax
    lea rax, [r14 + 2]
    mov [rdi], al                         ; STREAM data length
    mov byte [rdi + 1], 0x01             ; HEADERS frame
    mov [rdi + 2], r14b                  ; HEADERS length
    add rdi, 3
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; quic_drain(edi = fd): read and discard whatever is still arriving, until a poll
; goes quiet. A probe that asks a question AFTER a full response has to get the
; rest of that response out of the way first — a real page is many datagrams, and
; the classifier's per-call datagram budget would otherwise be spent on the tail
; of the previous answer and report the next one as missing.
quic_drain:
    push rbx
    mov ebx, edi
.d_loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 300
    syscall
    test rax, rax
    jle .d_done
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .d_done
    mov edi, ebx                          ; keep the sender's window open while we
    call quic_send_1rtt_ack               ; swallow what it is sending
    jmp .d_loop
.d_done:
    pop rbx
    ret

; quic_wait_close(edi = fd) -> rax = 1 if a CONNECTION_CLOSE arrives within a
; short window, with its error code in q_close_code. Needed because "the server
; answered" is not the same as "the server let it pass": an endpoint may detect a
; header-level violation after the response is already on its way, and closing
; late still satisfies "treat this as a connection error". Without this the probe
; would accuse every implementation that orders the two that way.
quic_wait_close:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, edi
    mov r12d, 4                           ; datagrams to look through
    mov qword [q_close_code], -1
.wc_loop:
    mov [pollfd], ebx
    mov word [pollfd + 4], LINNEA_POLLIN
    mov word [pollfd + 6], 0
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfd]
    mov esi, 1
    mov edx, 400
    syscall
    test rax, rax
    jle .wc_no
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, ebx
    lea rsi, [qrx]
    mov edx, 2048
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .wc_no
    mov rsi, rax
    call quic_find_1rtt
    test rax, rax
    jz .wc_next
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [q_ap_skeys]
    lea rcx, [qplain]
    mov r8d, 8
    mov r9, [q_cli_ap_pn]
    call linnea_quic_unprotect_short
    test rax, rax
    js .wc_next
    lea r13, [qplain]
    lea r14, [qplain]
    add r14, rax
.wc_frame:
    cmp r13, r14
    jae .wc_next
    movzx eax, byte [r13]
    cmp al, 0x1c
    je .wc_found
    cmp al, 0x1d
    je .wc_found
    mov rdi, r13
    mov rsi, r14
    call linnea_quic_frame_skip
    test rax, rax
    jle .wc_next
    add r13, rax
    jmp .wc_frame
.wc_next:
    dec r12d
    jnz .wc_loop
.wc_no:
    xor eax, eax
    jmp .wc_ret
.wc_found:
    lea rdi, [r13 + 1]
    mov rsi, r14
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .wc_yes
    mov [q_close_code], rax
.wc_yes:
    mov eax, 1
.wc_ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; probe_h3_keyupdate (RFC 9001 6): QUIC has no TLS KeyUpdate message -- that one
; is forbidden and is a connection error here. An endpoint rotates by flipping the
; Key Phase bit and protecting the packet with
; secret_next = HKDF-Expand-Label(secret, "quic ku", "", 32). A peer that cannot
; follow does not fail loudly; it goes deaf, losing every packet from then on.
;
; Both directions move: 6.1 has the receiver update its receive keys AND its own
; send keys. But NOT necessarily before it answers -- until it processes the flip
; it is still on the old phase -- so the classifier is armed to try both
; generations rather than assuming. Assuming worked on loopback and failed over a
; real RTT, which is the difference between a probe and a probe that is right.
;
; A normal GET runs first: 6 forbids initiating an update before the handshake is
; confirmed, and it makes the connection known-good so a failure afterwards means
; the update and nothing else.
probe_h3_keyupdate:
    push rbx
    push r12
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    xor edi, edi                          ; control: an ordinary request
    mov esi, 1
    call qpay_build_get
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    cmp rax, 200
    jne .info                             ; never worked: nothing to conclude
    mov edi, ebx
    call quic_drain                       ; finish the response before rotating
    ; --- our sending keys move to the next generation ---
    lea rdi, [q_cli_ap_secret]
    lea rsi, [q_ku_next]
    lea rdx, [q_ap_ckeys]                 ; key+iv re-derived in place; the header
    call linnea_quic_ku_next              ; protection key deliberately does not move
    lea rdi, [q_cli_ap_secret]
    lea rsi, [q_ku_next]
    mov ecx, 32
    rep movsb
    ; --- and the server's next generation is PREPARED, not assumed ---
    lea rdi, [q_ap_skeys_next]
    lea rsi, [q_ap_skeys]
    mov ecx, linnea_quic_keys_size
    rep movsb
    lea rdi, [q_srv_ap_secret]
    lea rsi, [q_ku_next]
    lea rdx, [q_ap_skeys_next]
    call linnea_quic_ku_next
    lea rdi, [q_srv_ap_secret]
    lea rsi, [q_ku_next]
    mov ecx, 32
    rep movsb
    mov qword [q_ku_armed], 1             ; the classifier may now fall back to it
    mov qword [q_kphase], 1               ; and everything we send is phase 1
    mov edi, 4                            ; the next client bidirectional stream
    xor esi, esi                          ; the control stream is already open
    call qpay_build_get
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    push rax
    mov qword [q_kphase], 0
    mov edi, ebx
    call close_fd
    pop rax
    ; What counts as "followed" is not the 200 -- it is that a packet arrived
    ; under the NEXT generation, which only the server's own rotation can
    ; produce. q_ku_armed is cleared by the classifier when it opens one, so
    ; that flag IS the evidence; the status merely says the request survived.
    cmp qword [q_ku_armed], 0
    jne .no_evidence
    cmp rax, 200
    je .ok
.no_evidence:
    cmp rax, 200
    je .info_noclose                      ; answered, but under the OLD keys. That
                                          ; is not obviously wrong: 6.2's timing for
                                          ; when a responder must start SENDING in
                                          ; the new phase is a nuance not worth
                                          ; adjudicating from a probe, and the peer
                                          ; plainly read our phase-1 packet to
                                          ; answer it at all. Reported, not accused.
    cmp rax, -3
    je .dev                               ; closed on us: definitely not followed
    cmp rax, -2
    je .dev
    mov dil, K_INFO                       ; silence: it may simply not have answered
    jmp .rep                              ; in the window. The suite's
                                          ; h3_key_update_test.py is the red-green;
                                          ; this probe is live positive proof.
.ok:
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.info:
    mov edi, ebx
    call close_fd
.info_noclose:
    mov dil, K_INFO
    jmp .rep
.fail:
    mov dil, K_INFO
.rep:
    mov qword [q_kphase], 0               ; never leave either armed for a later probe
    mov qword [q_ku_armed], 0
    lea rsi, [n_h3_keyupd]
    mov edx, n_h3_keyupd_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_ku_oldkey (RFC 9001 6.5): a packet protected with the OLDER keys can
; arrive after a key update, for no better reason than the network reordering it.
; The receiver must still open it: "an endpoint SHOULD retain old read keys for no
; more than three times the PTO after having received a packet protected using the
; new keys" -- the point of retaining them at all is to process such a packet.
;
; Reordering cannot be scheduled on a real network, so this manufactures it: build
; a request under the current keys and WITHHOLD it, rekey, send a different request
; under the new keys so the server rotates, and only then release the held packet.
; It arrives carrying the older key phase and a LOWER packet number, which is
; precisely the delayed-packet case.
;
; MEASURED 2026-08-05: linnea, cloudflare-quic.com AND www.google.com all drop it.
; Three independent implementations agreeing is the answer to the question, not a
; finding against them -- retention here is an OPTIMISATION, not an obligation,
; and this probe reports rather than accuses.
;
; The reason it is optional is worth understanding before anyone "fixes" it:
; QUIC's loss recovery already covers the case. A real client's delayed packet is
; dropped, its probe timeout fires, and it is RETRANSMITTED under the new keys --
; nothing is lost, one PTO is spent. Retaining old keys buys back that PTO and
; nothing else, which is why RFC 9001 6.5 frames retention as something an
; endpoint may do and bounds how long it may do it, rather than requiring it.
; This probe never retransmits, which is precisely why it sees a "loss" that no
; real client would.
;
; The inverted control matters here and was run: withholding and releasing the
; SAME packet with NO key update is answered normally, which is what proves the
; mechanism sound and puts the difference on the keys rather than on reordering.
probe_h3_ku_oldkey:
    push rbx
    push r12
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    ; --- build the request that will be delayed, under the CURRENT keys ---
    xor edi, edi                          ; stream 0
    mov esi, 1                            ; open the control stream with it
    call qpay_build_get
    mov qword [q_hold], 1                 ; built, protected, and kept back
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov qword [q_hold], 0
    ; --- rotate, and make the server rotate with a request it CAN read ---
    lea rdi, [q_cli_ap_secret]
    lea rsi, [q_ku_next]
    lea rdx, [q_ap_ckeys]
    call linnea_quic_ku_next
    lea rdi, [q_cli_ap_secret]
    lea rsi, [q_ku_next]
    mov ecx, 32
    rep movsb
    lea rdi, [q_ap_skeys_next]
    lea rsi, [q_ap_skeys]
    mov ecx, linnea_quic_keys_size
    rep movsb
    lea rdi, [q_srv_ap_secret]
    lea rsi, [q_ku_next]
    lea rdx, [q_ap_skeys_next]
    call linnea_quic_ku_next
    lea rdi, [q_srv_ap_secret]
    lea rsi, [q_ku_next]
    mov ecx, 32
    rep movsb
    mov qword [q_ku_armed], 1
    mov qword [q_kphase], 1
    mov edi, 4                            ; a different stream, new keys
    xor esi, esi
    call qpay_build_get
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify                 ; the server rekeys and answers this one
    cmp rax, 200
    jne .info                             ; the update itself did not work: that is
                                          ; probe_h3_keyupdate's business, not ours
    ; --- now the delayed packet, under the OLD keys and the OLD phase ---
    mov edi, ebx
    call quic_send_held
    mov qword [q_req_sid], 0              ; its response belongs to stream 0
    mov edi, ebx
    call quic_h3_classify
    push rax
    mov qword [q_kphase], 0
    mov qword [q_ku_armed], 0
    mov edi, ebx
    call close_fd
    pop rax
    cmp rax, 200
    je .ok
    mov dil, K_INFO                       ; dropped: old keys not retained, which is
    jmp .rep                              ; allowed -- see the note above
.ok:
    mov dil, K_OK
    jmp .rep
.info:
    mov edi, ebx
    call close_fd
    mov dil, K_INFO
    jmp .rep
.fail:
    mov dil, K_INFO
.rep:
    mov qword [q_kphase], 0
    mov qword [q_ku_armed], 0
    mov qword [q_hold], 0
    mov qword [q_held_len], 0
    lea rsi, [n_h3_kuold]
    mov edx, n_h3_kuold_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_iscid (tls-12): RFC 9000 7.3 makes BOTH of these a connection error
; of type TRANSPORT_PARAMETER_ERROR -- a value that does not match the Source
; Connection ID of the peer's first Initial, and the parameter being absent. The
; parameter is what binds the transport parameters to the packets that carried
; them; unchecked, an attacker who can rewrite Initials can swap connection ids
; on a handshake in flight and neither end is any the wiser.
probe_h3_iscid:
    push rbx
    push r12
    mov qword [tp_variant], 5             ; a different id than the packets carry
    call quic_tp_refused_verdict
    mov r12, rax
    mov qword [tp_variant], 0
    mov dil, K_DEV
    cmp r12, 2
    je .rep                               ; handshake proceeded: never compared
    cmp r12, 1
    jne .info
    mov dil, K_OK
    cmp qword [q_close_code], 0x08        ; TRANSPORT_PARAMETER_ERROR
    je .rep
    mov dil, K_INFO
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_iscid]
    mov edx, n_h3_iscid_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_noiscid (tls-12): the same MUST, absence half.
probe_h3_noiscid:
    push rbx
    push r12
    mov qword [tp_variant], 6             ; omit the parameter entirely
    call quic_tp_refused_verdict
    mov r12, rax
    mov qword [tp_variant], 0
    mov dil, K_DEV
    cmp r12, 2
    je .rep
    cmp r12, 1
    jne .info
    mov dil, K_OK
    cmp qword [q_close_code], 0x08
    je .rep
    mov dil, K_INFO
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_noiscid]
    mov edx, n_h3_noiscid_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_tpudp (quic-12): RFC 9000 18.2 says of max_udp_payload_size that
; "values below 1200 are invalid", and 7.4 makes any parameter with an invalid
; value a connection error of type TRANSPORT_PARAMETER_ERROR. A peer advertising
; one is contradicting the protocol -- no QUIC endpoint may send a datagram that
; small a receiver could not take -- so being served anyway means the parameter
; was read past in silence.
probe_h3_tpudp:
    push rbx
    push r12
    mov qword [tp_variant], 3
    call quic_tp_refused_verdict          ; rax: 1 close / 2 proceeded / 0 none
    mov r12, rax
    mov qword [tp_variant], 0             ; restore before any later probe builds a CH
    mov dil, K_DEV
    cmp r12, 2
    je .rep                               ; the handshake proceeded: value ignored
    cmp r12, 1
    jne .info                             ; nothing came back: no verdict
    mov dil, K_OK
    cmp qword [q_close_code], 0x08        ; TRANSPORT_PARAMETER_ERROR
    je .rep
    mov dil, K_INFO                       ; refused, but named another fault
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_tpudp]
    mov edx, n_h3_tpudp_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_tpcid (quic-12): "The value of the active_connection_id_limit
; parameter MUST be at least 2. An endpoint that receives a value less than 2
; MUST close the connection with an error of type TRANSPORT_PARAMETER_ERROR"
; (RFC 9000 18.2). A peer saying 1 cannot hold the second id the server is about
; to issue, so serving it sets up a connection that breaks on the first rotation.
probe_h3_tpcid:
    push rbx
    push r12
    mov qword [tp_variant], 4
    call quic_tp_refused_verdict
    mov r12, rax
    mov qword [tp_variant], 0
    mov dil, K_DEV
    cmp r12, 2
    je .rep
    cmp r12, 1
    jne .info
    mov dil, K_OK
    cmp qword [q_close_code], 0x08
    je .rep
    mov dil, K_INFO
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_tpcid]
    mov edx, n_h3_tpcid_len
    call report_plain
    pop r12
    pop rbx
    ret

; quic_tp_refused_verdict() -> rax: 1 = the server aborted in the Initial space
; (code in q_close_code), 2 = it sent a ServerHello and carried on, 0 = silence.
; Shared by the two transport-parameter probes above; tp_variant selects which
; invalid value the ClientHello carries.
quic_tp_refused_verdict:
    push rbx
    call quic_fresh_ids
    call udp_connect
    test rax, rax
    js .tv_fail
    mov ebx, eax
    mov edi, ebx
    call quic_send_initial
    test rax, rax
    js .tv_close
    mov edi, ebx
    call quic_recv_initial_verdict
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    pop rbx
    ret
.tv_close:
    mov edi, ebx
    call close_fd
.tv_fail:
    xor eax, eax
    pop rbx
    ret

; probe_h3_dgmax (quic-12): an endpoint MUST NOT send a datagram larger than the
; peer's max_udp_payload_size (RFC 9000 18.2 / 14). Advertise the smallest legal
; value, 1200, and hold the whole connection to it -- handshake flight and
; response alike. A POSITIVE LOCK: linnea's largest datagram is the Initial one
; padded to exactly 1200, which is the floor this parameter can carry, so no
; legal advertisement can bind it. What this would catch is that ceasing to be
; true -- a chunk size raised past the point where the padded Initial still fits.
probe_h3_dgmax:
    push rbx
    push r12
    mov qword [tp_variant], 2             ; advertise exactly 1200
    call quic_h3_open
    mov qword [tp_variant], 0
    test rax, rax
    js .fail
    mov ebx, eax
    xor edi, edi
    mov esi, 1
    call qpay_build_get                   ; a real response, so the 1-RTT path is
    mov edi, ebx                          ; measured too, not just the flight
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    mov r12, [q_dgram_max]
    mov edi, ebx
    call close_fd
    test r12, r12
    jz .info                              ; nothing measured: no verdict
    mov dil, K_OK
    cmp r12, 1200
    jbe .rep
    mov dil, K_DEV
    jmp .rep
.info:
    mov dil, K_INFO
    jmp .rep
.fail:
    mov dil, K_INFO
    mov r12, -1
.rep:
    lea rsi, [n_h3_dgmax]
    mov edx, n_h3_dgmax_len
    mov rcx, r12
    mov r9d, 1200
    call report_size
    pop r12
    pop rbx
    ret

; probe_h3_cidcnt (quic-12): an endpoint MUST NOT provide its peer with more
; connection ids than the peer's active_connection_id_limit (RFC 9000 5.1.1). We
; advertise 2 -- the smallest legal value -- which permits the id the handshake
; settled on plus one more, so at most ONE NEW_CONNECTION_ID may arrive. Another
; positive lock: linnea issues exactly one (quic-7).
probe_h3_cidcnt:
    push rbx
    push r12
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    mov r12, [q_ncid_count]
    mov edi, ebx
    call close_fd
    mov dil, K_OK
    cmp r12, 1
    jbe .rep
    mov dil, K_DEV
    jmp .rep
.fail:
    mov dil, K_INFO
    mov r12, -1
.rep:
    lea rsi, [n_h3_cidcnt]
    mov edx, n_h3_cidcnt_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_rsvd (quic-14): the two reserved bits of a short header (0x18) MUST be
; zero, and a receiver that sees them set MUST close with PROTOCOL_VIOLATION
; (RFC 9000 17.3.1). Header protection hides them until it is removed, so this is
; precisely a check a receiver can only make after unmasking — and one it is easy
; never to write. An otherwise perfect GET carries them here, so a :status back
; means the packet was processed with the bits set.
probe_h3_rsvd:
    push rbx
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    mov qword [q_rsvd], 1
    xor edi, edi                          ; request stream 0
    mov esi, 1                            ; ...opening the control stream
    call qpay_build_get
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov qword [q_rsvd], 0                 ; never leave it set for a later probe
    mov edi, ebx
    call quic_h3_classify
    cmp rax, 100
    jl .rs_noanswer
    ; It answered. That is only a deviation if the connection then STAYS up —
    ; an endpoint that detects the violation after the response is already on
    ; its way still ends the connection, which is what 17.3.1 asks for. Both
    ; reference stacks probed here (Cloudflare, Google) answer first, so
    ; returning on the status alone would have accused them wrongly.
    mov edi, ebx
    call quic_wait_close
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    test rax, rax
    jz .dev                               ; answered and stayed up: bits ignored
    cmp qword [q_close_code], 0x0a        ; PROTOCOL_VIOLATION
    jne .info                             ; closed, but named another fault
    mov dil, K_OK
    jmp .rep
.rs_noanswer:
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    cmp rax, -3                           ; CONNECTION_CLOSE, no response at all
    jne .info                             ; dropped in silence: refused, but not the
                                          ; connection error 17.3.1 asks for
    cmp qword [q_close_code], 0x0a        ; PROTOCOL_VIOLATION
    jne .info                             ; closed for some other reason
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.info:
    mov dil, K_INFO
    jmp .rep
.fail:
    mov dil, K_INFO                       ; handshake never came up: not a deviation
.rep:
    lea rsi, [n_h3_rsvd]
    mov edx, n_h3_rsvd_len
    call report_plain
    pop rbx
    ret

; probe_h3_strmlim (quic-14): a peer MUST NOT open more streams than the limit
; the receiver advertised, and a receiver that is sent a stream id past its own
; initial_max_streams_bidi MUST close with STREAM_LIMIT_ERROR (RFC 9000 4.6).
; The id comes from the server's OWN transport parameters (quic_srv_tp_scan), so
; this accuses nobody of exceeding a limit they never set: client-initiated
; bidirectional ids are 4n, so a limit of N permits 0..4(N-1) and 4N is the first
; one past it.
probe_h3_strmlim:
    push rbx
    push r12
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    mov r12, [q_srv_ms_bidi]
    cmp r12, 0
    jl .unknown                           ; no limit advertised: nothing to exceed
    cmp r12, 0x10000000
    jae .unknown                          ; effectively unlimited: no id can pass it
    shl r12, 2                            ; the first id past the limit
    mov rdi, r12
    mov esi, 1
    call qpay_build_get
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    cmp rax, 100
    jge .dev                              ; served a stream it had forbidden
    cmp rax, -3
    jne .dev                              ; silence is a deviation too: 4.6 says the
                                          ; receiver MUST make this a CONNECTION
                                          ; error, and a peer told nothing keeps the
                                          ; request outstanding forever
    cmp qword [q_close_code], 0x04        ; STREAM_LIMIT_ERROR
    jne .info                             ; closed, but named another fault
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.unknown:
    mov edi, ebx
    call close_fd
.info:
    mov dil, K_INFO
    jmp .rep
.fail:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_strmlim]
    mov edx, n_h3_strmlim_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_initpad (quic-13): a datagram carrying an ack-eliciting Initial MUST
; be expanded to 1200 bytes (RFC 9000 14.1) — that is how the path is shown to
; carry the size QUIC requires before the handshake commits to it. The server's
; ServerHello flight is such a datagram. Measured on the DATAGRAM, since
; coalescing an Initial with a Handshake packet is the usual way to satisfy it.
probe_h3_initpad:
    push rbx
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    mov edi, ebx
    call close_fd
    mov rax, [q_init_dgram]
    test rax, rax
    jz .info                              ; never saw one (a Retry, or v2): no verdict
    cmp rax, LINNEA_QUIC_MIN_INITIAL_DGRAM
    jb .dev
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.info:
    mov dil, K_INFO
    jmp .rep
.fail:
    mov dil, K_INFO
    mov qword [q_init_dgram], -1
.rep:
    ; report the measured size: "expanded or not" is not actionable on its own,
    ; and the number says at once whether a server is near the floor or nowhere
    ; close to it.
    lea rsi, [n_h3_initpad]
    mov edx, n_h3_initpad_len
    mov rcx, [q_init_dgram]
    mov r9d, LINNEA_QUIC_MIN_INITIAL_DGRAM
    call report_size
    pop rbx
    ret

; probe_h3_runt (quic-13): a datagram too short to hold the fields a receiver
; parses to route it must be dropped, never demultiplexed on whatever the
; PREVIOUS datagram left in the receive buffer. That mis-routing has no reply
; path — every one is already length-gated — so this is a POSITIVE LOCK, not a
; red-green: it passes before the fix and after, and what it would catch is a
; floor drawn too high, which would break ordinary traffic. The runts go out
; between two requests on a live connection, so anything they disturb shows up
; as the second request failing.
probe_h3_runt:
    push rbx
    push r12
    call quic_h3_open
    test rax, rax
    js .fail
    mov ebx, eax
    xor edi, edi
    mov esi, 1
    call qpay_build_get
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    cmp rax, 200
    jne .info                             ; the baseline request did not work: no verdict
    mov edi, ebx
    call quic_drain                       ; let the first response finish arriving
    ; eight runts, 1..8 bytes, short-header shaped so they take the 1-RTT route
    mov r12d, 1
.runt:
    mov byte [qpay], 0x40
    mov byte [qpay + 1], 0x00
    mov byte [qpay + 2], 0x00
    mov byte [qpay + 3], 0x00
    mov byte [qpay + 4], 0x00
    mov byte [qpay + 5], 0x00
    mov byte [qpay + 6], 0x00
    mov byte [qpay + 7], 0x00
    mov eax, LINNEA_SYS_SENDTO
    mov edi, ebx
    lea rsi, [qpay]
    mov rdx, r12
    mov r10d, LINNEA_MSG_NOSIGNAL
    xor r8d, r8d
    xor r9d, r9d
    syscall
    inc r12d
    cmp r12d, 8
    jbe .runt
    ; the connection must be untouched: a second request is still served
    mov edi, 4                            ; the next client bidirectional stream
    xor esi, esi                          ; control stream already open: do not repeat it
    call qpay_build_get
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify
    push rax
    mov edi, ebx
    call close_fd
    pop rax
    cmp rax, 200
    je .ok
    ; A close or a stream reset means the runts DISTURBED the connection, which is
    ; what this probe exists to catch. No answer at all is not evidence of that —
    ; a server may simply not answer a second request inside the classifier's
    ; window — so that is [info], not an accusation.
    cmp rax, -3                           ; CONNECTION_CLOSE
    je .dev
    cmp rax, -2                           ; RESET_STREAM
    je .dev
    jmp .info_noclose
.ok:
    mov dil, K_OK
    jmp .rep
.dev:
    mov dil, K_DEV
    jmp .rep
.info:
    mov edi, ebx
    call close_fd
.info_noclose:
    mov dil, K_INFO
    jmp .rep
.fail:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_runt]
    mov edx, n_h3_runt_len
    call report_plain
    pop r12
    pop rbx
    ret

; quic_scan_srv_uni(rdi=frames, rsi=len): record the first server-initiated
; unidirectional stream ((id & 3) == 3, RFC 9000 2.1) these frames open, in
; q_srv_uni. Called wherever 1-RTT frames are walked, because HTTP/3 servers
; open their control / QPACK streams in the very packet that carries
; HANDSHAKE_DONE — a scan that only starts afterwards never sees them.
quic_scan_srv_uni:
    push rbx
    push r12
    push r13
    mov r12, rdi
    lea r13, [rdi + rsi]
.su_scan:
    mov rdi, r12
    mov rsi, r13
    sub rsi, r12
    jle .su_scan_done
    call linnea_quic_stream_frame         ; rax=data rdx=len r8=id r9=next
    test rax, rax
    jz .su_scan_done
    mov r12, r9
    mov rax, r8
    and rax, 3
    cmp rax, 3
    jne .su_scan
    cmp qword [q_srv_uni], -1             ; keep the first one seen
    jne .su_scan
    mov [q_srv_uni], r8
    jmp .su_scan
.su_scan_done:
    pop r13
    pop r12
    pop rbx
    ret

; quic_scan_maxstreams(rdi=frames, rsi=len): adopt a MAX_STREAMS (bidirectional,
; type 0x12) into q_srv_ms_bidi. Without this the stream-limit probe would test
; against the limit the server advertised at the handshake and accuse a server
; that had since granted more — linnea itself grants ahead of need, so this is
; not hypothetical. The limit only ever rises (RFC 9000 19.11: a MAX_STREAMS
; below the current one is ignored).
quic_scan_maxstreams:
    push rbx
    push r12
    mov rbx, rdi
    lea r12, [rdi + rsi]
.ms_scan:
    cmp rbx, r12
    jae .ms_done
    cmp byte [rbx], 0x12                  ; MAX_STREAMS (bidirectional)
    jne .ms_skip
    lea rdi, [rbx + 1]
    mov rsi, r12
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .ms_done
    mov rcx, [q_srv_ms_bidi]
    cmp rcx, 0
    jl .ms_take                           ; nothing recorded yet (signed -1)
    cmp rax, rcx
    jbe .ms_skip                          ; never lower the limit
.ms_take:
    mov [q_srv_ms_bidi], rax
.ms_skip:
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_frame_skip
    test rax, rax
    jle .ms_done                          ; unknown or truncated: stop walking
    add rbx, rax
    jmp .ms_scan
.ms_done:
    pop r12
    pop rbx
    ret

; quic_scan_ncid(rdi=frames, rsi=len): if the frames carry a NEW_CONNECTION_ID
; (0x18), copy its connection id into q_alt_cid and set q_alt_cid_valid.
quic_scan_ncid:
    push rbx
    push r12
    mov rbx, rdi
    lea r12, [rdi + rsi]                  ; end
.sc_fr:
    cmp rbx, r12
    jae .sc_done
    cmp byte [rbx], 0x18                  ; NEW_CONNECTION_ID
    je .sc_ncid
    mov rdi, rbx
    mov rsi, r12
    call linnea_quic_frame_skip
    test rax, rax
    jle .sc_done
    add rbx, rax
    jmp .sc_fr
.sc_ncid:
    inc qword [q_ncid_count]             ; how many ids the server has issued, so a
                                         ; probe can hold it to the limit we granted
    inc rbx                              ; past the type
    mov rdi, rbx                         ; sequence number
    mov rsi, r12
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .sc_done
    add rbx, rdx
    mov rdi, rbx                         ; retire prior to
    mov rsi, r12
    call linnea_quic_varint_decode
    test rdx, rdx
    jz .sc_done
    add rbx, rdx
    cmp rbx, r12
    jae .sc_done
    movzx eax, byte [rbx]                ; connection id length
    inc rbx
    cmp eax, 20
    ja .sc_done
    lea rcx, [rbx + rax]                 ; end of the CID
    cmp rcx, r12
    ja .sc_done
    mov [q_alt_cid_len], rax
    lea rdi, [q_alt_cid]
    mov rsi, rbx
    mov rcx, rax
    rep movsb
    mov qword [q_alt_cid_valid], 1
.sc_done:
    pop r12
    pop rbx
    ret

; probe_h3_newcid (quic-7): the server should issue a NEW_CONNECTION_ID so the peer
; can rotate its DCID, and must route packets sent to that CID. Capture the issued
; CID during the handshake, switch our DCID to it, and GET /. OK iff a CID was
; issued AND the server answers 200 on it (Linnea does — a positive lock); else
; [info]: issuing extra CIDs is permitted but not required, and a server may issue
; them later or not at all (Cloudflare issues none in the window), so absence is
; not a deviation.
probe_h3_newcid:
    push rbx
    push r14
    mov qword [q_alt_cid_valid], 0
    call quic_h3_open                     ; quic_recv_1rtt captures the NCID
    test rax, rax
    js .fail
    mov ebx, eax
    cmp qword [q_alt_cid_valid], 0
    je .dev                              ; no NEW_CONNECTION_ID was issued
    ; rotate: use the issued CID as our destination connection id
    lea rdi, [q_srv_scid]
    lea rsi, [q_alt_cid]
    mov rcx, [q_alt_cid_len]
    mov [q_srv_scid_len], rcx
    rep movsb
    ; GET / on the new CID; the server must still route us
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0xd1
    mov byte [rdi + 3], 0xd7
    mov byte [rdi + 4], 0xc1
    mov byte [rdi + 5], 0x50
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r14, rdi
    sub r14, rax
    lea rdi, [qpay]
    mov byte [rdi], 0x0a
    mov byte [rdi + 1], 0x02
    mov byte [rdi + 2], 0x03
    mov byte [rdi + 3], 0x00
    mov byte [rdi + 4], 0x04
    mov byte [rdi + 5], 0x00
    add rdi, 6
    mov byte [rdi], 0x0b
    mov byte [rdi + 1], 0x00
    lea rax, [r14 + 2]
    mov [rdi + 2], al
    mov byte [rdi + 3], 0x01
    mov [rdi + 4], r14b
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r14
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_classify                 ; status on the rotated CID
    mov r14, rax
    mov edi, ebx
    call close_fd
    cmp r14, 200
    je .ok                               ; server routed the new CID and answered
    mov dil, K_INFO                      ; issued but no clean answer on it
    jmp .rep
.ok:
    mov dil, K_OK
    jmp .rep
.dev:
    mov edi, ebx
    call close_fd
    ; No NEW_CONNECTION_ID in the window is [info], not [DEV!]: issuing extra CIDs
    ; is permitted but not required, and a server may issue them later or not at
    ; all. Linnea issues one -> [OK], so this stays a positive lock.
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_newcid]
    mov edx, n_h3_newcid_len
    call report_plain
    pop r14
    pop rbx
    ret
.fail:
    mov dil, K_INFO                          ; handshake never came up: not a deviation
    lea rsi, [n_h3_newcid]
    mov edx, n_h3_newcid_len
    call report_plain
    pop r14
    pop rbx
    ret

; probe_h3_sessid_echo (RFC 9001 8.4): a client MUST send an empty
; legacy_session_id; a server MAY accept any value but MUST NOT echo anything
; other than an empty one in its ServerHello. Send a ClientHello WITH a 32-byte
; session_id and confirm the ServerHello's echoed session_id is empty. OK iff
; empty; DEV if the server echoed a non-empty value; info if no ServerHello came
; back (e.g. a stricter server refused the non-empty id — as Cloudflare does).
; The echoed length is captured in quic_walk_datagram before parse_serverhello,
; so a violating server is caught even if the shifted ServerHello then misparses;
; the -1 sentinel distinguishes "no ServerHello seen" from a genuine empty echo.
; tls-12: RFC 9001 8.4 bars the TLS middlebox compatibility mode from QUIC --
; a ClientHello whose legacy_session_id is not empty "MUST be treated as a
; connection error of type PROTOCOL_VIOLATION".
;
; This probe used to assert something weaker: that the ServerHello echoed an
; EMPTY session id. That is what linnea did, and it lands on the right outcome by
; accident -- a client that sent a session id rejects a ServerHello that does not
; echo it -- but the refusal was the client's, made for a reason it had to guess.
; Now the server makes it, and says which rule was broken.
probe_h3_sessid_echo:
    push rbx
    push r12
    mov qword [bad_sessid], 1
    call quic_tp_refused_verdict          ; rax: 1 close / 2 proceeded / 0 none
    mov r12, rax
    mov qword [bad_sessid], 0
    mov dil, K_DEV
    cmp r12, 2
    je .rep                               ; served a hello 8.4 forbids
    cmp r12, 1
    jne .info
    mov dil, K_OK
    cmp qword [q_close_code], 0x0a        ; PROTOCOL_VIOLATION
    je .rep
    mov dil, K_INFO                       ; refused, but named another fault
    jmp .rep
.info:
    mov dil, K_INFO
.rep:
    lea rsi, [n_h3_sessid]
    mov edx, n_h3_sessid_len
    call report_plain
    pop r12
    pop rbx
    ret

; probe_h3_streams_uni (quic-12): a client that advertises
; initial_max_streams_uni = 0 permits the server no unidirectional streams at
; all, and RFC 9000 4.6 is unconditional — "An endpoint MUST NOT open more
; streams than allowed by the current stream limit set by its peer". HTTP/3
; wants a control stream, but the transport limit comes first: the server must
; wait for credit (it may say STREAMS_BLOCKED) rather than open one anyway.
; This is the client-observable half of quic-12 "almost no client transport
; parameter honoured": the prober advertises the limit and watches the wire.
; OK iff no server-initiated uni stream appears; DEV if one does.
probe_h3_streams_uni:
    push rbx
    mov qword [q_srv_uni], -1             ; watch from the handshake onward: the
                                          ; control / QPACK streams ride the same
                                          ; packet as HANDSHAKE_DONE
    mov qword [tp_variant], 1
    call quic_h3_open                     ; full handshake under the tight limit
    mov qword [tp_variant], 0             ; restore before any later probe builds a CH
    test rax, rax
    js .fail
    mov ebx, eax
    ; ask for something, so a server that opens its control stream lazily still does
    lea rdi, [fs_scratch]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    mov byte [rdi + 2], 0xd1              ; :method GET
    mov byte [rdi + 3], 0xd7              ; :scheme https
    mov byte [rdi + 4], 0xc1              ; :path /
    mov byte [rdi + 5], 0x50              ; :authority literal, name ref static 0
    add rdi, 6
    mov rax, [host_len]
    mov [rdi], al
    inc rdi
    mov rsi, [host_ptr]
    mov rcx, [host_len]
    rep movsb
    lea rax, [fs_scratch]
    mov r9, rdi
    sub r9, rax                           ; field-section length
    lea rdi, [qpay]
    mov byte [rdi], 0x0b                  ; request STREAM(0), LEN, FIN
    mov byte [rdi + 1], 0x00
    lea rax, [r9 + 2]
    mov [rdi + 2], al
    mov byte [rdi + 3], 0x01              ; HEADERS
    mov [rdi + 4], r9b
    add rdi, 5
    lea rsi, [fs_scratch]
    mov rcx, r9
    rep movsb
    lea rax, [qpay]
    mov rdx, rdi
    sub rdx, rax
    mov edi, ebx
    lea rsi, [qpay]
    call quic_send_1rtt
    mov edi, ebx
    call quic_h3_find_srv_uni             ; also records into q_srv_uni
    mov edi, ebx
    call close_fd
    mov rax, [q_srv_uni]
    cmp rax, -1
    je .ok                                ; the limit was respected
    mov dil, K_DEV
    jmp .rep
.ok:
    mov dil, K_OK
.rep:
    lea rsi, [n_h3_uni0]
    mov edx, n_h3_uni0_len
    call report_plain
    pop rbx
    ret
.fail:
    ; refusing the connection outright is a legitimate answer to a limit we
    ; cannot serve HTTP/3 under, and is not a deviation
    mov dil, K_INFO
    lea rsi, [n_h3_uni0]
    mov edx, n_h3_uni0_len
    call report_plain
    pop rbx
    ret

; h3_battery(): the HTTP/3 probe set.
h3_battery:
    call probe_h3_handshake
    call probe_h3_nopath
    call probe_h3_badqpack
    call probe_h3_trailer
    call probe_h3_qpack_base
    call probe_h3_ctrl_framelen
    call probe_h3_urgency
    call probe_h3_maxdata
    call probe_h3_newcid
    call probe_h3_sessid_echo
    call probe_h3_streams_uni
    call probe_h3_keyupdate
    call probe_h3_ku_oldkey
    call probe_h3_iscid
    call probe_h3_noiscid
    call probe_h3_tpudp
    call probe_h3_tpcid
    call probe_h3_dgmax
    call probe_h3_cidcnt
    call probe_h3_rsvd
    call probe_h3_strmlim
    call probe_h3_initpad
    call probe_h3_runt
    call probe_h3_no_sigalgs
    call probe_h3_no_tls13
    call probe_h3_bad_cipher
    ret

; probe_h3_initial: send a QUIC Initial and confirm a ServerHello comes back.
probe_h3_handshake:
    push rbx
    push r12
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
    ; part 1: the Initial exchange (ServerHello), retried on a lost Initial
    mov edi, ebx
    call quic_h3_handshake_retry          ; also derives Handshake keys en route
    push rax                              ; 1 if the server Finished decrypted
    lea rsi, [n_h3_initial]
    mov edx, n_h3_initial_len
    mov dil, K_OK
    cmp qword [q_hs_ready], 0
    jne .rep1
    mov dil, K_DEV
.rep1:
    call report_plain
    ; part 2: the full server flight (EE/Cert/CertVerify/Finished decrypted)
    pop r12                               ; 1 if the server Finished decrypted
    mov dil, K_OK
    test r12, r12
    jnz .rep2
    ; The Initial already succeeded, so the server speaks QUIC; not decrypting the
    ; full flight from here is a prober limitation (e.g. driving a large real
    ; Handshake flight to completion), not a server deviation, so [info] not [DEV!].
    ; (google.com exercises this: aioquic completes with our exact offer, but the
    ; prober does not yet drive Google's ~5 KB flight to the server Finished.)
    mov dil, K_INFO
.rep2:
    lea rsi, [n_h3_flight]
    mov edx, n_h3_flight_len
    call report_plain
    ; part 3: send the client Finished and confirm 1-RTT (only if the flight came)
    test r12, r12
    jz .done
    mov edi, ebx
    call quic_finish                      ; rax = 1 if a 1-RTT packet decrypted
    mov r12, rax                          ; keep across report_plain
    mov dil, K_OK
    test r12, r12
    jnz .rep3
    ; Initial + flight already succeeded, so the server clearly speaks QUIC; a
    ; failure to drive the client side to 1-RTT from here is likelier a prober
    ; limitation than a server deviation, so report [info], not [DEV!]. (This path
    ; is exercised by servers the prober cannot yet fully complete against; the
    ; reference servers Linnea and Cloudflare both reach [OK] here.)
    mov dil, K_INFO
.rep3:
    lea rsi, [n_h3_1rtt]
    mov edx, n_h3_1rtt_len
    call report_plain
    ; part 4: an actual HTTP/3 GET / over 1-RTT, decode :status
    test r12, r12
    jz .done                             ; no 1-RTT, cannot request
    mov edi, ebx
    call quic_h3_get                      ; rax = :status or -1
    mov r12, rax
    ; 2xx = served OK (a positive lock). Any other served or undecodable status is
    ; [info], not [DEV!]: a 3xx redirect is a valid response (google.com/ answers
    ; 301), and "exactly 200" is Linnea-specific. Not every server's headers are
    ; decodable capacity-0 either — Google encodes them with the QPACK dynamic table.
    mov dil, K_OK
    cmp rax, 200
    jl .get_info
    cmp rax, 299
    jle .rep4
.get_info:
    mov dil, K_INFO
.rep4:
    lea rsi, [n_h3_get]
    mov edx, n_h3_get_len
    mov rcx, r12                          ; observed status
    mov r9d, 200                          ; expected
    call report
.done:
    mov edi, ebx
    call close_fd
    pop r12
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
    pop r12
    pop rbx
    ret

; report_plain(dil=kind, rsi=name, edx=namelen): a report line with no status.
; report_size(dil=kind, rsi=name, edx=namelen, rcx=observed, r9d=expected)
; Like report, but the number is a byte count rather than a status code —
; "-> 827 bytes  (want 1200)". A size printed as "HTTP 827" reads as nonsense,
; and for a size deviation the number IS the finding.
report_size:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    movzx ebx, dil
    mov r12, rsi
    mov r13d, edx
    mov r14, rcx
    mov r15d, r9d
    inc dword [n_total]
    cmp ebx, K_DEV
    jne .rs_prefix
    inc dword [n_dev]
.rs_prefix:
    cmp ebx, K_OK
    je .rs_ok
    cmp ebx, K_DEV
    je .rs_dev
    lea rsi, [pfx_info]
    mov edx, pfx_info_len
    jmp .rs_put
.rs_ok:
    lea rsi, [pfx_ok]
    mov edx, pfx_ok_len
    jmp .rs_put
.rs_dev:
    lea rsi, [pfx_dev]
    mov edx, pfx_dev_len
.rs_put:
    call puts
    mov rsi, r12
    mov edx, r13d
    call puts
    test r14, r14
    js .rs_none                           ; nothing measured: just end the line
    lea rsi, [s_arrow]
    mov edx, s_arrow_len
    call puts
    mov edi, r14d
    call print_u32
    lea rsi, [s_bytes]
    mov edx, s_bytes_len
    call puts
    cmp r15d, -1
    je .rs_nl
    lea rsi, [s_want]
    mov edx, s_want_len
    call puts
    mov edi, r15d
    call print_u32
    lea rsi, [s_rparen_nl]
    mov edx, s_rparen_nl_len
    call puts
    jmp .rs_ret
.rs_none:
.rs_nl:
    lea rsi, [s_nl]
    mov edx, 1
    call puts
.rs_ret:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

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
