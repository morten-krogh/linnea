; TLS 1.3 (RFC 8446), the linnea profile: TLS_AES_128_GCM_SHA256 with an
; x25519 key share and an ECDSA P-256 certificate chain, no
; HelloRetryRequest, no resumption, no 0-RTT, no client certificates. The handshake runs in
; userspace; application-data record protection is handed to the kernel
; (kTLS) once it completes.

%include "linnea_sha256.inc"
%include "linnea_aesgcm.inc"
%include "linnea_p256_ecdsa.inc"

; One direction of record protection: the AES-GCM schedule for the
; traffic key, the static IV, and the record sequence number that gets
; xored into it. Rebuilt from a new traffic secret on every key change.
struc linnea_tls_keys
    .aes:    resb linnea_aesgcm_ctx_size
    .iv:     resb 12
    .pad:    resb 4
    .seq:    resq 1
endstruc

; Handshake states (linnea_tls_hs.state / linnea_tls_hs_input result)
LINNEA_TLS_WAIT_CH      equ 0
LINNEA_TLS_WAIT_FIN     equ 1
LINNEA_TLS_DONE         equ 2
LINNEA_TLS_FAILED       equ 3

; server_name (RFC 6066): the longest host_name kept from a ClientHello.
; A DNS name is at most 255 octets, so anything longer cannot match a
; configured hostname and is ignored rather than stored.
LINNEA_TLS_MAX_SNI      equ 255

; Session resumption (RFC 8446 4.6.1 / 4.2.11, psk_dhe_ke only): the
; server hands out one stateless NewSessionTicket per handshake. The
; ticket is the PSK itself, AES-128-GCM-sealed under a per-run key:
;   nonce(12) || GCM( psk(32) || issued(8) || sni_hash(8) ) || tag(16)
; sni_hash ties the ticket to the server_name it was issued under, so a
; ticket only resumes when the client offers the same name again.
LINNEA_TLS_TICKET_LEN      equ 76
LINNEA_TLS_TICKET_LIFETIME equ 86400   ; seconds; also advertised in the NST

; Test-only: the x25519 private key and the server random are injected by
; the caller instead of coming from getrandom(2), and the
; signature_algorithms check is skipped. The RFC 8448 trace's ClientHello
; does offer ecdsa_secp256r1_sha256, so the skip is no longer load-bearing
; for the sigalgs check itself; the injection is what the trace needs, and
; the flight past ServerHello diverges from the trace regardless (its
; certificate is RSA).
LINNEA_TLS_FLAG_TRACE   equ 1

; The whole handshake state overlays a connection's up_buf (no proxying is
; active during the handshake), so linnea_tls_hs_size must stay <= up_buf.
; The flight buffer holds EE + Certificate(certificate_list) +
; CertificateVerify + Finished; 4096 covers an ECDSA leaf plus its
; intermediates (the four-cert Let's Encrypt long chain is ~3.4 KiB; a
; chain of large RSA intermediates would not fit, and linnea_tls_setup
; refuses it at startup).
LINNEA_TLS_MSG_BUF      equ 4096   ; handshake message reassembly space

; msg_buf is smaller than the largest record in_buf can hold, so the record
; layer must not be handed anything longer than it. This bound is enforced
; on UNAUTHENTICATED input (linnea_tls_open writes the plaintext out before
; it checks the tag), which is what keeps a client's Finished record from
; running off the end of msg_buf -- and, since the state overlays up_buf,
; off the end of the connection slot. Stricter than the RFC 8446 ciphertext
; limit of 2^14+256, which only matters for a Finished padded past 4 KiB.
LINNEA_TLS_MAX_FRAGMENT equ LINNEA_TLS_MSG_BUF

; build_flight assembles EncryptedExtensions(6) + Certificate(8 + list) +
; CertificateVerify(8 + signature) + Finished(36) into msg_buf, so the
; certificate_list is bounded by msg_buf minus that framing.
; linnea_tls_setup refuses a larger one at startup rather than let the
; flight overrun.
;
; The CertificateVerify term must be computed from the signature's MAXIMUM,
; not its typical size: an ECDSA signature is DER, so its length varies with
; r and s and usually lands a byte or two under the bound. The term is
; header(4) + scheme(2) + length(2) + LINNEA_P256_ECDSA_MAX_SIG.
LINNEA_TLS_FLIGHT_OVERHEAD equ 6 + 8 + (8 + LINNEA_P256_ECDSA_MAX_SIG) + 36
LINNEA_TLS_MAX_CERT_LIST equ LINNEA_TLS_MSG_BUF - LINNEA_TLS_FLIGHT_OVERHEAD

; kTLS handoff (docs.kernel.org/networking/tls.html). After the handshake
; the application traffic keys go to the kernel and io_uring send/recv
; transparently encrypt/decrypt, so the rest of the server is unchanged.
LINNEA_SOL_TCP          equ 6
LINNEA_TCP_ULP          equ 31
LINNEA_SOL_TLS          equ 282
LINNEA_TLS_TX           equ 1
LINNEA_TLS_RX           equ 2
LINNEA_TLS_1_3_VERSION  equ 0x0304
LINNEA_TLS_CIPHER_AES_GCM_128 equ 51
; struct tls12_crypto_info_aes_gcm_128 = version(2) cipher(2) iv(8) key(16)
; salt(4) rec_seq(8) = 40 bytes.
LINNEA_TLS_CRYPTO_INFO_SIZE equ 40

; Record content types
LINNEA_TLS_CT_CCS        equ 20
LINNEA_TLS_CT_ALERT      equ 21
LINNEA_TLS_CT_HANDSHAKE  equ 22
LINNEA_TLS_CT_APPDATA    equ 23

; Alert descriptions (all sent fatal)
LINNEA_TLS_A_CLOSE_NOTIFY        equ 0
LINNEA_TLS_A_UNEXPECTED_MESSAGE  equ 10
LINNEA_TLS_A_BAD_RECORD_MAC      equ 20
LINNEA_TLS_A_RECORD_OVERFLOW     equ 22
LINNEA_TLS_A_HANDSHAKE_FAILURE   equ 40
LINNEA_TLS_A_ILLEGAL_PARAMETER   equ 47
LINNEA_TLS_A_DECODE_ERROR        equ 50
LINNEA_TLS_A_DECRYPT_ERROR       equ 51
LINNEA_TLS_A_PROTOCOL_VERSION    equ 70
LINNEA_TLS_A_INTERNAL_ERROR      equ 80

; Per-connection handshake state. The traffic secrets stay resident
; because the kTLS handoff needs the application secrets after
; the handshake ends.
struc linnea_tls_hs
    .state:      resd 1
    .flags:      resd 1
    .cert_list:     resq 1  ; pre-framed TLS certificate_list (sent verbatim)
    .cert_list_len: resq 1
    .key_priv:   resq 1     ; 32-byte P-256 private scalar
    .out_len:    resq 1     ; bytes placed in out by the last _input call
    .consumed:   resq 1     ; input bytes eaten by the last _input call
    .alert:      resd 1     ; alert description sent when state = FAILED
    .msg_len:    resd 1     ; bytes assembled in .msg_buf
    .sid_len:    resd 1     ; client legacy_session_id, echoed in SH
    .sid:        resb 32
    .client_pub: resb 32    ; client x25519 key share
    ; SNI vhost selection. The embedder may install a hook after hs_init:
    ; select_cb(rdi=select_ctx, rsi=sni, rdx=sni_len) -> rax=cert_list
    ; (with rdx=cert_list_len, rcx=key_priv), or rax=0 to keep the cert
    ; given to hs_init. Called between the ClientHello parse and the
    ; server flight; 0 (the hs_init default) means no selection.
    .select_cb:  resq 1
    .select_ctx: resq 1
    .sni_len:    resd 1     ; host_name from the ClientHello, 0 = none
    .sni:        resb LINNEA_TLS_MAX_SNI
    ; resumption offer, recorded by parse_ch and judged in hs_input
    .ticket:     resb LINNEA_TLS_TICKET_LEN  ; the client's first identity
    .binder:     resb 32    ; its first binder (SHA-256 sized)
    .psk:        resb 32    ; the PSK, once the ticket opens
    .ch_base:    resq 1     ; the raw ClientHello (parse_ch scratch)
    .binders_off: resq 1    ; truncated-CH length for the binder hash
    .psk_flags:  resd 1     ; bit0 offer recorded, bit1 psk_dhe_ke offered
    .resumed:    resd 1     ; 1 = PSK accepted: no cert, SH carries 0x29
    ; ALPN (RFC 7301): the selected protocol as a length-prefixed name to
    ; echo in EncryptedExtensions, or 0 for none. Set by parse_ch.
    .alpn_name:  resq 1
    .alpn_is_h2: resd 1     ; 1 = the selection was h2 (vs http/1.1)
    .alpn_h2_ok: resd 1     ; 1 = this server offers h2 (config.http2), set
                            ; by the accept path before the ClientHello
    .transcript: resb linnea_sha256_ctx_size
    .priv:       resb 32    ; ephemeral x25519 private key
    .srand:      resb 32    ; server random
    .c_hs:       resb 32    ; client handshake traffic secret
    .s_hs:       resb 32    ; server handshake traffic secret
    .master:     resb 32
    .c_ap:       resb 32    ; client application traffic secret
    .s_ap:       resb 32    ; server application traffic secret
    .wkeys:      resb linnea_tls_keys_size   ; server write direction
    .rkeys:      resb linnea_tls_keys_size   ; client write direction
    .msg_buf:    resb LINNEA_TLS_MSG_BUF
endstruc
