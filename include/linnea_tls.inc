; TLS 1.3 (RFC 8446), the linnea profile: TLS_AES_128_GCM_SHA256 with an
; x25519 key share and an Ed25519 certificate, no HelloRetryRequest, no
; resumption, no 0-RTT, no client certificates. The handshake runs in
; userspace; application-data record protection moves into the kernel
; (kTLS) in M6 — until then the same record layer serves both.

%include "linnea_sha256.inc"
%include "linnea_aesgcm.inc"

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

; Test-only: x25519 private key and server random are injected by the
; caller instead of getrandom(2), and the signature_algorithms check is
; skipped (the RFC 8448 trace ClientHello predates ed25519 support).
LINNEA_TLS_FLAG_TRACE   equ 1

; The whole handshake state overlays a connection's up_buf (no proxying is
; active during the handshake), so linnea_tls_hs_size must stay <= up_buf.
; The flight buffer holds EE + Certificate(DER) + CertificateVerify +
; Finished; 4096 covers a single Ed25519 leaf well past any real size.
LINNEA_TLS_MSG_BUF      equ 4096   ; handshake message reassembly space

; msg_buf is smaller than the largest record in_buf can hold, so the record
; layer must not be handed anything longer than it. This bound is enforced
; on UNAUTHENTICATED input (linnea_tls_open writes the plaintext out before
; it checks the tag), which is what keeps a client's Finished record from
; running off the end of msg_buf -- and, since the state overlays up_buf,
; off the end of the connection slot. Stricter than the RFC 8446 ciphertext
; limit of 2^14+256, which only matters for a Finished padded past 4 KiB.
LINNEA_TLS_MAX_FRAGMENT equ LINNEA_TLS_MSG_BUF

; build_flight assembles EncryptedExtensions(6) + Certificate(13 + DER) +
; CertificateVerify(72) + Finished(36) into msg_buf, so a certificate is
; bounded by msg_buf minus that 127 bytes of framing. linnea_tls_setup
; refuses a larger one at startup rather than let the flight overrun.
LINNEA_TLS_FLIGHT_OVERHEAD equ 127
LINNEA_TLS_MAX_CERT     equ LINNEA_TLS_MSG_BUF - LINNEA_TLS_FLIGHT_OVERHEAD

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
; because M6 needs the application secrets for the kTLS handoff after
; the handshake ends.
struc linnea_tls_hs
    .state:      resd 1
    .flags:      resd 1
    .cert:       resq 1     ; DER certificate (sent verbatim)
    .cert_len:   resq 1
    .key_seed:   resq 1     ; 32-byte Ed25519 private seed
    .out_len:    resq 1     ; bytes placed in out by the last _input call
    .consumed:   resq 1     ; input bytes eaten by the last _input call
    .alert:      resd 1     ; alert description sent when state = FAILED
    .msg_len:    resd 1     ; bytes assembled in .msg_buf
    .sid_len:    resd 1     ; client legacy_session_id, echoed in SH
    .sid:        resb 32
    .client_pub: resb 32    ; client x25519 key share
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
