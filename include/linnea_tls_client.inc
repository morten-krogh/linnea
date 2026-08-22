; linnea_tls_client.inc — per-connection state for the backend TLS 1.3 client.
;
; One handshake's whole state lives in a linnea_tls_client_hs, so the SAME crypto
; core drives a blocking test harness and the async io_uring proxy path: the
; blocking driver loops recv->input->send around it; the proxy will call
; linnea_tls_client_start / _input from io_uring completions, one struct per
; backend leg. See docs/design/tls-client-handshake-plan.md.

%include "linnea_tls.inc"                 ; linnea_tls_keys (for wkeys/rkeys)

; handshake state (linnea_tls_client_hs.state)
LINNEA_CLIENT_HS_INIT        equ 0
LINNEA_CLIENT_HS_WAIT_SH     equ 1        ; ClientHello sent, awaiting ServerHello
LINNEA_CLIENT_HS_WAIT_FLIGHT equ 2        ; SH parsed, awaiting the encrypted flight
LINNEA_CLIENT_HS_DONE        equ 3        ; authenticated; .out holds client Finished
LINNEA_CLIENT_HS_FAILED      equ 4

; linnea_tls_client_input return codes
LINNEA_CLIENT_MORE           equ 0        ; need more bytes; recv and call again
LINNEA_CLIENT_DONE           equ 1        ; send .out (client Finished), then hand off
LINNEA_CLIENT_FAIL           equ -1

LINNEA_CLIENT_TR_CAP   equ 16384          ; transcript buffer (whole handshake)
LINNEA_CLIENT_REC_CAP  equ 20480          ; one TLS record; decrypted-flight buffer
LINNEA_CLIENT_OUT_CAP  equ 1024           ; ClientHello / client Finished record

struc linnea_tls_client_hs
    .state:        resq 1
    .priv:         resb 32                ; own x25519 ephemeral
    .pub:          resb 32
    .random:       resb 32
    .sessid:       resb 32
    .srvpub:       resb 32                ; server key share
    .shared:       resb 32
    .c_hs:         resb 32                ; traffic secrets
    .s_hs:         resb 32
    .master:       resb 32
    .c_ap:         resb 32
    .s_ap:         resb 32
    .pin:          resb 32                ; configured SHA-256(SPKI)
    .srv_pubkey:   resb 64                ; extracted leaf P-256 point
    .th_buf:       resb 32                ; scratch transcript hash
    .srv_fin_key:  resb 32
    .srv_fin_calc: resb 32
    .spki_hash:    resb 32
    .sni_ptr:      resq 1                 ; SNI to send (caller-owned, must persist)
    .sni_len:      resq 1
    .alpn_ptr:     resq 1
    .alpn_len:     resq 1
    .tr_len:       resq 1
    .tr_ch_len:    resq 1                 ; transcript length after ClientHello, so
                                          ; each idempotent re-process keeps the CH
    .rbuf_len:     resq 1                 ; buffered inbound bytes (partial records)
    .hs_plain_len: resq 1                 ; decrypted handshake bytes
    .parse_off:    resq 1                 ; walked offset into .hs_plain
    .out_len:      resq 1                 ; bytes to send from .out
    .bodylen:      resq 1                 ; scratch: current hs message body length
    .wkeys:        resb linnea_tls_keys_size
    .rkeys:        resb linnea_tls_keys_size
    .out:          resb LINNEA_CLIENT_OUT_CAP
    .tr_buf:       resb LINNEA_CLIENT_TR_CAP
    .rbuf:         resb LINNEA_CLIENT_REC_CAP
    .hs_plain:     resb LINNEA_CLIENT_REC_CAP
endstruc
