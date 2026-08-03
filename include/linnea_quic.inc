; QUIC (RFC 9000 / 9001) constants and structures.

; A packet-protection key set for one direction and encryption level.
struc linnea_quic_keys
    .key:  resb 16      ; AEAD_AES_128_GCM key
    .iv:   resb 12      ; AEAD nonce base (XORed with the packet number)
    .hp:   resb 16      ; header-protection key (AES-128-ECB)
endstruc

LINNEA_QUIC_MAX_CID   equ 20      ; RFC 9000: connection IDs are 0..20 bytes

; A sealed resumption ticket, exactly as linnea_quic_ticket_seal writes it:
;   nonce(12) || GCM( psk(32) || issued(8) || sni_hash(8) ) || tag(16)
; linnea_quic_ticket_open writes in_len-28 plaintext bytes into a fixed-size
; slot, so an offered PskIdentity must be exactly this long before it is
; allowed to reach the AEAD — the length comes straight off the wire.
LINNEA_QUIC_TICKET_PT  equ 48
LINNEA_QUIC_TICKET_LEN equ LINNEA_QUIC_TICKET_PT + 28

; 0-RTT is accepted only for a ticket issued within this many seconds, which
; bounds how long the replay strike register must remember a binder (RFC 9001
; 9.2). A resuming client past the window still resumes — just at 1-RTT.
LINNEA_QUIC_REPLAY_WINDOW equ 10

; The pieces of a ClientHello the QUIC handshake needs.
struc linnea_quic_ch
    .sni_ptr:  resq 1      ; server_name (host_name), 0 = none
    .sni_len:  resq 1
    .alpn_ptr: resq 1      ; ALPN ProtocolNameList (after the 2-byte list length)
    .alpn_len: resq 1
    .tp_ptr:   resq 1      ; QUIC transport parameters (extension 0x39)
    .tp_len:   resq 1
    .ks_ptr:   resq 1      ; the client's x25519 key_share (32 bytes), 0 = none
    ; session resumption (pre_shared_key 0x29 / psk_key_exchange_modes 0x2d):
    .psk_id_ptr:    resq 1 ; first PSK identity (the ticket) bytes, 0 = no offer
    .psk_id_len:    resq 1
    .psk_binder_ptr: resq 1 ; first binder's 32 bytes
    .psk_binders_pos: resq 1 ; absolute ptr to the binders-length field (truncated CH end)
    .psk_dhe_ke:    resq 1 ; 1 if the client offered psk_dhe_ke (the only mode we do)
    .early_data:    resq 1 ; 1 if the client offered early_data (0x2a) for 0-RTT
    .sigalg_seen:   resq 1 ; 1 if signature_algorithms (0x000d) was offered
endstruc
