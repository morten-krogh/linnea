; QUIC (RFC 9000 / 9001) constants and structures.

; A packet-protection key set for one direction and encryption level.
struc linnea_quic_keys
    .key:  resb 16      ; AEAD_AES_128_GCM key
    .iv:   resb 12      ; AEAD nonce base (XORed with the packet number)
    .hp:   resb 16      ; header-protection key (AES-128-ECB)
endstruc

LINNEA_QUIC_MAX_CID   equ 20      ; RFC 9000: connection IDs are 0..20 bytes

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
endstruc
