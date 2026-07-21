; QUIC connection state and the connection pool.
;
; A QUIC connection is identified by the connection ID the peer puts in the
; Destination Connection ID field, which is the ID *we* chose and advertised as
; our Source Connection ID during the handshake. We pick that ID, so we encode
; the pool index in its first two bytes and fill the rest with randomness:
;
;     scid = [ index(16, big-endian) ][ 6 random bytes ]
;
; Demultiplexing an incoming packet is then O(1) with no map — read the index,
; bounds-check it, and confirm the slot's full ID matches (the random tail makes
; the ID unguessable, so a wrong or spoofed ID fails the compare).
;
; Requires linnea_quic.inc (linnea_quic_keys_size, LINNEA_QUIC_MAX_CID).

LINNEA_QUIC_MAX_CONNS equ 64        ; connections per worker
LINNEA_QUIC_RXBUF_SIZE equ 2048     ; linnea_quic_rxbuf, the datagram we read into
LINNEA_QUIC_SCID_LEN  equ 8         ; every connection ID we issue is 8 bytes
LINNEA_QUIC_IDLE_SECS equ 30        ; reclaim a slot after this long with no packet

; Handshake progress, so a packet can be checked against the connection's stage.
LINNEA_QUIC_ST_NEW       equ 0      ; allocated, nothing processed yet
LINNEA_QUIC_ST_HANDSHAKE equ 1      ; server flight sent, awaiting the client
LINNEA_QUIC_ST_CONNECTED equ 2      ; client Finished verified, 1-RTT keys live

struc linnea_quic_conn
    .in_use:     resq 1
    .dcid_len:   resq 1              ; length of the peer's connection ID
    .peer_len:   resq 1              ; sockaddr length
    .state:      resq 1
    .pn_1rtt:    resq 1              ; next 1-RTT packet number we send
    .last_active: resq 1             ; CLOCK_MONOTONIC seconds of the last packet
    .scid:       resb LINNEA_QUIC_SCID_LEN   ; ours (index || random)
    .dcid:       resb LINNEA_QUIC_MAX_CID    ; the peer's, our DCID when sending
    .peer:       resb 16                     ; sockaddr_in of the client
    .hs_sec:     resb 96             ; c_hs || s_hs || handshake_secret
    .th_cfin:    resb 32             ; H(CH..server Finished)
    .ini_client: resb linnea_quic_keys_size
    .ini_server: resb linnea_quic_keys_size
    .hs_ckeys:   resb linnea_quic_keys_size
    .hs_skeys:   resb linnea_quic_keys_size
    .ap_ckeys:   resb linnea_quic_keys_size
    .ap_skeys:   resb linnea_quic_keys_size
    .pad:        resb 4              ; keep the size a multiple of 8
endstruc

; linnea_quic_conn_lookup(rdi=dcid ptr, rsi=dcid len) -> rax = conn* or 0.
;   Marks the slot active, so a connection in use never falls to the sweep.
; linnea_quic_conn_alloc(rdi=peer ptr, rsi=peer len) -> rax = conn* or 0.
;   Sweeps idle slots first, then zeroes one, assigns a fresh connection ID and
;   records the peer. Returns 0 only when the pool is genuinely full of live
;   connections.
; linnea_quic_conn_free(rdi=conn) — return the slot to the pool. A client that
;   closes cleanly frees its slot at once; the sweep is the backstop for those
;   that simply vanish.
; linnea_quic_conn_sweep(rdi=now seconds, rsi=idle seconds) -> rax = slots freed.
;   Exposed with an explicit clock so it can be tested without waiting.
; linnea_quic_conn_active() -> rax = slots currently in use.
