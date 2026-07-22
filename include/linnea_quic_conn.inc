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

; Loss recovery for the 1-RTT space. Every ack-eliciting packet we send is kept
; here until the peer acknowledges it, so a lost copy can be resent — under a
; fresh packet number, since QUIC forbids reusing one (RFC 9002 A.5). The frames
; are stored, not the protected bytes, so a retransmission is re-encrypted with a
; new number. The slot count bounds how much can be outstanding at once; the
; payload cap is far above anything a single reply we build reaches today.
LINNEA_QUIC_RTX_SLOTS   equ 8       ; outstanding 1-RTT packets tracked per conn
LINNEA_QUIC_RTX_PAYLOAD equ 1500    ; frame bytes kept per packet
LINNEA_QUIC_ACK_MAXR    equ 16      ; ACK ranges decoded from one incoming frame

; Probe timeout: a buffered packet unacknowledged for this long is resent, under
; a fresh number. The threshold doubles per attempt (a lost reply on a slow or
; congested path is not lost again just because the first probe was early) up to
; a cap, and after a maximum number of attempts the packet is abandoned — a peer
; that has vanished should not be probed until the idle sweep reclaims it.
LINNEA_QUIC_PTO_MS      equ 250     ; base probe timeout, milliseconds
LINNEA_QUIC_PTO_CAP     equ 4       ; largest backoff shift (250ms << 4 = 4s)
LINNEA_QUIC_PTO_MAX     equ 6       ; attempts before a packet is given up on

struc linnea_quic_sent
    .in_use:   resq 1
    .pn:       resq 1               ; packet number it last went out under
    .sent_ms:  resq 1               ; CLOCK_MONOTONIC ms when (re)sent, for the PTO
    .len:      resq 1               ; frame-payload length
    .tries:    resq 1               ; retransmissions so far (0 = first send)
    .payload:  resb LINNEA_QUIC_RTX_PAYLOAD
    .pad:      resb 4               ; round the record to a multiple of 8
endstruc

struc linnea_quic_conn
    .in_use:     resq 1
    .dcid_len:   resq 1              ; length of the peer's connection ID
    .peer_len:   resq 1              ; sockaddr length
    .state:      resq 1
    .pn_1rtt:    resq 1              ; next 1-RTT packet number we send
    .last_active: resq 1             ; CLOCK_MONOTONIC seconds of the last packet
    ; acknowledgement state for the 1-RTT space (see linnea_quic_ack_record):
    ; these three must stay adjacent and in this order.
    .rx_have:    resq 1
    .rx_largest: resq 1
    .rx_mask:    resq 1
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
    .sent:       resb LINNEA_QUIC_RTX_SLOTS * linnea_quic_sent_size ; loss-recovery ring
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
