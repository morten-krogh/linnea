; QUIC connection state and the connection pool.
;
; A QUIC connection is identified by the connection ID the peer puts in the
; Destination Connection ID field, which is the ID *we* chose and advertised as
; our Source Connection ID during the handshake. We pick that ID, so we encode
; routing into its first two bytes and fill the rest with randomness:
;
;     scid = [ worker index(8) ][ pool index(8) ][ 6 random bytes ]
;
; The worker index is the first byte so the BPF reuseport program can read it
; and steer the connection's packets back to the worker that owns it, even after
; the client migrates to a new address (see src/linnea_bpf.asm). The pool index
; demultiplexes to the slot within that worker: O(1), no map — read the index,
; bounds-check it, and confirm the slot's full ID matches (the random tail makes
; the ID unguessable, so a wrong or spoofed ID fails the compare).
;
; Requires linnea_quic.inc (linnea_quic_keys_size, LINNEA_QUIC_MAX_CID).

LINNEA_QUIC_MAX_CONNS equ 64        ; connections per worker
LINNEA_QUIC_RXBUF_SIZE equ 2048     ; linnea_quic_rxbuf, the datagram we read into
LINNEA_QUIC_SCID_LEN  equ 8         ; every connection ID we issue is 8 bytes
LINNEA_QUIC_IDLE_SECS equ 30        ; reclaim a slot after this long with no packet

; The server handshake flight carries the whole certificate chain in CRYPTO
; frames, which for a real chain far exceeds one datagram. QUIC forbids IP
; fragmentation (packets set don't-fragment), so a flight larger than the path
; MTU must be split: the CRYPTO byte stream is chopped into chunks, each carried
; by its own Handshake packet (increasing packet number, increasing CRYPTO
; offset) in its own datagram. This chunk size keeps a datagram — even the first,
; which coalesces the Initial ahead of the Handshake packet — under the 1200-byte
; floor every QUIC endpoint must accept (RFC 9000 s14.1).
LINNEA_QUIC_CRYPTO_CHUNK equ 960    ; max CRYPTO payload per Handshake packet
LINNEA_QUIC_HS_FLIGHT_MAX equ 8192  ; largest flight the shared hsmsg scratch assembles
LINNEA_QUIC_FLIGHT_TAIL   equ 320   ; per-conn EE || CertVerify || Finished kept for resume

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

; A request whose frames span several packets is reassembled in a per-connection
; buffer: each frame is placed at its offset (out-of-order frames are buffered,
; not dropped), a parallel byte-map records which bytes have arrived, and the
; contiguous prefix length advances as gaps fill. The request is served once the
; stream is complete (FIN seen and the prefix covers it). One reassembly is
; tracked at a time — a whole request in a single packet (the common case) still
; takes a copy-free fast path. Requests larger than this buffer are not served.
LINNEA_QUIC_RA_BUF      equ 8192    ; reassembly capacity for one request stream

; 0-RTT (early data): a resuming client can send its request in a 0-RTT packet
; coalesced with the ClientHello, before the handshake completes. The decrypted
; early frames are buffered here and served once the 1-RTT keys are up. Small: a
; 0-RTT request is a single GET (a large early body is neither expected nor kept).
LINNEA_QUIC_EARLY_BUF   equ 1024

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
    .ctrl_id:    resq 1              ; the peer's control stream id, 0 until seen
    .h3_goaway_id: resq 1            ; lowest request stream a drain would reject
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
    ; Session resumption (RFC 8446 4.6.1): the PSK a NewSessionTicket will carry,
    ; derived at ClientHello time (while the transcript inputs are still in scratch)
    ; and sealed into the ticket at handshake completion — a later datagram, by when
    ; that scratch is gone. sni_hash ties the ticket to the server_name it was
    ; issued under, matched on resumption.
    .resumption_psk: resb 32
    .sni_hash:   resb 8
    ; 0-RTT: the early-data keys and the buffered early request (served at completion)
    .zrtt_ckeys: resb linnea_quic_keys_size
    .early_len:  resq 1              ; bytes of buffered early-data frames (0 = none)
    .early_buf:  resb LINNEA_QUIC_EARLY_BUF
    .ini_client: resb linnea_quic_keys_size
    .ini_server: resb linnea_quic_keys_size
    .hs_ckeys:   resb linnea_quic_keys_size
    .hs_skeys:   resb linnea_quic_keys_size
    .ap_ckeys:   resb linnea_quic_keys_size
    .ap_skeys:   resb linnea_quic_keys_size
    .sent:       resb LINNEA_QUIC_RTX_SLOTS * linnea_quic_sent_size ; loss-recovery ring
    ; anti-amplification (RFC 9000 s8.1) and the resumable handshake flight. Until
    ; the peer proves its address, we may send at most 3x the bytes it sent us, so
    ; a spoofed Initial cannot make us flood a third party. A large certificate
    ; chain overflows that budget on the first round trip, so the flight tail is
    ; released once the peer's first Handshake packet validates the address (only a
    ; client that received our flight can produce it). The flight is EE ||
    ; Certificate || CertVerify || Finished; the Certificate is identical for every
    ; connection, so only the per-connection edge (EE, the randomized CertVerify,
    ; and Finished) is kept here — the flight is recomposed into the shared hsmsg
    ; scratch from this tail plus the shared certificate list when resuming.
    .amp_credit: resq 1             ; bytes we may still send pre-validation (3xrecv - sent)
    .amp_valid:  resq 1             ; 1 once the peer's address is validated
    .flight_len: resq 1             ; total handshake-flight (CRYPTO) bytes
    .flight_off: resq 1             ; bytes of the flight already sent
    .flight_pn:  resq 1             ; packet number of the next Handshake packet
    .flight_ee_len: resq 1          ; EncryptedExtensions length (Certificate follows it)
    .flight_cv_len: resq 1          ; CertificateVerify length (Finished's 36 follow it)
    .flight_tail: resb LINNEA_QUIC_FLIGHT_TAIL   ; EE || CertVerify || Finished
    ; request-stream reassembly (one stream at a time):
    .ra_active:  resq 1             ; 1 while a multi-packet request is buffering
    .ra_sid:     resq 1             ; the stream id being reassembled
    .ra_len:     resq 1             ; contiguous bytes received from offset 0
    .ra_hi:      resq 1             ; highest offset+len seen (extent of ra_seen set)
    .ra_fin:     resq 1             ; the FIN has been seen
    .ra_final:   resq 1             ; the stream's total size (valid once ra_fin)
    .ra_buf:     resb LINNEA_QUIC_RA_BUF
    .ra_seen:    resb LINNEA_QUIC_RA_BUF   ; byte i = 1 once stream byte i has arrived
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
