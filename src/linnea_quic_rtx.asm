; linnea_quic_rtx.asm — loss-recovery bookkeeping for the 1-RTT space.
;
; Every ack-eliciting 1-RTT packet the server sends is kept in a small per-
; connection ring (linnea_quic_conn.sent) until the peer acknowledges it. The
; frames are stored rather than the protected wire bytes, so a retransmission
; can be re-encrypted under a fresh packet number — QUIC forbids reusing one
; (RFC 9002 A.5). These three routines are the pure array operations over that
; ring; they take the clock as a parameter and touch nothing else, so they are
; unit-testable without a socket. The PTO sweep that actually resends lives with
; the event loop (it needs the clock and the socket).

default rel

%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"

global linnea_quic_rtx_record
global linnea_quic_rtx_ack_range
global linnea_quic_rtx_inflight
global linnea_quic_txchunk_record
global linnea_quic_txchunk_ack
global linnea_quic_txchunk_clear

section .text

; --- response-stream in-flight table (the congestion-controlled send window) ---
; A large response's chunks are tracked here, one record per chunk, keyed by the
; packet number they went out under. Because a chunk is rebuilt from the file on
; retransmission, only {pn, offset, length} is kept — the table is light enough
; to size for a real congestion window (hundreds of packets). bytes_in_flight is
; maintained here so the pump can gate on cwnd without scanning.

; linnea_quic_txchunk_record(rdi=conn, rsi=pn, rdx=offset, rcx=len, r8=now ms)
;   -> rax = 1 recorded, 0 = table full (the pump checks room before sending).
linnea_quic_txchunk_record:
    lea rax, [rdi + linnea_quic_conn.tx_infl]
    mov r9d, LINNEA_QUIC_TXINFL_SLOTS
.scan:
    cmp qword [rax + linnea_quic_txchunk.in_use], 0
    je .free
    add rax, linnea_quic_txchunk_size
    dec r9d
    jnz .scan
    xor eax, eax
    ret
.free:
    mov qword [rax + linnea_quic_txchunk.in_use], 1
    mov [rax + linnea_quic_txchunk.pn], rsi
    mov [rax + linnea_quic_txchunk.sent_ms], r8
    mov [rax + linnea_quic_txchunk.off], rdx
    mov [rax + linnea_quic_txchunk.len], rcx
    mov qword [rax + linnea_quic_txchunk.tries], 0
    add [rdi + linnea_quic_conn.bytes_in_flight], rcx
    mov eax, 1
    ret

; linnea_quic_txchunk_ack(rdi=conn, rsi=lo, rdx=hi) -> rax = bytes acknowledged.
; Frees every in-flight chunk whose pn is in [lo, hi], subtracting its length from
; bytes_in_flight; returns the total newly acknowledged (drives cwnd growth).
linnea_quic_txchunk_ack:
    lea r8, [rdi + linnea_quic_conn.tx_infl]
    xor r9d, r9d                      ; bytes acked
    mov ecx, LINNEA_QUIC_TXINFL_SLOTS
.scan:
    cmp qword [r8 + linnea_quic_txchunk.in_use], 0
    je .next
    mov rax, [r8 + linnea_quic_txchunk.pn]
    cmp rax, rsi
    jb .next
    cmp rax, rdx
    ja .next
    mov qword [r8 + linnea_quic_txchunk.in_use], 0
    mov rax, [r8 + linnea_quic_txchunk.len]
    add r9, rax
    sub [rdi + linnea_quic_conn.bytes_in_flight], rax
.next:
    add r8, linnea_quic_txchunk_size
    dec ecx
    jnz .scan
    mov rax, r9
    ret

; linnea_quic_txchunk_clear(rdi=conn) — drop every in-flight chunk and zero
; bytes_in_flight (the response stream is aborted or finished).
linnea_quic_txchunk_clear:
    lea rax, [rdi + linnea_quic_conn.tx_infl]
    mov ecx, LINNEA_QUIC_TXINFL_SLOTS
.scan:
    mov qword [rax + linnea_quic_txchunk.in_use], 0
    add rax, linnea_quic_txchunk_size
    dec ecx
    jnz .scan
    mov qword [rdi + linnea_quic_conn.bytes_in_flight], 0
    ret

; linnea_quic_rtx_record(rdi=conn, rsi=pn, rdx=payload ptr, rcx=len, r8=now ms)
; Buffer one ack-eliciting packet's frames. A payload larger than a record, or
; a full ring, is simply not tracked: retransmission is best-effort, and every
; reply we build is far under the cap, so in practice nothing is dropped.
linnea_quic_rtx_record:
    cmp rcx, LINNEA_QUIC_RTX_PAYLOAD
    ja .done                          ; too large to keep
    lea rax, [rdi + linnea_quic_conn.sent]
    mov r9d, LINNEA_QUIC_RTX_SLOTS
.scan:
    cmp qword [rax + linnea_quic_sent.in_use], 0
    je .free
    add rax, linnea_quic_sent_size
    dec r9d
    jnz .scan
    ret                               ; ring full: drop
.free:
    mov qword [rax + linnea_quic_sent.in_use], 1
    mov [rax + linnea_quic_sent.pn], rsi
    mov [rax + linnea_quic_sent.sent_ms], r8
    mov [rax + linnea_quic_sent.len], rcx
    mov qword [rax + linnea_quic_sent.tries], 0
    lea rdi, [rax + linnea_quic_sent.payload]
    mov rsi, rdx
    rep movsb                         ; rcx bytes of frames
.done:
    ret

; linnea_quic_rtx_ack_range(rdi=conn, rsi=lo, rdx=hi) — release every buffered
; packet whose number is in [lo, hi]. Called once per range of an incoming ACK.
linnea_quic_rtx_ack_range:
    lea rax, [rdi + linnea_quic_conn.sent]
    mov ecx, LINNEA_QUIC_RTX_SLOTS
.scan:
    cmp qword [rax + linnea_quic_sent.in_use], 0
    je .next
    mov r8, [rax + linnea_quic_sent.pn]
    cmp r8, rsi
    jb .next                          ; below the range
    cmp r8, rdx
    ja .next                          ; above the range
    mov qword [rax + linnea_quic_sent.in_use], 0
.next:
    add rax, linnea_quic_sent_size
    dec ecx
    jnz .scan
    ret

; linnea_quic_rtx_inflight(rdi=conn) -> rax = buffered (unacknowledged) packets.
linnea_quic_rtx_inflight:
    lea rdx, [rdi + linnea_quic_conn.sent]
    xor eax, eax
    mov ecx, LINNEA_QUIC_RTX_SLOTS
.scan:
    cmp qword [rdx + linnea_quic_sent.in_use], 0
    je .next
    inc eax
.next:
    add rdx, linnea_quic_sent_size
    dec ecx
    jnz .scan
    ret
