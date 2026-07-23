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
global linnea_quic_rtx_record_ref
global linnea_quic_rtx_ack_range
global linnea_quic_rtx_inflight
global linnea_quic_rtx_ref_count
global linnea_quic_rtx_ref_clear

section .text

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
    mov qword [rax + linnea_quic_sent.kind], LINNEA_QUIC_KIND_FRAMES
    mov qword [rax + linnea_quic_sent.s_off], 0
    lea rdi, [rax + linnea_quic_sent.payload]
    mov rsi, rdx
    rep movsb                         ; rcx bytes of frames
.done:
    ret

; linnea_quic_rtx_record_ref(rdi=conn, rsi=pn, rdx=stream offset, rcx=len,
;   r8=now ms) -> rax = 1 recorded, 0 = ring full. Buffer a chunk of the open
; response stream by reference: only [offset, offset+len) is kept — a
; retransmission rebuilds the STREAM frame from the connection's tx state, so a
; large body is never copied per packet. The caller checks the ring has room
; BEFORE sending (linnea_quic_rtx_inflight): an untracked chunk would leave a
; permanent hole in the stream, unlike a small reply, which the peer re-requests.
linnea_quic_rtx_record_ref:
    lea rax, [rdi + linnea_quic_conn.sent]
    mov r9d, LINNEA_QUIC_RTX_SLOTS
.rscan:
    cmp qword [rax + linnea_quic_sent.in_use], 0
    je .rfree
    add rax, linnea_quic_sent_size
    dec r9d
    jnz .rscan
    xor eax, eax                      ; ring full
    ret
.rfree:
    mov qword [rax + linnea_quic_sent.in_use], 1
    mov [rax + linnea_quic_sent.pn], rsi
    mov [rax + linnea_quic_sent.sent_ms], r8
    mov [rax + linnea_quic_sent.len], rcx
    mov qword [rax + linnea_quic_sent.tries], 0
    mov qword [rax + linnea_quic_sent.kind], LINNEA_QUIC_KIND_STREAM_REF
    mov [rax + linnea_quic_sent.s_off], rdx
    mov eax, 1
    ret

; linnea_quic_rtx_ref_count(rdi=conn) -> rax = buffered stream-ref chunks. Zero,
; with the whole stream sent, means every chunk was acknowledged: the response
; is delivered and the file mapping can be released.
linnea_quic_rtx_ref_count:
    lea rdx, [rdi + linnea_quic_conn.sent]
    xor eax, eax
    mov ecx, LINNEA_QUIC_RTX_SLOTS
.cscan:
    cmp qword [rdx + linnea_quic_sent.in_use], 0
    je .cnext
    cmp qword [rdx + linnea_quic_sent.kind], LINNEA_QUIC_KIND_STREAM_REF
    jne .cnext
    inc eax
.cnext:
    add rdx, linnea_quic_sent_size
    dec ecx
    jnz .cscan
    ret

; linnea_quic_rtx_ref_clear(rdi=conn) — drop every stream-ref record. Called
; when the response stream is aborted (its file unmapped): a surviving reference
; would rebuild a chunk from memory that is no longer mapped.
linnea_quic_rtx_ref_clear:
    lea rdx, [rdi + linnea_quic_conn.sent]
    mov ecx, LINNEA_QUIC_RTX_SLOTS
.xscan:
    cmp qword [rdx + linnea_quic_sent.kind], LINNEA_QUIC_KIND_STREAM_REF
    jne .xnext
    mov qword [rdx + linnea_quic_sent.in_use], 0
.xnext:
    add rdx, linnea_quic_sent_size
    dec ecx
    jnz .xscan
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
