; linnea_rtxtest.asm — 1-RTT loss-recovery unit tests. Exercises the sent-packet
; ring (record / ack-range / inflight) and the ACK-frame range decoder in
; isolation, then the two together: buffer some packets, decode a real ACK, and
; confirm exactly the acknowledged ones are released. Prints "quic-rtx
; <pass>/<total>" and exits 1 on any failure.

default rel

%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"

global _start

extern linnea_quic_rtx_record
extern linnea_quic_rtx_ack_range
extern linnea_quic_rtx_inflight
extern linnea_quic_txchunk_record
extern linnea_quic_txchunk_ack
extern linnea_quic_txchunk_clear
extern linnea_quic_flow_scan
extern linnea_quic_parse_priority
extern linnea_quic_ack_ranges
extern linnea_quic_ack_record
extern linnea_quic_ack_seen
extern linnea_quic_rtt_sample
extern linnea_quic_pto_ms
extern linnea_quic_frame_skip
extern linnea_quic_frames_check
extern linnea_quic_reset_scan
extern linnea_quic_path_seen
extern linnea_quic_path_data
extern linnea_print_stdout
extern linnea_print_u64_stdout

; EXPECT actual_reg, value — tally into r14d (total) / r15d (pass).
%macro EXPECT 2
    inc r14d
    mov r11, %2
    cmp %1, r11
    jne %%bad
    inc r15d
%%bad:
%endmacro

%macro EXPECT_ABOVE 2                   ; tally a "greater than" expectation
    inc r14d
    mov r11, %2
    cmp %1, r11
    jbe %%bad
    inc r15d
%%bad:
%endmacro

section .rodata
pay:       db "hello"
pay_len    equ $ - pay
; PADDING, PING, then an ACK: Largest=7, Delay=0, RangeCount=1, FirstRange=2
; (covers 5..7), then one range with Gap=0, Length=0 (covers 3). Two ranges out.
ackframe:  db 0x00, 0x01, 0x02, 0x07, 0x00, 0x01, 0x02, 0x00, 0x00
ackframe_len equ $ - ackframe
; the same ACK, but coalesced BEHIND a NEW_CONNECTION_ID and a MAX_DATA — as a
; real browser sends it. ack_ranges must skip past them to the ACK, or the
; in-flight chunks are never freed and the response stalls with its window full.
ackframe_ncid: db 0x18, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD
               db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
               db 0x10, 0x41, 0x2C
               db 0x02, 0x07, 0x00, 0x01, 0x02, 0x00, 0x00
ackframe_ncid_len equ $ - ackframe_ncid
; flow_scan must reach flow-control credit bundled behind other frames, as a real
; browser sends it. NEW_CONNECTION_ID(seq 1, retire 0, cid len 4, 16-byte token),
; then MAX_DATA=300 (0x412c), then MAX_STREAM_DATA(stream 0)=500 (0x41f4).
fs_ncid:   db 0x18, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD
           db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
           db 0x10, 0x41, 0x2C
           db 0x11, 0x00, 0x41, 0xF4
fs_ncid_len equ $ - fs_ncid
; MAX_STREAMS bidi=16, a STREAM|LEN frame (stream 3, 2 bytes of data), then
; MAX_STREAM_DATA(stream 4)=700 (0x42bc) — credit behind a data-carrying frame.
fs_stream: db 0x12, 0x10
           db 0x0A, 0x03, 0x02, 0xAB, 0xCD
           db 0x11, 0x04, 0x42, 0xBC
fs_stream_len equ $ - fs_stream
; RFC 9218 priority field values (u = urgency 0-7, i = incremental)
prio_ui:   db "u=1, i"
prio_ui_len equ $ - prio_ui
prio_u5:   db "u=5"
prio_u5_len equ $ - prio_u5
prio_i0:   db "i=?0, u=2"
prio_i0_len equ $ - prio_i0
prio_bare_i: db "i"
prio_bare_i_len equ $ - prio_bare_i
prio_bad:  db "u=9"                   ; out of range: falls back to the default
prio_bad_len equ $ - prio_bad

; --- frame-length table fixtures (RFC 9000 19) ---
fk_pad:     db 0x00
fk_ping:    db 0x01
fk_hd:      db 0x1e
fk_pc:      db 0x1a, 1,2,3,4,5,6,7,8
fk_maxdata: db 0x10, 0x41, 0x2C                       ; MAX_DATA 300 (2-byte varint)
fk_reset:   db 0x04, 0x03, 0x01, 0x05                 ; RESET_STREAM, three varints
fk_close:   db 0x1c, 0x01, 0x00, 0x00                 ; transport close, empty reason
fk_closea:  db 0x1d, 0x01, 0x00                       ; application close
fk_stream:  db 0x0a, 0x03, 0x02, 0xAB, 0xCD           ; STREAM|LEN, sid 3, 2 bytes
fk_strnol:  db 0x08, 0x03, 0xAA, 0xBB, 0xCC           ; STREAM, no LEN: runs to the end
fk_ncid:    db 0x18, 0x01, 0x00, 0x04, 0xDE,0xAD,0xBE,0xEF
            db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0       ; 16-byte reset token
fk_ack:     db 0x02, 0x07, 0x00, 0x01, 0x02, 0x00, 0x00
fk_ackecn:  db 0x03, 0x07, 0x00, 0x00, 0x02, 0x01, 0x02, 0x03
; ACK with three ranges: largest 10, delay 0, range count 2, first range 1,
; then two (gap, length) pairs. Browsers send multi-range ACKs routinely, and
; since a frame we mis-measure is now a connection error rather than a quiet
; stop, the walk over the ranges has to be exact.
fk_ack3:    db 0x02, 0x0a, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01
; CONNECTION_CLOSE carrying a reason phrase, which is the common shape
fk_closer:  db 0x1c, 0x01, 0x00, 0x02, 'n', 'o'
fk_unk:     db 0x22                                   ; not a type RFC 9000 defines
fk_trunc:   db 0x10                                   ; MAX_DATA with its varint missing
; a CONNECTION_CLOSE behind a STREAM frame, then MAX_DATA behind the close: the
; exact shape the partial per-scanner tables used to lose
fk_seq_ok:  db 0x01, 0x0a, 0x03, 0x02, 0xAB, 0xCD, 0x1c, 0x01, 0x00, 0x00, 0x10, 0x41, 0x2C
fk_seq_ok_len equ $ - fk_seq_ok
fk_seq_bad: db 0x01, 0x22, 0x10, 0x41, 0x2C           ; an unknown type in the middle
fk_seq_bad_len equ $ - fk_seq_bad
; a payload whose last frame is cut short: PING, then a MAX_DATA missing its
; varint. RFC 9000 12.4 makes that a connection error too — it used to stop the
; walk quietly, so everything behind it went unread while the packet was acked.
fk_seq_trunc: db 0x01, 0x10
fk_seq_trunc_len equ $ - fk_seq_trunc

msg_head:  db "quic-rtx "
msg_head_len equ $ - msg_head
msg_slash: db "/"
msg_nl:    db 10

; PATH_CHALLENGE (0x1a + 8 bytes) bundled behind PADDING and a PING, plus trailing
; PADDING: reset_scan must walk past the other frames and still capture it.
tf_pc:     db 0x00, 0x01, 0x1a, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, 0x00
tf_pc_len  equ $ - tf_pc
tf_nopc:   db 0x00, 0x01, 0x00      ; PADDING + PING + PADDING, no challenge
tf_nopc_len equ $ - tf_nopc

section .bss
conn:      resb linnea_quic_conn_size
pairs:     resb LINNEA_QUIC_ACK_MAXR * 16
flow_out:  resb 16                 ; [max_data, max_stream_data] from a flow scan
rid_out:   resq 16                 ; reset-stream ids (unused here; a valid dest)
as_state:  resq 3                  ; have / largest / mask — the whole receive window

section .text


; --- receive-window helpers: the three qwords linnea_quic_ack_record keeps ---
%macro AS_INIT 0
    mov qword [as_state], 0
    mov qword [as_state + 8], 0
    mov qword [as_state + 16], 0
%endmacro

%macro AS_REC 1                         ; note packet number %1 as received
    lea rdi, [as_state]
    mov rsi, %1
    call linnea_quic_ack_record
%endmacro

%macro EXPECT_SEEN 2                    ; ack_seen(%1) must answer %2
    lea rdi, [as_state]
    mov rsi, %1
    call linnea_quic_ack_seen
    EXPECT rax, %2
%endmacro


%macro RTT 1                            ; fold one round-trip sample, in ms
    lea rdi, [conn]
    mov rsi, %1
    call linnea_quic_rtt_sample
%endmacro

%macro PTO 1                            ; %1 = 1 to include the peer's max_ack_delay
    lea rdi, [conn]
    mov esi, %1
    call linnea_quic_pto_ms
%endmacro


%macro FSKIP 2                          ; %1 = fixture, %2 = bytes available
    lea rdi, [%1]
    lea rsi, [%1 + %2]
    call linnea_quic_frame_skip
%endmacro

; record one packet: rsi = pn, into conn with the shared payload at now = 0.
%macro RECORD 1
    lea rdi, [conn]
    mov rsi, %1
    lea rdx, [pay]
    mov ecx, pay_len
    xor r8d, r8d
    call linnea_quic_rtx_record
%endmacro

; free [lo, hi] from conn's ring.
%macro ACKRANGE 2
    lea rdi, [conn]
    mov rsi, %1
    mov rdx, %2
    call linnea_quic_rtx_ack_range
%endmacro

%macro INFLIGHT 0
    lea rdi, [conn]
    call linnea_quic_rtx_inflight
%endmacro

_start:
    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; pass

    ; --- three packets buffered ---
    RECORD 5
    RECORD 6
    RECORD 7
    INFLIGHT
    EXPECT rax, 3

    ; --- acking a sub-range releases only those ---
    ACKRANGE 6, 7
    INFLIGHT
    EXPECT rax, 1                     ; pn 5 remains
    ACKRANGE 5, 5
    INFLIGHT
    EXPECT rax, 0

    ; --- the ring is bounded: extra packets are simply not tracked ---
    xor r12d, r12d
.fill:
    lea rdi, [conn]
    lea rsi, [r12 + 100]             ; distinct packet numbers
    lea rdx, [pay]
    mov ecx, pay_len
    xor r8d, r8d
    call linnea_quic_rtx_record
    inc r12d
    cmp r12d, LINNEA_QUIC_RTX_SLOTS + 2
    jb .fill
    INFLIGHT
    EXPECT rax, LINNEA_QUIC_RTX_SLOTS
    ACKRANGE 0, -1                    ; release everything
    INFLIGHT
    EXPECT rax, 0

    ; --- a payload larger than a record is not tracked ---
    lea rdi, [conn]
    mov esi, 9
    lea rdx, [pay]
    mov ecx, LINNEA_QUIC_RTX_PAYLOAD + 1
    xor r8d, r8d
    call linnea_quic_rtx_record
    INFLIGHT
    EXPECT rax, 0

    ; --- ACK-frame decoding: two ranges, [5,7] and [3,3] ---
    lea rdi, [ackframe]
    mov esi, ackframe_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    EXPECT rax, 2
    mov rax, [pairs]
    EXPECT rax, 5                     ; pair 0 smallest
    mov rax, [pairs + 8]
    EXPECT rax, 7                     ; pair 0 largest
    mov rax, [pairs + 16]
    EXPECT rax, 3                     ; pair 1 smallest
    mov rax, [pairs + 24]
    EXPECT rax, 3                     ; pair 1 largest

    ; --- the same ACK behind NEW_CONNECTION_ID + MAX_DATA is still decoded ---
    lea rdi, [ackframe_ncid]
    mov esi, ackframe_ncid_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    EXPECT rax, 2                     ; both ranges reached past the leading frames
    mov rax, [pairs]
    EXPECT rax, 5
    mov rax, [pairs + 8]
    EXPECT rax, 7
    mov rax, [pairs + 16]
    EXPECT rax, 3
    mov rax, [pairs + 24]
    EXPECT rax, 3

    ; --- the two together: buffer 3,5,7; ingest the ACK; all released ---
    RECORD 3
    RECORD 5
    RECORD 7
    INFLIGHT
    EXPECT rax, 3
    lea rdi, [ackframe]
    mov esi, ackframe_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    mov r12, rax                     ; pair count
    lea r13, [pairs]
.free:
    test r12, r12
    jz .freed
    lea rdi, [conn]
    mov rsi, [r13]
    mov rdx, [r13 + 8]
    call linnea_quic_rtx_ack_range
    add r13, 16
    dec r12
    jmp .free
.freed:
    INFLIGHT
    EXPECT rax, 0

    ; --- response-stream in-flight table (the congestion-controlled window) ---
    lea rdi, [conn]                 ; start clean
    call linnea_quic_txchunk_clear
    ; record two chunks; bytes_in_flight tracks their lengths
    lea rdi, [conn]
    mov esi, 40                     ; pn
    mov edx, 0                      ; offset
    mov ecx, 1100                   ; len
    xor r8d, r8d
    xor r9d, r9d                    ; stream index 0
    call linnea_quic_txchunk_record
    EXPECT rax, 1
    lea rdi, [conn]
    mov esi, 41
    mov edx, 1100
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    EXPECT rax, 1
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 2200
    ; ack the first chunk: returns its bytes, drops bytes_in_flight
    lea rdi, [conn]
    mov esi, 40
    mov edx, 40
    call linnea_quic_txchunk_ack
    EXPECT rax, 1100                ; bytes acknowledged
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 1100
    ; acking a pn not in flight frees nothing
    lea rdi, [conn]
    mov esi, 99
    mov edx, 99
    call linnea_quic_txchunk_ack
    EXPECT rax, 0
    ; clear zeroes bytes_in_flight
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 0

    ; --- retransmit, then a cumulative ack of the ORIGINAL pn must free the chunk.
    ; A resend moves .pn to a fresh number; QUIC acks are cumulative, so the peer
    ; keeps acking the delivered original. Matching only .pn would miss that ack and
    ; pin the window forever (the real-browser tail-chunk wedge). .pn0 fixes it.
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    lea rdi, [conn]
    mov esi, 40                     ; original pn
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    EXPECT rax, 1
    mov qword [conn + linnea_quic_conn.tx_infl + linnea_quic_txchunk.pn], 50 ; PTO resend
    lea rdi, [conn]                 ; ack covers the original (40), not the resend (50)
    mov esi, 38
    mov edx, 45
    call linnea_quic_txchunk_ack
    EXPECT rax, 1100                ; freed via .pn0
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 0
    ; symmetric case: an ack covering only the resend pn frees it via .pn
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    lea rdi, [conn]
    mov esi, 60
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    mov qword [conn + linnea_quic_conn.tx_infl + linnea_quic_txchunk.pn], 70
    lea rdi, [conn]
    mov esi, 68
    mov edx, 72
    call linnea_quic_txchunk_ack
    EXPECT rax, 1100
    ; a range covering neither the original nor the resend frees nothing
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    lea rdi, [conn]
    mov esi, 80
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    mov qword [conn + linnea_quic_conn.tx_infl + linnea_quic_txchunk.pn], 90
    lea rdi, [conn]
    mov esi, 100
    mov edx, 110
    call linnea_quic_txchunk_ack
    EXPECT rax, 0
    lea rdi, [conn]
    call linnea_quic_txchunk_clear

    ; the table is bounded: filling it, one more record is refused
    xor r12d, r12d
.tcfill:
    lea rdi, [conn]
    lea rsi, [r12 + 500]            ; distinct pns
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    inc r12d
    cmp r12d, LINNEA_QUIC_TXINFL_SLOTS
    jb .tcfill
    lea rdi, [conn]
    mov esi, 9000
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    EXPECT rax, 0                    ; full: caller must wait for acks
    lea rdi, [conn]
    call linnea_quic_txchunk_clear

    ; --- flow_scan: credit bundled behind other frames must still be absorbed ---
    ; (the multi-image page stalled over the real internet because a browser sends
    ; MAX_DATA behind NEW_CONNECTION_ID / STREAM frames that the scan used to stop at)
    mov qword [flow_out], 0
    mov qword [flow_out + 8], 0
    lea rdi, [fs_ncid]
    mov esi, fs_ncid_len
    xor edx, edx                    ; our stream id = 0
    lea rcx, [flow_out]
    call linnea_quic_flow_scan
    mov rax, [flow_out]
    EXPECT rax, 300                 ; MAX_DATA reached past NEW_CONNECTION_ID
    mov rax, [flow_out + 8]
    EXPECT rax, 500                 ; MAX_STREAM_DATA(0) reached too
    ; credit behind MAX_STREAMS + a data-carrying STREAM frame
    mov qword [flow_out], 0
    mov qword [flow_out + 8], 0
    lea rdi, [fs_stream]
    mov esi, fs_stream_len
    mov edx, 4                       ; our stream id = 4
    lea rcx, [flow_out]
    call linnea_quic_flow_scan
    mov rax, [flow_out + 8]
    EXPECT rax, 700                 ; MAX_STREAM_DATA(4) reached past the STREAM frame
    ; MAX_STREAM_DATA for another stream is not credited to ours, MAX_DATA still is
    mov qword [flow_out], 0
    mov qword [flow_out + 8], 0
    lea rdi, [fs_ncid]
    mov esi, fs_ncid_len
    mov edx, 7                       ; a stream not named in the packet
    lea rcx, [flow_out]
    call linnea_quic_flow_scan
    mov rax, [flow_out + 8]
    EXPECT rax, 0                    ; MAX_STREAM_DATA(0) is not for stream 7
    mov rax, [flow_out]
    EXPECT rax, 300                 ; but the connection MAX_DATA is still absorbed

    ; --- RFC 9218 priority parse: urgency + incremental, with defaults ---
    lea rdi, [prio_ui]
    mov esi, prio_ui_len
    call linnea_quic_parse_priority     ; "u=1, i"
    EXPECT rax, 1
    EXPECT rdx, 1
    lea rdi, [prio_u5]
    mov esi, prio_u5_len
    call linnea_quic_parse_priority     ; "u=5" -> urgency 5, non-incremental
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_i0]
    mov esi, prio_i0_len
    call linnea_quic_parse_priority     ; "i=?0, u=2" -> urgency 2, incremental off
    EXPECT rax, 2
    EXPECT rdx, 0
    lea rdi, [prio_bare_i]
    mov esi, prio_bare_i_len
    call linnea_quic_parse_priority     ; bare "i" -> default urgency, incremental
    EXPECT rax, 3
    EXPECT rdx, 1
    lea rdi, [prio_bad]
    mov esi, prio_bad_len
    call linnea_quic_parse_priority     ; "u=9" out of range -> defaults
    EXPECT rax, 3
    EXPECT rdx, 0
    xor edi, edi                        ; no priority header (len 0) -> defaults
    xor esi, esi
    call linnea_quic_parse_priority
    EXPECT rax, 3
    EXPECT rdx, 0

    ; --- reset_scan captures a PATH_CHALLENGE bundled behind other frames, so the
    ; receive path can echo it in a PATH_RESPONSE (RFC 9000 8.2) ---
    lea rdi, [tf_pc]
    mov esi, tf_pc_len
    lea rdx, [rid_out]
    mov ecx, 16
    call linnea_quic_reset_scan
    EXPECT qword [linnea_quic_path_seen], 1
    EXPECT qword [linnea_quic_path_data], 0x8877665544332211
    ; a scan with no challenge leaves the flag clear
    lea rdi, [tf_nopc]
    mov esi, tf_nopc_len
    lea rdx, [rid_out]
    mov ecx, 16
    call linnea_quic_reset_scan
    EXPECT qword [linnea_quic_path_seen], 0

    ; --- the receive window: which packet numbers do we know we have processed?
    ; RFC 9000 12.3 asks for certainty, not for a duplicate check, so the answers
    ; are "new", "seen", and — outside the 64-packet window — "cannot tell, so
    ; treat as seen". Knowing exactly would cost unbounded memory; this costs 24
    ; bytes and drops what it cannot vouch for.

    ; nothing received yet: everything is new
    AS_INIT
    EXPECT_SEEN 0, 0
    EXPECT_SEEN 12345, 0

    ; a straight run 0..199 leaves largest=199 and the 64 below it known
    AS_INIT
    mov ebx, 0
.as_fill:
    AS_REC rbx
    inc ebx
    cmp ebx, 200
    jb .as_fill
    EXPECT_SEEN 199, 1                  ; the largest itself
    EXPECT_SEEN 198, 1                  ; first inside the window
    EXPECT_SEEN 135, 1                  ; last inside the window (offset 63)
    EXPECT_SEEN 134, 1                  ; past it: unknowable, so "seen"
    EXPECT_SEEN 500, 0                  ; above the largest: certainly new

    ; a gap inside the window stays known-not-seen, and filling it is recorded
    AS_INIT
    AS_REC 100
    AS_REC 101
    AS_REC 103
    EXPECT_SEEN 102, 0                  ; skipped, still describable
    EXPECT_SEEN 101, 1
    AS_REC 102                          ; arrives late (reordering)
    EXPECT_SEEN 102, 1

    ; an old number we truly never saw is still dropped: uncertainty resolves the
    ; safe way, and it costs nothing because ack_record already refused to
    ; acknowledge anything that far back, so the peer must resend it regardless
    AS_INIT
    AS_REC 1000
    EXPECT_SEEN 10, 1

    ; the .ar_reset boundary. A delta of exactly 64 puts the OLD largest at
    ; offset 63 — still inside the new window. Clearing the mask wholesale
    ; forgot it and made that one packet replayable once.
    AS_INIT
    AS_REC 100
    AS_REC 163                          ; delta 63: shift path keeps the bit
    EXPECT_SEEN 100, 1
    AS_INIT
    AS_REC 100
    AS_REC 164                          ; delta 64: reset path must keep it too
    EXPECT_SEEN 100, 1
    AS_INIT
    AS_REC 100
    AS_REC 165                          ; delta 65: offset 64, genuinely outside
    EXPECT_SEEN 100, 1                  ; ...so "cannot tell" -> seen


    ; --- RTT estimation (RFC 9002 5.3, 6.2.1) ---
    ; Before any sample the kInitialRtt defaults stand in: srtt 333, rttvar 166,
    ; so PTO = 333 + 4*166 = 997, and 1022 once the peer's max_ack_delay applies.
    ; This is deliberately slower than the flat 250 ms it replaced — the RFC
    ; would rather wait than retransmit into a path it has not measured.
    mov qword [conn + linnea_quic_conn.rtt_have], 0
    mov qword [conn + linnea_quic_conn.srtt], 0
    mov qword [conn + linnea_quic_conn.rttvar], 0
    mov qword [conn + linnea_quic_conn.min_rtt], 0
    PTO 0
    EXPECT rax, 997
    PTO 1
    EXPECT rax, 1022

    ; the first sample is adopted outright: srtt = latest, rttvar = latest/2
    RTT 100
    EXPECT qword [conn + linnea_quic_conn.srtt], 100
    EXPECT qword [conn + linnea_quic_conn.rttvar], 50
    EXPECT qword [conn + linnea_quic_conn.min_rtt], 100
    PTO 0
    EXPECT rax, 300                     ; 100 + 4*50

    ; a second identical sample: rttvar decays toward 0, srtt holds
    RTT 100
    EXPECT qword [conn + linnea_quic_conn.srtt], 100
    EXPECT qword [conn + linnea_quic_conn.rttvar], 37   ; (3*50 + 0) / 4

    ; a faster sample lowers min_rtt and pulls srtt down by an eighth of the gap
    RTT 60
    EXPECT qword [conn + linnea_quic_conn.min_rtt], 60
    EXPECT qword [conn + linnea_quic_conn.srtt], 95     ; (7*100 + 60) / 8
    EXPECT qword [conn + linnea_quic_conn.rttvar], 37   ; (3*37 + 40) / 4

    ; min_rtt never rises again on a slower sample
    RTT 500
    EXPECT qword [conn + linnea_quic_conn.min_rtt], 60

    ; a long-RTT path settles high, so its probes stop firing spuriously —
    ; this is the case the flat 250 ms got wrong, halving cwnd on every pass
    mov qword [conn + linnea_quic_conn.rtt_have], 0
    mov qword [conn + linnea_quic_conn.srtt], 0
    mov qword [conn + linnea_quic_conn.rttvar], 0
    mov qword [conn + linnea_quic_conn.min_rtt], 0
    mov r12d, 40
.rtt_settle:
    RTT 400
    dec r12d
    jnz .rtt_settle
    EXPECT qword [conn + linnea_quic_conn.srtt], 400
    PTO 1
    mov rcx, rax
    EXPECT_ABOVE rcx, 400               ; a 400 ms path must not probe under 400 ms

    ; the floor holds when a link is faster than the timer can express
    mov qword [conn + linnea_quic_conn.rtt_have], 0
    mov qword [conn + linnea_quic_conn.srtt], 0
    mov qword [conn + linnea_quic_conn.rttvar], 0
    mov qword [conn + linnea_quic_conn.min_rtt], 0
    RTT 0
    EXPECT qword [conn + linnea_quic_conn.srtt], 0      ; a real 0 ms measurement
    PTO 0
    EXPECT rax, LINNEA_QUIC_PTO_FLOOR   ; ...but never probe that fast

    ; and the ceiling caps a pathological estimate before backoff multiplies it
    mov qword [conn + linnea_quic_conn.rtt_have], 1
    mov qword [conn + linnea_quic_conn.srtt], 60000
    mov qword [conn + linnea_quic_conn.rttvar], 60000
    PTO 1
    EXPECT rax, LINNEA_QUIC_PTO_CEIL


    ; --- the shared frame-length table (RFC 9000 19) ---
    ; Six scanners used to carry partial copies of this and stop at the first
    ; type theirs did not list. Every length here is one of those copies' gaps.
    FSKIP fk_pad, 1
    EXPECT rax, 1                       ; PADDING
    FSKIP fk_ping, 1
    EXPECT rax, 1                       ; PING
    FSKIP fk_hd, 1
    EXPECT rax, 1                       ; HANDSHAKE_DONE
    FSKIP fk_pc, 9
    EXPECT rax, 9                       ; PATH_CHALLENGE
    FSKIP fk_maxdata, 3
    EXPECT rax, 3                       ; MAX_DATA
    FSKIP fk_reset, 4
    EXPECT rax, 4                       ; RESET_STREAM
    FSKIP fk_close, 4
    EXPECT rax, 4                       ; CONNECTION_CLOSE — unknown to four walks
    FSKIP fk_closea, 3
    EXPECT rax, 3                       ; CONNECTION_CLOSE (application)
    FSKIP fk_stream, 5
    EXPECT rax, 5                       ; STREAM with a length
    FSKIP fk_strnol, 5
    EXPECT rax, 5                       ; STREAM without one: runs to the end
    FSKIP fk_ncid, 24
    EXPECT rax, 24                      ; NEW_CONNECTION_ID
    FSKIP fk_ack, 7
    EXPECT rax, 7                       ; ACK
    FSKIP fk_ackecn, 8
    EXPECT rax, 8                       ; ACK with ECN counts
    FSKIP fk_ack3, 9
    EXPECT rax, 9                       ; ACK carrying three ranges
    FSKIP fk_closer, 6
    EXPECT rax, 6                       ; CONNECTION_CLOSE with a reason phrase

    ; a type RFC 9000 does not define is reported, with the type for the close
    FSKIP fk_unk, 1
    EXPECT rax, -1
    EXPECT rdx, 0x22
    ; and a frame that runs off the end is truncation, not an unknown type
    FSKIP fk_trunc, 1
    EXPECT rax, 0
    ; the same MAX_DATA, one byte short of complete
    FSKIP fk_maxdata, 2
    EXPECT rax, 0

    ; a lie about a length must not walk past the buffer
    FSKIP fk_stream, 3                  ; claims 2 bytes of data that are not there
    EXPECT rax, 0

    ; whole payloads: the shape that used to lose frames must now walk clean
    lea rdi, [fk_seq_ok]
    mov esi, fk_seq_ok_len
    call linnea_quic_frames_check
    EXPECT rax, 0
    ; ...and an unknown type anywhere in it is a connection error, named
    lea rdi, [fk_seq_bad]
    mov esi, fk_seq_bad_len
    call linnea_quic_frames_check
    EXPECT rax, -1
    EXPECT rdx, 0x22
    ; ...and so is a last frame that runs past the end of the payload. The type
    ; reported is 0, which 19.19 defines as "the frame type is unknown" — the
    ; bytes naming it may be the very ones that did not fit.
    lea rdi, [fk_seq_trunc]
    mov esi, fk_seq_trunc_len
    call linnea_quic_frames_check
    EXPECT rax, -1
    EXPECT rdx, 0

    ; print "quic-rtx <pass>/<total>\n"
    lea rdi, [msg_head]
    mov esi, msg_head_len
    call linnea_print_stdout
    mov edi, r15d
    call linnea_print_u64_stdout
    lea rdi, [msg_slash]
    mov esi, 1
    call linnea_print_stdout
    mov edi, r14d
    call linnea_print_u64_stdout
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stdout

    xor edi, edi
    cmp r15d, r14d
    je .exit
    mov edi, 1
.exit:
    mov eax, LINNEA_SYS_EXIT
    syscall
