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
msg_head:  db "quic-rtx "
msg_head_len equ $ - msg_head
msg_slash: db "/"
msg_nl:    db 10

section .bss
conn:      resb linnea_quic_conn_size
pairs:     resb LINNEA_QUIC_ACK_MAXR * 16
flow_out:  resb 16                 ; [max_data, max_stream_data] from a flow scan

section .text

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
