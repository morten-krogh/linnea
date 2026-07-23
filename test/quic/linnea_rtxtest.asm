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
msg_head:  db "quic-rtx "
msg_head_len equ $ - msg_head
msg_slash: db "/"
msg_nl:    db 10

section .bss
conn:      resb linnea_quic_conn_size
pairs:     resb LINNEA_QUIC_ACK_MAXR * 16

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
    call linnea_quic_txchunk_record
    EXPECT rax, 1
    lea rdi, [conn]
    mov esi, 41
    mov edx, 1100
    mov ecx, 1100
    xor r8d, r8d
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
    call linnea_quic_txchunk_record
    inc r12d
    cmp r12d, LINNEA_QUIC_TXINFL_SLOTS
    jb .tcfill
    lea rdi, [conn]
    mov esi, 9000
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    call linnea_quic_txchunk_record
    EXPECT rax, 0                    ; full: caller must wait for acks
    lea rdi, [conn]
    call linnea_quic_txchunk_clear

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
