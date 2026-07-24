; linnea_quic_debug.asm — opt-in QUIC connection-state tracing for diagnosing
; real-browser hangs the synthetic (aioquic) tests can't reproduce. It is dark
; until the operator creates the trigger file "linnea-qdbg" in the server's
; working directory (next to the log); the sweep then dumps every live
; connection's flow-control, congestion and per-stream progress to the server
; log once a second, so a stalled transfer shows exactly which gate is stuck
; (stream/conn flow control, congestion window, or a request whose reassembly
; never finished). Remove the file to go dark again — no restart.
;
; The trigger lives in the working directory, NOT /tmp, on purpose: the systemd
; unit sets PrivateTmp=true, so a /tmp file the operator creates is in a
; different mount namespace and the service would never see it. The working
; directory (where the log already lands) is shared, so the trigger works there.
;
; The cost when dark is one access() syscall per worker per second and nothing
; else, so it is safe to ship in the production binary.

default rel

%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"

global linnea_quic_dbg_tick
global linnea_quic_dbg_conn
global linnea_quic_dbg_rx
global qdbg_on
global qdbg_pass

extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp

LINNEA_SYS_ACCESS equ 21
QDBG_PERIOD       equ 20            ; sweep ticks per poll/dump (50 ms tick => ~1 s)

section .rodata
; relative to the server's working directory (like the "log" path), so it is
; visible despite the unit's PrivateTmp namespace — see the file header.
qdbg_path:  db "linnea-qdbg", 0

; label pieces for the dump lines; each has a matching _len
s_hdr:   db "qdbg cid="
s_hdr_len   equ $ - s_hdr
s_st:    db " st="
s_st_len    equ $ - s_st
s_la:    db " la="
s_la_len    equ $ - s_la
s_ms:    db " ms="
s_ms_len    equ $ - s_ms
s_cw:    db " cw="
s_cw_len    equ $ - s_cw
s_infl:  db " infl="
s_infl_len  equ $ - s_infl
s_fc:    db " fc="
s_fc_len    equ $ - s_fc
s_txn:   db " tx="
s_txn_len   equ $ - s_txn
s_ran:   db " ra="
s_ran_len   equ $ - s_ran
s_slash: db "/"
s_slash_len equ $ - s_slash
s_nl:    db 10
s_nl_len    equ $ - s_nl
s_tx:    db "qdbg   tx sid="
s_tx_len   equ $ - s_tx
s_off:   db " off="
s_off_len   equ $ - s_off
s_fcm:   db " fcm="
s_fcm_len   equ $ - s_fcm
s_sin:   db " infl="
s_sin_len   equ $ - s_sin
s_u:     db " u="
s_u_len     equ $ - s_u
s_i:     db " i="
s_i_len     equ $ - s_i
s_ra:    db "qdbg   ra sid="
s_ra_len   equ $ - s_ra
s_len:   db " len="
s_len_len   equ $ - s_len
s_hi:    db " hi="
s_hi_len    equ $ - s_hi
s_fin:   db " fin="
s_fin_len   equ $ - s_fin
s_rx:    db "qrx dcid="
s_rx_len   equ $ - s_rx
s_rxsrc: db " src="
s_rxsrc_len equ $ - s_rxsrc
s_rxport: db " port="
s_rxport_len equ $ - s_rxport
s_rxlen: db " len="
s_rxlen_len equ $ - s_rxlen
s_rxhf:  db " hf="
s_rxhf_len equ $ - s_rxhf

section .bss
qdbg_on:   resb 1               ; 1 while tracing is enabled (readable by others)
qdbg_pass: resb 1               ; 1 on the sweep pass that should dump connections
qdbg_tick: resq 1

section .text

; emit a fixed rodata string: %1 is the label, %1_len its length.
%macro W 1
    lea rdi, [%1]
    mov esi, %1 %+ _len
    call linnea_log_write
%endmacro

; emit conn/slot field %2 (offset from base register %1) as a decimal number.
%macro NUM 2
    mov rdi, [%1 + %2]
    call linnea_log_u64
%endmacro

; linnea_quic_dbg_tick() -> al = 1 if this sweep pass should dump connections.
; Called once per sweep. Every QDBG_PERIOD-th pass it re-reads the trigger file
; and refreshes qdbg_on; other passes report "no dump" without a syscall.
linnea_quic_dbg_tick:
    mov byte [qdbg_pass], 0
    inc qword [qdbg_tick]
    mov rax, [qdbg_tick]
    xor edx, edx
    mov ecx, QDBG_PERIOD
    div rcx
    test rdx, rdx
    jnz .nodump                 ; not a poll pass
    mov eax, LINNEA_SYS_ACCESS
    lea rdi, [qdbg_path]
    xor esi, esi                ; F_OK
    syscall
    test rax, rax
    jnz .off
    mov byte [qdbg_on], 1
    mov byte [qdbg_pass], 1
    mov al, 1
    ret
.off:
    mov byte [qdbg_on], 0
.nodump:
    xor eax, eax
    ret

; linnea_quic_dbg_conn(rdi = conn*) — one connection's state to the log: the
; header line (flow control / congestion), then a line per open response stream
; and per in-progress request reassembly. rbx/r13/r14 hold state across the log
; calls, all callee-saved, so the sweep's own registers survive the call.
linnea_quic_dbg_conn:
    push rbx
    push r13
    push r14
    push r15
    mov rbx, rdi

    ; count active response streams
    xor r15d, r15d
    lea r13, [rbx + linnea_quic_conn.tx_streams]
    xor r14d, r14d
.cnt_tx:
    cmp qword [r13 + linnea_quic_txstream.active], 0
    je .cnt_tx_n
    inc r15d
.cnt_tx_n:
    add r13, linnea_quic_txstream_size
    inc r14d
    cmp r14d, LINNEA_QUIC_TXSTREAMS
    jb .cnt_tx
    push r15                    ; active tx count

    ; count active reassembly contexts
    xor r15d, r15d
    lea r13, [rbx + linnea_quic_conn.ra_ctx]
    xor r14d, r14d
.cnt_ra:
    cmp qword [r13 + linnea_quic_ra.active], 0
    je .cnt_ra_n
    inc r15d
.cnt_ra_n:
    add r13, linnea_quic_ra_size
    inc r14d
    cmp r14d, LINNEA_QUIC_RA_CTXS
    jb .cnt_ra
                                ; stack: [r15 saved][ra count in r15]

    ; --- header line ---
    call linnea_log_stamp
    W s_hdr
    NUM rbx, linnea_quic_conn.scid          ; first 8 bytes as a connection tag
    W s_st
    NUM rbx, linnea_quic_conn.state
    W s_la
    NUM rbx, linnea_quic_conn.last_active
    W s_ms
    NUM rbx, linnea_quic_conn.ms_bidi_max
    W s_cw
    NUM rbx, linnea_quic_conn.cwnd
    W s_infl
    NUM rbx, linnea_quic_conn.bytes_in_flight
    W s_fc
    NUM rbx, linnea_quic_conn.fc_conn_sent
    W s_slash
    NUM rbx, linnea_quic_conn.fc_conn_max
    W s_txn
    mov rdi, [rsp]              ; tx count (saved on the stack; r15 now holds ra count)
    call linnea_log_u64
    W s_ran
    mov rdi, r15
    call linnea_log_u64
    W s_nl
    ; the saved tx count stays on the stack as an aligning slot (rsp % 16 == 0),
    ; so the calls in the loops below remain ABI-aligned; dropped before the pops.

    ; --- per open response stream ---
    lea r13, [rbx + linnea_quic_conn.tx_streams]
    xor r14d, r14d
.tx:
    cmp qword [r13 + linnea_quic_txstream.active], 0
    je .tx_n
    call linnea_log_stamp
    W s_tx
    NUM r13, linnea_quic_txstream.sid
    W s_off
    NUM r13, linnea_quic_txstream.off
    W s_slash
    NUM r13, linnea_quic_txstream.size
    W s_fcm
    NUM r13, linnea_quic_txstream.fc_max
    W s_sin
    NUM r13, linnea_quic_txstream.inflight
    W s_u
    NUM r13, linnea_quic_txstream.urgency
    W s_i
    NUM r13, linnea_quic_txstream.incremental
    W s_nl
.tx_n:
    add r13, linnea_quic_txstream_size
    inc r14d
    cmp r14d, LINNEA_QUIC_TXSTREAMS
    jb .tx

    ; --- per in-progress request reassembly ---
    lea r13, [rbx + linnea_quic_conn.ra_ctx]
    xor r14d, r14d
.ra:
    cmp qword [r13 + linnea_quic_ra.active], 0
    je .ra_n
    call linnea_log_stamp
    W s_ra
    NUM r13, linnea_quic_ra.sid
    W s_len
    NUM r13, linnea_quic_ra.len
    W s_slash
    NUM r13, linnea_quic_ra.final
    W s_hi
    NUM r13, linnea_quic_ra.hi
    W s_fin
    NUM r13, linnea_quic_ra.fin
    W s_nl
.ra_n:
    add r13, linnea_quic_ra_size
    inc r14d
    cmp r14d, LINNEA_QUIC_RA_CTXS
    jb .ra

    add rsp, 8                  ; drop the aligning tx-count slot
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; linnea_quic_dbg_rx(rdi = rxbuf, rsi = datagram len, rdx = source sockaddr) —
; log one arriving datagram: the connection id it targets (dcid: the id WE issued,
; so it matches the state dump's cid= tag), the source address and port, the length
; and the header form (0 short / 1 long). Dark unless the trigger is set. This is
; the receive-side counterpart to the per-connection dump: when a connection's dump
; shows la frozen (nothing received), this says whether the peer's datagrams were
; arriving-but-dropped (present here, wrong/absent connection) or truly absent.
linnea_quic_dbg_rx:
    cmp byte [qdbg_on], 0
    jne .on
    ret
.on:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov r15, rsi                 ; datagram length
    movzx eax, byte [rdi]        ; header form + dcid
    test al, 0x80
    jz .short
    mov ebp, 1                   ; long header
    mov rbx, [rdi + 6]           ; long-header DCID (first 8 bytes)
    jmp .haveid
.short:
    xor ebp, ebp                 ; short header
    mov rbx, [rdi + 1]           ; short-header DCID = the id we issued
.haveid:
    mov r13d, [rdx + 4]          ; sin_addr (u32)
    movzx eax, word [rdx + 2]    ; sin_port (network order)
    xchg al, ah                  ; -> host order
    movzx r14d, ax
    call linnea_log_stamp
    W s_rx
    mov rdi, rbx
    call linnea_log_u64
    W s_rxsrc
    mov rdi, r13
    call linnea_log_u64
    W s_rxport
    mov rdi, r14
    call linnea_log_u64
    W s_rxlen
    mov rdi, r15
    call linnea_log_u64
    W s_rxhf
    mov rdi, rbp
    call linnea_log_u64
    W s_nl
    pop r15
    pop r14
    pop r13
    pop rbp
    pop rbx
    ret
