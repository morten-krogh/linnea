; linnea_bpf.asm — eBPF connection-ID steering for the QUIC reuseport group.
;
; A SK_REUSEPORT program reads the QUIC packet's Destination Connection ID and
; steers the datagram to the worker that owns the connection: the steering index
; is the first byte of the DCID (short header: offset 1; long header: offset 6),
; used as the index into a REUSEPORT_SOCKARRAY the workers register into. An
; index with no socket (a client's random first-Initial CID, or a worker not yet
; up) makes the helper fail, and the program returns SK_PASS so the kernel falls
; back to its 4-tuple hash. bpf(2) is called directly with a hand-built attr
; block and hand-assembled program bytecode; loading needs CAP_BPF.
;
; The map and program live as long as the SERVICE, not the process: a hot
; upgrade hands both fds to the next generation (see the upgrade env in
; linnea_start.asm), which registers its sockets under the other half of the
; index space (steer_base 0 <-> LINNEA_BPF_STEER_HALF). Loading fresh instead would detach the old
; program from the group, and every draining worker's connection — its ids
; carry the old generation's indices — would steer to the new worker at that
; index, which has no state for it and answers with a stateless reset.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_bpf_reuseport_setup
global linnea_bpf_map_add
global linnea_bpf_attach
global linnea_bpf_probe
global linnea_bpf_map_fd
global linnea_bpf_prog_fd

extern linnea_print_stderr
extern linnea_print_u64_stderr

%define SYS_BPF 321
%define SYS_SETSOCKOPT 54
%define BPF_MAP_CREATE 0
%define BPF_MAP_UPDATE_ELEM 2
%define BPF_PROG_LOAD  5
%define MAP_TYPE_REUSEPORT_SOCKARRAY 20
%define PROG_TYPE_SK_REUSEPORT       21
%define SOL_SOCKET 1
%define SO_ATTACH_REUSEPORT_EBPF 52

section .rodata
gpl:  db "GPL", 0
; The steering program. Registers r0..r10; each instruction is 8 bytes
; {u8 opcode, u8 dst:4|src:4, s16 off, s32 imm}. Instruction 12 (the map-fd
; load) has its imm patched with the real map fd before the program is loaded.
prog_insns:
    ; ctx->data points at the UDP header, so the QUIC bytes are +8: the first
    ; byte is at 8, the short-header DCID at 9, the long-header DCID at 14.
    db 0x79, 0x12, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 0  r2 = *(u64*)(r1+0)   ctx->data
    db 0x79, 0x13, 0x08,0x00, 0x00,0x00,0x00,0x00   ; 1  r3 = *(u64*)(r1+8)   ctx->data_end
    db 0xbf, 0x24, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 2  r4 = r2
    db 0x07, 0x04, 0x00,0x00, 0x0f,0x00,0x00,0x00   ; 3  r4 += 15
    db 0x2d, 0x34, 0x0f,0x00, 0x00,0x00,0x00,0x00   ; 4  if r4 > r3 goto +15 (fallback)
    db 0x71, 0x25, 0x08,0x00, 0x00,0x00,0x00,0x00   ; 5  r5 = *(u8*)(r2+8)     first byte
    db 0x57, 0x05, 0x00,0x00, 0x80,0x00,0x00,0x00   ; 6  r5 &= 0x80            header form
    db 0x55, 0x05, 0x02,0x00, 0x00,0x00,0x00,0x00   ; 7  if r5 != 0 goto +2 (long)
    db 0x71, 0x25, 0x09,0x00, 0x00,0x00,0x00,0x00   ; 8  r5 = *(u8*)(r2+9)     short: worker byte
    db 0x05, 0x00, 0x01,0x00, 0x00,0x00,0x00,0x00   ; 9  goto +1 (select)
    db 0x71, 0x25, 0x0e,0x00, 0x00,0x00,0x00,0x00   ; 10 r5 = *(u8*)(r2+14)    long: worker byte
    db 0x63, 0x5a, 0xfc,0xff, 0x00,0x00,0x00,0x00   ; 11 *(u32*)(r10-4) = r5   the index
    db 0x18, 0x12, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 12 r2 = map_fd (patched) part 1
    db 0x00, 0x00, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 13 (map-fd load part 2)
    db 0xbf, 0xa3, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 14 r3 = r10
    db 0x07, 0x03, 0x00,0x00, 0xfc,0xff,0xff,0xff   ; 15 r3 += -4              &index
    db 0xb7, 0x04, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 16 r4 = 0                flags
    db 0x85, 0x00, 0x00,0x00, 0x52,0x00,0x00,0x00   ; 17 call bpf_sk_select_reuseport (82)
    db 0xb7, 0x00, 0x00,0x00, 0x01,0x00,0x00,0x00   ; 18 r0 = 1                SK_PASS
    db 0x95, 0x00, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 19 exit
    db 0xb7, 0x00, 0x00,0x00, 0x01,0x00,0x00,0x00   ; 20 r0 = 1 (fallback)     SK_PASS
    db 0x95, 0x00, 0x00,0x00, 0x00,0x00,0x00,0x00   ; 21 exit
prog_insns_len equ $ - prog_insns
prog_insns_cnt equ prog_insns_len / 8
MAP_FD_IMM_OFF equ 12 * 8 + 4       ; byte offset of insn 12's imm (the map fd)

msg_setup: db "bpf setup: "
msg_setup_len equ $ - msg_setup
msg_ok:   db "ok prog fd="
msg_ok_len   equ $ - msg_ok
; The probe is the only thing an operator has to find out why QUIC steering is
; not working, so it must say WHICH step refused and with what errno. It used
; to answer "FAILED err=1" for all six causes: every failure path returned the
; sentinel -1, and the probe negated it. That the sentinel happens to print as
; EPERM — much the commonest real cause — is why it read as plausible.
msg_failat: db "FAILED at "
msg_failat_len equ $ - msg_failat
msg_errno: db ": errno="
msg_errno_len equ $ - msg_errno
; and a steering mismatch is not an errno at all: everything loaded, and the
; packets went to the wrong sockets. The per-worker "W>R " lines above say which.
msg_steer: db "FAILED: loaded and attached, but a datagram did not steer by its "
           db "worker byte", 10
msg_steer_len equ $ - msg_steer
msg_log:  db 10, "verifier log:", 10
msg_log_len equ $ - msg_log
msg_nl:   db 10

stg_mapcreate: db "map create"
stg_mapcreate_len equ $ - stg_mapcreate
stg_progload:  db "program load"
stg_progload_len equ $ - stg_progload
stg_socket:    db "socket"
stg_socket_len equ $ - stg_socket
stg_reuseport: db "SO_REUSEPORT"
stg_reuseport_len equ $ - stg_reuseport
stg_bind:      db "bind"
stg_bind_len   equ $ - stg_bind
stg_client:    db "client socket"
stg_client_len equ $ - stg_client
stg_send:      db "sendto"
stg_send_len   equ $ - stg_send
stg_mapupdate: db "map update"
stg_mapupdate_len equ $ - stg_mapupdate
stg_attach:    db "attach"
stg_attach_len equ $ - stg_attach
stg_getsockname: db "getsockname"
stg_getsockname_len equ $ - stg_getsockname

section .bss
bpf_attr:      resb 128
prog_scratch:  resb prog_insns_len   ; a writable copy (the map fd is patched in)
verifier_log:  resb 8192
linnea_bpf_map_fd:  resq 1           ; the REUSEPORT_SOCKARRAY, -1 until created
linnea_bpf_prog_fd: resq 1           ; the steering program, -1 until loaded
mu_key:        resd 1                ; a map-update key (index)
mu_val:        resd 1                ; a map-update value (socket fd)
st_socks:      resd 4                ; the self-test's reuseport sockets
st_one:        resd 1
st_pkt:        resb 32
st_rcv:        resb 64
; The address the self-test's reuseport group binds. Built at run time with
; port 0 so the KERNEL picks one that is free, then overwritten by getsockname
; with the port it picked, which the remaining three binds and the client's
; sendto then use. A hardcoded port was the bug: the old 47610 sits inside this
; box's ephemeral range (32768-60999), so an unrelated process's client socket
; could already hold it and the probe would report the bind failure as if BPF
; itself were broken. Choosing a higher fixed number only narrows that window;
; asking the kernel closes it, and cannot collide with a suite fixture either.
st_saddr:      resb 16
st_alen:       resd 1                ; socklen_t, in and out
; which step is in flight, so a refusal can name itself rather than collapse
st_stage_ptr:  resq 1
st_stage_len:  resq 1
st_mismatch:   resb 1                ; steering went to the wrong socket

section .text

; STAGE name — record which step is about to run. Clobbers rax, so it goes
; immediately before the syscall number is loaded.
%macro STAGE 1
    lea rax, [%1]
    mov [st_stage_ptr], rax
    mov rax, %1 %+ _len
    mov [st_stage_len], rax
%endmacro

; linnea_bpf_reuseport_setup() -> rax = program fd (>= 0), or -errno on failure.
; Creates the REUSEPORT_SOCKARRAY (stored in linnea_bpf_map_fd) and loads the
; steering program with the map fd patched in. Idempotent enough for one call.
linnea_bpf_reuseport_setup:
    push rbx
    mov qword [linnea_bpf_map_fd], -1
    mov qword [linnea_bpf_prog_fd], -1
    ; --- create the map ---
    call zero_attr
    mov dword [bpf_attr], MAP_TYPE_REUSEPORT_SOCKARRAY
    mov dword [bpf_attr + 4], 4               ; key_size = u32 index
    mov dword [bpf_attr + 8], 4               ; value_size = socket fd
    mov dword [bpf_attr + 12], 2 * LINNEA_BPF_STEER_HALF   ; max_entries: the whole one-byte index range
    STAGE stg_mapcreate
    mov eax, SYS_BPF
    mov edi, BPF_MAP_CREATE
    lea rsi, [bpf_attr]
    mov edx, 64
    syscall
    test rax, rax
    js .ret                                   ; -errno
    mov [linnea_bpf_map_fd], rax
    mov ebx, eax                              ; map fd
    ; --- copy the program and patch in the map fd ---
    lea rdi, [prog_scratch]
    lea rsi, [prog_insns]
    mov ecx, prog_insns_len
    rep movsb
    mov [prog_scratch + MAP_FD_IMM_OFF], ebx
    ; --- load the program ---
    call zero_attr
    mov dword [bpf_attr], PROG_TYPE_SK_REUSEPORT
    mov dword [bpf_attr + 4], prog_insns_cnt
    lea rax, [prog_scratch]
    mov [bpf_attr + 8], rax                   ; insns
    lea rax, [gpl]
    mov [bpf_attr + 16], rax                  ; license
    mov dword [bpf_attr + 24], 1              ; log_level
    mov dword [bpf_attr + 28], 8192           ; log_size
    lea rax, [verifier_log]
    mov [bpf_attr + 32], rax                  ; log_buf
    STAGE stg_progload
    mov eax, SYS_BPF
    mov edi, BPF_PROG_LOAD
    lea rsi, [bpf_attr]
    mov edx, 72
    syscall
    test rax, rax
    js .ret                                   ; -errno (map created, program not)
    mov [linnea_bpf_prog_fd], rax
.ret:
    pop rbx
    ret

; linnea_bpf_map_add(edi = index, esi = socket fd) -> rax = 0 or -errno.
; Register a worker's reuseport socket at its index in the map.
linnea_bpf_map_add:
    mov [mu_key], edi
    mov [mu_val], esi
    call zero_attr
    mov eax, [linnea_bpf_map_fd]
    mov [bpf_attr], eax                       ; map_fd
    lea rax, [mu_key]
    mov [bpf_attr + 8], rax                   ; key ptr
    lea rax, [mu_val]
    mov [bpf_attr + 16], rax                  ; value ptr
    mov qword [bpf_attr + 24], 0              ; flags = BPF_ANY
    mov eax, SYS_BPF
    mov edi, BPF_MAP_UPDATE_ELEM
    lea rsi, [bpf_attr]
    mov edx, 32
    syscall
    ret

; linnea_bpf_attach(edi = socket fd, esi = program fd) -> rax = 0 or -errno.
; Attach the steering program to the reuseport group via one of its sockets.
linnea_bpf_attach:
    mov [mu_val], esi                         ; the setsockopt value is the prog fd
    mov eax, SYS_SETSOCKOPT
    ; edi already = socket fd
    mov esi, SOL_SOCKET
    mov edx, SO_ATTACH_REUSEPORT_EBPF
    lea r10, [mu_val]
    mov r8d, 4
    syscall
    ret

; zero_attr — clear the 128-byte attribute block.
zero_attr:
    push rdi
    push rcx
    push rax
    lea rdi, [bpf_attr]
    xor eax, eax
    mov ecx, 128
    rep stosb
    pop rax
    pop rcx
    pop rdi
    ret

; linnea_bpf_selftest() -> rax = the program fd (>= 0) once the whole sequence
; ran, or -errno from whichever syscall refused, with st_stage_* naming it.
; Steering that ran but routed wrongly is NOT an errno and is reported through
; st_mismatch instead, so no sentinel can be mistaken for one. Builds a
; 4-socket reuseport group, registers and attaches the program, and checks a
; short-header packet with worker byte W lands on socket W. Confirms the packet
; offsets the program reads.
linnea_bpf_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov byte [st_mismatch], 0
    call linnea_bpf_reuseport_setup
    test rax, rax
    js .st_fail
    ; 127.0.0.1, port 0 — the first bind makes the kernel choose a free port,
    ; and getsockname below writes it back here for the other three and the send
    mov word [st_saddr], 2                    ; AF_INET
    mov word [st_saddr + 2], 0                ; port 0
    mov dword [st_saddr + 4], 0x0100007F      ; 127.0.0.1, network order
    mov dword [st_saddr + 8], 0
    mov dword [st_saddr + 12], 0
    xor r12d, r12d                    ; socket index
.st_mk:
    STAGE stg_socket
    mov eax, LINNEA_SYS_SOCKET
    mov edi, 2                        ; AF_INET
    mov esi, 2                        ; SOCK_DGRAM
    xor edx, edx
    syscall
    test rax, rax
    js .st_fail
    mov [st_socks + r12*4], eax
    mov r13d, eax
    mov dword [st_one], 1
    STAGE stg_reuseport
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov edi, r13d
    mov esi, SOL_SOCKET
    mov edx, 15                       ; SO_REUSEPORT
    lea r10, [st_one]
    mov r8d, 4
    syscall
    test rax, rax                     ; unchecked, this surfaced as the SECOND
    js .st_fail                       ; bind's EADDRINUSE — a different step
    STAGE stg_bind
    mov eax, LINNEA_SYS_BIND
    mov edi, r13d
    lea rsi, [st_saddr]
    mov edx, 16
    syscall
    test rax, rax
    js .st_fail
    test r12d, r12d
    jnz .st_bound                     ; the port is already the kernel's answer
    STAGE stg_getsockname
    mov dword [st_alen], 16
    mov eax, LINNEA_SYS_GETSOCKNAME
    mov edi, r13d
    lea rsi, [st_saddr]
    lea rdx, [st_alen]
    syscall
    test rax, rax
    js .st_fail
.st_bound:
    STAGE stg_mapupdate
    mov edi, r12d
    mov esi, r13d
    call linnea_bpf_map_add           ; map[i] = socket
    test rax, rax
    js .st_fail
    inc r12d
    cmp r12d, 4
    jb .st_mk
    STAGE stg_attach
    mov edi, [st_socks]               ; attach the program to the group
    mov esi, [linnea_bpf_prog_fd]     ; not a register: r15 is the receiver below
    call linnea_bpf_attach
    test rax, rax
    js .st_fail
    STAGE stg_client
    mov eax, LINNEA_SYS_SOCKET        ; a client socket to send from
    mov edi, 2
    mov esi, 2
    xor edx, edx
    syscall
    test rax, rax                     ; unchecked, a refusal here reached the
    js .st_fail                       ; loop below and read as a steering failure
    mov r14d, eax
    mov rbx, -1                       ; rbx = 0 while every W steers to socket W
    xor r12d, r12d                    ; worker byte W
    inc rbx                           ; rbx = 0
.st_send:
    mov byte [st_pkt], 0x40           ; short header
    mov [st_pkt + 1], r12b            ; worker byte
    STAGE stg_send
    mov eax, LINNEA_SYS_SENDTO
    mov edi, r14d
    lea rsi, [st_pkt]
    mov edx, 24
    xor r10d, r10d
    lea r8, [st_saddr]
    mov r9d, 16
    syscall
    test rax, rax                     ; a datagram that never left is not a
    js .st_fail                       ; steering failure, though it looked like one
    ; find which of the four sockets received it
    xor r13d, r13d                    ; socket index
    mov r15d, -1                      ; receiver, -1 = dropped
.st_poll:
    mov edi, [st_socks + r13*4]
    mov eax, LINNEA_SYS_RECVFROM
    lea rsi, [st_rcv]
    mov edx, 64
    mov r10d, 0x40                    ; MSG_DONTWAIT
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    js .st_next
    mov r15d, r13d                    ; this socket got it
.st_next:
    inc r13d
    cmp r13d, 4
    jb .st_poll
    ; report "W -> receiver"
    mov edi, r12d
    call linnea_print_u64_stderr
    mov byte [st_pkt + 8], '>'
    lea rdi, [st_pkt + 8]
    mov esi, 1
    call linnea_print_stderr
    mov edi, r15d
    call linnea_print_u64_stderr
    mov byte [st_pkt + 8], ' '
    lea rdi, [st_pkt + 8]
    mov esi, 1
    call linnea_print_stderr
    cmp r15d, r12d                    ; must be socket W
    je .st_ok
    mov rbx, -1
.st_ok:
    inc r12d
    cmp r12d, 4
    jb .st_send
    test rbx, rbx
    jz .st_done
    mov byte [st_mismatch], 1         ; the steering failed, not a syscall
.st_done:
    mov rax, [linnea_bpf_prog_fd]     ; the fd the probe reports on success
.st_fail:                             ; a refused syscall arrives with -errno in rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_bpf_probe() -> rax = 0 on success, -1 on failure. Runs the real setup +
; steering self-test and reports the outcome (and, on failure, the log).
linnea_bpf_probe:
    push rbx
    call linnea_bpf_selftest
    mov rbx, rax
    lea rdi, [msg_setup]
    mov esi, msg_setup_len
    call linnea_print_stderr
    test rbx, rbx
    js .fail_errno
    cmp byte [st_mismatch], 0
    jne .fail_steer
    lea rdi, [msg_ok]
    mov esi, msg_ok_len
    call linnea_print_stderr
    mov edi, ebx                               ; the real program fd
    call linnea_print_u64_stderr
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stderr
    xor eax, eax
    pop rbx
    ret
.fail_steer:
    lea rdi, [msg_steer]
    mov esi, msg_steer_len
    call linnea_print_stderr
    mov eax, -1
    pop rbx
    ret
.fail_errno:
    lea rdi, [msg_failat]
    mov esi, msg_failat_len
    call linnea_print_stderr
    mov rdi, [st_stage_ptr]
    mov rsi, [st_stage_len]
    call linnea_print_stderr
    lea rdi, [msg_errno]
    mov esi, msg_errno_len
    call linnea_print_stderr
    mov edi, ebx
    neg edi
    call linnea_print_u64_stderr
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stderr
    ; the verifier only speaks about a program load; printing an empty section
    ; after a bind or socket failure is noise that reads like a missing log
    cmp byte [verifier_log], 0
    je .no_log
    lea rdi, [msg_log]
    mov esi, msg_log_len
    call linnea_print_stderr
    lea rdi, [verifier_log]
    mov esi, 8192
    call print_cstr
.no_log:
    mov eax, -1
    pop rbx
    ret

; print_cstr(rdi = string, rsi = the buffer's size) — write it to stderr, up to
; a NUL or the buffer's end. The bound matters because the scan is over a .bss
; buffer the KERNEL fills: an unterminated log would otherwise walk into
; whatever follows and print it.
print_cstr:
    mov rax, rdi
    lea rdx, [rdi + rsi]
.count:
    cmp rax, rdx
    jae .done
    cmp byte [rax], 0
    je .done
    inc rax
    jmp .count
.done:
    sub rax, rdi                               ; length
    mov esi, eax
    call linnea_print_stderr                   ; rdi = ptr, esi = len
    ret
