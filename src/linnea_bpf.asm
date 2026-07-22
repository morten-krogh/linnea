; linnea_bpf.asm — eBPF connection-ID steering for the QUIC reuseport group.
;
; A SK_REUSEPORT program reads the QUIC packet's Destination Connection ID and
; steers the datagram to the worker that owns the connection: the worker index
; is the first byte of the DCID (short header: offset 1; long header: offset 6),
; used as the index into a REUSEPORT_SOCKARRAY the workers register into. An
; index with no socket (a client's random first-Initial CID, or a worker not yet
; up) makes the helper fail, and the program returns SK_PASS so the kernel falls
; back to its 4-tuple hash. bpf(2) is called directly with a hand-built attr
; block and hand-assembled program bytecode; loading needs CAP_BPF.

default rel

%include "linnea_syscall.inc"

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
msg_err:  db "FAILED err="
msg_err_len  equ $ - msg_err
msg_log:  db 10, "verifier log:", 10
msg_log_len equ $ - msg_log
msg_nl:   db 10

section .rodata
; sockaddr_in for 127.0.0.1:47610 (the self-test's reuseport group)
st_saddr: db 0x02,0x00, 0xB9,0xFA, 0x7F,0x00,0x00,0x01, 0,0,0,0,0,0,0,0

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

section .text

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
    mov dword [bpf_attr + 12], 128            ; max_entries (>= worker count)
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

; linnea_bpf_selftest() -> rax = program fd (>= 0) if steering routes a datagram
; by its worker byte, else -1. Builds a 4-socket reuseport group, registers and
; attaches the program, and checks a short-header packet with worker byte W lands
; on socket W. Confirms the packet offsets the program reads.
linnea_bpf_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call linnea_bpf_reuseport_setup
    test rax, rax
    js .st_fail
    mov r15d, eax                     ; program fd
    xor r12d, r12d                    ; socket index
.st_mk:
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
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov edi, r13d
    mov esi, SOL_SOCKET
    mov edx, 15                       ; SO_REUSEPORT
    lea r10, [st_one]
    mov r8d, 4
    syscall
    mov eax, LINNEA_SYS_BIND
    mov edi, r13d
    lea rsi, [st_saddr]
    mov edx, 16
    syscall
    test rax, rax
    js .st_fail
    mov edi, r12d
    mov esi, r13d
    call linnea_bpf_map_add           ; map[i] = socket
    test rax, rax
    js .st_fail
    inc r12d
    cmp r12d, 4
    jb .st_mk
    mov edi, [st_socks]               ; attach the program to the group
    mov esi, r15d
    call linnea_bpf_attach
    test rax, rax
    js .st_fail
    mov eax, LINNEA_SYS_SOCKET        ; a client socket to send from
    mov edi, 2
    mov esi, 2
    xor edx, edx
    syscall
    mov r14d, eax
    mov rbx, -1                       ; rbx = 0 while every W steers to socket W
    xor r12d, r12d                    ; worker byte W
    inc rbx                           ; rbx = 0
.st_send:
    mov byte [st_pkt], 0x40           ; short header
    mov [st_pkt + 1], r12b            ; worker byte
    mov eax, LINNEA_SYS_SENDTO
    mov edi, r14d
    lea rsi, [st_pkt]
    mov edx, 24
    xor r10d, r10d
    lea r8, [st_saddr]
    mov r9d, 16
    syscall
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
    jnz .st_fail
    xor eax, eax                      ; all four steered correctly
    jmp .st_ret
.st_fail:
    mov rax, -1
.st_ret:
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
    js .fail
    lea rdi, [msg_ok]
    mov esi, msg_ok_len
    call linnea_print_stderr
    mov edi, ebx
    call linnea_print_u64_stderr
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stderr
    xor eax, eax
    pop rbx
    ret
.fail:
    lea rdi, [msg_err]
    mov esi, msg_err_len
    call linnea_print_stderr
    mov edi, ebx
    neg edi
    call linnea_print_u64_stderr
    lea rdi, [msg_log]
    mov esi, msg_log_len
    call linnea_print_stderr
    lea rdi, [verifier_log]
    call print_cstr
    mov eax, -1
    pop rbx
    ret

; print_cstr(rdi = NUL-terminated string) — write it to stderr.
print_cstr:
    mov rax, rdi
.count:
    cmp byte [rax], 0
    je .done
    inc rax
    jmp .count
.done:
    sub rax, rdi                               ; length
    mov esi, eax
    call linnea_print_stderr                   ; rdi = ptr, esi = len
    ret
