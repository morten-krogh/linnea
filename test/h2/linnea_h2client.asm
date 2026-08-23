; linnea_h2client.asm — test harness for the backend HTTP/2 client (Tier 1).
;
; Connects to 127.0.0.1:<port> (plaintext h2c), runs one linnea_h2c_exchange for
; <method> <path>, and writes the synthesized h1 response to stdout. A body is
; read from stdin when the method is not GET (for /echo round-trips).
;
;   linnea-h2client <port> [path] [method] [chunkcap]
;
; Exit 0 iff the exchange produced a response; exit 1 on a negative sentinel.

default rel
%include "linnea_syscall.inc"
%include "linnea_h2_client.inc"

global _start
extern linnea_h2c_exchange
extern linnea_h2c_drv_blocking
extern linnea_h2c_resp_buf
extern h2c_chunk_cap

section .rodata
def_path:   db "/hello"
def_path_len equ $ - def_path
def_method: db "GET"
def_method_len equ $ - def_method
host_line:  db " HTTP/1.1", 13, 10, "Host: h2c.test", 13, 10, 13, 10
host_line_len equ $ - host_line
get3:       db "GET"

section .bss
sa:        resb 16
head_buf:  resb 4096
body_buf:  resb 1048576
head_len:  resq 1
body_len:  resq 1
use_drv:   resq 1

section .text
_start:
    mov rbp, rsp
    mov rax, [rbp]                    ; argc
    cmp rax, 2
    jl .fail
    mov rdi, [rbp + 16]              ; argv[1] = port
    call atoi
    mov r15d, eax                    ; port

    ; path = argv[2] or default
    lea r13, [def_path]
    mov r14, def_path_len
    cmp qword [rbp], 3
    jl .have_path
    mov r13, [rbp + 24]
    mov rdi, r13
    call slen
    mov r14, rax
.have_path:
    ; method = argv[3] or "GET"
    lea rbx, [def_method]
    mov r12, def_method_len
    cmp qword [rbp], 4
    jl .have_method
    mov rbx, [rbp + 32]
    mov rdi, rbx
    call slen
    mov r12, rax
.have_method:
    ; optional argv[4] = chunk cap
    cmp qword [rbp], 5
    jl .nochunk
    mov rdi, [rbp + 40]
    call atoi
    mov [h2c_chunk_cap], rax
.nochunk:
    ; optional argv[5] = "drv" -> exercise the RESUMABLE driver instead
    mov qword [use_drv], 0
    cmp qword [rbp], 6
    jl .nomode
    mov rax, [rbp + 48]
    cmp byte [rax], 'd'
    jne .nomode
    mov qword [use_drv], 1
.nomode:

    ; --- build the h1 request head: "METHOD PATH HTTP/1.1\r\nHost: ...\r\n\r\n"
    lea rdi, [head_buf]
    mov rsi, rbx                      ; method
    mov rcx, r12
    rep movsb
    mov byte [rdi], ' '
    inc rdi
    mov rsi, r13                      ; path
    mov rcx, r14
    rep movsb
    lea rsi, [host_line]
    mov rcx, host_line_len
    rep movsb
    lea rax, [head_buf]
    sub rdi, rax
    mov [head_len], rdi

    ; --- body from stdin iff method != "GET" ---
    mov qword [body_len], 0
    cmp r12, 3
    jne .read_body
    cmp byte [rbx], 'G'
    jne .read_body
    cmp byte [rbx+1], 'E'
    jne .read_body
    cmp byte [rbx+2], 'T'
    je .no_body
.read_body:
    xor edi, edi                     ; fd 0
    lea rsi, [body_buf]
    mov rdx, 1048576
    call read_upto
    mov [body_len], rax
.no_body:

    ; --- connect 127.0.0.1:port (plaintext) ---
    mov eax, LINNEA_SYS_SOCKET
    mov edi, 2
    mov esi, 1
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov r14d, eax                    ; fd
    mov word [sa], 2
    mov eax, r15d
    xchg al, ah
    mov [sa + 2], ax
    mov dword [sa + 4], 0x0100007f
    mov eax, LINNEA_SYS_CONNECT
    mov edi, r14d
    lea rsi, [sa]
    mov edx, 16
    syscall
    test rax, rax
    js .fail

    ; --- exchange (blocking) or drive the resumable driver ---
    mov edi, r14d
    lea rsi, [head_buf]
    mov rdx, [head_len]
    lea rcx, [body_buf]
    mov r8, [body_len]
    mov r9, LINNEA_H2_SCHEME_HTTP
    cmp qword [use_drv], 0
    jne .drv
    call linnea_h2c_exchange
    jmp .after_ex
.drv:
    call linnea_h2c_drv_blocking
.after_ex:
    test rax, rax
    js .fail

    ; write the synthesized h1 response to stdout
    mov rdx, rax
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [linnea_h2c_resp_buf]
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.fail:
    mov eax, LINNEA_SYS_WRITE
    mov edi, 2
    lea rsi, [fail_msg]
    mov edx, fail_len
    syscall
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

section .rodata
fail_msg: db "H2C-FAIL", 10
fail_len equ $ - fail_msg

section .text
; Harness stub: linnea_hpack.o (linked whole for its primitives) references this
; from the authority-host parser, a request-only path the response decoder never
; reaches. The real symbol is present in the server build.
global linnea_network_parse_ipv6
linnea_network_parse_ipv6:
    mov rax, -1
    ret

; atoi(rdi=str) -> rax
atoi:
    xor eax, eax
.l:
    movzx ecx, byte [rdi]
    sub cl, '0'
    cmp cl, 9
    ja .d
    imul rax, rax, 10
    movzx ecx, cl
    add rax, rcx
    inc rdi
    jmp .l
.d:
    ret

; slen(rdi=str) -> rax = length (NUL-terminated).
slen:
    xor eax, eax
.l:
    cmp byte [rdi + rax], 0
    je .d
    inc rax
    jmp .l
.d:
    ret

; read_upto(edi=fd, rsi=buf, edx=cap) -> rax = bytes read (until EOF).
read_upto:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
    xor r14, r14                      ; accumulator (r15 holds the port)
.loop:
    test r13, r13
    jz .done
    mov eax, LINNEA_SYS_READ
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    jle .done
    add r12, rax
    sub r13, rax
    add r14, rax
    jmp .loop
.done:
    mov rax, r14
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
