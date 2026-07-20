; linnea_tlstest.asm — a blocking TLS 1.3 echo server for interop tests.
;
; Not part of the shipped server (that is the io_uring loop, wired up in
; M6). This is the smallest harness that drives linnea_tls against real
; clients — openssl s_client, curl, python ssl — over a plain accept()
; loop: complete one handshake, then echo every application record until
; the peer sends close_notify. It exercises the whole flight the RFC 8448
; trace can't (ECDSA CertificateVerify, client Finished verification).
;
; usage: linnea-tlstest <cert.pem> <key.pem> <port>

default rel

%include "linnea_syscall.inc"
%include "linnea_tls.inc"

extern linnea_pem_cert_list
extern linnea_pem_p256_key
extern linnea_tls_ticket_setup
extern linnea_tls_hs_init
extern linnea_tls_hs_input
extern linnea_tls_open
extern linnea_tls_seal

global _start

section .rodata
close_notify: db 1, 0          ; alert level warning, description close_notify

section .bss
alignb 8
hs:         resb linnea_tls_hs_size
list_buf:   resb 8192          ; pre-framed TLS certificate_list
inbuf:      resb 20000
plainbuf:   resb 20000
outbuf:     resb 20000
sockaddr:   resb 16
statbuf:    resb 144
have:       resq 1
listen_fd:  resq 1
conn_fd:    resq 1

section .text

_start:
    mov rax, [rsp]             ; argc
    cmp rax, 4
    jl .usage

    ; a per-run ticket key, so this echo server issues real, resumable
    ; NewSessionTickets (the production key is set up in linnea_tls_setup)
    call linnea_tls_ticket_setup

    ; --- load the certificate chain: map the PEM, frame the list ---
    mov rdi, [rsp + 16]        ; argv[1] cert path
    call map_file              ; rax=ptr, rdx=size
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [list_buf]
    mov ecx, 8192
    call linnea_pem_cert_list
    cmp rax, 0
    jle .fail
    mov r14, rax               ; certificate_list length

    ; --- load the private key scalar ---
    mov rdi, [rsp + 24]        ; argv[2] key path
    call map_file
    mov rdi, rax
    mov rsi, rdx
    call linnea_pem_p256_key
    cmp rax, -1
    je .fail
    mov r15, rax               ; seed pointer (static in linnea_pem)

    ; --- listen on the given port ---
    mov rdi, [rsp + 32]        ; argv[3] port
    call parse_u16
    mov r12, rax               ; port (host order)
    call setup_listener

.accept_loop:
    mov eax, LINNEA_SYS_ACCEPT
    mov rdi, [listen_fd]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .accept_loop
    mov [conn_fd], rax

    ; --- run one handshake ---
    lea rdi, [hs]
    lea rsi, [list_buf]
    mov rdx, r14
    mov rcx, r15
    xor r8d, r8d               ; no trace flag: real getrandom + sigalg check
    call linnea_tls_hs_init
    mov qword [have], 0
.hs_loop:
    xor ebx, ebx               ; progressed flag
    cmp qword [have], 0
    je .hs_read
    lea rdi, [hs]
    lea rsi, [inbuf]
    mov rdx, [have]
    lea rcx, [outbuf]
    mov r8, 20000
    call linnea_tls_hs_input
    mov r13, rax               ; state
    mov rcx, [hs + linnea_tls_hs.out_len]
    test rcx, rcx
    jz .hs_no_out
    mov rdi, [conn_fd]
    lea rsi, [outbuf]
    mov rdx, rcx
    call write_all
    mov ebx, 1
.hs_no_out:
    mov rcx, [hs + linnea_tls_hs.consumed]
    test rcx, rcx
    jz .hs_no_consume
    call shift_in              ; drop rcx consumed bytes from inbuf
    mov ebx, 1
.hs_no_consume:
    cmp r13, LINNEA_TLS_DONE
    je .app
    cmp r13, LINNEA_TLS_FAILED
    je .close                  ; the alert bytes were already written
    test ebx, ebx
    jnz .hs_loop               ; made progress; try the buffer again
.hs_read:
    call read_more
    test rax, rax
    jle .close
    jmp .hs_loop

    ; --- application data: echo every record until close_notify ---
.app:
    call recv_record           ; rax = full record length in inbuf, or <=0
    test rax, rax
    jle .close
    mov r13, rax               ; record length
    lea rdi, [hs + linnea_tls_hs.rkeys]
    lea rsi, [inbuf]
    mov rdx, r13
    lea rcx, [plainbuf]
    call linnea_tls_open       ; rax=content len, rdx=inner type
    push rdx
    push rax
    mov rcx, r13
    call shift_in
    pop rax
    pop rdx
    cmp rax, -1
    je .close                  ; bad record MAC
    cmp rdx, LINNEA_TLS_CT_ALERT
    je .send_close
    cmp rdx, LINNEA_TLS_CT_APPDATA
    jne .app                   ; ignore anything else (e.g. post-hs)
    ; echo the plaintext back as one application record
    lea rdi, [hs + linnea_tls_hs.wkeys]
    mov esi, LINNEA_TLS_CT_APPDATA
    lea rdx, [plainbuf]
    mov rcx, rax
    lea r8, [outbuf]
    call linnea_tls_seal
    mov rdi, [conn_fd]
    lea rsi, [outbuf]
    mov rdx, rax
    call write_all
    jmp .app

.send_close:
    lea rdi, [hs + linnea_tls_hs.wkeys]
    mov esi, LINNEA_TLS_CT_ALERT
    lea rdx, [close_notify]
    mov ecx, 2
    lea r8, [outbuf]
    call linnea_tls_seal
    mov rdi, [conn_fd]
    lea rsi, [outbuf]
    mov rdx, rax
    call write_all
.close:
    mov eax, LINNEA_SYS_CLOSE
    mov rdi, [conn_fd]
    syscall
    jmp .accept_loop

.usage:
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- helpers --------------------------------------------------------

; read_more() -> rax = bytes read (appended at inbuf+have), <=0 on EOF.
read_more:
    mov eax, LINNEA_SYS_READ
    mov rdi, [conn_fd]
    lea rsi, [inbuf]
    add rsi, [have]
    mov rdx, 20000
    sub rdx, [have]
    syscall
    test rax, rax
    jle .done
    add [have], rax
.done:
    ret

; shift_in(rcx = count) — drop the first rcx bytes of inbuf, keeping the
; rest, and decrement have.
shift_in:
    push rbx
    mov rbx, rcx
    mov rsi, [have]
    sub rsi, rbx               ; bytes to keep
    mov [have], rsi
    test rsi, rsi
    jz .done
    lea rdi, [inbuf]
    lea rsi, [inbuf + rbx]
    mov rcx, [have]
    rep movsb
.done:
    pop rbx
    ret

; recv_record() -> rax = 5 + record length once a whole record is
; buffered in inbuf, or <=0 on EOF before a full record arrives.
recv_record:
.need_header:
    cmp qword [have], 5
    jae .have_header
    call read_more
    test rax, rax
    jle .eof
    jmp .need_header
.have_header:
    movzx eax, byte [inbuf + 3]
    shl eax, 8
    mov al, [inbuf + 4]
    lea rax, [rax + 5]
    mov r10, rax               ; full record length
.need_body:
    cmp [have], r10
    jae .ready
    push r10
    call read_more
    pop r10
    test rax, rax
    jle .eof
    jmp .need_body
.ready:
    mov rax, r10
    ret
.eof:
    xor eax, eax
    ret

; write_all(rdi=fd, rsi=buf, rdx=len) — write the whole buffer.
write_all:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .done
    mov eax, LINNEA_SYS_WRITE
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    jle .done                  ; error: give up (the test will notice)
    add r12, rax
    sub r13, rax
    jmp .loop
.done:
    pop r13
    pop r12
    pop rbx
    ret

; setup_listener() — socket/setsockopt(SO_REUSEADDR)/bind/listen on the
; port in r12 (host order); stores the fd in listen_fd. Aborts on error.
setup_listener:
    push rbx
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov [listen_fd], rax
    mov rbx, rax
    ; SO_REUSEADDR = 1
    push 1
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, rbx
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEADDR
    mov r10, rsp
    mov r8d, 4
    syscall
    pop rax
    ; sockaddr_in
    mov word [sockaddr], LINNEA_AF_INET
    mov eax, r12d              ; port to network byte order
    xchg al, ah
    mov [sockaddr + 2], ax
    mov dword [sockaddr + 4], 0    ; INADDR_ANY
    mov qword [sockaddr + 8], 0
    mov eax, LINNEA_SYS_BIND
    mov rdi, rbx
    lea rsi, [sockaddr]
    mov edx, 16
    syscall
    test rax, rax
    js .fail
    mov eax, LINNEA_SYS_LISTEN
    mov rdi, rbx
    mov esi, LINNEA_BACKLOG
    syscall
    test rax, rax
    js .fail
    pop rbx
    ret
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; map_file(rdi=path cstr) -> rax=ptr, rdx=size. Read-only mmap; aborts
; the process on any failure (test tooling, no error plumbing).
map_file:
    push rbx
    mov eax, LINNEA_SYS_OPEN
    xor esi, esi               ; O_RDONLY
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov rbx, rax               ; fd
    mov eax, LINNEA_SYS_FSTAT
    mov rdi, rbx
    lea rsi, [statbuf]
    syscall
    test rax, rax
    js .fail
    mov rdx, [statbuf + LINNEA_STAT_ST_SIZE]
    test rdx, rdx
    jz .fail
    push rdx
    mov eax, LINNEA_SYS_MMAP
    xor edi, edi
    mov rsi, rdx               ; length
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8, rbx                ; fd
    xor r9d, r9d               ; offset
    syscall
    pop rdx
    test rax, rax
    js .fail
    push rax
    push rdx
    mov eax, LINNEA_SYS_CLOSE
    mov rdi, rbx
    syscall
    pop rdx
    pop rax
    pop rbx
    ret
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; parse_u16(rdi=cstr) -> rax — decimal, no validation (test tooling).
parse_u16:
    xor eax, eax
.loop:
    movzx ecx, byte [rdi]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul eax, eax, 10
    add eax, ecx
    inc rdi
    jmp .loop
.done:
    ret
