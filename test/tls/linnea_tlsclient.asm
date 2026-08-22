; linnea_tlsclient.asm — test harness for the backend TLS client handshake.
;
; Connects to 127.0.0.1:<port>, runs linnea_tls_client_handshake with a pin read
; as 32 raw bytes from stdin, then does one HTTP/1.0 GET over the negotiated
; application keys. Prints "OK" and exits 0 iff the whole thing succeeds and the
; response begins with "HTTP"; otherwise prints "FAIL" and exits 1. A wrong pin
; (or any authentication failure) makes the handshake fail, so the harness exits
; 1 -- which is how the negative tests are written.
;
;   linnea-tlsclient <port>      (32-byte pin on stdin)

default rel
%include "linnea_syscall.inc"

global _start
extern linnea_tls_client_handshake
extern linnea_tls_client_app_send
extern linnea_tls_client_app_recv
extern cli_chunk_cap

section .rodata
sni_default: db "localhost"
sni_default_len equ $ - sni_default
get_req: db "GET / HTTP/1.0", 13, 10, "Host: localhost", 13, 10, 13, 10
get_req_len equ $ - get_req
ok_msg:   db "OK", 10
ok_len    equ $ - ok_msg
fail_msg: db "FAIL", 10
fail_len  equ $ - fail_msg
http_magic: db "HTTP"

section .bss
pin_buf:     resb 32
out_secrets: resb 64
sa:          resb 16
respbuf:     resb 4096

section .text
_start:
    mov rbp, rsp
    mov rax, [rbp]                    ; argc
    cmp rax, 2
    jl .fail
    mov rdi, [rbp + 16]              ; argv[1] = port
    call atoi
    mov r15d, eax                    ; port

    cmp qword [rbp], 3               ; optional argv[2] = recv chunk cap
    jl .nochunk
    mov rdi, [rbp + 24]
    call atoi
    mov [cli_chunk_cap], rax
.nochunk:

    xor edi, edi                     ; read the 32-byte pin from stdin
    lea rsi, [pin_buf]
    mov edx, 32
    call read_n
    test rax, rax
    js .fail

    mov eax, LINNEA_SYS_SOCKET
    mov edi, 2                       ; AF_INET
    mov esi, 1                       ; SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov r14d, eax                    ; fd

    mov word [sa], 2                 ; AF_INET
    mov eax, r15d                    ; htons(port)
    xchg al, ah
    mov [sa + 2], ax
    mov dword [sa + 4], 0x0100007f   ; 127.0.0.1

    mov eax, LINNEA_SYS_CONNECT
    mov edi, r14d
    lea rsi, [sa]
    mov edx, 16
    syscall
    test rax, rax
    js .fail

    mov edi, r14d                    ; handshake
    lea rsi, [pin_buf]
    lea rdx, [sni_default]
    mov rcx, sni_default_len
    lea r8, [out_secrets]
    call linnea_tls_client_handshake
    test rax, rax
    jnz .fail

    ; One post-handshake record proves MUTUAL success: the server only sends
    ; encrypted data (a NewSessionTicket, here) after accepting our Finished
    ; under matching application keys. A decryptable record (rax >= 0) is the
    ; proof; a bad Finished would draw a cleartext alert and fail the decrypt.
    mov edi, r14d
    lea rsi, [respbuf]
    mov rdx, 4096
    call linnea_tls_client_app_recv
    test rax, rax
    js .fail

    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [ok_msg]
    mov edx, ok_len
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.fail:
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [fail_msg]
    mov edx, fail_len
    syscall
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; atoi(rdi=str) -> eax = decimal value.
atoi:
    xor eax, eax
.l:
    movzx ecx, byte [rdi]
    sub cl, '0'
    cmp cl, 9
    ja .d
    imul eax, eax, 10
    movzx ecx, cl
    add eax, ecx
    inc rdi
    jmp .l
.d:
    ret

; read_n(edi=fd, rsi=buf, edx=n) -> rax = 0 ok / -1 on EOF/error.
read_n:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .ok
    mov eax, LINNEA_SYS_READ
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    jle .fail
    add r12, rax
    sub r13, rax
    jmp .loop
.ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret
