; linnea_http.asm — HTTP/1.1 request head parsing and response building.
;
; Supported subset for this milestone:
; - Request line: METHOD SP TARGET SP "HTTP/1.1" CRLF; single spaces;
;   METHOD 1-32 bytes, TARGET 1-2048 bytes, printable ASCII (0x21-0x7E).
; - Header lines: NAME ":" OWS VALUE CRLF. NAME is non-empty printable
;   ASCII without ':'; VALUE may contain tab and bytes >= 0x20. The Host
;   header value is extracted (first occurrence, max 255 bytes).
; - The head must end with CRLF CRLF within the input buffer, else 431.
; - Request bodies are not read; every response says Connection: close
;   and the connection is closed after the response is sent.
; - Non-HTTP/1.1 versions get 505, anything malformed gets 400.
;
; The 200 response echoes what was parsed, one line per field:
;   server: <config hostname> / method / target / host (or "-").

default rel

%include "linnea_config.inc"
%include "linnea_connection.inc"

global linnea_http_handle

; linnea_http_handle return values
LINNEA_HTTP_NEED_MORE   equ 0
LINNEA_HTTP_RESPOND     equ 1

LINNEA_HTTP_MAX_METHOD  equ 32
LINNEA_HTTP_MAX_TARGET  equ 2048
LINNEA_HTTP_MAX_HOST    equ 255

extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_iequal

section .rodata

resp_400:       db "HTTP/1.1 400 Bad Request", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_400_len    equ $ - resp_400
resp_431:       db "HTTP/1.1 431 Request Header Fields Too Large", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_431_len    equ $ - resp_431
resp_505:       db "HTTP/1.1 505 HTTP Version Not Supported", 13, 10
                db "Content-Length: 0", 13, 10
                db "Connection: close", 13, 10, 13, 10
resp_505_len    equ $ - resp_505

status_200:     db "HTTP/1.1 200 OK", 13, 10
                db "Content-Type: text/plain", 13, 10
                db "Content-Length: "
status_200_len  equ $ - status_200
hdr_end:        db 13, 10, "Connection: close", 13, 10, 13, 10
hdr_end_len     equ $ - hdr_end

body_server:    db "server: "
body_server_len equ $ - body_server
body_method:    db "method: "
body_method_len equ $ - body_method
body_target:    db "target: "
body_target_len equ $ - body_target
body_host:      db "host: "
body_host_len   equ $ - body_host
; fixed body bytes: the four labels plus four CRLFs
BODY_FIXED      equ body_server_len + body_method_len + body_target_len + body_host_len + 8

crlf:           db 13, 10
dash:           db "-"
key_host:       db "host"
version_11:     db "HTTP/1.1"  ; 8 bytes, compared as one qword

section .bss

num_buf:        resb 20

section .text

; linnea_http_handle(rdi=connection*) -> rax
;   LINNEA_HTTP_NEED_MORE: incomplete head, arm another recv
;   LINNEA_HTTP_RESPOND:   out_ptr/out_rem set, send then close
;
; Stack locals:
;   [rsp+0]  method ptr   [rsp+8]  method len
;   [rsp+16] target ptr   [rsp+24] target len
;   [rsp+32] host ptr (0 = absent)  [rsp+40] host len
;   [rsp+48] scratch value ptr      [rsp+56] scratch value len
linnea_http_handle:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64
    mov rbx, rdi
    lea r14, [rbx + linnea_connection.in_buf]
    mov r12, [rbx + linnea_connection.in_len]

    ; find the CRLF CRLF terminator
    xor r13d, r13d
.scan:
    lea rax, [r13 + 4]
    cmp rax, r12
    ja .no_terminator
    cmp dword [r14 + r13], 0x0A0D0A0D    ; "\r\n\r\n"
    je .found
    inc r13
    jmp .scan
.no_terminator:
    cmp r12, LINNEA_CONN_IN_BUF
    jae .resp_431
    mov eax, LINNEA_HTTP_NEED_MORE
    jmp .ret

.found:
    ; r13 points at the last header line's CRLF; lines end strictly
    ; before r13 + 2 (the terminating empty line's CRLF).
    add r13, 2                 ; head limit
    xor r15d, r15d             ; cursor

    ; --- method ---------------------------------------------------
    mov [rsp], r14             ; method starts at offset 0
.method_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ' '
    je .method_done
    cmp al, 0x21
    jb .resp_400
    cmp al, 0x7e
    ja .resp_400
    inc r15
    jmp .method_loop
.method_done:
    mov [rsp + 8], r15
    test r15, r15
    jz .resp_400
    cmp r15, LINNEA_HTTP_MAX_METHOD
    ja .resp_400
    inc r15                    ; skip the SP

    ; --- target ---------------------------------------------------
    lea rax, [r14 + r15]
    mov [rsp + 16], rax
    mov rcx, r15
.target_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ' '
    je .target_done
    cmp al, 0x21
    jb .resp_400
    cmp al, 0x7e
    ja .resp_400
    inc r15
    jmp .target_loop
.target_done:
    mov rax, r15
    sub rax, rcx
    mov [rsp + 24], rax
    test rax, rax
    jz .resp_400
    cmp rax, LINNEA_HTTP_MAX_TARGET
    ja .resp_400
    inc r15                    ; skip the SP

    ; --- version: exactly "HTTP/1.1" CRLF -------------------------
    lea rax, [r15 + 8]
    cmp rax, r13
    ja .resp_400
    mov rax, [r14 + r15]
    mov rcx, [version_11]
    cmp rax, rcx
    jne .version_other
    add r15, 8
    cmp word [r14 + r15], 0x0A0D         ; CRLF
    jne .resp_400
    add r15, 2

    ; --- header lines ---------------------------------------------
    mov qword [rsp + 32], 0    ; no Host seen yet
    mov qword [rsp + 40], 0
.header_loop:
    cmp r15, r13
    jae .parsed
    mov rcx, r15               ; name start
.name_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ':'
    je .name_done
    cmp al, 0x21
    jb .resp_400
    cmp al, 0x7e
    ja .resp_400
    inc r15
    jmp .name_loop
.name_done:
    mov r8, r15
    sub r8, rcx                ; name len
    test r8, r8
    jz .resp_400
    inc r15                    ; skip ':'
.ows_loop:
    cmp r15, r13
    jae .resp_400
    movzx eax, byte [r14 + r15]
    cmp al, ' '
    je .ows_skip
    cmp al, 9
    je .ows_skip
    jmp .value_start
.ows_skip:
    inc r15
    jmp .ows_loop
.value_start:
    mov r9, r15                ; value start
.value_loop:
    movzx eax, byte [r14 + r15]
    cmp al, 13
    je .value_done
    cmp al, 9
    je .value_ok
    cmp al, 0x20
    jb .resp_400
.value_ok:
    inc r15
    cmp r15, r13
    jae .resp_400
    jmp .value_loop
.value_done:
    cmp byte [r14 + r15 + 1], 10
    jne .resp_400
    ; trim trailing OWS: value = [r9, r10)
    mov r10, r15
.trim:
    cmp r10, r9
    jbe .trimmed
    movzx eax, byte [r14 + r10 - 1]
    cmp al, ' '
    je .trim_dec
    cmp al, 9
    je .trim_dec
    jmp .trimmed
.trim_dec:
    dec r10
    jmp .trim
.trimmed:
    ; first Host header wins
    cmp qword [rsp + 32], 0
    jne .header_next
    lea rax, [r14 + r9]
    mov [rsp + 48], rax
    mov rax, r10
    sub rax, r9
    mov [rsp + 56], rax
    lea rdi, [r14 + rcx]
    mov rsi, r8
    lea rdx, [key_host]
    mov ecx, 4
    call linnea_string_iequal
    test eax, eax
    jz .header_next
    mov rax, [rsp + 48]
    mov [rsp + 32], rax
    mov rax, [rsp + 56]
    mov [rsp + 40], rax
.header_next:
    add r15, 2                 ; past the CRLF
    jmp .header_loop

.version_other:
    ; "HTTP/" followed by an unsupported version -> 505, else 400
    mov eax, [r14 + r15]
    cmp eax, 'HTTP'
    jne .resp_400
    cmp byte [r14 + r15 + 4], '/'
    jne .resp_400
    jmp .resp_505

    ; --- build the 200 response ------------------------------------
.parsed:
    cmp qword [rsp + 40], LINNEA_HTTP_MAX_HOST
    ja .resp_400
    mov ecx, [rbx + linnea_connection.server]
    imul rcx, rcx, linnea_config_server_size
    lea rax, [linnea_config_instance]
    lea r12, [rax + rcx + linnea_config.servers]   ; server*
    ; body length
    mov rax, BODY_FIXED
    add rax, [r12 + linnea_config_server.hostname_len]
    add rax, [rsp + 8]
    add rax, [rsp + 24]
    mov rcx, [rsp + 40]
    cmp qword [rsp + 32], 0
    jne .host_len_ok
    mov ecx, 1                 ; "-"
.host_len_ok:
    add rax, rcx
    mov r13, rax               ; body length
    ; assemble into out_buf, r15 = write cursor
    lea r15, [rbx + linnea_connection.out_buf]
    lea rdi, [status_200]
    mov esi, status_200_len
    call .append
    mov rdi, r13
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    call .append
    lea rdi, [hdr_end]
    mov esi, hdr_end_len
    call .append
    lea rdi, [body_server]
    mov esi, body_server_len
    call .append
    lea rdi, [r12 + linnea_config_server.hostname]
    mov rsi, [r12 + linnea_config_server.hostname_len]
    call .append
    lea rdi, [crlf]
    mov esi, 2
    call .append
    lea rdi, [body_method]
    mov esi, body_method_len
    call .append
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    call .append
    lea rdi, [crlf]
    mov esi, 2
    call .append
    lea rdi, [body_target]
    mov esi, body_target_len
    call .append
    mov rdi, [rsp + 16]
    mov rsi, [rsp + 24]
    call .append
    lea rdi, [crlf]
    mov esi, 2
    call .append
    lea rdi, [body_host]
    mov esi, body_host_len
    call .append
    mov rdi, [rsp + 32]
    mov rsi, [rsp + 40]
    test rdi, rdi
    jnz .host_append
    lea rdi, [dash]
    mov esi, 1
.host_append:
    call .append
    lea rdi, [crlf]
    mov esi, 2
    call .append
    ; hand the response to the caller
    lea rax, [rbx + linnea_connection.out_buf]
    mov [rbx + linnea_connection.out_ptr], rax
    mov rcx, r15
    sub rcx, rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov eax, LINNEA_HTTP_RESPOND
    jmp .ret

.resp_400:
    lea rax, [resp_400]
    mov [rbx + linnea_connection.out_ptr], rax
    mov qword [rbx + linnea_connection.out_rem], resp_400_len
    mov eax, LINNEA_HTTP_RESPOND
    jmp .ret
.resp_431:
    lea rax, [resp_431]
    mov [rbx + linnea_connection.out_ptr], rax
    mov qword [rbx + linnea_connection.out_rem], resp_431_len
    mov eax, LINNEA_HTTP_RESPOND
    jmp .ret
.resp_505:
    lea rax, [resp_505]
    mov [rbx + linnea_connection.out_ptr], rax
    mov qword [rbx + linnea_connection.out_rem], resp_505_len
    mov eax, LINNEA_HTTP_RESPOND
    jmp .ret

.ret:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .append(rdi=ptr, rsi=len) — local helper; r15 is the write cursor.
; The response caps (method 32, target 2048, host 255, hostname 255)
; keep the total well under LINNEA_CONN_OUT_BUF.
.append:
    mov rcx, rsi
    mov rsi, rdi
    mov rdi, r15
    rep movsb
    mov r15, rdi
    ret
