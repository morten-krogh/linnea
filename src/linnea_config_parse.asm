; linnea_config_parse.asm — schema-specific JSON parser for the config.
;
; Accepted grammar, exactly:
;   ws '{' member (ws ',' member)* ws '}' ws EOF
; where the top-level members are "log" (string) and "servers" (array of
; server objects), in any order, each required exactly once.
;   server := ws '{' member (ws ',' member)* ws '}'
;   member := ws string ws ':' ws value
;
; Server keys are "host" (string), "port" (integer), "hostname" (string),
; "root" (string), accepted in any order, each required exactly once.
; JSON subset: whitespace is space/tab/newline/carriage-return; strings
; have no escape sequences; numbers are non-negative decimal integers
; capped at 65535.
; All errors exit via linnea_error_parse with the byte offset of the error.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_config_parse
global linnea_parser_state

extern linnea_error_parse
extern linnea_string_equal
extern linnea_string_copy

section .rodata

key_servers:            db "servers"
key_servers_len         equ $ - key_servers
key_log:                db "log"
key_log_len             equ $ - key_log
key_host:               db "host"
key_host_len            equ $ - key_host
key_port:               db "port"
key_port_len            equ $ - key_port
key_hostname:           db "hostname"
key_hostname_len        equ $ - key_hostname
key_root:               db "root"
key_root_len            equ $ - key_root

msg_eof:                db "unexpected end of file"
msg_eof_len             equ $ - msg_eof
msg_top_missing:        db "config requires log and servers"
msg_top_missing_len     equ $ - msg_top_missing
msg_sep_array:          db "expected ',' or ']'"
msg_sep_array_len       equ $ - msg_sep_array
msg_sep_object:         db "expected ',' or '}'"
msg_sep_object_len      equ $ - msg_sep_object
msg_trailing:           db "trailing content after config"
msg_trailing_len        equ $ - msg_trailing
msg_too_many:           db "too many servers (max 16)"
msg_too_many_len        equ $ - msg_too_many
msg_unknown_key:        db "unknown key"
msg_unknown_key_len     equ $ - msg_unknown_key
msg_dup_key:            db "duplicate key"
msg_dup_key_len         equ $ - msg_dup_key
msg_missing_key:        db "server requires host, port, hostname and root"
msg_missing_key_len     equ $ - msg_missing_key
msg_unterminated:       db "unterminated string"
msg_unterminated_len    equ $ - msg_unterminated
msg_escape:             db "escape sequences not supported"
msg_escape_len          equ $ - msg_escape
msg_control:            db "control character in string"
msg_control_len         equ $ - msg_control
msg_number:             db "expected number"
msg_number_len          equ $ - msg_number
msg_port_range:         db "port must be between 1 and 65535"
msg_port_range_len      equ $ - msg_port_range
msg_host_long:          db "host too long"
msg_host_long_len       equ $ - msg_host_long
msg_hostname_long:      db "hostname too long"
msg_hostname_long_len   equ $ - msg_hostname_long
msg_root_long:          db "root too long"
msg_root_long_len       equ $ - msg_root_long
msg_log_long:           db "log too long"
msg_log_long_len        equ $ - msg_log_long

section .data

; The expected character is patched in before reporting a mismatch.
msg_expect:             db "expected '"
msg_expect_char:        db "?"
                        db "'"
msg_expect_len          equ $ - msg_expect

section .bss

linnea_parser_state:    resb linnea_parser_size

section .text

; linnea_config_parse(rdi=buf, rsi=len, rdx=config*)
; Fills the config from the JSON bytes or exits with a parse error.
; Top-level key presence tracked in a bitmask: servers=1, log=2.
linnea_config_parse:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdx               ; config*
    mov [linnea_parser_state + linnea_parser.base], rdi
    mov [linnea_parser_state + linnea_parser.size], rsi
    mov qword [linnea_parser_state + linnea_parser.pos], 0
    mov qword [rbx + linnea_config.server_count], 0
    mov qword [rbx + linnea_config.log_len], 0
    xor r13d, r13d             ; top-level key mask

    mov edi, '{'
    call linnea_parse_expect
.top_loop:
    call linnea_parse_string   ; rax=ptr, rdx=len
    mov r14, rax
    mov r15, rdx
    mov edi, ':'
    call linnea_parse_expect
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_servers]
    mov ecx, key_servers_len
    call linnea_string_equal
    test eax, eax
    jnz .top_servers
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_log]
    mov ecx, key_log_len
    call linnea_string_equal
    test eax, eax
    jnz .top_log
    lea rdi, [msg_unknown_key]
    mov esi, msg_unknown_key_len
    jmp linnea_parse_fail

.top_servers:
    test r13d, 1
    jnz .top_dup
    or r13d, 1
    mov edi, '['
    call linnea_parse_expect
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ']'
    jne .server_loop
    call linnea_parse_advance  ; empty array; validation rejects count 0
    jmp .top_sep
.server_loop:
    mov r12, [rbx + linnea_config.server_count]
    cmp r12, LINNEA_MAX_SERVERS
    jae .too_many
    imul rdi, r12, linnea_config_server_size
    lea rdi, [rbx + rdi + linnea_config.servers]
    call linnea_parse_server
    inc qword [rbx + linnea_config.server_count]
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ','
    je .next_server
    cmp al, ']'
    je .end_array
    lea rdi, [msg_sep_array]
    mov esi, msg_sep_array_len
    jmp linnea_parse_fail
.next_server:
    call linnea_parse_advance
    jmp .server_loop
.end_array:
    call linnea_parse_advance
    jmp .top_sep

.top_log:
    test r13d, 2
    jnz .top_dup
    or r13d, 2
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_LOG
    ja .log_long
    mov [rbx + linnea_config.log_len], rdx
    lea rdi, [rbx + linnea_config.log]
    mov rsi, rax
    call linnea_string_copy

.top_sep:
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ','
    je .top_next
    cmp al, '}'
    je .top_done
    lea rdi, [msg_sep_object]
    mov esi, msg_sep_object_len
    jmp linnea_parse_fail
.top_next:
    call linnea_parse_advance
    jmp .top_loop
.top_done:
    call linnea_parse_advance
    cmp r13d, 3
    jne .top_missing
    call linnea_parse_skip_ws
    mov rax, [linnea_parser_state + linnea_parser.pos]
    cmp rax, [linnea_parser_state + linnea_parser.size]
    jb .trailing
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.top_dup:
    lea rdi, [msg_dup_key]
    mov esi, msg_dup_key_len
    jmp linnea_parse_fail
.top_missing:
    lea rdi, [msg_top_missing]
    mov esi, msg_top_missing_len
    jmp linnea_parse_fail
.too_many:
    lea rdi, [msg_too_many]
    mov esi, msg_too_many_len
    jmp linnea_parse_fail
.log_long:
    lea rdi, [msg_log_long]
    mov esi, msg_log_long_len
    jmp linnea_parse_fail
.trailing:
    lea rdi, [msg_trailing]
    mov esi, msg_trailing_len
    jmp linnea_parse_fail

; linnea_parse_server(rdi=server*) — one server object, keys in any order.
; Key presence tracked in a bitmask: host=1, port=2, hostname=4, root=8.
linnea_parse_server:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi               ; server*
    xor r12d, r12d             ; key mask
    mov edi, '{'
    call linnea_parse_expect
.member_loop:
    call linnea_parse_skip_ws
    mov r15, [linnea_parser_state + linnea_parser.pos]   ; key start, for errors
    call linnea_parse_string
    mov r13, rax               ; key ptr
    mov r14, rdx               ; key len
    mov edi, ':'
    call linnea_parse_expect
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_host]
    mov ecx, key_host_len
    call linnea_string_equal
    test eax, eax
    jnz .key_host
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_port]
    mov ecx, key_port_len
    call linnea_string_equal
    test eax, eax
    jnz .key_port
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_hostname]
    mov ecx, key_hostname_len
    call linnea_string_equal
    test eax, eax
    jnz .key_hostname
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_root]
    mov ecx, key_root_len
    call linnea_string_equal
    test eax, eax
    jnz .key_root
    lea rdi, [msg_unknown_key]
    mov esi, msg_unknown_key_len
    mov rdx, r15
    jmp linnea_error_parse

.key_host:
    test r12d, 1
    jnz .dup
    or r12d, 1
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_HOST
    ja .host_long
    mov [rbx + linnea_config_server.host_len], rdx
    lea rdi, [rbx + linnea_config_server.host]
    mov rsi, rax
    call linnea_string_copy
    jmp .member_sep

.key_port:
    test r12d, 2
    jnz .dup
    or r12d, 2
    call linnea_parse_u64      ; rax <= 65535
    mov [rbx + linnea_config_server.port], ax
    jmp .member_sep

.key_hostname:
    test r12d, 4
    jnz .dup
    or r12d, 4
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_HOSTNAME
    ja .hostname_long
    mov [rbx + linnea_config_server.hostname_len], rdx
    lea rdi, [rbx + linnea_config_server.hostname]
    mov rsi, rax
    call linnea_string_copy
    jmp .member_sep

.key_root:
    test r12d, 8
    jnz .dup
    or r12d, 8
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .root_long
    mov [rbx + linnea_config_server.root_len], rdx
    lea rdi, [rbx + linnea_config_server.root]
    mov rsi, rax
    call linnea_string_copy

.member_sep:
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ','
    je .next_member
    cmp al, '}'
    je .end_object
    lea rdi, [msg_sep_object]
    mov esi, msg_sep_object_len
    jmp linnea_parse_fail
.next_member:
    call linnea_parse_advance
    jmp .member_loop
.end_object:
    call linnea_parse_advance
    cmp r12d, 15
    jne .missing
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.dup:
    lea rdi, [msg_dup_key]
    mov esi, msg_dup_key_len
    mov rdx, r15
    jmp linnea_error_parse
.missing:
    lea rdi, [msg_missing_key]
    mov esi, msg_missing_key_len
    jmp linnea_parse_fail
.host_long:
    lea rdi, [msg_host_long]
    mov esi, msg_host_long_len
    jmp linnea_parse_fail
.hostname_long:
    lea rdi, [msg_hostname_long]
    mov esi, msg_hostname_long_len
    jmp linnea_parse_fail
.root_long:
    lea rdi, [msg_root_long]
    mov esi, msg_root_long_len
    jmp linnea_parse_fail

; --- low-level helpers -------------------------------------------------

; linnea_parse_skip_ws() — advance pos past space, tab, newline, CR.
linnea_parse_skip_ws:
    mov r8, [linnea_parser_state + linnea_parser.pos]
    mov r9, [linnea_parser_state + linnea_parser.base]
    mov r10, [linnea_parser_state + linnea_parser.size]
.loop:
    cmp r8, r10
    jae .done
    movzx eax, byte [r9 + r8]
    cmp al, ' '
    je .ws
    cmp al, 9
    je .ws
    cmp al, 10
    je .ws
    cmp al, 13
    je .ws
.done:
    mov [linnea_parser_state + linnea_parser.pos], r8
    ret
.ws:
    inc r8
    jmp .loop

; linnea_parse_peek() -> al = byte at pos; parse error on EOF. Does not advance.
linnea_parse_peek:
    mov r8, [linnea_parser_state + linnea_parser.pos]
    cmp r8, [linnea_parser_state + linnea_parser.size]
    jae .eof
    mov r9, [linnea_parser_state + linnea_parser.base]
    movzx eax, byte [r9 + r8]
    ret
.eof:
    lea rdi, [msg_eof]
    mov esi, msg_eof_len
    jmp linnea_parse_fail

; linnea_parse_advance() — pos++
linnea_parse_advance:
    inc qword [linnea_parser_state + linnea_parser.pos]
    ret

; linnea_parse_expect(rdi=char) — skip ws, require char, advance past it.
linnea_parse_expect:
    push rbx
    mov ebx, edi               ; expected char
    call linnea_parse_skip_ws
    mov r8, [linnea_parser_state + linnea_parser.pos]
    cmp r8, [linnea_parser_state + linnea_parser.size]
    jae .eof
    mov r9, [linnea_parser_state + linnea_parser.base]
    mov al, [r9 + r8]
    cmp al, bl
    jne .mismatch
    inc r8
    mov [linnea_parser_state + linnea_parser.pos], r8
    pop rbx
    ret
.eof:
    lea rdi, [msg_eof]
    mov esi, msg_eof_len
    jmp linnea_parse_fail
.mismatch:
    mov [msg_expect_char], bl
    lea rdi, [msg_expect]
    mov esi, msg_expect_len
    jmp linnea_parse_fail

; linnea_parse_string() -> rax=ptr into buffer, rdx=len
; Expects '"' (after ws), scans to the closing '"'. No escape sequences.
linnea_parse_string:
    mov edi, '"'
    call linnea_parse_expect
    mov r8, [linnea_parser_state + linnea_parser.pos]
    mov r10, r8                ; start offset
    mov r9, [linnea_parser_state + linnea_parser.base]
    mov r11, [linnea_parser_state + linnea_parser.size]
.loop:
    cmp r8, r11
    jae .unterminated
    movzx eax, byte [r9 + r8]
    cmp al, '"'
    je .done
    cmp al, '\'
    je .escape
    cmp al, 0x20
    jb .control
    inc r8
    jmp .loop
.done:
    lea rax, [r9 + r10]        ; ptr
    mov rdx, r8
    sub rdx, r10               ; len
    inc r8
    mov [linnea_parser_state + linnea_parser.pos], r8
    ret
.unterminated:
    mov [linnea_parser_state + linnea_parser.pos], r8
    lea rdi, [msg_unterminated]
    mov esi, msg_unterminated_len
    jmp linnea_parse_fail
.escape:
    mov [linnea_parser_state + linnea_parser.pos], r8
    lea rdi, [msg_escape]
    mov esi, msg_escape_len
    jmp linnea_parse_fail
.control:
    mov [linnea_parser_state + linnea_parser.pos], r8
    lea rdi, [msg_control]
    mov esi, msg_control_len
    jmp linnea_parse_fail

; linnea_parse_u64() -> rax = value
; Non-negative decimal integer; errors as soon as the value exceeds 65535.
linnea_parse_u64:
    call linnea_parse_skip_ws
    call linnea_parse_peek
    sub al, '0'
    cmp al, 9
    ja .not_number
    mov r8, [linnea_parser_state + linnea_parser.pos]
    mov r9, [linnea_parser_state + linnea_parser.base]
    mov r10, [linnea_parser_state + linnea_parser.size]
    xor eax, eax               ; accumulator
.loop:
    cmp r8, r10
    jae .done
    movzx ecx, byte [r9 + r8]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul eax, eax, 10
    add eax, ecx
    cmp eax, 65535
    ja .range
    inc r8
    jmp .loop
.done:
    mov [linnea_parser_state + linnea_parser.pos], r8
    ret
.not_number:
    lea rdi, [msg_number]
    mov esi, msg_number_len
    jmp linnea_parse_fail
.range:
    mov [linnea_parser_state + linnea_parser.pos], r8
    lea rdi, [msg_port_range]
    mov esi, msg_port_range_len
    jmp linnea_parse_fail

; linnea_parse_fail(rdi=msg, rsi=len) — report at current pos, never returns.
linnea_parse_fail:
    mov rdx, [linnea_parser_state + linnea_parser.pos]
    jmp linnea_error_parse
