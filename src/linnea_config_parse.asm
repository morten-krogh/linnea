; linnea_config_parse.asm — schema-specific JSON parser for the config.
;
; Accepted grammar, exactly:
;   ws '{' member (ws ',' member)* ws '}' ws EOF
; where the top-level members are "log" (string) and "servers" (array of
; server objects), both required, plus the optional "timeout" (seconds,
; 1-3600) and "max_connections" (1-65536), in any order, each at most once.
;   server := ws '{' member (ws ',' member)* ws '}'
;   member := ws string ws ':' ws value
;
; Server keys are "host" (string), "port" (integer), "hostname" (string),
; "locations" (array of location objects), accepted in any order, each
; required exactly once. Location keys are "prefix" (string, required)
; plus exactly one of "root" (string), "proxy" ("ip:port" string, IPv4
; literal only, validated and prebuilt into a sockaddr_in here) and
; "redirect" (URL prefix a matched request is 301'd to).
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
extern linnea_network_parse_ipv4

section .rodata

key_servers:            db "servers"
key_servers_len         equ $ - key_servers
key_log:                db "log"
key_log_len             equ $ - key_log
key_timeout:            db "timeout"
key_timeout_len         equ $ - key_timeout
key_maxconn:            db "max_connections"
key_maxconn_len         equ $ - key_maxconn
key_workers:            db "workers"
key_workers_len         equ $ - key_workers
key_http2:              db "http2"
key_http2_len           equ $ - key_http2
key_host:               db "host"
key_host_len            equ $ - key_host
key_port:               db "port"
key_port_len            equ $ - key_port
key_hostname:           db "hostname"
key_hostname_len        equ $ - key_hostname
key_locations:          db "locations"
key_locations_len       equ $ - key_locations
key_prefix:             db "prefix"
key_prefix_len          equ $ - key_prefix
key_root:               db "root"
key_root_len            equ $ - key_root
key_proxy:              db "proxy"
key_proxy_len           equ $ - key_proxy
key_redirect:           db "redirect"
key_redirect_len        equ $ - key_redirect
key_cert:               db "cert"
key_cert_len            equ $ - key_cert
key_key:                db "key"
key_key_len             equ $ - key_key

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
msg_too_many_locs:      db "too many locations (max 8)"
msg_too_many_locs_len   equ $ - msg_too_many_locs
msg_unknown_key:        db "unknown key"
msg_unknown_key_len     equ $ - msg_unknown_key
msg_dup_key:            db "duplicate key"
msg_dup_key_len         equ $ - msg_dup_key
msg_missing_key:        db "server requires host, port, hostname and locations"
msg_missing_key_len     equ $ - msg_missing_key
msg_location_keys:      db "location requires prefix and exactly one of root, proxy or redirect"
msg_location_keys_len   equ $ - msg_location_keys
msg_bad_proxy:          db "invalid proxy address (IPv4:port required)"
msg_bad_proxy_len       equ $ - msg_bad_proxy
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
msg_number_range:       db "number too large"
msg_number_range_len    equ $ - msg_number_range
msg_timeout_range:      db "timeout must be between 1 and 3600"
msg_timeout_range_len   equ $ - msg_timeout_range
msg_maxconn_range:      db "max_connections must be between 1 and 65536"
msg_maxconn_range_len   equ $ - msg_maxconn_range
msg_workers_range:      db "workers must be between 1 and 256"
msg_workers_range_len   equ $ - msg_workers_range
msg_http2_range:        db "http2 must be 0 or 1"
msg_http2_range_len     equ $ - msg_http2_range
msg_host_long:          db "host too long"
msg_host_long_len       equ $ - msg_host_long
msg_hostname_long:      db "hostname too long"
msg_hostname_long_len   equ $ - msg_hostname_long
msg_root_long:          db "root too long"
msg_root_long_len       equ $ - msg_root_long
msg_redirect_long:      db "redirect too long"
msg_redirect_long_len   equ $ - msg_redirect_long
msg_path_long:          db "cert/key path too long"
msg_path_long_len       equ $ - msg_path_long
msg_prefix_long:        db "prefix too long"
msg_prefix_long_len     equ $ - msg_prefix_long
msg_proxy_long:         db "proxy address too long"
msg_proxy_long_len      equ $ - msg_proxy_long
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
; Top-level key presence tracked in a bitmask: servers=1, log=2 (required),
; timeout=4, max_connections=8, workers=16 (optional, mask bits only for
; dup detection).
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
    mov qword [rbx + linnea_config.timeout], LINNEA_DEFAULT_TIMEOUT
    mov qword [rbx + linnea_config.max_connections], LINNEA_DEFAULT_MAX_CONNECTIONS
    mov qword [rbx + linnea_config.workers], LINNEA_DEFAULT_WORKERS
    mov qword [rbx + linnea_config.http2], 1     ; HTTP/2 on by default (M19)
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
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_timeout]
    mov ecx, key_timeout_len
    call linnea_string_equal
    test eax, eax
    jnz .top_timeout
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_maxconn]
    mov ecx, key_maxconn_len
    call linnea_string_equal
    test eax, eax
    jnz .top_maxconn
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_workers]
    mov ecx, key_workers_len
    call linnea_string_equal
    test eax, eax
    jnz .top_workers
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_http2]
    mov ecx, key_http2_len
    call linnea_string_equal
    test eax, eax
    jnz .top_http2
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
    jmp .top_sep

.top_timeout:
    test r13d, 4
    jnz .top_dup
    or r13d, 4
    call linnea_parse_u64
    test rax, rax
    jz .timeout_range
    cmp rax, 3600
    ja .timeout_range
    mov [rbx + linnea_config.timeout], rax
    jmp .top_sep

.top_maxconn:
    test r13d, 8
    jnz .top_dup
    or r13d, 8
    call linnea_parse_u64
    test rax, rax
    jz .maxconn_range
    cmp rax, 65536
    ja .maxconn_range
    mov [rbx + linnea_config.max_connections], rax
    jmp .top_sep

.top_workers:
    test r13d, 16
    jnz .top_dup
    or r13d, 16
    call linnea_parse_u64
    test rax, rax
    jz .workers_range
    cmp rax, LINNEA_MAX_WORKERS
    ja .workers_range
    mov [rbx + linnea_config.workers], rax
    jmp .top_sep

.top_http2:
    test r13d, 32
    jnz .top_dup
    or r13d, 32
    call linnea_parse_u64       ; 0 or 1
    cmp rax, 1
    ja .http2_range
    mov [rbx + linnea_config.http2], rax

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
    mov eax, r13d
    and eax, 3                 ; log and servers are required
    cmp eax, 3
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
.timeout_range:
    lea rdi, [msg_timeout_range]
    mov esi, msg_timeout_range_len
    jmp linnea_parse_fail
.maxconn_range:
    lea rdi, [msg_maxconn_range]
    mov esi, msg_maxconn_range_len
    jmp linnea_parse_fail
.workers_range:
    lea rdi, [msg_workers_range]
    mov esi, msg_workers_range_len
    jmp linnea_parse_fail
.http2_range:
    lea rdi, [msg_http2_range]
    mov esi, msg_http2_range_len
    jmp linnea_parse_fail
.trailing:
    lea rdi, [msg_trailing]
    mov esi, msg_trailing_len
    jmp linnea_parse_fail

; linnea_parse_server(rdi=server*) — one server object, keys in any order.
; Key presence tracked in a bitmask: host=1, port=2, hostname=4, locations=8.
linnea_parse_server:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi               ; server*
    xor r12d, r12d             ; key mask
    mov qword [rbx + linnea_config_server.location_count], 0
    ; TLS is opt-in per server: clear the markers so a server with no
    ; "cert"/"key" is plaintext; validation enforces both-or-neither.
    mov dword [rbx + linnea_config_server.tls], 0
    mov qword [rbx + linnea_config_server.cert_path_len], 0
    mov qword [rbx + linnea_config_server.key_path_len], 0
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
    lea rdx, [key_locations]
    mov ecx, key_locations_len
    call linnea_string_equal
    test eax, eax
    jnz .key_locations
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_cert]
    mov ecx, key_cert_len
    call linnea_string_equal
    test eax, eax
    jnz .key_cert
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_key]
    mov ecx, key_key_len
    call linnea_string_equal
    test eax, eax
    jnz .key_key
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
    call linnea_parse_u64
    test rax, rax
    jz .port_range
    cmp rax, 65535
    ja .port_range
    mov [rbx + linnea_config_server.port], ax
    jmp .member_sep
.port_range:
    lea rdi, [msg_port_range]
    mov esi, msg_port_range_len
    jmp linnea_parse_fail

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

.key_cert:
    test r12d, 16
    jnz .dup
    or r12d, 16
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .path_long
    mov [rbx + linnea_config_server.cert_path_len], rdx
    lea rdi, [rbx + linnea_config_server.cert_path]
    mov rsi, rax
    call linnea_string_copy
    jmp .member_sep

.key_key:
    test r12d, 32
    jnz .dup
    or r12d, 32
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .path_long
    mov [rbx + linnea_config_server.key_path_len], rdx
    lea rdi, [rbx + linnea_config_server.key_path]
    mov rsi, rax
    call linnea_string_copy
    jmp .member_sep

.key_locations:
    test r12d, 8
    jnz .dup
    or r12d, 8
    mov edi, '['
    call linnea_parse_expect
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ']'
    jne .location_loop
    call linnea_parse_advance  ; empty array; validation rejects count 0
    jmp .member_sep
.location_loop:
    mov r13, [rbx + linnea_config_server.location_count]
    cmp r13, LINNEA_MAX_LOCATIONS
    jae .too_many_locations
    imul rdi, r13, linnea_config_location_size
    lea rdi, [rbx + rdi + linnea_config_server.locations]
    call linnea_parse_location
    inc qword [rbx + linnea_config_server.location_count]
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ','
    je .next_location
    cmp al, ']'
    je .end_locations
    lea rdi, [msg_sep_array]
    mov esi, msg_sep_array_len
    jmp linnea_parse_fail
.next_location:
    call linnea_parse_advance
    jmp .location_loop
.end_locations:
    call linnea_parse_advance

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
    mov eax, r12d              ; host+port+hostname+locations required;
    and eax, 15                ; cert/key (bits 16/32) are optional
    cmp eax, 15
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
.path_long:
    lea rdi, [msg_path_long]
    mov esi, msg_path_long_len
    jmp linnea_parse_fail
.too_many_locations:
    lea rdi, [msg_too_many_locs]
    mov esi, msg_too_many_locs_len
    jmp linnea_parse_fail

; linnea_parse_location(rdi=location*) — one location object.
; Key presence tracked in a bitmask: prefix=1, root=2, proxy=4,
; redirect=8; a location
; requires prefix plus exactly one of root and proxy (final mask 3 or 5).
; A proxy value is validated here and prebuilt into a sockaddr_in.
linnea_parse_location:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi               ; location*
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
    lea rdx, [key_prefix]
    mov ecx, key_prefix_len
    call linnea_string_equal
    test eax, eax
    jnz .key_prefix
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_root]
    mov ecx, key_root_len
    call linnea_string_equal
    test eax, eax
    jnz .key_root
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_proxy]
    mov ecx, key_proxy_len
    call linnea_string_equal
    test eax, eax
    jnz .key_proxy
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_redirect]
    mov ecx, key_redirect_len
    call linnea_string_equal
    test eax, eax
    jnz .key_redirect
    lea rdi, [msg_unknown_key]
    mov esi, msg_unknown_key_len
    mov rdx, r15
    jmp linnea_error_parse

.key_prefix:
    test r12d, 1
    jnz .dup
    or r12d, 1
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_PREFIX
    ja .prefix_long
    mov [rbx + linnea_config_location.prefix_len], rdx
    lea rdi, [rbx + linnea_config_location.prefix]
    mov rsi, rax
    call linnea_string_copy
    jmp .member_sep

.key_root:
    test r12d, 2
    jnz .dup
    or r12d, 2
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .root_long
    mov [rbx + linnea_config_location.root_len], rdx
    lea rdi, [rbx + linnea_config_location.root]
    mov rsi, rax
    call linnea_string_copy
    mov qword [rbx + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jmp .member_sep

.key_redirect:
    test r12d, 8
    jnz .dup
    or r12d, 8
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .redirect_long
    mov [rbx + linnea_config_location.redirect_len], rdx
    lea rdi, [rbx + linnea_config_location.redirect]
    mov rsi, rax
    call linnea_string_copy
    mov qword [rbx + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    jmp .member_sep

.key_proxy:
    test r12d, 4
    jnz .dup
    or r12d, 4
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_PROXY_STR
    ja .proxy_long
    mov [rbx + linnea_config_location.proxy_str_len], rdx
    lea rdi, [rbx + linnea_config_location.proxy_str]
    mov rsi, rax
    call linnea_string_copy
    ; split "ip:port" at the ':' — the ip half is NUL-terminated in place
    ; (we own the buffer), parsed, and the ':' restored
    lea r13, [rbx + linnea_config_location.proxy_str]
    mov rdx, [rbx + linnea_config_location.proxy_str_len]
    xor ecx, ecx
.proxy_colon_scan:
    cmp rcx, rdx
    jae .bad_proxy             ; no ':'
    cmp byte [r13 + rcx], ':'
    je .proxy_colon_found
    inc rcx
    jmp .proxy_colon_scan
.proxy_colon_found:
    test rcx, rcx
    jz .bad_proxy              ; empty ip part
    lea rax, [rcx + 1]
    cmp rax, rdx
    jae .bad_proxy             ; empty port part
    mov r14, rcx               ; ':' offset
    mov byte [r13 + r14], 0
    mov rdi, r13
    call linnea_network_parse_ipv4
    mov byte [r13 + r14], ':'
    cmp rax, -1
    je .bad_proxy
    mov r15d, eax              ; ip, network byte order
    ; port: decimal digits only, 1-65535
    mov rdx, [rbx + linnea_config_location.proxy_str_len]
    sub rdx, r14
    dec rdx                    ; digit count
    lea rsi, [r13 + r14 + 1]
    xor eax, eax               ; port accumulator
    xor ecx, ecx               ; digit index
.proxy_port_loop:
    cmp rcx, rdx
    jae .proxy_port_done
    movzx r8d, byte [rsi + rcx]
    sub r8d, '0'
    cmp r8d, 9
    ja .bad_proxy
    imul eax, eax, 10
    add eax, r8d
    cmp eax, 65535
    ja .bad_proxy
    inc rcx
    jmp .proxy_port_loop
.proxy_port_done:
    test eax, eax
    jz .bad_proxy
    ; prebuild the upstream sockaddr_in
    lea rdi, [rbx + linnea_config_location.proxy_addr]
    mov word [rdi], LINNEA_AF_INET
    xchg al, ah                ; htons
    mov [rdi + 2], ax
    mov [rdi + 4], r15d
    mov qword [rdi + 8], 0
    mov qword [rbx + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY

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
    cmp r12d, 3                ; prefix + root
    je .done
    cmp r12d, 5                ; prefix + proxy
    je .done
    cmp r12d, 9                ; prefix + redirect
    je .done
    lea rdi, [msg_location_keys]
    mov esi, msg_location_keys_len
    jmp linnea_parse_fail
.done:
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
.prefix_long:
    lea rdi, [msg_prefix_long]
    mov esi, msg_prefix_long_len
    jmp linnea_parse_fail
.root_long:
    lea rdi, [msg_root_long]
    mov esi, msg_root_long_len
    jmp linnea_parse_fail
.redirect_long:
    lea rdi, [msg_redirect_long]
    mov esi, msg_redirect_long_len
    jmp linnea_parse_fail
.proxy_long:
    lea rdi, [msg_proxy_long]
    mov esi, msg_proxy_long_len
    jmp linnea_parse_fail
.bad_proxy:
    lea rdi, [msg_bad_proxy]
    mov esi, msg_bad_proxy_len
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
; Non-negative decimal integer, capped at 2^32 against overflow; range
; validation with a key-specific message is the caller's job.
linnea_parse_u64:
    call linnea_parse_skip_ws
    call linnea_parse_peek
    sub al, '0'
    cmp al, 9
    ja .not_number
    mov r8, [linnea_parser_state + linnea_parser.pos]
    mov r9, [linnea_parser_state + linnea_parser.base]
    mov r10, [linnea_parser_state + linnea_parser.size]
    mov r11, 1 << 32
    xor eax, eax               ; accumulator
.loop:
    cmp r8, r10
    jae .done
    movzx ecx, byte [r9 + r8]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul rax, rax, 10
    add rax, rcx
    cmp rax, r11
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
    lea rdi, [msg_number_range]
    mov esi, msg_number_range_len
    jmp linnea_parse_fail

; linnea_parse_fail(rdi=msg, rsi=len) — report at current pos, never returns.
linnea_parse_fail:
    mov rdx, [linnea_parser_state + linnea_parser.pos]
    jmp linnea_error_parse
