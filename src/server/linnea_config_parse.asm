; linnea_config_parse.asm — schema-specific JSON parser for the config.
;
; Accepted grammar, exactly:
;   ws '{' member (ws ',' member)* ws '}' ws EOF
; where the top-level members are "log" (string) and "servers" (array of
; server objects), both required, plus the optional "timeout" (seconds,
; 1-3600), "max_connections" (1-65536), "head_timeout" (1-3600, the total a
; request head may take), "drain_timeout" (1-3600, how long a reload's drain
; may take) and "max_per_ip" (1-65536, connections one source address may hold
; at once), in any order, each at most once.
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
key_errlog:             db "error_log"
key_errlog_len          equ $ - key_errlog
key_spill:              db "spill_dir"
key_spill_len           equ $ - key_spill
key_portfile:           db "port_file"
key_portfile_len        equ $ - key_portfile
; The default is what every deployment got before the key existed. It is a
; poor default — see the note in linnea_config.inc — so validate warns when
; the directory it names turns out to be tmpfs rather than silently costing
; RAM per upload.
default_spill:          db "/tmp"
default_spill_len       equ $ - default_spill
key_timeout:            db "timeout"
key_timeout_len         equ $ - key_timeout
key_proxytmo:           db "proxy_timeout"
key_proxytmo_len        equ $ - key_proxytmo
key_tunneltmo:          db "tunnel_timeout"
key_tunneltmo_len       equ $ - key_tunneltmo
key_maxconn:            db "max_connections"
key_maxconn_len         equ $ - key_maxconn
key_headtmo:            db "head_timeout"
key_headtmo_len         equ $ - key_headtmo
key_drain:              db "drain_timeout"
key_drain_len           equ $ - key_drain
key_perip:              db "max_per_ip"
key_perip_len           equ $ - key_perip
key_ratelimit:          db "rate_limit"
key_ratelimit_len       equ $ - key_ratelimit
key_maxup:              db "max_upstream"
key_maxup_len           equ $ - key_maxup
key_maxbody:            db "max_body"
key_maxbody_len         equ $ - key_maxbody
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
key_cache_control:      db "cache_control"
key_cache_control_len   equ $ - key_cache_control
key_cert:               db "cert"
key_cert_len            equ $ - key_cert
key_key:                db "key"
key_key_len             equ $ - key_key
key_hsts:               db "hsts"
key_hsts_len            equ $ - key_hsts
key_nosniff:            db "nosniff"
key_nosniff_len         equ $ - key_nosniff
key_v6only:             db "v6only"
key_v6only_len          equ $ - key_v6only

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
msg_bad_proxy_list:     db "proxy list must be an array of ip:port strings"
msg_bad_proxy_list_len  equ $ - msg_bad_proxy_list
msg_bad_proxy_empty:    db "proxy list names no backend"
msg_bad_proxy_empty_len equ $ - msg_bad_proxy_empty
msg_bad_proxy_many:     db "too many proxy backends"
msg_bad_proxy_many_len  equ $ - msg_bad_proxy_many
msg_unterminated:       db "unterminated string"
msg_unterminated_len    equ $ - msg_unterminated
msg_escape:             db "escape sequences not supported"
msg_escape_len          equ $ - msg_escape
msg_control:            db "control character in string"
msg_control_len         equ $ - msg_control
msg_number:             db "expected number"
msg_number_len          equ $ - msg_number
msg_port_range:         db "port must be 0 (kernel-chosen) or between 1 and 65535"
msg_port_range_len      equ $ - msg_port_range
msg_number_range:       db "number too large"
msg_number_range_len    equ $ - msg_number_range
msg_timeout_range:      db "timeout must be between 1 and 3600"
msg_timeout_range_len   equ $ - msg_timeout_range
msg_maxconn_range:      db "max_connections must be between 1 and 65536"
msg_maxconn_range_len   equ $ - msg_maxconn_range
msg_ratelimit_range:    db "rate_limit must be between 0 and 1000000"
msg_ratelimit_range_len equ $ - msg_ratelimit_range
msg_tunneltmo_range:    db "tunnel_timeout must be between 1 and 86400"
msg_tunneltmo_range_len equ $ - msg_tunneltmo_range
msg_proxytmo_range:     db "proxy_timeout must be between 1 and 3600"
msg_proxytmo_range_len  equ $ - msg_proxytmo_range
msg_headtmo_range:      db "head_timeout must be between 1 and 3600"
msg_headtmo_range_len   equ $ - msg_headtmo_range
msg_drain_range:        db "drain_timeout must be between 1 and 3600"
msg_drain_range_len     equ $ - msg_drain_range
msg_perip_range:        db "max_per_ip must be between 1 and 65536"
msg_perip_range_len     equ $ - msg_perip_range
msg_maxup_range:        db "max_upstream must be between 1 and 65536"
msg_maxup_range_len     equ $ - msg_maxup_range
msg_maxbody_range:      db "max_body must be at least 1"
msg_maxbody_range_len   equ $ - msg_maxbody_range
msg_workers_range:      db "workers must be between 0 and 256 (0 = one per CPU)"
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
msg_hsts_type:          db "hsts takes the header VALUE as a string, e.g. "
                        db '"max-age=31536000; includeSubDomains"'
                        db " -- the nosniff beside it is the 0/1 one"
msg_hsts_type_len       equ $ - msg_hsts_type
msg_nosniff:            db "nosniff must be 0 or 1"
msg_nosniff_len         equ $ - msg_nosniff
msg_v6only:             db "v6only must be 0 or 1"
msg_v6only_len          equ $ - msg_v6only
msg_cc_long:            db "cache_control too long"
msg_cc_long_len         equ $ - msg_cc_long
msg_path_long:          db "cert/key path too long"
msg_path_long_len       equ $ - msg_path_long
msg_prefix_long:        db "prefix too long"
msg_prefix_long_len     equ $ - msg_prefix_long
msg_proxy_long:         db "proxy address too long"
msg_proxy_long_len      equ $ - msg_proxy_long
msg_errlog_bad:         db "error_log must not be empty"
msg_errlog_bad_len      equ $ - msg_errlog_bad
msg_log_long:           db "log too long"
msg_log_long_len        equ $ - msg_log_long
msg_spill_bad:          db "spill_dir must be a non-empty path of at most 255 bytes"
msg_spill_bad_len       equ $ - msg_spill_bad
msg_portfile_bad:       db "port_file must be a non-empty path of at most 255 bytes"
msg_portfile_bad_len    equ $ - msg_portfile_bad

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
    mov qword [rbx + linnea_config.error_log_len], 0
    mov qword [rbx + linnea_config.timeout], LINNEA_DEFAULT_TIMEOUT
    mov qword [rbx + linnea_config.proxy_timeout], LINNEA_DEFAULT_PROXY_TIMEOUT
    mov qword [rbx + linnea_config.tunnel_timeout], LINNEA_DEFAULT_TUNNEL_TIMEOUT
    mov qword [rbx + linnea_config.max_connections], LINNEA_DEFAULT_MAX_CONNECTIONS
    mov qword [rbx + linnea_config.head_timeout], LINNEA_DEFAULT_HEAD_TIMEOUT
    mov qword [rbx + linnea_config.drain_timeout], LINNEA_DEFAULT_DRAIN_TIMEOUT
    mov qword [rbx + linnea_config.max_per_ip], LINNEA_DEFAULT_MAX_PER_IP
    mov qword [rbx + linnea_config.rate_limit], LINNEA_DEFAULT_RATE_LIMIT
    mov qword [rbx + linnea_config.max_upstream], LINNEA_DEFAULT_MAX_UPSTREAM
    mov qword [rbx + linnea_config.max_body], LINNEA_DEFAULT_MAX_BODY
    mov qword [rbx + linnea_config.workers], LINNEA_DEFAULT_WORKERS
    mov qword [rbx + linnea_config.http2], 1     ; HTTP/2 on by default (M19)
    push rdi
    push rsi
    lea rdi, [rbx + linnea_config.spill_dir]
    lea rsi, [default_spill]
    mov ecx, default_spill_len
    rep movsb
    mov byte [rdi], 0
    pop rsi
    pop rdi
    mov qword [rbx + linnea_config.spill_dir_len], default_spill_len
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
    lea rdx, [key_errlog]
    mov ecx, key_errlog_len
    call linnea_string_equal
    test eax, eax
    jnz .top_errlog
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_log]
    mov ecx, key_log_len
    call linnea_string_equal
    test eax, eax
    jnz .top_log
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_spill]
    mov ecx, key_spill_len
    call linnea_string_equal
    test eax, eax
    jnz .top_spill
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_portfile]
    mov ecx, key_portfile_len
    call linnea_string_equal
    test eax, eax
    jnz .top_portfile
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_timeout]
    mov ecx, key_timeout_len
    call linnea_string_equal
    test eax, eax
    jnz .top_timeout
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_tunneltmo]
    mov ecx, key_tunneltmo_len
    call linnea_string_equal
    test eax, eax
    jnz .top_tunneltmo
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_proxytmo]
    mov ecx, key_proxytmo_len
    call linnea_string_equal
    test eax, eax
    jnz .top_proxytmo
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_maxconn]
    mov ecx, key_maxconn_len
    call linnea_string_equal
    test eax, eax
    jnz .top_maxconn
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_headtmo]
    mov ecx, key_headtmo_len
    call linnea_string_equal
    test eax, eax
    jnz .top_headtmo
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_drain]
    mov ecx, key_drain_len
    call linnea_string_equal
    test eax, eax
    jnz .top_drain
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_ratelimit]
    mov ecx, key_ratelimit_len
    call linnea_string_equal
    test eax, eax
    jnz .top_ratelimit
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_perip]
    mov ecx, key_perip_len
    call linnea_string_equal
    test eax, eax
    jnz .top_perip
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_maxup]
    mov ecx, key_maxup_len
    call linnea_string_equal
    test eax, eax
    jnz .top_maxup
    mov rdi, r14
    mov rsi, r15
    lea rdx, [key_maxbody]
    mov ecx, key_maxbody_len
    call linnea_string_equal
    test eax, eax
    jnz .top_maxbody
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

.top_errlog:
    test r13d, 16384
    jnz .top_dup
    or r13d, 16384
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_LOG
    ja .log_long
    test rdx, rdx
    jz .errlog_bad                 ; an empty path names no file — and saying
                                   ; "too long" about an empty string is the
                                   ; cause-collapse this tree keeps finding
    mov [rbx + linnea_config.error_log_len], rdx
    lea rdi, [rbx + linnea_config.error_log]
    mov rsi, rax
    call linnea_string_copy
    jmp .top_sep

.top_spill:
    test r13d, 2048
    jnz .top_dup
    or r13d, 2048
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .spill_long
    test rdx, rdx
    jz .spill_long                 ; empty names no filesystem at all
    mov [rbx + linnea_config.spill_dir_len], rdx
    lea rdi, [rbx + linnea_config.spill_dir]
    mov rsi, rax
    call linnea_string_copy
    jmp .top_sep

.top_portfile:
    test r13d, 4096
    jnz .top_dup
    or r13d, 4096
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .portfile_bad
    test rdx, rdx
    jz .portfile_bad               ; an empty path names no file
    mov [rbx + linnea_config.port_file_len], rdx
    lea rdi, [rbx + linnea_config.port_file]
    mov rsi, rax
    call linnea_string_copy
    jmp .top_sep
.portfile_bad:
    lea rdi, [msg_portfile_bad]
    mov esi, msg_portfile_bad_len
    jmp linnea_parse_fail

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

.top_tunneltmo:
    test r13d, 65536
    jnz .top_dup
    or r13d, 65536
    call linnea_parse_u64
    test rax, rax
    jz .tunneltmo_range
    cmp rax, 86400                 ; a day: a tunnel may legitimately be long
    ja .tunneltmo_range
    mov [rbx + linnea_config.tunnel_timeout], rax
    jmp .top_sep

.top_proxytmo:
    test r13d, 8192
    jnz .top_dup
    or r13d, 8192
    call linnea_parse_u64
    test rax, rax
    jz .proxytmo_range
    cmp rax, 3600
    ja .proxytmo_range
    mov [rbx + linnea_config.proxy_timeout], rax
    jmp .top_sep

.top_headtmo:
    test r13d, 64
    jnz .top_dup
    or r13d, 64
    call linnea_parse_u64
    test rax, rax
    jz .headtmo_range
    cmp rax, 3600
    ja .headtmo_range
    mov [rbx + linnea_config.head_timeout], rax
    jmp .top_sep

.top_drain:
    test r13d, 1024
    jnz .top_dup
    or r13d, 1024
    call linnea_parse_u64
    test rax, rax
    jz .drain_range
    cmp rax, 3600
    ja .drain_range
    mov [rbx + linnea_config.drain_timeout], rax
    jmp .top_sep

.top_ratelimit:
    test r13d, 32768
    jnz .top_dup
    or r13d, 32768
    call linnea_parse_u64
    cmp rax, 1000000               ; 0 is legal: it means "no limit"
    ja .ratelimit_range
    mov [rbx + linnea_config.rate_limit], rax
    jmp .top_sep

.top_perip:
    test r13d, 128
    jnz .top_dup
    or r13d, 128
    call linnea_parse_u64
    test rax, rax
    jz .perip_range
    cmp rax, 65536
    ja .perip_range
    mov [rbx + linnea_config.max_per_ip], rax
    jmp .top_sep

.top_maxup:
    test r13d, 256
    jnz .top_dup
    or r13d, 256
    call linnea_parse_u64
    test rax, rax
    jz .maxup_range
    cmp rax, 65536
    ja .maxup_range
    mov [rbx + linnea_config.max_upstream], rax
    jmp .top_sep

.top_maxbody:
    test r13d, 512
    jnz .top_dup
    or r13d, 512
    call linnea_parse_u64
    ; No ceiling of our own beyond what a u64 holds: the point of the key is to
    ; BE the limit, and a bound invented here is one more number to go stale.
    ; Zero is still refused — it would mean "accept no body at all", which is a
    ; way of turning uploads off that nobody would guess at.
    test rax, rax
    jz .maxbody_range
    mov [rbx + linnea_config.max_body], rax
    jmp .top_sep

.top_workers:
    test r13d, 16
    jnz .top_dup
    or r13d, 16
    call linnea_parse_u64
    ; 0 is legal and means "one worker per online CPU" — which is also the
    ; default, and used to be unwritable: the range started at 1, so the only
    ; way to ASK for the default was to leave the key out. resolve_workers has
    ; always turned 0 into the CPU count, so this only stops rejecting it.
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
    ; "unset" means "follow timeout". Resolve it HERE rather than at each
    ; consumer: a sentinel that survives into the running server is one more
    ; thing every reader has to remember, and the startup line would print 0
    ; for a deadline that is really 5.
    cmp qword [rbx + linnea_config.proxy_timeout], 0
    jne .top_ptmo_set
    mov rax, [rbx + linnea_config.timeout]
    mov [rbx + linnea_config.proxy_timeout], rax
.top_ptmo_set:
    cmp qword [rbx + linnea_config.tunnel_timeout], 0
    jne .top_ttmo_set
    mov rax, [rbx + linnea_config.timeout]
    mov [rbx + linnea_config.tunnel_timeout], rax
.top_ttmo_set:
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
.spill_long:
    lea rdi, [msg_spill_bad]
    mov esi, msg_spill_bad_len
    jmp linnea_parse_fail
.timeout_range:
    lea rdi, [msg_timeout_range]
    mov esi, msg_timeout_range_len
    jmp linnea_parse_fail
.errlog_bad:
    lea rdi, [msg_errlog_bad]
    mov esi, msg_errlog_bad_len
    jmp linnea_parse_fail
.ratelimit_range:
    lea rdi, [msg_ratelimit_range]
    mov esi, msg_ratelimit_range_len
    jmp linnea_parse_fail
.tunneltmo_range:
    lea rdi, [msg_tunneltmo_range]
    mov esi, msg_tunneltmo_range_len
    jmp linnea_parse_fail
.proxytmo_range:
    lea rdi, [msg_proxytmo_range]
    mov esi, msg_proxytmo_range_len
    jmp linnea_parse_fail
.headtmo_range:
    lea rdi, [msg_headtmo_range]
    mov esi, msg_headtmo_range_len
    jmp linnea_parse_fail
.drain_range:
    lea rdi, [msg_drain_range]
    mov esi, msg_drain_range_len
    jmp linnea_parse_fail

.maxbody_range:
    lea rdi, [msg_maxbody_range]
    mov esi, msg_maxbody_range_len
    jmp linnea_parse_fail
.maxup_range:
    lea rdi, [msg_maxup_range]
    mov esi, msg_maxup_range_len
    jmp linnea_parse_fail

.perip_range:
    lea rdi, [msg_perip_range]
    mov esi, msg_perip_range_len
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
    mov qword [rbx + linnea_config_server.hsts_len], 0
    mov qword [rbx + linnea_config_server.nosniff], 0
    mov qword [rbx + linnea_config_server.v6only], 0
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
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_hsts]
    mov ecx, key_hsts_len
    call linnea_string_equal
    test eax, eax
    jnz .key_hsts
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_nosniff]
    mov ecx, key_nosniff_len
    call linnea_string_equal
    test eax, eax
    jnz .key_nosniff
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_v6only]
    mov ecx, key_v6only_len
    call linnea_string_equal
    test eax, eax
    jnz .key_v6only
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
    ; 0 is allowed and means "let the kernel choose a free one": the bind
    ; resolves it and writes the answer back into this field, so everything
    ; downstream — the shared-listener scan, the log line, Alt-Svc, port_file —
    ; reads the real port. parse_u64 never returns to signal failure, so a 0
    ; here is a 0 the config actually wrote.
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

.key_hsts:
    test r12d, 64
    jnz .dup
    or r12d, 64
    ; hsts is a STRING (the header value) while nosniff beside it is a flag, so
    ; "hsts": 1 is the natural thing to write and the natural thing to get
    ; wrong. Peeking first turns a bare `expected '"'` into a message that says
    ; what to write instead.
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, '"'
    jne .hsts_type
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .path_long
    mov [rbx + linnea_config_server.hsts_len], rdx
    lea rdi, [rbx + linnea_config_server.hsts]
    mov rsi, rax
    call linnea_string_copy
    jmp .member_sep

.key_nosniff:
    test r12d, 128
    jnz .dup
    or r12d, 128
    call linnea_parse_u64
    cmp rax, 1
    ja .nosniff_range
    mov [rbx + linnea_config_server.nosniff], rax
    jmp .member_sep
.hsts_type:
    lea rdi, [msg_hsts_type]
    mov esi, msg_hsts_type_len
    jmp linnea_parse_fail

.nosniff_range:
    lea rdi, [msg_nosniff]
    mov esi, msg_nosniff_len
    jmp linnea_parse_fail

.key_v6only:
    test r12d, 256
    jnz .dup
    or r12d, 256
    call linnea_parse_u64
    cmp rax, 1
    ja .v6only_range
    mov [rbx + linnea_config_server.v6only], rax
    jmp .member_sep
.v6only_range:
    lea rdi, [msg_v6only]
    mov esi, msg_v6only_len
    jmp linnea_parse_fail

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
; Key presence tracked in a bitmask: prefix=1, root=2, proxy=4, redirect=8,
; cache_control=16; a location requires prefix plus exactly one of root,
; proxy and redirect; cache_control is optional (a Cache-Control value sent
; on static responses). A proxy value is validated here and prebuilt into a
; sockaddr_in.
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
    mov rdi, r13
    mov rsi, r14
    lea rdx, [key_cache_control]
    mov ecx, key_cache_control_len
    call linnea_string_equal
    test eax, eax
    jnz .key_cache_control
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

.key_cache_control:
    test r12d, 16
    jnz .dup
    or r12d, 16
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_ROOT
    ja .cc_long
    mov [rbx + linnea_config_location.cache_control_len], rdx
    lea rdi, [rbx + linnea_config_location.cache_control]
    mov rsi, rax
    call linnea_string_copy
    jmp .member_sep

.key_proxy:
    test r12d, 4
    jnz .dup
    or r12d, 4
    ; "proxy" is either one "ip:port" or an ARRAY of them. One backend is the
    ; overwhelmingly common shape and stays spelled the way it always was; the
    ; array is what lets a location name a spare (audit follow-up: upstream
    ; keep-alive and failover).
    mov qword [rbx + linnea_config_location.proxy_count], 0
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, '['
    je .proxy_array
    call .proxy_one                    ; a bare string: exactly one backend
    mov qword [rbx + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    jmp .member_sep
.proxy_array:
    call linnea_parse_advance          ; past '['
.proxy_elem:
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ']'
    je .proxy_array_end
    call .proxy_one
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ','
    jne .proxy_array_end
    call linnea_parse_advance
    jmp .proxy_elem
.proxy_array_end:
    call linnea_parse_skip_ws
    call linnea_parse_peek
    cmp al, ']'
    jne .bad_proxy_list
    call linnea_parse_advance
    cmp qword [rbx + linnea_config_location.proxy_count], 0
    je .bad_proxy_empty                ; "proxy": [] names no upstream at all
    mov qword [rbx + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    jmp .member_sep

; .proxy_one — parse one "ip:port" string at the cursor and append it to this
; location's backend list. Both spellings above come through here, so the
; grammar is written once: the single-string form is the one-element case of
; the array, not a second implementation of it.
.proxy_one:
    push r13
    push r14
    push r15
    mov rax, [rbx + linnea_config_location.proxy_count]
    cmp rax, LINNEA_MAX_BACKENDS
    jae .bad_proxy_many
    call linnea_parse_string
    cmp rdx, LINNEA_MAX_PROXY_STR
    ja .proxy_long
    ; slot = proxy_count; str slot is (MAX+1)-strided, addr slot 16-strided
    mov r14, [rbx + linnea_config_location.proxy_count]
    mov [rbx + linnea_config_location.proxy_str_len + r14 * 8], rdx
    mov r13, r14
    imul r13, r13, LINNEA_MAX_PROXY_STR + 1
    lea rdi, [rbx + linnea_config_location.proxy_str]
    add rdi, r13
    mov rsi, rax
    push rdx
    call linnea_string_copy
    pop rdx
    lea r13, [rbx + linnea_config_location.proxy_str]
    mov r14, [rbx + linnea_config_location.proxy_count]
    imul r14, r14, LINNEA_MAX_PROXY_STR + 1
    add r13, r14                       ; r13 = this backend's string
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
    push rdx
    mov byte [r13 + r14], 0
    mov rdi, r13
    call linnea_network_parse_ipv4
    mov byte [r13 + r14], ':'
    pop rdx
    cmp rax, -1
    je .bad_proxy
    mov r15d, eax              ; ip, network byte order
    ; port: decimal digits only, 1-65535
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
    ; prebuild this backend's sockaddr_in
    mov r14, [rbx + linnea_config_location.proxy_count]
    shl r14, 4                         ; * sizeof(sockaddr_in slot)
    lea rdi, [rbx + linnea_config_location.proxy_addr]
    add rdi, r14
    mov word [rdi], LINNEA_AF_INET
    xchg al, ah                ; htons
    mov [rdi + 2], ax
    mov [rdi + 4], r15d
    mov qword [rdi + 8], 0
    inc qword [rbx + linnea_config_location.proxy_count]
    pop r15
    pop r14
    pop r13
    ret

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
    and r12d, ~16              ; cache_control is optional, any kind
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
.cc_long:
    lea rdi, [msg_cc_long]
    mov esi, msg_cc_long_len
    jmp linnea_parse_fail
.proxy_long:
    lea rdi, [msg_proxy_long]
    mov esi, msg_proxy_long_len
    jmp linnea_parse_fail
.bad_proxy:
    lea rdi, [msg_bad_proxy]
    mov esi, msg_bad_proxy_len
    jmp linnea_parse_fail
; These three jump out of .proxy_one without unwinding its pushes. That is safe
; only because linnea_parse_fail ends at linnea_error_die and the process never
; returns here — stated rather than assumed, since a later change making a parse
; error recoverable would turn each of them into a corrupted stack.
.bad_proxy_list:
    lea rdi, [msg_bad_proxy_list]
    mov esi, msg_bad_proxy_list_len
    jmp linnea_parse_fail
.bad_proxy_empty:
    lea rdi, [msg_bad_proxy_empty]
    mov esi, msg_bad_proxy_empty_len
    jmp linnea_parse_fail
.bad_proxy_many:
    lea rdi, [msg_bad_proxy_many]
    mov esi, msg_bad_proxy_many_len
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
; A non-negative decimal integer, over the FULL 64-bit range. Only a value that
; will not fit in 64 bits is refused here; what a key will actually accept is
; the key's own business, and its own message says so.
;
; This used to stop at 2^32 "against overflow", which is a real hazard handled
; the wrong way: it silently overrode the key ranges above it. max_body
; documented and advertised a ceiling of 68719476736, and its own error message
; named that number, but anything past 4294967296 was refused by this generic
; guard before max_body's check ever ran — so a documented range was a quarter
; of a percent reachable, and the specific message unreachable.
;
; Overflow is now detected exactly rather than approximated: an accumulator
; above (2^64-1)/10 cannot survive the multiply, and the carry out of the digit
; catches the one value that can.
linnea_parse_u64:
    call linnea_parse_skip_ws
    call linnea_parse_peek
    sub al, '0'
    cmp al, 9
    ja .not_number
    mov r8, [linnea_parser_state + linnea_parser.pos]
    mov r9, [linnea_parser_state + linnea_parser.base]
    mov r10, [linnea_parser_state + linnea_parser.size]
    mov r11, 1844674407370955161   ; (2^64-1)/10
    xor eax, eax               ; accumulator
.loop:
    cmp r8, r10
    jae .done
    movzx ecx, byte [r9 + r8]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    cmp rax, r11               ; would the multiply wrap?
    ja .range
    imul rax, rax, 10          ; ...it cannot now: the product fits
    add rax, rcx
    jc .range                  ; ...but the digit still can
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
