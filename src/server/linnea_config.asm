; linnea_config.asm — config storage, semantic validation, and dump.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_config_instance
global linnea_config_validate
global linnea_config_dump
global linnea_config_match_location

extern linnea_string_equal
extern linnea_print_stdout
extern linnea_print_u64_stdout
extern linnea_error_exit
extern linnea_error_duplicate_hostname
extern linnea_string_equal
extern linnea_string_iequal
extern linnea_network_fill_sockaddr6

section .rodata

dump_config:            db "config: "
dump_config_len         equ $ - dump_config
dump_servers:           db " servers timeout="
dump_servers_len        equ $ - dump_servers
dump_maxconn:           db " max_connections="
dump_maxconn_len        equ $ - dump_maxconn
dump_workers:           db " workers="
dump_workers_len        equ $ - dump_workers
dump_http2:             db " http2="
dump_http2_len          equ $ - dump_http2
dump_spill:             db " spill_dir="
dump_spill_len          equ $ - dump_spill
; Named on the startup line, and called out when it is tmpfs: that is the
; difference between an upload capture the kernel can write back and reclaim
; and one that is simply RAM. Silent before, and the cost only showed up as
; memory pressure under concurrent uploads.
warn_spill_tmpfs:       db " (tmpfs: uploads are held in RAM, not written back)"
warn_spill_tmpfs_len    equ $ - warn_spill_tmpfs
dump_headtmo:           db " head_timeout="
dump_headtmo_len        equ $ - dump_headtmo
dump_proxytmo:          db " proxy_timeout="
dump_proxytmo_len       equ $ - dump_proxytmo
dump_ratelimit:         db " rate_limit="
dump_ratelimit_len      equ $ - dump_ratelimit
dump_drain:             db " drain_timeout="
dump_drain_len          equ $ - dump_drain
dump_perip:             db " max_per_ip="
dump_perip_len          equ $ - dump_perip
dump_maxup:             db " max_upstream="
dump_maxup_len          equ $ - dump_maxup
dump_maxbody:           db " max_body="
dump_maxbody_len        equ $ - dump_maxbody
dump_server:            db "server "
dump_server_len         equ $ - dump_server
dump_host:              db ": host="
dump_host_len           equ $ - dump_host
dump_port:              db " port="
dump_port_len           equ $ - dump_port
dump_hostname:          db " hostname="
dump_hostname_len       equ $ - dump_hostname
dump_locations:         db " locations="
dump_locations_len      equ $ - dump_locations
dump_location:          db "location "
dump_location_len       equ $ - dump_location
dump_prefix:            db ": prefix="
dump_prefix_len         equ $ - dump_prefix
dump_root:              db " root="
dump_root_len           equ $ - dump_root
dump_proxy:             db " proxy="
dump_proxy_len          equ $ - dump_proxy
dump_redirect:          db " redirect="
dump_redirect_len       equ $ - dump_redirect
newline:                db 10

scheme_http:            db "http://"
scheme_http_len         equ $ - scheme_http
scheme_https:           db "https://"
scheme_https_len        equ $ - scheme_https

msg_no_servers:         db "config must define at least one server"
msg_no_servers_len      equ $ - msg_no_servers
msg_empty_host:         db "server host must not be empty"
msg_empty_host_len      equ $ - msg_empty_host
msg_empty_hostname:     db "server hostname must not be empty"
msg_empty_hostname_len  equ $ - msg_empty_hostname
msg_no_locations:       db "server requires at least one location"
msg_no_locations_len    equ $ - msg_no_locations
msg_bad_prefix:         db "location prefix must start with '/'"
msg_bad_prefix_len      equ $ - msg_bad_prefix
msg_empty_root:         db "location root must not be empty"
msg_empty_root_len      equ $ - msg_empty_root
msg_bad_redirect:       db "redirect target must start with http:// or https://"
msg_bad_redirect_len    equ $ - msg_bad_redirect
msg_empty_log:          db "config log must not be empty"
msg_empty_log_len       equ $ - msg_empty_log
msg_cert_key:           db "server needs both cert and key, or neither"
msg_cert_key_len        equ $ - msg_cert_key
msg_bad_host_ip:        db 'server host must be an IPv4 literal or "::" (a name is not resolved)' 
msg_bad_host_ip_len     equ $ - msg_bad_host_ip
msg_no_root_dir:        db "location root is not an existing directory"
msg_no_root_dir_len     equ $ - msg_no_root_dir
msg_no_spill_dir:       db "spill_dir is not an existing directory"
msg_no_spill_dir_len    equ $ - msg_no_spill_dir
msg_spill_notmp:        db "spill_dir does not support O_TMPFILE (try a directory on a local disk)"
msg_spill_notmp_len     equ $ - msg_spill_notmp
msg_no_log_dir:         db "the log's directory does not exist"
msg_no_log_dir_len      equ $ - msg_no_log_dir
msg_tls_mismatch:       db "servers sharing a listener must all set TLS or none"
msg_tls_mismatch_len    equ $ - msg_tls_mismatch

dump_tls_on:            db " tls=on cert="
dump_tls_on_len         equ $ - dump_tls_on

section .bss
log_dir_buf: resb LINNEA_MAX_ROOT + 2   ; the log path, cut at its last /
host_probe_sa: resb 28                  ; scratch sockaddr_in6, to ask the binder

linnea_config_instance: resb linnea_config_size

section .text

; linnea_config_validate(rdi=config*) — semantic rules, checked after parse.
; Exits with an error message on the first violation.
; dir_exists(rdi = NUL-terminated path) -> eax = 1 when it opens as a
; directory. openat with O_DIRECTORY does the whole job: a missing path, a
; path that is a plain file, and a path we may not traverse all fail it.
; Clobbers only the caller-saved set the callers already push.
; spill_is_tmpfs(rdi = NUL-terminated path) -> rax = 1 when the path is on
; tmpfs. f_type is the first qword of struct statfs. A failed statfs answers 0:
; this only drives a warning, and a path that cannot be interrogated has
; already been proved openable by the validate above.
spill_is_tmpfs:
    sub rsp, LINNEA_STATFS_BUF + 8
    mov rsi, rsp
    mov eax, LINNEA_SYS_STATFS
    syscall
    cmp rax, -4095
    jae .st_no
    mov rax, [rsp]
    cmp rax, LINNEA_TMPFS_MAGIC
    jne .st_no
    add rsp, LINNEA_STATFS_BUF + 8
    mov eax, 1
    ret
.st_no:
    add rsp, LINNEA_STATFS_BUF + 8
    xor eax, eax
    ret

dir_exists:
    mov esi, LINNEA_O_RDONLY | LINNEA_O_DIRECTORY | LINNEA_O_CLOEXEC
    xor edx, edx
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .de_no
    mov edi, eax
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov eax, 1
    ret
.de_no:
    xor eax, eax
    ret

linnea_config_validate:
    cmp qword [rdi + linnea_config.log_len], 0
    je .empty_log
    ; The log's DIRECTORY must exist — the file itself is created on open, so
    ; only the directory can be wrong, and it was another thing --test used to
    ; miss. Copy the path and cut it at the last '/'; a bare filename means the
    ; working directory, which by definition exists.
    push rax
    push rdi
    mov rsi, rdi
    mov rcx, [rsi + linnea_config.log_len]
    lea rsi, [rsi + linnea_config.log]
    lea rdi, [log_dir_buf]
    push rcx
    rep movsb
    pop rcx
    mov byte [log_dir_buf + rcx], 0
.ld_scan:
    test rcx, rcx
    jz .ld_ok                     ; no '/': the cwd, which exists
    dec rcx
    cmp byte [log_dir_buf + rcx], '/'
    jne .ld_scan
    test rcx, rcx
    jnz .ld_cut
    mov byte [log_dir_buf + 1], 0 ; "/x" -> the root directory
    jmp .ld_check
.ld_cut:
    mov byte [log_dir_buf + rcx], 0
.ld_check:
    lea rdi, [log_dir_buf]
    call dir_exists
    test eax, eax
    jz .ld_bad
.ld_ok:
    pop rdi
    pop rax
    jmp .have_log
.ld_bad:
    pop rdi
    pop rax
    jmp .no_log_dir
.have_log:
    ; The upload capture directory has to exist AND support O_TMPFILE — the
    ; open is the only honest test, since plenty of directories exist that
    ; cannot give an unnamed file (some network filesystems, and older ones).
    ; Checked here so a bad value is a startup error and a --test failure,
    ; rather than surfacing as a failed upload on the first big POST.
    push rax
    push rdi
    lea rdi, [rdi + linnea_config.spill_dir]
    call dir_exists
    test eax, eax
    jz .sd_bad
    pop rdi
    push rdi
    lea rdi, [rdi + linnea_config.spill_dir]
    mov esi, LINNEA_O_TMPFILE | LINNEA_O_RDWR | LINNEA_O_CLOEXEC
    mov edx, LINNEA_MODE_0600
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .sd_notmp
    mov edi, eax
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop rdi
    pop rax
    jmp .spill_ok
.sd_bad:
    pop rdi
    pop rax
    jmp .no_spill_dir
.sd_notmp:
    pop rdi
    pop rax
    jmp .spill_no_tmpfile
.spill_ok:
    mov rax, [rdi + linnea_config.server_count]
    test rax, rax
    jz .no_servers
    xor r8d, r8d               ; server index
.loop:
    cmp r8, rax
    jae .ok
    imul r9, r8, linnea_config_server_size
    lea r9, [rdi + r9 + linnea_config.servers]
    ; port 0 is deliberate here, not missing: it means "let the kernel choose",
    ; resolved at bind time. A key left out entirely is caught by the parser's
    ; required-key check, so nothing silently binds a random port.
    cmp qword [r9 + linnea_config_server.host_len], 0
    je .empty_host
    cmp qword [r9 + linnea_config_server.hostname_len], 0
    je .empty_hostname
    ; The bind address must be one the listener can actually use. Discovered
    ; only at bind time before, so `--test` passed a config that could not
    ; start — and --test is what gates the hot upgrade, so the reload succeeded
    ; (listeners are inherited, never re-bound) and the fault surfaced at the
    ; next cold restart, detached from the edit that caused it.
    ;
    ; Asks the binder's own function rather than restating the rule: the first
    ; attempt here duplicated it as "must parse as IPv4" and immediately
    ; diverged, rejecting the "::" wildcard that the listener accepts and that
    ; the IPv6 fixtures use. One definition, in the place that binds.
    push rax
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov rdi, r9
    lea rsi, [host_probe_sa]
    call linnea_network_fill_sockaddr6
    cmp rax, -1
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rax
    je .bad_host_ip
    mov r10, [r9 + linnea_config_server.location_count]
    test r10, r10
    jz .no_locations
    xor r11d, r11d             ; location index
.loc_loop:
    cmp r11, r10
    jae .loc_done
    imul rdx, r11, linnea_config_location_size
    lea rdx, [r9 + rdx + linnea_config_server.locations]
    cmp qword [rdx + linnea_config_location.prefix_len], 0
    je .bad_prefix
    cmp byte [rdx + linnea_config_location.prefix], '/'
    jne .bad_prefix
    cmp qword [rdx + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jne .loc_not_root
    cmp qword [rdx + linnea_config_location.root_len], 0
    je .empty_root
    push rax
    push rdi
    push rdx
    push r8
    push r9
    push r10
    push r11
    lea rdi, [rdx + linnea_config_location.root]
    call dir_exists
    test eax, eax
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rdi
    pop rax
    jz .no_root_dir
    jmp .loc_next
.loc_not_root:
    cmp qword [rdx + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    jne .loc_next
    ; the target must be an absolute URL: a matched request's raw target
    ; ("/...") is appended verbatim, so a scheme-less value cannot work.
    ; The outer loops live in rax/rdi/r8-r11, all of which the compare
    ; calls (or this block) scratch: save the lot.
    push rax
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov r10, rdx
    cmp qword [r10 + linnea_config_location.redirect_len], scheme_http_len
    jb .bad_redirect
    lea rdi, [r10 + linnea_config_location.redirect]
    mov esi, scheme_http_len
    lea rdx, [scheme_http]
    mov ecx, scheme_http_len
    call linnea_string_equal
    test eax, eax
    jnz .redirect_ok
    cmp qword [r10 + linnea_config_location.redirect_len], scheme_https_len
    jb .bad_redirect
    lea rdi, [r10 + linnea_config_location.redirect]
    mov esi, scheme_https_len
    lea rdx, [scheme_https]
    mov ecx, scheme_https_len
    call linnea_string_equal
    test eax, eax
    jz .bad_redirect
.redirect_ok:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rax
.loc_next:
    inc r11
    jmp .loc_loop
.loc_done:
    ; TLS is both-or-neither; when both paths are present mark the server
    ; TLS so the listener-consistency pass and the accept path can see it.
    mov r10, [r9 + linnea_config_server.cert_path_len]
    mov r11, [r9 + linnea_config_server.key_path_len]
    test r10, r10
    jnz .has_cert
    test r11, r11
    jnz .cert_key            ; key without cert
    jmp .server_next        ; neither: plaintext
.has_cert:
    test r11, r11
    jz .cert_key            ; cert without key
    mov dword [r9 + linnea_config_server.tls], 1
.server_next:
    inc r8
    jmp .loop
.ok:
    ; servers sharing a listener (same host:port, as linnea_network pairs
    ; them) must not repeat a hostname: Host matching takes the first, so
    ; a duplicate could never be selected. Compared case-insensitively,
    ; like the vhost lookup.
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12d, 1                ; server index i
.dup_loop:
    cmp r12, [rbx + linnea_config.server_count]
    jae .dup_ok
    imul r13, r12, linnea_config_server_size
    lea r13, [rbx + r13 + linnea_config.servers]   ; server i
    xor r14d, r14d             ; earlier server index j
.dup_prior:
    cmp r14, r12
    jae .dup_next
    imul r15, r14, linnea_config_server_size
    lea r15, [rbx + r15 + linnea_config.servers]   ; server j
    mov ax, [r13 + linnea_config_server.port]
    cmp ax, [r15 + linnea_config_server.port]
    jne .dup_prior_next
    lea rdi, [r13 + linnea_config_server.host]
    mov rsi, [r13 + linnea_config_server.host_len]
    lea rdx, [r15 + linnea_config_server.host]
    mov rcx, [r15 + linnea_config_server.host_len]
    call linnea_string_equal
    test eax, eax
    jz .dup_prior_next
    ; same host:port -> the two servers share a listener; their TLS-ness
    ; must agree. SNI selects each vhost's certificate within a TLS
    ; listener, but cannot mix TLS and plaintext on one socket.
    mov eax, [r13 + linnea_config_server.tls]
    cmp eax, [r15 + linnea_config_server.tls]
    jne .tls_mismatch
    lea rdi, [r13 + linnea_config_server.hostname]
    mov rsi, [r13 + linnea_config_server.hostname_len]
    lea rdx, [r15 + linnea_config_server.hostname]
    mov rcx, [r15 + linnea_config_server.hostname_len]
    call linnea_string_iequal
    test eax, eax
    jnz .dup_hostname
.dup_prior_next:
    inc r14
    jmp .dup_prior
.dup_next:
    inc r12
    jmp .dup_loop
.dup_ok:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.dup_hostname:
    mov rdi, r13
    jmp linnea_error_duplicate_hostname
.no_servers:
    lea rdi, [msg_no_servers]
    mov esi, msg_no_servers_len
    jmp linnea_error_exit
.empty_host:
    lea rdi, [msg_empty_host]
    mov esi, msg_empty_host_len
    jmp linnea_error_exit
.empty_hostname:
    lea rdi, [msg_empty_hostname]
    mov esi, msg_empty_hostname_len
    jmp linnea_error_exit
.no_locations:
    lea rdi, [msg_no_locations]
    mov esi, msg_no_locations_len
    jmp linnea_error_exit
.bad_host_ip:
    lea rdi, [msg_bad_host_ip]
    mov esi, msg_bad_host_ip_len
    jmp linnea_error_exit
.no_spill_dir:
    lea rdi, [msg_no_spill_dir]
    mov esi, msg_no_spill_dir_len
    jmp linnea_error_exit
.spill_no_tmpfile:
    lea rdi, [msg_spill_notmp]
    mov esi, msg_spill_notmp_len
    jmp linnea_error_exit
.no_root_dir:
    lea rdi, [msg_no_root_dir]
    mov esi, msg_no_root_dir_len
    jmp linnea_error_exit
.no_log_dir:
    lea rdi, [msg_no_log_dir]
    mov esi, msg_no_log_dir_len
    jmp linnea_error_exit
.bad_prefix:
    lea rdi, [msg_bad_prefix]
    mov esi, msg_bad_prefix_len
    jmp linnea_error_exit
.bad_redirect:
    lea rdi, [msg_bad_redirect]
    mov esi, msg_bad_redirect_len
    jmp linnea_error_exit
.empty_root:
    lea rdi, [msg_empty_root]
    mov esi, msg_empty_root_len
    jmp linnea_error_exit
.empty_log:
    lea rdi, [msg_empty_log]
    mov esi, msg_empty_log_len
    jmp linnea_error_exit
.cert_key:
    lea rdi, [msg_cert_key]
    mov esi, msg_cert_key_len
    jmp linnea_error_exit
.tls_mismatch:
    lea rdi, [msg_tls_mismatch]
    mov esi, msg_tls_mismatch_len
    jmp linnea_error_exit

; linnea_config_dump(rdi=config*) — human-readable dump to stdout:
;   config: 2 servers timeout=5 max_connections=1024 workers=2
;   server 0: host=0.0.0.0 port=8080 hostname=example.com locations=2
;   location 0: prefix=/ root=test/www
;   location 1: prefix=/api proxy=127.0.0.1:3000
linnea_config_dump:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    lea rdi, [dump_config]
    mov esi, dump_config_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.server_count]
    call linnea_print_u64_stdout
    lea rdi, [dump_servers]
    mov esi, dump_servers_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.timeout]
    call linnea_print_u64_stdout
    lea rdi, [dump_maxconn]
    mov esi, dump_maxconn_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.max_connections]
    call linnea_print_u64_stdout
    lea rdi, [dump_workers]
    mov esi, dump_workers_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.workers]
    call linnea_print_u64_stdout
    lea rdi, [dump_http2]
    mov esi, dump_http2_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.http2]
    call linnea_print_u64_stdout
    lea rdi, [dump_spill]
    mov esi, dump_spill_len
    call linnea_print_stdout
    lea rdi, [rbx + linnea_config.spill_dir]
    mov rsi, [rbx + linnea_config.spill_dir_len]
    call linnea_print_stdout
    lea rdi, [rbx + linnea_config.spill_dir]
    call spill_is_tmpfs
    test eax, eax
    jz .dump_spill_ok
    lea rdi, [warn_spill_tmpfs]
    mov esi, warn_spill_tmpfs_len
    call linnea_print_stdout
.dump_spill_ok:
    lea rdi, [dump_ratelimit]
    mov esi, dump_ratelimit_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.rate_limit]
    call linnea_print_u64_stdout
    lea rdi, [dump_proxytmo]
    mov esi, dump_proxytmo_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.proxy_timeout]
    call linnea_print_u64_stdout
    lea rdi, [dump_headtmo]
    mov esi, dump_headtmo_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.head_timeout]
    call linnea_print_u64_stdout
    lea rdi, [dump_drain]
    mov esi, dump_drain_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.drain_timeout]
    call linnea_print_u64_stdout
    lea rdi, [dump_perip]
    mov esi, dump_perip_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.max_per_ip]
    call linnea_print_u64_stdout
    lea rdi, [dump_maxup]
    mov esi, dump_maxup_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.max_upstream]
    call linnea_print_u64_stdout
    ; max_body was the one limit the dump did not name, which is awkward for
    ; the limit that stands between one client and the disk: setting it left
    ; nothing to check it by.
    lea rdi, [dump_maxbody]
    mov esi, dump_maxbody_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.max_body]
    call linnea_print_u64_stdout
    lea rdi, [newline]
    mov esi, 1
    call linnea_print_stdout
    xor r12d, r12d             ; server index
.loop:
    cmp r12, [rbx + linnea_config.server_count]
    jae .done
    imul r13, r12, linnea_config_server_size
    lea r13, [rbx + r13 + linnea_config.servers]
    lea rdi, [dump_server]
    mov esi, dump_server_len
    call linnea_print_stdout
    mov rdi, r12
    call linnea_print_u64_stdout
    lea rdi, [dump_host]
    mov esi, dump_host_len
    call linnea_print_stdout
    lea rdi, [r13 + linnea_config_server.host]
    mov rsi, [r13 + linnea_config_server.host_len]
    call linnea_print_stdout
    lea rdi, [dump_port]
    mov esi, dump_port_len
    call linnea_print_stdout
    movzx edi, word [r13 + linnea_config_server.port]
    call linnea_print_u64_stdout
    lea rdi, [dump_hostname]
    mov esi, dump_hostname_len
    call linnea_print_stdout
    lea rdi, [r13 + linnea_config_server.hostname]
    mov rsi, [r13 + linnea_config_server.hostname_len]
    call linnea_print_stdout
    cmp dword [r13 + linnea_config_server.tls], 0
    je .no_tls
    lea rdi, [dump_tls_on]
    mov esi, dump_tls_on_len
    call linnea_print_stdout
    lea rdi, [r13 + linnea_config_server.cert_path]
    mov rsi, [r13 + linnea_config_server.cert_path_len]
    call linnea_print_stdout
.no_tls:
    lea rdi, [dump_locations]
    mov esi, dump_locations_len
    call linnea_print_stdout
    mov rdi, [r13 + linnea_config_server.location_count]
    call linnea_print_u64_stdout
    lea rdi, [newline]
    mov esi, 1
    call linnea_print_stdout
    xor r14d, r14d             ; location index
.loc_loop:
    cmp r14, [r13 + linnea_config_server.location_count]
    jae .loc_done
    imul r15, r14, linnea_config_location_size
    lea r15, [r13 + r15 + linnea_config_server.locations]
    lea rdi, [dump_location]
    mov esi, dump_location_len
    call linnea_print_stdout
    mov rdi, r14
    call linnea_print_u64_stdout
    lea rdi, [dump_prefix]
    mov esi, dump_prefix_len
    call linnea_print_stdout
    lea rdi, [r15 + linnea_config_location.prefix]
    mov rsi, [r15 + linnea_config_location.prefix_len]
    call linnea_print_stdout
    cmp qword [r15 + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    je .loc_proxy
    cmp qword [r15 + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    je .loc_redirect
    lea rdi, [dump_root]
    mov esi, dump_root_len
    call linnea_print_stdout
    lea rdi, [r15 + linnea_config_location.root]
    mov rsi, [r15 + linnea_config_location.root_len]
    jmp .loc_target
.loc_redirect:
    lea rdi, [dump_redirect]
    mov esi, dump_redirect_len
    call linnea_print_stdout
    lea rdi, [r15 + linnea_config_location.redirect]
    mov rsi, [r15 + linnea_config_location.redirect_len]
    jmp .loc_target
.loc_proxy:
    lea rdi, [dump_proxy]
    mov esi, dump_proxy_len
    call linnea_print_stdout
    lea rdi, [r15 + linnea_config_location.proxy_str]
    mov rsi, [r15 + linnea_config_location.proxy_str_len]
.loc_target:
    call linnea_print_stdout
    lea rdi, [newline]
    mov esi, 1
    call linnea_print_stdout
    inc r14
    jmp .loc_loop
.loc_done:
    inc r12
    jmp .loop
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; linnea_config_match_location(rdi=server*, rsi=path, rdx=path len)
;   -> rax = location*, or 0 if none claims the path
;
; Longest prefix wins, and a prefix is compared byte for byte and never
; stripped: the whole path is what gets appended to the root or sent upstream.
; Lifted out of the HTTP/1.1 parser so that HTTP/3, which used to be handed a
; document root and no locations at all, can route by exactly the same rule
; rather than by a second implementation of it.
linnea_config_match_location:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov r12, rdi                     ; server*
    mov r13, rsi                     ; path
    mov r14, rdx                     ; path length
    xor ebx, ebx                     ; best location so far
    xor r15d, r15d                   ; its prefix length
    xor ebp, ebp                     ; index
.loop:
    cmp rbp, [r12 + linnea_config_server.location_count]
    jae .done
    imul rax, rbp, linnea_config_location_size
    lea rax, [r12 + rax + linnea_config_server.locations]
    mov rcx, [rax + linnea_config_location.prefix_len]
    cmp rcx, r14
    ja .next                         ; prefix longer than the path
    cmp rcx, r15
    jbe .next                        ; no longer than the best already found
    push rax                         ; the candidate, across the compare
    mov rdi, r13
    mov rsi, rcx
    lea rdx, [rax + linnea_config_location.prefix]
    call linnea_string_equal
    pop rcx
    test eax, eax
    jz .next
    mov rbx, rcx
    mov r15, [rcx + linnea_config_location.prefix_len]
.next:
    inc rbp
    jmp .loop
.done:
    mov rax, rbx
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
