; linnea_start.asm — entry point and top-level orchestration:
; map config file -> parse -> validate -> load TLS material -> bind (or
; adopt) listeners -> fork workers -> supervise.
;
; Multi-process model: the master parses the config, loads certs and
; keys, and binds every listener exactly once, then forks
; config.workers workers ("workers" in the config; the default is one
; per online CPU). Each worker inherits the listening fds and runs the
; whole event loop; the kernel completes each incoming connection on
; exactly one worker's accept. The master serves no traffic: it waits on
; its workers and respawns any that die.
;
; Shutdown: every worker carries PR_SET_PDEATHSIG(SIGTERM), so a master
; death takes them with it; a SIGTERM to the group drains them (M11).
;
; Zero-downtime binary upgrade (SIGUSR2, i.e. `systemctl reload`): the
; master re-execs the new binary in place — same PID, so systemd keeps
; tracking it. The listening sockets have no CLOEXEC, so they survive
; the exec; the new master adopts them (never closing them, so no
; connection is refused), spawns new workers, then SIGQUITs the old
; workers, which drain with the old code still mapped. Before committing
; the master runs the new binary in config-check mode (`-t`); if it
; rejects the config the upgrade is refused and the old generation keeps
; serving. A hot upgrade assumes the listener set is unchanged — a
; config that adds or moves listeners needs a full restart instead.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global _start

extern linnea_file_map_readonly
extern linnea_file_unmap
extern linnea_bpf_probe
extern linnea_bpf_reuseport_setup
extern linnea_bpf_map_fd
extern linnea_bpf_prog_fd
extern linnea_quic_reset_secret_init
extern linnea_quic_retry_secret_init
extern linnea_worker_index
extern linnea_config_parse
extern linnea_config_validate
extern linnea_config_dump
extern linnea_config_instance
extern linnea_tls_setup
extern linnea_log_open
extern linnea_log_reopen
extern linnea_log_stamp
extern linnea_log_write
extern linnea_log_u64
extern linnea_network_listen_all
extern linnea_connections_init
extern linnea_h2p_init
extern linnea_uring_run
extern linnea_error_usage
extern linnea_error_exit
extern linnea_string_from_u64

section .rodata

opt_t:          db "-t", 0
env_prefix:     db "LINNEA_UPGRADE="
env_prefix_len  equ $ - env_prefix

msg_fork:       db "cannot fork worker"
msg_fork_len    equ $ - msg_fork
msg_wait:       db "wait4 failed in the master"
msg_wait_len    equ $ - msg_wait
msg_storm:      db "worker died within a second of starting; giving up"
msg_storm_len   equ $ - msg_storm
msg_topology:   db "hot upgrade needs an unchanged listener set; use restart"
msg_topology_len equ $ - msg_topology
msg_fdlimit:    db "file descriptor limit too low for max_connections; raise LimitNOFILE"
msg_fdlimit_len equ $ - msg_fdlimit

log_worker:     db "worker "
log_worker_len  equ $ - log_worker
log_started:    db " started", 10
log_started_len equ $ - log_started
log_died:       db " exited, respawning", 10
log_died_len    equ $ - log_died
log_up_req:     db "binary upgrade requested", 10
log_up_req_len  equ $ - log_up_req
log_up_reject:  db "upgrade rejected: new binary failed the config check", 10
log_up_reject_len equ $ - log_up_reject
log_up_exec:    db "upgrade: re-exec of the new binary", 10
log_up_exec_len equ $ - log_up_exec
log_up_execfail: db "upgrade failed: execve error, continuing with old binary", 10
log_up_execfail_len equ $ - log_up_execfail
log_up_done:    db "binary upgrade complete: new workers up, draining old", 10
log_up_done_len equ $ - log_up_done

section .bss

alignb 8
worker_pids:    resq LINNEA_MAX_WORKERS
worker_spawned: resq LINNEA_MAX_WORKERS  ; CLOCK_MONOTONIC ns at spawn
master_pid:     resq 1
argv0_ptr:      resq 1
config_ptr:     resq 1
upgrade_env:    resq 1                   ; the LINNEA_UPGRADE value, or 0
old_pids:       resq LINNEA_MAX_WORKERS  ; previous generation, to drain
old_pid_count:  resq 1
; QUIC CID-steering handoff (see the bpf section of the upgrade env). The BPF
; map and program are INHERITED across a hot upgrade: the draining workers'
; sockets stay registered in the map, so their connections' packets keep
; steering to them. Each generation stamps and registers under its own half of
; the index space (steer_base 0 or 64) so the two never collide.
steer_base:     resq 1                   ; this generation's steering-index base
adopt_bpf_map:  resq 1                   ; inherited map fd (valid if adopt_bpf_ok)
adopt_bpf_prog: resq 1                   ; inherited program fd
adopt_bpf_ok:   resq 1                   ; 1 = the env carried a bpf section
adopt_fd_table: resd LINNEA_MAX_SERVERS  ; inherited listener fds
wait_status:    resd 1
check_status:   resd 1
sa_buf:         resb 32                  ; struct kernel_sigaction
exec_argv:      resq 4
exec_envp:      resq 2
chk_argv:       resq 4
chk_envp:       resq 2
env_buf:        resb 4096                ; "LINNEA_UPGRADE=fds;pids"
time_scratch:   resq 2
affinity_mask:  resb 128
fd_rlimit:      resq 2         ; struct rlimit64 {cur, max} for RLIMIT_NOFILE

section .text

_start:
    mov r15, [rsp]             ; argc
    mov rax, [rsp + 8]         ; argv[0], stashed for the re-exec
    mov [argv0_ptr], rax
    ; scan the environment for LINNEA_UPGRADE (envp starts past argv+NULL)
    lea rsi, [rsp + 16]
    lea rsi, [rsi + r15 * 8]   ; &envp[0]
    call scan_env
    cmp r15, 2
    jl .usage
    ; config-check mode: `linnea -t <config>` parses and validates only
    mov rsi, [rsp + 16]        ; argv[1]
    cmp byte [rsi], '-'
    jne .normal_args
    cmp byte [rsi + 1], 'b'
    je .bpf_probe
    cmp byte [rsi + 1], 't'
    jne .normal_args
    cmp byte [rsi + 2], 0
    jne .normal_args
    cmp r15, 3
    jl .usage
    mov rax, [rsp + 24]        ; argv[2]
    mov [config_ptr], rax
    jmp check_config
.bpf_probe:                    ; `linnea -b`: verify BPF reuseport steering loads
    cmp byte [rsi + 2], 0
    jne .normal_args
    call linnea_bpf_probe
    mov edi, eax
    neg edi                    ; exit 0 when the probe returned 0
    mov eax, LINNEA_SYS_EXIT
    syscall
.normal_args:
    mov rax, [rsp + 16]        ; argv[1] = config path
    mov [config_ptr], rax

    mov rdi, [config_ptr]
    call linnea_file_map_readonly
    mov r12, rax               ; ptr
    mov r13, rdx               ; size
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [linnea_config_instance]
    call linnea_config_parse
    mov rdi, r12
    mov rsi, r13
    call linnea_file_unmap
    lea rdi, [linnea_config_instance]
    call linnea_config_validate
    call resolve_workers
    call ensure_fd_limit       ; the pool is only real if we have the fds for it
    lea rdi, [linnea_config_instance + linnea_config.log]
    call linnea_log_open
    lea rdi, [linnea_config_instance]
    call linnea_config_dump
    lea rdi, [linnea_config_instance]     ; CPUID gate + cert/key loading
    call linnea_tls_setup

    ; listeners: bind fresh, or adopt the fds inherited across an upgrade
    cmp qword [upgrade_env], 0
    jne .adopt_listeners
    lea rdi, [linnea_config_instance]
    xor esi, esi                          ; bind
    call linnea_network_listen_all
    jmp .listeners_ready
.adopt_listeners:
    call parse_upgrade_env                ; fills adopt_fd_table + old_pids
    lea rdi, [linnea_config_instance]
    lea rsi, [adopt_fd_table]
    call linnea_network_listen_all
.listeners_ready:

    mov eax, LINNEA_SYS_GETPID
    syscall
    mov [master_pid], rax
    call install_sigusr2       ; catch SIGUSR2 to trigger a hot upgrade
    call install_sighup        ; and SIGHUP to reopen the log after a rotate
    ; load the BPF connection-ID steering program before forking so the workers
    ; inherit the map and program fds. Best-effort: without CAP_BPF it fails and
    ; the QUIC reuseport group falls back to plain 4-tuple hashing. Across a hot
    ; upgrade the PREVIOUS generation's map and program are adopted instead of
    ; loaded fresh: attaching a new program would replace the group's steering
    ; wholesale, and the draining workers' connections — whose ids carry THEIR
    ; indices — would steer to our workers, who answer with stateless resets.
    cmp qword [adopt_bpf_ok], 0
    je .bpf_fresh
    mov rax, [adopt_bpf_map]
    mov [linnea_bpf_map_fd], rax
    mov rax, [adopt_bpf_prog]
    mov [linnea_bpf_prog_fd], rax
    jmp .bpf_ready
.bpf_fresh:
    call linnea_bpf_reuseport_setup
.bpf_ready:
    ; derive the stateless-reset key once, here in the master, so every forked
    ; worker inherits the same secret and computes matching reset tokens (RFC 9000 10.3)
    call linnea_quic_reset_secret_init
    call linnea_quic_retry_secret_init

    xor r12d, r12d             ; worker slot
.spawn_loop:
    cmp r12, [linnea_config_instance + linnea_config.workers]
    jae .spawned
    mov rdi, r12
    call spawn_worker          ; only the master returns
    inc r12
    jmp .spawn_loop
.spawned:
    ; an upgrade: the new workers are accepting on the shared sockets, so
    ; now retire the old generation — SIGQUIT makes them drain (M11)
    cmp qword [upgrade_env], 0
    je .supervise
    call kill_old_workers
    call linnea_log_stamp
    lea rdi, [log_up_done]
    mov esi, log_up_done_len
    call linnea_log_write

; --- master: reap dead workers and respawn into their slot -----------
.supervise:
    mov eax, LINNEA_SYS_WAIT4
    mov rdi, -1
    lea rsi, [wait_status]
    xor edx, edx               ; options: block
    xor r10d, r10d             ; rusage: none
    syscall
    cmp rax, -4                ; -EINTR: a signal, maybe SIGUSR2
    je .interrupted
    cmp rax, -4095
    jae .wait_fail
    xor r12d, r12d             ; find the dead pid's slot
.find:
    cmp r12, [linnea_config_instance + linnea_config.workers]
    jae .supervise             ; not a current worker (e.g. a drained old
                               ; one): reaped and ignored
    cmp rax, [worker_pids + r12 * 8]
    je .found
    inc r12
    jmp .find
.found:
    ; a worker that EXITED within a second of spawning hit a startup
    ; error and would exit again at once: give up. A signal death — a
    ; crash, an operator's kill — is respawned whatever its age.
    mov r13, rax               ; dead pid, for the log line
    call monotonic_ns
    sub rax, [worker_spawned + r12 * 8]
    cmp rax, 1000000000
    jae .respawn
    mov eax, [wait_status]
    and eax, 0x7f              ; 0 = exited (WIFEXITED)
    jz .storm
.respawn:
    call linnea_log_stamp
    lea rdi, [log_worker]
    mov esi, log_worker_len
    call linnea_log_write
    mov rdi, r13
    call linnea_log_u64
    lea rdi, [log_died]
    mov esi, log_died_len
    call linnea_log_write
    mov rdi, r12
    call spawn_worker
    jmp .supervise
.interrupted:
    cmp byte [hup_pending], 0
    je .chk_upgrade
    mov byte [hup_pending], 0
    ; a rotation: reopen our own log, then tell the workers to do the same.
    ; They each hold their own descriptor (inherited across the fork), so
    ; every one of them has to reopen or it keeps filling the rotated file.
    call linnea_log_reopen
    call signal_workers_hup
.chk_upgrade:
    cmp byte [upgrade_pending], 0
    je .supervise
    mov byte [upgrade_pending], 0
    call do_upgrade            ; returns only if the upgrade was refused
    jmp .supervise

.usage:
    jmp linnea_error_usage
.wait_fail:
    lea rdi, [msg_wait]
    mov esi, msg_wait_len
    jmp linnea_error_exit
.storm:
    lea rdi, [msg_storm]
    mov esi, msg_storm_len
    jmp linnea_error_exit

; spawn_worker(rdi=slot) — fork one worker into the given slot. Returns
; in the master; the child never returns.
spawn_worker:
    push rbx
    mov rbx, rdi
    call monotonic_ns
    mov [worker_spawned + rbx * 8], rax
    mov eax, LINNEA_SYS_FORK
    syscall
    cmp rax, -4095
    jae .fork_fail
    test rax, rax
    jz .child
    mov [worker_pids + rbx * 8], rax
    mov rbx, rax               ; log "worker <pid> started"
    call linnea_log_stamp
    lea rdi, [log_worker]
    mov esi, log_worker_len
    call linnea_log_write
    mov rdi, rbx
    call linnea_log_u64
    lea rdi, [log_started]
    mov esi, log_started_len
    call linnea_log_write
    pop rbx
    ret
.child:
    ; die when the master does. The prctl is racy against a master that
    ; died between fork and here — the signal is only sent on a death
    ; AFTER the prctl — so re-check the parent afterwards.
    mov eax, LINNEA_SYS_PRCTL
    mov edi, LINNEA_PR_SET_PDEATHSIG
    mov esi, LINNEA_SIGTERM
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    syscall
    mov eax, LINNEA_SYS_GETPPID
    syscall
    cmp rax, [master_pid]
    jne .orphan
    ; the steering index this worker stamps into its connection ids and
    ; registers its QUIC socket under: its slot, offset into this generation's
    ; half of the map so it never collides with a generation still draining
    mov rax, [steer_base]
    add rax, rbx
    mov [linnea_worker_index], rax
    mov rdi, [linnea_config_instance + linnea_config.max_connections]
    call linnea_connections_init
    mov rdi, [linnea_config_instance + linnea_config.max_connections]
    call linnea_h2p_init                  ; proxy-over-h2 upstream slots
    lea rdi, [linnea_config_instance]
    call linnea_uring_run      ; never returns
.orphan:
    mov eax, LINNEA_SYS_EXIT
    xor edi, edi
    syscall
.fork_fail:
    lea rdi, [msg_fork]
    mov esi, msg_fork_len
    jmp linnea_error_exit

; ---- config-check mode (`linnea -t <config>`) -----------------------
; Parse, validate, and load the TLS material, then exit 0. Any fault
; exits non-zero via linnea_error_exit. The upgrading master runs this
; against the NEW binary before committing, so a broken config or a bad
; certificate refuses the upgrade instead of taking the service down.
check_config:
    mov rdi, [config_ptr]
    call linnea_file_map_readonly
    mov r12, rax
    mov r13, rdx
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [linnea_config_instance]
    call linnea_config_parse
    mov rdi, r12
    mov rsi, r13
    call linnea_file_unmap
    lea rdi, [linnea_config_instance]
    call linnea_config_validate
    call resolve_workers
    lea rdi, [linnea_config_instance]
    call linnea_tls_setup
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- do_upgrade — check the new binary, then re-exec in place -------
do_upgrade:
    call linnea_log_stamp
    lea rdi, [log_up_req]
    mov esi, log_up_req_len
    call linnea_log_write
    ; 1. run the new binary in `-t` mode to validate the config
    mov eax, LINNEA_SYS_FORK
    syscall
    cmp rax, -4095
    jae .execfail              ; fork failed: keep serving
    test rax, rax
    jz .check_child
    mov r12, rax               ; check pid
.check_wait:
    mov eax, LINNEA_SYS_WAIT4
    mov rdi, r12
    lea rsi, [check_status]
    xor edx, edx
    xor r10d, r10d
    syscall
    cmp rax, -4
    je .check_wait
    mov eax, [check_status]
    test eax, 0x7f             ; signalled -> not a clean exit
    jnz .reject
    shr eax, 8
    and eax, 0xff
    test eax, eax
    jnz .reject                ; non-zero exit: config rejected
    ; 2. build the handoff environment and re-exec argv[0] in place.
    ; bpf(2) fds are born close-on-exec (sockets are not): clear the flag so
    ; the steering map and program survive into the next generation.
    cmp qword [linnea_bpf_prog_fd], 0
    jl .no_bpf_fds
    mov rdi, [linnea_bpf_map_fd]
    call clear_cloexec
    mov rdi, [linnea_bpf_prog_fd]
    call clear_cloexec
.no_bpf_fds:
    call build_upgrade_env
    mov rax, [argv0_ptr]
    mov [exec_argv], rax
    mov rax, [config_ptr]
    mov [exec_argv + 8], rax
    mov qword [exec_argv + 16], 0
    lea rax, [env_buf]
    mov [exec_envp], rax
    mov qword [exec_envp + 8], 0
    call linnea_log_stamp
    lea rdi, [log_up_exec]
    mov esi, log_up_exec_len
    call linnea_log_write
    mov eax, LINNEA_SYS_EXECVE
    mov rdi, [argv0_ptr]
    lea rsi, [exec_argv]
    lea rdx, [exec_envp]
    syscall
    ; execve returned: it failed. We are still the old master with old
    ; workers, so log and resume serving.
.execfail:
    call linnea_log_stamp
    lea rdi, [log_up_execfail]
    mov esi, log_up_execfail_len
    call linnea_log_write
    ret
.reject:
    call linnea_log_stamp
    lea rdi, [log_up_reject]
    mov esi, log_up_reject_len
    call linnea_log_write
    ret
.check_child:
    mov rax, [argv0_ptr]
    mov [chk_argv], rax
    lea rax, [opt_t]
    mov [chk_argv + 8], rax
    mov rax, [config_ptr]
    mov [chk_argv + 16], rax
    mov qword [chk_argv + 24], 0
    mov qword [chk_envp], 0    ; a clean env: `-t` reads none
    mov eax, LINNEA_SYS_EXECVE
    mov rdi, [argv0_ptr]
    lea rsi, [chk_argv]
    lea rdx, [chk_envp]
    syscall
    mov edi, 1                 ; execve of the check failed
    mov eax, LINNEA_SYS_EXIT
    syscall

; build_upgrade_env — write "LINNEA_UPGRADE=fd0:fd1:...;pid0:pid1:..."
; into env_buf: one fd per server (in order), then the current worker
; pids. rbx = write cursor across the number formatting.
build_upgrade_env:
    push rbx
    push r12
    lea rbx, [env_buf]
    lea rsi, [env_prefix]      ; copy the prefix
    mov ecx, env_prefix_len
.copy_pfx:
    mov al, [rsi]
    mov [rbx], al
    inc rsi
    inc rbx
    dec ecx
    jnz .copy_pfx
    xor r12d, r12d
.fd_loop:
    cmp r12, [linnea_config_instance + linnea_config.server_count]
    jae .fds_done
    imul rax, r12, linnea_config_server_size
    lea rax, [linnea_config_instance + rax + linnea_config.servers]
    mov edi, [rax + linnea_config_server.listen_fd]
    mov rsi, rbx
    call linnea_string_from_u64
    add rbx, rax
    inc r12
    cmp r12, [linnea_config_instance + linnea_config.server_count]
    jae .fds_done
    mov byte [rbx], ':'
    inc rbx
    jmp .fd_loop
.fds_done:
    mov byte [rbx], ';'
    inc rbx
    xor r12d, r12d
.pid_loop:
    cmp r12, [linnea_config_instance + linnea_config.workers]
    jae .pids_done
    mov rdi, [worker_pids + r12 * 8]
    mov rsi, rbx
    call linnea_string_from_u64
    add rbx, rax
    inc r12
    cmp r12, [linnea_config_instance + linnea_config.workers]
    jae .pids_done
    mov byte [rbx], ':'
    inc rbx
    jmp .pid_loop
.pids_done:
    ; the steering handoff: the map and program fds (kept open across execve)
    ; and the base half of the index space this generation stamped, so the next
    ; one takes the other half. Omitted when the steering never loaded — the
    ; next generation then tries a fresh load, exactly like a cold start.
    cmp qword [linnea_bpf_prog_fd], 0
    jl .env_done
    mov byte [rbx], ';'
    inc rbx
    mov rdi, [linnea_bpf_map_fd]
    mov rsi, rbx
    call linnea_string_from_u64
    add rbx, rax
    mov byte [rbx], ':'
    inc rbx
    mov rdi, [linnea_bpf_prog_fd]
    mov rsi, rbx
    call linnea_string_from_u64
    add rbx, rax
    mov byte [rbx], ':'
    inc rbx
    mov rdi, [steer_base]
    mov rsi, rbx
    call linnea_string_from_u64
    add rbx, rax
.env_done:
    mov byte [rbx], 0
    pop r12
    pop rbx
    ret

; parse_upgrade_env — decode the LINNEA_UPGRADE value into adopt_fd_table
; (one fd per server) and old_pids. Exits if the fd count does not match
; the config's server count (a changed listener set cannot be adopted).
parse_upgrade_env:
    push rbx
    mov rsi, [upgrade_env]
    xor r12d, r12d             ; fd index
.fd_loop:
    ; the value comes from the environment, so bound the write: more entries
    ; than there are listener slots would walk straight past the table. A short
    ; count then fails the server_count check below and refuses the upgrade.
    cmp r12, LINNEA_MAX_SERVERS
    jae .topology
    call parse_dec             ; rax = value, rsi advanced
    mov [adopt_fd_table + r12 * 4], eax
    inc r12
    cmp byte [rsi], ':'
    jne .fds_done
    inc rsi
    jmp .fd_loop
.fds_done:
    cmp byte [rsi], ';'
    jne .topology
    inc rsi
    cmp r12, [linnea_config_instance + linnea_config.server_count]
    jne .topology
    xor r12d, r12d             ; pid index
.pid_loop:
    cmp byte [rsi], 0
    je .pids_done
    cmp r12, LINNEA_MAX_WORKERS        ; likewise bounded: environment input
    jae .pids_done
    call parse_dec
    mov [old_pids + r12 * 8], rax
    inc r12
    cmp byte [rsi], ':'
    jne .pids_done
    inc rsi
    jmp .pid_loop
.pids_done:
    mov [old_pid_count], r12
    ; the optional steering handoff: "…;map:prog:base". Malformed or absent
    ; means no adoption — a fresh load, which is always safe, just not seamless.
    cmp byte [rsi], ';'
    jne .no_bpf
    inc rsi
    call parse_dec             ; the previous generation's map fd
    mov [adopt_bpf_map], rax
    cmp byte [rsi], ':'
    jne .no_bpf
    inc rsi
    call parse_dec             ; its program fd
    mov [adopt_bpf_prog], rax
    cmp byte [rsi], ':'
    jne .no_bpf
    inc rsi
    call parse_dec             ; the half of the index space it stamped
    xor rax, 64                ; take the other half…
    and rax, 64                ; …and force a sane base whatever the env held
    cmp qword [linnea_config_instance + linnea_config.workers], 64
    jbe .base_ok
    xor eax, eax               ; more workers than half the map holds: share
                               ; base 0 (colliding, the pre-Q118 behaviour)
.base_ok:
    mov [steer_base], rax
    mov qword [adopt_bpf_ok], 1
.no_bpf:
    pop rbx
    ret
.topology:
    lea rdi, [msg_topology]
    mov esi, msg_topology_len
    jmp linnea_error_exit

; clear_cloexec(rdi = fd) — drop FD_CLOEXEC so the fd survives an execve.
clear_cloexec:
    mov eax, LINNEA_SYS_FCNTL
    mov esi, LINNEA_F_SETFD
    xor edx, edx               ; flags = 0: no FD_CLOEXEC
    syscall
    ret

; parse_dec(rsi=ptr) -> rax = decimal value, rsi advanced past the digits
parse_dec:
    xor eax, eax
.d:
    movzx ecx, byte [rsi]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul rax, rax, 10
    add rax, rcx
    inc rsi
    jmp .d
.done:
    ret

; kill_old_workers — retire the previous generation with SIGQUIT, the
; patient drain: the new workers are already serving on the same listeners,
; so an old worker holding an idle keep-alive connection costs nothing and
; the client keeps its connection until it is done with it. A stop (SIGTERM)
; is the impatient one, because then nobody is left to serve.
kill_old_workers:
    push rbx
    xor ebx, ebx
.loop:
    cmp rbx, [old_pid_count]
    jae .done
    mov eax, LINNEA_SYS_KILL
    mov rdi, [old_pids + rbx * 8]
    mov esi, LINNEA_SIGQUIT
    syscall
    inc rbx
    jmp .loop
.done:
    pop rbx
    ret

; install_sigusr2 — catch SIGUSR2 with a handler that only flags a
; pending upgrade; the master acts on it when wait4 returns EINTR.
install_sigusr2:
    lea rax, [sigusr2_handler]
    mov [sa_buf], rax
    mov qword [sa_buf + 8], LINNEA_SA_RESTORER
    lea rax, [sig_restorer]
    mov [sa_buf + 16], rax
    mov qword [sa_buf + 24], 0
    mov eax, LINNEA_SYS_RT_SIGACTION
    mov edi, LINNEA_SIGUSR2
    lea rsi, [sa_buf]
    xor edx, edx               ; no oldact
    mov r10d, 8                ; sigsetsize
    syscall
    ret

; install_sighup — catch SIGHUP the same way: the handler only flags, and
; the supervision loop does the work when wait4 returns -EINTR.
install_sighup:
    lea rax, [sighup_handler]
    mov [sa_buf], rax
    mov qword [sa_buf + 8], LINNEA_SA_RESTORER
    lea rax, [sig_restorer]
    mov [sa_buf + 16], rax
    mov qword [sa_buf + 24], 0
    mov eax, LINNEA_SYS_RT_SIGACTION
    mov edi, LINNEA_SIGHUP
    lea rsi, [sa_buf]
    xor edx, edx
    mov r10d, 8
    syscall
    ret

; signal_workers_hup — SIGHUP every live worker so it reopens its log.
signal_workers_hup:
    push rbx
    xor ebx, ebx
.sw_loop:
    cmp rbx, [linnea_config_instance + linnea_config.workers]
    jae .sw_done
    mov rdi, [worker_pids + rbx * 8]
    test rdi, rdi
    jz .sw_next
    mov esi, LINNEA_SIGHUP
    mov eax, LINNEA_SYS_KILL
    syscall
.sw_next:
    inc rbx
    jmp .sw_loop
.sw_done:
    pop rbx
    ret

; The handlers and their restorer. Async-signal-safe: only a byte store.
sigusr2_handler:
    mov byte [upgrade_pending], 1
    ret
sighup_handler:
    mov byte [hup_pending], 1
    ret
sig_restorer:
    mov eax, LINNEA_SYS_RT_SIGRETURN
    syscall

; scan_env(rsi=&envp[0]) — set upgrade_env to the value after
; "LINNEA_UPGRADE=", or 0 if the variable is absent.
scan_env:
    mov qword [upgrade_env], 0
.loop:
    mov rax, [rsi]
    test rax, rax
    jz .done
    push rsi
    mov rdi, rax
    lea rsi, [env_prefix]
    mov ecx, env_prefix_len
    call prefix_eq
    pop rsi
    test eax, eax
    jnz .found
    add rsi, 8
    jmp .loop
.found:
    mov rax, [rsi]
    add rax, env_prefix_len
    mov [upgrade_env], rax
.done:
    ret

; prefix_eq(rdi=str, rsi=prefix, ecx=len) -> eax = 1 if str starts with it
prefix_eq:
    xor eax, eax
.c:
    test ecx, ecx
    jz .yes
    mov dl, [rdi]
    cmp dl, [rsi]
    jne .no
    inc rdi
    inc rsi
    dec ecx
    jmp .c
.yes:
    mov eax, 1
.no:
    ret

; resolve_workers — turn config.workers = 0 (auto) into the online CPU
; count: the popcount of the sched_getaffinity mask, clamped to
; [1, LINNEA_MAX_WORKERS]. An explicit value passes through untouched.
resolve_workers:
    mov rax, [linnea_config_instance + linnea_config.workers]
    test rax, rax
    jnz .done
    mov eax, LINNEA_SYS_SCHED_GETAFFINITY
    xor edi, edi
    mov esi, 128
    lea rdx, [affinity_mask]
    syscall
    cmp rax, -4095
    jae .one
    xor ecx, ecx
    xor edi, edi
.count:
    cmp ecx, 16
    jae .counted
    popcnt rax, qword [affinity_mask + rcx * 8]
    add rdi, rax
    inc ecx
    jmp .count
.counted:
    mov rax, rdi
    test rax, rax
    jz .one
    cmp rax, LINNEA_MAX_WORKERS
    jbe .store
    mov eax, LINNEA_MAX_WORKERS
    jmp .store
.one:
    mov eax, 1
.store:
    mov [linnea_config_instance + linnea_config.workers], rax
.done:
    ret

; ensure_fd_limit() — make RLIMIT_NOFILE big enough for the configured pool,
; or refuse to start.
;
; Every connection is a descriptor, and a proxied one is two, so a worker
; whose soft limit is below its own max_connections can never fill its pool:
; accept(2) starts failing with EMFILE while the server still believes it has
; room, and the graceful pool-full path never runs. The default soft limit
; (1024) is exactly the default max_connections, so the stock configuration
; hits this. A process may raise its own soft limit up to the hard limit
; without privilege, so do that here rather than making it the operator's
; problem; only a hard limit that is genuinely too low is fatal. Runs in the
; master, before the fork, so every worker inherits the raised limit.
ensure_fd_limit:
    push rbx
    ; what one worker can have open at once, plus room for the listeners, the
    ; log, the ring, the signalfd and the BPF fds
    mov rbx, [linnea_config_instance + linnea_config.max_connections]
    add rbx, [linnea_config_instance + linnea_config.max_upstream]
    mov rax, [linnea_config_instance + linnea_config.server_count]
    lea rbx, [rbx + rax * 2]   ; a TCP and a UDP listener per server
    add rbx, 32                ; slack for the fixed descriptors
    ; read the current limit
    xor edi, edi               ; pid 0 = us
    mov esi, LINNEA_RLIMIT_NOFILE
    xor edx, edx               ; no new limit: just read
    lea r10, [fd_rlimit]
    mov eax, LINNEA_SYS_PRLIMIT64
    syscall
    cmp rax, -4095
    jae .done                  ; cannot read it: leave the limit alone
    cmp [fd_rlimit], rbx       ; soft limit already sufficient?
    jae .done
    cmp [fd_rlimit + 8], rbx   ; hard limit is the ceiling we may raise to
    jb .too_low
    mov [fd_rlimit], rbx       ; raise the soft limit, keep the hard one
    xor edi, edi
    mov esi, LINNEA_RLIMIT_NOFILE
    lea rdx, [fd_rlimit]
    xor r10d, r10d
    mov eax, LINNEA_SYS_PRLIMIT64
    syscall
    cmp rax, -4095
    jae .too_low               ; refused: the pool would silently not fit
.done:
    pop rbx
    ret
.too_low:
    lea rdi, [msg_fdlimit]
    mov esi, msg_fdlimit_len
    jmp linnea_error_exit

; monotonic_ns() -> rax = CLOCK_MONOTONIC now, as nanoseconds.
monotonic_ns:
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    mov edi, LINNEA_CLOCK_MONOTONIC
    lea rsi, [time_scratch]
    syscall
    mov rax, [time_scratch]
    imul rax, rax, 1000000000
    add rax, [time_scratch + 8]
    ret

section .bss
alignb 8
upgrade_pending: resb 1
hup_pending:    resb 1
