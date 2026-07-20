; linnea_start.asm — entry point and top-level orchestration:
; map config file -> parse -> unmap -> validate -> dump -> load TLS
; material -> bind listeners -> fork workers -> supervise.
;
; Multi-process model: the master parses the config, loads certs and
; keys, and binds every listener exactly once, then forks
; config.workers workers ("workers" in the config; the default is one
; per online CPU). Each worker inherits the listening fds and runs the
; whole event loop — its own io_uring, its own connection pool, its own
; multishot accepts on the shared sockets; the kernel completes each
; incoming connection on exactly one worker's accept. The master serves
; no traffic: it sits in wait4 and respawns any worker that dies.
;
; Shutdown needs no signal handlers: every worker carries
; PR_SET_PDEATHSIG(SIGTERM), so however the master goes — SIGTERM,
; SIGINT, SIGKILL, a crash — the workers are killed with it.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global _start

extern linnea_file_map_readonly
extern linnea_file_unmap
extern linnea_config_parse
extern linnea_config_validate
extern linnea_config_dump
extern linnea_config_instance
extern linnea_tls_setup
extern linnea_log_open
extern linnea_log_stamp
extern linnea_log_write
extern linnea_log_u64
extern linnea_network_listen_all
extern linnea_connections_init
extern linnea_uring_run
extern linnea_error_usage
extern linnea_error_exit

section .rodata

msg_fork:       db "cannot fork worker"
msg_fork_len    equ $ - msg_fork
msg_wait:       db "wait4 failed in the master"
msg_wait_len    equ $ - msg_wait
msg_storm:      db "worker died within a second of starting; giving up"
msg_storm_len   equ $ - msg_storm

log_worker:     db "worker "
log_worker_len  equ $ - log_worker
log_started:    db " started", 10
log_started_len equ $ - log_started
log_died:       db " exited, respawning", 10
log_died_len    equ $ - log_died

section .bss

alignb 8
worker_pids:    resq LINNEA_MAX_WORKERS
worker_spawned: resq LINNEA_MAX_WORKERS  ; CLOCK_MONOTONIC ns at spawn
master_pid:     resq 1
wait_status:    resd 1
pad:            resd 1
time_scratch:   resq 2                   ; struct timespec
affinity_mask:  resb 128                 ; cpu_set_t, up to 1024 CPUs

section .text

_start:
    mov rax, [rsp]             ; argc
    cmp rax, 2
    jl .usage
    mov rdi, [rsp + 16]        ; argv[1] = config path
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
    lea rdi, [linnea_config_instance + linnea_config.log]
    call linnea_log_open
    lea rdi, [linnea_config_instance]
    call linnea_config_dump
    lea rdi, [linnea_config_instance]     ; CPUID gate + cert/key loading
    call linnea_tls_setup
    lea rdi, [linnea_config_instance]     ; the master binds every listener
    call linnea_network_listen_all        ; once; workers inherit the fds

    mov eax, LINNEA_SYS_GETPID
    syscall
    mov [master_pid], rax

    xor r12d, r12d             ; worker slot
.spawn_loop:
    cmp r12, [linnea_config_instance + linnea_config.workers]
    jae .supervise
    mov rdi, r12
    call spawn_worker          ; only the master returns
    inc r12
    jmp .spawn_loop

; --- master: reap dead workers and respawn into their slot -----------
.supervise:
    mov eax, LINNEA_SYS_WAIT4
    mov rdi, -1
    lea rsi, [wait_status]
    xor edx, edx               ; options: block
    xor r10d, r10d             ; rusage: none
    syscall
    cmp rax, -4                ; -EINTR: wait again
    je .supervise
    cmp rax, -4095
    jae .wait_fail
    xor r12d, r12d             ; find the dead pid's slot
.find:
    cmp r12, [linnea_config_instance + linnea_config.workers]
    jae .supervise             ; not one of ours: ignore
    cmp rax, [worker_pids + r12 * 8]
    je .found
    inc r12
    jmp .find
.found:
    ; a worker that EXITED within a second of spawning hit a startup
    ; error (a bad bind, a broken environment) and would exit again at
    ; once: give up and take the server down instead of forking forever.
    ; PDEATHSIG stops the other workers. A signal death — a crash, an
    ; operator's kill — is respawned whatever its age.
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
    mov rdi, [linnea_config_instance + linnea_config.max_connections]
    call linnea_connections_init
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

; resolve_workers — turn config.workers = 0 (auto) into the number of
; CPUs this process may run on: the popcount of the sched_getaffinity
; mask, clamped to [1, LINNEA_MAX_WORKERS]. An explicit config value was
; already range-checked by the parser and passes through untouched.
resolve_workers:
    mov rax, [linnea_config_instance + linnea_config.workers]
    test rax, rax
    jnz .done
    mov eax, LINNEA_SYS_SCHED_GETAFFINITY
    xor edi, edi               ; pid 0 = self
    mov esi, 128
    lea rdx, [affinity_mask]
    syscall
    cmp rax, -4095
    jae .one
    ; the kernel wrote rax bytes; the rest of the .bss buffer is zero
    xor ecx, ecx
    xor edi, edi               ; CPU count
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
