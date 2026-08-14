; linnea_crash.asm — turn a fatal memory fault into a line an operator can read.
;
; A worker that segfaults used to leave the master's "exited on signal 11" and
; nothing else: which signal, and not one word about where. That is better than
; the bare "exited, respawning" it replaced, but it still does not name a
; function, and on this unit there is no second chance to find out —
; AmbientCapabilities clears the dumpable flag, so a prod worker cannot leave a
; core whatever LimitCORE and fs.suid_dumpable say. Seven segfaults on
; 2026-08-14 produced no dump at all, and none of them reproduced on loopback.
;
; So the faulting process reports its own position before it dies:
;
;   fatal: SIGSEGV addr=0x0000000000000000 rip=0x0000000000407a31 rsp=0x...
;
; `addr` is what was touched, `rip` is the instruction that touched it. Feed rip
; to `addr2line -e bin/linnea` or find it in `objdump -d` and the fault has a
; function name — which is the whole difference between "a worker died" and a
; defect you can go and read. Compare rip against the SAME build: the binary is
; built with -g -F dwarf, so a rebuilt tree moves every address.
;
; Deliberately NOT a core dump. A core would carry the TLS session keys and
; anything else in the worker's memory; three integers carry none of it, and
; need no change to the unit's hardening.
;
; SA_RESETHAND puts the default disposition back before the handler runs, and
; the handler then re-raises the same signal at itself, so the process dies of
; SIGSEGV exactly as it did before -- the master still logs "exited on signal
; 11" and still respawns. This only ADDS a line; it changes no outcome, which
; is the property that makes it safe to leave switched on in production.
;
; Limit worth knowing: a fault caused by exhausting the stack cannot be reported
; this way -- the handler needs stack to run on, and there is none. That would
; want SA_ONSTACK and a sigaltstack, which is not here because nothing observed
; so far looks like unbounded recursion.

default rel

%include "linnea_syscall.inc"

global linnea_crash_install

extern linnea_log_error_fd

; Signal numbers and rt_sigreturn are kept local rather than added to
; linnea_syscall.inc: that header is a prerequisite of every object, so a line
; there rebuilds all four products and moves every hash for no emitted change.
SIG_SEGV        equ 11
SIG_BUS         equ 7
SYS_RT_SIGRETURN equ 15

SA_SIGINFO      equ 0x00000004
SA_RESTORER     equ 0x04000000
SA_RESETHAND    equ 0x80000000

; x86-64 layouts, fixed by the ABI:
;   siginfo_t.si_addr            offset 16
;   ucontext_t.uc_mcontext       offset 40, gregs[] from there
;   gregs[REG_RSP] = 15, gregs[REG_RIP] = 16
SI_ADDR_OFF     equ 16
UC_RSP_OFF      equ 40 + 15*8
UC_RIP_OFF      equ 40 + 16*8

section .rodata

m_segv:     db "fatal: SIGSEGV"
m_segv_len  equ $ - m_segv
m_bus:      db "fatal: SIGBUS"
m_bus_len   equ $ - m_bus
m_addr:     db " addr=0x"
m_addr_len  equ $ - m_addr
m_rip:      db " rip=0x"
m_rip_len   equ $ - m_rip
m_rsp:      db " rsp=0x"
m_rsp_len   equ $ - m_rsp
hexdig:     db "0123456789abcdef"

section .data

align 8
; struct kernel_sigaction: handler, flags, restorer, mask. The pointers are
; filled in at install time -- this is position-independent code, so they
; cannot be relocations in .data.
sa_act:     dq 0
            dq SA_SIGINFO | SA_RESTORER | SA_RESETHAND
            dq 0
            dq 0

section .bss

; One line, one process. The fault is fatal and the handler runs once, so a
; shared buffer needs neither locking nor allocation -- and allocation is not
; available to a signal handler anyway.
crashbuf:   resb 192

section .text

; linnea_crash_install() — report a memory fault before dying. Called once per
; worker, after the log is open so the line has somewhere to go.
linnea_crash_install:
    lea rax, [crash_handler]
    mov [sa_act], rax
    lea rax, [crash_restorer]
    mov [sa_act + 16], rax
    mov edi, SIG_SEGV
    call install_one
    mov edi, SIG_BUS
    call install_one
    ret

install_one:
    mov eax, LINNEA_SYS_RT_SIGACTION
    lea rsi, [sa_act]
    xor edx, edx                    ; no old action wanted
    mov r10d, 8                     ; sizeof(sigset_t)
    syscall
    ret

; The kernel needs a restorer on x86-64; without SA_RESTORER and this stub the
; return from a handler goes nowhere.
crash_restorer:
    mov eax, SYS_RT_SIGRETURN
    syscall

; crash_handler(rdi = signo, rsi = siginfo*, rdx = ucontext*)
; Async-signal-safe by construction: it formats into a static buffer and makes
; one write(2). It calls nothing that takes a lock and nothing that allocates.
crash_handler:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rsi                    ; siginfo
    mov r13, rdx                    ; ucontext
    mov r14, rdi                    ; signo
    lea rbx, [crashbuf]             ; the write cursor

    cmp r14d, SIG_BUS
    je .bus
    lea rsi, [m_segv]
    mov ecx, m_segv_len
    jmp .named
.bus:
    lea rsi, [m_bus]
    mov ecx, m_bus_len
.named:
    call cb_copy

    lea rsi, [m_addr]
    mov ecx, m_addr_len
    call cb_copy
    mov rax, [r12 + SI_ADDR_OFF]
    call cb_hex

    lea rsi, [m_rip]
    mov ecx, m_rip_len
    call cb_copy
    mov rax, [r13 + UC_RIP_OFF]
    call cb_hex

    lea rsi, [m_rsp]
    mov ecx, m_rsp_len
    call cb_copy
    mov rax, [r13 + UC_RSP_OFF]
    call cb_hex

    mov byte [rbx], 10
    inc rbx

    ; Straight to the descriptor, NOT through linnea_log_write: that buffers a
    ; line and this handler may well have interrupted it mid-build.
    call linnea_log_error_fd        ; -> eax = the error stream's fd
    mov edi, eax
    lea rsi, [crashbuf]
    mov rdx, rbx
    sub rdx, rsi
    mov eax, LINNEA_SYS_WRITE
    syscall

    ; Die, deterministically. Returning would re-execute the faulting
    ; instruction and fault again -- correct for a REAL fault, but a signal
    ; that was DELIVERED rather than faulted (kill -11, and every test that
    ; uses it) has no instruction to repeat, so the worker would sail on and
    ; the handler would have changed behaviour rather than only observed it.
    ; SA_RESETHAND has already put the default disposition back, so this is
    ; terminal either way and the master still logs "exited on signal 11".
    mov eax, LINNEA_SYS_GETPID
    syscall
    mov edi, eax
    mov esi, r14d                   ; the same signal we caught
    mov eax, LINNEA_SYS_KILL
    syscall
    pop r14
    pop r13
    pop r12
    pop rbx
    ret                             ; not reached

; cb_copy(rsi = src, ecx = len) — append to [rbx], advancing it.
cb_copy:
    test ecx, ecx
    jz .done
.next:
    mov al, [rsi]
    mov [rbx], al
    inc rsi
    inc rbx
    dec ecx
    jnz .next
.done:
    ret

; cb_hex(rax = value) — sixteen hex digits, most significant first.
cb_hex:
    push r8
    lea r8, [hexdig]
    mov ecx, 16
.next:
    rol rax, 4                      ; bring the next nibble down; sixteen
    mov edx, eax                    ; rotations leave rax as it started
    and edx, 15
    mov dl, [r8 + rdx]
    mov [rbx], dl
    inc rbx
    dec ecx
    jnz .next
    pop r8
    ret
