; linnea_ratelimit.asm — a token bucket per source address, per worker.
;
; max_per_ip bounds how many CONNECTIONS one address may hold. That is a memory
; control, and on a multiplexed protocol it is a weak request control: h2 and h3
; each allow 100 concurrent streams, so the default 64 connections is 6400
; requests in flight from one address, all of them perfectly well formed. This
; bounds the request RATE instead.
;
; Keyed exactly the way linnea_connection_count_ip keys its cap — IPv4 in full,
; native IPv6 on the /64 prefix, mapped and loopback addresses in full — because
; two limits that disagree about what "one client" is are worse than one limit.
;
; Per WORKER, like every other pool here. A client whose connections land on
; several workers is metered by each of them separately, so the effective
; ceiling is rate x workers; docs/config.md says so rather than implying a
; global number this server has no shared state to enforce.
;
; The table is open-addressed with a short probe and no deletion: an address
; that stops asking simply ages out when its slot is wanted by someone else,
; and the victim is always the least recently seen of the probed slots. A miss
; therefore costs a full bucket, never a refusal — the failure direction is
; "allowed something we might have metered", never "refused someone we have
; never seen".

default rel

%include "linnea_ratelimit.inc"
%include "linnea_syscall.inc"

global linnea_ratelimit_init
global linnea_ratelimit_take
global linnea_ratelimit_take_sa
global linnea_ratelimit_on

section .bss
; The configured rate, exported so a caller can skip the whole call when the
; limiter is off — which is every deployment that has not asked for it.
linnea_ratelimit_on:
rl_rate:    resq 1                 ; requests per second; 0 = disabled
rl_cap:     resq 1                 ; bucket ceiling, in milli-tokens
rl_tab:     resb LINNEA_RL_SLOTS * linnea_rl_entry_size

section .text

; linnea_ratelimit_init(rdi = requests per second, 0 = off)
; The bucket holds one second of allowance, so a client that has been quiet may
; spend a whole second's worth at once and is then held to the rate. Tokens are
; milli-tokens throughout: the refill is elapsed_ms * rate, which for the
; largest elapsed we ever multiply (999) and the largest rate (1000000) is
; ~1e9 — nowhere near a 64-bit overflow.
linnea_ratelimit_init:
    mov [rl_rate], rdi
    imul rdi, rdi, 1000
    mov [rl_cap], rdi
    ; every slot free
    lea rdi, [rl_tab]
    xor eax, eax
    mov ecx, LINNEA_RL_SLOTS * linnea_rl_entry_size
    rep stosb
    ret

; linnea_ratelimit_take_sa(rdi = sockaddr, rdx = now in nanoseconds)
;   -> rax = 0 allow, 1 refuse.
; For a caller that holds the peer's sockaddr rather than the extracted bytes —
; the QUIC side, whose connections never had a socket to ask. Extracts exactly
; what linnea_network_peer_addr extracts, so one client keys to ONE bucket
; whichever protocol it arrives over. Two extractions that disagree would meter
; the same address twice over, which is the sort of thing nobody notices until
; the limit is mysteriously double.
linnea_ratelimit_take_sa:
    sub rsp, 24
    movzx eax, word [rdi]
    cmp eax, LINNEA_AF_INET6
    je .sa_v6
    mov eax, [rdi + 4]              ; sockaddr_in: 4 address bytes
    mov [rsp], eax
    mov esi, 4
    jmp .sa_go
.sa_v6:
    mov rax, [rdi + 8]              ; sockaddr_in6: 16 address bytes
    mov [rsp], rax
    mov rax, [rdi + 16]
    mov [rsp + 8], rax
    mov esi, 16
.sa_go:
    mov rdi, rsp
    call linnea_ratelimit_take
    add rsp, 24
    ret

; linnea_ratelimit_take(rdi = address bytes, rsi = address length,
;                       rdx = now, in nanoseconds from any monotonic clock)
;   -> rax = 0 to allow the request, 1 to refuse it.
; Clobbers caller-saved registers only.
linnea_ratelimit_take:
    cmp qword [rl_rate], 0
    jne .rl_on
    xor eax, eax                   ; disabled: allow, and touch nothing
    ret
.rl_on:
    test rsi, rsi
    jz .rl_allow                   ; address unreadable: nothing to meter
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                   ; address
    mov r13, rsi                   ; its length
    ; now, in milliseconds. The clock only has to be monotonic and shared
    ; between calls; the limiter never compares it to a wall clock.
    mov rax, rdx
    xor edx, edx
    mov rcx, 1000000
    div rcx
    mov r14, rax                   ; now_ms

    ; --- the key: the same bytes max_per_ip compares -------------------
    ; first 8 bytes always; the second 8 only for an address whose /64 prefix
    ; is zero, which is a mapped IPv4 or loopback and must not share a bucket
    ; with every other address in ::/64.
    mov rbx, [r12]                 ; key hi
    xor r15d, r15d                 ; key lo
    cmp r13, 8
    jbe .rl_keyed
    test rbx, rbx
    jnz .rl_keyed
    mov r15, [r12 + 8]
.rl_keyed:
    ; --- hash: multiply-shift, then a short linear probe ----------------
    mov rax, rbx
    xor rax, r15
    mov rcx, 0x9E3779B97F4A7C15
    imul rax, rcx
    shr rax, 64 - LINNEA_RL_SHIFT  ; the top bits are the best mixed
    and rax, LINNEA_RL_SLOTS - 1
    mov rdi, rax                   ; slot index
    xor esi, esi                   ; probes taken
    mov r8, -1                     ; victim slot, if we must evict
    mov r9, -1                     ; ...and its last-seen stamp
.rl_probe:
    mov rax, rdi
    imul rax, rax, linnea_rl_entry_size
    lea rcx, [rl_tab + rax]        ; the entry
    cmp qword [rcx + linnea_rl_entry.klen], 0
    je .rl_claim                   ; free slot: it is ours
    cmp [rcx + linnea_rl_entry.klen], r13
    jne .rl_next
    cmp [rcx + linnea_rl_entry.key_hi], rbx
    jne .rl_next
    cmp [rcx + linnea_rl_entry.key_lo], r15
    je .rl_found
.rl_next:
    ; remember the least recently seen of the probed slots, in case none match
    mov rax, [rcx + linnea_rl_entry.last]
    cmp r9, -1
    je .rl_victim
    cmp rax, r9
    jae .rl_after_victim
.rl_victim:
    mov r9, rax
    mov r8, rdi
.rl_after_victim:
    inc rdi
    and rdi, LINNEA_RL_SLOTS - 1
    inc esi
    cmp esi, LINNEA_RL_PROBES
    jb .rl_probe
    ; every probed slot belongs to someone else: take the oldest
    mov rdi, r8
.rl_claim:
    mov rax, rdi
    imul rax, rax, linnea_rl_entry_size
    lea rcx, [rl_tab + rax]
    mov [rcx + linnea_rl_entry.key_hi], rbx
    mov [rcx + linnea_rl_entry.key_lo], r15
    mov [rcx + linnea_rl_entry.klen], r13
    mov rax, [rl_cap]
    mov [rcx + linnea_rl_entry.tokens], rax   ; a client we have not seen
    mov [rcx + linnea_rl_entry.last], r14     ; starts with a full bucket
    jmp .rl_spend
.rl_found:
    ; --- refill by the time since we last saw it ------------------------
    mov rax, r14
    sub rax, [rcx + linnea_rl_entry.last]
    jbe .rl_spend                  ; same millisecond, or a clock that went
                                   ; backwards: no refill, never a penalty
    mov [rcx + linnea_rl_entry.last], r14
    cmp rax, 1000
    jae .rl_full                   ; a whole second idle refills it by
                                   ; definition, and skips the multiply
    imul rax, [rl_rate]            ; elapsed_ms * rate = milli-tokens
    add rax, [rcx + linnea_rl_entry.tokens]
    cmp rax, [rl_cap]
    jbe .rl_store
.rl_full:
    mov rax, [rl_cap]
.rl_store:
    mov [rcx + linnea_rl_entry.tokens], rax
.rl_spend:
    mov rax, [rcx + linnea_rl_entry.tokens]
    cmp rax, 1000
    jb .rl_refuse                  ; less than one whole token left
    sub rax, 1000
    mov [rcx + linnea_rl_entry.tokens], rax
    xor eax, eax
    jmp .rl_ret
.rl_refuse:
    mov eax, 1
.rl_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.rl_allow:
    xor eax, eax
    ret
