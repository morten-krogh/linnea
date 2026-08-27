; linnea_quic_conn.asm — the QUIC connection pool. Slots are demultiplexed by
; the connection ID we issued: its first two bytes hold the pool index, so an
; incoming packet is routed with an index read and one 8-byte compare, without
; a hash map. The remaining six bytes are random, so an ID cannot be guessed
; and a stale or spoofed one fails the compare.

default rel

%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"

global linnea_quic_conn_lookup
global linnea_quic_conn_lookup_odcid
global linnea_quic_conn_alloc
global linnea_quic_conn_free
global linnea_quic_conn_sweep
global linnea_quic_conn_active
global linnea_quic_conn_unvalidated
global linnea_quic_conn_sweep_now
global linnea_quic_conn_slot
global linnea_worker_index
global linnea_quic_conn_free_hook

section .bss
conn_pool: resb LINNEA_QUIC_MAX_CONNS * linnea_quic_conn_size
; called with rdi = conn on every path that frees a slot (0 = no hook). The QUIC
; server hangs per-connection resource release here (an open response stream's
; file mapping); the pool itself stays free of mmap knowledge.
linnea_quic_conn_free_hook: resq 1
; this worker's steering index, stamped into every connection id it issues so
; the BPF reuseport program can steer the connection's later packets back here.
; The worker's slot plus its generation's steer_base (0, or LINNEA_BPF_STEER_HALF across a hot
; upgrade — the map is shared between the generations, so each stamps its own
; half and a draining worker's connections keep steering to it). Zero until
; the master sets it after fork.
linnea_worker_index: resq 1

section .data
; How long a connection slot may go without a packet before the sweep reclaims
; it, in seconds. The server sets it from the config's `timeout`; the default is
; LINNEA_QUIC_IDLE_SECS, which is what it was fixed at before it became
; configurable, and is what linnea-pooltest keeps -- that harness links this
; file with no config and no src/lib/linnea_quic.o, so the value lives here
; rather than being read across from the transport parameter beside it.
extern linnea_quic_pto_ms
global linnea_quic_conn_idle_secs
linnea_quic_conn_idle_secs: dq LINNEA_QUIC_IDLE_SECS

section .text

; linnea_quic_conn_lookup(rdi=dcid ptr, rsi=dcid len) -> rax = conn* or 0.
linnea_quic_conn_lookup:
    cmp rsi, LINNEA_QUIC_SCID_LEN
    jne .miss                        ; not an ID we could have issued
    movzx eax, byte [rdi + 1]        ; pool index (byte 0 is the worker, for steering)
    cmp eax, LINNEA_QUIC_MAX_CONNS
    jae .miss
    imul rax, rax, linnea_quic_conn_size
    lea rax, [conn_pool + rax]
    cmp qword [rax + linnea_quic_conn.in_use], 0
    je .miss
    ; the full ID must match — the random tail authenticates the slot. The primary
    ; scid (unless the peer retired it) or any active alternate routes here
    ; (Finding 21: a retired local CID no longer routes).
    mov rcx, [rdi]
    cmp qword [rax + linnea_quic_conn.scid_retired], 0
    jne .lk_alts
    cmp rcx, [rax + linnea_quic_conn.scid]
    je .match
.lk_alts:
    lea rdx, [rax + linnea_quic_conn.lalts]
    mov r8d, LINNEA_QUIC_LOCAL_ALTS
.lk_alt:
    ; ACTIVE or PENDING (issued, awaiting its announce) both route; FREE/RETIRED do not
    mov r9, [rdx + linnea_quic_lcid.state]
    cmp r9, LINNEA_QUIC_CID_ACTIVE
    je .lk_alt_hit
    cmp r9, LINNEA_QUIC_CID_PENDING
    jne .lk_alt_next
.lk_alt_hit:
    cmp rcx, [rdx + linnea_quic_lcid.cid]
    je .match
.lk_alt_next:
    add rdx, linnea_quic_lcid_size
    dec r8d
    jnz .lk_alt
    jmp .miss
.match:
    ; a packet arrived for it, so it is not idle
    push rax
    call conn_now
    pop rcx
    mov [rcx + linnea_quic_conn.last_active], rax
    mov rax, rcx
    ret
.miss:
    xor eax, eax
    ret

; linnea_quic_conn_lookup_odcid(rdi=dcid ptr, rsi=dcid len) -> rax = conn* or 0.
; Finds the connection whose recorded original DCID matches, by a linear scan of
; the pool. This is the handshake-phase demux: before the client has processed
; our ServerHello it still addresses us by the DCID it chose, so a second Initial
; (the rest of a large ClientHello, or a retransmission) must reach the slot the
; first one opened. A zero-length id never matches — it would alias every slot
; whose original DCID is not yet recorded.
linnea_quic_conn_lookup_odcid:
    test rsi, rsi
    jz .lo_miss
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi                     ; dcid ptr
    mov r13, rsi                     ; dcid len
    lea rbx, [conn_pool]
    mov r14d, LINNEA_QUIC_MAX_CONNS
.lo_slot:
    cmp qword [rbx + linnea_quic_conn.in_use], 0
    je .lo_next
    cmp [rbx + linnea_quic_conn.odcid_len], r13
    jne .lo_next
    xor ecx, ecx                     ; compare r13 bytes of the original DCID
.lo_cmp:
    cmp rcx, r13
    jae .lo_hit
    mov al, [r12 + rcx]
    lea rdx, [rbx + linnea_quic_conn.odcid]
    cmp al, [rdx + rcx]
    jne .lo_next
    inc rcx
    jmp .lo_cmp
.lo_hit:
    mov rax, rbx
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.lo_next:
    add rbx, linnea_quic_conn_size
    dec r14d
    jnz .lo_slot
    pop r14
    pop r13
    pop r12
    pop rbx
.lo_miss:
    xor eax, eax
    ret

; linnea_quic_conn_alloc(rdi=peer ptr, rsi=peer len) -> rax = conn* or 0.
linnea_quic_conn_alloc:
    push rbx
    push r12
    push r13
    push r14
    mov r13, rdi                     ; peer
    mov r14, rsi                     ; peer len
    ; reclaim anything that has gone quiet before looking for a free slot, so
    ; connections abandoned without a close cannot fill the pool for good
    call conn_now
    mov rdi, rax
    mov rsi, [linnea_quic_conn_idle_secs]
    call linnea_quic_conn_sweep
    xor r12d, r12d                   ; index
    lea rbx, [conn_pool]
.scan:
    cmp qword [rbx + linnea_quic_conn.in_use], 0
    je .found
    add rbx, linnea_quic_conn_size
    inc r12d
    cmp r12d, LINNEA_QUIC_MAX_CONNS
    jb .scan
    xor eax, eax                     ; pool exhausted
    jmp .aret
.found:
    ; zero the slot, then fill in identity and peer
    mov rdi, rbx
    xor eax, eax
    mov ecx, linnea_quic_conn_size
    rep stosb
    mov qword [rbx + linnea_quic_conn.in_use], 1
    mov rax, [linnea_quic_conn_idle_secs]
    mov [rbx + linnea_quic_conn.idle_secs], rax
    mov qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_NEW
    ; "no capture file" is -1, and the zeroing above writes 0 -- which is a
    ; PERFECTLY GOOD descriptor. The teardown releases all RA_CTXS contexts
    ; unconditionally (a completed one has given its slot back and still holds
    ; its file), so without this every connection that ended closed fd 0 once
    ; per context it never used. The worker closes stdin, so fd 0 is routinely
    ; the capture file of a request on ANOTHER connection: that upload's next
    ; pwrite returned EBADF and the client got a 413 naming no method and no
    ; path, because the request head had not been parsed yet. Intermittent by
    ; nature -- it needs the two to overlap -- and it cost a long detour from
    ; the bug it was hiding behind.
    lea rdi, [rbx + linnea_quic_conn.ra_ctx]
    mov ecx, LINNEA_QUIC_RA_CTXS
.spill_none:
    mov qword [rdi + linnea_quic_ra.spill_fd], -1
    add rdi, linnea_quic_ra_size
    dec ecx
    jnz .spill_none
    ; connection id = steering index || pool index || 6 random bytes. The
    ; steering index routes the connection back to this worker (BPF reuseport);
    ; the pool index locates the slot; the random tail authenticates it.
    mov [rbx + linnea_quic_conn.scid + 1], r12b       ; pool index
    mov eax, [linnea_worker_index]
    mov [rbx + linnea_quic_conn.scid], al             ; steering index
    lea rdi, [rbx + linnea_quic_conn.scid + 2]
    mov esi, LINNEA_QUIC_SCID_LEN - 2
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    cmp rax, LINNEA_QUIC_SCID_LEN - 2
    jne .arand_fail
    ; alternate connection id (quic-7): copy the worker/pool bytes so it routes to
    ; this same slot, then a fresh random tail. Announced later via
    ; NEW_CONNECTION_ID; conn_lookup matches it once cid1_active is set.
    mov ax, [rbx + linnea_quic_conn.scid]             ; worker || pool bytes
    mov [rbx + linnea_quic_conn.cid1], ax
    lea rdi, [rbx + linnea_quic_conn.cid1 + 2]
    mov esi, LINNEA_QUIC_SCID_LEN - 2
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    cmp rax, LINNEA_QUIC_SCID_LEN - 2
    jne .arand_fail
    mov qword [rbx + linnea_quic_conn.cid1_active], 1
    ; mirror cid1 as our sequence-1 alternate in the local CID table, and set the
    ; next sequence we will issue to 2 (scid is 0, cid1 is 1) (Finding 21)
    mov qword [rbx + linnea_quic_conn.lalts + linnea_quic_lcid.state], LINNEA_QUIC_CID_ACTIVE
    mov qword [rbx + linnea_quic_conn.lalts + linnea_quic_lcid.seq], 1
    mov rax, [rbx + linnea_quic_conn.cid1]
    mov [rbx + linnea_quic_conn.lalts + linnea_quic_lcid.cid], rax
    mov qword [rbx + linnea_quic_conn.lcid_next], 2
    ; record the peer address (sockaddr_in6; IPv4 arrives as ::ffff:x)
    mov rcx, r14
    cmp rcx, 28
    jbe .acplen
    mov ecx, 28
.acplen:
    mov [rbx + linnea_quic_conn.peer_len], rcx
    mov rsi, r13
    lea rdi, [rbx + linnea_quic_conn.peer]
    rep movsb
    call conn_now
    mov [rbx + linnea_quic_conn.last_active], rax
    mov rax, rbx
    jmp .aret
.arand_fail:
    mov qword [rbx + linnea_quic_conn.in_use], 0
    xor eax, eax
.aret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_conn_sweep(rdi=now seconds, rsi=idle seconds) -> rax = slots freed.
; Frees every slot whose last packet is older than the idle window. The clock is
; a parameter rather than read here so a test can age connections instantly.
linnea_quic_conn_sweep:
    push rbx
    push r12
    xor r12d, r12d                   ; freed
    lea rbx, [conn_pool]
    mov rcx, LINNEA_QUIC_MAX_CONNS
.sw_slot:
    cmp qword [rbx + linnea_quic_conn.in_use], 0
    je .sw_next
    mov rax, rdi
    sub rax, [rbx + linnea_quic_conn.last_active]
    jb .sw_next                      ; stamped ahead of now: treat as active,
                                     ; never let the subtraction wrap and
                                     ; reclaim a live connection
    ; an established connection gets the full idle window; one still handshaking
    ; gets a much shorter one (see LINNEA_QUIC_HS_IDLE_SECS)
    ; the caller's window is the ceiling; this connection may have agreed a
    ; shorter one with its peer (RFC 9000 10.1, .idle_secs)
    mov rdx, rsi
    mov r8, [rbx + linnea_quic_conn.idle_secs]
    test r8, r8
    jz .sw_have_window               ; unset (an older slot): keep the ceiling
    cmp r8, rdx
    jae .sw_have_window
    mov rdx, r8
.sw_have_window:
    ; RFC 9000 10.1 MUST: "endpoints MUST increase the idle timeout period to be
    ; at least three times the current Probe Timeout (PTO). This allows for
    ; multiple PTOs to expire, and therefore multiple probes to be sent and
    ; lost, prior to idle timeout." CURRENT is the word that decides where this
    ; belongs: the PTO falls by orders of magnitude once the connection has an
    ; RTT sample, so a floor computed while parsing transport parameters would
    ; be the initial-RTT one -- about a second -- frozen for the connection's
    ; life (audit-report-90). Here it is the figure the connection actually has,
    ; which on a fast path is tens of milliseconds and changes nothing, and on a
    ; slow one is seconds and is exactly when the rule matters.
    ; rcx is the slot counter of the walk this sits inside, so it is saved with
    ; the rest; the result comes back in r9, which the walk does not use, since
    ; every register it does use has to be restored before the comparison.
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8                          ; six: rsp stays 16-aligned for the call
    mov rdi, rbx
    mov esi, 1                       ; application space: the peer's max_ack_delay
    call linnea_quic_pto_ms
    lea rax, [rax + rax * 2]         ; three of them, in ms
    add rax, 999
    xor edx, edx
    mov ecx, 1000
    div rcx                          ; -> seconds, rounded up
    mov r9, rax
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    cmp rdx, r9
    jae .sw_pto_ok
    mov rdx, r9                      ; the window is below three PTOs: raise it
.sw_pto_ok:
    cmp qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    je .sw_window
    cmp rdx, LINNEA_QUIC_HS_IDLE_SECS
    jbe .sw_window
    mov edx, LINNEA_QUIC_HS_IDLE_SECS
.sw_window:
    cmp rax, rdx
    jbe .sw_next                     ; still within the idle window
    cmp qword [linnea_quic_conn_free_hook], 0
    je .sw_reclaim
    push rdi                         ; the hook must not disturb the walk
    push rsi
    push rcx
    mov rdi, rbx
    call [linnea_quic_conn_free_hook]
    pop rcx
    pop rsi
    pop rdi
.sw_reclaim:
    mov qword [rbx + linnea_quic_conn.in_use], 0
    inc r12d
.sw_next:
    add rbx, linnea_quic_conn_size
    dec rcx
    jnz .sw_slot
    mov eax, r12d
    pop r12
    pop rbx
    ret

; linnea_quic_conn_sweep_now() -> rax = slots reclaimed. Reads the clock itself
; and reclaims every connection that has gone quiet. The allocation path sweeps
; too, but that is not enough on its own: while address validation is engaged, an
; Initial without a token never reaches allocation, so nothing would ever sweep
; and the forged slots that engaged it would hold it engaged for good. Driven
; from the periodic timer, the pool recovers on its own.
linnea_quic_conn_sweep_now:
    call conn_now
    mov rdi, rax
    mov esi, LINNEA_QUIC_IDLE_SECS
    jmp linnea_quic_conn_sweep

; linnea_quic_conn_unvalidated() -> rax = slots held by peers that have not proved
; their address (no Handshake packet yet, and no Retry token). This is what the
; server gates on before opening a connection for an unvalidated Initial.
linnea_quic_conn_unvalidated:
    xor eax, eax
    lea rdx, [conn_pool]
    mov ecx, LINNEA_QUIC_MAX_CONNS
.uv_slot:
    cmp qword [rdx + linnea_quic_conn.in_use], 0
    je .uv_next
    cmp qword [rdx + linnea_quic_conn.amp_valid], 0
    jne .uv_next
    inc eax
.uv_next:
    add rdx, linnea_quic_conn_size
    dec ecx
    jnz .uv_slot
    ret

; linnea_quic_conn_active() -> rax = slots currently in use.
linnea_quic_conn_active:
    xor eax, eax
    lea rdx, [conn_pool]
    mov ecx, LINNEA_QUIC_MAX_CONNS
.ac_slot:
    cmp qword [rdx + linnea_quic_conn.in_use], 0
    je .ac_next
    inc eax
.ac_next:
    add rdx, linnea_quic_conn_size
    dec ecx
    jnz .ac_slot
    ret

; linnea_quic_conn_slot(rdi=index) -> rax = conn* if that slot is in use, else 0.
; Lets a caller walk the pool by index (the loss-recovery sweep needs every live
; connection) without exposing the pool array.
linnea_quic_conn_slot:
    cmp rdi, LINNEA_QUIC_MAX_CONNS
    jae .none
    imul rax, rdi, linnea_quic_conn_size
    lea rax, [conn_pool + rax]
    cmp qword [rax + linnea_quic_conn.in_use], 0
    je .none
    ret
.none:
    xor eax, eax
    ret

; conn_now() -> rax = CLOCK_MONOTONIC seconds. Monotonic so a clock step cannot
; make every connection look ancient (or eternally fresh).
conn_now:
    sub rsp, 24
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    mov edi, LINNEA_CLOCK_MONOTONIC
    mov rsi, rsp
    syscall
    mov rax, [rsp]
    add rsp, 24
    ret

; linnea_quic_conn_free(rdi=conn) — return the slot to the pool.
linnea_quic_conn_free:
    test rdi, rdi
    jz .fret
    cmp qword [linnea_quic_conn_free_hook], 0
    je .f_reclaim
    push rdi
    call [linnea_quic_conn_free_hook]
    pop rdi
.f_reclaim:
    mov qword [rdi + linnea_quic_conn.in_use], 0
.fret:
    ret
