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
global linnea_quic_conn_alloc
global linnea_quic_conn_free

section .bss
conn_pool: resb LINNEA_QUIC_MAX_CONNS * linnea_quic_conn_size

section .text

; linnea_quic_conn_lookup(rdi=dcid ptr, rsi=dcid len) -> rax = conn* or 0.
linnea_quic_conn_lookup:
    cmp rsi, LINNEA_QUIC_SCID_LEN
    jne .miss                        ; not an ID we could have issued
    movzx eax, byte [rdi]            ; index, big-endian
    shl eax, 8
    movzx ecx, byte [rdi + 1]
    or eax, ecx
    cmp eax, LINNEA_QUIC_MAX_CONNS
    jae .miss
    imul rax, rax, linnea_quic_conn_size
    lea rax, [conn_pool + rax]
    cmp qword [rax + linnea_quic_conn.in_use], 0
    je .miss
    ; the full ID must match — the random tail authenticates the slot
    mov rcx, [rdi]
    cmp rcx, [rax + linnea_quic_conn.scid]
    jne .miss
    ret
.miss:
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
    mov qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_NEW
    ; connection id = index (big-endian) || 6 random bytes
    mov eax, r12d
    mov [rbx + linnea_quic_conn.scid + 1], al
    shr eax, 8
    mov [rbx + linnea_quic_conn.scid], al
    lea rdi, [rbx + linnea_quic_conn.scid + 2]
    mov esi, LINNEA_QUIC_SCID_LEN - 2
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    cmp rax, LINNEA_QUIC_SCID_LEN - 2
    jne .arand_fail
    ; record the peer address
    mov rcx, r14
    cmp rcx, 16
    jbe .acplen
    mov ecx, 16
.acplen:
    mov [rbx + linnea_quic_conn.peer_len], rcx
    mov rsi, r13
    lea rdi, [rbx + linnea_quic_conn.peer]
    rep movsb
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

; linnea_quic_conn_free(rdi=conn) — return the slot to the pool.
linnea_quic_conn_free:
    test rdi, rdi
    jz .fret
    mov qword [rdi + linnea_quic_conn.in_use], 0
.fret:
    ret
