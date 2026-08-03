; linnea_p256_mont.asm — Montgomery arithmetic mod a 256-bit prime.
;
; The shared core behind linnea_p256_fe.asm (modulus p) and
; linnea_p256_scalar.asm (modulus n); see include/linnea_p256_mont.inc for
; why both moduli share one reduction rather than each carrying a copy.
;
; Multiplication is schoolbook 4x4 into nine limbs followed by a four-round
; Montgomery reduction (CIOS), both as fixed-trip-count loops: the operands
; are secret, so the bounds must not depend on them, and they don't -- every
; count here is a compile-time constant or a public round index. Plain
; mul/adc, not mulx/adcx/adox, which would widen the startup CPUID gate past
; AES-NI + PCLMULQDQ to buy cycles on a path that runs once per handshake.
;
; The limb-level carry structure was modelled and asserted in Python before
; any of it was written, for both moduli (they do not share carry behaviour
; automatically -- different limbs, separately checked). Two results are
; load-bearing below:
;   - a reduction round's carry can ripple TWO limbs past the four-limb
;     window, so .ripple walks it out rather than adding once;
;   - the schoolbook row carry into t[i+4] provably cannot overflow, so a
;     plain add suffices there.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 preserved. Values are passed
; by pointer to four little-endian 64-bit limbs. Output may alias any input:
; every routine finishes reading its operands before it writes.

default rel

%include "linnea_p256_mont.inc"

global linnea_p256_mont_mul
global linnea_p256_mont_sq
global linnea_p256_mont_add
global linnea_p256_mont_sub
global linnea_p256_mont_inv
global linnea_p256_mont_frombytes
global linnea_p256_mont_tobytes
global linnea_p256_mont_copy
global linnea_p256_mont_cmov
global linnea_p256_mont_1
global linnea_p256_mont_0

section .text

; p256_reduce_once(rdi=out, r8..r11 = v's low limbs, r12 = v's top limb,
;                  rbp = ctx)
;   Subtract m from v exactly if v >= m, branch-free, and store the four limbs
;   to rdi. Requires v < 2m, which is what makes one subtract enough.
;   File-local. Clobbers rax rcx rbx r12-r15; preserves rbp and rdi.
p256_reduce_once:
    mov r13, r8
    mov r14, r9
    mov r15, r10
    mov rbx, r11
    sub r13, [rbp + linnea_p256_mont_ctx.m]
    sbb r14, [rbp + linnea_p256_mont_ctx.m + 8]
    sbb r15, [rbp + linnea_p256_mont_ctx.m + 16]
    sbb rbx, [rbp + linnea_p256_mont_ctx.m + 24]
    sbb r12, 0                  ; borrow out of the top limb
    sbb rax, rax                ; rax = -CF: all ones iff v < m (keep v)
    mov rcx, rax
    not rcx                     ; ~mask: all ones iff v >= m (take v - m)
    and r8, rax
    and r13, rcx
    or r8, r13
    and r9, rax
    and r14, rcx
    or r9, r14
    and r10, rax
    and r15, rcx
    or r10, r15
    and r11, rax
    and rbx, rcx
    or r11, rbx
    mov [rdi], r8
    mov [rdi + 8], r9
    mov [rdi + 16], r10
    mov [rdi + 24], r11
    ret

; p256_redc(rdi=out, rsi=t, rbp=ctx) — Montgomery-reduce the nine
;   little-endian limbs at rsi (destroyed in place) into the four at rdi:
;   t * 2^-256 mod m. Requires t < m * 2^256, which bounds the result below 2m
;   and lets p256_reduce_once finish the job.
;   File-local. Clobbers rax rcx rdx rbx r8-r15; preserves rbp and rdi.
p256_redc:
    xor r12, r12                ; i = round
.round:
    mov r13, [rsi + r12*8]
    imul r13, [rbp + linnea_p256_mont_ctx.n0]   ; m_i = t[i] * n0' mod 2^64
    xor r14, r14                ; carry
    xor r15, r15                ; j
.col:
    mov rax, r13
    mul qword [rbp + linnea_p256_mont_ctx.m + r15*8]
    lea rbx, [r12 + r15]
    add rax, [rsi + rbx*8]
    adc rdx, 0
    add rax, r14
    adc rdx, 0
    mov [rsi + rbx*8], rax
    mov r14, rdx
    inc r15
    cmp r15, 4
    jb .col

    ; Walk the row carry out to t[8]. The Python model measured this rippling
    ; two limbs past the window for BOTH moduli, so a single add would be
    ; wrong -- and wrong only for the inputs that reach that far, which no
    ; fixed vector would be likely to hit. The trip count depends on i
    ; (public), never on the data.
    lea rbx, [r12 + 4]
.ripple:
    add [rsi + rbx*8], r14
    setc r14b
    movzx r14d, r14b
    inc rbx
    cmp rbx, 9
    jb .ripple

    inc r12
    cmp r12, 4
    jb .round

    ; the reduced value is t[4..8], now < 2m
    mov r8,  [rsi + 32]
    mov r9,  [rsi + 40]
    mov r10, [rsi + 48]
    mov r11, [rsi + 56]
    mov r12, [rsi + 64]
    jmp p256_reduce_once        ; tail call: its ret returns to our caller

; linnea_p256_mont_mul(rdi=out, rsi=a, rdx=b, rcx=ctx) — out = a*b*R^-1 mod m.
;   out may alias a and/or b: the operands are fully consumed into the stack
;   product before out is written.
linnea_p256_mont_mul:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72                 ; t[0..8]; leaves rsp 16-aligned for the call

    mov rbp, rcx                ; ctx
    mov rcx, rdx                ; b (rdx is about to be the mul high half)

    xor eax, eax
    mov [rsp], rax
    mov [rsp + 8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax
    mov [rsp + 32], rax
    mov [rsp + 40], rax
    mov [rsp + 48], rax
    mov [rsp + 56], rax
    mov [rsp + 64], rax

    xor r12, r12                ; i
.row:
    mov r13, [rsi + r12*8]      ; a[i]
    xor r14, r14                ; carry
    xor r15, r15                ; j
.col:
    mov rax, r13
    mul qword [rcx + r15*8]     ; rdx:rax = a[i] * b[j]
    lea rbx, [r12 + r15]
    add rax, [rsp + rbx*8]
    adc rdx, 0
    add rax, r14
    adc rdx, 0
    mov [rsp + rbx*8], rax
    mov r14, rdx
    inc r15
    cmp r15, 4
    jb .col
    ; t[i+4] is untouched by earlier rows, so this add cannot carry out
    ; (asserted in the model).
    lea rbx, [r12 + 4]
    add [rsp + rbx*8], r14
    inc r12
    cmp r12, 4
    jb .row

    mov rsi, rsp
    call p256_redc              ; rdi holds out, rbp holds ctx

    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; linnea_p256_mont_sq(rdi=out, rsi=a, rdx=ctx) — out = a^2 * R^-1 mod m.
;   No dedicated squaring path: the cross terms would save about a third of
;   the multiplies on a once-per-handshake operation. Correctness first.
linnea_p256_mont_sq:
    mov rcx, rdx                ; ctx
    mov rdx, rsi                ; b = a
    jmp linnea_p256_mont_mul

; linnea_p256_mont_add(rdi=out, rsi=a, rdx=b, rcx=ctx) — out = a + b mod m.
linnea_p256_mont_add:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbp, rcx                ; ctx
    mov r8,  [rsi]
    mov r9,  [rsi + 8]
    mov r10, [rsi + 16]
    mov r11, [rsi + 24]
    add r8,  [rdx]
    adc r9,  [rdx + 8]
    adc r10, [rdx + 16]
    adc r11, [rdx + 24]
    mov r12, 0
    adc r12, 0                  ; the 257th bit: a + b < 2m may not fit 256
    sub rsp, 8                  ; six pushes leave rsp at 8 mod 16; realign
    call p256_reduce_once
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; linnea_p256_mont_sub(rdi=out, rsi=a, rdx=b, rcx=ctx) — out = a - b mod m.
linnea_p256_mont_sub:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r8,  [rsi]
    mov r9,  [rsi + 8]
    mov r10, [rsi + 16]
    mov r11, [rsi + 24]
    sub r8,  [rdx]
    sbb r9,  [rdx + 8]
    sbb r10, [rdx + 16]
    sbb r11, [rdx + 24]
    sbb rax, rax                ; mask = -borrow: all ones iff a < b
    ; Mask m's limbs into registers FIRST: `and` clears CF, so folding the
    ; masking into the add chain below would break it.
    lea rbx, [rcx + linnea_p256_mont_ctx.m]
    mov r12, [rbx]
    mov r13, [rbx + 8]
    mov r14, [rbx + 16]
    mov r15, [rbx + 24]
    and r12, rax
    and r13, rax
    and r14, rax
    and r15, rax
    add r8,  r12
    adc r9,  r13
    adc r10, r14
    adc r11, r15
    mov [rdi], r8
    mov [rdi + 8], r9
    mov [rdi + 16], r10
    mov [rdi + 24], r11
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_p256_mont_inv(rdi=out, rsi=a, rdx=ctx) — out = a^-1 mod m, via
;   Fermat (a^(m-2)). The ladder runs in the Montgomery domain: the
;   accumulator starts at ctx.r1 (Montgomery one) and every step is a
;   Montgomery multiply, so the result is the Montgomery form of a^(m-2) --
;   exactly what the caller wants, with no conversion. inv(0) = 0.
;
;   The exponent is a public constant, so branching on its bits leaks
;   nothing; the operand never steers control flow. A tuned addition chain
;   would cut the ~128 multiplies roughly in half; this runs once per
;   signature, so the simple ladder stays until something says otherwise.
linnea_p256_mont_inv:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72                 ; [rsp] = acc, [rsp+32] = base; keeps 16-align

    mov rbp, rdx                ; ctx (survives the calls below)
    mov r13, rdi                ; out (a may alias it)
    mov rax, [rsi]
    mov [rsp + 32], rax
    mov rax, [rsi + 8]
    mov [rsp + 40], rax
    mov rax, [rsi + 16]
    mov [rsp + 48], rax
    mov rax, [rsi + 24]
    mov [rsp + 56], rax

    lea rdi, [rsp]
    mov rsi, rbp
    call linnea_p256_mont_1     ; acc = 1

    mov r12, 255                ; bit index
.bit:
    lea rdi, [rsp]
    lea rsi, [rsp]
    mov rdx, rbp
    call linnea_p256_mont_sq

    mov rax, r12
    shr rax, 6                  ; limb
    mov rcx, r12
    and rcx, 63                 ; bit within limb
    lea rbx, [rbp + linnea_p256_mont_ctx.exp]
    mov rax, [rbx + rax*8]
    shr rax, cl
    test al, 1
    jz .next
    lea rdi, [rsp]
    lea rsi, [rsp]
    lea rdx, [rsp + 32]
    mov rcx, rbp
    call linnea_p256_mont_mul
.next:
    dec r12
    jns .bit

    mov rdi, r13
    lea rsi, [rsp]
    call linnea_p256_mont_copy

    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; linnea_p256_mont_copy(rdi=dst, rsi=src)
linnea_p256_mont_copy:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    ret

; linnea_p256_mont_cmov(rdi=dst, rsi=src, rdx=cond) — dst = src if cond != 0.
;   Branch-free and index-free: cond is secret at the point-arithmetic call
;   sites.
linnea_p256_mont_cmov:
    neg rdx                     ; CF = (cond != 0)
    sbb rax, rax                ; rax = -CF: all ones iff cond != 0
    mov rcx, rax
    not rcx
    mov r8, [rdi]
    and r8, rcx
    mov r9, [rsi]
    and r9, rax
    or r8, r9
    mov [rdi], r8
    mov r8, [rdi + 8]
    and r8, rcx
    mov r9, [rsi + 8]
    and r9, rax
    or r8, r9
    mov [rdi + 8], r8
    mov r8, [rdi + 16]
    and r8, rcx
    mov r9, [rsi + 16]
    and r9, rax
    or r8, r9
    mov [rdi + 16], r8
    mov r8, [rdi + 24]
    and r8, rcx
    mov r9, [rsi + 24]
    and r9, rax
    or r8, r9
    mov [rdi + 24], r8
    ret

; linnea_p256_mont_1(rdi=out, rsi=ctx) — out = 1, in Montgomery form.
linnea_p256_mont_1:
    lea rsi, [rsi + linnea_p256_mont_ctx.r1]
    jmp linnea_p256_mont_copy

; linnea_p256_mont_0(rdi=out) — out = 0 (the same in either form).
linnea_p256_mont_0:
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    ret

; linnea_p256_mont_frombytes(rdi=out, rsi=in, rdx=ctx) — read 32 big-endian
;   bytes (SEC1) and enter Montgomery form. Input at or above m is reduced
;   silently rather than rejected: multiplying by R2 reduces mod m for any
;   256-bit input (x * R2 < R * m, which is the bound redc needs), and
;   canonicality is a parsing question for the caller. linnea_p256_scalar
;   exposes an explicit range check for the callers that need one.
linnea_p256_mont_frombytes:
    push rbx
    sub rsp, 32
    mov rbx, rdx                ; ctx
    mov rax, [rsi]              ; most significant eight bytes
    bswap rax
    mov [rsp + 24], rax
    mov rax, [rsi + 8]
    bswap rax
    mov [rsp + 16], rax
    mov rax, [rsi + 16]
    bswap rax
    mov [rsp + 8], rax
    mov rax, [rsi + 24]
    bswap rax
    mov [rsp], rax
    mov rsi, rsp
    lea rdx, [rbx + linnea_p256_mont_ctx.r2]
    mov rcx, rbx
    call linnea_p256_mont_mul   ; out = x * R2 * R^-1 = x * R mod m
    add rsp, 32
    pop rbx
    ret

; linnea_p256_mont_tobytes(rdi=out, rsi=a, rdx=ctx) — leave Montgomery form
;   and write 32 big-endian bytes (SEC1). The result is canonical: redc
;   reduces fully.
linnea_p256_mont_tobytes:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 120                ; [rsp] = t[0..8], [rsp+72] = reduced limbs,
                                ; [rsp+104] = saved out pointer

    mov rbp, rdx                ; ctx
    ; out has to survive p256_redc, which clobbers every callee-saved
    ; register except rbp (it is file-local and spills nothing), so it goes
    ; on the stack rather than into rbx.
    mov [rsp + 104], rdi
    mov rax, [rsi]
    mov [rsp], rax
    mov rax, [rsi + 8]
    mov [rsp + 8], rax
    mov rax, [rsi + 16]
    mov [rsp + 16], rax
    mov rax, [rsi + 24]
    mov [rsp + 24], rax
    xor eax, eax                ; t = a || 0: redc then divides by R
    mov [rsp + 32], rax
    mov [rsp + 40], rax
    mov [rsp + 48], rax
    mov [rsp + 56], rax
    mov [rsp + 64], rax

    lea rdi, [rsp + 72]
    mov rsi, rsp
    call p256_redc

    mov rbx, [rsp + 104]
    mov rax, [rsp + 72 + 24]
    bswap rax
    mov [rbx], rax
    mov rax, [rsp + 72 + 16]
    bswap rax
    mov [rbx + 8], rax
    mov rax, [rsp + 72 + 8]
    bswap rax
    mov [rbx + 16], rax
    mov rax, [rsp + 72]
    bswap rax
    mov [rbx + 24], rax

    add rsp, 120
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
