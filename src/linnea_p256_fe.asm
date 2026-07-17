; linnea_p256_fe.asm — arithmetic in GF(p), p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
;
; Montgomery form, four 64-bit limbs; see include/linnea_p256_fe.inc for the
; representation and why it differs from fe25519's.
;
; Multiplication is schoolbook 4x4 into nine limbs followed by a four-round
; Montgomery reduction (CIOS), both written as fixed-trip-count loops rather
; than unrolled straight-line code: the operands are secret, so the loop
; bounds must not depend on them, and they don't -- every count here is a
; compile-time constant. Plain mul/adc throughout, not mulx/adcx/adox, which
; would widen the startup CPUID gate past today's AES-NI + PCLMULQDQ to buy
; cycles on a path that runs once per handshake.
;
; The limb-level carry structure was modelled and asserted in Python before
; any of this was written (the technique that made AES-GCM pass its vectors
; first try). Two results from that model are load-bearing below:
;   - a reduction round's carry can ripple TWO limbs past the four-limb
;     window, so .ripple walks it out rather than adding once;
;   - the schoolbook row carry into t[i+4] provably cannot overflow, so a
;     plain add suffices there.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 preserved. A field element is
; passed by pointer to four little-endian 64-bit limbs. Output may alias any
; input: every routine finishes reading its operands before it writes.

default rel

%include "linnea_p256_fe.inc"

global linnea_p256_fe_frombytes
global linnea_p256_fe_tobytes
global linnea_p256_fe_mul
global linnea_p256_fe_sq
global linnea_p256_fe_add
global linnea_p256_fe_sub
global linnea_p256_fe_inv
global linnea_p256_fe_copy
global linnea_p256_fe_cmov
global linnea_p256_fe_1
global linnea_p256_fe_0

section .rodata

align 8
; p, little-endian limbs. p0 = -1 mod 2^64 is what gives n0' = 1.
p256_p:         dq 0xffffffffffffffff, 0x00000000ffffffff
                dq 0x0000000000000000, 0xffffffff00000001

; 2^256 mod p — Montgomery's "one".
p256_r1:        dq 0x0000000000000001, 0xffffffff00000000
                dq 0xffffffffffffffff, 0x00000000fffffffe

; (2^256)^2 mod p — multiply by this to enter Montgomery form.
p256_r2:        dq 0x0000000000000003, 0xfffffffbffffffff
                dq 0xfffffffffffffffe, 0x00000004fffffffd

; p-2, the Fermat exponent for inversion. A public constant, so inv may
; branch on its bits.
p256_p_minus_2: dq 0xfffffffffffffffd, 0x00000000ffffffff
                dq 0x0000000000000000, 0xffffffff00000001

section .text

; p256_reduce_once(rdi=out, r8..r11 = v's low limbs, r12 = v's top limb)
;   Subtract p from v exactly if v >= p, branch-free, and store the four
;   limbs to rdi. Requires v < 2p, which is what makes one subtract enough.
;   File-local. Clobbers rax rcx rbx rbp r12-r15; the caller must already
;   have saved whichever of those it cares about.
p256_reduce_once:
    lea rbp, [p256_p]
    mov r13, r8
    mov r14, r9
    mov r15, r10
    mov rbx, r11
    sub r13, [rbp]
    sbb r14, [rbp + 8]
    sbb r15, [rbp + 16]
    sbb rbx, [rbp + 24]
    sbb r12, 0                  ; borrow out of the top limb
    sbb rax, rax                ; rax = -CF: all ones iff v < p (keep v)
    mov rcx, rax
    not rcx                     ; ~mask: all ones iff v >= p (take v - p)
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

; p256_redc(rdi=out, rsi=t) — Montgomery-reduce the nine little-endian limbs
;   at rsi (destroyed in place) into the four limbs at rdi, i.e. compute
;   t * 2^-256 mod p. Requires t < p * 2^256, which bounds the result below
;   2p and lets p256_reduce_once finish the job.
;   File-local. Clobbers rax rcx rdx rbx rbp r8-r15.
p256_redc:
    lea rbp, [p256_p]
    xor r12, r12                ; i = round
.round:
    mov r13, [rsi + r12*8]      ; m = t[i] * n0' mod 2^64, and n0' is 1
    xor r14, r14                ; carry
    xor r15, r15                ; j
.col:
    mov rax, r13
    mul qword [rbp + r15*8]     ; rdx:rax = m * p[j]
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

    ; Walk the row carry out to t[8]. The Python model measured this
    ; rippling two limbs past the window, so a single add would be wrong --
    ; and wrong only for the inputs that reach that far, which no fixed
    ; vector would be likely to hit. The trip count depends on i (public),
    ; never on the data.
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

    ; the reduced value is t[4..8], now < 2p
    mov r8,  [rsi + 32]
    mov r9,  [rsi + 40]
    mov r10, [rsi + 48]
    mov r11, [rsi + 56]
    mov r12, [rsi + 64]
    jmp p256_reduce_once        ; tail call: its ret returns to our caller

; linnea_p256_fe_mul(rdi=out, rsi=a, rdx=b) — out = a * b * 2^-256 mod p,
;   i.e. the Montgomery product. out may alias a and/or b: the operands are
;   fully consumed into the stack product before out is written.
linnea_p256_fe_mul:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72                 ; t[0..8]; leaves rsp 16-aligned for the call

    mov rbp, rdx                ; b (rdx is about to be the mul high half)

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
    mul qword [rbp + r15*8]     ; rdx:rax = a[i] * b[j]
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
    call p256_redc              ; rdi already holds out

    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; linnea_p256_fe_sq(rdi=out, rsi=a) — out = a^2 * 2^-256 mod p.
;   No dedicated squaring path: the cross terms would save about a third of
;   the multiplies on a once-per-handshake operation. Correctness first.
linnea_p256_fe_sq:
    mov rdx, rsi
    jmp linnea_p256_fe_mul

; linnea_p256_fe_add(rdi=out, rsi=a, rdx=b) — out = a + b mod p.
linnea_p256_fe_add:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r8,  [rsi]
    mov r9,  [rsi + 8]
    mov r10, [rsi + 16]
    mov r11, [rsi + 24]
    add r8,  [rdx]
    adc r9,  [rdx + 8]
    adc r10, [rdx + 16]
    adc r11, [rdx + 24]
    mov r12, 0
    adc r12, 0                  ; the 257th bit: a + b < 2p may not fit 256
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

; linnea_p256_fe_sub(rdi=out, rsi=a, rdx=b) — out = a - b mod p.
linnea_p256_fe_sub:
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
    ; Mask p's limbs into registers FIRST: `and` clears CF, so folding the
    ; masking into the add chain below would break it.
    lea rbx, [p256_p]
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

; linnea_p256_fe_inv(rdi=out, rsi=a) — out = a^-1 mod p, via Fermat
;   (a^(p-2)). Square-and-multiply over the bits of p-2, high to low. The
;   exponent is a public constant, so branching on its bits leaks nothing;
;   the operand never steers control flow. inv(0) = 0, as Fermat gives.
;
;   A tuned addition chain would cut the ~128 multiplies roughly in half;
;   this runs once per signature (P2 needs it for the affine conversion), so
;   the simple ladder stays until something says otherwise.
linnea_p256_fe_inv:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72                 ; [rsp] = acc, [rsp+32] = base; keeps 16-align

    mov r13, rdi                ; save out (a may alias it)
    mov rax, [rsi]
    mov [rsp + 32], rax
    mov rax, [rsi + 8]
    mov [rsp + 40], rax
    mov rax, [rsi + 16]
    mov [rsp + 48], rax
    mov rax, [rsi + 24]
    mov [rsp + 56], rax

    lea rdi, [rsp]
    call linnea_p256_fe_1       ; acc = 1

    mov r12, 255                ; bit index
.bit:
    lea rdi, [rsp]
    lea rsi, [rsp]
    call linnea_p256_fe_sq

    mov rax, r12
    shr rax, 6                  ; limb
    mov rcx, r12
    and rcx, 63                 ; bit within limb
    lea rbx, [p256_p_minus_2]
    mov rax, [rbx + rax*8]
    shr rax, cl
    test al, 1
    jz .next
    lea rdi, [rsp]
    lea rsi, [rsp]
    lea rdx, [rsp + 32]
    call linnea_p256_fe_mul
.next:
    dec r12
    jns .bit

    mov rdi, r13
    lea rsi, [rsp]
    call linnea_p256_fe_copy

    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; linnea_p256_fe_copy(rdi=dst, rsi=src)
linnea_p256_fe_copy:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    ret

; linnea_p256_fe_cmov(rdi=dst, rsi=src, rdx=cond) — dst = src if cond != 0.
;   Branch-free and index-free: cond is secret at the call sites in P2.
linnea_p256_fe_cmov:
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

; linnea_p256_fe_1(rdi=out) — out = 1, in Montgomery form.
linnea_p256_fe_1:
    lea rsi, [p256_r1]
    jmp linnea_p256_fe_copy

; linnea_p256_fe_0(rdi=out) — out = 0 (the same in either form).
linnea_p256_fe_0:
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    ret

; linnea_p256_fe_frombytes(rdi=out, rsi=in) — read 32 big-endian bytes (SEC1)
;   and enter Montgomery form. Input at or above p is reduced silently rather
;   than rejected: multiplying by R2 reduces mod p for any 256-bit input, and
;   canonicality is a parsing question that belongs to P2's point and scalar
;   decoders, not to the field.
linnea_p256_fe_frombytes:
    push rbx                    ; (alignment; rbx is not otherwise used)
    sub rsp, 32
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
    lea rdx, [p256_r2]
    call linnea_p256_fe_mul     ; out = x * R2 * R^-1 = x * R mod p
    add rsp, 32
    pop rbx
    ret

; linnea_p256_fe_tobytes(rdi=out, rsi=fe) — leave Montgomery form and write 32
;   big-endian bytes (SEC1). The result is canonical: redc reduces fully.
linnea_p256_fe_tobytes:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 120                ; [rsp] = t[0..8], [rsp+72] = reduced limbs,
                                ; [rsp+104] = saved out pointer

    ; out has to survive p256_redc, which clobbers every callee-saved
    ; register (it is file-local and spills nothing), so it goes on the
    ; stack rather than into rbx.
    mov [rsp + 104], rdi
    mov rax, [rsi]
    mov [rsp], rax
    mov rax, [rsi + 8]
    mov [rsp + 8], rax
    mov rax, [rsi + 16]
    mov [rsp + 16], rax
    mov rax, [rsi + 24]
    mov [rsp + 24], rax
    xor eax, eax                ; t = fe || 0: redc then divides by R
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
