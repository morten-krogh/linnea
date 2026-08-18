; linnea_strtest.asm — known-answer tests for linnea_string_to_u64, the one
; decimal parser every protocol's Content-Length now goes through
; (audit-report-5 Finding 1). Five hand-rolled copies preceded it and three
; were wrong, each at a different place in the same six instructions, so the
; vectors here are chosen to sit exactly on the seams:
;
;   * 18446744073709551615 must PARSE (verdict 0, value UINT64_MAX). It is a
;     legal Content-Length, and every parser that reported failure by returning
;     -1 confused it with one -- HTTP/2 treated a body declaring it as having
;     no usable length and forwarded its own count instead.
;   * 18446744073709551616 must be OUT OF RANGE (verdict 2). It used to wrap to
;     zero, which is precisely the DATA sum of a request that sends no body, so
;     the one value that "cannot possibly match" was the one that matched.
;   * 4611686018427387904 * 10 (2^62 followed by a 0) wraps to 2^63 -- LARGER
;     than what it came from, which is why "the product got smaller" is not an
;     overflow test, and why the guard has to be applied before the multiply.
;   * 1844674407370955161 is (2^64-1)/10 exactly, the largest value the multiply
;     may still be attempted on: appending 5 is in range and appending 6 is not,
;     which is the boundary the digit's own carry has to catch.
;
; Prints "str <pass>/<total>" and exits 1 if any check fails.

default rel

global _start

extern linnea_string_to_u64
extern linnea_print_stdout
extern linnea_print_u64_stdout

section .rodata
; --- accepted: (text, length, expected value) ---
s_zero:   db "0"
s_zero_n  equ $ - s_zero
s_one:    db "1"
s_one_n   equ $ - s_one
s_lead0:  db "0000000000000000000005"           ; leading zeros are still digits
s_lead0_n equ $ - s_lead0
s_5:      db "5"
s_5_n     equ $ - s_5
s_max:    db "18446744073709551615"             ; UINT64_MAX: legal, not a fault
s_max_n   equ $ - s_max
s_div10:  db "1844674407370955161"              ; (2^64-1)/10
s_div10_n equ $ - s_div10
s_div10_5: db "18446744073709551615"            ; ...*10 + 5: the last in range
s_div10_5_n equ $ - s_div10_5
s_2_62:   db "4611686018427387904"              ; 2^62
s_2_62_n  equ $ - s_2_62
s_2_63m:  db "9223372036854775807"
s_2_63m_n equ $ - s_2_63m
s_big:    db "200000"
s_big_n   equ $ - s_big

; --- out of range (verdict 2): all digits, past 2^64-1 ---
r_2_64:   db "18446744073709551616"             ; 2^64 -- wrapped to 0
r_2_64_n  equ $ - r_2_64
r_2_64p1: db "18446744073709551617"             ; 2^64+1 -- wrapped to 1
r_2_64p1_n equ $ - r_2_64p1
r_div10_6: db "18446744073709551616"            ; (2^64-1)/10*10 + 6: the carry
r_div10_6_n equ $ - r_div10_6
r_2_62_0: db "46116860184273879040"             ; 2^62*10: wraps UPWARD to 2^63
r_2_62_0_n equ $ - r_2_62_0
r_40:     times 40 db "1"
r_40_n    equ $ - r_40
r_21z:    db "100000000000000000000"            ; 10^20, one digit too wide
r_21z_n   equ $ - r_21z

; --- not a number (verdict 1) ---
b_alpha:  db "5x"
b_alpha_n equ $ - b_alpha
b_space:  db " 5"
b_space_n equ $ - b_space
b_tail:   db "5 "
b_tail_n  equ $ - b_tail
b_sign:   db "+5"
b_sign_n  equ $ - b_sign
b_neg:    db "-1"
b_neg_n   equ $ - b_neg
b_list:   db "5, 5"                             ; RFC 9110 8.6's comma list form
b_list_n  equ $ - b_list
b_hex:    db "0x10"
b_hex_n   equ $ - b_hex

msg:      db "str "
msg_len   equ $ - msg
slash:    db "/"
nl:       db 10

section .text
; OK text, len, expected — verdict 0 and the exact value.
%macro OK 3
    lea rdi, [%1]
    mov esi, %2
    call linnea_string_to_u64
    inc r14d
    test edx, edx
    jnz %%bad
    mov rcx, %3
    cmp rax, rcx
    jne %%bad
    inc r15d
%%bad:
%endmacro

; RANGE text, len — verdict 2 (all digits, but past 2^64-1).
%macro RANGE 2
    lea rdi, [%1]
    mov esi, %2
    call linnea_string_to_u64
    inc r14d
    cmp edx, 2
    jne %%bad
    inc r15d
%%bad:
%endmacro

; SYNTAX text, len — verdict 1 (empty, or a byte that is not a digit).
%macro SYNTAX 2
    lea rdi, [%1]
    mov esi, %2
    call linnea_string_to_u64
    inc r14d
    cmp edx, 1
    jne %%bad
    inc r15d
%%bad:
%endmacro

_start:
    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; pass

    OK s_zero,    s_zero_n,    0
    OK s_one,     s_one_n,     1
    OK s_5,       s_5_n,       5
    OK s_lead0,   s_lead0_n,   5
    OK s_big,     s_big_n,     200000
    OK s_2_62,    s_2_62_n,    4611686018427387904
    OK s_2_63m,   s_2_63m_n,   9223372036854775807
    OK s_div10,   s_div10_n,   1844674407370955161
    OK s_div10_5, s_div10_5_n, 18446744073709551615
    OK s_max,     s_max_n,     18446744073709551615

    RANGE r_2_64,    r_2_64_n
    RANGE r_2_64p1,  r_2_64p1_n
    RANGE r_div10_6, r_div10_6_n
    RANGE r_2_62_0,  r_2_62_0_n
    RANGE r_40,      r_40_n
    RANGE r_21z,     r_21z_n

    SYNTAX b_alpha, b_alpha_n
    SYNTAX b_space, b_space_n
    SYNTAX b_tail,  b_tail_n
    SYNTAX b_sign,  b_sign_n
    SYNTAX b_neg,   b_neg_n
    SYNTAX b_list,  b_list_n
    SYNTAX b_hex,   b_hex_n
    ; an empty value is not a number either -- it is what a bare
    ; "Content-Length:" line carries, and h3 answered it 431 once
    SYNTAX b_alpha, 0

    ; A fault must not leave a partial value behind for a caller that only
    ; looked at rax: both bad verdicts return zero.
    lea rdi, [r_2_64]
    mov esi, r_2_64_n
    call linnea_string_to_u64
    inc r14d
    test rax, rax
    jnz .zero_bad
    inc r15d
.zero_bad:

    lea rdi, [msg]
    mov esi, msg_len
    call linnea_print_stdout
    mov edi, r15d
    call linnea_print_u64_stdout
    lea rdi, [slash]
    mov esi, 1
    call linnea_print_stdout
    mov edi, r14d
    call linnea_print_u64_stdout
    lea rdi, [nl]
    mov esi, 1
    call linnea_print_stdout

    xor edi, edi
    cmp r15d, r14d
    je .exit
    mov edi, 1
.exit:
    mov eax, 60
    syscall
