; linnea_string.asm — string and number utilities.

default rel

global linnea_string_length
global linnea_string_equal
global linnea_string_iequal
global linnea_string_copy
global linnea_string_from_u64
global linnea_string_from_hex_u64
global linnea_string_is_token
global linnea_u64_add_within

section .text

; linnea_u64_add_within(rdi = current, rsi = incoming, rdx = max) -> rax = 1 when
; current + incoming <= max with NO unsigned wrap, else 0. Assumes the caller's
; invariant current <= max (every bounded counter here is rejected before it can
; exceed max), so headroom = max - current does not underflow. Comparing incoming
; against the headroom — rather than adding first and comparing the sum — is what
; keeps a length near 2^64 from wrapping the counter past a max_body of 2^64-1
; (audit Finding 2). Touches only rax.
linnea_u64_add_within:
    mov rax, rdx
    sub rax, rdi                     ; headroom = max - current (>= 0 by invariant)
    cmp rsi, rax
    ja .over                         ; incoming > headroom: the add would wrap/exceed
    mov eax, 1
    ret
.over:
    xor eax, eax
    ret

section .rodata

; RFC 9110 5.6.2 tchar, as a 256-bit set: bit (c & 7) of byte (c >> 3) is set
; when c may appear in a token. Everything else is out — the control bytes and
; DEL, SP, the high half, and the delimiters "(),/:;<=>?@[\]{} and the quote.
; A bitmap rather than a chain of range compares because the excluded set is
; scattered through the printable range; getting that wrong by hand is how a
; delimiter slips through.
tchar_map:      db 0x00, 0x00, 0x00, 0x00, 0xfa, 0x6c, 0xff, 0x03   ; 0x00-0x3f
                db 0xfe, 0xff, 0xff, 0xc7, 0xff, 0xff, 0xff, 0x57   ; 0x40-0x7f
                db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   ; 0x80-0xbf
                db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   ; 0xc0-0xff

section .text

; linnea_string_is_token(rdi = ptr, rsi = len) -> rax = 1 when those bytes are a
; non-empty RFC 9110 5.6.2 token, else 0. Touches only caller-saved registers.
;
; A method is a token, and nothing checked that. The access log writes the method
; verbatim inside quotes, so a method carrying a double quote — a delimiter, so
; never legal — split the log line's own quoting, and an ESC or backspace rode
; into the log on h2/h3 where the h1 request-line parse would have refused it.
linnea_string_is_token:
    test rsi, rsi
    jz .nt_no                        ; a token is at least one character
.nt_next:
    movzx eax, byte [rdi]
    mov ecx, eax
    shr ecx, 3                       ; which byte of the set
    and eax, 7                       ; which bit within it
    movzx edx, byte [tchar_map + rcx]
    bt edx, eax
    jnc .nt_no
    inc rdi
    dec rsi
    jnz .nt_next
    mov eax, 1
    ret
.nt_no:
    xor eax, eax
    ret

; linnea_string_length(rdi=cstr) -> rax=len
linnea_string_length:
    xor eax, eax
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret

; linnea_string_equal(rdi=ptr1, rsi=len1, rdx=ptr2, rcx=len2) -> rax=1/0
linnea_string_equal:
    cmp rsi, rcx
    jne .no
    xor eax, eax
.loop:
    cmp rax, rsi
    jae .yes
    mov r8b, [rdi + rax]
    cmp r8b, [rdx + rax]
    jne .no
    inc rax
    jmp .loop
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; linnea_string_iequal(rdi=ptr1, rsi=len1, rdx=ptr2, rcx=len2) -> rax=1/0
; ASCII case-insensitive comparison (for HTTP header names).
linnea_string_iequal:
    cmp rsi, rcx
    jne .no
    xor eax, eax
.loop:
    cmp rax, rsi
    jae .yes
    mov r8b, [rdi + rax]
    mov r9b, [rdx + rax]
    cmp r8b, 'A'
    jb .c1
    cmp r8b, 'Z'
    ja .c1
    add r8b, 32
.c1:
    cmp r9b, 'A'
    jb .c2
    cmp r9b, 'Z'
    ja .c2
    add r9b, 32
.c2:
    cmp r8b, r9b
    jne .no
    inc rax
    jmp .loop
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; linnea_string_copy(rdi=dst, rsi=src, rdx=len) — copies len bytes, NUL-terminates.
; Caller must ensure dst has room for len + 1 bytes.
linnea_string_copy:
    mov rcx, rdx
    rep movsb
    mov byte [rdi], 0
    ret

; linnea_string_from_hex_u64(rdi=value, rsi=buf) -> rax=len
; Formats value as lowercase hex at the start of buf, no leading zeros
; (0 formats as "0"). buf must be >= 16 bytes.
linnea_string_from_hex_u64:
    mov rax, rdi
    lea r8, [rsi + 16]         ; end of buf
    mov r9, r8                 ; write cursor, moves down
.digit:
    mov ecx, eax
    and ecx, 0x0F
    cmp cl, 10
    jb .decimal
    add cl, 'a' - 10
    jmp .put
.decimal:
    add cl, '0'
.put:
    dec r9
    mov [r9], cl
    shr rax, 4
    jnz .digit
    mov rcx, r8
    sub rcx, r9                ; len
    mov rax, rcx
    mov rdi, rsi               ; dst = start of buf
    mov rsi, r9                ; src = first digit
    rep movsb
    ret

; linnea_string_from_u64(rdi=value, rsi=buf) -> rax=len
; Formats value as decimal digits at the start of buf. buf must be >= 20 bytes.
linnea_string_from_u64:
    mov rax, rdi
    lea r8, [rsi + 20]         ; end of buf
    mov r9, r8                 ; write cursor, moves down
    mov r10, 10
.digit:
    xor edx, edx
    div r10
    add dl, '0'
    dec r9
    mov [r9], dl
    test rax, rax
    jnz .digit
    mov rcx, r8
    sub rcx, r9                ; len
    mov rax, rcx
    mov rdi, rsi               ; dst = start of buf
    mov rsi, r9                ; src = first digit
    rep movsb
    ret
