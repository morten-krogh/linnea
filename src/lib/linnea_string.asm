; linnea_string.asm — string and number utilities.

default rel

global linnea_string_length
global linnea_string_equal
global linnea_string_iequal
global linnea_string_copy
global linnea_string_from_u64
global linnea_string_to_u64
global linnea_string_from_hex_u64
global linnea_string_is_token
global linnea_string_trim_ows
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


; linnea_string_trim_ows(rdi = ptr, rsi = length)
;   -> rax = pointer past any leading OWS, rdx = length with trailing OWS gone.
;
; RFC 9110 5.5: the optional whitespace around a field value belongs to the
; FIELD LINE, not to the value. HTTP/1 may relay the line as it stands, which is
; why this is not needed there -- but RFC 9113 8.2.1 forbids an HTTP/2 field
; value that starts or ends with SP or HTAB, and HTTP/3 carries no field-line
; syntax at all, so both binary emitters have to send the VALUE rather than the
; line. They each stripped a leading SP and nothing else, so a perfectly legal
; upstream "X-Note:\tvalue\t" became a malformed downstream field section
; (audit-report-14 Finding 2).
;
; Internal whitespace is untouched: that is part of the value. An all-OWS value
; trims to length 0, which is a legal empty field value and not an error.
linnea_string_trim_ows:
    mov rax, rdi
    xor edx, edx
    test rsi, rsi
    jz .to_ret
    mov rdx, rsi
.to_lead:
    test rdx, rdx
    jz .to_ret
    movzx ecx, byte [rax]
    cmp cl, ' '
    je .to_lead_step
    cmp cl, 9
    jne .to_trail
.to_lead_step:
    inc rax
    dec rdx
    jmp .to_lead
.to_trail:
    test rdx, rdx
    jz .to_ret
    movzx ecx, byte [rax + rdx - 1]
    cmp cl, ' '
    je .to_trail_step
    cmp cl, 9
    jne .to_ret
.to_trail_step:
    dec rdx
    jmp .to_trail
.to_ret:
    ret

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

; linnea_string_to_u64(rdi = ptr, rsi = len) -> rax = value, edx = verdict:
;   edx = 0  every byte is a digit and the number fits in 64 bits; rax is it
;   edx = 1  the text is empty, or carries a byte that is not an ASCII digit
;   edx = 2  the text is all digits, but the number is past 2^64-1
; rax is 0 for either fault, so a caller that ignores edx cannot use a partial
; value. Touches rax, rcx, rdx, r8 and r9 only.
;
; The one decimal parser for a Content-Length arriving on ANY protocol
; (audit-report-5 Finding 1). There were five hand-rolled copies -- HTTP/1's
; request and response heads, HTTP/2's, HTTP/3's request, HTTP/3's proxy
; response -- and three were wrong, each differently:
;
;   * The bound belongs BEFORE the multiply. "value*10 came out SMALLER, so it
;     wrapped" is not an overflow test — (2^61+1)*10 wraps to 2^62+10, which is
;     larger. HTTP/2's parser tested exactly that and had no carry check on the
;     digit at all, so 18446744073709551616 parsed as 0: a POST declaring 2^64
;     bytes and sending none was a well-formed empty request, and reached the
;     proxy backend as one. HTTP/3 re-parsed the field with no check whatever.
;   * HTTP/3's proxy tested `jc` after an `lea` — which sets no flags at all, so
;     the carry it read was the one the preceding `shl rax, 3` left, i.e. bit 61
;     of the value and nothing about the *2 or the add.
;   * The verdict must come back APART from the value: 18446744073709551615 is
;     a legal Content-Length, and a parser that says "bad" by returning -1
;     cannot tell it from a fault. HTTP/2 could not, and treated a body
;     declaring UINT64_MAX as having no usable length -- it collected the body
;     and forwarded its own count, which is the very substitution the
;     reconciliation exists to prevent.
;
; Splitting a range fault from a syntax fault is what lets HTTP/1 keep
; answering 413 for "more than we could ever accept" and 400 for "not a number".
linnea_string_to_u64:
    xor eax, eax
    xor ecx, ecx
    test rsi, rsi
    jz .tu_syntax                    ; an empty value is not a number
    mov r9, 1844674407370955161      ; (2^64-1)/10
.tu_digit:
    cmp rcx, rsi
    jae .tu_ok
    movzx r8d, byte [rdi + rcx]
    sub r8d, '0'
    cmp r8d, 9
    ja .tu_syntax
    cmp rax, r9                      ; would the multiply wrap?
    ja .tu_range
    imul rax, rax, 10
    add rax, r8                      ; ...and the digit can still carry
    jc .tu_range
    inc rcx
    jmp .tu_digit
.tu_ok:
    xor edx, edx
    ret
.tu_syntax:
    xor eax, eax
    mov edx, 1
    ret
.tu_range:
    xor eax, eax
    mov edx, 2
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
