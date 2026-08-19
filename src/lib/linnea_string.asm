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
global linnea_string_is_tchar
global linnea_u64_add_within
global linnea_chunk_ext_step

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


; linnea_string_is_tchar(dil = byte) -> eax = 1 when it may appear in a token.
; The same tchar_map linnea_string_is_token walks, one byte at a time, for the
; parsers that cannot hand over a whole span: the three chunked decoders read a
; trailer line byte by byte and have nowhere to buffer it, so they need to judge
; each byte as it arrives (audit-report-21). One bitmap, one rule, three
; callers -- the alternative is a fourth hand-rolled character class.
linnea_string_is_tchar:
    movzx eax, dil
    mov ecx, eax
    shr ecx, 3
    and eax, 7
    movzx edx, byte [tchar_map + rcx]
    bt edx, eax
    jc .tc_yes
    xor eax, eax
    ret
.tc_yes:
    mov eax, 1
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

; linnea_chunk_ext_step(rdi = state, esi = byte) -> rax
;   rax >= 0   the byte belongs to the chunk-ext; this is the state after it
;   rax == -1  the byte cannot appear here: the chunk header is malformed
;   rax == -2  the byte is the CR that legally ends the chunk-ext
;
; RFC 9112 7.1.1:
;   chunk-ext      = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
;   chunk-ext-name = token
;   chunk-ext-val  = token / quoted-string
;
; All three chunk decoders scanned an extension as a byte CLASS -- anything
; printable, plus HTAB, up to the CR -- so `4;=bad` (no name), `4;` (no
; extension at all), `4;a=` (no value), `4;a b`, `4;a,b` and `4;a="unterminated`
; were all read as well-formed chunk headers (audit-report-23). The unterminated
; quote is the one that matters: a parser that DOES track the quoted-string
; carries on past the CRLF looking for the closing quote, so it and we disagree
; about where the chunk data begins -- and that disagreement is the whole of
; request smuggling. CR and LF are not qdtext, so refusing them inside a quote
; is what keeps the line ending unambiguous.
;
; The rule is one function because it has to hold in three decoders that share
; no code: h1's chunked_decode re-parses from the body start, h2's h2p_decode
; re-scans the size line, and linnea_spill_chunked resumes byte by byte. Each
; keeps the state wherever it already keeps its own -- a register, a register,
; a connection field -- and only 0 (the start), -1 and -2 mean anything outside
; here. It lives in linnea_string.o because that object is in every link set
; while the three decoders are in three that no single harness links together,
; the same reason linnea_string_is_tchar does. Touches only rax.
CEXT_SEP    equ 0      ; between components: ';' opens one, CR ends the line
CEXT_SEPWS  equ 1      ; BWS seen, and BWS is only BWS if a ';' follows it
CEXT_NAME   equ 2      ; after ';': BWS, then a mandatory token name
CEXT_NAMED  equ 3      ; inside the name
CEXT_NAMEWS equ 4      ; BWS after a name: only '=' or ';' may follow it
CEXT_VAL    equ 5      ; after '=': BWS, then a token or a quoted-string
CEXT_VALTOK equ 6      ; inside a token value
CEXT_QSTR   equ 7      ; inside a quoted-string
CEXT_QPAIR  equ 8      ; the byte after a backslash inside one

linnea_chunk_ext_step:
    push rcx
    push rdx
    movzx esi, sil
    cmp rdi, CEXT_SEP
    je .sep
    cmp rdi, CEXT_SEPWS
    je .sepws
    cmp rdi, CEXT_NAME
    je .name
    cmp rdi, CEXT_NAMED
    je .named
    cmp rdi, CEXT_NAMEWS
    je .namews
    cmp rdi, CEXT_VAL
    je .val
    cmp rdi, CEXT_VALTOK
    je .valtok
    cmp rdi, CEXT_QSTR
    je .qstr
    cmp rdi, CEXT_QPAIR
    je .qpair
    jmp .bad                         ; no other state exists
.sep:
    cmp esi, ';'
    je .go_name
    cmp esi, 13
    je .eol
    cmp esi, ' '
    je .go_sepws
    cmp esi, 9
    je .go_sepws
    jmp .bad
.sepws:
    cmp esi, ';'
    je .go_name
    cmp esi, ' '
    je .go_sepws
    cmp esi, 9
    je .go_sepws
    jmp .bad                         ; BWS with no ';' behind it is not BWS,
                                     ; which is what keeps "4 " malformed while
                                     ; "4 ;a=b" is not
.name:
    cmp esi, ' '
    je .go_name
    cmp esi, 9
    je .go_name
    call .tchar
    jnc .bad                         ; the name is not optional
    mov eax, CEXT_NAMED
    jmp .ret
.named:
    call .tchar
    jc .go_named
    cmp esi, '='
    je .go_val
    cmp esi, ';'
    je .go_name
    cmp esi, 13
    je .eol
    cmp esi, ' '
    je .go_namews
    cmp esi, 9
    je .go_namews
    jmp .bad
.namews:
    cmp esi, ' '
    je .go_namews
    cmp esi, 9
    je .go_namews
    cmp esi, '='
    je .go_val
    cmp esi, ';'
    je .go_name
    jmp .bad
.val:
    cmp esi, ' '
    je .go_val
    cmp esi, 9
    je .go_val
    cmp esi, '"'
    je .go_qstr
    call .tchar
    jnc .bad                         ; '=' with nothing that can be a value
    mov eax, CEXT_VALTOK
    jmp .ret
.valtok:
    call .tchar
    jc .go_valtok
    cmp esi, ';'
    je .go_name
    cmp esi, 13
    je .eol
    cmp esi, ' '
    je .go_sepws
    cmp esi, 9
    je .go_sepws
    jmp .bad
.qstr:
    ; qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
    cmp esi, '"'
    je .go_sep                       ; the value ends here
    cmp esi, '\'
    je .go_qpair
    cmp esi, 9
    je .go_qstr
    cmp esi, 0x20
    jb .bad
    cmp esi, 0x7f
    je .bad
    jmp .go_qstr
.qpair:
    ; quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text ): a quote or a backslash
    ; is an ordinary byte here, which is the point of the escape
    cmp esi, 9
    je .go_qstr
    cmp esi, 0x20
    jb .bad
    cmp esi, 0x7f
    je .bad
    jmp .go_qstr
.go_sep:
    mov eax, CEXT_SEP
    jmp .ret
.go_sepws:
    mov eax, CEXT_SEPWS
    jmp .ret
.go_name:
    mov eax, CEXT_NAME
    jmp .ret
.go_named:
    mov eax, CEXT_NAMED
    jmp .ret
.go_namews:
    mov eax, CEXT_NAMEWS
    jmp .ret
.go_val:
    mov eax, CEXT_VAL
    jmp .ret
.go_valtok:
    mov eax, CEXT_VALTOK
    jmp .ret
.go_qstr:
    mov eax, CEXT_QSTR
    jmp .ret
.go_qpair:
    mov eax, CEXT_QPAIR
    jmp .ret
.eol:
    mov rax, -2
    jmp .ret
.bad:
    mov rax, -1
.ret:
    pop rdx
    pop rcx
    ret
.tchar:                              ; CF = 1 when the byte in esi is a tchar
    mov eax, esi
    mov ecx, eax
    shr ecx, 3
    and eax, 7
    movzx edx, byte [tchar_map + rcx]
    bt edx, eax
    ret
