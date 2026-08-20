; linnea_static.asm — static-file resolution shared by the HTTP/2 and HTTP/3
; serve paths (and protocol-independent generally): request-target
; normalization, opening/mapping the file, and the extension -> MIME table.
; Extracted from linnea_http2.asm so h2 and h3 resolve and reject paths
; identically, and so the h3 path does not drag in the h2 connection machinery.

default rel

%include "linnea_syscall.inc"

LINNEA_STATIC_MAX_PATH equ 2048     ; bound on the decoded path length

global linnea_static_normalize
global linnea_static_open
global linnea_static_open_enc
global linnea_static_mime
global linnea_static_mtime
global linnea_static_validators
global linnea_static_etag
global linnea_static_etag_len
global linnea_static_lastmod
global linnea_http_ae_accepts
global linnea_http_identity_refused
global linnea_http_inm_match
global linnea_http_etag_match
global linnea_http_ifrange_match
global linnea_http_range_parse

extern linnea_string_iequal
extern linnea_string_equal
extern linnea_time_parse_http_date
extern linnea_string_from_hex_u64
extern linnea_time_http_date

%include "linnea_time.inc"

section .text
; linnea_static_normalize(rdi=dst, rsi=raw, rdx=raw len) -> rax = end ptr (0 = 400),
; r9 = directory flag. Percent-decodes then normalizes ".."/"."/"" in place,
; refusing traversal above the root. Ported from the HTTP/1.1 handler.
linnea_static_normalize:
    push r13
    cmp rdx, LINNEA_STATIC_MAX_PATH
    ja .zbad
    mov r13, rdi                     ; start of decoded target
    mov rcx, rdx                     ; raw length
    xor edx, edx                     ; raw index
.zdec:
    cmp rdx, rcx
    jae .zdecoded
    movzx eax, byte [rsi + rdx]
    cmp al, '?'
    je .zdecoded                     ; the query string is not part of the path
    cmp al, '%'
    je .zpct
    cmp al, 0x20
    jb .zbad                         ; a raw control byte: NUL truncates the name
    cmp al, 0x7f                     ; at open(2) while the MIME lookup keeps
    je .zbad                         ; reading past it, and CR/LF forges a second
    mov [rdi], al                    ; request line in a proxied head
    inc rdi
    inc rdx
    jmp .zdec
.zpct:
    lea rax, [rdx + 3]
    cmp rax, rcx
    ja .zbad
    movzx eax, byte [rsi + rdx + 1]
    call .zhex
    test eax, eax
    js .zbad
    mov r8d, eax
    movzx eax, byte [rsi + rdx + 2]
    call .zhex
    test eax, eax
    js .zbad
    shl r8d, 4
    or eax, r8d
    jz .zbad                         ; %00 truncates the path
    cmp al, 0x20                     ; and no encoded control byte either
    jb .zbad
    cmp al, 0x7f
    je .zbad
    mov [rdi], al
    inc rdi
    add rdx, 3
    jmp .zdec
.zdecoded:
    cmp byte [r13], '/'
    jne .zbad
    mov rsi, r13                     ; read cursor
    mov rcx, rdi                     ; end of decoded input
    mov rdi, r13                     ; write cursor
    xor r9d, r9d                     ; directory flag
.znl:
    cmp rsi, rcx
    jae .znd
    inc rsi
    mov rdx, rsi
.zse:
    cmp rdx, rcx
    jae .zhs
    cmp byte [rdx], '/'
    je .zhs
    inc rdx
    jmp .zse
.zhs:
    mov rax, rdx
    sub rax, rsi                     ; segment length
    test rax, rax
    jz .zskip
    cmp rax, 1
    jne .znnd
    cmp byte [rsi], '.'
    je .zskip
    jmp .zcp
.znnd:
    cmp rax, 2
    jne .zcp
    cmp word [rsi], '..'
    jne .zcp
    cmp rdi, r13
    jbe .zbad                        ; ".." above the root
    dec rdi
.zpop:
    cmp rdi, r13
    jbe .zskip
    cmp byte [rdi], '/'
    je .zskip
    dec rdi
    jmp .zpop
.zskip:
    cmp rdx, rcx
    jb .znx
    mov r9d, 1
    jmp .znx
.zcp:
    mov byte [rdi], '/'
    inc rdi
.zcpl:
    cmp rsi, rdx
    jae .zcpd
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    jmp .zcpl
.zcpd:
    xor r9d, r9d
.znx:
    mov rsi, rdx
    jmp .znl
.znd:
    cmp rdi, r13
    jne .zok
    mov byte [rdi], '/'              ; the root itself
    inc rdi
    mov r9d, 1
.zok:
    mov rax, rdi
    pop r13
    ret
.zbad:
    xor eax, eax
    pop r13
    ret
.zhex:                               ; al -> eax (nibble), -1 if not hex
    cmp al, '0'
    jb .zhbad
    cmp al, '9'
    jbe .zhdig
    or al, 0x20
    cmp al, 'a'
    jb .zhbad
    cmp al, 'f'
    ja .zhbad
    movzx eax, al
    sub eax, 'a' - 10
    ret
.zhdig:
    movzx eax, al
    sub eax, '0'
    ret
.zhbad:
    mov eax, -1
    ret


; linnea_static_open(rdi=path cstr) -> rax = base (0 = missing/irregular), rdx = size.
; A non-empty regular file is mapped read-only; an empty file returns the
; sentinel base 1 with size 0 (found, but nothing to map).
linnea_static_open:
    push rbx
    push r12
    xor esi, esi                     ; O_RDONLY
    xor edx, edx
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .omiss
    mov rbx, rax                     ; fd
    mov rdi, rax
    lea rsi, [static_statbuf]
    mov eax, LINNEA_SYS_FSTAT
    syscall
    cmp rax, -4095
    jae .oreject
    mov eax, [static_statbuf + LINNEA_STAT_ST_MODE]
    and eax, LINNEA_S_IFMT
    cmp eax, LINNEA_S_IFREG
    jne .oreject
    mov rax, [static_statbuf + LINNEA_STAT_ST_MTIME]
    mov [linnea_static_mtime], rax   ; for the caller's validators (ETag/Last-Modified)
    mov r12, [static_statbuf + LINNEA_STAT_ST_SIZE]
    test r12, r12
    jz .oempty
    mov rsi, r12                     ; size
    xor edi, edi
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, ebx                     ; fd
    xor r9d, r9d
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .oreject
    push rax
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop rax
    mov rdx, r12
    pop r12
    pop rbx
    ret
.oempty:
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov eax, 1
    xor edx, edx
    pop r12
    pop rbx
    ret
.oreject:
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
.omiss:
    xor eax, eax
    xor edx, edx
    pop r12
    pop rbx
    ret

; linnea_static_open_enc(rdi=path start, rsi=path end, rdx=Accept-Encoding
;   value ptr (0 = none), rcx=its len) -> rax = base (0 = miss, 1 = empty),
;   rdx = size, r8 = coding served (0 plain, 1 gzip, 2 br), r9 = 1 when the
;   client refused the unencoded form and no coded variant was acceptable --
;   rax is 0 there and the caller answers 406, not 404.
; Content-encoding negotiation, the h1 recipe shared: a pre-compressed file
; sitting beside the plain one is the whole opt-in — when the client's
; Accept-Encoding allows the coding and "<path>.br" (tried first: it
; compresses better) or "<path>.gz" is there, that variant is served.
; The suffix and NUL are written at path end (the caller's buffer has room);
; the caller's MIME lookup keeps using the name before the suffix, and the
; validators describe the variant actually opened.
linnea_static_open_enc:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rsi                     ; path end
    mov r12, rdx                     ; the caller's array of (ptr,len) spans
    mov r13, rcx                     ; how many of them
    mov r14, rdi                     ; path start
    test r13, r13
    jz .oe_plain                     ; no Accept-Encoding: nothing to negotiate
    lea rdi, [enc_br_st]
    mov esi, enc_br_st_len
    call .oe_any_accepts
    test eax, eax
    jz .oe_try_gz
    mov dword [rbx], '.br'           ; three bytes and the NUL
    mov rdi, r14
    call linnea_static_open
    test rax, rax
    jz .oe_try_gz
    mov r8d, 2
    xor r9d, r9d
    jmp .oe_ret
.oe_try_gz:
    lea rdi, [enc_gzip_st]
    mov esi, enc_gzip_st_len
    call .oe_any_accepts
    test eax, eax
    jz .oe_plain
    mov dword [rbx], '.gz'
    mov rdi, r14
    call linnea_static_open
    test rax, rax
    jz .oe_plain
    mov r8d, 1
    xor r9d, r9d
    jmp .oe_ret
.oe_plain:
    ; the fallback is the unencoded form, so this is where it matters whether
    ; the client will take it: identity;q=0 forbids it, and nothing else we
    ; could send is acceptable either or we would have sent it above
    mov rdi, r12
    mov rsi, r13
    call linnea_http_identity_refused
    test eax, eax
    jnz .oe_unacceptable
    mov byte [rbx], 0                ; drop whichever suffix was tried
    mov rdi, r14
    call linnea_static_open
    xor r8d, r8d
    xor r9d, r9d
    jmp .oe_ret
.oe_unacceptable:
    xor eax, eax                     ; nothing to serve...
    xor edx, edx
    xor r8d, r8d
    mov r9d, 1                       ; ...and it is a 406, not a 404
.oe_ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; .oe_any_accepts(rdi = coding, esi = its length) -> eax = 1 when ANY of the
; caller's Accept-Encoding spans accepts it. Repeated field lines are the
; comma-joined value, so asking each in turn is the same question as asking the
; join, without copying anything -- the shape HTTP/1 has used since h1-14.
; Preserves r12/r13/r14/rbx, which the caller is holding.
.oe_any_accepts:
    push rbx
    push r15
    push rdi
    push rsi
    xor r15d, r15d                   ; span cursor
.oe_span:
    cmp r15, r13
    jae .oe_span_no
    mov rbx, r15
    shl rbx, 4
    add rbx, r12
    mov rdi, [rbx]
    mov rsi, [rbx + 8]
    mov rdx, [rsp + 8]               ; the coding, as pushed
    mov ecx, [rsp]
    call linnea_http_ae_accepts
    inc r15
    test eax, eax
    jz .oe_span
    mov eax, 1
    jmp .oe_span_ret
.oe_span_no:
    xor eax, eax
.oe_span_ret:
    add rsp, 16                      ; the coding and its length
    pop r15
    pop rbx
    ret

; linnea_static_validators(rdi=mtime, rsi=size) — format the response validators
; for the file just opened into linnea_static_etag / linnea_static_lastmod,
; setting linnea_static_etag_len. The ETag is "<hex mtime>-<hex size>" in
; quotes, the same recipe as the HTTP/1.1 handler's, so a client that switches
; protocols revalidates against an identical tag. Single-threaded per worker,
; like every other response scratch buffer here.
linnea_static_validators:
    push rbx
    push r12
    mov rbx, rsi                     ; size
    mov r12, rdi                     ; mtime
    lea rax, [linnea_static_etag]
    mov byte [rax], '"'
    lea rsi, [linnea_static_etag + 1]
    call linnea_string_from_hex_u64  ; rax = digits written
    lea rcx, [linnea_static_etag + 1]
    add rcx, rax
    mov byte [rcx], '-'
    inc rcx
    push rcx
    mov rdi, rbx                     ; size
    mov rsi, rcx
    call linnea_string_from_hex_u64
    pop rcx
    add rcx, rax
    mov byte [rcx], '"'
    inc rcx
    lea rax, [linnea_static_etag]
    sub rcx, rax
    mov [linnea_static_etag_len], rcx
    mov rdi, r12                     ; mtime
    lea rsi, [linnea_static_lastmod]
    call linnea_time_http_date
    pop r12
    pop rbx
    ret

; linnea_static_mime(rdi=name ptr, rsi=name len) -> rax = mime ptr, rdx = mime len.
linnea_static_mime:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    lea r13, [rdi + rsi]             ; name end
    mov rcx, r13
.uscan:
    cmp rcx, r12
    jbe .udefault
    movzx eax, byte [rcx - 1]
    cmp al, '/'
    je .udefault
    cmp al, '.'
    je .ufound
    dec rcx
    jmp .uscan
.ufound:
    mov r14, rcx                     ; extension bytes (after the '.')
    mov r15, r13
    sub r15, rcx                     ; extension length
    lea r12, [mime_table_h2]
.uloop:
    mov rdx, [r12]
    test rdx, rdx
    jz .udefault
    mov rdi, r14
    mov rsi, r15
    mov rcx, [r12 + 8]
    call linnea_string_iequal
    test eax, eax
    jnz .umatch
    add r12, 32
    jmp .uloop
.umatch:
    mov rax, [r12 + 16]
    mov rdx, [r12 + 24]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.udefault:
    lea rax, [mime_default_h2]
    mov edx, mime_default_h2_len
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; --- request-evaluation helpers (conditionals, ranges, codings) ---
; Shared by the HTTP/1.1, h2 and h3 serve paths; they live here, not in
; linnea_http.asm, so the h3 test binaries can link them without dragging
; in the whole TCP front end.

; linnea_http_ae_accepts(rdi=value, rsi=len, rdx=token, rcx=token len) -> rax
; 1 when an Accept-Encoding names this coding and does not refuse it with
; q=0. Relative q values are not compared: linnea has exactly two variants
; and its own preference between them (br first), so all it needs to know
; is whether a coding is allowed at all. "*" is not honoured — it would
; mean guessing which coding the client meant.
;
; rdx comes back 1 when the coding was NAMED at all, whatever its q. A caller
; that only wants "may I send this?" ignores it; the identity check below needs
; it, because "not mentioned" and "mentioned with q=0" are opposite answers for
; the unencoded form: absent, identity is acceptable by default (RFC 9110
; 12.5.3); named with q=0, it is forbidden. Returning only "accepted" collapsed
; the two, which is why identity;q=0 went unnoticed for as long as it did.
; Locals: [rsp+0] token end (linnea_string_iequal clobbers rcx)
;         [rsp+8] the found flag, which no register survives the compare
linnea_http_ae_accepts:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov rbx, rdi               ; value
    mov r12, rsi               ; value len
    mov r13, rdx               ; token
    mov r14, rcx               ; token len
    mov qword [rsp + 8], 0     ; not named yet
    xor r15d, r15d             ; cursor
.element:
    cmp r15, r12
    jae .no
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .element_skip
    cmp al, 9
    je .element_skip
    cmp al, ','
    je .element_skip
    jmp .token_start
.element_skip:
    inc r15
    jmp .element
.token_start:
    mov rcx, r15
.token_scan:
    cmp rcx, r12
    jae .token_end
    movzx eax, byte [rbx + rcx]
    cmp al, ','
    je .token_end
    cmp al, ';'
    je .token_end
    cmp al, ' '
    je .token_end
    cmp al, 9
    je .token_end
    inc rcx
    jmp .token_scan
.token_end:
    mov [rsp], rcx
    mov rax, rcx
    sub rax, r15               ; candidate length
    lea rdi, [rbx + r15]
    mov rsi, rax
    mov rdx, r13
    mov rcx, r14
    call linnea_string_iequal
    mov rcx, [rsp]
    test eax, eax
    jnz .matched
.to_comma:                     ; some other coding: skip the whole element
    cmp rcx, r12
    jae .no
    cmp byte [rbx + rcx], ','
    je .comma
    inc rcx
    jmp .to_comma
.comma:
    lea r15, [rcx + 1]
    jmp .element
.matched:
    mov qword [rsp + 8], 1     ; named; the q below decides whether it is allowed
    mov r15, rcx               ; parameters may still refuse it
.param_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .param_ws_next
    cmp al, 9
    je .param_ws_next
    jmp .param
.param_ws_next:
    inc r15
    jmp .param_ws
.param:
    cmp al, ';'
    jne .yes                   ; end of the element: no q at all
    inc r15
.q_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .q_ws_next
    cmp al, 9
    je .q_ws_next
    jmp .q_name
.q_ws_next:
    inc r15
    jmp .q_ws
.q_name:
    or al, 0x20                ; ASCII lowercase
    cmp al, 'q'
    jne .yes                   ; some other parameter: leave it accepted
    inc r15
.eq_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .eq_ws_next
    cmp al, 9
    je .eq_ws_next
    jmp .eq
.eq_ws_next:
    inc r15
    jmp .eq_ws
.eq:
    cmp al, '='
    jne .yes
    inc r15
.value_ws:
    cmp r15, r12
    jae .yes
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .value_ws_next
    cmp al, 9
    je .value_ws_next
    jmp .value
.value_ws_next:
    inc r15
    jmp .value_ws
.value:
    cmp al, '0'                ; only q=0, in its various spellings, refuses
    jne .yes
    inc r15
    cmp r15, r12
    jae .no                    ; bare "0"
    cmp byte [rbx + r15], '.'
    jne .no                    ; "0" then a separator
    inc r15
.fraction:
    cmp r15, r12
    jae .no                    ; "0." and zeros all the way
    movzx eax, byte [rbx + r15]
    cmp al, '0'
    je .fraction_next
    sub eax, '1'
    cmp eax, 8
    jbe .yes                   ; a nonzero digit: 0.001 still allows it
    jmp .no                    ; the value ended: every digit was zero
.fraction_next:
    inc r15
    jmp .fraction
.yes:
    mov eax, 1
    jmp .ret
.no:
    xor eax, eax
.ret:
    mov rdx, [rsp + 8]         ; was it named at all?
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_http_identity_refused(rdi = span array, rsi = span count) -> rax = 1
; when any Accept-Encoding line names `identity` with q=0.
;
; RFC 9110 12.5.3: a representation with no content coding "is acceptable by
; default unless specifically excluded" -- and identity;q=0 excludes it. The
; negotiation only ever asked whether br or gzip was allowed, never whether the
; form it actually falls back to was, so a client that refused the unencoded
; representation was served it (audit-report-35).
;
; `*;q=0` would exclude it too, and is deliberately not handled here for the
; reason ae_accepts gives for `*` generally: it would mean guessing. Written
; down rather than left implied.
linnea_http_identity_refused:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    xor r13d, r13d
.ir_span:
    cmp r13, r12
    jae .ir_no
    mov rax, r13
    shl rax, 4
    mov rdi, [rbx + rax]
    mov rsi, [rbx + rax + 8]
    lea rdx, [enc_identity_st]
    mov ecx, enc_identity_st_len
    call linnea_http_ae_accepts       ; rax = allowed, rdx = named at all
    inc r13
    test rdx, rdx
    jz .ir_span                       ; this line never mentions identity
    test eax, eax
    jnz .ir_span                      ; mentioned and allowed
    mov eax, 1                        ; mentioned and refused
    jmp .ir_ret
.ir_no:
    xor eax, eax
.ir_ret:
    pop r13
    pop r12
    pop rbx
    ret

; linnea_http_inm_match(rdi=value, rsi=len, rdx=etag, rcx=etag len) -> rax
; 1 if an If-None-Match value matches our entity-tag. The value is "*", or
; a comma-separated list of entity-tags, each optionally weak ("W/"). The
; comparison is weak (RFC 9110 13.1.2): the W/ prefix does not affect a
; match, so it is simply skipped. The etag we are handed carries its
; quotes, and so does each candidate.
;
; linnea_http_etag_match takes the same arguments plus r8 = 1 for a STRONG
; comparison, which is what If-Match wants (13.1.1): a weak candidate can never
; match, so it is skipped rather than compared. inm_match is that routine with
; the flag cleared.
; Locals: [rsp+0] closing-quote offset (linnea_string_equal clobbers rcx)
;         [rsp+8] strong flag — a register would not survive the compare, which
;                 is the same reason the offset above is spilled
linnea_http_inm_match:
    xor r8d, r8d               ; weak comparison
linnea_http_etag_match:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov rbx, rdi               ; value
    mov r12, rsi               ; value len
    mov r13, rdx               ; our etag
    mov r14, rcx               ; our etag len
    mov [rsp + 8], r8          ; strong?
    xor r15d, r15d             ; cursor
.next:
    cmp r15, r12
    jae .no
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .skip
    cmp al, 9
    je .skip
    cmp al, ','
    je .skip
    jmp .candidate
.skip:
    inc r15
    jmp .next
.candidate:
    cmp al, '*'
    je .yes                    ; matches any representation, and we have one
    cmp al, 'W'
    jne .strong_ok
    lea rax, [r15 + 1]
    cmp rax, r12
    jae .no
    cmp byte [rbx + rax], '/'
    jne .no
    add r15, 2
    ; a weak tag under a strong comparison cannot match anything, but the tags
    ; after it still can — so step over this one rather than failing the list
    cmp qword [rsp + 8], 0
    je .quoted
    cmp r15, r12
    jae .no
    cmp byte [rbx + r15], '"'
    jne .no
    lea rcx, [r15 + 1]
.weak_skip:
    cmp rcx, r12
    jae .no
    cmp byte [rbx + rcx], '"'
    je .weak_skipped
    inc rcx
    jmp .weak_skip
.weak_skipped:
    lea r15, [rcx + 1]
    jmp .next
.strong_ok:
.quoted:
    cmp r15, r12
    jae .no
    cmp byte [rbx + r15], '"'
    jne .no                    ; not an entity-tag: nothing here can match
    lea rcx, [r15 + 1]
.find_close:
    cmp rcx, r12
    jae .no                    ; unterminated
    cmp byte [rbx + rcx], '"'
    je .close_found
    inc rcx
    jmp .find_close
.close_found:
    mov [rsp], rcx
    mov rax, rcx
    sub rax, r15
    inc rax                    ; candidate length, quotes included
    lea rdi, [rbx + r15]
    mov rsi, rax
    mov rdx, r13
    mov rcx, r14
    call linnea_string_equal
    test eax, eax
    jnz .yes
    mov r15, [rsp]
    inc r15                    ; past the closing quote, on to the next tag
    jmp .next
.yes:
    mov eax, 1
    jmp .ret
.no:
    xor eax, eax
.ret:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_http_ifrange_match(rdi=value, rsi=len, rdx=etag, rcx=etag len,
;   r8=mtime) -> rax = 1 when the If-Range validator STRONG-matches our
; representation (the range may be applied), else 0 (serve the full file —
; always safe; patching a stale copy with fresh bytes would corrupt it).
; RFC 9110 13.1.5: an entity-tag must match byte-identically and must not be
; weak; a date matches only the exact instant.
linnea_http_ifrange_match:
    push rbx
    test rsi, rsi
    jz .ifr_no
    movzx eax, byte [rdi]
    cmp al, '"'
    je .ifr_etag
    cmp al, 'W'                ; "W/..." is a weak tag, which can never
    jne .ifr_date              ; strong-match — but "Wed, ..." is a date
    cmp rsi, 2
    jb .ifr_no
    cmp byte [rdi + 1], '/'
    je .ifr_no
.ifr_date:
    mov rbx, r8                ; mtime, across the parse
    call linnea_time_parse_http_date
    cmp rax, -1
    je .ifr_no                 ; unparseable: not a match
    cmp rbx, rax
    jne .ifr_no                ; strong: the exact instant only
    jmp .ifr_yes
.ifr_etag:
    call linnea_string_equal   ; strong: byte-identical, case included
    test eax, eax
    jz .ifr_no
.ifr_yes:
    mov eax, 1
    pop rbx
    ret
.ifr_no:
    xor eax, eax
    pop rbx
    ret

; linnea_http_range_parse(rdi=value, rsi=len, rdx=file size) -> rax, rdx
; Parses a Range value holding a single byte range: "bytes=first-last",
; "bytes=first-" or "bytes=-suffix". Returns the byte offset in rax and
; the count in rdx, or rax = -1 when the header should be ignored
; (another unit, several ranges, malformed) or -2 when the single range
; is valid but unsatisfiable (a 416). Absurdly long numbers saturate at
; 2^62, far past any file size, and fall out as unsatisfiable or as a
; last clamped to the end. No calls, caller-saved registers only.
linnea_http_range_parse:
    mov r10, rdx               ; file size
    cmp rsi, 7                 ; "bytes=" and at least one spec byte
    jb .rp_ignore
    mov r8d, [rdi]
    or r8d, 0x20202020         ; ASCII lowercase
    cmp r8d, 'byte'
    jne .rp_ignore
    movzx r8d, byte [rdi + 4]
    or r8d, 0x20
    cmp r8b, 's'
    jne .rp_ignore
    cmp byte [rdi + 5], '='
    jne .rp_ignore
    add rdi, 6
    sub rsi, 6
    xor ecx, ecx               ; cursor
    cmp byte [rdi], '-'
    je .rp_suffix
    ; ---- first, digits up to '-' -------------------------------------
    xor eax, eax
.rp_first_loop:
    cmp rcx, rsi
    jae .rp_ignore             ; no '-' at all
    movzx r8d, byte [rdi + rcx]
    cmp r8b, '-'
    je .rp_first_done
    sub r8d, '0'
    cmp r8d, 9
    ja .rp_ignore
    imul rax, rax, 10
    add rax, r8
    mov r11, 1 << 62
    cmp rax, r11
    jbe .rp_first_next
    mov rax, r11               ; saturate
.rp_first_next:
    inc rcx
    jmp .rp_first_loop
.rp_first_done:
    inc rcx                    ; past the '-'
    cmp rcx, rsi
    jae .rp_open_end           ; "first-": everything from first on
    ; ---- last, digits to the end -------------------------------------
    xor r9d, r9d
.rp_last_loop:
    cmp rcx, rsi
    jae .rp_have_last
    movzx r8d, byte [rdi + rcx]
    sub r8d, '0'
    cmp r8d, 9
    ja .rp_ignore              ; a ',' (several ranges) lands here too
    imul r9, r9, 10
    add r9, r8
    mov r11, 1 << 62
    cmp r9, r11
    jbe .rp_last_next
    mov r9, r11                ; saturate
.rp_last_next:
    inc rcx
    jmp .rp_last_loop
.rp_have_last:
    cmp rax, r9
    ja .rp_ignore              ; first > last is not a range
    cmp rax, r10
    jae .rp_unsat              ; starts at or past the end
    lea r8, [r10 - 1]
    cmp r9, r8
    jbe .rp_last_fits
    mov r9, r8                 ; a long last means "to the end"
.rp_last_fits:
    mov rdx, r9
    sub rdx, rax
    inc rdx                    ; count = last - first + 1
    ret
.rp_open_end:
    cmp rax, r10
    jae .rp_unsat
    mov rdx, r10
    sub rdx, rax               ; to the end of the file
    ret
    ; ---- "-suffix": the last N bytes ----------------------------------
.rp_suffix:
    mov ecx, 1                 ; past the '-'
    xor eax, eax
    xor r9d, r9d               ; digit count
.rp_suffix_loop:
    cmp rcx, rsi
    jae .rp_suffix_done
    movzx r8d, byte [rdi + rcx]
    sub r8d, '0'
    cmp r8d, 9
    ja .rp_ignore
    imul rax, rax, 10
    add rax, r8
    mov r11, 1 << 62
    cmp rax, r11
    jbe .rp_suffix_next
    mov rax, r11               ; saturate
.rp_suffix_next:
    inc r9d
    inc rcx
    jmp .rp_suffix_loop
.rp_suffix_done:
    test r9d, r9d
    jz .rp_ignore              ; bare "-"
    test rax, rax
    jz .rp_unsat               ; "-0" selects nothing
    test r10, r10
    jz .rp_unsat               ; nothing to take a suffix of
    cmp rax, r10
    jbe .rp_suffix_fits
    mov rax, r10               ; longer than the file: all of it
.rp_suffix_fits:
    mov rdx, rax               ; count
    mov rax, r10
    sub rax, rdx               ; offset = size - count
    ret
.rp_ignore:
    mov rax, -1
    ret
.rp_unsat:
    mov rax, -2
    ret

section .rodata
enc_br_st:    db "br"
enc_br_st_len equ $ - enc_br_st
enc_gzip_st:  db "gzip"
enc_gzip_st_len equ $ - enc_gzip_st
enc_identity_st: db "identity"
enc_identity_st_len equ $ - enc_identity_st
ext_html_h2: db "html"
ext_css_h2:  db "css"
ext_js_h2:   db "js"
ext_json_h2: db "json"
ext_txt_h2:  db "txt"
ext_png_h2:  db "png"
ext_jpg_h2:  db "jpg"
ext_jpeg_h2: db "jpeg"
ext_gif_h2:  db "gif"
ext_svg_h2:  db "svg"
ext_ico_h2:  db "ico"
ext_mp4_h2:  db "mp4"
ext_webm_h2: db "webm"
ext_ogv_h2:  db "ogv"
ext_htm_h2: db "htm"
ext_mjs_h2: db "mjs"
ext_wasm_h2: db "wasm"
ext_webp_h2: db "webp"
ext_avif_h2: db "avif"
ext_woff2_h2: db "woff2"
ext_woff_h2: db "woff"
ext_ttf_h2: db "ttf"
ext_otf_h2: db "otf"
ext_mp3_h2: db "mp3"
ext_ogg_h2: db "ogg"
ext_wav_h2: db "wav"
ext_m4a_h2: db "m4a"
ext_aac_h2: db "aac"
ext_flac_h2: db "flac"
ext_pdf_h2: db "pdf"
ext_xml_h2: db "xml"
ext_csv_h2: db "csv"
ext_md_h2: db "md"
ext_zip_h2: db "zip"
ext_gz_h2: db "gz"
ext_map_h2: db "map"
ext_wmanifest_h2: db "webmanifest"
mime_html_h2: db "text/html; charset=utf-8"
mime_html_h2_len equ $ - mime_html_h2
mime_css_h2:  db "text/css; charset=utf-8"
mime_css_h2_len equ $ - mime_css_h2
mime_js_h2:   db "text/javascript; charset=utf-8"
mime_js_h2_len equ $ - mime_js_h2
mime_json_h2: db "application/json"
mime_json_h2_len equ $ - mime_json_h2
mime_txt_h2:  db "text/plain; charset=utf-8"
mime_txt_h2_len equ $ - mime_txt_h2
mime_png_h2:  db "image/png"
mime_png_h2_len equ $ - mime_png_h2
mime_jpeg_h2: db "image/jpeg"
mime_jpeg_h2_len equ $ - mime_jpeg_h2
mime_gif_h2:  db "image/gif"
mime_gif_h2_len equ $ - mime_gif_h2
mime_svg_h2:  db "image/svg+xml"
mime_svg_h2_len equ $ - mime_svg_h2
mime_ico_h2:  db "image/x-icon"
mime_ico_h2_len equ $ - mime_ico_h2
mime_htm_h2: db "text/html; charset=utf-8"
mime_htm_h2_len equ $ - mime_htm_h2
mime_mjs_h2: db "text/javascript; charset=utf-8"
mime_mjs_h2_len equ $ - mime_mjs_h2
mime_wasm_h2: db "application/wasm"
mime_wasm_h2_len equ $ - mime_wasm_h2
mime_webp_h2: db "image/webp"
mime_webp_h2_len equ $ - mime_webp_h2
mime_avif_h2: db "image/avif"
mime_avif_h2_len equ $ - mime_avif_h2
mime_woff2_h2: db "font/woff2"
mime_woff2_h2_len equ $ - mime_woff2_h2
mime_woff_h2: db "font/woff"
mime_woff_h2_len equ $ - mime_woff_h2
mime_ttf_h2: db "font/ttf"
mime_ttf_h2_len equ $ - mime_ttf_h2
mime_otf_h2: db "font/otf"
mime_otf_h2_len equ $ - mime_otf_h2
mime_mp3_h2: db "audio/mpeg"
mime_mp3_h2_len equ $ - mime_mp3_h2
mime_ogg_h2: db "audio/ogg"
mime_ogg_h2_len equ $ - mime_ogg_h2
mime_wav_h2: db "audio/wav"
mime_wav_h2_len equ $ - mime_wav_h2
mime_m4a_h2: db "audio/mp4"
mime_m4a_h2_len equ $ - mime_m4a_h2
mime_aac_h2: db "audio/aac"
mime_aac_h2_len equ $ - mime_aac_h2
mime_flac_h2: db "audio/flac"
mime_flac_h2_len equ $ - mime_flac_h2
mime_pdf_h2: db "application/pdf"
mime_pdf_h2_len equ $ - mime_pdf_h2
mime_xml_h2: db "application/xml"
mime_xml_h2_len equ $ - mime_xml_h2
mime_csv_h2: db "text/csv; charset=utf-8"
mime_csv_h2_len equ $ - mime_csv_h2
mime_md_h2: db "text/markdown; charset=utf-8"
mime_md_h2_len equ $ - mime_md_h2
mime_zip_h2: db "application/zip"
mime_zip_h2_len equ $ - mime_zip_h2
mime_gz_h2: db "application/gzip"
mime_gz_h2_len equ $ - mime_gz_h2
mime_map_h2: db "application/json"
mime_map_h2_len equ $ - mime_map_h2
mime_wmanifest_h2: db "application/manifest+json"
mime_wmanifest_h2_len equ $ - mime_wmanifest_h2
mime_mp4_h2:  db "video/mp4"
mime_mp4_h2_len equ $ - mime_mp4_h2
mime_webm_h2: db "video/webm"
mime_webm_h2_len equ $ - mime_webm_h2
mime_ogv_h2:  db "video/ogg"
mime_ogv_h2_len equ $ - mime_ogv_h2
mime_default_h2: db "application/octet-stream"
mime_default_h2_len equ $ - mime_default_h2
mime_table_h2:
    dq ext_html_h2, 4, mime_html_h2, mime_html_h2_len
    dq ext_css_h2,  3, mime_css_h2,  mime_css_h2_len
    dq ext_js_h2,   2, mime_js_h2,   mime_js_h2_len
    dq ext_json_h2, 4, mime_json_h2, mime_json_h2_len
    dq ext_txt_h2,  3, mime_txt_h2,  mime_txt_h2_len
    dq ext_png_h2,  3, mime_png_h2,  mime_png_h2_len
    dq ext_jpg_h2,  3, mime_jpeg_h2, mime_jpeg_h2_len
    dq ext_jpeg_h2, 4, mime_jpeg_h2, mime_jpeg_h2_len
    dq ext_gif_h2,  3, mime_gif_h2,  mime_gif_h2_len
    dq ext_svg_h2,  3, mime_svg_h2,  mime_svg_h2_len
    dq ext_ico_h2,  3, mime_ico_h2,  mime_ico_h2_len
    dq ext_mp4_h2,  3, mime_mp4_h2,  mime_mp4_h2_len
    dq ext_webm_h2, 4, mime_webm_h2, mime_webm_h2_len
    dq ext_ogv_h2,  3, mime_ogv_h2,  mime_ogv_h2_len
    dq ext_htm_h2, 3, mime_htm_h2, mime_htm_h2_len
    dq ext_mjs_h2, 3, mime_mjs_h2, mime_mjs_h2_len
    dq ext_wasm_h2, 4, mime_wasm_h2, mime_wasm_h2_len
    dq ext_webp_h2, 4, mime_webp_h2, mime_webp_h2_len
    dq ext_avif_h2, 4, mime_avif_h2, mime_avif_h2_len
    dq ext_woff2_h2, 5, mime_woff2_h2, mime_woff2_h2_len
    dq ext_woff_h2, 4, mime_woff_h2, mime_woff_h2_len
    dq ext_ttf_h2, 3, mime_ttf_h2, mime_ttf_h2_len
    dq ext_otf_h2, 3, mime_otf_h2, mime_otf_h2_len
    dq ext_mp3_h2, 3, mime_mp3_h2, mime_mp3_h2_len
    dq ext_ogg_h2, 3, mime_ogg_h2, mime_ogg_h2_len
    dq ext_wav_h2, 3, mime_wav_h2, mime_wav_h2_len
    dq ext_m4a_h2, 3, mime_m4a_h2, mime_m4a_h2_len
    dq ext_aac_h2, 3, mime_aac_h2, mime_aac_h2_len
    dq ext_flac_h2, 4, mime_flac_h2, mime_flac_h2_len
    dq ext_pdf_h2, 3, mime_pdf_h2, mime_pdf_h2_len
    dq ext_xml_h2, 3, mime_xml_h2, mime_xml_h2_len
    dq ext_csv_h2, 3, mime_csv_h2, mime_csv_h2_len
    dq ext_md_h2, 2, mime_md_h2, mime_md_h2_len
    dq ext_zip_h2, 3, mime_zip_h2, mime_zip_h2_len
    dq ext_gz_h2, 2, mime_gz_h2, mime_gz_h2_len
    dq ext_map_h2, 3, mime_map_h2, mime_map_h2_len
    dq ext_wmanifest_h2, 11, mime_wmanifest_h2, mime_wmanifest_h2_len
    dq 0


section .bss
static_statbuf:  resb LINNEA_STAT_SIZE
linnea_static_mtime:    resq 1       ; st_mtime of the last linnea_static_open
linnea_static_etag:     resb 48      ; '"' + 16 + '-' + 16 + '"' fits well inside
linnea_static_etag_len: resq 1
linnea_static_lastmod:  resb LINNEA_HTTP_DATE_LEN
