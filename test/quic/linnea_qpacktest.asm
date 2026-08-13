; linnea_qpacktest.asm — test-only: read a QPACK-encoded field section on stdin,
; decode it with linnea_qpack_decode, and print the recovered pseudo-headers
; (:method, :path, :scheme, :authority) each on their own line. Exits non-zero
; on a decode error. Driven by qpack_test.py, which encodes with pylsqpack.

%include "linnea_syscall.inc"
%include "linnea_hpack.inc"

global _start
extern linnea_qpack_decode
extern linnea_qpack_encode_response
extern linnea_qpack_reset_response
extern linnea_qpack_location_ptr
extern linnea_qpack_location_len
extern linnea_qpack_hsts_ptr
extern linnea_qpack_hsts_len

section .rodata
enc_label: db "qpack-encode "
enc_label_len equ $ - enc_label
enc_slash: db "/"
enc_nl:    db 10
ct_text:   db "text/plain; charset=utf-8"
ct_text_len equ $ - ct_text
clen_text: db "0"

section .bss
inbuf:    resb 8192
scratch:  resb 8192
hbuf:     resb 8192
req:      resb linnea_h2_req_size
; The encoder writes here. ENC_LIMIT is the "buffer" it is told it has; the
; bytes above it are a canary, so a write past the limit is visible rather than
; merely out of bounds somewhere harmless. That is the whole point: the
; overflow this guards against was silent — it landed in a neighbouring buffer
; nothing read again, so only a canary can fail the test.
ENC_LIMIT equ 512
ENC_CANARY equ 4096
encbuf:   resb ENC_LIMIT + ENC_CANARY
locbuf:   resb 4096

section .text
_start:
    ; argv[1] (any value) selects the encoder-bound checks instead of the
    ; stdin decode, so qpack_test.py keeps its contract untouched
    cmp qword [rsp], 1
    ja encode_checks
    ; read the encoded field section from stdin
    xor eax, eax                     ; read
    xor edi, edi                     ; fd 0
    lea rsi, [inbuf]
    mov edx, 8192
    syscall
    test rax, rax
    js .fail
    mov r12, rax                     ; block length
    ; zero the req struct
    lea rdi, [req]
    xor eax, eax
    mov ecx, linnea_h2_req_size
    rep stosb
    ; scratch region for Huffman-decoded literals
    lea rax, [scratch]
    mov [req + linnea_h2_req.scratch], rax
    lea rax, [scratch + 8192]
    mov [req + linnea_h2_req.scratch_end], rax
    ; arm the proxy header rebuild, so the decode also produces the h1 lines an
    ; upstream would be sent — the same shared path h2 and h3 both rely on
    lea rax, [hbuf]
    mov [req + linnea_h2_req.hb_start], rax
    mov [req + linnea_h2_req.hb_cur], rax
    lea rax, [hbuf + 8192]
    mov [req + linnea_h2_req.hb_end], rax
    ; decode
    lea rdi, [inbuf]
    mov rsi, r12
    lea rdx, [req]
    call linnea_qpack_decode
    test rax, rax
    jnz .fail
    ; print :method, :path, :scheme, :authority each on its own line
    mov rdi, [req + linnea_h2_req.method_ptr]
    mov rsi, [req + linnea_h2_req.method_len]
    call .putline
    mov rdi, [req + linnea_h2_req.path_ptr]
    mov rsi, [req + linnea_h2_req.path_len]
    call .putline
    mov rdi, [req + linnea_h2_req.scheme_ptr]
    mov rsi, [req + linnea_h2_req.scheme_len]
    call .putline
    mov rdi, [req + linnea_h2_req.auth_ptr]
    mov rsi, [req + linnea_h2_req.auth_len]
    call .putline
    ; then the rebuilt forwardable headers, verbatim (they carry their own CRLFs)
    mov rsi, [req + linnea_h2_req.hb_cur]
    lea rdi, [hbuf]
    sub rsi, rdi                     ; bytes the rebuild produced
    jbe .done                        ; none, or parked past the end on overflow
    mov rdx, rsi
    lea rsi, [hbuf]
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    syscall
.done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; .putline(rdi=ptr, rsi=len) — write the field (if present) then a newline.
.putline:
    push rdi
    push rsi
    test rdi, rdi
    jz .nl
    mov rdx, rsi
    mov rsi, rdi
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    syscall
.nl:
    mov byte [inbuf + 8100], 10
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [inbuf + 8100]
    mov edx, 1
    syscall
    pop rsi
    pop rdi
    ret
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; --- the encoder's output bound --------------------------------------------
; linnea_qpack_encode_response assembles a field section into a buffer the
; caller owns. It used to take no limit and write whatever it was given, while
; linnea_qpack_encode_proxy — same file, same job for a relayed head — had
; carried one all along. The gap was reachable from the wire: a redirect's
; Location is the configured target plus the CLIENT's request target, so a long
; path produced a section far past the end of a 768-byte buffer, and nothing
; noticed because the bytes landed somewhere nothing read again.
;
; So these checks put a canary above the limit and assert both halves: the call
; refuses (-1), and the canary is untouched. Prints "qpack-encode <pass>/<n>".
encode_checks:
    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; passed

    ; (1) control: a section that FITS must still be produced, and must leave
    ; the canary alone. Without this the checks below would pass on an encoder
    ; that simply never wrote anything.
    call enc_fill
    call linnea_qpack_reset_response
    call enc_call
    inc r14d
    test rax, rax
    jle .c1_bad
    cmp rax, ENC_LIMIT
    ja .c1_bad
    inc r15d
.c1_bad:
    inc r14d
    call enc_canary_ok
    add r15d, eax

    ; (2) a Location too long for the limit: refuse, and write nothing past it.
    call enc_fill
    call linnea_qpack_reset_response
    lea rax, [locbuf]
    mov [linnea_qpack_location_ptr], rax
    mov qword [linnea_qpack_location_len], 4000   ; far past ENC_LIMIT
    call enc_call
    inc r14d
    cmp rax, -1
    je .c2_ok
    jmp .c2_done
.c2_ok:
    inc r15d
.c2_done:
    inc r14d
    call enc_canary_ok
    add r15d, eax

    ; (3) the same shape via hsts, which is emitted last: a field section that
    ; only overruns at its very end must be refused too, not truncated.
    call enc_fill
    call linnea_qpack_reset_response
    lea rax, [locbuf]
    mov [linnea_qpack_hsts_ptr], rax
    mov qword [linnea_qpack_hsts_len], 4000
    call enc_call
    mov qword [linnea_qpack_hsts_ptr], 0
    inc r14d
    cmp rax, -1
    je .c3_ok
    jmp .c3_done
.c3_ok:
    inc r15d
.c3_done:
    inc r14d
    call enc_canary_ok
    add r15d, eax

    ; report
    lea rsi, [enc_label]
    mov edx, enc_label_len
    call enc_write
    mov edi, r15d
    call enc_putu
    lea rsi, [enc_slash]
    mov edx, 1
    call enc_write
    mov edi, r14d
    call enc_putu
    lea rsi, [enc_nl]
    mov edx, 1
    call enc_write
    xor edi, edi
    cmp r15d, r14d
    je .exit
    mov edi, 1
.exit:
    mov eax, LINNEA_SYS_EXIT
    syscall

; enc_call — encode a 200 into encbuf with the limit at encbuf + ENC_LIMIT.
enc_call:
    lea rdi, [encbuf]
    mov esi, 200
    lea rdx, [ct_text]
    mov ecx, ct_text_len
    lea r8, [clen_text]
    mov r9d, 1
    lea r10, [encbuf + ENC_LIMIT]
    jmp linnea_qpack_encode_response

; enc_fill — 0xAA over the whole buffer, canary included.
enc_fill:
    lea rdi, [encbuf]
    mov eax, 0xAA
    mov ecx, ENC_LIMIT + ENC_CANARY
    rep stosb
    ret

; enc_canary_ok -> eax = 1 when every byte above the limit is still 0xAA.
enc_canary_ok:
    lea rsi, [encbuf + ENC_LIMIT]
    mov ecx, ENC_CANARY
.ck:
    cmp byte [rsi], 0xAA
    jne .bad
    inc rsi
    dec ecx
    jnz .ck
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

; enc_write(rsi=ptr, edx=len)
enc_write:
    push rdi
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    syscall
    pop rdi
    ret

; enc_putu(edi=value) — the small counts this prints are always < 100.
enc_putu:
    mov eax, edi
    xor edx, edx
    mov ecx, 10
    div ecx
    test eax, eax
    jz .one
    add al, '0'
    mov [inbuf + 8000], al
    add dl, '0'
    mov [inbuf + 8001], dl
    lea rsi, [inbuf + 8000]
    mov edx, 2
    jmp enc_write
.one:
    add dl, '0'
    mov [inbuf + 8000], dl
    lea rsi, [inbuf + 8000]
    mov edx, 1
    jmp enc_write
