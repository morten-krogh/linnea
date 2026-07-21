; linnea_qpack.asm — QPACK (RFC 9204) decoder for the HTTP/3 request path.
;
; Like the HPACK decoder, this runs with a zero-capacity dynamic table: we
; advertise QPACK_MAX_TABLE_CAPACITY = 0, so the peer's encoder can only
; reference the 99-entry static table and emit literals — never the dynamic
; table. That makes the decoder stateless across field sections, needs no
; encoder/decoder streams, and lets it reuse the HPACK primitives directly
; (the prefix-integer, string and Huffman codings are identical between the
; two, RFC 7541 == RFC 9204 for those pieces).
;
; linnea_qpack_decode(rdi=block, rsi=len, rdx=req *linnea_h2_req) -> rax=0|-err.
; The block is one encoded field section (the payload of an HTTP/3 HEADERS
; frame). The caller zeroes the req and sets .scratch / .scratch_end. Error
; codes are shared with HPACK (LINNEA_HPACK_ERR*).

default rel

%include "linnea_hpack.inc"
%include "linnea_qpack_data.inc"

global linnea_qpack_decode
global linnea_qpack_encode_response

extern hpack_int
extern hpack_str
extern emit_field

section .rodata
; status -> QPACK static-table index (RFC 9204 Appendix A). Statuses not listed
; are encoded as a literal with the :status name reference (index 24).
qpack_status_tab:
    dw 100, 63,  103, 24,  200, 25,  204, 64,  206, 65,  302, 66
    dw 304, 26,  400, 67,  403, 68,  404, 27,  421, 69,  425, 70
    dw 500, 71,  503, 28
qpack_status_end:

section .text

linnea_qpack_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdx                     ; req
    mov r12, rdi                     ; cursor
    lea r13, [rdi + rsi]             ; end
    ; --- field section prefix (RFC 9204 4.5.1) ---
    ; Required Insert Count: 8-bit prefix integer; must be 0 (no dynamic table).
    mov rsi, r12
    mov rdi, r13
    mov ecx, 8
    call hpack_int
    jc .err
    test rax, rax
    jnz .err
    mov r12, rsi
    ; Delta Base: sign bit (bit 7) + 7-bit prefix integer; must be 0.
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_int
    jc .err
    test rax, rax
    jnz .err
    mov r12, rsi
.next:
    cmp r12, r13
    jae .ok
    movzx eax, byte [r12]
    test al, 0x80
    jnz .indexed                     ; 1_______  Indexed Field Line
    test al, 0x40
    jnz .lit_nameref                 ; 01______  Literal w/ Name Reference
    test al, 0x20
    jnz .lit_literal                 ; 001_____  Literal w/ Literal Name
    jmp .err                         ; 000_____  post-base (dynamic): unsupported

; Indexed Field Line: 1 T index(6). T (bit 6) selects the table; only static.
.indexed:
    test al, 0x40
    jz .err                          ; dynamic table (T=0): unsupported
    mov rsi, r12
    mov rdi, r13
    mov ecx, 6
    call hpack_int
    jc .err
    mov r12, rsi
    cmp rax, QPACK_STATIC_COUNT
    jae .err_index
    shl rax, 4                       ; index * 16 (four dwords)
    lea rcx, [qpack_static_tab]
    add rcx, rax
    lea r14, [qpack_static_blob]
    mov eax, [rcx]                   ; name offset
    lea rax, [r14 + rax]             ; name ptr
    mov edx, [rcx + 4]               ; name len
    mov esi, [rcx + 8]               ; value offset
    lea rsi, [r14 + rsi]             ; value ptr
    mov edi, [rcx + 12]              ; value len
    call emit_field
    jc .err_limit
    jmp .next

; Literal Field Line with Name Reference: 01 N T name_index(4). T (bit 4)
; selects the table; N (bit 5, never-indexed) is ignored on decode.
.lit_nameref:
    test al, 0x10
    jz .err                          ; dynamic name reference: unsupported
    mov rsi, r12
    mov rdi, r13
    mov ecx, 4
    call hpack_int
    jc .err
    mov r12, rsi
    cmp rax, QPACK_STATIC_COUNT
    jae .err_index
    shl rax, 4
    lea rcx, [qpack_static_tab]
    add rcx, rax
    lea r14, [qpack_static_blob]
    mov eax, [rcx]
    lea r14, [r14 + rax]             ; name ptr (kept across hpack_str)
    mov r15d, [rcx + 4]              ; name len
    ; value: string with a 7-bit length prefix (H in bit 7)
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_str
    jc .err
    mov r12, rsi
    mov rsi, rax                     ; value ptr
    mov rdi, rdx                     ; value len
    mov rax, r14                     ; name ptr
    mov rdx, r15                     ; name len
    call emit_field
    jc .err_limit
    jmp .next

; Literal Field Line with Literal Name: 001 N H name_len(3). The name is a
; string with a 3-bit length prefix (H in bit 3); the value a 7-bit one.
.lit_literal:
    mov rsi, r12
    mov rdi, r13
    mov ecx, 3
    call hpack_str                   ; name (H flag in bit 3)
    jc .err
    mov r12, rsi
    mov r14, rax                     ; name ptr
    mov r15, rdx                     ; name len
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_str                   ; value
    jc .err
    mov r12, rsi
    mov rsi, rax                     ; value ptr
    mov rdi, rdx                     ; value len
    mov rax, r14                     ; name ptr
    mov rdx, r15                     ; name len
    call emit_field
    jc .err_limit
    jmp .next

.ok:
    xor eax, eax
    jmp .ret
.err:
    mov rax, -LINNEA_HPACK_ERR
    jmp .ret
.err_index:
    mov rax, -LINNEA_HPACK_ERR_INDEX
    jmp .ret
.err_limit:
    mov rax, -LINNEA_HPACK_ERR_LIMIT
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; qenc_int(rdi=out, rax=value, cl=N prefix bits, dl=pattern) -> rdi advanced.
; Prefix-integer encoding (RFC 7541 5.1 == RFC 9204 4.1.1). Clobbers rax/r8/r9.
qenc_int:
    mov r8d, 1
    shl r8d, cl
    dec r8d                          ; max = (1<<N)-1
    cmp rax, r8
    jae .qi_big
    or dl, al                        ; pattern | value (fits in the prefix)
    mov [rdi], dl
    inc rdi
    ret
.qi_big:
    mov r9b, dl
    or r9b, r8b                       ; pattern | max
    mov [rdi], r9b
    inc rdi
    sub rax, r8
.qi_cont:
    cmp rax, 128
    jb .qi_last
    mov r9, rax
    and r9b, 0x7f
    or r9b, 0x80
    mov [rdi], r9b
    inc rdi
    shr rax, 7
    jmp .qi_cont
.qi_last:
    mov [rdi], al
    inc rdi
    ret

; qenc_str(rdi=out, rsi=str, rdx=len) -> rdi advanced. Length prefix (N=7, no
; Huffman) then the raw bytes. Clobbers rax/rcx/r8/r9.
qenc_str:
    mov rax, rdx
    push rsi
    push rdx
    mov cl, 7
    xor edx, edx                     ; pattern 0x00 (H=0)
    call qenc_int
    pop rdx
    pop rsi
    mov rcx, rdx
    rep movsb
    ret

; linnea_qpack_encode_response(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=clen_ptr, r9=clen_len) -> rax = field-section length.
; Encodes :status (indexed if a static value, else literal with name ref 24),
; content-type (name ref 44) and content-length (name ref 4) with literal
; values. No dynamic table — matches a zero-capacity decoder.
linnea_qpack_encode_response:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 24                      ; [0]=out start, [8..11]=status digits
    mov rbx, rdi                     ; out cursor
    mov [rsp], rdi                   ; out start
    mov r12d, esi                    ; status
    mov r13, rdx                     ; content-type ptr
    mov r14, rcx                     ; content-type len
    mov r15, r8                      ; content-length ptr
    mov rbp, r9                      ; content-length len
    ; field section prefix: Required Insert Count = 0, Delta Base = 0
    mov word [rbx], 0x0000
    add rbx, 2
    ; --- :status ---
    lea rsi, [qpack_status_tab]
    lea r10, [qpack_status_end]
.st_loop:
    cmp rsi, r10
    jae .st_literal
    movzx eax, word [rsi]
    cmp eax, r12d
    je .st_found
    add rsi, 4
    jmp .st_loop
.st_found:
    movzx eax, word [rsi + 2]        ; static index
    mov rdi, rbx
    mov cl, 6
    mov dl, 0xc0                     ; indexed field line, static table
    call qenc_int
    mov rbx, rdi
    jmp .after_status
.st_literal:
    mov rdi, rbx
    mov eax, 24                      ; literal w/ name ref :status (static)
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rbx, rdi
    ; format the status as three ASCII digits
    mov eax, r12d
    xor edx, edx
    mov ecx, 100
    div ecx
    add al, '0'
    mov [rsp + 8], al
    mov eax, edx
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    mov [rsp + 9], al
    add dl, '0'
    mov [rsp + 10], dl
    mov rdi, rbx
    lea rsi, [rsp + 8]
    mov rdx, 3
    call qenc_str
    mov rbx, rdi
.after_status:
    ; --- content-type: literal with name reference (static index 44) ---
    mov rdi, rbx
    mov eax, 44
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rdi, rdi                     ; (rdi already advanced)
    mov rsi, r13
    mov rdx, r14
    call qenc_str
    mov rbx, rdi
    ; --- content-length: literal with name reference (static index 4) ---
    mov rdi, rbx
    mov eax, 4
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, r15
    mov rdx, rbp
    call qenc_str
    mov rbx, rdi
    ; length = cursor - start
    mov rax, rbx
    sub rax, [rsp]
    add rsp, 24
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
