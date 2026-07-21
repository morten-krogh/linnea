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

extern hpack_int
extern hpack_str
extern emit_field

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
