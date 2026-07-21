; linnea_hpack.asm — HPACK (RFC 7541) decoder, HTTP/2 request path (M16).
;
; Decodes one header block (already reassembled from HEADERS + CONTINUATION)
; into request pseudo-headers. We advertise SETTINGS_HEADER_TABLE_SIZE = 0,
; so the dynamic table is always empty (see linnea_hpack.inc): the field
; representations are all parsed, but indexed references resolve only
; against the 61-entry static table and incremental-indexing inserts are
; discarded. That makes the decoder stateless across header blocks.
;
; Register discipline: linnea_hpack_decode keeps req in rbx, the input
; cursor in r12, the input end in r13 (callee-saved). hpack_int / hpack_str
; take the cursor in rsi and end in rdi and touch only caller-saved
; registers, so r12/r13 survive each call; the caller copies rsi back into
; r12 after every field.

default rel

%include "linnea_hpack.inc"
%include "linnea_hpack_data.inc"

global linnea_hpack_decode
; shared with the QPACK decoder (same Huffman code and pseudo-header logic)
global hpack_int
global hpack_str
global hpack_huffman
global emit_field

section .rodata
pseudo_method:  db ":method"
pseudo_path:    db ":path"
pseudo_scheme:  db ":scheme"
pseudo_auth:    db ":authority"
hdr_host:       db "host"

section .text

; linnea_hpack_decode(rdi=block, rsi=len, rdx=req) -> rax = 0 | -err
linnea_hpack_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdx                    ; req
    mov r12, rdi                    ; cur
    lea r13, [rdi + rsi]            ; end

.next:
    cmp r12, r13
    jae .ok                         ; consumed the whole block
    movzx eax, byte [r12]
    test al, 0x80
    jnz .indexed
    test al, 0x40
    jnz .lit_inc                    ; literal, incremental indexing
    test al, 0x20
    jnz .tsize                      ; dynamic table size update
    jmp .lit_noindex                ; never / without indexing (4-bit prefix)

; --- 6.1 Indexed Header Field --------------------------------------------
.indexed:
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_int                  ; rax = index
    jc .err
    mov r12, rsi
    test rax, rax
    jz .err                         ; index 0 is illegal
    cmp rax, HPACK_STATIC_COUNT
    ja .err_index                   ; dynamic table is empty
    lea rdx, [rax - 1]
    shl rdx, 4                      ; * HPACK_STATIC_ENTRY_SIZE (16)
    lea rsi, [hpack_static_tab]
    add rsi, rdx
    mov r8d, [rsi]                  ; name off
    mov r9d, [rsi + 4]              ; name len
    mov r10d, [rsi + 8]             ; val off
    mov r11d, [rsi + 12]            ; val len
    lea r14, [hpack_static_blob]
    lea rax, [r14 + r8]             ; name ptr
    mov rdx, r9                     ; name len
    lea rsi, [r14 + r10]            ; value ptr
    mov rdi, r11                    ; value len
    call emit_field
    jc .err_limit
    jmp .next

; --- 6.2.x Literal Header Field ------------------------------------------
.lit_inc:
    mov ecx, 6                      ; incremental indexing: 6-bit prefix
    jmp .literal
.lit_noindex:
    mov ecx, 4                      ; without / never indexed: 4-bit prefix
.literal:
    mov rsi, r12
    mov rdi, r13
    call hpack_int                  ; rax = name index (0 => literal name)
    jc .err
    mov r12, rsi
    test rax, rax
    jnz .lit_name_indexed
    mov rsi, r12                    ; literal name string
    mov rdi, r13
    mov ecx, 7
    call hpack_str                  ; rax=name ptr, rdx=name len
    jc .err
    mov r12, rsi
    mov r14, rax                    ; name ptr
    mov r15, rdx                    ; name len
    jmp .lit_value
.lit_name_indexed:
    cmp rax, HPACK_STATIC_COUNT
    ja .err_index
    lea rdx, [rax - 1]
    shl rdx, 4
    lea rsi, [hpack_static_tab]
    add rsi, rdx
    mov r8d, [rsi]                  ; name off
    mov r9d, [rsi + 4]              ; name len
    lea r14, [hpack_static_blob]
    add r14, r8                     ; name ptr
    mov r15, r9                     ; name len
.lit_value:
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_str                  ; rax=value ptr, rdx=value len
    jc .err
    mov r12, rsi
    mov rsi, rax                    ; value ptr
    mov rdi, rdx                    ; value len
    mov rax, r14                    ; name ptr
    mov rdx, r15                    ; name len
    call emit_field
    jc .err_limit
    jmp .next

; --- 6.3 Dynamic Table Size Update ---------------------------------------
.tsize:
    mov rsi, r12
    mov rdi, r13
    mov ecx, 5
    call hpack_int                  ; rax = new max size
    jc .err
    mov r12, rsi
    test rax, rax
    jnz .err                        ; our advertised max is 0
    jmp .next

.ok:
    xor eax, eax
    jmp .ret
.err:
    mov eax, -LINNEA_HPACK_ERR
    jmp .ret
.err_index:
    mov eax, -LINNEA_HPACK_ERR_INDEX
    jmp .ret
.err_limit:
    mov eax, -LINNEA_HPACK_ERR_LIMIT
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; emit_field(rax=name ptr, rdx=name len, rsi=value ptr, rdi=value len)
; Records a pseudo-header of interest into the req (rbx) and enforces the
; count / list-size bounds. CF=set if a bound is exceeded. Touches only
; caller-saved registers plus [rbx]. name_eq clobbers rcx/rsi/rdi, so the
; value ptr/len are saved around each probe.
emit_field:
    mov r8, [rbx + linnea_h2_req.nheaders]
    inc r8
    cmp r8, LINNEA_HPACK_MAX_HEADERS
    ja .ef_limit
    mov [rbx + linnea_h2_req.nheaders], r8
    mov r8, [rbx + linnea_h2_req.listsize]
    add r8, rdx
    add r8, rdi
    add r8, 32
    cmp r8, LINNEA_HPACK_MAX_LISTSIZE
    ja .ef_limit
    mov [rbx + linnea_h2_req.listsize], r8
    ; :method (len 7)
    cmp rdx, 7
    jne .not_method
    push rsi
    push rdi
    lea r9, [pseudo_method]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_method
    mov [rbx + linnea_h2_req.method_ptr], rsi
    mov [rbx + linnea_h2_req.method_len], rdi
    clc
    ret
.not_method:
    cmp rdx, 5
    jne .not_path
    push rsi
    push rdi
    lea r9, [pseudo_path]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_path
    mov [rbx + linnea_h2_req.path_ptr], rsi
    mov [rbx + linnea_h2_req.path_len], rdi
    clc
    ret
.not_path:
    cmp rdx, 7
    jne .not_scheme
    push rsi
    push rdi
    lea r9, [pseudo_scheme]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_scheme
    mov [rbx + linnea_h2_req.scheme_ptr], rsi
    mov [rbx + linnea_h2_req.scheme_len], rdi
    clc
    ret
.not_scheme:
    cmp rdx, 10
    jne .not_auth
    push rsi
    push rdi
    lea r9, [pseudo_auth]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_auth
    mov [rbx + linnea_h2_req.auth_ptr], rsi
    mov [rbx + linnea_h2_req.auth_len], rdi
    clc
    ret
.not_auth:
    cmp rdx, 4
    jne .done
    push rsi
    push rdi
    lea r9, [hdr_host]
    call name_eq
    pop rdi
    pop rsi
    jnz .done
    cmp qword [rbx + linnea_h2_req.auth_ptr], 0
    jne .done                       ; :authority wins over Host
    mov [rbx + linnea_h2_req.auth_ptr], rsi
    mov [rbx + linnea_h2_req.auth_len], rdi
.done:
    clc
    ret
.ef_limit:
    stc
    ret

; name_eq(rax=ptr, rdx=len, r9=const ptr) -> ZF=1 if the len bytes match.
; The caller has already matched the length. Clobbers rcx, rsi, rdi.
name_eq:
    mov rcx, rdx
    mov rsi, rax
    mov rdi, r9
    repe cmpsb
    ret

; hpack_int(rsi=cur, rdi=end, ecx=N prefix bits) -> rax=value, rsi advanced.
; CF=set on truncation or an over-long continuation. Caller-saved only.
hpack_int:
    mov r8d, 1
    shl r8d, cl
    dec r8d                         ; max = (1<<N) - 1
    cmp rsi, rdi
    jae .ie
    movzx eax, byte [rsi]
    inc rsi
    and eax, r8d
    cmp eax, r8d
    jne .id                         ; value fits in the prefix
    xor r11d, r11d                  ; M (continuation shift)
    mov rax, r8                     ; value = max
.il:
    cmp rsi, rdi
    jae .ie
    movzx edx, byte [rsi]
    inc rsi
    cmp r11b, 28
    ja .ie                          ; bound the magnitude
    mov r10d, edx
    and r10d, 0x7f
    mov ecx, r11d
    shl r10, cl
    add rax, r10
    add r11b, 7
    test dl, 0x80
    jnz .il
.id:
    clc
    ret
.ie:
    stc
    ret

; hpack_str(rsi=cur, rdi=end, ecx=N prefix bits) -> rax=ptr, rdx=len, rsi
; advanced. CF on error. The Huffman flag is the bit just above the N-bit length
; prefix (mask 1<<N): HPACK values use N=7 (H in bit 7); QPACK's literal name
; uses N=3 (H in bit 3). Raw literals point into the input block; Huffman
; literals decode into the req scratch region (req in rbx). Caller-saved only.
hpack_str:
    cmp rsi, rdi
    jae .serr
    mov r10d, 1
    shl r10d, cl                    ; H-flag mask = 1 << N
    movzx r8d, byte [rsi]
    and r8d, r10d                   ; H flag
    push r8
    call hpack_int                  ; rax = string length (ecx = N)
    pop r8
    jc .serr
    mov r9, rdi
    sub r9, rsi                     ; bytes available
    cmp rax, r9
    ja .serr                        ; length runs past the block
    test r8d, r8d
    jnz .shuff
    mov rdx, rax                    ; raw: point into the block
    mov rax, rsi
    add rsi, rdx
    clc
    ret
.shuff:
    push rsi                        ; save enc ptr (cur)
    push rax                        ; save enc length
    mov rdx, rax                    ; enc len
    mov r8, [rbx + linnea_h2_req.scratch]
    mov r9, [rbx + linnea_h2_req.scratch_end]
    call hpack_huffman              ; rax = decoded len
    pop r10                         ; enc length
    pop rsi                         ; enc ptr
    jc .serr
    add rsi, r10                    ; advance past the encoded bytes
    mov rdx, rax                    ; decoded len
    mov rax, [rbx + linnea_h2_req.scratch]
    lea r11, [rax + rdx]
    mov [rbx + linnea_h2_req.scratch], r11
    clc
    ret
.serr:
    stc
    ret

; hpack_huffman(rsi=enc ptr, rdx=enc len, r8=out ptr, r9=out end)
;   -> rax = decoded length, CF=set on error (overflow, EOS, bad padding).
; Canonical per-length decode (see tools/gen_hpack_tables.py). Preserves the
; decode loop's callee-saved registers so hpack_str / decode state survives.
hpack_huffman:
    push r12
    push r13
    push r14
    push r15
    push rbx
    mov r12, rsi                    ; enc cursor
    lea r13, [rsi + rdx]            ; enc end
    mov r14, r8                     ; out cursor
    mov r15, r9                     ; out end
    mov rbx, r8                     ; out start (for the length)
    xor r10d, r10d                  ; code accumulator
    xor r11d, r11d                  ; current code length
.byte_loop:
    cmp r12, r13
    jae .flush
    movzx r9d, byte [r12]           ; next encoded byte
    inc r12
    mov cl, 7                       ; bit index, MSB first
.bit_loop:
    mov eax, r9d
    shr eax, cl
    and eax, 1                      ; bit
    add r10d, r10d
    or r10d, eax                    ; code = (code << 1) | bit
    inc r11d
    cmp r11d, HPACK_HUFF_MAXLEN
    ja .herr                        ; longer than any code
    lea rax, [hpack_huff_cnt]
    mov edx, [rax + r11*4]          ; n = cnt[len]
    test edx, edx
    jz .bit_next
    lea rax, [hpack_huff_first_code]
    mov esi, [rax + r11*4]
    mov edi, r10d
    sub edi, esi                    ; d = code - first_code[len]
    cmp edi, edx                    ; unsigned d < n ?
    jae .bit_next
    lea rax, [hpack_huff_first_sym]
    mov esi, [rax + r11*4]
    add esi, edi                    ; symbol slot
    lea rax, [hpack_huff_syms]
    movzx eax, word [rax + rsi*2]
    cmp eax, HPACK_HUFF_EOS
    je .herr                        ; EOS must not appear
    cmp r14, r15
    jae .herr                       ; output overflow
    mov [r14], al
    inc r14
    xor r10d, r10d                  ; reset for the next symbol
    xor r11d, r11d
.bit_next:
    dec cl
    jns .bit_loop
    jmp .byte_loop
.flush:
    ; leftover bits must be EOS padding: at most 7 bits, all ones
    test r11b, r11b
    jz .hok
    cmp r11b, 7
    ja .herr
    mov ecx, r11d
    mov eax, 1
    shl eax, cl
    dec eax                         ; (1 << len) - 1
    cmp r10d, eax
    jne .herr
.hok:
    mov rax, r14
    sub rax, rbx                    ; decoded length
    clc
    jmp .hret
.herr:
    stc
.hret:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret
