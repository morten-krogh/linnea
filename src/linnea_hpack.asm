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
global hpack_dyn_reset

section .rodata
pseudo_method:  db ":method"
pseudo_path:    db ":path"
pseudo_scheme:  db ":scheme"
pseudo_auth:    db ":authority"
hdr_host:       db "host"
hdr_priority:   db "priority"
hdr_inm:        db "if-none-match"
hdr_ims:        db "if-modified-since"
hdr_range:      db "range"
hdr_ifr:        db "if-range"
hdr_ae:         db "accept-encoding"
; names stripped from the proxy header rebuild (hop-by-hop / managed)
hdr_te:         db "te"
hdr_conn:       db "connection"
hdr_ka:         db "keep-alive"
hdr_cl2:        db "content-length"
hdr_pconn:      db "proxy-connection"
hdr_tenc:       db "transfer-encoding"
hdr_upg:        db "upgrade"

section .bss
lit_form:      resq 1

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
    ja .indexed_dyn                 ; past the static table: the peer's own
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

; An index past the static table names an entry the peer inserted earlier on
; this connection (RFC 7541 2.3.3): 62 selects the newest.
.indexed_dyn:
    mov rdi, [rbx + linnea_h2_req.dyn]
    test rdi, rdi
    jz .err_index                   ; no table (HTTP/3): undecodable
    lea rsi, [rax - HPACK_STATIC_COUNT - 1]     ; 0 = newest
    call hpack_dyn_get              ; -> rax = name, rdx = nlen, rsi = value,
    jc .err_index                   ;    rdi = vlen; CF = out of range
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
    mov [lit_form], ecx             ; the form, for the store decision below
                                    ; (a file-scope slot, not the red zone:
                                    ; hpack_int/hpack_str/emit_field all push,
                                    ; and one decode runs at a time)
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
    ja .lit_name_dyn
    lea rdx, [rax - 1]
    shl rdx, 4
    lea rsi, [hpack_static_tab]
    add rsi, rdx
    mov r8d, [rsi]                  ; name off
    mov r9d, [rsi + 4]              ; name len
    lea r14, [hpack_static_blob]
    add r14, r8                     ; name ptr
    mov r15, r9                     ; name len
    jmp .lit_value
.lit_name_dyn:
    mov rdi, [rbx + linnea_h2_req.dyn]
    test rdi, rdi
    jz .err_index
    lea rsi, [rax - HPACK_STATIC_COUNT - 1]
    call hpack_dyn_get              ; -> rax = name ptr, rdx = name len
    jc .err_index
    mov r14, rax
    mov r15, rdx
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
    mov ecx, [lit_form]             ; the representation's prefix width
    cmp ecx, 6                      ; a 6-bit prefix marks incremental
    jne .lit_emit                   ; indexing: the peer stored this field,
    push rax                        ; so we must too or its later indices
    push rdx                        ; would resolve to the wrong entry
    push rsi
    push rdi
    mov r8, [rbx + linnea_h2_req.dyn]
    test r8, r8
    jz .lit_stored
    push rcx
    call hpack_dyn_insert
    pop rcx
    test rax, rax
    js .lit_desync                   ; table out of sync with the peer: bail
.lit_stored:
    pop rdi
    pop rsi
    pop rdx
    pop rax
.lit_emit:
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
    cmp rax, LINNEA_HPACK_DYN_CAP
    ja .err                         ; larger than the protocol default
    mov rdi, [rbx + linnea_h2_req.dyn]
    test rdi, rdi
    jz .tsize_none
    mov [rdi + linnea_hpack_dyn.max], rax
    call hpack_dyn_evict            ; shrink to the new limit
    jmp .next
.tsize_none:
    test rax, rax
    jnz .err                        ; no table here: only "0" is meaningful
    jmp .next

.ok:
    xor eax, eax
    jmp .ret
.lit_desync:
    add rsp, 32                     ; drop the saved name/value ptr+len (4 qwords)
    ; fall through: an out-of-sync dynamic table is a COMPRESSION_ERROR
; 64-bit, not eax: the caller tests the sign of the whole rax, and a 32-bit
; move zero-extends, so every one of these errors arrived as a large POSITIVE
; number and the caller's `js` never fired. linnea_qpack_decode always got
; this right, which is why h3 reacted to a bad field section and h2 did not.
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
    ; --- proxy rebuild: append the field as an h1 "name: value" line -----
    cmp qword [rbx + linnea_h2_req.hb_start], 0
    je .no_rebuild
    cmp byte [rax], ':'
    je .no_rebuild                   ; pseudo-headers do not forward
    ; hop-by-hop / managed names are stripped (see linnea_hpack.inc)
    cmp rdx, 2
    je .rb_chk_te
    cmp rdx, 4
    je .rb_chk_host
    cmp rdx, 7
    je .rb_chk_upg
    cmp rdx, 10
    je .rb_chk_10
    cmp rdx, 14
    je .rb_chk_cl
    cmp rdx, 16
    je .rb_chk_pconn
    cmp rdx, 17
    je .rb_chk_tenc
    jmp .rebuild
.rb_chk_te:
    lea r9, [hdr_te]
    jmp .rb_probe
.rb_chk_host:
    lea r9, [hdr_host]
    jmp .rb_probe
.rb_chk_upg:
    lea r9, [hdr_upg]
    jmp .rb_probe
.rb_chk_cl:
    push rsi
    push rdi
    lea r9, [hdr_cl2]
    call name_eq
    pop rdi
    pop rsi
    jne .rebuild
    mov [rbx + linnea_h2_req.cl_ptr], rsi    ; kept: the proxy path forwards
    mov [rbx + linnea_h2_req.cl_len], rdi    ; it and streams the body
    jmp .no_rebuild
.rb_chk_pconn:
    lea r9, [hdr_pconn]
    jmp .rb_probe
.rb_chk_tenc:
    lea r9, [hdr_tenc]
    jmp .rb_probe
.rb_chk_10:
    push rsi
    push rdi
    lea r9, [hdr_conn]
    call name_eq
    pop rdi
    pop rsi
    je .no_rebuild
    lea r9, [hdr_ka]
.rb_probe:
    push rsi
    push rdi
    call name_eq
    pop rdi
    pop rsi
    je .no_rebuild                   ; a stripped name: capture only
.rebuild:
    push rax
    push rdx
    push rsi
    push rdi
    mov r10, [rbx + linnea_h2_req.hb_cur]
    lea r8, [r10 + rdx]
    add r8, rdi
    add r8, 4                        ; ": " + CRLF
    cmp r8, [rbx + linnea_h2_req.hb_end]
    ja .rb_over
    mov rcx, rdx
    mov rdi, r10
    mov rsi, rax
    rep movsb                        ; the name (already lowercase in h2)
    mov word [rdi], ': '
    add rdi, 2
    mov rsi, [rsp + 8]               ; value ptr
    mov rcx, [rsp]                   ; value len
    rep movsb
    mov word [rdi], 0x0a0d           ; CRLF
    add rdi, 2
    mov [rbx + linnea_h2_req.hb_cur], rdi
    jmp .rb_done
.rb_over:
    mov r10, [rbx + linnea_h2_req.hb_end]
    inc r10                          ; overflow sentinel: cur past end
    mov [rbx + linnea_h2_req.hb_cur], r10
.rb_done:
    pop rdi
    pop rsi
    pop rdx
    pop rax
.no_rebuild:
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
    cmp rdx, 8                       ; "priority" (RFC 9218) — capture its value
    jne .not_prio
    push rsi
    push rdi
    lea r9, [hdr_priority]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_prio
    mov [rbx + linnea_h2_req.prio_ptr], rsi
    mov [rbx + linnea_h2_req.prio_len], rdi
    clc
    ret
.not_prio:
    cmp rdx, 13                      ; "if-none-match"
    jne .not_inm
    push rsi
    push rdi
    lea r9, [hdr_inm]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_inm
    mov [rbx + linnea_h2_req.inm_ptr], rsi
    mov [rbx + linnea_h2_req.inm_len], rdi
    clc
    ret
.not_inm:
    cmp rdx, 17                      ; "if-modified-since"
    jne .not_ims
    push rsi
    push rdi
    lea r9, [hdr_ims]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_ims
    mov [rbx + linnea_h2_req.ims_ptr], rsi
    mov [rbx + linnea_h2_req.ims_len], rdi
    clc
    ret
.not_ims:
    cmp rdx, 5                       ; "range"
    jne .not_range
    push rsi
    push rdi
    lea r9, [hdr_range]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_range
    mov [rbx + linnea_h2_req.rng_ptr], rsi
    mov [rbx + linnea_h2_req.rng_len], rdi
    clc
    ret
.not_range:
    cmp rdx, 8                       ; "if-range"
    jne .not_ifr
    push rsi
    push rdi
    lea r9, [hdr_ifr]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_ifr
    mov [rbx + linnea_h2_req.ifr_ptr], rsi
    mov [rbx + linnea_h2_req.ifr_len], rdi
    clc
    ret
.not_ifr:
    cmp rdx, 15                      ; "accept-encoding"
    jne .not_ae
    push rsi
    push rdi
    lea r9, [hdr_ae]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_ae
    mov [rbx + linnea_h2_req.ae_ptr], rsi
    mov [rbx + linnea_h2_req.ae_len], rdi
    clc
    ret
.not_ae:
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

; --- decoder dynamic table (RFC 7541 2.3.2, 4.1, 4.4) --------------------
; Entries are copied into the connection's arena so they outlive the header
; block they arrived in. The index arrays are a ring: .head is the newest, and
; index i counts back from it. Eviction drops the oldest until the new entry
; fits; an entry larger than the whole table empties it and is not stored,
; which RFC 7541 4.4 explicitly allows.

; hpack_dyn_reset(rdi = table*) — start empty, at the protocol default size.
hpack_dyn_reset:
    mov qword [rdi + linnea_hpack_dyn.count], 0
    mov qword [rdi + linnea_hpack_dyn.head], 0
    mov qword [rdi + linnea_hpack_dyn.size], 0
    mov qword [rdi + linnea_hpack_dyn.used], 0
    mov qword [rdi + linnea_hpack_dyn.max], LINNEA_HPACK_DYN_CAP
    ret

; hpack_dyn_get(rdi = table*, rsi = i, 0 = newest)
;   -> rax = name ptr, rdx = name len, rsi = value ptr, rdi = value len.
; CF set when i is past the live entries. Caller-saved only.
hpack_dyn_get:
    cmp rsi, [rdi + linnea_hpack_dyn.count]
    jae .dg_bad
    mov rax, [rdi + linnea_hpack_dyn.head]
    sub rax, rsi
    jns .dg_slot
    add rax, LINNEA_HPACK_DYN_MAX               ; wrapped
.dg_slot:
    mov r8, [rdi + linnea_hpack_dyn.off + rax * 8]
    mov rdx, [rdi + linnea_hpack_dyn.nlen + rax * 8]
    mov r9, [rdi + linnea_hpack_dyn.vlen + rax * 8]
    lea rax, [rdi + linnea_hpack_dyn.arena]
    add rax, r8                                 ; name ptr
    lea rsi, [rax + rdx]                        ; value follows the name
    mov rdi, r9
    clc
    ret
.dg_bad:
    stc
    ret

; hpack_dyn_evict(rdi = table*) — drop oldest entries until the live size is
; within .max. Caller-saved only.
hpack_dyn_evict:
.de_loop:
    mov rax, [rdi + linnea_hpack_dyn.size]
    cmp rax, [rdi + linnea_hpack_dyn.max]
    jbe .de_done
    cmp qword [rdi + linnea_hpack_dyn.count], 0
    je .de_done
    ; the oldest is head - (count - 1)
    mov rcx, [rdi + linnea_hpack_dyn.head]
    sub rcx, [rdi + linnea_hpack_dyn.count]
    inc rcx
    jns .de_slot
    add rcx, LINNEA_HPACK_DYN_MAX
.de_slot:
    mov rdx, [rdi + linnea_hpack_dyn.nlen + rcx * 8]
    add rdx, [rdi + linnea_hpack_dyn.vlen + rcx * 8]
    add rdx, 32                                 ; RFC 7541 4.1 entry size
    sub [rdi + linnea_hpack_dyn.size], rdx
    dec qword [rdi + linnea_hpack_dyn.count]
    jmp .de_loop
.de_done:
    ; an empty table reclaims the whole arena
    cmp qword [rdi + linnea_hpack_dyn.count], 0
    jne .de_ret
    mov qword [rdi + linnea_hpack_dyn.used], 0
.de_ret:
    ret

; hpack_dyn_insert(r8 = table*, rax = name ptr, rdx = name len,
;                  rsi = value ptr, rdi = value len)
; Store a literal-with-incremental-indexing field. Best effort: an entry that
; cannot fit the arena empties the table and is dropped, exactly as a table
; smaller than the entry would (RFC 7541 4.4) — later indices then simply do
; not resolve, which is a decode error rather than a wrong header.
hpack_dyn_insert:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, r8                     ; table
    mov r12, rax                    ; name ptr
    mov r13, rdx                    ; name len
    mov r14, rsi                    ; value ptr
    mov r15, rdi                    ; value len
    ; make room for size + 32
    lea rax, [r13 + r15]
    add rax, 32
    cmp rax, [rbx + linnea_hpack_dyn.max]
    ja .di_clear                    ; larger than the table: it empties it
    add [rbx + linnea_hpack_dyn.size], rax
    mov rdi, rbx
    call hpack_dyn_evict            ; bring the size back within max
    cmp qword [rbx + linnea_hpack_dyn.count], LINNEA_HPACK_DYN_MAX
    jae .di_drop                    ; entry slots exhausted
    ; the arena is a bump allocator: compact by wrapping to the start when the
    ; live entries have all been evicted, else refuse (rare: a long-lived
    ; connection whose peer keeps inserting)
    mov rax, [rbx + linnea_hpack_dyn.used]
    lea rcx, [r13 + r15]
    add rcx, rax
    cmp rcx, LINNEA_HPACK_DYN_CAP
    jbe .di_space
    cmp qword [rbx + linnea_hpack_dyn.count], 0
    jne .di_drop
    xor eax, eax                    ; the table is empty: start over
    mov [rbx + linnea_hpack_dyn.used], rax
.di_space:
    ; copy name ++ value into the arena
    lea rdi, [rbx + linnea_hpack_dyn.arena]
    add rdi, rax
    push rax
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov rsi, r14
    mov rcx, r15
    rep movsb
    pop rax
    ; claim the newest slot
    mov rcx, [rbx + linnea_hpack_dyn.head]
    cmp qword [rbx + linnea_hpack_dyn.count], 0
    je .di_first
    inc rcx
    cmp rcx, LINNEA_HPACK_DYN_MAX
    jb .di_head
    xor ecx, ecx
    jmp .di_head
.di_first:
    xor ecx, ecx
.di_head:
    mov [rbx + linnea_hpack_dyn.head], rcx
    mov [rbx + linnea_hpack_dyn.off + rcx * 8], rax
    mov [rbx + linnea_hpack_dyn.nlen + rcx * 8], r13
    mov [rbx + linnea_hpack_dyn.vlen + rcx * 8], r15
    inc qword [rbx + linnea_hpack_dyn.count]
    lea rax, [r13 + r15]
    add [rbx + linnea_hpack_dyn.used], rax
    xor eax, eax                    ; stored: in sync with the peer
    jmp .di_ret
.di_drop:
    ; We could not store an entry the peer's encoder DID add to its table
    ; (our slots or the non-compacting arena ran out). The index spaces are now
    ; out of sync, so every later reference would resolve to the wrong entry —
    ; a decode error, not a silently-substituted header. Signal it: the caller
    ; ends the connection (COMPRESSION_ERROR). A compliant peer never reaches
    ; here because we advertise SETTINGS_HEADER_TABLE_SIZE = 0.
    lea rax, [r13 + r15]
    add rax, 32
    sub [rbx + linnea_hpack_dyn.size], rax   ; keep the accounting honest
    mov eax, -1
    jmp .di_ret
.di_clear:
    ; entry larger than the table max: both sides drop it, table empties, they
    ; stay in sync (RFC 7541 4.4) — not an error
    mov qword [rbx + linnea_hpack_dyn.count], 0
    mov qword [rbx + linnea_hpack_dyn.size], 0
    mov qword [rbx + linnea_hpack_dyn.used], 0
    xor eax, eax
.di_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
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
