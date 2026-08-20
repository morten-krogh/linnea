; linnea_hpack.asm — HPACK (RFC 7541) decoder, HTTP/2 request path (M16).
;
; Decodes one header block (already reassembled from HEADERS + CONTINUATION)
; into request pseudo-headers.
;
; We advertise SETTINGS_HEADER_TABLE_SIZE = 4096 (Q153), so the dynamic table
; is load-bearing for real traffic rather than dead state a conforming peer
; never touches — a browser's cookie and user-agent are identical on every
; request of a page load, and indexed they cost one byte each. The decoder is
; therefore stateful across the header blocks of a connection.
; (This block used to say we advertised 0. Enabling the table is what made
; hpack_dyn_get's copy-out reachable from real traffic, and with it the scratch
; bound at .fault.) That state is the thing
; to protect: a block we start decoding must be walked to its end even when the
; request is doomed, or our table falls behind the peer's and a later block
; decodes against the wrong entries. See .fault.
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
global linnea_http_authority_host
global linnea_http_head_conn_named
extern linnea_network_parse_ipv6
; shared with the QPACK decoder (same Huffman code and pseudo-header logic)
global hpack_int
global hpack_str
global hpack_huffman
global emit_field
global linnea_hpack_req_check
global hpack_dyn_reset

extern linnea_string_to_u64
extern linnea_string_is_token
extern linnea_string_iequal

section .rodata

; reg-name allowlist (RFC 3986 unreserved + sub-delims; pct-encoding is not
; supported so "%" is not set). Bit (c & 7) of byte (c >> 3) is set for an
; allowed ASCII byte; every byte >= 0x80 is rejected outright.
ah_regname_tab: db 0x00,0x00,0x00,0x00,0xd2,0x7f,0xff,0x2b,0xfe,0xff,0xff,0x87,0xfe,0xff,0xff,0x47
pseudo_method:  db ":method"
pseudo_path:    db ":path"
pseudo_scheme:  db ":scheme"
pseudo_auth:    db ":authority"
hdr_host:       db "host"
hdr_priority:   db "priority"
hdr_inm:        db "if-none-match"
hdr_ims:        db "if-modified-since"
hdr_ifm:        db "if-match"
hdr_ius:        db "if-unmodified-since"
hdr_range:      db "range"
hdr_ifr:        db "if-range"
hdr_ae:         db "accept-encoding"
; names stripped from the proxy header rebuild (hop-by-hop / managed)
hdr_te:         db "te"
hdr_trailers:   db "trailers"   ; the one TE value RFC 9113 8.2.2 permits
hdr_conn:       db "connection"
hdr_ka:         db "keep-alive"
hdr_cl2:        db "content-length"
hdr_pconn:      db "proxy-connection"
hdr_tenc:       db "transfer-encoding"
hdr_upg:        db "upgrade"
hdr_cookie:     db "cookie"
hdr_expect:     db "expect"
expect_100_val: db "100-continue"

section .bss
ah_ip6_lit:     resb 64      ; a bracketed authority's contents, NUL-terminated for parse_ipv6
ah_ip6_out:     resb 16      ; parse_ipv6's 16-byte output (discarded; we only want its verdict)
lit_form:      resq 1
; The first field fault of the block in progress, or 0. A bad or over-limit
; field does NOT stop the walk (see .fault), so the fault waits here until the
; block has been read to its end. A file-scope slot for the same reason
; lit_form is one: one decode runs at a time.
dec_fault:     resq 1
; Set once a normal field representation has been decoded in this block, so a
; dynamic-table size update that follows one can be rejected (RFC 7541 4.2:
; updates only at the beginning of a block; Finding 29). One decode at a time.
dec_field_seen: resq 1
; The req's scratch cursor as it stood before the field now being decoded. A
; field the walk goes on to REJECT keeps nothing — emit_field records its
; pointers only after the bounds pass — so its scratch is reclaimed at .fault
; and the next field reuses it. Without that, the walk-on-after-fault below
; (which exists to keep the dynamic table in sync) left nothing bounding
; scratch at all: see the comment there.
dec_scratch:   resq 1

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
    mov qword [dec_fault], 0
    mov qword [dec_field_seen], 0

.next:
    cmp r12, r13
    jae .ok                         ; consumed the whole block
    ; remember where this field's decoded bytes will start, so a field the
    ; bounds reject can give its scratch back (see dec_scratch)
    mov rax, [rbx + linnea_h2_req.scratch]
    mov [dec_scratch], rax
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
    mov qword [dec_field_seen], 1   ; a field: any later size update is illegal (#29)
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
    jc .fault
    jmp .next

; An index past the static table names an entry the peer inserted earlier on
; this connection (RFC 7541 2.3.3): 62 selects the newest.
.indexed_dyn:
    mov rdi, [rbx + linnea_h2_req.dyn]
    test rdi, rdi
    jz .err_index                   ; no table (HTTP/3): undecodable
    lea rsi, [rax - HPACK_STATIC_COUNT - 1]     ; 0 = newest
    mov rdx, rbx                    ; req, whose scratch receives the copy
    call hpack_dyn_get              ; -> rax = name, rdx = nlen, rsi = value,
    jc .err_index                   ;    rdi = vlen; CF = out of range
    call emit_field
    jc .fault
    jmp .next

; --- 6.2.x Literal Header Field ------------------------------------------
.lit_inc:
    mov ecx, 6                      ; incremental indexing: 6-bit prefix
    jmp .literal
.lit_noindex:
    mov ecx, 4                      ; without / never indexed: 4-bit prefix
.literal:
    mov qword [dec_field_seen], 1   ; a field: any later size update is illegal (#29)
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
    mov rdx, rbx                    ; req, whose scratch receives the copy
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
    jc .fault
    jmp .next

; --- 6.3 Dynamic Table Size Update ---------------------------------------
.tsize:
    ; RFC 7541 4.2 (Finding 29): a size update may only appear at the beginning
    ; of a block, before any field. One after a field is a COMPRESSION_ERROR.
    cmp qword [dec_field_seen], 0
    jne .err
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
    mov rax, [dec_fault]             ; 0, or the fault the walk deferred
    jmp .ret
.fault:
    ; The field is bad — malformed, or past our list bound — but the block is
    ; NOT abandoned here. HPACK is stateful: every literal-with-incremental-
    ; indexing still to come in this block enters the encoder's dynamic table
    ; whether or not we like this request, so returning now would leave our
    ; table short of the peer's and silently decode a LATER request against the
    ; wrong entries. Walk the rest for its table side effects and report the
    ; first fault at the end, where RFC 9113 8.1.1 can fail just the stream
    ; because the field section did, in the end, decode.
    ;
    ; And give the field's scratch back. Walking on is what keeps the table in
    ; sync, but it also meant the header-list bound stopped bounding scratch:
    ; every field past the fault was still DECODED on the way by, and an
    ; indexed reference to a dynamic entry is copied into scratch by
    ; hpack_dyn_get -- one wire byte, up to 4064 of scratch. Eight of them, a
    ; 76-byte block, exhausted a 16384-byte scratch sized only for Huffman
    ; expansion, and the resulting .dg_bad came back as a COMPRESSION_ERROR:
    ; the whole connection, where our own limit is a stream error and the same
    ; over-limit block built from literals correctly got one. A rejected field
    ; keeps nothing, so its bytes are free to reuse.
    mov rax, [dec_scratch]
    mov [rbx + linnea_h2_req.scratch], rax
    cmp qword [dec_fault], 0
    jne .next                        ; keep the first cause, not the last
    mov qword [dec_fault], -LINNEA_HPACK_ERR_LIMIT
    jmp .next
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
    ; RFC 9113 8.2.1 / RFC 9114 4.1.2: a field name must be lowercase and carry
    ; no delimiter, and neither name nor value may contain CR, LF or NUL. This
    ; is load-bearing, not pedantry. The proxy rebuild below writes the field
    ; out as "name: value CRLF" straight into an HTTP/1.1 request head, so a CR
    ; or LF in either half forges a second request at the backend — and an
    ; uppercase name walks past the hop-by-hop checks further down, which
    ; compare against lowercase constants, so a capitalised Transfer-Encoding
    ; or Content-Length reaches the upstream and desynchronises it.
    ; rax = name, rdx = name length, rsi = value, rdi = value length.
    ; rcx and r8 are already this function's scratch (see name_eq).
    test rdx, rdx
    jz .ef_bad                       ; a field name is a token, so never empty
                                     ; (RFC 9110 5.1). An empty one skipped the
                                     ; scan below entirely, went out as a bare
                                     ; ": value" line to the upstream, and left
                                     ; the pseudo-header test reading a byte the
                                     ; field does not own.
    xor ecx, ecx
.ef_name_scan:
    cmp rcx, rdx
    jae .ef_name_ok
    movzx r8d, byte [rax + rcx]
    cmp r8b, 0x20
    jbe .ef_bad                      ; CR, LF, NUL, any control byte — and SP
                                     ; itself: 8.2.1 excludes 0x00-0x20
                                     ; INCLUSIVE, and `jb` let 0x20 through, so
                                     ; a name like "x foo" reached the proxy
                                     ; rebuild and was written into an HTTP/1.1
                                     ; head no other parser would read the same
    cmp r8b, 0x7f
    jae .ef_bad
    cmp r8b, 'A'
    jb .ef_name_next
    cmp r8b, 'Z'
    jbe .ef_bad                      ; uppercase: malformed, and a filter bypass
.ef_name_next:
    cmp r8b, ':'
    jne .ef_name_inc
    test rcx, rcx
    jnz .ef_bad                      ; ':' only as a pseudo-header's first byte
.ef_name_inc:
    inc rcx
    jmp .ef_name_scan
.ef_name_ok:
    xor ecx, ecx
.ef_val_scan:
    cmp rcx, rdi
    jae .ef_val_ok
    movzx r8d, byte [rsi + rcx]
    cmp r8b, 0x0d
    je .ef_bad
    cmp r8b, 0x0a
    je .ef_bad
    test r8b, r8b
    jz .ef_bad
    inc rcx
    jmp .ef_val_scan
.ef_val_ok:
    ; A field value must not begin or end with SP or HTAB (RFC 9113 8.2.1 /
    ; RFC 9114 4.2). Only CR, LF and NUL were refused, so such a value was
    ; forwarded verbatim into the request head we build for an upstream, where
    ; where it is the next parser's guess what the value actually was.
    test rdi, rdi
    jz .ef_val_edges_ok
    movzx r8d, byte [rsi]
    cmp r8b, 0x20
    je .ef_bad
    cmp r8b, 0x09
    je .ef_bad
    movzx r8d, byte [rsi + rdi - 1]
    cmp r8b, 0x20
    je .ef_bad
    cmp r8b, 0x09
    je .ef_bad
.ef_val_edges_ok:
    ; --- connection-specific fields (RFC 9113 8.2.2 / RFC 9114 4.2) ---------
    ; "Any message containing connection-specific header fields MUST be treated
    ; as malformed." These names were matched only inside the proxy rebuild, and
    ; only to skip them from the head sent upstream — so on a static request, or
    ; on HTTP/3 (which never sets hb_start, so the block never ran at all), they
    ; were simply served. Stripping them stopped the smuggle into an h1 upstream;
    ; it did not make the request the malformed one the RFC says it is.
    cmp byte [rax], ':'
    je .ef_conn_ok                   ; a pseudo-header is none of these
    cmp rdx, 2
    je .ef_chk_te
    cmp rdx, 7
    je .ef_chk_upg
    cmp rdx, 10
    je .ef_chk_10
    cmp rdx, 16
    je .ef_chk_pconn
    cmp rdx, 17
    je .ef_chk_tenc
    jmp .ef_conn_ok
.ef_chk_upg:
    lea r9, [hdr_upg]
    jmp .ef_conn_probe
.ef_chk_pconn:
    lea r9, [hdr_pconn]
    jmp .ef_conn_probe
.ef_chk_tenc:
    lea r9, [hdr_tenc]
    jmp .ef_conn_probe
.ef_chk_10:
    push rsi
    push rdi
    lea r9, [hdr_conn]
    call name_eq
    pop rdi
    pop rsi
    je .ef_malformed
    lea r9, [hdr_ka]
.ef_conn_probe:
    push rsi
    push rdi
    call name_eq
    pop rdi
    pop rsi
    je .ef_malformed
    jmp .ef_conn_ok
.ef_chk_te:
    push rsi
    push rdi
    lea r9, [hdr_te]
    call name_eq
    pop rdi
    pop rsi
    jne .ef_conn_ok
    ; TE is the single exception 8.2.2 allows, and only for one value: it "MUST
    ; NOT contain any value other than trailers". Compared case-insensitively —
    ; it is a token, and refusing "Trailers" would reject a conforming peer.
    push rax
    push rdx
    push rsi
    push rdi
    mov r8, rsi                      ; value pointer
    mov r9, rdi                      ; value length
    mov rdi, r8
    mov rsi, r9
    lea rdx, [hdr_trailers]
    mov ecx, 8
    call linnea_string_iequal
    mov r8d, eax                     ; the verdict, before the pops below put
                                     ; the saved name pointer back into rax
    pop rdi
    pop rsi
    pop rdx
    pop rax
    test r8d, r8d
    jz .ef_malformed
.ef_conn_ok:
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
    ; --- pseudo-header placement and repetition (RFC 9113 8.3 / 9114 4.3.1) -
    ; A repeated pseudo-header is the h2/h3 twin of a repeated Host: we would
    ; keep the last, an intermediary the first, and one request becomes two
    ; different ones. A pseudo-header trailing a regular field, or one we do
    ; not know, is malformed for the same reason — the peer and we would not
    ; agree on what the request says.
    cmp byte [rax], ':'
    je .ef_pseudo
    mov qword [rbx + linnea_h2_req.regular_seen], 1
    jmp .ef_order_ok
.ef_pseudo:
    cmp qword [rbx + linnea_h2_req.regular_seen], 0
    jne .ef_malformed                ; pseudo-header after a regular field
    push rax
    push rdx
    push rsi
    push rdi
    call pseudo_bit                  ; -> r8 = the bit, 0 if unrecognized
    pop rdi
    pop rsi
    pop rdx
    pop rax
    test r8, r8
    jz .ef_malformed                 ; an unknown pseudo-header
    test [rbx + linnea_h2_req.pseudo_seen], r8
    jnz .ef_malformed                ; a repeat
    or [rbx + linnea_h2_req.pseudo_seen], r8
.ef_order_ok:
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
    cmp rdx, 6
    je .rb_chk_cookie
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
.rb_chk_cookie:
    ; The cookie coalescing (Finding 32) and expect:100-continue handling
    ; (Finding 33) are HTTP/2-only: they use ck_buf and a local 100 the h2 path
    ; emits, and the shared rebuild also runs for HTTP/3 (which never sets
    ; ck_buf). Without this guard an h3 cookie wrote to a null ck_buf -- a crash.
    cmp qword [rbx + linnea_h2_req.ck_buf], 0
    je .rebuild                      ; h3: forward the field as an ordinary line
    push rsi
    push rdi
    lea r9, [hdr_cookie]
    call name_eq
    pop rdi
    pop rsi
    jne .rb_chk_expect               ; a different 6-char name: try "expect"
    ; A cookie field (RFC 9113 8.2.3, Finding 32): do not rebuild a line for it;
    ; append its value to ck_buf, joined with "; ", and let the proxy head emit
    ; one Cookie line at the end. rax=name, rdx=6, rsi=value ptr, rdi=value len.
    mov r10, [rbx + linnea_h2_req.ck_len]   ; length joined so far
    cmp r10, -1
    je .no_rebuild                   ; already overflowed: drop (head fails 431)
    mov r8, r10                      ; prospective new length
    test r10, r10
    jz .rb_ck_bound
    add r8, 2                        ; a "; " separator precedes this value
.rb_ck_bound:
    add r8, rdi
    cmp r8, 8192                     ; ck_buf capacity
    ja .rb_ck_over
    mov r9, [rbx + linnea_h2_req.ck_buf]
    add r9, r10                      ; write cursor = base + current length
    test r10, r10
    jz .rb_ck_val
    mov word [r9], '; '
    add r9, 2
.rb_ck_val:
    push rsi
    push rdi
    mov rcx, rdi                     ; value length
    mov rdi, r9                      ; dest (rsi already = value ptr)
    rep movsb
    pop rdi
    pop rsi
    mov [rbx + linnea_h2_req.ck_len], r8
    jmp .no_rebuild
.rb_ck_over:
    mov qword [rbx + linnea_h2_req.ck_len], -1
    jmp .no_rebuild
.rb_chk_expect:
    push rsi
    push rdi
    lea r9, [hdr_expect]
    call name_eq
    jne .rb_expect_no                ; neither cookie nor expect: append normally
    ; "expect": only "100-continue" is handled -- the proxy path emits a local
    ; interim 100 and strips the field (RFC 9110 10.1.1, Finding 33). Any other
    ; expectation is forwarded unchanged for the backend to answer (e.g. 417).
    mov rdi, [rsp + 8]               ; value ptr
    mov rsi, [rsp]                   ; value len
    lea rdx, [expect_100_val]
    mov rcx, 12
    call linnea_string_iequal        ; eax = 1 when equal (case-insensitive)
    pop rdi
    pop rsi
    test eax, eax
    jz .rebuild                      ; a different expectation: forward it
    mov qword [rbx + linnea_h2_req.expect_100], 1
    jmp .no_rebuild                  ; stripped: we generate the 100 ourselves
.rb_expect_no:
    pop rdi
    pop rsi
    jmp .rebuild
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
    ; Content-Length is not rebuilt as a line -- the proxy head declares the
    ; body we actually collected -- but its VALUE is the message's own framing,
    ; and this is the one place h2 and h3 both hand it over. So it is checked
    ; here, once, instead of at each protocol's reconciliation (audit-report-5
    ; Finding 1): h2 parsed it with a broken overflow guard and h3 with none at
    ; all, so "18446744073709551616" wrapped to zero on both and an empty POST
    ; declaring 2^64 bytes was served -- and proxied -- as a well-formed one.
    ; A non-digit, an empty value, or a number past 2^64-1 is a malformed
    ; message (RFC 9110 8.6): .ef_malformed fails the STREAM, which is what
    ; RFC 9113 8.1.1 and RFC 9114 4.1.2 ask for, and leaves the connection and
    ; the compression context alone.
    ;
    ; This runs inside the rebuild block, so it needs .hb_start set -- which the
    ; h2 and h3 request paths both do unconditionally, for every request and not
    ; only a proxied one (linnea_http2.asm arms it beside the scratch region,
    ; linnea_quic_server.asm beside h3_hdrs_buf). .cl_ptr has always been
    ; collected under exactly that condition; the check simply joins it.
    push rax                          ; the name and its length: .no_rebuild
    push rdx                          ; below still matches pseudo-headers on
    push rsi                          ; them, in rax/rdx, the way name_eq wants
    push rdi
    mov rax, rdi                      ; value length
    mov rdi, rsi                      ; value pointer
    mov rsi, rax
    call linnea_string_to_u64         ; -> rax = value, edx = 0 ok / 1 / 2
    test edx, edx
    jnz .rb_cl_bad                    ; empty, not a number, or past 2^64-1
    cmp qword [rbx + linnea_h2_req.cl_ptr], 0
    jne .rb_cl_bad                    ; a SECOND content-length. Keeping the
                                      ; last silently resolved "0 then 1" in
                                      ; the client's favour and dropped the
                                      ; contradiction; h1 has refused a repeat
                                      ; since it was written, and two lengths
                                      ; cannot both equal the body whether or
                                      ; not they agree with each other
    mov [rbx + linnea_h2_req.cl_val], rax
    pop rdi
    pop rsi
    pop rdx
    pop rax
    mov [rbx + linnea_h2_req.cl_ptr], rsi    ; kept: the proxy path forwards
    mov [rbx + linnea_h2_req.cl_len], rdi    ; it and streams the body
    jmp .no_rebuild
.rb_cl_bad:
    add rsp, 32                       ; the four saved above; emit_field itself
    jmp .ef_malformed                 ; keeps nothing on the stack
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
    ; one span per line, up to three (see linnea_hpack.inc)
    mov rax, [rbx + linnea_h2_req.inm_n]
    cmp rax, 3
    jae .inm_full
    shl rax, 4
    lea rdx, [rbx + linnea_h2_req.inm_ptr]
    mov [rdx + rax], rsi
    mov [rdx + rax + 8], rdi
    inc qword [rbx + linnea_h2_req.inm_n]
.inm_full:
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
    cmp rdx, 8                       ; "if-match"
    jne .not_ifm
    push rsi
    push rdi
    lea r9, [hdr_ifm]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_ifm
    mov rax, [rbx + linnea_h2_req.ifm_n]
    cmp rax, 3
    jae .ifm_full
    shl rax, 4
    lea rdx, [rbx + linnea_h2_req.ifm_ptr]
    mov [rdx + rax], rsi
    mov [rdx + rax + 8], rdi
    inc qword [rbx + linnea_h2_req.ifm_n]
.ifm_full:
    clc
    ret
.not_ifm:
    cmp rdx, 19                      ; "if-unmodified-since"
    jne .not_ius
    push rsi
    push rdi
    lea r9, [hdr_ius]
    call name_eq
    pop rdi
    pop rsi
    jnz .not_ius
    mov [rbx + linnea_h2_req.ius_ptr], rsi
    mov [rbx + linnea_h2_req.ius_len], rdi
    clc
    ret
.not_ius:
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
    inc qword [rbx + linnea_h2_req.host_count]
    cmp qword [rbx + linnea_h2_req.host_ptr], 0
    jne .done                       ; keep the first; the count rejects a repeat
    mov [rbx + linnea_h2_req.host_ptr], rsi
    mov [rbx + linnea_h2_req.host_len], rdi
.done:
    clc
    ret
.ef_malformed:
    mov qword [rbx + linnea_h2_req.malformed], 1
    stc
    ret
.ef_limit:
    stc
    ret
.ef_bad:
    ; A syntax fault is a MALFORMED request, not a resource limit. Setting only
    ; the carry left HTTP/3 unable to tell the two apart: linnea_qpack_decode
    ; maps every carry to the limit error, and the h3 path answered an uppercase
    ; name or a space in a value with "431 Request Header Fields Too Large" —
    ; which is not what went wrong and tells the client to shrink headers that
    ; were never too big. RFC 9114 4.1.2 wants a stream error, and .malformed is
    ; what the h3 path reads to raise one. HTTP/2 already reset the stream on the
    ; carry alone, so nothing changes there.
    mov qword [rbx + linnea_h2_req.malformed], 1
    stc
    ret

; pseudo_bit(rax = name, rdx = name length) -> r8 = the LINNEA_H2_PS_* bit for
; a request pseudo-header we know, 0 for anything else. name_eq wants the name
; in rax/rdx and clobbers rcx/rsi/rdi, so the name is held in r10/r11 across
; the probes; the caller has saved rax/rdx/rsi/rdi and the rebuild below
; reloads r10 itself.
pseudo_bit:
    mov r10, rax                     ; name
    mov r11, rdx                     ; length
    cmp r11, 7
    je .pb_len7
    cmp r11, 5
    je .pb_len5
    cmp r11, 10
    je .pb_len10
    jmp .pb_none
.pb_len7:
    lea r9, [pseudo_method]
    call name_eq
    je .pb_method
    mov rax, r10
    mov rdx, r11
    lea r9, [pseudo_scheme]
    call name_eq
    je .pb_scheme
    jmp .pb_none
.pb_len5:
    lea r9, [pseudo_path]
    call name_eq
    je .pb_path
    jmp .pb_none
.pb_len10:
    lea r9, [pseudo_auth]
    call name_eq
    je .pb_auth
.pb_none:
    xor r8d, r8d
    ret
.pb_method:
    mov r8d, LINNEA_H2_PS_METHOD
    ret
.pb_path:
    mov r8d, LINNEA_H2_PS_PATH
    ret
.pb_scheme:
    mov r8d, LINNEA_H2_PS_SCHEME
    ret
.pb_auth:
    mov r8d, LINNEA_H2_PS_AUTH
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

; di_ring_copy(rbx = table, rdi = arena cursor, rsi = source, rcx = length)
;   -> rdi advanced past the bytes written, wrapping at the end of the arena.
; Splits the copy when it reaches the end. Touches rax/rcx/rdx/rsi/rdi/r8.
di_ring_copy:
    test rcx, rcx
    jz .rc_done
    lea rax, [rbx + linnea_hpack_dyn.arena]
    lea rdx, [rax + LINNEA_HPACK_DYN_CAP]    ; one past the arena
    mov r8, rdx
    sub r8, rdi                              ; bytes left before the wrap
    cmp rcx, r8
    jbe .rc_tail                             ; fits without wrapping
    sub rcx, r8                              ; the part past the end
    push rcx
    mov rcx, r8
    rep movsb                                ; fill to the end
    pop rcx
    lea rdi, [rbx + linnea_hpack_dyn.arena]  ; and resume at the start
.rc_tail:
    rep movsb
.rc_done:
    ret

; hpack_dyn_get(rdi = table*, rsi = i, 0 = newest, rdx = req)
;   -> rax = name ptr, rdx = name len, rsi = value ptr, rdi = value len.
; CF set when i is past the live entries, or the req's scratch cannot take the
; copy. The entry is copied into that scratch, so the pointers stay valid for
; as long as every other decoded pointer does.
hpack_dyn_get:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi                                ; table
    mov r14, rdx                                ; req, for its scratch
    cmp rsi, [rbx + linnea_hpack_dyn.count]
    jae .dg_bad
    mov rax, [rbx + linnea_hpack_dyn.head]
    sub rax, rsi
    jns .dg_slot
    add rax, LINNEA_HPACK_DYN_MAX               ; wrapped
.dg_slot:
    mov r12, [rbx + linnea_hpack_dyn.off + rax * 8]
    mov r13, [rbx + linnea_hpack_dyn.nlen + rax * 8]
    mov r15, [rbx + linnea_hpack_dyn.vlen + rax * 8]
    ; The entry is COPIED into the request's scratch rather than pointed at in
    ; place. Two reasons, and the first is the load-bearing one: the pointers
    ; handed back here end up in the req and are read long after this call — by
    ; the serve, and by the proxy header rebuild — whereas the arena is a ring
    ; that a later insert in the SAME header block can evict and write over. It
    ; also frees the arena to store an entry across the wrap. linnea_hpack.inc
    ; has always said a decoded pointer references the input block, the static
    ; blob or scratch; the arena was never on that list.
    mov rdi, [r14 + linnea_h2_req.scratch]
    mov rax, [r14 + linnea_h2_req.scratch_end]
    sub rax, rdi
    mov rcx, r13
    add rcx, r15
    cmp rcx, rax
    ja .dg_bad                                  ; scratch exhausted
    push rdi                                    ; where the copy begins
    ; the entry's bytes may straddle the end of the ring
    lea rsi, [rbx + linnea_hpack_dyn.arena]
    add rsi, r12
    call dg_ring_read                           ; name ++ value, rcx bytes
    pop rax                                     ; name ptr, in scratch
    mov rdi, [r14 + linnea_h2_req.scratch]
    add rdi, r13
    add rdi, r15
    mov [r14 + linnea_h2_req.scratch], rdi      ; bump past the copy
    mov rdx, r13                                ; name len
    lea rsi, [rax + rdx]                        ; value follows the name
    mov rdi, r15                                ; value len
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    clc
    ret
.dg_bad:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    stc
    ret

; dg_ring_read(rbx = table, rsi = arena cursor, rdi = destination, rcx = length)
; Reads rcx bytes from the ring starting at rsi, wrapping at the arena's end.
dg_ring_read:
    test rcx, rcx
    jz .rr_done
    lea rax, [rbx + linnea_hpack_dyn.arena]
    lea rdx, [rax + LINNEA_HPACK_DYN_CAP]
    mov r8, rdx
    sub r8, rsi                                 ; bytes before the wrap
    cmp rcx, r8
    jbe .rr_tail
    sub rcx, r8
    push rcx
    mov rcx, r8
    rep movsb
    pop rcx
    lea rsi, [rbx + linnea_hpack_dyn.arena]     ; resume at the start
.rr_tail:
    rep movsb
.rr_done:
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
    ; The arena is a RING. .used is the write cursor; an evicted entry's bytes
    ; are reclaimed simply by the cursor coming round to them again, so a peer
    ; that keeps inserting no longer walks the cursor off the end. It was a bump
    ; allocator that only reset at count == 0, which is why a table left enabled
    ; would eventually refuse an entry the peer HAD stored and kill the
    ; connection — see .di_drop.
    ;
    ; There is always room. Every entry costs its bytes + 32 against .max, and
    ; eviction above has already brought .size within .max <= CAP, so the bytes
    ; actually stored are size - 32*entries, i.e. at least 32 per entry below
    ; CAP. The check below is a belt-and-braces guard, not a live path.
    lea rax, [r13 + r15]             ; L: the bytes this entry occupies
    mov rcx, [rbx + linnea_hpack_dyn.size]
    sub rcx, rax
    sub rcx, 32                      ; .size already counts this entry: drop it
    mov rdx, [rbx + linnea_hpack_dyn.count]
    shl rdx, 5                       ; 32 bytes of per-entry overhead
    sub rcx, rdx                     ; rcx = bytes the live entries occupy
    add rcx, rax
    cmp rcx, LINNEA_HPACK_DYN_CAP
    ja .di_drop                      ; unreachable while max <= CAP
    ; write name ++ value at the cursor, splitting across the end if it lands
    ; there. Nothing outside this file reads the arena — hpack_dyn_get copies
    ; out — so an entry that straddles the wrap costs only this second movsb.
    mov rax, [rbx + linnea_hpack_dyn.used]
    push rax                         ; the offset this entry starts at
    lea rdi, [rbx + linnea_hpack_dyn.arena]
    add rdi, rax
    mov rsi, r12                     ; name
    mov rcx, r13
    call di_ring_copy
    mov rsi, r14                     ; value, continuing from where name ended
    mov rcx, r15
    call di_ring_copy
    ; advance the cursor by L, modulo the arena
    mov rax, [rbx + linnea_hpack_dyn.used]
    lea rax, [rax + r13]
    add rax, r15
    cmp rax, LINNEA_HPACK_DYN_CAP
    jb .di_cursor
    sub rax, LINNEA_HPACK_DYN_CAP
.di_cursor:
    mov [rbx + linnea_hpack_dyn.used], rax
    pop rax                          ; the entry's starting offset
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
    xor eax, eax                    ; stored: in sync with the peer
    jmp .di_ret
.di_drop:
    ; We could not store an entry the peer's encoder DID add to its table
    ; (our slots or the non-compacting arena ran out). The index spaces are now
    ; out of sync, so every later reference would resolve to the wrong entry —
    ; a decode error, not a silently-substituted header. Signal it: the caller
    ; ends the connection (COMPRESSION_ERROR). A compliant peer still never
    ; reaches here, but no longer because it inserts nothing — we advertise
    ; 4096 now — rather because every entry costs at least 32 against that,
    ; so 4096/32 = 128 live entries is exactly the slot count.
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

; linnea_hpack_req_check(rdi = req) -> rax = 0 when the decoded request is
; well formed, -1 when it is not (a STREAM error; see .malformed).
;
; What the field-by-field pass cannot see: whether the request ended up with
; an authority at all, and whether the two places it can come from agree.
; RFC 9113 8.3.1 / RFC 9114 4.3.1: a request carries :authority (or, from an
; intermediary translating HTTP/1.1, Host), and a Host that contradicts
; :authority is malformed — we would route on one, the next hop on the other.
; The value itself must be able to BE an authority: non-empty, no spaces or
; control bytes, exactly as the HTTP/1.1 side now demands of Host.
linnea_hpack_req_check:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + linnea_h2_req.host_count], 1
    ja .bad                          ; more than one Host: the h1 rule, here too
    mov rsi, [rbx + linnea_h2_req.auth_ptr]
    test rsi, rsi
    jnz .have_auth
    ; no :authority — Host stands in for it, and must then exist
    mov rsi, [rbx + linnea_h2_req.host_ptr]
    test rsi, rsi
    jz .bad
    mov rdx, [rbx + linnea_h2_req.host_len]
    mov [rbx + linnea_h2_req.auth_ptr], rsi
    mov [rbx + linnea_h2_req.auth_len], rdx
    jmp .check_value
.have_auth:
    cmp qword [rbx + linnea_h2_req.host_count], 0
    je .check_value                  ; :authority alone
    ; both present: they must say the same thing
    mov rdx, [rbx + linnea_h2_req.auth_len]
    cmp rdx, [rbx + linnea_h2_req.host_len]
    jne .bad
    mov rdi, [rbx + linnea_h2_req.host_ptr]
    mov rcx, rdx
    test rcx, rcx
    jz .check_value
    repe cmpsb
    jne .bad
.check_value:
    mov rdi, [rbx + linnea_h2_req.auth_ptr]
    mov rsi, [rbx + linnea_h2_req.auth_len]
    test rsi, rsi
    jz .bad                          ; an empty authority names nothing
    ; STRUCTURE, not just control-freeness: a reg-name or bracketed IPv6
    ; literal and an optional one-to-five-digit port, the same grammar the
    ; HTTP/1.1 Host demands. rbx (the req) survives the call.
    call linnea_http_authority_host
    cmp rax, -1
    je .bad
    ; :path gets the same treatment. On HTTP/1.1 the request line cannot hold a
    ; space or a control byte and survive parsing, but here the target is just
    ; another field value, where only CR/LF/NUL are refused — so an ESC or a
    ; backspace used to travel all the way into the access log, which h1 would
    ; never have written. A URI has no room for either byte anyway (RFC 3986 2).
    mov rsi, [rbx + linnea_h2_req.path_ptr]
    test rsi, rsi
    jz .scheme_check                 ; absent: judged below, not waved through
    mov rcx, [rbx + linnea_h2_req.path_len]
    test rcx, rcx
    jz .scheme_check
.pv_scan:
    movzx eax, byte [rsi]
    cmp al, 0x20
    jbe .bad
    cmp al, 0x7f
    je .bad
    inc rsi
    dec rcx
    jnz .pv_scan
.scheme_check:
    ; :scheme and a non-empty :path are required for an http/https request
    ; (RFC 9113 8.3.1, RFC 9114 4.3.1), and a request omitting a mandatory
    ; pseudo-header is malformed. :scheme was decoded into the request struct
    ; and then read nowhere in the whole tree, so its absence was never noticed;
    ; an empty :path was served as though the client had asked for "/". Both are
    ; MUSTs and both used to be answered with an ordinary 200.
    ;
    ; The VALUE of :scheme is deliberately left alone: 8.3.1 says outright that
    ; it "is not restricted to http and https schemed URIs", so a gateway may
    ; legitimately be handed another one. Only its presence is required.
    ;
    ; CONNECT omits both by design (8.5), and is already refused before this —
    ; so requiring them here does not change what a CONNECT gets.
    cmp qword [rbx + linnea_h2_req.scheme_ptr], 0
    je .bad
    cmp qword [rbx + linnea_h2_req.path_ptr], 0
    je .bad
    cmp qword [rbx + linnea_h2_req.path_len], 0
    je .bad
.method_check:
    ; :method is a token and must be present (RFC 9110 9.1, RFC 9113 8.3.1).
    ; Nothing checked it: a field value only has CR/LF/NUL refused, so a method
    ; could carry a control byte — which h1's request line cannot — or a double
    ; quote, which breaks the quoting of the access line the method is written
    ; into. The presence half also matters for HTTP/3, which had no check of its
    ; own (HTTP/2 tests method_ptr separately after this returns).
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    test rdi, rdi
    jz .bad
    mov rsi, [rbx + linnea_h2_req.method_len]
    call linnea_string_is_token       ; leaves rbx alone, and the single push at
    test eax, eax                     ; entry is what keeps this call 16-aligned
    jz .bad
.ok:
    xor eax, eax
    pop rbx
    ret
.bad:
    mov qword [rbx + linnea_h2_req.malformed], 1
    mov rax, -1
    pop rbx
    ret


hcn_connection: db "connection"

; linnea_http_head_conn_named(rdi = head ptr, rsi = head length,
;                             rdx = field name, rcx = name length)
;   -> eax = 1 when a Connection field in this upstream head names that field.
;
; RFC 9110 7.6.1 MUST: an intermediary parses Connection, removes every field
; its value names, then removes Connection itself. That value is the
; EXTENSIBILITY mechanism -- how a peer marks a field connection-specific that
; no implementation has heard of -- so a fixed table cannot implement the rule,
; only the half of it that was known when the table was written. The request
; direction had a rule of its own that read only the LAST Connection line, and
; calls this one now (audit-report-29); the response direction had only the
; table, so an upstream sending
;     Connection: X-Backend-Only
;     X-Backend-Only: leaked
; delivered X-Backend-Only to the client on all three protocols
; (audit-report-10 Finding 2).
;
; The head is re-walked once per field rather than a token set being built
; ahead of time. A head is a few KiB with a handful of fields, so the second
; pass costs less than anywhere to keep the set would -- and repeated
; Connection lines, which are legal, then work without being thought about.
;
; It is GENERIC: `upgrade` is matched like any other name. It did not used to
; be -- the exception was written here so the 101 tunnel could complete, which
; is broader than that purpose and leaked `Upgrade: websocket` out of an
; ordinary 200 whose upstream had scoped it to the backend hop
; (audit-report-11 Finding 1). The tunnel's need is narrower than a global
; field-name exception and now lives where it can be justified: the HTTP/1 101
; path, which has already checked both the client's upgrade wish and the
; upstream status.
;
; It lives in this file, not linnea_http.asm, because linnea_qpack.o is linked
; by four test harnesses that have no linnea_http.o -- the same reason
; linnea_http_authority_host is here.
linnea_http_head_conn_named:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                        ; six pushes leave rsp 8 past aligned
    xor eax, eax
    test rcx, rcx
    jz .cx_out                        ; an empty name names nothing
    mov r12, rdi                      ; head
    mov r13, rdi
    add r13, rsi                      ; head end
    mov r14, rdx                      ; the name being asked about
    mov r15, rcx
.cx_scan:
    mov rbx, r12                      ; cursor: skip the status line
.cx_status:
    cmp rbx, r13
    jae .cx_no
    cmp byte [rbx], 13
    je .cx_status_end
    inc rbx
    jmp .cx_status
.cx_status_end:
    add rbx, 2
.cx_line:
    cmp rbx, r13
    jae .cx_no
    cmp byte [rbx], 13
    je .cx_no                         ; the empty line ends the head
    mov rbp, rbx                      ; find this line's CR
.cx_eol:
    cmp rbp, r13
    jae .cx_no
    cmp byte [rbp], 13
    je .cx_have
    inc rbp
    jmp .cx_eol
.cx_have:
    mov rdi, rbx                      ; is this line's name "connection"?
.cx_colon:
    cmp rdi, rbp
    jae .cx_next                      ; no colon: not a field line
    cmp byte [rdi], ':'
    je .cx_colon_found
    inc rdi
    jmp .cx_colon
.cx_colon_found:
    mov rax, rdi
    sub rax, rbx                      ; name length
    cmp rax, 10
    jne .cx_next
    push rdi                          ; the colon, across the call
    mov rdi, rbx
    mov rsi, 10
    lea rdx, [hcn_connection]
    mov ecx, 10
    call linnea_string_iequal
    pop rdi
    test eax, eax
    jz .cx_next
    inc rdi                           ; the value: a comma-separated token list
.cx_tok:
    cmp rdi, rbp
    jae .cx_next
    movzx eax, byte [rdi]
    cmp al, ','
    je .cx_tok_step
    cmp al, ' '
    je .cx_tok_step
    cmp al, 9
    je .cx_tok_step
    mov rsi, rdi                      ; token start
.cx_tok_end:
    cmp rsi, rbp
    jae .cx_tok_cmp
    movzx eax, byte [rsi]
    cmp al, ','
    je .cx_tok_cmp
    cmp al, ' '
    je .cx_tok_cmp
    cmp al, 9
    je .cx_tok_cmp
    inc rsi
    jmp .cx_tok_end
.cx_tok_cmp:
    push rdi
    push rsi
    mov rax, rsi
    sub rax, rdi                      ; token length
    mov rsi, rax
    mov rdx, r14
    mov rcx, r15
    call linnea_string_iequal         ; rdi is already the token start
    pop rsi
    pop rdi
    test eax, eax
    jnz .cx_yes
    mov rdi, rsi                      ; past this token
    jmp .cx_tok
.cx_tok_step:
    inc rdi
    jmp .cx_tok
.cx_next:
    lea rbx, [rbp + 2]                ; past this line's CRLF
    jmp .cx_line
.cx_yes:
    mov eax, 1
    jmp .cx_out
.cx_no:
    xor eax, eax
.cx_out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

LINNEA_MAX_IP6_LIT equ 45         ; ffff:...:255.255.255.255 -- the longest literal
linnea_http_authority_host:
    push rbx
    push r12
    push r13
    mov r12, rdi                      ; authority ptr, held across parse_ipv6
    mov r13, rsi                      ; authority len, likewise (rsi is clobbered)
    test r13, r13
    jz .ah_bad                        ; empty: names nothing
    cmp byte [r12], '['
    je .ah_bracket
    ; --- reg-name / IPv4 form: host up to ':', then a bounded numeric port ---
    xor ecx, ecx                      ; scan index
.ah_u_scan:
    cmp rcx, r13
    jae .ah_u_hostonly                ; ran to the end with no ':' -> all host
    movzx eax, byte [r12 + rcx]
    cmp al, ':'
    je .ah_u_port
    call .ah_regname_ok               ; CF set if not an RFC 3986 reg-name byte
    jc .ah_bad                        ; "/", "?", "#", "@", ... are not a host
    inc rcx
    jmp .ah_u_scan
.ah_u_hostonly:
    test rcx, rcx
    jz .ah_bad                        ; empty host
    mov rax, rcx                      ; host_len
    xor edx, edx                      ; host_off = 0
    pop r13
    pop r12
    pop rbx
    ret
.ah_u_port:
    test rcx, rcx
    jz .ah_bad                        ; ":port" with no host
    mov rbx, rcx                      ; host_len
    inc rcx                           ; first port byte
    call .ah_port_tail                ; 1..5 digits AND <= 65535
    jc .ah_bad
    mov rax, rbx
    xor edx, edx
    pop r13
    pop r12
    pop rbx
    ret
    ; --- "[" IPv6 "]" [ ":" port ] ------------------------------------
.ah_bracket:
    mov rcx, 1                        ; first byte inside the brackets
.ah_b_scan:
    cmp rcx, r13
    jae .ah_bad                       ; no closing ']'
    movzx eax, byte [r12 + rcx]
    cmp al, ']'
    je .ah_b_close
    cmp al, 0x20
    jbe .ah_bad
    cmp al, 0x7f
    je .ah_bad
    cmp al, '['
    je .ah_bad                        ; no nested '['
    inc rcx
    jmp .ah_b_scan
.ah_b_close:
    cmp rcx, 1
    jbe .ah_bad                       ; "[]" : empty literal
    mov rbx, rcx                      ; index of ']'  (host is bytes 1..rbx-1)
    ; the contents must be a real IPv6 address, not just non-empty printable
    ; bytes: "[deadbeef]" is hex but not an address. Copy them NUL-terminated
    ; and run them through the config's inet_pton-style parser.
    lea rax, [rbx - 1]                ; content length
    cmp rax, LINNEA_MAX_IP6_LIT
    ja .ah_bad                        ; longer than any IPv6 literal
    lea rsi, [r12 + 1]
    lea rdi, [ah_ip6_lit]
    mov rcx, rax
    rep movsb
    mov byte [rdi], 0
    lea rdi, [ah_ip6_lit]
    lea rsi, [ah_ip6_out]
    call linnea_network_parse_ipv6    ; rsp is 16-aligned here (3 pushes above)
    test rax, rax
    js .ah_bad                        ; not a valid IPv6 literal
    ; a port, if present, follows the ']'
    lea rcx, [rbx + 1]                ; byte after ']'
    cmp rcx, r13
    jae .ah_b_ok                      ; nothing after ']' : the bare literal
    movzx eax, byte [r12 + rcx]
    cmp al, ':'
    jne .ah_bad                       ; "[::1]x" : junk after the literal
    inc rcx
    call .ah_port_tail
    jc .ah_bad
.ah_b_ok:
    lea rax, [rbx - 1]                ; host_len = ']' index - 1
    mov edx, 1                        ; host_off = 1 (past the '[')
    pop r13
    pop r12
    pop rbx
    ret
.ah_bad:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; .ah_regname_ok(al = byte) -> CF clear iff al is an RFC 3986 reg-name byte
; (unreserved or a sub-delim). Bitmap lookup; every byte >= 0x80 is rejected.
; Internal to linnea_http_authority_host; clobbers r8,r9,r10 (not rax/rbx/rcx).
.ah_regname_ok:
    cmp al, 0x80
    jae .rn_no                        ; non-ASCII is not reg-name
    movzx r8d, al
    mov r9d, r8d
    shr r9d, 3
    movzx r10d, byte [ah_regname_tab + r9]
    and r8d, 7
    bt r10d, r8d
    jnc .rn_no
    clc
    ret
.rn_no:
    stc
    ret

; .ah_port_tail(rcx = first port index, r13 = len, r12 = ptr)
; CF clear iff rcx..len is one to five decimal digits AND names a value in
; 0..65535. Internal to linnea_http_authority_host; clobbers rax, rcx, r8.
.ah_port_tail:
    cmp rcx, r13
    jae .pt_bad                       ; a ':' with no port at all
    mov rax, r13
    sub rax, rcx
    cmp rax, 5
    ja .pt_bad                        ; more digits than any port has
    xor r8d, r8d                      ; the port value
.pt_scan:
    cmp rcx, r13
    jae .pt_ok
    movzx eax, byte [r12 + rcx]
    cmp al, '0'
    jb .pt_bad
    cmp al, '9'
    ja .pt_bad
    lea r8d, [r8d + r8d*4]            ; r8 *= 5
    lea r8d, [eax + r8d*2 - 0x30]     ; r8 = r8*10 + (digit)
    inc rcx
    jmp .pt_scan
.pt_ok:
    cmp r8d, 65535
    ja .pt_bad                        ; out of the 0..65535 port range
    clc
    ret
.pt_bad:
    stc
    ret
