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
%include "linnea_time.inc"
%include "linnea_config.inc"
%include "linnea_http3.inc"

global linnea_qpack_decode
global linnea_qpack_encode_response
global linnea_qpack_encode_proxy
global linnea_qpack_reset_response
global linnea_qpack_send_validators
global linnea_qpack_crange_ptr
global linnea_qpack_crange_len
global linnea_qpack_location_ptr
global linnea_qpack_location_len
global linnea_qpack_ccontrol_ptr
global linnea_qpack_ccontrol_len
global linnea_qpack_cenc
global linnea_qpack_hsts_ptr
global linnea_qpack_hsts_len
global linnea_qpack_nosniff
global linnea_qpack_response_headers_ptr
global linnea_qpack_max_fss
global linnea_qpack_fss_over
global linnea_qpack_fss_size

extern hpack_int
extern hpack_str
extern emit_field
extern linnea_static_etag
extern linnea_static_etag_len
extern linnea_static_lastmod
extern linnea_time_http_now
extern linnea_string_iequal
extern linnea_string_trim_ows
extern linnea_http_head_conn_named
extern linnea_string_from_u64

section .rodata
; status -> QPACK static-table index (RFC 9204 Appendix A). Statuses not listed
; are encoded as a literal with the :status name reference (index 24).
qpack_status_tab:
    dw 100, 63,  103, 24,  200, 25,  204, 64,  206, 65,  302, 66
    dw 304, 26,  400, 67,  403, 68,  404, 27,  421, 69,  425, 70
    dw 500, 71,  503, 28
qpack_status_end:

qpack_srv_name: db "linnea"
qpack_srv_name_len equ $ - qpack_srv_name
crange_name:    db "content-range"
crange_name_len equ $ - crange_name
; A 405 must say what the resource does allow (RFC 9110 15.5.6). Static files
; answer GET and HEAD; POST is h3's own echo and not something the resource
; supports, so it is deliberately not listed.
allow_name:     db "allow"
allow_name_len  equ $ - allow_name
allow_value:    db "GET, HEAD"
allow_value_len equ $ - allow_value

; --- relaying an upstream response head (linnea_qpack_encode_proxy) --------
; The hop this RESPONSE crossed, so the version it names is the one the
; upstream answered on, not the one the client asked over (RFC 9110 7.6.3) —
; the request's own Via says 3, and is added where that head is built. QPACK's
; static table has no `via` entry, so both halves are literals.
qp_via_name:    db "via"
qp_via_name_len equ $ - qp_via_name
qp_via_val:     db "1.1 linnea"
qp_via_val_len  equ $ - qp_via_val
qp_n_cl:        db "content-length"
; Fields that must never reach the client: hop-by-hop (RFC 9110 7.6.1) and the
; framing HTTP/3 carries itself. Content-length is judged separately — it is
; dropped only when we restate it from the body we actually captured.
qp_d_conn:      db "connection"
qp_d_ka:        db "keep-alive"
qp_d_tenc:      db "transfer-encoding"
qp_d_upg:       db "upgrade"
qp_d_trailer:   db "trailer"
qp_d_pauth:     db "proxy-authenticate"
qp_d_pconn:     db "proxy-connection"
; TE is hop-by-hop like the rest, and on HTTP/3 it is more than that: RFC 9114
; 4.2 makes any connection-specific field malformed, TE included unless its
; value is exactly "trailers". A backend answering "TE: gzip" would otherwise
; have us emit a message the client is entitled to reject.
qp_d_te:        db "te"
qp_drop_tab:
    dq qp_d_conn, 10
    dq qp_d_ka, 10
    dq qp_d_tenc, 17
    dq qp_d_upg, 7
    dq qp_d_trailer, 7
    dq qp_d_pauth, 18
    dq qp_d_pconn, 16
    dq qp_d_te, 2
    dq 0, 0
; Fields we would otherwise append a second copy of. The upstream's wins: a
; backend that states its own Date or its own policy is describing its own
; response, and two of either is a header a cache has to guess about.
qp_n_date:      db "date"
qp_n_server:    db "server"
qp_n_hsts:      db "strict-transport-security"
qp_n_nosniff:   db "x-content-type-options"
qp_note_tab:
    dq qp_n_date, 4, 1
    dq qp_n_server, 6, 2
    dq qp_n_hsts, 25, 4
    dq qp_n_nosniff, 22, 8
    dq 0, 0, 0

section .bss
; set by the h3 serve path once it has computed the opened file's validators
; (linnea_static_etag / linnea_static_lastmod); cleared for every response
; that describes no file. Read by linnea_qpack_encode_response.
linnea_qpack_send_validators: resq 1
; content-range value for a 206/416 (0 = absent); set/cleared per response
; by the h3 serve path
linnea_qpack_crange_ptr: resq 1
linnea_qpack_crange_len: resq 1
; Location, for a redirect location. Set by the serve path, cleared with the
; other per-response fields; static table index 12 is "location".
linnea_qpack_location_ptr: resq 1
linnea_qpack_location_len: resq 1
; the vhost's configured Cache-Control value (0 = none); set per request by
; the QUIC server before the serve, emitted only alongside the validators
linnea_qpack_ccontrol_ptr: resq 1
linnea_qpack_ccontrol_len: resq 1
; the coding of the variant served (0 plain, 1 gzip, 2 br); set per response
; by the h3 serve path, emitted as an indexed content-encoding line
linnea_qpack_cenc: resq 1
; the serving vhost's security headers (ptr 0 / 0 = not configured), set per
; request by the QUIC server before the serve
linnea_qpack_hsts_ptr: resq 1
linnea_qpack_hsts_len: resq 1
linnea_qpack_nosniff:  resq 1
; The matched static location whose bounded extra fields belong on this
; response.  Zero before routing and for proxy/redirect responses.
linnea_qpack_response_headers_ptr: resq 1
; The peer's SETTINGS_MAX_FIELD_SECTION_SIZE (0 = none advertised), set per request
; by the QUIC server from the connection, and a flag the response builder raises
; when a response would exceed it — the serve path then resets the stream rather
; than sending an oversized field section (Finding 8).
linnea_qpack_max_fss:  resq 1
linnea_qpack_fss_over: resq 1
; The size of the field section the last encode produced, counted the way RFC
; 9114 4.2.2 defines it: for every field, name length + value length + 32,
; UNCOMPRESSED. That is what SETTINGS_MAX_FIELD_SECTION_SIZE bounds. The
; encoded QPACK length is a different and always smaller number -- 626 bytes of
; field section for the static /hello.txt response encode to under 200 -- so
; comparing that to the setting under-enforces the limit by whatever the
; encoding saved, and a peer that advertised 200 was sent the 626 it said it
; would not take (audit-report-143 Finding 1).
linnea_qpack_fss_size: resq 1
; scratch for relaying an upstream response head: one field name, lowercased,
; and the re-derived content-length as digits
qp_nmbuf:  resb LINNEA_HTTP_MAX_FIELD_NAME
qp_numbuf: resb 24

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
    ; The sign used to be discarded (h3-14), accepting S=1 as though it were
    ; S=0 — but with Required Insert Count 0 a set sign makes the Base
    ; negative (0 - 0 - 1), which RFC 9204 4.5.1.2 forbids outright.
    cmp r12, r13
    jae .err
    test byte [r12], 0x80
    jnz .err
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

; qenc_status(rdi=out, esi=status) -> rdi advanced. The :status field line:
; a single indexed byte when the status is one the static table carries, else
; a literal with the :status name reference (24) and three ASCII digits.
; Clobbers rax/rcx/rdx/rsi/r8/r9/r10.
qenc_status:
    sub rsp, 24
    mov r10d, esi
    lea rsi, [qpack_status_tab]
    lea r9, [qpack_status_end]
.qs_loop:
    cmp rsi, r9
    jae .qs_literal
    movzx eax, word [rsi]
    cmp eax, r10d
    je .qs_found
    add rsi, 4
    jmp .qs_loop
.qs_found:
    movzx eax, word [rsi + 2]        ; static index
    mov cl, 6
    mov dl, 0xc0                     ; indexed field line, static table
    call qenc_int
    add rsp, 24
    ret
.qs_literal:
    mov eax, 24                      ; literal w/ name ref :status (static)
    mov cl, 4
    mov dl, 0x50
    push r10
    call qenc_int
    pop r10
    mov eax, r10d                    ; the status as three ASCII digits
    xor edx, edx
    mov ecx, 100
    div ecx
    add al, '0'
    mov [rsp], al
    mov eax, edx
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    mov [rsp + 1], al
    add dl, '0'
    mov [rsp + 2], dl
    mov rsi, rsp
    mov rdx, 3
    call qenc_str
    add rsp, 24
    ret

; linnea_qpack_reset_response() — clobbers no register, so it can be called
; with a builder's arguments already live in rdi/rsi/rdx/rcx/r8/r9.
; The fields below describe the ENTITY of one response: the variant's
; coding, the validators of the file it came from, its content-range, a
; redirect's target and the matched location's Cache-Control. They live in
; .bss — per WORKER, not per connection or per request — so until something
; clears them they describe whichever request this worker answered most
; recently, on any connection it holds.
;
; linnea_h3_serve clears the first four at entry, which covers every response
; it builds itself. A response built anywhere else has to clear them here, or
; it inherits a stranger's. Cache-Control is in the list because the canned
; errors are built before a request has routed, so no location owns it yet.
linnea_qpack_reset_response:
    mov qword [linnea_qpack_send_validators], 0
    mov qword [linnea_qpack_crange_ptr], 0
    mov qword [linnea_qpack_location_ptr], 0
    mov qword [linnea_qpack_cenc], 0
    mov qword [linnea_qpack_ccontrol_ptr], 0
    mov qword [linnea_qpack_response_headers_ptr], 0
    ret

; QROOM n — refuse the whole section unless n more bytes fit before the limit.
; rbx is the cursor, [rsp + 16] the limit. Clobbers rax, so it goes before the
; argument loads for the field it guards.
%macro QROOM 1
    lea rax, [rbx + %1]
    cmp rax, [rsp + 16]
    ja .too_long
%endmacro

; QFSS const[, len] — add one field's RFC 9114 4.2.2 contribution to the running
; field-section size: the constant part (name length + 32, and the value length
; when it is fixed) plus a register holding a variable value length. The total
; lives in memory rather than a register because the section is built across a
; dozen branches and both encoders have every register spoken for. It clobbers
; flags, so it goes beside a QROOM or after a branch, never between a cmp and
; its jcc.
%macro QFSS 1-2
    add qword [linnea_qpack_fss_size], %1
%if %0 > 1
    add qword [linnea_qpack_fss_size], %2
%endif
%endmacro

; linnea_qpack_encode_response(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=clen_ptr, r9=clen_len, r10=out limit) -> rax = field-section length,
;   or -1 when the section would not fit under the limit.
; Encodes :status (indexed if a static value, else literal with name ref 24),
; content-type (name ref 44) and content-length (name ref 4) with literal
; values — either is skipped when its pointer is 0 (a 304 carries neither).
; When linnea_qpack_crange_ptr is set, content-range follows (a literal name:
; RFC 9204's static table has no content-range entry). A 405 carries allow,
; also a literal name for the same reason. When
; linnea_qpack_send_validators is set (the serve path computed them for the
; file it opened), accept-ranges (indexed 32, skipped on a 304), etag (name
; ref 7), last-modified (name ref 10) and — when linnea_qpack_ccontrol_ptr
; is set — cache-control (name ref 36) follow. Every response ends with date
; (name ref 6) and server (name ref 92). No dynamic table — matches a
; zero-capacity decoder.
;
; Every variable-length value is checked against the limit before it is written.
; It used to write whatever it was given into a 768-byte fs_buf with no bound at
; all, while linnea_qpack_encode_proxy — the same file, the same job for a
; relayed head — carried an out limit and honoured it. The redirect Location
; made the difference reachable from the wire: a client's own request target is
; appended to it, so a 2000-byte path produced a 2070-byte section and ~1300
; bytes went past the end of the buffer.
linnea_qpack_encode_response:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 24                      ; [0]=out start, [16]=out limit
    mov rbx, rdi                     ; out cursor
    mov [rsp], rdi                   ; out start
    mov [rsp + 16], r10              ; the caller's buffer end
    mov r12d, esi                    ; status
    mov r13, rdx                     ; content-type ptr
    mov r14, rcx                     ; content-type len
    mov r15, r8                      ; content-length ptr
    mov rbp, r9                      ; content-length len
    mov qword [linnea_qpack_fss_size], 0
    ; field section prefix: Required Insert Count = 0, Delta Base = 0
    QROOM 8                          ; the prefix and the longest :status
    mov word [rbx], 0x0000
    add rbx, 2
    ; --- :status ---
    mov rdi, rbx
    mov esi, r12d
    call qenc_status
    QFSS 42                          ; ":status" (7) + three digits + 32
    mov rbx, rdi
.after_status:
    ; --- content-type: literal with name reference (static index 44) ---
    test r13, r13
    jz .no_ct
    QFSS 44, r14                     ; "content-type" (12) + 32
    QROOM r14 + 4
    mov rdi, rbx
    mov eax, 44
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, r13
    mov rdx, r14
    call qenc_str
    mov rbx, rdi
.no_ct:
    ; --- content-length: literal with name reference (static index 4) ---

    test r15, r15
    jz .no_clen
    QFSS 46, rbp                     ; "content-length" (14) + 32
    QROOM rbp + 4
    mov rdi, rbx
    mov eax, 4
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, r15
    mov rdx, rbp
    call qenc_str
    mov rbx, rdi
.no_clen:
    ; --- content-range, when the serve path set one (206 / 416). The QPACK
    ; static table has no content-range entry, so the name is a literal. ---
    cmp qword [linnea_qpack_crange_ptr], 0
    je .no_crange
    mov rax, [linnea_qpack_crange_len]
    QFSS 45, rax                     ; "content-range" (13) + 32
    QROOM rax + 18
    mov rdi, rbx
    mov rax, crange_name_len         ; literal field line with literal name
    mov cl, 3                        ; (001 N H namelen(3)), name not Huffman
    mov dl, 0x20
    call qenc_int
    lea rsi, [crange_name]
    mov rdx, crange_name_len
    mov rcx, rdx
    rep movsb
    mov rsi, [linnea_qpack_crange_ptr]
    mov rdx, [linnea_qpack_crange_len]
    call qenc_str
    mov rbx, rdi
.no_crange:
    ; --- allow, on a 405. RFC 9110 15.5.6 requires it, and like content-range
    ; the name is a literal: RFC 9204's static table has no allow entry. ---
    cmp r12d, 405
    jne .no_allow
    QFSS 46                          ; "allow" (5) + "GET, HEAD" (9) + 32
    QROOM 20
    mov rdi, rbx
    mov rax, allow_name_len          ; literal field line with literal name
    mov cl, 3                        ; (001 N H namelen(3)), name not Huffman
    mov dl, 0x20
    call qenc_int
    lea rsi, [allow_name]
    mov rdx, allow_name_len
    mov rcx, rdx
    rep movsb
    lea rsi, [allow_value]
    mov rdx, allow_value_len
    call qenc_str
    mov rbx, rdi
.no_allow:
    ; --- location, for a redirect ---
    ; Ahead of the validators branch on purpose: a redirect has no validators,
    ; so it takes the .vary_only shortcut below and would skip anything emitted
    ; after it. Put here first, the 301 went out with no Location at all — the
    ; status was right and the header simply absent, which curl showed by
    ; declining to follow it.
    cmp qword [linnea_qpack_location_ptr], 0
    je .no_location
    mov rax, [linnea_qpack_location_len]
    QFSS 40, rax                     ; "location" (8) + 32
    QROOM rax + 6
    mov rdi, rbx
    mov eax, 12                      ; location: name reference (RFC 9204 A)
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, [linnea_qpack_location_ptr]
    mov rdx, [linnea_qpack_location_len]
    call qenc_str
    mov rbx, rdi
.no_location:
    ; --- validators, when the serve path computed them for this response ---
    cmp qword [linnea_qpack_send_validators], 0
    je .vary_only                    ; no validators: an error response, but a
                                     ; 404 still has to carry Vary (see below)
    QROOM 3                          ; accept-ranges, vary and content-encoding
    cmp r12d, 304                    ; are one indexed byte each
    je .no_aranges                   ; a 304 restates no accept-ranges
    QFSS 50                          ; "accept-ranges" (13) + "bytes" (5) + 32
    mov rdi, rbx
    mov al, 0xc0 | 32                ; accept-ranges: bytes — indexed, static
    mov [rdi], al
    inc rdi
    mov rbx, rdi
.no_aranges:
    ; vary: accept-encoding (indexed 59) — a file response always varies on
    ; it, whether or not a compressed variant was found
    QFSS 51                          ; "vary" (4) + "accept-encoding" (15) + 32
    mov rdi, rbx
    mov byte [rdi], 0xc0 | 59
    inc rdi
    mov rbx, rdi
    ; content-encoding for a compressed variant — coding metadata a 304
    ; should not restate (like the h1 handler)
    cmp r12d, 304
    je .no_cenc
    mov rax, [linnea_qpack_cenc]
    test rax, rax
    jz .no_cenc
    mov rdi, rbx
    mov byte [rdi], 0xc0 | 43        ; content-encoding: gzip — indexed, static
    QFSS 52                          ; "content-encoding" (16) + "gzip" (4) + 32
    cmp rax, 2
    jne .cenc_put
    mov byte [rdi], 0xc0 | 42        ; content-encoding: br
    QFSS -2                          ; ...and "br" is two bytes shorter
.cenc_put:
    inc rdi
    mov rbx, rdi
.no_cenc:
    mov rax, [linnea_static_etag_len]
    QFSS 36, rax                     ; "etag" (4) + 32
    QFSS 45 + LINNEA_HTTP_DATE_LEN   ; "last-modified" (13) + the date + 32
    QROOM rax + LINNEA_HTTP_DATE_LEN + 8
    mov rdi, rbx
    mov eax, 7                       ; etag: literal with name reference
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    lea rsi, [linnea_static_etag]
    mov rdx, [linnea_static_etag_len]
    call qenc_str
    mov eax, 10                      ; last-modified
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    lea rsi, [linnea_static_lastmod]
    mov edx, LINNEA_HTTP_DATE_LEN
    call qenc_str
    mov rbx, rdi
    ; --- cache-control, when the vhost's location configures one ---
    cmp qword [linnea_qpack_ccontrol_ptr], 0
    je .no_ccontrol
    mov rax, [linnea_qpack_ccontrol_len]
    QFSS 45, rax                     ; "cache-control" (13) + 32
    QROOM rax + 6
    mov rdi, rbx
    mov eax, 36                      ; cache-control: name reference
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, [linnea_qpack_ccontrol_ptr]
    mov rdx, [linnea_qpack_ccontrol_len]
    call qenc_str
    mov rbx, rdi
.no_ccontrol:
.vary_only:
    ; A static path is content-negotiated even when it misses: a ".br" with no
    ; plain file beside it is served to whoever takes the encoding and 404s
    ; everyone else, so without Vary a shared cache stores this 404 under the
    ; bare URL and then hands it to the very clients the variant was for
    ; (h1-15's sibling on h3). The 406 needs it for a stronger reason: it is
    ; the one status that exists ONLY because of Accept-Encoding. It is absent
    ; from the list below because it did not exist when this was written, which
    ; is how the enumeration went stale (audit-report-37). 400/405/421/431/503
    ; do not depend on Accept-Encoding, and saying they do would split their
    ; cache entries for nothing.
    cmp r12d, 404
    je .emit_vary_h3
    cmp r12d, 406
    jne .no_validators
.emit_vary_h3:
    QFSS 51                          ; "vary" (4) + "accept-encoding" (15) + 32
    QROOM 2
    mov rdi, rbx
    mov byte [rdi], 0xc0 | 59        ; vary: accept-encoding — indexed, static
    inc rdi
    mov rbx, rdi
.no_validators:
    ; --- the vhost's security headers, on every response ---
    cmp qword [linnea_qpack_nosniff], 0
    je .no_nosniff
    QFSS 61                          ; the name (22) + "nosniff" (7) + 32
    QROOM 2
    mov rdi, rbx
    mov byte [rdi], 0xc0 | 61        ; x-content-type-options: nosniff —
    inc rdi                          ; name and value both in the table
    mov rbx, rdi
.no_nosniff:
    cmp qword [linnea_qpack_hsts_ptr], 0
    je .no_hsts
    mov rax, [linnea_qpack_hsts_len]
    QFSS 57, rax                     ; "strict-transport-security" (25) + 32
    QROOM rax + 6
    mov rdi, rbx
    mov eax, 56                      ; strict-transport-security: name ref
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, [linnea_qpack_hsts_ptr]
    mov rdx, [linnea_qpack_hsts_len]
    call qenc_str
    mov rbx, rdi
.no_hsts:
    ; --- bounded extra fields of the matched static location ---
    mov rax, [linnea_qpack_response_headers_ptr]
    test rax, rax
    jz .no_response_headers
    mov qword [rsp + 8], 0
.response_header_loop:
    mov rcx, [rsp + 8]
    cmp rcx, [rax + linnea_config_location.response_header_count]
    jae .no_response_headers
    imul rdx, rcx, linnea_config_response_header_size
    lea r10, [rax + rdx + linnea_config_location.response_headers]
    ; The whole legal set's literal encoding is at most one byte longer than
    ; its H1 wire budget (see linnea_config_response_header.wire_len).
    mov rax, [r10 + linnea_config_response_header.wire_len]
    inc rax
    QROOM rax
    mov rax, [r10 + linnea_config_response_header.field_size]
    add [linnea_qpack_fss_size], rax
    mov rdi, rbx
    lea rsi, [r10 + linnea_config_response_header.name]
    mov rdx, [r10 + linnea_config_response_header.name_len]
    lea rcx, [r10 + linnea_config_response_header.value]
    mov r8, [r10 + linnea_config_response_header.value_len]
    call qenc_lit
    mov rbx, rdi
    inc qword [rsp + 8]
    mov rax, [linnea_qpack_response_headers_ptr]
    jmp .response_header_loop
.no_response_headers:
    ; --- date and server, on every response ---
    QFSS 36 + LINNEA_HTTP_DATE_LEN   ; "date" (4) + the date + 32
    QFSS 44                          ; "server" (6) + "linnea" (6) + 32
    QROOM LINNEA_HTTP_DATE_LEN + qpack_srv_name_len + 8
    call linnea_time_http_now        ; rax = current IMF-fixdate text
    mov r13, rax
    mov rdi, rbx
    mov eax, 6                       ; date
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, r13
    mov edx, LINNEA_HTTP_DATE_LEN
    call qenc_str
    mov eax, 92                      ; server
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    lea rsi, [qpack_srv_name]
    mov edx, qpack_srv_name_len
    call qenc_str
    mov rbx, rdi
    ; length = cursor - start
    mov rax, rbx
    sub rax, [rsp]
    jmp .enc_ret
.too_long:
    ; The section does not fit the buffer it was given. Say so rather than write
    ; past the end: the caller answers with something that does fit. Same
    ; contract linnea_qpack_encode_proxy has had all along.
    mov rax, -1
.enc_ret:
    add rsp, 24
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; qenc_lit(rdi=out, rsi=name, rdx=namelen, rcx=val, r8=vallen) -> rdi advanced.
; A literal field line with a literal name (001 N H, 3-bit name length), which
; can carry any field — the static table has no entry for most of what a
; backend sends, and a name reference would only save a byte on the few it has.
qenc_lit:
    push rcx                         ; value
    push r8                          ; value length
    push rsi                         ; name
    push rdx                         ; name length
    mov rax, rdx
    mov cl, 3
    mov dl, 0x20
    call qenc_int
    pop rdx
    pop rsi
    mov rcx, rdx
    rep movsb                        ; the name, already lowercased by the caller
    pop rdx
    pop rsi
    jmp qenc_str

; linnea_qpack_encode_proxy(rdi=out, esi=status, rdx=head ptr, rcx=head len,
;   r8=content-length to state (-1 = state none and forward the upstream's,
;   -2 = state none and drop the upstream's too), r9=vhost server* or 0)
;   -> rax = field-section length, or -1 when it would not fit the reserve.
; Translates an upstream HTTP/1.1 response head into an HTTP/3 field section:
; the status as :status, then every field except the hop-by-hop ones and the
; framing HTTP/3 carries itself. Names are lowercased, as RFC 9114 4.1.2
; requires. Our own via, and the vhost's security headers, are appended — the
; latter only when the backend did not set them, so an application that sends
; its own policy still wins. Date and server are added only when the upstream
; sent neither, so a proxied response never carries two of either.
; Locals: [0] out start, [8] content-length, [16] vhost, [24] seen flags,
;         [32] name length, [40] colon offset, [48] out limit
linnea_qpack_encode_proxy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 72
    mov rbx, rdi                     ; out cursor
    mov [rsp], rdi                   ; out start
    mov [rsp + 8], r8                ; content-length to state
    mov [rsp + 16], r9               ; vhost
    mov qword [rsp + 24], 0          ; nothing seen yet
    lea rax, [rdi + LINNEA_H3_PROXY_RESERVE - 32]
    mov [rsp + 48], rax              ; the framing added after us needs the slack
    mov r12, rdx                     ; head
    mov r13, rcx                     ; head length
    mov qword [linnea_qpack_fss_size], 0
    ; field section prefix: Required Insert Count = 0, Delta Base = 0
    mov word [rbx], 0x0000
    add rbx, 2
    mov rdi, rbx
    call qenc_status
    QFSS 42                          ; ":status" (7) + three digits + 32
    mov rbx, rdi
    ; --- content-length, when it is ours to state. The captured body's length
    ; is what the client will actually receive, whatever the upstream framed.
    mov rax, [rsp + 8]
    cmp rax, -1
    je .ep_walk
    cmp rax, -2
    je .ep_walk                      ; the status forbids one: state none, and
                                     ; .ep_classify drops the upstream's below,
                                     ; since -2 is "not -1" to the test there
    mov rdi, rax
    lea rsi, [qp_numbuf]
    call linnea_string_from_u64      ; rax = digits written
    QFSS 46, rax                     ; "content-length" (14) + 32
    push rax                         ; keep the digit count across the name
    mov rdi, rbx
    mov eax, 4                       ; content-length: name reference (static 4)
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    pop rdx                          ; the digit count is the value's length
    lea rsi, [qp_numbuf]
    call qenc_str
    mov rbx, rdi
.ep_walk:
    ; --- the upstream's own fields ---
    xor r14d, r14d                   ; line cursor
.ep_status_eol:
    cmp r14, r13
    jae .ep_done
    cmp byte [r12 + r14], 13
    je .ep_status_done
    inc r14
    jmp .ep_status_eol
.ep_status_done:
    add r14, 2
.ep_line:
    cmp r14, r13
    jae .ep_done
    mov r15, r14
.ep_eol:
    cmp r15, r13
    jae .ep_done
    cmp byte [r12 + r15], 13
    je .ep_have
    inc r15
    jmp .ep_eol
.ep_have:
    cmp r15, r14
    je .ep_done                      ; the empty line ends the head
    mov rdx, r14                     ; split at the colon
.ep_colon:
    cmp rdx, r15
    jae .ep_next                     ; no colon: not a field line
    cmp byte [r12 + rdx], ':'
    je .ep_colon_found
    inc rdx
    jmp .ep_colon
.ep_colon_found:
    mov [rsp + 40], rdx
    mov rax, rdx
    sub rax, r14                     ; name length
    test rax, rax
    jz .ep_next
    cmp rax, LINNEA_HTTP_MAX_FIELD_NAME
    ja .ep_next                      ; a backstop on this buffer, not a
                                     ; policy: the shared validator has
                                     ; already refused a longer name, so
                                     ; reaching here would be a bug. It
                                     ; WAS the policy, at 64 bytes and
                                     ; enforced only here, which erased
                                     ; valid fields h1 forwarded
                                     ; (audit-report-12 Finding 2).
    mov [rsp + 32], rax
    ; lowercase the name into the scratch (HTTP/3 forbids uppercase, 4.1.2)
    lea rdi, [qp_nmbuf]
    lea rsi, [r12 + r14]
    mov rcx, rax
.ep_lower:
    movzx edx, byte [rsi]
    cmp dl, 'A'
    jb .ep_lower_put
    cmp dl, 'Z'
    ja .ep_lower_put
    or dl, 0x20
.ep_lower_put:
    mov [rdi], dl
    inc rsi
    inc rdi
    dec rcx
    jnz .ep_lower
    ; note the ones we would otherwise duplicate, and drop what must not travel
    lea rdi, [qp_nmbuf]
    mov rsi, [rsp + 32]
    ; "ours" here means "not the upstream's to send": either we restate it from
    ; the captured body, or the status forbids the field entirely (-2).
    xor edx, edx
    cmp qword [rsp + 8], -1
    setne dl
    call .ep_classify                ; eax = 1 to drop, rdx = the seen bit
    mov [rsp + 56], rdx              ; hold it: a field only counts as the
                                     ; backend's policy once it has survived
                                     ; EVERY filter, and the dynamic Connection
                                     ; check below is one of them. ORing it here
                                     ; let an upstream name its own
                                     ; Strict-Transport-Security in Connection
                                     ; and thereby suppress ours, leaving the
                                     ; client with neither (audit-report-15
                                     ; Finding 2).
    test eax, eax
    jnz .ep_next
    ; ...and the fields this head's own Connection value names (RFC 9110 7.6.1,
    ; and RFC 9114 4.2 forbids them in an HTTP/3 message outright). qp_drop_tab
    ; is the fixed half of the rule; this is the half the peer declares
    ; (audit-report-10 Finding 2). Interim heads are re-encoded through here
    ; too, each with its own head, so the rule cannot drift between them.
    mov rdi, r12                     ; the head being re-encoded...
    mov rsi, r13                     ; ...and its length
    lea rdx, [qp_nmbuf]
    mov rcx, [rsp + 32]
    call linnea_http_head_conn_named
    test eax, eax
    jnz .ep_next
    mov rdx, [rsp + 56]              ; it travels: now it counts
    or [rsp + 24], rdx
    ; The VALUE, not the field line. HTTP/3 carries no field-line syntax, so the
    ; OWS around an HTTP/1 value is not something to translate -- it is a
    ; delimiter that has no meaning here. Leading SP alone was stripped
    ; (audit-report-14 Finding 2).
    mov rdx, [rsp + 40]
    inc rdx                          ; past the colon
    lea rdi, [r12 + rdx]
    mov rsi, r15
    sub rsi, rdx                     ; the raw span between colon and CR
    call linnea_string_trim_ows      ; -> rax = value, rdx = its length
    mov rcx, rdx                     ; value length
    mov rdx, rax                     ; value pointer
.ep_vdone:
    ; room? A head that outgrows the reserve cannot be written in front of the
    ; body, so the caller answers 502 rather than send a truncated field section
    mov rax, rbx
    add rax, [rsp + 32]
    add rax, rcx
    cmp rax, [rsp + 48]
    ja .ep_toolong
    mov rax, [rsp + 32]              ; this field's name length...
    add rax, rcx                     ; ...and its value's
    QFSS 32, rax
    mov rdi, rbx
    lea rsi, [qp_nmbuf]
    mov r8, rcx                      ; value length
    mov rcx, rdx                     ; value pointer (already trimmed)
    mov rdx, [rsp + 32]              ; name length
    call qenc_lit
    mov rbx, rdi
.ep_next:
    lea r14, [r15 + 2]
    jmp .ep_line
.ep_done:
    ; the hop this response crossed (RFC 9110 7.6.3)
    mov rdi, rbx
    lea rsi, [qp_via_name]
    mov rdx, qp_via_name_len
    lea rcx, [qp_via_val]
    mov r8, qp_via_val_len
    call qenc_lit
    QFSS 32 + qp_via_name_len + qp_via_val_len
    mov rbx, rdi
    ; --- the vhost's security headers, when the backend set neither ---
    mov r14, [rsp + 16]
    test r14, r14
    jz .ep_datesrv
    test qword [rsp + 24], 4         ; the upstream sent its own HSTS
    jnz .ep_nosniff
    cmp qword [r14 + linnea_config_server.hsts_len], 0
    je .ep_nosniff
    mov rdi, rbx
    mov eax, 56                      ; strict-transport-security: name ref
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    lea rsi, [r14 + linnea_config_server.hsts]
    mov rdx, [r14 + linnea_config_server.hsts_len]
    call qenc_str
    mov rbx, rdi
    mov rax, [r14 + linnea_config_server.hsts_len]
    QFSS 57, rax                     ; "strict-transport-security" (25) + 32
.ep_nosniff:
    test qword [rsp + 24], 8
    jnz .ep_datesrv
    cmp qword [r14 + linnea_config_server.nosniff], 0
    je .ep_datesrv
    mov rdi, rbx
    mov byte [rdi], 0xc0 | 61        ; x-content-type-options: nosniff —
    inc rdi                          ; name and value both in the static table
    mov rbx, rdi
    QFSS 61                          ; the name (22) + "nosniff" (7) + 32
.ep_datesrv:
    ; --- date and server, each only when the upstream sent none ---
    test qword [rsp + 24], 1
    jnz .ep_server
    call linnea_time_http_now        ; rax = current IMF-fixdate text
    mov rdi, rbx
    mov r14, rax
    mov eax, 6                       ; date: name reference
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    mov rsi, r14
    mov edx, LINNEA_HTTP_DATE_LEN
    call qenc_str
    QFSS 36 + LINNEA_HTTP_DATE_LEN   ; "date" (4) + the date + 32
    mov rbx, rdi
.ep_server:
    test qword [rsp + 24], 2
    jnz .ep_fin
    mov rdi, rbx
    mov eax, 92                      ; server: name reference
    mov cl, 4
    mov dl, 0x50
    call qenc_int
    lea rsi, [qpack_srv_name]
    mov edx, qpack_srv_name_len
    call qenc_str
    QFSS 38 + qpack_srv_name_len     ; "server" (6) + the name + 32
    mov rbx, rdi
.ep_fin:
    cmp rbx, [rsp + 48]
    ja .ep_toolong
    mov rax, rbx
    sub rax, [rsp]
    jmp .ep_ret
.ep_toolong:
    mov rax, -1
.ep_ret:
    add rsp, 72
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .ep_classify(rdi = lowercased name, rsi = its length, edx = 1 when
;   content-length is ours to state) -> eax = 1 when the field must not be
;   forwarded, rdx = the seen bit for a field we would otherwise duplicate.
; Two tables: one of fields that must never travel to the client (hop-by-hop,
; RFC 9110 7.6.1, plus the framing HTTP/3 carries itself), and one of fields we
; add ourselves and so must notice the upstream already sending.
.ep_classify:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r14d, edx                    ; content-length is ours
    xor r13d, r13d                   ; the seen bit, if any
    ; content-length, dropped only when we restate it from the captured body
    cmp r12, 14
    jne .cl_note_scan
    test r14d, r14d
    jz .cl_note_scan
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [qp_n_cl]
    mov ecx, 14
    call linnea_string_iequal
    test eax, eax
    jnz .cl_yes
.cl_note_scan:
    lea r14, [qp_note_tab]
.cl_note:
    mov rcx, [r14]
    test rcx, rcx
    jz .cl_drop_scan
    cmp qword [r14 + 8], r12
    jne .cl_note_next
    push r14
    mov rdi, rbx
    mov rsi, r12
    mov rdx, rcx
    mov rcx, r12
    call linnea_string_iequal
    pop r14
    test eax, eax
    jz .cl_note_next
    mov r13, [r14 + 16]              ; this field's seen bit
    jmp .cl_drop_scan
.cl_note_next:
    add r14, 24
    jmp .cl_note
.cl_drop_scan:
    lea r14, [qp_drop_tab]
.cl_drop:
    mov rcx, [r14]
    test rcx, rcx
    jz .cl_keep
    cmp qword [r14 + 8], r12
    jne .cl_drop_next
    push r14
    mov rdi, rbx
    mov rsi, r12
    mov rdx, rcx
    mov rcx, r12
    call linnea_string_iequal
    pop r14
    test eax, eax
    jnz .cl_yes
.cl_drop_next:
    add r14, 16
    jmp .cl_drop
.cl_yes:
    mov eax, 1
    xor edx, edx                     ; a dropped field notes nothing
    jmp .cl_ret
.cl_keep:
    xor eax, eax
    mov rdx, r13
.cl_ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
