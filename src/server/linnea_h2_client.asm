; ============================================================================
; linnea_h2_client.asm — backend HTTP/2 client leg (roadmap #1 Tier 1).
;
; Single-stream (id 1) h2 client, built as an h1<->h2 translator. The blocking
; entry linnea_h2c_exchange runs one request/response over a connected byte
; socket (h2c plaintext for the fixture; the kTLS backend socket in production —
; identical framing). It parses the proxy's normalized h1 request head into an
; HPACK HEADERS block (+ DATA from the captured body) and synthesizes an h1
; response from the decoded h2 response. Response HPACK decode reuses the global
; primitives hpack_int/hpack_str + the dyn-table helpers, over a private block
; walk (see docs/design/backend-h2-plan.md).
;
; This is the tested reference; a resumable driver for the proxy loop is layered
; on top of the same pieces later, mirroring the TLS client.
; ============================================================================

default rel

%include "linnea_syscall.inc"
%include "linnea_h2_client.inc"

global linnea_h2c_exchange
global linnea_h2c_resp_buf
global h2c_chunk_cap                     ; test knob: cap the blocking read chunk

; Response HPACK decode reuses these (already global in linnea_hpack.asm) plus
; the dyn-table helpers exported for this leg.
extern hpack_int
extern hpack_str
extern hpack_dyn_get
extern hpack_dyn_insert
extern hpack_dyn_evict
extern hpack_dyn_reset
extern hpack_static_tab
extern hpack_static_blob

; RFC 7541 Appendix A: fixed. Duplicated as equ (the data .inc that defines them
; also emits the table itself, which this object must not re-emit).
HPACK_STATIC_COUNT      equ 61
HPACK_STATIC_ENTRY_SIZE equ 16

section .rodata

h2c_preface:  db "PRI * HTTP/2.0", 13, 10, 13, 10, "SM", 13, 10, 13, 10
h2c_preface_len equ $ - h2c_preface

http11:       db "HTTP/1.1 "
http11_len    equ $ - http11
hdr_cl:       db "content-length: "
hdr_cl_len    equ $ - hdr_cl
crlf:         db 13, 10

; hop-by-hop / connection-specific field names never relayed (RFC 9113 8.2.2).
; lowercase; matched against the decoded (already-lowercase) response names.
section .rodata
hop_connection:  db "connection"
hop_connection_len equ $ - hop_connection
hop_te:          db "transfer-encoding"
hop_te_len       equ $ - hop_te
hop_keepalive:   db "keep-alive"
hop_keepalive_len equ $ - hop_keepalive
hop_upgrade:     db "upgrade"
hop_upgrade_len  equ $ - hop_upgrade
hop_proxyconn:   db "proxy-connection"
hop_proxyconn_len equ $ - hop_proxyconn
hop_cl:          db "content-length"
hop_cl_len       equ $ - hop_cl

hop_tefield:     db "te"
hop_tefield_len  equ $ - hop_tefield
val_trailers:    db "trailers"
val_trailers_len equ $ - val_trailers

pseudo_status:   db ":status"
pseudo_status_len equ $ - pseudo_status

extern linnea_http_status_no_content

; The window we advertise is a promise about what we will accept. Assert at
; assembly time that the buffers can keep it, so lowering a cap without lowering
; the advertisement fails the build instead of failing a backend (audit-report-64).
%if LINNEA_H2C_INITWIN > LINNEA_H2C_D_BODY_CAP
%error "advertised stream window exceeds the response body the driver retains"
%endif
%if LINNEA_H2C_INITWIN > LINNEA_H2C_RESP_CAP
%error "advertised stream window exceeds the blocking oracle's response buffer"
%endif

section .bss
alignb 16
linnea_h2c_resp_buf: resb LINNEA_H2C_RESP_CAP   ; synthesized h1 response (out)
h2c_body_buf:  resb LINNEA_H2C_RESP_CAP         ; response body accumulation
h2c_out_buf:   resb LINNEA_H2C_OUT_CAP          ; outbound frame staging
h2c_frame_buf: resb 20480                       ; one inbound frame (hdr+payload)
h2c_hdrblk:    resb LINNEA_H2C_HDRBLK_CAP       ; reassembled response header block
h2c_hdrlines:  resb LINNEA_H2C_HDRBLK_CAP       ; synthesized "name: value\r\n" lines
h2c_scratch:   resb LINNEA_H2C_SCRATCH_CAP      ; hpack scratch (Huffman/dyn copies)
h2c_carrier:   resb linnea_h2_req_size          ; scratch/dyn carrier for the primitives
h2c_dyn:       resb linnea_hpack_dyn_size       ; response decoder dynamic table

h2c_chunk_cap: resq 1                           ; 0 = read LINNEA_H2C_RXCHUNK at a time
h2c_fd:        resq 1
h2c_status:    resq 1                           ; decoded response :status
h2c_hdrlines_len: resq 1
; Set by h2c_emit for any field whose name starts with ':'. Legal in a header
; section, MALFORMED in a trailer section (RFC 9113 8.1) — which is the only
; place it is read. Cleared before every decode.
h2c_saw_pseudo: resq 1
h2c_hdr_open:  resq 1                           ; a header block awaits its CONTINUATION
h2c_preface_ok: resq 1                          ; the server's SETTINGS preface has arrived
h2c_field_seen: resq 1                          ; a field representation has been
                                                ; decoded in THIS block (7541 4.2)
h2c_status_seen: resq 1                         ; this block already carried a :status
h2c_regular_seen: resq 1                        ; ...and a regular field (8.3 ordering)
h2c_cl_seen:   resq 1                           ; this block declared a content-length
h2c_cl_val:    resq 1                           ; ...and its value (8.1.1)
h2c_tr_cl_s:   resq 1                           ; held across a trailer decode
h2c_tr_cl_v:   resq 1
h2c_is_head:   resq 1                           ; the REQUEST was HEAD
h2c_tr_status: resq 1                           ; status/lines held across a
h2c_tr_lines:  resq 1                           ; trailer decode (see below)
h2c_body_len:  resq 1
h2c_stream_win: resq 1                          ; our stream-1 SEND window
h2c_conn_win:  resq 1                           ; connection SEND window
h2c_peer_init_win: resq 1                       ; peer's INITIAL_WINDOW_SIZE (6.9.2)
h2c_scheme:    resq 1
h2c_lit_form:  resq 1                           ; transient: current literal prefix width
; request-head parse spans
h2c_m_ptr:     resq 1
h2c_m_len:     resq 1
h2c_t_ptr:     resq 1
h2c_t_len:     resq 1
h2c_host_ptr:  resq 1
h2c_host_len:  resq 1
h2c_hdr_start: resq 1                            ; first header line in the h1 head
h2c_head_end:  resq 1                            ; end of the h1 head
h2c_n_ptr:     resq 1                            ; current header name span
h2c_n_len:     resq 1
h2c_v_ptr:     resq 1                            ; current header value span
h2c_v_len:     resq 1
; last frame read
h2c_fr_flags:  resq 1
h2c_fr_sid:    resq 1
h2c_fr_len:    resq 1
; response assembly
h2c_hdrblk_len: resq 1                           ; bytes in h2c_hdrblk
h2c_hdr_es:    resq 1                            ; END_STREAM flag on the response HEADERS
; --- resumable driver (proxy path): the current leg context, set at each driver
; entry; the driver's own helpers read/write per-leg state through it. ---
h2c_ctx:       resq 1

section .text

; ============================================================================
; linnea_h2c_exchange(rdi=fd, rsi=h1head, rdx=h1len, rcx=body_ptr, r8=body_len,
;                     r9=scheme) -> rax = length written to linnea_h2c_resp_buf,
;   or a negative LINNEA_H2C_* sentinel. Blocking.
; ============================================================================
linnea_h2c_exchange:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8                            ; align
    mov [h2c_fd], rdi
    mov [h2c_scheme], r9
    mov qword [h2c_hdrlines_len], 0
    mov qword [h2c_body_len], 0
    mov qword [h2c_status], 0
    mov qword [h2c_stream_win], 65535     ; default until server SETTINGS
    mov qword [h2c_conn_win], 65535
    mov qword [h2c_peer_init_win], 65535
    mov r14, rsi                          ; h1 head ptr
    mov r15, rdx                          ; h1 head len
    mov r12, rcx                          ; body ptr
    mov r13, r8                           ; body len

    ; init the decoder carrier + its dynamic table
    call h2c_init_carrier
    mov qword [h2c_preface_ok], 0     ; a new connection owes us its preface

    ; --- build the outbound preface + SETTINGS + HEADERS into h2c_out_buf ---
    lea rdi, [h2c_out_buf]
    lea rsi, [h2c_preface]
    mov rcx, h2c_preface_len
    rep movsb                             ; rdi advanced
    ; SETTINGS frame: length=6, type=4, flags=0, sid=0, payload {0x0004, initwin}
    mov byte [rdi + 0], 0
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 18                ; three settings
    mov byte [rdi + 3], LINNEA_H2C_FT_SETTINGS
    mov byte [rdi + 4], 0
    mov dword [rdi + 5], 0                ; sid 0
    add rdi, 9
    mov byte [rdi + 0], 0                 ; id hi
    mov byte [rdi + 1], LINNEA_H2C_SET_INITWIN
    ; INITIAL_WINDOW_SIZE value, big-endian
    mov byte [rdi + 2], (LINNEA_H2C_INITWIN >> 24) & 0xff
    mov byte [rdi + 3], (LINNEA_H2C_INITWIN >> 16) & 0xff
    mov byte [rdi + 4], (LINNEA_H2C_INITWIN >> 8) & 0xff
    mov byte [rdi + 5], LINNEA_H2C_INITWIN & 0xff
    add rdi, 6
    ; ...and the size of response header list we will actually accept. Unsent,
    ; its default is unlimited, so the buffer bound became a promise we had not
    ; made (audit follow-up: nginx, 18188 bytes, refused).
    mov byte [rdi + 0], 0
    mov byte [rdi + 1], LINNEA_H2C_SET_MAXHDRS
    mov byte [rdi + 2], (LINNEA_H2C_MAXHDRS >> 24) & 0xff
    mov byte [rdi + 3], (LINNEA_H2C_MAXHDRS >> 16) & 0xff
    mov byte [rdi + 4], (LINNEA_H2C_MAXHDRS >> 8) & 0xff
    mov byte [rdi + 5], LINNEA_H2C_MAXHDRS & 0xff
    add rdi, 6
    ; We do not want pushes, and the DEFAULT is that we do (RFC 9113 6.5.2:
    ; ENABLE_PUSH starts at 1). Left unsaid, a backend was entitled to
    ; PUSH_PROMISE at us and we would have ignored the frames -- and a promise
    ; split across a CONTINUATION now fails the leg outright against the 6.10
    ; gate. Saying 0 makes a push a protocol error the backend must not commit:
    ; a rule with an owner, rather than a frame we quietly drop.
    mov byte [rdi + 0], 0
    mov byte [rdi + 1], LINNEA_H2C_SET_PUSH
    mov dword [rdi + 2], 0                ; ENABLE_PUSH = 0
    add rdi, 6

    ; HEADERS frame: build the HPACK block first into h2c_hdrblk, then frame it.
    push rdi                              ; save out cursor
    call h2c_build_headers               ; -> rax = block len in h2c_hdrblk (or <0)
    pop rdi
    test rax, rax
    js .fail_err
    mov rbp, rax                          ; block len
    ; frame header — length (24-bit big-endian)
    mov rax, rbp
    shr rax, 16
    mov [rdi + 0], al
    mov rax, rbp
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], bpl
    mov byte [rdi + 3], LINNEA_H2C_FT_HEADERS
    ; flags: END_HEADERS always; END_STREAM iff no body
    mov al, LINNEA_H2C_FL_END_HEADERS
    test r13, r13
    jnz .have_body_flag
    or al, LINNEA_H2C_FL_END_STREAM
.have_body_flag:
    mov [rdi + 4], al
    mov dword [rdi + 5], 0x01000000       ; stream id 1, big-endian
    add rdi, 9
    lea rsi, [h2c_hdrblk]
    mov rcx, rbp
    rep movsb
    ; send preface+SETTINGS+HEADERS
    lea rax, [h2c_out_buf]
    mov rdx, rdi
    sub rdx, rax                          ; total length
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_out_buf]
    call h2c_send_all
    test rax, rax
    js .fail_err

    ; --- send request body as DATA frames (if any) ---
    test r13, r13
    jz .read_loop
    mov rsi, r12                          ; body ptr
    mov rdx, r13                          ; body len
    call h2c_send_body
    test rax, rax
    js .fail_err

.read_loop:
    ; drive the response: read frames until END_STREAM on stream 1, or an error.
    call h2c_run_response                 ; -> rax = 0 done, or negative sentinel
    test rax, rax
    js .propagate
    ; compose the h1 response into linnea_h2c_resp_buf
    call h2c_compose
    ; rax = length
    jmp .done

.propagate:
    ; rax already a negative sentinel
    jmp .done
.fail_err:
    mov rax, LINNEA_H2C_ERR
.done:
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; h2c_init_carrier — point the carrier at scratch + a fresh dynamic table.
h2c_init_carrier:
    lea rax, [h2c_scratch]
    mov [h2c_carrier + linnea_h2_req.scratch], rax
    lea rcx, [rax + LINNEA_H2C_SCRATCH_CAP]
    mov [h2c_carrier + linnea_h2_req.scratch_end], rcx
    lea rdx, [h2c_dyn]
    mov [h2c_carrier + linnea_h2_req.dyn], rdx
    mov rdi, rdx
    call hpack_dyn_reset
    ret

; ----------------------------------------------------------------------------
; h2c_send_all(edi=fd, rsi=buf, rdx=len) -> rax 0 / -1
h2c_send_all:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .ok
    mov eax, LINNEA_SYS_WRITE
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    jle .fail
    add r12, rax
    sub r13, rax
    jmp .loop
.ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; HPACK encode primitives (stateless; static-index refs + literals only).
; ============================================================================
; h2c_enc_int(rdi=out, rax=value, cl=N bits, r8b=flags) -> rdi advanced.
h2c_enc_int:
    mov edx, 1
    shl edx, cl
    dec edx                       ; mask = (1<<N)-1
    cmp rax, rdx
    jae .big
    or al, r8b
    mov [rdi], al
    inc rdi
    ret
.big:
    mov r9d, r8d
    or r9b, dl
    mov [rdi], r9b
    inc rdi
    sub rax, rdx
.loop:
    cmp rax, 0x80
    jb .last
    mov r9, rax
    and r9d, 0x7f
    or r9d, 0x80
    mov [rdi], r9b
    inc rdi
    shr rax, 7
    jmp .loop
.last:
    mov [rdi], al
    inc rdi
    ret

; h2c_enc_str(rdi=out, rsi=str, rdx=len) -> rdi advanced (raw, H=0).
h2c_enc_str:
    push rbx
    push r12
    mov rbx, rsi
    mov r12, rdx
    mov rax, r12
    mov cl, 7
    xor r8d, r8d
    call h2c_enc_int
    mov rsi, rbx
    mov rcx, r12
    rep movsb
    pop r12
    pop rbx
    ret

; h2c_enc_str_lc(rdi=out, rsi=str, rdx=len) -> rdi advanced (lowercased name).
h2c_enc_str_lc:
    push rbx
    push r12
    mov rbx, rsi
    mov r12, rdx
    mov rax, r12
    mov cl, 7
    xor r8d, r8d
    call h2c_enc_int
    mov rsi, rbx
    mov rcx, r12
.lc:
    test rcx, rcx
    jz .done
    mov al, [rsi]
    cmp al, 'A'
    jb .keep
    cmp al, 'Z'
    ja .keep
    add al, 0x20
.keep:
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .lc
.done:
    pop r12
    pop rbx
    ret

; h2c_emit_method(rdi=out) -> rdi advanced. GET->0x82, POST->0x83, else literal.
h2c_emit_method:
    mov rsi, [h2c_m_ptr]
    mov rdx, [h2c_m_len]
    ; A HEAD response carries the content-length a GET would have returned and
    ; no body at all -- legal, and byte-for-byte what a mismatch looks like. The
    ; leg has to remember which it asked for (RFC 9110 9.3.2).
    mov qword [h2c_is_head], 0
    cmp rdx, 4
    jne .nothead
    cmp dword [rsi], 'HEAD'
    jne .nothead
    mov qword [h2c_is_head], 1
.nothead:
    cmp rdx, 3
    jne .np
    cmp byte [rsi], 'G'
    jne .np
    cmp byte [rsi+1], 'E'
    jne .np
    cmp byte [rsi+2], 'T'
    jne .np
    mov byte [rdi], 0x82
    inc rdi
    ret
.np:
    cmp rdx, 4
    jne .other
    cmp byte [rsi], 'P'
    jne .other
    cmp byte [rsi+1], 'O'
    jne .other
    cmp byte [rsi+2], 'S'
    jne .other
    cmp byte [rsi+3], 'T'
    jne .other
    mov byte [rdi], 0x83
    inc rdi
    ret
.other:
    mov rax, 2                    ; :method name index 2, without indexing
    mov cl, 4
    xor r8d, r8d
    call h2c_enc_int
    mov rsi, [h2c_m_ptr]
    mov rdx, [h2c_m_len]
    call h2c_enc_str
    ret

; h2c_emit_scheme(rdi=out) -> rdi advanced.
h2c_emit_scheme:
    cmp qword [h2c_scheme], LINNEA_H2C_SCHEME_HTTPS
    je .https
    mov byte [rdi], 0x86          ; :scheme http
    inc rdi
    ret
.https:
    mov byte [rdi], 0x87          ; :scheme https
    inc rdi
    ret

; ============================================================================
; h1 request-head parsing -> HPACK HEADERS block (into h2c_hdrblk).
; ============================================================================
; h2c_is_host(rdi=ptr, rsi=len) -> rax = 1 iff "host" (ci). Preserves r12/r13/rbp.
h2c_is_host:
    cmp rsi, 4
    jne .no
    mov al, [rdi]
    or al, 0x20
    cmp al, 'h'
    jne .no
    mov al, [rdi+1]
    or al, 0x20
    cmp al, 'o'
    jne .no
    mov al, [rdi+2]
    or al, 0x20
    cmp al, 's'
    jne .no
    mov al, [rdi+3]
    or al, 0x20
    cmp al, 't'
    jne .no
    mov rax, 1
    ret
.no:
    xor eax, eax
    ret

; h2c_eq(rdi=ptr, rsi=len, rdx=lit, rcx=litlen) -> rax=1 equal, byte for byte.
;
; For a PSEUDO-HEADER name, case-insensitive matching is not a convenience, it
; is a bug: RFC 9113 8.2.1 forbids uppercase in a field name, and a
; pseudo-header name is a field name. ":Status" is not another spelling of
; ":status" -- it is malformed, and matching it here let it past the validity
; gate that only the ordinary-field branch reaches (audit-report-65). nghttp2
; refuses it as an invalid field.
;
; The ci comparisons that remain are for ORDINARY field names, and they are
; reached only after h2c_field_ok has already refused every uppercase byte, so
; by then both sides are lowercase and the fold is a no-op.
h2c_eq:
    cmp rsi, rcx
    jne .ne
    xor r8, r8
.el:
    cmp r8, rsi
    jae .eq
    mov al, [rdi + r8]
    cmp al, [rdx + r8]
    jne .ne
    inc r8
    jmp .el
.eq:
    mov rax, 1
    ret
.ne:
    xor eax, eax
    ret

; h2c_ci_eq(rdi=ptr, rsi=len, rdx=lit, rcx=litlen) -> rax=1 equal (ci).
; Uses only rax/r8/r9; preserves rdi/rsi/rdx/rcx and r12-r15/rbp/rbx.
h2c_ci_eq:
    cmp rsi, rcx
    jne .no
    xor r8, r8
.l:
    cmp r8, rsi
    jae .yes
    mov al, [rdi + r8]
    or al, 0x20
    mov r9b, [rdx + r8]
    or r9b, 0x20
    cmp al, r9b
    jne .no
    inc r8
    jmp .l
.yes:
    mov rax, 1
    ret
.no:
    xor eax, eax
    ret

; h2c_is_skip(rdi=name ptr, rsi=name len) -> rax=1 to drop (host/hop-by-hop/CL).
h2c_is_skip:
    call h2c_is_host
    test rax, rax
    jnz .skip
    lea rdx, [hop_connection]
    mov rcx, hop_connection_len
    call h2c_ci_eq
    test rax, rax
    jnz .skip
    lea rdx, [hop_te]
    mov rcx, hop_te_len
    call h2c_ci_eq
    test rax, rax
    jnz .skip
    lea rdx, [hop_keepalive]
    mov rcx, hop_keepalive_len
    call h2c_ci_eq
    test rax, rax
    jnz .skip
    lea rdx, [hop_upgrade]
    mov rcx, hop_upgrade_len
    call h2c_ci_eq
    test rax, rax
    jnz .skip
    lea rdx, [hop_proxyconn]
    mov rcx, hop_proxyconn_len
    call h2c_ci_eq
    test rax, rax
    jnz .skip
    lea rdx, [hop_cl]
    mov rcx, hop_cl_len
    call h2c_ci_eq
    test rax, rax
    jnz .skip
    xor eax, eax
    ret
.skip:
    mov rax, 1
    ret

; h2c_next_hdr_line(r12=cur, r13=end) -> rax=1 (spans in h2c_n_*/h2c_v_*), r12
; advanced past the line; rax=0 at end-of-headers. Preserves r13/rbp/rbx/r14/r15.
h2c_next_hdr_line:
    cmp r12, r13
    jae .end
    mov al, [r12]
    cmp al, 13
    je .end
    cmp al, 10
    je .end
    mov [h2c_n_ptr], r12
.nm:
    cmp r12, r13
    jae .end
    cmp byte [r12], ':'
    je .nmd
    inc r12
    jmp .nm
.nmd:
    mov rax, r12
    sub rax, [h2c_n_ptr]
    mov [h2c_n_len], rax
    inc r12
.ows:
    cmp r12, r13
    jae .v0
    mov al, [r12]
    cmp al, ' '
    je .owsa
    cmp al, 9
    je .owsa
    jmp .v0
.owsa:
    inc r12
    jmp .ows
.v0:
    mov [h2c_v_ptr], r12
.vl:
    cmp r12, r13
    jae .vld
    mov al, [r12]
    cmp al, 13
    je .vld
    cmp al, 10
    je .vld
    inc r12
    jmp .vl
.vld:
    mov rax, r12
    sub rax, [h2c_v_ptr]
.trim:
    test rax, rax
    jz .vset
    mov rcx, [h2c_v_ptr]
    mov dl, [rcx + rax - 1]
    cmp dl, ' '
    je .trimd
    cmp dl, 9
    je .trimd
    jmp .vset
.trimd:
    dec rax
    jmp .trim
.vset:
    mov [h2c_v_len], rax
.eol:
    cmp r12, r13
    jae .one
    mov al, [r12]
    inc r12
    cmp al, 10
    jne .eol
.one:
    mov rax, 1
    ret
.end:
    xor eax, eax
    ret

; h2c_build_headers() -> rax = HPACK block length in h2c_hdrblk, or -1.
; r14 = h1 head ptr, r15 = h1 head len (set by the caller). rbp = block cursor.
h2c_build_headers:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, r14                 ; cursor
    lea r13, [r14 + r15]         ; end
    mov [h2c_head_end], r13
    mov [h2c_m_ptr], r12
.msp:
    cmp r12, r13
    jae .perr
    cmp byte [r12], ' '
    je .mg
    inc r12
    jmp .msp
.mg:
    mov rax, r12
    sub rax, [h2c_m_ptr]
    mov [h2c_m_len], rax
    inc r12
    mov [h2c_t_ptr], r12
.tsp:
    cmp r12, r13
    jae .perr
    cmp byte [r12], ' '
    je .tg
    inc r12
    jmp .tsp
.tg:
    mov rax, r12
    sub rax, [h2c_t_ptr]
    mov [h2c_t_len], rax
.rleol:
    cmp r12, r13
    jae .perr
    mov al, [r12]
    inc r12
    cmp al, 10
    jne .rleol
    mov [h2c_hdr_start], r12
    mov qword [h2c_host_ptr], 0
    mov qword [h2c_host_len], 0
.pa:
    call h2c_next_hdr_line
    test rax, rax
    jz .pae
    mov rdi, [h2c_n_ptr]
    mov rsi, [h2c_n_len]
    call h2c_is_host
    test rax, rax
    jz .pa
    mov rax, [h2c_v_ptr]
    mov [h2c_host_ptr], rax
    mov rax, [h2c_v_len]
    mov [h2c_host_len], rax
    jmp .pa
.pae:
    lea rbp, [h2c_hdrblk]
    mov rdi, rbp
    call h2c_emit_method
    mov rbp, rdi
    mov rdi, rbp
    call h2c_emit_scheme
    mov rbp, rdi
    ; :path (name index 4)
    mov rdi, rbp
    mov rax, 4
    mov cl, 4
    xor r8d, r8d
    call h2c_enc_int
    mov rsi, [h2c_t_ptr]
    mov rdx, [h2c_t_len]
    call h2c_enc_str
    mov rbp, rdi
    ; :authority (name index 1) if a Host was present
    cmp qword [h2c_host_ptr], 0
    je .noauth
    mov rdi, rbp
    mov rax, 1
    mov cl, 4
    xor r8d, r8d
    call h2c_enc_int
    mov rsi, [h2c_host_ptr]
    mov rdx, [h2c_host_len]
    call h2c_enc_str
    mov rbp, rdi
.noauth:
    mov r12, [h2c_hdr_start]
    mov r13, [h2c_head_end]
.pb:
    call h2c_next_hdr_line
    test rax, rax
    jz .pbe
    mov rdi, [h2c_n_ptr]
    mov rsi, [h2c_n_len]
    call h2c_is_skip
    test rax, rax
    jnz .pb
    mov rdi, rbp
    xor eax, eax
    mov cl, 4
    xor r8d, r8d
    call h2c_enc_int             ; 0x00 (literal, literal name, without indexing)
    mov rsi, [h2c_n_ptr]
    mov rdx, [h2c_n_len]
    call h2c_enc_str_lc
    mov rsi, [h2c_v_ptr]
    mov rdx, [h2c_v_len]
    call h2c_enc_str
    mov rbp, rdi
    jmp .pb
.pbe:
    lea rax, [h2c_hdrblk]
    sub rbp, rax
    mov rax, rbp
    jmp .bret
.perr:
    mov rax, -1
.bret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ============================================================================
; Frame I/O (blocking).
; ============================================================================
; h2c_read_full(edi=fd, rsi=buf, rdx=n) -> rax=0 ok / -1 eof/err.
h2c_read_full:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.l:
    test r13, r13
    jz .ok
    mov rdx, r13
    mov rax, [h2c_chunk_cap]
    test rax, rax
    jz .go
    cmp rax, rdx
    jae .go
    mov rdx, rax
.go:
    mov eax, LINNEA_SYS_READ
    mov edi, ebx
    mov rsi, r12
    syscall
    test rax, rax
    jle .fail
    add r12, rax
    sub r13, rax
    jmp .l
.ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; h2c_next_frame() -> rax = type, or -1. Sets h2c_fr_flags/sid/len; payload at
; h2c_frame_buf+9.
h2c_next_frame:
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_frame_buf]
    mov rdx, 9
    call h2c_read_full
    test rax, rax
    js .eof
    movzx eax, byte [h2c_frame_buf]
    shl eax, 8
    movzx ecx, byte [h2c_frame_buf+1]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [h2c_frame_buf+2]
    or eax, ecx
    mov [h2c_fr_len], rax
    cmp rax, LINNEA_H2C_RX_FRAME_MAX   ; 4.2, before the buffer bound: a frame
    ja .eof                            ; can fit in memory and still be illegal
    cmp rax, 20480 - 9
    ja .eof
    movzx eax, byte [h2c_frame_buf+4]
    mov [h2c_fr_flags], rax
    mov eax, [h2c_frame_buf+5]
    bswap eax
    and eax, 0x7fffffff
    mov [h2c_fr_sid], rax
    mov rdx, [h2c_fr_len]
    test rdx, rdx
    jz .nopay
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_frame_buf+9]
    call h2c_read_full
    test rax, rax
    js .eof
.nopay:
    movzx eax, byte [h2c_frame_buf+3]     ; type
    ; RFC 9113 3.4: the server connection preface is a SETTINGS frame, and it
    ; MUST be the first frame the server sends -- an empty one is explicitly
    ; allowed, an ACK is not one. We enforced this for CLIENTS in the frontend
    ; from the start and never asked it of a BACKEND, so a server could answer
    ; before it had ever said what it supported (audit-report-56).
    ;
    ; It lives here, in the one reader that settle, the flow-control pump and
    ; the response loop all share, rather than in each of them: three copies of
    ; the PING rule is how audit-report-54 happened.
    cmp qword [h2c_preface_ok], 0
    jne .ret
    mov qword [h2c_preface_ok], 1
    cmp eax, LINNEA_H2C_FT_SETTINGS
    jne .eof
    cmp qword [h2c_fr_sid], 0
    jne .eof
    mov rcx, [h2c_fr_flags]
    test rcx, LINNEA_H2C_FL_ACK
    jnz .eof
.ret:
    ret
.eof:
    mov rax, -1
    ret

; h2c_send_settings_ack()
h2c_send_settings_ack:
    lea rdi, [h2c_out_buf]
    mov dword [rdi], 0
    mov byte [rdi+3], LINNEA_H2C_FT_SETTINGS
    mov byte [rdi+4], LINNEA_H2C_FL_ACK
    mov dword [rdi+5], 0
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_out_buf]
    mov rdx, 9
    call h2c_send_all
    ret

; h2c_send_ping_ack() — echo the 8-byte payload with ACK.
h2c_send_ping_ack:
    lea rdi, [h2c_out_buf]
    mov byte [rdi], 0
    mov byte [rdi+1], 0
    mov byte [rdi+2], 8
    mov byte [rdi+3], LINNEA_H2C_FT_PING
    mov byte [rdi+4], LINNEA_H2C_FL_ACK
    mov dword [rdi+5], 0
    mov rax, [h2c_frame_buf+9]
    mov [rdi+9], rax
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_out_buf]
    mov rdx, 17
    call h2c_send_all
    ret

; h2c_ping_frame() -> rax 0 = handled (echoed with ACK if it was a request),
; -1 = the frame is malformed OR the ACK could not be sent; the caller ends the
; exchange either way. 6.7: exactly 8 octets, stream 0, and an ACK is consumed
; and never answered.
;
; This exists because the rule was written out three times. When the checks went
; in (audit-report-46) two of the three copies were updated and the flow-control
; pump's was not, so a malformed PING read while the upload waited for credit
; was still echoed -- measured: a 7-octet PING came back as "1234567" plus a
; byte from past the frame (audit-report-54). One caller, one rule.
h2c_ping_frame:
    cmp qword [h2c_fr_sid], 0
    jne .bad
    cmp qword [h2c_fr_len], 8
    jne .bad
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_ACK
    jnz .ok
    call h2c_send_ping_ack
    test rax, rax
    js .bad                        ; the ACK could not be sent
.ok:
    xor eax, eax
    ret
.bad:
    mov rax, -1
    ret

; h2c_conn_specific(rdi=name, rsi=name len, rdx=value, rcx=value len)
;   -> rax = 1 when this field makes the message malformed (RFC 9113 8.2.2).
;
; Connection, Keep-Alive, Proxy-Connection, Transfer-Encoding and Upgrade are
; forbidden outright. TE is the single exception the section allows, and only
; for one value: it "MUST NOT contain any value other than trailers", compared
; case-insensitively because it is a token. nghttp2 as a client agrees on every
; one of these in a RESPONSE -- it refuses connection, transfer-encoding and
; "te: gzip", and serves "te: trailers".
h2c_conn_specific:
    push rbx
    push r12
    push r13
    mov r12, rdx                    ; value ptr
    mov r13, rcx                    ; value len
    mov rbx, rdi                    ; name ptr (rsi = name len, kept)
    lea rdx, [hop_connection]
    mov rcx, hop_connection_len
    call h2c_ci_eq
    test rax, rax
    jnz .cs_bad
    mov rdi, rbx
    lea rdx, [hop_keepalive]
    mov rcx, hop_keepalive_len
    call h2c_ci_eq
    test rax, rax
    jnz .cs_bad
    mov rdi, rbx
    lea rdx, [hop_proxyconn]
    mov rcx, hop_proxyconn_len
    call h2c_ci_eq
    test rax, rax
    jnz .cs_bad
    mov rdi, rbx
    lea rdx, [hop_te]               ; "transfer-encoding"
    mov rcx, hop_te_len
    call h2c_ci_eq
    test rax, rax
    jnz .cs_bad
    mov rdi, rbx
    lea rdx, [hop_upgrade]
    mov rcx, hop_upgrade_len
    call h2c_ci_eq
    test rax, rax
    jnz .cs_bad
    mov rdi, rbx
    lea rdx, [hop_tefield]          ; "te": allowed, but only as "trailers"
    mov rcx, hop_tefield_len
    call h2c_ci_eq
    test rax, rax
    jz .cs_ok
    cmp r13, val_trailers_len
    jne .cs_bad
    mov rdi, r12
    mov rsi, r13
    lea rdx, [val_trailers]
    mov rcx, val_trailers_len
    call h2c_ci_eq
    test rax, rax
    jz .cs_bad
.cs_ok:
    xor eax, eax
    jmp .cs_ret
.cs_bad:
    mov rax, 1
.cs_ret:
    pop r13
    pop r12
    pop rbx
    ret

; h2c_field_ok(rdi=name, rsi=name len, rdx=value, rcx=value len) -> rax 1 ok, 0
; malformed. RFC 9113 8.2.1, for an ORDINARY response field; 8.1.1 then says a
; malformed response must not be forwarded.
;
; The name half was a repair rather than a check: h2c_hdrline_append lowercased
; A-Z while copying, so "Content-Type" became "content-type" and the protocol
; error left no trace (audit-report-60).
;
; The VALUE half was not checked at all, and that is the half with teeth. This
; leg writes "name: value CRLF" into a synthesized HTTP/1 head which the proxy
; bridge then RE-PARSES, so a CR LF inside a value forges a header line. It was
; measured end to end: a backend sending ONE field whose value contained
; "\r\nx-injected: yes" delivered x-injected as a real header to an h1 AND an h2
; client. That is the response-direction twin of the note in linnea_hpack.asm's
; emit_field, where a CR or LF forges a second REQUEST at the backend.
;
; Touches rax/r8/r9 only.
h2c_field_ok:
    xor eax, eax
    test rsi, rsi
    jz .fo_ret                     ; a field name is a token: never empty
    xor r9, r9
.fo_name:
    cmp r9, rsi
    jae .fo_name_ok
    movzx r8d, byte [rdi + r9]
    cmp r8b, 0x20
    jbe .fo_ret                    ; 8.2.1 excludes 0x00-0x20 INCLUSIVE: SP too
    cmp r8b, 0x7f
    jae .fo_ret                    ; ...and 0x7f-0xff
    cmp r8b, 'A'
    jb .fo_name_next
    cmp r8b, 'Z'
    jbe .fo_ret                    ; uppercase: malformed, not something to fix
.fo_name_next:
    cmp r8b, ':'
    je .fo_ret                     ; only a pseudo-header carries one, and it
    inc r9                         ; never reaches here
    jmp .fo_name
.fo_name_ok:
    test rcx, rcx
    jz .fo_good                    ; an empty value is legal
    ; 8.2.1: no CR, LF or NUL anywhere, and no leading or trailing SP/HTAB.
    movzx r8d, byte [rdx]
    cmp r8b, 0x20
    je .fo_ret
    cmp r8b, 0x09
    je .fo_ret
    lea r9, [rcx - 1]
    movzx r8d, byte [rdx + r9]
    cmp r8b, 0x20
    je .fo_ret
    cmp r8b, 0x09
    je .fo_ret
    xor r9, r9
.fo_val:
    cmp r9, rcx
    jae .fo_good
    movzx r8d, byte [rdx + r9]
    test r8b, r8b
    jz .fo_ret                     ; NUL
    cmp r8b, 0x0d
    je .fo_ret                     ; CR -- the forged line
    cmp r8b, 0x0a
    je .fo_ret                     ; LF
    inc r9
    jmp .fo_val
.fo_good:
    mov rax, 1
.fo_ret:
    ret

; h2c_body_ok(rdi=status, rsi=is_head, rdx=cl_seen, rcx=cl_val, r8=body_len)
;   -> rax = 1 the response body is legal, 0 malformed.
;
; Two rules, in this order, because the first decides whether the second even
; applies:
;
;   1. A status defined to carry NO CONTENT must not carry any. 1xx, 204, 205
;      and 304 (linnea_http_status_no_content, the SAME predicate the h1 leg
;      calls -- three copies of that list once disagreed on 205,
;      audit-report-10). A content-length beside such a status is metadata and
;      stays legal; DATA bytes are not. Before this, a 204 whose backend sent a
;      DATA frame was relayed as "HTTP/1.1 204 No Content" with
;      "content-length: 8" AND eight bytes of body -- a response no client will
;      read as content, leaving those bytes to be parsed as whatever comes next.
;
;   2. Otherwise, a declared content-length must equal the DATA bytes
;      (RFC 9113 8.1.1, audit-report-58). A HEAD response is exempt: it declares
;      what a GET would have returned and sends nothing.
;
; The order matters. Checking the length first would ask the wrong question of a
; 304, whose declaration deliberately does not match what it sends.
h2c_body_ok:
    ; 0. HEAD, before anything else: RFC 9110 9.3.2 -- the response to a HEAD
    ;    has no content, whatever its head declares. The declared length is what
    ;    a GET WOULD have returned, so it is metadata and is NOT compared
    ;    against these bytes; that exemption was here from audit-report-58. What
    ;    was missing is its other half -- the bytes must not EXIST. The comment
    ;    said "sends nothing" and nothing checked it (audit-report-63).
    ;
    ;    Measured before the fix: a HEAD whose backend sent DATA came back from
    ;    the direct client API with the body attached, and reached an h1 client
    ;    through a real proxy_h2 front with four bytes of content after the
    ;    blank line. An h2 client saw none, because the h2 relay suppresses a
    ;    HEAD body downstream -- which hides it on one route and does not make
    ;    the backend response legal on either.
    test rsi, rsi
    jz .bo_status
    test r8, r8
    jnz .bo_bad
    mov rax, 1
    ret
.bo_status:
    push rcx
    push rdx
    push rsi
    push r8
    call linnea_http_status_no_content   ; edi = status; touches only eax
    pop r8
    pop rsi
    pop rdx
    pop rcx
    test eax, eax
    jz .bo_content
    test r8, r8
    jnz .bo_bad                    ; content on a status that may carry none
    mov rax, 1
    ret
.bo_content:
    mov rax, 1
    test rdx, rdx
    jz .bo_ret                     ; nothing declared: nothing to contradict
    cmp rcx, r8                    ; HEAD already returned above
    je .bo_ret
.bo_bad:
    xor eax, eax
.bo_ret:
    ret

; h2c_send_window(edi=sid, esi=inc)
h2c_send_window:
    push rbx
    mov ebx, esi
    lea rax, [h2c_out_buf]
    mov byte [rax], 0
    mov byte [rax+1], 0
    mov byte [rax+2], 4
    mov byte [rax+3], LINNEA_H2C_FT_WINDOW
    mov byte [rax+4], 0
    mov ecx, edi
    bswap ecx
    mov [rax+5], ecx
    mov ecx, ebx
    bswap ecx
    mov [rax+9], ecx
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_out_buf]
    mov rdx, 13
    call h2c_send_all
    pop rbx
    ret

; h2c_apply_settings() — record the server's INITIAL_WINDOW_SIZE as our stream-1
; send window (first SETTINGS; absolute, before any body has gone out).
; h2c_apply_settings() -> rax 0 ok / -1 protocol error. The oracle's twin of
; d_apply_settings, with 6.5's structural rules folded in so its three call
; sites inherit them: stream 0, and a payload that is a whole number of
; six-octet records. (The ACK-with-payload case is caught at the sites, which
; are the only place the flag is examined.)
h2c_apply_settings:
    cmp qword [h2c_fr_sid], 0
    jne .bad_s
    mov rax, [h2c_fr_len]
    xor edx, edx
    mov rcx, 6
    div rcx
    test rdx, rdx
    jnz .bad_s
    lea rsi, [h2c_frame_buf+9]
    mov rcx, [h2c_fr_len]
.l:
    cmp rcx, 6
    jb .done
    movzx eax, byte [rsi]
    shl eax, 8
    movzx edx, byte [rsi+1]
    or eax, edx
    cmp eax, LINNEA_H2C_SET_INITWIN    ; bounds as in d_apply_settings
    je .s_initwin
    cmp eax, LINNEA_H2C_SET_PUSH
    je .s_push
    cmp eax, LINNEA_H2C_SET_MAXFRAME
    je .s_maxframe
    jmp .next
.s_push:
    call d_set_val
    test eax, eax
    jnz .bad_s
    jmp .next
.s_maxframe:
    call d_set_val
    cmp eax, 16384
    jb .bad_s
    cmp eax, 16777215
    ja .bad_s
    jmp .next
.s_initwin:
    call d_set_val
    cmp eax, 0x7fffffff
    ja .bad_s
    mov rdx, [h2c_peer_init_win]
    mov [h2c_peer_init_win], rax
    sub rax, rdx                     ; the delta, signed -- see d_apply_settings
    add [h2c_stream_win], rax
.next:
    add rsi, 6
    sub rcx, 6
    jmp .l
.done:
    xor eax, eax
    ret
.bad_s:
    mov rax, -1
    ret

; h2c_apply_window() -> rax 0 ok / -1 protocol error. WINDOW_UPDATE: grow the
; conn (sid 0) or stream (sid 1) window. The oracle's twin of d_apply_window
; plus the framing checks its callers used to skip -- see there for why the
; maximum-window comparison is signed.
h2c_apply_window:
    cmp qword [h2c_fr_len], 4
    jne .bad_w
    cmp qword [h2c_fr_sid], 1
    ja .bad_w
    movzx eax, byte [h2c_frame_buf+9]
    shl eax, 8
    movzx edx, byte [h2c_frame_buf+10]
    or eax, edx
    shl eax, 8
    movzx edx, byte [h2c_frame_buf+11]
    or eax, edx
    shl eax, 8
    movzx edx, byte [h2c_frame_buf+12]
    or eax, edx
    and eax, 0x7fffffff
    test eax, eax
    jz .bad_w
    cmp qword [h2c_fr_sid], 0
    jne .stream
    mov rcx, [h2c_conn_win]
    add rcx, rax
    cmp rcx, 0x7fffffff
    jg .bad_w
    mov [h2c_conn_win], rcx
    xor eax, eax
    ret
.stream:
    mov rcx, [h2c_stream_win]
    add rcx, rax
    cmp rcx, 0x7fffffff
    jg .bad_w
    mov [h2c_stream_win], rcx
    xor eax, eax
    ret
.bad_w:
    mov rax, -1
    ret

; ============================================================================
; Request body send (flow-controlled) + settle/pump helpers.
; ============================================================================
; h2c_settle() — read frames until the server's (non-ACK) SETTINGS, apply+ACK it.
h2c_settle:
    call h2c_next_frame
    test rax, rax
    js .err
    cmp eax, LINNEA_H2C_FT_SETTINGS
    je .settings
    cmp eax, LINNEA_H2C_FT_WINDOW
    je .win
    cmp eax, LINNEA_H2C_FT_PING
    je .ping
    cmp eax, LINNEA_H2C_FT_RST
    je .rst                        ; settle did not dispatch this at all, so a
                                   ; reset here fell through to the loop and the
                                   ; body went out on a dead stream. I could not
                                   ; build a case where that differed from the
                                   ; driver -- a reset either lands while the
                                   ; sender waits for credit, and both stop, or
                                   ; it races a body already in flight, which
                                   ; cannot be un-sent. Added for the two to
                                   ; agree by construction (audit-report-51).
    cmp eax, LINNEA_H2C_FT_GOAWAY
    je .goaway
    jmp h2c_settle
.rst:
    cmp qword [h2c_fr_sid], 1
    jne .err
    cmp qword [h2c_fr_len], 4
    jne .err
    mov rax, LINNEA_H2C_RST
    ret
.settings:
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_ACK
    jz .s_apply
    cmp qword [h2c_fr_len], 0
    jne .err              ; an ACK with a payload (6.5)
    jmp h2c_settle
.s_apply:
    call h2c_apply_settings
    test rax, rax
    js .err
    call h2c_send_settings_ack
    xor eax, eax
    ret
.win:
    call h2c_apply_window
    test rax, rax
    js .err                        ; malformed WINDOW_UPDATE (6.9)
    jmp h2c_settle
.ping:
    call h2c_ping_frame
    test rax, rax
    js .err
    jmp h2c_settle
.goaway:
    cmp qword [h2c_fr_sid], 0
    jne .err
    cmp qword [h2c_fr_len], 8
    jb .err
    mov rax, LINNEA_H2C_GOAWAY
    ret
.err:
    mov rax, LINNEA_H2C_ERR
    ret

; h2c_pump_window() — read frames until both send windows are > 0.
h2c_pump_window:
.chk:
    mov rax, [h2c_stream_win]
    test rax, rax
    jle .read
    mov rax, [h2c_conn_win]
    test rax, rax
    jle .read
    xor eax, eax
    ret
.read:
    call h2c_next_frame
    test rax, rax
    js .err
    cmp eax, LINNEA_H2C_FT_WINDOW
    je .w
    cmp eax, LINNEA_H2C_FT_SETTINGS
    je .s
    cmp eax, LINNEA_H2C_FT_PING
    je .p
    cmp eax, LINNEA_H2C_FT_RST
    je .rst
    cmp eax, LINNEA_H2C_FT_GOAWAY
    je .goaway
    jmp .err                      ; response before END_STREAM: unsupported in v1
.w:
    call h2c_apply_window
    test rax, rax
    js .err                        ; malformed WINDOW_UPDATE (6.9)
    jmp .chk
.s:
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_ACK
    jz .s_apply2
    cmp qword [h2c_fr_len], 0
    jne .err              ; an ACK with a payload (6.5)
    jmp .chk
.s_apply2:
    call h2c_apply_settings
    test rax, rax
    js .err
    call h2c_send_settings_ack
    jmp .chk
.p:
    call h2c_ping_frame            ; unchecked until audit-report-54
    test rax, rax
    js .err
    jmp .chk
.rst:
    cmp qword [h2c_fr_sid], 1      ; bounds as in d_dispatch
    jne .err
    cmp qword [h2c_fr_len], 4
    jne .err
    mov rax, LINNEA_H2C_RST
    ret
.goaway:
    cmp qword [h2c_fr_sid], 0
    jne .err
    cmp qword [h2c_fr_len], 8
    jb .err
    mov rax, LINNEA_H2C_GOAWAY
    ret
.err:
    mov rax, LINNEA_H2C_ERR
    ret

; h2c_send_body(rsi=body ptr, rdx=body len) -> rax 0 / negative sentinel.
h2c_send_body:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14, rsi
    mov r15, rdx
    xor rbx, rbx                   ; sent
    call h2c_settle
    test rax, rax
    js .done
.loop:
    mov r12, r15
    sub r12, rbx                   ; remaining
    test r12, r12
    jz .ok
    call h2c_pump_window
    test rax, rax
    js .done
    mov r13, [h2c_stream_win]      ; min SIGNED -- see d_stage_body
    mov rax, [h2c_conn_win]
    cmp rax, r13
    jge .n1
    mov r13, rax
.n1:
    cmp r13, 16384
    jbe .n2
    mov r13, 16384
.n2:
    cmp r13, r12
    jbe .n3
    mov r13, r12
.n3:
    lea rdi, [h2c_out_buf]
    mov rax, r13
    shr rax, 16
    mov [rdi], al
    mov rax, r13
    shr rax, 8
    mov [rdi+1], al
    mov [rdi+2], r13b
    mov byte [rdi+3], LINNEA_H2C_FT_DATA
    mov rax, rbx
    add rax, r13
    cmp rax, r15
    jne .notlast
    mov byte [rdi+4], LINNEA_H2C_FL_END_STREAM
    jmp .fd
.notlast:
    mov byte [rdi+4], 0
.fd:
    mov dword [rdi+5], 0x01000000  ; stream 1 (BE)
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_out_buf]
    mov rdx, 9
    call h2c_send_all
    test rax, rax
    js .done
    mov edi, dword [h2c_fd]
    lea rsi, [r14 + rbx]
    mov rdx, r13
    call h2c_send_all
    test rax, rax
    js .done
    sub [h2c_stream_win], r13
    sub [h2c_conn_win], r13
    add rbx, r13
    cmp rbx, r15
    jb .loop
.ok:
    xor eax, eax
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; Response drive + HPACK decode + h1 synthesis.
; ============================================================================
; h2c_hdrblk_append(rsi=ptr, rdx=len) -> rax 0/-1.
h2c_hdrblk_append:
    test rdx, rdx
    js .of
    mov rax, [h2c_hdrblk_len]
    lea rcx, [rax + rdx]
    cmp rcx, LINNEA_H2C_HDRBLK_CAP
    ja .of
    push rcx
    lea rdi, [h2c_hdrblk]
    add rdi, rax
    mov rcx, rdx
    rep movsb
    pop rax
    mov [h2c_hdrblk_len], rax
    xor eax, eax
    ret
.of:
    mov rax, -1
    ret

; h2c_body_append(rsi=ptr, rdx=len) -> rax 0/-1.
h2c_body_append:
    test rdx, rdx
    js .of
    jz .ok
    mov rax, [h2c_body_len]
    lea rcx, [rax + rdx]
    cmp rcx, LINNEA_H2C_RESP_CAP
    ja .of
    push rcx
    lea rdi, [h2c_body_buf]
    add rdi, rax
    mov rcx, rdx
    rep movsb
    pop rax
    mov [h2c_body_len], rax
.ok:
    xor eax, eax
    ret
.of:
    mov rax, -1
    ret

; h2c_run_response() -> rax 0 done / negative sentinel.
h2c_run_response:
    push rbx
    mov qword [h2c_hdrblk_len], 0
    mov qword [h2c_saw_pseudo], 0
    mov qword [h2c_hdr_es], 0
    mov qword [h2c_hdr_open], 0
    xor ebx, ebx                   ; headers-decoded flag
.loop:
    call h2c_next_frame
    test rax, rax
    js .err
    ; the oracle's twin of d_dispatch's RFC 9113 6.10 gate -- see there
    cmp qword [h2c_hdr_open], 0
    jne .in_block
    cmp eax, LINNEA_H2C_FT_CONT
    je .err                        ; a continuation of nothing
    jmp .type
.in_block:
    cmp eax, LINNEA_H2C_FT_CONT
    jne .err                       ; anything else, interleaved
    cmp qword [h2c_fr_sid], 1
    jne .err
.type:
    cmp eax, LINNEA_H2C_FT_PUSH    ; see d_dispatch: we asked for no pushes
    je .err
    cmp eax, LINNEA_H2C_FT_SETTINGS
    je .settings
    cmp eax, LINNEA_H2C_FT_WINDOW
    je .win                        ; validated, not skipped (audit-report-47)
    cmp eax, LINNEA_H2C_FT_PING
    je .ping
    cmp eax, LINNEA_H2C_FT_HEADERS
    je .headers
    cmp eax, LINNEA_H2C_FT_CONT
    je .cont
    cmp eax, LINNEA_H2C_FT_DATA
    je .data
    cmp eax, LINNEA_H2C_FT_RST
    je .rst
    cmp eax, LINNEA_H2C_FT_GOAWAY
    je .goaway
    jmp .loop
.settings:
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_ACK
    jz .s_apply3
    cmp qword [h2c_fr_len], 0
    jne .err              ; an ACK with a payload (6.5)
    jmp .loop
.s_apply3:
    call h2c_apply_settings
    test rax, rax
    js .err
    call h2c_send_settings_ack
    jmp .loop
.win:
    call h2c_apply_window
    test rax, rax
    js .err
    jmp .loop
.ping:
    ; the oracle's twin of d_dispatch's check -- see there. It also never looked
    ; at the ACK flag, so it answered the backend's ACKs with ACKs of its own,
    ; which 6.7 forbids outright.
    call h2c_ping_frame
    test rax, rax
    js .err
    jmp .loop
.headers:
    ; 6.1/6.2: this leg is single-stream. A HEADERS or DATA frame naming
    ; stream 0, or a stream we never opened, cannot belong to this response.
    ; Skipping it is not the safe reading it looks like: HPACK state is per
    ; CONNECTION, so a header block passed over rather than decoded shifts
    ; every later dynamic index by one. Measured: a backend meaning index 63
    ; had "x-a: aaa" relayed in place of "x-b: bbb", under a clean 200
    ; (audit-report-53).
    cmp qword [h2c_fr_sid], 1
    jne .err
    mov rax, [h2c_fr_flags]
    and rax, LINNEA_H2C_FL_END_STREAM
    mov [h2c_hdr_es], rax
    lea rsi, [h2c_frame_buf+9]
    mov rdx, [h2c_fr_len]
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_PADDED
    jz .h_np
    cmp rdx, 1
    jl .err                          ; see d_dispatch: bounds before the read
    movzx ecx, byte [rsi]
    inc rsi
    dec rdx
    sub rdx, rcx
    js .err
.h_np:
    test rax, LINNEA_H2C_FL_PRIORITY
    jz .h_npr
    cmp rdx, 5
    jl .err
    add rsi, 5
    sub rdx, 5
.h_npr:
    call h2c_hdrblk_append
    test rax, rax
    js .err
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_END_HEADERS
    jz .h_open                     ; the block awaits its CONTINUATION
    mov qword [h2c_hdr_open], 0
    movzx edi, bl                  ; 1 once the final response head is in
    mov rsi, [h2c_hdr_es]
    call h2c_classify_block
    test rax, rax
    js .err
    mov qword [h2c_hdrblk_len], 0   ; per BLOCK, see d_decode_block
    cmp rax, 1
    je .loop                       ; informational: read on for the final head
    cmp rax, 2
    je .done                       ; a trailer section, END_STREAM checked
    mov ebx, 1
    cmp qword [h2c_hdr_es], 0
    jne .done
    jmp .loop
.cont:
    cmp qword [h2c_fr_sid], 1          ; unreachable: the open-block gate above
    jne .err                           ; already refuses a CONTINUATION that is
    lea rsi, [h2c_frame_buf+9]         ; on another stream or opens nothing
    mov rdx, [h2c_fr_len]
    call h2c_hdrblk_append
    test rax, rax
    js .err
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_END_HEADERS
    jz .loop                       ; still open, still owed a CONTINUATION
    mov qword [h2c_hdr_open], 0
    movzx edi, bl                  ; 1 once the final response head is in
    mov rsi, [h2c_hdr_es]
    call h2c_classify_block
    test rax, rax
    js .err
    mov qword [h2c_hdrblk_len], 0   ; per BLOCK, see d_decode_block
    cmp rax, 1
    je .loop                       ; informational: read on for the final head
    cmp rax, 2
    je .done                       ; a trailer section, END_STREAM checked
    mov ebx, 1
    cmp qword [h2c_hdr_es], 0
    jne .done
    jmp .loop
.data:
    cmp qword [h2c_fr_sid], 1          ; see .headers
    jne .err
    test ebx, ebx
    jz .err                        ; DATA before the response head, see d_dispatch
    lea rsi, [h2c_frame_buf+9]
    mov rdx, [h2c_fr_len]
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_PADDED
    jz .d_np
    cmp rdx, 1
    jl .err                          ; see d_dispatch: bounds before the read
    movzx ecx, byte [rsi]
    inc rsi
    dec rdx
    sub rdx, rcx
    js .err
.d_np:
    call h2c_body_append
    test rax, rax
    js .err
    ; return flow-control credit for the whole frame payload
    cmp qword [h2c_fr_len], 0
    je .d_es
    mov esi, dword [h2c_fr_len]
    xor edi, edi
    call h2c_send_window
    mov esi, dword [h2c_fr_len]
    mov edi, 1
    call h2c_send_window
.d_es:
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2C_FL_END_STREAM
    jnz .done
    jmp .loop
.h_open:
    mov qword [h2c_hdr_open], 1
    jmp .loop
.rst:
    cmp qword [h2c_fr_sid], 1      ; bounds as in d_dispatch
    jne .err
    cmp qword [h2c_fr_len], 4
    jne .err
    mov rax, LINNEA_H2C_RST
    jmp .ret
.goaway:
    cmp qword [h2c_fr_sid], 0
    jne .err
    cmp qword [h2c_fr_len], 8
    jb .err
    mov rax, LINNEA_H2C_GOAWAY
    jmp .ret
.done:
    test ebx, ebx
    jz .err
    mov rdi, [h2c_status]
    mov rsi, [h2c_is_head]
    mov rdx, [h2c_cl_seen]
    mov rcx, [h2c_cl_val]
    mov r8, [h2c_body_len]
    call h2c_body_ok
    test rax, rax
    jz .err                        ; 8.1.1 + no-content, see h2c_body_ok
    xor eax, eax
    jmp .ret
.err:
    mov rax, LINNEA_H2C_ERR
.ret:
    pop rbx
    ret

; h2c_do_decode() -> rax 0/-1: decode the reassembled response header block.
h2c_do_decode:
    lea rsi, [h2c_hdrblk]
    mov rdx, [h2c_hdrblk_len]
    call h2c_decode
    ret

; h2c_decode(rsi=block ptr, rdx=len) -> rax 0/-1. Faithful copy of the
; linnea_hpack_decode control flow (rbx=carrier, r12=cur, r13=end), but emits
; into the response model and, being single-stream + non-pooled, fails fast on
; the first error rather than walking on for table sync.
h2c_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea rbx, [h2c_carrier]
    mov r12, rsi
    lea r13, [rsi + rdx]
    ; Per FIELD BLOCK, and this decoder runs once per completed block -- after
    ; the HEADERS and all its CONTINUATIONs have been reassembled -- so clearing
    ; it here is exactly the lifetime RFC 7541 4.2 describes.
    mov qword [h2c_field_seen], 0
.next:
    cmp r12, r13
    jae .ok
    movzx eax, byte [r12]
    test al, 0x80
    jnz .indexed
    test al, 0x40
    jnz .lit_inc
    test al, 0x20
    jnz .tsize
    mov ecx, 4
    jmp .literal
.indexed:
    mov qword [h2c_field_seen], 1
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_int
    jc .err
    mov r12, rsi
    test rax, rax
    jz .err
    cmp rax, HPACK_STATIC_COUNT
    ja .idyn
    lea rdx, [rax - 1]
    shl rdx, 4
    lea rsi, [hpack_static_tab]
    add rsi, rdx
    mov r8d, [rsi]
    mov r9d, [rsi+4]
    mov r10d, [rsi+8]
    mov r11d, [rsi+12]
    lea r14, [hpack_static_blob]
    lea rax, [r14 + r8]
    mov rdx, r9
    lea rsi, [r14 + r10]
    mov rdi, r11
    call h2c_emit
    jc .err
    jmp .next
.idyn:
    mov rdi, [rbx + linnea_h2_req.dyn]
    lea rsi, [rax - HPACK_STATIC_COUNT - 1]
    mov rdx, rbx
    call hpack_dyn_get
    jc .err
    call h2c_emit
    jc .err
    jmp .next
.lit_inc:
    mov ecx, 6
.literal:
    ; both literal forms arrive here -- 0x40 with indexing and the 0x00/0x10
    ; forms without -- so the 4.2 mark goes on the shared label. Marking only
    ; the fall-through would have let "literal WITH indexing, then a late
    ; update" through, which is the form an encoder actually emits.
    mov qword [h2c_field_seen], 1
    mov [h2c_lit_form], ecx
    mov rsi, r12
    mov rdi, r13
    call hpack_int
    jc .err
    mov r12, rsi
    test rax, rax
    jnz .lit_nameidx
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_str
    jc .err
    mov r12, rsi
    mov r14, rax
    mov r15, rdx
    jmp .lit_value
.lit_nameidx:
    cmp rax, HPACK_STATIC_COUNT
    ja .lit_namedyn
    lea rdx, [rax - 1]
    shl rdx, 4
    lea rsi, [hpack_static_tab]
    add rsi, rdx
    mov r8d, [rsi]
    mov r9d, [rsi+4]
    lea r14, [hpack_static_blob]
    add r14, r8
    mov r15, r9
    jmp .lit_value
.lit_namedyn:
    mov rdi, [rbx + linnea_h2_req.dyn]
    lea rsi, [rax - HPACK_STATIC_COUNT - 1]
    mov rdx, rbx
    call hpack_dyn_get
    jc .err
    mov r14, rax
    mov r15, rdx
.lit_value:
    mov rsi, r12
    mov rdi, r13
    mov ecx, 7
    call hpack_str
    jc .err
    mov r12, rsi
    mov r10, rax                   ; val ptr
    mov r11, rdx                   ; val len
    cmp dword [h2c_lit_form], 6
    jne .emit_lit
    push r14
    push r15
    push r10
    push r11
    mov r8, [rbx + linnea_h2_req.dyn]
    mov rax, r14
    mov rdx, r15
    mov rsi, r10
    mov rdi, r11
    call hpack_dyn_insert
    pop r11
    pop r10
    pop r15
    pop r14
    test rax, rax
    js .err
.emit_lit:
    mov rax, r14
    mov rdx, r15
    mov rsi, r10
    mov rdi, r11
    call h2c_emit
    jc .err
    jmp .next
.tsize:
    ; RFC 7541 4.2: a dynamic table size update may only appear at the BEGINNING
    ; of a field block, before any field representation; RFC 9113 4.3 makes a
    ; field-block decoding error a connection error of type COMPRESSION_ERROR.
    ; Several updates in a row at the beginning stay legal -- an encoder signals
    ; a shrink and a restore that way -- so this is bounded by the first FIELD,
    ; not by a count.
    ;
    ; The request decoder has enforced this since its own Finding 29; this is
    ; the same rule, in the response-direction copy of the decoder, which never
    ; had it (audit-report-61). nghttp2 answers the late update with GOAWAY
    ; COMPRESSION_ERROR(0x09) and the legal placements with NO_ERROR.
    cmp qword [h2c_field_seen], 0
    jne .err
    mov rsi, r12
    mov rdi, r13
    mov ecx, 5
    call hpack_int
    jc .err
    mov r12, rsi
    cmp rax, LINNEA_HPACK_DYN_CAP
    ja .err
    mov rdi, [rbx + linnea_h2_req.dyn]
    mov [rdi + linnea_hpack_dyn.max], rax
    call hpack_dyn_evict
    jmp .next
.ok:
    xor eax, eax
    jmp .dret
.err:
    mov rax, -1
.dret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2c_emit(rax=name ptr, rdx=name len, rsi=val ptr, rdi=val len) -> CF on error.
; :status captured; other pseudo-headers ignored; hop-by-hop dropped; the rest
; appended as h1 "name: value\r\n" lines.
h2c_emit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rax
    mov r13, rdx
    mov r14, rsi
    mov r15, rdi
    mov rdi, r12
    mov rsi, r13
    lea rdx, [pseudo_status]
    mov rcx, pseudo_status_len
    call h2c_eq                      ; EXACT, deliberately -- see h2c_eq
    test rax, rax
    jnz .status
    test r13, r13
    jz .badfield                     ; an empty name owns no byte to inspect,
                                     ; and is not a field name either way
    cmp byte [r12], ':'
    je .pseudo
    mov qword [h2c_regular_seen], 1  ; 8.3: every pseudo-header comes BEFORE
                                     ; the regular fields, so this closes them
    ; 8.2.1, and BEFORE the skip table below: a name we would have dropped is
    ; still a malformed response, so an uppercase "Connection" must fail rather
    ; than quietly vanish into the hop-by-hop filter.
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov rcx, r15
    call h2c_field_ok
    test rax, rax
    jz .badfield
    ; RFC 9113 8.2.2: "Any message containing connection-specific header fields
    ; MUST be treated as malformed." These names were on the skip list, so a
    ; response carrying Connection or Transfer-Encoding was quietly cleaned up
    ; and relayed as if the backend had behaved. Dropping a field is not the
    ; same as refusing the message -- the request side has said so since its own
    ; sweep, in these words: "stripping them stopped the smuggle into an h1
    ; upstream; it did not make the request the malformed one the RFC says it
    ; is." (request-side-parity sweep, after audit-report-62.)
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov rcx, r15
    call h2c_conn_specific
    test rax, rax
    jnz .badfield
    ; RFC 9113 8.1.1: a content-length that does not equal the sum of the DATA
    ; payloads makes the response MALFORMED, and an intermediary must not
    ; forward it. The field is still dropped here -- the composer writes its own
    ; from the bytes it holds -- but dropping it without ever READING it turned
    ; a malformed response into a valid one: "content-length: 1" over a 4-byte
    ; body was relayed as "content-length: 4" (audit-report-58).
    mov rdi, r12
    mov rsi, r13
    lea rdx, [hop_cl]
    mov rcx, hop_cl_len
    call h2c_ci_eq
    test rax, rax
    jnz .clen
    mov rdi, r12
    mov rsi, r13
    call h2c_is_skip
    test rax, rax
    jnz .ok
    call h2c_hdrline_append
    jc .of
.ok:
    clc
    jmp .ret
.pseudo:
    ; RFC 9113 8.3: a field block containing an UNDEFINED pseudo-header is
    ; malformed, and :status is the only one defined for a response. Recording
    ; it and dropping the field made an undefined one ordinary; the flag it set
    ; belongs to a different rule -- pseudo-headers in a TRAILER -- and covering
    ; one is not covering the other (audit-report-59, found beside its filed
    ; finding). The request side has refused all of this for a long time; see
    ; "pseudo-header placement and repetition" in linnea_hpack.asm.
    mov qword [h2c_saw_pseudo], 1
    stc
    jmp .ret
.status:
    mov qword [h2c_saw_pseudo], 1
    ; 8.3: at most one :status per field block, and it precedes every regular
    ; field. Neither was checked, so two of them overwrote each other silently:
    ; the same pair of values relayed 500 in one order and 200 in the other, and
    ; the field block is the HEADERS and its CONTINUATIONs COMBINED, so the
    ; duplicate could even be split across frames (audit-report-59).
    cmp qword [h2c_regular_seen], 0
    jne .badst
    cmp qword [h2c_status_seen], 0
    jne .badst
    mov qword [h2c_status_seen], 1
    ; RFC 9110 15.1: a status code is EXACTLY three digits, and 9113 8.3.2 says
    ; :status carries that code. This stopped at the first byte that was not a
    ; digit and kept whatever it had accumulated, so the value was never
    ; checked, only mined: "200x" and "200 " became 200, and "2000" became 200
    ; by truncation -- a four-digit status turned into a legal one and relayed
    ; as a clean response (audit-report-57).
    ;
    ; The h1 leg has rejected exactly this for a long time ("HTTP/1.1 2000" is
    ; not a status line, see linnea_http_check_response_head). This is the same
    ; rule finally asked of the h2 leg. The RANGE stays where it is, in the
    ; classifier: three digits is necessary, not sufficient.
    cmp r15, 3
    jne .badst
    xor eax, eax
    xor ecx, ecx
.psl:
    cmp rcx, 3
    jae .psd
    mov dl, [r14 + rcx]
    cmp dl, '0'
    jb .badst
    cmp dl, '9'
    ja .badst
    imul eax, eax, 10
    movzx edx, dl
    sub edx, '0'
    add eax, edx
    inc rcx
    jmp .psl
.psd:
    mov [h2c_status], rax
    clc
    jmp .ret
.badst:
.badfield:
    stc
    jmp .ret
.clen:
    ; A duplicate is refused outright, as the h1 leg has refused one since
    ; report 6 -- two declarations of the same length are at best a rewrite
    ; waiting to disagree.
    cmp qword [h2c_cl_seen], 0
    jne .badcl
    test r15, r15
    jz .badcl                      ; an empty value is not a number
    cmp r15, 19
    ja .badcl                      ; more digits than a u64 holds
    xor eax, eax
    xor ecx, ecx
.cll:
    cmp rcx, r15
    jae .cldone
    movzx edx, byte [r14 + rcx]
    sub edx, '0'
    cmp edx, 9
    ja .badcl                      ; a sign, a space or a letter: not DIGITs
    imul rax, rax, 10
    add rax, rdx
    inc rcx
    jmp .cll
.cldone:
    mov [h2c_cl_val], rax
    mov qword [h2c_cl_seen], 1
    clc
    jmp .ret
.badcl:
    stc
    jmp .ret
.of:
    stc
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2c_hdrline_append() — append "name: value\r\n" (r12/r13 name, r14/r15 value).
; CF on overflow. Uses rax/rcx/rdx/rsi/rdi only (preserves r12-r15).
h2c_hdrline_append:
    mov rax, [h2c_hdrlines_len]
    mov rcx, rax
    add rcx, r13
    add rcx, r15
    add rcx, 4
    cmp rcx, LINNEA_H2C_HDRBLK_CAP
    ja .of
    lea rdi, [h2c_hdrlines]
    add rdi, rax
    mov rsi, r12
    mov rcx, r13
.nm:
    test rcx, rcx
    jz .nmd
    mov al, [rsi]
    cmp al, 'A'
    jb .nk
    cmp al, 'Z'
    ja .nk
    add al, 0x20
.nk:
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .nm
.nmd:
    mov byte [rdi], ':'
    mov byte [rdi+1], ' '
    add rdi, 2
    mov rsi, r14
    mov rcx, r15
    rep movsb
    mov byte [rdi], 13
    mov byte [rdi+1], 10
    add rdi, 2
    lea rax, [h2c_hdrlines]
    sub rdi, rax
    mov [h2c_hdrlines_len], rdi
    clc
    ret
.of:
    stc
    ret

; h2c_compose() -> rax = total length written to linnea_h2c_resp_buf.
h2c_compose:
    push rbx
    lea rdi, [linnea_h2c_resp_buf]
    lea rsi, [http11]
    mov rcx, http11_len
    rep movsb
    mov rax, [h2c_status]
    call h2c_dec3
    mov byte [rdi], ' '
    inc rdi
    mov rax, [h2c_status]
    push rdi
    call h2c_reason               ; -> rsi=ptr, rdx=len
    pop rdi
    mov rcx, rdx
    rep movsb
    mov byte [rdi], 13
    mov byte [rdi+1], 10
    add rdi, 2
    lea rsi, [h2c_hdrlines]
    mov rcx, [h2c_hdrlines_len]
    rep movsb
    lea rsi, [hdr_cl]
    mov rcx, hdr_cl_len
    rep movsb
    ; RFC 9110 9.3.2: a HEAD response's content-length is the length a GET
    ; WOULD have returned. Writing the MEASURED body length reported 0 for
    ; every HEAD -- destroying the one thing the method exists to ask for,
    ; from a backend that had just said 4. The bytes that follow stay the
    ; measured ones (none), which is what a HEAD response IS.
    ;
    ; This composition exists THREE times -- here, in the harness composer, and
    ; in linnea_h2c_drv_head, which is the one production uses. All three get
    ; it (audit-report-63, beside its filed finding).
    mov rax, [h2c_body_len]
    cmp qword [h2c_is_head], 0
    je .cl_have
    cmp qword [h2c_cl_seen], 0
    je .cl_have
    mov rax, [h2c_cl_val]
.cl_have:
    call h2c_u64_dec
    mov byte [rdi], 13
    mov byte [rdi+1], 10
    add rdi, 2
    mov byte [rdi], 13
    mov byte [rdi+1], 10
    add rdi, 2
    lea rsi, [h2c_body_buf]
    mov rcx, [h2c_body_len]
    rep movsb
    lea rax, [linnea_h2c_resp_buf]
    sub rdi, rax
    mov rax, rdi                  ; length, not the buffer address
    pop rbx
    ret

; h2c_dec3(rax=0..999, rdi=out) -> rdi += 3.
h2c_dec3:
    mov r8d, 100
    xor edx, edx
    div r8d
    add al, '0'
    mov [rdi], al
    mov eax, edx
    mov r8d, 10
    xor edx, edx
    div r8d
    add al, '0'
    mov [rdi+1], al
    add dl, '0'
    mov [rdi+2], dl
    add rdi, 3
    ret

; h2c_u64_dec(rax=value, rdi=out) -> rdi advanced.
h2c_u64_dec:
    push rbx
    mov rbx, rdi
    mov rcx, rdi
    test rax, rax
    jnz .conv
    mov byte [rdi], '0'
    inc rdi
    pop rbx
    ret
.conv:
    mov r8, 10
.dl:
    test rax, rax
    jz .rev
    xor edx, edx
    div r8
    add dl, '0'
    mov [rcx], dl
    inc rcx
    jmp .dl
.rev:
    mov rdi, rcx
    dec rcx
.rl:
    cmp rbx, rcx
    jae .done
    mov al, [rbx]
    mov dl, [rcx]
    mov [rbx], dl
    mov [rcx], al
    inc rbx
    dec rcx
    jmp .rl
.done:
    pop rbx
    ret

; h2c_reason(eax=status) -> rsi=ptr, rdx=len (0 = none).
h2c_reason:
    cmp eax, 200
    je .r200
    cmp eax, 204
    je .r204
    cmp eax, 206
    je .r206
    cmp eax, 301
    je .r301
    cmp eax, 302
    je .r302
    cmp eax, 304
    je .r304
    cmp eax, 400
    je .r400
    cmp eax, 403
    je .r403
    cmp eax, 404
    je .r404
    cmp eax, 500
    je .r500
    cmp eax, 502
    je .r502
    cmp eax, 503
    je .r503
    lea rsi, [reason_generic]
    mov rdx, reason_generic_len
    ret
.r200: lea rsi, [reason_200]
       mov rdx, reason_200_len
       ret
.r204: lea rsi, [reason_204]
       mov rdx, reason_204_len
       ret
.r206: lea rsi, [reason_206]
       mov rdx, reason_206_len
       ret
.r301: lea rsi, [reason_301]
       mov rdx, reason_301_len
       ret
.r302: lea rsi, [reason_302]
       mov rdx, reason_302_len
       ret
.r304: lea rsi, [reason_304]
       mov rdx, reason_304_len
       ret
.r400: lea rsi, [reason_400]
       mov rdx, reason_400_len
       ret
.r403: lea rsi, [reason_403]
       mov rdx, reason_403_len
       ret
.r404: lea rsi, [reason_404]
       mov rdx, reason_404_len
       ret
.r500: lea rsi, [reason_500]
       mov rdx, reason_500_len
       ret
.r502: lea rsi, [reason_502]
       mov rdx, reason_502_len
       ret
.r503: lea rsi, [reason_503]
       mov rdx, reason_503_len
       ret

section .rodata
reason_generic: db "Status"
reason_generic_len equ $ - reason_generic
reason_200: db "OK"
reason_200_len equ $ - reason_200
reason_204: db "No Content"
reason_204_len equ $ - reason_204
reason_206: db "Partial Content"
reason_206_len equ $ - reason_206
reason_301: db "Moved Permanently"
reason_301_len equ $ - reason_301
reason_302: db "Found"
reason_302_len equ $ - reason_302
reason_304: db "Not Modified"
reason_304_len equ $ - reason_304
reason_400: db "Bad Request"
reason_400_len equ $ - reason_400
reason_403: db "Forbidden"
reason_403_len equ $ - reason_403
reason_404: db "Not Found"
reason_404_len equ $ - reason_404
reason_500: db "Internal Server Error"
reason_500_len equ $ - reason_500
reason_502: db "Bad Gateway"
reason_502_len equ $ - reason_502
reason_503: db "Service Unavailable"
reason_503_len equ $ - reason_503

section .text
; ============================================================================
; Resumable driver (proxy io_uring path). Per-leg context via [h2c_ctx].
; Reuses the tested pure helpers WITHIN a step; only cross-step state is per-leg.
; ============================================================================
global linnea_h2c_drv_start
global linnea_h2c_drv_on_sent
global linnea_h2c_drv_on_recv
global linnea_h2c_drv_compose
global linnea_h2c_drv_head

; d_out_append(rsi=ptr, rdx=len) — append to ctx.out_buf (rbx=ctx). CF on overflow.
d_out_append:
    mov rax, [rbx + linnea_h2c.out_len]
    lea rcx, [rax + rdx]
    cmp rcx, LINNEA_H2C_D_OUT_CAP
    ja .of
    push rsi
    push rdi
    lea rdi, [rbx + linnea_h2c.out_buf]
    add rdi, rax
    mov rcx, rdx
    rep movsb
    lea rax, [rbx + linnea_h2c.out_buf]
    sub rdi, rax
    mov [rbx + linnea_h2c.out_len], rdi
    pop rdi
    pop rsi
    clc
    ret
.of:
    stc
    ret

; d_stage_settings_ack() — stage a SETTINGS ACK (rbx=ctx).
d_stage_settings_ack:
    lea rsi, [d_ack_tmpl]
    mov rdx, 9
    jmp d_out_append
section .rodata
d_ack_tmpl: db 0,0,0, LINNEA_H2C_FT_SETTINGS, LINNEA_H2C_FL_ACK, 0,0,0,0
section .text

; d_stage_ping_ack(rsi=8-byte payload ptr) — stage a PING ACK (rbx=ctx).
d_stage_ping_ack:
    lea rdi, [d_scr]
    mov byte [rdi],0
    mov byte [rdi+1],0
    mov byte [rdi+2],8
    mov byte [rdi+3],LINNEA_H2C_FT_PING
    mov byte [rdi+4],LINNEA_H2C_FL_ACK
    mov dword [rdi+5],0
    mov rax,[rsi]
    mov [rdi+9],rax
    lea rsi,[d_scr]
    mov rdx,17
    jmp d_out_append
section .bss
d_scr: resb 32
section .text

; d_stage_window(edi=sid, esi=inc) — stage a WINDOW_UPDATE (rbx=ctx).
d_stage_window:
    push rbx
    mov r8d, edi                       ; sid
    mov r9d, esi                       ; inc
    pop rbx
    lea rax,[d_scr]
    mov byte [rax],0
    mov byte [rax+1],0
    mov byte [rax+2],4
    mov byte [rax+3],LINNEA_H2C_FT_WINDOW
    mov byte [rax+4],0
    mov ecx,r8d
    bswap ecx
    mov [rax+5],ecx
    mov ecx,r9d
    bswap ecx
    mov [rax+9],ecx
    lea rsi,[d_scr]
    mov rdx,13
    jmp d_out_append

; d_apply_settings(rsi=payload ptr, rcx=payload len) — set ctx.stream_win from
; the server's INITIAL_WINDOW_SIZE (rbx=ctx).
; d_apply_settings(rsi=payload, rcx=len) — apply a backend's SETTINGS (rbx=ctx).
;
; INITIAL_WINDOW_SIZE is the only identifier acted on, and that is deliberate
; rather than unfinished. Measured against the peers this actually meets: nginx
; advertises MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE and MAX_FRAME_SIZE, and
; nothing else. Taking the rest in turn --
;
;   HEADER_TABLE_SIZE   bounds the dynamic table an ENCODER may index into. Ours
;                       never indexes: h2c_build_headers emits 0x00 only,
;                       literal with a literal name, without indexing. There is
;                       no table to size, so there is nothing to honour.
;   MAX_FRAME_SIZE      is a ceiling we are already under -- we emit nothing
;                       larger than 16384, which every peer must accept, so
;                       nginx's 16777215 buys only an optimisation we decline.
;                       Its VALUE is nonetheless checked against 6.5.2's bounds
;                       now: "we need not act on it" and "we need not validate
;                       it" are different claims, and this comment used to make
;                       the first and imply the second (audit-report-50).
;   MAX_CONCURRENT      limits streams WE may open on this leg. A leg carries
;                       exactly one request on stream 1, so the smallest legal
;                       value already accommodates us. 6.5.2 gives it no bounds
;                       beyond being a 32-bit value, so there is nothing to
;                       reject.
;   MAX_HEADER_LIST_SIZE would bound the request head we send. Ours is capped far
;                       below any advertised value in practice, and neither nginx
;                       nor curl sends the setting at all -- the default is
;                       unlimited. Enforcing it here would be code no peer we
;                       interoperate with can reach, and unreachable code that
;                       enforces a protocol rule can only ever be wrong.
;
; Unknown identifiers must be ignored (RFC 9113 6.5.2), which is what the walk
; below does by falling through .next.
;
; ENABLE_PUSH we now both send (0) and validate on receipt -- and validate more
; strictly than "0 or 1", because 6.5.2 forbids a SERVER to set it to 1 at all
; and obliges a client to treat receipt of 1 as a connection error. Zero is the
; only value that may reach us here.
; d_apply_settings(rsi=payload, rcx=len) -> rax 0 ok / -1 protocol error.
; The caller has established stream 0 and a length that is a multiple of six.
;
; INITIAL_WINDOW_SIZE is applied as a DELTA (RFC 9113 6.9.2): a change adjusts
; every open stream's CURRENT window by new - old. Assigning it outright was
; correct only for the first SETTINGS, before any body had gone out. Measured
; against a peer that let 8192 bytes through and then lowered the setting to
; 1024 without granting anything: the correct window is 0 + (1024 - 8192),
; negative, so not one further byte may be sent -- and 1024 bytes went out
; (audit-report-48).
; d_set_val(rsi = a six-octet SETTINGS record) -> eax = its 32-bit value.
; Shared by both walkers so the identifier can be dispatched BEFORE the value is
; read, without threading the value through a register the callers might want.
d_set_val:
    movzx eax, byte [rsi+2]
    shl eax, 8
    movzx edx, byte [rsi+3]
    or eax, edx
    shl eax, 8
    movzx edx, byte [rsi+4]
    or eax, edx
    shl eax, 8
    movzx edx, byte [rsi+5]
    or eax, edx
    ret

d_apply_settings:
.l:
    cmp rcx, 6
    jb .done
    movzx eax, byte [rsi]
    shl eax, 8
    movzx edx, byte [rsi+1]
    or eax, edx
    ; 6.5.2 gives BOUNDS for the defined identifiers, and a value outside them
    ; is a connection error -- which is a different rule from "ignore what you do
    ; not know". Only INITIAL_WINDOW_SIZE was checked, so a backend could send
    ; ENABLE_PUSH 2 or MAX_FRAME_SIZE 1 and be acknowledged (audit-report-50).
    cmp eax, LINNEA_H2C_SET_INITWIN
    je .s_initwin
    cmp eax, LINNEA_H2C_SET_PUSH
    je .s_push
    cmp eax, LINNEA_H2C_SET_MAXFRAME
    je .s_maxframe
    jmp .next                        ; genuinely unknown: ignore, as 6.5.2 says
.s_push:
    ; Stricter than "0 or 1", and deliberately: a SERVER must not set this to 1,
    ; and a client must treat receipt of 1 as a connection error. Only 0 may
    ; ever reach us here.
    call d_set_val
    test eax, eax
    jnz .bad_s
    jmp .next
.s_maxframe:
    call d_set_val
    cmp eax, 16384
    jb .bad_s
    cmp eax, 16777215
    ja .bad_s
    jmp .next                        ; in range; we emit 16384 regardless
.s_initwin:
    call d_set_val
    cmp eax, 0x7fffffff
    ja .bad_s                        ; 6.5.2: above the maximum window
    mov rdx, [rbx + linnea_h2c.peer_init_win]
    mov [rbx + linnea_h2c.peer_init_win], rax
    sub rax, rdx                     ; the delta, signed
    add [rbx + linnea_h2c.stream_win], rax
.next:
    add rsi,6
    sub rcx,6
    jmp .l
.done:
    xor eax, eax
    ret
.bad_s:
    mov rax, -1
    ret

; d_apply_window(rsi=payload ptr, rdi=sid) — grow ctx conn/stream send window.
; d_apply_window(rdi=sid, rsi=payload) -> rax 0 ok / -1 protocol error.
; The caller has already established that the frame is four octets on a stream
; this leg owns; what is left is the value. RFC 9113 6.9: a zero increment is a
; protocol error, and 6.9.1 forbids a window above 2^31-1. Neither was checked
; and the addition was unguarded, so a backend could inflate the credit the body
; sender then spends (audit-report-47).
;
; The comparison is SIGNED. A window may legitimately be negative -- a SETTINGS
; that lowers INITIAL_WINDOW_SIZE takes it there, and d_stage_body already
; treats <= 0 as blocked -- and an unsigned test would read a negative window as
; enormous and refuse a perfectly good increment.
d_apply_window:
    movzx eax, byte [rsi]
    shl eax,8
    movzx edx, byte [rsi+1]
    or eax,edx
    shl eax,8
    movzx edx, byte [rsi+2]
    or eax,edx
    shl eax,8
    movzx edx, byte [rsi+3]
    or eax,edx
    and eax, 0x7fffffff
    test eax, eax
    jz .bad_w
    test rdi, rdi
    jnz .stream
    mov rcx, [rbx + linnea_h2c.conn_win]
    add rcx, rax
    cmp rcx, 0x7fffffff
    jg .bad_w
    mov [rbx + linnea_h2c.conn_win], rcx
    xor eax, eax
    ret
.stream:
    mov rcx, [rbx + linnea_h2c.stream_win]
    add rcx, rax
    cmp rcx, 0x7fffffff
    jg .bad_w
    mov [rbx + linnea_h2c.stream_win], rcx
    xor eax, eax
    ret
.bad_w:
    mov rax, -1
    ret

; h2c_classify_block(rdi = 1 if the final response head is already in, else 0;
;                     rsi = the END_STREAM bit of the frame that OPENED this
;                     block) -> rax:
;     0  this block IS the final response header section; the globals
;        h2c_status / h2c_hdrlines(+_len) hold it and nothing else
;     1  an informational (1xx) response: discarded, keep reading
;     2  a valid trailer section: discarded, the response is complete
;    -1  malformed
;
; A response is not one header block. RFC 9113 8.1: zero or more 1xx blocks,
; then the single final response, then optionally a TRAILER section that ends
; the stream. All three are "a completed HEADERS block", and only the middle one
; is the response — so the block has to be classified by what is in it, not by
; how many came before. Every one of them is decoded either way, because HPACK
; is stateful: a block left undecoded desynchronizes the dynamic table for every
; block after it, on this connection, for good.
;
; The staged block must already be in h2c_hdrblk/h2c_hdrblk_len. On 1, 2 and -1
; the status and header lines the response head produced are put back, so a
; discarded block leaves no trace in them.
h2c_classify_block:
    push rbx
    push r12
    mov rbx, rdi                     ; have-final-head flag
    mov r12, rsi                     ; this block's END_STREAM bit
    mov rax, [h2c_status]
    mov [h2c_tr_status], rax
    mov rax, [h2c_hdrlines_len]
    mov [h2c_tr_lines], rax
    mov rax, [h2c_cl_seen]
    mov [h2c_tr_cl_s], rax
    mov rax, [h2c_cl_val]
    mov [h2c_tr_cl_v], rax
    mov qword [h2c_cl_seen], 0       ; ...and THIS block's content-length: a
    mov qword [h2c_cl_val], 0        ; trailer's must never reach the assertion
    mov qword [h2c_status_seen], 0   ; 8.3 is per FIELD BLOCK: an interim
    mov qword [h2c_regular_seen], 0  ; response and the final one each get one
    mov qword [h2c_status], 0        ; judge THIS block's :status, not a stale one
    mov qword [h2c_saw_pseudo], 0
    test rbx, rbx
    jnz .decode                      ; a later block appends ABOVE the head's
    mov qword [h2c_hdrlines_len], 0  ; no head yet: this block starts the lines
.decode:
    call h2c_do_decode
    test rax, rax
    js .bad
    ; Once the final response head is in, EVERY later block is a trailer
    ; section. An informational response cannot follow the response it informs
    ; about, so a late 1xx is refused by the trailer rule — which admits no
    ; pseudo-header — rather than mistaken for an early one. Asking "is it 1xx?"
    ; FIRST let a post-final :status=103 be dropped as though it were allowed,
    ; and the DATA after it completed the exchange (audit-report-44). The order
    ; of these two questions IS the rule: what a block may be depends on what
    ; has already arrived, not only on what is in it.
    test rbx, rbx
    jnz .trailer
    ; --- informational? 1xx is not the response and not a trailer -------------
    mov rax, [h2c_status]
    cmp rax, 100
    jb .final
    cmp rax, 200
    jae .final
    ; RFC 9113 8.6: HTTP/2 does not support 101, and 8.8.5 describes
    ; informational responses as the 1xx codes OTHER than it. There is no
    ; Upgrade-based protocol switch on an h2 stream, so a backend sending 101
    ; has sent something this leg cannot translate -- accepting it as an interim
    ; block DROPPED it and relayed whatever came next as the answer
    ; (audit-report-62). The frontend has refused the same status from an h1
    ; upstream since its own Finding 30, in almost these words: "101 has no
    ; meaning over an h2 proxy".
    cmp rax, 101
    je .bad
    test r12, r12
    jnz .bad                         ; a 1xx cannot end the stream
    call .restore
    mov rax, 1
    jmp .ret
.final:
    ; A response header section must carry :status, and it must be one. Without
    ; this the driver accepted a block that had none and synthesized
    ; "HTTP/1.1 000 Status", leaving a downstream validator to notice — which
    ; the proxy does, but the driver has callers that do not.
    cmp rax, 200                     ; 1xx already went to the branch above
    jb .bad
    cmp rax, 599
    ja .bad
    xor eax, eax                     ; the final response header section
    jmp .ret
.trailer:
    ; A trailer section carries no pseudo-header, and it MUST carry END_STREAM:
    ; that bit is what makes it the end of the response rather than a stray
    ; header block. Without it, the DATA that followed was appended to the body
    ; and its END_STREAM completed the exchange, so a backend protocol error was
    ; relayed as a response the client believed had completed properly
    ; (audit-report-43).
    call .restore
    cmp qword [h2c_saw_pseudo], 0
    jne .bad
    test r12, r12
    jz .bad
    mov rax, 2
    jmp .ret
.restore:
    mov rax, [h2c_tr_status]
    mov [h2c_status], rax
    mov rax, [h2c_tr_lines]
    mov [h2c_hdrlines_len], rax
    mov rax, [h2c_tr_cl_s]
    mov [h2c_cl_seen], rax
    mov rax, [h2c_tr_cl_v]
    mov [h2c_cl_val], rax
    ret
.bad:
    call .restore
    mov rax, -1
.ret:
    pop r12
    pop rbx
    ret

; d_decode_block() — decode ctx.hdrblk into ctx.status + ctx.hdrlines, reusing
; the global decoder (wired to the per-leg dyn table). rbx=ctx. rax 0/-1.
; Only the FIRST completed block of a response may set either; ctx.hdr_done says
; which block this is, and a later one is a trailer section.
d_decode_block:
    lea rax, [h2c_scratch]
    mov [h2c_carrier + linnea_h2_req.scratch], rax
    lea rcx, [rax + LINNEA_H2C_SCRATCH_CAP]
    mov [h2c_carrier + linnea_h2_req.scratch_end], rcx
    lea rdx, [rbx + linnea_h2c.dyn]
    mov [h2c_carrier + linnea_h2_req.dyn], rdx
    lea rsi, [rbx + linnea_h2c.hdrblk]
    lea rdi, [h2c_hdrblk]
    mov rcx, [rbx + linnea_h2c.hdrblk_len]
    mov [h2c_hdrblk_len], rcx
    rep movsb
    ; hdrblk holds ONE block. It used to be left filled, so a trailer section
    ; decoded the concatenation of itself and the initial block — re-running the
    ; initial block's bytes against a dynamic table those same bytes had already
    ; grown, and re-emitting its fields ahead of the trailer's.
    mov qword [rbx + linnea_h2c.hdrblk_len], 0
    mov rdi, [rbx + linnea_h2c.hdr_done]
    mov rsi, [rbx + linnea_h2c.hdr_es]
    call h2c_classify_block
    test rax, rax
    jnz .ret                         ; -1 malformed, 1 informational, 2 trailer
    mov rax, [h2c_status]            ; the final head: commit it to the leg
    mov [rbx + linnea_h2c.status], rax
    mov rax, [h2c_cl_seen]
    mov [rbx + linnea_h2c.cl_seen], rax
    mov rax, [h2c_cl_val]
    mov [rbx + linnea_h2c.cl_val], rax
    mov rax, [h2c_is_head]
    mov [rbx + linnea_h2c.is_head], rax
    mov rcx, [h2c_hdrlines_len]
    mov [rbx + linnea_h2c.hdrlines_len], rcx
    lea rsi, [h2c_hdrlines]
    lea rdi, [rbx + linnea_h2c.hdrlines]
    rep movsb
    xor eax, eax
.ret:
    ret

; d_stage_body() — stage the next request DATA chunk (rbx=ctx). Returns
;   rax=0 staged (WANT_SEND), 1 window-blocked (WANT_RECV), 2 body complete.
d_stage_body:
    mov r8, [rbx + linnea_h2c.req_body_len]
    sub r8, [rbx + linnea_h2c.body_sent]      ; remaining
    jz .complete
    ; min(stream, conn) -- SIGNED. A stream window may be negative, and since
    ; 6.9.2 became a delta rather than an assignment it genuinely goes there: a
    ; peer that lowers INITIAL_WINDOW_SIZE below what a stream has already spent
    ; owes nothing until it grants. Taken unsigned, that negative window reads
    ; as enormous, the connection window wins the minimum, and the sender spends
    ; credit the peer never gave -- measured at 21808 bytes past a window of
    ; -7168. The `jle` below was already signed; this comparison was not.
    mov r9, [rbx + linnea_h2c.stream_win]
    mov rax, [rbx + linnea_h2c.conn_win]
    cmp rax, r9
    jge .m1
    mov r9, rax
.m1:
    test r9, r9
    jle .blocked
    cmp r9, 16384
    jbe .m2
    mov r9, 16384
.m2:
    cmp r9, r8
    jbe .m3
    mov r9, r8                                 ; n = min(win,16384,remaining)
.m3:
    ; DATA frame header into d_scr, then append header + payload to out
    lea rdi, [d_scr]
    mov rax, r9
    shr rax, 16
    mov [rdi], al
    mov rax, r9
    shr rax, 8
    mov [rdi+1], al
    mov [rdi+2], r9b
    mov byte [rdi+3], LINNEA_H2C_FT_DATA
    mov rax, [rbx + linnea_h2c.body_sent]
    add rax, r9
    cmp rax, [rbx + linnea_h2c.req_body_len]
    jne .nl
    mov byte [rdi+4], LINNEA_H2C_FL_END_STREAM
    jmp .fh
.nl:
    mov byte [rdi+4], 0
.fh:
    mov dword [rdi+5], 0x01000000
    lea rsi, [d_scr]
    mov rdx, 9
    call d_out_append
    jc .fail
    mov rsi, [rbx + linnea_h2c.req_body]
    add rsi, [rbx + linnea_h2c.body_sent]
    mov rdx, r9
    call d_out_append
    jc .fail
    sub [rbx + linnea_h2c.stream_win], r9
    sub [rbx + linnea_h2c.conn_win], r9
    add [rbx + linnea_h2c.body_sent], r9
    xor eax, eax
    ret
.blocked:
    mov rax, 1
    ret
.complete:
    mov rax, 2
    ret
.fail:
    mov rax, 1                                 ; treat as blocked (shouldn't happen)
    ret

; linnea_h2c_drv_start(rdi=ctx, rsi=h1head, rdx=h1len, rcx=body, r8=bodylen,
;                      r9=scheme) -> rax verdict.
linnea_h2c_drv_start:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [h2c_ctx], rdi
    mov rbx, rdi
    mov qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_SEND_INIT
    mov [rbx+linnea_h2c.scheme], r9
    mov qword [rbx+linnea_h2c.stream_win], 65535
    mov qword [rbx+linnea_h2c.conn_win], 65535
    mov qword [rbx+linnea_h2c.peer_init_win], 65535
    mov qword [rbx+linnea_h2c.status], 0
    mov qword [rbx+linnea_h2c.hdrblk_len], 0
    mov qword [rbx+linnea_h2c.hdr_open], 0
    mov qword [rbx+linnea_h2c.hdr_big], 0
    mov qword [rbx+linnea_h2c.hdrlines_len], 0
    mov qword [rbx+linnea_h2c.body_len], 0
    mov [rbx+linnea_h2c.req_body], rcx
    mov [rbx+linnea_h2c.req_body_len], r8
    mov qword [rbx+linnea_h2c.body_sent], 0
    mov qword [rbx+linnea_h2c.out_len], 0
    mov qword [rbx+linnea_h2c.out_sent], 0
    mov qword [rbx+linnea_h2c.in_len], 0
    mov qword [rbx+linnea_h2c.settled], 0
    mov qword [rbx+linnea_h2c.hdr_es], 0
    mov qword [rbx+linnea_h2c.hdr_done], 0
    lea rdi, [rbx+linnea_h2c.dyn]
    call hpack_dyn_reset
    mov r9, [rbx+linnea_h2c.scheme]
    mov [h2c_scheme], r9
    mov r14, rsi
    mov r15, rdx
    call h2c_build_headers               ; -> rax = block len in h2c_hdrblk
    test rax, rax
    js .fail
    mov r12, rax
    lea rdi, [rbx+linnea_h2c.out_buf]
    lea rsi, [h2c_preface]
    mov rcx, h2c_preface_len
    rep movsb
    mov byte [rdi],0
    mov byte [rdi+1],0
    mov byte [rdi+2],18                   ; three settings, see the blocking twin
    mov byte [rdi+3],LINNEA_H2C_FT_SETTINGS
    mov byte [rdi+4],0
    mov dword [rdi+5],0
    add rdi,9
    mov byte [rdi],0
    mov byte [rdi+1],LINNEA_H2C_SET_INITWIN
    mov byte [rdi+2],(LINNEA_H2C_INITWIN>>24)&0xff
    mov byte [rdi+3],(LINNEA_H2C_INITWIN>>16)&0xff
    mov byte [rdi+4],(LINNEA_H2C_INITWIN>>8)&0xff
    mov byte [rdi+5],LINNEA_H2C_INITWIN&0xff
    add rdi,6
    mov byte [rdi],0
    mov byte [rdi+1],LINNEA_H2C_SET_MAXHDRS
    mov byte [rdi+2],(LINNEA_H2C_MAXHDRS>>24)&0xff
    mov byte [rdi+3],(LINNEA_H2C_MAXHDRS>>16)&0xff
    mov byte [rdi+4],(LINNEA_H2C_MAXHDRS>>8)&0xff
    mov byte [rdi+5],LINNEA_H2C_MAXHDRS&0xff
    add rdi,6
    mov byte [rdi],0
    mov byte [rdi+1],LINNEA_H2C_SET_PUSH
    mov dword [rdi+2],0                   ; ENABLE_PUSH = 0
    add rdi,6
    mov rax,r12
    shr rax,16
    mov [rdi],al
    mov rax,r12
    shr rax,8
    mov [rdi+1],al
    mov [rdi+2],r12b
    mov byte [rdi+3],LINNEA_H2C_FT_HEADERS
    mov al, LINNEA_H2C_FL_END_HEADERS
    cmp qword [rbx+linnea_h2c.req_body_len],0
    jne .hb
    or al, LINNEA_H2C_FL_END_STREAM
.hb:
    mov [rdi+4],al
    mov dword [rdi+5],0x01000000
    add rdi,9
    lea rsi,[h2c_hdrblk]
    mov rcx,r12
    rep movsb
    lea rax,[rbx+linnea_h2c.out_buf]
    sub rdi,rax
    mov [rbx+linnea_h2c.out_len],rdi
    mov rax, LINNEA_H2C_WANT_SEND
    jmp .ret
.fail:
    mov qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_FAILED
    mov rax, LINNEA_H2C_DRV_FAIL
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h2c_drv_on_sent(rdi=ctx, rsi=nsent) -> rax verdict.
linnea_h2c_drv_on_sent:
    push rbx
    mov [h2c_ctx], rdi
    mov rbx, rdi
    add [rbx+linnea_h2c.out_sent], rsi
    mov rax,[rbx+linnea_h2c.out_sent]
    cmp rax,[rbx+linnea_h2c.out_len]
    jb .more
    mov qword [rbx+linnea_h2c.out_sent],0
    mov qword [rbx+linnea_h2c.out_len],0
    mov rax,[rbx+linnea_h2c.state]
    cmp rax, LINNEA_H2C_ST_SEND_INIT
    je .after_init
    cmp rax, LINNEA_H2C_ST_SEND_BODY
    je .after_body
    mov rax, LINNEA_H2C_WANT_RECV
    jmp .ret
.after_init:
    cmp qword [rbx+linnea_h2c.req_body_len],0
    je .to_resp
    mov qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_SETTLE
    mov rax, LINNEA_H2C_WANT_RECV
    jmp .ret
.to_resp:
    mov qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_RESP
    mov rax, LINNEA_H2C_WANT_RECV
    jmp .ret
.after_body:
    call d_stage_body
    cmp rax, 0
    je .want_send
    cmp rax, 2
    je .to_resp
    mov rax, LINNEA_H2C_WANT_RECV
    jmp .ret
.want_send:
    mov rax, LINNEA_H2C_WANT_SEND
    jmp .ret
.more:
    mov rax, LINNEA_H2C_WANT_SEND
.ret:
    pop rbx
    ret

; linnea_h2c_drv_on_recv(rdi=ctx, rsi=data, rdx=len) -> rax verdict.
; Accumulates into ctx.in_buf, parses every complete frame, and dispatches.
linnea_h2c_drv_on_recv:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [h2c_ctx], rdi
    mov rbx, rdi
    ; append data to in_buf (bounded)
    mov rax, [rbx+linnea_h2c.in_len]
    lea r12, [rax + rdx]                ; new in_len
    cmp r12, LINNEA_H2C_D_IN_CAP
    ja .fail
    lea rdi, [rbx+linnea_h2c.in_buf]
    add rdi, rax
    mov rcx, rdx
    rep movsb
    mov [rbx+linnea_h2c.in_len], r12
    ; --- parse frames from in_buf[0 .. in_len) ---
    xor r13, r13                        ; parse offset
.parse:
    mov r14, [rbx+linnea_h2c.in_len]
    mov rax, r13
    add rax, 9
    cmp rax, r14
    ja .compact                        ; < 9 bytes: need more
    lea rsi, [rbx+linnea_h2c.in_buf]
    add rsi, r13                        ; frame start
    ; length (24-bit)
    movzx eax, byte [rsi]
    shl eax,8
    movzx ecx, byte [rsi+1]
    or eax,ecx
    shl eax,8
    movzx ecx, byte [rsi+2]
    or eax,ecx
    mov r15, rax                        ; frame payload len
    cmp r15, LINNEA_H2C_RX_FRAME_MAX    ; 4.2: refuse it now, rather than wait
    ja .fail                            ; for a frame we will not accept anyway
    mov rax, r13
    add rax, 9
    add rax, r15
    cmp rax, r14
    ja .compact                        ; frame not fully present
    ; dispatch on type
    movzx eax, byte [rsi+3]            ; type
    movzx ecx, byte [rsi+4]           ; flags
    mov [d_fr_flags], rcx
    mov ecx, [rsi+5]
    bswap ecx
    and ecx, 0x7fffffff
    mov [d_fr_sid], rcx
    lea r12, [rsi+9]                   ; payload ptr
    ; advance parse offset past this frame now
    add r13, 9
    add r13, r15
    call d_dispatch                    ; rax: 0 ok, negative sentinel to return
    test rax, rax
    js .propagate
    jmp .parse
.compact:
    ; move the unparsed tail [r13 .. in_len) to the front
    mov r14, [rbx+linnea_h2c.in_len]
    sub r14, r13                       ; remaining
    test r13, r13
    jz .no_move
    lea rsi, [rbx+linnea_h2c.in_buf]
    add rsi, r13
    lea rdi, [rbx+linnea_h2c.in_buf]
    mov rcx, r14
    rep movsb
.no_move:
    mov [rbx+linnea_h2c.in_len], r14
    ; mid-upload with the window reopened (or just settled): stage the next DATA
    cmp qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_SEND_BODY
    jne .chk_done
    call d_stage_body
    cmp rax, 2
    jne .chk_done
    mov qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_RESP
.chk_done:
    ; response complete?
    cmp qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_DONE
    je .done
    ; output staged?
    mov rax, [rbx+linnea_h2c.out_len]
    cmp rax, [rbx+linnea_h2c.out_sent]
    ja .want_send
    mov rax, LINNEA_H2C_WANT_RECV
    jmp .ret
.want_send:
    mov rax, LINNEA_H2C_WANT_SEND
    jmp .ret
.done:
    mov rax, LINNEA_H2C_DRV_DONE
    jmp .ret
.propagate:
    ; rax holds a negative sentinel: map to verdict
    cmp rax, -2
    je .rst
    cmp rax, -3
    je .goaway
    mov rax, LINNEA_H2C_DRV_FAIL
    jmp .ret
.rst:
    mov rax, LINNEA_H2C_DRV_RST
    jmp .ret
.goaway:
    mov rax, LINNEA_H2C_DRV_GOAWAY
    jmp .ret
.fail:
    mov rax, LINNEA_H2C_DRV_FAIL
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; d_dispatch() — process one parsed frame. rbx=ctx, eax=type, r12=payload ptr,
; r15=payload len, [d_fr_flags]/[d_fr_sid] set. Returns rax=0 ok, or -1/-2/-3.
d_dispatch:
    ; RFC 9113 3.4: nothing may precede the server's SETTINGS preface -- not a
    ; PING, not a WINDOW_UPDATE, not a response, and not an ACK of ours. See
    ; h2c_next_frame for the same rule on the blocking side. .settled is exactly
    ; "a non-ACK SETTINGS has been applied", which is what the preface is, so
    ; the state this needed was already here and simply unused.
    cmp qword [rbx+linnea_h2c.settled], 0
    jne .prefaced
    cmp eax, LINNEA_H2C_FT_SETTINGS
    jne .bad
    cmp qword [d_fr_sid], 0
    jne .bad
    mov rdx, [d_fr_flags]
    test rdx, LINNEA_H2C_FL_ACK
    jnz .bad
.prefaced:
    ; RFC 9113 6.10: a CONTINUATION may only follow a HEADERS or CONTINUATION
    ; whose block is still open, on the same stream, with NO frame of any kind
    ; in between -- not a PING, not a SETTINGS, not one for another stream. The
    ; driver had no notion of a block being open at all, so a CONTINUATION out
    ; of nowhere was decoded as though it were the response head, and a PING
    ; could sit between a HEADERS and its continuation (audit-report-45).
    cmp qword [rbx+linnea_h2c.hdr_open], 0
    jne .in_block
    cmp eax, LINNEA_H2C_FT_CONT
    je .bad                             ; a continuation of nothing
    jmp .type
.in_block:
    cmp eax, LINNEA_H2C_FT_CONT
    jne .bad                            ; anything else, interleaved
    cmp qword [d_fr_sid], 1             ; the block was opened on stream 1
    jne .bad
.type:
    ; 8.4: having set ENABLE_PUSH 0, receipt of a PUSH_PROMISE is a connection
    ; error. Before, it fell into the ignore-unknown arm at the end and the
    ; promise was silently dropped.
    cmp eax, LINNEA_H2C_FT_PUSH
    je .bad
    cmp eax, LINNEA_H2C_FT_SETTINGS
    je .settings
    cmp eax, LINNEA_H2C_FT_WINDOW
    je .window
    cmp eax, LINNEA_H2C_FT_PING
    je .ping
    cmp eax, LINNEA_H2C_FT_HEADERS
    je .headers
    cmp eax, LINNEA_H2C_FT_CONT
    je .cont
    cmp eax, LINNEA_H2C_FT_DATA
    je .data
    cmp eax, LINNEA_H2C_FT_RST
    je .rst
    cmp eax, LINNEA_H2C_FT_GOAWAY
    je .goaway
    xor eax, eax                        ; ignore unknown
    ret
.settings:
    ; 6.5: SETTINGS is a connection frame -- stream 0 -- an ACK carries no
    ; payload, and a non-ACK payload is a whole number of six-octet records.
    ; None of that was checked, so a SETTINGS naming a stream, an ACK with
    ; bytes in it, and a five-octet payload were all accepted and acknowledged
    ; (audit-report-48).
    cmp qword [d_fr_sid], 0
    jne .bad
    mov rax, [d_fr_flags]
    test rax, LINNEA_H2C_FL_ACK
    jz .set_nonack
    test r15, r15
    jnz .bad                         ; an ACK with a payload
    jmp .ok
.set_nonack:
    mov rax, r15
    xor edx, edx
    mov rcx, 6
    div rcx
    test rdx, rdx
    jnz .bad                         ; not a multiple of six
    mov rsi, r12
    mov rcx, r15
    call d_apply_settings
    test rax, rax
    js .bad
    call d_stage_settings_ack
    mov qword [rbx+linnea_h2c.settled], 1
    ; if we were settling before the body, start sending it now; the actual
    ; staging happens in on_recv's post-parse step (uniform with WINDOW_UPDATE).
    cmp qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_SETTLE
    jne .ok
    mov qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_SEND_BODY
.ok:
    xor eax, eax
    ret
.h_open:
    mov qword [rbx+linnea_h2c.hdr_open], 1
    xor eax, eax
    ret
.window:
    ; 6.9: exactly four octets, on stream 0 or the one stream this leg owns.
    ; Neither was checked -- a three-octet update had its fourth byte read from
    ; past the frame, and an update naming an unrelated stream credited stream 1
    ; all the same (audit-report-47).
    cmp r15, 4
    jne .bad
    mov rdi, [d_fr_sid]
    cmp rdi, 1
    ja .bad
    mov rsi, r12
    call d_apply_window
    test rax, rax
    js .bad
    xor eax, eax
    ret
.ping:
    ; RFC 9113 6.7: a PING is exactly 8 octets, on stream 0. Neither was
    ; checked, and d_stage_ping_ack reads a full qword from the payload pointer
    ; regardless of the length the frame declared -- so a 7-byte PING was
    ; answered with those seven bytes plus whatever followed them in the leg's
    ; receive arena, echoed back to the backend. Measured, not inferred:
    ; b"1234567\x00" (audit-report-46).
    ;
    ; Unused FLAG bits are deliberately not checked. 4.1 requires them to be
    ; ignored on receipt, and the frontend's own matrix asserts only these two
    ; PING errors -- rejecting a flag we do not know would be over-strict in a
    ; place the spec is explicit about.
    cmp qword [d_fr_sid], 0
    jne .bad
    cmp r15, 8
    jne .bad
    mov rax, [d_fr_flags]
    test rax, LINNEA_H2C_FL_ACK
    jnz .ok
    mov rsi, r12
    call d_stage_ping_ack
    xor eax, eax
    ret
.headers:
    ; 6.1/6.2: this leg is single-stream. A HEADERS or DATA frame naming
    ; stream 0, or a stream we never opened, cannot belong to this response.
    ; Skipping it is not the safe reading it looks like: HPACK state is per
    ; CONNECTION, so a header block passed over rather than decoded shifts
    ; every later dynamic index by one. Measured: a backend meaning index 63
    ; had "x-a: aaa" relayed in place of "x-b: bbb", under a clean 200
    ; (audit-report-53).
    cmp qword [d_fr_sid], 1
    jne .bad
    mov rax, [d_fr_flags]
    and rax, LINNEA_H2C_FL_END_STREAM
    mov [rbx+linnea_h2c.hdr_es], rax
    mov rsi, r12
    mov rdx, r15
    mov rax, [d_fr_flags]
    test rax, LINNEA_H2C_FL_PADDED
    jz .h_np
    ; RFC 9113 6.1: PADDED means the payload STARTS with a Pad Length octet, so
    ; a padded frame whose payload is empty is malformed and the octet must not
    ; be read. The read came first and the length check came after, in the
    ; append helper -- which does reject the negative result, so nothing stale
    ; was ever relayed. That downstream check is the only thing that made it
    ; safe, and audit-report-46 is what happens when there is no such check
    ; below: the same read-then-hope shape, and the bytes went back to the
    ; backend. Bounds first (audit-report-49).
    cmp rdx, 1
    jl .bad
    movzx ecx, byte [rsi]
    inc rsi
    dec rdx
    sub rdx, rcx
    js .bad                          ; padding longer than what is left
.h_np:
    test rax, LINNEA_H2C_FL_PRIORITY
    jz .h_npr
    cmp rdx, 5
    jl .bad                          ; the priority field is not there either
    add rsi, 5
    sub rdx, 5
.h_npr:
    call d_hdrblk_append
    test rax, rax
    js .bad
    mov rax, [d_fr_flags]
    test rax, LINNEA_H2C_FL_END_HEADERS
    jz .h_open                       ; the block awaits its CONTINUATION
    mov qword [rbx+linnea_h2c.hdr_open], 0
    call d_decode_block
    test rax, rax
    js .bad
    cmp rax, 1
    je .ok                           ; informational: read on for the final head
    cmp rax, 2
    je .complete                     ; a trailer section, END_STREAM checked
    mov qword [rbx+linnea_h2c.hdr_done], 1
    cmp qword [rbx+linnea_h2c.hdr_es], 0
    jne .complete
    xor eax, eax
    ret
.cont:
    cmp qword [d_fr_sid], 1             ; unreachable: the open-block gate above
    jne .bad                            ; already refuses a CONTINUATION that is
    mov rsi, r12                        ; on another stream or opens nothing
    mov rdx, r15
    call d_hdrblk_append
    test rax, rax
    js .bad
    mov rax, [d_fr_flags]
    test rax, LINNEA_H2C_FL_END_HEADERS
    jz .ok                           ; still open, still owed a CONTINUATION
    mov qword [rbx+linnea_h2c.hdr_open], 0
    call d_decode_block
    test rax, rax
    js .bad
    cmp rax, 1
    je .ok                           ; informational: read on for the final head
    cmp rax, 2
    je .complete                     ; a trailer section, END_STREAM checked
    mov qword [rbx+linnea_h2c.hdr_done], 1
    cmp qword [rbx+linnea_h2c.hdr_es], 0
    jne .complete
    xor eax, eax
    ret
.data:
    cmp qword [d_fr_sid], 1             ; see .headers
    jne .bad
    ; DATA before the response head is not body: nothing has said what this
    ; response IS yet. It used to be appended anyway, so bytes that arrived
    ; ahead of the head were prepended to the body the client received.
    cmp qword [rbx+linnea_h2c.hdr_done], 0
    je .bad
    mov rsi, r12
    mov rdx, r15
    mov rax, [d_fr_flags]
    test rax, LINNEA_H2C_FL_PADDED
    jz .d_np
    cmp rdx, 1
    jl .bad                          ; see .headers: bounds before the read
    movzx ecx, byte [rsi]
    inc rsi
    dec rdx
    sub rdx, rcx
    js .bad
.d_np:
    call d_body_append
    test rax, rax
    js .bad
    ; return flow-control credit for the whole frame payload
    test r15, r15
    jz .d_es
    mov esi, r15d
    xor edi, edi
    call d_stage_window
    mov esi, r15d
    mov edi, 1
    call d_stage_window
.d_es:
    mov rax, [d_fr_flags]
    test rax, LINNEA_H2C_FL_END_STREAM
    jnz .complete
    xor eax, eax
    ret
.complete:
    mov rdi, [rbx + linnea_h2c.status]
    mov rsi, [rbx + linnea_h2c.is_head]
    mov rdx, [rbx + linnea_h2c.cl_seen]
    mov rcx, [rbx + linnea_h2c.cl_val]
    mov r8, [rbx + linnea_h2c.body_len]
    call h2c_body_ok
    test rax, rax
    jz .bad                        ; 8.1.1 + no-content, see h2c_body_ok
    mov qword [rbx+linnea_h2c.state], LINNEA_H2C_ST_DONE
    xor eax, eax
    ret
    ; 6.4/6.8: RST_STREAM is exactly four octets on a nonzero stream, GOAWAY at
    ; least eight on stream 0. Neither was checked -- a three-octet reset and a
    ; GOAWAY naming a stream became ordinary terminal outcomes (audit-report-51).
    ; This changes classification, not behaviour: a valid reset already ends the
    ; exchange in a 502, so a malformed one did too. The distinction is for the
    ; code to be able to tell them apart, not for anything downstream today.
.rst:
    cmp qword [d_fr_sid], 1
    jne .bad
    cmp r15, 4
    jne .bad
    mov rax, -2
    ret
.goaway:
    cmp qword [d_fr_sid], 0
    jne .bad
    cmp r15, 8
    jb .bad
    mov rax, -3
    ret
.bad:
    mov rax, -1
    ret

; d_hdrblk_append(rsi=ptr, rdx=len) — append to ctx.hdrblk (rbx=ctx). rax 0/-1.
d_hdrblk_append:
    test rdx, rdx
    js .of
    mov rax, [rbx+linnea_h2c.hdrblk_len]
    lea rcx, [rax+rdx]
    cmp rcx, LINNEA_H2C_HDRBLK_CAP
    ja .toobig
    push rsi
    lea rdi, [rbx+linnea_h2c.hdrblk]
    add rdi, rax
    mov rcx, rdx
    rep movsb
    pop rsi
    lea rax, [rbx+linnea_h2c.hdrblk]
    sub rdi, rax
    mov [rbx+linnea_h2c.hdrblk_len], rdi
    xor eax, eax
    ret
.toobig:
    ; the block outgrew the buffer. Recorded apart from a malformed one: the
    ; backend did nothing wrong, and the failure must not read as its fault.
    mov qword [rbx+linnea_h2c.hdr_big], 1
.of:
    mov rax, -1
    ret

; d_body_append(rsi=ptr, rdx=len) — append to ctx.body_buf (rbx=ctx). rax 0/-1.
d_body_append:
    test rdx, rdx
    js .of
    jz .ok
    mov rax, [rbx+linnea_h2c.body_len]
    lea rcx, [rax+rdx]
    cmp rcx, LINNEA_H2C_D_BODY_CAP
    ja .of
    push rsi
    lea rdi, [rbx+linnea_h2c.body_buf]
    add rdi, rax
    mov rcx, rdx
    rep movsb
    pop rsi
    lea rax, [rbx+linnea_h2c.body_buf]
    sub rdi, rax
    mov [rbx+linnea_h2c.body_len], rdi
.ok:
    xor eax, eax
    ret
.of:
    mov rax, -1
    ret

; linnea_h2c_drv_compose(rdi=ctx, rsi=out) -> rax = length. Writes the h1
; response (status line + headers + content-length + body) to `out`.
linnea_h2c_drv_compose:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r13, rsi                        ; out cursor
    mov rdi, r13
    lea rsi, [http11]
    mov rcx, http11_len
    rep movsb
    mov rax, [rbx+linnea_h2c.status]
    call h2c_dec3
    mov byte [rdi], ' '
    inc rdi
    mov eax, [rbx+linnea_h2c.status]
    mov r12, rdi
    call h2c_reason
    mov rdi, r12
    mov rcx, rdx
    rep movsb
    mov byte [rdi],13
    mov byte [rdi+1],10
    add rdi,2
    lea rsi, [rbx+linnea_h2c.hdrlines]
    mov rcx, [rbx+linnea_h2c.hdrlines_len]
    rep movsb
    lea rsi, [hdr_cl]
    mov rcx, hdr_cl_len
    rep movsb
    mov rax, [rbx+linnea_h2c.body_len]   ; the HEAD rule, see h2c_compose
    cmp qword [rbx+linnea_h2c.is_head], 0
    je .cl_have
    cmp qword [rbx+linnea_h2c.cl_seen], 0
    je .cl_have
    mov rax, [rbx+linnea_h2c.cl_val]
.cl_have:
    call h2c_u64_dec
    mov byte [rdi],13
    mov byte [rdi+1],10
    add rdi,2
    mov byte [rdi],13
    mov byte [rdi+1],10
    add rdi,2
    lea rsi, [rbx+linnea_h2c.body_buf]
    mov rcx, [rbx+linnea_h2c.body_len]
    rep movsb
    mov rax, rdi
    sub rax, r13
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h2c_drv_head(rdi=ctx, rsi=out, rdx=cap) -> rax = head length, or -1
; when the head will not fit in `cap` bytes. Writes just the h1 response head
; (status line + relayed headers + content-length + connection: close + blank
; line) to `out`; the proxy queues ctx.body_buf behind it. v1 closes the client
; connection after the response (no keep-alive).
;
; The capacity is not decoration. This wrote hdrlines with a bare rep movsb and
; no bound, into buffers SMALLER than hdrlines can be: out_buf is 8512 bytes and
; up_buf 8448, against a hdrlines that reaches HDRBLK_CAP. A backend answering
; with ~15 KB of headers had ~6.7 KB written past the end of out_buf -- measured,
; not theorised. It stayed inside the connection struct only because up_buf sits
; next to out_buf and is dead on that path; up_buf is the LAST field, so a larger
; head would have run into the next connection in the pool.
linnea_h2c_drv_head:
    push rbx
    push r13
    ; refuse before writing a byte. 128 covers the status line, the longest
    ; reason phrase, "content-length: " + 20 digits, "connection: close" and the
    ; blank line -- everything this function adds around hdrlines.
    mov rax, [rdi + linnea_h2c.hdrlines_len]
    add rax, 128
    cmp rax, rdx
    ja .nofit
    mov rbx, rdi
    mov r13, rsi
    mov rdi, r13
    lea rsi, [http11]
    mov rcx, http11_len
    rep movsb
    mov rax, [rbx+linnea_h2c.status]
    call h2c_dec3
    mov byte [rdi], ' '
    inc rdi
    mov eax, [rbx+linnea_h2c.status]
    push rdi
    call h2c_reason
    pop rdi
    mov rcx, rdx
    rep movsb
    mov byte [rdi],13
    mov byte [rdi+1],10
    add rdi,2
    lea rsi, [rbx+linnea_h2c.hdrlines]
    mov rcx, [rbx+linnea_h2c.hdrlines_len]
    rep movsb
    lea rsi, [hdr_cl]
    mov rcx, hdr_cl_len
    rep movsb
    mov rax, [rbx+linnea_h2c.body_len]   ; the HEAD rule, see h2c_compose
    cmp qword [rbx+linnea_h2c.is_head], 0
    je .cl_have
    cmp qword [rbx+linnea_h2c.cl_seen], 0
    je .cl_have
    mov rax, [rbx+linnea_h2c.cl_val]
.cl_have:
    call h2c_u64_dec
    mov byte [rdi],13
    mov byte [rdi+1],10
    add rdi,2
    lea rsi, [hdr_conn_close]
    mov rcx, hdr_conn_close_len
    rep movsb
    mov byte [rdi],13
    mov byte [rdi+1],10
    add rdi,2
    mov rax, rdi
    sub rax, r13
    pop r13
    pop rbx
    ret
.nofit:
    ; the same flag an oversized block sets, so the callers' existing "ours, not
    ; the backend's" reporting covers this too
    mov qword [rdi + linnea_h2c.hdr_big], 1
    mov rax, -1
    pop r13
    pop rbx
    ret

section .rodata
hdr_conn_close: db "connection: close", 13, 10
hdr_conn_close_len equ $ - hdr_conn_close

section .bss
d_fr_flags: resq 1
d_fr_sid:   resq 1
h2c_drv_ctx: resb linnea_h2c_size          ; the test driver's leg context
section .text

; linnea_h2c_drv_blocking(rdi=fd, rsi=h1head, rdx=h1len, rcx=body, r8=bodylen,
;   r9=scheme) -> rax = length in linnea_h2c_resp_buf, or -1. Drives the
; RESUMABLE driver over a blocking socket (test entry: proves the async driver
; produces the same result as the blocking exchange, over the fixture).
global linnea_h2c_drv_blocking
linnea_h2c_drv_blocking:
    push rbx
    push r12
    push r13
    push r14
    mov r14d, edi
    lea rdi, [h2c_drv_ctx]
    call linnea_h2c_drv_start
    mov r13, rax
.loop:
    cmp r13, LINNEA_H2C_WANT_SEND
    je .snd
    cmp r13, LINNEA_H2C_WANT_RECV
    je .rcv
    cmp r13, LINNEA_H2C_DRV_DONE
    je .done
    mov rax, -1
    jmp .ret
.snd:
    lea rbx, [h2c_drv_ctx]
    mov r12, [rbx+linnea_h2c.out_len]
    sub r12, [rbx+linnea_h2c.out_sent]
    lea rsi, [rbx+linnea_h2c.out_buf]
    add rsi, [rbx+linnea_h2c.out_sent]
    mov edi, r14d
    mov rdx, r12
    call h2c_send_all
    test rax, rax
    js .fail
    lea rdi, [h2c_drv_ctx]
    mov rsi, r12
    call linnea_h2c_drv_on_sent
    mov r13, rax
    jmp .loop
.rcv:
    mov rdx, 20480
    mov rax, [h2c_chunk_cap]
    test rax, rax
    jz .rgo
    cmp rax, rdx
    jae .rgo
    mov rdx, rax
.rgo:
    mov eax, LINNEA_SYS_READ
    mov edi, r14d
    lea rsi, [h2c_frame_buf]
    syscall
    test rax, rax
    jle .fail
    lea rdi, [h2c_drv_ctx]
    lea rsi, [h2c_frame_buf]
    mov rdx, rax
    call linnea_h2c_drv_on_recv
    mov r13, rax
    jmp .loop
.done:
    lea rdi, [h2c_drv_ctx]
    lea rsi, [linnea_h2c_resp_buf]
    call linnea_h2c_drv_compose
    jmp .ret
.fail:
    mov rax, -1
.ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

