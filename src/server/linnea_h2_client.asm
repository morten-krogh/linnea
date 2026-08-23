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

pseudo_status:   db ":status"
pseudo_status_len equ $ - pseudo_status

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
h2c_body_len:  resq 1
h2c_stream_win: resq 1                          ; our stream-1 SEND window
h2c_conn_win:  resq 1                           ; connection SEND window
h2c_rx_len:    resq 1                           ; bytes buffered in h2c_frame_buf from a prior read
h2c_scheme:    resq 1
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
    mov qword [h2c_rx_len], 0
    mov qword [h2c_stream_win], 65535     ; default until server SETTINGS
    mov qword [h2c_conn_win], 65535
    mov r14, rsi                          ; h1 head ptr
    mov r15, rdx                          ; h1 head len
    mov r12, rcx                          ; body ptr
    mov r13, r8                           ; body len

    ; init the decoder carrier + its dynamic table
    call h2c_init_carrier

    ; --- build the outbound preface + SETTINGS + HEADERS into h2c_out_buf ---
    lea rdi, [h2c_out_buf]
    lea rsi, [h2c_preface]
    mov rcx, h2c_preface_len
    rep movsb                             ; rdi advanced
    ; SETTINGS frame: length=6, type=4, flags=0, sid=0, payload {0x0004, initwin}
    mov byte [rdi + 0], 0
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 6
    mov byte [rdi + 3], LINNEA_H2_FT_SETTINGS
    mov byte [rdi + 4], 0
    mov dword [rdi + 5], 0                ; sid 0
    add rdi, 9
    mov byte [rdi + 0], 0                 ; id hi
    mov byte [rdi + 1], LINNEA_H2_SET_INITWIN
    ; INITIAL_WINDOW_SIZE value, big-endian
    mov byte [rdi + 2], (LINNEA_H2C_INITWIN >> 24) & 0xff
    mov byte [rdi + 3], (LINNEA_H2C_INITWIN >> 16) & 0xff
    mov byte [rdi + 4], (LINNEA_H2C_INITWIN >> 8) & 0xff
    mov byte [rdi + 5], LINNEA_H2C_INITWIN & 0xff
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
    mov byte [rdi + 3], LINNEA_H2_FT_HEADERS
    ; flags: END_HEADERS always; END_STREAM iff no body
    mov al, LINNEA_H2_FL_END_HEADERS
    test r13, r13
    jnz .have_body_flag
    or al, LINNEA_H2_FL_END_STREAM
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
    cmp qword [h2c_scheme], LINNEA_H2_SCHEME_HTTPS
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
    ret
.eof:
    mov rax, -1
    ret

; h2c_send_settings_ack()
h2c_send_settings_ack:
    lea rdi, [h2c_out_buf]
    mov dword [rdi], 0
    mov byte [rdi+3], LINNEA_H2_FT_SETTINGS
    mov byte [rdi+4], LINNEA_H2_FL_ACK
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
    mov byte [rdi+3], LINNEA_H2_FT_PING
    mov byte [rdi+4], LINNEA_H2_FL_ACK
    mov dword [rdi+5], 0
    mov rax, [h2c_frame_buf+9]
    mov [rdi+9], rax
    mov edi, dword [h2c_fd]
    lea rsi, [h2c_out_buf]
    mov rdx, 17
    call h2c_send_all
    ret

; h2c_send_window(edi=sid, esi=inc)
h2c_send_window:
    push rbx
    mov ebx, esi
    lea rax, [h2c_out_buf]
    mov byte [rax], 0
    mov byte [rax+1], 0
    mov byte [rax+2], 4
    mov byte [rax+3], LINNEA_H2_FT_WINDOW
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
h2c_apply_settings:
    lea rsi, [h2c_frame_buf+9]
    mov rcx, [h2c_fr_len]
.l:
    cmp rcx, 6
    jb .done
    movzx eax, byte [rsi]
    shl eax, 8
    movzx edx, byte [rsi+1]
    or eax, edx
    cmp eax, LINNEA_H2_SET_INITWIN
    jne .next
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
    mov [h2c_stream_win], rax
.next:
    add rsi, 6
    sub rcx, 6
    jmp .l
.done:
    ret

; h2c_apply_window() — WINDOW_UPDATE: grow conn (sid 0) or stream (sid 1) window.
h2c_apply_window:
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
    cmp qword [h2c_fr_sid], 0
    jne .stream
    add [h2c_conn_win], rax
    ret
.stream:
    add [h2c_stream_win], rax
    ret

; ============================================================================
; Request body send (flow-controlled) + settle/pump helpers.
; ============================================================================
; h2c_settle() — read frames until the server's (non-ACK) SETTINGS, apply+ACK it.
h2c_settle:
    call h2c_next_frame
    test rax, rax
    js .err
    cmp eax, LINNEA_H2_FT_SETTINGS
    je .settings
    cmp eax, LINNEA_H2_FT_WINDOW
    je .win
    cmp eax, LINNEA_H2_FT_PING
    je .ping
    cmp eax, LINNEA_H2_FT_GOAWAY
    je .goaway
    jmp h2c_settle
.settings:
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2_FL_ACK
    jnz h2c_settle
    call h2c_apply_settings
    call h2c_send_settings_ack
    xor eax, eax
    ret
.win:
    call h2c_apply_window
    jmp h2c_settle
.ping:
    call h2c_send_ping_ack
    jmp h2c_settle
.goaway:
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
    cmp eax, LINNEA_H2_FT_WINDOW
    je .w
    cmp eax, LINNEA_H2_FT_SETTINGS
    je .s
    cmp eax, LINNEA_H2_FT_PING
    je .p
    cmp eax, LINNEA_H2_FT_RST
    je .rst
    cmp eax, LINNEA_H2_FT_GOAWAY
    je .goaway
    jmp .err                      ; response before END_STREAM: unsupported in v1
.w:
    call h2c_apply_window
    jmp .chk
.s:
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2_FL_ACK
    jnz .chk
    call h2c_apply_settings
    call h2c_send_settings_ack
    jmp .chk
.p:
    call h2c_send_ping_ack
    jmp .chk
.rst:
    mov rax, LINNEA_H2C_RST
    ret
.goaway:
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
    mov r13, [h2c_stream_win]
    mov rax, [h2c_conn_win]
    cmp rax, r13
    jae .n1
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
    mov byte [rdi+3], LINNEA_H2_FT_DATA
    mov rax, rbx
    add rax, r13
    cmp rax, r15
    jne .notlast
    mov byte [rdi+4], LINNEA_H2_FL_END_STREAM
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
    mov qword [h2c_hdr_es], 0
    xor ebx, ebx                   ; headers-decoded flag
.loop:
    call h2c_next_frame
    test rax, rax
    js .err
    cmp eax, LINNEA_H2_FT_SETTINGS
    je .settings
    cmp eax, LINNEA_H2_FT_WINDOW
    je .loop
    cmp eax, LINNEA_H2_FT_PING
    je .ping
    cmp eax, LINNEA_H2_FT_HEADERS
    je .headers
    cmp eax, LINNEA_H2_FT_CONT
    je .cont
    cmp eax, LINNEA_H2_FT_DATA
    je .data
    cmp eax, LINNEA_H2_FT_RST
    je .rst
    cmp eax, LINNEA_H2_FT_GOAWAY
    je .goaway
    jmp .loop
.settings:
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2_FL_ACK
    jnz .loop
    call h2c_apply_settings
    call h2c_send_settings_ack
    jmp .loop
.ping:
    call h2c_send_ping_ack
    jmp .loop
.headers:
    cmp qword [h2c_fr_sid], 1
    jne .loop
    mov rax, [h2c_fr_flags]
    and rax, LINNEA_H2_FL_END_STREAM
    mov [h2c_hdr_es], rax
    lea rsi, [h2c_frame_buf+9]
    mov rdx, [h2c_fr_len]
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2_FL_PADDED
    jz .h_np
    movzx ecx, byte [rsi]
    inc rsi
    dec rdx
    sub rdx, rcx
.h_np:
    test rax, LINNEA_H2_FL_PRIORITY
    jz .h_npr
    add rsi, 5
    sub rdx, 5
.h_npr:
    call h2c_hdrblk_append
    test rax, rax
    js .err
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2_FL_END_HEADERS
    jz .loop
    call h2c_do_decode
    test rax, rax
    js .err
    mov ebx, 1
    cmp qword [h2c_hdr_es], 0
    jne .done
    jmp .loop
.cont:
    cmp qword [h2c_fr_sid], 1
    jne .loop
    lea rsi, [h2c_frame_buf+9]
    mov rdx, [h2c_fr_len]
    call h2c_hdrblk_append
    test rax, rax
    js .err
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2_FL_END_HEADERS
    jz .loop
    call h2c_do_decode
    test rax, rax
    js .err
    mov ebx, 1
    cmp qword [h2c_hdr_es], 0
    jne .done
    jmp .loop
.data:
    cmp qword [h2c_fr_sid], 1
    jne .loop
    lea rsi, [h2c_frame_buf+9]
    mov rdx, [h2c_fr_len]
    mov rax, [h2c_fr_flags]
    test rax, LINNEA_H2_FL_PADDED
    jz .d_np
    movzx ecx, byte [rsi]
    inc rsi
    dec rdx
    sub rdx, rcx
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
    test rax, LINNEA_H2_FL_END_STREAM
    jnz .done
    jmp .loop
.rst:
    mov rax, LINNEA_H2C_RST
    jmp .ret
.goaway:
    mov rax, LINNEA_H2C_GOAWAY
    jmp .ret
.done:
    test ebx, ebx
    jz .err
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
    call h2c_ci_eq
    test rax, rax
    jnz .status
    test r13, r13
    jz .ok
    cmp byte [r12], ':'
    je .ok                         ; unknown pseudo-header: ignore
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
.status:
    xor eax, eax
    xor ecx, ecx
.psl:
    cmp rcx, r15
    jae .psd
    cmp rcx, 3
    jae .psd
    mov dl, [r14 + rcx]
    cmp dl, '0'
    jb .psd
    cmp dl, '9'
    ja .psd
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
    mov rax, [h2c_body_len]
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

section .bss
h2c_lit_form: resd 1
