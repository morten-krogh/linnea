; linnea_tls.asm — the TLS 1.3 server handshake (RFC 8446).
;
; A sans-IO state machine: linnea_tls_hs_input consumes whatever plaintext
; bytes have arrived and appends whatever must be sent, so the same code
; drives the blocking test server now and the io_uring loop in M6. The
; profile is fixed — TLS_AES_128_GCM_SHA256, x25519, an ECDSA P-256 leaf
; certificate — so there is exactly one path through the schedule and no
; HelloRetryRequest: a ClientHello without an x25519 share is a fatal
; handshake_failure.
;
; The transcript hash absorbs handshake *messages* (never record
; headers). The server flight (EncryptedExtensions, Certificate,
; CertificateVerify, Finished) is coalesced into one encrypted record.
; The whole key schedule was verified byte-for-byte against the RFC 8448
; trace before this code shipped (test/crypto/gen_vectors.rfc8448).
;
; ABI: System V; callee-saved preserved.

default rel

%include "linnea_syscall.inc"
%include "linnea_tls.inc"

global linnea_tls_hs_init
global linnea_tls_hs_input
global linnea_tls_drain_early
global linnea_tls_ticket_setup

extern linnea_sha256
extern linnea_sha256_init
extern linnea_sha256_update
extern linnea_sha256_final
extern linnea_hmac_sha256
extern linnea_hkdf_extract
extern linnea_x25519
extern linnea_p256_ecdsa_sign
extern linnea_tls_derive_secret
extern linnea_tls_hkdf_expand_label
extern linnea_tls_keys_init
extern linnea_tls_seal
extern linnea_tls_open
extern linnea_aesgcm_init
extern linnea_aesgcm_seal
extern linnea_aesgcm_open

section .rodata

align 16
x25519_base:  db 9
              times 31 db 0
empty_hash:   db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14
              db 0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
              db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
              db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
zeros32:      times 32 db 0

lbl_derived:  db "derived"
lbl_c_hs:     db "c hs traffic"
lbl_s_hs:     db "s hs traffic"
lbl_c_ap:     db "c ap traffic"
lbl_s_ap:     db "s ap traffic"
lbl_finished: db "finished"
lbl_res_binder: db "res binder"
lbl_res_master: db "res master"
lbl_resumption: db "resumption"
ticket_nonce: db 0, 0          ; one ticket per handshake: a fixed nonce
; ALPN protocol names, length-prefixed (byte length then the bytes), the
; form build_ee copies. http/1.1 is the only one selected until the h2
; connection path exists; h2 is here for the M15+ milestones.
alpn_http11:  db 8, "http/1.1"
alpn_http11_name equ alpn_http11 + 1
alpn_h2:      db 2, "h2"

; the signed content for CertificateVerify (RFC 8446 4.4.3): 64 spaces,
; the context string, a separator, then the transcript hash appended
; at run time.
cv_prefix:    times 64 db 0x20
              db "TLS 1.3, server CertificateVerify"
              db 0x00
cv_prefix_len equ $ - cv_prefix

ccs_record:   db 0x14, 0x03, 0x03, 0x00, 0x01, 0x01

section .bss

alignb 8
cv_msg:       resb cv_prefix_len + 32    ; CertificateVerify signed content
cv_digest:    resb 32                    ; ...and its SHA-256: ECDSA signs a
                                         ; digest, not the content
ticket_key:   resb 16                    ; per-run stateless-ticket key
ticket_ctx:   resb linnea_aesgcm_ctx_size
nst_pt:       resb 48                    ; ticket plaintext: psk|issued|sni
nst_msg:      resb 128                   ; the NewSessionTicket message

section .text

; ---- linnea_tls_ticket_setup() — generate the per-run ticket key and
; build its AES schedule. The server calls this once in the master,
; before the workers fork, so every worker seals and opens the same
; tickets and any worker can resume any worker's session. A process
; that never calls it has an uninitialized (zero) schedule and would
; neither issue nor accept real tickets — the test harnesses call it.
linnea_tls_ticket_setup:
.again:
    lea rdi, [ticket_key]
    mov esi, 16
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    cmp rax, 16
    jne .again
    lea rdi, [ticket_ctx]
    lea rsi, [ticket_key]
    jmp linnea_aesgcm_init

; ===================================================================
; helpers
; ===================================================================

; tls_absorb(rdi=hs, rsi=data, rdx=len) — feed a handshake message to the
; transcript hash. Tail-calls sha256_update.
tls_absorb:
    lea rdi, [rdi + linnea_tls_hs.transcript]
    jmp linnea_sha256_update

; tls_th(rdi=hs, rsi=out32) — snapshot the transcript hash without
; disturbing the running context (final is destructive, so clone first).
tls_th:
    push rbx
    sub rsp, linnea_sha256_ctx_size + 8
    mov rbx, rsi
    lea rsi, [rdi + linnea_tls_hs.transcript]
    mov rdi, rsp
    mov rcx, linnea_sha256_ctx_size
    rep movsb
    mov rdi, rsp
    mov rsi, rbx
    call linnea_sha256_final
    add rsp, linnea_sha256_ctx_size + 8
    pop rbx
    ret

; ct_eq32(rdi=a, rsi=b) -> eax = 1 if the 32 bytes are equal, in constant
; time (accumulate the OR of xored bytes).
ct_eq32:
    xor eax, eax
    xor ecx, ecx
.loop:
    mov dl, [rdi + rcx]
    xor dl, [rsi + rcx]
    or al, dl
    inc ecx
    cmp ecx, 32
    jb .loop
    sub al, 1                  ; al=0 -> CF set; al!=0 -> CF clear
    sbb eax, eax
    and eax, 1
    ret

; ===================================================================
; linnea_tls_hs_init(rdi=hs, rsi=cert_list, rdx=cert_list_len,
;                    rcx=key_priv, r8d=flags)
; ===================================================================
linnea_tls_hs_init:
    mov dword [rdi + linnea_tls_hs.state], LINNEA_TLS_WAIT_CH
    mov [rdi + linnea_tls_hs.flags], r8d
    mov [rdi + linnea_tls_hs.cert_list], rsi
    mov [rdi + linnea_tls_hs.cert_list_len], rdx
    mov [rdi + linnea_tls_hs.key_priv], rcx
    mov qword [rdi + linnea_tls_hs.out_len], 0
    mov qword [rdi + linnea_tls_hs.consumed], 0
    mov dword [rdi + linnea_tls_hs.msg_len], 0
    mov qword [rdi + linnea_tls_hs.select_cb], 0
    mov qword [rdi + linnea_tls_hs.select_ctx], 0
    mov dword [rdi + linnea_tls_hs.sni_len], 0
    mov dword [rdi + linnea_tls_hs.psk_flags], 0
    mov dword [rdi + linnea_tls_hs.resumed], 0
    mov qword [rdi + linnea_tls_hs.alpn_name], 0
    mov dword [rdi + linnea_tls_hs.alpn_is_h2], 0
    mov dword [rdi + linnea_tls_hs.alpn_h2_ok], 0   ; accept path may raise it
    lea rdi, [rdi + linnea_tls_hs.transcript]
    jmp linnea_sha256_init

; ===================================================================
; linnea_tls_hs_input(rdi=hs, rsi=inbuf, rdx=inlen, rcx=outbuf,
;                     r8=outcap) -> rax = state
; hs.consumed and hs.out_len report how much was eaten / produced.
; ===================================================================
%define IN_HS    0
%define IN_BUF   8
%define IN_LEN   16
%define IN_OUT   24
%define IN_OCAP  32
; 56 (not 48) so that after the six pushes rsp is 16-aligned at every
; internal call site — build_flight's callees (AES-GCM seal) use movdqa.
%define IN_FRAME 56

linnea_tls_hs_input:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, IN_FRAME
    mov [rsp + IN_HS], rdi
    mov [rsp + IN_BUF], rsi
    mov [rsp + IN_LEN], rdx
    mov [rsp + IN_OUT], rcx
    mov [rsp + IN_OCAP], r8
    mov rbp, rdi
    mov qword [rbp + linnea_tls_hs.consumed], 0
    mov qword [rbp + linnea_tls_hs.out_len], 0

    mov eax, [rbp + linnea_tls_hs.state]
    cmp eax, LINNEA_TLS_WAIT_CH
    je .do_ch
    cmp eax, LINNEA_TLS_WAIT_FIN
    je .do_fin
    jmp .ret                    ; DONE / FAILED: nothing to do

; ---- WAIT_CH: expect one handshake record carrying a ClientHello -----
.do_ch:
    mov rbx, [rsp + IN_BUF]
    mov r12, [rsp + IN_LEN]
    cmp r12, 5
    jb .ret                     ; need the record header
    movzx eax, byte [rbx]
    cmp al, LINNEA_TLS_CT_HANDSHAKE
    jne .ch_not_tls             ; plain HTTP or noise on the TLS port
    movzx r13d, byte [rbx + 3]  ; record length, big-endian
    shl r13d, 8
    mov al, [rbx + 4]
    mov r13b, al
    cmp r13d, 16640             ; 2^14 + 256, the record-overflow bound
    ja .ch_overflow
    lea rax, [r13 + 5]
    cmp rax, r12
    ja .ret                     ; wait for the rest of the record

    lea rsi, [rbx + 5]          ; handshake message (== the fragment)
    mov rdx, r13
    ; absorb the ClientHello into the transcript before responding
    mov rdi, rbp
    push rsi
    push rdx
    call tls_absorb
    pop rdx
    pop rsi
    mov rdi, rbp
    call parse_ch               ; rax = -1 ok, else alert descriptor
    cmp rax, -1
    jne .ch_alert

    ; SNI vhost selection: if the embedder installed a hook, let it swap
    ; the certificate for the requested name before the flight is built.
    ; rax = 0 keeps the hs_init default (the listener owner's cert), the
    ; RFC 6066 fallback for an absent or unrecognized server_name.
    mov rax, [rbp + linnea_tls_hs.select_cb]
    test rax, rax
    jz .no_select
    mov rdi, [rbp + linnea_tls_hs.select_ctx]
    lea rsi, [rbp + linnea_tls_hs.sni]
    mov edx, [rbp + linnea_tls_hs.sni_len]
    call rax
    test rax, rax
    jz .no_select
    mov [rbp + linnea_tls_hs.cert_list], rax
    mov [rbp + linnea_tls_hs.cert_list_len], rdx
    mov [rbp + linnea_tls_hs.key_priv], rcx
.no_select:

    ; resumption: if the ClientHello carried an acceptable PSK offer,
    ; try_resume sets hs.resumed and the flight skips the certificate
    mov rdi, rbp
    call try_resume

    ; consume the whole record regardless of what follows it
    lea rax, [r13 + 5]
    mov [rbp + linnea_tls_hs.consumed], rax

    mov rdi, rbp                ; SH + CCS + encrypted flight into outbuf
    mov rsi, [rsp + IN_OUT]
    mov rdx, [rsp + IN_OCAP]
    call build_flight
    mov dword [rbp + linnea_tls_hs.state], LINNEA_TLS_WAIT_FIN
    jmp .ret

.ch_not_tls:
    mov edi, LINNEA_TLS_A_DECODE_ERROR
    jmp .plain_alert
.ch_overflow:
    mov edi, LINNEA_TLS_A_RECORD_OVERFLOW
    jmp .plain_alert
.ch_alert:
    mov edi, eax                ; the descriptor parse_ch returned
.plain_alert:
    mov [rbp + linnea_tls_hs.alert], edi
    mov rcx, [rsp + IN_OUT]
    mov byte [rcx], LINNEA_TLS_CT_ALERT
    mov word [rcx + 1], 0x0303
    mov word [rcx + 3], 0x0200  ; length 2 (big-endian)
    mov byte [rcx + 5], 2       ; fatal
    mov [rcx + 6], dil
    mov qword [rbp + linnea_tls_hs.out_len], 7
    mov dword [rbp + linnea_tls_hs.state], LINNEA_TLS_FAILED
    jmp .ret

; ---- WAIT_FIN: skip a client CCS, then verify the client Finished ----
.do_fin:
    mov rbx, [rsp + IN_BUF]
    mov r12, [rsp + IN_LEN]
.fin_rec:
    cmp r12, 5
    jb .ret
    movzx eax, byte [rbx]
    movzx r13d, byte [rbx + 3]
    shl r13d, 8
    mov r13b, [rbx + 4]
    ; Refuse an over-long fragment on sight, before waiting for the rest of
    ; it: the plaintext has to fit msg_buf (linnea_tls_open writes it before
    ; authenticating it, so this must hold for any peer, not just one that
    ; knows the keys), and a record longer than in_buf could never finish
    ; arriving anyway. A real Finished record is 58 bytes.
    cmp r13, LINNEA_TLS_MAX_FRAGMENT
    ja .fin_overflow
    lea rcx, [r13 + 5]
    cmp rcx, r12
    ja .ret                     ; wait for the full record
    cmp al, LINNEA_TLS_CT_CCS
    jne .fin_data
    ; a bare ChangeCipherSpec: swallow it and look at the next record
    add rbx, rcx
    sub r12, rcx
    add [rbp + linnea_tls_hs.consumed], rcx
    jmp .fin_rec
.fin_data:
    cmp al, LINNEA_TLS_CT_APPDATA
    jne .fin_bad                ; anything else here is illegal
    ; decrypt with the client handshake keys into msg_buf
    lea rdi, [rbp + linnea_tls_hs.rkeys]
    mov rsi, rbx
    lea rdx, [r13 + 5]
    lea rcx, [rbp + linnea_tls_hs.msg_buf]
    call linnea_tls_open        ; rax = content len, rdx = inner type
    cmp rax, -1
    je .fin_badmac
    cmp rdx, LINNEA_TLS_CT_HANDSHAKE
    jne .fin_bad
    ; the message must be exactly Finished: 14 00 00 20 || 32 bytes
    cmp rax, 36
    jne .fin_bad
    lea rsi, [rbp + linnea_tls_hs.msg_buf]
    cmp dword [rsi], 0x20000014 ; 14 00 00 20 (type, length 32) little-endian
    jne .fin_bad

    lea rcx, [r13 + 5]          ; this record's length (open clobbered rcx)
    add rbx, rcx
    add [rbp + linnea_tls_hs.consumed], rcx

    ; expected verify_data = HMAC(client finished key, H(CH..server Fin)).
    ; The transcript still stands at server Finished, so snapshot it now.
    ; frame: [rsp..31] finished key, [rsp+32..63] computed verify_data,
    ;        [rsp+64..95] transcript hash.
    sub rsp, 128
    mov rdi, rbp
    lea rsi, [rsp + 64]
    call tls_th
    lea rdi, [rbp + linnea_tls_hs.c_hs]  ; finished key = Expand-Label(c_hs)
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [rsp]              ; HMAC(finished_key, transcript_hash)
    mov esi, 32
    lea rdx, [rsp + 64]
    mov ecx, 32
    lea r8, [rsp + 32]
    call linnea_hmac_sha256
    lea rdi, [rsp + 32]
    lea rsi, [rbp + linnea_tls_hs.msg_buf + 4]
    call ct_eq32
    add rsp, 128
    test eax, eax
    jz .fin_badmac

    ; success: absorb the client Finished, switch to application keys
    lea rsi, [rbp + linnea_tls_hs.msg_buf]
    mov edx, 36
    mov rdi, rbp
    call tls_absorb
    lea rdi, [rbp + linnea_tls_hs.wkeys]
    lea rsi, [rbp + linnea_tls_hs.s_ap]
    call linnea_tls_keys_init
    lea rdi, [rbp + linnea_tls_hs.rkeys]
    lea rsi, [rbp + linnea_tls_hs.c_ap]
    call linnea_tls_keys_init
    mov dword [rbp + linnea_tls_hs.state], LINNEA_TLS_DONE
    ; issue one NewSessionTicket if the client offered resumption. It is
    ; sealed under the just-installed server app key at seq 0, so the
    ; kernel takes over at seq 1 (see the handoff in linnea_uring).
    test dword [rbp + linnea_tls_hs.psk_flags], 2
    jz .ret
    mov rdi, rbp
    mov rsi, [rsp + IN_OUT]
    call build_nst
    jmp .ret

.fin_bad:
    mov edi, LINNEA_TLS_A_UNEXPECTED_MESSAGE
    jmp .enc_alert
.fin_overflow:
    mov edi, LINNEA_TLS_A_RECORD_OVERFLOW
    jmp .enc_alert
.fin_badmac:
    mov edi, LINNEA_TLS_A_DECRYPT_ERROR
.enc_alert:
    ; seal a fatal alert under the server handshake keys
    mov [rbp + linnea_tls_hs.alert], edi
    sub rsp, 16
    mov byte [rsp], 2           ; level fatal
    mov [rsp + 1], dil          ; description
    lea rdi, [rbp + linnea_tls_hs.wkeys]
    mov esi, LINNEA_TLS_CT_ALERT
    mov rdx, rsp
    mov ecx, 2
    mov r8, [rsp + IN_OUT + 16] ; outbuf (frame shifted by 16)
    call linnea_tls_seal
    mov [rbp + linnea_tls_hs.out_len], rax
    add rsp, 16
    mov dword [rbp + linnea_tls_hs.state], LINNEA_TLS_FAILED
    jmp .ret

.ret:
    mov eax, [rbp + linnea_tls_hs.state]
    add rsp, IN_FRAME
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ===================================================================
; parse_ch(rdi=hs, rsi=frag, rdx=fraglen) -> rax = -1 ok, else the fatal
; alert descriptor to send. Fills hs.client_pub / hs.sid / hs.sid_len.
; ===================================================================
; register use: rbp=hs, rbx=cursor, r13=end, r14/r15 scratch flags.
parse_ch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rdi
    mov rbx, rsi
    mov [rbp + linnea_tls_hs.ch_base], rsi   ; raw CH, for the binder hash
    lea r13, [rsi + rdx]
    xor r14d, r14d              ; bit0 x25519 seen, bit1 sv 1.3, bit2 sigalg
    ; also reuse r14 bits 8..10 for duplicate detection of the three
    ; extensions we parse

    ; handshake header: type(1)=client_hello, length(3) == fraglen-4
    lea rax, [rbx + 4]
    cmp rax, r13
    ja .decode
    cmp byte [rbx], 0x01
    jne .unexpected
    movzx eax, byte [rbx + 1]
    shl eax, 8
    mov al, [rbx + 2]
    shl eax, 8
    mov al, [rbx + 3]
    lea rcx, [rbx + 4]
    add rcx, rax
    cmp rcx, r13
    jne .decode                 ; body length must match the fragment
    add rbx, 4

    add rbx, 2                  ; legacy_version, ignored
    cmp rbx, r13
    ja .decode
    add rbx, 32                 ; random, ignored
    cmp rbx, r13
    ja .decode

    ; legacy_session_id <0..32>
    cmp rbx, r13
    jae .decode
    movzx eax, byte [rbx]
    inc rbx
    cmp eax, 32
    ja .illegal
    mov [rbp + linnea_tls_hs.sid_len], eax
    lea rcx, [rbx + rax]
    cmp rcx, r13
    ja .decode
    ; copy the session id out to echo later
    lea rdi, [rbp + linnea_tls_hs.sid]
    mov rsi, rbx
    mov rcx, rax
    rep movsb
    add rbx, rax

    ; cipher_suites <2..2^16-2>: must offer TLS_AES_128_GCM_SHA256
    lea rax, [rbx + 2]
    cmp rax, r13
    ja .decode
    movzx ecx, byte [rbx]
    shl ecx, 8
    mov cl, [rbx + 1]
    add rbx, 2
    test ecx, 1
    jnz .decode                 ; suite list is 2-byte units
    lea rax, [rbx + rcx]
    cmp rax, r13
    ja .decode
    xor r15d, r15d              ; suite-found flag
.suite_loop:
    test rcx, rcx
    jz .suite_done
    cmp word [rbx], 0x0113      ; 0x1301 big-endian in memory
    jne .suite_next
    mov r15d, 1
.suite_next:
    add rbx, 2
    sub rcx, 2
    jmp .suite_loop
.suite_done:
    test r15d, r15d
    jz .handshake_fail

    ; legacy_compression_methods <1..2^8-1>: must be exactly { null }
    lea rax, [rbx + 2]
    cmp rax, r13
    ja .decode
    movzx eax, byte [rbx]
    cmp eax, 1
    jne .illegal
    cmp byte [rbx + 1], 0
    jne .illegal
    add rbx, 2

    ; extensions <8..2^16-1>
    lea rax, [rbx + 2]
    cmp rax, r13
    ja .decode
    movzx eax, byte [rbx]
    shl eax, 8
    mov al, [rbx + 1]
    add rbx, 2
    lea rcx, [rbx + rax]
    cmp rcx, r13
    jne .decode                 ; extensions must fill the rest exactly
.ext_loop:
    cmp rbx, r13
    je .ext_done
    lea rax, [rbx + 4]
    cmp rax, r13
    ja .decode
    movzx r12d, byte [rbx]      ; ext type
    shl r12d, 8
    mov r12b, [rbx + 1]
    movzx eax, byte [rbx + 2]   ; ext length
    shl eax, 8
    mov al, [rbx + 3]
    add rbx, 4
    lea rcx, [rbx + rax]        ; ext body end
    cmp rcx, r13
    ja .decode
    push rcx                    ; body end for after the handler
    ; dispatch the three extensions we require, plus server_name
    cmp r12d, 0x2b              ; supported_versions
    je .ext_sv
    cmp r12d, 0x33              ; key_share
    je .ext_ks
    cmp r12d, 0x0d              ; signature_algorithms
    je .ext_sa
    cmp r12d, 0x29             ; pre_shared_key (must be the last extension)
    je .ext_psk
    cmp r12d, 0x2d             ; psk_key_exchange_modes
    je .ext_pskmodes
    cmp r12d, 0x10             ; application_layer_protocol_negotiation
    je .ext_alpn
    test r12d, r12d             ; server_name
    jz .ext_sni
    jmp .ext_skip
.ext_sv:
    test r14d, 0x200
    jnz .ext_dup
    or r14d, 0x200
    movzx eax, byte [rbx]       ; list length (1 byte)
    lea rcx, [rbx + 1 + rax]
    cmp rcx, [rsp]
    jne .pop_decode
    test eax, 1
    jnz .pop_decode
    lea rsi, [rbx + 1]
    lea rdi, [rbx + 1 + rax]
.sv_loop:
    cmp rsi, rdi
    jae .ext_skip
    cmp word [rsi], 0x0403      ; 0x0304 big-endian
    jne .sv_next
    or r14d, 2
.sv_next:
    add rsi, 2
    jmp .sv_loop
.ext_ks:
    test r14d, 0x100
    jnz .ext_dup
    or r14d, 0x100
    lea rax, [rbx + 2]
    cmp rax, [rsp]
    ja .pop_decode
    movzx eax, byte [rbx]       ; client_shares length
    shl eax, 8
    mov al, [rbx + 1]
    lea rcx, [rbx + 2 + rax]
    cmp rcx, [rsp]
    jne .pop_decode
    lea rsi, [rbx + 2]          ; cursor over KeyShareEntry list
    mov r10, rcx                ; list end
.ks_loop:
    cmp rsi, r10
    jae .ext_skip
    lea rax, [rsi + 4]
    cmp rax, r10
    ja .pop_decode
    movzx eax, byte [rsi + 2]   ; key_exchange length
    shl eax, 8
    mov al, [rsi + 3]
    lea rcx, [rsi + 4 + rax]    ; next entry
    cmp rcx, r10
    ja .pop_decode
    cmp word [rsi], 0x1d00      ; group 0x001d (x25519), big-endian
    jne .ks_next
    cmp eax, 32
    jne .ks_next
    test r14d, 1
    jnz .ks_next               ; already captured one x25519 share
    or r14d, 1
    push rsi
    push rcx
    push r10
    lea rdi, [rbp + linnea_tls_hs.client_pub]
    lea rsi, [rsi + 4]
    mov rcx, 32
    rep movsb
    pop r10
    pop rcx
    pop rsi
.ks_next:
    mov rsi, rcx
    jmp .ks_loop
.ext_sa:
    test r14d, 0x400
    jnz .ext_dup
    or r14d, 0x400
    lea rax, [rbx + 2]
    cmp rax, [rsp]
    ja .pop_decode
    movzx eax, byte [rbx]
    shl eax, 8
    mov al, [rbx + 1]
    lea rcx, [rbx + 2 + rax]
    cmp rcx, [rsp]
    jne .pop_decode
    lea rsi, [rbx + 2]
    lea rdi, [rbx + 2 + rax]
.sa_loop:
    cmp rsi, rdi
    jae .ext_skip
    cmp word [rsi], 0x0304      ; ecdsa_secp256r1_sha256 = 0x0403 big-endian
    jne .sa_next
    or r14d, 4
.sa_next:
    add rsi, 2
    jmp .sa_loop
.ext_sni:
    test r14d, 0x800
    jnz .ext_dup
    or r14d, 0x800
    lea rax, [rbx + 2]
    cmp rax, [rsp]
    ja .pop_decode
    movzx eax, byte [rbx]       ; server_name_list length
    shl eax, 8
    mov al, [rbx + 1]
    lea rcx, [rbx + 2 + rax]
    cmp rcx, [rsp]
    jne .pop_decode
    lea rsi, [rbx + 2]          ; cursor over ServerName entries
    mov r10, rcx                ; list end
.sni_loop:
    cmp rsi, r10
    jae .ext_skip
    lea rax, [rsi + 3]
    cmp rax, r10
    ja .pop_decode
    movzx eax, byte [rsi + 1]   ; name length
    shl eax, 8
    mov al, [rsi + 2]
    lea rcx, [rsi + 3 + rax]    ; next entry
    cmp rcx, r10
    ja .pop_decode
    cmp byte [rsi], 0           ; name_type host_name
    jne .sni_next
    test eax, eax
    jz .sni_next                ; empty name: nothing to match
    cmp eax, LINNEA_TLS_MAX_SNI
    ja .sni_next                ; longer than any DNS name: unmatchable
    cmp dword [rbp + linnea_tls_hs.sni_len], 0
    jne .sni_next               ; keep the first host_name
    mov [rbp + linnea_tls_hs.sni_len], eax
    push rcx
    push r10
    lea rdi, [rbp + linnea_tls_hs.sni]
    lea rsi, [rsi + 3]
    mov ecx, eax
    rep movsb
    pop r10
    pop rcx
.sni_next:
    mov rsi, rcx
    jmp .sni_loop
; psk_key_exchange_modes: we only do psk_dhe_ke (mode 1). Record whether
; the client offered it; without it a pre_shared_key offer is ignored.
.ext_pskmodes:
    test r14d, 0x2000
    jnz .ext_dup
    or r14d, 0x2000
    movzx eax, byte [rbx]        ; ke_modes length (1 byte)
    lea rcx, [rbx + 1 + rax]
    cmp rcx, [rsp]
    jne .pop_decode
    lea rsi, [rbx + 1]
    lea rdi, [rbx + 1 + rax]
.pskmodes_loop:
    cmp rsi, rdi
    jae .ext_skip
    cmp byte [rsi], 1           ; psk_dhe_ke
    jne .pskmodes_next
    or dword [rbp + linnea_tls_hs.psk_flags], 2
.pskmodes_next:
    inc rsi
    jmp .pskmodes_loop

; pre_shared_key (RFC 8446 4.2.11), which MUST be the ClientHello's last
; extension. Record the first identity's ticket and binder, and the
; offset of the binders list (the truncated-CH length the binder is
; computed over). Selection happens later, in hs_input.
.ext_psk:
    test r14d, 0x1000
    jnz .ext_dup
    or r14d, 0x1000
    cmp qword [rsp], r13         ; its body must end the ClientHello
    jne .pop_illegal
    lea rax, [rbx + 2]
    cmp rax, [rsp]
    ja .pop_decode
    movzx eax, byte [rbx]        ; identities list length
    shl eax, 8
    mov al, [rbx + 1]
    lea r10, [rbx + 2 + rax]     ; end of identities == binders length field
    cmp r10, [rsp]
    jae .pop_decode
    ; first PskIdentity: opaque identity<1..2^16-1> + uint32 age
    lea rax, [rbx + 4]
    cmp rax, r10
    ja .pop_decode
    movzx ecx, byte [rbx + 2]    ; identity length
    shl ecx, 8
    mov cl, [rbx + 3]
    lea rax, [rbx + 4 + rcx]     ; end of the identity bytes
    lea rdx, [rax + 4]           ; ...plus the 4-byte obfuscated age
    cmp rdx, r10
    ja .pop_decode
    cmp ecx, LINNEA_TLS_TICKET_LEN
    jne .ext_skip                ; not our ticket shape: ignore the offer
    push rsi
    push rdi
    lea rsi, [rbx + 4]           ; copy the ticket out
    lea rdi, [rbp + linnea_tls_hs.ticket]
    mov ecx, LINNEA_TLS_TICKET_LEN
    rep movsb
    pop rdi
    pop rsi
    ; binders_off = distance from the CH start to the binders length field
    mov rax, r10
    sub rax, [rbp + linnea_tls_hs.ch_base]
    mov [rbp + linnea_tls_hs.binders_off], rax
    ; first binder: 1-byte length (must be 32) then the 32 bytes
    lea rax, [r10 + 3]
    cmp rax, [rsp]
    ja .pop_decode
    cmp byte [r10 + 2], 32
    jne .pop_illegal
    push rsi
    push rdi
    lea rsi, [r10 + 3]
    lea rdi, [rbp + linnea_tls_hs.binder]
    mov ecx, 32
    rep movsb
    pop rdi
    pop rsi
    or dword [rbp + linnea_tls_hs.psk_flags], 1   ; offer recorded
    jmp .ext_skip

; ALPN: record which of the protocols we understand the client offered
; (r14 bit 0x8000 = h2, 0x10000 = http/1.1). The choice is made at
; .ext_done, where h2 wins if this server offers it (config.http2).
.ext_alpn:
    test r14d, 0x4000
    jnz .ext_dup
    or r14d, 0x4000
    lea rax, [rbx + 2]
    cmp rax, [rsp]
    ja .pop_decode
    movzx eax, byte [rbx]       ; ProtocolNameList length
    shl eax, 8
    mov al, [rbx + 1]
    lea rcx, [rbx + 2 + rax]
    cmp rcx, [rsp]
    jne .pop_decode
    lea rsi, [rbx + 2]          ; cursor over the name list
    mov r10, rcx                ; list end
.alpn_loop:
    cmp rsi, r10
    jae .ext_skip
    movzx eax, byte [rsi]       ; protocol name length
    lea rcx, [rsi + 1 + rax]
    cmp rcx, r10
    ja .pop_decode
    cmp eax, 2                  ; "h2"
    jne .alpn_not_h2
    cmp word [rsi + 1], 0x3268  ; 'h','2' little-endian
    jne .alpn_next
    or r14d, 0x8000
    jmp .alpn_next
.alpn_not_h2:
    cmp eax, 8                  ; "http/1.1"
    jne .alpn_next
    mov r8, [rsi + 1]
    cmp r8, [alpn_http11_name]
    jne .alpn_next
    or r14d, 0x10000
.alpn_next:
    mov rsi, rcx
    jmp .alpn_loop
.ext_skip:
    pop rbx                     ; body end -> continue after this ext
    jmp .ext_loop
.ext_dup:
    pop rcx
    jmp .illegal
.pop_illegal:
    pop rcx
    jmp .illegal
.pop_decode:
    pop rcx
    jmp .decode

.ext_done:
    test r14d, 2                ; supported_versions offered TLS 1.3?
    jz .protocol_version
    test r14d, 1                ; an x25519 key share present?
    jz .handshake_fail
    ; signature_algorithms must offer ecdsa_secp256r1_sha256, unless this
    ; is the trace (which injects its key and diverges after ServerHello)
    test dword [rbp + linnea_tls_hs.flags], LINNEA_TLS_FLAG_TRACE
    jnz .alpn_select
    test r14d, 4
    jz .handshake_fail
.alpn_select:
    ; choose the ALPN protocol: h2 when the client offered it and this
    ; server enables it, else http/1.1 if offered, else none
    test r14d, 0x8000          ; h2 offered?
    jz .alpn_try_h11
    cmp dword [rbp + linnea_tls_hs.alpn_h2_ok], 0
    je .alpn_try_h11
    lea rax, [alpn_h2]
    mov [rbp + linnea_tls_hs.alpn_name], rax
    mov dword [rbp + linnea_tls_hs.alpn_is_h2], 1
    jmp .ok
.alpn_try_h11:
    test r14d, 0x10000         ; http/1.1 offered?
    jz .ok
    lea rax, [alpn_http11]
    mov [rbp + linnea_tls_hs.alpn_name], rax
.ok:
    mov rax, -1
    jmp .pret
.unexpected:
    mov eax, LINNEA_TLS_A_UNEXPECTED_MESSAGE
    jmp .pret
.decode:
    mov eax, LINNEA_TLS_A_DECODE_ERROR
    jmp .pret
.illegal:
    mov eax, LINNEA_TLS_A_ILLEGAL_PARAMETER
    jmp .pret
.protocol_version:
    mov eax, LINNEA_TLS_A_PROTOCOL_VERSION
    jmp .pret
.handshake_fail:
    mov eax, LINNEA_TLS_A_HANDSHAKE_FAILURE
.pret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ===================================================================
; try_resume(rdi=hs) — decide whether the ClientHello's PSK offer can be
; accepted, and set hs.resumed + hs.psk if so. Silent no-op otherwise:
; an unacceptable offer just yields a full handshake, per RFC 8446.
;
; Accept requires: psk_dhe_ke offered, the ticket opens under the per-run
; key, its server_name binding matches the current SNI, and the binder
; verifies over the truncated ClientHello. Stack: 48-byte ticket
; plaintext, 32-byte early secret, 32-byte binder-key/scratch, 32-byte
; truncated-CH hash, 8-byte sni hash.
; ===================================================================
%define TR_PT     0            ; psk(32) issued(8) sni_hash(8)
%define TR_EARLY  48
%define TR_BKEY   80
%define TR_FKEY   112
%define TR_TH     144
%define TR_EXP    176          ; recomputed binder
%define TR_SNIH   208          ; hash of the current SNI
%define TR_FRAME  248          ; keeps rsp 16-aligned at the inner calls
try_resume:
    push rbx
    push rbp
    sub rsp, TR_FRAME
    mov rbp, rdi               ; hs
    mov eax, [rbp + linnea_tls_hs.psk_flags]
    and eax, 3                 ; offer recorded AND psk_dhe_ke offered
    cmp eax, 3
    jne .no
    ; open the ticket: nonce = ticket[0..12], ct = ticket[12..76]
    lea rdi, [ticket_ctx]
    lea rsi, [rbp + linnea_tls_hs.ticket]
    xor edx, edx               ; no AAD
    xor ecx, ecx
    lea r8, [rbp + linnea_tls_hs.ticket + 12]
    mov r9d, LINNEA_TLS_TICKET_LEN - 12   ; 64 = 48 ct + 16 tag
    sub rsp, 16
    lea rax, [rsp + 16 + TR_PT]
    mov [rsp], rax
    call linnea_aesgcm_open
    add rsp, 16
    test rax, rax
    js .no                     ; bad tag: forged or wrong-run ticket
    ; the ticket is bound to the server_name it was issued under
    lea rdi, [rbp + linnea_tls_hs.sni]
    mov esi, [rbp + linnea_tls_hs.sni_len]
    lea rdx, [rsp + TR_SNIH]
    call sni_hash8
    lea rdi, [rsp + TR_PT + 40]   ; sni_hash stored in the ticket
    lea rsi, [rsp + TR_SNIH]
    mov ecx, 8
    call bytes_eq8
    test eax, eax
    jz .no
    ; early_secret = HKDF-Extract(0, psk)
    lea rdi, [zeros32]
    xor esi, esi
    lea rdx, [rsp + TR_PT]      ; psk
    mov ecx, 32
    lea r8, [rsp + TR_EARLY]
    call linnea_hkdf_extract
    ; binder_key = Derive-Secret(early, "res binder", H(""))
    lea rdi, [rsp + TR_EARLY]
    lea rsi, [lbl_res_binder]
    mov edx, 10
    lea rcx, [empty_hash]
    lea r8, [rsp + TR_BKEY]
    call linnea_tls_derive_secret
    ; finished_key = Expand-Label(binder_key, "finished", "", 32)
    lea rdi, [rsp + TR_BKEY]
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp + TR_FKEY]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; th = SHA256(truncated ClientHello)
    mov rdi, [rbp + linnea_tls_hs.ch_base]
    mov rsi, [rbp + linnea_tls_hs.binders_off]
    lea rdx, [rsp + TR_TH]
    call linnea_sha256
    ; expected binder = HMAC(finished_key, th)
    lea rdi, [rsp + TR_FKEY]
    mov esi, 32
    lea rdx, [rsp + TR_TH]
    mov ecx, 32
    lea r8, [rsp + TR_EXP]
    call linnea_hmac_sha256
    lea rdi, [rsp + TR_EXP]
    lea rsi, [rbp + linnea_tls_hs.binder]
    call ct_eq32
    test eax, eax
    jz .no
    ; accepted: keep the PSK for the key schedule
    lea rdi, [rbp + linnea_tls_hs.psk]
    lea rsi, [rsp + TR_PT]
    mov ecx, 32
    rep movsb
    mov dword [rbp + linnea_tls_hs.resumed], 1
.no:
    add rsp, TR_FRAME
    pop rbp
    pop rbx
    ret

; sni_hash8(rdi=ptr, esi=len, rdx=out8) — the first 8 bytes of SHA-256
; over the server name, so a ticket binds to the name it was issued
; under. Uses a stack digest; preserves nothing the caller needs.
sni_hash8:
    push rbx
    push r12
    sub rsp, 56                ; 8 mod 16: rsp 16-aligned at the call
    mov rbx, rdx
    movzx esi, si
    lea rdx, [rsp]
    call linnea_sha256
    mov rax, [rsp]
    mov [rbx], rax
    add rsp, 56
    pop r12
    pop rbx
    ret

; bytes_eq8(rdi=a, rsi=b, ecx=8) -> eax=1 if equal (fixed 8, non-secret)
bytes_eq8:
    mov rax, [rdi]
    cmp rax, [rsi]
    sete al
    movzx eax, al
    ret

; ===================================================================
; build_nst(rdi=hs, rsi=outbuf) — derive the resumption PSK, seal it into
; a stateless ticket, wrap it in a NewSessionTicket handshake message,
; and seal that as one application_data record under the server app key
; (hs.wkeys at seq 0). Sets hs.out_len. Call once, after the client
; Finished is verified and wkeys is re-keyed to s_ap.
; Stack: [0]=transcript hash, [32]=res_master, [64]=psk, [96]=timespec.
; ===================================================================
build_nst:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 128
    mov rbx, rdi               ; hs
    mov r14, rsi               ; outbuf
    ; res_master = Derive-Secret(master, "res master", H(CH..client Fin))
    mov rdi, rbx
    lea rsi, [rsp]
    call tls_th
    lea rdi, [rbx + linnea_tls_hs.master]
    lea rsi, [lbl_res_master]
    mov edx, 10
    lea rcx, [rsp]
    lea r8, [rsp + 32]
    call linnea_tls_derive_secret
    ; psk = Expand-Label(res_master, "resumption", ticket_nonce, 32)
    lea rdi, [rsp + 32]
    lea rsi, [lbl_resumption]
    mov edx, 10
    lea rcx, [ticket_nonce]
    mov r8d, 2
    lea r9, [rsp + 64]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; ticket plaintext = psk(32) || issued(8) || sni_hash(8)
    lea rdi, [nst_pt]
    lea rsi, [rsp + 64]
    mov ecx, 32
    rep movsb
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    xor edi, edi               ; CLOCK_REALTIME
    lea rsi, [rsp + 96]
    syscall
    mov rax, [rsp + 96]        ; tv_sec
    mov [nst_pt + 32], rax
    lea rdi, [rbx + linnea_tls_hs.sni]
    mov esi, [rbx + linnea_tls_hs.sni_len]
    lea rdx, [nst_pt + 40]
    call sni_hash8
    ; ticket = nonce(12) || GCM-seal(plaintext) into the NST message body
    lea rdi, [nst_msg + 17]
    mov esi, 12
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    lea rdi, [ticket_ctx]
    lea rsi, [nst_msg + 17]     ; nonce
    xor edx, edx               ; no AAD
    xor ecx, ecx
    lea r8, [nst_pt]
    mov r9d, 48
    sub rsp, 16
    lea rax, [nst_msg + 29]
    mov [rsp], rax
    call linnea_aesgcm_seal
    add rsp, 16
    ; NewSessionTicket message fields
    mov byte [nst_msg], 0x04    ; type new_session_ticket
    mov byte [nst_msg + 1], 0
    mov word [nst_msg + 2], 0x5b00   ; body length 91, big-endian
    mov eax, LINNEA_TLS_TICKET_LIFETIME
    bswap eax
    mov [nst_msg + 4], eax      ; ticket_lifetime, big-endian
    lea rdi, [nst_msg + 8]      ; ticket_age_add: 4 random bytes
    mov esi, 4
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    mov byte [nst_msg + 12], 2  ; ticket_nonce length
    mov word [nst_msg + 13], 0  ; the nonce {0,0}
    mov word [nst_msg + 15], 0x4c00  ; ticket length 76, big-endian
    mov word [nst_msg + 93], 0  ; extensions length 0
    ; seal the 95-byte message as one handshake record under the app key
    lea rdi, [rbx + linnea_tls_hs.wkeys]
    mov esi, LINNEA_TLS_CT_HANDSHAKE
    lea rdx, [nst_msg]
    mov ecx, 95
    mov r8, r14
    call linnea_tls_seal
    mov [rbx + linnea_tls_hs.out_len], rax
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ===================================================================
; build_flight(rdi=hs, rsi=outbuf, rdx=outcap) — run the key schedule,
; assemble the ServerHello, ChangeCipherSpec and the encrypted
; {EE, Certificate, CertificateVerify, Finished} flight, and set
; hs.out_len. rbp = hs stays fixed for the caller.
; ===================================================================
%define BF_SHARED 0
%define BF_ES     32
%define BF_DRV    64
%define BF_HSK    96
%define BF_DRV2   128
%define BF_TH     160
%define BF_SRVPUB 192
%define BF_SHMSG  224      ; ServerHello message (<= 160 bytes)
%define BF_OUT    416      ; saved outbuf
%define BF_FRAME  432

build_flight:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, BF_FRAME
    mov [rsp + BF_OUT], rsi     ; outbuf

    ; 1. ephemeral key + server random, unless the trace injected them
    test dword [rbp + linnea_tls_hs.flags], LINNEA_TLS_FLAG_TRACE
    jnz .have_keys
    lea rdi, [rbp + linnea_tls_hs.priv]
    call getrandom32
    lea rdi, [rbp + linnea_tls_hs.srand]
    call getrandom32
.have_keys:
    ; server_pub = x25519(priv, base)
    lea rdi, [rsp + BF_SRVPUB]
    lea rsi, [rbp + linnea_tls_hs.priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    ; shared = x25519(priv, client_pub)
    lea rdi, [rsp + BF_SHARED]
    lea rsi, [rbp + linnea_tls_hs.priv]
    lea rdx, [rbp + linnea_tls_hs.client_pub]
    call linnea_x25519

    ; 2. schedule up to the handshake secret (no transcript needed yet).
    ; early = HKDF-Extract(0, PSK-or-0): resumption seeds the IKM with the
    ; ticket's PSK, a fresh handshake uses zeros. Everything downstream
    ; (derived, hs_secret from the ECDHE share) is identical either way.
    lea rdx, [zeros32]
    cmp dword [rbp + linnea_tls_hs.resumed], 0
    je .early_ikm
    lea rdx, [rbp + linnea_tls_hs.psk]
.early_ikm:
    lea rdi, [zeros32]
    xor esi, esi
    mov ecx, 32
    lea r8, [rsp + BF_ES]
    call linnea_hkdf_extract
    lea rdi, [rsp + BF_ES]      ; derived = Derive-Secret(early,"derived",H(""))
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [rsp + BF_DRV]
    call linnea_tls_derive_secret
    lea rdi, [rsp + BF_DRV]     ; hs_secret = HKDF-Extract(derived, shared)
    mov esi, 32
    lea rdx, [rsp + BF_SHARED]
    mov ecx, 32
    lea r8, [rsp + BF_HSK]
    call linnea_hkdf_extract

    ; 3. ServerHello, then absorb it and finish the handshake secrets
    lea rdi, [rsp + BF_SHMSG]
    lea rsi, [rsp + BF_SRVPUB]
    call build_sh               ; rax = SH message length
    mov r12, rax                ; SH length
    lea rsi, [rsp + BF_SHMSG]
    mov rdx, r12
    mov rdi, rbp
    call tls_absorb
    mov rdi, rbp                ; th = H(CH || SH)
    lea rsi, [rsp + BF_TH]
    call tls_th
    lea rdi, [rsp + BF_HSK]     ; c_hs
    lea rsi, [lbl_c_hs]
    mov edx, 12
    lea rcx, [rsp + BF_TH]
    lea r8, [rbp + linnea_tls_hs.c_hs]
    call linnea_tls_derive_secret
    lea rdi, [rsp + BF_HSK]     ; s_hs
    lea rsi, [lbl_s_hs]
    mov edx, 12
    lea rcx, [rsp + BF_TH]
    lea r8, [rbp + linnea_tls_hs.s_hs]
    call linnea_tls_derive_secret
    lea rdi, [rsp + BF_HSK]     ; derived2 = Derive-Secret(hs,"derived",H(""))
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [rsp + BF_DRV2]
    call linnea_tls_derive_secret
    lea rdi, [rsp + BF_DRV2]    ; master = HKDF-Extract(derived2, 0)
    mov esi, 32
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [rbp + linnea_tls_hs.master]
    call linnea_hkdf_extract

    ; 4. traffic keys for the handshake flight (write s_hs, read c_hs)
    lea rdi, [rbp + linnea_tls_hs.wkeys]
    lea rsi, [rbp + linnea_tls_hs.s_hs]
    call linnea_tls_keys_init
    lea rdi, [rbp + linnea_tls_hs.rkeys]
    lea rsi, [rbp + linnea_tls_hs.c_hs]
    call linnea_tls_keys_init

    ; 5. assemble EE || Certificate || CertificateVerify || Finished into
    ;    msg_buf, absorbing each message into the transcript
    lea rbx, [rbp + linnea_tls_hs.msg_buf]   ; flight write cursor
    ; -- EncryptedExtensions: empty, or one ALPN extension --
    mov rdi, rbp
    mov rsi, rbx
    call build_ee              ; writes EE at rbx, rax = its length
    mov r13, rax
    lea rsi, [rbx]
    mov rdx, r13
    mov rdi, rbp
    call tls_absorb
    add rbx, r13
    ; A resumed handshake authenticates with the PSK binder, so it sends
    ; neither Certificate nor CertificateVerify: skip straight to Finished
    ; (whose tls_th then covers H(CH..EE) instead of H(CH..CertVerify)).
    cmp dword [rbp + linnea_tls_hs.resumed], 0
    jne .flight_finished
    ; -- Certificate: the pre-framed certificate_list, sent verbatim --
    mov r13, [rbp + linnea_tls_hs.cert_list_len]  ; L
    mov byte [rbx], 0x0b
    lea eax, [r13d + 4]
    mov rdi, rbx
    call store_u24_1            ; length at [rbx+1..3]
    mov byte [rbx + 4], 0x00    ; cert_request_context length
    mov eax, r13d               ; certificate_list length
    lea rdi, [rbx + 4]
    call store_u24_1
    lea rdi, [rbx + 8]          ; the CertificateEntry list itself
    mov rsi, [rbp + linnea_tls_hs.cert_list]
    mov rcx, r13
    rep movsb
    lea r14, [r13 + 8]          ; Certificate message length
    lea rsi, [rbx]
    mov rdx, r14
    mov rdi, rbp
    call tls_absorb
    add rbx, r14
    ; -- CertificateVerify: ECDSA P-256 over the context + H(CH..Cert) --
    ; ECDSA signs the content's SHA-256 digest rather than the content,
    ; and its DER signature has no fixed length -- so both length fields
    ; here are computed rather than written as constants.
    lea rdi, [cv_msg]           ; cv_msg = prefix || transcript hash
    lea rsi, [cv_prefix]
    mov rcx, cv_prefix_len
    rep movsb
    mov rdi, rbp               ; append H(CH..Cert) after the prefix
    lea rsi, [cv_msg + cv_prefix_len]
    call tls_th
    lea rdi, [cv_msg]
    mov esi, cv_prefix_len + 32
    lea rdx, [cv_digest]
    call linnea_sha256
    lea rdi, [rbx + 8]          ; the signature itself
    lea rsi, [cv_digest]
    mov rdx, [rbp + linnea_tls_hs.key_priv]
    call linnea_p256_ecdsa_sign
    mov r15, rax                ; DER signature length, <= MAX_SIG
    mov byte [rbx], 0x0f        ; type CertificateVerify
    lea eax, [r15d + 4]         ; body = scheme(2) + sig length(2) + sig
    mov rdi, rbx
    call store_u24_1
    mov word [rbx + 4], 0x0304  ; scheme ecdsa_secp256r1_sha256 = 04 03
    mov byte [rbx + 6], 0       ; signature length, big-endian; the DER of a
    mov [rbx + 7], r15b         ; P-256 signature never reaches 256 bytes
    lea rdx, [r15 + 8]          ; whole message = header(4) + body
    lea rsi, [rbx]
    mov rdi, rbp
    call tls_absorb
    add rbx, r15
    add rbx, 8
.flight_finished:
    ; -- Finished: HMAC(server finished key, H(CH..CertificateVerify)) --
    lea rdi, [rbp + linnea_tls_hs.s_hs]      ; finished key -> BF_TH
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp + BF_TH]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    mov dword [rbx], 0x20000014 ; 14 00 00 20 (type, length 32) little-endian
    push rbx
    mov rdi, rbp                ; transcript hash H(CH..CV) into cv_msg scratch
    lea rsi, [cv_msg]
    call tls_th
    pop rbx
    lea rdi, [rsp + BF_TH]      ; HMAC(finished_key, hash)
    mov esi, 32
    lea rdx, [cv_msg]
    mov ecx, 32
    lea r8, [rbx + 4]
    call linnea_hmac_sha256
    lea rsi, [rbx]
    mov edx, 36
    mov rdi, rbp
    call tls_absorb
    add rbx, 36

    ; flight length = cursor - msg_buf
    lea rax, [rbp + linnea_tls_hs.msg_buf]
    sub rbx, rax
    mov r14, rbx                ; flight length

    ; 6. application traffic secrets from H(CH..server Finished)
    mov rdi, rbp
    lea rsi, [rsp + BF_TH]
    call tls_th
    lea rdi, [rbp + linnea_tls_hs.master]
    lea rsi, [lbl_c_ap]
    mov edx, 12
    lea rcx, [rsp + BF_TH]
    lea r8, [rbp + linnea_tls_hs.c_ap]
    call linnea_tls_derive_secret
    lea rdi, [rbp + linnea_tls_hs.master]
    lea rsi, [lbl_s_ap]
    mov edx, 12
    lea rcx, [rsp + BF_TH]
    lea r8, [rbp + linnea_tls_hs.s_ap]
    call linnea_tls_derive_secret

    ; 7. emit ServerHello record, ChangeCipherSpec, sealed flight
    mov r15, [rsp + BF_OUT]     ; output cursor
    mov byte [r15], LINNEA_TLS_CT_HANDSHAKE
    mov word [r15 + 1], 0x0303
    mov eax, r12d               ; SH length, big-endian
    xchg al, ah
    mov [r15 + 3], ax
    lea rdi, [r15 + 5]
    lea rsi, [rsp + BF_SHMSG]
    mov rcx, r12
    rep movsb
    lea r15, [r15 + 5 + r12]
    lea rdi, [r15]              ; ChangeCipherSpec (middlebox compatibility)
    lea rsi, [ccs_record]
    mov rcx, 6
    rep movsb
    add r15, 6
    lea rdi, [rbp + linnea_tls_hs.wkeys]   ; sealed handshake flight
    mov esi, LINNEA_TLS_CT_HANDSHAKE
    lea rdx, [rbp + linnea_tls_hs.msg_buf]
    mov rcx, r14
    mov r8, r15
    call linnea_tls_seal        ; rax = record length
    add r15, rax

    mov rax, [rsp + BF_OUT]
    sub r15, rax
    mov [rbp + linnea_tls_hs.out_len], r15

    add rsp, BF_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; build_sh(rdi=dest, rsi=server_pub32) -> rax = ServerHello message
; length. rbp = hs; the server random and echoed session id come from
; the connection state. The extension order (key_share then
; supported_versions) matches the RFC 8448 trace.
build_sh:
    push rbx
    push r12
    push r13
    mov rbx, rdi               ; message base
    mov r12, rsi               ; server pub
    mov byte [rbx], 0x02       ; server_hello; length filled in at the end
    mov word [rbx + 4], 0x0303 ; legacy_version
    lea rdi, [rbx + 6]         ; server random
    lea rsi, [rbp + linnea_tls_hs.srand]
    mov rcx, 32
    rep movsb                  ; rdi -> rbx + 38
    mov eax, [rbp + linnea_tls_hs.sid_len]
    mov [rdi], al
    inc rdi
    lea rsi, [rbp + linnea_tls_hs.sid]   ; echo legacy_session_id
    mov rcx, rax
    rep movsb                  ; rdi -> after the session id
    mov word [rdi], 0x0113     ; cipher_suite 0x1301 (big-endian in memory)
    mov byte [rdi + 2], 0x00   ; legacy_compression_method
    ; extensions length: key_share(40) + supported_versions(6) = 46, plus
    ; pre_shared_key(6) when resuming
    mov word [rdi + 3], 0x2e00 ; = 46
    cmp dword [rbp + linnea_tls_hs.resumed], 0
    je .sh_keyshare
    mov word [rdi + 3], 0x3400 ; = 52
.sh_keyshare:
    mov word [rdi + 5], 0x3300 ; key_share ext type 0x0033
    mov word [rdi + 7], 0x2400 ; ext length 36
    mov word [rdi + 9], 0x1d00 ; group 0x001d (x25519)
    mov word [rdi + 11], 0x2000 ; key_exchange length 32
    lea r13, [rdi + 13]
    push rdi
    mov rdi, r13               ; server public key share
    mov rsi, r12
    mov rcx, 32
    rep movsb
    pop rdi
    mov word [rdi + 45], 0x2b00 ; supported_versions ext type 0x002b
    mov word [rdi + 47], 0x0200 ; ext length 2
    mov word [rdi + 49], 0x0403 ; selected_version 0x0304
    lea rax, [rdi + 51]        ; message end (no PSK)
    cmp dword [rbp + linnea_tls_hs.resumed], 0
    je .sh_len
    mov word [rdi + 51], 0x2900 ; pre_shared_key ext type 0x0029
    mov word [rdi + 53], 0x0200 ; ext length 2
    mov word [rdi + 55], 0x0000 ; selected_identity = 0
    lea rax, [rdi + 57]
.sh_len:
    sub rax, rbx               ; total length
    ; write the 24-bit handshake length = total - 4
    lea rcx, [rax - 4]
    mov byte [rbx + 1], 0
    mov [rbx + 2], ch
    mov [rbx + 3], cl
    pop r13
    pop r12
    pop rbx
    ret

; build_ee(rdi=hs, rsi=dest) -> rax = EncryptedExtensions message length.
; Empty (6 bytes) unless an ALPN protocol was selected, in which case one
; ALPN extension echoes it. All fields are < 256 here (one short protocol
; name), so the 24-bit and 16-bit high bytes are always zero.
build_ee:
    mov byte [rsi], 0x08       ; type EncryptedExtensions
    mov rax, [rdi + linnea_tls_hs.alpn_name]
    test rax, rax
    jz .empty
    movzx ecx, byte [rax]      ; L = protocol name length
    lea r8d, [ecx + 13]        ; total message length
    mov byte [rsi + 1], 0
    mov byte [rsi + 2], 0
    lea edx, [ecx + 9]
    mov [rsi + 3], dl          ; handshake body length = L + 9
    mov byte [rsi + 4], 0
    lea edx, [ecx + 7]
    mov [rsi + 5], dl          ; extensions length = L + 7
    mov byte [rsi + 6], 0x00   ; ext type 0x0010 (ALPN)
    mov byte [rsi + 7], 0x10
    mov byte [rsi + 8], 0
    lea edx, [ecx + 3]
    mov [rsi + 9], dl          ; ext body length = L + 3
    mov byte [rsi + 10], 0
    lea edx, [ecx + 1]
    mov [rsi + 11], dl         ; ProtocolNameList length = L + 1
    mov [rsi + 12], cl         ; protocol name length
    lea rdi, [rsi + 13]        ; copy the name (rcx = L still)
    lea rsi, [rax + 1]
    rep movsb
    mov rax, r8
    ret
.empty:
    mov byte [rsi + 1], 0
    mov byte [rsi + 2], 0
    mov byte [rsi + 3], 2      ; body length 2
    mov word [rsi + 4], 0x0000 ; extensions length 0
    mov eax, 6
    ret

; store_u24_1(rdi=base, eax=value) — write value big-endian into
; [rdi+1 .. rdi+3]. Used for handshake message length fields. Clobbers
; ecx only; eax is preserved.
store_u24_1:
    mov ecx, eax
    shr ecx, 16
    mov [rdi + 1], cl          ; bits 16..23
    mov [rdi + 2], ah          ; bits 8..15
    mov [rdi + 3], al          ; bits 0..7
    ret

; getrandom32(rdi=dest) — fill 32 bytes from getrandom(2). Retries a
; short return; aborts the process on error (startup entropy is assumed).
getrandom32:
    push rbx
    push r12
    mov rbx, rdi
    xor r12d, r12d
.loop:
    lea rdi, [rbx + r12]       ; buf
    mov esi, 32
    sub rsi, r12               ; remaining length
    xor edx, edx               ; flags
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    test rax, rax
    jle .fail
    add r12, rax
    cmp r12, 32
    jb .loop
    pop r12
    pop rbx
    ret
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; ===================================================================
; linnea_tls_drain_early(rdi=hs, rsi=in_buf, rdx=in_len, rcx=scratch,
;                        r8=in_cap)
; scratch takes one record's plaintext, so it must be at least in_cap: no
; record longer than the buffer it arrived in ever gets here (see below).
; The client may pipeline application records right after its Finished --
; a TLS 1.3 client does not wait for anything before sending its request --
; so they land as ciphertext in in_buf while the keys are still ours.
; Decrypt each with the client keys (hs.rkeys, the c_ap keys once the state
; is DONE), compacting the plaintext to the front of in_buf for the HTTP
; layer.
;
; The kernel can only take over on a record boundary, so this refuses to
; run at all until the buffer holds whole records: a partial one means the
; caller must read more first. Closing instead would be wrong -- the first
; segment of a pipelined request routinely arrives without the rest of it,
; and dropping those connections would be invisible on loopback (where the
; whole write lands at once) and common over a real network.
;
; Returns:
;   rax >= 0 : plaintext length, and rdx = the next record sequence number
;              (what the kernel resumes RX from)
;   rax = -1 : a record failed to authenticate
;   rax = -2 : a partial record trails and in_buf has room for the rest --
;              read more and call again (nothing has been consumed)
;   rax = -3 : a trailing record cannot fit in_cap even once complete, so
;              waiting could never help -- the caller closes
; ===================================================================
linnea_tls_drain_early:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rdi              ; hs
    mov r12, rsi              ; in_buf
    mov r13, rdx              ; in_len
    mov r14, rcx              ; scratch (one record's plaintext)
    mov rbp, r8               ; in_buf capacity

    ; --- pass 1: whole records only, and decrypt nothing before we know.
    ; Decrypting is destructive (it rewrites in_buf and advances the record
    ; sequence), so a buffer that stops mid-record has to be left exactly as
    ; it is for the caller to top up and retry.
    xor r15d, r15d            ; scan cursor
.scan:
    mov rax, r13
    sub rax, r15              ; bytes left to scan
    jz .scanned              ; ends on a record boundary: ready
    cmp rax, 5
    jb .partial              ; header itself is incomplete
    lea rcx, [r12 + r15]
    movzx edx, byte [rcx + 3]
    shl edx, 8
    mov dl, [rcx + 4]
    add edx, 5               ; record length = 5 + fragment length
    mov rcx, r15
    add rcx, rdx             ; where this record would end
    cmp rcx, rbp
    ja .toobig               ; ...past the buffer: waiting cannot help
    cmp rdx, rax
    ja .partial              ; the rest has not arrived yet
    add r15, rdx
    jmp .scan
.partial:
    cmp r13, rbp
    jae .toobig              ; no room left to receive the remainder
    mov rax, -2
    jmp .ret
.toobig:
    mov rax, -3
    jmp .ret
.scanned:

    ; --- pass 2: every record is whole, so decrypt and compact in place.
    xor r15d, r15d            ; src cursor
    xor ebp, ebp             ; dst cursor (compacted plaintext)
.loop:
    mov rax, r13
    sub rax, r15
    jz .done                 ; pass 1 proved this lands on a boundary
    lea rcx, [r12 + r15]     ; record start
    movzx edx, byte [rcx + 3]
    shl edx, 8
    mov dl, [rcx + 4]
    add edx, 5               ; record length = 5 + fragment length
    lea rdi, [rbx + linnea_tls_hs.rkeys]
    mov rsi, rcx             ; record ptr
    mov rcx, r14            ; plaintext scratch (rdx = reclen)
    push rdx                 ; save reclen (also 16-aligns rsp for the call)
    call linnea_tls_open     ; rax = content len, rdx = inner type
    pop rcx                  ; reclen
    cmp rax, -1
    je .bad
    add r15, rcx             ; consume the record
    cmp rdx, LINNEA_TLS_CT_APPDATA
    jne .loop               ; non-application record: consumed, nothing to copy
    mov rcx, rax             ; copy the plaintext to the compacted position
    lea rdi, [r12 + rbp]
    mov rsi, r14
    add rbp, rax
    rep movsb
    jmp .loop
.done:
    mov rax, rbp            ; total plaintext length
    mov rdx, [rbx + linnea_tls_hs.rkeys + linnea_tls_keys.seq]
    jmp .ret
.bad:
    mov rax, -1
.ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
