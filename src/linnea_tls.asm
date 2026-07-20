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

section .text

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
    ; dispatch the three extensions we require
    cmp r12d, 0x2b              ; supported_versions
    je .ext_sv
    cmp r12d, 0x33              ; key_share
    je .ext_ks
    cmp r12d, 0x0d              ; signature_algorithms
    je .ext_sa
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
.ext_skip:
    pop rbx                     ; body end -> continue after this ext
    jmp .ext_loop
.ext_dup:
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
    jnz .ok
    test r14d, 4
    jz .handshake_fail
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

    ; 2. schedule up to the handshake secret (no transcript needed yet)
    lea rdi, [zeros32]          ; early = HKDF-Extract(0, 0)
    xor esi, esi
    lea rdx, [zeros32]
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
    ; -- EncryptedExtensions: no extensions --
    mov dword [rbx], 0x02000008              ; 08 00 00 02 (LE store)
    mov word [rbx + 4], 0x0000
    lea rsi, [rbx]
    mov edx, 6
    mov rdi, rbp
    call tls_absorb
    add rbx, 6
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
    mov word [rdi + 3], 0x2e00 ; extensions length = 46
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
    lea rax, [rdi + 51]        ; message end
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
