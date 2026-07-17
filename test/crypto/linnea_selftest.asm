; linnea_selftest.asm — standalone crypto self-test binary.
;
; Default: run every embedded known-answer table (SHA-256, HMAC, HKDF)
; and print "<name> <pass>/<total>" per category; exit 1 if any failed.
; The vectors come from test/crypto/gen_vectors.py (hashlib/hmac are the
; reference); this binary checks the assembly against them.
;
; "sha256-stdin" mode: read length-prefixed frames from stdin
; (4-byte LE length, then the bytes), emit each 32-byte digest to stdout,
; loop to EOF. One process then serves a million-input differential
; driver (test/crypto/diff_sha256.py) without per-input fork overhead.

default rel

%include "linnea_syscall.inc"
%include "linnea_tls.inc"
%include "linnea_p256_fe.inc"
%include "sha256_vectors.inc"

global _start

extern linnea_print_stdout
extern linnea_print_u64_stdout
extern linnea_sha256
extern linnea_sha512
extern linnea_hmac_sha256
extern linnea_hkdf_extract
extern linnea_hkdf_expand
extern linnea_x25519
extern linnea_ed25519_sign
extern linnea_p256_fe_frombytes
extern linnea_p256_fe_tobytes
extern linnea_p256_fe_mul
extern linnea_p256_fe_sq
extern linnea_p256_fe_add
extern linnea_p256_fe_sub
extern linnea_p256_fe_inv
extern linnea_aesgcm_init
extern linnea_aesgcm_seal
extern linnea_aesgcm_open
extern linnea_tls_hkdf_expand_label
extern linnea_tls_keys_init
extern linnea_tls_seal
extern linnea_tls_open
extern linnea_pem_ed25519_seed
extern linnea_tls_hs_init
extern linnea_tls_hs_input

section .rodata

mode_stdin:  db "sha256-stdin", 0
mode_s512:   db "sha512-stdin", 0
mode_xstdin: db "x25519-stdin", 0
mode_xiter:  db "x25519-iter", 0
mode_edstd:  db "ed25519-stdin", 0
mode_gseal:  db "aesgcm-stdin", 0
mode_gopen:  db "aesgcm-open-stdin", 0
mode_pem:    db "pem-seed-stdin", 0
mode_p256fe: db "p256-fe-stdin", 0
lbl_sha:     db "sha256 "
lbl_sha_len  equ $ - lbl_sha
lbl_sha5:    db "sha512 "
lbl_sha5_len equ $ - lbl_sha5
lbl_hmac:    db "hmac "
lbl_hmac_len equ $ - lbl_hmac
lbl_ext:     db "hkdf-extract "
lbl_ext_len  equ $ - lbl_ext
lbl_exp:     db "hkdf-expand "
lbl_exp_len  equ $ - lbl_exp
lbl_x:       db "x25519 "
lbl_x_len    equ $ - lbl_x
lbl_xi:      db "x25519-iter "
lbl_xi_len   equ $ - lbl_xi
lbl_ed:      db "ed25519 "
lbl_ed_len   equ $ - lbl_ed
lbl_p256:    db "p256-fe "
lbl_p256_len equ $ - lbl_p256
lbl_gs:      db "aesgcm-seal "
lbl_gs_len   equ $ - lbl_gs
lbl_go:      db "aesgcm-open "
lbl_go_len   equ $ - lbl_go
lbl_hel:     db "tls-expand-label "
lbl_hel_len  equ $ - lbl_hel
lbl_tsl:     db "tls-seal "
lbl_tsl_len  equ $ - lbl_tsl
lbl_top:     db "tls-open "
lbl_top_len  equ $ - lbl_top
lbl_trace:   db "tls-trace "
lbl_trace_len equ $ - lbl_trace
dummy_cert:  db 0x30, 0x82, 0x01, 0x00   ; a small opaque blob; the trace
                                          ; check never inspects the cert
sep_slash:   db "/"
nl:          db 10

section .bss

outbuf:      resb 1 << 20       ; digest / OKM / AEAD output scratch
lenbuf:      resb 8
inbuf:       resb 1 << 20       ; stdin-mode input frame
iter_k:      resb 32            ; X25519 iterated-test working values
iter_u:      resb 32
iter_r:      resb 32
p256_a:      resb LINNEA_P256_FE_SIZE   ; P-256 field working values
p256_b:      resb LINNEA_P256_FE_SIZE
p256_r:      resb LINNEA_P256_FE_SIZE
gcm_ctx:     resb linnea_aesgcm_ctx_size
tls_keys:    resb linnea_tls_keys_size
tls_hs:      resb linnea_tls_hs_size
dummy_seed:  resb 32

section .text

_start:
    mov rax, [rsp]              ; argc
    cmp rax, 2
    jl .vectors
    mov rdi, [rsp + 16]         ; argv[1]
    lea rsi, [mode_stdin]
    call streq
    test eax, eax
    jnz .stdin
    mov rdi, [rsp + 16]
    lea rsi, [mode_s512]
    call streq
    test eax, eax
    jnz .s512
    mov rdi, [rsp + 16]
    lea rsi, [mode_xstdin]
    call streq
    test eax, eax
    jnz .xstdin
    mov rdi, [rsp + 16]
    lea rsi, [mode_xiter]
    call streq
    test eax, eax
    jnz .xiter
    mov rdi, [rsp + 16]
    lea rsi, [mode_edstd]
    call streq
    test eax, eax
    jnz .edstdin
    mov rdi, [rsp + 16]
    lea rsi, [mode_gseal]
    call streq
    test eax, eax
    jnz .gsstdin
    mov rdi, [rsp + 16]
    lea rsi, [mode_gopen]
    call streq
    test eax, eax
    jnz .gostdin
    mov rdi, [rsp + 16]
    lea rsi, [mode_pem]
    call streq
    test eax, eax
    jnz .pemstdin
    mov rdi, [rsp + 16]
    lea rsi, [mode_p256fe]
    call streq
    test eax, eax
    jnz .p256festdin

; ---- known-answer tables --------------------------------------------
.vectors:
    xor r15d, r15d             ; total failures across categories

    ; SHA-256
    lea rbx, [sha256_tests]
    xor r12d, r12d
    xor r13d, r13d
.sha_loop:
    cmp r12, sha256_test_count
    jae .sha_done
    imul rax, r12, 24
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]
    mov rsi, [r14 + 8]
    lea rdx, [outbuf]
    call linnea_sha256
    lea rdi, [outbuf]
    mov rsi, [r14 + 16]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .sha_loop
.sha_done:
    lea rdi, [lbl_sha]
    mov rsi, lbl_sha_len
    mov rdx, r13
    mov rcx, sha256_test_count
    call report
    add r15, sha256_test_count
    sub r15, r13               ; += (total - pass); the count is a constant,
                               ; rcx was clobbered by report's print calls

    ; SHA-512
    lea rbx, [sha512_tests]
    xor r12d, r12d
    xor r13d, r13d
.sha5_loop:
    cmp r12, sha512_test_count
    jae .sha5_done
    imul rax, r12, 24
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]
    mov rsi, [r14 + 8]
    lea rdx, [outbuf]
    call linnea_sha512
    lea rdi, [outbuf]
    mov rsi, [r14 + 16]
    mov rcx, 64
    call memeq
    add r13, rax
    inc r12
    jmp .sha5_loop
.sha5_done:
    lea rdi, [lbl_sha5]
    mov rsi, lbl_sha5_len
    mov rdx, r13
    mov rcx, sha512_test_count
    call report
    add r15, sha512_test_count
    sub r15, r13

    ; HMAC
    lea rbx, [hmac_tests]
    xor r12d, r12d
    xor r13d, r13d
.hmac_loop:
    cmp r12, hmac_test_count
    jae .hmac_done
    imul rax, r12, 40
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; key
    mov rsi, [r14 + 8]         ; keylen
    mov rdx, [r14 + 16]        ; msg
    mov rcx, [r14 + 24]        ; msglen
    lea r8, [outbuf]
    call linnea_hmac_sha256
    lea rdi, [outbuf]
    mov rsi, [r14 + 32]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .hmac_loop
.hmac_done:
    lea rdi, [lbl_hmac]
    mov rsi, lbl_hmac_len
    mov rdx, r13
    mov rcx, hmac_test_count
    call report
    add r15, hmac_test_count
    sub r15, r13

    ; HKDF-Extract
    lea rbx, [hkdf_extract_tests]
    xor r12d, r12d
    xor r13d, r13d
.ext_loop:
    cmp r12, hkdf_extract_test_count
    jae .ext_done
    imul rax, r12, 40
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; salt
    mov rsi, [r14 + 8]         ; saltlen
    mov rdx, [r14 + 16]        ; ikm
    mov rcx, [r14 + 24]        ; ikmlen
    lea r8, [outbuf]
    call linnea_hkdf_extract
    lea rdi, [outbuf]
    mov rsi, [r14 + 32]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .ext_loop
.ext_done:
    lea rdi, [lbl_ext]
    mov rsi, lbl_ext_len
    mov rdx, r13
    mov rcx, hkdf_extract_test_count
    call report
    add r15, hkdf_extract_test_count
    sub r15, r13

    ; HKDF-Expand
    lea rbx, [hkdf_expand_tests]
    xor r12d, r12d
    xor r13d, r13d
.exp_loop:
    cmp r12, hkdf_expand_test_count
    jae .exp_done
    imul rax, r12, 48
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; prk
    mov rsi, [r14 + 8]         ; prklen
    mov rdx, [r14 + 16]        ; info
    mov rcx, [r14 + 24]        ; infolen
    lea r8, [outbuf]
    mov r9, [r14 + 40]         ; outlen
    call linnea_hkdf_expand
    lea rdi, [outbuf]
    mov rsi, [r14 + 32]
    mov rcx, [r14 + 40]
    call memeq
    add r13, rax
    inc r12
    jmp .exp_loop
.exp_done:
    lea rdi, [lbl_exp]
    mov rsi, lbl_exp_len
    mov rdx, r13
    mov rcx, hkdf_expand_test_count
    call report
    add r15, hkdf_expand_test_count
    sub r15, r13

    ; X25519 single-shot
    lea rbx, [x25519_tests]
    xor r12d, r12d
    xor r13d, r13d
.x_loop:
    cmp r12, x25519_test_count
    jae .x_done
    imul rax, r12, 24
    lea r14, [rbx + rax]
    lea rdi, [outbuf]
    mov rsi, [r14 + 0]         ; scalar
    mov rdx, [r14 + 8]         ; u
    call linnea_x25519
    lea rdi, [outbuf]
    mov rsi, [r14 + 16]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .x_loop
.x_done:
    lea rdi, [lbl_x]
    mov rsi, lbl_x_len
    mov rdx, r13
    mov rcx, x25519_test_count
    call report
    add r15, x25519_test_count
    sub r15, r13

    ; X25519 iterated (k = u = 9, RFC recurrence)
    lea rbx, [x25519_iter_tests]
    xor r12d, r12d
    xor r13d, r13d
.xi_loop:
    cmp r12, x25519_iter_test_count
    jae .xi_done
    imul rax, r12, 16
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; iteration count
    lea rsi, [outbuf]
    call run_iter
    lea rdi, [outbuf]
    mov rsi, [r14 + 8]
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .xi_loop
.xi_done:
    lea rdi, [lbl_xi]
    mov rsi, lbl_xi_len
    mov rdx, r13
    mov rcx, x25519_iter_test_count
    call report
    add r15, x25519_iter_test_count
    sub r15, r13

    ; Ed25519 signing
    lea rbx, [ed25519_tests]
    xor r12d, r12d
    xor r13d, r13d
.ed_loop:
    cmp r12, ed25519_test_count
    jae .ed_done
    imul rax, r12, 32
    lea r14, [rbx + rax]
    lea rdi, [outbuf]          ; sig out (64 bytes)
    mov rsi, [r14 + 8]         ; msg
    mov rdx, [r14 + 16]        ; msglen
    mov rcx, [r14 + 0]         ; seed
    call linnea_ed25519_sign
    lea rdi, [outbuf]
    mov rsi, [r14 + 24]        ; expected sig
    mov rcx, 64
    call memeq
    add r13, rax
    inc r12
    jmp .ed_loop
.ed_done:
    lea rdi, [lbl_ed]
    mov rsi, lbl_ed_len
    mov rdx, r13
    mov rcx, ed25519_test_count
    call report
    add r15, ed25519_test_count
    sub r15, r13

    ; P-256 field arithmetic. Each record is (op, a, b, want) with the
    ; operands big-endian: convert both into Montgomery form, apply the op,
    ; convert back, compare. That exercises frombytes/tobytes on every case
    ; as well as the op itself.
    lea rbx, [p256_fe_tests]
    xor r12d, r12d
    xor r13d, r13d
.p256_loop:
    cmp r12, p256_fe_test_count
    jae .p256_done
    imul rax, r12, 32
    lea r14, [rbx + rax]
    lea rdi, [p256_a]
    mov rsi, [r14 + 8]
    call linnea_p256_fe_frombytes
    lea rdi, [p256_b]
    mov rsi, [r14 + 16]
    call linnea_p256_fe_frombytes
    mov rax, [r14 + 0]         ; op
    lea rdi, [p256_r]
    lea rsi, [p256_a]
    lea rdx, [p256_b]
    cmp rax, 0
    je .p256_mul
    cmp rax, 1
    je .p256_sq
    cmp rax, 2
    je .p256_add
    cmp rax, 3
    je .p256_sub
    call linnea_p256_fe_inv
    jmp .p256_cmp
.p256_mul:
    call linnea_p256_fe_mul
    jmp .p256_cmp
.p256_sq:
    call linnea_p256_fe_sq
    jmp .p256_cmp
.p256_add:
    call linnea_p256_fe_add
    jmp .p256_cmp
.p256_sub:
    call linnea_p256_fe_sub
.p256_cmp:
    lea rdi, [outbuf]
    lea rsi, [p256_r]
    call linnea_p256_fe_tobytes
    lea rdi, [outbuf]
    mov rsi, [r14 + 24]        ; want
    mov rcx, 32
    call memeq
    add r13, rax
    inc r12
    jmp .p256_loop
.p256_done:
    lea rdi, [lbl_p256]
    mov rsi, lbl_p256_len
    mov rdx, r13
    mov rcx, p256_fe_test_count
    call report
    add r15, p256_fe_test_count
    sub r15, r13

    ; AES-GCM seal: out must be ct || tag, ptlen + 16 bytes
    lea rbx, [aesgcm_seal_tests]
    xor r12d, r12d
    xor r13d, r13d
.gs_loop:
    cmp r12, aesgcm_seal_test_count
    jae .gs_done
    imul rax, r12, 56
    lea r14, [rbx + rax]
    lea rdi, [gcm_ctx]
    mov rsi, [r14 + 0]         ; key
    call linnea_aesgcm_init
    lea rdi, [gcm_ctx]
    mov rsi, [r14 + 8]         ; nonce
    mov rdx, [r14 + 16]        ; aad
    mov rcx, [r14 + 24]        ; aadlen
    mov r8,  [r14 + 32]        ; pt
    mov r9,  [r14 + 40]        ; ptlen
    sub rsp, 16
    lea rax, [outbuf]
    mov [rsp], rax
    call linnea_aesgcm_seal
    add rsp, 16
    lea rdi, [outbuf]
    mov rsi, [r14 + 48]        ; expected ct || tag
    mov rcx, [r14 + 40]
    add rcx, 16
    call memeq
    add r13, rax
    inc r12
    jmp .gs_loop
.gs_done:
    lea rdi, [lbl_gs]
    mov rsi, lbl_gs_len
    mov rdx, r13
    mov rcx, aesgcm_seal_test_count
    call report
    add r15, aesgcm_seal_test_count
    sub r15, r13

    ; AES-GCM open: the ok flag must match, and out must hold the
    ; expected plaintext (zeros for rejected inputs)
    lea rbx, [aesgcm_open_tests]
    xor r12d, r12d
    xor r13d, r13d
.go_loop:
    cmp r12, aesgcm_open_test_count
    jae .go_done
    imul rax, r12, 64
    lea r14, [rbx + rax]
    lea rdi, [gcm_ctx]
    mov rsi, [r14 + 0]         ; key
    call linnea_aesgcm_init
    lea rdi, [gcm_ctx]
    mov rsi, [r14 + 8]         ; nonce
    mov rdx, [r14 + 16]        ; aad
    mov rcx, [r14 + 24]        ; aadlen
    mov r8,  [r14 + 32]        ; ct || tag
    mov r9,  [r14 + 40]        ; ctlen incl. tag
    sub rsp, 16
    lea rax, [outbuf]
    mov [rsp], rax
    call linnea_aesgcm_open
    add rsp, 16
    xor edx, edx
    test rax, rax
    setz dl                    ; 1 = accepted
    cmp rdx, [r14 + 56]        ; expected ok flag
    jne .go_next
    mov rcx, [r14 + 40]        ; plaintext length, 0 if shorter than a tag
    sub rcx, 16
    jns .go_ptlen
    xor ecx, ecx
.go_ptlen:
    lea rdi, [outbuf]
    mov rsi, [r14 + 48]        ; expected plaintext
    call memeq
    add r13, rax
.go_next:
    inc r12
    jmp .go_loop
.go_done:
    lea rdi, [lbl_go]
    mov rsi, lbl_go_len
    mov rdx, r13
    mov rcx, aesgcm_open_test_count
    call report
    add r15, aesgcm_open_test_count
    sub r15, r13

    ; TLS 1.3 HKDF-Expand-Label (RFC 8448 trace derivations)
    lea rbx, [tls_hel_tests]
    xor r12d, r12d
    xor r13d, r13d
.hel_loop:
    cmp r12, tls_hel_test_count
    jae .hel_done
    imul rax, r12, 56
    lea r14, [rbx + rax]
    mov rdi, [r14 + 0]         ; secret
    mov rsi, [r14 + 8]         ; label
    mov rdx, [r14 + 16]        ; labellen
    mov rcx, [r14 + 24]        ; context
    mov r8,  [r14 + 32]        ; ctxlen
    lea r9,  [outbuf]
    sub rsp, 16
    mov rax, [r14 + 48]        ; outlen
    mov [rsp], rax
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [outbuf]
    mov rsi, [r14 + 40]        ; expected
    mov rcx, [r14 + 48]
    call memeq
    add r13, rax
    inc r12
    jmp .hel_loop
.hel_done:
    lea rdi, [lbl_hel]
    mov rsi, lbl_hel_len
    mov rdx, r13
    mov rcx, tls_hel_test_count
    call report
    add r15, tls_hel_test_count
    sub r15, r13

    ; TLS record seal: derive keys from the traffic secret, seal at the
    ; table's sequence number, compare the exact wire record
    lea rbx, [tls_seal_tests]
    xor r12d, r12d
    xor r13d, r13d
.tsl_loop:
    cmp r12, tls_seal_test_count
    jae .tsl_done
    imul rax, r12, 56
    lea r14, [rbx + rax]
    lea rdi, [tls_keys]
    mov rsi, [r14 + 0]         ; traffic secret
    call linnea_tls_keys_init
    mov rax, [r14 + 8]         ; sequence number
    mov [tls_keys + linnea_tls_keys.seq], rax
    lea rdi, [tls_keys]
    mov rsi, [r14 + 16]        ; inner type
    mov rdx, [r14 + 24]        ; payload
    mov rcx, [r14 + 32]        ; payload length
    lea r8, [outbuf]
    call linnea_tls_seal
    cmp rax, [r14 + 48]        ; expected record length
    jne .tsl_next
    lea rdi, [outbuf]
    mov rsi, [r14 + 40]        ; expected record
    mov rcx, [r14 + 48]
    call memeq
    add r13, rax
.tsl_next:
    inc r12
    jmp .tsl_loop
.tsl_done:
    lea rdi, [lbl_tsl]
    mov rsi, lbl_tsl_len
    mov rdx, r13
    mov rcx, tls_seal_test_count
    call report
    add r15, tls_seal_test_count
    sub r15, r13

    ; TLS record open: same records back through the read side, plus
    ; padding, corruption and wrong-sequence rejections
    lea rbx, [tls_open_tests]
    xor r12d, r12d
    xor r13d, r13d
.top_loop:
    cmp r12, tls_open_test_count
    jae .top_done
    imul rax, r12, 64
    lea r14, [rbx + rax]
    lea rdi, [tls_keys]
    mov rsi, [r14 + 0]         ; traffic secret
    call linnea_tls_keys_init
    mov rax, [r14 + 8]
    mov [tls_keys + linnea_tls_keys.seq], rax
    lea rdi, [tls_keys]
    mov rsi, [r14 + 16]        ; record
    mov rdx, [r14 + 24]        ; record length
    lea rcx, [outbuf]
    call linnea_tls_open
    cmp qword [r14 + 56], 0    ; expected ok flag
    je .top_bad
    cmp rax, [r14 + 40]        ; expected content length
    jne .top_next
    cmp rdx, [r14 + 48]        ; expected inner type
    jne .top_next
    lea rdi, [outbuf]
    mov rsi, [r14 + 32]        ; expected content
    mov rcx, [r14 + 40]
    call memeq
    add r13, rax
    jmp .top_next
.top_bad:
    cmp rax, -1
    jne .top_next
    inc r13
.top_next:
    inc r12
    jmp .top_loop
.top_done:
    lea rdi, [lbl_top]
    mov rsi, lbl_top_len
    mov rdx, r13
    mov rcx, tls_open_test_count
    call report
    add r15, tls_open_test_count
    sub r15, r13

    ; TLS 1.3 handshake vs the RFC 8448 trace: feed the trace ClientHello
    ; with the trace's ephemeral key + server random injected; the emitted
    ; ServerHello record and the handshake/master secrets must match the
    ; trace byte-for-byte. (The flight past the SH signs with our Ed25519
    ; key where the trace used RSA, so only the schedule is comparable.)
    lea rdi, [tls_hs]
    lea rsi, [dummy_cert]
    mov rdx, 4
    lea rcx, [dummy_seed]
    mov r8d, LINNEA_TLS_FLAG_TRACE
    call linnea_tls_hs_init
    lea rdi, [tls_hs + linnea_tls_hs.priv]   ; inject server ephemeral key
    lea rsi, [trace_srv_priv]
    call copy32
    lea rdi, [tls_hs + linnea_tls_hs.srand]  ; inject server random
    lea rsi, [trace_srv_rand]
    call copy32
    lea rdi, [tls_hs]
    lea rsi, [trace_ch_rec]
    mov rdx, tls_trace_ch_rec_len
    lea rcx, [outbuf]
    mov r8, 1 << 20
    call linnea_tls_hs_input

    xor r13d, r13d
    lea rdi, [outbuf]           ; ServerHello record bytes
    lea rsi, [trace_sh_rec]
    mov rcx, tls_trace_sh_rec_len
    call memeq
    add r13, rax
    lea rdi, [tls_hs + linnea_tls_hs.c_hs]
    lea rsi, [trace_c_hs]
    mov rcx, 32
    call memeq
    add r13, rax
    lea rdi, [tls_hs + linnea_tls_hs.s_hs]
    lea rsi, [trace_s_hs]
    mov rcx, 32
    call memeq
    add r13, rax
    lea rdi, [tls_hs + linnea_tls_hs.master]
    lea rsi, [trace_master]
    mov rcx, 32
    call memeq
    add r13, rax
    lea rdi, [lbl_trace]
    mov rsi, lbl_trace_len
    mov rdx, r13
    mov rcx, 4
    call report
    add r15, 4
    sub r15, r13

    ; exit 1 if anything failed
    mov edi, 1
    test r15, r15
    jnz .exit
    xor edi, edi
.exit:
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- x25519-stdin differential mode (64-byte scalar||u frames) ------
.xstdin:
    lea rdi, [inbuf]
    mov rsi, 64
    call read_full
    cmp eax, 64
    jne .xstdin_done
    lea rdi, [outbuf]
    lea rsi, [inbuf]
    lea rdx, [inbuf + 32]
    call linnea_x25519
    lea rdi, [outbuf]
    mov rsi, 32
    call linnea_print_stdout
    jmp .xstdin
.xstdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- x25519-iter mode: argv[2] rounds, raw 32-byte result to stdout -
.xiter:
    mov rax, [rsp + 8]         ; argc
    cmp rax, 3
    jl .xiter_bad
    mov rdi, [rsp + 24]        ; argv[2]
    call parse_u64
    mov rdi, rax
    lea rsi, [outbuf]
    call run_iter
    lea rdi, [outbuf]
    mov rsi, 32
    call linnea_print_stdout
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.xiter_bad:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- ed25519-stdin: frames of [4-byte len][seed32 || msg] -> 64-byte sig
.edstdin:
    lea rdi, [lenbuf]
    mov rsi, 4
    call read_full
    cmp eax, 4
    jne .edstdin_done
    mov ecx, [lenbuf]
    lea rdi, [inbuf]
    mov rsi, rcx
    call read_full
    lea rdi, [outbuf]          ; sig (64)
    lea rsi, [inbuf + 32]      ; msg
    mov edx, [lenbuf]
    sub edx, 32                ; msglen = frame - seed
    lea rcx, [inbuf]           ; seed
    call linnea_ed25519_sign
    lea rdi, [outbuf]
    mov rsi, 64
    call linnea_print_stdout
    jmp .edstdin
.edstdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- aesgcm-stdin: frames of [4-byte len][key16 || nonce12 ||
; aadlen4 || aad || pt] -> ct || tag (ptlen + 16 bytes) ----------------
.gsstdin:
    lea rdi, [lenbuf]
    mov rsi, 4
    call read_full
    cmp eax, 4
    jne .gsstdin_done
    mov ecx, [lenbuf]
    lea rdi, [inbuf]
    mov rsi, rcx
    call read_full
    lea rdi, [gcm_ctx]
    lea rsi, [inbuf]           ; key
    call linnea_aesgcm_init
    mov ecx, [inbuf + 28]      ; aadlen
    lea rdx, [inbuf + 32]      ; aad
    lea r8, [rdx + rcx]        ; pt
    mov r9d, [lenbuf]
    sub r9, 32
    sub r9, rcx                ; ptlen = frame - key - nonce - aadlen4 - aad
    lea rdi, [gcm_ctx]
    lea rsi, [inbuf + 16]      ; nonce
    sub rsp, 16
    lea rax, [outbuf]
    mov [rsp], rax
    call linnea_aesgcm_seal
    add rsp, 16
    mov esi, [lenbuf]          ; reply length = ptlen + 16
    sub esi, 16
    sub esi, [inbuf + 28]
    lea rdi, [outbuf]
    call linnea_print_stdout
    jmp .gsstdin
.gsstdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- aesgcm-open-stdin: frames of [4-byte len][key16 || nonce12 ||
; aadlen4 || aad || ct || tag] -> [1-byte rc][pt (ctlen - 16 bytes,
; zeros when the tag was rejected)] ------------------------------------
.gostdin:
    lea rdi, [lenbuf]
    mov rsi, 4
    call read_full
    cmp eax, 4
    jne .gostdin_done
    mov ecx, [lenbuf]
    lea rdi, [inbuf]
    mov rsi, rcx
    call read_full
    lea rdi, [gcm_ctx]
    lea rsi, [inbuf]           ; key
    call linnea_aesgcm_init
    mov ecx, [inbuf + 28]      ; aadlen
    lea rdx, [inbuf + 32]      ; aad
    lea r8, [rdx + rcx]        ; ct || tag
    mov r9d, [lenbuf]
    sub r9, 32
    sub r9, rcx                ; ctlen incl. tag
    lea rdi, [gcm_ctx]
    lea rsi, [inbuf + 16]      ; nonce
    sub rsp, 16
    lea rax, [outbuf + 1]      ; plaintext lands after the rc byte
    mov [rsp], rax
    call linnea_aesgcm_open
    add rsp, 16
    xor edx, edx
    test rax, rax
    setnz dl                   ; rc: 0 accepted, 1 rejected
    mov [outbuf], dl
    mov esi, [lenbuf]          ; reply length = 1 + (ctlen - 16)
    sub esi, 32
    sub esi, [inbuf + 28]
    sub esi, 16
    jns .gostdin_write
    xor esi, esi
.gostdin_write:
    inc esi
    lea rdi, [outbuf]
    call linnea_print_stdout
    jmp .gostdin
.gostdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- pem-seed-stdin: frame [4-byte len][PEM text] -> [1-byte rc]
; [32-byte seed] (rc 0 ok, 1 rejected -> seed omitted) -----------------
.pemstdin:
    lea rdi, [lenbuf]
    mov rsi, 4
    call read_full
    cmp eax, 4
    jne .pemstdin_done
    mov ecx, [lenbuf]
    lea rdi, [inbuf]
    mov rsi, rcx
    call read_full
    lea rdi, [inbuf]
    mov esi, [lenbuf]
    call linnea_pem_ed25519_seed
    cmp rax, -1
    je .pem_reject
    mov byte [outbuf], 0
    mov rsi, rax
    lea rdi, [outbuf + 1]
    call copy32
    lea rdi, [outbuf]
    mov rsi, 33
    call linnea_print_stdout
    jmp .pemstdin
.pem_reject:
    mov byte [outbuf], 1
    lea rdi, [outbuf]
    mov rsi, 1
    call linnea_print_stdout
    jmp .pemstdin
.pemstdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- p256-fe-stdin mode: 65-byte frames [op][a 32B BE][b 32B BE],
;      reply with the 32-byte big-endian result. Drives
;      test/crypto/diff_p256_fe.py; op numbering matches gen_vectors.py.
.p256festdin:
    lea rdi, [inbuf]
    mov rsi, 65
    call read_full
    cmp eax, 65
    jne .p256festdin_done
    lea rdi, [p256_a]
    lea rsi, [inbuf + 1]
    call linnea_p256_fe_frombytes
    lea rdi, [p256_b]
    lea rsi, [inbuf + 33]
    call linnea_p256_fe_frombytes
    movzx rax, byte [inbuf]
    lea rdi, [p256_r]
    lea rsi, [p256_a]
    lea rdx, [p256_b]
    cmp rax, 0
    je .p256fe_mul
    cmp rax, 1
    je .p256fe_sq
    cmp rax, 2
    je .p256fe_add
    cmp rax, 3
    je .p256fe_sub
    call linnea_p256_fe_inv
    jmp .p256fe_out
.p256fe_mul:
    call linnea_p256_fe_mul
    jmp .p256fe_out
.p256fe_sq:
    call linnea_p256_fe_sq
    jmp .p256fe_out
.p256fe_add:
    call linnea_p256_fe_add
    jmp .p256fe_out
.p256fe_sub:
    call linnea_p256_fe_sub
.p256fe_out:
    lea rdi, [outbuf]
    lea rsi, [p256_r]
    call linnea_p256_fe_tobytes
    lea rdi, [outbuf]
    mov rsi, 32
    call linnea_print_stdout
    jmp .p256festdin
.p256festdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- sha256-stdin differential mode ---------------------------------
.stdin:
    lea rdi, [lenbuf]
    mov rsi, 4
    call read_full
    cmp eax, 4
    jne .stdin_done
    mov ecx, [lenbuf]          ; frame length, little-endian
    lea rdi, [inbuf]
    mov rsi, rcx
    call read_full
    lea rdi, [inbuf]
    mov esi, [lenbuf]
    lea rdx, [outbuf]
    call linnea_sha256
    lea rdi, [outbuf]
    mov rsi, 32
    call linnea_print_stdout
    jmp .stdin
.stdin_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; ---- sha512-stdin differential mode ---------------------------------
.s512:
    lea rdi, [lenbuf]
    mov rsi, 4
    call read_full
    cmp eax, 4
    jne .s512_done
    mov ecx, [lenbuf]
    lea rdi, [inbuf]
    mov rsi, rcx
    call read_full
    lea rdi, [inbuf]
    mov esi, [lenbuf]
    lea rdx, [outbuf]
    call linnea_sha512
    lea rdi, [outbuf]
    mov rsi, 64
    call linnea_print_stdout
    jmp .s512
.s512_done:
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; report(rdi=label, rsi=labellen, rdx=pass, rcx=total) — "<label><p>/<t>\n"
report:
    push rbx
    push r12
    push r13
    mov rbx, rdx               ; pass
    mov r12, rcx               ; total
    call linnea_print_stdout   ; label (rdi/rsi already set)
    mov rdi, rbx
    call linnea_print_u64_stdout
    lea rdi, [sep_slash]
    mov rsi, 1
    call linnea_print_stdout
    mov rdi, r12
    call linnea_print_u64_stdout
    lea rdi, [nl]
    mov rsi, 1
    call linnea_print_stdout
    pop r13
    pop r12
    pop rbx
    ret

; memeq(rdi=a, rsi=b, rcx=n) -> eax = 1 if the n bytes match, else 0.
memeq:
    xor eax, eax
.loop:
    test rcx, rcx
    jz .equal
    mov dl, [rdi]
    cmp dl, [rsi]
    jne .done
    inc rdi
    inc rsi
    dec rcx
    jmp .loop
.equal:
    mov eax, 1
.done:
    ret

; read_full(rdi=buf, rsi=count) -> eax = bytes actually read (== count, or
; fewer at EOF). Loops over short reads.
read_full:
    push rbx
    push r12
    push r13
    mov rbx, rdi               ; buf cursor
    mov r12, rsi               ; remaining
    xor r13d, r13d             ; total read
.loop:
    test r12, r12
    jz .done
    xor eax, eax               ; SYS_READ
    xor edi, edi               ; stdin
    mov rsi, rbx
    mov rdx, r12
    syscall
    test rax, rax
    jle .done                  ; 0 = EOF, <0 = error
    add rbx, rax
    sub r12, rax
    add r13, rax
    jmp .loop
.done:
    mov rax, r13
    pop r13
    pop r12
    pop rbx
    ret

; run_iter(rdi=n, rsi=out32) — the RFC 7748 recurrence: k = u = 9, then
; n times (r = X25519(k,u); u = k; k = r); write the final k to out.
run_iter:
    push rbx
    push r12
    push r13
    mov rbx, rdi               ; n
    mov r12, rsi               ; out
    lea rdi, [iter_k]
    call zero32
    lea rdi, [iter_u]
    call zero32
    mov byte [iter_k], 9
    mov byte [iter_u], 9
.loop:
    test rbx, rbx
    jz .done
    lea rdi, [iter_r]
    lea rsi, [iter_k]
    lea rdx, [iter_u]
    call linnea_x25519
    lea rdi, [iter_u]
    lea rsi, [iter_k]
    call copy32
    lea rdi, [iter_k]
    lea rsi, [iter_r]
    call copy32
    dec rbx
    jmp .loop
.done:
    mov rdi, r12
    lea rsi, [iter_k]
    call copy32
    pop r13
    pop r12
    pop rbx
    ret

; copy32(rdi=dst, rsi=src) — copy 32 bytes.
copy32:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    ret

; zero32(rdi=dst) — clear 32 bytes.
zero32:
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    ret

; parse_u64(rdi=cstr) -> rax — decimal, no validation (test tooling).
parse_u64:
    xor eax, eax
.loop:
    movzx ecx, byte [rdi]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul rax, rax, 10
    add rax, rcx
    inc rdi
    jmp .loop
.done:
    ret

; streq(rdi=a, rsi=b) -> eax = 1 if the NUL-terminated strings are equal.
streq:
    xor eax, eax
.loop:
    mov dl, [rdi]
    cmp dl, [rsi]
    jne .done
    test dl, dl
    jz .equal
    inc rdi
    inc rsi
    jmp .loop
.equal:
    mov eax, 1
.done:
    ret
