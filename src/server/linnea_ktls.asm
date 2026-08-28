; linnea_ktls.asm — TLS startup (CPUID gate, cert/key loading) and the
; kTLS handoff.
;
; linnea_tls_setup runs once at startup: if any server serves TLS it
; requires the instructions the record protection is built on (see
; cpuid_check_aesni), then loads each TLS server's PEM certificate chain
; (every CERTIFICATE block, pre-framed as the TLS certificate_list and
; sent verbatim) and PKCS#8 P-256 key into persistent buffers, bounding
; the list so the handshake flight cannot outgrow the message buffer it
; is assembled in.
;
; linnea_ktls_enable performs the handoff after a handshake completes:
; TCP_ULP "tls", then the AES-128-GCM application traffic keys for the
; send and receive directions via SOL_TLS. From then on the kernel does
; record protection and ordinary send/recv carry plaintext, so the whole
; HTTP / proxy / tunnel event loop runs over TLS unchanged.
;
; ABI: System V; callee-saved preserved.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_p256_ecdsa.inc"
%include "linnea_tls.inc"

global linnea_tls_setup
global linnea_ktls_enable
global linnea_ktls_rekey_rx
global linnea_ktls_rekey_tx
global linnea_ktls_key_update
global linnea_ktls_fail_step
global linnea_ktls_fail_errno
global linnea_ktls_close_notify

extern linnea_file_map_readonly
extern linnea_file_unmap
extern linnea_pem_cert_list
extern linnea_pem_p256_key
extern linnea_tls_ticket_setup
extern linnea_quic_ticket_setup
extern linnea_p256_scalar_is_valid
extern linnea_tls_hkdf_expand_label
extern linnea_error_exit
extern linnea_x509_leaf_spki
extern linnea_x509_leaf_usage_ok
extern linnea_x509_leaf_validity_times
extern linnea_time_days_from_civil
extern linnea_print_stderr
extern linnea_pem_key_pub
extern linnea_x509_spki_point
extern linnea_p256_ecdsa_sign
extern linnea_p256_ecdsa_verify_der
extern linnea_x509_leaf_host_ok
extern linnea_x509_leaf_selfsig
extern linnea_sha256

section .rodata
pair_digest: times 32 db 0x5a       ; any fixed digest; only the pairing matters


ulp_tls:    db "tls", 0
lbl_key:    db "key"
lbl_iv:     db "iv"
lbl_traffic_upd: db "traffic upd"     ; RFC 8446 7.2, the KeyUpdate derivation
lbl_traffic_upd_len equ $ - lbl_traffic_upd

msg_no_aesni: db "TLS requires a CPU with AES-NI, PCLMULQDQ and SSSE3"
msg_no_aesni_len equ $ - msg_no_aesni
msg_cert_expired: db "WARNING: the TLS certificate has EXPIRED -- clients will refuse it; serving anyway", 10
msg_cert_expired_len equ $ - msg_cert_expired
msg_cert_future: db "WARNING: the TLS certificate is NOT YET VALID -- clients will refuse it; serving anyway", 10
msg_cert_future_len equ $ - msg_cert_future
msg_bad_usage: db "the certificate does not permit TLS server authentication (keyUsage lacks digitalSignature, or extendedKeyUsage lacks serverAuth)", 10
msg_bad_usage_len equ $ - msg_bad_usage
msg_key_selfcontra: db "the key file embeds a public key that its own private scalar does not sign for", 10
msg_key_selfcontra_len equ $ - msg_key_selfcontra
msg_cert_name: db "WARNING: the TLS certificate presents no name matching this server's hostname -- clients will refuse it unless they reach this vhost over a connection authenticated for another of its names", 10
msg_cert_name_len equ $ - msg_cert_name
msg_bad_sig: db "the certificate is self-signed but its signature does not verify under its own public key: the file is corrupt or has been tampered with", 10
msg_bad_sig_len equ $ - msg_bad_sig
msg_key_mismatch: db "certificate and key are different identities: the key does not sign for this certificate", 10
msg_key_mismatch_len equ $ - msg_key_mismatch
msg_no_entropy: db "cannot seed the session-ticket keys: getrandom failed", 10
msg_no_entropy_len equ $ - msg_no_entropy
msg_bad_cert: db "cannot load TLS certificate chain (not PEM CERTIFICATEs?)"
msg_bad_cert_len equ $ - msg_bad_cert
msg_crit_ext: db "the certificate chain carries a CRITICAL X.509 extension this build does not implement: RFC 5280 4.2 requires clients to reject it, so serving it would fail every handshake"
msg_crit_ext_len equ $ - msg_crit_ext
msg_bad_key:  db "cannot load TLS key (not a PKCS#8 P-256 key in [1, n-1]?)"
msg_bad_key_len equ $ - msg_bad_key
msg_cert_big: db "TLS certificate chain too large to fit the handshake flight"
msg_cert_big_len equ $ - msg_cert_big

; Decode scratch, deliberately looser than LINNEA_TLS_MAX_CERT_LIST so
; that a chain just over the limit is diagnosed as too large rather than
; as malformed (linnea_pem_cert_list reports overflow as any bad block).
MAX_CERT_LIST equ 8192

section .bss
val_times:   resq 6      ; notBefore ptr/len/tag, notAfter ptr/len/tag

; the cert/key pairing self-check (audit-report-99 F2)
leaf_pub:    resb 64
pair_sig:    resb LINNEA_P256_ECDSA_MAX_SIG

; the leaf's own signature check (audit-report-119 F2)
leaf_der:    resq 2      ; the leaf DER pointer and its length
sig_parts:   resq 6      ; tbs ptr/len, sig ptr/len, self-issued, sha256-ecdsa
tbs_hash:    resb 32


alignb 8
cert_pool:  resb LINNEA_MAX_SERVERS * MAX_CERT_LIST
key_pool:  resb LINNEA_MAX_SERVERS * 32
; Why the last handoff failed. linnea_ktls_enable used to collapse every
; failure to -1, so a connection closed with "tls kernel handoff failed" and
; nothing said which of the three setsockopts refused it or why — the one
; question worth answering when it happens in production. Kept as globals
; rather than returned so the caller's contract (0 / -1) is unchanged.
linnea_ktls_fail_step:  resq 1     ; 1 = TCP_ULP, 2 = TLS_TX, 3 = TLS_RX
linnea_ktls_fail_errno: resq 1     ; the negative errno the syscall returned

section .text

; ---- linnea_tls_setup(rdi=config*) ----------------------------------

; ---- x509_time_epoch(rdi=digits, rsi=len, rdx=tag) -> rax = POSIX seconds, or -1
; RFC 5280 4.1.2.5: UTCTime is YYMMDDHHMMSSZ with YY >= 50 meaning 19YY;
; GeneralizedTime is YYYYMMDDHHMMSSZ. Only the Zulu forms the RFC mandates.
x509_time_epoch:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r14, rsi
    cmp rdx, 0x18
    je .xt_gen
    cmp rdx, 0x17
    jne .xt_no
    cmp r14, 13
    jne .xt_no
    mov r13d, 2                      ; two year digits
    jmp .xt_year
.xt_gen:
    cmp r14, 15
    jne .xt_no
    mov r13d, 4
.xt_year:
    cmp byte [rbx + r14 - 1], 'Z'
    jne .xt_no
    xor r12, r12
    xor ecx, ecx
.xt_yd:
    cmp ecx, r13d
    jae .xt_ydone
    movzx eax, byte [rbx + rcx]
    sub eax, '0'
    cmp eax, 9
    ja .xt_no
    imul r12, r12, 10
    add r12, rax
    inc ecx
    jmp .xt_yd
.xt_ydone:
    cmp r13d, 4
    je .xt_have_year
    cmp r12, 50                      ; UTCTime pivot
    jb .xt_20
    add r12, 1900
    jmp .xt_have_year
.xt_20:
    add r12, 2000
.xt_have_year:
    mov r13d, ecx                    ; cursor
    call xt_two                      ; month
    cmp rax, -1
    je .xt_no
    mov r14, rax
    call xt_two                      ; day
    cmp rax, -1
    je .xt_no
    mov rdi, r12
    mov rsi, r14
    mov rdx, rax
    call linnea_time_days_from_civil
    imul r12, rax, 86400
    call xt_two                      ; hour
    cmp rax, -1
    je .xt_no
    imul rax, rax, 3600
    add r12, rax
    call xt_two                      ; minute
    cmp rax, -1
    je .xt_no
    imul rax, rax, 60
    add r12, rax
    call xt_two                      ; second
    cmp rax, -1
    je .xt_no
    add r12, rax
    mov rax, r12
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.xt_no:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; xt_two -> rax = the two decimal digits at [rbx + r13d], advancing r13d.
xt_two:
    movzx eax, byte [rbx + r13]
    sub eax, '0'
    cmp eax, 9
    ja .x2_no
    movzx edx, byte [rbx + r13 + 1]
    sub edx, '0'
    cmp edx, 9
    ja .x2_no
    imul eax, eax, 10
    add eax, edx
    add r13d, 2
    ret
.x2_no:
    mov rax, -1
    ret

linnea_tls_setup:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi               ; config*

    ; any TLS servers at all?
    xor r12d, r12d
    xor r15d, r15d             ; "TLS seen" flag
.scan:
    cmp r12, [rbx + linnea_config.server_count]
    jae .scanned
    imul rax, r12, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    cmp dword [rax + linnea_config_server.tls], 0
    je .scan_next
    mov r15d, 1
.scan_next:
    inc r12
    jmp .scan
.scanned:
    test r15d, r15d
    jz .done                   ; no TLS: nothing to check or load
    call cpuid_check_aesni
    ; one stateless-ticket key for the whole run, generated here in the
    ; master before the workers fork so every worker resumes every
    ; worker's sessions (the key is inherited copy-on-write).
    ; Both results are checked: these used to retry a failed getrandom forever,
    ; hanging the master here with no diagnostic (audit-report-97). Refusing to
    ; start is the only safe answer for pre-fork key material.
    call linnea_tls_ticket_setup
    test eax, eax
    js .no_entropy
    ; the QUIC session-ticket key shares the same pre-fork lifetime (its own key,
    ; since a QUIC session never resumes a TCP one)
    call linnea_quic_ticket_setup
    test eax, eax
    js .no_entropy

    ; load each TLS server's cert and key
    xor r12d, r12d
.load:
    cmp r12, [rbx + linnea_config.server_count]
    jae .done
    imul r13, r12, linnea_config_server_size
    lea r13, [rbx + r13 + linnea_config.servers]   ; server*
    cmp dword [r13 + linnea_config_server.tls], 0
    je .load_next

    ; certificate chain: map the PEM, frame every CERTIFICATE block
    ; into this server's slot as a ready-made TLS certificate_list
    lea rdi, [r13 + linnea_config_server.cert_path]
    call linnea_file_map_readonly     ; rax=ptr, rdx=size
    mov r14, rax                      ; mapping ptr
    mov r15, rdx                      ; mapping size
    imul rax, r12, MAX_CERT_LIST
    lea rax, [cert_pool + rax]         ; this server's list slot
    mov [r13 + linnea_config_server.cert_list], rax
    mov rdi, r14
    mov rsi, r15
    mov rdx, [r13 + linnea_config_server.cert_list]
    mov ecx, MAX_CERT_LIST
    call linnea_pem_cert_list
    cmp rax, -3
    je .bad_crit_ext           ; named, not folded into the generic message
    cmp rax, 0
    jle .bad_cert
    cmp rax, LINNEA_TLS_MAX_CERT_LIST  ; must leave room for the rest of
    ja .cert_big                   ; the flight in msg_buf (linnea_tls.inc)
    mov [r13 + linnea_config_server.cert_list_len], rax
    mov rdi, r14
    mov rsi, r15
    call linnea_file_unmap

    ; key: map the PEM, walk out the P-256 private scalar, copy into our slot
    lea rdi, [r13 + linnea_config_server.key_path]
    call linnea_file_map_readonly
    mov r14, rax
    mov r15, rdx
    mov rdi, rax
    mov rsi, rdx
    call linnea_pem_p256_key          ; rax = scalar ptr (static) or -1
    cmp rax, -1
    je .bad_key
    ; The scalar must be in [1, n-1]. Checked once here rather than on every
    ; signature: linnea_p256_ecdsa_sign assumes it, and a key outside the
    ; range is an operator error to fail at startup, not per handshake.
    push rax
    mov rdi, rax
    call linnea_p256_scalar_is_valid
    test eax, eax
    pop rax
    jz .bad_key
    imul rcx, r12, 32
    lea rdi, [key_pool + rcx]
    mov [r13 + linnea_config_server.key_priv], rdi
    mov rsi, rax                       ; copy the 32-byte scalar out before the
    mov rcx, 32                        ; static buffer is reused next server
    rep movsb
    mov rdi, r14
    mov rsi, r15
    call linnea_file_unmap

    ; ---- prove the certificate and the key are ONE identity -----------------
    ; Both files parsed on their own; nothing tied them together. A renewal
    ; that updates the chain and the key as separate files could land half of a
    ; pair, pass this preflight, and retire a working generation for one that
    ; cannot authenticate any fresh client -- TLS 1.3 defines CertificateVerify
    ; as proof of possession of the key matching the certificate (RFC 8446
    ; 4.4.3), so a signature from an unrelated key is guaranteed to be rejected
    ; (audit-report-99 F2).
    ;
    ; Parsing the leaf's SPKI is also what makes an arbitrary byte string stop
    ; being a "certificate": the loader used to accept any nonempty body and
    ; frame it (F1). The leaf DER sits behind the u24 CertificateEntry length
    ; that linnea_pem_cert_list wrote.
    mov rax, [r13 + linnea_config_server.cert_list]
    movzx edi, byte [rax]
    shl edi, 16
    movzx ecx, byte [rax + 1]
    shl ecx, 8
    or edi, ecx
    movzx ecx, byte [rax + 2]
    or edi, ecx                        ; edi = leaf DER length
    mov rsi, rdi
    lea rdi, [rax + 3]                 ; the DER itself
    ; ...and the leaf must be allowed to authenticate a TLS SERVER. RFC 8446
    ; 4.4.2.2: if Key Usage is present digitalSignature must be set, and a leaf
    ; whose Extended Key Usage is only clientAuth cannot serve. Absent is fine
    ; -- every certificate here has neither, and OpenSSL's sslserver purpose
    ; check passes them. LEAF ONLY: an issuer legitimately carries keyCertSign
    ; and no serverAuth (audit-report-117).
    push rdi
    push rsi
    call linnea_x509_leaf_usage_ok
    test eax, eax
    pop rsi
    pop rdi
    jz .bad_usage
    ; ...and WARN if the validity window does not contain now. Deliberately a
    ; warning and not a refusal: nginx and Apache both start on an expired
    ; certificate, and refusing would turn a renewal that silently failed --
    ; a degraded state clients merely complain about -- into a total outage the
    ; operator cannot restart out of, while also blocking the hot upgrade that
    ; might carry the fix. --test exits 0 for the same reason, and because a
    ; config check whose verdict changes with the clock is not a config check.
    ; Making this fatal is a one-line change if that trade is ever wanted
    ; (audit-report-118).
    push rdi
    push rsi
    lea rdx, [val_times]
    call linnea_x509_leaf_validity_times
    test eax, eax
    jz .val_done
    mov rdi, [val_times]
    mov rsi, [val_times + 8]
    mov rdx, [val_times + 16]
    call x509_time_epoch
    cmp rax, -1
    je .val_done
    mov r15, rax                     ; notBefore
    mov rdi, [val_times + 24]
    mov rsi, [val_times + 32]
    mov rdx, [val_times + 40]
    call x509_time_epoch
    cmp rax, -1
    je .val_done
    mov r14, rax                     ; notAfter
    sub rsp, 16
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    xor edi, edi                     ; CLOCK_REALTIME
    mov rsi, rsp
    syscall
    mov rax, [rsp]
    add rsp, 16
    cmp rax, r15
    jb .val_future
    cmp rax, r14
    jbe .val_done
    lea rdi, [msg_cert_expired]
    mov esi, msg_cert_expired_len
    call linnea_print_stderr         ; --test never opens the log, and this is
                                     ; exactly when the operator must see it
    jmp .val_done
.val_future:
    lea rdi, [msg_cert_future]
    mov esi, msg_cert_future_len
    call linnea_print_stderr
.val_done:
    pop rsi
    pop rdi
    mov [leaf_der], rdi                ; kept for the signature check below
    mov [leaf_der + 8], rsi
    ; ...and WARN when the certificate does not speak for the name this server
    ; answers to. RFC 6125: the SAN dNSNames decide, and only a certificate
    ; without any of them falls back to the CN. A warning for the same reason
    ; the expiry check is one -- and for one more: a name the certificate omits
    ; is legitimate when a client reaches this vhost over a connection
    ; authenticated for another name, which is exactly what HTTP/2 connection
    ; coalescing does (test/configs/tls-coalesce.json serves alias.test from a
    ; localhost certificate on purpose). Refusing would break that
    ; (audit-report-119 F1).
    push rdi
    push rsi
    mov rcx, [r13 + linnea_config_server.hostname_len]
    test rcx, rcx
    jz .host_done                      ; a server with no name to check
    lea rdi, [r13 + linnea_config_server.hostname]
    mov rsi, rcx
    call host_is_ip
    test eax, eax
    jnz .host_done                     ; an IP literal is never a dNSName
    mov rdi, [rsp + 8]                 ; the leaf DER, read back off the stack
    mov rsi, [rsp]
    lea rdx, [r13 + linnea_config_server.hostname]
    mov rcx, [r13 + linnea_config_server.hostname_len]
    call linnea_x509_leaf_host_ok
    test eax, eax
    jnz .host_done
    lea rdi, [msg_cert_name]
    mov esi, msg_cert_name_len
    call linnea_print_stderr
.host_done:
    pop rsi
    pop rdi
    call linnea_x509_leaf_spki         ; rax = SPKI, rdx = its length
    test rax, rax
    jz .bad_cert                       ; no SPKI in the field where one belongs
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [leaf_pub]
    call linnea_x509_spki_point        ; -> 64-byte X||Y
    test eax, eax
    jz .bad_cert
    ; sign a fixed digest with the configured key and verify it under the
    ; certificate's point: equality of identity, proven through the very
    ; primitive the handshake will use.
    lea rdi, [pair_sig]
    lea rsi, [pair_digest]
    mov rdx, [r13 + linnea_config_server.key_priv]
    call linnea_p256_ecdsa_sign        ; rax = DER length
    mov r14, rax                      ; keep it for the second verify below
    lea rsi, [pair_sig]
    mov rdx, rax
    lea rdi, [pair_digest]
    lea rcx, [leaf_pub]
    call linnea_p256_ecdsa_verify_der
    test eax, eax
    jz .key_mismatch
    ; ...and if the key file carried its own SEC1 [1] publicKey, the same
    ; signature must verify under THAT point too. RFC 5915 3 calls it "the EC
    ; public key associated with the private key in question", so a point that
    ; disagrees with the scalar is a self-contradictory file, not a harmless
    ; annotation -- and it was accepted unchecked (audit-report-105 F2).
    ; Reusing pair_sig means no second signing and no base-point multiply.
    call linnea_pem_key_pub
    test rax, rax
    jz .pair_done                     ; the key carried none: nothing to tie
    mov rcx, rax
    lea rsi, [pair_sig]
    mov rdx, r14                      ; the DER length kept from the sign
    lea rdi, [pair_digest]
    call linnea_p256_ecdsa_verify_der
    test eax, eax
    jz .key_selfcontradictory
.pair_done:
    ; ---- and when the certificate signs for ITSELF, check that signature.
    ; A self-issued leaf carries the very key that signed it, so this needs no
    ; trust store and no chain: it catches a corrupted or tampered certificate
    ; (openssl x509 -badsig) that every check above still calls well-formed.
    ;
    ; Scope is deliberate. An issued leaf is signed by a key we do not have --
    ; and would mostly be RSA or P-384, which this build cannot verify at all --
    ; so it is left UNVERIFIED rather than refused, and rather than warned about
    ; on every boot of a perfectly good Let's Encrypt certificate. A check that
    ; runs and fails is fatal; a check that cannot run says nothing
    ; (audit-report-119 F2).
    mov rdi, [leaf_der]
    mov rsi, [leaf_der + 8]
    lea rdx, [sig_parts]
    call linnea_x509_leaf_selfsig
    test eax, eax
    jz .sig_done
    cmp qword [sig_parts + 32], 0      ; issuer == subject?
    je .sig_done
    cmp qword [sig_parts + 40], 0      ; ecdsa-with-SHA256?
    je .sig_done
    mov rdi, [sig_parts]
    mov rsi, [sig_parts + 8]
    lea rdx, [tbs_hash]
    call linnea_sha256                 ; over the whole tbsCertificate element
    lea rdi, [tbs_hash]
    mov rsi, [sig_parts + 16]
    mov rdx, [sig_parts + 24]
    lea rcx, [leaf_pub]
    call linnea_p256_ecdsa_verify_der
    test eax, eax
    jz .bad_sig
.sig_done:
.load_next:
    inc r12
    jmp .load
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.no_entropy:
    lea rdi, [msg_no_entropy]
    mov esi, msg_no_entropy_len
    jmp linnea_error_exit
.bad_usage:
    lea rdi, [msg_bad_usage]
    mov esi, msg_bad_usage_len
    jmp linnea_error_exit
.key_selfcontradictory:
    lea rdi, [msg_key_selfcontra]
    mov esi, msg_key_selfcontra_len
    jmp linnea_error_exit
.key_mismatch:
    lea rdi, [msg_key_mismatch]
    mov esi, msg_key_mismatch_len
    jmp linnea_error_exit
.bad_sig:
    lea rdi, [msg_bad_sig]
    mov esi, msg_bad_sig_len
    jmp linnea_error_exit
.bad_cert:
    lea rdi, [msg_bad_cert]
    mov esi, msg_bad_cert_len
    jmp linnea_error_exit
.bad_crit_ext:
    lea rdi, [msg_crit_ext]
    mov esi, msg_crit_ext_len
    jmp linnea_error_exit
.cert_big:
    lea rdi, [msg_cert_big]
    mov esi, msg_cert_big_len
    jmp linnea_error_exit
.bad_key:
    lea rdi, [msg_bad_key]
    mov esi, msg_bad_key_len
    jmp linnea_error_exit

; host_is_ip(rdi=name, rsi=len) -> eax = 1 when the text is an IP literal and
; not a DNS name: any ':' makes it IPv6, and digits-and-dots throughout makes
; it IPv4. Such a name cannot appear as a dNSName at all, so a certificate that
; omits it is not evidence of anything and must not draw a warning.
host_is_ip:
    xor eax, eax
    test rsi, rsi
    jz .hi_ret
    xor ecx, ecx
.hi_scan:
    cmp rcx, rsi
    jae .hi_yes                ; ran off the end having seen only digits/dots
    movzx edx, byte [rdi + rcx]
    cmp dl, ':'
    je .hi_yes
    cmp dl, '.'
    je .hi_next
    cmp dl, '0'
    jb .hi_ret
    cmp dl, '9'
    ja .hi_ret
.hi_next:
    inc rcx
    jmp .hi_scan
.hi_yes:
    mov eax, 1
.hi_ret:
    ret

; cpuid_check_aesni — abort unless CPUID leaf 1 reports everything
; linnea_aesgcm.asm actually uses: AES-NI (ECX bit 25) for the block
; cipher, PCLMULQDQ (ECX bit 1) for GHASH, and SSSE3 (ECX bit 9) for the
; pshufb byteswaps. Any CPU with AES-NI has had SSSE3 since Westmere, so
; the last bit never fails in practice — it is here so the gate names the
; real requirements rather than a subset of them.
%define AESGCM_CPU_BITS ((1 << 25) | (1 << 9) | (1 << 1))
cpuid_check_aesni:
    push rbx                   ; cpuid clobbers rbx (callee-saved)
    mov eax, 1
    xor ecx, ecx
    cpuid
    and ecx, AESGCM_CPU_BITS
    cmp ecx, AESGCM_CPU_BITS
    jne .missing
    pop rbx
    ret
.missing:
    pop rbx
    lea rdi, [msg_no_aesni]
    mov esi, msg_no_aesni_len
    jmp linnea_error_exit

; ---- linnea_ktls_enable(rdi=fd, rsi=s_ap secret, rdx=c_ap secret,
;                         rcx=tx_seq, r8=rx_seq) -> rax 0 ok / -1 -------
; Attach kTLS and install the AES-128-GCM application keys for both
; directions. tx_seq/rx_seq are the next record sequence numbers (the
; server's is 0; the client's is however many app records were already
; consumed in userspace before the handoff).
%define K_FD    0
%define K_SAP   8
%define K_CAP   16
%define K_TXSEQ 24
%define K_RXSEQ 32
%define K_INFO  48       ; 40-byte crypto_info scratch
%define K_KEYIV 96       ; 16-byte key + 12-byte iv scratch
; 2 pushes + this sub keeps rsp 16-aligned at the internal call sites
%define K_FRAME 136

linnea_ktls_enable:
    push rbx
    push r12
    sub rsp, K_FRAME
    mov [rsp + K_FD], rdi
    mov [rsp + K_SAP], rsi
    mov [rsp + K_CAP], rdx
    mov [rsp + K_TXSEQ], rcx
    mov [rsp + K_RXSEQ], r8

    ; setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 4) — attach the kernel ULP
    mov qword [linnea_ktls_fail_step], 1
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov edi, [rsp + K_FD]
    mov esi, LINNEA_SOL_TCP
    mov edx, LINNEA_TCP_ULP
    lea r10, [ulp_tls]
    mov r8d, 4
    syscall
    test rax, rax
    js .fail

    ; TX: the server application traffic secret, seq = tx_seq
    mov qword [linnea_ktls_fail_step], 2
    mov rdi, [rsp + K_SAP]
    mov rsi, [rsp + K_TXSEQ]
    mov edx, LINNEA_TLS_TX
    mov ecx, [rsp + K_FD]
    lea r8, [rsp + K_INFO]
    lea r9, [rsp + K_KEYIV]
    call install_direction
    test rax, rax
    js .fail

    ; RX: the client application traffic secret, seq = rx_seq
    mov qword [linnea_ktls_fail_step], 3
    mov rdi, [rsp + K_CAP]
    mov rsi, [rsp + K_RXSEQ]
    mov edx, LINNEA_TLS_RX
    mov ecx, [rsp + K_FD]
    lea r8, [rsp + K_INFO]
    lea r9, [rsp + K_KEYIV]
    call install_direction
    test rax, rax
    js .fail

    xor eax, eax
    mov qword [linnea_ktls_fail_step], 0
    jmp .ret
.fail:
    mov [linnea_ktls_fail_errno], rax   ; keep the errno: the caller logs it
    mov rax, -1
.ret:
    add rsp, K_FRAME
    pop r12
    pop rbx
    ret

; install_direction(rdi=secret, rsi=seq, edx=TLS_TX/TLS_RX, ecx=fd,
;                   r8=info40 scratch, r9=keyiv28 scratch)
; -> rax = setsockopt result. Derives the traffic key+iv, assembles the
; struct tls12_crypto_info_aes_gcm_128, and installs it.
install_direction:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8                 ; an even number of pushes leaves rsp 8 off:
                               ; pad so the expand-label calls below land on
                               ; a 16-aligned rsp, as the ABI requires
    mov rbx, rdi               ; traffic secret
    mov r12, rsi               ; seq
    mov r13d, edx              ; direction
    mov r14d, ecx              ; fd
    mov r15, r8                ; crypto_info scratch
    mov rbp, r9                ; key||iv scratch

    ; key = HKDF-Expand-Label(secret, "key", 16) -> keyiv[0:16]
    mov rdi, rbx
    lea rsi, [lbl_key]
    mov edx, 3
    xor ecx, ecx
    xor r8d, r8d
    mov r9, rbp
    sub rsp, 16
    mov qword [rsp], 16
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; iv = HKDF-Expand-Label(secret, "iv", 12) -> keyiv[16:28]
    mov rdi, rbx
    lea rsi, [lbl_iv]
    mov edx, 2
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rbp + 16]
    sub rsp, 16
    mov qword [rsp], 12
    call linnea_tls_hkdf_expand_label
    add rsp, 16

    ; assemble struct tls12_crypto_info_aes_gcm_128
    mov word [r15], LINNEA_TLS_1_3_VERSION
    mov word [r15 + 2], LINNEA_TLS_CIPHER_AES_GCM_128
    mov eax, [rbp + 16]        ; salt = iv[0:4]
    mov [r15 + 28], eax
    mov eax, [rbp + 20]        ; explicit nonce = iv[4:8]
    mov [r15 + 4], eax
    mov eax, [rbp + 24]        ; iv[8:12]
    mov [r15 + 8], eax
    mov rax, [rbp]             ; key[0:8]
    mov [r15 + 12], rax
    mov rax, [rbp + 8]         ; key[8:16]
    mov [r15 + 20], rax
    mov rax, r12              ; rec_seq, big-endian
    bswap rax
    mov [r15 + 32], rax

    mov eax, LINNEA_SYS_SETSOCKOPT
    mov edi, r14d
    mov esi, LINNEA_SOL_TLS
    mov edx, r13d
    mov r10, r15
    mov r8d, LINNEA_TLS_CRYPTO_INFO_SIZE
    syscall
    add rsp, 8                 ; the alignment pad
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; linnea_ktls_rekey_rx(rdi = fd, rsi = the client application traffic secret)
; linnea_ktls_rekey_tx(rdi = fd, rsi = the server application traffic secret)
;   -> rax = 0 installed, -1 setsockopt refused. The secret is ADVANCED IN PLACE
;   on success, so the next KeyUpdate derives from the right generation.
;
; RFC 8446 7.2: after a KeyUpdate the peer's next traffic secret is
;   application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", 32)
; and 5.3 restarts that direction's record sequence number at 0 with it.
;
; Installing a second RX key on a socket that already has one is precisely what
; mainline kTLS used to refuse with -EBUSY. Measured on this box (kernel 7.0.8):
; the second setsockopt returns 0 and the kernel decrypts the following records
; under the new key. That measurement is what unblocked this; if a kernel ever
; refuses, the caller closes the connection, which is exactly what it did before.
linnea_ktls_rekey_tx:
    mov r10d, LINNEA_TLS_TX
    jmp rekey_body
linnea_ktls_rekey_rx:
    mov r10d, LINNEA_TLS_RX
rekey_body:
    push rbx
    push r12
    push r13
    push r14                          ; an even number of pushes: the frame below
                                      ; keeps rsp 16-aligned for the calls
    mov r13d, r10d                    ; the direction to install
    sub rsp, 112                      ; 32 next secret | 40 crypto_info | 28 key||iv
                                      ; (112 keeps rsp 16-aligned through the calls)
    mov r12d, edi                     ; fd
    mov rbx, rsi                      ; the caller's secret, advanced at the end
    ; next = HKDF-Expand-Label(secret, "traffic upd", "", 32)
    mov rdi, rbx
    lea rsi, [lbl_traffic_upd]
    mov edx, lbl_traffic_upd_len
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; install it for the receive direction, sequence number back to 0
    lea rdi, [rsp]                    ; the next secret
    xor esi, esi                      ; seq 0 (RFC 8446 5.3)
    mov edx, r13d
    mov ecx, r12d
    lea r8, [rsp + 32]                ; crypto_info scratch
    lea r9, [rsp + 72]                ; key||iv scratch
    call install_direction
    test rax, rax
    js .rk_fail
    ; only now adopt it: a refused install leaves the connection on the old
    ; secret, which is still the one the kernel is using
    mov rdi, rbx
    lea rsi, [rsp]
    mov ecx, 32
    rep movsb
    xor eax, eax
    jmp .rk_ret
.rk_fail:
    mov rax, -1
.rk_ret:
    add rsp, 112
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_ktls_key_update(edi = fd) -> rax = sendmsg result.
; Send a KeyUpdate with request_update = update_not_requested (RFC 8446 4.6.3):
; handshake message 0x18, 3-byte length 1, one payload byte 0. It rides a
; HANDSHAKE record, which with kTLS means naming the type in a control message
; exactly as close_notify names the alert type.
;
; SAME CALLER CONTRACT AS close_notify, and for a sharper reason: this record
; says "everything after this comes under my next key", so it must not be
; interleaved with a send the kernel is still framing, and the transmit key must
; not turn over until it is out. The caller proves the socket is quiet
; (tx_inflight == 0) before calling.
;
; Layout: msghdr(56) | iovec(16) | cmsghdr+data(24) | payload(5).
linnea_ktls_key_update:
    push rbx
    mov ebx, edi                      ; fd
    sub rsp, 112
    mov byte [rsp + 96], 0x18         ; key_update
    mov byte [rsp + 97], 0x00         ; length, 3 bytes big-endian
    mov byte [rsp + 98], 0x00
    mov byte [rsp + 99], 0x01
    mov byte [rsp + 100], 0x00        ; update_not_requested: answering a request
                                      ; with another request would loop forever
    lea rax, [rsp + 96]
    mov [rsp + 56], rax               ; iov_base
    mov qword [rsp + 64], 5           ; iov_len
    mov qword [rsp + 72], 17          ; cmsg_len = CMSG_LEN(1)
    mov dword [rsp + 80], LINNEA_SOL_TLS
    mov dword [rsp + 84], LINNEA_TLS_SET_RECORD_TYPE
    mov byte [rsp + 88], LINNEA_TLS_REC_HANDSHAKE
    mov qword [rsp + 0], 0            ; msg_name
    mov dword [rsp + 8], 0            ; msg_namelen
    lea rax, [rsp + 56]
    mov [rsp + 16], rax               ; msg_iov
    mov qword [rsp + 24], 1           ; msg_iovlen
    lea rax, [rsp + 72]
    mov [rsp + 32], rax               ; msg_control
    mov qword [rsp + 40], 24          ; msg_controllen = CMSG_SPACE(1)
    mov dword [rsp + 48], 0           ; msg_flags
    mov eax, LINNEA_SYS_SENDMSG
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, LINNEA_MSG_NOSIGNAL      ; NOT MSG_DONTWAIT: a short write here would
                                      ; leave the peer expecting a key change that
                                      ; never fully arrived. Five bytes, and the
                                      ; caller only reaches here with the socket
                                      ; quiet, so blocking is not a real risk.
    syscall
    add rsp, 112
    pop rbx
    ret

; linnea_ktls_close_notify(edi = fd) — send a TLS close_notify alert.
;
; RFC 8446 6.1 MUST: "Each party MUST send a close_notify alert before closing
; its write side of the connection." Without it every connection ends as a
; truncation from the peer's point of view, and a response that is neither
; length- nor chunk-delimited has no defence against a truncation attack.
;
; With kTLS the kernel builds the record, so send() can only emit application
; data; the record type rides in a control message instead.
;
; The CALLER owns the one thing that makes this safe: it must run only where no
; other send is outstanding on this socket. Interleaving an alert with a send
; the kernel is still framing splices it into the middle of a record, and the
; peer sees corruption rather than a goodbye.
;
; Layout: msghdr(56) | iovec(16) | cmsghdr+data(24) | payload(2).
linnea_ktls_close_notify:
    push rbx
    mov ebx, edi                      ; fd
    sub rsp, 112
    mov byte [rsp + 96], 1            ; legacy level "warning" (8446 6 ignores it)
    mov byte [rsp + 97], LINNEA_TLS_A_CLOSE_NOTIFY
    lea rax, [rsp + 96]
    mov [rsp + 56], rax               ; iov_base
    mov qword [rsp + 64], 2           ; iov_len
    mov qword [rsp + 72], 17          ; cmsg_len = CMSG_LEN(1)
    mov dword [rsp + 80], LINNEA_SOL_TLS
    mov dword [rsp + 84], LINNEA_TLS_SET_RECORD_TYPE
    mov byte [rsp + 88], LINNEA_TLS_CT_ALERT
    mov qword [rsp + 0], 0            ; msg_name
    mov dword [rsp + 8], 0            ; msg_namelen
    lea rax, [rsp + 56]
    mov [rsp + 16], rax               ; msg_iov
    mov qword [rsp + 24], 1           ; msg_iovlen
    lea rax, [rsp + 72]
    mov [rsp + 32], rax               ; msg_control
    mov qword [rsp + 40], 24          ; msg_controllen = CMSG_SPACE(1)
    mov dword [rsp + 48], 0           ; msg_flags
    mov eax, LINNEA_SYS_SENDMSG
    mov edi, ebx
    lea rsi, [rsp]
    ; MSG_NOSIGNAL is load-bearing, not tidiness. The whole point of this call is
    ; that the connection is ending, and the peer is very often gone already —
    ; it reset the stream, or hung up first. Without the flag that write raises
    ; SIGPIPE, whose default action kills the worker. MSG_DONTWAIT because a
    ; full send buffer is not worth stalling the event loop over.
    mov edx, LINNEA_MSG_DONTWAIT | LINNEA_MSG_NOSIGNAL
    syscall
    add rsp, 112
    pop rbx
    ret
