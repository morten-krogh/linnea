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
%include "linnea_tls.inc"

global linnea_tls_setup
global linnea_ktls_enable

extern linnea_file_map_readonly
extern linnea_file_unmap
extern linnea_pem_cert_list
extern linnea_pem_p256_key
extern linnea_tls_ticket_setup
extern linnea_p256_scalar_is_valid
extern linnea_tls_hkdf_expand_label
extern linnea_error_exit

section .rodata

ulp_tls:    db "tls", 0
lbl_key:    db "key"
lbl_iv:     db "iv"

msg_no_aesni: db "TLS requires a CPU with AES-NI, PCLMULQDQ and SSSE3"
msg_no_aesni_len equ $ - msg_no_aesni
msg_bad_cert: db "cannot load TLS certificate chain (not PEM CERTIFICATEs?)"
msg_bad_cert_len equ $ - msg_bad_cert
msg_bad_key:  db "cannot load TLS key (not a PKCS#8 P-256 key in [1, n-1]?)"
msg_bad_key_len equ $ - msg_bad_key
msg_cert_big: db "TLS certificate chain too large to fit the handshake flight"
msg_cert_big_len equ $ - msg_cert_big

; Decode scratch, deliberately looser than LINNEA_TLS_MAX_CERT_LIST so
; that a chain just over the limit is diagnosed as too large rather than
; as malformed (linnea_pem_cert_list reports overflow as any bad block).
MAX_CERT_LIST equ 8192

section .bss

alignb 8
cert_pool:  resb LINNEA_MAX_SERVERS * MAX_CERT_LIST
key_pool:  resb LINNEA_MAX_SERVERS * 32

section .text

; ---- linnea_tls_setup(rdi=config*) ----------------------------------
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
    call linnea_tls_ticket_setup

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
.bad_cert:
    lea rdi, [msg_bad_cert]
    mov esi, msg_bad_cert_len
    jmp linnea_error_exit
.cert_big:
    lea rdi, [msg_cert_big]
    mov esi, msg_cert_big_len
    jmp linnea_error_exit
.bad_key:
    lea rdi, [msg_bad_key]
    mov esi, msg_bad_key_len
    jmp linnea_error_exit

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
    jmp .ret
.fail:
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
