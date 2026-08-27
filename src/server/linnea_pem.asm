; linnea_pem.asm — minimal PEM decoding for the cert chain and key.
;
; linnea_pem_decode finds a "-----BEGIN <name>-----" / "-----END-----"
; block and base64-decodes its body (skipping any whitespace) into the
; caller's buffer. linnea_pem_cert_list decodes every CERTIFICATE block
; in a file — leaf first, then the chain, the order PEM chain files are
; written in — into a pre-framed TLS 1.3 certificate_list.
; linnea_pem_p256_key decodes a PKCS#8 "PRIVATE KEY" block and walks its
; DER to the 32-byte P-256 private scalar.
;
; Deliberately not a general PEM/DER parser: linnea only ever loads its
; own operator-supplied files, one cert chain and one key. Errors are -1
; (no matching BEGIN block) or -2 (a block that is malformed or overflows
; the buffer); the caller turns both into a startup error_exit.
;
; ABI: System V; callee-saved preserved.

default rel

global linnea_pem_decode
global linnea_pem_cert_list
global linnea_pem_p256_key
global linnea_x509_find_spki
global linnea_x509_cert_wellformed
global linnea_x509_leaf_spki
global linnea_x509_spki_point

section .rodata

begin_pfx:  db "-----BEGIN "
begin_len   equ $ - begin_pfx
end_pfx:    db "-----END "
end_len     equ $ - end_pfx
dashes5:    db "-----"

section .bss

alignb 8
b64_table:  resb 256          ; ASCII -> 6-bit value, 0xff for non-alphabet
key_buf:    resb 256          ; decoded PKCS#8 EC key; the real thing is
key_buf_cap equ 256           ; ~138 bytes with the optional public key

section .text

; ---- linnea_pem_decode(rdi=src, rsi=srclen, rdx=name, rcx=namelen,
;      r8=out, r9=outcap) -> rax = DER length, or -1 when no BEGIN <name>
;      block exists, -2 when a block is malformed or outgrows outcap.
;      On success rdx points just past the decoded body (at or before its
;      END line): the resume point for scanning a multi-block file. -----
linnea_pem_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rdi              ; src cursor
    lea r13, [rdi + rsi]      ; src end
    mov r14, rdx              ; name
    mov r15, rcx              ; namelen
    mov rbp, r8               ; out
    mov r12, r9               ; outcap

    ; find "-----BEGIN <name>-----"
    lea rdi, [begin_pfx]
    mov rsi, begin_len
    call find_bytes
    test rax, rax
    js .nofind
    add rbx, begin_len
    lea rax, [rbx + r15]     ; bytes_eq has no end check, so bound it here:
    cmp rax, r13             ; a truncated file (no mmap zero-fill tail when the
    ja .bad                  ; size is a page multiple) would else read past it
    mov rdi, rbx             ; the name must follow immediately
    mov rsi, r14
    mov rcx, r15
    call bytes_eq
    test eax, eax
    jz .bad
    add rbx, r15
    lea rax, [rbx + 5]
    cmp rax, r13
    ja .bad
    mov rdi, rbx             ; ...and then the closing dashes
    lea rsi, [dashes5]
    mov rcx, 5
    call bytes_eq
    test eax, eax
    jz .bad
    add rbx, 5

    call build_b64_table

    ; base64-decode until "-----END", accumulating bits
    xor r8d, r8d             ; bit accumulator
    xor r9d, r9d             ; bits held
    xor r10d, r10d           ; output length
.loop:
    cmp rbx, r13
    jae .bad                 ; ran out before the END marker
    ; is this the start of the END line? (only meaningful at column-ish
    ; positions, but '-' never appears in base64 so a plain check is safe)
    cmp byte [rbx], '-'
    jne .decode
    lea rax, [rbx + end_len]    ; not enough bytes left to be "-----END": it is
    cmp rax, r13               ; data, not the marker (and bytes_eq is unbounded)
    ja .decode
    mov rdi, rbx
    lea rsi, [end_pfx]
    mov rcx, end_len
    call bytes_eq
    test eax, eax
    jnz .end_boundary
.decode:
    movzx eax, byte [rbx]
    inc rbx
    cmp al, '='
    je .pad                  ; padding ends the DATA, not the encapsulation
    movzx eax, byte [b64_table + rax]
    cmp al, 0xff
    je .loop                 ; whitespace / newline
    shl r8d, 6
    or r8d, eax
    add r9d, 6
    cmp r9d, 8
    jb .loop
    sub r9d, 8
    mov ecx, r9d
    mov eax, r8d
    shr eax, cl              ; take the top 8 completed bits
    cmp r10, r12
    jae .bad                 ; would overflow the caller's buffer
    mov [rbp + r10], al
    inc r10
    jmp .loop
; RFC 7468 2-3: the encapsulated text is followed by a post-encapsulation
; boundary -- "-----END ", a label, and exactly five dashes. Neither half of the
; old completion checked for one: the first '=' returned success outright, and
; the nine-byte "-----END " prefix was accepted with no closing dashes. So a
; file whose END line was replaced by "=", or truncated to "-----END PRIVATE
; KEY", decoded as a complete credential (audit-report-99 F3). The label is NOT
; compared: RFC 7468's lax grammar tolerates a mismatched END label, and
; tightening that would reject files other tools accept.
.pad:
    ; How much padding is legal is decided by the FINAL QUANTUM, not by taste.
    ; r9d holds the leftover bits: 4 after two data symbols (so "==" follows),
    ; 2 after three (so "="), and 0 or 6 mean the quantum cannot take padding
    ; at all. My report-99 fix skipped every '=' unconditionally, so four of
    ; them before the END line were accepted on a body needing none
    ; (audit-report-100 F3). rbx is already past the first '='.
    cmp r9d, 4
    je .pad_need2
    cmp r9d, 2
    jne .bad                 ; 0 or 6 leftover bits: no padding belongs here
    jmp .pad_tail            ; exactly one '=', and it is consumed
.pad_need2:
    ; the second '=' is required; a line break may separate them
    cmp rbx, r13
    jae .bad
    movzx eax, byte [rbx]
    cmp al, '='
    je .pad_two
    movzx ecx, byte [b64_table + rax]
    cmp cl, 0xff
    jne .bad
    inc rbx
    jmp .pad_need2
.pad_two:
    inc rbx
.pad_tail:
    ; only whitespace, then the boundary. A further '=' is more padding than
    ; the quantum can justify.
    cmp rbx, r13
    jae .bad
    movzx eax, byte [rbx]
    cmp al, '-'
    je .at_dash
    cmp al, '='
    je .bad
    movzx ecx, byte [b64_table + rax]
    cmp cl, 0xff
    jne .bad                 ; base64 payload after the padding
    inc rbx
    jmp .pad_tail
.at_dash:
    lea rax, [rbx + end_len]
    cmp rax, r13
    ja .bad
    mov rdi, rbx
    lea rsi, [end_pfx]
    mov rcx, end_len
    call bytes_eq
    test eax, eax
    jz .bad
.end_boundary:
    ; past "-----END ", skip the label and require its five closing dashes
    lea rdi, [rbx + end_len]
    xor ecx, ecx
.eb_scan:
    cmp ecx, 80              ; longest label we will look past
    ja .bad
    lea rax, [rdi + 5]
    cmp rax, r13
    ja .bad                  ; no room for "-----": a truncated boundary
    cmp byte [rdi], 10       ; a line end before the dashes: truncated
    je .bad
    push rdi
    push rcx
    lea rsi, [dashes5]
    mov rcx, 5
    call bytes_eq
    pop rcx
    pop rdi
    test eax, eax
    jnz .done
    inc rdi
    inc ecx
    jmp .eb_scan
.done:
    mov rax, r10
    mov rdx, rbx             ; resume point for the next block
    jmp .ret
.nofind:
    mov rax, -1
    jmp .ret
.bad:
    mov rax, -2
.ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- linnea_pem_cert_list(rdi=src, rsi=srclen, rdx=out, rcx=outcap)
;      -> rax = certificate_list length, or -1 / -2 as linnea_pem_decode.
;
;      Decodes every CERTIFICATE block and emits each as a TLS 1.3
;      CertificateEntry (RFC 8446 4.4.2): u24 DER length, the DER, and an
;      empty (u16 0) extensions block. The result is the certificate_list
;      body, copied verbatim into the Certificate handshake message. At
;      least one block is required; the file's order (leaf first, then
;      the chain) is the order the wire wants. --------------------------
linnea_pem_cert_list:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi              ; src cursor
    lea r13, [rdi + rsi]      ; src end
    mov r14, rdx              ; out
    mov r15, rcx              ; outcap
    xor ebx, ebx              ; list length so far
.next:
    lea rax, [rbx + 5]        ; this entry's framing: u24 length + u16 ext
    cmp rax, r15
    ja .bad
    mov rdi, r12
    mov rsi, r13
    sub rsi, r12              ; source bytes left
    lea rdx, [cert_name]
    mov ecx, cert_name_len
    lea r8, [r14 + rbx + 3]   ; the DER lands after its u24 length
    mov r9, r15
    sub r9, rax               ; room left after the framing
    call linnea_pem_decode
    test rax, rax
    js .no_more
    jz .bad                   ; an empty CERTIFICATE block: malformed (-2)
    ; EVERY entry must be a structurally complete Certificate, not just the
    ; leaf. Only the leaf gets the key-pairing check, so a malformed
    ; INTERMEDIATE used to be framed and sent unexamined -- and the
    ; intermediate is exactly what a renewal half-writes
    ; (audit-report-100 F2). Issuers may use other algorithms and have no
    ; configured key, so this is syntax only.
    push rax
    push rdx
    lea rdi, [r14 + rbx + 3]  ; the DER: recomputed, because linnea_pem_decode
    mov rsi, rax              ; takes r8 as its own out pointer and clobbers it
    call linnea_x509_cert_wellformed
    test eax, eax
    pop rdx
    pop rax
    jz .bad
    mov r12, rdx              ; resume past this block
    mov ecx, eax              ; u24 DER length, big-endian
    shr ecx, 16
    mov [r14 + rbx], cl
    mov ecx, eax
    shr ecx, 8
    mov [r14 + rbx + 1], cl
    mov [r14 + rbx + 2], al
    lea rcx, [r14 + rbx]
    mov word [rcx + rax + 3], 0    ; per-certificate extensions: none
    lea rbx, [rbx + rax + 5]
    jmp .next
.no_more:
    cmp rax, -2
    je .ret                   ; a malformed block: propagate
    test rbx, rbx
    jz .ret                   ; no CERTIFICATE block at all: rax = -1
    mov rax, rbx
    jmp .ret
.bad:
    mov rax, -2
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

section .rodata
cert_name:    db "CERTIFICATE"
cert_name_len equ $ - cert_name
section .text

; ---- p256_der_open(rdi=p, rsi=end, edx=tag) -> rax = content ptr or -1,
;      rcx = content length. Checks the tag, decodes the length, and
;      verifies the content fits within end.
;
;      Short form and the 0x81 long form only. A P-256 PKCS#8 key is about
;      140 bytes, so a length that needs two or more bytes is malformed
;      rather than merely unsupported, and a 0x81 carrying a value below 128
;      is non-minimal DER. Both are rejected. ------------------------------
p256_der_open:
    push rbx
    mov rbx, rsi
    sub rbx, rdi
    cmp rbx, 2
    jb .bad
    movzx eax, byte [rdi]
    cmp eax, edx
    jne .bad
    movzx ecx, byte [rdi + 1]
    lea rax, [rdi + 2]
    cmp ecx, 0x80
    jb .have                  ; short form: the byte is the length
    cmp ecx, 0x81
    jne .bad
    cmp rbx, 3
    jb .bad
    movzx ecx, byte [rdi + 2]
    cmp ecx, 0x80
    jb .bad                   ; 0x81 with a short value: not minimal
    lea rax, [rdi + 3]
.have:
    mov rbx, rsi
    sub rbx, rax
    cmp rbx, rcx              ; content must fit inside end
    jb .bad
    pop rbx
    ret
.bad:
    mov rax, -1
    xor ecx, ecx
    pop rbx
    ret

; ---- linnea_pem_p256_key(rdi=src, rsi=srclen) -> rax = pointer to the
;      32-byte private scalar, or -1. The pointer is into a static buffer.
;
;      Walks the PKCS#8 structure rather than comparing a fixed prefix: an
;      EC key's inner SEC1 ECPrivateKey carries an OPTIONAL [1] public key,
;      and whether the generator emits it shifts every length byte before the
;      scalar. A prefix compare would accept keys from `openssl genpkey` and
;      reject otherwise valid ones that omit it.
;
;        SEQUENCE                          PrivateKeyInfo
;          INTEGER 0                       version
;          SEQUENCE                        AlgorithmIdentifier
;            OID id-ecPublicKey, OID prime256v1
;          OCTET STRING                    privateKey, wrapping:
;            SEQUENCE                      SEC1 ECPrivateKey
;              INTEGER 1                   version
;              OCTET STRING (32)           <- the scalar
;              [1] BIT STRING              publicKey, optional, ignored
;
;      The curve is pinned by the AlgorithmIdentifier compare: a P-384 or
;      secp256k1 key is refused here rather than being silently misused. ---
linnea_pem_p256_key:
    push rbx
    push r12
    push r13
    lea rdx, [pk_name]
    mov rcx, pk_name_len
    lea r8, [key_buf]
    mov r9, key_buf_cap
    call linnea_pem_decode
    cmp rax, 0
    jl .fail

    lea rbx, [key_buf]
    lea r13, [key_buf + rax]

    mov rdi, rbx                    ; SEQUENCE PrivateKeyInfo
    mov rsi, r13
    mov edx, 0x30
    call p256_der_open
    cmp rax, -1
    je .fail
    mov rbx, rax
    lea r13, [rax + rcx]

    mov rdi, rbx                    ; INTEGER 0
    mov rsi, r13
    mov edx, 0x02
    call p256_der_open
    cmp rax, -1
    je .fail
    cmp rcx, 1
    jne .fail
    cmp byte [rax], 0
    jne .fail
    lea rbx, [rax + rcx]

    mov rdi, rbx                    ; SEQUENCE AlgorithmIdentifier
    mov rsi, r13
    mov edx, 0x30
    call p256_der_open
    cmp rax, -1
    je .fail
    lea r12, [rax + rcx]            ; where the next element begins
    cmp rcx, alg_ec_len
    jne .fail
    mov rdi, rax
    lea rsi, [alg_ec]
    mov rcx, alg_ec_len
    call bytes_eq
    test eax, eax
    jz .fail
    mov rbx, r12

    mov rdi, rbx                    ; OCTET STRING privateKey
    mov rsi, r13
    mov edx, 0x04
    call p256_der_open
    cmp rax, -1
    je .fail
    mov rbx, rax
    lea r13, [rax + rcx]

    mov rdi, rbx                    ; SEQUENCE ECPrivateKey
    mov rsi, r13
    mov edx, 0x30
    call p256_der_open
    cmp rax, -1
    je .fail
    mov rbx, rax
    lea r13, [rax + rcx]

    mov rdi, rbx                    ; INTEGER 1
    mov rsi, r13
    mov edx, 0x02
    call p256_der_open
    cmp rax, -1
    je .fail
    cmp rcx, 1
    jne .fail
    cmp byte [rax], 1
    jne .fail
    lea rbx, [rax + rcx]

    mov rdi, rbx                    ; OCTET STRING, the scalar
    mov rsi, r13
    mov edx, 0x04
    call p256_der_open
    cmp rax, -1
    je .fail
    cmp rcx, 32                     ; SEC1 fixes this at ceil(log2 n / 8)
    jne .fail
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

; ---- X.509 leaf-certificate public-key extraction (for backend TLS: pinning
;      a server's cert and verifying its CertificateVerify). Client-side, and
;      unlike everything above it parses an UNTRUSTED certificate, so it bounds
;      every length against the input and rejects anything it does not expect.
;      Still deliberately narrow: it finds the SubjectPublicKeyInfo and reads a
;      prime256v1 point; it does not validate a chain, dates, or names -- the
;      SPKI PIN is the trust decision (see docs/design/tls-client-handshake-plan.md).

; der_any(rdi=p, rsi=end, edx unused) -> rax = content ptr (or -1),
;   rcx = content length, dl = tag. DER TLV with the short, 0x81 and 0x82
;   length forms (X.509 needs 0x82); non-minimal long forms and content that
;   overruns end are rejected. File-local. Clobbers rax rcx rdx r8.
der_any:
    push rbx
    mov rbx, rsi
    sub rbx, rdi                 ; bytes available
    cmp rbx, 2
    jb .bad
    movzx edx, byte [rdi]        ; tag -> dl
    movzx ecx, byte [rdi + 1]
    lea rax, [rdi + 2]
    cmp ecx, 0x80
    jb .have                     ; short form: the byte is the length
    cmp ecx, 0x81
    je .len1
    cmp ecx, 0x82
    je .len2
    jmp .bad                     ; 0x83+ unsupported and unneeded for a cert
.len1:
    cmp rbx, 3
    jb .bad
    movzx ecx, byte [rdi + 2]
    cmp ecx, 0x80
    jb .bad                      ; 0x81 with a value < 128: non-minimal
    lea rax, [rdi + 3]
    jmp .have
.len2:
    cmp rbx, 4
    jb .bad
    movzx ecx, byte [rdi + 2]
    shl ecx, 8
    movzx r8d, byte [rdi + 3]
    or ecx, r8d
    cmp ecx, 0x100
    jb .bad                      ; 0x82 with a value < 256: non-minimal
    lea rax, [rdi + 4]
.have:
    mov rbx, rsi
    sub rbx, rax                 ; content bytes available
    cmp rbx, rcx
    jb .bad                      ; content overruns end
    pop rbx
    ret
.bad:
    mov rax, -1
    xor ecx, ecx
    xor edx, edx
    pop rbx
    ret

; ---- der_tiles(rdi=content, rsi=end) -> rax = 1 when the range is exactly
;      covered by complete TLVs, else 0. A SEQUENCE whose tag and length are
;      right can still hold rubbish; this is what makes "it is a SEQUENCE" into
;      "it is a well-formed container" (audit-report-102). Preserves rbx/r12+.
der_tiles:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
.dt_next:
    cmp rbx, r12
    je .dt_yes                       ; landed exactly on the end
    ja .dt_no                        ; a child overran it
    mov rdi, rbx
    mov rsi, r12
    call der_any
    cmp rax, -1
    je .dt_no
    lea rbx, [rax + rcx]
    jmp .dt_next
.dt_yes:
    mov eax, 1
    pop r12
    pop rbx
    ret
.dt_no:
    xor eax, eax
    pop r12
    pop rbx
    ret

; ---- tbs_walk(rdi=der, rsi=len) -> rax = the SubjectPublicKeyInfo element,
;      rdx = its length; rax = 0 if these bytes are not a structurally valid
;      X.509 Certificate. File-local; the two public entry points below share it
;      so they cannot drift apart (audit-report-101).
;
;      RFC 5280 4.1: Certificate ::= SEQUENCE { tbsCertificate, AlgorithmIdentifier,
;      BIT STRING }, and 4.1.2: TBSCertificate ::= SEQUENCE { [0] version OPTIONAL,
;      INTEGER serialNumber, SEQUENCE signature, SEQUENCE issuer, SEQUENCE
;      validity, SEQUENCE subject, SEQUENCE subjectPublicKeyInfo, ... }.
;
;      The TYPES are checked, not just the count: stepping over six anonymous
;      TLVs accepted a serialNumber retagged as an OCTET STRING, because a
;      bounded TLV of any tag still advances the cursor (audit-report-101 F1).
;      Algorithm-independent on purpose -- issuers need not be P-256, so the
;      key-algorithm check belongs to the leaf entry point, not here.
tbs_walk:
    push rbx
    push r12
    push r13
    push r14
    lea r13, [rdi + rsi]             ; entry end
    mov rsi, r13
    call der_any                     ; Certificate
    cmp rax, -1
    je .tw_no
    cmp dl, 0x30
    jne .tw_no
    lea rbx, [rax + rcx]
    cmp rbx, r13
    jne .tw_no                       ; trailing bytes after the Certificate
    mov rdi, rax
    mov rsi, rbx
    call der_any                     ; tbsCertificate
    cmp rax, -1
    je .tw_no
    cmp dl, 0x30
    jne .tw_no
    mov r12, rax                     ; TBS content
    mov r14, rcx                     ; TBS length
    ; --- the outer signatureAlgorithm and signatureValue -------------------
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; signatureAlgorithm
    cmp rax, -1
    je .tw_no
    cmp dl, 0x30
    jne .tw_no
    test rcx, rcx
    jz .tw_no                        ; an empty AlgorithmIdentifier
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; signatureValue
    cmp rax, -1
    je .tw_no
    cmp dl, 0x03                     ; BIT STRING
    jne .tw_no
    test rcx, rcx
    jz .tw_no                        ; no unused-bits octet at all
    cmp byte [rax], 8                ; that octet must be 0..7
    jae .tw_no
    cmp rcx, 1
    jbe .tw_no                       ; unused-bits octet and nothing signed
    lea rdi, [rax + rcx]
    cmp rdi, rbx
    jne .tw_no                       ; a fourth element: not a Certificate
    ; --- the TBSCertificate fields, by type -------------------------------
    lea rbx, [r12 + r14]             ; TBS content end
    mov rdi, r12
    mov rsi, rbx
    call der_any
    cmp rax, -1
    je .tw_no
    cmp dl, 0xa0                     ; [0] EXPLICIT version, optional
    jne .tw_serial                   ; absent: this element IS serialNumber
    ; Open it. RFC 5280 4.1.2.1: [0] EXPLICIT Version, an INTEGER of v1/v2/v3.
    ; The wrapper's content used to be skipped unopened, so a version retagged
    ; as an OCTET STRING -- or holding 9 -- passed (audit-report-102).
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call der_any                     ; the Version itself
    cmp rax, -1
    je .tw_no_pop2
    cmp dl, 0x02                     ; INTEGER
    jne .tw_no_pop2
    cmp rcx, 1                       ; one byte: v1/v2/v3 all fit
    jne .tw_no_pop2
    cmp byte [rax], 2                ; 0, 1 or 2
    ja .tw_no_pop2
    lea rdi, [rax + rcx]
    pop rcx
    pop rax
    lea rsi, [rax + rcx]
    cmp rdi, rsi
    jne .tw_no                       ; trailing bytes inside the [0] wrapper
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any
    cmp rax, -1
    je .tw_no
.tw_serial:
    cmp dl, 0x02                     ; serialNumber: INTEGER
    jne .tw_no
    ; signature, issuer, validity, subject -- each a SEQUENCE, and each opened.
    ; A right tag over rubbish is not a field (audit-report-102).
    mov r12d, 4
.tw_seq:
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any
    cmp rax, -1
    je .tw_no
    cmp dl, 0x30                     ; each of the four is a SEQUENCE
    jne .tw_no
    cmp r12d, 2
    je .tw_validity                  ; the third is Validity: two Times
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call der_tiles                   ; its children must tile it exactly
    test eax, eax
    pop rcx
    pop rax
    jz .tw_no
    jmp .tw_seq_next
.tw_validity:
    ; RFC 5280 4.1.2.5: exactly notBefore and notAfter, each UTCTime (0x17) or
    ; GeneralizedTime (0x18), filling the SEQUENCE.
    push rax
    push rcx
    lea r14, [rax + rcx]             ; validity end
    mov rdi, rax
    mov rsi, r14
    call der_any
    cmp rax, -1
    je .tw_no_pop2
    cmp dl, 0x17
    je .tw_v2
    cmp dl, 0x18
    jne .tw_no_pop2
.tw_v2:
    lea rdi, [rax + rcx]
    mov rsi, r14
    call der_any
    cmp rax, -1
    je .tw_no_pop2
    cmp dl, 0x17
    je .tw_vend
    cmp dl, 0x18
    jne .tw_no_pop2
.tw_vend:
    lea rdi, [rax + rcx]
    cmp rdi, r14
    jne .tw_no_pop2                  ; a third element in Validity
    pop rcx
    pop rax
.tw_seq_next:
    dec r12d
    jnz .tw_seq
    lea r14, [rax + rcx]             ; subjectPublicKeyInfo begins here
    mov rdi, r14
    mov rsi, rbx
    call der_any
    cmp rax, -1
    je .tw_no
    cmp dl, 0x30
    jne .tw_no
    lea rdx, [rax + rcx]
    sub rdx, r14                     ; its full length, header included
    mov rax, r14
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.tw_no_pop2:
    add rsp, 16                      ; drop the two saved words
.tw_no:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- linnea_x509_cert_wellformed(rdi=der, rsi=len) -> rax = 1 if the bytes are
;      a structurally complete X.509 Certificate, else 0. Applied to EVERY chain
;      entry, so it is algorithm-agnostic: an issuer may be RSA, or any curve.
;
;      Deliberately separate from linnea_x509_find_spki, which searches
;      untrusted PEER input for a pinned key and is right to be permissive about
;      everything else. This validates a LOCAL credential we are about to send
;      to every client, where "some child looked like an SPKI" is not evidence
;      that the surrounding bytes are a certificate (audit-report-100 F1). It
;      does no trust or hostname validation -- only syntax, which is all a
;      preflight can honestly promise.
linnea_x509_cert_wellformed:
    call tbs_walk
    test rax, rax
    jz .cw_no
    mov eax, 1
    ret
.cw_no:
    xor eax, eax
    ret

; ---- linnea_x509_leaf_spki(rdi=der, rsi=len) -> rax = SubjectPublicKeyInfo
;      pointer, rdx = its length; rax = 0 on failure.
;
;      POSITIONAL, not a search: the SPKI is the field RFC 5280 puts it in, so
;      an SPKI-shaped object sitting in another field is not mistaken for one.
;      And the declared algorithm MUST be id-ecPublicKey + prime256v1 -- the
;      first positional version dropped that comparison, which
;      linnea_x509_find_spki had always made, so a certificate declaring a
;      different curve over a P-256-sized point was accepted
;      (audit-report-101 F2). RFC 5280 4.1.2.7 binds the key to its algorithm;
;      the bytes are not ignorable metadata.
linnea_x509_leaf_spki:
    push rbx
    push r12
    call tbs_walk
    test rax, rax
    jz .ls_no
    mov rbx, rax                     ; SPKI element
    mov r12, rdx                     ; its length
    lea rsi, [rax + rdx]
    mov rdi, rax
    call der_any                     ; the SPKI SEQUENCE
    cmp rax, -1
    je .ls_no
    mov rdi, rax
    lea rsi, [rax + rcx]
    call der_any                     ; its AlgorithmIdentifier
    cmp rax, -1
    je .ls_no
    cmp dl, 0x30
    jne .ls_no
    cmp rcx, alg_ec_len
    jne .ls_no                       ; not exactly id-ecPublicKey + prime256v1
    mov rdi, rax
    lea rsi, [alg_ec]
    mov rcx, alg_ec_len
    call bytes_eq
    test eax, eax
    jz .ls_no
    mov rax, rbx
    mov rdx, r12
    pop r12
    pop rbx
    ret
.ls_no:
    xor eax, eax
    pop r12
    pop rbx
    ret

; ---- linnea_x509_find_spki(rdi=der, rsi=derlen) -> rax = pointer to the
;      SubjectPublicKeyInfo SEQUENCE (its tag byte) or 0, rdx = that element's
;      total length. Walks Certificate -> tbsCertificate and returns the child
;      SEQUENCE whose AlgorithmIdentifier is id-ecPublicKey + prime256v1. For
;      the pin, hash the returned span; for the key, pass it to
;      linnea_x509_spki_point. ---------------------------------------------
linnea_x509_find_spki:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea r15, [rdi + rsi]            ; der end
    mov rsi, r15
    call der_any                    ; Certificate SEQUENCE
    cmp rax, -1
    je .fail
    cmp dl, 0x30
    jne .fail
    mov rdi, rax                    ; Certificate body
    lea rbx, [rax + rcx]
    mov rsi, rbx
    call der_any                    ; tbsCertificate SEQUENCE
    cmp rax, -1
    je .fail
    cmp dl, 0x30
    jne .fail
    mov r12, rax                    ; tbs cursor
    lea r13, [rax + rcx]            ; tbs end
.iter:
    cmp r12, r13
    jae .fail
    mov rdi, r12
    mov rsi, r13
    call der_any
    cmp rax, -1
    je .fail
    mov rbx, rax                    ; element content start
    lea r14, [rax + rcx]            ; next element
    cmp dl, 0x30                    ; only a SEQUENCE can be the SPKI
    jne .adv
    mov rdi, rbx                    ; open its first child (AlgorithmIdentifier)
    mov rsi, r14
    call der_any
    cmp rax, -1
    je .adv
    cmp dl, 0x30
    jne .adv
    cmp rcx, alg_ec_len
    jne .adv
    mov rdi, rax
    lea rsi, [alg_ec]
    mov rcx, alg_ec_len
    call bytes_eq
    test eax, eax
    jz .adv
    mov rax, r12                    ; FOUND: the SPKI element is [r12, r14)
    mov rdx, r14
    sub rdx, r12
    jmp .ret
.adv:
    mov r12, r14
    jmp .iter
.fail:
    xor eax, eax
    xor edx, edx
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- linnea_x509_spki_point(rdi=spki, rsi=spkilen, rdx=out64) -> rax = 1 on
;      success (out64 gets the 64-byte X||Y), 0 on failure. The SPKI is
;      SEQUENCE { AlgorithmIdentifier, BIT STRING 00||04||X||Y }; only the
;      uncompressed prime256v1 point is accepted. ---------------------------
linnea_x509_spki_point:
    push rbx
    push r12
    mov r12, rdx                    ; out64
    lea rbx, [rdi + rsi]           ; spki end
    mov rsi, rbx
    call der_any                    ; SPKI SEQUENCE
    cmp rax, -1
    je .fail
    cmp dl, 0x30
    jne .fail
    mov rdi, rax                    ; SPKI body
    lea rbx, [rax + rcx]
    mov rsi, rbx
    call der_any                    ; skip AlgorithmIdentifier
    cmp rax, -1
    je .fail
    lea rdi, [rax + rcx]           ; -> BIT STRING
    mov rsi, rbx
    call der_any                    ; BIT STRING
    cmp rax, -1
    je .fail
    cmp dl, 0x03
    jne .fail
    cmp rcx, 66                    ; 00 unused-bits + 04 + X(32) + Y(32)
    jne .fail
    cmp byte [rax], 0x00
    jne .fail
    cmp byte [rax + 1], 0x04       ; uncompressed point only
    jne .fail
    lea rsi, [rax + 2]
    mov rdi, r12
    mov ecx, 64
    rep movsb
    mov eax, 1
    jmp .ret
.fail:
    xor eax, eax
.ret:
    pop r12
    pop rbx
    ret

section .rodata
; The AlgorithmIdentifier content for a prime256v1 key: OID id-ecPublicKey
; (1.2.840.10045.2.1) then OID prime256v1 (1.2.840.10045.3.1.7).
alg_ec:     db 0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01
            db 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07
alg_ec_len  equ $ - alg_ec
section .text

section .rodata
pk_name:    db "PRIVATE KEY"
pk_name_len equ $ - pk_name
section .text

; find_bytes(rdi=needle, rsi=needlelen, needle stays, rcx from bytes_eq) —
; scan [rbx, r13) for the needle; on success rbx points at the match and
; rax = 0, else rax = -1. Clobbers rax, rcx, r11 (not rbx on failure path
; leaves rbx at end).
find_bytes:
    mov r11, rsi             ; needlelen
.scan:
    mov rax, r13
    sub rax, rbx
    cmp rax, r11
    jb .miss
    push rdi
    push rsi
    mov rsi, rdi             ; needle
    mov rdi, rbx             ; haystack cursor
    mov rcx, r11
    call bytes_eq
    pop rsi
    pop rdi
    test eax, eax
    jnz .hit
    inc rbx
    jmp .scan
.hit:
    xor eax, eax
    ret
.miss:
    mov rax, -1
    ret

; bytes_eq(rdi=a, rsi=b, rcx=n) -> eax = 1 if equal. Preserves rdi/rsi.
bytes_eq:
    push rdi
    push rsi
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
    pop rsi
    pop rdi
    ret

; build_b64_table — fill b64_table: A-Z/a-z/0-9/+/ -> 0..63, else 0xff.
build_b64_table:
    lea rdi, [b64_table]
    mov eax, 0xff
    mov ecx, 256
    rep stosb
    lea rdi, [b64_table]
    xor ecx, ecx             ; value 0..63
.az:
    cmp ecx, 26
    jae .after_az
    mov byte [rdi + rcx + 'A'], cl
    inc ecx
    jmp .az
.after_az:
    xor ecx, ecx
.a_z:
    cmp ecx, 26
    jae .after_a_z
    lea eax, [ecx + 26]
    mov [rdi + rcx + 'a'], al
    inc ecx
    jmp .a_z
.after_a_z:
    xor ecx, ecx
.d09:
    cmp ecx, 10
    jae .after_09
    lea eax, [ecx + 52]
    mov [rdi + rcx + '0'], al
    inc ecx
    jmp .d09
.after_09:
    mov byte [b64_table + '+'], 62
    mov byte [b64_table + '/'], 63
    ret
