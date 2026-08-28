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
global linnea_pem_key_pub
global linnea_x509_find_spki
global linnea_x509_cert_wellformed
global linnea_x509_leaf_spki
global linnea_x509_leaf_usage_ok
global linnea_x509_leaf_validity_times
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

section .bss
; An optional SEC1 [1] publicKey, when the key file carries one. RFC 5915 3
; calls it "the EC public key associated with the private key in question", so
; it is not advisory: ktls proves the scalar signs for it (audit-report-105 F2).
key_pub:      resb 64
key_pub_set:  resq 1

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
    jnz .end_unpadded
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
    jmp .end_boundary               ; the PADDED path: its quantum was already
                                    ; checked, and r9d legitimately holds 2 or 4
.end_unpadded:
    ; Reached the boundary with NO padding, so the body must have ended on a
    ; whole four-symbol group: r9d is the bits still held, and anything but 0
    ; means a truncated final quantum. One stray symbol holds six bits and
    ; emits no byte, so the DER came out identical and every later check
    ; passed on text that is not valid Base64 (audit-report-106). Two or three
    ; strays were already caught, but only because they corrupted the DER --
    ; which is luck, not a check.
    test r9d, r9d
    jnz .bad
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

; ---- pk_attrs_ok(rdi=content, rsi=end) -> rax = 1 when the range is a PKCS#8
;      Attributes payload: zero or more Attribute ::= SEQUENCE { type OBJECT
;      IDENTIFIER, values SET OF AttributeValue }, tiling it exactly. The
;      wrapper used to be skipped whole, so any bounded bytes inside it passed
;      (audit-report-116).
;
;      The values SET is NOT required to be non-empty, though the report asks
;      for that: OpenSSL accepts an Attribute with an empty values SET, and
;      refusing a file the reference takes is the report-114 mistake. Measured,
;      not assumed. Preserves rbx/r12+.
pk_attrs_ok:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r13, rsi
.as_next:
    cmp rbx, r13
    je .as_yes
    ja .as_no
    mov rdi, rbx
    mov rsi, r13
    call der_any                     ; one Attribute
    cmp rax, -1
    je .as_no
    cmp dl, 0x30
    jne .as_no
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call pk_attr_one
    test eax, eax
    pop rcx
    pop rax
    jz .as_no
    lea rbx, [rax + rcx]
    jmp .as_next
.as_yes:
    mov eax, 1
    pop r13
    pop r12
    pop rbx
    ret
.as_no:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

; ---- pk_attr_one(rdi=content, rsi=end) -> rax = 1 for one Attribute's body.
pk_attr_one:
    push rbx
    mov rbx, rsi
    call der_any                     ; type
    cmp rax, -1
    je .a1_no
    cmp dl, 0x06
    jne .a1_no
    push rax
    push rcx
    mov rdi, rax
    mov rsi, rcx
    call oid_ok
    test eax, eax
    pop rcx
    pop rax
    jz .a1_no
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; values
    cmp rax, -1
    je .a1_no
    cmp dl, 0x31                     ; SET OF
    jne .a1_no
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call der_tiles                   ; its values must be complete elements
    test eax, eax
    pop rcx
    pop rax
    jz .a1_no
    lea rdi, [rax + rcx]
    cmp rdi, rbx
    jne .a1_no                       ; trailing bytes inside the Attribute
    mov eax, 1
    pop rbx
    ret
.a1_no:
    xor eax, eax
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
    push r14
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
    mov r14, r13                    ; the OUTER PrivateKeyInfo end. r13 is
                                    ; repurposed for the privateKey OCTET STRING
                                    ; below, so without this copy the outer
                                    ; sequence's remaining bytes were never
                                    ; looked at (audit-report-115).

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
    ; --- and the rest of ECPrivateKey, to its exact end -------------------
    ; RFC 5915 3: version, privateKey, [0] parameters OPTIONAL, [1] publicKey
    ; OPTIONAL. This returned the moment it had the scalar, so everything after
    ; it went unexamined and a [1] retagged as an OCTET STRING passed while
    ; OpenSSL refuses the file (audit-report-104). Ignoring an ABSENT optional
    ; field is not the same as accepting an ill-formed one.
    push rax                        ; the scalar, to return
    push rcx
    mov qword [key_pub_set], 0      ; no [1] seen yet for THIS key
    xor r12d, r12d                  ; bit 0 = [0] seen, bit 1 = [1] seen
    lea rbx, [rax + rcx]
.pk_tail:
    cmp rbx, r13
    jae .pk_end
    mov rdi, rbx
    mov rsi, r13
    call der_any
    cmp rax, -1
    je .pk_bad
    cmp dl, 0xa0
    je .pk_params
    cmp dl, 0xa1
    jne .pk_bad                     ; nothing else belongs in ECPrivateKey
    test r12d, 2
    jnz .pk_bad                     ; a second [1]
    or r12d, 2
    lea r10, [rax + rcx]            ; the [1] wrapper's content end
    ; [1] wraps a BIT STRING holding an uncompressed P-256 point. Accepting it
    ; unexamined is what the report objected to; it is checked structurally
    ; here, and the ktls pairing then proves the SCALAR signs for the
    ; certificate, which is the property that actually matters.
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call der_any
    cmp rax, -1
    je .pk_bad2
    cmp dl, 0x03                    ; BIT STRING
    jne .pk_bad2
    cmp rcx, 66                     ; 00 unused-bits + 04 + X(32) + Y(32)
    jne .pk_bad2
    cmp byte [rax], 0x00
    jne .pk_bad2
    cmp byte [rax + 1], 0x04        ; uncompressed only
    jne .pk_bad2
    ; RFC 5915 3: publicKey [1] BIT STRING OPTIONAL -- ONE BIT STRING, not a
    ; container holding one plus whatever follows. The wrapper's own length was
    ; used to advance, so a trailing TLV inside it was stepped over unseen
    ; (audit-report-110).
    lea rdx, [rax + rcx]
    cmp rdx, r10
    jne .pk_bad2
    push rdi
    push rsi
    lea rsi, [rax + 2]              ; X||Y, for ktls to tie to the scalar
    lea rdi, [key_pub]
    mov ecx, 64
    rep movsb
    mov qword [key_pub_set], 1
    pop rsi
    pop rdi
    pop rcx
    pop rax
    jmp .pk_next                    ; NOT a fall-through: .pk_params follows
.pk_params:
    ; RFC 5915 3: [0] ECParameters, i.e. a named-curve OID. It was skipped
    ; unopened, so a BIT STRING retagged from [1] to [0] was waved through
    ; (audit-report-105 F1). Real PKCS#8 keys omit it -- the curve is pinned by
    ; the outer AlgorithmIdentifier -- but when present it must agree.
    test r12d, 1
    jnz .pk_bad                     ; a second [0]
    or r12d, 1
    cmp rcx, alg_ec_curve_len
    jne .pk_bad
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [alg_ec_curve]
    mov rcx, alg_ec_curve_len
    call bytes_eq
    test eax, eax
    pop rcx
    pop rax
    jz .pk_bad
.pk_next:
    lea rbx, [rax + rcx]
    jmp .pk_tail
.pk_end:
    cmp rbx, r13
    jne .pk_bad                     ; a child overran ECPrivateKey
    ; ...and now the OUTER sequence. RFC 5208 5: PrivateKeyInfo is version,
    ; AlgorithmIdentifier, privateKey, and at most an optional [0] IMPLICIT
    ; Attributes. MEASURED: OpenSSL accepts a trailing [0] and refuses a bare
    ; NULL, so this allows exactly the one and refuses the other -- rejecting
    ; both would repeat report 114's too-strict mistake.
    cmp r13, r14
    je .pk_outer_done
    ja .pk_bad
    mov rdi, r13
    mov rsi, r14
    call der_any
    cmp rax, -1
    je .pk_bad
    cmp dl, 0xa0                    ; [0] IMPLICIT Attributes
    jne .pk_bad
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call pk_attrs_ok                ; ...and its CONTENT, not just its wrapper
    test eax, eax
    pop rcx
    pop rax
    jz .pk_bad
    lea rdi, [rax + rcx]
    cmp rdi, r14
    jne .pk_bad                     ; something after the attributes
.pk_outer_done:
    pop rcx
    pop rax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.pk_bad2:
    add rsp, 16                     ; drop the inner save
.pk_bad:
    add rsp, 16                     ; drop the scalar save
    jmp .fail
.fail:
    mov rax, -1
    pop r14
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

; ---- oid_ok(rdi=content, rsi=len) -> rax = 1 when the bytes are the content
;      of a DER OBJECT IDENTIFIER: base-128 subidentifiers, the final one
;      terminated (continuation bit clear), and none beginning 0x80, which is a
;      leading zero and not the minimal encoding.
;
;      ONE implementation, deliberately. Report 107 put this check inside
;      alg_id_ok; report 108 then wrote a WEAKER copy in attr_ok that tested
;      only the final byte -- and report 109 is that copy being wrong. Two
;      partial implementations of one rule is exactly how they drift, so both
;      callers now share this. Preserves rbx/r12+.
oid_ok:
    push rbx
    push r12
    test rsi, rsi
    jz .oid_no                       ; an empty OID names nothing
    cmp byte [rdi + rsi - 1], 0x80
    jae .oid_no                      ; the final subidentifier never terminated
    mov r12, rdi
    lea rbx, [rdi + rsi]
    mov r8b, 1                       ; 1 = at a subidentifier's first byte
.oid_scan:
    cmp r12, rbx
    jae .oid_yes
    mov r9b, [r12]
    test r8b, r8b
    jz .oid_mid
    cmp r9b, 0x80
    je .oid_no                       ; a leading 0x80: non-minimal
.oid_mid:
    xor r8b, r8b
    test r9b, 0x80
    jnz .oid_next                    ; a continuation byte
    mov r8b, 1                       ; this subidentifier ended here
.oid_next:
    inc r12
    jmp .oid_scan
.oid_yes:
    mov eax, 1
    pop r12
    pop rbx
    ret
.oid_no:
    xor eax, eax
    pop r12
    pop rbx
    ret

; ---- alg_id_ok(rdi=content, rsi=end) -> rax = 1 when the range is an
;      AlgorithmIdentifier: an OBJECT IDENTIFIER, then optional parameters,
;      filling it exactly. RFC 5280 4.1.1.2. "A nonempty SEQUENCE" is not an
;      AlgorithmIdentifier -- retagging the OID to NULL used to pass
;      (audit-report-103 F1). Preserves rbx/r12+.
alg_id_ok:
    push rbx
    push r12
    mov rbx, rsi                     ; end
    call der_any                     ; the algorithm OID
    cmp rax, -1
    je .ai_no
    cmp dl, 0x06                     ; OBJECT IDENTIFIER
    jne .ai_no
    push rax
    push rcx
    mov rdi, rax
    mov rsi, rcx
    call oid_ok                      ; the shared DER OID rule
    test eax, eax
    pop rcx
    pop rax
    jz .ai_no
    lea r12, [rax + rcx]
    cmp r12, rbx
    je .ai_yes                       ; absent parameters: legal
    mov rdi, r12
    mov rsi, rbx
    call der_any                     ; the parameters, whatever they are
    cmp rax, -1
    je .ai_no
    lea r12, [rax + rcx]
    cmp r12, rbx
    jne .ai_no                       ; a third element
.ai_yes:
    mov eax, 1
    pop r12
    pop rbx
    ret
.ai_no:
    xor eax, eax
    pop r12
    pop rbx
    ret

; ---- name_ok(rdi=content, rsi=end) -> rax = 1 when the range is an X.509
;      Name. RFC 5280 4.1.2.4: Name ::= RDNSequence ::= SEQUENCE OF
;      RelativeDistinguishedName, each a SET OF AttributeTypeAndValue, each of
;      those a SEQUENCE { OBJECT IDENTIFIER type, ANY value }.
;
;      issuer and subject used to reach only der_tiles, which is satisfied by
;      ANY bounded TLVs -- so an RDN retagged from SET to SEQUENCE tiled just as
;      well and passed (audit-report-108). An EMPTY RDNSequence is legal and
;      stays legal: some issuers really do have one.
;
;      The attribute VALUE is required to be exactly one element, but its tag is
;      deliberately not enumerated: the string types in use are many, and
;      refusing an unlisted-but-legal one would reject certificates every client
;      accepts. Preserves rbx/r12+.
name_ok:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi                     ; RDNSequence cursor
    mov r13, rsi                     ; its end
.no_rdn:
    cmp rbx, r13
    je .no_yes
    ja .no_no
    mov rdi, rbx
    mov rsi, r13
    call der_any                     ; a RelativeDistinguishedName
    cmp rax, -1
    je .no_no
    cmp dl, 0x31                     ; SET, not merely "some container"
    jne .no_no
    test rcx, rcx
    jz .no_no                        ; SET OF requires at least one attribute
    mov r12, rax                     ; walk the attributes
    lea r14, [rax + rcx]             ; the SET's end
.no_attr:
    cmp r12, r14
    je .no_rdn_done
    ja .no_no
    mov rdi, r12
    mov rsi, r14
    call der_any                     ; AttributeTypeAndValue
    cmp rax, -1
    je .no_no
    cmp dl, 0x30
    jne .no_no
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call attr_ok
    test eax, eax
    pop rcx
    pop rax
    jz .no_no
    lea r12, [rax + rcx]
    jmp .no_attr
.no_rdn_done:
    lea rbx, [rax + rcx]
    jmp .no_rdn
.no_yes:
    mov eax, 1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.no_no:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- utf8_ok(rdi=ptr, rsi=len) -> rax = 1 when the bytes are well-formed
;      UTF-8 (RFC 3629 3): no 0xC0/0xC1 overlong leads, no 0xF5-0xFF, correct
;      continuation counts, and the E0/ED/F0/F4 guards that exclude overlongs,
;      UTF-16 surrogates and anything past U+10FFFF. Preserves rbx/r12+.
utf8_ok:
    push rbx
    push r12
    mov rbx, rdi
    lea r12, [rdi + rsi]
.u8:
    cmp rbx, r12
    jae .u8_yes
    movzx eax, byte [rbx]
    cmp al, 0x80
    jb .u8_1                         ; ASCII
    cmp al, 0xc2
    jb .u8_no                        ; a lone continuation, or an overlong lead
    cmp al, 0xdf
    jbe .u8_2
    cmp al, 0xef
    jbe .u8_3
    cmp al, 0xf4
    jbe .u8_4
    jmp .u8_no                       ; 0xF5-0xFF are never valid
.u8_1:
    inc rbx
    jmp .u8
.u8_2:
    lea rcx, [rbx + 2]
    cmp rcx, r12
    ja .u8_no
    movzx edx, byte [rbx + 1]
    sub edx, 0x80
    cmp edx, 0x3f
    ja .u8_no
    mov rbx, rcx
    jmp .u8
.u8_3:
    lea rcx, [rbx + 3]
    cmp rcx, r12
    ja .u8_no
    movzx edx, byte [rbx + 1]
    cmp al, 0xe0
    jne .u8_3b
    cmp dl, 0xa0                     ; E0 A0..BF: below this is overlong
    jb .u8_no
    cmp dl, 0xbf
    ja .u8_no
    jmp .u8_3tail
.u8_3b:
    cmp al, 0xed
    jne .u8_3any
    cmp dl, 0x80                     ; ED 80..9F: above this is a surrogate
    jb .u8_no
    cmp dl, 0x9f
    ja .u8_no
    jmp .u8_3tail
.u8_3any:
    sub edx, 0x80
    cmp edx, 0x3f
    ja .u8_no
.u8_3tail:
    movzx edx, byte [rbx + 2]
    sub edx, 0x80
    cmp edx, 0x3f
    ja .u8_no
    mov rbx, rcx
    jmp .u8
.u8_4:
    lea rcx, [rbx + 4]
    cmp rcx, r12
    ja .u8_no
    movzx edx, byte [rbx + 1]
    cmp al, 0xf0
    jne .u8_4b
    cmp dl, 0x90                     ; F0 90..BF: below this is overlong
    jb .u8_no
    cmp dl, 0xbf
    ja .u8_no
    jmp .u8_4tail
.u8_4b:
    cmp al, 0xf4
    jne .u8_4any
    cmp dl, 0x80                     ; F4 80..8F: above this exceeds U+10FFFF
    jb .u8_no
    cmp dl, 0x8f
    ja .u8_no
    jmp .u8_4tail
.u8_4any:
    sub edx, 0x80
    cmp edx, 0x3f
    ja .u8_no
.u8_4tail:
    movzx edx, byte [rbx + 2]
    sub edx, 0x80
    cmp edx, 0x3f
    ja .u8_no
    movzx edx, byte [rbx + 3]
    sub edx, 0x80
    cmp edx, 0x3f
    ja .u8_no
    mov rbx, rcx
    jmp .u8
.u8_yes:
    mov eax, 1
    pop r12
    pop rbx
    ret
.u8_no:
    xor eax, eax
    pop r12
    pop rbx
    ret

; ---- str_ok(dil=tag, rsi=ptr, rdx=len) -> rax = 1 when the content matches the
;      character set its tag promises. Report 111 admitted these tags without
;      looking at the bytes, so a UTF8String holding 0xFF was accepted while
;      OpenSSL refused the certificate (audit-report-112).
;
;      TeletexString (0x14) is NOT here: its real-world contents are a mess of
;      T.61 and Latin-1 and cannot be validated correctly, so following report
;      112's second option it is dropped from the allow-list rather than
;      admitted unchecked. Re-adding it is one line, if a real certificate ever
;      needs it.
str_ok:
    push rbx
    push r12
    mov r12, rsi
    lea rbx, [rsi + rdx]
    cmp dil, 0x0c                    ; UTF8String
    je .s_utf8
    cmp dil, 0x13                    ; PrintableString
    je .s_print
    cmp dil, 0x16                    ; IA5String: 7-bit
    je .s_ia5
    cmp dil, 0x1a                    ; VisibleString: 0x20..0x7E
    je .s_vis
    cmp dil, 0x12                    ; NumericString: digits and space
    je .s_num
    cmp dil, 0x1e                    ; BMPString: UCS-2 pairs
    je .s_bmp
    cmp dil, 0x1c                    ; UniversalString: UCS-4 quads
    je .s_uni
    jmp .s_no
.s_utf8:
    mov rdi, r12
    mov rsi, rbx
    sub rsi, r12
    call utf8_ok
    test eax, eax
    jz .s_no
    jmp .s_yes
.s_bmp:
    mov rax, rbx
    sub rax, r12
    test al, 1
    jnz .s_no
    jmp .s_yes
.s_uni:
    mov rax, rbx
    sub rax, r12
    test al, 3
    jnz .s_no
    jmp .s_yes
.s_ia5:
    cmp r12, rbx
    jae .s_yes
    cmp byte [r12], 0x80
    jae .s_no
    inc r12
    jmp .s_ia5
.s_vis:
    cmp r12, rbx
    jae .s_yes
    movzx eax, byte [r12]
    cmp al, 0x20
    jb .s_no
    cmp al, 0x7e
    ja .s_no
    inc r12
    jmp .s_vis
.s_num:
    cmp r12, rbx
    jae .s_yes
    movzx eax, byte [r12]
    cmp al, ' '
    je .s_num_next
    cmp al, '0'
    jb .s_no
    cmp al, '9'
    ja .s_no
.s_num_next:
    inc r12
    jmp .s_num
.s_print:
    ; A-Z a-z 0-9 and  ' ( ) + , - . / : = ?  and space (X.680)
    cmp r12, rbx
    jae .s_yes
    movzx eax, byte [r12]
    cmp al, 'A'
    jb .s_p_punct
    cmp al, 'Z'
    jbe .s_p_next
    cmp al, 'a'
    jb .s_p_punct
    cmp al, 'z'
    jbe .s_p_next
    jmp .s_p_punct
.s_p_punct:
    cmp al, '0'
    jb .s_p_sym
    cmp al, '9'
    jbe .s_p_next
.s_p_sym:
    cmp al, ' '
    je .s_p_next
    cmp al, 0x27                     ; '
    je .s_p_next
    cmp al, '('
    je .s_p_next
    cmp al, ')'
    je .s_p_next
    cmp al, '+'
    je .s_p_next
    cmp al, ','
    je .s_p_next
    cmp al, '-'
    je .s_p_next
    cmp al, '.'
    je .s_p_next
    cmp al, '/'
    je .s_p_next
    cmp al, ':'
    je .s_p_next
    cmp al, '='
    je .s_p_next
    cmp al, '?'
    jne .s_no
.s_p_next:
    inc r12
    jmp .s_print
.s_yes:
    mov eax, 1
    pop r12
    pop rbx
    ret
.s_no:
    xor eax, eax
    pop r12
    pop rbx
    ret

; ---- attr_ok(rdi=content, rsi=end) -> rax = 1 when the range is an
;      AttributeTypeAndValue: an OBJECT IDENTIFIER then exactly one value,
;      filling it. Preserves rbx/r12+.
attr_ok:
    push rbx
    mov rbx, rsi
    call der_any                     ; the attribute type
    cmp rax, -1
    je .at_no
    cmp dl, 0x06                     ; OBJECT IDENTIFIER
    jne .at_no
    push rax
    push rcx
    mov rdi, rax
    mov rsi, rcx
    call oid_ok                      ; the SAME rule alg_id_ok uses
    test eax, eax
    pop rcx
    pop rax
    jz .at_no
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; the value
    cmp rax, -1
    je .at_no
    ; ...and it must be a string whose CONTENT matches its tag. Report 111
    ; admitted a fixed set of tags without looking at the bytes, so a
    ; UTF8String holding 0xFF was accepted while OpenSSL refused the
    ; certificate (audit-report-112). str_ok owns both halves of that rule.
    push rax
    push rcx
    movzx edi, dl                    ; the tag
    mov rsi, rax                     ; content
    mov rdx, rcx                     ; length
    call str_ok
    test eax, eax
    pop rcx
    pop rax
    jz .at_no
    lea rdi, [rax + rcx]
    cmp rdi, rbx
    jne .at_no                       ; a second value, or trailing bytes
    mov eax, 1
    pop rbx
    ret
.at_no:
    xor eax, eax
    pop rbx
    ret

; ---- spki_ok(rdi=content, rsi=end) -> rax = 1 when the range is a
;      SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING },
;      filling it exactly. GENERIC on purpose -- it runs on every chain entry
;      and an issuer need not be P-256; the leaf's curve requirement lives in
;      linnea_x509_leaf_spki. Only the LEAF used to reach any SPKI check at all,
;      so a malformed intermediate was framed and sent (audit-report-113 F2).
spki_ok:
    push rbx
    mov rbx, rsi
    call der_any                     ; AlgorithmIdentifier
    cmp rax, -1
    je .sp_no
    cmp dl, 0x30
    jne .sp_no
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call alg_id_ok
    test eax, eax
    pop rcx
    pop rax
    jz .sp_no
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; subjectPublicKey
    cmp rax, -1
    je .sp_no
    cmp dl, 0x03                     ; BIT STRING
    jne .sp_no
    test rcx, rcx
    jz .sp_no
    cmp byte [rax], 8                ; the unused-bits octet is 0..7
    jae .sp_no
    lea rdi, [rax + rcx]
    cmp rdi, rbx
    jne .sp_no                       ; a third child
    mov eax, 1
    pop rbx
    ret
.sp_no:
    xor eax, eax
    pop rbx
    ret

; ---- exts_ok(rdi=content, rsi=end) -> rax = 1 when the range is an Extensions
;      SEQUENCE's content: zero or more Extension ::= SEQUENCE { extnID OBJECT
;      IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING },
;      each filling itself exactly. extnValue's bytes stay opaque -- the point
;      is the framing, not the policy (audit-report-114 F2). Preserves rbx/r12+.
exts_ok:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r13, rsi
.ex_next:
    cmp rbx, r13
    je .ex_yes
    ja .ex_no
    mov rdi, rbx
    mov rsi, r13
    call der_any                     ; one Extension
    cmp rax, -1
    je .ex_no
    cmp dl, 0x30
    jne .ex_no
    mov r12, rax                     ; remember where it continues
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call ext_one_ok
    test eax, eax
    pop rcx
    pop rax
    jz .ex_no
    lea rbx, [rax + rcx]
    jmp .ex_next
.ex_yes:
    mov eax, 1
    pop r13
    pop r12
    pop rbx
    ret
.ex_no:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

; ---- ext_one_ok(rdi=content, rsi=end) -> rax = 1 for one Extension's body.
ext_one_ok:
    push rbx
    mov rbx, rsi
    call der_any                     ; extnID
    cmp rax, -1
    je .e1_no
    cmp dl, 0x06
    jne .e1_no
    push rax
    push rcx
    mov rdi, rax
    mov rsi, rcx
    call oid_ok
    test eax, eax
    pop rcx
    pop rax
    jz .e1_no
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; critical BOOLEAN, or extnValue
    cmp rax, -1
    je .e1_no
    cmp dl, 0x01                     ; BOOLEAN: present only when TRUE is meant
    jne .e1_value
    cmp rcx, 1
    jne .e1_no
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; then extnValue must follow
    cmp rax, -1
    je .e1_no
.e1_value:
    cmp dl, 0x04                     ; OCTET STRING
    jne .e1_no
    lea rdi, [rax + rcx]
    cmp rdi, rbx
    jne .e1_no                       ; trailing bytes inside the Extension
    mov eax, 1
    pop rbx
    ret
.e1_no:
    xor eax, eax
    pop rbx
    ret

; ---- tbs_suffix_ok(rdi=from, rsi=end) -> rax = 1 when what follows the SPKI is
;      a legal TBSCertificate tail: nothing, or [1] issuerUniqueID, [2]
;      subjectUniqueID, [3] extensions -- each at most once, in ascending order,
;      ending exactly at the TBS end. The walk used to RETURN at the SPKI, so an
;      untagged NULL appended after it was never seen (audit-report-113 F1).
tbs_suffix_ok:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    xor r13d, r13d                   ; highest optional tag accepted so far
.ts_next:
    cmp rbx, r12
    je .ts_yes
    ja .ts_no                        ; a child overran the TBS
    mov rdi, rbx
    mov rsi, r12
    call der_any
    cmp rax, -1
    je .ts_no
    ; RFC 5280 4.1.2: [1] and [2] are IMPLICIT UniqueIdentifier, i.e. BIT
    ; STRING, so their DER tags are PRIMITIVE 0x81/0x82 -- not the constructed
    ; 0xa1/0xa2 this first accepted. That was wrong in both directions: a
    ; conformant certificate carrying 81 01 00 was REJECTED, and the malformed
    ; constructed form was accepted (audit-report-114 F1).
    cmp dl, 0x81
    je .ts_uid1
    cmp dl, 0x82
    je .ts_uid2
    cmp dl, 0xa3
    je .ts_three
    jmp .ts_no                       ; nothing else may follow the SPKI
.ts_uid1:
    mov edi, 1
    jmp .ts_uid
.ts_uid2:
    mov edi, 2
.ts_uid:
    ; an IMPLICIT BIT STRING: at least the unused-bits octet, and it is 0..7
    test rcx, rcx
    jz .ts_no
    cmp byte [rax], 8
    jae .ts_no
    jmp .ts_order
.ts_three:
    mov edi, 3
    ; [3] is EXPLICIT: exactly one Extensions SEQUENCE filling the wrapper
    push rax
    push rcx
    push rdi
    mov rdi, rax
    lea rsi, [rax + rcx]
    mov r8, rsi                      ; the wrapper's end
    call der_any
    cmp rax, -1
    je .ts_no_pop3
    cmp dl, 0x30
    jne .ts_no_pop3
    lea rdx, [rax + rcx]
    cmp rdx, r8
    jne .ts_no_pop3                  ; a second child in the wrapper
    mov rdi, rax
    lea rsi, [rax + rcx]
    call exts_ok
    test eax, eax
    pop rdi
    pop rcx
    pop rax
    jz .ts_no
.ts_order:
    cmp edi, r13d
    jbe .ts_no                       ; repeated, or out of order
    mov r13d, edi
    lea rbx, [rax + rcx]
    jmp .ts_next
.ts_yes:
    mov eax, 1
    pop r13
    pop r12
    pop rbx
    ret
.ts_no_pop3:
    add rsp, 24                      ; drop the three saved words
.ts_no:
    xor eax, eax
    pop r13
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
    push r15
    push rbp
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
    push rax                         ; keep its span: RFC 5280 4.1.1.2 requires
    push rcx                         ; it to EQUAL the TBS signature field
    mov rdi, rax
    lea rsi, [rax + rcx]
    call alg_id_ok
    test eax, eax
    pop rcx
    pop rax
    jz .tw_no
    mov r15, rax                     ; the outer AlgorithmIdentifier's span,
    mov rbp, rcx                     ; to compare with the TBS signature field
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
    cmp r12d, 4
    je .tw_tbssig                    ; the first is `signature`
    cmp r12d, 2
    je .tw_validity                  ; the third is Validity: two Times
    ; the second and fourth are issuer and subject: Names, not just containers
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call name_ok
    test eax, eax
    pop rcx
    pop rax
    jz .tw_no
    jmp .tw_seq_next                 ; NOT a fall-through: .tw_validity follows
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
.tw_tbssig:
    ; RFC 5280 4.1.1.2: this field MUST contain the same algorithm identifier as
    ; the Certificate's signatureAlgorithm. Both are validated as
    ; AlgorithmIdentifiers, then compared whole -- two DIFFERENT algorithm
    ; identifiers is a malformed certificate, not a stylistic variation.
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call alg_id_ok
    test eax, eax
    pop rcx
    pop rax
    jz .tw_no
    cmp rcx, rbp                     ; same content length as the outer one?
    jne .tw_no
    push rax
    push rcx
    mov rdi, rax
    mov rsi, r15
    call bytes_eq                    ; ...and the same bytes
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
    ; the SPKI's own shape, for EVERY entry
    push rax
    push rcx
    mov rdi, rax
    lea rsi, [rax + rcx]
    call spki_ok
    test eax, eax
    pop rcx
    pop rax
    jz .tw_no
    ; ...and whatever follows it must be a legal TBS tail, ending exactly
    push rax
    push rcx
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call tbs_suffix_ok
    test eax, eax
    pop rcx
    pop rax
    jz .tw_no
    lea rdx, [rax + rcx]
    sub rdx, r14                     ; its full length, header included
    mov rax, r14
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.tw_no_pop2:
    add rsp, 16                      ; drop the two saved words
.tw_no:
    xor eax, eax
    pop rbp
    pop r15
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
; ---- linnea_pem_key_pub() -> rax = the optional SEC1 [1] public point from the
;      last key parsed (64 bytes X||Y), or 0 if that key carried none.
linnea_pem_key_pub:
    cmp qword [key_pub_set], 0
    je .kp_none
    lea rax, [key_pub]
    ret
.kp_none:
    xor eax, eax
    ret

linnea_x509_cert_wellformed:
    call tbs_walk
    test rax, rax
    jz .cw_no
    mov eax, 1
    ret
.cw_no:
    xor eax, eax
    ret

; ---- linnea_x509_leaf_validity_times(rdi=der, rsi=len, rdx=out) -> rax = 1 on
;      success. Writes six qwords at `out`: notBefore ptr/len/tag then notAfter
;      ptr/len/tag. It does NOT compare them with the clock.
;
;      The split is deliberate: five test harnesses link this object without
;      linnea_time.o, so doing the epoch arithmetic here would break them the way
;      report 96's lib-calling-a-server-symbol broke linnea-probe. pem parses
;      DER; linnea_ktls.asm owns the clock and the policy (audit-report-118).
linnea_x509_leaf_validity_times:
    push rbx
    push r12
    push r13
    push r14
    mov r14, rdx                     ; out
    lea r13, [rdi + rsi]
    mov rsi, r13
    call der_any                     ; Certificate
    cmp rax, -1
    je .vt_no
    mov rdi, rax
    lea rbx, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; tbsCertificate
    cmp rax, -1
    je .vt_no
    mov rdi, rax
    lea r13, [rax + rcx]             ; TBS end
    mov rsi, r13
    call der_any
    cmp rax, -1
    je .vt_no
    cmp dl, 0xa0                     ; optional version
    jne .vt_serial
    lea rdi, [rax + rcx]
    mov rsi, r13
    call der_any
    cmp rax, -1
    je .vt_no
.vt_serial:
    mov r12d, 3                      ; step over serial, signature, issuer
.vt_skip:
    lea rdi, [rax + rcx]
    mov rsi, r13
    call der_any
    cmp rax, -1
    je .vt_no
    dec r12d
    jnz .vt_skip
    cmp dl, 0x30                     ; Validity
    jne .vt_no
    mov rdi, rax
    lea rbx, [rax + rcx]             ; its end
    mov rsi, rbx
    call der_any                     ; notBefore
    cmp rax, -1
    je .vt_no
    mov [r14], rax
    mov [r14 + 8], rcx
    movzx edx, dl
    mov [r14 + 16], rdx
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; notAfter
    cmp rax, -1
    je .vt_no
    mov [r14 + 24], rax
    mov [r14 + 32], rcx
    movzx edx, dl
    mov [r14 + 40], rdx
    mov eax, 1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.vt_no:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- linnea_x509_leaf_usage_ok(rdi=der, rsi=len) -> rax = 1 when this leaf may
;      be used for TLS SERVER authentication, else 0.
;
;      RFC 8446 4.4.2.2: a server certificate that signs CertificateVerify must
;      allow signing -- if Key Usage is present, digitalSignature must be set --
;      and a leaf whose Extended Key Usage is limited to clientAuth cannot serve.
;      ABSENT is fine for both: every certificate in this tree has neither, and
;      OpenSSL's sslserver purpose check passes them (audit-report-117).
;
;      LEAF ONLY. Intermediates keep the structural check and nothing more: an
;      issuer legitimately carries keyCertSign and no serverAuth.
linnea_x509_leaf_usage_ok:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea r13, [rdi + rsi]
    mov rsi, r13
    call der_any                     ; Certificate
    cmp rax, -1
    je .lu_no
    mov rdi, rax
    lea rbx, [rax + rcx]
    mov rsi, rbx
    call der_any                     ; tbsCertificate
    cmp rax, -1
    je .lu_no
    mov r14, rax                     ; TBS content
    lea r15, [rax + rcx]             ; TBS end
    ; walk to the [3] extensions, if any
    mov rbx, r14
.lu_scan:
    cmp rbx, r15
    jae .lu_yes                      ; no extensions at all: nothing to forbid
    mov rdi, rbx
    mov rsi, r15
    call der_any
    cmp rax, -1
    je .lu_no
    cmp dl, 0xa3
    je .lu_exts
    lea rbx, [rax + rcx]
    jmp .lu_scan
.lu_exts:
    mov rdi, rax
    lea rsi, [rax + rcx]
    call der_any                     ; the Extensions SEQUENCE
    cmp rax, -1
    je .lu_no
    mov rbx, rax
    lea r15, [rax + rcx]
.lu_each:
    cmp rbx, r15
    jae .lu_yes                      ; neither extension present
    mov rdi, rbx
    mov rsi, r15
    call der_any                     ; one Extension
    cmp rax, -1
    je .lu_no
    mov r14, rax                     ; its content
    lea r12, [rax + rcx]             ; its end
    push r12
    mov rdi, r14
    mov rsi, r12
    call der_any                     ; extnID
    cmp rax, -1
    je .lu_no_pop
    ; is it keyUsage or extKeyUsage?
    lea rdi, [rax - 2]               ; the OID element, tag included
    mov rsi, rcx
    add rsi, 2
    cmp rsi, oid_ku_len
    jne .lu_try_eku
    lea rsi, [oid_ku]
    mov rcx, oid_ku_len
    call bytes_eq
    test eax, eax
    jnz .lu_is_ku
.lu_try_eku:
    pop r12
    push r12
    mov rdi, r14
    mov rsi, r12
    call der_any
    lea rdi, [rax - 2]
    mov rsi, rcx
    add rsi, 2
    cmp rsi, oid_eku_len
    jne .lu_next
    lea rsi, [oid_eku]
    mov rcx, oid_eku_len
    call bytes_eq
    test eax, eax
    jnz .lu_is_eku
.lu_next:
    pop r12
    mov rbx, r12
    jmp .lu_each
.lu_is_ku:
    ; extnValue is an OCTET STRING wrapping a BIT STRING; bit 0 is
    ; digitalSignature, i.e. 0x80 of the first data octet.
    pop r12
    push r12
    mov rdi, r14
    mov rsi, r12
    call ext_value_of
    test rax, rax
    jz .lu_no_pop
    mov rdi, rax
    mov rsi, rcx
    call der_any                     ; the BIT STRING
    cmp rax, -1
    je .lu_no_pop
    cmp dl, 0x03
    jne .lu_no_pop
    cmp rcx, 2
    jb .lu_no_pop                    ; no data octet at all
    test byte [rax + 1], 0x80        ; digitalSignature
    jz .lu_no_pop
    jmp .lu_next
.lu_is_eku:
    pop r12
    push r12
    mov rdi, r14
    mov rsi, r12
    call ext_value_of
    test rax, rax
    jz .lu_no_pop
    mov rdi, rax
    mov rsi, rcx
    call der_any                     ; SEQUENCE OF KeyPurposeId
    cmp rax, -1
    je .lu_no_pop
    cmp dl, 0x30
    jne .lu_no_pop
    mov rdi, rax
    lea rsi, [rax + rcx]
    call eku_has_server
    test eax, eax
    jz .lu_no_pop
    jmp .lu_next
.lu_yes:
    mov eax, 1
    jmp .lu_ret
.lu_no_pop:
    pop r12
.lu_no:
    xor eax, eax
.lu_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- ext_value_of(rdi=extension content, rsi=end) -> rax = the OCTET STRING's
;      content, rcx = its length; rax = 0 on failure. Skips extnID and the
;      optional critical BOOLEAN.
ext_value_of:
    push rbx
    mov rbx, rsi
    call der_any                     ; extnID
    cmp rax, -1
    je .ev_no
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any
    cmp rax, -1
    je .ev_no
    cmp dl, 0x01                     ; critical BOOLEAN, optional
    jne .ev_have
    lea rdi, [rax + rcx]
    mov rsi, rbx
    call der_any
    cmp rax, -1
    je .ev_no
.ev_have:
    cmp dl, 0x04                     ; extnValue OCTET STRING
    jne .ev_no
    pop rbx
    ret
.ev_no:
    xor eax, eax
    pop rbx
    ret

; ---- eku_has_server(rdi=content, rsi=end) -> rax = 1 when the KeyPurposeId list
;      contains id-kp-serverAuth or anyExtendedKeyUsage.
eku_has_server:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
.ek_next:
    cmp rbx, r12
    jae .ek_no
    mov rdi, rbx
    mov rsi, r12
    call der_any
    cmp rax, -1
    je .ek_no
    lea rdi, [rax - 2]               ; the OID element with its tag
    mov rsi, rcx
    add rsi, 2
    push rdi
    push rsi
    push rax
    push rcx
    cmp rsi, oid_srv_len
    jne .ek_try_any
    lea rsi, [oid_srv]
    mov rcx, oid_srv_len
    call bytes_eq
    test eax, eax
    jnz .ek_yes4
.ek_try_any:
    pop rcx
    pop rax
    pop rsi
    pop rdi
    push rdi
    push rsi
    push rax
    push rcx
    cmp rsi, oid_any_len
    jne .ek_skip
    lea rsi, [oid_any]
    mov rcx, oid_any_len
    call bytes_eq
    test eax, eax
    jnz .ek_yes4
.ek_skip:
    pop rcx
    pop rax
    pop rsi
    pop rdi
    lea rbx, [rax + rcx]
    jmp .ek_next
.ek_yes4:
    add rsp, 32
    mov eax, 1
    pop r12
    pop rbx
    ret
.ek_no:
    xor eax, eax
    pop r12
    pop rbx
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
    ; RFC 5280 4.1.2.7: SubjectPublicKeyInfo is EXACTLY an AlgorithmIdentifier
    ; and a BIT STRING. The key was copied out of the second child without
    ; checking that it ended the SEQUENCE, so a third child went unseen
    ; (audit-report-103 F2). rbx is the SPKI content end.
    lea rdx, [rax + rcx]
    cmp rdx, rbx
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
; ...and its curve half alone, for the optional SEC1 [0] parameters field
oid_ku:     db 0x06,0x03,0x55,0x1d,0x0f          ; 2.5.29.15  keyUsage
oid_ku_len  equ $ - oid_ku
oid_eku:    db 0x06,0x03,0x55,0x1d,0x25          ; 2.5.29.37  extKeyUsage
oid_eku_len equ $ - oid_eku
oid_srv:    db 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x01  ; id-kp-serverAuth
oid_srv_len equ $ - oid_srv
oid_any:    db 0x06,0x04,0x55,0x1d,0x25,0x00     ; anyExtendedKeyUsage
oid_any_len equ $ - oid_any
alg_ec_curve     equ alg_ec + 9
alg_ec_curve_len equ 10
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
