; linnea_nettest.asm — known-answer tests for the IP-literal parsers, above all
; linnea_network_parse_ipv6 (audit follow-up: specific-IPv6 host grammar). The
; "::" zero-run compression is where the bugs live, so every accepted vector
; checks the 16 output bytes and every rejected vector checks the -1 return.
; Prints "net <pass>/<total>" and exits 1 if any check fails.

default rel

%include "linnea_config.inc"

global _start

extern linnea_network_parse_ipv6
extern linnea_print_stdout
extern linnea_print_u64_stdout
extern linnea_client_identity_append

section .rodata
; --- accepted: (string, expected 16 bytes) ---
s_loop:   db "::1", 0
e_loop:   db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1
s_any:    db "::", 0
e_any:    db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
s_doc:    db "2001:db8::1", 0
e_doc:    db 0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,1
s_ll:     db "fe80::1", 0
e_ll:     db 0xfe,0x80,0,0,0,0,0,0, 0,0,0,0,0,0,0,1
s_full:   db "2001:0db8:0000:0000:0000:0000:0000:0001", 0
e_full:   db 0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,1
s_lead:   db "1::", 0
e_lead:   db 0,1,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
s_mapped: db "::ffff:1.2.3.4", 0
e_mapped: db 0,0,0,0,0,0,0,0, 0,0,0xff,0xff,1,2,3,4
s_embed:  db "2001:db8::1.2.3.4", 0
e_embed:  db 0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,1,2,3,4
s_mid:    db "1:2::7:8", 0
e_mid:    db 0,1,0,2,0,0,0,0, 0,0,0,0,0,7,0,8
s_max:    db "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0
e_max:    times 16 db 0xff

; --- rejected ---
r_triple: db ":::", 0
r_two2:   db "1::2::3", 0
r_short:  db "2001:db8", 0
r_5hex:   db "12345::", 0
r_gg:     db "gg::", 0
r_shortq: db "::1.2.3", 0
r_lead1:  db ":1::", 0
r_zone:   db "fe80::1%eth0", 0
r_9grp:   db "1:2:3:4:5:6:7:8:9", 0
r_trailc: db "1:2:3:4:5:6:7:8:", 0

id_ip4:   db 127,0,0,1
id_map:   db 0,0,0,0,0,0,0,0, 0,0,0xff,0xff,1,2,3,4
id_ip6:   db 0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,1
id_e4:    db "Linnea-Client-Identity: v1;ip4=7f000001",13,10
id_e4_len equ $ - id_e4
id_em:    db "Linnea-Client-Identity: v1;ip4=01020304",13,10
id_em_len equ $ - id_em
id_e6:    db "Linnea-Client-Identity: v1;ip6=20010db8000000000000000000000001",13,10
id_e6_len equ $ - id_e6

msg:      db "net "
msg_len   equ $ - msg
slash:    db "/"
nl:       db 10

section .bss
out16:    resb 16
id_out:   resb LINNEA_PROXY_CLIENT_IDENTITY_MAX
id_loc:   resb linnea_config_location_size

section .text
; CHECK str, expected — parse must succeed and the 16 bytes must match.
%macro CHECK 2
    lea rdi, [%1]
    lea rsi, [out16]
    call linnea_network_parse_ipv6
    inc r14d
    test rax, rax
    jnz %%bad
    lea rdi, [out16]
    lea rsi, [%2]
    mov ecx, 16
    repe cmpsb
    jne %%bad
    inc r15d
%%bad:
%endmacro

; ID_CHECK address, address length, expected, expected length.
%macro ID_CHECK 4
    lea rdi, [id_out]
    lea rsi, [id_loc]
    lea rdx, [%1]
    mov ecx, %2
    call linnea_client_identity_append
    inc r14d
    lea rdx, [id_out + %4]
    cmp rax, rdx
    jne %%bad
    lea rdi, [id_out]
    lea rsi, [%3]
    mov ecx, %4
    repe cmpsb
    jne %%bad
    inc r15d
%%bad:
%endmacro

; REJECT str — parse must return -1.
%macro REJECT 1
    lea rdi, [%1]
    lea rsi, [out16]
    call linnea_network_parse_ipv6
    inc r14d
    cmp rax, -1
    jne %%bad
    inc r15d
%%bad:
%endmacro

_start:
    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; pass

    CHECK s_loop,   e_loop
    CHECK s_any,    e_any
    CHECK s_doc,    e_doc
    CHECK s_ll,     e_ll
    CHECK s_full,   e_full
    CHECK s_lead,   e_lead
    CHECK s_mapped, e_mapped
    CHECK s_embed,  e_embed
    CHECK s_mid,    e_mid
    CHECK s_max,    e_max

    REJECT r_triple
    REJECT r_two2
    REJECT r_short
    REJECT r_5hex
    REJECT r_gg
    REJECT r_shortq
    REJECT r_lead1
    REJECT r_zone
    REJECT r_9grp
    REJECT r_trailc

    ; Disabled means no header and does not require source metadata.
    lea rdi, [id_out]
    lea rsi, [id_loc]
    xor edx, edx
    xor ecx, ecx
    call linnea_client_identity_append
    inc r14d
    lea rdx, [id_out]
    cmp rax, rdx
    jne .id_off_bad
    inc r15d
.id_off_bad:
    mov qword [id_loc + linnea_config_location.proxy_client_identity], 1
    ID_CHECK id_ip4, 4, id_e4, id_e4_len
    ID_CHECK id_map, 16, id_em, id_em_len
    ID_CHECK id_ip6, 16, id_e6, id_e6_len
    ; An enabled location fails closed when no kernel-derived address exists.
    lea rdi, [id_out]
    lea rsi, [id_loc]
    lea rdx, [id_ip4]
    mov ecx, 3
    call linnea_client_identity_append
    inc r14d
    test rax, rax
    jnz .id_bad_len
    inc r15d
.id_bad_len:

    lea rdi, [msg]
    mov esi, msg_len
    call linnea_print_stdout
    mov edi, r15d
    call linnea_print_u64_stdout
    lea rdi, [slash]
    mov esi, 1
    call linnea_print_stdout
    mov edi, r14d
    call linnea_print_u64_stdout
    lea rdi, [nl]
    mov esi, 1
    call linnea_print_stdout

    xor edi, edi
    cmp r15d, r14d
    je .exit
    mov edi, 1
.exit:
    mov eax, 60
    syscall
