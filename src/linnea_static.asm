; linnea_static.asm — static-file resolution shared by the HTTP/2 and HTTP/3
; serve paths (and protocol-independent generally): request-target
; normalization, opening/mapping the file, and the extension -> MIME table.
; Extracted from linnea_http2.asm so h2 and h3 resolve and reject paths
; identically, and so the h3 path does not drag in the h2 connection machinery.

default rel

%include "linnea_syscall.inc"

LINNEA_STATIC_MAX_PATH equ 2048     ; bound on the decoded path length

global linnea_static_normalize
global linnea_static_open
global linnea_static_mime

extern linnea_string_iequal

section .text
; linnea_static_normalize(rdi=dst, rsi=raw, rdx=raw len) -> rax = end ptr (0 = 400),
; r9 = directory flag. Percent-decodes then normalizes ".."/"."/"" in place,
; refusing traversal above the root. Ported from the HTTP/1.1 handler.
linnea_static_normalize:
    push r13
    cmp rdx, LINNEA_STATIC_MAX_PATH
    ja .zbad
    mov r13, rdi                     ; start of decoded target
    mov rcx, rdx                     ; raw length
    xor edx, edx                     ; raw index
.zdec:
    cmp rdx, rcx
    jae .zdecoded
    movzx eax, byte [rsi + rdx]
    cmp al, '%'
    je .zpct
    mov [rdi], al
    inc rdi
    inc rdx
    jmp .zdec
.zpct:
    lea rax, [rdx + 3]
    cmp rax, rcx
    ja .zbad
    movzx eax, byte [rsi + rdx + 1]
    call .zhex
    test eax, eax
    js .zbad
    mov r8d, eax
    movzx eax, byte [rsi + rdx + 2]
    call .zhex
    test eax, eax
    js .zbad
    shl r8d, 4
    or eax, r8d
    jz .zbad                         ; %00 truncates the path
    mov [rdi], al
    inc rdi
    add rdx, 3
    jmp .zdec
.zdecoded:
    cmp byte [r13], '/'
    jne .zbad
    mov rsi, r13                     ; read cursor
    mov rcx, rdi                     ; end of decoded input
    mov rdi, r13                     ; write cursor
    xor r9d, r9d                     ; directory flag
.znl:
    cmp rsi, rcx
    jae .znd
    inc rsi
    mov rdx, rsi
.zse:
    cmp rdx, rcx
    jae .zhs
    cmp byte [rdx], '/'
    je .zhs
    inc rdx
    jmp .zse
.zhs:
    mov rax, rdx
    sub rax, rsi                     ; segment length
    test rax, rax
    jz .zskip
    cmp rax, 1
    jne .znnd
    cmp byte [rsi], '.'
    je .zskip
    jmp .zcp
.znnd:
    cmp rax, 2
    jne .zcp
    cmp word [rsi], '..'
    jne .zcp
    cmp rdi, r13
    jbe .zbad                        ; ".." above the root
    dec rdi
.zpop:
    cmp rdi, r13
    jbe .zskip
    cmp byte [rdi], '/'
    je .zskip
    dec rdi
    jmp .zpop
.zskip:
    cmp rdx, rcx
    jb .znx
    mov r9d, 1
    jmp .znx
.zcp:
    mov byte [rdi], '/'
    inc rdi
.zcpl:
    cmp rsi, rdx
    jae .zcpd
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    jmp .zcpl
.zcpd:
    xor r9d, r9d
.znx:
    mov rsi, rdx
    jmp .znl
.znd:
    cmp rdi, r13
    jne .zok
    mov byte [rdi], '/'              ; the root itself
    inc rdi
    mov r9d, 1
.zok:
    mov rax, rdi
    pop r13
    ret
.zbad:
    xor eax, eax
    pop r13
    ret
.zhex:                               ; al -> eax (nibble), -1 if not hex
    cmp al, '0'
    jb .zhbad
    cmp al, '9'
    jbe .zhdig
    or al, 0x20
    cmp al, 'a'
    jb .zhbad
    cmp al, 'f'
    ja .zhbad
    movzx eax, al
    sub eax, 'a' - 10
    ret
.zhdig:
    movzx eax, al
    sub eax, '0'
    ret
.zhbad:
    mov eax, -1
    ret


; linnea_static_open(rdi=path cstr) -> rax = base (0 = missing/irregular), rdx = size.
; A non-empty regular file is mapped read-only; an empty file returns the
; sentinel base 1 with size 0 (found, but nothing to map).
linnea_static_open:
    push rbx
    push r12
    xor esi, esi                     ; O_RDONLY
    xor edx, edx
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .omiss
    mov rbx, rax                     ; fd
    mov rdi, rax
    lea rsi, [static_statbuf]
    mov eax, LINNEA_SYS_FSTAT
    syscall
    cmp rax, -4095
    jae .oreject
    mov eax, [static_statbuf + LINNEA_STAT_ST_MODE]
    and eax, LINNEA_S_IFMT
    cmp eax, LINNEA_S_IFREG
    jne .oreject
    mov r12, [static_statbuf + LINNEA_STAT_ST_SIZE]
    test r12, r12
    jz .oempty
    mov rsi, r12                     ; size
    xor edi, edi
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, ebx                     ; fd
    xor r9d, r9d
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .oreject
    push rax
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop rax
    mov rdx, r12
    pop r12
    pop rbx
    ret
.oempty:
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov eax, 1
    xor edx, edx
    pop r12
    pop rbx
    ret
.oreject:
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
.omiss:
    xor eax, eax
    xor edx, edx
    pop r12
    pop rbx
    ret

; linnea_static_mime(rdi=name ptr, rsi=name len) -> rax = mime ptr, rdx = mime len.
linnea_static_mime:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    lea r13, [rdi + rsi]             ; name end
    mov rcx, r13
.uscan:
    cmp rcx, r12
    jbe .udefault
    movzx eax, byte [rcx - 1]
    cmp al, '/'
    je .udefault
    cmp al, '.'
    je .ufound
    dec rcx
    jmp .uscan
.ufound:
    mov r14, rcx                     ; extension bytes (after the '.')
    mov r15, r13
    sub r15, rcx                     ; extension length
    lea r12, [mime_table_h2]
.uloop:
    mov rdx, [r12]
    test rdx, rdx
    jz .udefault
    mov rdi, r14
    mov rsi, r15
    mov rcx, [r12 + 8]
    call linnea_string_iequal
    test eax, eax
    jnz .umatch
    add r12, 32
    jmp .uloop
.umatch:
    mov rax, [r12 + 16]
    mov rdx, [r12 + 24]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.udefault:
    lea rax, [mime_default_h2]
    mov edx, mime_default_h2_len
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

section .rodata
ext_html_h2: db "html"
ext_css_h2:  db "css"
ext_js_h2:   db "js"
ext_json_h2: db "json"
ext_txt_h2:  db "txt"
ext_png_h2:  db "png"
ext_jpg_h2:  db "jpg"
ext_jpeg_h2: db "jpeg"
ext_gif_h2:  db "gif"
ext_svg_h2:  db "svg"
ext_ico_h2:  db "ico"
mime_html_h2: db "text/html"
mime_html_h2_len equ $ - mime_html_h2
mime_css_h2:  db "text/css"
mime_css_h2_len equ $ - mime_css_h2
mime_js_h2:   db "application/javascript"
mime_js_h2_len equ $ - mime_js_h2
mime_json_h2: db "application/json"
mime_json_h2_len equ $ - mime_json_h2
mime_txt_h2:  db "text/plain"
mime_txt_h2_len equ $ - mime_txt_h2
mime_png_h2:  db "image/png"
mime_png_h2_len equ $ - mime_png_h2
mime_jpeg_h2: db "image/jpeg"
mime_jpeg_h2_len equ $ - mime_jpeg_h2
mime_gif_h2:  db "image/gif"
mime_gif_h2_len equ $ - mime_gif_h2
mime_svg_h2:  db "image/svg+xml"
mime_svg_h2_len equ $ - mime_svg_h2
mime_ico_h2:  db "image/x-icon"
mime_ico_h2_len equ $ - mime_ico_h2
mime_default_h2: db "application/octet-stream"
mime_default_h2_len equ $ - mime_default_h2
mime_table_h2:
    dq ext_html_h2, 4, mime_html_h2, mime_html_h2_len
    dq ext_css_h2,  3, mime_css_h2,  mime_css_h2_len
    dq ext_js_h2,   2, mime_js_h2,   mime_js_h2_len
    dq ext_json_h2, 4, mime_json_h2, mime_json_h2_len
    dq ext_txt_h2,  3, mime_txt_h2,  mime_txt_h2_len
    dq ext_png_h2,  3, mime_png_h2,  mime_png_h2_len
    dq ext_jpg_h2,  3, mime_jpeg_h2, mime_jpeg_h2_len
    dq ext_jpeg_h2, 4, mime_jpeg_h2, mime_jpeg_h2_len
    dq ext_gif_h2,  3, mime_gif_h2,  mime_gif_h2_len
    dq ext_svg_h2,  3, mime_svg_h2,  mime_svg_h2_len
    dq ext_ico_h2,  3, mime_ico_h2,  mime_ico_h2_len
    dq 0


section .bss
static_statbuf:  resb LINNEA_STAT_SIZE
