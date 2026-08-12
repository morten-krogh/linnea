; linnea_api.asm — the little HTTP/1.1 backend behind linnea's /api location.
;
; Two endpoints, both answering JSON:
;
;   POST /api/upload   the request body IS the file. It is written to an
;                      O_TMPFILE and SHA-256'd in the same pass, the descriptor
;                      is closed as soon as the answer is composed — which is
;                      what deletes it — and the reply is
;                      {"name":..,"size":..,"checksum":..}. The name comes from
;                      the client's X-Filename header, which the browser
;                      percent-encodes because a header may not carry arbitrary
;                      bytes; it is decoded for the answer and NEVER used to
;                      build a path. There is no path: the file has no name.
;
;   GET  /api/random   {"value":N}, 1 <= N <= 1000, from getrandom(2).
;
; One request per connection: linnea proxies with Connection: close, so there
; is nothing to gain from keeping it. Blocking syscalls and one connection at a
; time — this is a test backend for the site's upload demo, not a server. That
; is why both socket deadlines are set: with no concurrency, one peer that says
; nothing is the whole service, and a blocking read has no other way back.
;
; Usage: linnea-api [port]        (default 7700, bound to 127.0.0.1)

default rel

%include "linnea_syscall.inc"
%include "linnea_sha256.inc"

global _start

extern linnea_sha256_init
extern linnea_sha256_update
extern linnea_sha256_final
extern linnea_print_stdout
extern linnea_print_u64_stdout

LINNEA_EINTR    equ 4
LINNEA_EAGAIN   equ 11

DEFAULT_PORT    equ 7700
HEAD_BUF        equ 8192          ; request head, plus whatever body rode with it
IO_BUF          equ 65536
RESP_BUF        equ 1024          ; the composed JSON answer
NAME_MAX        equ 255           ; decoded filename bytes we will repeat back
; The SAME ceiling linnea's max_body carries, deliberately. linnea refuses an
; oversized body before the bytes land; this is the backstop for a request that
; reaches 127.0.0.1:7700 without having come through it.
;
; Kept equal rather than "comfortably above", which is what it used to claim.
; It was not: the live config sat at 80 MiB against this 64, so an upload
; between the two passed the front door and was refused back here — the
; confusing failure, not a safe one. If you move either, move both.
;
; The claim this replaces also said the live config was 8 MiB, years after it
; stopped being. A number written where the server cannot correct it goes
; stale; the site's upload card carried the same 8 MiB for the same reason.
MAX_UPLOAD      equ 67108864
; This server handles one connection at a time and blocks while it does, so a
; peer that connects and then says nothing stops every other request until it
; goes away — measured at exactly that, indefinitely, before this existed.
;
; The deadline does not make the server concurrent; it bounds the damage. One
; stuck peer costs everyone behind it this long instead of for ever, so the
; number wants to be as small as it can be without ever firing in anger. Only
; linnea reaches this port, over loopback, having already buffered the whole
; request before it opens the leg — a read that takes ten seconds is not a slow
; client, it is a linnea that is no longer there.
IO_TIMEOUT_SEC  equ 10

section .rodata

msg_listen:     db "linnea-api listening on 127.0.0.1:"
msg_listen_len  equ $ - msg_listen
msg_nl:         db 10
msg_bind_fail:  db "linnea-api: cannot bind", 10
msg_bind_fail_len equ $ - msg_bind_fail

hn_clen:        db "content-length"
hn_clen_len     equ $ - hn_clen
hn_fname:       db "x-filename"
hn_fname_len    equ $ - hn_fname

path_upload:    db "/api/upload"
path_upload_len equ $ - path_upload
path_random:    db "/api/random"
path_random_len equ $ - path_random

; The directory only supplies the filesystem — O_TMPFILE creates no entry in it,
; so there is no name for a client to have a say in.
tmp_dir:        db "/tmp", 0

; Status lines and bodies are kept apart so that no Content-Length is ever
; written by hand: send_status counts the body. Three of these four were
; miscounted when they were literals, and a short count truncates the JSON.
st_200:         db "HTTP/1.1 200 OK", 13, 10
st_200_len      equ $ - st_200
st_400:         db "HTTP/1.1 400 Bad Request", 13, 10
st_400_len      equ $ - st_400
st_404:         db "HTTP/1.1 404 Not Found", 13, 10
st_404_len      equ $ - st_404
st_411:         db "HTTP/1.1 411 Length Required", 13, 10
st_411_len      equ $ - st_411
st_413:         db "HTTP/1.1 413 Content Too Large", 13, 10
st_413_len      equ $ - st_413
st_500:         db "HTTP/1.1 500 Internal Server Error", 13, 10
st_500_len      equ $ - st_500

resp_fixed:     db "Content-Type: application/json", 13, 10
                db "Connection: close", 13, 10
                db "Content-Length: "
resp_fixed_len  equ $ - resp_fixed
resp_crlf2:     db 13, 10, 13, 10
resp_crlf2_len  equ $ - resp_crlf2

json_name:      db '{"name":"'
json_name_len   equ $ - json_name
json_size:      db '","size":'
json_size_len   equ $ - json_size
json_sum:       db ',"checksum":"'
json_sum_len    equ $ - json_sum
json_end:       db '"}'
json_end_len    equ $ - json_end
json_value:     db '{"value":'
json_value_len  equ $ - json_value
json_brace:     db '}'

body_404:       db '{"error":"no such route"}'
body_404_len    equ $ - body_404
body_411:       db '{"error":"no body length"}'
body_411_len    equ $ - body_411
body_413:       db '{"error":"upload too big"}'
body_413_len    equ $ - body_413
body_400:       db '{"error":"bad request"}'
body_400_len    equ $ - body_400
body_500:       db '{"error":"server error"}'
body_500_len    equ $ - body_500
; struct timeval for the socket deadlines
align 8
io_timeout:     dq IO_TIMEOUT_SEC, 0

hexdigits:      db "0123456789abcdef"
default_name:   db "upload"
default_name_len equ $ - default_name

section .bss

listen_fd:      resq 1
conn_fd:        resq 1
port:           resq 1
sockaddr:       resb 16
headbuf:        resb HEAD_BUF
head_len:       resq 1            ; bytes up to and including the blank line
in_len:         resq 1            ; everything read so far (head + body prefix)
iobuf:          resb IO_BUF
namebuf:        resb NAME_MAX + 8
name_len:       resq 1
respbuf:        resb RESP_BUF
numbuf:         resb 24
ctx:            resb linnea_sha256_ctx_size
digest:         resb LINNEA_SHA256_DIGEST
hexsum:         resb 64

section .text

_start:
    ; argv[1] is an optional port
    mov rax, [rsp]                 ; argc
    cmp rax, 2
    jb .default_port
    mov rdi, [rsp + 16]            ; argv[1]
    call cstr_len
    mov rsi, rax
    mov rdi, [rsp + 16]
    call parse_u64
    test rax, rax
    jz .default_port
    mov [port], rax
    jmp .have_port
.default_port:
    mov qword [port], DEFAULT_PORT
.have_port:
    call setup_listener
    lea rdi, [msg_listen]
    mov esi, msg_listen_len
    call linnea_print_stdout
    mov rdi, [port]
    call linnea_print_u64_stdout
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stdout

.accept_loop:
    mov eax, LINNEA_SYS_ACCEPT
    mov rdi, [listen_fd]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .accept_loop                ; EINTR and friends: just go round again
    mov [conn_fd], rax
    ; Deadlines, before a single byte is read. Both directions: a peer that
    ; never speaks and a peer that never reads wedge this server identically,
    ; since it serves one connection at a time and blocks in both.
    mov edx, LINNEA_SO_RCVTIMEO
    call set_timeout
    mov edx, LINNEA_SO_SNDTIMEO
    call set_timeout
    call handle_conn
    mov eax, LINNEA_SYS_CLOSE
    mov rdi, [conn_fd]
    syscall
    jmp .accept_loop


; set_timeout(edx = SO_RCVTIMEO or SO_SNDTIMEO) — arm one deadline on conn_fd.
; A failure is not worth refusing the connection over: the result is the old
; behaviour, which served this backend for a while.
set_timeout:
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, [conn_fd]
    mov esi, LINNEA_SOL_SOCKET
    lea r10, [io_timeout]
    mov r8d, 16                    ; sizeof(struct timeval)
    syscall
    ret


; handle_conn() — read one request head, dispatch on method and path.
handle_conn:
    push rbx
    call read_head
    test rax, rax
    js .done                       ; no head: the peer went away, or sent junk
    ; method
    lea rdi, [headbuf]
    cmp dword [rdi], 'GET '
    je .get
    cmp dword [rdi], 'POST'
    jne .bad
    cmp byte [rdi + 4], ' '
    jne .bad
    lea rdi, [headbuf + 5]
    call target_len                ; rax = length of the target
    lea rsi, [path_upload]
    mov rdx, path_upload_len
    call path_is
    test eax, eax
    jz .notfound
    call do_upload
    jmp .done
.get:
    lea rdi, [headbuf + 4]
    call target_len
    lea rsi, [path_random]
    mov rdx, path_random_len
    call path_is
    test eax, eax
    jz .notfound
    call do_random
    jmp .done
.notfound:
    lea rdi, [st_404]
    mov esi, st_404_len
    lea rdx, [body_404]
    mov ecx, body_404_len
    call send_status
    jmp .done
.bad:
    lea rdi, [st_400]
    mov esi, st_400_len
    lea rdx, [body_400]
    mov ecx, body_400_len
    call send_status
.done:
    pop rbx
    ret


; do_random() — {"value":N}, 1..1000.
do_random:
    push rbx
.draw:
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [numbuf]
    mov esi, 8
    xor edx, edx
    syscall
    cmp rax, -LINNEA_EINTR
    je .draw
    ; Unchecked, this read whatever numbuf happened to hold — zeroed .bss on the
    ; first call, so a failure would have answered a confident {"value":1}. It
    ; effectively cannot fail for eight bytes with no flags, which is the reason
    ; to say so out loud rather than to leave it out.
    cmp rax, 8
    jne .no_random
    mov rax, [numbuf]
    xor edx, edx
    mov rcx, 1000
    div rcx                        ; rdx = value mod 1000
    lea rbx, [rdx + 1]             ; 1..1000
    ; body
    lea rdi, [json_value]
    mov esi, json_value_len
    lea rdx, [respbuf]
    call append
    mov rdi, rbx
    mov rsi, rax
    call append_u64
    lea rdi, [json_brace]
    mov esi, 1
    mov rdx, rax
    call append
    lea rdx, [respbuf]
    mov rcx, rax
    sub rcx, rdx                   ; body length
    lea rdi, [st_200]
    mov esi, st_200_len
    call send_status
    pop rbx
    ret
.no_random:
    lea rdi, [st_500]
    mov esi, st_500_len
    lea rdx, [body_500]
    mov ecx, body_500_len
    call send_status
    pop rbx
    ret


; do_upload() — stream the body to a temporary file, hashing as it goes, then
; delete the file and answer with what it contained.
do_upload:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Content-Length is required: without it there is no body to speak of, and
    ; guessing one from the connection closing would make a truncated upload
    ; indistinguishable from a complete one.
    lea rdi, [hn_clen]
    mov esi, hn_clen_len
    call hdr_find
    test rax, rax
    jz .no_length
    mov rdi, rax
    mov rsi, rdx
    call parse_u64
    test rdx, rdx
    jz .fail400                    ; present but not a number: not 411, and not
                                   ; a zero-length upload either
    mov r12, rax                   ; declared length
    cmp r12, MAX_UPLOAD
    ja .too_big
    call temp_open                 ; rax = fd
    test rax, rax
    js .fail400
    mov r13, rax                   ; file fd
    lea rdi, [ctx]
    call linnea_sha256_init
    xor r14, r14                   ; bytes captured
    ; whatever body bytes arrived with the head go first
    mov rbx, [in_len]
    sub rbx, [head_len]
    jz .stream
    cmp rbx, r12
    jbe .have_prefix
    mov rbx, r12                   ; ignore anything past the declared length
.have_prefix:
    lea rsi, [headbuf]
    add rsi, [head_len]
    mov rdx, rbx
    mov rdi, r13
    call absorb
    test rax, rax
    js .fail_file
    add r14, rbx
.stream:
    cmp r14, r12
    jae .complete
    mov rax, r12
    sub rax, r14                   ; still wanted
    cmp rax, IO_BUF
    jbe .take
    mov eax, IO_BUF
.take:
    mov r15, rax
    mov eax, LINNEA_SYS_READ
    mov rdi, [conn_fd]
    lea rsi, [iobuf]
    mov rdx, r15
    syscall
    cmp rax, -LINNEA_EINTR
    je .take                       ; a signal, not the end of anything
    cmp rax, 0
    jle .fail_file                 ; EOF, error, or the deadline: either way the
                                   ; upload never completed
    mov rbx, rax
    lea rsi, [iobuf]
    mov rdx, rbx
    mov rdi, r13
    call absorb
    test rax, rax
    js .fail_file
    add r14, rbx
    jmp .stream
.complete:
    mov eax, LINNEA_SYS_CLOSE      ; the close IS the delete: O_TMPFILE has no
    mov rdi, r13                   ; link, so this is what returns the space
    syscall
    lea rdi, [ctx]
    lea rsi, [digest]
    call linnea_sha256_final
    lea rdi, [digest]
    mov esi, LINNEA_SHA256_DIGEST
    lea rdx, [hexsum]
    call hex_encode
    call read_filename
    ; {"name":"<name>","size":<n>,"checksum":"<hex>"}
    lea rdi, [json_name]
    mov esi, json_name_len
    lea rdx, [respbuf]
    call append
    lea rdi, [namebuf]
    mov rsi, [name_len]
    mov rdx, rax
    ; the tail after the name is fixed-shape: ","size": + digits + ,"checksum":"
    ; + 64 hex + "}. Keep exactly that much back.
    lea rcx, [respbuf + RESP_BUF - (json_size_len + 20 + json_sum_len + 64 + json_end_len)]
    call append_escaped
    lea rdi, [json_size]
    mov esi, json_size_len
    mov rdx, rax
    call append
    mov rdi, r14
    mov rsi, rax
    call append_u64
    lea rdi, [json_sum]
    mov esi, json_sum_len
    mov rdx, rax
    call append
    lea rdi, [hexsum]
    mov esi, 64
    mov rdx, rax
    call append
    lea rdi, [json_end]
    mov esi, json_end_len
    mov rdx, rax
    call append
    lea rdx, [respbuf]
    mov rcx, rax
    sub rcx, rdx
    lea rdi, [st_200]
    mov esi, st_200_len
    call send_status
    jmp .out
.fail_file:
    mov eax, LINNEA_SYS_CLOSE      ; a half-written upload leaves nothing behind
    mov rdi, r13
    syscall
    jmp .out                       ; and no answer: the request was never whole
.no_length:
    lea rdi, [st_411]
    mov esi, st_411_len
    lea rdx, [body_411]
    mov ecx, body_411_len
    call send_status
    jmp .out
.too_big:
    lea rdi, [st_413]
    mov esi, st_413_len
    lea rdx, [body_413]
    mov ecx, body_413_len
    call send_status
    jmp .out
.fail400:
    lea rdi, [st_400]
    mov esi, st_400_len
    lea rdx, [body_400]
    mov ecx, body_400_len
    call send_status
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; absorb(rdi=fd, rsi=buf, rdx=len) -> rax = 0 ok, -1 write failed
; One pass: the bytes go to the file and through the hash together, so the
; upload is never read back.
absorb:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    test r13, r13
    jz .ok
    lea rdi, [ctx]
    mov rsi, r12
    mov rdx, r13
    call linnea_sha256_update
    mov rsi, r12
    mov rdx, r13
.wloop:
    mov eax, LINNEA_SYS_WRITE
    mov rdi, rbx
    syscall
    cmp rax, -LINNEA_EINTR
    je .wloop
    cmp rax, 0
    jle .fail
    add rsi, rax
    sub rdx, rax
    jnz .wloop
.ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov eax, -1
    pop r13
    pop r12
    pop rbx
    ret


; temp_open() -> rax = fd (or negative).
;
; O_TMPFILE: the directory supplies the filesystem and no entry is made in it.
; The file has no name, so nothing else on the box can open it, two uploads
; cannot collide over one, and the kernel reclaims it when the descriptor closes
; — INCLUDING if this process is killed mid-upload, which a named file would
; have survived. It was a named file until this: "/tmp/linnea-api-<pid>-<n>",
; built here so a client could not steer it, and removed by hand afterwards.
; That hand was the only thing keeping /tmp clean, and a kill took it away.
; linnea's own two capture paths (linnea_spill.asm, and the h3 one in
; linnea_quic_server.asm) had both already reached this conclusion.
;
; Nothing ever reads the file back: the checksum comes from the SHA-256 running
; over the same bytes in the same pass, and the answer is composed from memory.
; It is written because receiving an upload onto disk is what this endpoint
; exists to demonstrate.
temp_open:
    lea rdi, [tmp_dir]
    mov esi, LINNEA_O_TMPFILE | LINNEA_O_WRONLY | LINNEA_O_CLOEXEC
    mov edx, LINNEA_MODE_0600
    mov eax, LINNEA_SYS_OPEN
    syscall
    ret


; read_filename() — decode X-Filename into namebuf. Absent or empty gives
; "upload"; anything longer than NAME_MAX is truncated rather than refused.
read_filename:
    push rbx
    push r12
    lea rdi, [hn_fname]
    mov esi, hn_fname_len
    call hdr_find
    test rax, rax
    jz .fallback
    test rdx, rdx
    jz .fallback
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [namebuf]
    mov ecx, NAME_MAX
    call pct_decode
    mov [name_len], rax
    test rax, rax
    jz .fallback
    jmp .out
.fallback:
    lea rdi, [namebuf]
    lea rsi, [default_name]
    mov ecx, default_name_len
    rep movsb
    mov qword [name_len], default_name_len
.out:
    pop r12
    pop rbx
    ret


; pct_decode(rdi=in, rsi=len, rdx=out, rcx=max) -> rax = bytes written
; The browser percent-encodes the filename because an HTTP header field value
; is not a place for arbitrary bytes. A stray '%' that is not followed by two
; hex digits is kept as itself rather than treated as an error.
pct_decode:
    push rbx
    push r12
    push r13
    mov r8, rdx                    ; out cursor
    mov r9, rdx
    add r9, rcx                    ; out limit
    xor r10, r10                   ; in cursor
.loop:
    cmp r10, rsi
    jae .done
    cmp r8, r9
    jae .done
    movzx eax, byte [rdi + r10]
    cmp al, '%'
    jne .literal
    lea rbx, [r10 + 2]
    cmp rbx, rsi
    jae .literal                   ; not enough left to be an escape
    movzx eax, byte [rdi + r10 + 1]
    call hex_val
    cmp eax, -1
    je .literal_reload
    mov r11d, eax
    movzx eax, byte [rdi + r10 + 2]
    call hex_val
    cmp eax, -1
    je .literal_reload
    shl r11d, 4
    or eax, r11d
    add r10, 3
    jmp .emit
.literal_reload:
    movzx eax, byte [rdi + r10]
.literal:
    inc r10
.emit:
    ; control characters would corrupt the log line and mean nothing in a
    ; filename, so they are dropped rather than escaped
    cmp al, 0x20
    jb .loop
    cmp al, 0x7f
    je .loop
    mov [r8], al
    inc r8
    jmp .loop
.done:
    mov rax, r8
    sub rax, rdx
    pop r13
    pop r12
    pop rbx
    ret

; hex_val(al) -> eax = 0..15, or -1
hex_val:
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .digit
    or al, 0x20
    cmp al, 'a'
    jb .bad
    cmp al, 'f'
    ja .bad
    movzx eax, al
    sub eax, 'a' - 10
    ret
.digit:
    movzx eax, al
    sub eax, '0'
    ret
.bad:
    mov eax, -1
    ret


; append(rdi=src, rsi=len, rdx=dst) -> rax = dst end
append:
    push rcx
    push rdi
    push rsi
    mov rcx, rsi
    mov rsi, rdi
    mov rdi, rdx
    rep movsb
    mov rax, rdi
    pop rsi
    pop rdi
    pop rcx
    ret

; append_escaped(rdi=src, rsi=len, rdx=dst, rcx=dst limit) -> rax = dst end
; The name is the client's, so it goes into the JSON escaped: a quote or a
; backslash in a filename would otherwise end the string early and let the
; client write the rest of the object.
;
; The limit is the only thing in this function that bounds it. It was safe
; without one — 255 name bytes escape to at most 510, and the rest of the object
; leaves room for that in respbuf — but every term of that argument lives
; somewhere else, and NAME_MAX moving would have broken it silently and at a
; distance. Two bytes are needed for an escape, so the check is for two.
append_escaped:
    xor r8, r8
.loop:
    cmp r8, rsi
    jae .done
    lea rax, [rdx + 2]
    cmp rax, rcx
    ja .done                       ; no room even for an escaped byte
    movzx eax, byte [rdi + r8]
    cmp al, '"'
    je .escape
    cmp al, '\'
    je .escape
    mov [rdx], al
    inc rdx
    inc r8
    jmp .loop
.escape:
    mov byte [rdx], '\'
    mov [rdx + 1], al
    add rdx, 2
    inc r8
    jmp .loop
.done:
    mov rax, rdx
    ret

; append_u64(rdi=value, rsi=dst) -> rax = dst end
append_u64:
    push rbx
    mov rbx, rsi
    mov rsi, rbx
    call u64_to_dec
    add rbx, rax
    mov rax, rbx
    pop rbx
    ret


; send_status(rdi=status line, rsi=status len, rdx=body, rcx=body len)
; The length in the head is counted here, never written out by hand.
send_status:
    push rbx
    push r12
    mov rbx, rdx                   ; body
    mov r12, rcx                   ; body length
    lea rdx, [iobuf]               ; rdi/rsi are already the status line
    call append
    lea rdi, [resp_fixed]
    mov esi, resp_fixed_len
    mov rdx, rax
    call append
    mov rdi, r12
    mov rsi, rax
    call append_u64
    lea rdi, [resp_crlf2]
    mov esi, resp_crlf2_len
    mov rdx, rax
    call append
    mov rdi, rbx
    mov rsi, r12
    mov rdx, rax
    call append
    lea rsi, [iobuf]
    mov rdx, rax
    sub rdx, rsi
    call send_buf
    pop r12
    pop rbx
    ret

; send_buf(rsi=buf, rdx=len) — write it all, MSG_NOSIGNAL so a peer that has
; gone kills the response rather than the process.
send_buf:
.loop:
    test rdx, rdx
    jz .done
    mov eax, LINNEA_SYS_SENDTO
    mov rdi, [conn_fd]
    mov r10d, LINNEA_MSG_NOSIGNAL
    xor r8d, r8d
    xor r9d, r9d
    push rsi
    push rdx
    syscall
    pop rdx
    pop rsi
    cmp rax, -LINNEA_EINTR
    je .loop                       ; a signal must not truncate the response
    cmp rax, 0
    jle .done                      ; error or the send deadline: give up on it
    add rsi, rax
    sub rdx, rax
    jmp .loop
.done:
    ret


; read_head() -> rax = 0 once headbuf holds a complete head, -1 otherwise.
; in_len counts everything read, which is usually more than the head: the body
; starts arriving in the same segments.
read_head:
    push rbx
    mov qword [in_len], 0
    mov qword [head_len], 0
.more:
    mov rax, HEAD_BUF
    sub rax, [in_len]
    jz .fail                       ; a head this long is not one we serve
    mov rbx, rax
    mov eax, LINNEA_SYS_READ
    mov rdi, [conn_fd]
    lea rsi, [headbuf]
    add rsi, [in_len]
    mov rdx, rbx
    syscall
    cmp rax, -LINNEA_EINTR
    je .more
    cmp rax, 0
    jle .fail                      ; EOF, error, or the read deadline
    add [in_len], rax
    call find_head_end             ; rax = head length, or 0 while incomplete
    test rax, rax
    jz .more
    mov [head_len], rax
    xor eax, eax
    pop rbx
    ret
.fail:
    mov eax, -1
    pop rbx
    ret

; find_head_end() -> rax = bytes up to and including CRLFCRLF, 0 if not there
find_head_end:
    mov rcx, [in_len]
    cmp rcx, 4
    jb .none
    sub rcx, 3
    xor eax, eax
.scan:
    cmp rax, rcx
    jae .none
    lea rdx, [headbuf]
    cmp dword [rdx + rax], 0x0a0d0a0d    ; CR LF CR LF, little-endian
    je .found
    inc rax
    jmp .scan
.found:
    add rax, 4
    ret
.none:
    xor eax, eax
    ret


; target_len(rdi=target start) -> rax = bytes up to the next space
; Also leaves the target pointer in rdi for path_is.
target_len:
    xor eax, eax
.scan:
    cmp byte [rdi + rax], ' '
    je .done
    cmp byte [rdi + rax], 13
    je .done
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    cmp rax, 2048
    jb .scan
.done:
    ret

; path_is(rdi=target, rax=target len, rsi=path, rdx=path len) -> eax = 1/0
; The target's query string, if any, is not part of the comparison.
path_is:
    push rbx
    mov rbx, rax                   ; target length
    xor ecx, ecx
.qscan:
    cmp rcx, rbx
    jae .have_path
    cmp byte [rdi + rcx], '?'
    je .cut
    inc rcx
    jmp .qscan
.cut:
    mov rbx, rcx
.have_path:
    cmp rbx, rdx
    jne .no
    xor ecx, ecx
.cmp:
    cmp rcx, rdx
    jae .yes
    mov al, [rdi + rcx]
    cmp al, [rsi + rcx]
    jne .no
    inc rcx
    jmp .cmp
.yes:
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret


; hdr_find(rdi=name, rsi=namelen) -> rax = value ptr (0 = absent), rdx = value len
; Case-insensitive on the field name, and the value's surrounding spaces go.
hdr_find:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14, rdi
    mov r15, rsi
    ; start after the request line
    xor rbx, rbx
.rl:
    cmp rbx, [head_len]
    jae .absent
    cmp byte [headbuf + rbx], 13
    je .rl_done
    inc rbx
    jmp .rl
.rl_done:
    add rbx, 2
.line:
    cmp rbx, [head_len]
    jae .absent
    cmp byte [headbuf + rbx], 13
    je .absent                     ; the blank line: no more fields
    ; find the colon
    mov r12, rbx
.colon:
    cmp r12, [head_len]
    jae .absent
    cmp byte [headbuf + r12], ':'
    je .have_colon
    cmp byte [headbuf + r12], 13
    je .next_line_at
    inc r12
    jmp .colon
.next_line_at:
    mov rbx, r12
    jmp .skip_eol
.have_colon:
    mov rax, r12
    sub rax, rbx                   ; name length
    cmp rax, r15
    jne .skip_to_eol
    xor rcx, rcx
.icmp:
    cmp rcx, r15
    jae .matched
    movzx eax, byte [headbuf + rbx + rcx]
    or al, 0x20                    ; the field name is matched case-insensitively
    movzx edx, byte [r14 + rcx]
    cmp al, dl
    jne .skip_to_eol
    inc rcx
    jmp .icmp
.matched:
    inc r12                        ; past the colon
.lead:
    cmp r12, [head_len]
    jae .absent
    cmp byte [headbuf + r12], ' '
    je .lead_skip
    cmp byte [headbuf + r12], 9
    jne .value_start
.lead_skip:
    inc r12
    jmp .lead
.value_start:
    mov r13, r12
.vend:
    cmp r13, [head_len]
    jae .value_done
    cmp byte [headbuf + r13], 13
    je .value_done
    inc r13
    jmp .vend
.value_done:
    mov rdx, r13
    sub rdx, r12
.trail:
    test rdx, rdx
    jz .value_ret
    mov rax, r12
    add rax, rdx
    dec rax
    cmp byte [headbuf + rax], ' '
    je .trail_cut
    cmp byte [headbuf + rax], 9
    jne .value_ret
.trail_cut:
    dec rdx
    jmp .trail
.value_ret:
    lea rax, [headbuf]
    add rax, r12
    jmp .out
.skip_to_eol:
    mov rbx, r12
.eol:
    cmp rbx, [head_len]
    jae .absent
    cmp byte [headbuf + rbx], 13
    je .skip_eol
    inc rbx
    jmp .eol
.skip_eol:
    add rbx, 2
    jmp .line
.absent:
    xor eax, eax
    xor edx, edx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; parse_u64(rdi=ptr, rsi=len) -> rax = value, rdx = 1 if the whole field was
; digits and there was at least one, 0 otherwise.
;
; The validity flag is not decoration. Returning 0 for "abc" is
; indistinguishable from returning 0 for "0", and Content-Length took the first
; as the second: a malformed length was answered 200 with an empty upload
; rather than refused. RFC 9110 8.6 is 1*DIGIT and nothing else — no sign, no
; hex, no trailing rubbish (hdr_find has already trimmed the spaces).
;
; Saturates rather than wrapping: a length that cannot be represented must not
; come out small enough to look acceptable.
parse_u64:
    xor rax, rax
    xor rcx, rcx
    test rsi, rsi
    jz .invalid                    ; no digits at all
.loop:
    cmp rcx, rsi
    jae .valid
    movzx edx, byte [rdi + rcx]
    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid
    mov r8, 0x1999999999999999
    cmp rax, r8
    ja .saturate
    imul rax, rax, 10
    sub dl, '0'
    movzx edx, dl
    add rax, rdx
    inc rcx
    jmp .loop
.saturate:
    ; Still a number, just not one we will serve — but the REST of it has to be
    ; checked too, or "999...9zz" would come back valid because the overflow
    ; happened before the rubbish did.
    mov rax, -1
.sat_scan:
    inc rcx
    cmp rcx, rsi
    jae .valid
    movzx edx, byte [rdi + rcx]
    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid
    jmp .sat_scan
.valid:
    mov edx, 1
    ret
.invalid:
    xor eax, eax
    xor edx, edx
    ret

; u64_to_dec(rdi=value, rsi=out) -> rax = digits written
u64_to_dec:
    push rbx
    mov rax, rdi
    mov rbx, rsi
    lea r8, [numbuf + 24]          ; fill backwards
    mov r9, r8
    mov rcx, 10
.digit:
    xor edx, edx
    div rcx
    add dl, '0'
    dec r9
    mov [r9], dl
    test rax, rax
    jnz .digit
    mov rcx, r8
    sub rcx, r9                    ; digit count
    mov rsi, r9
    mov rdi, rbx
    mov rax, rcx
    push rax
    rep movsb
    pop rax
    pop rbx
    ret

; hex_encode(rdi=in, rsi=len, rdx=out)
hex_encode:
    xor rcx, rcx
.loop:
    cmp rcx, rsi
    jae .done
    movzx eax, byte [rdi + rcx]
    mov r8d, eax
    shr r8d, 4
    lea r9, [hexdigits]
    mov r8b, [r9 + r8]
    mov [rdx], r8b
    and eax, 15
    mov al, [r9 + rax]
    mov [rdx + 1], al
    add rdx, 2
    inc rcx
    jmp .loop
.done:
    ret

; cstr_len(rdi=cstr) -> rax
cstr_len:
    xor eax, eax
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    cmp rax, 64
    jb .loop
.done:
    ret


; setup_listener() — 127.0.0.1 only: this backend is reached through linnea,
; never from outside the box.
setup_listener:
    push rbx
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js .fail
    mov [listen_fd], rax
    mov rbx, rax
    push 1
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, rbx
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEADDR
    mov r10, rsp
    mov r8d, 4
    syscall
    pop rax
    mov word [sockaddr], LINNEA_AF_INET
    mov eax, [port]
    xchg al, ah
    mov [sockaddr + 2], ax
    mov dword [sockaddr + 4], 0x0100007f    ; 127.0.0.1, network order
    mov qword [sockaddr + 8], 0
    mov eax, LINNEA_SYS_BIND
    mov rdi, rbx
    lea rsi, [sockaddr]
    mov edx, 16
    syscall
    test rax, rax
    js .fail
    mov eax, LINNEA_SYS_LISTEN
    mov rdi, rbx
    mov esi, LINNEA_BACKLOG
    syscall
    test rax, rax
    js .fail
    pop rbx
    ret
.fail:
    lea rdi, [msg_bind_fail]
    mov esi, msg_bind_fail_len
    call linnea_print_stdout
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
