; linnea_ws.asm — a WebSocket backend, behind linnea's proxy.
;
; It keeps one number. A client sends the text "inc" and the number goes up;
; the new value is then pushed to EVERY connected client, which is the whole
; point of the exercise — two browser tabs on the page watch the same counter
; move. Any other text is a query, answered to the asker alone. The state is
; {"count":N,"clients":M} as a text frame; the count lives in memory only and
; starts again at zero when the process restarts.
;
; linnea itself never parses a frame. It relays an accepted upgrade as an
; opaque byte tunnel (LINNEA_PROXY_TUNNEL), so everything RFC 6455 — the
; handshake, the framing, the masking — happens here.
;
; What is implemented, and what is not:
;
;   * The opening handshake of RFC 6455 4.2.2, including Sec-WebSocket-Accept
;     = base64(sha1(key ++ GUID)). Anything that is not a version-13 upgrade
;     is refused with 400, not with a half-open socket.
;   * Origin is checked (RFC 6455 10.2) against an allowlist. A WebSocket
;     handshake is not subject to the same-origin policy and carries no
;     preflight, so without this any site on the internet could open a socket
;     here from a visitor's browser. The list is the only thing preventing
;     that, whether or not the socket happens to share an origin with the
;     page today. An ABSENT Origin is allowed: that is a non-browser client,
;     which the tests are, and which the same-origin rules were never about.
;   * Frames: text, binary, ping (answered), pong (ignored), close (echoed).
;     Client frames must be masked, and are unmasked in place.
;   * Fragmented messages are NOT supported and are refused with close code
;     1003. Nothing here sends a message worth splitting, and a browser will
;     not fragment a three-byte send.
;   * No extensions: a non-zero RSV bit is a protocol error, since none were
;     negotiated.
;
; One poll(2) loop over the listener and up to MAX_CLIENTS sockets, all
; non-blocking, with a small output queue per client so that a slow reader
; stalls only itself. A client whose queue would overflow is disconnected
; rather than blocked on — it is 30 bytes behind and not coming back.
;
; Usage: linnea-ws [port]         (default 7701, bound to 127.0.0.1)

default rel

%include "linnea_syscall.inc"

global _start

extern linnea_sha1
extern linnea_base64_encode
extern linnea_print_stdout
extern linnea_print_u64_stdout

DEFAULT_PORT    equ 7701
MAX_CLIENTS     equ 64
IN_BUF          equ 2048          ; a request head, or one client frame
OUT_BUF         equ 1024          ; queued frames not yet written

ST_HANDSHAKE    equ 0
ST_OPEN         equ 1
ST_DRAIN        equ 2             ; write what is queued, then close

OP_CONT         equ 0x0
OP_TEXT         equ 0x1
OP_BIN          equ 0x2
OP_CLOSE        equ 0x8
OP_PING         equ 0x9
OP_PONG         equ 0xA

WS_NORMAL       equ 1000
WS_PROTOCOL     equ 1002
WS_UNSUPPORTED  equ 1003
WS_TOO_BIG      equ 1009

struc ws_client
    .fd:        resq 1            ; -1 when the slot is free
    .state:     resq 1
    .in_len:    resq 1
    .out_len:   resq 1
    .out_off:   resq 1            ; how much of .out has been written
    .in:        resb IN_BUF
    .out:       resb OUT_BUF
endstruc

section .rodata

msg_listen:     db "linnea-ws listening on 127.0.0.1:"
msg_listen_len  equ $ - msg_listen
msg_nl:         db 10
msg_bind_fail:  db "linnea-ws: cannot bind", 10
msg_bind_fail_len equ $ - msg_bind_fail

hn_upgrade:     db "upgrade"
hn_upgrade_len  equ $ - hn_upgrade
hn_conn:        db "connection"
hn_conn_len     equ $ - hn_conn
hn_key:         db "sec-websocket-key"
hn_key_len      equ $ - hn_key
hn_ver:         db "sec-websocket-version"
hn_ver_len      equ $ - hn_ver
hn_origin:      db "origin"
hn_origin_len   equ $ - hn_origin

tok_websocket:  db "websocket"
tok_websocket_len equ $ - tok_websocket
tok_upgrade:    db "upgrade"
tok_upgrade_len equ $ - tok_upgrade
ver_13:         db "13"
ver_13_len      equ $ - ver_13

; RFC 6455 1.3's constant, appended to the client's key before hashing.
ws_guid:        db "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ws_guid_len     equ $ - ws_guid

; Origins allowed to open a socket here. Each entry is a length byte followed
; by the text; a zero length ends the list. linnea2.amberbio.com was here
; while the socket lived on that vhost; the vhost was retired on 2026-08-10
; and the origin with it, so nothing is allowed that cannot be reached.
origins:
    db 27, "https://linnea.amberbio.com"
    db 0

resp_101:       db "HTTP/1.1 101 Switching Protocols", 13, 10
                db "Upgrade: websocket", 13, 10
                db "Connection: Upgrade", 13, 10
                db "Sec-WebSocket-Accept: "
resp_101_len    equ $ - resp_101
resp_101_tail:  db 13, 10, 13, 10
resp_101_tail_len equ $ - resp_101_tail

resp_400:       db "HTTP/1.1 400 Bad Request", 13, 10
                db "Content-Type: text/plain", 13, 10
                db "Connection: close", 13, 10
                db "Content-Length: 25", 13, 10, 13, 10
                db "expected a websocket/13", 13, 10
resp_400_len    equ $ - resp_400

resp_403:       db "HTTP/1.1 403 Forbidden", 13, 10
                db "Content-Type: text/plain", 13, 10
                db "Connection: close", 13, 10
                db "Content-Length: 20", 13, 10, 13, 10
                db "origin not allowed", 13, 10
resp_403_len    equ $ - resp_403

; A request head that will not fit IN_BUF. Every other refusal here answers in
; HTTP and this one used to hang up mid-request instead, which reads to the
; client as a network fault rather than as a decision. A browser's upgrade runs
; a few hundred bytes, so this is headroom rather than a live limit — but the
; way it failed was the wrong way to fail.
resp_431:       db "HTTP/1.1 431 Request Header Fields Too Large", 13, 10
                db "Content-Type: text/plain", 13, 10
                db "Connection: close", 13, 10
                db "Content-Length: 24", 13, 10, 13, 10
                db "request head too large", 13, 10
resp_431_len    equ $ - resp_431

json_count:     db '{"count":'
json_count_len  equ $ - json_count
json_clients:   db ',"clients":'
json_clients_len equ $ - json_clients
json_end:       db '}'

cmd_inc:        db "inc"
cmd_inc_len     equ $ - cmd_inc

; struct timespec { 0 s, 100 ms }, for the one place that has to back off.
align 8
pause_100ms:    dq 0, 100000000

section .bss

listen_fd:      resq 1
port:           resq 1
sockaddr:       resb 16
clients:        resb MAX_CLIENTS * ws_client_size
pollfds:        resb (MAX_CLIENTS + 1) * 8    ; { int fd; short ev; short rev; }
poll_map:       resq MAX_CLIENTS + 1          ; pollfd slot -> client index
poll_n:         resq 1
counter:        resq 1
open_count:     resq 1
keybuf:         resb 128          ; the client's key, with the GUID appended
digest:         resb 20
acceptbuf:      resb 64
statebuf:       resb 96           ; the JSON state, before framing
framebuf:       resb 160          ; one server frame, ready to queue

section .text

_start:
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
    call clients_init
    call setup_listener
    lea rdi, [msg_listen]
    mov esi, msg_listen_len
    call linnea_print_stdout
    mov rdi, [port]
    call linnea_print_u64_stdout
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stdout

.loop:
    call build_pollfds
    mov eax, LINNEA_SYS_POLL
    lea rdi, [pollfds]
    mov rsi, [poll_n]
    mov edx, -1                    ; block: there is no timer work to do
    syscall
    test rax, rax
    js .poll_err
    ; the listener first, so a burst of connections is taken in one pass
    movzx eax, word [pollfds + 6]
    test eax, LINNEA_POLLIN
    jz .clients
    call accept_client
.clients:
    mov rbx, 1
.each:
    cmp rbx, [poll_n]
    jae .loop
    lea r12, [pollfds]
    lea r12, [r12 + rbx * 8]
    movzx r13d, word [r12 + 6]     ; revents
    test r13d, r13d
    jz .next
    mov rax, [poll_map + rbx * 8]
    call client_ptr
    mov r14, rax
    ; Writability first: draining the queue may be what lets a close finish.
    test r13d, LINNEA_POLLOUT
    jz .rd
    mov rdi, r14
    call client_write
    cmp qword [r14 + ws_client.fd], 0
    jl .next                       ; the write closed it
.rd:
    test r13d, LINNEA_POLLIN | LINNEA_POLLERR | LINNEA_POLLHUP
    jz .next
    mov rdi, r14
    call client_read
.next:
    inc rbx
    jmp .each
.poll_err:
    ; EINTR is the ordinary one and comes straight back round. Anything else —
    ; ENOMEM is the realistic candidate — would spin this loop at the speed of
    ; the syscall, burning a core for as long as it lasted, since the wait that
    ; paces the loop is the very thing that failed. Pause first, so a transient
    ; fault costs a tenth of a second and a permanent one is merely idle.
    cmp rax, -4                    ; EINTR
    je .loop
    lea rdi, [pause_100ms]
    xor esi, esi
    mov eax, LINNEA_SYS_NANOSLEEP
    syscall
    jmp .loop


; clients_init() — every slot free.
clients_init:
    xor rcx, rcx
.next:
    cmp rcx, MAX_CLIENTS
    jae .done
    mov rax, rcx
    push rcx
    call client_ptr
    pop rcx
    mov qword [rax + ws_client.fd], -1
    inc rcx
    jmp .next
.done:
    ret


; client_ptr(rax = index) -> rax = &clients[index]
client_ptr:
    imul rax, rax, ws_client_size
    lea rdx, [clients]
    add rax, rdx
    ret


; build_pollfds() — the listener, then every live client, with POLLOUT asked
; for only where there is something queued to write.
build_pollfds:
    push rbx
    push r12
    mov rax, [listen_fd]
    mov [pollfds], eax
    mov word [pollfds + 4], LINNEA_POLLIN
    mov word [pollfds + 6], 0
    mov qword [poll_n], 1
    xor rbx, rbx
.next:
    cmp rbx, MAX_CLIENTS
    jae .done
    mov rax, rbx
    call client_ptr
    mov r12, rax
    cmp qword [r12 + ws_client.fd], 0
    jl .skip
    mov rcx, [poll_n]
    lea rdx, [pollfds]
    lea rdx, [rdx + rcx * 8]
    mov eax, [r12 + ws_client.fd]
    mov [rdx], eax
    mov ax, LINNEA_POLLIN
    mov rsi, [r12 + ws_client.out_len]
    cmp rsi, [r12 + ws_client.out_off]
    jbe .no_out
    or ax, LINNEA_POLLOUT
.no_out:
    mov [rdx + 4], ax
    mov word [rdx + 6], 0
    mov [poll_map + rcx * 8], rbx
    inc rcx
    mov [poll_n], rcx
.skip:
    inc rbx
    jmp .next
.done:
    pop r12
    pop rbx
    ret


; accept_client() — take everything waiting, parking each in a free slot.
;
; The whole queue, not one: poll is level-triggered so a burst would eventually
; be taken either way, but a connection refused for want of a slot has to be
; closed and the next one looked at, or a full table turns every poll into an
; accept-and-close of the same backlog. The listener is non-blocking (see
; setup_listener), so EAGAIN is what ends this loop and is the ordinary exit.
accept_client:
    push rbx
    push r12
.again:
    mov eax, LINNEA_SYS_ACCEPT
    mov rdi, [listen_fd]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .done                       ; EAGAIN: the queue is empty, which is the
                                   ; end of the burst. ECONNABORTED (the peer
                                   ; left before we looked) ends it too — poll
                                   ; will say so again if there is more.
    mov rbx, rax
    ; a free slot, or turn it away
    xor r12, r12
.find:
    cmp r12, MAX_CLIENTS
    jae .full
    mov rax, r12
    call client_ptr
    cmp qword [rax + ws_client.fd], 0
    jl .have
    inc r12
    jmp .find
.full:
    mov eax, LINNEA_SYS_CLOSE
    mov rdi, rbx
    syscall
    jmp .again                     ; and look at the next one, or the backlog
                                   ; is re-offered on every poll for ever
.have:
    mov r12, rax                   ; the slot
    mov eax, LINNEA_SYS_FCNTL
    mov rdi, rbx
    mov esi, LINNEA_F_SETFL
    mov edx, LINNEA_O_NONBLOCK
    syscall
    mov [r12 + ws_client.fd], rbx
    mov qword [r12 + ws_client.state], ST_HANDSHAKE
    mov qword [r12 + ws_client.in_len], 0
    mov qword [r12 + ws_client.out_len], 0
    mov qword [r12 + ws_client.out_off], 0
    jmp .again
.done:
    pop r12
    pop rbx
    ret


; close_client(rdi = client) — drop it, and keep the open count honest.
close_client:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + ws_client.fd], 0
    jl .done
    cmp qword [rbx + ws_client.state], ST_OPEN
    jne .not_open
    dec qword [open_count]
.not_open:
    mov eax, LINNEA_SYS_CLOSE
    mov rdi, [rbx + ws_client.fd]
    syscall
    mov qword [rbx + ws_client.fd], -1
    mov qword [rbx + ws_client.state], ST_HANDSHAKE
    mov qword [rbx + ws_client.in_len], 0
    mov qword [rbx + ws_client.out_len], 0
    mov qword [rbx + ws_client.out_off], 0
.done:
    pop rbx
    ret


; client_read(rdi = client) — take what has arrived and act on it.
client_read:
    push rbx
    push r12
    mov rbx, rdi
    mov rax, IN_BUF
    sub rax, [rbx + ws_client.in_len]
    test rax, rax
    jz .overflow                   ; a head or frame larger than the buffer
    mov r12, rax
    mov eax, LINNEA_SYS_READ
    mov rdi, [rbx + ws_client.fd]
    lea rsi, [rbx + ws_client.in]
    add rsi, [rbx + ws_client.in_len]
    mov rdx, r12
    syscall
    cmp rax, -11                   ; EAGAIN: poll was optimistic, no harm
    je .done
    cmp rax, -4                    ; EINTR: likewise, come back next time
    je .done
    test rax, rax
    jle .gone                      ; 0 = the peer closed; < 0 = a real error
    add [rbx + ws_client.in_len], rax
    cmp qword [rbx + ws_client.state], ST_HANDSHAKE
    jne .frames
    mov rdi, rbx
    call try_handshake
    jmp .done
.frames:
    cmp qword [rbx + ws_client.state], ST_OPEN
    jne .done                      ; draining: nothing more it says matters
    mov rdi, rbx
    call drain_frames
.done:
    pop r12
    pop rbx
    ret
.overflow:
    ; Before the upgrade this is a request head too long to hold, and it is
    ; answered in HTTP like every other refusal. After it, it is a frame larger
    ; than the buffer, which is 1009 on the WebSocket connection.
    cmp qword [rbx + ws_client.state], ST_HANDSHAKE
    jne .overflow_frame
    mov rdi, rbx
    lea rsi, [resp_431]
    mov rdx, resp_431_len
    call refuse
    jmp .done
.overflow_frame:
    mov rdi, rbx
    mov esi, WS_TOO_BIG
    call fail_close
    jmp .done
.gone:
    mov rdi, rbx
    call close_client
    jmp .done


; client_write(rdi = client) — push out what is queued.
client_write:
    push rbx
    mov rbx, rdi
    mov rdx, [rbx + ws_client.out_len]
    sub rdx, [rbx + ws_client.out_off]
    jbe .empty
    mov eax, LINNEA_SYS_SENDTO
    mov rdi, [rbx + ws_client.fd]
    lea rsi, [rbx + ws_client.out]
    add rsi, [rbx + ws_client.out_off]
    mov r10d, LINNEA_MSG_NOSIGNAL | LINNEA_MSG_DONTWAIT
    xor r8d, r8d                   ; a connected socket needs no address...
    xor r9d, r9d                   ; ...and MSG_NOSIGNAL is why this is not write(2)
    syscall
    cmp rax, -11
    je .done                       ; EAGAIN: try again when poll says so
    cmp rax, -4
    je .done                       ; EINTR: likewise
    test rax, rax
    jle .gone
    add [rbx + ws_client.out_off], rax
.empty:
    mov rax, [rbx + ws_client.out_off]
    cmp rax, [rbx + ws_client.out_len]
    jb .done
    mov qword [rbx + ws_client.out_off], 0
    mov qword [rbx + ws_client.out_len], 0
    cmp qword [rbx + ws_client.state], ST_DRAIN
    jne .done
    mov rdi, rbx
    call close_client
.done:
    pop rbx
    ret
.gone:
    mov rdi, rbx
    call close_client
    jmp .done


; queue(rdi = client, rsi = bytes, rdx = length) -> rax = 0, or -1 if the
; client is too far behind to hold it, in which case it has been closed.
queue:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    ; reclaim the written prefix first, so a steady trickle does not creep
    ; the buffer full
    mov rax, [rbx + ws_client.out_off]
    test rax, rax
    jz .no_shift
    cmp rax, [rbx + ws_client.out_len]
    jb .shift
    mov qword [rbx + ws_client.out_off], 0
    mov qword [rbx + ws_client.out_len], 0
    jmp .no_shift
.shift:
    mov rcx, [rbx + ws_client.out_len]
    sub rcx, rax
    lea rdi, [rbx + ws_client.out]
    lea rsi, [rdi + rax]
    rep movsb
    mov rax, [rbx + ws_client.out_len]
    sub rax, [rbx + ws_client.out_off]
    mov [rbx + ws_client.out_len], rax
    mov qword [rbx + ws_client.out_off], 0
.no_shift:
    mov rax, [rbx + ws_client.out_len]
    add rax, r13
    cmp rax, OUT_BUF
    ja .overfull
    lea rdi, [rbx + ws_client.out]
    add rdi, [rbx + ws_client.out_len]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    add [rbx + ws_client.out_len], r13
    xor eax, eax
    jmp .done
.overfull:
    ; not reading its socket, and now 1 KB behind on 30-byte messages
    mov rdi, rbx
    call close_client
    mov rax, -1
.done:
    pop r13
    pop r12
    pop rbx
    ret


; ---- the opening handshake -------------------------------------------

; try_handshake(rdi = client) — if the head is whole, answer it.
try_handshake:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    ; the blank line ending the head
    mov r12, [rbx + ws_client.in_len]
    cmp r12, 4
    jb .done
    lea r13, [rbx + ws_client.in]
    xor rcx, rcx
.scan:
    lea rax, [rcx + 4]
    cmp rax, r12
    ja .done                       ; not yet whole; wait for more
    cmp dword [r13 + rcx], 0x0a0d0a0d
    je .found
    inc rcx
    jmp .scan
.found:
    lea r14, [rcx + 4]             ; head length, blank line included
    ; GET, and nothing else, may be upgraded
    cmp dword [r13], 'GET '
    jne .bad
    ; Upgrade: ... websocket ...
    mov rdi, r13
    mov rsi, r14
    lea rdx, [hn_upgrade]
    mov rcx, hn_upgrade_len
    call hdr_find
    test rax, rax
    jz .bad
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [tok_websocket]
    mov rcx, tok_websocket_len
    call contains_ci
    test eax, eax
    jz .bad
    ; Connection: ... upgrade ...
    mov rdi, r13
    mov rsi, r14
    lea rdx, [hn_conn]
    mov rcx, hn_conn_len
    call hdr_find
    test rax, rax
    jz .bad
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [tok_upgrade]
    mov rcx, tok_upgrade_len
    call contains_ci
    test eax, eax
    jz .bad
    ; Sec-WebSocket-Version: 13, and only 13
    mov rdi, r13
    mov rsi, r14
    lea rdx, [hn_ver]
    mov rcx, hn_ver_len
    call hdr_find
    test rax, rax
    jz .bad
    cmp rdx, ver_13_len
    jne .bad
    cmp byte [rax], '1'
    jne .bad
    cmp byte [rax + 1], '3'
    jne .bad
    ; Origin, when the client sends one, must be on the list
    mov rdi, r13
    mov rsi, r14
    lea rdx, [hn_origin]
    mov rcx, hn_origin_len
    call hdr_find
    test rax, rax
    jz .no_origin
    mov rdi, rax
    mov rsi, rdx
    call origin_allowed
    test eax, eax
    jz .forbidden
.no_origin:
    ; Sec-WebSocket-Key -> the accept token
    mov rdi, r13
    mov rsi, r14
    lea rdx, [hn_key]
    mov rcx, hn_key_len
    call hdr_find
    test rax, rax
    jz .bad
    cmp rdx, 0
    je .bad
    cmp rdx, 64                    ; a 16-byte nonce base64s to 24; be generous
    ja .bad
    push r14
    mov rdi, rax
    mov rcx, rdx
    lea r8, [keybuf]
    xor r9, r9
.copy_key:
    cmp r9, rcx
    jae .key_done
    mov al, [rdi + r9]
    mov [r8 + r9], al
    inc r9
    jmp .copy_key
.key_done:
    lea rdi, [keybuf]
    add rdi, rdx
    lea rsi, [ws_guid]
    mov rcx, ws_guid_len
    push rdx
    rep movsb
    pop rdx
    add rdx, ws_guid_len
    lea rdi, [keybuf]
    mov rsi, rdx
    lea rdx, [digest]
    call linnea_sha1
    lea rdi, [digest]
    mov rsi, 20
    lea rdx, [acceptbuf]
    call linnea_base64_encode      ; rax = 28
    mov r12, rax
    pop r14
    ; 101, in three pieces so the token is never miscounted
    mov rdi, rbx
    lea rsi, [resp_101]
    mov rdx, resp_101_len
    call queue
    test rax, rax
    js .done
    mov rdi, rbx
    lea rsi, [acceptbuf]
    mov rdx, r12
    call queue
    test rax, rax
    js .done
    mov rdi, rbx
    lea rsi, [resp_101_tail]
    mov rdx, resp_101_tail_len
    call queue
    test rax, rax
    js .done
    ; the head is consumed; anything after it is already WebSocket
    mov rdi, rbx
    mov rsi, r14
    call consume
    mov qword [rbx + ws_client.state], ST_OPEN
    inc qword [open_count]
    ; tell the newcomer where the counter stands — only it, since nothing
    ; changed for anyone else
    mov rdi, rbx
    call send_state
    mov rdi, rbx
    call drain_frames
    jmp .done
.forbidden:
    mov rdi, rbx
    lea rsi, [resp_403]
    mov rdx, resp_403_len
    call refuse
    jmp .done
.bad:
    mov rdi, rbx
    lea rsi, [resp_400]
    mov rdx, resp_400_len
    call refuse
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; refuse(rdi = client, rsi = response, rdx = length) — answer in HTTP and go.
refuse:
    push rbx
    mov rbx, rdi
    call queue
    test rax, rax
    js .done                       ; queue already closed it
    mov qword [rbx + ws_client.state], ST_DRAIN
    mov qword [rbx + ws_client.in_len], 0
    mov rdi, rbx
    call client_write              ; usually finishes and closes here
.done:
    pop rbx
    ret


; origin_allowed(rdi = origin, rsi = length) -> eax = 1 if it is on the list
origin_allowed:
    push rbx
    lea rbx, [origins]
.next:
    movzx ecx, byte [rbx]
    test ecx, ecx
    jz .no
    inc rbx
    cmp rcx, rsi
    jne .skip
    xor rdx, rdx
.cmp:
    cmp rdx, rcx
    jae .yes
    mov al, [rbx + rdx]
    cmp al, [rdi + rdx]
    jne .skip
    inc rdx
    jmp .cmp
.skip:
    add rbx, rcx
    jmp .next
.yes:
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret


; ---- framing ---------------------------------------------------------

; consume(rdi = client, rsi = bytes) — drop a processed prefix of .in.
consume:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, [rbx + ws_client.in_len]
    sub r12, rsi                   ; what is left after it — kept out of rcx,
    jbe .all                       ; which rep movsb winds down to zero
    lea rdi, [rbx + ws_client.in]
    lea rsi, [rdi + rsi]
    mov rcx, r12
    rep movsb
    mov [rbx + ws_client.in_len], r12
    jmp .done
.all:
    mov qword [rbx + ws_client.in_len], 0
.done:
    pop r12
    pop rbx
    ret


; drain_frames(rdi = client) — handle every whole frame sitting in .in.
drain_frames:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
.frame:
    cmp qword [rbx + ws_client.state], ST_OPEN
    jne .done                      ; a close or a failure ended it
    mov r12, [rbx + ws_client.in_len]
    cmp r12, 2
    jb .done
    lea r13, [rbx + ws_client.in]
    movzx r14d, byte [r13]         ; FIN | RSV | opcode
    movzx r15d, byte [r13 + 1]     ; MASK | length
    test r14d, 0x70
    jnz .protocol                  ; RSV set, but no extension was negotiated
    test r15d, 0x80
    jz .protocol                   ; RFC 6455 5.1: client frames are masked
    and r15d, 0x7f
    mov rcx, 2                     ; header length so far
    mov rdx, r15                   ; payload length
    cmp r15d, 126
    jb .have_len
    je .len16
    ; 64-bit length. Nothing this backend accepts is remotely that big, but
    ; the field still has to be parsed to know where the frame ends — and it
    ; cannot end inside a buffer this size, so the connection is over either
    ; way.
    cmp r12, 10
    jb .done
    jmp .too_big
.len16:
    cmp r12, 4
    jb .done
    movzx edx, word [r13 + 2]
    xchg dl, dh                    ; big-endian on the wire
    mov rcx, 4
.have_len:
    add rcx, 4                     ; the masking key
    mov rax, rcx
    add rax, rdx
    cmp rax, IN_BUF
    ja .too_big                    ; it can never fit, so waiting is pointless
    cmp r12, rax
    jb .done                       ; the rest is still in flight
    ; control frames: short, and never fragmented (RFC 6455 5.5)
    mov r8d, r14d
    and r8d, 0x0f                  ; opcode
    cmp r8d, 8
    jb .data
    cmp rdx, 125
    ja .protocol
    test r14d, 0x80
    jz .protocol
.data:
    ; unmask in place: payload[i] ^= key[i & 3]
    push rax                       ; the whole frame's length, for consume
    lea rdi, [r13 + rcx]           ; payload
    lea rsi, [r13 + rcx - 4]       ; the four key bytes sit just before it
    xor r9, r9
.unmask:
    cmp r9, rdx
    jae .unmasked
    mov r10, r9
    and r10, 3
    mov al, [rsi + r10]
    xor [rdi + r9], al
    inc r9
    jmp .unmask
.unmasked:
    ; rdi = payload, rdx = its length, r8d = opcode, r14d = the first byte
    call dispatch_frame
    pop rax
    mov rdi, rbx
    mov rsi, rax
    call consume
    jmp .frame
.too_big:
    mov rdi, rbx
    mov esi, WS_TOO_BIG
    call fail_close
    jmp .done
.protocol:
    mov rdi, rbx
    mov esi, WS_PROTOCOL
    call fail_close
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; dispatch_frame(rbx = client, rdi = payload, rdx = length, r8d = opcode,
;                r14d = the frame's first byte) — act on one whole frame.
dispatch_frame:
    push r12
    push r13
    mov r12, rdi
    mov r13, rdx
    cmp r8d, OP_TEXT
    je .text
    cmp r8d, OP_BIN
    je .text
    cmp r8d, OP_PING
    je .ping
    cmp r8d, OP_PONG
    je .done                       ; unsolicited or not, nothing to do
    cmp r8d, OP_CLOSE
    je .close
    cmp r8d, OP_CONT
    je .fragment                   ; nothing was left open to continue
    mov rdi, rbx
    mov esi, WS_PROTOCOL
    call fail_close
    jmp .done
.text:
    test r14d, 0x80
    jz .fragment
    mov rdi, r12
    mov rsi, r13
    call handle_command
    jmp .done
.fragment:
    mov rdi, rbx
    mov esi, WS_UNSUPPORTED
    call fail_close
    jmp .done
.ping:
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    mov ecx, OP_PONG
    call send_frame
    jmp .done
.close:
    ; RFC 6455 5.5.1: answer a close with a close, then stop — and answer it
    ; with the code the peer sent rather than 1000 regardless, which is what
    ; "echoed" is supposed to mean and told a client that closed with 1001
    ; Going Away that we had understood something else.
    ;
    ; An empty payload is a close with no code, answered with none of ours
    ; either (1000 is what the peer is entitled to read into it). A payload of
    ; exactly ONE byte cannot hold a code and is a protocol error, as is a code
    ; outside the ranges 7.4.1 allows a peer to send: 1004 was never assigned,
    ; 1005 and 1006 mean "no code" and "abnormal" and exist only inside an
    ; implementation, and the registered range stops at 1011 until the private
    ; 3000-4999.
    test r13, r13
    jz .close_normal
    cmp r13, 2
    jb .protocol_close             ; one byte: half a code
    movzx eax, byte [r12]
    shl eax, 8
    movzx edx, byte [r12 + 1]
    or eax, edx                    ; the code, big-endian on the wire
    cmp eax, 3000
    jae .close_private
    cmp eax, 1000
    jb .protocol_close
    cmp eax, 1003
    jbe .close_echo
    cmp eax, 1007
    jb .protocol_close             ; 1004, 1005, 1006
    cmp eax, 1011
    ja .protocol_close
.close_echo:
    mov rdi, rbx
    mov esi, eax
    call fail_close
    jmp .done
.close_private:
    cmp eax, 4999
    ja .protocol_close
    jmp .close_echo
.protocol_close:
    mov rdi, rbx
    mov esi, WS_PROTOCOL
    call fail_close
    jmp .done
.close_normal:
    mov rdi, rbx
    mov esi, WS_NORMAL
    call fail_close
.done:
    pop r13
    pop r12
    ret


; handle_command(rbx = client, rdi = payload, rsi = length) — "inc" moves the
; counter and tells everybody; anything else asks, and is told alone.
handle_command:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    cmp r13, cmd_inc_len
    jne .query
    mov al, [r12]
    cmp al, 'i'
    jne .query
    mov al, [r12 + 1]
    cmp al, 'n'
    jne .query
    mov al, [r12 + 2]
    cmp al, 'c'
    jne .query
    inc qword [counter]
    call broadcast_state
    jmp .done
.query:
    mov rdi, rbx
    call send_state
.done:
    pop r13
    pop r12
    pop rbx
    ret


; build_state() -> rax = length of the JSON in statebuf
build_state:
    push rbx
    lea rbx, [statebuf]
    lea rdi, [json_count]
    mov rsi, json_count_len
    mov rdx, rbx
    call copy_bytes
    add rbx, json_count_len
    mov rdi, [counter]
    mov rsi, rbx
    call u64_to_dec
    add rbx, rax
    lea rdi, [json_clients]
    mov rsi, json_clients_len
    mov rdx, rbx
    call copy_bytes
    add rbx, json_clients_len
    mov rdi, [open_count]
    mov rsi, rbx
    call u64_to_dec
    add rbx, rax
    mov byte [rbx], '}'
    inc rbx
    lea rax, [statebuf]
    sub rbx, rax
    mov rax, rbx
    pop rbx
    ret


; send_state(rdi = client) — the current state, to one client.
send_state:
    push rbx
    mov rbx, rdi
    call build_state
    mov rdi, rbx
    lea rsi, [statebuf]
    mov rdx, rax
    mov ecx, OP_TEXT
    call send_frame
    pop rbx
    ret


; broadcast_state() — ...and to every client that finished its handshake.
; This is the part linnea's tunnel makes possible: the push is unsolicited,
; travelling up a connection nobody requested anything on.
broadcast_state:
    push rbx
    push r12
    push r13
    call build_state
    mov r13, rax
    xor rbx, rbx
.next:
    cmp rbx, MAX_CLIENTS
    jae .done
    mov rax, rbx
    call client_ptr
    mov r12, rax
    cmp qword [r12 + ws_client.fd], 0
    jl .skip
    cmp qword [r12 + ws_client.state], ST_OPEN
    jne .skip
    mov rdi, r12
    lea rsi, [statebuf]
    mov rdx, r13
    mov ecx, OP_TEXT
    call send_frame
.skip:
    inc rbx
    jmp .next
.done:
    pop r13
    pop r12
    pop rbx
    ret


; send_frame(rdi = client, rsi = payload, rdx = length, ecx = opcode)
; A server frame is never masked, and nothing sent from here reaches 126
; bytes, so the header is always two bytes.
send_frame:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    cmp r13, 125
    ja .done                       ; would need a longer header; nothing does
    mov eax, ecx
    or eax, 0x80                   ; FIN
    lea rdi, [framebuf]
    mov [rdi], al
    mov [rdi + 1], r13b
    mov rdi, r12
    mov rsi, r13
    lea rdx, [framebuf + 2]
    call copy_bytes
    mov rdi, rbx
    lea rsi, [framebuf]
    mov rdx, r13
    add rdx, 2
    call queue
.done:
    pop r13
    pop r12
    pop rbx
    ret


; fail_close(rdi = client, esi = close code) — send a close frame and stop
; reading. The socket goes once the frame is out.
fail_close:
    push rbx
    push r12
    mov rbx, rdi
    mov r12d, esi
    cmp qword [rbx + ws_client.state], ST_OPEN
    jne .just_go
    mov ax, r12w
    xchg al, ah                    ; the code is big-endian in the payload
    mov [framebuf + 8], ax         ; scratch, clear of send_frame's own use
    mov rdi, rbx
    lea rsi, [framebuf + 8]
    mov rdx, 2
    mov ecx, OP_CLOSE
    call send_frame
    cmp qword [rbx + ws_client.fd], 0
    jl .done                       ; send_frame's queue gave up on it
    dec qword [open_count]         ; it is no longer a broadcast target...
    mov qword [rbx + ws_client.state], ST_DRAIN   ; ...and close_client must
                                                  ; not count it a second time
    mov qword [rbx + ws_client.in_len], 0
    mov rdi, rbx
    call client_write
    jmp .done
.just_go:
    mov rdi, rbx
    call close_client
.done:
    pop r12
    pop rbx
    ret


; ---- request head parsing --------------------------------------------

; hdr_find(rdi = head, rsi = head length, rdx = lowercase name, rcx = its
; length) -> rax = value pointer (0 if absent), rdx = value length.
; Field names are matched case-insensitively; the value is trimmed of the
; optional whitespace either side.
hdr_find:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov r14, rdx                   ; the name
    mov r15, rcx                   ; its length
    mov rbp, rdi                   ; the head
    mov r13, rsi                   ; its length
    xor rbx, rbx
.rl:
    cmp rbx, r13
    jae .absent
    cmp byte [rbp + rbx], 13
    je .rl_done
    inc rbx
    jmp .rl
.rl_done:
    add rbx, 2                     ; past the request line
.line:
    cmp rbx, r13
    jae .absent
    cmp byte [rbp + rbx], 13
    je .absent                     ; the blank line: no fields left
    mov r12, rbx
.colon:
    cmp r12, r13
    jae .absent
    cmp byte [rbp + r12], ':'
    je .have_colon
    cmp byte [rbp + r12], 13
    je .next_line
    inc r12
    jmp .colon
.next_line:
    mov rbx, r12
    jmp .skip_eol
.have_colon:
    mov rax, r12
    sub rax, rbx
    cmp rax, r15
    jne .skip_to_eol
    xor rcx, rcx
    lea r9, [rbp + rbx]            ; two registers is the limit in an address
.icmp:
    cmp rcx, r15
    jae .matched
    movzx eax, byte [r9 + rcx]
    or al, 0x20
    movzx edx, byte [r14 + rcx]
    cmp al, dl
    jne .skip_to_eol
    inc rcx
    jmp .icmp
.matched:
    inc r12
.lead:
    cmp r12, r13
    jae .absent
    cmp byte [rbp + r12], ' '
    je .lead_skip
    cmp byte [rbp + r12], 9
    jne .value
.lead_skip:
    inc r12
    jmp .lead
.value:
    mov rcx, r12
.vend:
    cmp rcx, r13
    jae .vdone
    cmp byte [rbp + rcx], 13
    je .vdone
    inc rcx
    jmp .vend
.vdone:
    mov rdx, rcx
    sub rdx, r12
.trail:
    test rdx, rdx
    jz .ret
    lea rax, [r12 + rdx - 1]
    cmp byte [rbp + rax], ' '
    je .trail_cut
    cmp byte [rbp + rax], 9
    jne .ret
.trail_cut:
    dec rdx
    jmp .trail
.ret:
    lea rax, [rbp + r12]
    jmp .out
.skip_to_eol:
    mov rbx, r12
.eol:
    cmp rbx, r13
    jae .absent
    cmp byte [rbp + rbx], 13
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
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; contains_ci(rdi = haystack, rsi = its length, rdx = lowercase needle,
;             rcx = its length) -> eax = 1 if present.
; Both Upgrade and Connection may carry a comma-separated list, and a search
; is the honest way to read one without a tokeniser.
contains_ci:
    push rbx
    cmp rsi, rcx
    jb .no                         ; or the bound below underflows and the
    xor rbx, rbx                   ; search runs off the end of the head
.at:
    mov rax, rsi
    sub rax, rcx
    cmp rbx, rax
    ja .no
    xor r8, r8
    lea r10, [rdi + rbx]           ; likewise
.cmp:
    cmp r8, rcx
    jae .yes
    movzx eax, byte [r10 + r8]
    or al, 0x20
    movzx r9d, byte [rdx + r8]
    cmp al, r9b
    jne .step
    inc r8
    jmp .cmp
.step:
    inc rbx
    jmp .at
.yes:
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret


; ---- small helpers ----------------------------------------------------

; copy_bytes(rdi = src, rsi = length, rdx = dst)
copy_bytes:
    push rcx
    mov rcx, rsi
    mov rsi, rdi
    mov rdi, rdx
    rep movsb
    pop rcx
    ret


; u64_to_dec(rdi = value, rsi = out) -> rax = digits written
u64_to_dec:
    push rbx
    push r12
    mov rax, rdi
    mov r12, rsi
    sub rsp, 32
    mov rbx, 32                    ; fill a scratch area backwards
    mov r8, 10
.digit:
    xor edx, edx
    div r8
    dec rbx
    add dl, '0'
    mov [rsp + rbx], dl
    test rax, rax
    jnz .digit
    mov rcx, 32
    sub rcx, rbx                   ; how many digits
    mov rax, rcx
    lea rsi, [rsp + rbx]
    mov rdi, r12
    rep movsb
    add rsp, 32
    pop r12
    pop rbx
    ret


; cstr_len(rdi = NUL-terminated string) -> rax = length
cstr_len:
    xor rax, rax
.next:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    jmp .next
.done:
    ret


; parse_u64(rdi = digits, rsi = length) -> rax = value, 0 if it is not a number
parse_u64:
    xor rax, rax
    xor rcx, rcx
.next:
    cmp rcx, rsi
    jae .done
    movzx edx, byte [rdi + rcx]
    cmp dl, '0'
    jb .bad
    cmp dl, '9'
    ja .bad
    imul rax, rax, 10
    sub dl, '0'
    add rax, rdx
    inc rcx
    jmp .next
.bad:
    xor eax, eax
.done:
    ret


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
    ; ...and non-blocking, which accept_client's loop has always assumed and
    ; this never actually set. Readiness from poll(2) is not a promise that a
    ; connection is still there to take — the peer may have reset it in between,
    ; and on a blocking listener that is a single-threaded server asleep in
    ; accept(2) with a poll set it is no longer watching.
    mov eax, LINNEA_SYS_FCNTL
    mov rdi, rbx
    mov esi, LINNEA_F_SETFL
    mov edx, LINNEA_O_NONBLOCK
    syscall
    pop rbx
    ret
.fail:
    lea rdi, [msg_bind_fail]
    mov esi, msg_bind_fail_len
    call linnea_print_stdout
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
