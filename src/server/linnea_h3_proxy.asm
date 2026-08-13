; linnea_h3_proxy.asm — proxying an HTTP/3 request to an HTTP/1.1 upstream.
;
; The backend only ever speaks h1, so a proxied h3 request is an ordinary h1
; exchange on a socket of its own. What is new is that there is no client
; socket to answer on: the response is owed to ONE STREAM of a QUIC connection,
; which lives in a different pool and is driven by datagrams, not completions.
;
; Two decisions follow from that, and they are what make this small.
;
; The upstream half borrows an ordinary linnea_connection. Not a slot pool of
; its own (which is how proxy-over-h2 does it): the connection already carries
; up_fd, up_buf, the send cursor, the spill file and proxy_state, and the loop
; already has .on_connect / .on_up_send / .on_up_recv keyed on its index, with
; linked timeouts, the max_upstream ceiling and the 502/504 mapping around
; them. The leg sets .fd to -1 and names its owner in .h3_owner/.h3_qidx/
; .h3_qgen/.h3_sid; every client-facing path tests .h3_owner and diverts here.
;
; The response is buffered whole before any of it is sent. It is captured into
; the O_TMPFILE the request-body machinery already uses and then mapped, which
; is exactly the shape a linnea_quic_txstream slot wants — head plus a mapping
; — so the QUIC pump needs to learn nothing about sockets: it streams a proxied
; response the same way it streams a file, congestion- and flow-controlled,
; interleaved with the connection's other responses by priority. A chunked
; upstream is de-chunked for free on the way into the file.
;
; The cost is that a slow backend holds a connection slot and the client waits
; for the last byte before it sees the first. This backend answers small JSON;
; when that stops being true, the thing to change is this file, not the pump.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_connection.inc"
%include "linnea_hpack.inc"
%include "linnea_http.inc"
%include "linnea_http3.inc"
%include "linnea_uring.inc"

global linnea_h3_proxy_start
global linnea_h3_proxy_head
global linnea_h3_proxy_body
global linnea_h3_proxy_deliver
global linnea_h3_proxy_fail
global linnea_h3_proxy_release
global linnea_h3_proxy_cancel

extern linnea_connection_at
extern linnea_connection_alloc
extern linnea_connection_free
extern linnea_upstream_open
extern linnea_upstream_closed
extern linnea_upstream_count
extern linnea_upstream_limit
extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_iequal
extern linnea_spill_open
extern linnea_spill_write
extern linnea_spill_chunked
extern linnea_spill_release
extern linnea_qpack_encode_proxy
extern linnea_qpack_hsts_ptr
extern linnea_qpack_hsts_len
extern linnea_qpack_nosniff
extern linnea_quic_varint_encode
extern linnea_h3_build_response
extern linnea_h3_build_canned
; the request body the serve path parked for us, and where the serve path looks
; for this module (it is installed as a hook, so the framing and response
; builders stay linkable without any of the upstream machinery)
extern linnea_h3_proxy_body_ptr
extern linnea_h3_proxy_body_len
extern linnea_h3_body_fd
; the delivery parameter block and the entry point that consumes it, both in
; the QUIC server: the response stream slots are its to hand out
extern linnea_quic_h3_deliver
extern linnea_h3d_qidx
extern linnea_h3d_qgen
extern linnea_h3d_sid
extern linnea_h3d_hdr
extern linnea_h3d_hlen
extern linnea_h3d_base
extern linnea_h3d_size
extern linnea_h3d_foff
extern linnea_h3d_flen
; the access line, written here rather than through the h1 proxy log: that one
; reads the request out of a client connection's buffers, which an h3 leg has
; none of
extern linnea_log_access
extern linnea_log_acc_peer
extern linnea_log_acc_peer_len
extern linnea_log_acc_meth
extern linnea_log_acc_meth_len
extern linnea_log_acc_tgt
extern linnea_log_acc_tgt_len
extern linnea_log_acc_host
extern linnea_log_acc_host_len
extern linnea_log_acc_proto
extern linnea_log_acc_proto_len
extern linnea_log_acc_status
extern linnea_log_acc_bytes

section .rodata

http11_host:   db " HTTP/1.1", 13, 10, "Host: "
http11_host_len equ $ - http11_host
hdr_clen:      db "Content-Length: "
hdr_clen_len   equ $ - hdr_clen
; RFC 9110 7.6.3: name the hop and the protocol it was received on. The client
; spoke HTTP/3, so "3" is the protocol-name-less form 7.6.3 allows for HTTP.
hdr_via:       db "Via: 3 linnea", 13, 10
hdr_via_len    equ $ - hdr_via
hdr_close:     db "Connection: close", 13, 10, 13, 10
hdr_close_len  equ $ - hdr_close
proto_h3:      db "HTTP/3"
proto_h3_len   equ $ - proto_h3
hn_te:         db "transfer-encoding"
hn_cl:         db "content-length"
val_chunked:   db "chunked"
txt_plain:     db "text/plain; charset=utf-8"
txt_plain_len  equ $ - txt_plain
body_502:      db "502 Bad Gateway", 10
body_502_len   equ $ - body_502
body_504:      db "504 Gateway Timeout", 10
body_504_len   equ $ - body_504
body_503:      db "503 Service Unavailable", 10
body_503_len   equ $ - body_503
body_413:      db "413 Content Too Large", 10
body_413_len   equ $ - body_413

section .bss
; Legs in flight. Only so that a QUIC connection closing on a server that
; proxies nothing over h3 — the usual case — can skip the pool walk entirely.
h3_legs_live: resq 1
num_buf:  resb 24
; The response head as it goes out: the HTTP/3 HEADERS frame and the DATA frame
; header. It lives only for the length of one delivery — the loop is
; single-threaded, and the head is written into the capture file (or copied
; into a response slot, for a canned error) before anything else can run.
h3p_head: resb LINNEA_H3_PROXY_RESERVE
h3p_fs:   resb LINNEA_H3_PROXY_RESERVE  ; the QPACK field section before framing

section .text

; linnea_h3_proxy_start(rdi = req*, rsi = location*, rdx = vhost server*,
;   rcx = QUIC conn index, r8 = its generation, r9 = stream id)
;   -> rax = 0 when the request is on its way upstream and the stream is
;      parked, or an HTTP status to answer on the stream instead.
; The request body is taken from linnea_h3_proxy_body_ptr/_len, set by the
; caller — an h3 body is already whole and in memory (the reassembly joined the
; DATA frames), so it is copied in behind the head rather than streamed.
linnea_h3_proxy_start:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 24
    mov rbx, rdi                     ; req
    mov [rsp], rsi                   ; location
    mov [rsp + 8], rdx               ; vhost
    mov r13, rcx                     ; quic conn index
    mov r14, r8                      ; its generation
    mov r15, r9                      ; stream id
    ; A rebuild that overflowed h3_hdrs_buf parked hb_cur past hb_end. Forwarding
    ; what fits would send the backend a request missing headers it was given,
    ; which is worse than refusing: 431 says which side the limit is on.
    mov rax, [rbx + linnea_h2_req.hb_cur]
    cmp rax, [rbx + linnea_h2_req.hb_end]
    ja .st_431
    ; the backend gets no more connections than it was sized for
    call linnea_upstream_count
    cmp rax, [linnea_upstream_limit]
    jae .st_503
    call linnea_connection_alloc     ; -> rax = leg, or 0 when the pool is full
    test rax, rax
    jz .st_503
    mov r12, rax                     ; the upstream leg
    ; Claim it as an h3 leg BEFORE anything can fail: every teardown path from
    ; here on tests .h3_owner to know it must not touch a client socket.
    mov qword [r12 + linnea_connection.h3_owner], 1
    inc qword [h3_legs_live]         ; counted for exactly as long as that is set
    mov qword [r12 + linnea_connection.h3_cancel], 0
    mov dword [r12 + linnea_connection.fd], -1        ; no client socket at all
    mov [r12 + linnea_connection.h3_qidx], r13
    mov [r12 + linnea_connection.h3_qgen], r14
    mov [r12 + linnea_connection.h3_sid], r15
    mov qword [r12 + linnea_connection.h3_hlen], 0
    mov qword [r12 + linnea_connection.h3_nobody], 0
    ; A recycled slot carries the last client's address, and the per-source
    ; connection cap counts every in_use slot whose peer_ip matches. A leg that
    ; kept one would charge that client for a connection it never made. (.peer,
    ; the formatted text beside it, is log-only and is filled in below.)
    mov qword [r12 + linnea_connection.peer_ip_len], 0
    mov qword [r12 + linnea_connection.keep_alive], 0
    mov qword [r12 + linnea_connection.upgrade], 0    ; h3 has no upgrade to forward
    mov qword [r12 + linnea_connection.conn_opts], 0
    mov qword [r12 + linnea_connection.up_status], 0
    mov qword [r12 + linnea_connection.relayed], 0
    mov qword [r12 + linnea_connection.up_len], 0
    mov qword [r12 + linnea_connection.body_rem], 0
    mov qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_NONE
    mov rax, [rsp]
    mov [r12 + linnea_connection.location], rax
    mov rax, [rsp + 8]
    mov [r12 + linnea_connection.vhost], rax
    ; a HEAD request takes no body, whatever the backend sends back
    xor eax, eax
    cmp qword [rbx + linnea_h2_req.method_len], 4
    jne .st_nothead
    mov rcx, [rbx + linnea_h2_req.method_ptr]
    cmp dword [rcx], 0x44414548      ; "HEAD", little-endian
    jne .st_nothead
    mov eax, 1
.st_nothead:
    mov [r12 + linnea_connection.is_head], rax
    ; --- the access line's who-and-what, parked for the delivery -------
    ; The log block the QUIC server filled for this request points into the
    ; reassembly buffer and is shared with every other stream, so none of it
    ; survives to the completion that finally answers. Take a copy.
    mov rdi, r12
    mov rsi, [linnea_log_acc_meth]
    mov rdx, [linnea_log_acc_meth_len]
    mov ecx, 0
    mov r8d, LINNEA_H3_LG_METH_MAX
    call .lg_park
    mov [r12 + linnea_connection.h3_lg_meth_len], rax
    mov rdi, r12
    mov rsi, [linnea_log_acc_tgt]
    mov rdx, [linnea_log_acc_tgt_len]
    mov ecx, LINNEA_H3_LG_TGT
    mov r8d, LINNEA_H3_LG_TGT_MAX
    call .lg_park
    mov [r12 + linnea_connection.h3_lg_tgt_len], rax
    mov rdi, r12
    mov rsi, [linnea_log_acc_host]
    mov rdx, [linnea_log_acc_host_len]
    mov ecx, LINNEA_H3_LG_HOST
    mov r8d, LINNEA_H3_LG_HOST_MAX
    call .lg_park
    mov [r12 + linnea_connection.h3_lg_host_len], rax
    ; the peer text goes in the connection's own .peer, which nothing but the
    ; log reads (the per-source cap counts .peer_ip, zeroed above)
    mov qword [r12 + linnea_connection.peer_len], 0
    mov rsi, [linnea_log_acc_peer]
    test rsi, rsi
    jz .st_peer_done                 ; no peer was set (a driver with no socket)
    mov rdx, [linnea_log_acc_peer_len]
    cmp rdx, 80                      ; .peer is 80 bytes; an address is far less
    jbe .st_peer_fits
    mov edx, 80
.st_peer_fits:
    mov [r12 + linnea_connection.peer_len], rdx
    lea rdi, [r12 + linnea_connection.peer]
    mov rcx, rdx
    rep movsb
.st_peer_done:
    ; --- the request head, into up_buf ---------------------------------
    ; Bound it first: .up_append is an unchecked copy, and a head that outgrew
    ; up_buf would run into the next connection in the pool.
    mov rcx, [rbx + linnea_h2_req.method_len]
    add rcx, [rbx + linnea_h2_req.path_len]
    add rcx, [rbx + linnea_h2_req.auth_len]
    mov rax, [rbx + linnea_h2_req.hb_cur]
    sub rax, [rbx + linnea_h2_req.hb_start]
    add rcx, rax
    add rcx, http11_host_len + hdr_clen_len + hdr_via_len + hdr_close_len + 32
    ; ...and the body, when it is the in-memory kind. A captured body is mapped
    ; and queued behind the head (.st_body_file) and costs up_buf nothing, but a
    ; request that arrived whole in one datagram is COPIED in behind the head by
    ; the same unchecked .up_append this bound exists to protect — and the bound
    ; did not count it.
    ;
    ; Nothing reachable overruns it today: a datagram is at most
    ; LINNEA_QUIC_RXBUF_SIZE, and the header-list bound caps how far QPACK can
    ; expand that into rebuilt lines, so head and body together stay well inside
    ; up_buf. But that is arithmetic across three constants in two other files,
    ; written down nowhere, and it is the only thing between an unchecked copy
    ; and the next connection in the pool.
    cmp qword [linnea_h3_body_fd], -1
    jne .st_bound_done
    add rcx, [linnea_h3_proxy_body_len]
.st_bound_done:
    cmp rcx, LINNEA_CONN_UP_BUF
    ja .st_toobig
    lea rbp, [r12 + linnea_connection.up_buf]         ; append cursor
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    mov rsi, [rbx + linnea_h2_req.method_len]
    call .up_append
    mov byte [rbp], ' '
    inc rbp
    mov rdi, [rbx + linnea_h2_req.path_ptr]
    mov rsi, [rbx + linnea_h2_req.path_len]
    call .up_append
    lea rdi, [http11_host]                            ; " HTTP/1.1" CRLF "Host: "
    mov esi, http11_host_len
    call .up_append
    ; :authority is what the request was addressed to; linnea_hpack_req_check
    ; has already made it agree with any Host the client also sent.
    mov rdi, [rbx + linnea_h2_req.auth_ptr]
    test rdi, rdi
    jz .st_nohost
    mov rsi, [rbx + linnea_h2_req.auth_len]
    call .up_append
.st_nohost:
    mov word [rbp], 0x0a0d
    add rbp, 2
    ; the client's own fields, rebuilt as h1 lines during the QPACK decode:
    ; hop-by-hop names refused outright, host/content-length/te left to us
    mov rdi, [rbx + linnea_h2_req.hb_start]
    mov rsi, [rbx + linnea_h2_req.hb_cur]
    sub rsi, rdi
    call .up_append
    ; Content-Length is ours to declare: the body is whole and counted here,
    ; whatever framing (or none) the client used to send it.
    mov r13, [linnea_h3_proxy_body_len]
    test r13, r13
    jz .st_nobody
    lea rdi, [hdr_clen]
    mov esi, hdr_clen_len
    call .up_append
    mov rdi, r13
    lea rsi, [num_buf]
    call linnea_string_from_u64      ; rax = digits written
    lea rdi, [num_buf]
    mov rsi, rax
    call .up_append
    mov word [rbp], 0x0a0d
    add rbp, 2
.st_nobody:
    lea rdi, [hdr_via]
    mov esi, hdr_via_len
    call .up_append
    lea rdi, [hdr_close]             ; one request per upstream connection,
    mov esi, hdr_close_len           ; then the empty line that ends the head
    call .up_append
.st_sendwin:
    lea rax, [r12 + linnea_connection.up_buf]
    mov [r12 + linnea_connection.out_ptr], rax
    mov rcx, rbp
    sub rcx, rax
    mov [r12 + linnea_connection.out_rem], rcx
    ; The body is QUEUED behind the head rather than copied in with it: the
    ; head send drains file_ptr/file_rem next, which is how h1 has always sent
    ; a captured upload. Copying was fine while a body could not outgrow the
    ; buffer; now that a request stream is consumed as it arrives, it can.
    mov qword [r12 + linnea_connection.file_rem], 0
    test r13, r13
    jz .st_socket
    mov rax, [linnea_h3_body_fd]
    cmp rax, -1
    jne .st_body_file
    ; still in memory (a request that arrived in one frame): it fits, and the
    ; bytes live only as long as this datagram, so take a copy behind the head
    mov rdi, [linnea_h3_proxy_body_ptr]
    mov rsi, r13
    call .up_append
    mov rcx, rbp
    lea rax, [r12 + linnea_connection.up_buf]
    sub rcx, rax
    mov [r12 + linnea_connection.out_rem], rcx
    jmp .st_socket
.st_body_file:
    ; captured on the way in: map it, and let the leg own the mapping. The
    ; descriptor is the caller's to close — a mapping outlives it.
    xor edi, edi
    mov rsi, r13
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, eax
    xor r9d, r9d
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .st_nomap
    mov [r12 + linnea_connection.file_base], rax
    mov [r12 + linnea_connection.file_ptr], rax
    mov [r12 + linnea_connection.file_size], r13
    mov [r12 + linnea_connection.file_rem], r13
.st_socket:
    ; --- the socket, which the loop then connects --------------------
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .st_nosock
    mov [r12 + linnea_connection.up_fd], eax
    call linnea_upstream_open
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CONNECTING
    ; The connect is the io_uring loop's to queue, and this module is not the
    ; loop's to reach into — the loop installs the hook at startup, the way the
    ; QUIC pool takes its free hook. Without one (a unit test with no loop
    ; behind it) nothing would ever drive the leg, so say so rather than park a
    ; stream that can never be answered.
    mov rax, [linnea_h3_proxy_arm_hook]
    test rax, rax
    jz .st_noloop
    mov rdi, r12
    call rax
    xor eax, eax                     ; parked: no response on this stream yet
    jmp .st_ret
.st_noloop:
    mov rdi, r12
    call linnea_h3_proxy_release
    mov eax, 502
    jmp .st_ret
.st_nomap:
    mov rdi, r12
    call .st_drop
    mov eax, 500                     ; the body is on disk and we cannot read it
    jmp .st_ret
.st_nosock:
    mov rdi, r12
    call .st_drop
    mov eax, 502
    jmp .st_ret
.st_toobig:
    mov rdi, r12
    call .st_drop
    mov eax, 431
    jmp .st_ret
.st_431:
    mov eax, 431
    jmp .st_ret
.st_503:
    ; at the ceiling, or out of connection slots: 503 says "try again", which is
    ; true, where 502 would blame a backend that was never asked
    mov eax, 503
.st_ret:
    add rsp, 24
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .st_drop(rdi = leg) — give a leg back before it was ever armed. The ordinary
; release does exactly the right thing here: no socket is open yet on any path
; that reaches this, so it closes nothing, and going through it is what keeps
; the live-leg count in one place rather than two.
.st_drop:
    jmp linnea_h3_proxy_release

; .lg_park(rdi = leg, rsi = text, rdx = its length, ecx = offset in in_buf,
;   r8d = the room there) -> rax = the length actually kept.
; A missing field (a request with no :authority, say) parks as nothing, which
; the log prints as "-" exactly as it would have.
.lg_park:
    mov rax, rdx
    test rsi, rsi
    jnz .lp_have
    xor eax, eax
    ret
.lp_have:
    cmp rax, r8
    jbe .lp_fits
    mov rax, r8
.lp_fits:
    push rax
    lea rdi, [rdi + linnea_connection.in_buf]
    add rdi, rcx
    mov rcx, rax
    rep movsb
    pop rax
    ret

; .lg_at(rdi = leg, esi = offset in in_buf) -> rax = the parked text's address.
.lg_at:
    lea rax, [rdi + linnea_connection.in_buf]
    add rax, rsi
    ret

; .lg_publish(rdi = leg) — put this leg's parked access-line facts back into
; the shared log block, so the line about to be written names the request that
; was actually made rather than whichever one was served most recently.
.lg_publish:
    push rbx
    mov rbx, rdi
    lea rax, [rbx + linnea_connection.peer]
    mov [linnea_log_acc_peer], rax
    mov rax, [rbx + linnea_connection.peer_len]
    mov [linnea_log_acc_peer_len], rax
    mov rdi, rbx
    xor esi, esi
    call .lg_at
    mov [linnea_log_acc_meth], rax
    mov rax, [rbx + linnea_connection.h3_lg_meth_len]
    mov [linnea_log_acc_meth_len], rax
    mov rdi, rbx
    mov esi, LINNEA_H3_LG_TGT
    call .lg_at
    mov [linnea_log_acc_tgt], rax
    mov rax, [rbx + linnea_connection.h3_lg_tgt_len]
    mov [linnea_log_acc_tgt_len], rax
    mov rdi, rbx
    mov esi, LINNEA_H3_LG_HOST
    call .lg_at
    mov [linnea_log_acc_host], rax
    mov rax, [rbx + linnea_connection.h3_lg_host_len]
    mov [linnea_log_acc_host_len], rax
    pop rbx
    ret

; .up_append(rdi = src, rsi = len) — copy to rbp and advance it. rbx, r12 and
; r13 are the caller's; rbp is the shared cursor.
.up_append:
    mov rcx, rsi
    mov rsi, rdi
    mov rdi, rbp
    rep movsb
    mov rbp, rdi
    ret

; linnea_h3_proxy_head(rdi = leg) -> rax = LINNEA_HTTP_HEAD_MORE / _READY /
; _BAD, the same verdicts linnea_http_proxy_head returns, so the loop's
; surrounding re-arm logic is shared.
; READY means up_buf holds the whole response head (.h3_hlen bytes of it), the
; status and body framing are recorded, and the leg has moved to capturing the
; body. Nothing is rewritten: the head is re-encoded in QPACK at delivery, so
; it is kept as the upstream wrote it.
linnea_h3_proxy_head:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    lea r12, [rbx + linnea_connection.up_buf]
    mov r13, [rbx + linnea_connection.up_len]
    cmp r13, 12                      ; "HTTP/1.1 200" at the very least
    jb .ph_more
    mov eax, [r12]
    cmp eax, 'HTTP'
    jne .ph_bad
    cmp byte [r12 + 4], '/'
    jne .ph_bad
    cmp byte [r12 + 8], ' '
    jne .ph_bad
    xor eax, eax
    xor ecx, ecx
.ph_status:
    cmp ecx, 3
    jae .ph_status_done
    movzx edx, byte [r12 + rcx + 9]
    sub edx, '0'
    cmp edx, 9
    ja .ph_bad
    imul eax, eax, 10
    add eax, edx
    inc ecx
    jmp .ph_status
.ph_status_done:
    mov [rbx + linnea_connection.up_status], rax
    ; the head ends at the first CRLF CRLF
    xor ecx, ecx
.ph_scan:
    lea rax, [rcx + 4]
    cmp rax, r13
    ja .ph_more
    cmp dword [r12 + rcx], 0x0A0D0A0D
    je .ph_found
    inc rcx
    jmp .ph_scan
.ph_found:
    add rcx, 4
    cmp rcx, LINNEA_H3_PROXY_RHEAD_MAX
    ja .ph_bad                       ; the same head h2 refuses to relay
    mov [rbx + linnea_connection.h3_hlen], rcx
    ; --- body framing: Transfer-Encoding: chunked wins over Content-Length,
    ; and a response that carries no body at all overrides both.
    mov qword [rbx + linnea_connection.capture_chunked], 0
    mov rdi, r12
    mov rsi, rcx
    lea rdx, [hn_te]
    mov ecx, 17
    call .ph_find                    ; -> rax = value ptr, rdx = value length
    test rdx, rdx
    jz .ph_clen
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [val_chunked]
    mov ecx, 7
    call .ph_val_has
    test eax, eax
    jz .ph_clen
    mov qword [rbx + linnea_connection.capture_chunked], 1
    mov qword [rbx + linnea_connection.body_rem], -1
    ; ...but a response carrying BOTH is contradictory, and the two lengths
    ; disagreeing is the whole response-splitting vector (RFC 9112 6.3). h1 has
    ; always refused it — "forwarding both would let a compromised backend split
    ; the next keep-alive response" — while h2 and h3 each picked a side and
    ; relayed. One backend answer, three client-visible outcomes: h1 502, h2 a
    ; 200 stating the upstream's content-length over a de-chunked body that is a
    ; different length (which its own client rejects as PROTOCOL_ERROR), h3 a
    ; clean 200 with the chunked length restated. Which one a client sees came
    ; down to the protocol it happened to negotiate. Refuse, like h1.
    mov rdi, r12
    mov rsi, [rbx + linnea_connection.h3_hlen]
    lea rdx, [hn_cl]
    mov ecx, 14
    call .ph_find                    ; preserves rbx/r12/r13
    test rdx, rdx
    jnz .ph_bad
    jmp .ph_nobody_chk
.ph_clen:
    mov rdi, r12
    mov rsi, [rbx + linnea_connection.h3_hlen]
    lea rdx, [hn_cl]
    mov ecx, 14
    call .ph_find
    test rdx, rdx
    jz .ph_close_delim
    mov rdi, rax
    mov rsi, rdx
    call .ph_dec_u64                 ; -> rax = value, or -1
    cmp rax, -1
    je .ph_bad
    mov [rbx + linnea_connection.body_rem], rax
    jmp .ph_nobody_chk
.ph_close_delim:
    mov qword [rbx + linnea_connection.body_rem], -1   ; until the upstream closes
.ph_nobody_chk:
    ; A HEAD request, a 204, a 304 or any 1xx carries no body whatever the
    ; headers say (RFC 9110 6.4.1). Reading one would hang on a backend that
    ; keeps the connection open, and de-chunking bytes that are not there is
    ; how a proxy invents a body.
    cmp qword [rbx + linnea_connection.is_head], 0
    jne .ph_nobody
    mov rax, [rbx + linnea_connection.up_status]
    cmp rax, 204
    je .ph_nobody
    cmp rax, 304
    je .ph_nobody
    cmp rax, 200
    jb .ph_nobody
    jmp .ph_ready
.ph_nobody:
    mov qword [rbx + linnea_connection.body_rem], 0
    mov qword [rbx + linnea_connection.capture_chunked], 0
    mov qword [rbx + linnea_connection.h3_nobody], 1
.ph_ready:
    ; Open the capture file now and start the body a fixed distance into it,
    ; leaving a hole for this response's own head. The head cannot be written
    ; yet — its content-length is whatever the capture turns out to be — and it
    ; has to precede the body in the mapping, so the space is claimed up front.
    ; The hole costs nothing until it is written to.
    mov rdi, rbx
    call linnea_spill_open
    test eax, eax
    js .ph_bad
    mov edi, [rbx + linnea_connection.spill_fd]
    mov esi, LINNEA_H3_PROXY_RESERVE
    xor edx, edx                     ; SEEK_SET
    mov eax, LINNEA_SYS_LSEEK
    syscall
    cmp rax, -4095
    jae .ph_bad
    mov qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_H3BODY
    mov eax, LINNEA_HTTP_HEAD_READY
    jmp .ph_ret
.ph_more:
    mov eax, LINNEA_HTTP_HEAD_MORE
    jmp .ph_ret
.ph_bad:
    mov eax, LINNEA_HTTP_HEAD_BAD
.ph_ret:
    pop r13
    pop r12
    pop rbx
    ret

; .ph_find(rdi = head, rsi = head len, rdx = name, ecx = name len)
;   -> rax = value ptr, rdx = value length (0 = the field is absent).
; The value is trimmed of leading spaces; a line without a colon is skipped.
.ph_find:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rdi                     ; head
    mov r12, rsi                     ; head length
    mov r13, rdx                     ; name
    mov r14d, ecx                    ; name length
    xor r15d, r15d
.pf_status_eol:
    cmp r15, r12
    jae .pf_none
    cmp byte [rbx + r15], 13
    je .pf_status_done
    inc r15
    jmp .pf_status_eol
.pf_status_done:
    add r15, 2
.pf_line:
    cmp r15, r12
    jae .pf_none
    mov rbp, r15
.pf_eol:
    cmp rbp, r12
    jae .pf_none
    cmp byte [rbx + rbp], 13
    je .pf_have
    inc rbp
    jmp .pf_eol
.pf_have:
    cmp rbp, r15
    je .pf_none                      ; the empty line ends the head
    mov rcx, r15
.pf_colon:
    cmp rcx, rbp
    jae .pf_next
    cmp byte [rbx + rcx], ':'
    je .pf_colon_found
    inc rcx
    jmp .pf_colon
.pf_colon_found:
    mov rax, rcx
    sub rax, r15                     ; this line's name length
    cmp rax, r14
    jne .pf_next
    push rcx
    lea rdi, [rbx + r15]
    mov rsi, rax
    mov rdx, r13
    mov rcx, r14
    call linnea_string_iequal
    pop rcx
    test eax, eax
    jz .pf_next
    inc rcx                          ; past the colon
.pf_lead:
    cmp rcx, rbp
    jae .pf_val
    cmp byte [rbx + rcx], ' '
    jne .pf_val
    inc rcx
    jmp .pf_lead
.pf_val:
    lea rax, [rbx + rcx]
    mov rdx, rbp
    sub rdx, rcx
    jmp .pf_ret
.pf_next:
    lea r15, [rbp + 2]
    jmp .pf_line
.pf_none:
    xor eax, eax
    xor edx, edx
.pf_ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .ph_val_has(rdi = value, rsi = len, rdx = token, ecx = token len)
;   -> eax = 1 when the comma-separated value lists the token.
.ph_val_has:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14d, ecx
    xor r15d, r15d                   ; element start
.vh_elem:
    cmp r15, r12
    jae .vh_no
    cmp byte [rbx + r15], ' '
    je .vh_skip
    cmp byte [rbx + r15], 9
    jne .vh_end_scan
.vh_skip:
    inc r15
    jmp .vh_elem
.vh_end_scan:
    mov rcx, r15
.vh_find_comma:
    cmp rcx, r12
    jae .vh_test
    cmp byte [rbx + rcx], ','
    je .vh_test
    inc rcx
    jmp .vh_find_comma
.vh_test:
    mov rax, rcx
    sub rax, r15                     ; element length, trailing space trimmed
    lea rdx, [rbx + r15]             ; the element's first byte
.vh_trim:
    test rax, rax
    jz .vh_after
    movzx r8d, byte [rdx + rax - 1]
    cmp r8b, ' '
    je .vh_trim_one
    cmp r8b, 9
    jne .vh_after
.vh_trim_one:
    dec rax
    jmp .vh_trim
.vh_after:
    cmp rax, r14
    jne .vh_next
    push rcx
    lea rdi, [rbx + r15]
    mov rsi, rax
    mov rdx, r13
    mov rcx, r14
    call linnea_string_iequal
    pop rcx
    test eax, eax
    jnz .vh_yes
.vh_next:
    lea r15, [rcx + 1]
    cmp rcx, r12
    jb .vh_elem
.vh_no:
    xor eax, eax
    jmp .vh_ret
.vh_yes:
    mov eax, 1
.vh_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .ph_dec_u64(rdi = digits, rsi = len) -> rax = value, or -1 when the text is
; not a plain decimal number or would overflow.
.ph_dec_u64:
    xor eax, eax
    test rsi, rsi
    jz .du_bad
    xor ecx, ecx
.du_loop:
    cmp rcx, rsi
    jae .du_ret
    movzx edx, byte [rdi + rcx]
    sub edx, '0'
    cmp edx, 9
    ja .du_bad
    mov r8, rax
    shl rax, 3
    lea rax, [rax + r8 * 2]          ; value * 10
    jc .du_bad
    add rax, rdx
    jc .du_bad
    inc rcx
    jmp .du_loop
.du_bad:
    mov rax, -1
.du_ret:
    ret

; linnea_h3_proxy_body(rdi = leg, rsi = bytes, rdx = count)
;   -> rax = 0 need more, 1 the body is complete, -1 the upstream broke its
;      own framing or the capture failed.
; The bytes go straight into the spill file, de-chunked when the upstream
; chose that framing, so what is finally mapped is the body and nothing else.
linnea_h3_proxy_body:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    cmp qword [rbx + linnea_connection.body_rem], 0
    je .pb_done                      ; a bodiless response: anything else is
                                     ; the backend's next-request pipelining
    cmp qword [rbx + linnea_connection.capture_chunked], 0
    jne .pb_chunked
    ; counted or close-delimited: everything that arrives is body, up to the
    ; declared length
    mov rax, r13
    mov rcx, [rbx + linnea_connection.body_rem]
    cmp rcx, -1
    je .pb_take                      ; until the close: take it all
    cmp rax, rcx
    jbe .pb_count
    mov rax, rcx                     ; the upstream overshot its own length
.pb_count:
    sub [rbx + linnea_connection.body_rem], rax
.pb_take:
    mov rdi, rbx
    mov rsi, r12
    mov rdx, rax
    call linnea_spill_write
    test eax, eax
    js .pb_fail
    ; linnea_spill_write has no cap of its own — the chunked decoder carries
    ; one because a request body needed it. A backend answering without a
    ; length could otherwise fill the disk one response at a time.
    lea rax, [linnea_config_instance]
    mov rax, [rax + linnea_config.max_body]
    cmp [rbx + linnea_connection.spill_len], rax
    ja .pb_fail
    cmp qword [rbx + linnea_connection.body_rem], 0
    je .pb_done
    xor eax, eax                     ; more to come
    jmp .pb_ret
.pb_chunked:
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call linnea_spill_chunked        ; 0 more, 1 done, -1 bad, -2 too large
    cmp eax, 1
    je .pb_done
    test eax, eax
    jns .pb_ret                      ; 0: need more
    jmp .pb_fail
.pb_done:
    mov eax, 1
    jmp .pb_ret
.pb_fail:
    mov eax, -1
.pb_ret:
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_proxy_deliver(rdi = leg, esi = UDP socket fd)
; The response is complete: map what was captured, encode the head for HTTP/3
; and hand both to a response-stream slot on the owning QUIC connection. The
; mapping's ownership passes to that slot, which unmaps it once the stream is
; sent and acknowledged; if the connection is gone (or has no slot free) the
; mapping is released here instead. The leg is freed either way.
linnea_h3_proxy_deliver:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbx, rdi
    mov r12d, esi                    ; UDP fd
    mov r14, [rbx + linnea_connection.spill_len]      ; body bytes captured
    ; --- the HTTP/3 response head: HEADERS frame + DATA frame header ---
    ; The upstream's fields are re-encoded from the head still sitting in
    ; up_buf; content-length is re-derived from what we actually captured, so
    ; a de-chunked body is described by the length it really has. A response
    ; that carries no body keeps whatever length the upstream stated (RFC 9110
    ; 9.3.2: a HEAD's content-length is the GET's, not the zero bytes we hold).
    lea rdi, [h3p_fs]
    mov esi, [rbx + linnea_connection.up_status]
    lea rdx, [rbx + linnea_connection.up_buf]
    mov rcx, [rbx + linnea_connection.h3_hlen]
    mov r8, r14
    cmp qword [rbx + linnea_connection.h3_nobody], 0
    je .dl_clen
    mov r8, -1                       ; forward the upstream's own, if it had one
.dl_clen:
    mov r9, [rbx + linnea_connection.vhost]
    call linnea_qpack_encode_proxy   ; rax = field-section length, or -1 when it
    cmp rax, -1                      ; would not fit the reserve
    je .dl_bad_head
    mov [rsp], rax
    lea rdi, [h3p_head]
    mov byte [rdi], LINNEA_H3_FRAME_HEADERS
    inc rdi
    mov rsi, rax
    call linnea_quic_varint_encode
    add rdi, rax
    lea rsi, [h3p_fs]
    mov rcx, [rsp]
    rep movsb                        ; the field section behind its frame header
    test r14, r14
    jz .dl_nodata
    mov byte [rdi], LINNEA_H3_FRAME_DATA
    inc rdi
    mov rsi, r14
    call linnea_quic_varint_encode
    add rdi, rax
.dl_nodata:
    lea rax, [h3p_head]
    sub rdi, rax
    mov r15, rdi                     ; the head's length
    cmp r15, LINNEA_H3_PROXY_RESERVE
    ja .dl_bad_head                  ; more head than the hole reserved for it
    ; Write it into the hole so that it ends exactly where the body begins:
    ; head and body are then one contiguous run in the file, which is what a
    ; response-stream slot streams from. This also extends the file to at least
    ; the reserve, so a bodiless response still has something to map.
    mov edi, [rbx + linnea_connection.spill_fd]
    lea rsi, [h3p_head]
    mov rdx, r15
    mov r10, LINNEA_H3_PROXY_RESERVE
    sub r10, r15                     ; offset: the head ends at the reserve
    mov eax, LINNEA_SYS_PWRITE64
    syscall
    cmp rax, r15
    jne .dl_fail                     ; a short or failed write: nothing to send
    ; map head and body together
    xor edi, edi
    mov rsi, LINNEA_H3_PROXY_RESERVE
    add rsi, r14
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, [rbx + linnea_connection.spill_fd]
    xor r9d, r9d
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .dl_fail
    mov r13, rax                     ; the mapping, now the response slot's
    mov [linnea_h3d_base], r13
    mov rax, LINNEA_H3_PROXY_RESERVE
    add rax, r14
    mov [linnea_h3d_size], rax       ; the WHOLE mapping, for the munmap
    mov rax, LINNEA_H3_PROXY_RESERVE
    sub rax, r15
    mov [linnea_h3d_foff], rax       ; the response starts at the head
    lea rax, [r15 + r14]
    mov [linnea_h3d_flen], rax       ; head + body, streamed as one run
    mov qword [linnea_h3d_hlen], 0   ; nothing is held in the slot's own hdr
    mov qword [linnea_h3d_hdr], 0
    mov rax, [rbx + linnea_connection.h3_qidx]
    mov [linnea_h3d_qidx], rax
    mov rax, [rbx + linnea_connection.h3_qgen]
    mov [linnea_h3d_qgen], rax
    mov rax, [rbx + linnea_connection.h3_sid]
    mov [linnea_h3d_sid], rax
    ; The access line, from the facts parked when the request was forwarded.
    ; Written here rather than through the h1 proxy log: that one reads the
    ; request out of a client connection's buffers, and an h3 leg has none —
    ; it produced a line with no peer, no method, no target and "HTTP/1.1".
    mov [rbx + linnea_connection.relayed], r14
    mov rdi, rbx
    call linnea_h3_proxy_start.lg_publish
    lea rax, [proto_h3]
    mov [linnea_log_acc_proto], rax
    mov qword [linnea_log_acc_proto_len], proto_h3_len
    mov rax, [rbx + linnea_connection.up_status]
    mov [linnea_log_acc_status], rax
    mov [linnea_log_acc_bytes], r14
    call linnea_log_access
    mov edi, r12d
    call linnea_quic_h3_deliver      ; -> 1 sent, 0 the connection is gone,
    cmp eax, 1                       ; -1 no response slot free
    je .dl_done                      ; the slot owns the mapping now
    mov rdi, r13                     ; nobody took it: release it here
    mov rsi, LINNEA_H3_PROXY_RESERVE
    add rsi, r14
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.dl_done:
    mov rdi, rbx
    call linnea_h3_proxy_release
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.dl_bad_head:
.dl_fail:
    mov rdi, rbx
    mov esi, 502
    mov edx, r12d
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    jmp linnea_h3_proxy_fail

; linnea_h3_proxy_fail(rdi = leg, esi = status, edx = UDP socket fd)
; The exchange failed before any response byte reached the client, so it can
; still be answered honestly: a small complete response on the stream, sent
; through the same response-stream slot a real answer uses. The leg is freed.
linnea_h3_proxy_fail:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12d, esi                    ; status
    mov r13d, edx                    ; UDP fd
    mov [rbx + linnea_connection.up_status], r12
    ; the body that names the status, for a human reading the stream
    lea rax, [body_502]
    mov ecx, body_502_len
    cmp r12d, 504
    jne .fl_pick_503
    lea rax, [body_504]
    mov ecx, body_504_len
    jmp .fl_build
.fl_pick_503:
    cmp r12d, 503
    jne .fl_pick_413
    lea rax, [body_503]
    mov ecx, body_503_len
    jmp .fl_build
.fl_pick_413:
    cmp r12d, 413
    jne .fl_build
    lea rax, [body_413]
    mov ecx, body_413_len
.fl_build:
    ; linnea_h3_build_response writes the access line itself, from the shared
    ; log block — which by now describes whichever request was served most
    ; recently, not this one. Put this leg's own facts back first.
    ; The encoder's per-response fields are stale for exactly the same reason,
    ; and linnea_h3_build_canned below is what clears those.
    push rax
    push rcx
    mov rdi, rbx
    call linnea_h3_proxy_start.lg_publish
    pop rcx
    pop rax
    ; A canned error is small enough to ride entirely in the slot's head, so it
    ; needs no mapping at all: hlen covers the HEADERS frame, the DATA frame
    ; header and the body, and flen is zero.
    lea rdi, [h3p_head]
    mov esi, r12d
    lea rdx, [txt_plain]
    mov r8, rax
    mov r9d, ecx
    mov ecx, txt_plain_len
    call linnea_h3_build_canned      ; rax = the whole response's length
    cmp rax, LINNEA_H3_HEAD_MAX
    ja .fl_free                      ; unreachable: these bodies are fixed
    mov [linnea_h3d_hlen], rax
    lea rax, [h3p_head]
    mov [linnea_h3d_hdr], rax
    mov qword [linnea_h3d_foff], 0
    mov rax, [rbx + linnea_connection.h3_qidx]
    mov [linnea_h3d_qidx], rax
    mov rax, [rbx + linnea_connection.h3_qgen]
    mov [linnea_h3d_qgen], rax
    mov rax, [rbx + linnea_connection.h3_sid]
    mov [linnea_h3d_sid], rax
    mov qword [linnea_h3d_base], 0
    mov qword [linnea_h3d_size], 0
    mov qword [linnea_h3d_flen], 0
    mov qword [rbx + linnea_connection.relayed], 0
    mov edi, r13d
    call linnea_quic_h3_deliver
.fl_free:
    mov rdi, rbx
    call linnea_h3_proxy_release
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_proxy_cancel(rdi = QUIC conn index, rsi = its connection ID,
;   rdx = stream id, or -1 for every stream on that connection)
; Nobody is waiting for these answers any more — the peer reset the stream, or
; the whole connection has gone. Without this the leg ran to completion and its
; answer was dropped at delivery: correct, but it held a connection slot and an
; upstream socket for as long as the backend took, and a client that cancels a
; page's worth of requests holds one of each per request.
;
; The leg cannot be freed here. It has an io_uring operation in flight and the
; kernel owns its buffer until that completes, so freeing now would hand the
; buffer to a new connection while the kernel was still writing into it. Shut
; the socket down instead — which is what makes the completion arrive at once
; rather than whenever the backend finishes — and mark the leg; the completion
; frees it. The same bargain .h2_closing makes on the client side.
linnea_h3_proxy_cancel:
    ; Every QUIC connection that closes comes through here, and most servers
    ; proxy nothing over h3 at all — so the pool walk below is skipped outright
    ; unless a leg actually exists. Without this a connection close paid for a
    ; max_connections-long scan to find nothing, on every close.
    cmp qword [h3_legs_live], 0
    je .cn_none
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov r13, rdi                     ; quic conn index
    mov r14, rsi                     ; its connection id
    mov r15, rdx                     ; stream id, or -1 for all of them
    xor ebp, ebp                     ; pool index
    lea rax, [linnea_config_instance]
    mov rbx, [rax + linnea_config.max_connections]
.cn_slot:
    cmp rbp, rbx
    jae .cn_done
    mov rdi, rbp
    call linnea_connection_at
    mov r12, rax
    cmp qword [r12 + linnea_connection.in_use], 0
    je .cn_next
    cmp qword [r12 + linnea_connection.h3_owner], 0
    je .cn_next                      ; an ordinary client connection
    cmp qword [r12 + linnea_connection.h3_cancel], 0
    jne .cn_next                     ; already on its way out
    cmp [r12 + linnea_connection.h3_qidx], r13
    jne .cn_next
    cmp [r12 + linnea_connection.h3_qgen], r14
    jne .cn_next                     ; a leg of an earlier incarnation
    cmp r15, -1
    je .cn_hit                       ; every stream of this connection
    cmp [r12 + linnea_connection.h3_sid], r15
    jne .cn_next
.cn_hit:
    mov qword [r12 + linnea_connection.h3_cancel], 1
    mov edi, [r12 + linnea_connection.up_fd]
    cmp edi, -1
    je .cn_next                      ; nothing open yet; the completion still comes
    mov esi, 2                       ; SHUT_RDWR
    mov eax, LINNEA_SYS_SHUTDOWN
    syscall
.cn_next:
    inc rbp
    jmp .cn_slot
.cn_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.cn_none:
    ret

; linnea_h3_proxy_release(rdi = leg) — close the upstream socket, drop the
; capture file and give the connection slot back. Nothing here is armed, so
; there is no in-flight operation to wait for: every caller reaches this from
; the completion of the leg's last one.
linnea_h3_proxy_release:
    push rbx
    mov rbx, rdi
    mov edi, [rbx + linnea_connection.up_fd]
    cmp edi, -1
    je .rl_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed      ; or a burst of failures wedges proxying
    mov dword [rbx + linnea_connection.up_fd], -1
.rl_nofd:
    mov rdi, rbx
    call linnea_spill_release
    ; the REQUEST body's mapping, if this leg took one. The response's mapping
    ; is not here: that one is handed to a response-stream slot, which unmaps it
    ; when the stream is done, and the deliver path clears these first.
    mov rdi, [rbx + linnea_connection.file_base]
    test rdi, rdi
    jz .rl_nomap
    push rbx
    mov rsi, [rbx + linnea_connection.file_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    pop rbx
.rl_nomap:
    mov qword [rbx + linnea_connection.file_base], 0
    mov qword [rbx + linnea_connection.file_size], 0
    mov qword [rbx + linnea_connection.file_rem], 0
    mov qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_IDLE
    cmp qword [rbx + linnea_connection.h3_owner], 0
    je .rl_counted                   ; released twice: give the count back once
    dec qword [h3_legs_live]
.rl_counted:
    mov qword [rbx + linnea_connection.h3_owner], 0
    mov qword [rbx + linnea_connection.h3_cancel], 0   ; not a leg awaiting a
                                                       ; reap any more either
    mov rdi, rbx
    call linnea_connection_free
    pop rbx
    ret

section .bss
; Called with rdi = the leg the moment it is ready to connect (0 = no loop).
; The io_uring loop installs it at startup: queuing an SQE is the loop's, and
; only the loop's, and this module has no business including its header.
global linnea_h3_proxy_arm_hook
linnea_h3_proxy_arm_hook: resq 1
