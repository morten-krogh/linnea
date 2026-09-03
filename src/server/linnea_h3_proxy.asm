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
extern linnea_upstream_socket
extern linnea_upstream_closed
extern linnea_upstream_method_safe
extern linnea_upstream_mark_ok
extern linnea_upstream_park
extern linnea_upstream_take
extern linnea_upstream_pick
extern linnea_upstream_count
extern linnea_upstream_reap_one
extern linnea_upstream_limit
extern linnea_config_instance
extern linnea_string_equal
extern linnea_string_from_u64
extern linnea_string_to_u64
extern linnea_http_upstream_head_valid
extern linnea_http_status_no_content
extern linnea_http_status_no_clen
extern linnea_string_iequal
extern linnea_string_has_token
extern linnea_spill_open
extern linnea_spill_write
extern linnea_spill_chunked
extern linnea_spill_release
extern linnea_qpack_encode_proxy
extern linnea_qpack_fss_size
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
extern linnea_h3_proxy_source_ptr
extern linnea_h3_proxy_source_len
extern linnea_client_identity_append
extern linnea_h3_body_fd
; the delivery parameter block and the entry point that consumes it, both in
; the QUIC server: the response stream slots are its to hand out
extern linnea_quic_h3_deliver
extern linnea_h3d_qidx
extern linnea_h3d_qgen
extern linnea_h3d_sid
extern linnea_h3d_hdr
extern linnea_h3d_hlen
extern linnea_h3d_fss
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
h3_ck_hdr:     db "Cookie: "
h3_ck_hdr_len  equ $ - h3_ck_hdr
h3_ck_crlf:    db 13, 10
h3_mf_hdr:     db "Max-Forwards: "
h3_mf_hdr_len  equ $ - h3_mf_hdr
h3_mf_options: db "OPTIONS"
hdr_clen:      db "Content-Length: "
hdr_clen_len   equ $ - hdr_clen
; RFC 9110 7.6.3: name the hop and the protocol it was received on. The client
; spoke HTTP/3, so "3" is the protocol-name-less form 7.6.3 allows for HTTP.
hdr_via:       db "Via: 3 linnea", 13, 10
hdr_via_len    equ $ - hdr_via
hdr_close:     db "Connection: close", 13, 10, 13, 10
hdr_close_len  equ $ - hdr_close
hdr_keep:      db "Connection: keep-alive", 13, 10, 13, 10
hdr_keep_len   equ $ - hdr_keep
hn_conn_h3:    db "connection"
val_close_h3:  db "close"
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
    ; ...and what is in it has to be a legal HTTP/1.1 head. DEL is a valid byte
    ; in an h3 field value (RFC 9114 4.2 forbids only NUL, LF and CR) and not in
    ; an h1 one (RFC 9110 5.5), so a request carrying it is answered 400 here
    ; rather than forwarded -- the same door h2 closes at .serve_proxy, since
    ; both protocols rebuild their upstream head with the one emit_field.
    cmp qword [rbx + linnea_h2_req.h1_unsafe], 0
    jne .st_400
    ; The backend's ceiling used to be tested HERE, before a leg even existed --
    ; and therefore before the idle pool could be consulted. A parked connection
    ; is already counted against max_upstream, so that refused the pool's own
    ; inventory; and because `take` is the only thing that reaps an expired pool
    ; entry, the refusal never reclaimed the descriptor either and the location
    ; stayed 503 instead of recovering (audit-report-39). It now sits beside the
    ; socket it governs, in .st_fresh.
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
    mov qword [r12 + linnea_connection.h3_hoff], 0
    mov qword [r12 + linnea_connection.h3_inum], 0
    mov qword [r12 + linnea_connection.h3_nobody], 0
    ; A recycled slot carries the last client's address, and the per-source
    ; connection cap counts every in_use slot whose peer_ip matches. A leg that
    ; kept one would charge that client for a connection it never made. (.peer,
    ; the formatted text beside it, is log-only and is filled in below.)
    mov qword [r12 + linnea_connection.peer_ip_len], 0
    mov qword [r12 + linnea_connection.keep_alive], 0
    mov qword [r12 + linnea_connection.upgrade], 0    ; h3 has no upgrade to forward
    mov qword [r12 + linnea_connection.up_status], 0
    mov qword [r12 + linnea_connection.relayed], 0
    mov qword [r12 + linnea_connection.up_len], 0
    mov qword [r12 + linnea_connection.body_rem], 0
    mov qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_NONE
    mov rax, [rsp]
    mov [r12 + linnea_connection.location], rax
    mov rax, [rsp + 8]
    mov [r12 + linnea_connection.vhost], rax
    ; per-REQUEST, and legs come from a reused pool of connection slots. This
    ; one is cleared HERE rather than beside the other two at .st_socket,
    ; because the head builder in between is what sets it.
    mov qword [r12 + linnea_connection.up_reusable], 0
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
    add rcx, http11_host_len + hdr_clen_len + hdr_via_len + hdr_keep_len + 96
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
    ; ...and the cookie field lines, joined into one. RFC 9114 4.2.1 lets an
    ; HTTP/3 client split Cookie across lines for compression and requires an
    ; intermediary to concatenate them with "; " before a hop that is not
    ; HTTP/3 -- the same rule, in the same words, that RFC 9113 8.2.3 sets for
    ; HTTP/2 and that h2 has followed since Finding 32. h3 forwarded them
    ; unjoined, so a backend reading Cookie saw the first line's crumbs and a
    ; session cookie a browser had split was silently truncated. The values
    ; were accumulated during the decode; one line goes out here.
    mov r13, [rbx + linnea_h2_req.ck_len]
    test r13, r13
    jz .st_cookies_done              ; no cookie field at all
    cmp r13, -1
    je .st_cookie_over               ; the join outgrew its buffer
    lea rdi, [h3_ck_hdr]
    mov esi, h3_ck_hdr_len
    call .up_append
    mov rdi, [rbx + linnea_h2_req.ck_buf]
    mov rsi, r13
    call .up_append
    lea rdi, [h3_ck_crlf]
    mov esi, 2
    call .up_append
    jmp .st_cookies_done
.st_cookie_over:
    ; too much cookie to join: refusing is the only honest answer, since a
    ; shortened Cookie is a different request. The h2 path answers 431 here.
    jmp .st_431
.st_cookies_done:
    ; ...and Max-Forwards, kept out of the rebuild so it can be re-emitted with
    ; one hop taken off for an OPTIONS (RFC 9110 7.6.2) and untouched for any
    ; other method. The zero case never reaches here: it was answered before an
    ; upstream was chosen, so the subtraction cannot wrap.
    cmp qword [rbx + linnea_h2_req.mf_seen], 0
    je .st_mf_done
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    mov rsi, [rbx + linnea_h2_req.method_len]
    lea rdx, [h3_mf_options]
    mov ecx, 7
    call linnea_string_equal
    mov rdi, [rbx + linnea_h2_req.mf_val]
    test eax, eax
    jz .st_mf_render
    dec rdi
.st_mf_render:
    lea rsi, [num_buf]
    call linnea_string_from_u64      ; -> rax = digits written
    mov r13, rax
    lea rdi, [h3_mf_hdr]
    mov esi, h3_mf_hdr_len
    call .up_append
    lea rdi, [num_buf]
    mov rsi, r13
    call .up_append
    lea rdi, [h3_ck_crlf]
    mov esi, 2
    call .up_append
.st_mf_done:
    ; Content-Length is ours to declare: the body is whole and counted here,
    ; whatever framing (or none) the client used to send it.
    mov r13, [linnea_h3_proxy_body_len]
    test r13, r13
    jnz .st_clen
    ; No bytes -- but a client that DECLARED a length has sent "a body of no
    ; bytes", which is not the same request upstream as one with no body at
    ; all, and only the first carries a Content-Length. Dropping it turned an
    ; empty file upload into a POST with no framing, and a backend entitled to
    ; require a length answered 411; h1 forwards "Content-Length: 0" here.
    cmp qword [rbx + linnea_h2_req.cl_ptr], 0
    je .st_nobody
.st_clen:
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
    mov rdi, rbp
    mov rsi, [r12 + linnea_connection.location]
    mov rdx, [linnea_h3_proxy_source_ptr]
    mov rcx, [linnea_h3_proxy_source_len]
    call linnea_client_identity_append
    test rax, rax
    jz .st_identity_missing
    mov rbp, rax
    ; Keep the connection when this location opted in and the method may be
    ; sent again -- the same rule and the same reasons as h1 (docs/config.md,
    ; "Upstream connections"). Otherwise close, which is also what makes a
    ; close-delimited response terminate.
    mov rcx, [r12 + linnea_connection.location]
    test rcx, rcx
    jz .st_conn_close
    cmp qword [rcx + linnea_config_location.proxy_keepalive], 0
    je .st_conn_close
    ; A TLS backend leg is never parked, the same rule h1 has carried since
    ; backend TLS landed: a parked kTLS socket carries kernel crypto state the
    ; pool does not track (up_ktls is per-leg and the taker's is clear), so the
    ; next request reads it as a plaintext socket. h3 was pooling them — a
    ; second h3 request took the parked kTLS leg (audit-report-41).
    cmp qword [rcx + linnea_config_location.proxy_tls], 0
    jne .st_conn_close
    push rbx
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    mov rsi, [rbx + linnea_h2_req.method_len]
    call linnea_upstream_method_safe
    pop rbx
    test eax, eax
    jz .st_conn_close
    mov qword [r12 + linnea_connection.up_reusable], 1
    lea rdi, [hdr_keep]
    mov esi, hdr_keep_len
    call .up_append
    jmp .st_sendwin
.st_conn_close:
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
    ; --- the connection: a parked one if there is one, else a new socket -----
    ; choose the backend first; a parked connection belongs to exactly one
    mov qword [r12 + linnea_connection.up_no_reuse], 0
    mov qword [r12 + linnea_connection.up_pooled], 0
    mov rdi, [r12 + linnea_connection.location]
    call linnea_upstream_pick
    mov [r12 + linnea_connection.up_backend], rax
    mov qword [r12 + linnea_connection.up_tries], 1
    cmp qword [r12 + linnea_connection.up_reusable], 0
    je .st_fresh
    mov rdi, [r12 + linnea_connection.location]
    mov rsi, [r12 + linnea_connection.up_backend]
    call linnea_upstream_take
    cmp eax, -1
    je .st_fresh
    mov [r12 + linnea_connection.up_fd], eax
    mov qword [r12 + linnea_connection.up_pooled], 1
    ; snapshot the request head so a dead parked socket can be retried on a fresh
    ; connection (out_rem is up_buf..head-end here; a reusable leg is GET/HEAD)
    mov rcx, [r12 + linnea_connection.out_rem]
    mov [r12 + linnea_connection.up_head_len], rcx
    ; already connected: the loop's hook starts this leg at the send
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_SENDING
    jmp .st_armed
.st_fresh:
    call linnea_upstream_count
    cmp rax, [linnea_upstream_limit]
    jb .st_room
    call linnea_upstream_reap_one     ; an idle parked socket yields to a request
    test eax, eax
    jnz .st_fresh                      ; freed one: re-check the ceiling
    jmp .st_busy                       ; genuinely at capacity: a leg is live, give it back
.st_room:
    mov rdi, [r12 + linnea_connection.location]
    mov rsi, [r12 + linnea_connection.up_backend]
    call linnea_upstream_socket
    cmp rax, -4095
    jae .st_nosock
    mov [r12 + linnea_connection.up_fd], eax
    call linnea_upstream_open
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CONNECTING
.st_armed:
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
.st_busy:
    ; at the ceiling with nothing poolable to borrow. Unlike the old check this
    ; one runs with a leg allocated, so it goes back before the 503 -- the same
    ; shape .st_nosock has always had.
    mov rdi, r12
    call .st_drop
    mov eax, 503
    jmp .st_ret
.st_toobig:
    mov rdi, r12
    call .st_drop
    mov eax, 431
    jmp .st_ret
.st_identity_missing:
    mov rdi, r12
    call .st_drop
    mov eax, 503
    jmp .st_ret
.st_400:
    mov eax, 400
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
.ph_restart:
    ; Parse the head at .h3_hoff, not at the front of the buffer. They differ
    ; once the upstream has sent an interim (1xx) response: those heads stay
    ; where they are, and .h3_hoff steps past each one so the next parse sees
    ; the head behind it. Nothing is shifted -- delivery re-encodes them all
    ; from up_buf, in order (audit-report-7 Finding 1).
    lea r12, [rbx + linnea_connection.up_buf]
    add r12, [rbx + linnea_connection.h3_hoff]
    mov r13, [rbx + linnea_connection.up_len]
    sub r13, [rbx + linnea_connection.h3_hoff]
    jbe .ph_more                     ; nothing of the next head has arrived
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
    ; ...and the same head h2 refuses to VALIDATE (audit-report-6 Finding 1).
    ; Before this, h3 went straight from finding the CRLF CRLF to choosing a
    ; body framing, so nothing ever checked the field section: a name with a
    ; space and a NUL in a value were QPACK-encoded onto the wire for the
    ; client, a colonless line was silently dropped, and two disagreeing
    ; Content-Lengths became a clean 200 carrying the first one's worth of body
    ; -- the contradiction erased rather than refused, because delivery
    ; re-derives its own length from what it captured. It has to happen HERE,
    ; ahead of the framing choice below, since the framing is picked from the
    ; very fields being validated. rcx is the head length and r12 the buffer;
    ; the validator preserves rbx/r12/r13 but not rcx, so the length is read
    ; back from h3_hlen.
    mov rdi, r12
    mov rsi, rcx
    call linnea_http_upstream_head_valid
    test eax, eax
    jz .ph_bad                       ; malformed upstream head: 502, not relayed
    mov rcx, [rbx + linnea_connection.h3_hlen]
    ; --- an interim response is not the answer ---------------------------
    ; RFC 9114 4.1: a response stream carries zero or more interim responses
    ; before exactly one final one, and RFC 9110 15.2 makes forwarding a 1xx a
    ; MUST for a proxy. This used to fall through to the framing below, where
    ; "status < 200" reads as "carries no body" -- true, but it was then
    ; DELIVERED as the final response and the leg torn down, so the real answer
    ; was never sent. h2 has had the distinction since Finding 30.
    ;
    ; Step over this head and parse the next one. It may already be buffered
    ; (an upstream that writes the interim and the final together), which is
    ; why this loops rather than returning to wait for a read; if it is not,
    ; the restart falls out at .ph_more and the caller reads more into up_buf
    ; behind what is already there.
    mov rax, [rbx + linnea_connection.up_status]
    cmp rax, 200
    jae .ph_final
    cmp rax, 100
    jb .ph_bad                       ; below 100 is not a status at all
    cmp rax, 101
    je .ph_bad                       ; a 101 has no meaning over an h3 proxy,
                                     ; exactly as h2 refuses one
    add [rbx + linnea_connection.h3_hoff], rcx
    inc qword [rbx + linnea_connection.h3_inum]
    cmp qword [rbx + linnea_connection.h3_inum], LINNEA_H3_PROXY_IMAX
    ja .ph_bad                       ; a chain longer than we will re-encode:
                                     ; refused HERE, before a body is captured
                                     ; for a response that could not be sent
    jmp .ph_restart
.ph_final:
    ; A backend that says "close" is about to go; parking that socket would
    ; hand the next request a race with its FIN.
    ;
    ; rcx is the head length and .ph_find neither preserves it nor can -- it
    ; takes the NAME length in the same register. So it is saved before ecx is
    ; touched, and every path below reaches the pop.
    push rcx
    mov rdi, r12
    mov rsi, rcx
    lea rdx, [hn_conn_h3]
    mov ecx, 10
    call .ph_find
    test rdx, rdx
    jz .ph_conn_done
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [val_close_h3]
    mov ecx, 5
    call .ph_val_has
    test eax, eax
    jz .ph_conn_done
    mov qword [rbx + linnea_connection.up_no_reuse], 1
.ph_conn_done:
    pop rcx                          ; the head length, for the framing lookups
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
    call linnea_string_to_u64        ; -> rax = value, edx = 0 ok / 1 / 2
    test edx, edx
    jnz .ph_bad
    cmp rax, -1
    je .ph_bad                       ; body_rem's -1 means "until the upstream
                                     ; closes"; a backend declaring exactly
                                     ; 2^64-1 bytes would turn a counted body
                                     ; into a close-delimited one
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
    ; 1xx, 204, 205 and 304 carry no content, whatever the head says. 205 was
    ; missing from all three of these lists (audit-report-10 Finding 1); the
    ; rule is one predicate now so they cannot disagree again.
    mov edi, [rbx + linnea_connection.up_status]
    call linnea_http_status_no_content
    test eax, eax
    jnz .ph_nobody
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
    je .pf_lead_skip
    cmp byte [rbx + rcx], 9          ; HTAB is OWS as well (RFC 9110 5.6.3);
    jne .pf_val                      ; the trailing trim below already takes it
.pf_lead_skip:
    inc rcx
    jmp .pf_lead
.pf_val:
    lea rax, [rbx + rcx]
    mov rdx, rbp
    sub rdx, rcx
    ; ...and trim the TRAILING OWS too. RFC 9112 5 puts OWS on both sides of a
    ; field value; the leading half is skipped just above, and the trailing half
    ; was not -- so "Content-Length:   5  " reached the number parser as "5  "
    ; and h3 answered 502 to a response h1 and h2 both served. h2's own
    ; h2p_head_find has trimmed both ends all along (.hf_trail); this is the
    ; third copy of the same field-value lookup and the one that drifted.
    ; No scratch register: the compare reads through rax/rdx directly.
.pf_trail:
    test rdx, rdx
    jz .pf_ret
    cmp byte [rax + rdx - 1], ' '
    je .pf_untrim
    cmp byte [rax + rdx - 1], 9      ; HTAB is OWS as well
    jne .pf_ret
.pf_untrim:
    dec rdx
    jmp .pf_trail
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
    ; the shared #rule matcher: this used to be a local copy
    jmp linnea_string_has_token

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
    lea rcx, [rbx + linnea_connection.chunk_state]   ; the capture's own state
    mov r8d, LINNEA_CHUNK_CAPTURE
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
    sub rsp, 32                      ; [0] field-section length, [8] the head
    mov rbx, rdi                     ; cursor, [16] the interim walk offset,
                                     ; [24] the largest RFC 9114 4.2.2 field-
                                     ; section size any of its HEADERS frames
                                     ; carries.
                                     ; 32 not 24: five pushes leave rsp 16-byte
                                     ; aligned, so an odd multiple of 8 here
                                     ; hands every callee a misaligned stack --
                                     ; which the crypto paths meet as a movdqa
                                     ; fault that reads like a null dereference
    mov r12d, esi                    ; UDP fd
    mov r14, [rbx + linnea_connection.spill_len]      ; body bytes captured
    ; --- the HTTP/3 response head: HEADERS frame(s) + DATA frame header ---
    ; The upstream's fields are re-encoded from the head still sitting in
    ; up_buf; content-length is re-derived from what we actually captured, so
    ; a de-chunked body is described by the length it really has. A response
    ; that carries no body keeps whatever length the upstream stated (RFC 9110
    ; 9.3.2: a HEAD's content-length is the GET's, not the zero bytes we hold)
    ; -- except on the statuses where the field is forbidden outright.
    ;
    ; Interim (1xx) responses come first, each as its own HEADERS frame, in the
    ; order the upstream sent them (audit-report-7 Finding 1). They are all
    ; frames on one stream and the FIN rides the stream, not any frame, so
    ; HEADERS(103) HEADERS(200) DATA is exactly the sequence RFC 9114 4.1
    ; describes. NB they reach the client WITH the final response rather than
    ; ahead of it: an h3 leg captures the whole body before it sends anything,
    ; so 103 Early Hints is forwarded as the MUST in RFC 9110 15.2 requires but
    ; without the head start that is its point. Delivering it early would mean
    ; sending on the request stream before the response slot exists, which the
    ; one-slot-per-response model does not do.
    lea rdi, [h3p_head]
    mov [rsp + 8], rdi               ; the cursor across every frame below
    xor eax, eax
    mov [rsp + 16], rax              ; walk offset: the first interim head
    mov [rsp + 24], rax              ; no field section measured yet
.dl_interim:
    mov rax, [rsp + 16]
    cmp rax, [rbx + linnea_connection.h3_hoff]
    jae .dl_final                    ; no interim heads left (usually none)
    ; this interim head runs to its own CRLF CRLF
    lea rsi, [rbx + linnea_connection.up_buf]
    add rsi, rax
    mov rcx, [rbx + linnea_connection.h3_hoff]
    sub rcx, rax                     ; bytes remaining in the interim region
    xor edx, edx
.dl_iscan:
    lea r8, [rdx + 4]
    cmp r8, rcx
    ja .dl_bad_head                  ; h3_hoff always ends on a CRLF CRLF
    cmp dword [rsi + rdx], 0x0A0D0A0D
    je .dl_ifound
    inc rdx
    jmp .dl_iscan
.dl_ifound:
    add rdx, 4                       ; this head's length
    push rdx
    push rsi
    ; its status: three digits at offset 9, the shape .ph_status already checked
    movzx eax, byte [rsi + 9]
    sub eax, '0'
    imul eax, eax, 100
    movzx r8d, byte [rsi + 10]
    sub r8d, '0'
    imul r8d, r8d, 10
    add eax, r8d
    movzx r8d, byte [rsi + 11]
    sub r8d, '0'
    add eax, r8d
    mov esi, eax                     ; status
    lea rdi, [h3p_fs]
    mov rdx, [rsp]                   ; head ptr (pushed second, so on top)
    mov rcx, [rsp + 8]               ; head length
    mov r8, -2                       ; an interim head frames no body, so it
                                     ; carries no Content-Length: not one of
                                     ; ours, and not the upstream's either
                                     ; (RFC 9110 8.6, audit-report-9 Finding 2)
    mov r9, [rbx + linnea_connection.vhost]
    call linnea_qpack_encode_proxy
    pop rsi
    pop rdx                          ; this head's length, back off the stack
    cmp rax, -1
    je .dl_bad_head
    call .dl_note_fss                ; this interim section's uncompressed size
    add [rsp + 16], rdx              ; step the walk past it
    mov rdi, [rsp + 8]
    mov rsi, rax                     ; the field-section length
    call .dl_put_headers
    test rax, rax
    jz .dl_bad_head                  ; no room left for another HEADERS frame
    mov [rsp + 8], rax
    jmp .dl_interim
.dl_final:
    ; The length decision first, while rdi is still free: it is an argument to
    ; the encoder below, and taking it as a scratch register for the status is
    ; how this crashed the worker on its first 204 -- the field section was
    ; encoded to address 204.
    mov r8, r14
    cmp qword [rbx + linnea_connection.h3_nobody], 0
    je .dl_clen
    ; A bodiless answer states no length of its own. On HEAD and 304 the
    ; upstream's Content-Length describes the representation the client is not
    ; being sent and must survive; on 204 the field is forbidden and must not
    ; (RFC 9110 8.6, audit-report-9 Finding 2).
    mov edi, [rbx + linnea_connection.up_status]
    call linnea_http_status_no_clen
    mov r8, -1                       ; forward the upstream's own, if it had one
    test eax, eax
    jz .dl_clen
    mov r8, -2                       ; ...unless the status forbids one
.dl_clen:
    lea rdi, [h3p_fs]
    mov esi, [rbx + linnea_connection.up_status]
    lea rdx, [rbx + linnea_connection.up_buf]
    add rdx, [rbx + linnea_connection.h3_hoff]        ; past any interim heads
    mov rcx, [rbx + linnea_connection.h3_hlen]
    mov r9, [rbx + linnea_connection.vhost]
    call linnea_qpack_encode_proxy   ; rax = field-section length, or -1 when it
    cmp rax, -1                      ; would not fit the reserve
    je .dl_bad_head
    call .dl_note_fss                ; and the final response's own size
    mov rdi, [rsp + 8]
    mov rsi, rax
    call .dl_put_headers
    test rax, rax
    jz .dl_bad_head
    mov [rsp + 8], rax
    mov rdi, rax                     ; the cursor, for the DATA frame header
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
    mov r15, rdi                     ; the head's length, frames and all
    cmp r15, LINNEA_H3_PROXY_RESERVE
    ja .dl_bad_head                  ; belt to .dl_put_headers' braces: that
                                     ; refuses to write past the buffer, this
                                     ; catches a DATA frame header that would
                                     ; not fit behind what it wrote
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
    mov rax, [rsp + 24]
    mov [linnea_h3d_fss], rax        ; the limit is the OWNING connection's, and
                                     ; only the delivery still knows which that
                                     ; is (audit-report-143 Finding 1)
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
    ; a complete response: whatever this backend did before, it is working now.
    ; h3 does not pass through the uring loop's .proxy_finish, so it says so
    ; here -- the failure side it DOES share, through .proxy_fail.
    mov rdi, [rbx + linnea_connection.location]
    mov rsi, [rbx + linnea_connection.up_backend]
    call linnea_upstream_mark_ok
    ; The response is delivered and the upstream exchange is over. Keep the
    ; connection on the same terms h1 uses: the location opted in and the method
    ; was safe (up_reusable), the backend did not say close, and the body was
    ; delimited -- counted and fully consumed, or chunked through its terminal
    ; chunk, which is what .pb_done means for each. A close-delimited response
    ; has capture_chunked 0 and body_rem still -1, so it cannot pass.
    cmp qword [rbx + linnea_connection.up_reusable], 0
    je .dl_release
    cmp qword [rbx + linnea_connection.up_no_reuse], 0
    jne .dl_release
    cmp dword [rbx + linnea_connection.up_fd], -1
    je .dl_release
    cmp qword [rbx + linnea_connection.capture_chunked], 0
    jne .dl_park
    cmp qword [rbx + linnea_connection.body_rem], 0
    jne .dl_release
.dl_park:
    mov rdi, [rbx + linnea_connection.location]
    mov rsi, [rbx + linnea_connection.up_backend]
    mov edx, [rbx + linnea_connection.up_fd]
    call linnea_upstream_park
    test eax, eax
    jz .dl_release             ; pool full: release closes it, as before
    mov dword [rbx + linnea_connection.up_fd], -1
.dl_release:
    mov rdi, rbx
    call linnea_h3_proxy_release
    add rsp, 32
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
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    jmp linnea_h3_proxy_fail

; .dl_note_fss() — keep the largest RFC 9114 4.2.2 field-section size the
; encoder has reported so far in [rsp + 32] (the caller's [rsp + 24], one call
; deep). The limit is per field section, so an interim chain is judged by its
; biggest head rather than by their sum. Clobbers only rcx and flags: rax is
; the field-section length its callers still need.
.dl_note_fss:
    mov rcx, [linnea_qpack_fss_size]
    cmp rcx, [rsp + 32]
    jbe .dnf_ret
    mov [rsp + 32], rcx
.dnf_ret:
    ret

; .dl_put_headers(rdi = cursor into h3p_head, rsi = field-section length, the
;   section itself sitting in h3p_fs) -> rax = the cursor past the frame it
;   wrote, or 0 when it would not fit.
; The bound is checked BEFORE the copy. It used to be checked after: the field
; section alone may be as large as the whole reserve, so type byte + length
; varint + section could run a few bytes past h3p_head and the "is it too big"
; test only saw it afterwards. Harmless while there was exactly one HEADERS
; frame per response; not once interim responses can add more.
.dl_put_headers:
    sub rsp, 16
    mov [rsp], rsi                   ; field-section length
    lea rax, [h3p_head + LINNEA_H3_PROXY_RESERVE]
    sub rax, rdi                     ; bytes left in the buffer
    mov rcx, rsi
    add rcx, 9                       ; 1 type byte + a varint of at most 8
    cmp rcx, rax
    ja .dl_ph_full
    mov byte [rdi], LINNEA_H3_FRAME_HEADERS
    inc rdi
    mov rsi, [rsp]
    call linnea_quic_varint_encode
    add rdi, rax
    lea rsi, [h3p_fs]
    mov rcx, [rsp]
    rep movsb                        ; the field section behind its frame header
    mov rax, rdi
    add rsp, 16
    ret
.dl_ph_full:
    xor eax, eax
    add rsp, 16
    ret

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
    mov rcx, [linnea_qpack_fss_size] ; what the canned head's fields measure
    mov [linnea_h3d_fss], rcx        ; under RFC 9114 4.2.2
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
