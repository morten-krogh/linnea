; Connection pool limits and per-connection state layout.
; The pool size comes from the config (max_connections).

; Sizes for the per-connection kTLS receive state below. Kernel ABI: struct
; msghdr is 56 bytes on x86-64 and struct iovec 16; the control buffer holds one
; cmsghdr (16) plus the single record-type byte, rounded up. Defined HERE rather
; than in linnea_uring.inc because several modules include this file WITHOUT
; that one, and the .inc files carry no include guards -- one definition, so the
; struct and the code that fills it cannot drift apart.
LINNEA_KTLS_MSGHDR_SIZE equ 56
LINNEA_KTLS_IOVEC_SIZE  equ 16
LINNEA_KTLS_CMSG_SIZE   equ 32

; Request head+body buffer (431/413 if exceeded). It must also be able to
; hold one maximum-size TLS record: during the userspace handshake we read a
; record at a time, and a record the client pipelines behind its Finished has
; to be decrypted here before the kernel takes over the connection. TLS 1.3
; caps a record at 16384 plaintext bytes plus header and expansion.
LINNEA_CONN_IN_BUF      equ 17408
LINNEA_CONN_UP_BUF      equ 8448   ; the outbound request head (client head
                                   ; plus our Connection line), then reused
                                   ; for the upstream response head and the
                                   ; relayed body (the request is fully sent
                                   ; before the response is read)
; A rewritten upstream head is the original minus its Connection line plus
; ours, so it can outgrow up_buf by the length of "Connection: keep-alive"
; and the CRLFs; 64 bytes of slack covers it.
LINNEA_CONN_OUT_BUF     equ LINNEA_CONN_UP_BUF + 64

; conn.proxy_state
LINNEA_PROXY_IDLE       equ 0      ; not proxying
LINNEA_PROXY_CONNECTING equ 1      ; connect() to the upstream is in flight
LINNEA_PROXY_SENDING    equ 2      ; sending the request upstream
LINNEA_PROXY_HEAD       equ 3      ; reading the upstream response head
LINNEA_PROXY_RELAY      equ 4      ; relaying the upstream body to the client
LINNEA_PROXY_UPGRADE    equ 5      ; a 101 head is going out to the client;
                                   ; when it drains the tunnel starts
LINNEA_PROXY_TUNNEL     equ 6      ; full-duplex byte relay after a 101; the
                                   ; one-op invariant becomes one PER DIRECTION
LINNEA_PROXY_CLOSING    equ 7      ; tunnel torn down; both sockets are shut
                                   ; down, waiting for in-flight ops to drain
LINNEA_PROXY_REQ_BODY   equ 8      ; relaying a request body too large to
                                   ; buffer: client recv -> upstream send,
                                   ; a chunk at a time, until it is all sent

; conn.tls_phase — a TLS connection is only special until the keys reach the
; kernel; after that the ordinary HTTP/proxy/tunnel path runs unchanged.
LINNEA_TLS_PHASE_NONE   equ 0      ; plaintext listener
LINNEA_TLS_PHASE_HS     equ 1      ; userspace handshake: client recv/send are
                                   ; routed to the TLS handlers, state in up_buf
LINNEA_TLS_PHASE_KTLS   equ 2      ; handed off: the kernel does record
                                   ; protection, so this behaves as plaintext
                                   ; everywhere EXCEPT that recv reports the
                                   ; peer's close_notify as -EIO (see .recv_eof)

struc linnea_connection
    .fd:            resd 1         ; accepted socket
    .server:        resd 1         ; index of the server that accepted it
    .index:         resq 1         ; own pool index, kept for user_data and free
    .gen:           resq 1         ; bumped on every alloc. An io_uring
                                   ; completion carries only indices, so a
                                   ; late one (a proxy upstream op whose
                                   ; connection has since closed) is detected
                                   ; by comparing the generation it was armed
                                   ; under — the slot may already belong to a
                                   ; different client.
    .next_free:     resq 1         ; free-list link (pool index), -1 = end
    .in_use:        resq 1         ; 1 while handed out. The drain walks the
                                   ; pool looking for connections to close, and
                                   ; a free slot's fields are stale.
    .in_len:        resq 1         ; bytes received so far
    .head_len:      resq 1         ; bytes consumed by the current request head
    .keep_alive:    resq 1         ; 1 = keep the connection after the response
    .out_ptr:       resq 1         ; unsent response bytes
    .out_rem:       resq 1
    .file_base:     resq 1         ; mmap'd file being served (0 = none)
    .file_size:     resq 1         ; full mapping size, for munmap
    .file_ptr:      resq 1         ; bytes queued behind the header send
    .file_rem:      resq 1         ; (the file body, or a proxied request body)
    .peer:          resb 80        ; peer as "a.b.c.d:port" or "[v6]:port"
    .peer_len:      resq 1         ; (sized for the number formatter's 20-byte scratch)
    ; --- proxying ---------------------------------------------------
    .up_fd:         resd 1         ; upstream socket, -1 = none
    .up_pad:        resd 1
    .proxy_state:   resq 1         ; LINNEA_PROXY_*
    .location:      resq 1         ; matched location* (static config memory)
    .vhost:         resq 1         ; server* handling the request, for the log
    .body_rem:      resq 1         ; upstream body bytes still expected;
                                   ; -1 = until the upstream closes
    .relayed:       resq 1         ; body bytes relayed to the client
    .up_len:        resq 1         ; bytes buffered in up_buf
    .req_body_rem:  resq 1         ; request-body bytes still to come from the
                                   ; client and be relayed upstream. Nonzero
                                   ; only for a body too large to buffer with
                                   ; the head, which streams through in_buf a
                                   ; chunk at a time instead of being held
                                   ; whole (a 413 before Q89).
    .up_status:     resq 1         ; upstream status code, for the log
    .is_head:       resq 1         ; 1 = the client sent HEAD (no body relay)
    ; --- upgrade tunnel (websockets etc.) ----------------------------
    ; The client's Connection field value, so the proxy rewriter can honour
    ; RFC 9110 7.6.1: every field this names is hop-by-hop and MUST be removed
    ; before forwarding. Without it the rewriter dropped only Connection itself
    ; and passed the named fields straight to the backend — which is exactly the
    ; header-smuggling primitive that requirement exists to close.
    .conn_opts:     resq 1         ; -> the field value, 0 = no Connection field
    .conn_opts_len: resq 1
    .upgrade:       resq 1         ; 1 = the client asked to upgrade and the
                                   ; wish was forwarded; a 101 starts a tunnel
    .ws_c2u_busy:   resq 1         ; an op is in flight client->upstream
    .ws_u2c_busy:   resq 1         ; an op is in flight upstream->client
    .ws_c2u_ptr:    resq 1         ; unsent client bytes (in_buf); the
    .ws_c2u_rem:    resq 1         ; u2c direction owns out_ptr/out_rem
    ; the peer's address without its port, for the per-source connection cap: the
    ; formatted .peer above carries the port too, and two connections from one
    ; host differ there
    .peer_ip:       resb 16
    .peer_ip_len:   resq 1
    ; CLOCK_MONOTONIC seconds when the current request head started arriving (at
    ; accept, then again after each request completes). The idle timeout rearms on
    ; every byte; this does not, so a head that never finishes is still bounded.
    .req_start:     resq 1
    .last_activity: resq 1         ; CLOCK_MONOTONIC seconds of the last data
                                   ; in either direction; a tunnel recv that
                                   ; times out re-arms unless both are idle
    .close_reason:  resq 1         ; teardown reason, held while CLOSING
    .close_reason_len: resq 1      ; waits for the other direction's op
    ; --- TLS: the handshake state overlays up_buf, so only a phase flag
    ; lives here (see LINNEA_TLS_PHASE_* below).
    .tls_phase:     resq 1
    .h2_saw_settings: resq 1       ; the client's preface SETTINGS has arrived
    .continue_sent: resq 1         ; the 100 (Continue) interim response has
                                   ; gone out for the request being read
    .close_notified: resq 1        ; the close_notify alert has gone out
    .is_h2:         resq 1         ; 1 = HTTP/2 connection (post-handoff)
    .h2_state:      resq 1         ; LINNEA_H2_* connection state
    ; --- HTTP/2 multiplexing state (M18) -----------------------------
    ; Per-stream body state lives in a pool overlaid on up_buf; only
    ; connection-wide bookkeeping is here.
    .h2_cwnd:        resq 1        ; connection send window (signed)
    .h2_rr_cursor:   resq 1        ; round-robin scheduler cursor (slot index)
    .h2_last_stream: resq 1        ; highest client stream id seen
    .h2_rst_count:   resq 1        ; RST_STREAMs seen (rapid-reset guard)
    .h2_done_count:  resq 1        ; streams whose body completed (reset budget)
    .h2_init_swnd:   resq 1        ; peer's SETTINGS_INITIAL_WINDOW_SIZE
    .h2_tx_busy:     resq 1        ; a client send is in flight: out_buf is
                                   ; owned by it, defer frame building
    .h2_upload:      resq 1        ; slot index + 1 owning the upload buffer
    .h2_rx_busy:     resq 1        ; a client recv is in flight. Upstream
                                   ; completions can reach the client side at
                                   ; any time, so both directions are tracked
                                   ; explicitly: an op is armed only when its
                                   ; direction is idle, and every path that
                                   ; could leave the connection with nothing
                                   ; armed re-arms the recv
    ; Teardown began while the other direction still had an op in flight. The
    ; kernel owns in_buf/out_buf (and any stream body mapping) until that op
    ; completes, so the socket is shut down and the free deferred — freeing now
    ; would let the kernel write into a recycled buffer. close_reason holds the
    ; log reason across the wait, as it does for a tunnel.
    .h2_closing:     resq 1
    ; Lingering close (drain): the response's last bytes were handed to the
    ; kernel, but close(2) with unread inbound (a downloading h2 client is
    ; always sending WINDOW_UPDATEs) answers with an RST that discards the
    ; untransmitted tail of the send buffer. The write side is shut down
    ; (the FIN queues behind the data) and reads are drained until the peer
    ; closes or a short timeout runs out; only then is the socket closed.
    ; Holds 1 + the number of linger reads served, so a peer trickling bytes
    ; cannot extend the linger forever.
    .linger:         resq 1
    ; The vhost whose certificate this connection presented (0 = the
    ; accepting server's, the RFC 6066 fallback for an absent or unknown
    ; server_name). It is what decides which names the connection may speak
    ; for: HTTP/2 routes per request by :authority, and a name belonging to a
    ; vhost with a DIFFERENT certificate is answered 421, exactly as HTTP/3
    ; does since Q124.
    .sni_vhost:      resq 1
    ; The two application traffic secrets, kept for the life of the connection.
    ; A TLS 1.3 KeyUpdate (RFC 8446 4.6.3) means the peer has derived the next
    ; generation of its secret and switched to it, so the receiver must derive
    ; the same one -- which needs the current secret. They are computed in the
    ; handshake state, and that state is OVERLAID ON up_buf, which is reused as
    ; a buffer the moment the kernel takes the connection over; so they have to
    ; be copied somewhere that outlives the handoff. 64 bytes against buffers
    ; measured in kilobytes.
    .c_ap_secret:    resb 32
    .s_ap_secret:    resb 32
    ; kTLS receive: a msghdr, its iovec and room for the control message the
    ; kernel attaches to every record it delivers (TLS_GET_RECORD_TYPE). A plain
    ; recv cannot carry that cmsg, and a record that is not application data then
    ; fails the read with -EIO AND IS CONSUMED -- the connection cannot be
    ; recovered from that point -- so a kTLS connection reads with RECVMSG and
    ; asks for the type up front. The kernel reads these asynchronously, so they
    ; live per connection rather than in shared scratch.
    .rx_msg:         resb LINNEA_KTLS_MSGHDR_SIZE
    .rx_iov:         resb LINNEA_KTLS_IOVEC_SIZE
    .rx_cmsg:        resb LINNEA_KTLS_CMSG_SIZE
    .rx_msg_armed:   resq 1     ; 1 when the outstanding read is a RECVMSG, so a
                                ; completion knows whether rx_cmsg holds anything
    .rx_rectype:     resq 1     ; TLS record type of the last completed read
    .in_buf:        resb LINNEA_CONN_IN_BUF
    .out_buf:       resb LINNEA_CONN_OUT_BUF
    .up_buf:        resb LINNEA_CONN_UP_BUF
endstruc
