; Connection pool limits and per-connection state layout.
; The pool size comes from the config (max_connections).

LINNEA_CONN_IN_BUF      equ 8192   ; request head+body buffer (431/413 if exceeded)
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
    .next_free:     resq 1         ; free-list link (pool index), -1 = end
    .in_len:        resq 1         ; bytes received so far
    .head_len:      resq 1         ; bytes consumed by the current request head
    .keep_alive:    resq 1         ; 1 = keep the connection after the response
    .out_ptr:       resq 1         ; unsent response bytes
    .out_rem:       resq 1
    .file_base:     resq 1         ; mmap'd file being served (0 = none)
    .file_size:     resq 1         ; full mapping size, for munmap
    .file_ptr:      resq 1         ; bytes queued behind the header send
    .file_rem:      resq 1         ; (the file body, or a proxied request body)
    .peer:          resb 48        ; peer as "a.b.c.d:port" (sized for the
    .peer_len:      resq 1         ; number formatter's 20-byte scratch)
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
    .up_status:     resq 1         ; upstream status code, for the log
    .is_head:       resq 1         ; 1 = the client sent HEAD (no body relay)
    ; --- upgrade tunnel (websockets etc.) ----------------------------
    .upgrade:       resq 1         ; 1 = the client asked to upgrade and the
                                   ; wish was forwarded; a 101 starts a tunnel
    .ws_c2u_busy:   resq 1         ; an op is in flight client->upstream
    .ws_u2c_busy:   resq 1         ; an op is in flight upstream->client
    .ws_c2u_ptr:    resq 1         ; unsent client bytes (in_buf); the
    .ws_c2u_rem:    resq 1         ; u2c direction owns out_ptr/out_rem
    .last_activity: resq 1         ; CLOCK_MONOTONIC seconds of the last data
                                   ; in either direction; a tunnel recv that
                                   ; times out re-arms unless both are idle
    .close_reason:  resq 1         ; teardown reason, held while CLOSING
    .close_reason_len: resq 1      ; waits for the other direction's op
    ; --- TLS: the handshake state overlays up_buf, so only a phase flag
    ; lives here (see LINNEA_TLS_PHASE_* below).
    .tls_phase:     resq 1
    .is_h2:         resq 1         ; 1 = HTTP/2 connection (post-handoff)
    .h2_state:      resq 1         ; LINNEA_H2_* connection state
    ; --- HTTP/2 single-stream response send state (M17) --------------
    .h2_send_stream: resq 1        ; stream whose body is streaming (0 = none)
    .h2_body_ptr:    resq 1        ; next unframed body byte (mmap + offset)
    .h2_body_rem:    resq 1        ; body bytes not yet framed
    .h2_end_stream:  resq 1        ; 1 = the final DATA frame sets END_STREAM
    .h2_swnd:        resq 1        ; per-stream send window (signed)
    .h2_cwnd:        resq 1        ; connection send window (signed)
    .in_buf:        resb LINNEA_CONN_IN_BUF
    .out_buf:       resb LINNEA_CONN_OUT_BUF
    .up_buf:        resb LINNEA_CONN_UP_BUF
endstruc
