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
    .in_buf:        resb LINNEA_CONN_IN_BUF
    .out_buf:       resb LINNEA_CONN_OUT_BUF
    .up_buf:        resb LINNEA_CONN_UP_BUF
endstruc
