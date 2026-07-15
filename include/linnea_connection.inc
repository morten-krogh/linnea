; Connection pool limits and per-connection state layout.
; The pool size comes from the config (max_connections).

LINNEA_CONN_IN_BUF      equ 8192   ; request head+body buffer (431/413 if exceeded)
LINNEA_CONN_OUT_BUF     equ 4096   ; response buffer

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
    .file_ptr:      resq 1         ; file bytes queued behind the header send
    .file_rem:      resq 1
    .peer:          resb 48        ; peer as "a.b.c.d:port" (sized for the
    .peer_len:      resq 1         ; number formatter's 20-byte scratch)
    .in_buf:        resb LINNEA_CONN_IN_BUF
    .out_buf:       resb LINNEA_CONN_OUT_BUF
endstruc
