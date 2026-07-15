; Connection pool limits and per-connection state layout.

LINNEA_MAX_CONNECTIONS  equ 1024
LINNEA_CONN_IN_BUF      equ 8192   ; request head buffer (431 if exceeded)
LINNEA_CONN_OUT_BUF     equ 4096   ; response buffer

struc linnea_connection
    .fd:            resd 1         ; accepted socket
    .server:        resd 1         ; index of the server that accepted it
    .index:         resq 1         ; own pool index, kept for user_data and free
    .next_free:     resq 1         ; free-list link (pool index), -1 = end
    .in_len:        resq 1         ; bytes received so far
    .out_ptr:       resq 1         ; unsent response bytes
    .out_rem:       resq 1
    .in_buf:        resb LINNEA_CONN_IN_BUF
    .out_buf:       resb LINNEA_CONN_OUT_BUF
endstruc
