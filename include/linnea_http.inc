; The linnea_http request-handling contract, shared with the event loop.

; linnea_http_handle return values
LINNEA_HTTP_NEED_MORE   equ 0    ; incomplete head, arm another recv
LINNEA_HTTP_RESPOND     equ 1    ; out/file fields set; send, then consult
                                 ; conn.keep_alive
LINNEA_HTTP_PROXY       equ 2    ; upstream socket open, request rewritten;
                                 ; connect, send it, then read the response

; linnea_http_proxy_head return values
LINNEA_HTTP_HEAD_MORE   equ 0    ; the response head is not complete yet
LINNEA_HTTP_HEAD_READY  equ 1    ; rewritten head ready to send to the client
LINNEA_HTTP_HEAD_BAD    equ -1   ; malformed head; answer the client 502
