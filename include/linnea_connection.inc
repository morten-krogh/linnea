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
LINNEA_PROXY_CAPTURE    equ 8      ; capturing a request body too large to
                                   ; buffer: client recv -> spill file, until
                                   ; it is complete. The upstream has not been
                                   ; contacted yet, so a client that gives up
                                   ; here leaves the backend untouched rather
                                   ; than holding a truncated request.
LINNEA_PROXY_H3BODY     equ 9      ; an HTTP/3-owned leg capturing the upstream
                                   ; RESPONSE body into the spill file. There is
                                   ; no client socket to relay to — the answer
                                   ; goes out as QUIC stream chunks once whole —
                                   ; so the response is buffered exactly as an
                                   ; oversized request body is on the way in.

; conn.chunk_state — where an incremental chunked decode stopped. The states
; are per BYTE, not per line: any of these boundaries can fall between two
; recvs, and a decoder that assumed otherwise would reject valid framing.
LINNEA_CHUNK_SIZE       equ 0      ; accumulating the hex size
LINNEA_CHUNK_EXT        equ 1      ; chunk-ext, ignored, runs to the CR
LINNEA_CHUNK_SIZE_LF    equ 2      ; saw the CR of the size line
LINNEA_CHUNK_DATA       equ 3      ; copying chunk_rem bytes of data
LINNEA_CHUNK_DATA_CR    equ 4      ; the CR that must follow the data
LINNEA_CHUNK_DATA_LF    equ 5
LINNEA_CHUNK_TRAIL      equ 6      ; at the start of a trailer line
LINNEA_CHUNK_TRAIL_LINE equ 7      ; inside one, dropping it
LINNEA_CHUNK_TRAIL_LF   equ 8
LINNEA_CHUNK_END_LF     equ 9      ; the LF that ends the whole body
LINNEA_CHUNK_TRAIL_VAL  equ 11     ; past the colon, reading the value
; Where a chunk-ext begins, for the three decoders that hand their state to
; linnea_chunk_ext_step. That function owns every other value; this is the
; only one a caller may name.
LINNEA_CHUNK_EXT_START  equ 0
LINNEA_CHUNK_DONE       equ 10

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
                                   ; client. Nonzero only for a body too large
                                   ; to buffer with the head, which is captured
                                   ; into the spill file below and forwarded
                                   ; once complete (a 413 before Q89).
    .spill_fd:      resd 1         ; O_TMPFILE holding the captured request
    .spill_pad:     resd 1         ; body, -1 = none
    .spill_len:     resq 1         ; bytes captured so far
    ; A chunked body has no declared length, so it is decoded as it arrives —
    ; the state a decode carries between one recv and the next, since a chunk
    ; header, its data or even a CRLF can be split across datagrams.
    .chunk_state:   resq 1         ; LINNEA_CHUNK_*
    .chunk_rem:     resq 1         ; the size being accumulated, then the data
                                   ; bytes of that chunk still to come
    .chunk_digits:  resq 1         ; hex digits in the current size line
    .chunk_ext:     resq 1         ; where linnea_chunk_ext_step has got to in
                                   ; the chunk-ext, carried across recvs like
                                   ; every other piece of this decode. Only
                                   ; that function reads its value; 0 is "at a
                                   ; component boundary", which is where the
                                   ; size line's digits leave it.
    .chunk_raw:     resq 1         ; encoded bytes consumed, capped like the
                                   ; decoded ones: endless empty chunks and
                                   ; trailers must not run forever
    ; The SECOND block of the same five, for the other direction. An HTTP/1
    ; upstream response is relayed byte for byte rather than captured, so its
    ; chunked framing used to reach the client exactly as the upstream wrote it
    ; -- a malformed extension or trailer arriving as a clean, complete 200
    ; while h2 and h3 answered 502 to the same upstream bytes
    ; (audit-report-24). The relay now runs the same decoder over what it is
    ; about to forward, in a mode that judges and copies nothing, and it needs
    ; its own state to do that: the capture's block belongs to the REQUEST and
    ; is live for a chunked upload on the same connection.
    .resp_chunk_state:  resq 1
    .resp_chunk_rem:    resq 1
    .resp_chunk_digits: resq 1
    .resp_chunk_ext:    resq 1
    .resp_chunk_raw:    resq 1
    .resp_chunked:      resq 1     ; 1 = the response being relayed is chunked
    .capture_chunked: resq 1       ; 1 = the capture is decoding chunked framing
    .capture_done:  resq 1         ; 1 = the captured body is complete, and the
                                   ; parser's second pass serves it from the
                                   ; mapping rather than from in_buf
    .pend_len:      resq 1         ; pipelined suffix bytes stashed at
                                   ; in_buf[head_len] because the NEXT request
                                   ; arrived in the same recv as a streamed
                                   ; body's tail. keep-alive folds them back
                                   ; into in_len; 0 = nothing pending. Only the
                                   ; chunked capture path stashes here — the
                                   ; counted one caps its recv so the suffix is
                                   ; never pulled out of the kernel to begin with.
    .answer_linger: resq 1         ; 1 = this response was written while the
                                   ; client was still sending its body, so the
                                   ; close has to linger: close(2) with unread
                                   ; inbound answers RST and the client would
                                   ; never get to read the answer
    .up_status:     resq 1         ; upstream status code, for the log
    .is_head:       resq 1         ; 1 = the client sent HEAD (no body relay)
    ; --- an upstream leg owned by an HTTP/3 request -------------------
    ; A proxied h3 request has no client socket of its own: the answer is owed
    ; to one stream of a QUIC connection, which lives in a different pool. So
    ; the leg borrows an ordinary connection slot for its UPSTREAM half alone
    ; (.fd stays -1) and names its owner here. The generation is what makes a
    ; late completion safe: a QUIC connection that died meanwhile has had its
    ; slot recycled, and the response is dropped rather than sent to whoever
    ; holds it now. Zero .h3_owner means an ordinary client-facing connection,
    ; which is what every path outside the h3 proxy tests for.
    .h3_owner:      resq 1         ; 1 = this leg answers an HTTP/3 stream
    ; Nobody is waiting for this answer any more: the peer cancelled the stream,
    ; or its whole connection is gone. The leg cannot simply be freed — an
    ; io_uring operation is in flight and the kernel owns its buffer until that
    ; completes, so freeing now would let it write into a recycled connection.
    ; The socket is shut down instead (which makes the completion prompt) and
    ; this is set; whichever completion arrives next does the freeing and sends
    ; nothing. Same shape as .h2_closing on the client side.
    .h3_cancel:     resq 1
    .h3_qidx:       resq 1         ; the QUIC connection's pool index
    .h3_qgen:       resq 1         ; its generation when the leg was started
    .h3_sid:        resq 1         ; the request stream to answer
    .h3_hlen:       resq 1         ; response-head bytes of the FINAL response
    ; Where that final head starts within up_buf. Nonzero only when the upstream
    ; sent interim (1xx) responses first: those heads are left in place ahead of
    ; it, and delivery walks [0, .h3_hoff) to re-encode each one as its own
    ; HEADERS frame before the final one (audit-report-7 Finding 1). h3 used to
    ; classify any status below 200 as a bodiless FINAL response, so a backend
    ; sending "103 Early Hints" then "200 OK" gave the client the 103 and
    ; nothing else -- the answer it asked for was never delivered.
    .h3_hoff:       resq 1
    ; ...and how many of them there were, capped at LINNEA_H3_PROXY_IMAX
    ; while parsing. Bounding the raw bytes alone would not bound the
    ; ENCODED size: every head, however small, encodes to a field section
    ; carrying its own via, date and server (audit-report-8 Finding 2).
    .h3_inum:       resq 1
    ; The access line's who-and-what, parked when the request is forwarded. It
    ; is written long afterwards, from an upstream completion, by which time the
    ; QUIC reassembly buffer those fields pointed into has been reused — and the
    ; shared log parameter block belongs to whichever request was served most
    ; recently. Copied into in_buf, which an h3 leg has no other use for:
    ; method at 0, target at LINNEA_H3_LG_TGT, host at LINNEA_H3_LG_HOST. Each
    ; is truncated to its slot, as HTTP/2's proxy log fields are.
    .h3_lg_meth_len: resq 1
    .h3_lg_tgt_len:  resq 1
    .h3_lg_host_len: resq 1
    .h3_nobody:     resq 1         ; 1 = this response carries no body at all
                                   ; (a HEAD, a 204, a 304, a 1xx), so its
                                   ; content-length is the upstream's to state
                                   ; and not ours to re-derive from a capture
                                   ; that was always going to be empty
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
    ; Client sends this connection has queued and not yet had completed. A COUNT
    ; rather than a flag: a flag cleared by the first of two overlapping sends
    ; would claim the socket was idle while one was still in flight. It exists
    ; for one decision -- when it is safe to send our own KeyUpdate and switch
    ; the transmit key underneath it. Interleaving that with a send the kernel is
    ; still framing would encrypt application data under a key the peer has not
    ; been told to expect. If this ever sticks above zero the KeyUpdate is simply
    ; never sent, which is what the server did before it could send one at all.
    .tx_inflight:    resq 1
    ; A peer asked for a KeyUpdate of our own (RFC 8446 4.6.3 update_requested)
    ; and a send was in flight, so it waits for that send to complete.
    .ku_pending:     resq 1
    .in_buf:        resb LINNEA_CONN_IN_BUF
    .out_buf:       resb LINNEA_CONN_OUT_BUF
    .up_buf:        resb LINNEA_CONN_UP_BUF
endstruc

; The two blocks above are addressed through a base pointer by
; linnea_spill_chunked, which is what lets one decoder serve the request
; capture and the response relay. Their layout is therefore part of the
; contract, and the assembler is made to say so rather than a comment.
struc linnea_chunk
    .state:   resq 1
    .rem:     resq 1
    .digits:  resq 1
    .ext:     resq 1
    .raw:     resq 1
endstruc

%if (linnea_connection.chunk_rem - linnea_connection.chunk_state) != linnea_chunk.rem
  %error "linnea_connection.chunk_* has drifted from struc linnea_chunk"
%endif
%if (linnea_connection.chunk_digits - linnea_connection.chunk_state) != linnea_chunk.digits
  %error "linnea_connection.chunk_* has drifted from struc linnea_chunk"
%endif
%if (linnea_connection.chunk_ext - linnea_connection.chunk_state) != linnea_chunk.ext
  %error "linnea_connection.chunk_* has drifted from struc linnea_chunk"
%endif
%if (linnea_connection.chunk_raw - linnea_connection.chunk_state) != linnea_chunk.raw
  %error "linnea_connection.chunk_* has drifted from struc linnea_chunk"
%endif
%if (linnea_connection.resp_chunk_rem - linnea_connection.resp_chunk_state) != linnea_chunk.rem
  %error "linnea_connection.resp_chunk_* has drifted from struc linnea_chunk"
%endif
%if (linnea_connection.resp_chunk_digits - linnea_connection.resp_chunk_state) != linnea_chunk.digits
  %error "linnea_connection.resp_chunk_* has drifted from struc linnea_chunk"
%endif
%if (linnea_connection.resp_chunk_ext - linnea_connection.resp_chunk_state) != linnea_chunk.ext
  %error "linnea_connection.resp_chunk_* has drifted from struc linnea_chunk"
%endif
%if (linnea_connection.resp_chunk_raw - linnea_connection.resp_chunk_state) != linnea_chunk.raw
  %error "linnea_connection.resp_chunk_* has drifted from struc linnea_chunk"
%endif

; linnea_spill_chunked's two modes: capture writes the decoded body to the
; spill file and stashes anything pipelined behind it; validate only judges.
LINNEA_CHUNK_CAPTURE  equ 0
LINNEA_CHUNK_VALIDATE equ 1
