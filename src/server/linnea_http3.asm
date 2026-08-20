; linnea_http3.asm — HTTP/3 (RFC 9114) request streams, end to end: the frame
; walk over a client's request stream (resumable, so one stream may arrive over
; many datagrams), the QPACK decode of its HEADERS, and the whole response side
; — routing to a location, serving a file with its validators, ranges and
; pre-compressed variants, redirects, the canned errors, and handing a proxied
; request to the upstream hook.
;
; The header said "the response path and stream demux come later" until well
; after both arrived, which is worth a line of its own: a file header is the
; first thing a reader trusts and the last thing anyone updates.

default rel

%include "linnea_http3.inc"
%include "linnea_config.inc"
%include "linnea_hpack.inc"
%include "linnea_syscall.inc"

global linnea_h3_read_headers
global linnea_h3_walk_feed
global linnea_h3_walk_decode
global linnea_h3_build_response
global linnea_h3_build_canned
global linnea_h3_build_431
global linnea_h3_build_429
global linnea_h3_build_413
global linnea_h3_build_500
global linnea_h3_build_421
global linnea_h3_build_response_head
global linnea_h3_serve
global linnea_h3_srv
global h3_hdrs_buf
global h3_cookie_buf
global linnea_h3_tx_cap
global linnea_h3_owner_idx
global linnea_h3_owner_gen
global linnea_h3_owner_sid
global linnea_h3_proxy_hook
global linnea_h3_proxy_body_ptr
global linnea_h3_proxy_body_len
global linnea_h3_body_fd

extern linnea_hpack_req_check
extern s_is_early
extern linnea_quic_varint_decode
extern linnea_quic_varint_encode
extern linnea_log_access
extern linnea_log_acc_peer
extern linnea_log_acc_proto
extern linnea_log_acc_proto_len
extern linnea_log_acc_status
extern linnea_log_acc_bytes
extern linnea_qpack_decode
extern linnea_qpack_encode_response
extern linnea_qpack_reset_response
extern linnea_qpack_send_validators
extern linnea_qpack_crange_ptr
extern linnea_qpack_location_ptr
extern linnea_qpack_location_len
extern linnea_qpack_max_fss
extern linnea_qpack_fss_over
extern linnea_qpack_crange_len
extern linnea_qpack_cenc
extern linnea_qpack_ccontrol_ptr
extern linnea_qpack_ccontrol_len
; static-file resolution, shared with the HTTP/2 serve path
extern linnea_config_match_location
extern linnea_static_normalize
extern linnea_static_open
extern linnea_string_equal
extern linnea_static_open_enc
extern linnea_static_mime
extern linnea_static_validators
extern linnea_static_mtime
extern linnea_static_etag
extern linnea_static_etag_len
extern linnea_http_inm_match
extern linnea_http_etag_match
extern linnea_http_range_parse
extern linnea_http_ifrange_match
extern linnea_time_parse_http_date

global linnea_h3_body_off
global linnea_h3_body_len

section .rodata
idx_name:      db "index.html"
idx_name_len   equ $ - idx_name
txt_plain:     db "text/plain; charset=utf-8"
txt_plain_len  equ $ - txt_plain
body_404:      db "404 Not Found", 10
body_404_len   equ $ - body_404
body_400:      db "400 Bad Request", 10
body_400_len   equ $ - body_400
body_502:      db "502 Bad Gateway", 10
body_502_len   equ $ - body_502
body_405:      db "405 Method Not Allowed", 10
body_405_len   equ $ - body_405
body_425:      db "425 Too Early", 10
body_425_len   equ $ - body_425
body_417:      db "417 Expectation Failed", 10
method_trace_h3:   db "TRACE"
method_options_h3: db "OPTIONS"
body_options_h3:   db "Allow: GET, HEAD, OPTIONS", 10
body_options_h3_len equ $ - body_options_h3
body_417_len   equ $ - body_417
proto_h3: db "HTTP/3"
proto_h3_len equ $ - proto_h3
body_421: db "421 Misdirected Request", 10
body_421_len equ $ - body_421
body_431:      db "431 Request Header Fields Too Large", 10
body_431_len   equ $ - body_431
body_429:      db "429 Too Many Requests", 10
body_429_len   equ $ - body_429
body_413:      db "413 Content Too Large", 10
body_413_len   equ $ - body_413
body_503:      db "503 Service Unavailable", 10
body_503_len   equ $ - body_503
body_500:      db "500 Internal Server Error", 10
body_500_len   equ $ - body_500

section .bss
; The encoded response field section. Sized by LINNEA_H3_FS_BUF for the worst
; section the documented config can produce (a redirect's Location dominates),
; and passed to the encoder as a hard limit — it was 768 with no limit at all,
; which a long request target to a redirect location wrote straight past.
fs_buf:   resb LINNEA_H3_FS_BUF
clen_buf: resb 20                     ; content-length as decimal ASCII
h3_path_buf: resb 4096                ; root ++ decoded path ++ NUL
; the Location value of a redirect: the configured target with the request's
; RAW target appended, exactly as h1 builds it — same resource, other origin,
; percent-encoding untouched
h3_loc_buf:  resb 4096
h3_join:     resq 1                   ; where the joined root++path starts
; The vhost's config server*, set by the caller before linnea_h3_serve so the
; request can be routed to a location. Zero means "no routing": serve the root
; the caller passed, which is what h3 did before it could route at all.
linnea_h3_srv: resq 1
; Which QUIC connection and stream this request arrived on, so a proxied one
; can name the owner its answer is owed to. The generation is the connection ID
; that incarnation issued: a slot recycled meanwhile carries a different one and
; the response is dropped rather than sent to whoever holds it now. Set by the
; QUIC server before linnea_h3_serve, alongside linnea_h3_srv.
linnea_h3_owner_idx: resq 1
linnea_h3_owner_gen: resq 1
linnea_h3_owner_sid: resq 1
; What a proxy location does with a request (0 = nothing can): the server
; installs linnea_h3_proxy_start here at startup. A pointer rather than a
; direct call so that the framing and response builders stay linkable on their
; own — the test binaries that exercise them have no connection pool, no
; io_uring loop and no upstream to reach.
linnea_h3_proxy_hook: resq 1
; The request body the hook forwards, whole and in memory: an h3 request stream
; is reassembled before it is served, so its DATA frames have already been
; joined into one run.
linnea_h3_proxy_body_ptr: resq 1
linnea_h3_proxy_body_len: resq 1
; ...or, when the stream was consumed as it arrived, the file it was captured
; into (-1 = none). The bytes are too many and too long-lived to sit in the
; reassembly buffer: that is reused as soon as the datagram is done with, and a
; proxied request does not go upstream until its connect completes.
linnea_h3_body_fd: resq 1
; Where emit_field rebuilds the client's forwardable headers as h1 lines, for
; the request we send upstream. Same size as h2's, and overflow is detectable:
; the rebuild parks hb_cur past hb_end rather than writing past it.
h3_hdrs_buf: resb LINNEA_H3_HDRS_BUF
; RFC 9114 4.2.1 in the same words RFC 9113 8.2.3 uses for HTTP/2: a client may
; split Cookie across field lines for compression, and an intermediary MUST
; join them with "; " before a hop that is not HTTP/3. h2 has done that since
; Finding 32; h3 did not, because the decoder guards the whole block on ck_buf
; being set and h3 passed none -- a guard added to stop a null write from
; crashing, which also switched the behaviour off. A backend reading Cookie
; sees the first line only, so a session cookie a browser split was silently
; truncated. Same buffer size as h2's, and the same overflow rule (ck_len -1).
h3_cookie_buf: resb LINNEA_H3_COOKIE_BUF
; May this request start a CHUNKED response? 1 while any of the connection's
; response-stream slots is free, 0 when all are busy — set by the QUIC server
; per request before linnea_h3_serve, which refuses a large body with a 503
; (retryable) rather than have nowhere to stream it from.
;
; A flag, not a byte count. It was an allowance once, and the description
; outlived the change: every reader here tests it against 0.
linnea_h3_tx_cap: resq 1
; For a chunked (large-body) response: where the body starts within the file
; mapping linnea_h3_serve hands back, and how many bytes of it to stream — a
; 206's range slice, or 0 / the whole size. The caller copies these into the
; response-stream slot beside the mapping.
linnea_h3_body_off: resq 1
linnea_h3_body_len: resq 1
h3_crange_buf: resb 80                ; "bytes first-last/size" / "bytes */size"
; Trailer field sections are decoded for validation, but must not overwrite the
; request that will be routed. Keep a separate request and Huffman arena for
; that throwaway decode: the real request's pointers may refer to h3scratch.
h3_trailer_req:     resb linnea_h2_req_size
h3_trailer_scratch: resb LINNEA_HPACK_MAX_LISTSIZE
; The one request-stream walk. One at a time is enough while the caller feeds a
; whole stream in a single call; driving it incrementally moves this into the
; per-stream context, which is what lets several uploads run at once.
h3_walk: resb linnea_h3_walk_size

section .text

; linnea_h3_walk_feed(rdi = walk state, rsi = bytes, rdx = length, rcx = req,
;   r8 = 1 when these bytes end the stream) -> rax = 0 more of the stream is
;   needed, 1 the request is complete, or -LINNEA_H3_ERR_* .
;
; The request-stream frame walk, resumable: it may be called once with a whole
; stream or many times with successive pieces of one, and the two must reach
; the same verdict. Everything that can be split at any byte — a frame header,
; a field section, a payload — is carried in the state rather than the stack.
;
; Runs of DATA payload go to .sink when one is set — the spill file, for a
; stream being consumed as it arrives, so the body never has to be held whole.
; Without a sink they are joined IN PLACE instead, as the one-pass walk always
; did: each run is moved down onto the end of the body so the whole body reads
; as one run without a copy elsewhere (the destination is at or below the
; source, so the overlap is safe). That path needs the caller to be feeding
; successive slices of ONE buffer, which is what a whole stream in one call is.
linnea_h3_walk_feed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8                       ; [rsp] = the frame type across two decodes
    mov rbx, rdi                     ; walk state
    mov r12, rsi                     ; cursor
    lea r13, [rsi + rdx]             ; end of what arrived
    mov r14, rcx                     ; req
    mov r15, r8                      ; does the stream end here?
    cmp qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_DONE
    je .w_spent
.w_step:
    mov rax, [rbx + linnea_h3_walk.phase]
    cmp rax, LINNEA_H3_W_HEADER
    je .w_header
    cmp rax, LINNEA_H3_W_FIELDS
    je .w_fields
    cmp rax, LINNEA_H3_W_DATA
    je .w_data
    jmp .w_skip

; --- a frame header: two varints, taken a byte at a time so a header split
; across STREAM frames resumes exactly where it stopped ---------------------
.w_header:
    cmp r12, r13
    jae .w_input_end
    mov rcx, [rbx + linnea_h3_walk.hdr_len]
    cmp rcx, 16
    jae .w_truncated                 ; unreachable: two varints are 16 bytes at
                                     ; most, so a header cannot outgrow .hdr —
                                     ; and a frame we cannot read the header of
                                     ; is a frame error, as 7.1 has it
    movzx eax, byte [r12]
    mov [rbx + linnea_h3_walk.hdr + rcx], al
    inc rcx
    mov [rbx + linnea_h3_walk.hdr_len], rcx
    inc r12
    lea rdi, [rbx + linnea_h3_walk.hdr]
    lea rsi, [rdi + rcx]
    call linnea_quic_varint_decode   ; the type
    test rdx, rdx
    jz .w_header                     ; incomplete: another byte
    mov [rsp], rax                   ; hold it across the length's decode
    lea rdi, [rbx + linnea_h3_walk.hdr]
    add rdi, rdx
    lea rsi, [rbx + linnea_h3_walk.hdr]
    add rsi, [rbx + linnea_h3_walk.hdr_len]
    call linnea_quic_varint_decode   ; the payload length
    test rdx, rdx
    jz .w_header
    mov qword [rbx + linnea_h3_walk.hdr_len], 0
    mov [rbx + linnea_h3_walk.frame_rem], rax
    mov rcx, [rsp]
    cmp rcx, LINNEA_H3_FRAME_HEADERS
    je .w_headers_frame
    cmp rcx, LINNEA_H3_FRAME_DATA
    je .w_data_frame
    ; Neither. A request stream carries only those two; the reserved HTTP/2
    ; types (0x02..0x09, RFC 9114 7.2.8), the control/push frames and
    ; MAX_PUSH_ID are a connection error here, as is PRIORITY_UPDATE (RFC 9218
    ; 7.2) which belongs on the control stream. GREASE and any other unknown
    ; type MUST be ignored (7.2, 9).
    cmp rcx, LINNEA_H3_FRAME_MAX_PUSH_ID
    je .w_unexpected
    mov rdx, rcx
    sub rdx, 2
    cmp rdx, 7                       ; original type in 0x02..0x09
    jbe .w_unexpected
    cmp rcx, LINNEA_H3_FRAME_PRIORITY_UPDATE
    je .w_unexpected
    cmp rcx, LINNEA_H3_FRAME_PRIORITY_UPDATE_PUSH
    je .w_unexpected
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_SKIP
    jmp .w_step
.w_headers_frame:
    ; A HEADERS after the first is a trailer section, which must NOT merge into
    ; the request: a trailing range or if-none-match would change the response
    ; the client never asked to change. A third is an invalid sequence (4.1).
    mov rcx, [rbx + linnea_h3_walk.seq]
    cmp rcx, 2
    jae .w_unexpected
    test rcx, rcx
    jnz .w_trailer
    mov qword [rbx + linnea_h3_walk.fs_have], 0
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_FIELDS
    jmp .w_step
.w_trailer:
    ; A trailer is still a QPACK field section. Accumulate it just like the
    ; request headers, then decode it into the throwaway target below. Decoding
    ; matters even though the fields are discarded: a malformed section is a
    ; QPACK connection error, and pseudo-fields are a stream-level message
    ; error. The real request remains untouched so a trailer cannot affect
    ; routing or proxy-header rebuild.
    mov qword [rbx + linnea_h3_walk.seq], 2
    mov qword [rbx + linnea_h3_walk.fs_have], 0
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_FIELDS
    jmp .w_step
.w_data_frame:
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_DATA
    jmp .w_step

; --- a HEADERS payload: decoded where it lies when it all arrived together,
; which is every request that fits one packet; accumulated only when split ---
.w_fields:
    mov rax, r13
    sub rax, r12                     ; bytes in hand
    mov rcx, [rbx + linnea_h3_walk.frame_rem]
    cmp qword [rbx + linnea_h3_walk.fs_have], 0
    jne .w_fields_accum              ; already accumulating: keep to one place
    cmp qword [rbx + linnea_h3_walk.defer], 0
    jne .w_fields_accum              ; held for later: it has to be copied out
    cmp rcx, rax
    ja .w_fields_accum
    mov rdi, r12                     ; the whole section is contiguous
    mov rsi, rcx
    add r12, rcx
    mov qword [rbx + linnea_h3_walk.frame_rem], 0
    jmp .w_decode
.w_fields_accum:
    test rax, rax
    jz .w_input_end
    cmp rax, rcx
    jbe .w_fa_take
    mov rax, rcx
.w_fa_take:
    mov rdx, [rbx + linnea_h3_walk.fs_have]
    lea rcx, [rdx + rax]
    cmp rcx, LINNEA_H3_WALK_FS
    ja .w_toolarge
    push rax
    lea rdi, [rbx + linnea_h3_walk.fs]
    add rdi, rdx
    mov rsi, r12
    mov rcx, rax
    rep movsb
    pop rax
    add [rbx + linnea_h3_walk.fs_have], rax
    add r12, rax
    sub [rbx + linnea_h3_walk.frame_rem], rax
    jnz .w_step                      ; more of the section still to come
    cmp qword [rbx + linnea_h3_walk.defer], 0
    jne .w_fields_held
    lea rdi, [rbx + linnea_h3_walk.fs]
    mov rsi, [rbx + linnea_h3_walk.fs_have]
.w_decode:
    cmp qword [rbx + linnea_h3_walk.seq], 2
    je .w_decode_trailer
    mov rdx, r14
    call linnea_qpack_decode         ; 0 | -err
    test rax, rax
    jns .w_decoded
    ; A request that broke a semantic rule decoded fine — the QPACK state is
    ; intact, so RFC 9114 4.1.2 fails the STREAM, which -LINNEA_H3_ERR does.
    cmp qword [r14 + linnea_h2_req.malformed], 0
    jne .w_err
    ; a header list past our bound is a resource limit, answerable on the
    ; stream; only a genuine decode failure is a connection error
    cmp rax, -LINNEA_HPACK_ERR_LIMIT
    jne .w_qpack_bad
    jmp .w_toolarge
.w_decoded:
    ; the whole-request rules (an agreeing, plausible authority from one source
    ; or the other) — shared with HTTP/2
    mov rdi, r14
    call linnea_hpack_req_check
    test rax, rax
    js .w_err
    mov qword [rbx + linnea_h3_walk.seq], 1
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_HEADER
    jmp .w_step
.w_decode_trailer:
    ; Preserve the field-section pointer/length while preparing a fresh req.
    ; The decoder's Huffman output must also not reuse h3scratch: the original
    ; request may have pointers into it which are needed by the serve path.
    push rdi
    push rsi
    lea rdi, [h3_trailer_req]
    xor eax, eax
    mov ecx, linnea_h2_req_size / 8
    rep stosq
    lea rax, [h3_trailer_scratch]
    mov [h3_trailer_req + linnea_h2_req.scratch], rax
    lea rax, [h3_trailer_scratch + LINNEA_HPACK_MAX_LISTSIZE]
    mov [h3_trailer_req + linnea_h2_req.scratch_end], rax
    pop rsi
    pop rdi
    lea rdx, [h3_trailer_req]
    call linnea_qpack_decode
    test rax, rax
    jns .w_trailer_decoded
    ; emit_field marks a syntactically valid but semantically malformed field
    ; block in the temporary request. That is a stream error; all other decode
    ; failures mean the peer's QPACK state cannot be trusted and close the
    ; connection, just as for the initial field section.
    cmp qword [h3_trailer_req + linnea_h2_req.malformed], 0
    jne .w_err
    cmp rax, -LINNEA_HPACK_ERR_LIMIT
    je .w_toolarge
    jmp .w_qpack_bad
.w_trailer_decoded:
    ; RFC 9114 4.3: request pseudo-fields MUST NOT appear in trailers. Regular
    ; fields were syntax-checked by emit_field and connection-specific fields
    ; were rejected there as well; none of the decoded trailer values are
    ; copied into the live request.
    cmp qword [h3_trailer_req + linnea_h2_req.malformed], 0
    jne .w_err
    cmp qword [h3_trailer_req + linnea_h2_req.pseudo_seen], 0
    jne .w_err
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_HEADER
    jmp .w_step
.w_fields_held:
    ; A deferred initial section is decoded when the request is served. A
    ; trailer, however, must be validated now so a reassembled stream cannot
    ; complete successfully while its trailer was never decoded.
    cmp qword [rbx + linnea_h3_walk.seq], 2
    je .w_held_trailer
    ; the section is whole in .fs; the caller decodes it when it serves
    mov qword [rbx + linnea_h3_walk.seq], 1
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_HEADER
    jmp .w_step
.w_held_trailer:
    lea rdi, [rbx + linnea_h3_walk.fs]
    mov rsi, [rbx + linnea_h3_walk.fs_have]
    jmp .w_decode

; --- a DATA payload: the body is the concatenation of every DATA frame's
; payload (4.1), which an encoder may split any way it likes ----------------
.w_data:
    mov rcx, [rbx + linnea_h3_walk.seq]
    test rcx, rcx
    jz .w_unexpected                 ; DATA before HEADERS
    cmp rcx, 2
    jae .w_unexpected                ; ...and DATA after the trailer section
    cmp qword [rbx + linnea_h3_walk.frame_rem], 0
    je .w_frame_end
    mov rax, r13
    sub rax, r12
    test rax, rax
    jz .w_input_end
    mov rcx, [rbx + linnea_h3_walk.frame_rem]
    cmp rax, rcx
    jbe .w_d_take
    mov rax, rcx
.w_d_take:
    ; Where this run of body goes. A sink takes it somewhere that outlives the
    ; bytes in hand — the spill file — which is what lets the stream be
    ; consumed as it arrives instead of held whole. Without one the run is
    ; joined in place, as the one-pass walk always did.
    cmp qword [rbx + linnea_h3_walk.sink], 0
    je .w_d_join
    mov [rsp], rax                   ; the run's length, across the sink's call
    mov rdi, rbx
    mov rsi, r12
    mov rdx, rax
    call [rbx + linnea_h3_walk.sink]
    test eax, eax
    js .w_sink_failed
    mov rax, [rsp]
    jmp .w_d_extend
.w_d_join:
    mov rdx, [rbx + linnea_h3_walk.body_ptr]
    test rdx, rdx
    jz .w_d_first
    add rdx, [rbx + linnea_h3_walk.body_len]   ; where the body ends now
    cmp rdx, r12
    je .w_d_extend                   ; already contiguous: nothing to move
    mov [rsp], rax                   ; squeeze this run down onto that end
    mov rdi, rdx
    mov rsi, r12
    mov rcx, rax
    rep movsb
    mov rax, [rsp]
    jmp .w_d_extend
.w_d_first:
    mov [rbx + linnea_h3_walk.body_ptr], r12
.w_d_extend:
    add [rbx + linnea_h3_walk.body_len], rax
    add r12, rax
    sub [rbx + linnea_h3_walk.frame_rem], rax
    jnz .w_step
    jmp .w_frame_end

; --- a payload we do not read: grease or an unknown frame type --------------
.w_skip:
    cmp qword [rbx + linnea_h3_walk.frame_rem], 0
    je .w_frame_end
    mov rax, r13
    sub rax, r12
    test rax, rax
    jz .w_input_end
    mov rcx, [rbx + linnea_h3_walk.frame_rem]
    cmp rax, rcx
    jbe .w_s_take
    mov rax, rcx
.w_s_take:
    add r12, rax
    sub [rbx + linnea_h3_walk.frame_rem], rax
    jnz .w_step
.w_frame_end:
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_HEADER
    jmp .w_step

; --- the bytes in hand ran out ---------------------------------------------
.w_input_end:
    test r15, r15
    jz .w_more                       ; more of the stream is still to come
    ; The stream has ended here. Both entries to the serve require the FIN, so
    ; a walk stopped inside a frame means its last frame was cut short — RFC
    ; 9114 7.1 makes that a connection error, not a stream one.
    cmp qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_HEADER
    jne .w_truncated
    cmp qword [rbx + linnea_h3_walk.hdr_len], 0
    jne .w_truncated
    cmp qword [rbx + linnea_h3_walk.seq], 0
    je .w_noheaders
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_DONE
    mov eax, 1
    jmp .w_ret
.w_more:
    xor eax, eax
    jmp .w_ret
.w_spent:
    ; bytes after the walk finished, which the caller should not have fed
    mov rax, -LINNEA_H3_ERR_UNEXPECTED
    jmp .w_ret
.w_unexpected:
    mov rax, -LINNEA_H3_ERR_UNEXPECTED
    jmp .w_fail
.w_truncated:
    mov rax, -LINNEA_H3_ERR_TRUNCATED
    jmp .w_fail
.w_noheaders:
    mov rax, -LINNEA_H3_ERR_NOHEADERS
    jmp .w_fail
.w_toolarge:
    mov rax, -LINNEA_H3_ERR_TOOLARGE
    jmp .w_fail
.w_qpack_bad:
    mov rax, -LINNEA_H3_ERR_QPACK
    jmp .w_fail
.w_sink_failed:
    ; The body could not be put where it was going. Two different things, and
    ; they must not answer alike: -2 is the body outgrowing max_body, which is
    ; the peer's to hear about as a 413; anything else is the capture file
    ; failing us, which is ours and earns a 500. Collapsing them is how a write
    ; to a descriptor another connection had closed came back as "too large".
    cmp eax, -2
    je .w_sink_toobig
    mov rax, -LINNEA_H3_ERR_SINK
    jmp .w_fail
.w_sink_toobig:
    mov rax, -LINNEA_H3_ERR_TOOBIG
    jmp .w_fail
.w_err:
    mov rax, -LINNEA_H3_ERR
.w_fail:
    mov qword [rbx + linnea_h3_walk.phase], LINNEA_H3_W_DONE
.w_ret:
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_walk_decode(rdi = walk state, rsi = req) -> rax = 0 | -err.
; Decode the field section a deferred walk held, at the point the request is
; finally served. Same verdicts as decoding it inline: the bytes are the same
; bytes, only later, and the caller has just armed the req the decoder fills.
linnea_h3_walk_decode:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rbx + linnea_h3_walk.fs]
    mov rsi, [rbx + linnea_h3_walk.fs_have]
    mov rdx, r12
    call linnea_qpack_decode
    test rax, rax
    jns .wd_ok
    ; the same mapping the inline decode makes: a semantic breach fails the
    ; stream, a bound fails the request, anything else fails the connection
    cmp qword [r12 + linnea_h2_req.malformed], 0
    jne .wd_err
    cmp rax, -LINNEA_HPACK_ERR_LIMIT
    jne .wd_qpack
    mov rax, -LINNEA_H3_ERR_TOOLARGE
    jmp .wd_ret
.wd_ok:
    mov rdi, r12
    call linnea_hpack_req_check
    test rax, rax
    js .wd_err
    xor eax, eax
    jmp .wd_ret
.wd_qpack:
    mov rax, -LINNEA_H3_ERR_QPACK
    jmp .wd_ret
.wd_err:
    mov rax, -LINNEA_H3_ERR
.wd_ret:
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_read_headers(rdi=stream, rsi=len, rdx=req)
;   -> rax = 0 | -err, and on success r8 = request-body ptr, r9 = body length
;   (0 if none). Each frame is varint(type) varint(length) payload. Decode the
;   first HEADERS frame's field section into req via QPACK, and capture the first
;   DATA frames after it as the body. r8 points into the stream: the first DATA
;   payload stays where it is and any later one is moved down onto the end of it,
;   so the body reads as one run without a copy elsewhere. DATA before HEADERS is
;   a connection error; unknown frame types are skipped. The QUIC layer hands us
;   a stream that is already whole (it only serves on the FIN), so these bytes
;   hold the entire request.
; Body ptr/len live in stack locals [rsp]/[rsp+8] during the walk (all callee-
; saved registers are already in use) and move to r8/r9 at return.
; linnea_h3_read_headers(rdi=stream, rsi=len, rdx=req)
;   -> rax = 0 | -err, and on success r8 = request-body ptr, r9 = body length
;   (0 if none).
; A request whose stream arrived whole, which is every request until the walk
; above is driven incrementally: reset the walk and feed it the lot WITH the
; FIN, so it must reach a verdict rather than ask for more.
linnea_h3_read_headers:
    push rbx
    push r12
    push r13                         ; three pushes: the calls stay 16-aligned
    mov rbx, rdi                     ; stream
    mov r12, rsi                     ; length
    mov r13, rdx                     ; req
    lea rdi, [h3_walk]
    xor eax, eax
    mov ecx, LINNEA_H3_WALK_RESET
    rep stosb
    lea rdi, [h3_walk]
    mov rsi, rbx
    mov rdx, r12
    mov rcx, r13
    mov r8d, 1
    call linnea_h3_walk_feed
    cmp rax, 1
    je .rh_ok
    test rax, rax
    js .rh_ret                       ; the walk's own error code
    mov rax, -LINNEA_H3_ERR_TRUNCATED   ; unreachable: it was given the FIN
    jmp .rh_ret
.rh_ok:
    xor eax, eax
.rh_ret:
    mov r8, [h3_walk + linnea_h3_walk.body_ptr]
    mov r9, [h3_walk + linnea_h3_walk.body_len]
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h3_build_headers(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=content_length) -> rax = length written.
; Emits only the HEADERS frame (0x01) wrapping the QPACK-encoded response
; fields — :status, content-type, content-length (both omitted for a 304),
; plus whatever linnea_qpack_encode_response adds (validators when armed,
; then date and server). A HEAD response is exactly this — no DATA frame
; follows — and it is the first half of a full response head.
linnea_h3_build_headers:
    push rbx
    push r14
    push r15
    push rbp
    ; The access line: every HTTP/3 response of any shape passes through here,
    ; and the server parked the who-and-what (peer, host, method, target) in
    ; the log's parameter block before serving. Only the outcome is added. A
    ; zero peer means no context was set (a bare test driver): log nothing.
    cmp qword [linnea_log_acc_peer], 0
    je .no_acc
    mov eax, esi
    mov [linnea_log_acc_status], rax
    mov [linnea_log_acc_bytes], r8
    lea rax, [proto_h3]                 ; this builder is HTTP/3-only
    mov [linnea_log_acc_proto], rax
    mov qword [linnea_log_acc_proto_len], proto_h3_len
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    call linnea_log_access
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
.no_acc:
    mov rbx, rdi                     ; out start
    mov r14, rdi                     ; out cursor
    mov r15d, esi                    ; status
    ; content-length text = decimal(content_length)
    push rdx
    push rcx
    lea rdi, [clen_buf]
    mov rax, r8
    call u64_to_dec                  ; rax = digit count
    pop rcx
    pop rdx
    mov rbp, rax                     ; content-length text length
    ; QPACK-encode the response fields into fs_buf
    lea rdi, [fs_buf]
    mov esi, r15d
    ; rdx = ct_ptr, rcx = ct_len already
    lea r8, [clen_buf]
    mov r9, rbp
    ; A 304 restates only the validators, not the representation's type or
    ; length — and a 412 is the same shape: bodiless, and about the condition
    ; rather than the resource. Both call sites leave rdx/rcx unset because of
    ; this, so a status that reaches .enc without them carries a garbage
    ; content-type pointer into the encoder. That killed the worker the first
    ; time 412 was added here, right after the access line had already logged
    ; the response as served.
    cmp r15d, 304
    je .no_repr
    cmp r15d, 412
    jne .enc
.no_repr:
    xor edx, edx
    xor r8d, r8d
.enc:
    lea r10, [fs_buf + LINNEA_H3_FS_BUF]
    call linnea_qpack_encode_response ; rax = field-section length, or -1
    test rax, rax
    jns .encoded
    ; It would not fit. Nothing here can be shortened selectively — the long
    ; fields are the vhost's policy and a redirect's target — so drop every
    ; optional one and state the failure instead. A bare 500 is a few dozen
    ; bytes and cannot fail this second time.
    ;
    ; A backstop, not a path with a budget: fs_buf is sized for the largest
    ; section any documented config can produce, so reaching here means that
    ; sizing is wrong rather than that some request was too big. The access line
    ; has already been written above, and it names the status this response was
    ; going to have — one more reason this must stay unreachable.
    call linnea_qpack_reset_response
    lea rdi, [fs_buf]
    mov esi, 500
    xor edx, edx                     ; no content-type
    xor ecx, ecx
    xor r8d, r8d                     ; and no content-length
    xor r9d, r9d
    lea r10, [fs_buf + LINNEA_H3_FS_BUF]
    call linnea_qpack_encode_response
.encoded:
    mov rbp, rax                     ; field-section length
    ; The peer's SETTINGS_MAX_FIELD_SECTION_SIZE (Finding 8): a response whose field
    ; section exceeds it may be rejected by the client, so flag it and let the serve
    ; path reset the stream instead of sending. The encoded length is compared — a
    ; lower bound on the uncompressed size RFC 9114 4.2.2 governs (QPACK only ever
    ; shrinks) — so this never falsely rejects, and it catches every response that
    ; definitely exceeds the limit. 0 = no limit advertised.
    mov rax, [linnea_qpack_max_fss]
    test rax, rax
    jz .no_fss_limit
    cmp rbp, rax
    jbe .no_fss_limit
    mov qword [linnea_qpack_fss_over], 1
.no_fss_limit:
    ; HEADERS frame: type 0x01, length varint, field section
    mov byte [r14], LINNEA_H3_FRAME_HEADERS
    inc r14
    mov rdi, r14
    mov rsi, rbp
    call linnea_quic_varint_encode
    add r14, rax
    lea rsi, [fs_buf]
    mov rdi, r14
    mov rcx, rbp
    rep movsb
    mov r14, rdi
    mov rax, r14
    sub rax, rbx                     ; headers length
    pop rbp
    pop r15
    pop r14
    pop rbx
    ret

; linnea_h3_build_response_head(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=body_len) -> rax = length written.
; The HEADERS frame (content-length = body_len) followed by the DATA frame's
; type and length varint — everything of the response that precedes the body
; bytes. A caller that inlines the body appends it right after; a chunked
; response keeps this head per connection and streams the body from its file
; mapping, so the head and body never share a buffer.
linnea_h3_build_response_head:
    push rbx
    push r13
    push r14
    mov rbx, rdi                     ; out start
    mov r13, r8                      ; body len
    call linnea_h3_build_headers     ; rax = headers length (args unchanged)
    lea r14, [rbx + rax]             ; cursor after the HEADERS frame
    mov byte [r14], LINNEA_H3_FRAME_DATA
    inc r14
    mov rdi, r14
    mov rsi, r13
    call linnea_quic_varint_encode
    add r14, rax
    mov rax, r14
    sub rax, rbx                     ; total head length
    pop r14
    pop r13
    pop rbx
    ret

; linnea_h3_build_421(rdi=out) -> rax = length written.
; The whole response for a request whose authority this connection is not
; authoritative for (its certificate covers a different site). A client that
; coalesced onto this connection retries on a fresh one, where the right
; certificate is presented; nothing else recovers as cleanly.
linnea_h3_build_421:
    mov esi, 421
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_421]
    mov r9d, body_421_len
    jmp linnea_h3_build_canned

; linnea_h3_build_413(rdi=out) -> rax = length written.
; The whole response for a request body larger than max_body. The request never
; finished parsing, so there is no path or vhost to serve from — only the status
; that says which side the limit is on, which beats resetting the stream and
; leaving the client to guess whether to retry.
linnea_h3_build_413:
    mov esi, 413
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_413]
    mov r9d, body_413_len
    jmp linnea_h3_build_canned

; linnea_h3_build_500(rdi=out) -> rax = length written.
; The whole response for a request we could not carry out through no fault of
; the client's: the capture file could not be opened or written, or the payload
; was fragmented past what the range list will track. The request never finished
; parsing, so there is no path or vhost to serve from — only a status, and the
; status has to say OURS. Answering 413 here (which it did) tells the client to
; send less, which cannot help and is not true.
linnea_h3_build_500:
    mov esi, 500
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_500]
    mov r9d, body_500_len
    jmp linnea_h3_build_canned

; linnea_h3_build_429(rdi=out) -> rax = length written.
; The whole response for a request refused by rate_limit. Like the others here
; it is built OUTSIDE linnea_h3_serve — the request is turned away before it is
; routed — so it goes through linnea_h3_build_canned, which clears the
; encoder's per-response fields. A 429 wearing the previous request's
; content-encoding would be the same defect as every other canned error here.
linnea_h3_build_429:
    mov esi, 429
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_429]
    mov r9d, body_429_len
    jmp linnea_h3_build_canned

; linnea_h3_build_431(rdi=out) -> rax = length written.
; The whole response for a request whose header section we will not hold: the
; request never parsed, so there is no path, method or vhost to serve from —
; only a status the client can act on, which beats resetting the stream and
; leaving it to guess why.
linnea_h3_build_431:
    mov esi, 431
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_431]
    mov r9d, body_431_len
    jmp linnea_h3_build_canned

; linnea_h3_build_canned(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=body_ptr, r9=body_len) -> rax = total length written.
; linnea_h3_build_response for a response built OUTSIDE linnea_h3_serve: the
; canned errors the reader answers before a request has routed (413/421/431/
; 500), and the proxy's 502/503/504, which is built on an io_uring completion
; long after the serve that parked its request returned. Only linnea_h3_serve
; clears the encoder's per-response fields, so a response built out here
; encodes with whatever the worker's most recent OTHER request left behind —
; measured, not supposed: one static hit was enough to make the next 413 go
; out with that file's content-encoding, etag, last-modified and
; Cache-Control. A client honouring the encoding could not decode the error at
; all, and the Cache-Control made a transient failure storable for a week.
;
; It is the same hazard the proxy's .fl_build already works around for the
; shared log block; that fix restored the access line and left the field
; section, so this is the rest of it. Reset first, then build.
linnea_h3_build_canned:
    call linnea_qpack_reset_response ; clobbers no register: the arguments
                                     ; above stay live across it
    ; fall through

; linnea_h3_build_response(rdi=out, esi=status, rdx=ct_ptr, rcx=ct_len,
;   r8=body_ptr, r9=body_len) -> rax = total length written.
; The head (HEADERS frame + DATA frame header) followed by the body bytes.
; The out buffer must hold the field section + body + framing.
; Reached by fall-through from linnea_h3_build_canned above — keep them
; adjacent, and do not put anything between them.
linnea_h3_build_response:
    push r12
    push r13
    push r14
    mov r12, r8                      ; body ptr
    mov r13, r9                      ; body len
    mov r14, rdi                     ; out
    mov r8, r9                       ; the head takes the body's length
    call linnea_h3_build_response_head
    lea rdi, [r14 + rax]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    add rax, r13                     ; head + body
    pop r14
    pop r13
    pop r12
    ret

; linnea_h3_serve(rdi=req, rsi=root ptr, rdx=root len, rcx=out, r8=body ptr,
;   r9=body len) -> rax = response length written to out, and r8/r9 = the
; response file's mapping base/size when the body was too large to inline
; (r9 = 0 otherwise: out holds the complete response, nothing stays mapped).
; Resolves the request's :path to a location on the vhost (linnea_h3_srv) and,
; for a static one, serves the file under that location's root with its MIME
; type, or a 404 / 400 / 405. The path normalizer, opener and MIME table are the
; shared ones, so h3 and h2 resolve and reject paths identically. A proxy
; location instead forwards the request upstream and returns -1: the stream is
; parked, and its answer arrives on a later io_uring completion.
; A body over LINNEA_H3_INLINE_MAX is not copied: out receives only the head
; (HEADERS frame + DATA frame header), the file stays mapped, and the caller
; streams the body as chunks — unless head + body exceeds the caller's
; flow-control allowance (linnea_h3_tx_cap), which is refused with a 503: the
; client's window cannot take the response, and overrunning it would kill the
; connection instead of the request.
linnea_h3_serve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 88                      ; [0/8] mime ptr/len, [16/24] range
    ;                                ; offset/length, [32] ranged flag,
    ;                                ; [40/48] the request body a proxy forwards,
    ;                                ; [56/64] the root the caller passed,
    ;                                ; [72] the If-Match/If-None-Match span cursor
    mov rbx, rdi                     ; req
    mov r12, rcx                     ; out
    mov [rsp + 40], r8               ; the body the reader joined for us (0/0
    mov [rsp + 48], r9               ; when the request carried none)
    mov [rsp + 56], rsi              ; the caller's root, for a request that
    mov [rsp + 64], rdx              ; routes to no location of its own
    ; more If-Match/If-None-Match lines than can be combined: answered before
    ; anything is routed or opened, so a proxy location cannot forward a list
    ; with a member missing either (audit-report-31)
    cmp qword [rbx + linnea_h2_req.list_over], 0
    jne .list_over_431
    ; no validators or content-range until a file is opened and the request's
    ; conditionals and range are evaluated
    mov qword [linnea_qpack_send_validators], 0
    mov qword [linnea_qpack_crange_ptr], 0
    mov qword [linnea_qpack_location_ptr], 0
    mov qword [linnea_qpack_cenc], 0
    ; The path is normalized at a fixed offset, leaving room in front of it for
    ; a root that is not known yet: which root depends on which location the
    ; path matches, so the join happens after the routing, not before it. Same
    ; shape as h1 and h2, which have always reserved LINNEA_*_PATH_ROOT here.
    mov rsi, [rbx + linnea_h2_req.path_ptr]
    test rsi, rsi
    jz .bad                          ; no :path in the request
    mov rdx, [rbx + linnea_h2_req.path_len]
    lea rdi, [h3_path_buf + LINNEA_H3_PATH_ROOT]
    call linnea_static_normalize     ; rax = end ptr (0 = reject), r9 = dir flag
    test rax, rax
    jz .bad
    mov r14, rax                     ; end of the resolved path
    mov r13, r9                      ; the directory flag, across the routing
    ; --- 0-RTT safety: early data carries only safe methods -------------
    ; A request drawn from accepted 0-RTT (s_is_early) that is not GET or HEAD is
    ; not replay-safe: it could be forwarded to a proxy backend as a side effect.
    ; 0-RTT is replayable by design (RFC 9001 9.2), and the per-worker strike
    ; register is best-effort across workers -- so the safety cannot rest on it.
    ; Answer 425 Too Early (RFC 8470) and let the client retry the request under
    ; 1-RTT keys. This gate is what MAKES "only safe methods over 0-RTT" true,
    ; rather than assumed; it sits before routing so a proxy or redirect location
    ; is covered too, not just static.
    cmp qword [s_is_early], 0
    je .early_ok
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    mov rcx, [rbx + linnea_h2_req.method_len]
    cmp rcx, 3
    jne .early_head
    cmp word [rdi], 'GE'
    jne .resp_425
    cmp byte [rdi + 2], 'T'
    je .early_ok
    jmp .resp_425
.early_head:
    cmp rcx, 4
    jne .resp_425
    cmp dword [rdi], 0x44414548      ; "HEAD", little-endian
    jne .resp_425
.early_ok:
    ; --- routing ------------------------------------------------------
    ; h3 used to be handed a document root and nothing else, so every path
    ; resolved under one root and a vhost with any other kind of location was
    ; kept off h3 entirely. It now matches locations by the same longest-prefix
    ; rule as the other protocols, and the matched kind decides what happens.
    mov rdi, [linnea_h3_srv]
    test rdi, rdi
    jz .unrouted                     ; the root the caller passed
    lea rsi, [h3_path_buf + LINNEA_H3_PATH_ROOT]
    mov rdx, r14
    sub rdx, rsi
    call linnea_config_match_location
    test rax, rax
    jz .notfound                     ; no location claims this path
    ; TRACE reflects the received request to whoever sent it; through a proxy
    ; that hands the caller its own credentials. Refused before the kinds
    ; diverge, so the answer does not depend on which location matched.
    push rax
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    mov rsi, [rbx + linnea_h2_req.method_len]
    lea rdx, [method_trace_h3]
    mov ecx, 5
    call linnea_string_equal
    mov r11d, eax              ; the verdict; the pop below wants rax back
    pop rax
    test r11d, r11d
    jnz .resp_405
    ; RFC 9110 7.6.2: an OPTIONS carrying Max-Forwards: 0 has reached its final
    ; recipient and MUST NOT be forwarded.
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    jne .h3_mf_done
    cmp qword [rbx + linnea_h2_req.mf_seen], 0
    je .h3_mf_done
    cmp qword [rbx + linnea_h2_req.mf_val], 0
    jne .h3_mf_done
    push rax
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    mov rsi, [rbx + linnea_h2_req.method_len]
    lea rdx, [method_options_h3]
    mov ecx, 7
    call linnea_string_equal
    mov r11d, eax
    pop rax
    test r11d, r11d
    jnz .resp_options_final
.h3_mf_done:
    ; every answer below is ours to make -- a file, a redirect, an error -- so
    ; an expectation we cannot meet is refused, not ignored. A proxy location
    ; forwards it instead, the backend being the one asked (audit-report-33).
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    je .h3_expect_ok
    cmp qword [rbx + linnea_h2_req.expect_bad], 0
    jne .resp_417
.h3_expect_ok:
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    je .redirect
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jne .not_static
    ; Cache-Control belongs to the matched location, not to whichever location
    ; happened to be registered with the vhost.
    mov r10, [rax + linnea_config_location.cache_control_len]
    mov [linnea_qpack_ccontrol_len], r10
    lea r11, [rax + linnea_config_location.cache_control]
    test r10, r10
    jnz .cc_set
    xor r11d, r11d
.cc_set:
    mov [linnea_qpack_ccontrol_ptr], r11
    lea rsi, [rax + linnea_config_location.root]
    mov rdx, [rax + linnea_config_location.root_len]
    jmp .method_gate
.unrouted:
    ; No config server to route on (a driver that hands the serve a bare root).
    ; The root is the caller's, saved at entry: the normalize above reused rsi
    ; and rdx for the path, so they no longer hold it.
    mov rsi, [rsp + 56]
    mov rdx, [rsp + 64]
.method_gate:
    ; A STATIC location answers GET and HEAD and nothing else, exactly as the h1
    ; and h2 static paths do — a PROPFIND, PUT or DELETE against a file used to
    ; fall through here and be served as if it were a GET. The method is matched
    ; exactly, not case-insensitively: RFC 9110 9.1 makes it case-sensitive.
    ;
    ; The gate belongs HERE, after the routing, not before it: a proxy location
    ; forwards whatever method it is given, and while it sat in front of the
    ; match a POST to a proxied path was answered 405 by us instead of reaching
    ; the backend at all. h1 and h2 both place it the same way.
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    cmp qword [rbx + linnea_h2_req.method_len], 3
    jne .method_head
    cmp word [rdi], 'GE'
    jne .resp_405
    cmp byte [rdi + 2], 'T'
    jne .resp_405
    jmp .join
.method_head:
    cmp qword [rbx + linnea_h2_req.method_len], 4
    jne .resp_405
    cmp dword [rdi], 0x44414548      ; "HEAD", little-endian
    jne .resp_405
.join:
    ; A static location serves a file: it has no use for request content, and
    ; content on GET or HEAD has no defined semantics anyway (RFC 9110 9.3.1).
    ; Serving the file regardless means silently discarding bytes the client
    ; announced -- the request-smuggling shape 9.3.1 names -- so refuse instead.
    ; [rsp+48] is the reassembled body length, whether it came inline or through
    ; a capture file, and h3 has the whole request here, which is why it is the
    ; one protocol that can decide this on the CONTENT rather than on the
    ; declaration. A declared length that disagreed with it never reaches this
    ; function: linnea_quic_server reconciles the two first.
    ;
    ; After the method gate, not before it: a POST to a static path is a method
    ; fault (405), and answering 400 for it would be reporting the wrong thing.
    cmp qword [rsp + 48], 0
    jne .bad
    ; the root goes immediately in front of the path, ending where it begins
    lea rdi, [h3_path_buf + LINNEA_H3_PATH_ROOT]
    sub rdi, rdx
    mov [h3_join], rdi
    mov rcx, rdx
    rep movsb                        ; rsi = root, rdi lands on the path
    mov r9, r13                      ; the directory flag again
    test r9, r9
    jz .noindex
    mov rdi, r14                     ; a directory: serve index.html from it
    cmp byte [rdi - 1], '/'          ; normalize consumed the trailing slash on
    je .append_index                 ; every directory but "/", so put it back
    mov byte [rdi], '/'
    inc rdi
.append_index:
    lea rsi, [idx_name]
    mov ecx, idx_name_len
    rep movsb
    mov r14, rdi
.noindex:
    ; open the file — negotiating a pre-compressed variant when the client's
    ; Accept-Encoding allows one (open_enc writes the suffix and NUL at r14;
    ; the MIME lookup below keeps using the name before it)
    mov rdi, [h3_join]
    mov rsi, r14
    lea rdx, [rbx + linnea_h2_req.ae_ptr]   ; one span per field line
    mov rcx, [rbx + linnea_h2_req.ae_n]
    call linnea_static_open_enc      ; rax = base (0 = missing), rdx = size,
    mov [linnea_qpack_cenc], r8      ; r8 = the coding served
    test rax, rax
    jz .notfound
    mov r15, rax                     ; mapped body base (1 = empty file)
    mov rbp, rdx                     ; body size
    ; validators for this file, then the request's conditionals: If-None-Match
    ; wins over If-Modified-Since, and an INM mismatch answers 200 whatever
    ; If-Modified-Since says (RFC 9110 13.2.2)
    mov rdi, [linnea_static_mtime]
    mov rsi, rbp
    call linnea_static_validators
    mov qword [linnea_qpack_send_validators], 1
    ; If-Match first, then If-Unmodified-Since when it is absent (13.2.2); a
    ; failure is 412 and beats an If-None-Match that would have said 304. Same
    ; evaluation as h1 (Q187) and h2, so the answer no longer depends on which
    ; protocol carried the request.
    ; ...and each line of either field is its own span, any of which may carry
    ; the matching tag: they are lists, and repeated lines are the comma-joined
    ; value (RFC 9110 5.3). Keeping one span let the LAST line decide here while
    ; the FIRST decided on h1 (audit-report-30).
    cmp qword [rbx + linnea_h2_req.ifm_n], 0
    je .chk_ius
    mov qword [rsp + 72], 0
.ifm_span:
    mov rax, [rsp + 72]
    cmp rax, [rbx + linnea_h2_req.ifm_n]
    jae .h3_412                      ; no line matched
    shl rax, 4
    lea rdx, [rbx + linnea_h2_req.ifm_ptr]
    mov rdi, [rdx + rax]
    mov rsi, [rdx + rax + 8]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    mov r8d, 1                       ; If-Match compares strongly (13.1.1)
    call linnea_http_etag_match
    inc qword [rsp + 72]
    test eax, eax
    jz .ifm_span
    jmp .chk_inm
.chk_ius:
    mov rdi, [rbx + linnea_h2_req.ius_ptr]
    test rdi, rdi
    jz .chk_inm
    mov rsi, [rbx + linnea_h2_req.ius_len]
    call linnea_time_parse_http_date
    cmp rax, -1
    je .chk_inm                      ; unparseable: ignored, as elsewhere
    cmp [linnea_static_mtime], rax
    ja .h3_412
.chk_inm:
    cmp qword [rbx + linnea_h2_req.inm_n], 0
    je .chk_ims
    mov qword [rsp + 72], 0
.inm_span:
    mov rax, [rsp + 72]
    cmp rax, [rbx + linnea_h2_req.inm_n]
    jae .cond_done                   ; no line matched, which beats If-Modified-Since
    shl rax, 4
    lea rdx, [rbx + linnea_h2_req.inm_ptr]
    mov rdi, [rdx + rax]
    mov rsi, [rdx + rax + 8]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    call linnea_http_inm_match
    inc qword [rsp + 72]
    test eax, eax
    jz .inm_span
    jmp .h3_304
.chk_ims:
    mov rdi, [rbx + linnea_h2_req.ims_ptr]
    test rdi, rdi
    jz .cond_done
    mov rsi, [rbx + linnea_h2_req.ims_len]
    call linnea_time_parse_http_date
    cmp rax, -1
    je .cond_done                    ; unparseable: the RFC says ignore it
    cmp [linnea_static_mtime], rax
    jbe .h3_304                      ; not modified since the client's copy
.cond_done:
    lea rdi, [h3_path_buf]
    mov rsi, r14
    sub rsi, rdi                     ; resolved path length
    call linnea_static_mime          ; rax = mime ptr, rdx = mime len
    mov [rsp], rax                   ; keep the MIME across the range work
    mov [rsp + 8], rdx
    mov qword [rsp + 16], 0          ; whole file until a range narrows it
    mov [rsp + 24], rbp
    mov qword [rsp + 32], 0          ; not a 206
    ; --- Range: a single bytes= range on a GET, evaluated after the
    ; conditionals as RFC 9110 orders and gated by If-Range (strong match
    ; only). Anything not understood serves the full 200, which is always
    ; safe; a valid but unsatisfiable range earns the 416.
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    cmp qword [rbx + linnea_h2_req.method_len], 4
    jne .range_chk
    cmp dword [rdi], 0x44414548      ; "HEAD": ranges apply to GET alone
    je .range_done
.range_chk:
    mov rdi, [rbx + linnea_h2_req.rng_ptr]
    test rdi, rdi
    jz .range_done
    mov rdi, [rbx + linnea_h2_req.ifr_ptr]
    test rdi, rdi
    jz .range_eval
    mov rsi, [rbx + linnea_h2_req.ifr_len]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    mov r8, [linnea_static_mtime]
    call linnea_http_ifrange_match
    test eax, eax
    jz .range_done                   ; stale validator: the whole file
.range_eval:
    mov rdi, [rbx + linnea_h2_req.rng_ptr]
    mov rsi, [rbx + linnea_h2_req.rng_len]
    mov rdx, rbp
    call linnea_http_range_parse     ; rax = offset, rdx = count | -1 | -2
    cmp rax, -1
    je .range_done
    cmp rax, -2
    je .h3_416
    mov [rsp + 16], rax
    mov [rsp + 24], rdx
    mov qword [rsp + 32], 1
    ; content-range value: "bytes first-last/size"
    lea rdi, [h3_crange_buf]
    mov dword [rdi], 'byte'
    mov word [rdi + 4], 's '
    add rdi, 6
    mov rax, [rsp + 16]              ; first
    call u64_to_dec
    mov byte [rdi], '-'
    inc rdi
    mov rax, [rsp + 16]
    add rax, [rsp + 24]
    dec rax                          ; last = first + count - 1
    call u64_to_dec
    mov byte [rdi], '/'
    inc rdi
    mov rax, rbp                     ; the representation's whole size
    call u64_to_dec
    lea rax, [h3_crange_buf]
    sub rdi, rax
    mov [linnea_qpack_crange_len], rdi
    mov [linnea_qpack_crange_ptr], rax
.range_done:
    ; a HEAD request: emit only the headers (content-length = the file size) and
    ; no body — whatever the size. A bodiless response is not flow-controlled.
    mov rdi, [rbx + linnea_h2_req.method_ptr]
    cmp qword [rbx + linnea_h2_req.method_len], 4
    jne .body_serve
    cmp dword [rdi], 0x44414548      ; "HEAD", little-endian
    jne .body_serve
    mov rdi, r12                     ; out
    mov esi, 200
    mov rdx, [rsp]                   ; mime ptr / len
    mov rcx, [rsp + 8]
    mov r8, rbp                      ; content-length = file size
    call linnea_h3_build_headers     ; rax = response length (headers only)
    cmp r15, 1
    jbe .sret                        ; empty-file sentinel: nothing was mapped
    push rax
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    pop rax
    jmp .sret
.body_serve:
    mov esi, 200                     ; 206 when a range narrowed the body
    cmp qword [rsp + 32], 0
    je .st_sel
    mov esi, 206
.st_sel:
    mov rdx, [rsp]                   ; mime ptr / len
    mov rcx, [rsp + 8]
    mov rax, [rsp + 24]              ; body length: the slice's
    cmp rax, LINNEA_H3_INLINE_MAX
    ja .large                        ; too big for one packet: stream it
    mov r8, r15
    add r8, [rsp + 16]               ; the slice, or the whole file
    mov r9, [rsp + 24]
    cmp r15, 1                       ; empty-file sentinel: found, nothing mapped
    jne .havebody
    xor r8d, r8d
    xor r9d, r9d
.havebody:
    mov rdi, r12
    call linnea_h3_build_response    ; rax = response length
    cmp r15, 1
    jbe .sret                        ; nothing was mapped
    push rax
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    pop rax
    jmp .sret
.large:
    ; may we start a chunked response? Only one is in flight at a time; a
    ; concurrent large request is refused (503). The body itself streams within
    ; the client's flow-control window, enforced by the pump, so its size is not
    ; checked here. (esi = status, rdx/rcx = MIME, kept live.)
    cmp qword [linnea_h3_tx_cap], 0
    je .refuse
    mov rdi, r12
    mov r8, [rsp + 24]               ; body length (for content-length + DATA len)
    call linnea_h3_build_response_head ; rax = head length written to out
    mov rcx, [rsp + 16]              ; where the body starts in the mapping,
    mov [linnea_h3_body_off], rcx    ; and how much of it the pump streams
    mov rcx, [rsp + 24]
    mov [linnea_h3_body_len], rcx
    mov r8, r15                      ; the mapping is the caller's to stream + unmap
    mov r9, rbp
    jmp .sret_large
.h3_416:
    ; the single range is valid but unsatisfiable: unmap the file and answer
    ; a bodiless 416 whose Content-Range names the actual length ("bytes
    ; */size") so the client can retry sensibly. It describes no
    ; representation, so the validators are dropped again.
    cmp r15, 1
    jbe .h3_416_nomap                ; empty-file sentinel: nothing was mapped
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h3_416_nomap:
    mov qword [linnea_qpack_send_validators], 0
    lea rdi, [h3_crange_buf]         ; content-range value: "bytes */size"
    mov dword [rdi], 'byte'
    mov dword [rdi + 4], 's */'
    add rdi, 8
    mov rax, rbp
    call u64_to_dec
    lea rax, [h3_crange_buf]
    sub rdi, rax
    mov [linnea_qpack_crange_len], rdi
    mov [linnea_qpack_crange_ptr], rax
    mov rdi, r12                     ; out
    mov esi, 416
    xor edx, edx                     ; no content-type
    xor r8d, r8d                     ; content-length: 0, and no DATA frame
    call linnea_h3_build_headers     ; rax = response length (headers only)
    jmp .sret

.h3_304:
    ; the client's copy is current: unmap the file and answer a bodiless 304
    ; carrying the validators it will compare next time. Like a HEAD response,
    ; a 304 is headers-only and so never flow-controlled.
    cmp r15, 1
    jbe .h3_304_nomap                ; empty-file sentinel: nothing was mapped
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h3_304_nomap:
    mov rdi, r12                     ; out
    mov esi, 304
    xor r8d, r8d                     ; no content-length (none is encoded)
    call linnea_h3_build_headers     ; rax = response length (headers only)
    jmp .sret

.h3_412:
    ; a precondition the client set is not met: unmap and answer a bodiless
    ; 412. The validators stay on (15.5.13) so a client that guessed wrong can
    ; see what the representation actually is.
    cmp r15, 1
    jbe .h3_412_nomap                ; empty-file sentinel: nothing was mapped
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h3_412_nomap:
    mov rdi, r12                     ; out
    mov esi, 412
    xor r8d, r8d                     ; no content-length
    call linnea_h3_build_headers     ; rax = response length (headers only)
    jmp .sret

.refuse:
    ; unmap the file and answer 503: refused, not broken — the client may retry
    ; (e.g. once the connection's open response stream finishes). The 503
    ; describes no file: drop the validators computed for the mapping.
    mov qword [linnea_qpack_send_validators], 0
    mov rdi, r15
    mov rsi, rbp
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov rdi, r12
    mov esi, 503
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_503]
    mov r9d, body_503_len
    call linnea_h3_build_response
    jmp .sret
.redirect:
    ; --- redirect location: 301 with Location = target ++ the raw request ---
    ; h3 could not do this at all until now: a vhost with a redirect location
    ; was kept off HTTP/3 entirely, so ONE such location silently cost the whole
    ; server its QUIC listener. QPACK has a static name for "location" (index
    ; 12) and always did; nothing was stopping it but the missing branch.
    mov r10, [rax + linnea_config_location.redirect_len]
    mov r11, [rbx + linnea_h2_req.path_len]
    lea rcx, [r10 + r11]
    cmp rcx, 4096                    ; the value must fit h3_loc_buf
    ja .redirect_too_long
    push rax
    push rbx
    lea rdi, [h3_loc_buf]
    lea rsi, [rax + linnea_config_location.redirect]
    mov rcx, r10
    rep movsb
    mov rsi, [rbx + linnea_h2_req.path_ptr]
    mov rcx, [rbx + linnea_h2_req.path_len]
    rep movsb
    pop rbx
    pop rax
    lea rcx, [h3_loc_buf]
    mov [linnea_qpack_location_ptr], rcx
    mov r10, [rax + linnea_config_location.redirect_len]
    add r10, [rbx + linnea_h2_req.path_len]
    mov [linnea_qpack_location_len], r10
    mov rdi, r12
    mov esi, 301
    xor edx, edx                     ; no content-type
    xor ecx, ecx
    xor r8d, r8d                     ; and no body: the Location is the answer
    xor r9d, r9d
    call linnea_h3_build_response
    jmp .sret
.redirect_too_long:
    ; the configured target plus this request's own target does not fit; 414 is
    ; what h1 answers for the same case
    mov rdi, r12
    mov esi, 414
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    xor r8d, r8d
    xor r9d, r9d
    call linnea_h3_build_response
    jmp .sret

.not_static:
    ; A proxy location. The request goes to the location's upstream on a leg of
    ; its own and this stream is PARKED: the answer arrives on an io_uring
    ; completion, long after this datagram has been dealt with. A redirect
    ; location is handled above and never reaches here.
    ; Is there a response-stream slot to park this request in? The caller
    ; already scanned for one (linnea_h3_tx_cap). Asking now rather than at the
    ; park matters: the upstream is contacted before the stream is parked, so
    ; without this the backend would serve a request we then had nowhere to put
    ; the answer to. 503 says the same thing a large static response says when
    ; every slot is busy — refused, try again.
    cmp qword [linnea_h3_tx_cap], 0
    je .proxy_busy
    mov r10, [linnea_h3_proxy_hook]
    test r10, r10
    jz .no_proxy                     ; a build without the upstream machinery
    mov rdi, [rsp + 40]              ; the request body, joined by the reader
    mov [linnea_h3_proxy_body_ptr], rdi
    mov rdi, [rsp + 48]
    mov [linnea_h3_proxy_body_len], rdi
    mov rdi, rbx                     ; req
    mov rsi, rax                     ; the matched location
    mov rdx, [linnea_h3_srv]         ; its vhost, for the response's own headers
    mov rcx, [linnea_h3_owner_idx]
    mov r8, [linnea_h3_owner_gen]
    mov r9, [linnea_h3_owner_sid]
    call r10                         ; rax = 0 parked, else a status to answer
    test eax, eax
    jnz .proxy_status
    mov rax, -1                      ; nothing to send on this stream yet
    jmp .sret                        ; (and no mapping: .sret zeroes r8/r9)
.proxy_busy:
    mov eax, 503
.proxy_status:
    ; The upstream was never reached — no socket, no slot, a head we would not
    ; forward — so the client gets a status of ours instead. These describe no
    ; representation, so they carry no validators.
    mov qword [linnea_qpack_send_validators], 0
    mov r13d, eax                    ; the status, across the body selection
    lea r8, [body_502]
    mov r9d, body_502_len
    cmp r13d, 503
    jne .ps_431
    lea r8, [body_503]
    mov r9d, body_503_len
    jmp .ps_emit
.ps_431:
    cmp r13d, 431
    jne .ps_emit
    lea r8, [body_431]
    mov r9d, body_431_len
.ps_emit:
    mov rdi, r12
    mov esi, r13d
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    call linnea_h3_build_response
    jmp .sret
.no_proxy:
    ; The route is ours and the request is well-formed; this build simply has
    ; no way to reach an upstream. 502 is what h3 answered for every proxy
    ; location before it could proxy at all.
    mov rdi, r12
    mov esi, 502
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_502]
    mov r9d, body_502_len
    call linnea_h3_build_response
    jmp .sret
.notfound:
    mov rdi, r12
    mov esi, 404
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_404]
    mov r9d, body_404_len
    call linnea_h3_build_response
    jmp .sret
.resp_405:
    mov rdi, r12
    mov esi, 405
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_405]
    mov r9d, body_405_len
    call linnea_h3_build_response
    jmp .sret
.resp_options_final:
    ; the final recipient of an OPTIONS describes ITSELF (RFC 9110 9.3.7)
    mov rdi, r12
    mov esi, 200
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_options_h3]
    mov r9d, body_options_h3_len
    call linnea_h3_build_response
    jmp .sret
.resp_417:
    mov rdi, r12
    mov esi, 417
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_417]
    mov r9d, body_417_len
    call linnea_h3_build_response
    jmp .sret
.resp_425:
    mov rdi, r12
    mov esi, 425
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_425]
    mov r9d, body_425_len
    call linnea_h3_build_response
    jmp .sret
.list_over_431:
    mov rdi, r12
    call linnea_h3_build_431
    jmp .sret
.bad:
    mov rdi, r12
    mov esi, 400
    lea rdx, [txt_plain]
    mov ecx, txt_plain_len
    lea r8, [body_400]
    mov r9d, body_400_len
    call linnea_h3_build_response
.sret:
    xor r8d, r8d                     ; complete response in out, nothing mapped
    xor r9d, r9d
.sret_large:
    add rsp, 88
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; u64_to_dec(rdi=out, rax=value) -> rax = number of digits written (no NUL).
u64_to_dec:
    sub rsp, 24
    lea r8, [rsp + 24]               ; one past the temp end
    mov r9, r8                       ; write digits backwards
    mov r10, 10
    test rax, rax
    jnz .d1
    dec r9
    mov byte [r9], '0'
    jmp .d2
.d1:
    dec r9
    xor edx, edx
    div r10
    add dl, '0'
    mov [r9], dl
    test rax, rax
    jnz .d1
.d2:
    mov rcx, r8
    sub rcx, r9                      ; digit count
    mov rax, rcx
    mov rsi, r9
    rep movsb                        ; copy to out (rdi)
    add rsp, 24
    ret
