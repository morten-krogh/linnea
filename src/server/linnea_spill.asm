; linnea_spill.asm — capture a request body on disk before it is forwarded.
;
; A proxied upload larger than in_buf used to be relayed upstream as it
; arrived, which meant a client that died mid-upload left the backend holding a
; truncated request it could not tell from a complete one — and may already
; have acted on. So the body is captured in full first and only then forwarded,
; the way nginx's proxy_request_buffering does it.
;
; The capture file is opened O_TMPFILE: it has no name, so no other process can
; see it, two connections cannot collide over it, and it is reclaimed by the
; kernel when the fd closes — including if we are killed mid-upload. There is
; nothing to clean up and no directory to litter.
;
; Once the body is complete the file is mapped and handed to the connection's
; existing file_base/file_size pair, so it is sent by the same code that queues
; a static file behind a response head, and unmapped by the same teardown.
;
; The cap matters as much as the capture: without one a single client could
; fill the disk, so a body past max_body is refused (413) rather than spilled.

default rel

%include "linnea_syscall.inc"
%include "linnea_connection.inc"
%include "linnea_uring.inc"        ; errno names
%include "linnea_config.inc"

extern linnea_config_instance

global linnea_spill_open
global linnea_spill_open_fd
global linnea_spill_write
global linnea_spill_chunked
global linnea_spill_finish
global linnea_spill_release
global linnea_spill_reset

section .rodata

; The directory only supplies the filesystem — O_TMPFILE creates no entry in
; it. It comes from the config (spill_dir) rather than being fixed here: the
; old literal was "/tmp", which under PrivateTmp is always tmpfs, so every
; captured upload was held in RAM up to max_body with no writeback and nothing
; the kernel could reclaim.

extern linnea_string_is_tchar
extern linnea_chunk_ext_step

section .text

; linnea_spill_open_fd() -> rax = an open capture fd, or -1.
; The one place that knows where captures live and how they are opened. HTTP/2
; captures per STREAM rather than per connection (several uploads may share a
; connection), so it needs the file without the connection bookkeeping — and
; a second copy of this would be a second place for spill_dir to be wrong,
; which is how the directory came to be the literal "/tmp" once already.
linnea_spill_open_fd:
    lea rdi, [linnea_config_instance]
    lea rdi, [rdi + linnea_config.spill_dir]
    mov esi, LINNEA_O_TMPFILE | LINNEA_O_RDWR | LINNEA_O_CLOEXEC
    mov edx, LINNEA_MODE_0600
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jb .ok
    mov eax, -1
.ok:
    ret

; linnea_spill_open(rdi=connection*) -> rax = 0 ok, -1 failed
; Idempotent: a body arriving in several chunks calls this once per chunk
; rather than tracking whose turn it is to create the file.
linnea_spill_open:
    cmp dword [rdi + linnea_connection.spill_fd], -1
    jne .already
    push rdi
    call linnea_spill_open_fd
    pop rdi
    test eax, eax
    js .fail
    mov [rdi + linnea_connection.spill_fd], eax
    mov qword [rdi + linnea_connection.spill_len], 0
.already:
    xor eax, eax
    ret
.fail:
    mov eax, -1
    ret

; linnea_spill_write(rdi=connection*, rsi=buf, rdx=len) -> rax = 0 ok, -1 failed
; A regular file's write returns short only on a full filesystem or a signal,
; so the loop is for correctness rather than for the common case.
linnea_spill_write:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    test r13, r13
    jz .done
    mov rdi, rbx                   ; the args are in rbx/r12/r13 now
    call linnea_spill_open
    test eax, eax
    js .fail
.loop:
    mov edi, [rbx + linnea_connection.spill_fd]
    mov rsi, r12
    mov rdx, r13
    mov eax, LINNEA_SYS_WRITE
    syscall
    cmp rax, -4095
    jae .retry_or_fail
    test rax, rax
    jz .fail                       ; no progress: treat as a full filesystem
    add [rbx + linnea_connection.spill_len], rax
    add r12, rax
    sub r13, rax
    jnz .loop
.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.retry_or_fail:
    cmp rax, -LINNEA_EINTR
    je .loop
    cmp rax, -LINNEA_EAGAIN
    je .loop
.fail:
    mov eax, -1
    pop r13
    pop r12
    pop rbx
    ret

; linnea_spill_chunked(rdi=connection*, rsi=buf, rdx=len, rcx=state, r8d=mode)
;   -> rax = 0 need more, 1 body complete, -1 malformed framing, -2 past max_body,
;      -3 body complete but the request pipelined behind it will not fit the stash
;
; rcx is a struc linnea_chunk the caller owns; the connection carries two, one
; for the request capture and one for the HTTP/1 response relay, because a
; chunked upload and a chunked response can be in flight on the same connection.
; r8d is LINNEA_CHUNK_CAPTURE, _VALIDATE or _DECHUNK. Validate mode judges and
; nothing else: no spill file, no max_body (that bounds a request, not a relayed
; response), and no pipelined-suffix stash. It exists so the HTTP/1 relay can
; apply THIS grammar to the bytes it is about to forward instead of a second
; transcription of it -- one decoder, two directions (audit-report-24).
;
; Dechunk mode is validate plus one thing: each chunk's DATA is moved down over
; the framing that preceded it, in the caller's own buffer, and rdx comes back
; holding how many decoded bytes now sit at buf. The destination is always at or
; behind the source -- framing only ever shrinks a message -- so the copy is a
; forward one and never overruns bytes it has not read yet. The HTTP/1 relay
; uses it to strip a transfer coding an HTTP/1.0 client must not be sent
; (RFC 9112 7.1, audit-report-130); the message is close-delimited either way,
; so nothing else about the relay changes.
;
; On completion any bytes left in buf after the terminal chunk are the NEXT
; request, pipelined in the same recv. They are copied to in_buf[head_len] (free
; during a chunked capture: head_len is the pure head) and their length recorded
; in .pend_len, so keep-alive serves them instead of dropping them. -3 is that
; suffix being too large for the room after the head — a pathological >8 KiB head
; pipelined behind a streamed body; the caller closes rather than lose it silently.
;
; Decodes chunked framing as it arrives and captures only the decoded bytes, so
; what reaches the backend is an ordinary counted request — the same shape a
; chunked body small enough to buffer has always been given. The client's
; framing is never forwarded, which is what keeps a proxy from becoming a
; request-smuggling relay: nothing goes upstream that we did not decode
; ourselves and re-describe with a length we counted.
;
; The rules are chunked_decode's, deliberately: at least one hex digit, a size
; no body could have refused before it can overflow, chunk-ext ignored to the
; CR, a bare LF never a line ending, CRLF required after the size line and
; after every chunk's data, a zero-size chunk ending the body, and trailers
; dropped. Where the two differ is only that this one resumes: chunked_decode
; sees the whole body at once, this one sees it in pieces.
linnea_spill_chunked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rdi
    mov r12, rsi                   ; read cursor
    lea r13, [rsi + rdx]           ; end of what arrived
    mov r15, rcx                   ; the decode state, struc linnea_chunk
    mov ebp, r8d                   ; LINNEA_CHUNK_CAPTURE, _VALIDATE or _DECHUNK
    sub rsp, 16
    mov [rsp], rsi                 ; dechunk's write cursor, starting at buf...
    mov [rsp + 8], rsi             ; ...and where it started, for the count
    cmp ebp, LINNEA_CHUNK_CAPTURE
    jne .step                      ; judging only: no sink, and no cap either
    ; Encoded bytes are capped as well as decoded ones. A client can send
    ; empty chunks and trailer lines forever without the decoded length ever
    ; growing, so a cap on the decoded body alone would never fire.
    ; Subtraction-before-addition (Finding 2): compare the incoming encoded run
    ; (rdx) against the headroom before adding it to chunk_raw, so a length near
    ; 2^64 cannot wrap the counter past a max_body of 2^64-1. chunk_raw <= max_body
    ; holds (rejected before it exceeds), so the subtraction does not underflow.
    ;
    ; max_body bounds a REQUEST, so it is applied in capture mode alone: a
    ; relayed response is not a body we are holding, and capping it here would
    ; have turned every download past max_body into a dropped connection.
    lea rax, [linnea_config_instance]
    mov rax, [rax + linnea_config.max_body]
    sub rax, [r15 + linnea_chunk.raw]   ; headroom = max_body - current
    cmp rdx, rax                                   ; incoming encoded run > headroom?
    ja .too_large
    add [r15 + linnea_chunk.raw], rdx   ; now safe from wrap
.step:
    cmp r12, r13
    jae .need_more
    mov r14, [r15 + linnea_chunk.state]
    cmp r14, LINNEA_CHUNK_SIZE
    je .s_size
    cmp r14, LINNEA_CHUNK_EXT
    je .s_ext
    cmp r14, LINNEA_CHUNK_SIZE_LF
    je .s_size_lf
    cmp r14, LINNEA_CHUNK_DATA
    je .s_data
    cmp r14, LINNEA_CHUNK_DATA_CR
    je .s_data_cr
    cmp r14, LINNEA_CHUNK_DATA_LF
    je .s_data_lf
    cmp r14, LINNEA_CHUNK_TRAIL
    je .s_trail
    cmp r14, LINNEA_CHUNK_TRAIL_LINE
    je .s_trail_line
    cmp r14, LINNEA_CHUNK_TRAIL_VAL
    je .s_trail_val
    cmp r14, LINNEA_CHUNK_TRAIL_LF
    je .s_trail_lf
    cmp r14, LINNEA_CHUNK_END_LF
    je .s_end_lf
    jmp .complete_nostash          ; DONE: a re-entry after completion. The cursor
                                   ; has not advanced, so there is no fresh suffix
                                   ; to stash — just report complete again.

.s_size:
    movzx eax, byte [r12]
    cmp al, '0'
    jb .size_end
    cmp al, '9'
    jbe .size_digit
    or al, 0x20                    ; fold A-F to a-f
    cmp al, 'a'
    jb .size_end
    cmp al, 'f'
    ja .size_end
    sub al, 'a' - 10
    jmp .size_accum
.size_digit:
    sub al, '0'
.size_accum:
    mov rcx, [r15 + linnea_chunk.rem]
    mov rdx, 0x0fffffffffffffff
    cmp rcx, rdx
    ja .bad                        ; a size no body could ever have
    shl rcx, 4
    movzx eax, al
    or rcx, rax
    cmp rcx, rdx                   ; and AFTER the shift: the test above only
    ja .bad                        ; stops the shift overflowing, so a 16-digit
                                   ; value up to 0xffff... still passed a bound
                                   ; meant to say "no body could be this large"
    mov [r15 + linnea_chunk.rem], rcx
    inc qword [r15 + linnea_chunk.digits]
    inc r12
    jmp .step
.size_end:
    cmp qword [r15 + linnea_chunk.digits], 0
    je .bad                        ; no digits: not a chunk header
    ; chunk = chunk-size [ chunk-ext ] CRLF: everything from here to the CR is
    ; the extension, and linnea_chunk_ext_step is the one place that grammar
    ; lives. The byte that ended the size run belongs to it, so it is left for
    ; the ext state to judge rather than tested twice here.
    mov qword [r15 + linnea_chunk.ext], LINNEA_CHUNK_EXT_START
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_EXT
    jmp .step

.s_ext:
    ; This scanned a byte CLASS -- anything printable, plus HTAB, up to the CR
    ; -- which took "4 ", "4g" and "4\0" as a size of four (fixed by the sweep
    ; after report 21) and then still took "4;=bad" and "4;a=\"unterminated" as
    ; well-formed chunk headers (audit-report-23). The state rides in the
    ; connection because this decoder alone resumes byte by byte.
    movzx esi, byte [r12]
    mov rdi, [r15 + linnea_chunk.ext]
    call linnea_chunk_ext_step
    cmp rax, -2
    je .ext_cr                     ; the CR that ends the size line
    cmp rax, -1
    je .bad
    mov [r15 + linnea_chunk.ext], rax
    inc r12
    jmp .step
.ext_cr:
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_SIZE_LF
    jmp .step

.s_size_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [r15 + linnea_chunk.digits], 0
    cmp qword [r15 + linnea_chunk.rem], 0
    je .size_zero                  ; a zero-size chunk ends the body
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_DATA
    jmp .step
.size_zero:
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_TRAIL
    jmp .step

.s_data:
    mov rax, r13
    sub rax, r12                   ; bytes in hand
    mov rcx, [r15 + linnea_chunk.rem]
    cmp rcx, rax
    jbe .data_take                 ; the rest of the chunk is here
    mov rcx, rax                   ; take what there is
.data_take:
    cmp ebp, LINNEA_CHUNK_DECHUNK
    je .data_move
    cmp ebp, LINNEA_CHUNK_VALIDATE
    je .data_skip                  ; judging only: the bytes go nowhere here
    push rcx
    mov rdi, rbx
    mov rsi, r12
    mov rdx, rcx
    call linnea_spill_write
    pop rcx
    test eax, eax
    js .write_failed
    lea rax, [linnea_config_instance]
    mov rax, [rax + linnea_config.max_body]
    cmp [rbx + linnea_connection.spill_len], rax
    ja .too_large
    jmp .data_skip
.data_move:
    ; The decoded run moves down over the framing already consumed. rcx is the
    ; run length and is still needed below, so it rides in rdx across the copy;
    ; rdx is dead here (the size-overflow mask is the only thing that used it).
    mov rdx, rcx
    mov rdi, [rsp]                 ; write cursor
    mov rsi, r12                   ; read cursor, always at or ahead of it
    rep movsb
    mov [rsp], rdi
    mov rcx, rdx
.data_skip:
    add r12, rcx
    sub [r15 + linnea_chunk.rem], rcx
    jnz .step                      ; more of this chunk still to come
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_DATA_CR
    jmp .step

.s_data_cr:
    cmp byte [r12], 13
    jne .bad
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_DATA_LF
    jmp .step
.s_data_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_SIZE
    jmp .step                      ; chunk_rem is 0 here: the next size accrues

.s_trail:
    ; A field line needs at least one name byte, so a line that OPENS with a
    ; colon has an empty name. Checked here, at the start of a line, rather
    ; than with a counter in the name state.
    cmp byte [r12], ':'
    je .bad
    cmp byte [r12], 13
    je .trail_end
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_TRAIL_LINE
    jmp .step
.trail_end:
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_END_LF
    jmp .step
.s_trail_line:
    ; A trailer section is made of HTTP field LINES. Rejecting a bare LF made
    ; the DELIMITERS right without making the line a field, so a colonless line
    ; or a NUL in a value still completed the message (audit-report-21). The
    ; name is judged byte by byte -- there is nowhere here to buffer the line --
    ; against the same tchar bitmap the head validator uses.
    cmp byte [r12], ':'
    je .trail_colon
    cmp byte [r12], 13
    je .bad                        ; no colon: not a field line
    cmp byte [r12], 10
    je .bad
    movzx edi, byte [r12]
    push r12
    push rbx
    call linnea_string_is_tchar
    pop rbx
    pop r12
    test eax, eax
    jz .bad
    inc r12
    jmp .step
.trail_colon:
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_TRAIL_VAL
    jmp .step
.s_trail_val:
    cmp byte [r12], 13
    je .trail_line_cr
    cmp byte [r12], 10
    je .bad
    cmp byte [r12], 9
    je .trail_val_ok               ; HTAB is legal in a value
    cmp byte [r12], 0x20
    jb .bad                        ; any other control byte is not
    cmp byte [r12], 0x7f
    je .bad                        ; DEL
.trail_val_ok:
    inc r12
    jmp .step
.trail_line_cr:
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_TRAIL_LF
    jmp .step
.s_trail_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_TRAIL
    jmp .step

.s_end_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [r15 + linnea_chunk.state], LINNEA_CHUNK_DONE
.complete:
    cmp ebp, LINNEA_CHUNK_CAPTURE
    jne .complete_nostash          ; a relayed response has nothing pipelined
                                   ; behind it: the caller forwards the bytes
                                   ; itself and owns whatever follows
    ; The body is whole. Whatever remains in this buffer after the cursor (r12)
    ; is the next request, pipelined behind the body in the same recv. Park it at
    ; in_buf[head_len] so keep-alive picks it up; without this it was overwritten
    ; and the pipelined request silently went unanswered.
    mov rcx, r13
    sub rcx, r12                   ; unconsumed suffix length
    jz .complete_nostash           ; nothing pipelined behind the body
    mov rdx, [rbx + linnea_connection.head_len]
    lea rax, [rdx + rcx]
    cmp rax, LINNEA_CONN_IN_BUF
    ja .suffix_too_big             ; no room after the head: caller closes cleanly
    lea rdi, [rbx + linnea_connection.in_buf]
    add rdi, rdx                   ; dst = in_buf + head_len
    mov rsi, r12                   ; src = the unconsumed tail. For the in-buffer
                                   ; first pass src is in_buf+head_len+n (dst<src,
                                   ; a forward copy is safe); for an out_buf recv
                                   ; the two are disjoint. rep movsb serves both.
    mov [rbx + linnea_connection.pend_len], rcx
    rep movsb
.complete_nostash:
    mov eax, 1
    jmp .ret
.suffix_too_big:
    mov eax, -3
    jmp .ret
.need_more:
    xor eax, eax
    jmp .ret
.bad:
    mov eax, -1
    jmp .ret
.write_failed:
    mov eax, -1
    jmp .ret
.too_large:
    mov eax, -2
.ret:
    mov rdx, [rsp]                 ; decoded bytes now at buf; zero in the two
    sub rdx, [rsp + 8]             ; modes that never move the write cursor
    add rsp, 16
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_spill_finish(rdi=connection*) -> rax = 0 ok, -1 failed
; The body is complete: map it and point the connection's send cursor at it.
; MAP_PRIVATE read-only — nothing writes through the mapping, and the file is
; ours alone, so no one can change it underneath us either.
linnea_spill_finish:
    push rbx
    mov rbx, rdi
    mov rsi, [rbx + linnea_connection.spill_len]
    test rsi, rsi
    jz .empty
    xor edi, edi                   ; addr = NULL
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, [rbx + linnea_connection.spill_fd]
    xor r9d, r9d                   ; offset 0
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .fail
    ; file_base/file_size own the mapping — the connection teardown unmaps it.
    ; file_ptr/file_rem are the send cursor the proxy head send drains.
    mov [rbx + linnea_connection.file_base], rax
    mov [rbx + linnea_connection.file_ptr], rax
    mov rcx, [rbx + linnea_connection.spill_len]
    mov [rbx + linnea_connection.file_size], rcx
    mov [rbx + linnea_connection.file_rem], rcx
    xor eax, eax
    pop rbx
    ret
.empty:
    mov qword [rbx + linnea_connection.file_rem], 0
    xor eax, eax
    pop rbx
    ret
.fail:
    mov eax, -1
    pop rbx
    ret

; linnea_spill_reset(rdi=connection*) — clear every trace of a capture so the
; NEXT request on a kept-alive connection starts from nothing. Without this the
; capture file is reused: spill_open is idempotent, so a second upload appends
; to the first one's bytes and is described by a length that no longer matches
; what the file holds. The mapping is already gone by here — the response send
; unmaps file_base — so closing the fd is what returns the disk space.
linnea_spill_reset:
    push rdi
    call linnea_spill_release
    pop rdi
    mov qword [rdi + linnea_connection.chunk_state], LINNEA_CHUNK_SIZE
    mov qword [rdi + linnea_connection.chunk_rem], 0
    mov qword [rdi + linnea_connection.chunk_digits], 0
    mov qword [rdi + linnea_connection.chunk_ext], LINNEA_CHUNK_EXT_START
    mov qword [rdi + linnea_connection.chunk_raw], 0
    mov qword [rdi + linnea_connection.capture_chunked], 0
    mov qword [rdi + linnea_connection.capture_done], 0
    mov qword [rdi + linnea_connection.answer_linger], 0
    ret

; linnea_spill_release(rdi=connection*)
; Closing the fd is what frees the disk space: an O_TMPFILE has no link, so the
; kernel reclaims it here. The mapping outlives the fd and is released by the
; connection's own file_base teardown.
linnea_spill_release:
    mov ecx, [rdi + linnea_connection.spill_fd]
    cmp ecx, -1
    je .none
    push rdi
    mov edi, ecx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop rdi
    mov dword [rdi + linnea_connection.spill_fd], -1
    mov qword [rdi + linnea_connection.spill_len], 0
.none:
    ret
