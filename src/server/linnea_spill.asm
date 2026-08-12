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

; linnea_spill_chunked(rdi=connection*, rsi=buf, rdx=len)
;   -> rax = 0 need more, 1 body complete, -1 malformed framing, -2 past max_body
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
    mov rbx, rdi
    mov r12, rsi                   ; read cursor
    lea r13, [rsi + rdx]           ; end of what arrived
    ; Encoded bytes are capped as well as decoded ones. A client can send
    ; empty chunks and trailer lines forever without the decoded length ever
    ; growing, so a cap on the decoded body alone would never fire.
    add [rbx + linnea_connection.chunk_raw], rdx
    lea rax, [linnea_config_instance]
    mov rax, [rax + linnea_config.max_body]
    cmp [rbx + linnea_connection.chunk_raw], rax
    ja .too_large
.step:
    cmp r12, r13
    jae .need_more
    mov r14, [rbx + linnea_connection.chunk_state]
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
    cmp r14, LINNEA_CHUNK_TRAIL_LF
    je .s_trail_lf
    cmp r14, LINNEA_CHUNK_END_LF
    je .s_end_lf
    jmp .complete                  ; DONE: trailing bytes are not ours to read

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
    mov rcx, [rbx + linnea_connection.chunk_rem]
    mov rdx, 0x0fffffffffffffff
    cmp rcx, rdx
    ja .bad                        ; a size no body could ever have
    shl rcx, 4
    movzx eax, al
    or rcx, rax
    mov [rbx + linnea_connection.chunk_rem], rcx
    inc qword [rbx + linnea_connection.chunk_digits]
    inc r12
    jmp .step
.size_end:
    cmp qword [rbx + linnea_connection.chunk_digits], 0
    je .bad                        ; no digits: not a chunk header
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_EXT
    jmp .step                      ; the byte itself belongs to the ext state

.s_ext:
    cmp byte [r12], 13
    je .ext_cr
    cmp byte [r12], 10
    je .bad                        ; a bare LF is not a line ending here
    inc r12
    jmp .step
.ext_cr:
    inc r12
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_SIZE_LF
    jmp .step

.s_size_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [rbx + linnea_connection.chunk_digits], 0
    cmp qword [rbx + linnea_connection.chunk_rem], 0
    je .size_zero                  ; a zero-size chunk ends the body
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_DATA
    jmp .step
.size_zero:
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_TRAIL
    jmp .step

.s_data:
    mov rax, r13
    sub rax, r12                   ; bytes in hand
    mov rcx, [rbx + linnea_connection.chunk_rem]
    cmp rcx, rax
    jbe .data_take                 ; the rest of the chunk is here
    mov rcx, rax                   ; take what there is
.data_take:
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
    add r12, rcx
    sub [rbx + linnea_connection.chunk_rem], rcx
    jnz .step                      ; more of this chunk still to come
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_DATA_CR
    jmp .step

.s_data_cr:
    cmp byte [r12], 13
    jne .bad
    inc r12
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_DATA_LF
    jmp .step
.s_data_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_SIZE
    jmp .step                      ; chunk_rem is 0 here: the next size accrues

.s_trail:
    cmp byte [r12], 13
    je .trail_end
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_TRAIL_LINE
    jmp .step
.trail_end:
    inc r12
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_END_LF
    jmp .step
.s_trail_line:
    cmp byte [r12], 13
    je .trail_line_cr
    inc r12
    jmp .step
.trail_line_cr:
    inc r12
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_TRAIL_LF
    jmp .step
.s_trail_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_TRAIL
    jmp .step

.s_end_lf:
    cmp byte [r12], 10
    jne .bad
    inc r12
    mov qword [rbx + linnea_connection.chunk_state], LINNEA_CHUNK_DONE
.complete:
    mov eax, 1
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
