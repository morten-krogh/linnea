; io_uring constants and struct layouts.
;
; SQE and CQE layouts are stable kernel ABI. The struct io_uring offsets are
; liburing internals — they are pinned to the vendored liburing-2.15 build
; (lib/liburing) and were verified with offsetof() against its headers:
;   sizeof(struct io_uring) = 216, offsetof(cq.khead) = 104.

; struct io_uring_sqe (kernel ABI, 64 bytes)
LINNEA_SQE_OPCODE       equ 0    ; u8
LINNEA_SQE_FLAGS        equ 1    ; u8
LINNEA_SQE_IOPRIO       equ 2    ; u16
LINNEA_SQE_FD           equ 4    ; s32
LINNEA_SQE_OFF          equ 8    ; u64 (addr2 / addrlen pointer for accept)
LINNEA_SQE_ADDR         equ 16   ; u64 (sockaddr pointer for accept)
LINNEA_SQE_LEN          equ 24   ; u32
LINNEA_SQE_OP_FLAGS     equ 28   ; u32 (accept_flags for accept)
LINNEA_SQE_USER_DATA    equ 32   ; u64
LINNEA_SQE_SIZE         equ 64

; struct io_uring_cqe (kernel ABI, 16 bytes)
LINNEA_CQE_USER_DATA    equ 0    ; u64
LINNEA_CQE_RES          equ 8    ; s32
LINNEA_CQE_FLAGS        equ 12   ; u32

LINNEA_IORING_OP_ACCEPT      equ 13
LINNEA_IORING_OP_LINK_TIMEOUT equ 15
LINNEA_IORING_OP_CONNECT     equ 16
LINNEA_IORING_OP_SEND        equ 26
LINNEA_IORING_OP_RECV        equ 27
LINNEA_IORING_ACCEPT_MULTISHOT equ 1   ; set in sqe.ioprio
LINNEA_IORING_CQE_F_MORE     equ 2     ; multishot op is still armed
LINNEA_IOSQE_IO_LINK         equ 4     ; sqe.flags: link to the next sqe

; user_data encoding: (index << 8) | op tag. For accepts the index is the
; server index; for every other tag it is the connection pool index.
LINNEA_UD_ACCEPT        equ 0
LINNEA_UD_RECV          equ 1
LINNEA_UD_SEND          equ 2
LINNEA_UD_TIMEOUT       equ 3          ; linked-timeout cqe, always ignored
LINNEA_UD_CONNECT       equ 4          ; connect to a proxy upstream
LINNEA_UD_UP_SEND       equ 5          ; request bytes to the upstream
LINNEA_UD_UP_RECV       equ 6          ; response bytes from the upstream

; Idle timeout: a linked timeout is attached to every recv. If the peer
; sends nothing for that long, the recv completes with -ECANCELED and the
; connection is closed. The duration comes from the config's "timeout".

; struct io_uring (liburing 2.15 internal layout)
LINNEA_URING_RING_SIZE  equ 216
LINNEA_URING_CQ_KHEAD   equ 104  ; struct io_uring_cq.khead pointer

LINNEA_URING_ENTRIES    equ 256  ; submission queue depth
LINNEA_EINTR            equ 4
LINNEA_ECANCELED        equ 125
