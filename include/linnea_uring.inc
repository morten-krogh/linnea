; io_uring constants and struct layouts. Every offset here is stable kernel ABI
; (io_uring(7)): the sqe and cqe layouts, the io_uring_params block that
; io_uring_setup(2) fills in, and the ring offsets inside it. linnea_ring
; below is ours — src/linnea_ring.asm builds and drives the rings directly, so
; nothing in this file depends on a library's private layout.

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

LINNEA_IORING_OP_TIMEOUT     equ 11
LINNEA_IORING_OP_ACCEPT      equ 13
LINNEA_IORING_OP_ASYNC_CANCEL equ 14
LINNEA_IORING_OP_LINK_TIMEOUT equ 15
LINNEA_IORING_OP_CONNECT     equ 16
LINNEA_IORING_OP_READ        equ 22
LINNEA_IORING_OP_SEND        equ 26
LINNEA_IORING_OP_RECV        equ 27
LINNEA_IORING_OP_RECVMSG     equ 10
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
LINNEA_UD_SIGNAL        equ 7          ; signalfd read: SIGTERM = stop now,
                                       ; SIGQUIT = drain, SIGHUP = reopen log
LINNEA_UD_CANCEL        equ 8          ; accept-cancel cqe, always ignored
LINNEA_UD_QRECV         equ 9          ; datagram on the QUIC (UDP) listener
LINNEA_UD_QTIMER        equ 10         ; QUIC probe-timeout tick: run the rtx sweep
; proxy-over-h2 upstream ops: the index field carries (conn index << 3) | slot,
; so a completion can find its upstream slot without touching the connection
LINNEA_UD_ARETRY        equ 14         ; accept-retry tick after a failed accept
LINNEA_UD_DRAINTIMER    equ 15         ; the hot upgrade's drain deadline expired
LINNEA_UD_H2UP_CONNECT  equ 11
LINNEA_UD_H2UP_SEND     equ 12
LINNEA_UD_H2UP_RECV     equ 13

; struct msghdr (x86-64), for the QUIC listener's recvmsg: UDP needs the
; sender's address, which plain recv does not report.
LINNEA_MSGHDR_NAME      equ 0    ; void*
LINNEA_MSGHDR_NAMELEN   equ 8    ; int (kernel updates it with the real length)
LINNEA_MSGHDR_IOV       equ 16   ; struct iovec*
LINNEA_MSGHDR_IOVLEN    equ 24   ; size_t
LINNEA_MSGHDR_CONTROL   equ 32
LINNEA_MSGHDR_CONTROLLEN equ 40
LINNEA_MSGHDR_FLAGS     equ 48   ; int
LINNEA_MSGHDR_SIZE      equ 56
; struct cmsghdr: len(8) level(4) type(4) then the data. One u32 counter.
LINNEA_CMSG_LEN         equ 0
LINNEA_CMSG_LEVEL       equ 8
LINNEA_CMSG_TYPE        equ 12
LINNEA_CMSG_DATA        equ 16
LINNEA_QRECV_CMSG_SIZE  equ 32
LINNEA_IOVEC_BASE       equ 0
LINNEA_IOVEC_LEN        equ 8
LINNEA_IOVEC_SIZE       equ 16

; Idle timeout: a linked timeout is attached to every per-connection op
; (recv, send, connect, upstream send/recv). An op that makes no progress
; for that long completes with -ECANCELED; the request fails or the
; connection closes. The duration comes from the config's "timeout".

; struct io_uring_params (kernel ABI, 120 bytes) — io_uring_setup(2) reports the
; queue sizes it chose, the features it supports, and where each queue's fields
; sit inside the ring mappings.
LINNEA_URING_P_SQ_ENTRIES equ 0    ; u32
LINNEA_URING_P_CQ_ENTRIES equ 4    ; u32
LINNEA_URING_P_FLAGS      equ 8    ; u32 (IORING_SETUP_*)
LINNEA_URING_P_FEATURES   equ 20   ; u32 (IORING_FEAT_*)
LINNEA_URING_P_SQ_OFF     equ 40   ; struct io_sqring_offsets
LINNEA_URING_P_CQ_OFF     equ 80   ; struct io_cqring_offsets
LINNEA_URING_PARAMS_SIZE  equ 120

; struct io_sqring_offsets / io_cqring_offsets: byte offsets into the ring mapping
LINNEA_SQ_OFF_HEAD        equ 0
LINNEA_SQ_OFF_TAIL        equ 4
LINNEA_SQ_OFF_RING_MASK   equ 8
LINNEA_SQ_OFF_RING_ENTRIES equ 12
LINNEA_SQ_OFF_FLAGS       equ 16
LINNEA_SQ_OFF_DROPPED     equ 20
LINNEA_SQ_OFF_ARRAY       equ 24
LINNEA_CQ_OFF_HEAD        equ 0
LINNEA_CQ_OFF_TAIL        equ 4
LINNEA_CQ_OFF_RING_MASK   equ 8
LINNEA_CQ_OFF_RING_ENTRIES equ 12
LINNEA_CQ_OFF_OVERFLOW    equ 16
LINNEA_CQ_OFF_CQES        equ 20

; mmap offsets that select which region io_uring_setup's fd maps
LINNEA_IORING_OFF_SQ_RING equ 0
LINNEA_IORING_OFF_CQ_RING equ 0x8000000
LINNEA_IORING_OFF_SQES    equ 0x10000000

LINNEA_IORING_FEAT_SINGLE_MMAP equ 1   ; sq and cq rings share one mapping
LINNEA_IORING_ENTER_GETEVENTS  equ 1   ; io_uring_enter flag: also reap completions
LINNEA_IORING_SQ_CQ_OVERFLOW   equ 2   ; sq flags: completions are backlogged

; struct linnea_ring — our ring handle: the queue pointers the hot paths need,
; cached out of the mappings, plus what is required to submit and to unmap.
struc linnea_ring
    .fd:        resq 1               ; the io_uring_setup(2) fd
    .sq_khead:  resq 1               ; u32*: submissions the kernel has consumed
    .sq_ktail:  resq 1               ; u32*: submissions we have published
    .sq_kflags: resq 1               ; u32*: IORING_SQ_*
    .sq_mask:   resq 1
    .sq_entries: resq 1
    .sqes:      resq 1               ; struct io_uring_sqe[]
    .sq_tail:   resq 1               ; our tail: prepared, not yet published
    .cq_khead:  resq 1               ; u32*: completions we have consumed
    .cq_ktail:  resq 1               ; u32*: completions the kernel has published
    .cq_mask:   resq 1
    .cqes:      resq 1               ; struct io_uring_cqe[]
    .sq_base:   resq 1               ; mappings, kept for munmap
    .sq_len:    resq 1
    .cq_base:   resq 1               ; 0 when the cq shares the sq mapping
    .cq_len:    resq 1
    .sqes_len:  resq 1
endstruc
LINNEA_RING_SIZE        equ linnea_ring_size

LINNEA_URING_ENTRIES    equ 256  ; submission queue depth
; Completion queue depth, sized explicitly rather than taking the kernel's
; default of twice the submission queue. Every operation here carries a linked
; timeout, so a parked connection accounts for TWO completions, and the default
; 512 was already under water at a few hundred connections — past that the
; kernel has to backlog completions internally. It handles that correctly, but
; the ring reports it only in a flag nobody was reading, so the cost was
; invisible. Must be a power of two and at least LINNEA_URING_ENTRIES.
LINNEA_URING_CQ_ENTRIES equ 4096
LINNEA_IORING_SETUP_CQSIZE equ 8    ; params.cq_entries is meaningful
LINNEA_EINTR            equ 4
LINNEA_EAGAIN           equ 11
LINNEA_EIO              equ 5
LINNEA_EBUSY            equ 16
LINNEA_ECANCELED        equ 125
; A peer that hung up abruptly rather than closing. Routine from a browser —
; a tab closed, a navigation, a connection pool trimmed — so it is told apart
; from a real read failure rather than logged as one.
LINNEA_ECONNRESET       equ 104
LINNEA_EPIPE            equ 32      ; a send to a peer that has gone: routine
