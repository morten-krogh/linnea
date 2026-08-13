; Linux x86-64 syscall numbers and kernel ABI constants.
; Kernel convention: number in rax, args in rdi, rsi, rdx, r10, r8, r9.
; syscall clobbers rcx and r11. Errors return -errno in rax
; (unsigned rax > -4096, test with: cmp rax, -4095 / jae error).

LINNEA_SYS_READ      equ 0
LINNEA_SYS_WRITE     equ 1
LINNEA_SYS_OPEN      equ 2
LINNEA_SYS_CLOSE     equ 3
LINNEA_SYS_FSTAT     equ 5
LINNEA_SYS_STATFS    equ 137     ; what KIND of filesystem a path is on, which
                                 ; is the difference between an upload capture
                                 ; that can be written back and evicted and one
                                 ; that is simply RAM (see spill_dir)
LINNEA_STATFS_BUF    equ 120     ; struct statfs; f_type is the first qword
LINNEA_TMPFS_MAGIC   equ 0x01021994
LINNEA_SYS_LSEEK     equ 8
LINNEA_SEEK_SET      equ 0
LINNEA_SYS_PWRITE64  equ 18      ; write at an explicit offset, without moving
                                 ; the file position a sequential write uses
LINNEA_SYS_MMAP      equ 9
LINNEA_SYS_MUNMAP    equ 11
LINNEA_SYS_RT_SIGACTION equ 13
LINNEA_SYS_RT_SIGPROCMASK equ 14
LINNEA_SYS_RT_SIGRETURN equ 15
LINNEA_SYS_PAUSE     equ 34
LINNEA_SYS_FCNTL     equ 72
LINNEA_F_SETFD       equ 2       ; fcntl: set the fd flags (FD_CLOEXEC is bit 0)
LINNEA_F_SETFL       equ 4       ; fcntl: set the file status flags
LINNEA_O_NONBLOCK    equ 0o4000  ; ...of which this is the one we ever set
LINNEA_SYS_EXECVE    equ 59
LINNEA_SYS_KILL      equ 62
LINNEA_SYS_ACCEPT    equ 43
LINNEA_SYS_SOCKET    equ 41
LINNEA_SYS_CONNECT   equ 42      ; client-side: reach out to a server (linnea-probe)
LINNEA_SYS_POLL      equ 7       ; readability wait with a timeout (linnea-probe)
LINNEA_SYS_NANOSLEEP equ 35      ; deliberate pauses for slow-drip probes
LINNEA_POLLIN        equ 1
LINNEA_POLLOUT       equ 4       ; ...and writability, for linnea-ws's loop
LINNEA_POLLERR       equ 8
LINNEA_POLLHUP       equ 16
LINNEA_SYS_SENDTO    equ 44
LINNEA_SYS_SENDMSG   equ 46
LINNEA_MSG_DONTWAIT  equ 0x40
; Without MSG_NOSIGNAL a write to a peer that has already gone raises SIGPIPE,
; whose default action kills the process outright.
LINNEA_MSG_NOSIGNAL  equ 0x4000
LINNEA_SYS_RECVFROM  equ 45
LINNEA_SYS_SHUTDOWN  equ 48
LINNEA_SYS_BIND      equ 49
LINNEA_SYS_LISTEN    equ 50
LINNEA_SYS_GETSOCKNAME equ 51
LINNEA_SYS_GETPEERNAME equ 52
LINNEA_SYS_SETSOCKOPT equ 54
LINNEA_SYS_GETPID    equ 39
LINNEA_SYS_UNLINK    equ 87
LINNEA_SYS_RENAME    equ 82
LINNEA_SYS_FORK      equ 57
LINNEA_SYS_EXIT      equ 60
LINNEA_SYS_IO_URING_SETUP equ 425
LINNEA_SYS_IO_URING_ENTER equ 426
LINNEA_SYS_WAIT4     equ 61
LINNEA_SYS_GETPPID   equ 110
LINNEA_SYS_PRCTL     equ 157
LINNEA_SYS_PRLIMIT64 equ 302
LINNEA_RLIMIT_NOFILE equ 7
LINNEA_SYS_SCHED_GETAFFINITY equ 204
LINNEA_SYS_CLOCK_GETTIME equ 228
LINNEA_SYS_SIGNALFD4 equ 289
LINNEA_SYS_GETRANDOM equ 318

LINNEA_PR_SET_PDEATHSIG equ 1
LINNEA_SIGHUP        equ 1
LINNEA_SIGQUIT       equ 3
LINNEA_SIGTERM       equ 15
LINNEA_SIGUSR2       equ 12
LINNEA_SIG_BLOCK     equ 0
LINNEA_SA_RESTORER   equ 0x04000000

LINNEA_CLOCK_REALTIME equ 0
LINNEA_CLOCK_MONOTONIC equ 1

LINNEA_SHUT_WR       equ 1
LINNEA_SHUT_RDWR     equ 2

LINNEA_STDIN         equ 0
LINNEA_STDOUT        equ 1
LINNEA_STDERR        equ 2

LINNEA_O_RDONLY      equ 0
LINNEA_O_WRONLY      equ 1
LINNEA_O_RDWR        equ 2
LINNEA_O_CREAT       equ 0x40
LINNEA_O_APPEND      equ 0x400
LINNEA_O_CLOEXEC     equ 0x80000
; O_TMPFILE is __O_TMPFILE | O_DIRECTORY: the path names the filesystem, and
; the file it creates there has no directory entry at all
LINNEA_O_TMPFILE     equ 0x410000
LINNEA_O_DIRECTORY   equ 0x10000   ; open only if the path IS a directory
LINNEA_O_TRUNC       equ 0x200
LINNEA_MODE_0600     equ 384  ; rw-------
LINNEA_MODE_0644     equ 420  ; rw-r--r--
LINNEA_PROT_READ     equ 1
LINNEA_PROT_WRITE    equ 2
LINNEA_MAP_SHARED    equ 1
LINNEA_MAP_PRIVATE   equ 2
LINNEA_MAP_ANONYMOUS equ 0x20
LINNEA_MAP_POPULATE  equ 0x8000

LINNEA_STAT_ST_MODE  equ 24   ; offset of st_mode in struct stat, x86-64
LINNEA_STAT_ST_SIZE  equ 48   ; offset of st_size in struct stat, x86-64
LINNEA_STAT_ST_MTIME equ 88   ; offset of st_mtime in struct stat, x86-64
LINNEA_STAT_SIZE     equ 144  ; sizeof(struct stat), x86-64
LINNEA_S_IFMT        equ 0xF000
LINNEA_S_IFREG       equ 0x8000

LINNEA_AF_INET       equ 2
LINNEA_AF_INET6      equ 10
LINNEA_SOCK_STREAM   equ 1
LINNEA_SOCK_DGRAM    equ 2
LINNEA_SOL_SOCKET    equ 1
LINNEA_SO_REUSEADDR  equ 2
LINNEA_SO_REUSEPORT  equ 15
LINNEA_SO_RCVBUF     equ 8
LINNEA_SO_RXQ_OVFL   equ 40    ; ask for the per-socket drop count as a cmsg
; Deadlines for a blocking socket, which is the only thing standing between a
; serial server and one peer that says nothing (linnea-api). Both take a struct
; timeval, and a expiry surfaces as EAGAIN — distinguishable from EINTR, which
; is the one worth retrying.
LINNEA_SO_RCVTIMEO   equ 20
LINNEA_SO_SNDTIMEO   equ 21
LINNEA_IPPROTO_IPV6  equ 41
LINNEA_IPV6_V6ONLY   equ 26
LINNEA_SOCKADDR_IN_SIZE equ 16  ; struct sockaddr_in: family u16, port u16 (BE), addr u32 (BE), zero[8]
LINNEA_SOCKADDR_IN6_SIZE equ 28 ; struct sockaddr_in6: family u16, port u16 (BE), flowinfo u32, addr[16], scope_id u32
LINNEA_BACKLOG       equ 128
LINNEA_ENOSPC   equ 28
