; Linux x86-64 syscall numbers and kernel ABI constants.
; Kernel convention: number in rax, args in rdi, rsi, rdx, r10, r8, r9.
; syscall clobbers rcx and r11. Errors return -errno in rax
; (unsigned rax > -4096, test with: cmp rax, -4095 / jae error).

LINNEA_SYS_WRITE     equ 1
LINNEA_SYS_OPEN      equ 2
LINNEA_SYS_CLOSE     equ 3
LINNEA_SYS_FSTAT     equ 5
LINNEA_SYS_MMAP      equ 9
LINNEA_SYS_MUNMAP    equ 11
LINNEA_SYS_PAUSE     equ 34
LINNEA_SYS_SOCKET    equ 41
LINNEA_SYS_SHUTDOWN  equ 48
LINNEA_SYS_BIND      equ 49
LINNEA_SYS_LISTEN    equ 50
LINNEA_SYS_GETPEERNAME equ 52
LINNEA_SYS_SETSOCKOPT equ 54
LINNEA_SYS_EXIT      equ 60
LINNEA_SYS_CLOCK_GETTIME equ 228

LINNEA_CLOCK_REALTIME equ 0
LINNEA_CLOCK_MONOTONIC equ 1

LINNEA_SHUT_RDWR     equ 2

LINNEA_STDIN         equ 0
LINNEA_STDOUT        equ 1
LINNEA_STDERR        equ 2

LINNEA_O_RDONLY      equ 0
LINNEA_O_WRONLY      equ 1
LINNEA_O_CREAT       equ 0x40
LINNEA_O_APPEND      equ 0x400
LINNEA_MODE_0644     equ 420  ; rw-r--r--
LINNEA_PROT_READ     equ 1
LINNEA_PROT_WRITE    equ 2
LINNEA_MAP_PRIVATE   equ 2
LINNEA_MAP_ANONYMOUS equ 0x20

LINNEA_STAT_ST_MODE  equ 24   ; offset of st_mode in struct stat, x86-64
LINNEA_STAT_ST_SIZE  equ 48   ; offset of st_size in struct stat, x86-64
LINNEA_STAT_ST_MTIME equ 88   ; offset of st_mtime in struct stat, x86-64
LINNEA_STAT_SIZE     equ 144  ; sizeof(struct stat), x86-64
LINNEA_S_IFMT        equ 0xF000
LINNEA_S_IFREG       equ 0x8000

LINNEA_AF_INET       equ 2
LINNEA_SOCK_STREAM   equ 1
LINNEA_SOL_SOCKET    equ 1
LINNEA_SO_REUSEADDR  equ 2
LINNEA_SOCKADDR_IN_SIZE equ 16  ; struct sockaddr_in: family u16, port u16 (BE), addr u32 (BE), zero[8]
LINNEA_BACKLOG       equ 128
