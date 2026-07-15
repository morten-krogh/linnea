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
LINNEA_SYS_BIND      equ 49
LINNEA_SYS_LISTEN    equ 50
LINNEA_SYS_SETSOCKOPT equ 54
LINNEA_SYS_EXIT      equ 60

LINNEA_STDIN         equ 0
LINNEA_STDOUT        equ 1
LINNEA_STDERR        equ 2

LINNEA_O_RDONLY      equ 0
LINNEA_PROT_READ     equ 1
LINNEA_PROT_WRITE    equ 2
LINNEA_MAP_PRIVATE   equ 2
LINNEA_MAP_ANONYMOUS equ 0x20

LINNEA_STAT_ST_SIZE  equ 48   ; offset of st_size in struct stat, x86-64
LINNEA_STAT_SIZE     equ 144  ; sizeof(struct stat), x86-64

LINNEA_AF_INET       equ 2
LINNEA_SOCK_STREAM   equ 1
LINNEA_SOL_SOCKET    equ 1
LINNEA_SO_REUSEADDR  equ 2
LINNEA_SOCKADDR_IN_SIZE equ 16  ; struct sockaddr_in: family u16, port u16 (BE), addr u32 (BE), zero[8]
LINNEA_BACKLOG       equ 128
