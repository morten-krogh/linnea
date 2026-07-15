; linnea_time.asm — UTC calendar maths and HTTP dates.
;
; Everything is UTC: HTTP dates are defined to be, and the log stamp is by
; choice. The civil-from-days / days-from-civil pair is Howard Hinnant's,
; shifting the era so that March starts the year and the leap day falls at
; the end of it. Only years from 1970 on are expected.

default rel

%include "linnea_syscall.inc"
%include "linnea_time.inc"

global linnea_time_civil
global linnea_time_days_from_civil
global linnea_time_http_date
global linnea_time_parse_http_date

section .rodata

; Three-letter names, indexed by wday (0 = Sunday) and by month (1-12), so
; the month table carries an unused first entry. Both are padded: the name
; lookups read four bytes at a time and the last name must not run off the
; end of the table.
wday_names:     db "SunMonTueWedThuFriSat", 0, 0, 0
month_names:    db "???JanFebMarAprMayJunJulAugSepOctNovDec", 0, 0, 0

section .text

; linnea_time_civil(rdi=unix seconds, rsi=linnea_tm*)
; Splits a POSIX timestamp into UTC calendar fields.
linnea_time_civil:
    push rbx
    mov rbx, rsi
    mov rax, rdi
    xor edx, edx
    mov rcx, 86400
    div rcx                    ; rax = days since epoch, rdx = second of day
    mov r8, rdx
    mov rsi, rax               ; keep days
    ; weekday: 1970-01-01 was a Thursday, which is 4 with Sunday = 0
    add rax, 4
    xor edx, edx
    mov rcx, 7
    div rcx
    mov [rbx + linnea_tm.wday], rdx
    ; time of day
    mov rax, r8
    xor edx, edx
    mov ecx, 3600
    div ecx
    mov [rbx + linnea_tm.hour], rax
    mov eax, edx
    xor edx, edx
    mov ecx, 60
    div ecx
    mov [rbx + linnea_tm.min], rax
    mov [rbx + linnea_tm.sec], rdx
    ; civil date: z = days + 719468 shifts the epoch to 0000-03-01
    mov rax, rsi
    add rax, 719468
    xor edx, edx
    mov rcx, 146097
    div rcx                    ; rax = era, rdx = day of era
    mov r9, rax                ; era
    mov r10, rdx               ; doe
    ; yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365
    mov rax, r10
    xor edx, edx
    mov rcx, 1460
    div rcx
    mov r11, r10
    sub r11, rax
    mov rax, r10
    xor edx, edx
    mov rcx, 36524
    div rcx
    add r11, rax
    mov rax, r10
    xor edx, edx
    mov rcx, 146096
    div rcx
    sub r11, rax
    mov rax, r11
    xor edx, edx
    mov rcx, 365
    div rcx
    mov r11, rax               ; yoe
    ; y = yoe + era * 400
    imul r9, r9, 400
    add r9, r11
    ; doy = doe - (365*yoe + yoe/4 - yoe/100)
    imul rcx, r11, 365
    mov rax, r11
    shr rax, 2
    add rcx, rax
    mov rax, r11
    xor edx, edx
    mov rsi, 100
    div rsi
    sub rcx, rax
    sub r10, rcx               ; doy
    ; mp = (5*doy + 2) / 153
    imul rax, r10, 5
    add rax, 2
    xor edx, edx
    mov rcx, 153
    div rcx
    mov r11, rax               ; mp
    ; d = doy - (153*mp + 2)/5 + 1
    imul rax, r11, 153
    add rax, 2
    xor edx, edx
    mov rcx, 5
    div rcx
    sub r10, rax
    inc r10
    mov [rbx + linnea_tm.day], r10
    ; m = mp + 3 if mp < 10 else mp - 9; January and February close out y+1
    lea rcx, [r11 + 3]
    cmp r11, 10
    jb .month_ok
    lea rcx, [r11 - 9]
    inc r9
.month_ok:
    mov [rbx + linnea_tm.month], rcx
    mov [rbx + linnea_tm.year], r9
    pop rbx
    ret

; linnea_time_days_from_civil(rdi=year, rsi=month 1-12, rdx=day) -> rax
; Days since the epoch; the inverse of the date half of linnea_time_civil.
linnea_time_days_from_civil:
    mov r8, rdx                ; day
    mov rax, rdi               ; year
    cmp rsi, 2
    ja .march_based
    dec rax                    ; January and February belong to the prior year
.march_based:
    xor edx, edx
    mov rcx, 400
    div rcx
    mov r9, rax                ; era = y / 400
    mov r10, rdx               ; yoe = y % 400
    ; doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
    mov rax, rsi
    cmp rsi, 2
    ja .mp_march
    add rax, 9
    jmp .mp_done
.mp_march:
    sub rax, 3
.mp_done:
    imul rax, rax, 153
    add rax, 2
    xor edx, edx
    mov rcx, 5
    div rcx
    add rax, r8
    dec rax
    mov r11, rax               ; doy
    ; doe = yoe * 365 + yoe/4 - yoe/100 + doy
    imul rax, r10, 365
    mov rcx, r10
    shr rcx, 2
    add rax, rcx
    mov rcx, rax               ; yoe*365 + yoe/4
    mov rax, r10
    xor edx, edx
    mov rsi, 100
    div rsi
    sub rcx, rax
    add rcx, r11               ; doe
    ; days = era * 146097 + doe - 719468
    mov rax, r9
    imul rax, rax, 146097
    add rax, rcx
    sub rax, 719468
    ret

; linnea_time_http_date(rdi=unix seconds, rsi=buf) -> rax = length
; Writes "Sun, 06 Nov 1994 08:49:37 GMT"; buf needs LINNEA_HTTP_DATE_LEN bytes.
linnea_time_http_date:
    push rbx
    push r12
    sub rsp, linnea_tm_size
    mov rbx, rsi               ; out buffer
    mov rsi, rsp
    call linnea_time_civil
    mov rax, [rsp + linnea_tm.wday]
    lea rcx, [rax + rax * 2]   ; three bytes per name
    lea rsi, [wday_names]
    mov eax, [rsi + rcx]
    mov [rbx], ax
    shr eax, 16
    mov [rbx + 2], al
    mov word [rbx + 3], ', '
    mov rax, [rsp + linnea_tm.day]
    lea rdi, [rbx + 5]
    call .put2
    mov byte [rbx + 7], ' '
    mov rax, [rsp + linnea_tm.month]
    lea rcx, [rax + rax * 2]
    lea rsi, [month_names]
    mov eax, [rsi + rcx]
    mov [rbx + 8], ax
    shr eax, 16
    mov [rbx + 10], al
    mov byte [rbx + 11], ' '
    mov rax, [rsp + linnea_tm.year]
    xor edx, edx
    mov ecx, 100
    div ecx
    mov r12, rdx               ; year % 100
    lea rdi, [rbx + 12]
    call .put2                 ; century
    mov rax, r12
    lea rdi, [rbx + 14]
    call .put2
    mov byte [rbx + 16], ' '
    mov rax, [rsp + linnea_tm.hour]
    lea rdi, [rbx + 17]
    call .put2
    mov byte [rbx + 19], ':'
    mov rax, [rsp + linnea_tm.min]
    lea rdi, [rbx + 20]
    call .put2
    mov byte [rbx + 22], ':'
    mov rax, [rsp + linnea_tm.sec]
    lea rdi, [rbx + 23]
    call .put2
    mov dword [rbx + 25], ' GMT'
    add rsp, linnea_tm_size
    mov eax, LINNEA_HTTP_DATE_LEN
    pop r12
    pop rbx
    ret

; .put2(rax=value 0-99, rdi=dest) — two zero-padded digits
.put2:
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    mov [rdi], al
    add dl, '0'
    mov [rdi + 1], dl
    ret

; linnea_time_parse_http_date(rdi=ptr, rsi=len) -> rax = unix seconds, or -1
; Accepts only IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT"), the format
; every client sends today and the only one linnea hands out. The obsolete
; RFC 850 and asctime forms parse as invalid, which callers must treat the
; way the RFC requires: ignore the header and answer unconditionally.
linnea_time_parse_http_date:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp rsi, LINNEA_HTTP_DATE_LEN
    jne .bad
    mov rbx, rdi
    ; fixed layout: the separators must be exactly where they belong
    cmp byte [rbx + 3], ','
    jne .bad
    cmp byte [rbx + 4], ' '
    jne .bad
    cmp byte [rbx + 7], ' '
    jne .bad
    cmp byte [rbx + 11], ' '
    jne .bad
    cmp byte [rbx + 16], ' '
    jne .bad
    cmp byte [rbx + 19], ':'
    jne .bad
    cmp byte [rbx + 22], ':'
    jne .bad
    cmp byte [rbx + 25], ' '
    jne .bad
    mov eax, [rbx + 25]
    cmp eax, ' GMT'            ; only UTC; anything else is not IMF-fixdate
    jne .bad
    lea rdi, [rbx + 5]         ; day
    call .num2
    cmp eax, -1
    je .bad
    test eax, eax
    jz .bad
    cmp eax, 31
    ja .bad
    mov r12d, eax
    lea rdi, [rbx + 17]        ; hour
    call .num2
    cmp eax, -1
    je .bad
    cmp eax, 23
    ja .bad
    mov r13d, eax
    lea rdi, [rbx + 20]        ; minute
    call .num2
    cmp eax, -1
    je .bad
    cmp eax, 59
    ja .bad
    mov r14d, eax
    lea rdi, [rbx + 23]        ; second
    call .num2
    cmp eax, -1
    je .bad
    cmp eax, 60                ; a leap second folds onto the minute
    ja .bad
    mov r15d, eax
    lea rdi, [rbx + 12]        ; year, four digits
    call .num2
    cmp eax, -1
    je .bad
    mov r8d, eax
    lea rdi, [rbx + 14]
    call .num2
    cmp eax, -1
    je .bad
    imul r8d, r8d, 100
    add r8d, eax               ; year
    cmp r8d, 1970
    jb .bad
    ; month name -> 1-12
    mov eax, [rbx + 8]
    and eax, 0x00FFFFFF        ; three name bytes
    lea rsi, [month_names]
    mov ecx, 1
.month_loop:
    cmp ecx, 12
    ja .bad
    lea rdx, [rcx + rcx * 2]
    mov r9d, [rsi + rdx]
    and r9d, 0x00FFFFFF
    cmp r9d, eax
    je .month_found
    inc ecx
    jmp .month_loop
.month_found:
    mov edi, r8d               ; year
    mov esi, ecx               ; month
    mov edx, r12d              ; day
    call linnea_time_days_from_civil
    ; seconds = days * 86400 + hh:mm:ss
    imul rax, rax, 86400
    imul rcx, r13, 3600
    add rax, rcx
    imul rcx, r14, 60
    add rax, rcx
    add rax, r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; .num2(rdi=ptr) -> eax = two-digit value, or -1 if either byte is not a digit
.num2:
    movzx eax, byte [rdi]
    sub eax, '0'
    cmp eax, 9
    ja .num_bad
    movzx ecx, byte [rdi + 1]
    sub ecx, '0'
    cmp ecx, 9
    ja .num_bad
    imul eax, eax, 10
    add eax, ecx
    ret
.num_bad:
    mov eax, -1
    ret
