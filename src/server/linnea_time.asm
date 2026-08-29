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
global linnea_time_http_now

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

; linnea_time_http_now() -> rax = pointer to the current time as an IMF-fixdate
; (LINNEA_HTTP_DATE_LEN bytes, no NUL) — the Date header's value. The text is
; reformatted only when the second changes, so a burst of responses within one
; second pays for one clock_gettime each and one formatting in total.
linnea_time_http_now:
    sub rsp, 24                ; timespec (16) + alignment
    mov edi, LINNEA_CLOCK_REALTIME
    mov rsi, rsp
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    syscall
    mov rdi, [rsp]             ; seconds
    cmp rdi, [now_date_sec]
    je .cached
    mov [now_date_sec], rdi
    lea rsi, [now_date_buf]
    call linnea_time_http_date
.cached:
    lea rax, [now_date_buf]
    add rsp, 24
    ret

; linnea_time_parse_http_date(rdi=ptr, rsi=len) -> rax = unix seconds, or -1
;
; RFC 9110 5.6.7 MUST: "A recipient that parses a timestamp value in an HTTP
; field MUST accept all three HTTP-date formats." Only IMF-fixdate was accepted;
; the two obsolete forms parsed as invalid, so a conditional request carrying one
; was answered unconditionally — a client with a valid cached copy got the whole
; body back instead of a 304.
;
;   IMF-fixdate  Sun, 06 Nov 1994 08:49:37 GMT   (what we send, and what
;                                                 everything modern sends)
;   RFC 850      Sunday, 06-Nov-94 08:49:37 GMT  (two-digit year)
;   asctime      Sun Nov  6 08:49:37 1994        (space-padded day, no zone)
;
; The obsolete forms are rewritten into an IMF-shaped scratch buffer and parsed
; by the same code, so there is one date parser rather than three.
linnea_time_parse_http_date:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp rsi, LINNEA_HTTP_DATE_LEN
    jne .obsolete
    cmp byte [rdi + 3], ','
    jne .obsolete
    mov rbx, rdi
    jmp .imf
.obsolete:
    call .normalise            ; -> rax = 1 and date_scratch filled, or 0
    test eax, eax
    jz .bad
    lea rbx, [date_scratch]
.imf:
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
    ; RFC 9110 gives the date components the same semantics as RFC 5322
    ; section 3.3: the day has to exist in the named month of this year.  The
    ; 1..31 check above is necessary but not sufficient -- passing (for
    ; example) 29 Feb 2099 into days_from_civil turns it into a March day and
    ; lets an invalid conditional date affect the response.
    mov eax, 31
    cmp ecx, 2
    je .calendar_feb
    cmp ecx, 4
    je .calendar_30
    cmp ecx, 6
    je .calendar_30
    cmp ecx, 9
    je .calendar_30
    cmp ecx, 11
    jne .calendar_check
.calendar_30:
    mov eax, 30
    jmp .calendar_check
.calendar_feb:
    ; Leap years are divisible by 4, except century years unless divisible by
    ; 400.  Divide rather than rely on a table so the same small rule covers
    ; every four-digit HTTP year.
    mov eax, r8d
    xor edx, edx
    mov r9d, 4
    div r9d
    test edx, edx
    jnz .calendar_28
    mov eax, r8d
    xor edx, edx
    mov r9d, 100
    div r9d
    test edx, edx
    jnz .calendar_29
    mov eax, r8d
    xor edx, edx
    mov r9d, 400
    div r9d
    test edx, edx
    jnz .calendar_28
.calendar_29:
    mov eax, 29
    jmp .calendar_check
.calendar_28:
    mov eax, 28
.calendar_check:
    cmp r12d, eax
    ja .bad
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

; .normalise(rdi = ptr, rsi = len) -> eax = 1 with date_scratch holding an
; IMF-fixdate rendering of an obsolete timestamp, or 0 if it is neither form.
; The weekday is copied through without checking: the IMF parse never validates
; it either, and 5.6.7 says a recipient "MUST ignore" a weekday that disagrees
; with the date.
.normalise:
    ; asctime first: a fixed 24 bytes, "Www Mmm DD HH:MM:SS YYYY", no zone
    cmp rsi, 24
    jne .n_rfc850
    cmp byte [rdi + 3], ' '
    jne .n_rfc850
    cmp byte [rdi + 7], ' '
    jne .n_rfc850
    cmp byte [rdi + 10], ' '
    jne .n_rfc850
    cmp byte [rdi + 19], ' '
    jne .n_rfc850
    lea rsi, [date_scratch]
    mov eax, [rdi]             ; weekday, 3 bytes (the 4th is overwritten below)
    mov [rsi], eax
    mov word [rsi + 3], ', '
    mov al, [rdi + 8]          ; day, space-padded in this form
    cmp al, ' '
    jne .n_asc_day
    mov al, '0'
.n_asc_day:
    mov [rsi + 5], al
    mov al, [rdi + 9]
    mov [rsi + 6], al
    mov byte [rsi + 7], ' '
    mov eax, [rdi + 4]         ; month name
    mov [rsi + 8], al
    shr eax, 8
    mov [rsi + 9], al
    shr eax, 8
    mov [rsi + 10], al
    mov byte [rsi + 11], ' '
    mov eax, [rdi + 20]        ; year, four digits
    mov [rsi + 12], eax
    mov byte [rsi + 16], ' '
    mov rax, [rdi + 11]        ; HH:MM:SS
    mov [rsi + 17], rax
    mov byte [rsi + 25], ' '
    mov dword [rsi + 26], 'GMT'    ; writes a fourth byte, inside the buffer
    mov eax, 1
    ret
.n_rfc850:
    ; "Weekday, DD-Mon-YY HH:MM:SS GMT" — the weekday is spelled out, so the
    ; only fixed part is the 22 bytes after the comma and space.
    cmp rsi, 3
    jbe .n_no
    mov rcx, rsi
    xor edx, edx               ; index of the comma
.n_comma:
    cmp rdx, rcx
    jae .n_no
    cmp byte [rdi + rdx], ','
    je .n_comma_found
    inc rdx
    jmp .n_comma
.n_comma_found:
    cmp rdx, 3                 ; a weekday name is at least three letters
    jb .n_no
    lea r8, [rdx + 2]          ; -> the day-of-month digits
    mov r9, rsi
    sub r9, r8
    cmp r9, 22                 ; "06-Nov-94 08:49:37 GMT"
    jne .n_no
    cmp byte [rdi + rdx + 1], ' '
    jne .n_no
    add r8, rdi                ; absolute pointer to "DD-Mon-YY ..."
    cmp byte [r8 + 2], '-'
    jne .n_no
    cmp byte [r8 + 6], '-'
    jne .n_no
    cmp byte [r8 + 9], ' '
    jne .n_no
    lea rsi, [date_scratch]
    mov eax, [rdi]             ; the first three letters of the weekday name
    mov [rsi], eax
    mov word [rsi + 3], ', '
    mov al, [r8]               ; day
    mov [rsi + 5], al
    mov al, [r8 + 1]
    mov [rsi + 6], al
    mov byte [rsi + 7], ' '
    mov al, [r8 + 3]           ; month name
    mov [rsi + 8], al
    mov al, [r8 + 4]
    mov [rsi + 9], al
    mov al, [r8 + 5]
    mov [rsi + 10], al
    mov byte [rsi + 11], ' '
    push rsi
    push r8
    lea rdi, [r8 + 7]          ; the two YEAR digits, not the day's
    call .century              ; -> eax = the century to prefix, e.g. 1900/2000
    pop r8
    pop rsi
    ; write the four-digit year: century + the two digits as they stand
    mov ecx, eax
    mov eax, ecx
    xor edx, edx
    mov r9d, 1000
    div r9d                    ; thousands
    add al, '0'
    mov [rsi + 12], al
    mov eax, edx
    xor edx, edx
    mov r9d, 100
    div r9d                    ; hundreds
    add al, '0'
    mov [rsi + 13], al
    mov al, [r8 + 7]           ; the two digits the timestamp carried
    mov [rsi + 14], al
    mov al, [r8 + 8]
    mov [rsi + 15], al
    mov byte [rsi + 16], ' '
    mov rax, [r8 + 10]         ; HH:MM:SS
    mov [rsi + 17], rax
    mov byte [rsi + 25], ' '
    mov dword [rsi + 26], 'GMT'
    mov eax, 1
    ret
.n_no:
    xor eax, eax
    ret

; .century(rdi = pointer to the two year digits) -> eax = the century to prefix.
;
; 5.6.7: a two-digit year "that appears to be more than 50 years in the future"
; means the most recent past year with those digits. So the same century as now,
; stepped back one if that lands too far ahead. The current year is taken from
; the epoch seconds directly — a division by the mean year length is a day or so
; out at a new year, and the boundary it feeds is fifty years away.
;
; The digits are passed in rather than read at a fixed offset from the timestamp:
; the first cut of this read the DAY of the month instead, so "06-Nov-94" was
; windowed on 06, kept the current century and became 2094 — a date in the
; future, which turned an If-Modified-Since for 1994 into a 304.
.century:
    push rbx
    push r12
    mov r12, rdi
    sub rsp, 16
    mov qword [rsp], 0
    mov qword [rsp + 8], 0
    mov edi, 0                 ; CLOCK_REALTIME
    mov rsi, rsp
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    syscall
    mov rax, [rsp]
    xor edx, edx
    mov rcx, 31556952          ; mean tropical year, in seconds
    div rcx
    add rax, 1970              ; current year, near enough for a 50-year window
    mov ebx, eax
    xor edx, edx
    mov ecx, 100
    div ecx
    imul eax, eax, 100         ; the current century, e.g. 2000
    ; year = century + digits; step back a century if that is >50 years ahead
    movzx ecx, byte [r12]
    sub ecx, '0'
    imul ecx, ecx, 10
    movzx edx, byte [r12 + 1]
    sub edx, '0'
    add ecx, edx               ; the two digits as a number
    add ecx, eax               ; candidate year
    lea edx, [rbx + 50]
    cmp ecx, edx
    jbe .cent_done
    sub eax, 100
.cent_done:
    add rsp, 16
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

section .bss
; an obsolete timestamp, rewritten into IMF-fixdate shape (+3 slack for the
; four-byte 'GMT' store)
date_scratch:   resb 32
now_date_sec: resq 1                  ; the second now_date_buf was formatted for
now_date_buf: resb LINNEA_HTTP_DATE_LEN
