; Broken-down UTC time, shared by the log stamp and HTTP dates.

struc linnea_tm
    .year:   resq 1    ; e.g. 2026
    .month:  resq 1    ; 1-12
    .day:    resq 1    ; 1-31
    .hour:   resq 1    ; 0-23
    .min:    resq 1    ; 0-59
    .sec:    resq 1    ; 0-59
    .wday:   resq 1    ; 0 = Sunday
endstruc

; "Sun, 06 Nov 1994 08:49:37 GMT" — the only date format HTTP sends on the
; wire nowadays, and the only one linnea writes.
LINNEA_HTTP_DATE_LEN    equ 29
