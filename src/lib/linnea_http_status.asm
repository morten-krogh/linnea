; ============================================================================
; linnea_http_status.asm -- status-code predicates shared by every protocol.
;
; Split out of linnea_http.asm so the BACKEND h2 leg can ask the same question
; the h1 leg asks. linnea_h2_client.asm is linked into a standalone harness
; (bin/linnea-h2client) that must not drag in the server, so the rule could not
; simply be called where it lived -- and copying it would have made a FOURTH
; copy of a list that has already disagreed with itself once
; (audit-report-10 Finding 1, quoted below).
; ============================================================================

global linnea_http_status_no_content

section .text

; linnea_http_status_no_content(edi = status) -> eax = 1 when a response with
; this status carries no content at all.
; RFC 9110: 1xx and 204 (6.4.1), 205 (15.3.6 -- "the server MUST NOT generate
; content in a 205 response"), 304 (15.4.5). A HEAD is the caller's business:
; that depends on the request, not on the status.
;
; This is NOT linnea_http_status_no_clen, and the difference is the whole of
; audit-report-10 Finding 1. That one answers "may this response carry a
; Content-Length FIELD"; this one answers "may it carry CONTENT". They genuinely
; disagree on 205: it may carry a Content-Length, but only to say zero. All
; three framing paths listed HEAD/204/304 and omitted 205 -- easy to miss
; precisely because report 9's predicate looked like it already covered it.
; Touches only eax, so a caller may treat it as clobbering nothing else.
linnea_http_status_no_content:
    xor eax, eax
    cmp edi, 100
    jb .nn_ret
    cmp edi, 199
    jbe .nn_yes
    cmp edi, 204
    je .nn_yes
    cmp edi, 205
    je .nn_yes
    cmp edi, 304
    jne .nn_ret
.nn_yes:
    mov eax, 1
.nn_ret:
    ret
