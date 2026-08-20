; HPACK (RFC 7541) decoder interface for the HTTP/2 request path (M16).
;
; The decoder runs with SETTINGS_HEADER_TABLE_SIZE = 0 advertised to the
; peer, so the dynamic table is always empty: indexed references only ever
; hit the 61-entry static table, and literal-with-incremental-indexing
; fields are parsed but never stored. That makes the decoder stateless
; across header blocks — no per-connection HPACK context is needed.
;
; linnea_hpack_decode(rdi = block ptr, rsi = block len, rdx = *linnea_h2_req)
;   -> rax = 0 on success, negative on a decoding error.
; The caller zeroes the struct and sets .scratch / .scratch_end to a
; writable region (Huffman-decoded literals land there). Decoded field
; pointers reference the input block, the rodata static blob, or scratch —
; all valid until the caller finishes building the response.

; --- decoder dynamic table (RFC 7541 2.3.2) -------------------------------
; We advertise SETTINGS_HEADER_TABLE_SIZE = 0, but that only binds the peer
; once it has PROCESSED our SETTINGS. Until then it may index up to the
; protocol default of 4096 bytes — and a client that opens several streams at
; once (a page load, or parallel API calls) routinely does, referencing
; entries it inserted on an earlier request of the same connection. Without a
; table those references are undecodable, which cost a GOAWAY and every
; in-flight request with it. So the decoder keeps one: entries are copied into
; a per-connection arena, oldest evicted first, and an index of 62 + i selects
; the i-th newest (RFC 7541 2.3.3).
LINNEA_HPACK_DYN_CAP    equ 4096   ; arena bytes = the protocol default size
LINNEA_HPACK_DYN_MAX    equ 128    ; entries (each costs >= 32 by RFC 7541 4.1)

struc linnea_hpack_dyn
    .count:   resq 1               ; live entries
    .head:    resq 1               ; slot index of the newest entry
    .size:    resq 1               ; RFC 7541 4.1 size of the live entries
    .max:     resq 1               ; the peer's current table size limit
    .used:    resq 1               ; arena bytes in use (append cursor)
    .gen:     resq 1               ; connection incarnation this belongs to
    .off:     resq LINNEA_HPACK_DYN_MAX     ; per entry: arena offset,
    .nlen:    resq LINNEA_HPACK_DYN_MAX     ; name length,
    .vlen:    resq LINNEA_HPACK_DYN_MAX     ; value length
    .arena:   resb LINNEA_HPACK_DYN_CAP
endstruc

; Bounds (HPACK-bomb / resource guards).
LINNEA_HPACK_MAX_HEADERS   equ 128    ; total fields in one block
LINNEA_HPACK_MAX_LISTSIZE  equ 8192   ; sum of (name+value+32) per RFC 7541 4.1

; Error codes (returned negated in rax).
LINNEA_HPACK_ERR           equ 1      ; malformed field / truncated
LINNEA_HPACK_ERR_INDEX     equ 2      ; index out of range (no dynamic table)
LINNEA_HPACK_ERR_HUFFMAN   equ 3      ; bad Huffman padding / EOS
LINNEA_HPACK_ERR_LIMIT     equ 4      ; header-list or count bound exceeded
; A semantically malformed REQUEST (RFC 9113 8.3 / RFC 9114 4.3.1): a repeated
; or misplaced pseudo-header, an unknown one, a Host that contradicts
; :authority, a missing or implausible authority. The field block decoded
; cleanly — the compression state is fine — so this ends the STREAM, not the
; connection, unlike every other error here.
LINNEA_HPACK_ERR_MALFORMED equ 5

; .pseudo_seen bits
LINNEA_H2_PS_METHOD equ 1
LINNEA_H2_PS_PATH   equ 2
LINNEA_H2_PS_SCHEME equ 4
LINNEA_H2_PS_AUTH   equ 8

struc linnea_h2_req
    .method_ptr:  resq 1
    .method_len:  resq 1
    .path_ptr:    resq 1
    .path_len:    resq 1
    .scheme_ptr:  resq 1
    .scheme_len:  resq 1
    .auth_ptr:    resq 1        ; :authority, or Host as a fallback
    .auth_len:    resq 1
    ; Pseudo-header bookkeeping (RFC 9113 8.3): which ones have been seen (a
    ; repeat is malformed), and whether a regular field has appeared yet (a
    ; pseudo-header after one is malformed). Zeroed with the rest of the struct.
    .pseudo_seen: resq 1        ; bitmask, LINNEA_H2_PS_*
    .regular_seen: resq 1       ; 1 once a non-pseudo field has been decoded
    .host_ptr:    resq 1        ; the Host field itself, kept apart from
    .host_len:    resq 1        ; .auth_ptr so the two can be compared
    .host_count:  resq 1        ; Host field lines (more than one is malformed)
    .malformed:   resq 1        ; 1 = the request breaks a semantic rule, so
                                ; the STREAM fails; the field block itself
                                ; decoded, leaving the connection usable
    .nheaders:    resq 1        ; fields decoded (bound guard)
    .listsize:    resq 1        ; running RFC 7541 4.1 size (bound guard)
    .scratch:     resq 1        ; bump cursor for Huffman output
    .scratch_end: resq 1        ; end of the scratch region
    .prio_ptr:    resq 1        ; the `priority` field value (RFC 9218), 0 if absent
    .prio_len:    resq 1
    ; if-none-match and if-match carry entity-tag LISTS, and repeated field
    ; lines are the comma-joined value (RFC 9110 5.3). Each line is kept as its
    ; own span and they are tried in turn, which is the same answer as joining
    ; them without copying anything -- the shape Accept-Encoding has had on the
    ; HTTP/1 side since h1-14. Overwriting one span meant the LAST line decided,
    ; where HTTP/1 let the FIRST decide: the same request was 304 on one
    ; protocol and 200 on another, and reversing the client's two lines swapped
    ; which protocol was right (audit-report-30). Three spans is far more than a
    ; real client sends. A FOURTH is refused rather than dropped: discarding a
    ; legal list member changes the answer to a conditional request and does it
    ; silently, so a matching tag on the fourth line became a 200 where a 304
    ; was due, or a 412 on a request that had to pass (audit-report-31). The
    ; fourth sets .etag_over and the request is answered 431 -- refused, not
    ; silently shortened, and refused the same way on all three protocols.
    ; HTTP/1 does the same, though it alone could re-walk its head: none of the
    ; three can re-walk a DECODED field section -- the QPACK/HPACK dynamic table
    ; has moved on -- so the policy is set by the two that cannot, rather than
    ; letting the protocols disagree again in the tail (audit-report-30).
    .inm_ptr:     resq 1        ; if-none-match spans; .inm_n is the count
    .inm_len:     resq 1
    .inm_ptr2:    resq 1
    .inm_len2:    resq 1
    .inm_ptr3:    resq 1
    .inm_len3:    resq 1
    .inm_n:       resq 1
    .ims_ptr:     resq 1        ; if-modified-since value, 0 if absent
    .ims_len:     resq 1
    .ifm_ptr:     resq 1        ; if-match spans; .ifm_n is the count
    .ifm_len:     resq 1
    .ifm_ptr2:    resq 1
    .ifm_len2:    resq 1
    .ifm_ptr3:    resq 1
    .ifm_len3:    resq 1
    .ifm_n:       resq 1
    ; 1 when either list carried more lines than there are spans. The decode is
    ; NOT aborted for it: stopping mid-block would leave the HPACK dynamic table
    ; behind the peer's and cost the whole connection, where the request itself
    ; is merely one we will not answer. The serve path reads this before it does
    ; anything else and returns 431.
    .etag_over:   resq 1
    .ius_ptr:     resq 1        ; if-unmodified-since value, 0 if absent
    .ius_len:     resq 1
    .rng_ptr:     resq 1        ; range value, 0 if absent
    .rng_len:     resq 1
    .ifr_ptr:     resq 1        ; if-range value, 0 if absent
    .ifr_len:     resq 1
    ; accept-encoding is list-valued too, so repeated field lines are the
    ; comma-joined value and a coding is acceptable if ANY line accepts it
    ; (RFC 9110 5.3). Keeping one span meant the LAST line decided, so
    ; `Accept-Encoding: br` then `Accept-Encoding: identity` served the plain
    ; file here while HTTP/1 -- which has kept a span per line since h1-14 --
    ; served the .br variant. Found beside audit-report-32, and the same defect
    ; report 30 fixed for the entity-tag lists, on the very field whose
    ; treatment report 30 cited as the precedent. Ignoring a fourth line can
    ; only narrow what is served, never answer wrongly, so it is ignored here
    ; exactly as HTTP/1 ignores it.
    .ae_ptr:      resq 1        ; accept-encoding spans; .ae_n is the count
    .ae_len:      resq 1
    .ae_ptr2:     resq 1
    .ae_len2:     resq 1
    .ae_ptr3:     resq 1
    .ae_len3:     resq 1
    .ae_n:        resq 1
    ; Header rebuild for proxying: when .hb_start is nonzero, emit_field
    ; appends every forwardable field as an h1 "name: value\r\n" line at
    ; .hb_cur (bounded by .hb_end; overflow parks .hb_cur past .hb_end).
    ; Pseudo-headers and hop-by-hop/managed fields are skipped: connection,
    ; keep-alive, transfer-encoding, upgrade, te, proxy-connection, host
    ; (rewritten from :authority) and content-length (rewritten from the
    ; actual collected body).
    .hb_start:    resq 1
    .hb_end:      resq 1
    .hb_cur:      resq 1
    .cl_ptr:      resq 1        ; content-length value, 0 if absent (the
    .cl_len:      resq 1        ; proxy path forwards it and streams the body)
    ; ...and what those bytes mean, parsed ONCE by linnea_string_to_u64 while
    ; the field section decodes (audit-report-5 Finding 1). Meaningful only when
    ; .cl_ptr is nonzero: a value that is not a plain in-range decimal number,
    ; or a SECOND content-length line, never gets here at all -- emit_field
    ; marks the request .malformed instead, so h2 and h3 both fail the stream
    ; before routing rather than each re-parsing the text their own way.
    .cl_val:      resq 1
    ; Split cookie fields are accumulated rather than rebuilt one line each
    ; (RFC 9113 8.2.3, Finding 32): the joined "v1; v2; ..." value grows in the
    ; buffer .ck_buf points at (0 = not the proxy path, no accumulation) and
    ; .ck_len tracks it (0 = no cookie field seen yet; -1 = overflowed the buffer).
    .ck_buf:      resq 1
    .ck_len:      resq 1
    ; Set when the request carried "expect: 100-continue" (RFC 9110 10.1.1,
    ; Finding 33): the proxy path emits a local interim 100 before collecting the
    ; body, and the field is stripped from the upstream request.
    .expect_100:  resq 1
    .dyn:         resq 1        ; *linnea_hpack_dyn for this connection, or 0
                                ; (QPACK passes 0: HTTP/3 has its own table
                                ; encoding, and we advertise zero capacity)
endstruc
