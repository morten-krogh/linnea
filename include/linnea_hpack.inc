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

struc linnea_h2_req
    .method_ptr:  resq 1
    .method_len:  resq 1
    .path_ptr:    resq 1
    .path_len:    resq 1
    .scheme_ptr:  resq 1
    .scheme_len:  resq 1
    .auth_ptr:    resq 1        ; :authority, or Host as a fallback
    .auth_len:    resq 1
    .nheaders:    resq 1        ; fields decoded (bound guard)
    .listsize:    resq 1        ; running RFC 7541 4.1 size (bound guard)
    .scratch:     resq 1        ; bump cursor for Huffman output
    .scratch_end: resq 1        ; end of the scratch region
    .prio_ptr:    resq 1        ; the `priority` field value (RFC 9218), 0 if absent
    .prio_len:    resq 1
    .inm_ptr:     resq 1        ; if-none-match value, 0 if absent
    .inm_len:     resq 1
    .ims_ptr:     resq 1        ; if-modified-since value, 0 if absent
    .ims_len:     resq 1
    .rng_ptr:     resq 1        ; range value, 0 if absent
    .rng_len:     resq 1
    .ifr_ptr:     resq 1        ; if-range value, 0 if absent
    .ifr_len:     resq 1
    .ae_ptr:      resq 1        ; accept-encoding value, 0 if absent
    .ae_len:      resq 1
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
    .dyn:         resq 1        ; *linnea_hpack_dyn for this connection, or 0
                                ; (QPACK passes 0: HTTP/3 has its own table
                                ; encoding, and we advertise zero capacity)
endstruc
