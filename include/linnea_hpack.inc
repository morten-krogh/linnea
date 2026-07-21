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
endstruc
