; linnea_rtxtest.asm — 1-RTT loss-recovery unit tests. Exercises the sent-packet
; ring (record / ack-range / inflight) and the ACK-frame range decoder in
; isolation, then the two together: buffer some packets, decode a real ACK, and
; confirm exactly the acknowledged ones are released. Prints "quic-rtx
; <pass>/<total>" and exits 1 on any failure.

default rel

%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"

global _start

extern linnea_quic_rtx_record
extern linnea_quic_rtx_ack_range
extern linnea_quic_rtx_inflight
extern linnea_quic_txchunk_record
extern linnea_quic_txchunk_ack
extern linnea_quic_txchunk_clear
extern linnea_quic_flow_scan
extern linnea_quic_parse_priority
extern linnea_quic_tp_parse
extern linnea_quic_tp_error
extern linnea_quic_ack_ranges
extern linnea_quic_ack_record
extern linnea_quic_ack_seen
extern linnea_quic_rtt_sample
extern linnea_quic_pto_ms
extern linnea_quic_frame_skip
extern linnea_quic_frames_check
extern linnea_quic_reset_scan
extern linnea_quic_path_seen
extern linnea_quic_path_data
extern linnea_print_stdout
extern linnea_print_u64_stdout

; EXPECT actual_reg, value — tally into r14d (total) / r15d (pass).
%macro EXPECT 2
    inc r14d
    mov r11, %2
    cmp %1, r11
    jne %%bad
    inc r15d
%%bad:
%endmacro

%macro EXPECT_ABOVE 2                   ; tally a "greater than" expectation
    inc r14d
    mov r11, %2
    cmp %1, r11
    jbe %%bad
    inc r15d
%%bad:
%endmacro

section .rodata
pay:       db "hello"
pay_len    equ $ - pay
; PADDING, PING, then an ACK: Largest=7, Delay=0, RangeCount=1, FirstRange=2
; (covers 5..7), then one range with Gap=0, Length=0 (covers 3). Two ranges out.
ackframe:  db 0x00, 0x01, 0x02, 0x07, 0x00, 0x01, 0x02, 0x00, 0x00
ackframe_len equ $ - ackframe
; the same ACK, but coalesced BEHIND a NEW_CONNECTION_ID and a MAX_DATA — as a
; real browser sends it. ack_ranges must skip past them to the ACK, or the
; in-flight chunks are never freed and the response stalls with its window full.
ackframe_ncid: db 0x18, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD
               db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
               db 0x10, 0x41, 0x2C
               db 0x02, 0x07, 0x00, 0x01, 0x02, 0x00, 0x00
ackframe_ncid_len equ $ - ackframe_ncid
; RFC 9000 19.3.1 underflow: a First ACK Range larger than Largest Acknowledged
; puts the smallest below packet 0. Largest=3, Delay=0, RangeCount=0, First=5.
ack_uf_first:  db 0x02, 0x03, 0x00, 0x00, 0x05
ack_uf_first_len equ $ - ack_uf_first
; ...and the same underflow hidden in a LATER pair (the Q135 guard saw only
; pair 0): a valid first range [7,7], then Gap=10 drives the next largest
; (7 - 10 - 2) below zero.
ack_uf_gap:    db 0x02, 0x07, 0x00, 0x01, 0x00, 0x0A, 0x00
ack_uf_gap_len equ $ - ack_uf_gap
; a legal two-pair ACK whose SECOND pair sits right at the boundary — proves the
; guard does not reject valid ranges. Largest=7, First=0 ([7,7]); Gap=4,
; Length=1: next largest = 7-4-2 = 1, smallest = 0, so [0,1]. Nothing underflows.
ack_boundary:  db 0x02, 0x07, 0x00, 0x01, 0x00, 0x04, 0x01
ack_boundary_len equ $ - ack_boundary
; flow_scan must reach flow-control credit bundled behind other frames, as a real
; browser sends it. NEW_CONNECTION_ID(seq 1, retire 0, cid len 4, 16-byte token),
; then MAX_DATA=300 (0x412c), then MAX_STREAM_DATA(stream 0)=500 (0x41f4).
fs_ncid:   db 0x18, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD
           db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
           db 0x10, 0x41, 0x2C
           db 0x11, 0x00, 0x41, 0xF4
fs_ncid_len equ $ - fs_ncid
; MAX_STREAMS bidi=16, a STREAM|LEN frame (stream 3, 2 bytes of data), then
; MAX_STREAM_DATA(stream 4)=700 (0x42bc) — credit behind a data-carrying frame.
fs_stream: db 0x12, 0x10
           db 0x0A, 0x03, 0x02, 0xAB, 0xCD
           db 0x11, 0x04, 0x42, 0xBC
fs_stream_len equ $ - fs_stream
; RFC 9218 priority field values (u = urgency 0-7, i = incremental)
prio_ui:   db "u=1, i"
prio_ui_len equ $ - prio_ui
prio_u5:   db "u=5"
prio_u5_len equ $ - prio_u5
prio_i0:   db "i=?0, u=2"
prio_i0_len equ $ - prio_i0
prio_bare_i: db "i"
prio_bare_i_len equ $ - prio_bare_i
prio_bad:  db "u=9"                   ; out of range: falls back to the default
prio_bad_len equ $ - prio_bad
; audit-report-81's three examples, measured rather than assumed
prio_7x:   db "u=7x"                  ; digits that do not end the member
prio_7x_len equ $ - prio_7x
prio_dup:  db "u=1,u=5"               ; a repeated key: RFC 8941 4.2.2, last wins
prio_dup_len equ $ - prio_dup
prio_i2:   db "i=?2"                  ; ?2 is not an RFC 8941 boolean
prio_i2_len equ $ - prio_i2
prio_dupi: db "i,i=?0"                ; ...and the same for the boolean key
prio_dupi_len equ $ - prio_dupi
prio_ikey: db "important=1"           ; an unknown key that merely starts with i
prio_ikey_len equ $ - prio_ikey
prio_ix:   db "i=x"                   ; not a boolean at all
prio_ix_len equ $ - prio_ix
prio_i1x:  db "i=?1x"                 ; a boolean that does not end the member
prio_i1x_len equ $ - prio_i1x
prio_i0i2: db "i=?0,i=?2"             ; an explicit off, then an invalid member
prio_i0i2_len equ $ - prio_i0i2
prio_ipar: db "i;q=1"                 ; bare i carrying an 8941 parameter
prio_ipar_len equ $ - prio_ipar
prio_i1par: db "i=?1;q=2"             ; ...and the same on the explicit form
prio_i1par_len equ $ - prio_i1par
; audit-report-82: OWS beside a comma is SP *or HTAB* (8941's ABNF imports OWS
; from 7230), while the edges of the value take SP only, and a value that does
; not parse is ignored WHOLE (8941 4.2).
prio_tabsep: db "u=7", 9, "i"         ; two members, no comma: a parse failure
prio_tabsep_len equ $ - prio_tabsep
prio_tabows: db "u=7", 9, ",i"        ; HTAB before the comma: legal OWS
prio_tabows_len equ $ - prio_tabows
prio_owstab: db "u=7,", 9, "i"        ; HTAB after the comma: legal OWS
prio_owstab_len equ $ - prio_owstab
prio_tablead: db 9, "u=7"             ; a leading HTAB: the edges take SP only
prio_tablead_len equ $ - prio_tablead
prio_splead: db " u=7"                ; ...and a leading SP is fine
prio_splead_len equ $ - prio_splead
prio_spsep: db "u=7 i"                ; the same failure with a space
prio_spsep_len equ $ - prio_spsep
prio_part:  db "u=1,u=7x"             ; a valid member, then a broken one
prio_part_len equ $ - prio_part
prio_parti: db "u=1,i=?2"             ; ...and with the boolean broken instead
prio_parti_len equ $ - prio_parti
prio_unk:   db "u=1,zz=3"             ; an UNKNOWN member leaves the rest alone
prio_unk_len equ $ - prio_unk
prio_range: db "u=1,u=9"              ; a repeated key takes the LAST value
prio_range_len equ $ - prio_range
prio_trail: db "u=1,"                 ; a trailing comma is a parse failure
prio_trail_len equ $ - prio_trail
; audit-report-83: a ";" introduces PARAMETERS, and they have a grammar too --
; ";" *SP key [ "=" bare-item ]. The key is checked; the value is skipped.
prio_pareq: db "u=7;="                ; "=" is not a key
prio_pareq_len equ $ - prio_pareq
prio_parq:  db "i;", 34               ; nor is a quote
prio_parq_len equ $ - prio_parq
prio_parsp: db "u=7;bad space"        ; a key, then a word with no separator
prio_parsp_len equ $ - prio_parsp
prio_parno: db "u=7;"                 ; a ";" with no parameter behind it
prio_parno_len equ $ - prio_parno
prio_pardup: db "u=7;;q=1"            ; an empty parameter
prio_pardup_len equ $ - prio_pardup
prio_parup: db "u=5;Q=1"              ; 8941 keys are lcalpha: "Q" is not one
prio_parup_len equ $ - prio_parup
prio_parnov: db "u=5;q="              ; "=" with no bare-item after it
prio_parnov_len equ $ - prio_parnov
prio_parok: db "u=5;q=1"              ; ...and the legal shapes
prio_parok_len equ $ - prio_parok
prio_parsp2: db "u=5; q=1"            ; 8941 allows SP after the ";"
prio_parsp2_len equ $ - prio_parsp2
prio_partwo: db "u=5;q=1;r=2"         ; two parameters
prio_partwo_len equ $ - prio_partwo
prio_parstar: db "u=5;*k=1"           ; a key may start with "*"
prio_parstar_len equ $ - prio_parstar
prio_parbare: db "u=5;a;b"            ; parameters with no value
prio_parbare_len equ $ - prio_parbare
prio_parstr: db "u=5;q=", 34, "x", 34 ; a value we do not interpret
prio_parstr_len equ $ - prio_parstr
; audit-report-84: a parameter's value is an RFC 8941 bare-item, and there are
; six forms. Skipping to a delimiter instead of parsing one accepted what is not
; an item AND refused what is: a string may hold a space, comma or semicolon.
prio_bunterm: db "u=7;foo=", 34, "unterminated"
prio_bunterm_len equ $ - prio_bunterm
prio_bslash: db "u=7;foo=", 92      ; a lone backslash is not an item
prio_bslash_len equ $ - prio_bslash
prio_bbool2: db "u=7;q=?2"          ; nor is "?2" a boolean
prio_bbool2_len equ $ - prio_bbool2
prio_bdot:  db "u=7;q=1."           ; a decimal needs digits after the dot
prio_bdot_len equ $ - prio_bdot
prio_bnodot: db "u=7;q=.5"          ; ...and before it
prio_bnodot_len equ $ - prio_bnodot
prio_b1a:   db "u=7;q=1a"           ; a number does not continue into a token
prio_b1a_len equ $ - prio_b1a
prio_bctl:  db "u=5;q=", 34, "a", 9, "b", 34   ; a control byte is not unescaped
prio_bctl_len equ $ - prio_bctl
prio_b16:   db "u=5;q=1234567890123456"        ; 16 digits: an integer takes 15
prio_b16_len equ $ - prio_b16
prio_bd13:  db "u=5;q=1234567890123.5"         ; a decimal takes 12 before the dot
prio_bd13_len equ $ - prio_bd13
prio_bf4:   db "u=5;q=1.2345"                  ; ...and 3 after it
prio_bf4_len equ $ - prio_bf4
; ...and the legal items, one of every form
prio_bsp:   db "u=5;q=", 34, "a b", 34         ; a STRING may hold a space
prio_bsp_len equ $ - prio_bsp
prio_bcomma: db "u=5;q=", 34, "a,b", 34, ",i"  ; ...or a comma, which is not a
prio_bcomma_len equ $ - prio_bcomma             ; separator inside one
prio_bsemi: db "u=5;q=", 34, "a;b", 34         ; ...or a semicolon
prio_bsemi_len equ $ - prio_bsemi
prio_besc:  db "u=5;q=", 34, "a", 92, 34, "b", 34   ; an escaped quote
prio_besc_len equ $ - prio_besc
prio_bempty: db "u=5;q=", 34, 34               ; the empty string
prio_bempty_len equ $ - prio_bempty
prio_bneg:  db "u=5;q=-0.5"                    ; a negative decimal
prio_bneg_len equ $ - prio_bneg
prio_b15:   db "u=5;q=123456789012345"         ; exactly 15 digits
prio_b15_len equ $ - prio_b15
prio_btok:  db "u=5;q=a:b/c"                   ; a token takes ":" and "/"
prio_btok_len equ $ - prio_btok
prio_bbin:  db "u=5;q=:aGVsbG8=:"              ; a byte sequence
prio_bbin_len equ $ - prio_bbin
prio_bbin0: db "u=5;q=::"                      ; ...which may be empty
prio_bbin0_len equ $ - prio_bbin0
; audit-reports 85/86: a repeated key is LEGAL -- 8941 4.2.3.2 step 7 overwrites
; it, exactly as 4.2.2 does for a repeated dictionary member. These are controls
; against a "fix" that would refuse them.
prio_dpar:  db "u=7;foo=1;foo=2"
prio_dpar_len equ $ - prio_dpar
prio_dpar2: db "u=7;foo=1;bar=2;foo=3"
prio_dpar2_len equ $ - prio_dpar2
; ...and an unknown MEMBER still has to parse, even though its meaning is
; ignored (audit-report-86 Finding 2).
prio_umbad: db "u=7,unknown=", 34, "unterminated"
prio_umbad_len equ $ - prio_umbad
prio_um1a:  db "u=7,zz=1a"           ; not a bare-item
prio_um1a_len equ $ - prio_um1a
prio_umno:  db "u=7,zz="             ; "=" with no value
prio_umno_len equ $ - prio_umno
prio_umb2:  db "u=7,zz=?2"           ; not a boolean
prio_umb2_len equ $ - prio_umb2
prio_umbare: db "u=7,zz"             ; ...and the legal shapes
prio_umbare_len equ $ - prio_umbare
prio_umpar: db "u=7,zz;a=1"          ; a bare member with parameters
prio_umpar_len equ $ - prio_umpar
prio_umstr: db "u=7,zz=", 34, "a,b", 34   ; a string holding a comma
prio_umstr_len equ $ - prio_umstr
prio_umlist: db "u=7,zz=(1 2);p=3"   ; an inner list: skipped, never refused
prio_umlist_len equ $ - prio_umlist
prio_umi:   db "u=7,zz=?1,i"         ; ...and the member after it still applies
prio_umi_len equ $ - prio_umi
; audit-report-87: an unknown member's INNER LIST is walked now, not skipped.
; inner-list = "(" *SP [ sf-item *( 1*SP sf-item ) *SP ] ")" parameters.
prio_ilunt: db "u=7,zz=(1 ", 34, "unterminated"   ; the report's own case
prio_ilunt_len equ $ - prio_ilunt
prio_ilnoc: db "u=7,zz=(1 2"         ; no closing paren
prio_ilnoc_len equ $ - prio_ilnoc
prio_ilcom: db "u=7,zz=(1,2)"        ; items are separated by SP, not commas
prio_ilcom_len equ $ - prio_ilcom
prio_ilbad: db "u=7,zz=(?2)"         ; an item that is not a bare-item
prio_ilbad_len equ $ - prio_ilbad
prio_ilnest: db "u=7,zz=((1))"       ; 8941 has no list inside a list
prio_ilnest_len equ $ - prio_ilnest
prio_ilpbad: db "u=7,zz=(1;a=?2)"    ; an item parameter that does not parse
prio_ilpbad_len equ $ - prio_ilpbad
prio_ilok:  db "u=7,zz=(1 2)"        ; ...and the legal shapes
prio_ilok_len equ $ - prio_ilok
prio_ilempty: db "u=7,zz=()"         ; an empty list is legal
prio_ilempty_len equ $ - prio_ilempty
prio_ilpad: db "u=7,zz=( 1 2 )"      ; *SP inside the parens
prio_ilpad_len equ $ - prio_ilpad
prio_il2sp: db "u=7,zz=(1  2)"       ; more than one space between items
prio_il2sp_len equ $ - prio_il2sp
prio_ilipar: db "u=7,zz=(1;a=2 3)"   ; an item carrying parameters
prio_ilipar_len equ $ - prio_ilipar
prio_ilstr: db "u=7,zz=(", 34, "a b", 34, " 2)"  ; a string item with a space
prio_ilstr_len equ $ - prio_ilstr
prio_illpar: db "u=7,zz=(1 2);p=3"   ; parameters on the LIST
prio_illpar_len equ $ - prio_illpar
prio_ilnext: db "u=7,zz=(1 2),i"     ; and the member after it still applies
prio_ilnext_len equ $ - prio_ilnext

; audit-report-88: RFC 9000 7.4 -- a parameter may not appear twice, and a
; receiver SHOULD close on one that does. Ids below 64 had a bitmap; the
; extension/GREASE space above it was not tracked at all. Each blob below is a
; transport-parameters extension: id varint, length varint, payload.
; 0x4040 is the two-byte varint for id 64, 0x4041 for 65.
tp_lowdup:  db 0x04, 0x01, 0x0f, 0x04, 0x01, 0x0f     ; 0x04 twice
tp_lowdup_len equ $ - tp_lowdup
tp_hidup:   db 0x04, 0x01, 0x0f, 0x40, 0x40, 0x01, 0xaa, 0x40, 0x40, 0x01, 0xaa
tp_hidup_len equ $ - tp_hidup                          ; id 64 twice
tp_hidup2:  db 0x40, 0x40, 0x01, 0xaa, 0x40, 0x41, 0x01, 0xbb, 0x40, 0x40, 0x01, 0xcc
tp_hidup2_len equ $ - tp_hidup2                        ; 64, 65, then 64 again
tp_hiok:    db 0x04, 0x01, 0x0f, 0x40, 0x40, 0x01, 0xaa, 0x40, 0x41, 0x01, 0xbb
tp_hiok_len equ $ - tp_hiok                            ; 64 and 65: different ids
tp_hione:   db 0x04, 0x01, 0x0f, 0x40, 0x40, 0x01, 0xaa
tp_hione_len equ $ - tp_hione                          ; one extension parameter
tp_plain:   db 0x04, 0x01, 0x0f, 0x05, 0x01, 0x0f
tp_plain_len equ $ - tp_plain                          ; two different low ids

; --- frame-length table fixtures (RFC 9000 19) ---
fk_pad:     db 0x00
fk_ping:    db 0x01
fk_hd:      db 0x1e
fk_pc:      db 0x1a, 1,2,3,4,5,6,7,8
fk_maxdata: db 0x10, 0x41, 0x2C                       ; MAX_DATA 300 (2-byte varint)
fk_reset:   db 0x04, 0x03, 0x01, 0x05                 ; RESET_STREAM, three varints
fk_close:   db 0x1c, 0x01, 0x00, 0x00                 ; transport close, empty reason
fk_closea:  db 0x1d, 0x01, 0x00                       ; application close
fk_stream:  db 0x0a, 0x03, 0x02, 0xAB, 0xCD           ; STREAM|LEN, sid 3, 2 bytes
fk_strnol:  db 0x08, 0x03, 0xAA, 0xBB, 0xCC           ; STREAM, no LEN: runs to the end
fk_ncid:    db 0x18, 0x01, 0x00, 0x04, 0xDE,0xAD,0xBE,0xEF
            db 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0       ; 16-byte reset token
fk_ack:     db 0x02, 0x07, 0x00, 0x01, 0x02, 0x00, 0x00
fk_ackecn:  db 0x03, 0x07, 0x00, 0x00, 0x02, 0x01, 0x02, 0x03
; ACK with three ranges: largest 10, delay 0, range count 2, first range 1,
; then two (gap, length) pairs. Browsers send multi-range ACKs routinely, and
; since a frame we mis-measure is now a connection error rather than a quiet
; stop, the walk over the ranges has to be exact.
fk_ack3:    db 0x02, 0x0a, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01
; CONNECTION_CLOSE carrying a reason phrase, which is the common shape
fk_closer:  db 0x1c, 0x01, 0x00, 0x02, 'n', 'o'
fk_unk:     db 0x22                                   ; not a type RFC 9000 defines
fk_trunc:   db 0x10                                   ; MAX_DATA with its varint missing
; a CONNECTION_CLOSE behind a STREAM frame, then MAX_DATA behind the close: the
; exact shape the partial per-scanner tables used to lose
fk_seq_ok:  db 0x01, 0x0a, 0x03, 0x02, 0xAB, 0xCD, 0x1c, 0x01, 0x00, 0x00, 0x10, 0x41, 0x2C
fk_seq_ok_len equ $ - fk_seq_ok
fk_seq_bad: db 0x01, 0x22, 0x10, 0x41, 0x2C           ; an unknown type in the middle
fk_seq_bad_len equ $ - fk_seq_bad
; a payload whose last frame is cut short: PING, then a MAX_DATA missing its
; varint. RFC 9000 12.4 makes that a connection error too — it used to stop the
; walk quietly, so everything behind it went unread while the packet was acked.
fk_seq_trunc: db 0x01, 0x10
fk_seq_trunc_len equ $ - fk_seq_trunc

msg_head:  db "quic-rtx "
msg_head_len equ $ - msg_head
msg_slash: db "/"
msg_nl:    db 10

; PATH_CHALLENGE (0x1a + 8 bytes) bundled behind PADDING and a PING, plus trailing
; PADDING: reset_scan must walk past the other frames and still capture it.
tf_pc:     db 0x00, 0x01, 0x1a, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, 0x00
tf_pc_len  equ $ - tf_pc
tf_nopc:   db 0x00, 0x01, 0x00      ; PADDING + PING + PADDING, no challenge
tf_nopc_len equ $ - tf_nopc

section .bss
conn:      resb linnea_quic_conn_size
pairs:     resb LINNEA_QUIC_ACK_MAXR * 16
flow_out:  resb 16                 ; [max_data, max_stream_data] from a flow scan
rid_out:   resq 16                 ; reset-stream ids (unused here; a valid dest)
as_state:  resq 3                  ; have / largest / mask — the whole receive window

section .text


; --- receive-window helpers: the three qwords linnea_quic_ack_record keeps ---
%macro AS_INIT 0
    mov qword [as_state], 0
    mov qword [as_state + 8], 0
    mov qword [as_state + 16], 0
%endmacro

%macro AS_REC 1                         ; note packet number %1 as received
    lea rdi, [as_state]
    mov rsi, %1
    call linnea_quic_ack_record
%endmacro

%macro EXPECT_SEEN 2                    ; ack_seen(%1) must answer %2
    lea rdi, [as_state]
    mov rsi, %1
    call linnea_quic_ack_seen
    EXPECT rax, %2
%endmacro


%macro RTT 1                            ; fold one round-trip sample, in ms
    lea rdi, [conn]
    mov rsi, %1
    call linnea_quic_rtt_sample
%endmacro

%macro PTO 1                            ; %1 = 1 to include the peer's max_ack_delay
    lea rdi, [conn]
    mov esi, %1
    call linnea_quic_pto_ms
%endmacro


%macro FSKIP 2                          ; %1 = fixture, %2 = bytes available
    lea rdi, [%1]
    lea rsi, [%1 + %2]
    call linnea_quic_frame_skip
%endmacro

; record one packet: rsi = pn, into conn with the shared payload at now = 0.
%macro RECORD 1
    lea rdi, [conn]
    mov rsi, %1
    lea rdx, [pay]
    mov ecx, pay_len
    xor r8d, r8d
    call linnea_quic_rtx_record
%endmacro

; free [lo, hi] from conn's ring.
%macro ACKRANGE 2
    lea rdi, [conn]
    mov rsi, %1
    mov rdx, %2
    call linnea_quic_rtx_ack_range
%endmacro

%macro INFLIGHT 0
    lea rdi, [conn]
    call linnea_quic_rtx_inflight
%endmacro

_start:
    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; pass

    ; --- three packets buffered ---
    RECORD 5
    RECORD 6
    RECORD 7
    INFLIGHT
    EXPECT rax, 3

    ; --- acking a sub-range releases only those ---
    ACKRANGE 6, 7
    INFLIGHT
    EXPECT rax, 1                     ; pn 5 remains
    ACKRANGE 5, 5
    INFLIGHT
    EXPECT rax, 0

    ; --- the ring is bounded: extra packets are simply not tracked ---
    xor r12d, r12d
.fill:
    lea rdi, [conn]
    lea rsi, [r12 + 100]             ; distinct packet numbers
    lea rdx, [pay]
    mov ecx, pay_len
    xor r8d, r8d
    call linnea_quic_rtx_record
    inc r12d
    cmp r12d, LINNEA_QUIC_RTX_SLOTS + 2
    jb .fill
    INFLIGHT
    EXPECT rax, LINNEA_QUIC_RTX_SLOTS
    ACKRANGE 0, -1                    ; release everything
    INFLIGHT
    EXPECT rax, 0

    ; --- a payload larger than a record is not tracked ---
    lea rdi, [conn]
    mov esi, 9
    lea rdx, [pay]
    mov ecx, LINNEA_QUIC_RTX_PAYLOAD + 1
    xor r8d, r8d
    call linnea_quic_rtx_record
    INFLIGHT
    EXPECT rax, 0

    ; --- ACK-frame decoding: two ranges, [5,7] and [3,3] ---
    lea rdi, [ackframe]
    mov esi, ackframe_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    EXPECT rax, 2
    mov rax, [pairs]
    EXPECT rax, 5                     ; pair 0 smallest
    mov rax, [pairs + 8]
    EXPECT rax, 7                     ; pair 0 largest
    mov rax, [pairs + 16]
    EXPECT rax, 3                     ; pair 1 smallest
    mov rax, [pairs + 24]
    EXPECT rax, 3                     ; pair 1 largest

    ; --- the same ACK behind NEW_CONNECTION_ID + MAX_DATA is still decoded ---
    lea rdi, [ackframe_ncid]
    mov esi, ackframe_ncid_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    EXPECT rax, 2                     ; both ranges reached past the leading frames
    mov rax, [pairs]
    EXPECT rax, 5
    mov rax, [pairs + 8]
    EXPECT rax, 7
    mov rax, [pairs + 16]
    EXPECT rax, 3
    mov rax, [pairs + 24]
    EXPECT rax, 3

    ; --- underflow: a First ACK Range past the largest is FRAME_ENCODING_ERROR ---
    lea rdi, [ack_uf_first]
    mov esi, ack_uf_first_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    EXPECT rax, -1                    ; the caller maps -1 to a connection close
    ; ...and an underflow buried in a later pair, not just pair 0
    lea rdi, [ack_uf_gap]
    mov esi, ack_uf_gap_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    EXPECT rax, -1
    ; ...while a legal two-pair ACK ending exactly at packet 0 is accepted
    lea rdi, [ack_boundary]
    mov esi, ack_boundary_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    EXPECT rax, 2
    mov rax, [pairs + 16]
    EXPECT rax, 0                     ; pair 1 smallest is exactly packet 0
    mov rax, [pairs + 24]
    EXPECT rax, 1                     ; pair 1 largest

    ; --- the two together: buffer 3,5,7; ingest the ACK; all released ---
    RECORD 3
    RECORD 5
    RECORD 7
    INFLIGHT
    EXPECT rax, 3
    lea rdi, [ackframe]
    mov esi, ackframe_len
    lea rdx, [pairs]
    mov ecx, LINNEA_QUIC_ACK_MAXR
    call linnea_quic_ack_ranges
    mov r12, rax                     ; pair count
    lea r13, [pairs]
.free:
    test r12, r12
    jz .freed
    lea rdi, [conn]
    mov rsi, [r13]
    mov rdx, [r13 + 8]
    call linnea_quic_rtx_ack_range
    add r13, 16
    dec r12
    jmp .free
.freed:
    INFLIGHT
    EXPECT rax, 0

    ; --- response-stream in-flight table (the congestion-controlled window) ---
    lea rdi, [conn]                 ; start clean
    call linnea_quic_txchunk_clear
    ; record two chunks; bytes_in_flight tracks their lengths
    lea rdi, [conn]
    mov esi, 40                     ; pn
    mov edx, 0                      ; offset
    mov ecx, 1100                   ; len
    xor r8d, r8d
    xor r9d, r9d                    ; stream index 0
    call linnea_quic_txchunk_record
    EXPECT rax, 1
    lea rdi, [conn]
    mov esi, 41
    mov edx, 1100
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    EXPECT rax, 1
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 2200
    ; ack the first chunk: returns its bytes, drops bytes_in_flight
    lea rdi, [conn]
    mov esi, 40
    mov edx, 40
    call linnea_quic_txchunk_ack
    EXPECT rax, 1100                ; bytes acknowledged
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 1100
    ; acking a pn not in flight frees nothing
    lea rdi, [conn]
    mov esi, 99
    mov edx, 99
    call linnea_quic_txchunk_ack
    EXPECT rax, 0
    ; clear zeroes bytes_in_flight
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 0

    ; --- retransmit, then a cumulative ack of the ORIGINAL pn must free the chunk.
    ; A resend moves .pn to a fresh number; QUIC acks are cumulative, so the peer
    ; keeps acking the delivered original. Matching only .pn would miss that ack and
    ; pin the window forever (the real-browser tail-chunk wedge). .pn0 fixes it.
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    lea rdi, [conn]
    mov esi, 40                     ; original pn
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    EXPECT rax, 1
    mov qword [conn + linnea_quic_conn.tx_infl + linnea_quic_txchunk.pn], 50 ; PTO resend
    lea rdi, [conn]                 ; ack covers the original (40), not the resend (50)
    mov esi, 38
    mov edx, 45
    call linnea_quic_txchunk_ack
    EXPECT rax, 1100                ; freed via .pn0
    mov rax, [conn + linnea_quic_conn.bytes_in_flight]
    EXPECT rax, 0
    ; symmetric case: an ack covering only the resend pn frees it via .pn
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    lea rdi, [conn]
    mov esi, 60
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    mov qword [conn + linnea_quic_conn.tx_infl + linnea_quic_txchunk.pn], 70
    lea rdi, [conn]
    mov esi, 68
    mov edx, 72
    call linnea_quic_txchunk_ack
    EXPECT rax, 1100
    ; a range covering neither the original nor the resend frees nothing
    lea rdi, [conn]
    call linnea_quic_txchunk_clear
    lea rdi, [conn]
    mov esi, 80
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    mov qword [conn + linnea_quic_conn.tx_infl + linnea_quic_txchunk.pn], 90
    lea rdi, [conn]
    mov esi, 100
    mov edx, 110
    call linnea_quic_txchunk_ack
    EXPECT rax, 0
    lea rdi, [conn]
    call linnea_quic_txchunk_clear

    ; the table is bounded: filling it, one more record is refused
    xor r12d, r12d
.tcfill:
    lea rdi, [conn]
    lea rsi, [r12 + 500]            ; distinct pns
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    inc r12d
    cmp r12d, LINNEA_QUIC_TXINFL_SLOTS
    jb .tcfill
    lea rdi, [conn]
    mov esi, 9000
    mov edx, 0
    mov ecx, 1100
    xor r8d, r8d
    xor r9d, r9d
    call linnea_quic_txchunk_record
    EXPECT rax, 0                    ; full: caller must wait for acks
    lea rdi, [conn]
    call linnea_quic_txchunk_clear

    ; --- flow_scan: credit bundled behind other frames must still be absorbed ---
    ; (the multi-image page stalled over the real internet because a browser sends
    ; MAX_DATA behind NEW_CONNECTION_ID / STREAM frames that the scan used to stop at)
    mov qword [flow_out], 0
    mov qword [flow_out + 8], 0
    lea rdi, [fs_ncid]
    mov esi, fs_ncid_len
    xor edx, edx                    ; our stream id = 0
    lea rcx, [flow_out]
    call linnea_quic_flow_scan
    mov rax, [flow_out]
    EXPECT rax, 300                 ; MAX_DATA reached past NEW_CONNECTION_ID
    mov rax, [flow_out + 8]
    EXPECT rax, 500                 ; MAX_STREAM_DATA(0) reached too
    ; credit behind MAX_STREAMS + a data-carrying STREAM frame
    mov qword [flow_out], 0
    mov qword [flow_out + 8], 0
    lea rdi, [fs_stream]
    mov esi, fs_stream_len
    mov edx, 4                       ; our stream id = 4
    lea rcx, [flow_out]
    call linnea_quic_flow_scan
    mov rax, [flow_out + 8]
    EXPECT rax, 700                 ; MAX_STREAM_DATA(4) reached past the STREAM frame
    ; MAX_STREAM_DATA for another stream is not credited to ours, MAX_DATA still is
    mov qword [flow_out], 0
    mov qword [flow_out + 8], 0
    lea rdi, [fs_ncid]
    mov esi, fs_ncid_len
    mov edx, 7                       ; a stream not named in the packet
    lea rcx, [flow_out]
    call linnea_quic_flow_scan
    mov rax, [flow_out + 8]
    EXPECT rax, 0                    ; MAX_STREAM_DATA(0) is not for stream 7
    mov rax, [flow_out]
    EXPECT rax, 300                 ; but the connection MAX_DATA is still absorbed

    ; --- RFC 9218 priority parse: urgency + incremental, with defaults ---
    lea rdi, [prio_ui]
    mov esi, prio_ui_len
    call linnea_quic_parse_priority     ; "u=1, i"
    EXPECT rax, 1
    EXPECT rdx, 1
    lea rdi, [prio_u5]
    mov esi, prio_u5_len
    call linnea_quic_parse_priority     ; "u=5" -> urgency 5, non-incremental
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_i0]
    mov esi, prio_i0_len
    call linnea_quic_parse_priority     ; "i=?0, u=2" -> urgency 2, incremental off
    EXPECT rax, 2
    EXPECT rdx, 0
    lea rdi, [prio_bare_i]
    mov esi, prio_bare_i_len
    call linnea_quic_parse_priority     ; bare "i" -> default urgency, incremental
    EXPECT rax, 3
    EXPECT rdx, 1
    lea rdi, [prio_bad]
    mov esi, prio_bad_len
    call linnea_quic_parse_priority     ; "u=9" out of range -> defaults
    EXPECT rax, 3
    EXPECT rdx, 0
    xor edi, edi                        ; no priority header (len 0) -> defaults
    xor esi, esi
    call linnea_quic_parse_priority
    EXPECT rax, 3
    EXPECT rdx, 0

    ; audit-report-81: the three values that report calls malformed. RFC 9218 4
    ; is explicit -- "unknown priority parameters, priority parameters with
    ; out-of-range values, or values of unexpected types MUST be ignored" -- so
    ; falling back to the default is the REQUIRED handling for the first and the
    ; third, not leniency. The middle one is not malformed at all: RFC 8941 4.2.2
    ; makes a repeated dictionary key legal, with the LAST value winning, and
    ; getting that backwards would be a real defect.
    lea rdi, [prio_7x]
    mov esi, prio_7x_len
    call linnea_quic_parse_priority     ; "u=7x" -> not a number: ignored
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_dup]
    mov esi, prio_dup_len
    call linnea_quic_parse_priority     ; "u=1,u=5" -> the LAST u wins
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_i2]
    mov esi, prio_i2_len
    call linnea_quic_parse_priority     ; "i=?2" -> not a boolean: ignored
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_dupi]
    mov esi, prio_dupi_len
    call linnea_quic_parse_priority     ; "i,i=?0" -> the LAST i wins: false
    EXPECT rax, 3
    EXPECT rdx, 0

    ; ...and the class the report's "i=?2" belongs to. RFC 9218 4 again: an
    ; unknown member, or one whose value is of an unexpected type, MUST be
    ; ignored -- so none of these may reach incremental. Every one of them
    ; turned it ON, because the branch set true before it validated anything:
    ; "important=1" is not even this key.
    lea rdi, [prio_ikey]
    mov esi, prio_ikey_len
    call linnea_quic_parse_priority     ; an unknown key beginning with 'i'
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_ix]
    mov esi, prio_ix_len
    call linnea_quic_parse_priority     ; "i=x": not a boolean
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_i1x]
    mov esi, prio_i1x_len
    call linnea_quic_parse_priority     ; "i=?1x": a boolean that never ends
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_i0i2]
    mov esi, prio_i0i2_len
    call linnea_quic_parse_priority     ; an invalid member must not undo "?0"
    EXPECT rax, 3
    EXPECT rdx, 0
    ; the controls: the legal spellings must still be read, parameters included
    lea rdi, [prio_ipar]
    mov esi, prio_ipar_len
    call linnea_quic_parse_priority     ; "i;q=1" -> bare i is true
    EXPECT rax, 3
    EXPECT rdx, 1
    lea rdi, [prio_i1par]
    mov esi, prio_i1par_len
    call linnea_quic_parse_priority     ; "i=?1;q=2" -> true
    EXPECT rax, 3
    EXPECT rdx, 1

    ; audit-report-82. Three different rules, and the point is that they differ:
    ; an unknown member is ignored, a known key with an out-of-range value goes
    ; back to the DEFAULT (8941 gives a repeated key its last value), and a
    ; value that does not parse is ignored ENTIRELY -- members already applied
    ; from it included.
    lea rdi, [prio_tabsep]
    mov esi, prio_tabsep_len
    call linnea_quic_parse_priority     ; "u=7<TAB>i": two members, no comma
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_spsep]
    mov esi, prio_spsep_len
    call linnea_quic_parse_priority     ; "u=7 i": the same, with a space
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_tablead]
    mov esi, prio_tablead_len
    call linnea_quic_parse_priority     ; a leading HTAB: the edge takes SP only
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_part]
    mov esi, prio_part_len
    call linnea_quic_parse_priority     ; "u=1,u=7x": the 1 must NOT survive
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_parti]
    mov esi, prio_parti_len
    call linnea_quic_parse_priority     ; "u=1,i=?2": nor here
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_trail]
    mov esi, prio_trail_len
    call linnea_quic_parse_priority     ; "u=1,": a trailing comma
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_range]
    mov esi, prio_range_len
    call linnea_quic_parse_priority     ; "u=1,u=9": last wins, then ignored
    EXPECT rax, 3
    EXPECT rdx, 0
    ; the controls: HTAB beside a comma is ordinary whitespace and must cost
    ; nothing, a leading SP is legal, and an unknown member is still just
    ; ignored -- this fix fails by refusing values that are perfectly fine.
    lea rdi, [prio_tabows]
    mov esi, prio_tabows_len
    call linnea_quic_parse_priority     ; "u=7<TAB>,i" -> both members apply
    EXPECT rax, 7
    EXPECT rdx, 1
    lea rdi, [prio_owstab]
    mov esi, prio_owstab_len
    call linnea_quic_parse_priority     ; "u=7,<TAB>i" -> both members apply
    EXPECT rax, 7
    EXPECT rdx, 1
    lea rdi, [prio_splead]
    mov esi, prio_splead_len
    call linnea_quic_parse_priority     ; " u=7" -> a leading SP is discarded
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_unk]
    mov esi, prio_unk_len
    call linnea_quic_parse_priority     ; "u=1,zz=3" -> the 1 stands
    EXPECT rax, 1
    EXPECT rdx, 0

    ; audit-report-83: the ";" branch was the one door left open by the rule
    ; above -- it ended the member and sent the rest away unread, so a value
    ; whose PARAMETERS do not parse still applied its urgency.
    lea rdi, [prio_pareq]
    mov esi, prio_pareq_len
    call linnea_quic_parse_priority     ; "u=7;=" -> "=" is not a key
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_parq]
    mov esi, prio_parq_len
    call linnea_quic_parse_priority     ; 'i;"' -> nor is a quote
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_parsp]
    mov esi, prio_parsp_len
    call linnea_quic_parse_priority     ; "u=7;bad space" -> no separator
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_parno]
    mov esi, prio_parno_len
    call linnea_quic_parse_priority     ; "u=7;" -> a ";" behind nothing
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_pardup]
    mov esi, prio_pardup_len
    call linnea_quic_parse_priority     ; "u=7;;q=1" -> an empty parameter
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_parup]
    mov esi, prio_parup_len
    call linnea_quic_parse_priority     ; "u=5;Q=1" -> 8941 keys are lcalpha
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_parnov]
    mov esi, prio_parnov_len
    call linnea_quic_parse_priority     ; "u=5;q=" -> no bare-item
    EXPECT rax, 3
    EXPECT rdx, 0
    ; the controls: every legal parameter shape must still leave its member
    ; applied. This fix fails by refusing them.
    lea rdi, [prio_parok]
    mov esi, prio_parok_len
    call linnea_quic_parse_priority     ; "u=5;q=1"
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_parsp2]
    mov esi, prio_parsp2_len
    call linnea_quic_parse_priority     ; "u=5; q=1" -- SP after the ";"
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_partwo]
    mov esi, prio_partwo_len
    call linnea_quic_parse_priority     ; "u=5;q=1;r=2"
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_parstar]
    mov esi, prio_parstar_len
    call linnea_quic_parse_priority     ; "u=5;*k=1" -- a key may start with *
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_parbare]
    mov esi, prio_parbare_len
    call linnea_quic_parse_priority     ; "u=5;a;b" -- parameters with no value
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_parstr]
    mov esi, prio_parstr_len
    call linnea_quic_parse_priority     ; a quoted value we never interpret
    EXPECT rax, 5
    EXPECT rdx, 0

    ; audit-report-84: the six bare-item forms. These fail the WHOLE value --
    ; none of them is an item at all.
    lea rdi, [prio_bunterm]
    mov esi, prio_bunterm_len
    call linnea_quic_parse_priority     ; an unterminated string
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_bslash]
    mov esi, prio_bslash_len
    call linnea_quic_parse_priority     ; a lone backslash
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_bbool2]
    mov esi, prio_bbool2_len
    call linnea_quic_parse_priority     ; "?2" is not a boolean
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_bdot]
    mov esi, prio_bdot_len
    call linnea_quic_parse_priority     ; "1." has no fraction
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_bnodot]
    mov esi, prio_bnodot_len
    call linnea_quic_parse_priority     ; ".5" has no integer part
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_b1a]
    mov esi, prio_b1a_len
    call linnea_quic_parse_priority     ; a number does not run into a token
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_bctl]
    mov esi, prio_bctl_len
    call linnea_quic_parse_priority     ; a control byte inside a string
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_b16]
    mov esi, prio_b16_len
    call linnea_quic_parse_priority     ; 16 digits: an integer takes 15
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_bd13]
    mov esi, prio_bd13_len
    call linnea_quic_parse_priority     ; 13 digits before a decimal point
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_bf4]
    mov esi, prio_bf4_len
    call linnea_quic_parse_priority     ; four digits after one
    EXPECT rax, 3
    EXPECT rdx, 0
    ; ...and the legal items. THREE of these were refused before, because a
    ; string may hold the very characters the old skip stopped at -- which is
    ; how tightening a parser breaks what was working.
    lea rdi, [prio_bsp]
    mov esi, prio_bsp_len
    call linnea_quic_parse_priority     ; a string containing a space
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_bcomma]
    mov esi, prio_bcomma_len
    call linnea_quic_parse_priority     ; a string containing a comma, then a member
    EXPECT rax, 5
    EXPECT rdx, 1
    lea rdi, [prio_bsemi]
    mov esi, prio_bsemi_len
    call linnea_quic_parse_priority     ; a string containing a semicolon
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_besc]
    mov esi, prio_besc_len
    call linnea_quic_parse_priority     ; an escaped quote
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_bempty]
    mov esi, prio_bempty_len
    call linnea_quic_parse_priority     ; the empty string
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_bneg]
    mov esi, prio_bneg_len
    call linnea_quic_parse_priority     ; a negative decimal
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_b15]
    mov esi, prio_b15_len
    call linnea_quic_parse_priority     ; exactly 15 integer digits
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_btok]
    mov esi, prio_btok_len
    call linnea_quic_parse_priority     ; a token with ":" and "/"
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_bbin]
    mov esi, prio_bbin_len
    call linnea_quic_parse_priority     ; a byte sequence
    EXPECT rax, 5
    EXPECT rdx, 0
    lea rdi, [prio_bbin0]
    mov esi, prio_bbin0_len
    call linnea_quic_parse_priority     ; an empty byte sequence
    EXPECT rax, 5
    EXPECT rdx, 0

    ; audit-reports 85 and 86 Finding 1 say a repeated parameter key is
    ; malformed. It is not: 8941 4.2.3.2 step 7 says "If parameters already
    ; contains a key param_key ... overwrite its value". These two rows are
    ; controls against implementing that finding.
    lea rdi, [prio_dpar]
    mov esi, prio_dpar_len
    call linnea_quic_parse_priority     ; a repeated parameter key: legal
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_dpar2]
    mov esi, prio_dpar2_len
    call linnea_quic_parse_priority     ; ...with another key between them
    EXPECT rax, 7
    EXPECT rdx, 0
    ; audit-report-86 Finding 2: an unknown member is IGNORED (9218 4) but the
    ; value it sits in must still PARSE (8941 4.2). Two rules, not one.
    lea rdi, [prio_umbad]
    mov esi, prio_umbad_len
    call linnea_quic_parse_priority     ; an unterminated string in an unknown member
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_um1a]
    mov esi, prio_um1a_len
    call linnea_quic_parse_priority     ; "1a" is not a bare-item
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_umno]
    mov esi, prio_umno_len
    call linnea_quic_parse_priority     ; "zz=" has no value
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_umb2]
    mov esi, prio_umb2_len
    call linnea_quic_parse_priority     ; "?2" is not a boolean
    EXPECT rax, 3
    EXPECT rdx, 0
    ; ...and the legal unknown members, which must still cost nothing
    lea rdi, [prio_umbare]
    mov esi, prio_umbare_len
    call linnea_quic_parse_priority     ; a bare unknown member
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_umpar]
    mov esi, prio_umpar_len
    call linnea_quic_parse_priority     ; a bare unknown member with parameters
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_umstr]
    mov esi, prio_umstr_len
    call linnea_quic_parse_priority     ; a string holding a comma
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_umlist]
    mov esi, prio_umlist_len
    call linnea_quic_parse_priority     ; an inner list: skipped, not refused
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_umi]
    mov esi, prio_umi_len
    call linnea_quic_parse_priority     ; a member after an unknown one still applies
    EXPECT rax, 7
    EXPECT rdx, 1

    ; audit-report-87: the last construct that was skipped rather than parsed.
    lea rdi, [prio_ilunt]
    mov esi, prio_ilunt_len
    call linnea_quic_parse_priority     ; an unterminated string inside a list
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_ilnoc]
    mov esi, prio_ilnoc_len
    call linnea_quic_parse_priority     ; a list with no closing paren
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_ilcom]
    mov esi, prio_ilcom_len
    call linnea_quic_parse_priority     ; items separated by a comma, not SP
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_ilbad]
    mov esi, prio_ilbad_len
    call linnea_quic_parse_priority     ; an item that is not a bare-item
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_ilnest]
    mov esi, prio_ilnest_len
    call linnea_quic_parse_priority     ; a list inside a list
    EXPECT rax, 3
    EXPECT rdx, 0
    lea rdi, [prio_ilpbad]
    mov esi, prio_ilpbad_len
    call linnea_quic_parse_priority     ; an item parameter that does not parse
    EXPECT rax, 3
    EXPECT rdx, 0
    ; ...and every legal shape, which must go on costing nothing. Refusing one
    ; of these is how this fix fails.
    lea rdi, [prio_ilok]
    mov esi, prio_ilok_len
    call linnea_quic_parse_priority     ; a plain inner list
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_ilempty]
    mov esi, prio_ilempty_len
    call linnea_quic_parse_priority     ; an empty inner list
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_ilpad]
    mov esi, prio_ilpad_len
    call linnea_quic_parse_priority     ; *SP inside the parens
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_il2sp]
    mov esi, prio_il2sp_len
    call linnea_quic_parse_priority     ; more than one space between items
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_ilipar]
    mov esi, prio_ilipar_len
    call linnea_quic_parse_priority     ; an item carrying its own parameters
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_ilstr]
    mov esi, prio_ilstr_len
    call linnea_quic_parse_priority     ; a string item containing a space
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_illpar]
    mov esi, prio_illpar_len
    call linnea_quic_parse_priority     ; parameters on the list itself
    EXPECT rax, 7
    EXPECT rdx, 0
    lea rdi, [prio_ilnext]
    mov esi, prio_ilnext_len
    call linnea_quic_parse_priority     ; the member after the list still applies
    EXPECT rax, 7
    EXPECT rdx, 1

    ; audit-report-88: a repeated transport parameter, in both id ranges.
    mov qword [linnea_quic_tp_error], 0
    lea rdi, [tp_lowdup]
    mov esi, tp_lowdup_len
    call linnea_quic_tp_parse           ; id 0x04 twice: the bitmap caught this already
    EXPECT qword [linnea_quic_tp_error], 1
    mov qword [linnea_quic_tp_error], 0
    lea rdi, [tp_hidup]
    mov esi, tp_hidup_len
    call linnea_quic_tp_parse           ; id 64 twice: the extension range was not tracked
    EXPECT qword [linnea_quic_tp_error], 1
    mov qword [linnea_quic_tp_error], 0
    lea rdi, [tp_hidup2]
    mov esi, tp_hidup2_len
    call linnea_quic_tp_parse           ; ...and with a different id between them
    EXPECT qword [linnea_quic_tp_error], 1
    ; the controls: distinct ids must go on parsing cleanly, or a peer's
    ; GREASE parameter would start killing handshakes.
    mov qword [linnea_quic_tp_error], 0
    lea rdi, [tp_hiok]
    mov esi, tp_hiok_len
    call linnea_quic_tp_parse           ; ids 64 and 65 are two parameters, not one
    EXPECT qword [linnea_quic_tp_error], 0
    mov qword [linnea_quic_tp_error], 0
    lea rdi, [tp_hione]
    mov esi, tp_hione_len
    call linnea_quic_tp_parse           ; a single extension parameter
    EXPECT qword [linnea_quic_tp_error], 0
    mov qword [linnea_quic_tp_error], 0
    lea rdi, [tp_plain]
    mov esi, tp_plain_len
    call linnea_quic_tp_parse           ; two different standardised ids
    EXPECT qword [linnea_quic_tp_error], 0

    ; --- reset_scan captures a PATH_CHALLENGE bundled behind other frames, so the
    ; receive path can echo it in a PATH_RESPONSE (RFC 9000 8.2) ---
    lea rdi, [tf_pc]
    mov esi, tf_pc_len
    lea rdx, [rid_out]
    mov ecx, 16
    call linnea_quic_reset_scan
    EXPECT qword [linnea_quic_path_seen], 1
    EXPECT qword [linnea_quic_path_data], 0x8877665544332211
    ; a scan with no challenge leaves the flag clear
    lea rdi, [tf_nopc]
    mov esi, tf_nopc_len
    lea rdx, [rid_out]
    mov ecx, 16
    call linnea_quic_reset_scan
    EXPECT qword [linnea_quic_path_seen], 0

    ; --- the receive window: which packet numbers do we know we have processed?
    ; RFC 9000 12.3 asks for certainty, not for a duplicate check, so the answers
    ; are "new", "seen", and — outside the 64-packet window — "cannot tell, so
    ; treat as seen". Knowing exactly would cost unbounded memory; this costs 24
    ; bytes and drops what it cannot vouch for.

    ; nothing received yet: everything is new
    AS_INIT
    EXPECT_SEEN 0, 0
    EXPECT_SEEN 12345, 0

    ; a straight run 0..199 leaves largest=199 and the 64 below it known
    AS_INIT
    mov ebx, 0
.as_fill:
    AS_REC rbx
    inc ebx
    cmp ebx, 200
    jb .as_fill
    EXPECT_SEEN 199, 1                  ; the largest itself
    EXPECT_SEEN 198, 1                  ; first inside the window
    EXPECT_SEEN 135, 1                  ; last inside the window (offset 63)
    EXPECT_SEEN 134, 1                  ; past it: unknowable, so "seen"
    EXPECT_SEEN 500, 0                  ; above the largest: certainly new

    ; a gap inside the window stays known-not-seen, and filling it is recorded
    AS_INIT
    AS_REC 100
    AS_REC 101
    AS_REC 103
    EXPECT_SEEN 102, 0                  ; skipped, still describable
    EXPECT_SEEN 101, 1
    AS_REC 102                          ; arrives late (reordering)
    EXPECT_SEEN 102, 1

    ; an old number we truly never saw is still dropped: uncertainty resolves the
    ; safe way, and it costs nothing because ack_record already refused to
    ; acknowledge anything that far back, so the peer must resend it regardless
    AS_INIT
    AS_REC 1000
    EXPECT_SEEN 10, 1

    ; the .ar_reset boundary. A delta of exactly 64 puts the OLD largest at
    ; offset 63 — still inside the new window. Clearing the mask wholesale
    ; forgot it and made that one packet replayable once.
    AS_INIT
    AS_REC 100
    AS_REC 163                          ; delta 63: shift path keeps the bit
    EXPECT_SEEN 100, 1
    AS_INIT
    AS_REC 100
    AS_REC 164                          ; delta 64: reset path must keep it too
    EXPECT_SEEN 100, 1
    AS_INIT
    AS_REC 100
    AS_REC 165                          ; delta 65: offset 64, genuinely outside
    EXPECT_SEEN 100, 1                  ; ...so "cannot tell" -> seen


    ; --- RTT estimation (RFC 9002 5.3, 6.2.1) ---
    ; Before any sample the kInitialRtt defaults stand in: srtt 333, rttvar 166,
    ; so PTO = 333 + 4*166 = 997, and 1022 once the peer's max_ack_delay applies.
    ; This is deliberately slower than the flat 250 ms it replaced — the RFC
    ; would rather wait than retransmit into a path it has not measured.
    ; max_ack_delay is the PEER's advertised value (Finding 23), 25 ms by default;
    ; the fixture sets it explicitly since it is no longer a compile-time constant.
    mov qword [conn + linnea_quic_conn.rtt_have], 0
    mov qword [conn + linnea_quic_conn.srtt], 0
    mov qword [conn + linnea_quic_conn.rttvar], 0
    mov qword [conn + linnea_quic_conn.min_rtt], 0
    mov qword [conn + linnea_quic_conn.max_ack_peer], 25
    PTO 0
    EXPECT rax, 997                     ; Initial/Handshake: no ack delay
    PTO 1
    EXPECT rax, 1022                    ; application space: + the peer's 25 ms
    ; a peer promising a longer ack deadline pushes the probe out with it, so we
    ; do not declare loss before its promised deadline (Finding 23)
    mov qword [conn + linnea_quic_conn.max_ack_peer], 100
    PTO 1
    EXPECT rax, 1097                    ; 997 + 100
    mov qword [conn + linnea_quic_conn.max_ack_peer], 25

    ; the first sample is adopted outright: srtt = latest, rttvar = latest/2
    RTT 100
    EXPECT qword [conn + linnea_quic_conn.srtt], 100
    EXPECT qword [conn + linnea_quic_conn.rttvar], 50
    EXPECT qword [conn + linnea_quic_conn.min_rtt], 100
    PTO 0
    EXPECT rax, 300                     ; 100 + 4*50

    ; a second identical sample: rttvar decays toward 0, srtt holds
    RTT 100
    EXPECT qword [conn + linnea_quic_conn.srtt], 100
    EXPECT qword [conn + linnea_quic_conn.rttvar], 37   ; (3*50 + 0) / 4

    ; a faster sample lowers min_rtt and pulls srtt down by an eighth of the gap
    RTT 60
    EXPECT qword [conn + linnea_quic_conn.min_rtt], 60
    EXPECT qword [conn + linnea_quic_conn.srtt], 95     ; (7*100 + 60) / 8
    EXPECT qword [conn + linnea_quic_conn.rttvar], 37   ; (3*37 + 40) / 4

    ; min_rtt never rises again on a slower sample
    RTT 500
    EXPECT qword [conn + linnea_quic_conn.min_rtt], 60

    ; a long-RTT path settles high, so its probes stop firing spuriously —
    ; this is the case the flat 250 ms got wrong, halving cwnd on every pass
    mov qword [conn + linnea_quic_conn.rtt_have], 0
    mov qword [conn + linnea_quic_conn.srtt], 0
    mov qword [conn + linnea_quic_conn.rttvar], 0
    mov qword [conn + linnea_quic_conn.min_rtt], 0
    mov r12d, 40
.rtt_settle:
    RTT 400
    dec r12d
    jnz .rtt_settle
    EXPECT qword [conn + linnea_quic_conn.srtt], 400
    PTO 1
    mov rcx, rax
    EXPECT_ABOVE rcx, 400               ; a 400 ms path must not probe under 400 ms

    ; the floor holds when a link is faster than the timer can express
    mov qword [conn + linnea_quic_conn.rtt_have], 0
    mov qword [conn + linnea_quic_conn.srtt], 0
    mov qword [conn + linnea_quic_conn.rttvar], 0
    mov qword [conn + linnea_quic_conn.min_rtt], 0
    RTT 0
    EXPECT qword [conn + linnea_quic_conn.srtt], 0      ; a real 0 ms measurement
    PTO 0
    EXPECT rax, LINNEA_QUIC_PTO_FLOOR   ; ...but never probe that fast

    ; and the ceiling caps a pathological estimate before backoff multiplies it
    mov qword [conn + linnea_quic_conn.rtt_have], 1
    mov qword [conn + linnea_quic_conn.srtt], 60000
    mov qword [conn + linnea_quic_conn.rttvar], 60000
    PTO 1
    EXPECT rax, LINNEA_QUIC_PTO_CEIL


    ; --- the shared frame-length table (RFC 9000 19) ---
    ; Six scanners used to carry partial copies of this and stop at the first
    ; type theirs did not list. Every length here is one of those copies' gaps.
    FSKIP fk_pad, 1
    EXPECT rax, 1                       ; PADDING
    FSKIP fk_ping, 1
    EXPECT rax, 1                       ; PING
    FSKIP fk_hd, 1
    EXPECT rax, 1                       ; HANDSHAKE_DONE
    FSKIP fk_pc, 9
    EXPECT rax, 9                       ; PATH_CHALLENGE
    FSKIP fk_maxdata, 3
    EXPECT rax, 3                       ; MAX_DATA
    FSKIP fk_reset, 4
    EXPECT rax, 4                       ; RESET_STREAM
    FSKIP fk_close, 4
    EXPECT rax, 4                       ; CONNECTION_CLOSE — unknown to four walks
    FSKIP fk_closea, 3
    EXPECT rax, 3                       ; CONNECTION_CLOSE (application)
    FSKIP fk_stream, 5
    EXPECT rax, 5                       ; STREAM with a length
    FSKIP fk_strnol, 5
    EXPECT rax, 5                       ; STREAM without one: runs to the end
    FSKIP fk_ncid, 24
    EXPECT rax, 24                      ; NEW_CONNECTION_ID
    FSKIP fk_ack, 7
    EXPECT rax, 7                       ; ACK
    FSKIP fk_ackecn, 8
    EXPECT rax, 8                       ; ACK with ECN counts
    FSKIP fk_ack3, 9
    EXPECT rax, 9                       ; ACK carrying three ranges
    FSKIP fk_closer, 6
    EXPECT rax, 6                       ; CONNECTION_CLOSE with a reason phrase

    ; a type RFC 9000 does not define is reported, with the type for the close
    FSKIP fk_unk, 1
    EXPECT rax, -1
    EXPECT rdx, 0x22
    ; and a frame that runs off the end is truncation, not an unknown type
    FSKIP fk_trunc, 1
    EXPECT rax, 0
    ; the same MAX_DATA, one byte short of complete
    FSKIP fk_maxdata, 2
    EXPECT rax, 0

    ; a lie about a length must not walk past the buffer
    FSKIP fk_stream, 3                  ; claims 2 bytes of data that are not there
    EXPECT rax, 0

    ; whole payloads: the shape that used to lose frames must now walk clean
    lea rdi, [fk_seq_ok]
    mov esi, fk_seq_ok_len
    call linnea_quic_frames_check
    EXPECT rax, 0
    ; ...and an unknown type anywhere in it is a connection error, named
    lea rdi, [fk_seq_bad]
    mov esi, fk_seq_bad_len
    call linnea_quic_frames_check
    EXPECT rax, -1
    EXPECT rdx, 0x22
    ; ...and so is a last frame that runs past the end of the payload. The type
    ; reported is 0, which 19.19 defines as "the frame type is unknown" — the
    ; bytes naming it may be the very ones that did not fit.
    lea rdi, [fk_seq_trunc]
    mov esi, fk_seq_trunc_len
    call linnea_quic_frames_check
    EXPECT rax, -1
    EXPECT rdx, 0

    ; print "quic-rtx <pass>/<total>\n"
    lea rdi, [msg_head]
    mov esi, msg_head_len
    call linnea_print_stdout
    mov edi, r15d
    call linnea_print_u64_stdout
    lea rdi, [msg_slash]
    mov esi, 1
    call linnea_print_stdout
    mov edi, r14d
    call linnea_print_u64_stdout
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stdout

    xor edi, edi
    cmp r15d, r14d
    je .exit
    mov edi, 1
.exit:
    mov eax, LINNEA_SYS_EXIT
    syscall
