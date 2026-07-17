; ECDSA signing on NIST P-256 with SHA-256, deterministic per RFC 6979.
;
; Sign only. The server never verifies a signature: there is no client
; authentication, and TLS 1.3 puts the server on the signing side of
; CertificateVerify only.
;
; The nonce is derived from the private key and the message digest by RFC
; 6979's HMAC_DRBG rather than drawn from getrandom(2). Two reasons: a
; repeated or biased nonce hands over the private key -- the failure mode that
; has broken real ECDSA deployments, and one no test can detect after the
; fact -- and determinism means the signature is a pure function of its
; inputs, so RFC 6979's published vectors pin it byte for byte.

; The signature is DER: SEQUENCE { INTEGER r, INTEGER s }. Each INTEGER is at
; most 33 bytes of content (32, plus a leading 0x00 when the high bit is set)
; and carries a 2-byte header, so the body is at most 70 and the whole
; structure at most 72. It is shorter whenever r or s has leading zero bytes,
; so callers must use the returned length, never this bound.
;
; TLS's CertificateVerify is sized against the MAXIMUM, not the typical: this
; is the constant the flight overhead must be computed from.
LINNEA_P256_ECDSA_MAX_SIG   equ 72
