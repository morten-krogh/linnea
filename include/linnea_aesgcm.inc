; AES-128-GCM — the TLS 1.3 record AEAD (TLS_AES_128_GCM_SHA256). The
; handshake records are sealed/opened here in userspace; application data
; is the kernel's job after the kTLS handoff. AES-NI and PCLMULQDQ are
; required (the startup CPUID check happens when TLS listeners exist).

struc linnea_aesgcm_ctx
    .rk:    resb 176   ; the 11 expanded AES-128 round keys
    .h:     resb 16    ; GHASH key H, byte-swapped and pre-shifted for clmul
endstruc

LINNEA_AESGCM_KEY       equ 16
LINNEA_AESGCM_NONCE     equ 12
LINNEA_AESGCM_TAG       equ 16
