.section .data
.align 16
AES_KEY:
    .quad 0x5295063b287fd8f6
    .quad 0x15d294a0893b1c61
    
SHUFFLE_MASK:
    .quad 0x08090a0b0c0d0e0f
    .quad 0x0001020304050607

.section .text

// [r8 | r9 | r10 | r11] + [r12 | r13 | r14 | r15] mod n256 & save to [xmm30 | xmm31]
.macro addmod
    add         %r11,   %r15
    adc         %r10,   %r14
    adc         %r9,    %r13
    adc         %r8,    %r12
    adc         $0,     %rax

    movq    %r12,   %r8
    movq    %r13,   %r9
    movq    %r14,   %r10
    movq    %r15,   %r11
    
    // c = (a + b) mod n & save to [r12 | r13 | r14 | r15]
    movq    $0xf3b9cac2fc632551,    %rbx
    subq    %rbx,    %r15
    movq    $0xbce6faada7179e84,    %rbx
    sbbq    %rbx,    %r14
    movq    $0xffffffffffffffff,    %rbx
    sbbq    %rbx,    %r13
    movq    $0xffffffff00000000,    %rbx
    sbbq    %rbx,    %r12
    sbbq    $0,      %rax
    jb      1f

    jmp    2f

1:
    movq    %r8,    %r12
    movq    %r9,    %r13
    movq    %r10,   %r14
    movq    %r11,   %r15

2:

    vpinsrq     $1,     %r12,   %xmm30,  %xmm30
    vpinsrq     $0,     %r13,   %xmm30,  %xmm30

    vpinsrq     $1,     %r14,   %xmm31,  %xmm31
    vpinsrq     $0,     %r15,   %xmm31,  %xmm31

.endm


.global dosecsig
.type dosecsig, @function

dosecsig:
    vmovdqu     AES_KEY(%rip), %xmm1  # Hardcode 128-bit AES key into xmm1
    vmovdqu     SHUFFLE_MASK(%rip), %xmm15  # Hardcode shuffle mask into xmm24

    xorq       %rax,   %rax
    xorq       %r8,    %r8
    xorq       %r9,    %r9
    xorq       %r10,   %r10
    xorq       %r11,   %r11
    xorq       %r12,   %r12
    xorq       %r13,   %r13
    xorq       %r14,   %r14
    xorq       %r15,   %r15
    
    // Dec k1
    vmovdqa64   (%rdi), %xmm0
    call        AES_DEC
    vpshufb     %xmm15,    %xmm0,  %xmm0
    pextrq      $1,     %xmm0,  %r8
    vmovq       %xmm0,  %r9

    vmovdqa64   16(%rdi), %xmm0
    call        AES_DEC
    vpshufb     %xmm15,    %xmm0,  %xmm0
    pextrq      $1,     %xmm0,  %r10
    vmovq       %xmm0,  %r11

    // read k2
    movq        32(%rdi), %r15
    movq        40(%rdi), %r14
    movq        48(%rdi), %r13
    movq        56(%rdi), %r12

    addmod
    // save k to [xmm30 | xmm31]
    
    // Dec a
    vmovdqa64   64(%rdi), %xmm0
    call        AES_DEC
    vpshufb     %xmm15,   %xmm0,  %xmm0
    vmovdqa64   %xmm0,    %xmm28

    vmovdqa64   80(%rdi), %xmm0
    call        AES_DEC
    vpshufb     %xmm15,   %xmm0,  %xmm0
    vmovdqa64   %xmm0,    %xmm29

    // Copy a to [xmm24 | xmm25]
    vmovdqa64   %xmm28,  %xmm24
    vmovdqa64   %xmm29,  %xmm25

    call        bignum_montmul_n256

    // store a * k * R^{-1} to [xmm13 | xmm14]
    vmovdqa64   %xmm26,  %xmm13
    vmovdqa64   %xmm27,  %xmm14

    // Dec d
    vmovdqa64   96(%rdi), %xmm0
    call        AES_DEC
    vpshufb     %xmm15,   %xmm0,  %xmm0
    vmovdqa64   %xmm0,    %xmm28

    vmovdqa64   112(%rdi), %xmm0
    call        AES_DEC
    vpshufb     %xmm15,    %xmm0,  %xmm0
    vmovdqa64   %xmm0,    %xmm29 

    // Load r * R^{-1}
    vmovdqa64   128(%rdi), %xmm30
    vpshufb     %xmm15,    %xmm30,  %xmm30
    vmovdqa64   144(%rdi), %xmm31
    vpshufb     %xmm15,    %xmm31,  %xmm31

    call        bignum_montmul_n256

    // Done r * d
    xorq       %rax,   %rax
    xorq       %r8,    %r8
    xorq       %r9,    %r9
    xorq       %r10,   %r10
    xorq       %r11,   %r11
    xorq       %r12,   %r12
    xorq       %r13,   %r13
    xorq       %r14,   %r14
    xorq       %r15,   %r15

    // Load d * r  to [r8 | r9 | r10 | r11]
    vpextrq      $1,     %xmm26, %r8
    vmovq       %xmm26, %r9
    vpextrq      $1,     %xmm27, %r10
    vmovq       %xmm27, %r11

    // Load H(m) to [r12 | r13 | r14 | r15]
    movq        160(%rdi), %r12
    movq        168(%rdi), %r13
    movq        176(%rdi), %r14
    movq        184(%rdi), %r15

    bswap       %r12
    bswap       %r13
    bswap       %r14
    bswap       %r15

    addmod

    vmovdqa64   %xmm24, %xmm28
    vmovdqa64   %xmm25, %xmm29

    call       bignum_montmul_n256
    
    vmovdqa64   %xmm14, (%rsi)
    vmovdqa64   %xmm13, 16(%rsi)
    vmovdqa64   %xmm27, 32(%rsi)
    vmovdqa64   %xmm26, 48(%rsi)

    ret
