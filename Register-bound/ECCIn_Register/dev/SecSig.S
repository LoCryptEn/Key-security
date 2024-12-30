.global dosecsig
.type dosecsig, @function

dosecsig:

    bswap       %rdi
    bswap       %rsi

    vpinsrq     $0,     %rdi,   %xmm1,  %xmm1
    vpinsrq     $1,     %rsi,   %xmm1,  %xmm1
    
    // Dec k1
    vmovdqu64   (%rdx), %xmm0
    call        AES_DEC
    vmovq       %xmm0,  %r8
    pextrq      $1,     %xmm0,  %r9
    bswap       %r8
    bswap       %r9

    vmovdqu64   16(%rdx), %xmm0
    call        AES_DEC
    vmovq       %xmm0,  %r10
    pextrq      $1,     %xmm0,  %r11
    bswap       %r10
    bswap       %r11

    // read k2
    movq        32(%rdx), %r12
    movq        40(%rdx),%r13
    movq        48(%rdx),%r14
    movq        56(%rdx),%r15
    
    bswap       %r12
    bswap       %r13
    bswap       %r14
    bswap       %r15

    add         %r11,   %r15
    adc         %r10,   %r14
    adc         %r9,    %r13
    adc         %r8,    %r12

    vpinsrq     $1,     %r12,   %xmm0,  %xmm0
    vpinsrq     $0,     %r13,   %xmm0,  %xmm0

    vinserti128 $0,     %xmm0, %ymm11,  %ymm11

    vpinsrq     $1,     %r14,   %xmm0,  %xmm0
    vpinsrq     $0,     %r15,   %xmm0,  %xmm0

    vinserti128 $1,     %xmm0, %ymm11,  %ymm11

    vmovaps     %ymm11, %ymm0 
    // Done k = k1 + k2
    
    // Dec a
    vmovdqu64   64(%rdx), %xmm0
    call        AES_DEC
    vmovq       %xmm0,  %r8
    pextrq      $1,     %xmm0,  %r9
    bswap       %r8
    bswap       %r9

    vmovdqu64   80(%rdx), %xmm0
    call        AES_DEC
    vmovq       %xmm0,  %r10
    pextrq      $1,     %xmm0,  %r11
    bswap       %r10
    bswap       %r11

    ret
