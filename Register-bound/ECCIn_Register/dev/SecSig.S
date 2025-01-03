.global dosecsig
.type dosecsig, @function

dosecsig:

    bswap       %rdi
    bswap       %rsi

    xorq       %rax,   %rax
    xorq       %r8,    %r8
    xorq       %r9,    %r9
    xorq       %r10,   %r10
    xorq       %r11,   %r11
    xorq       %r12,   %r12
    xorq       %r13,   %r13
    xorq       %r14,   %r14
    xorq       %r15,   %r15


    vpinsrq     $0,     %rdi,   %xmm1,  %xmm1
    vpinsrq     $1,     %rsi,   %xmm1,  %xmm1
    
    // Dec k1
    vmovdqu64   (%rdx), %xmm0
    call        AES_DEC
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
    movq        40(%rdx), %r13
    movq        48(%rdx), %r14
    movq        56(%rdx), %r15
    
    bswap       %r12
    bswap       %r13
    bswap       %r14
    bswap       %r15

    add         %r11,   %r15
    adc         %r10,   %r14
    adc         %r9,    %r13
    adc         %r8,    %r12
    adc         $0,     %rax

    movq    %r12,   %r8
    movq    %r13,   %r9
    movq    %r14,   %r10
    movq    %r15,   %r11
    
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

    // Done k = k1 + k2 & save to [xmm30 | xmm31]
    
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
