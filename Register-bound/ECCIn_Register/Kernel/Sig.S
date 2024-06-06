#include "aes.S"

.file   "Sig.S"
.text

    .set    A0,  %ymm0
    .set    A0xmm,   %xmm0

    .set    B0,  %ymm1
    .set    B0xmm,   %xmm1

    .set    M0,  %ymm2
    .set    M0xmm,   %xmm2

    .set    Z0,     %ymm3
    .set    Z0xmm,   %xmm3

    .set    K1,     %ymm4
    .set    K1xmm,   %xmm4

    .set    K2,     %ymm5
    .set    K2xmm,   %xmm5

    .set    TT,     %ymm6
    .set    TTxmm,      %xmm6

    .set    T,     %ymm7
    .set    Txmm,   %xmm7

    .set    Res,    %ymm8
    .set    Resxmm, %xmm8
    
    .set    RD,     %ymm9
    .set    RDxmm, %xmm9

    .set    ZRD,    %ymm10
    .set    ZRDxmm, %xmm10

    .set	s0, %r8
    .set    s1, %r9
    .set    s2, %r10
    .set    s3, %r11

    .set	s4, %r12
    .set    s5, %r13

    .set	aa0, %mm0
    .set    aa1, %mm1
    .set    aa2, %mm2
    .set    aa3, %mm3
    .set    aa4, %mm4
    .set    aa5, %mm5
    .set    aa6, %mm6
    .set    aa7, %mm7

    .set	rl, %r14    ##rcx
    .set	rh, %r15  ##rdx

    .set	ai, %rdx
    .set	mi, %rdx
   

    .set	bi, %rax

    .global do_secsig
    .type   do_secsig,  @function
    .align  64

do_secsig:    

    #stack balance
    subq $128,  %rsp

    movq    %rdi,   (%rsp)
    movq    %rsi,   8(%rsp)
    movq    %rdx,   16(%rsp)  
    movq    %r14,   24(%rsp)
    movq     %r15,  32(%rsp)
    movq    %rax,   40(%rsp)
    movq    %rbx,   48(%rsp)
    movq    %r8,   56(%rsp)
    movq    %r9,   64(%rsp)
    movq    %r10,   72(%rsp)
    movq    %r11,   80(%rsp)
    movq    %r12,   88(%rsp)
    movq    %r13,   96(%rsp)
    movq    %rcx,   104(%rsp)
    movq    %rbp,   112(%rsp)

    vpxorq  %ymm16,  %ymm16,  %ymm16
    vpxorq  %ymm17,  %ymm17,  %ymm17
    vpxorq  %ymm18,  %ymm18,  %ymm18
    vpxorq  %ymm19,  %ymm19,  %ymm19
    vpxorq  %ymm20,  %ymm20,  %ymm20

    vpxorq  TT,     TT,     TT
    # movq    $0x0123456789ABCDEF,    %rax
    movq    %dr0,   %rax
    vmovq   %rax,   TTxmm
    valignq     $1, %ymm0, TT,  %ymm0
    # movq    $0xFEDCBA9876543210,    %rax
    movq    %dr1,   %rax
    vmovq   %rax,   TTxmm
    valignq     $3, %ymm0, TT,  %ymm0
    vmovdqu64     %xmm0,  %xmm16

    vmovdqu64   (%rcx),    mes
    aes_dec
    vmovdqu64    mes,  %xmm17  ##k1

    vmovdqu64    %xmm16,  %xmm0
    vmovdqu64   16(%rcx),    mes
    aes_dec
    vmovdqu64     mes,  %xmm18  ##k1

    vmovdqu64     %xmm16,  %xmm0
    vmovdqu64   (%rdx),    mes
    aes_dec
    vmovdqu64     mes,  %xmm19  ##d

    vmovdqu64     %xmm16,  %xmm0
    vmovdqu64   16(%rdx),    mes
    aes_dec
    vmovdqu64    mes,  %xmm20  ##d

    vmovdqu64     %xmm16,  %xmm0
    vmovdqu64   32(%rdi),    mes
    aes_dec
    vmovdqu64    mes,  K2xmm # factor
    movq    48(%rdi), %rax
    movq    %rax,   aa7


    #set 0 
    vpxorq  TT,     TT,     TT
    vpxorq  T,  T,  T
    vpxorq  Z0,  Z0,  Z0
    vpxorq  RD,  RD,  RD
    vpxorq  ZRD,  ZRD,  ZRD

    xorq    s0, s0
    xorq    s1,     s1
    xorq    s2,     s2
    xorq    s3,     s3
    xorq    s4,     s4
    xorq    s5,     s5
    xorq    %rax,     %rax
    xorq    %rbx,     %rbx

    vmovdqu64   (%rsi),    A0
    valignq     $2, B0, %ymm19,  B0
    valignq     $2, B0, %ymm20,  B0
    ##vmovdqu64   (%rdx),    B0
    vmovdqu64   (%rcx),    Z0

    ##compute k1+k2 mod n##
    
    vmovq   %xmm17,  s0
    valignq     $1, %ymm17, TT,  %ymm17
    vmovq   %xmm17,  s1
    vmovq   %xmm18,  s2
    valignq     $1, %ymm18, TT,  %ymm18
    vmovq   %xmm18,  s3

    movq   32(%rcx),  s4
    movq   40(%rcx),  s5
    movq   48(%rcx),  rl
    movq   56(%rcx),  rh

    add     s4,    s0
    adc     s5,    s1
    adc     rl,    s2
    adc     rh,    s3
    adc   $0,  %rax

    movq    s0,    s4
    movq    s1,     s5
    movq    s2,     rl
    movq    s3,     rh
   

    movq    $0xf3b9cac2fc632551,    %rbx
    subq    %rbx,    s0
    movq    $0xbce6faada7179e84,    %rbx
    sbbq    %rbx,    s1
    movq    $0xffffffffffffffff,    %rbx
    sbbq    %rbx,    s2
    movq    $0xffffffff00000000,    %rbx
    sbbq    %rbx,    s3
    sbbq    $0, %rax
    jb      1f

    jmp    2f

1:
    movq    s4,    s0
    movq    s5,     s1
    movq    rl,     s2
    movq    rh,     s3

2:

    vmovq   K2xmm,  ai
    mulx    s0, s0, s4  #rdx *s0 low s0 high s4
    vmovq   s0,     Txmm
    valignq     $1, Z0, T, Z0

    mulx    s2, s2, s5
    mulx    s1, rl, rh

    add     rl,     s4
    vmovq   s4,     Txmm
    valignq     $1, Z0, T, Z0

    adc     rh,     s2
    vmovq   s2,     Txmm
    valignq     $1, Z0, T, Z0

    mulx    s3, rl, rh
    adc     rl,     s5
    vmovq   s5,     Txmm
    valignq     $1, Z0, T, Z0

    adc     $0, rh
    #vmovdqu64    Z0,  80(%rdi)
    #movq    rh,  112(%rdi)  #a*k finish

    #movq    aa7,   ai
    #movq    ai,  112(%rdi)


## new added

    xorq   %rax, %rax
    vmovq   Z0xmm,  s0
    valignq     $1, Z0, TT, Z0
    vmovq   Z0xmm,  s1
    valignq     $1, Z0, TT, Z0
    vmovq   Z0xmm,  s2
    valignq     $1, Z0, TT, Z0
    vmovq   Z0xmm,  s3

    movq    $0xf3b9cac2fc632551,    %rbx  ## a*k-t*p t should be secret, here is 2^0 
    subq    %rbx,    s0
    movq    $0xbce6faada7179e84,    %rbx
    sbbq    %rbx,    s1
    movq    $0xffffffffffffffff,    %rbx
    sbbq    %rbx,    s2
    movq    $0xffffffff00000000,    %rbx
    sbbq    %rbx,    s3
    sbbq    $0, rh

    movq    s0,  80(%rdi)
    movq    s1,  88(%rdi)
    movq    s2,  96(%rdi)
    movq    s3,  104(%rdi)
    movq    rh,  112(%rdi)

    xorq    s0, s0
    xorq    s1,     s1
    xorq    s2,     s2
    xorq    s3,     s3
    xorq    s4,     s4
    xorq    s5,     s5
    xorq    %rax,     %rax
    xorq    %rbx,     %rbx
    vpxorq  TT,     TT,     TT

    ### Recover k finish and set k in ZMM K1 finish#####

    vmovdqu     A0,     T
    vmovq   Txmm,  ai 
    movq   ai,     aa0       ##A[0]
    valignq     $1, T, TT, T
    vmovq   Txmm,  ai 
    movq   ai,     aa1       ##A[1]
    valignq     $1, T, TT, T
    vmovq   Txmm,  ai 
    movq   ai,     aa2       ##A[2]
    valignq     $1, T, TT, T
    vmovq   Txmm,  ai 
    movq   ai,     aa3       ##A[3]

    ##compute  r*d###

    vmovdqu     B0,     T
    vmovq   Txmm,  bi  ##B[0]
    #####################################
    movq    aa0,    ai      ##A[0]
    mulx    bi, s0, s1      ##A[0]*B[0]

    movq    aa2,    ai      ##A[2]
    mulx    bi, s2, s3      ##A[2]*B[0]
    #######################
    movq    aa1,    ai      ##A[1]
    mulx    bi, rl, rh      ##A[1]*B[0]
    add     rl,     s1
    adc     rh,     s2

    movq    aa3,    ai      ##A[3]
    mulx    bi, rl, rh      ##A[3]*B[0]
    adc     rl,     s3
    adc     rh,     s4
    adc     $0,     s5
    ############
    vmovq   s0, ZRDxmm
    valignq     $1, RD, ZRD, RD

    xorq    s0, s0
    ############################################
    ####### After the first round b0, result S is in s5 s4 s3 s2 s1 ############

    valignq     $1, T, TT, T
    vmovq   Txmm,  bi  ##B[1]
    #####################################
    movq    aa0,    ai      ##A[0]
    mulx    bi, rl, rh      ##A[0]*B[1]
    add     rl, s1
    adc     rh, s2

    movq    aa2,    ai      ##A[2]
    mulx    bi, rl, rh      ##A[2]*B[1]
    adc     rl, s3
    adc     rh, s4
    adc     $0, s5
    #######################
    movq    aa1,    ai      ##A[1]
    mulx    bi, rl, rh      ##A[1]*B[1]
    add     rl,     s2
    adc     rh,     s3

    movq    aa3,    ai      ##A[3]
    mulx    bi, rl, rh      ##A[3]*B[1]
    adc     rl,     s4
    adc     rh,     s5
    adc     $0,     s0
    ############
    vmovq   s1, ZRDxmm
    valignq     $1, RD, ZRD, RD

    xorq    s1, s1
    ############################################
    ####### After the second round b1, resulte S is in s0 s5 s4 s3 s2 ############

    valignq     $1, T, TT, T
    vmovq   Txmm,  bi  ##B[2]

    #####################################
    movq    aa0,    ai      ##A[0]
    mulx    bi, rl, rh      ##A[0]*B[2]
    add     rl, s2
    adc     rh, s3

    movq    aa2,    ai      ##A[2]
    mulx    bi, rl, rh      ##A[2]*B[2]
    adc     rl, s4
    adc     rh, s5
    adc     $0, s0
    #######################
    movq    aa1,    ai      ##A[1]
    mulx    bi, rl, rh      ##A[1]*B[2]
    add     rl,     s3
    adc     rh,     s4

    movq    aa3,    ai      ##A[3]
    mulx    bi, rl, rh      ##A[3]*B[2]
    adc     rl,     s5
    adc     rh,     s0
    adc     $0,     s1
    ############
    vmovq   s2, ZRDxmm
    valignq     $1, RD, ZRD, RD

    xorq    s2, s2
    ############################################
    ####### After the third round b2, resulte S is in s1 s0 s5 s4 s3  ############

    valignq     $1, T, TT, T
    vmovq   Txmm,  bi  ##B[3]

    #####################################
    movq    aa0,    ai      ##A[0]
    mulx    bi, rl, rh      ##A[0]*B[3]
    add     rl, s3
    adc     rh, s4

    movq    aa2,    ai      ##A[2]
    mulx    bi, rl, rh      ##A[2]*B[3]
    adc     rl, s5
    adc     rh, s0
    adc     $0, s1
    #######################
    movq    aa1,    ai      ##A[1]
    mulx    bi, rl, rh      ##A[1]*B[3]
    add     rl,     s4
    adc     rh,     s5

    movq    aa3,    ai      ##A[3]
    mulx    bi, rl, rh      ##A[3]*B[3]
    adc     rl,     s0
    adc     rh,     s1
    adc     $0,     s2
    ############
    vmovq   s3, ZRDxmm
    valignq     $1, RD, ZRD, RD

    xorq    s3, s3
    ############################################
    ####### After the forth round b3, resulte S is in s2 s1 s0 s5 s4 ############
    ##the mul result is in s2 s1 s0 s5 s4 and RD ##

    movq    (%rsp),     %rdi

    ##compute z+r*d##
    vmovdqu64   (%rdi),    Z0

    vpxor  TT, TT, TT
    vmovq   Z0xmm,  rl
    valignq     $1, Z0, TT, Z0
    vmovq   RDxmm,  rh
    valignq     $1, RD, TT, RD
    add    rl, rh
    #movq   rh, (%rdi)
    movq   rh,  aa0

    vmovq   Z0xmm,  rl
    valignq     $1, Z0, TT, Z0
    vmovq   RDxmm,  rh
    valignq     $1, RD, TT, RD
    adc    rl, rh
    #movq   rh, 8(%rdi)
    movq   rh,  aa1

    vmovq   Z0xmm,  rl
    valignq     $1, Z0, TT, Z0
    vmovq   RDxmm,  rh
    valignq     $1, RD, TT, RD
    adc    rl, rh
    #movq   rh, 16(%rdi)
    movq   rh,  aa2

    vmovq   Z0xmm,  rl
    valignq     $1, Z0, TT, Z0
    vmovq   RDxmm,  rh
    valignq     $1, RD, TT, RD
    adc    rl, rh
    #movq   rh, 24(%rdi)
    movq   rh,  aa3

    adc   $0, s4
    adc   $0, s5
    adc   $0, s0
    adc   $0, s1
    adc   $0, s2

    vmovq   K2xmm,  ai
    movq   aa0,  bi
    mulx    bi, rl, s3
    movq   rl, (%rdi)

    movq   rl, aa4

    movq   aa1,  bi
    mulx    bi, rl, rh
    add     s3,     rl
    movq   rl, 8(%rdi)

    movq   rl, aa5

    movq   aa2,  bi
    mulx    bi, rl, s3
    adc     rh,     rl
    movq   rl, 16(%rdi)

    movq   rl, aa6

    movq   aa3,  bi
    mulx    bi, rl, rh
    adc     s3,     rl
    movq   rl, 24(%rdi)

    movq   rl, aa7

    mulx    s4, rl, s3
    adc     rh,     rl
    movq   rl, 32(%rdi)

    movq   rl, aa0

    mulx    s5, rl, rh
    adc     s3,     rl
    movq   rl, 40(%rdi)

    movq   rl, aa1

    mulx    s0, rl, s3
    adc     rh,     rl
    movq   rl, 48(%rdi)

    movq   rl, aa2

    mulx    s1, rl, rh
    adc     s3,     rl
    movq   rl, 56(%rdi)

    movq   rl, aa3

    mulx    s2, rl, s3
    adc     rh,     rl
    movq   rl, 64(%rdi)

    movq   rl,  ai

    adc     $0, s3
    movq   s3,  72(%rdi)

    movq   rl,  bi


## newadded

    movq   aa1, s0
    movq   aa2, s1
    movq   aa3, s2
    movq   ai, s3
    movq   bi, s4


Again_loop2:
    cmp     $0, s4
    jge     Again_end_loop2
    movq    $0xf3b9cac2fc632551,    %rbx
    subq    %rbx,    s0
    movq    $0xbce6faada7179e84,    %rbx
    sbbq    %rbx,    s1
    movq    $0xffffffffffffffff,    %rbx
    sbbq    %rbx,    s2
    movq    $0xffffffff00000000,    %rbx
    sbbq    %rbx,    s3
    sbbq    $0, s4

    jmp Again_loop2

Again_end_loop2:

    movq   aa0, s4 ## a*(z+r*d)-t*p t should be secret, here is 2^256 

    ## a*(z+r*d)-t*p t should be secret, here is 2^256 

    movq    $0xf3b9cac2fc632551,    %rbx
    subq    %rbx,    s4
    movq    $0xbce6faada7179e84,    %rbx
    sbbq    %rbx,    s0
    movq    $0xffffffffffffffff,    %rbx
    sbbq    %rbx,    s1
    movq    $0xffffffff00000000,    %rbx
    sbbq    %rbx,    s2
    sbbq    $0, s3

    movq   s4, 32(%rdi)
    movq   s0, 40(%rdi)
    movq   s1, 48(%rdi)
    movq   s2, 56(%rdi)
    movq   s3, 64(%rdi)
    movq   $0, %rax
    movq   %rax, 72(%rdi)

    #Recovery
    movq    (%rsp),     %rdi
    movq    8(%rsp),     %rsi
    movq    16(%rsp),     %rdx
    movq    24(%rsp),     %r14
    movq    32(%rsp),     %r15
    movq    40(%rsp),     %rax
    movq    48(%rsp),     %rbx
    movq    56(%rsp),     %r8
    movq    64(%rsp),     %r9
    movq    72(%rsp),     %r10
    movq    80(%rsp),     %r11
    movq    88(%rsp),     %r12
    movq    96(%rsp),     %r13
    movq    104(%rsp),  %rcx
    movq    112(%rsp),  %rbp

    addq    $128,  %rsp    

    ret
    .size	do_secsig, .-do_secsig
