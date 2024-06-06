.file   "call_rrmontmul.s"
.text

# A0-A31 
.set    A0, %zmm0
.set    B0, %zmm1

.set    R0, %zmm3

.set    T, %zmm4

#TT for temp register
.set    TT, %zmm9

.set    A1, %zmm5
.set    A2, %zmm6
.set    A3, %zmm7
.set    A4, %zmm8

.set   B1, %zmm11
.set   B2, %zmm12
.set   B3, %zmm13
.set   B4, %zmm14

.set   R5, %zmm15
.set   R6, %zmm16
.set   R7, %zmm17
.set   RR8, %zmm18
.set   RR9, %zmm23
.set   RR10, %zmm24
.set   RR11, %zmm25
.set   RR12, %zmm26
.set   RR13, %zmm27
.set   RR14, %zmm28

.set   R1, %zmm19
.set   R2, %zmm20
.set   R3, %zmm21
.set   R4, %zmm22

.set    A0xmm,  %xmm0
.set    A1xmm,  %xmm5
.set    A2xmm,  %xmm6
.set    A3xmm,  %xmm7
.set    A4xmm,  %xmm8
.set    B0xmm,  %xmm1
.set    B1xmm,  %xmm11
.set    B2xmm,  %xmm12
.set    B3xmm,  %xmm13
.set    B4xmm,  %xmm14
##  .set    M0xmm, %xmm2
.set    R0xmm,  %xmm3
.set    R1xmm,  %xmm19
.set    R2xmm,  %xmm20
.set    R3xmm,  %xmm21
.set    R4xmm,  %xmm22

.set    R5xmm,  %xmm15
.set    R6xmm,  %xmm16
.set    R7xmm,  %xmm17
.set    R8xmm,  %xmm18
.set    R9xmm,  %xmm23
.set    R10xmm,  %xmm24
.set    R11xmm,  %xmm25
.set    R12xmm,  %xmm26
.set    R13xmm,  %xmm27
.set    R14xmm,  %xmm28




    .global call_rrmontmul
    .type   call_rrmontmul, @function
    .align  64

call_rrmontmul:

    #stack balance
    subq        $128,   %rsp

	movq		%r12, (%rsp)
    movq		%r13, 8(%rsp)
    movq        %rdi,   16(%rsp)
    movq        %rsi,   24(%rsp)
    movq        %rdx,   32(%rsp)
    movq        %rcx,   40(%rsp) 
    movq        %rbx,   48(%rsp)
    movq        %r14,   56(%rsp)
    movq        %r15,   64(%rsp)
    movq        %rbp,   72(%rsp)   


    #zero register

    vpxorq A0, A0, A0
    vpxorq B0, B0, B0

    vpxorq R0, R0, R0
    vpxorq A1, A1, A1
    vpxorq B1, B1, B1

    vpxorq R1, R1, R1
    vpxorq A2, A2, A2
    vpxorq B2, B2, B2
   
    vpxorq R2, R2, R2
    vpxorq A3, A3, A3
    vpxorq B3, B3, B3

    vpxorq R3, R3, R3
    vpxorq A4, A4, A4
    vpxorq B4, B4, B4

    vpxorq R4, R4, R4
    vpxorq T, T, T
    vpxorq TT, TT, TT
    vpxorq R5, R5, R5
    vpxorq R6, R6, R6
    vpxorq R7, R7, R7

    vpxorq RR8, RR8, RR8
    vpxorq RR9, RR9, RR9
    vpxorq RR10, RR10, RR10
    vpxorq RR11, RR11, RR11
    vpxorq RR12, RR12, RR12
    vpxorq RR13, RR13, RR13


    xorq        %rax, %rax
    xorq        %rbp, %rbp
    xorq        %r9, %r9
    xorq        %r10, %r10
    xorq        %r12, %r12
    xorq        %r13, %r13
    xorq        %r14, %r14
    xorq        %r15, %r15


    xorq        %rbx, %rbx


    # load A    B

    vmovdqu64   (%rsi), A0
    vmovdqu64   (%rdx), B0

    vmovdqu64   64(%rsi), A1
    vmovdqu64   64(%rdx), B1

    vmovdqu64   128(%rsi), A2
    vmovdqu64  128(%rdx), B2

    vmovdqu64   192(%rsi), A3
    vmovdqu64  192(%rdx), B3

    vmovdqu64   256(%rsi), A4
    vmovdqu64  256(%rdx), B4

    vpxorq      %zmm10, %zmm10, %zmm10

    #load result  R  used to restore X0~Xq
    vmovdqu64   (%rdi), R0
    vmovdqu64   64(%rdi), R1
    vmovdqu64  128(%rdi), R2
    vmovdqu64   192(%rdi), R3
    vmovdqu64   256(%rdi), R4      

    ### start   big integer multiply ###

    # The first round b0

    #mul:   multiply rax and r64 , the result is restored in rdx(high 64 bits) and rax(low 64 bits)
    #add:    add the first src1 to the second src2, the result is restored in src2

    vmovq       B0xmm,  %r14

    # broadcast b0 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10


    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    #The first round finish

    #The second round b1

    valignq     $1, B0, %zmm10, B0
    vmovq       B0xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    #The second round finish

    # 3 round start b2
    valignq     $1, B0, %zmm10, B0
    vmovq       B0xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4

    # 3 round finish

    # 4 round start b3
    valignq     $1, B0, %zmm10, B0
    vmovq       B0xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4

    # 4 round finish

    # 5 round start b4
   valignq     $1, B0, %zmm10, B0
    vmovq       B0xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 5 round finish

    # 6 round start b5
    valignq     $1, B0, %zmm10, B0
    vmovq       B0xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 6 round finish

    # 7 round start b6
    valignq     $1, B0, %zmm10, B0
    vmovq       B0xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 7 round finish

    # 8 round start b7
    valignq     $1, B0, %zmm10, B0
    vmovq       B0xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R5, %zmm10, R5
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 8 round finish

    # 9 round start b8

    vmovq       B1xmm,  %r14

    # broadcast b8 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10


    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 9 round finish

    # 10 round start b9
    valignq     $1, B1, %zmm10, B1
    vmovq       B1xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 10 round finish

    # 11 round start b10
    valignq     $1, B1, %zmm10, B1
    vmovq       B1xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 11 round finish

    # 12 round start b11
    valignq     $1, B1, %zmm10, B1
    vmovq       B1xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 12 round finish

    # 13 round start b12
    valignq     $1, B1, %zmm10, B1
    vmovq       B1xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 13 round finish

    # 14 round start b13
    valignq     $1, B1, %zmm10, B1
    vmovq       B1xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 14 round finish

    # 15 round start b14
    valignq     $1, B1, %zmm10, B1
    vmovq       B1xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 15 round finish

    # 16 round start b15
    valignq     $1, B1, %zmm10, B1
    vmovq       B1xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R6, %zmm10, R6
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 16 round finish

    # 17 round start b16

    vmovq       B2xmm,  %r14

    # broadcast b0 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10


    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 17 round finish

    # 18 round start b17

    valignq     $1, B2, %zmm10, B2
    vmovq       B2xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 18 round finish

    # 19 round start b18
    valignq     $1, B2, %zmm10, B2
    vmovq       B2xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 19 round finish

    # 20 round start b19
    valignq     $1, B2, %zmm10, B2
    vmovq       B2xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 20 round finish

    # 21 round start b20
    valignq     $1, B2, %zmm10, B2
    vmovq       B2xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 21 round finish

    # 22 round start b21
    valignq     $1, B2, %zmm10, B2
    vmovq       B2xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 22 round finish

    # 23 round start b22
    valignq     $1, B2, %zmm10, B2
    vmovq       B2xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 23 round finish

    # 24 round start b23
   valignq     $1, B2, %zmm10, B2
    vmovq       B2xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, R7, %zmm10, R7
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 24 round finish

    # 25 round start b24

    vmovq       B3xmm,  %r14

    # broadcast b0 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10


    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 25 round finish
    
    # 26 round start b25

    valignq     $1, B3, %zmm10, B3
    vmovq       B3xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 26 round finish

    # 27 round start b26
    valignq     $1, B3, %zmm10, B3
    vmovq       B3xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 27 round finish

    # 28 round start b27
    valignq     $1, B3, %zmm10, B3
    vmovq       B3xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 28 round finish

    # 29 round start b28
    valignq     $1, B3, %zmm10, B3
    vmovq       B3xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 29 round finish

    # 30 round start b29
    valignq     $1, B3, %zmm10, B3
    vmovq       B3xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 30 round finish

    # 31 round start b30
    valignq     $1, B3, %zmm10, B3
    vmovq       B3xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 31 round finish

    # 32 round start b31
    valignq     $1, B3, %zmm10, B3
    vmovq       B3xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR8, %zmm10, RR8
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 32 round finish

    # 33 round start b32

    vmovq       B4xmm,  %r14

    # broadcast b0 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR9, %zmm10, RR9
    vpxorq      %zmm10, %zmm10, %zmm10


    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 33 round finish

    # 34 round start b33

    valignq     $1, B4, %zmm10, B4
    vmovq       B4xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR9, %zmm10, RR9
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 34 round finish

    # 35 round start b34
    valignq     $1, B4, %zmm10, B4
    vmovq       B4xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR9, %zmm10, RR9
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 35 round finish

    # 36 round start b35
    valignq     $1, B4, %zmm10, B4
    vmovq       B4xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR9, %zmm10, RR9
    vpxorq      %zmm10, %zmm10, %zmm10

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # 36 round finish

    #The last round : 37 round start b36
    valignq     $1, B4, %zmm10, B4
    vmovq       B4xmm,  %r14

    # broadcast b1 
    vpbroadcastq    %r14,   T

    #compute    for j=1~q,  X[j] = X[j] + A[j] * T
    vpmuludq    A0,     T,      TT 
    vpaddq          R0,     TT,      R0 

    vpmuludq    A1,     T,      TT
    vpaddq          R1,     TT,      R1 

    vpmuludq    A2,     T,      TT 
    vpaddq          R2,     TT,    R2 

    vpmuludq    A3,     T,      TT 
    vpaddq          R3,     TT,      R3

    vpmuludq    A4,     T,      TT 
    vpaddq          R4,     TT,      R4

    #store R0[0]
    vmovq   R0xmm,  %rax
    vmovq    %rax,   %xmm10
    valignq     $1, RR9, %zmm10, RR9
    vpxorq      %zmm10, %zmm10, %zmm10
    
    valignq     $1, RR9, %zmm10, RR9
    valignq     $1, RR9, %zmm10, RR9
    valignq     $1, RR9, %zmm10, RR9

    # Xq...X1=Xq...X1>>64
    valignq     $1, R0, R1, R0
    valignq     $1, R1, R2, R1
    valignq     $1, R2, R3, R2
    valignq     $1, R3, R4, R3
    valignq     $1, R4, %zmm10, R4
    # The last round : 37 round finish

    ###  The big integer multiply finish ###

    ## The sequence is R5 R6 R7 RR8 RR9 R0 R1 R2 R3 R4 (R4 has 4 digits and RR9 has 5 digits)
    ## RR10 RR11 RR12 RR13 is used for store results

    ###   transfer   the  redundant to 2^m  and immediately transfer to 2^64
    # rbp is for temp register
    #  In every round , transfer the 28 bits into 64 bits.   %r11 is used.

    xorq        %r11, %r11
    xorq        %rbp, %rbp


    #v0   rbx for u0
    vmovq   R5xmm,  %rbx
    valignq     $1, R5, %zmm10, R5
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v1   rbx for u1
    vmovq   R5xmm,  %rbx
    valignq     $1, R5, %zmm10, R5
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $28,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v2   rbx for u2
    vmovq   R5xmm,  %rbx
    valignq     $1, R5, %zmm10, R5
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000000ff,    %rax
    shl       $56,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    movq   %rbp,    %rax 
    and     $0x000000000fffff00,    %rax
    shr         $8,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v3   rbx for u3
    vmovq   R5xmm,  %rbx
    valignq     $1, R5, %zmm10, R5
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $20,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v4   rbx for u4
    vmovq   R5xmm,  %rbx
    valignq     $1, R5, %zmm10, R5
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000000ffff,    %rax
    shl       $48,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    movq   %rbp,    %rax 
    and     $0x000000000fff0000,    %rax
    shr         $16,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v5   rbx for u5
    vmovq   R5xmm,  %rbx
    valignq     $1, R5, %zmm10, R5
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $12,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v6   rbx for u6
    vmovq   R5xmm,  %rbx
    valignq     $1, R5, %zmm10, R5
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000ffffff,    %rax
    shl       $40,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    movq   %rbp,    %rax 
    and     $0x000000000f000000,    %rax
    shr         $24,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v7   rbx for u7
    vmovq   R5xmm,  %rbx
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $4,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v8   rbx for u8
    vmovq   R6xmm,  %rbx
    valignq     $1, R6, %zmm10, R6
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $32,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v9   rbx for u9
    vmovq   R6xmm,  %rbx
    valignq     $1, R6, %zmm10, R6
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000000000f,    %rax
    shl       $60,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    movq   %rbp,    %rax 
    and     $0x000000000ffffff0,    %rax
    shr         $4,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v10   rbx for u10
    vmovq   R6xmm,  %rbx
    valignq     $1, R6, %zmm10, R6
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $24,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v11   rbx for u11
    vmovq   R6xmm,  %rbx
    valignq     $1, R6, %zmm10, R6
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000000fff,    %rax
    shl       $52,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    movq   %rbp,    %rax 
    and     $0x000000000ffff000,    %rax
    shr         $12,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v12   rbx for u12
    vmovq   R6xmm,  %rbx
    valignq     $1, R6, %zmm10, R6
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $16,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v13   rbx for u13
    vmovq   R6xmm,  %rbx
    valignq     $1, R6, %zmm10, R6
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000fffff,    %rax
    shl       $44,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    movq   %rbp,    %rax 
    and     $0x000000000ff00000,    %rax
    shr         $20,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v14   rbx for u14
    vmovq   R6xmm,  %rbx
    valignq     $1, R6, %zmm10, R6
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $8,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v15  rbx for u15
    vmovq   R6xmm,  %rbx
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $36,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    shr         $28,    %rbp

    #v16   rbx for u16
    vmovq   R7xmm,  %rbx
    valignq     $1, R7, %zmm10, R7
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v17   rbx for u17
    vmovq   R7xmm,  %rbx
    valignq     $1, R7, %zmm10, R7
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $28,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v18   rbx for u18
    vmovq   R7xmm,  %rbx
    valignq     $1, R7, %zmm10, R7
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000000ff,    %rax
    shl       $56,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R11xmm
    valignq   $1, RR10, RR11, RR10
    movq   %rbp,    %rax 
    and     $0x000000000fffff00,    %rax
    shr         $8,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v19   rbx for u19
    vmovq   R7xmm,  %rbx
    valignq     $1, R7, %zmm10, R7
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $20,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v20   rbx for u20
    vmovq   R7xmm,  %rbx
    valignq     $1, R7, %zmm10, R7
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000000ffff,    %rax
    shl       $48,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    movq   %rbp,    %rax 
    and     $0x000000000fff0000,    %rax
    shr         $16,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v21   rbx for u21
    vmovq   R7xmm,  %rbx
    valignq     $1, R7, %zmm10, R7
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $12,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v22   rbx for u22
    vmovq   R7xmm,  %rbx
    valignq     $1, R7, %zmm10, R7
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000ffffff,    %rax
    shl       $40,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    movq   %rbp,    %rax 
    and     $0x000000000f000000,    %rax
    shr         $24,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v23   rbx for u23
    vmovq   R7xmm,  %rbx
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $4,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v24   rbx for u24
    vmovq   R8xmm,  %rbx
    valignq     $1, RR8, %zmm10, RR8
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $32,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v25   rbx for u25
    vmovq   R8xmm,  %rbx
    valignq     $1, RR8, %zmm10, RR8
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000000000f,    %rax
    shl       $60,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    movq   %rbp,    %rax 
    and     $0x000000000ffffff0,    %rax
    shr         $4,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v26   rbx for u26
    vmovq   R8xmm,  %rbx
    valignq     $1, RR8, %zmm10, RR8
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $24,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v27   rbx for u27
    vmovq   R8xmm,  %rbx
    valignq     $1, RR8, %zmm10, RR8
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000000fff,    %rax
    shl       $52,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    movq   %rbp,    %rax 
    and     $0x000000000ffff000,    %rax
    shr         $12,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v28   rbx for u28
    vmovq   R8xmm,  %rbx
    valignq     $1, RR8, %zmm10, RR8
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $16,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v29   rbx for u29
    vmovq   R8xmm,  %rbx
    valignq     $1, RR8, %zmm10, RR8
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000fffff,    %rax
    shl       $44,      %rax
    add     %rax,   %r11
   vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    movq   %rbp,    %rax 
    and     $0x000000000ff00000,    %rax
    shr         $20,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v30  rbx for u30
    vmovq   R8xmm,  %rbx
    valignq     $1, RR8, %zmm10, RR8
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $8,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v31   rbx for u31
    vmovq   R8xmm,  %rbx
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $36,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    shr         $28,    %rbp

    #v32   rbx for u32
    vmovq   R9xmm,  %rbx
    valignq     $1, RR9, %zmm10, RR9
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v33   rbx for u33
    vmovq   R9xmm,  %rbx
    valignq     $1, RR9, %zmm10, RR9
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $28,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v34   rbx for u34
    vmovq   R9xmm,  %rbx
    valignq     $1, RR9, %zmm10, RR9
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000000ff,    %rax
    shl       $56,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    movq   %rbp,    %rax 
    and     $0x000000000fffff00,    %rax
    shr         $8,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v35   rbx for u35
    vmovq   R9xmm,  %rbx
    valignq     $1, RR9, %zmm10, RR9
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $20,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v36   rbx for u36
    vmovq   R9xmm,  %rbx
    valignq     $1, RR9, %zmm10, RR9
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
   and     $0x000000000000ffff,    %rax
    shl       $48,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R12xmm
    valignq   $1, RR11, RR12, RR11
    vpxorq       %zmm10, %zmm10, %zmm10 
    movq   %rbp,    %rax 
    and     $0x000000000fff0000,    %rax
    shr         $16,    %rax
    movq   %rax,   %rbp

    #v37   rbx for u37
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $12,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v38   rbx for u38
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000ffffff,    %rax
    shl       $40,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    movq   %rbp,    %rax 
    and     $0x000000000f000000,    %rax
    shr         $24,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v39   rbx for u39
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $4,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v40   rbx for u40
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $32,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v41   rbx for u41
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000000000f,    %rax
    shl       $60,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    movq   %rbp,    %rax 
    and     $0x000000000ffffff0,    %rax
    shr         $4,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v42   rbx for u42
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $24,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v43   rbx for u43
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000000fff,    %rax
    shl       $52,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    movq   %rbp,    %rax 
    and     $0x000000000ffff000,    %rax
    shr         $12,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v44   rbx for u44
    vmovq   R0xmm,  %rbx
    valignq     $1, R0, %zmm10, R0
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $16,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v45   rbx for u45
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000fffff,    %rax
    shl       $44,      %rax
    add     %rax,   %r11
   vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    movq   %rbp,    %rax 
    and     $0x000000000ff00000,    %rax
    shr         $20,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v46  rbx for u46
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $8,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v47   rbx for u47
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $36,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    shr         $28,    %rbp

    #v48   rbx for u48
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v49   rbx for u49
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $28,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v50   rbx for u50
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000000ff,    %rax
    shl       $56,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    movq   %rbp,    %rax 
    and     $0x000000000fffff00,    %rax
    shr         $8,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v51   rbx for u51
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $20,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v52   rbx for u52
    vmovq   R1xmm,  %rbx
    valignq     $1, R1, %zmm10, R1
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
   and     $0x000000000000ffff,    %rax
    shl       $48,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    vpxorq       %zmm10, %zmm10, %zmm10 
    movq   %rbp,    %rax 
    and     $0x000000000fff0000,    %rax
    shr         $16,    %rax
    movq   %rax,   %rbp

    #v53   rbx for u53
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $12,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v54   rbx for u54
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000ffffff,    %rax
    shl       $40,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R13xmm
    valignq   $1, RR12, RR13, RR12
    movq   %rbp,    %rax 
    and     $0x000000000f000000,    %rax
    shr         $24,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v55   rbx for u55
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $4,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v56   rbx for u56
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $32,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v57   rbx for u57
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000000000f,    %rax
    shl       $60,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13
    movq   %rbp,    %rax 
    and     $0x000000000ffffff0,    %rax
    shr         $4,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v58   rbx for u58
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $24,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v59   rbx for u59
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000000fff,    %rax
    shl       $52,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13
    movq   %rbp,    %rax 
    and     $0x000000000ffff000,    %rax
    shr         $12,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v60   rbx for u60
    vmovq   R2xmm,  %rbx
    valignq     $1, R2, %zmm10, R2
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $16,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v61   rbx for u61
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000fffff,    %rax
    shl       $44,      %rax
    add     %rax,   %r11
   vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13
    movq   %rbp,    %rax 
    and     $0x000000000ff00000,    %rax
    shr         $20,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v62  rbx for u62
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $8,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v63   rbx for u63
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $36,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13
    shr         $28,    %rbp

    #v64   rbx for u64
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v65   rbx for u65
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $28,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v66   rbx for u66
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x00000000000000ff,    %rax
    shl       $56,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13
    movq   %rbp,    %rax 
    and     $0x000000000fffff00,    %rax
    shr         $8,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v67   rbx for u67
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $20,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v68   rbx for u68
    vmovq   R3xmm,  %rbx
    valignq     $1, R3, %zmm10, R3
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
   and     $0x000000000000ffff,    %rax
    shl       $48,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13
    movq   %rbp,    %rax 
    and     $0x000000000fff0000,    %rax
    shr         $16,    %rax
    movq   %rax,   %rbp

    #v69   rbx for u69
    vmovq   R4xmm,  %rbx
    valignq     $1, R4, %zmm10, R4
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $12,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v70   rbx for u70
    vmovq   R4xmm,  %rbx
    valignq     $1, R4, %zmm10, R4
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x0000000000ffffff,    %rax
    shl       $40,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13
    movq   %rbp,    %rax 
    and     $0x000000000f000000,    %rax
    shr         $24,    %rax
    movq   %rax,   %r11
    shr         $28,    %rbp

    #v71   rbx for u71
    vmovq   R4xmm,  %rbx
    valignq     $1, R4, %zmm10, R4
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $4,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v72   rbx for u72
    vmovq   R4xmm,  %rbx
    valignq     $1, R4, %zmm10, R4
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000fffffff,    %rax
    shl       $32,      %rax
    add     %rax,   %r11
    shr         $28,    %rbp

    #v73   rbx for u73
    vmovq   R4xmm,  %rbx
    valignq     $1, R4, %zmm10, R4
    add     %rbx,   %rbp
    movq   %rbp,    %rax 
    and     $0x000000000000000f,    %rax
    shl       $60,      %rax
    add     %rax,   %r11
    vmovq   %r11,   R14xmm
    valignq   $1, RR13, RR14, RR13

    # transfer finish

    /*
    # load R into rdi
    movq               %rbx,  (%rdi)
    vmovdqu64   R0,     8(%rdi)
    vmovdqu64   R1,     72(%rdi)
    vmovdqu64   R2,     136(%rdi)
    vmovdqu64   R3,     200(%rdi)
    vmovdqu64   R4,     264(%rdi)
    */

    /*
    # load A into rdi
    vmovdqu64   A0,     (%rdi)
    vmovdqu64   A1,     64(%rdi)
    vmovdqu64   A2,     128(%rdi)
    vmovdqu64   A3,     192(%rdi)
    vmovdqu64   A4,     256(%rdi)
    movq               %rbp,  320(%rdi)
    */

    #load RR10 ~ RR13 into rdi
    vmovdqu64   RR10,     (%rdi)
    vmovdqu64   RR11,     64(%rdi)
    vmovdqu64   RR12,     128(%rdi)
    vmovdqu64   RR13,     192(%rdi)
   
   ## movq                %rbp,   128(%rdi)

    ## recovery ##

    movq    (%rsp),     %r12
    movq    8(%rsp),     %r13
    movq    32(%rsp),     %rdx
    movq    48(%rsp),     %rbx
    movq    56(%rsp),     %r14
    movq    64(%rsp),     %r15
    movq    72(%rsp),     %rbp
    movq     16(%rsp),     %rdi
    movq      24(%rsp),    %rsi
    movq      32(%rsp),    %rdx
    movq       40(%rsp) ,   %rcx

    addq        $128,   %rsp

    ret
    .size	call_rrmontmul, .-call_rrmontmul
