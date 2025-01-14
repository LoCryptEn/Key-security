// Montmul n256
// n256: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
// Input: x(256 bits in [xmm28 | xmm29]), y(256 bits in [xmm30 | xmm31])
// Output: x * y * R^-1 store in [xmm26 | xmm27]


//  Macro "mulpadd i x" adds %rdx * x to the (i,i+1) position of
//  the rotating register window %r15,...,%r8 maintaining consistent
//  double-carrying using ADCX and ADOX and using %rbx/%rax as temps

.macro mulpadd i, x
    mulx   \x, %rax, %rbx
    .if (\i % 8) == 0
        adcx   %rax, %r8
        adox   %rbx, %r9
    .elseif (\i % 8) == 1
        adcx   %rax, %r9
        adox   %rbx, %r10
    .elseif (\i % 8) == 2
        adcx   %rax, %r10
        adox   %rbx, %r11
    .elseif (\i % 8) == 3
        adcx   %rax, %r11
        adox   %rbx, %r12
    .elseif (\i % 8) == 4
        adcx   %rax, %r12
        adox   %rbx, %r13
    .elseif (\i % 8) == 5
        adcx   %rax, %r13
        adox   %rbx, %r14
    .elseif (\i % 8) == 6
        adcx   %rax, %r14
        adox   %rbx, %r15
    .elseif (\i % 8) == 7
        adcx   %rax, %r15
        adox   %rbx, %r8
    .endif
.endm



                .global  bignum_montmul_n256
                .section .text

bignum_montmul_n256:


//  CIOS round 0
        xorq    %r8,    %r8
        xorq    %r9,    %r9
        xorq    %r10,   %r10
        xorq    %r11,   %r11
        xorq    %r12,   %r12
        xorq    %r13,   %r13
        xorq    %r14,   %r14
        xorq    %r15,   %r15

        vmovq   %xmm31, %rdx
        vmovq   %xmm29, %rax
        mulx    %rax,   %r8,    %r9
        vpextrq $1,     %xmm29, %rax
        mulx    %rax,   %rbx,   %r10 
        adcx    %rbx,   %r9
        vmovq   %xmm28, %rax
        mulx    %rax,   %rbx,   %r11 
        adcx    %rbx,   %r10
        vpextrq $1,     %xmm28, %rax
        mulx    %rax,   %rbx,   %r12 
        adcx    %rbx,   %r11
        adcx    %r13,   %r12

        movq    $0xccd1c8aaee00bc4f, %rdx
        mulx    %r8,    %rdx,   %rbx   
        movq    $0xf3b9cac2fc632551, %rax
        mulpadd 0,      %rax
        movq    $0xbce6faada7179e84, %rax
        mulpadd 1,      %rax
        movq    $0xffffffffffffffff, %rax
        mulpadd 2,      %rax
        movq    $0xffffffff00000000, %rax
        mulpadd 3,      %rax
        adcx    %r13,   %r12
        adox    %r14,   %r13

//  CIOS round 1

        vpextrq $1,     %xmm31,      %rdx
        xorq    %r8,    %r8
        vmovq   %xmm29, %rax
        mulpadd 1,      %rax
        vpextrq $1,     %xmm29, %rax
        mulpadd 2,      %rax
        vmovq   %xmm28, %rax
        mulpadd 3,      %rax
        vpextrq $1,     %xmm28, %rax
        mulpadd 4,      %rax
        adcx    %r14,   %r13
        adox    %r15,   %r14

        movq    $0xccd1c8aaee00bc4f, %rdx
        mulx    %r9,    %rdx,   %rbx   
        movq    $0xf3b9cac2fc632551, %rax
        mulpadd 1,      %rax
        movq    $0xbce6faada7179e84, %rax
        mulpadd 2,      %rax
        movq    $0xffffffffffffffff, %rax
        mulpadd 3,      %rax
        movq    $0xffffffff00000000, %rax
        mulpadd 4,      %rax
        adcx    %r14,   %r13
        adox    %r15,   %r14


//  CIOS round 2

        vmovq   %xmm30, %rdx
        xorq    %r8,    %r8
        vmovq   %xmm29, %rax
        mulpadd 2,      %rax
        vpextrq $1,     %xmm29, %rax
        mulpadd 3,      %rax
        vmovq   %xmm28, %rax
        mulpadd 4,      %rax
        vpextrq $1,     %xmm28, %rax
        mulpadd 5,      %rax
        adcx    %r15,   %r14
        adox    %r8,    %r15

        movq    $0xccd1c8aaee00bc4f, %rdx
        mulx    %r10,   %rdx,   %rbx 
        movq    $0xf3b9cac2fc632551, %rax
        mulpadd 2,      %rax
        movq    $0xbce6faada7179e84, %rax
        mulpadd 3,      %rax
        movq    $0xffffffffffffffff, %rax
        mulpadd 4,      %rax
        movq    $0xffffffff00000000, %rax
        mulpadd 5,      %rax
        adcx    %r15,   %r14
        adox    %r8,    %r15


//  Add row 3

        vpextrq $1,     %xmm30,      %rdx
        xorq    %r8,    %r8
        vmovq   %xmm29, %rax
        mulpadd 3,      %rax
        vpextrq $1,     %xmm29, %rax
        mulpadd 4,      %rax
        vmovq   %xmm28, %rax
        mulpadd 5,      %rax
        vpextrq $1,     %xmm28, %rax
        mulpadd 6,      %rax
        adcx    %r8,    %r15
        adox    %r9,    %r8

        movq    $0xccd1c8aaee00bc4f, %rdx
        mulx    %r11,   %rdx,   %rbx  
        movq    $0xf3b9cac2fc632551, %rax
        mulpadd 3,      %rax
        movq    $0xbce6faada7179e84, %rax
        mulpadd 4,      %rax
        movq    $0xffffffffffffffff, %rax
        mulpadd 5,      %rax
        movq    $0xffffffff00000000, %rax
        mulpadd 6,      %rax
        adcx    %r8,    %r15
        adox    %r9,    %r8

//  compare and sub 
        xorq    %rcx,   %rcx
        xorq    %rdx,   %rdx
        xorq    %rax,   %rax
        xorq    %r9,    %r9
        xorq    %r10,   %r10
        
        movq    $0x0c46353d039cdaaf, %rcx
        addq    %r12,   %rcx
        movq    $0x4319055258e8617b, %rdx
        adcq    %r13,   %rdx
        adcq    %r14,   %rax
        movq    $0x00000000ffffffff, %r9
        adcq    %r15,   %r9
        decq    %r10
        adcq    %r8,    %r10

        cmovc   %rcx,   %r12
        cmovc   %rdx,   %r13  
        cmovc   %rax,   %r14  
        cmovc   %r9,    %r15


        vpinsrq     $1,     %r15,   %xmm26,  %xmm26
        vpinsrq     $0,     %r14,   %xmm26,  %xmm26

        vpinsrq     $1,     %r13,   %xmm27,  %xmm27
        vpinsrq     $0,     %r12,   %xmm27,  %xmm27

        ret
