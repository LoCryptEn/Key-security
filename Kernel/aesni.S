.file	"aes.S"
.text

.set    rstate,     %xmm0  //AES state
.set    rhelp,     %xmm1  //helping reg 1
.set    round_key_i,     %xmm2  //round key i
.set    round_key_j,     %xmm3  //round key j
.set    mes,      %xmm15 //message

.macro      key_shedule     r0      r1      rcon
    pxor    rhelp,      rhelp
    movdqu      \r0,    \r1
    shufps      $0x1f,      \r1,    rhelp   
    pxor    rhelp,      \r1  
    shufps      $0x8c,      \r1,    rhelp
    pxor    rhelp,      \r1  
    aeskeygenassist      $\rcon,      \r0,    rhelp
    shufps      $0xff,      rhelp,    rhelp
    pxor    rhelp,      \r1 
.endm


#ENC用到：round_key_i round_key_j  rhelp （不算mes(因为本来就会用到),rstate(直接从DR里取到),3个寄存器） 
.macro      aes_enc
    vmovdqu     rstate,    round_key_i
    pxor    round_key_i,     mes
    key_shedule     round_key_i     round_key_j     0x1
    aesenc     round_key_j,     mes
    key_shedule     round_key_j     round_key_i     0x2
    aesenc     round_key_i,     mes
    key_shedule     round_key_i     round_key_j     0x4
    aesenc     round_key_j,     mes
    key_shedule     round_key_j     round_key_i     0x8
    aesenc     round_key_i,     mes
    key_shedule     round_key_i     round_key_j     0x10
    aesenc     round_key_j,     mes
    key_shedule     round_key_j     round_key_i     0x20
    aesenc     round_key_i,     mes
    key_shedule     round_key_i     round_key_j     0x40
    aesenc     round_key_j,     mes
    key_shedule     round_key_j     round_key_i     0x80
    aesenc     round_key_i,     mes
    key_shedule     round_key_i     round_key_j     0x1b
    aesenc     round_key_j,     mes
    key_shedule     round_key_j     round_key_i     0x36
    aesenclast     round_key_i,     mes
.endm

#生成解密用第i轮密钥，假设128bit AES，round为 0-10，共11轮密钥，这个宏用来生成1-10轮,
#结果放在 round_key_i
key_shedule_for_round_ith:
    # 保存寄存器-略

    movq %rdi, %rax #加载key_shedule执行次数到 %eax
     # 检查是否为 0
    cmpl $0, %eax
    je .L_key_shedule_for_round_end_after_imc
    key_shedule     round_key_i     round_key_j     0x1
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_j     round_key_i     0x2
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_i     round_key_j     0x4
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_j     round_key_i     0x8
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_i     round_key_j     0x10
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_j     round_key_i     0x20
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_i     round_key_j     0x40
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_j     round_key_i     0x80
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_i     round_key_j     0x1b
    decl %eax
    cmpl $0, %eax
    je .L_key_shedule_for_round_end
    key_shedule     round_key_j     round_key_i     0x36

    
.L_key_shedule_for_round_end:
    decl %eax
    cmpl $0, %eax   
    je .L_key_shedule_for_round_end_after_imc
    movq %rdi, %rax
    testb $1,%al
    jz .L_no_copy_from_round_key_j_to_round_key_i
    vmovdqu  round_key_j, round_key_i
.L_no_copy_from_round_key_j_to_round_key_i:
    movq %rdi, %rax
    cmpl $10, %eax
    je .L_key_shedule_for_round_end_after_imc
    aesimc  round_key_i,    round_key_i
.L_key_shedule_for_round_end_after_imc:  #第0/10轮不用imc
    # 恢复寄存器-略
    #Recovery


    ret


   


.macro      aes_dec
    pushq %rax
    pushq %rdi
    vmovdqu     rstate,    round_key_i
    # 调用函数 key_shedule_for_round_ith
    movq $10, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    pxor    round_key_i,     mes
    vmovdqu     rstate,    round_key_i
     # 调用函数 key_shedule_for_round_ith
    movq $9, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes 
    vmovdqu     rstate,    round_key_i
 
     # 调用函数 key_shedule_for_round_ith
    movq $8, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
    vmovdqu     rstate,    round_key_i
     # 调用函数 key_shedule_for_round_ith
    movq $7, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
    vmovdqu     rstate,    round_key_i
         # 调用函数 key_shedule_for_round_ith
    movq $6, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
        vmovdqu     rstate,    round_key_i
            # 调用函数 key_shedule_for_round_ith
    movq $5, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
        vmovdqu     rstate,    round_key_i
         # 调用函数 key_shedule_for_round_ith
    movq $4, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
        vmovdqu     rstate,    round_key_i
          # 调用函数 key_shedule_for_round_ith
    movq $3, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
        vmovdqu     rstate,    round_key_i
         # 调用函数 key_shedule_for_round_ith
    movq $2, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
        vmovdqu     rstate,    round_key_i
         # 调用函数 key_shedule_for_round_ith
    movq $1, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdec     round_key_i,     mes
        vmovdqu     rstate,    round_key_i
         # 调用函数 key_shedule_for_round_ith
    movq $0, %rdi  # 传递参数 
    call key_shedule_for_round_ith
    aesdeclast     round_key_i,     mes
    popq %rax
    popq %rdi
.endm