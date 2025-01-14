.section .text

.type aes_enc, @function
.type aes_dec, @function
.type aes_enc_master, @function
.type aes_dec_master, @function

.globl aes_enc
.globl aes_dec
.globl aes_enc_master
.globl aes_dec_master

.macro key_expand RCON DEST INV=0
    aeskeygenassist \RCON, %xmm0, %xmm1
    call key_combine
.if \INV
    aesimc %xmm0, \DEST #逆列混合
.else
    movapd %xmm0, \DEST
.endif
.endm


key_combine:
    pshufd $0b11111111, %xmm1, %xmm1
    shufps $0b00010000, %xmm0, %xmm2
    pxor   %xmm2, %xmm0
    shufps $0b10001100, %xmm0, %xmm2
    pxor   %xmm2, %xmm0
    pxor   %xmm1, %xmm0
    ret
 
aes_enc:
    push %rdi
    push %rsi
    push %rdx

	movupd (%rdi), %xmm0
    movapd %xmm0, %xmm5
    pxor   %xmm2, %xmm2

    key_expand $1,   %xmm6
    key_expand $2,   %xmm7
    key_expand $4,   %xmm8
    key_expand $8,   %xmm9
    key_expand $16,  %xmm10
    key_expand $32,  %xmm11
    key_expand $64,  %xmm12
    key_expand $128, %xmm13
    key_expand $27,  %xmm14
    key_expand $54,  %xmm15

    movupd (%rsi), %xmm0

    pxor       %xmm5,  %xmm0
    aesenc     %xmm6,  %xmm0
    aesenc     %xmm7,  %xmm0
    aesenc     %xmm8,  %xmm0
    aesenc     %xmm9,  %xmm0
    aesenc     %xmm10, %xmm0
    aesenc     %xmm11, %xmm0
    aesenc     %xmm12, %xmm0
    aesenc     %xmm13, %xmm0
    aesenc     %xmm14, %xmm0
    aesenclast %xmm15, %xmm0

    movupd %xmm0, (%rdx)

    pop %rdx
    pop %rsi
    pop %rdi
    mov $1,%rax
	ret


aes_dec:
    push %rdi
    push %rsi
    push %rdx

    movupd (%rdi), %xmm0        # mov key to xmm0
    movapd %xmm0, %xmm5
    pxor   %xmm2, %xmm2

    key_expand $1,   %xmm6,  1
    key_expand $2,   %xmm7,  1
    key_expand $4,   %xmm8,  1
    key_expand $8,   %xmm9,  1
    key_expand $16,  %xmm10, 1
    key_expand $32,  %xmm11, 1
    key_expand $64,  %xmm12, 1
    key_expand $128, %xmm13, 1
    key_expand $27,  %xmm14, 1
    key_expand $54,  %xmm15, 0  # No AESIMC on the last round.

    movupd (%rsi), %xmm0

    pxor       %xmm15, %xmm0
    aesdec     %xmm14, %xmm0
    aesdec     %xmm13, %xmm0
    aesdec     %xmm12, %xmm0
    aesdec     %xmm11, %xmm0
    aesdec     %xmm10, %xmm0
    aesdec     %xmm9,  %xmm0
    aesdec     %xmm8,  %xmm0
    aesdec     %xmm7,  %xmm0
    aesdec     %xmm6,  %xmm0
    aesdeclast %xmm5,  %xmm0

    movupd %xmm0, (%rdx)

    pop %rdx
    pop %rsi
    pop %rdi
    mov $1,%rax
	ret


aes_enc_master:
	push %r12
	push %r13
    push %rdi
	push %rsi

    mov %dr0, %r12
    mov %dr1, %r13
    sub $16, %rsp
    mov %r12, (%rsp)
    mov %r13, 8(%rsp)
    movupd (%rsp), %xmm0        # mov key to xmm0
	movq $0, (%rsp)  
    movq $0, 8(%rsp)            # clean key in stack
    add $16, %rsp

    movapd %xmm0, %xmm5
    pxor   %xmm2, %xmm2

    key_expand $1,   %xmm6
    key_expand $2,   %xmm7
    key_expand $4,   %xmm8
    key_expand $8,   %xmm9
    key_expand $16,  %xmm10
    key_expand $32,  %xmm11
    key_expand $64,  %xmm12
    key_expand $128, %xmm13
    key_expand $27,  %xmm14
    key_expand $54,  %xmm15

    movupd (%rdi), %xmm0

    pxor       %xmm5,  %xmm0
    aesenc     %xmm6,  %xmm0
    aesenc     %xmm7,  %xmm0
    aesenc     %xmm8,  %xmm0
    aesenc     %xmm9,  %xmm0
    aesenc     %xmm10, %xmm0
    aesenc     %xmm11, %xmm0
    aesenc     %xmm12, %xmm0
    aesenc     %xmm13, %xmm0
    aesenc     %xmm14, %xmm0
    aesenclast %xmm15, %xmm0

    movupd %xmm0, (%rsi)

    pop %rsi
    pop %rdi
	pop %r13
	pop %r12
    mov $1, %eax
	ret


aes_dec_master:
	push %r12
	push %r13
    push %rdi
	push %rsi

    mov %dr0, %r12
    mov %dr1, %r13
    sub $16, %rsp
    mov %r12, (%rsp)
    mov %r13, 8(%rsp)
    movupd (%rsp), %xmm0        # mov key to xmm0
	movq $0, (%rsp)  
    movq $0, 8(%rsp)            # clean key in stack
    add $16, %rsp

    movapd %xmm0, %xmm5
    pxor   %xmm2, %xmm2

    key_expand $1,   %xmm6,  1
    key_expand $2,   %xmm7,  1
    key_expand $4,   %xmm8,  1
    key_expand $8,   %xmm9,  1
    key_expand $16,  %xmm10, 1
    key_expand $32,  %xmm11, 1
    key_expand $64,  %xmm12, 1
    key_expand $128, %xmm13, 1
    key_expand $27,  %xmm14, 1
    key_expand $54,  %xmm15, 0  # No AESIMC on the last round.

    movupd (%rdi), %xmm0

    pxor       %xmm15, %xmm0
    aesdec     %xmm14, %xmm0
    aesdec     %xmm13, %xmm0
    aesdec     %xmm12, %xmm0
    aesdec     %xmm11, %xmm0
    aesdec     %xmm10, %xmm0
    aesdec     %xmm9,  %xmm0
    aesdec     %xmm8,  %xmm0
    aesdec     %xmm7,  %xmm0
    aesdec     %xmm6,  %xmm0
    aesdeclast %xmm5,  %xmm0

    movupd %xmm0, (%rsi)

    pop %rsi
    pop %rdi
	pop %r13
	pop %r12
    mov $1, %eax
	ret
