.section .data

.section .text

.type reg_init, @function
.globl reg_init

reg_init:
	xor %rcx, %rcx
	xor %rax, %rax
	xor %rdx, %rdx
	mov $0, %rax
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 1
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 2
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 3
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 4
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 5
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 6
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 7
	mov (%rdi,%rax,1), %dl
	mov %rdx, %dr0
	xor %rdx, %rdx
	inc %rax # 8
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 9
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 10
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 11
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 12
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 13
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 14
	mov (%rdi,%rax,1), %dl
	shl $8, %rdx
	inc %rax # 15
	mov (%rdi,%rax,1), %dl
	mov %rdx, %dr1
	mov $1, %eax
	ret