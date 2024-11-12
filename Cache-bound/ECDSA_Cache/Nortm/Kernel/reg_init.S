.section .data

.section .text

.type reg_init, @function
.globl reg_init

reg_init:
	push %rdx
	mov (%rdi), %rdx
	mov %rdx, %dr0
	mov 8(%rdi), %rdx
	mov %rdx, %dr1
	mov $1, %eax
	pop %rdx
	ret