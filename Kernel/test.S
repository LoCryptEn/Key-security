	.file	"test.S"
	.text

    .globl 	test
	.type  	test, @function
	.align 	64

test:

    subq    $512,   %rsp

    movq    %rdx,   (%rsp)

    addq    $1, 8000(%rdx)

    movq   (%rsp),  %rdx

    addq    $1, 16000(%rdx)

    addq    $512,   %rsp

	ret
	.size	test, .-test