.section .data
sbox:
	.byte 0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48

.section .text

.type sm4_enc, @function
.globl sm4_enc

sm4_enc:
	# ready
	push %rbx # push sample register need calle save
	push %r12
	push %r13
	push %r14
	push %r15
	push %rdx # push third argument register
	# mov input0-input3 to 
	mov $0, %rcx # mov input0 to %r8d
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	mov %eax, %r8d
	inc %rcx # mov input1 to %r9d
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	mov %eax, %r9d
	inc %rcx # mov input2 to %r10d
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	mov %eax, %r10d
	inc %rcx # mov input3 to %r11d
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	mov (%rsi,%rcx,1), %al
	mov %eax, %r11d
	# mov k0-k3 into %r12d-%r15d
	mov $0, %rbx # k0 = mk0 xor fk0
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	mov $0xA3B1BAC6, %ecx
	xor %ecx, %eax
	mov %eax, %r12d
	inc %rbx # k1 = mk1 xor fk1
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	mov $0x56AA3350, %ecx
	xor %ecx, %eax
	mov %eax, %r13d
	inc %rbx # k2 = mk2 xor fk2
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	mov $0x677D9197, %ecx
	xor %ecx, %eax
	mov %eax, %r14d
	inc %rbx # k3 = mk3 xor fk3
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	shl $8, %eax
	inc %rbx
	movb (%rdi,%rbx,1), %al
	mov $0xB27022DC, %ecx
	xor %ecx, %eax
	mov %eax, %r15d
	# ROUND 0
	# rk0 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x00070E15, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 0
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 1
	# rk1 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x1C232A31, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 1
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 2
	# rk2 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x383F464D, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 2
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 3
	# rk3 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x545B6269, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 3
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d	
	# ROUND 4
	# rk4 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x70777E85, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 4
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 5
	# rk5 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x8C939AA1, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 5
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 6
	# rk6 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xA8AFB6BD, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 6
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 7
	# rk7 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xC4CBD2D9, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 7
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 8
	# rk8 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xE0E7EEF5, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 8
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 9
	# rk9 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xFC030A11, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 9
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 10
	# rk10 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x181F262D, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 10
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 11
	# rk11 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x343B4249, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 11
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 12
	# rk12 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x50575E65, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 12
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 13
	# rk13 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x6C737A81, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 13
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 14
	# rk14 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x888F969D, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 14
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 15
	# rk15 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xA4ABB2B9, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 15
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 16
	# rk16 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xC0C7CED5, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 16
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 17
	# rk17 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xDCE3EAF1, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 17
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 18
	# rk18 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xF8FF060D, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 18
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 19
	# rk19 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x141B2229, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 19
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 20
	# rk20 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x30373E45, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 20
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 21
	# rk21 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x4C535A61, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 21
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 22
	# rk22 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x686F767D, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 22
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 23
	# rk23 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x848B9299, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 23
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d	
	# ROUND 24
	# rk24 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xA0A7AEB5, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 24
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 25
	# rk25 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xBCC3CAD1, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 25
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 26
	# rk26 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xD8DFE6ED, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 26
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 27
	# rk27 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0xF4FB0209, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 27
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 28
	# rk28 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x10171E25, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 28
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 29
	# rk29 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x2C333A41, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 29
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 30
	# rk30 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x484F565D, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 30
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %eax, %edx
	mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	mov %r10d, %r9d
	mov %r11d, %r10d
	mov %edx, %r11d
	# ROUND 31
	# rk31 generate
	mov %r13d, %eax # k1 xor k2 xor k3 xor ck0
	mov %r14d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov $0x646B7279, %ecx
	xor %ecx, %eax
	mov %eax, %ebx # tao
	and $0xFF000000, %ebx
	shr $24, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x00FF0000, %ebx
	shr $16, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x0000FF00, %ebx
	shr $8, %ebx
	movb sbox(,%rbx,1), %cl
	shl $8, %ecx
	mov %eax, %ebx
	and $0x000000FF, %ebx
	movb sbox(,%rbx,1), %cl
	mov %ecx, %eax # T' = L'
	rol $13, %eax
	xor %eax, %ecx
	rol $10, %eax
	xor %eax, %ecx
	mov %r12d, %eax # k0 xor T'
	xor %eax, %ecx
	mov %r13d, %r12d # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	mov %r14d, %r13d
	mov %r15d, %r14d
	mov %ecx, %r15d
	# enc 31
	mov %r9d, %eax # x1 xor x2 xor x3 xor rk0
	mov %r10d, %ecx
	xor %ecx, %eax
	mov %r11d, %ecx
	xor %ecx, %eax
	mov %r15d, %ecx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	mov %eax, %ecx
	and $0x000000FF, %ecx
	movb sbox(,%rcx,1), %dl
	mov %edx, %eax # T = L
	rol $2, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $8, %eax
	xor %eax, %edx
	rol $6, %eax
	xor %eax, %edx
	mov %r8d, %eax # x4 = x0 xor T
	xor %edx, %eax
	# xor %eax, %eax
	# mov %r9d, %r8d # x0 = x1, x1 = x2, x2 = x3, x3= x4
	# mov %r10d, %r9d
	# mov %r11d, %r10d
	# mov %edx, %r11d
	# output
	pop %rdx
	mov $3, %rcx # output 0
	movb $0xFF, %bl
	and %eax, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %eax
	dec %rcx
	movb $0xFF, %bl
	and %eax, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %eax
	dec %rcx
	movb $0xFF, %bl
	and %eax, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %eax
	dec %rcx
	movb $0xFF, %bl
	and %eax, %ebx 
	movb %bl, (%rdx,%rcx,1)
	mov $7, %rcx # output 1
	movb $0xFF, %bl
	and %r11d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r11d
	dec %rcx
	movb $0xFF, %bl
	and %r11d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r11d
	dec %rcx
	movb $0xFF, %bl
	and %r11d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r11d
	dec %rcx
	movb $0xFF, %bl
	and %r11d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	mov $11, %rcx # output 2
	movb $0xFF, %bl
	and %r10d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r10d
	dec %rcx
	movb $0xFF, %bl
	and %r10d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r10d
	dec %rcx
	movb $0xFF, %bl
	and %r10d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r10d
	dec %rcx
	movb $0xFF, %bl
	and %r10d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	mov $15, %rcx # output 3
	movb $0xFF, %bl
	and %r9d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r9d
	dec %rcx
	movb $0xFF, %bl
	and %r9d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r9d
	dec %rcx
	movb $0xFF, %bl
	and %r9d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	shr $8, %r9d
	dec %rcx
	movb $0xFF, %bl
	and %r9d, %ebx 
	movb %bl, (%rdx,%rcx,1)
	pop %r15 # pop sample register need calle save
	pop %r14
	pop %r13
	pop %r12
	pop %rbx 
	ret