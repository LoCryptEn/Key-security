.section .data
sbox:
	.byte 0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48

.section .text

.type sm4_dec_master, @function
.globl sm4_dec_master
sm4_dec_master:
	# ready
	push %rbx # push sample register need calle save
	push %r12
	push %r13
	push %r14
	push %r15
	push %rdx # push third argument register
	push %rsi # second
	# push %rdi
	# KEY DERIVE
	# xor %rax, %rax
	mov %dr0, %rdx # k0 = mk0 xor fk0 # k1 = mk1 xor fk1
	mov $0xA3B1BAC656AA3350, %rcx
	xor %rcx, %rdx
	mov %dr1, %rsi # k2 = mk2 xor fk2 # k3 = mk3 xor fk3
	mov $0x677D9197B27022DC, %rcx
	xor %rcx, %rsi
	# rk0 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x00070E15, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk1 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x1C232A31, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk2 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x383F464D, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk3 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x545B6269, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk4 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x70777E85, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk5 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x8C939AA1, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk6 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk7 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk8 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk9 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk10 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk11 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk12 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk13 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk14 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk15 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk16 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk17 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk18 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk19 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov r16-r19 to %r8-%r9
	mov %rdx, %r8
	mov %rsi, %r9
	# rk20 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk21 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk22 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk23 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov rk20-rk23 to %r10-%r11
	mov %rdx, %r10
	mov %rsi, %r11
	# rk24 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk25 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk26 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk27 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov rk24-rk27 to %r12-%r13
	mov %rdx, %r12
	mov %rsi, %r13
	# rk28 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk29 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk30 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk31 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov rk28-rk31 to %r14-%r15
	mov %rdx, %r14
	mov %rsi, %r15
	# get input
	pop %rsi
	# push %rdi
	mov $0, %rcx # mov input0 to %rdi
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	mov %eax, %edi
	shl $32, %rdi
	inc %rcx # mov input1 to %rdi
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	xor %rax, %rdi
	inc %rcx # mov input2 to %rbx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	mov %eax, %ebx
	shl $32, %rbx
	inc %rcx # mov input3 to %rbx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	shl $8, %eax
	inc %rcx
	movb (%rsi,%rcx,1), %al
	xor %rax, %rbx
	# ROUND 0
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r15, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 1
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r15
	and %r15, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 2
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r14, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 3
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r14
	and %r14, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 4
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r13, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 5
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r13
	and %r13, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 6
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r12, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 7
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r12
	and %r12, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 8
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r11, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 9
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r11
	and %r11, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 10
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r10, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 11
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r10
	and %r10, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 12
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r9, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 13
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r9
	and %r9, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 14
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r8, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 15
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r8
	and %r8, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# store rdi, rbx
	mov %rdi, %r14
	mov %rbx, %r15
	# regenerate rk0-rk15
	# pop %rdi
	mov %dr0, %rdx # k0 = mk0 xor fk0 # k1 = mk1 xor fk1
	mov $0xA3B1BAC656AA3350, %rcx
	xor %rcx, %rdx
	mov %dr1, %rsi # k2 = mk2 xor fk2 # k3 = mk3 xor fk3
	mov $0x677D9197B27022DC, %rcx
	xor %rcx, %rsi
	# rk0 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x00070E15, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
# rk1 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x1C232A31, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk2 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x383F464D, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk3 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x545B6269, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov rk0-rk3 to %r8-%r9
	mov %rdx, %r8
	mov %rsi, %r9
	# rk4 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x70777E85, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk5 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	mov $0x8C939AA1, %ecx
	xor %ecx, %eax
	# xor %ecx, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk6 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk7 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov rk4-rk7 to %r10-%r11
	mov %rdx, %r10
	mov %rsi, %r11
	# rk8 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk9 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk10 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk11 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov rk8-rk11 to %r12-%r13
	mov %rdx, %r12
	mov %rsi, %r13
	# rk12 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk13 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk14 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# rk15 generate
	mov $0xFFFFFFFF, %eax # k1 xor k3 xor k2 xor ck0
	and %edx, %eax
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
	xor %ecx, %eax
	rol $32, %rsi
	mov $0xFFFFFFFF, %ecx
	and %esi, %ecx
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
	rol $32, %rdx # k0 xor T'
	mov $0xFFFFFFFF, %eax
	and %edx, %eax
	xor %eax, %ecx
	shr $32, %rdx # k0 = k1, k1 = k2 , k2 = k3, k3 = k4 = r0
	shl $32, %rdx
	mov $0xFFFFFFFF, %eax 
	and %esi, %eax
	xor %rax, %rdx
	shr $32, %rsi
	shl $32, %rsi
	xor %rcx, %rsi
	# mov round out, mov key in
	mov %r14, %rdi
	mov %r15, %rbx
	mov %rdx, %r14
	mov %rsi, %r15
	# ROUND 16
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r15, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 17
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r15
	and %r15, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 18
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r14, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 19
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r14
	and %r14, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 20
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r13, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 21
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r13
	and %r13, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 22
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r12, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 23
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r12
	and %r12, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 24
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r11, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 25
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r11
	and %r11, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 26
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r10, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 27
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r10
	and %r10, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 28
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r9, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 29
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r9
	and %r9, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 30
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	and %r8, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx
	# ROUND 31
	mov $0xFFFFFFFF, %eax # x1 xor x3 xor x2 xor rk31
	and %edi, %eax
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	rol $32, %rbx
	mov $0xFFFFFFFF, %ecx
	and %ebx, %ecx
	xor %ecx, %eax
	mov $0xFFFFFFFF, %ecx
	shr $32, %r8
	and %r8, %rcx
	xor %ecx, %eax
	mov %eax, %ecx # tao
	and $0xFF000000, %ecx
	shr $24, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x00FF0000, %ecx
	shr $16, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
	mov %eax, %ecx
	and $0x0000FF00, %ecx
	shr $8, %ecx
	movb sbox(,%rcx,1), %dl
	shl $8, %edx
	xor %rcx, %rcx
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
	rol $32, %rdi # x4 = x0 xor T
	mov $0xFFFFFFFF, %eax
	and %edi, %eax
	xor %eax, %edx
	mov $0xFFFFFFFF, %eax # mov x0 = x1, x1 = x2, x2 = x3, x3 = x4
	and %ebx, %eax
	shr $32, %rdi
	shl $32, %rdi
	xor %rax, %rdi
	shr $32, %rbx
	shl $32, %rbx
	xor %rdx, %rbx

	# output
	pop %rdx # mov rbx to output[8-15]
	mov $3, %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rbx
	dec %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rbx
	dec %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rbx
	dec %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rbx
	mov $7, %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rbx
	dec %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rbx
	dec %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rbx
	dec %rcx
	movb $0xFF, %al
	and %rbx, %rax
	movb %al, (%rdx,%rcx,1)
	mov $11, %rcx # mov rdi to output[0-7]
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rdi
	dec %rcx
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rdi
	dec %rcx
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rdi
	dec %rcx
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rdi
	mov $15, %rcx
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rdi
	dec %rcx
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rdi
	dec %rcx
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	shr $8, %rdi
	dec %rcx
	movb $0xFF, %al
	and %rdi, %rax
	movb %al, (%rdx,%rcx,1)
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %rbx
	mov $1, %rax
	ret