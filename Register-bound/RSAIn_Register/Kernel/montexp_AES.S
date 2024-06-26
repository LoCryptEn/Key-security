	#include "montexp.S"
	#include "aesni.S"
		

	.file	"montexp_AES.S"
	.text




##################################################################################################
	###								###	
	### 	montexp1024_AES_p: 	load exp argument		###
	###		     		Dec argument			###	
	###		     		Call montexp 			###
	###				Enc result			###
	###				Store result			###
	###								###
##################################################################################################

	         

##################################################################################################
	###							###	
	### 	exp arg: 	0-1023		:p	:M	###
	###		     	1024-2047	:Cp	:A	###	
	###		     	2048-3071	:RRp	:B 	###
	###			3072-4095	:dmp1	:T	###
	###			4096-4159	:p0	:n0	###
	###							###
##################################################################################################





.globl 	montexp1024_AES_p
	.type  	montexp1024_AES_p, @function
	.align 	64

montexp1024_AES_p:


##################################################################################################
	###							###	
	### 	Load and Dec 					###
	###							###
	###	sum 						###
	###							###
##################################################################################################
	
	### restore rsi ###
	movq		%mm0, %rsi
	push		%rsi

	
	### load arg ###

	#####################################################################
	### load p to A B and Dec ###
	vmovdqu		(%rsi), A0xmm		#M[0] M[1]
	vmovdqu		16(%rsi), A1xmm		#M[2] M[3]
	vmovdqu		32(%rsi), A2xmm		#M[4] M[5]
	vmovdqu		48(%rsi), A3xmm		#M[6] M[7]
	vmovdqu		64(%rsi), B0xmm		#M[8] M[9]
	vmovdqu		80(%rsi), B1xmm		#M[10] M[11]
	vmovdqu		96(%rsi), B2xmm		#M[12] M[13]
	vmovdqu		112(%rsi), B3xmm	#M[14] M[15]

	#########new add#############
	movq    $0x0123456789ABCDEF,    %rax
    vmovq   %rax,   %xmm17
    valignq     $1, %ymm16, %ymm17,  %ymm16
    movq    $0xFEDCBA9876543210,    %rax
    vmovq   %rax,   %xmm17
    valignq     $3, %ymm16, %ymm17,  %ymm16
	vpxorq	A0xmm,	%xmm16,	A0xmm
	vpxorq	A1xmm,	%xmm16,	A1xmm
	vpxorq	A2xmm,	%xmm16,	A2xmm
	vpxorq	A3xmm,	%xmm16,	A3xmm
	vpxorq	B0xmm,	%xmm16,	B0xmm
	vpxorq	B1xmm,	%xmm16,	B1xmm
	vpxorq	B2xmm,	%xmm16,	B2xmm
	vpxorq	B3xmm,	%xmm16,	B3xmm
	###############################


	### load p0 to M0 and Dec ###
	addq		$512, %rsi
	vmovdqu		(%rsi), M0xmm


/*	
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### dec load arg ####
	key_schedule_128_128bit
	
	#10
	xor_arg_128_128bit
	vpxor 				rk_128, M0xmm, M0xmm

	#9
	inv_key_expansion_128_128bit	rk_128 0x36 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#8
	inv_key_expansion_128_128bit	rk_128 0x1b rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#7
	inv_key_expansion_128_128bit	rk_128 0x80 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#6
	inv_key_expansion_128_128bit	rk_128 0x40 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#5
	inv_key_expansion_128_128bit	rk_128 0x20 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#4
	inv_key_expansion_128_128bit	rk_128 0x10 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#3
	inv_key_expansion_128_128bit	rk_128 0x8 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#2
	inv_key_expansion_128_128bit	rk_128 0x4 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#1
	inv_key_expansion_128_128bit	rk_128 0x2 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#0
	inv_key_expansion_128_128bit	rk_128 0x1 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdeclast_arg_128_128bit
	vaesdeclast 			rhelp_128, M0xmm, M0xmm
*/
	### mov p0 from M0 to n0 ###
	### high 64bit is padding, is all zero ###
	vmovq				M0xmm, %rax
	movq				%rax, n0


	### rerange p to M ###

	vperm2i128	$0x20, B0, A0, M0
	vperm2i128	$0x20, B1, A1, M1
	vperm2i128	$0x20, B2, A2, M2
	vperm2i128	$0x20, B3, A3, M3

	vpermq		$0xD8, M0, M0		#imm=3120
	vpermq		$0xD8, M1, M1		#imm=3120
	vpermq		$0xD8, M2, M2		#imm=3120
	vpermq		$0xD8, M3, M3		#imm=3120


	/*
	vperm2i128	$0x20, B0, A0, M0
	vperm2i128	$0x20, B1, A1, M1
	vperm2i128	$0x20, B2, A2, M2
	vperm2i128	$0x20, B3, A3, M3

	vperm2i128	$0x1, M0, M0, T0
	vperm2i128	$0x1, M1, M1, T1
	vperm2i128	$0x1, M2, M2, T2
	vperm2i128	$0x1, M3, M3, T3
	
	vshufpd		$0x05, T0, T0, T0		#imm=0101
	vshufpd		$0x05, T1, T1, T1		#imm=0101
	vshufpd		$0x05, T2, T2, T2		#imm=0101
	vshufpd		$0x05, T3, T3, T3		#imm=0101

	vblendpd	$0x06, T0, M0, M0		#imm=0110
	vblendpd	$0x06, T1, M1, M1		#imm=0110
	vblendpd	$0x06, T2, M2, M2		#imm=0110
	vblendpd	$0x06, T3, M3, M3		#imm=0110
	*/

	#####################################################################

	### load RRp to A B and Dec ###

	popq		%rsi
	pushq		%rsi

	addq		$256, %rsi
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3

/*	
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### dec load arg ####
	key_schedule_128_128bit
	
	#10
	xor_arg_128_128bit

	#9
	inv_key_expansion_128_128bit	rk_128 0x36 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#8
	inv_key_expansion_128_128bit	rk_128 0x1b rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#7
	inv_key_expansion_128_128bit	rk_128 0x80 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#6
	inv_key_expansion_128_128bit	rk_128 0x40 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#5
	inv_key_expansion_128_128bit	rk_128 0x20 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#4
	inv_key_expansion_128_128bit	rk_128 0x10 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#3
	inv_key_expansion_128_128bit	rk_128 0x8 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#2
	inv_key_expansion_128_128bit	rk_128 0x4 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#1
	inv_key_expansion_128_128bit	rk_128 0x2 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#0
	inv_key_expansion_128_128bit	rk_128 0x1 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdeclast_arg_128_128bit
*/

	### rerange RRp to B ###
 
	vperm2i128	$0x20, B0, A0, A0	#B0 B1 B8 B9
	vperm2i128	$0x20, B1, A1, A1
	vperm2i128	$0x20, B2, A2, A2
	vperm2i128	$0x20, B3, A3, A3

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A0, T3, B0		#imm=1010
	vshufpd		$0x00, A0, T3, A0		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A1, T3, B1		#imm=1010
	vshufpd		$0x00, A1, T3, A1		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A2, T3, B2		#imm=1010
	vshufpd		$0x00, A2, T3, A2		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A3, T3, B3		#imm=1010
	vshufpd		$0x00, A3, T3, A3		#imm=0000

	### set A to 1 ###
	movq		$1, %rax
	vmovq		%rax, T3xmm
	vblendpd	$0x01, T3, A0, A0		#imm=0001	

	
	#####################################################################
	### Compute R=1*RRp*R^(-1)mod p ###

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	#### compute ####
	call montmul1024
/*
	vmovdqu64 	A0, %ymm24
	vmovdqu64 	A1, %ymm25
	vmovdqu64 	A2, %ymm26
	vmovdqu64 	A3, %ymm27
*/
	#####################################################################
	### Enc and Store R ###
	
	#### store B ####
	# store_B
	store_A

	vmovq	%xmm31,	%rcx
	vmovdqu64 	A0, (%rcx)
	vmovdqu64 	A1, 32(%rcx)
	vmovdqu64 	A2, 64(%rcx)
	vmovdqu64 	A3, 96(%rcx)
	vmovdqu64 	B0, 128(%rcx)
	vmovdqu64 	B1, 160(%rcx)
	vmovdqu64 	B2, 192(%rcx)
	vmovdqu64 	B3, 224(%rcx)


/*
	##################################################################
	#### prepare result for enc ####


	vpermq		$0x08, A0, A0			#imm=0020
	vpermq		$0x08, A1, A1			#imm=0020
	vpermq		$0x08, A2, A2			#imm=0020
	vpermq		$0x08, A3, A3			#imm=0020
	vpermq		$0x08, B0, B0			#imm=0020
	vpermq		$0x08, B1, B1			#imm=0020
	vpermq		$0x08, B2, B2			#imm=0020
	vpermq		$0x08, B3, B3			#imm=0020

*/

	

	##################################################################
	##################################################################
	### load Cp to A B and Dec ###

	popq		%rsi
	pushq		%rsi

	addq		$128, %rsi
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3
	subq		$128, %rsi

/*
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### dec load arg ####
	key_schedule_128_128bit
	
	#10
	xor_arg_128_128bit

	#9
	inv_key_expansion_128_128bit	rk_128 0x36 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#8
	inv_key_expansion_128_128bit	rk_128 0x1b rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#7
	inv_key_expansion_128_128bit	rk_128 0x80 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#6
	inv_key_expansion_128_128bit	rk_128 0x40 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#5
	inv_key_expansion_128_128bit	rk_128 0x20 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#4
	inv_key_expansion_128_128bit	rk_128 0x10 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#3
	inv_key_expansion_128_128bit	rk_128 0x8 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#2
	inv_key_expansion_128_128bit	rk_128 0x4 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#1
	inv_key_expansion_128_128bit	rk_128 0x2 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#0
	inv_key_expansion_128_128bit	rk_128 0x1 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdeclast_arg_128_128bit
*/
	
	### rerange Cp to A ###
 
	vperm2i128	$0x20, B0, A0, A0	#B0 B1 B8 B9
	vperm2i128	$0x20, B1, A1, A1
	vperm2i128	$0x20, B2, A2, A2
	vperm2i128	$0x20, B3, A3, A3

	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A0, B0		#imm=0101
	vshufpd		$0x00, T3, A0, A0		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A1, B1		#imm=0101
	vshufpd		$0x00, T3, A1, A1		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A2, B2		#imm=0101
	vshufpd		$0x00, T3, A2, A2		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A3, B3		#imm=0101
	vshufpd		$0x00, T3, A3, A3		#imm=0000


	#### restore B ####
	restore_B

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	### Compute CpR=Cp*RRp*R^(-1)mod p ###	
	#Cp in A, and result CpR store in A	
	call montmul1024

	vmovq	%xmm31,	%rcx
	addq	$256,	%rcx
	vmovdqu64 	A0, (%rcx)
	vmovdqu64 	A1, 32(%rcx)
	vmovdqu64 	A2, 64(%rcx)
	vmovdqu64 	A3, 96(%rcx)
	vmovdqu64 	B0, 128(%rcx)
	vmovdqu64 	B1, 160(%rcx)
	vmovdqu64 	B2, 192(%rcx)
	vmovdqu64 	B3, 224(%rcx)
/*
	vmovdqu64 	A0, %ymm24
	vmovdqu64 	A1, %ymm25
	vmovdqu64 	A2, %ymm26
	vmovdqu64 	A3, %ymm27
*/	
	
/*	
	#####################################################################
	### Enc and Store CpR ###

	#### prepare result for enc ####

	vpermq		$0x08, A0, A0			#imm=0020
	vpermq		$0x08, A1, A1			#imm=0020
	vpermq		$0x08, A2, A2			#imm=0020
	vpermq		$0x08, A3, A3			#imm=0020
	vpermq		$0x08, B0, B0			#imm=0020
	vpermq		$0x08, B1, B1			#imm=0020
	vpermq		$0x08, B2, B2			#imm=0020
	vpermq		$0x08, B3, B3			#imm=0020
*/


/*	
	#### copy CpR from A to B ####

	vpermq		$0x54, A0, A0			#imm=1110
	vpermq		$0xE0, A0, A0			#imm=3200
	vpermq		$0x54, A1, A1			#imm=1110
	vpermq		$0xE0, A1, A1			#imm=3200
	vpermq		$0x54, A2, A2			#imm=1110
	vpermq		$0xE0, A2, A2			#imm=3200
	vpermq		$0x54, A3, A3			#imm=1110
	vpermq		$0xE0, A3, A3			#imm=3200

	vpermq		$0x54, B0, B0			#imm=1110
	vpermq		$0xE0, B0, B0			#imm=3200
	vpermq		$0x54, B1, B1			#imm=1110
	vpermq		$0xE0, B1, B1			#imm=3200
	vpermq		$0x54, B2, B2			#imm=1110
	vpermq		$0xE0, B2, B2			#imm=3200
	vpermq		$0x54, B3, B3			#imm=1110
	vpermq		$0xE0, B3, B3			#imm=3200
*/	

/*
	vpermq		$0x0C, A0, A0			#imm=1100
	vpermq		$0x0C, A1, A1			#imm=1100
	vpermq		$0x0C, A2, A2			#imm=1100
	vpermq		$0x0C, A3, A3			#imm=1100
	vpermq		$0x0C, B0, B0			#imm=1100
	vpermq		$0x0C, B1, B1			#imm=1100
	vpermq		$0x0C, B2, B2			#imm=1100
	vpermq		$0x0C, B3, B3			#imm=1100
*/

	/*
	vshufpd		$0x00, A0, A0, A0		#imm=0101
	vshufpd		$0x00, A1, A1, A1		#imm=0101
	vshufpd		$0x00, A2, A2, A2		#imm=0101
	vshufpd		$0x00, A3, A3, A3		#imm=0101
	vshufpd		$0x00, B0, B0, B0		#imm=0101
	vshufpd		$0x00, B1, B1, B1		#imm=0101
	vshufpd		$0x00, B2, B2, B2		#imm=0101
	vshufpd		$0x00, B3, B3, B3		#imm=0101
	*/

	##################################################################
	
	#### transfer %rsi ####
	popq		%rsi
	movq		%rsi, %mm0

	
	### compute Cp^imp1 mod p ###
	#result in A
	call montexp1024



	
	##################################################################
	##################################################################

	#### set B to 1 ####
	vpxor 		T3, T3, T3

	movq		$1, %rax
	vmovq		%rax, T3xmm
	vshufpd		$0x00, T3, A0, A0		#imm=0000


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	
	#result*1*R(-1) mod p#
	call montmul1024	


	##################################################################
	#####################################################################
	### Enc Result ###

	#### prepare result for enc ####
/*
	vpermq		$0x08, A0, A0			#imm=0020
	vpermq		$0x08, A1, A1			#imm=0020
	vpermq		$0x08, A2, A2			#imm=0020
	vpermq		$0x08, A3, A3			#imm=0020
	vpermq		$0x08, B0, B0			#imm=0020
	vpermq		$0x08, B1, B1			#imm=0020
	vpermq		$0x08, B2, B2			#imm=0020
	vpermq		$0x08, B3, B3			#imm=0020
*/
/*
	##################################################################
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### enc result ####
	xor_arg_128_128bit

	key_expansion_128	rk_128 0x1 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x2 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x4 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x8 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x10 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x20 rhelp_128
	aesenc_arg_128_128bit	

	key_expansion_128	rk_128 0x40 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x80 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x1b rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x36 rhelp_128
	aesenclast_arg_128_128bit
*/

##################################################################################################
	###							###	
	### 	montexp1024_AES_p END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################


	ret
	.size	montexp1024_AES_p, .-montexp1024_AES_p









##################################################################################################
	###								###	
	### 	montexp1024_AES_q: 	load exp argument		###
	###		     		Dec argument			###	
	###		     		Call montexp 			###
	###				Enc result			###
	###				Store result			###
	###								###
##################################################################################################

	         

##################################################################################################
	###							###	
	### 	exp arg: 	0-1023		:q	:M	###
	###		     	1024-2047	:Cq	:A	###	
	###		     	2048-3071	:RRq	:B 	###
	###			3072-4095	:dmq1	:T	###
	###			4096-4159	:q0	:n0	###
	###							###
##################################################################################################







.globl 	montexp1024_AES_q
	.type  	montexp1024_AES_q, @function
	.align 	64

montexp1024_AES_q:


##################################################################################################
	###							###	
	### 	Load and Dec 					###
	###							###
	###	sum 						###
	###							###
##################################################################################################
	

	### restore rsi ###
	movq		%mm0, %rsi
	push		%rsi

	### new add-- aes-dec-- ###
	vpxorq  %ymm1,     %ymm1,     %ymm1
    movq    $0x0123456789ABCDEF,    %rax
    vmovq   %rax,   %xmm1
    valignq     $1, %ymm0, %ymm1,  %ymm0
    movq    $0xFEDCBA9876543210,    %rax
    vmovq   %rax,   %xmm1
    valignq     $3, %ymm0, %ymm1,  %ymm0

	vmovdqu		16(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	%xmm16
	vmovdqu		32(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	%xmm17
	vmovdqu		48(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	%xmm18
	vmovdqu		64(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	%xmm19
	vmovdqu		80(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	%xmm20
	vmovdqu		96(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	%xmm21
	vmovdqu		112(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	%xmm22
	vmovdqu		(%rsi), %xmm15
	aes_dec
	vmovdqu64		%xmm15,	A0xmm
	vmovdqu64		%xmm16,	A1xmm
	vmovdqu64		%xmm17,	A2xmm
	vmovdqu64		%xmm18,	A3xmm
	vmovdqu64		%xmm19,	B0xmm
	vmovdqu64		%xmm20,	B1xmm
	vmovdqu64		%xmm21,	B2xmm
	vmovdqu64		%xmm22,	B3xmm
	vpxorq	%ymm8,	%ymm8,	%ymm8
	vpxorq	%ymm9,	%ymm9,	%ymm9

	movq    $0x0123456789ABCDEF,    %rax
    vmovq   %rax,   %xmm9
    valignq     $1, %ymm8, %ymm9,  %ymm8
    movq    $0xFEDCBA9876543210,    %rax
    vmovq   %rax,   %xmm9
    valignq     $3, %ymm8, %ymm9,  %ymm8

	vpxorq	%xmm8,	%xmm15,	%xmm15
	vmovdqu64		%xmm15,		(%rsi)
	vpxorq	%xmm8,	%xmm16,	%xmm16
	vmovdqu64		%xmm16,		16(%rsi)
	vpxorq	%xmm8,	%xmm17,	%xmm17
	vmovdqu64		%xmm17,		32(%rsi)
	vpxorq	%xmm8,	%xmm18,	%xmm18
	vmovdqu64		%xmm18,		48(%rsi)
	vpxorq	%xmm8,	%xmm19,	%xmm19
	vmovdqu64		%xmm19,		64(%rsi)
	vpxorq	%xmm8,	%xmm20,	%xmm20
	vmovdqu64		%xmm20,		80(%rsi)
	vpxorq	%xmm8,	%xmm21,	%xmm21
	vmovdqu64		%xmm21,		96(%rsi)
	vpxorq	%xmm8,	%xmm22,	%xmm22
	vmovdqu64		%xmm22,		112(%rsi)


	vpxorq	%ymm8,	%ymm8,	%ymm8
	vpxorq	%ymm9,	%ymm9,	%ymm9
	vpxorq	%ymm10,	%ymm10,	%ymm10
	vpxorq	%ymm11,	%ymm11,	%ymm11
	vpxorq	%ymm12,	%ymm12,	%ymm12
	vpxorq	%ymm13,	%ymm13,	%ymm13
	vpxorq	%ymm15,	%ymm15,	%ymm15
	vpxorq	%ymm16,	%ymm16,	%ymm16
	vpxorq	%ymm17,	%ymm17,	%ymm17
	vpxorq	%ymm18,	%ymm18,	%ymm18
	vpxorq	%ymm19,	%ymm19,	%ymm19
	vpxorq	%ymm20,	%ymm20,	%ymm20
	vpxorq	%ymm21,	%ymm21,	%ymm21
	vpxorq	%ymm22,	%ymm22,	%ymm22
	
	########## aes_dec end###############

	
	### load arg ###
/*
	#####################################################################
	### load q to A B and Dec ###
	vmovdqu		(%rsi), A0xmm		#M[0] M[1]
	vmovdqu		16(%rsi), A1xmm		#M[2] M[3]
	vmovdqu		32(%rsi), A2xmm		#M[4] M[5]
	vmovdqu		48(%rsi), A3xmm		#M[6] M[7]
	vmovdqu		64(%rsi), B0xmm		#M[8] M[9]
	vmovdqu		80(%rsi), B1xmm		#M[10] M[11]
	vmovdqu		96(%rsi), B2xmm		#M[12] M[13]
	vmovdqu		112(%rsi), B3xmm	#M[14] M[15]
*/

	### load q0 to M0 and Dec ###
	addq		$512, %rsi
	vmovdqu		(%rsi), M0xmm

/*	
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### dec load arg ####
	key_schedule_128_128bit
	
	#10
	xor_arg_128_128bit
	vpxor 				rk_128, M0xmm, M0xmm

	#9
	inv_key_expansion_128_128bit	rk_128 0x36 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#8
	inv_key_expansion_128_128bit	rk_128 0x1b rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#7
	inv_key_expansion_128_128bit	rk_128 0x80 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#6
	inv_key_expansion_128_128bit	rk_128 0x40 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#5
	inv_key_expansion_128_128bit	rk_128 0x20 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#4
	inv_key_expansion_128_128bit	rk_128 0x10 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#3
	inv_key_expansion_128_128bit	rk_128 0x8 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#2
	inv_key_expansion_128_128bit	rk_128 0x4 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#1
	inv_key_expansion_128_128bit	rk_128 0x2 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit
	vaesdec 			rhelp_128, M0xmm, M0xmm

	#0
	inv_key_expansion_128_128bit	rk_128 0x1 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdeclast_arg_128_128bit
	vaesdeclast 			rhelp_128, M0xmm, M0xmm
*/
	### mov p0 from M0 to n0 ###
	### high 64bit is padding, is all zero ###
	vmovq				M0xmm, %rax
	movq				%rax, n0


	### rerange q to M ###

	vperm2i128	$0x20, B0, A0, M0
	vperm2i128	$0x20, B1, A1, M1
	vperm2i128	$0x20, B2, A2, M2
	vperm2i128	$0x20, B3, A3, M3


	vpermq		$0xD8, M0, M0		#imm=3120
	vpermq		$0xD8, M1, M1		#imm=3120
	vpermq		$0xD8, M2, M2		#imm=3120
	vpermq		$0xD8, M3, M3		#imm=3120


	#####################################################################

	### load RRq to A B and Dec ###

	popq		%rsi
	pushq		%rsi

	addq		$256, %rsi
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3


/*	
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### dec load arg ####
	key_schedule_128_128bit
	
	#10
	xor_arg_128_128bit

	#9
	inv_key_expansion_128_128bit	rk_128 0x36 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#8
	inv_key_expansion_128_128bit	rk_128 0x1b rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#7
	inv_key_expansion_128_128bit	rk_128 0x80 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#6
	inv_key_expansion_128_128bit	rk_128 0x40 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#5
	inv_key_expansion_128_128bit	rk_128 0x20 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#4
	inv_key_expansion_128_128bit	rk_128 0x10 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#3
	inv_key_expansion_128_128bit	rk_128 0x8 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#2
	inv_key_expansion_128_128bit	rk_128 0x4 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#1
	inv_key_expansion_128_128bit	rk_128 0x2 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#0
	inv_key_expansion_128_128bit	rk_128 0x1 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdeclast_arg_128_128bit
*/

	### rerange RRq to B ###
 
	vperm2i128	$0x20, B0, A0, A0		#B0 B1 B8 B9
	vperm2i128	$0x20, B1, A1, A1
	vperm2i128	$0x20, B2, A2, A2
	vperm2i128	$0x20, B3, A3, A3

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A0, T3, B0		#imm=1010
	vshufpd		$0x00, A0, T3, A0		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A1, T3, B1		#imm=1010
	vshufpd		$0x00, A1, T3, A1		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A2, T3, B2		#imm=1010
	vshufpd		$0x00, A2, T3, A2		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x0A, A3, T3, B3		#imm=1010
	vshufpd		$0x00, A3, T3, A3		#imm=0000


	### set A to 1 ###
	movq		$1, %rax
	vmovq		%rax, T3xmm
	vblendpd	$0x01, T3, A0, A0		#imm=0001

	
	#####################################################################
	### Compute R=1*RRq*R^(-1)mod q ###

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	#### compute ####
	call montmul1024
	


	#####################################################################
	### Enc and Store R ###
	
	#### store B ####
	# store_B
	store_A

	vmovq	%xmm31,	%rcx
	vmovdqu64 	A0, (%rcx)
	vmovdqu64 	A1, 32(%rcx)
	vmovdqu64 	A2, 64(%rcx)
	vmovdqu64 	A3, 96(%rcx)
	vmovdqu64 	B0, 128(%rcx)
	vmovdqu64 	B1, 160(%rcx)
	vmovdqu64 	B2, 192(%rcx)
	vmovdqu64 	B3, 224(%rcx)


/*
	##################################################################
	#### prepare result for enc ####

	vpermq		$0x08, A0, A0			#imm=0020
	vpermq		$0x08, A1, A1			#imm=0020
	vpermq		$0x08, A2, A2			#imm=0020
	vpermq		$0x08, A3, A3			#imm=0020
	vpermq		$0x08, B0, B0			#imm=0020
	vpermq		$0x08, B1, B1			#imm=0020
	vpermq		$0x08, B2, B2			#imm=0020
	vpermq		$0x08, B3, B3			#imm=0020

*/

	
	##################################################################
	##################################################################
	### load Cq to B and Dec ###

	popq		%rsi
	pushq		%rsi

	addq		$128, %rsi
	
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3
	
	subq		$128, %rsi


/*
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### dec load arg ####
	key_schedule_128_128bit
	
	#10
	xor_arg_128_128bit

	#9
	inv_key_expansion_128_128bit	rk_128 0x36 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#8
	inv_key_expansion_128_128bit	rk_128 0x1b rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#7
	inv_key_expansion_128_128bit	rk_128 0x80 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#6
	inv_key_expansion_128_128bit	rk_128 0x40 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#5
	inv_key_expansion_128_128bit	rk_128 0x20 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#4
	inv_key_expansion_128_128bit	rk_128 0x10 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#3
	inv_key_expansion_128_128bit	rk_128 0x8 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#2
	inv_key_expansion_128_128bit	rk_128 0x4 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#1
	inv_key_expansion_128_128bit	rk_128 0x2 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdec_arg_128_128bit

	#0
	inv_key_expansion_128_128bit	rk_128 0x1 rhelp_128
	vaesimc				rk_128, rhelp_128
	aesdeclast_arg_128_128bit
*/


	### rerange Cq to A ###
 
	vperm2i128	$0x20, B0, A0, A0		#B0 B1 B8 B9
	vperm2i128	$0x20, B1, A1, A1
	vperm2i128	$0x20, B2, A2, A2
	vperm2i128	$0x20, B3, A3, A3


	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A0, B0		#imm=0101
	vshufpd		$0x00, T3, A0, A0		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A1, B1		#imm=0101
	vshufpd		$0x00, T3, A1, A1		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A2, B2		#imm=0101
	vshufpd		$0x00, T3, A2, A2		#imm=0000

	vpxor		T3, T3, T3
	vshufpd		$0x05, T3, A3, B3		#imm=0101
	vshufpd		$0x00, T3, A3, A3		#imm=0000


	#### restore B ####
	restore_B



	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	### Compute CqR=Cq*RRq*R^(-1)mod q ###	
	#Cq in A, and result CqR store in A	

	call montmul1024

	vmovq	%xmm31,	%rcx
	addq	$256,	%rcx
	vmovdqu64 	A0, (%rcx)
	vmovdqu64 	A1, 32(%rcx)
	vmovdqu64 	A2, 64(%rcx)
	vmovdqu64 	A3, 96(%rcx)
	vmovdqu64 	B0, 128(%rcx)
	vmovdqu64 	B1, 160(%rcx)
	vmovdqu64 	B2, 192(%rcx)
	vmovdqu64 	B3, 224(%rcx)


/*
	#####################################################################
	### Enc and Store CqR ###

	#### prepare result for enc ####

	vpermq		$0x08, A0, A0			#imm=0020
	vpermq		$0x08, A1, A1			#imm=0020
	vpermq		$0x08, A2, A2			#imm=0020
	vpermq		$0x08, A3, A3			#imm=0020
	vpermq		$0x08, B0, B0			#imm=0020
	vpermq		$0x08, B1, B1			#imm=0020
	vpermq		$0x08, B2, B2			#imm=0020
	vpermq		$0x08, B3, B3			#imm=0020

	valignq  $2,   %zmm16,   %zmm0, %zmm16
	valignq  $2,   %zmm16,   %zmm1, %zmm16
	valignq  $2,   %zmm16,   %zmm2, %zmm16
	valignq  $2,   %zmm16,   %zmm3, %zmm16
	valignq  $2,   %zmm17,   %zmm4, %zmm17
	valignq  $2,   %zmm17,   %zmm5, %zmm17
	valignq  $2,   %zmm17,   %zmm6, %zmm17
	valignq  $2,   %zmm17,   %zmm7, %zmm17
*/


/*

	#### copy CqR from A to B ####

	vpermq		$0x54, A0, A0			#imm=1110
	vpermq		$0xE0, A0, A0			#imm=3200
	vpermq		$0x54, A1, A1			#imm=1110
	vpermq		$0xE0, A1, A1			#imm=3200
	vpermq		$0x54, A2, A2			#imm=1110
	vpermq		$0xE0, A2, A2			#imm=3200
	vpermq		$0x54, A3, A3			#imm=1110
	vpermq		$0xE0, A3, A3			#imm=3200

	vpermq		$0x54, B0, B0			#imm=1110
	vpermq		$0xE0, B0, B0			#imm=3200
	vpermq		$0x54, B1, B1			#imm=1110
	vpermq		$0xE0, B1, B1			#imm=3200
	vpermq		$0x54, B2, B2			#imm=1110
	vpermq		$0xE0, B2, B2			#imm=3200
	vpermq		$0x54, B3, B3			#imm=1110
	vpermq		$0xE0, B3, B3			#imm=3200
*/	


	##################################################################
	
	#### transfer %rsi ####
	popq		%rsi
	movq		%rsi, %mm0
/*
	vmovdqu64 	B0, %ymm24
	vmovdqu64 	B1, %ymm25
	vmovdqu64 	B2, %ymm26
	vmovdqu64 	B3, %ymm27
*/
	### compute Cq^imq1 mod p ###
	#result in A
	call montexp1024
/*
	vmovdqu64 	A0, %ymm24
	vmovdqu64 	A1, %ymm25
	vmovdqu64 	A2, %ymm26
	vmovdqu64 	A3, %ymm27
*/

	##################################################################
	##################################################################

	#### set B to 1 ####
	vpxor 		T3, T3, T3

	movq		$1, %rax
	vmovq		%rax, T3xmm
	vshufpd		$0x00, T3, A0, A0		#imm=0000


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	
	#result*1*R(-1) mod q#
	call montmul1024	
	
	
	#####################################################################
	### Enc Result ###

	#### prepare result for enc ####

	vpermq		$0x08, A0, A0			#imm=0020
	vpermq		$0x08, A1, A1			#imm=0020
	vpermq		$0x08, A2, A2			#imm=0020
	vpermq		$0x08, A3, A3			#imm=0020
	vpermq		$0x08, B0, B0			#imm=0020
	vpermq		$0x08, B1, B1			#imm=0020
	vpermq		$0x08, B2, B2			#imm=0020
	vpermq		$0x08, B3, B3			#imm=0020
/*
	vmovdqu64 	A0, %ymm24
	vmovdqu64 	A1, %ymm25
	vmovdqu64 	A2, %ymm26
	vmovdqu64 	A3, %ymm27
*/	
/*
	##################################################################
	#### load key ####
	vperm2i128	$0x10, M0, M0, T2

	#### enc result ####
	xor_arg_128_128bit

	key_expansion_128	rk_128 0x1 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x2 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x4 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x8 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x10 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x20 rhelp_128
	aesenc_arg_128_128bit	

	key_expansion_128	rk_128 0x40 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x80 rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x1b rhelp_128
	aesenc_arg_128_128bit

	key_expansion_128	rk_128 0x36 rhelp_128
	aesenclast_arg_128_128bit

*/	
	
##################################################################################################
	###							###	
	### 	montexp1024_AES_q END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################


	ret
	.size	montexp1024_AES_q, .-montexp1024_AES_q




