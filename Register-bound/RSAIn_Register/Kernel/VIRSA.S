	
	//#include "kernel.h"

	#include "RSA_function.S"


	.file	"VIRSA.S"
	.text




##################################################################################################
	###							###	
	### 	montmul2014_test				###
	###							###
	###	 						###
	###							###
##################################################################################################





	### function prototype ###
	
	# int VIRSA(unsigned long long *R, unsigned long long *Arg) #

	# R 	%rdi
	# Arg	%rsi

#######################################################################################################################
	

	#########################################################################################################		
	#													#
	# P:Arg+0	0-127		128-255		256-383		384-511		512-527			#	
	# 		p		Cp (CpR)		RRp	 	dmp1		p0(128bit cypher)	#
	# 													#			
	#########################################################################################################
	#													#
	# q:Arg+640	0-127		128-255		256-383		384-511		512-527			#	
	# 		q		Cq (CqR)		RRq		dmq1		q0(128bit cypher)	#
	# 													#			
	#########################################################################################################
	#													#
	# iqmp:Arg+1280			0-127									#	
	# 				iqmp									#
	# 													#			
	#########################################################################################################


#######################################################################################################################
	


	.globl 	VIRSA
	.type  	VIRSA, @function
	.align 	64

VIRSA:

	#########################################################
	### 	prologue 	###
	#########################################################
	
	### zero all YMM registers ###
	vzeroall

	### 1. stack for storing Rp and Rq ###
	subq		$512, %rsp
	
	### 2. store scalar register ###
	movq		%rbx, (%rsp)
	movq		%rbp, 8(%rsp)
	movq		%r12, 16(%rsp)
	movq		%r13, 24(%rsp)
	movq		%r14, 32(%rsp)
	movq		%r15, 40(%rsp)

	### 3. store two argment pointer ###
	movq		%rdi, 48(%rsp)
	movq		%rsi, 64(%rsp)			

	vmovq	%rdi,	%xmm31



	#########################################################
	### 	VIRSA computation	###
	#########################################################


	### input and output all are ciphers which encrypt by AES-256 ###
	### key of AES-256 stored in Debug registers ###

	### 1. Cq^(dmq1) mod q ###
	movq		64(%rsp), %rsi
	addq		$640, %rsi	#for q
	movq		%rsi, %mm0



	call montexp1024_AES_q


	##store result in zmm register##

	valignq  $2,   %zmm24,   %zmm0, %zmm24
	valignq  $2,   %zmm24,   %zmm1, %zmm24
	valignq  $2,   %zmm24,   %zmm2, %zmm24
	valignq  $2,   %zmm24,   %zmm3, %zmm24
	valignq  $2,   %zmm25,   %zmm4, %zmm25
	valignq  $2,   %zmm25,   %zmm5, %zmm25
	valignq  $2,   %zmm25,   %zmm6, %zmm25
	valignq  $2,   %zmm25,   %zmm7, %zmm25

	vmovdqu64	%zmm24,		%zmm21
	vmovdqu64	%zmm25,		%zmm27


	### 2. Cp^(dmp1) mod p ###
	movq		64(%rsp), %rsi
	movq		%rsi, %mm0

	call montexp1024_AES_p

	
	### 3. Rp-Rq mod p ###
	movq		64(%rsp), %rsi

	store_A
	vpxorq		%zmm26,	%zmm26,	%zmm26
	vmovdqu64		%xmm24,	%xmm0
	valignq  $2,   %zmm24,   %zmm26, %zmm24
	vmovdqu64		%xmm24,	%xmm1
	valignq  $2,   %zmm24,   %zmm26, %zmm24
	vmovdqu64		%xmm24,	%xmm2
	valignq  $2,   %zmm24,   %zmm26, %zmm24
	vmovdqu64		%xmm24,	%xmm3
	valignq  $2,   %zmm24,   %zmm26, %zmm24
	vmovdqu64		%xmm25,	%xmm4
	valignq  $2,   %zmm25,   %zmm26, %zmm25
	vmovdqu64		%xmm25,	%xmm5
	valignq  $2,   %zmm25,   %zmm26, %zmm25
	vmovdqu64		%xmm25,	%xmm6
	valignq  $2,   %zmm25,   %zmm26, %zmm25
	vmovdqu64		%xmm25,	%xmm7
	valignq  $2,   %zmm25,   %zmm26, %zmm25

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
	restore_A

	call		sub_mp_mq

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

	store_A


	
	### 4. R*qinv mod p ###  (qinv = R * qinv mod p)
	movq		64(%rsp), %rsi


	call		mul_qinv

	

	### 5. h*q+Rq ###	
	movq		64(%rsp), %rsi
	addq		$640, %rsi	#for q

	call 		mul_h_q_add_Rq
	

	### 6. store result ###


	vmovq		%xmm31, %rdi
/*	
	vmovdqu64 	%ymm24, (%rdi)
	vmovdqu64 	%ymm25, 32(%rdi)
	vmovdqu64 	%ymm26, 64(%rdi)
	vmovdqu64 	%ymm27, 96(%rdi)

	vmovdqu64 	A0, (%rdi)
	vmovdqu64 	A1, 32(%rdi)
	vmovdqu64 	A2, 64(%rdi)
	vmovdqu64 	A3, 96(%rdi)
	vmovdqu64 	B0, 128(%rdi)
	vmovdqu64 	B1, 160(%rdi)
	vmovdqu64 	B2, 192(%rdi)
	vmovdqu64 	B3, 224(%rdi)

	# vmovdqu64 	%zmm24, (%rdi)
	# vmovdqu64 	%zmm25, 64(%rdi)
*/

	#########################################################
	### 	prologue 	###
	#########################################################

	### 1. zero YMM registers ###
	vzeroall

	### 2. zero MMX registers ###
	pxor		%mm0, %mm0
	pxor		%mm1, %mm1
	pxor		%mm2, %mm2
	pxor		%mm3, %mm3
	pxor		%mm4, %mm4
	pxor		%mm5, %mm5
	pxor		%mm6, %mm6
	pxor		%mm7, %mm7
	
	### 3. zero scalar registers ###
	xorq		%rax, %rax
	xorq		%rbx, %rbx	
	xorq		%rcx, %rcx
	xorq		%rdx, %rdx
	xorq		%rdi, %rdi
	xorq		%rsi, %rsi	
	xorq		%rbp, %rbp
	xorq		%r8, %r8
	xorq		%r9, %r9
	xorq		%r10, %r10
	xorq		%r11, %r11
	xorq		%r12, %r12
	xorq		%r13, %r13
	xorq		%r14, %r14
	xorq		%r15, %r15

	### 4. restore scalar registers ###
	movq		(%rsp), %rbx
	movq		8(%rsp), %rbp
	movq		16(%rsp), %r12
	movq		24(%rsp), %r13
	movq		32(%rsp), %r14
	movq		40(%rsp), %r15

	### 5. stack balance ###
	addq		$512, %rsp

	#########################################################
	### 	End 		###
	#########################################################

	ret
	.size	VIRSA, .-VIRSA



##################################################################################################
	###							###	
	### 	montmul2014_test 				###
	###							###
	###							###
##################################################################################################
