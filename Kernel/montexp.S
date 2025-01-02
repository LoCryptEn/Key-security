	#include "montmul.S"
	#include "montsqu.S"

	#include "aesni.S"
	//#include "montmul_raw.S"
	//#include "montsqu_raw.S"	
	

	.file	"montexp.S"
	.data
	  my_var: .quad 0x123344
	.text



##################################################################################################
	###							###	
	### 	montexp(A,Exp,n0):				###
	###							###	
	###	R=A^Exp mod M 					###
	###							###
	###							###
##################################################################################################

	         





.macro 	store_B


##################################################################################################
	
	#### store B ####

	vshufpd		$0x05, A0, A0, T3		#imm=0101
	vmovq		T3xmm, %rax			#q0=B[0]  s0=B[8]
	movq		%rax, q0
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s0
	
	vshufpd		$0x05, A1, A1, T3		#imm=0101
	vmovq		T3xmm, %rax
	movq		%rax, q1
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s1

	vshufpd		$0x05, A2, A2, T3		#imm=0101
	vmovq		T3xmm, %rax
	movq		%rax, q2
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s2
	
	vshufpd		$0x05, A3, A3, T3		#imm=0101
	vmovq		T3xmm, %rax
	movq		%rax, q3
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s3

	vshufpd		$0x05, B0, B0, T3		#imm=0101
	vmovq		T3xmm, %rax
	movq		%rax, q4
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s4
	
	vshufpd		$0x05, B1, B1, T3		#imm=0101
	vmovq		T3xmm, %rax
	movq		%rax, q5
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s5

	vshufpd		$0x05, B2, B2, T3		#imm=0101
	vmovq		T3xmm, %rax
	movq		%rax, q6
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s6
	
	vshufpd		$0x05, B3, B3, T3		#imm=0101
	vmovq		T3xmm, %rax
	movq		%rax, q7
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, s7

	## new add ##
	#vpxorq	%zmm28,	%zmm28,	%zmm28
	movq	q0,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q1,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q2,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q3,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q4,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q5,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q6,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q7,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	s0,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s1,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s2,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s3,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s4,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s5,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s6,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s7,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

##################################################################################################

.endm	




.macro 	restore_B


##################################################################################################

	#### restore B ####

	vpxorq	%zmm30,	%zmm30,	%zmm30	
	vmovq	%xmm29,	s0
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s1
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s2
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s3
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s4
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s5
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s6
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s7
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	%rax,	%xmm23

	vmovq	%xmm28,	%rax
	movq	%rax,	q0
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q1
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q2
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q3
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q4
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q5
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q6
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q7
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm23,	%rax

	vpinsrq		$1, s0, T3xmm, T3xmm
	movq		q0, s0				#q0=B[0]  s0=B[8]
	vpinsrq		$0, s0, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A0, A0		#imm=1010


	vpinsrq		$1, s1, T3xmm, T3xmm
	movq		q1, s1
	vpinsrq		$0, s1, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B0, B0		#imm=1010



	vpinsrq		$1, s2, T3xmm, T3xmm
	movq		q2, s2
	vpinsrq		$0, s2, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A1, A1		#imm=1010

	vpinsrq		$1, s3, T3xmm, T3xmm
	movq		q3, s3
	vpinsrq		$0, s3, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B1, B1		#imm=1010

	vpinsrq		$1, s4, T3xmm, T3xmm
	movq		q4, s4
	vpinsrq		$0, s4, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A2, A2		#imm=1010

	vpinsrq		$1, s5, T3xmm, T3xmm
	movq		q5, s5
	vpinsrq		$0, s5, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B2, B2		#imm=1010

	vpinsrq		$1, s6, T3xmm, T3xmm
	movq		q6, s6
	vpinsrq		$0, s6, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A3, A3		#imm=1010

	vpinsrq		$1, s7, T3xmm, T3xmm
	movq		q7, s7
	vpinsrq		$0, s7, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B3, B3		#imm=1010


/*
	vpinsrq		$1, s0, T3xmm, T3xmm
	movq		q0, s0				#q0=B[0]  s0=B[8]
	vpinsrq		$0, s0, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A0, A0		#imm=1010

	vpinsrq		$1, s1, T3xmm, T3xmm
	movq		q1, s1
	vpinsrq		$0, s1, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A1, A1		#imm=1010

	vpinsrq		$1, s2, T3xmm, T3xmm
	movq		q2, s2
	vpinsrq		$0, s2, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A2, A2		#imm=1010

	vpinsrq		$1, s3, T3xmm, T3xmm
	movq		q3, s3
	vpinsrq		$0, s3, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, A3, A3		#imm=1010

	vpinsrq		$1, s4, T3xmm, T3xmm
	movq		q4, s4
	vpinsrq		$0, s4, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B0, B0		#imm=1010

	vpinsrq		$1, s5, T3xmm, T3xmm
	movq		q5, s5
	vpinsrq		$0, s5, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B1, B1		#imm=1010

	vpinsrq		$1, s6, T3xmm, T3xmm
	movq		q6, s6
	vpinsrq		$0, s6, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B2, B2		#imm=1010

	vpinsrq		$1, s7, T3xmm, T3xmm
	movq		q7, s7
	vpinsrq		$0, s7, T3xmm, T3xmm
	vpermq		$0x62, T3, T3			#imm=1202
	vblendpd	$0xA, T3, B3, B3		#imm=1010
*/

##################################################################################################


.endm	




.macro 	store_A


##################################################################################################
	
	#### store A ####

	vmovq		A0xmm, %rax			#q0=A[0]  s0=A[8]
	movq		%rax, q0
	vperm2i128	$0x01, A0, A0, A0
	vmovq		A0xmm, s0
	vperm2i128	$0x01, A0, A0, A0
	
	vmovq		B0xmm, %rax
	movq		%rax, q1
	vperm2i128	$0x01, B0, B0, B0
	vmovq		B0xmm, s1
	vperm2i128	$0x01, B0, B0, B0

	vmovq		A1xmm, %rax
	movq		%rax, q2
	vperm2i128	$0x01, A1, A1, A1
	vmovq		A1xmm, s2
	vperm2i128	$0x01, A1, A1, A1	


	vmovq		B1xmm, %rax
	movq		%rax, q3
	vperm2i128	$0x01, B1, B1, B1
	vmovq		B1xmm, s3
	vperm2i128	$0x01, B1, B1, B1


	vmovq		A2xmm, %rax
	movq		%rax, q4
	vperm2i128	$0x01, A2, A2, A2
	vmovq		A2xmm, s4
	vperm2i128	$0x01, A2, A2, A2
	
	vmovq		B2xmm, %rax
	movq		%rax, q5
	vperm2i128	$0x01, B2, B2, B2
	vmovq		B2xmm, s5
	vperm2i128	$0x01, B2, B2, B2

	vmovq		A3xmm, %rax
	movq		%rax, q6
	vperm2i128	$0x01, A3, A3, A3
	vmovq		A3xmm, s6
	vperm2i128	$0x01, A3, A3, A3
	
	vmovq		B3xmm, %rax
	movq		%rax, q7
	vperm2i128	$0x01, B3, B3, B3
	vmovq		B3xmm, s7
	vperm2i128	$0x01, B3, B3, B3

	## new add ##
	#vpxorq	%zmm28,	%zmm28,	%zmm28
	movq	q0,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q1,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q2,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q3,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q4,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q5,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q6,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	movq	q7,	%rax
	vmovq	%rax,	%xmm30
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	s0,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s1,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s2,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s3,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s4,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s5,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s6,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	s7,	%xmm30
	valignq  $1,   %zmm29,   %zmm30, %zmm29

##################################################################################################

.endm	




.macro 	restore_A


##################################################################################################

	#### restore A ####
	vpxorq	%zmm30,	%zmm30,	%zmm30	
	vmovq	%xmm29,	s0
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s1
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s2
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s3
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s4
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s5
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s6
	valignq  $1,   %zmm29,   %zmm30, %zmm29
	vmovq	%xmm29,	s7
	valignq  $1,   %zmm29,   %zmm30, %zmm29

	vmovq	%rax,	%xmm23

	vmovq	%xmm28,	%rax
	movq	%rax,	q0
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q1
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q2
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q3
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q4
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q5
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q6
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm28,	%rax
	movq	%rax,	q7
	valignq  $1,   %zmm28,   %zmm30, %zmm28

	vmovq	%xmm23,	%rax


	vpinsrq		$1, s0, T3xmm, T3xmm		#q0=A[0]  s0=A[8]
	movq		q0, s0
	vpinsrq		$0, s0, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, A0, A0		#imm=0101

	vpinsrq		$1, s1, T3xmm, T3xmm
	movq		q1, s1
	vpinsrq		$0, s1, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, B0, B0		#imm=0101

	vpinsrq		$1, s2, T3xmm, T3xmm
	movq		q2, s2
	vpinsrq		$0, s2, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, A1, A1		#imm=0101

	vpinsrq		$1, s3, T3xmm, T3xmm
	movq		q3, s3
	vpinsrq		$0, s3, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, B1, B1		#imm=0101

	vpinsrq		$1, s4, T3xmm, T3xmm
	movq		q4, s4
	vpinsrq		$0, s4, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, A2, A2		#imm=0101

	vpinsrq		$1, s5, T3xmm, T3xmm
	movq		q5, s5
	vpinsrq		$0, s5, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, B2, B2		#imm=0101

	vpinsrq		$1, s6, T3xmm, T3xmm
	movq		q6, s6
	vpinsrq		$0, s6, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, A3, A3		#imm=0101

	vpinsrq		$1, s7, T3xmm, T3xmm
	movq		q7, s7
	vpinsrq		$0, s7, T3xmm, T3xmm
	vpermq		$0x98, T3, T3			#imm=2120
	vblendpd	$0x5, T3, B3, B3		#imm=0101

##################################################################################################


.endm	















### exp inverse order, for square and multiplication algorithm ###
##################################################################


	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	# T[i]  9	11	13	15	#	
	# D[i]	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#
	#########################################


#########################################################





.globl 	montexp1024
	.type  	montexp1024, @function
	.align 	64

montexp1024:

#.macro	montexp1024

##################################################################################################
	###							###	
	### 	montexp1024					###
	###							###
	###	sum						###
	###							###
##################################################################################################

	
	movq		%mm0, %rsi

	vmovq	%xmm31,	%rcx
	vmovdqu64   (%rcx),		A0
	vmovdqu64   32(%rcx),		A1
	vmovdqu64   64(%rcx),		A2
	vmovdqu64   96(%rcx),		A3
	vmovdqu64   128(%rcx),		B0
	vmovdqu64   160(%rcx),		B1
	vmovdqu64   192(%rcx),		B2
	vmovdqu64   224(%rcx),		B3

	store_A

	vmovq	%xmm31,	%rcx
	addq	$256,	%rcx
	vmovdqu64   (%rcx),		A0
	vmovdqu64   32(%rcx),		A1
	vmovdqu64   64(%rcx),		A2
	vmovdqu64   96(%rcx),		A3
	vmovdqu64   128(%rcx),		B0
	vmovdqu64   160(%rcx),		B1
	vmovdqu64   192(%rcx),		B2
	vmovdqu64   224(%rcx),		B3

  

	mov	%rsi, my_var(%rip)

	mov   $0x01, %eax # 0000 0001
    kmovd %eax, %k1  
	mov   $0x02, %eax # 0000 0010
    kmovd %eax, %k2  
	mov   $0x03, %eax # 0000 0011
    kmovd %eax, %k3  

	#mov   $0x0F, %eax # 0000 1111
    #kmovd %eax, %k4    
    mov   $0xF0, %eax # 1111 0000
    kmovd %eax, %k5
    mov   $0x0F, %eax # 0000 1111
    kmovd %eax, %k6
    mov   $0xC0, %eax # 1100 0000
    kmovd %eax, %k7



 .rept	8
    valignq $0x04,%zmm4,%zmm0, %zmm0{%k5}{z} #shift 4*64
	valignq $0x04,%zmm5,%zmm1, %zmm1{%k5}{z} #shift 4*64
	valignq $0x04,%zmm6,%zmm2, %zmm2{%k5}{z} #shift 4*64
    valignq $0x04,%zmm7,%zmm3, %zmm3{%k5}{z} #shift 4*64
	vmovdqu64 %zmm0,%zmm4{%k5}
	vmovdqu64 %zmm1,%zmm5{%k5}
	vmovdqu64 %zmm2,%zmm6{%k5}
	vmovdqu64 %zmm3,%zmm7{%k5}


	
	mov my_var(%rip),	%rdx
	movq		384(%rdx), %rax
	addq	$8,	%rdx
	movq		384(%rdx), %rbx
	addq	$8,	%rdx
	mov	%rdx, my_var(%rip)
	#8*16=128b ,一次解密128

    vmovq	%rax,	%xmm16
	vmovdqu64 	%zmm16,%zmm17{%k1}{z}

	vmovq	%rbx,	%xmm16
	vpexpandq %zmm16,%zmm17{%k2}

	vmovdqu64 %zmm15,%zmm16 # dont forget!!!
	vmovdqu64 %zmm17,%zmm15

    ###########AES_DEC###########
	vpxorq  %ymm1,     %ymm1,     %ymm1
    movq    $0x0123456789ABCDEF,    %rax
    vmovq   %rax,   %xmm1
    valignq     $1, %ymm0, %ymm1,  %ymm0
    movq    $0xFEDCBA9876543210,    %rax
    vmovq   %rax,   %xmm1
    valignq     $3, %ymm0, %ymm1,  %ymm0
    aes_dec
    vmovdqu64 %zmm15,%zmm17 
	vmovdqu64 %zmm16,%zmm15
    vmovdqu64 %zmm17,%zmm16 

	valignq $0x04,%zmm4,%zmm0, %zmm0{%k6}{z} #shift 4*64
	valignq $0x04,%zmm5,%zmm1, %zmm1{%k6}{z} #shift 4*64
	valignq $0x04,%zmm6,%zmm2, %zmm2{%k6}{z} #shift 4*64
    valignq $0x04,%zmm7,%zmm3, %zmm3{%k6}{z} #shift 4*64

	.rept	128

	vmovq	%xmm16,	%rax
	vpermq $0xF1,%ymm16,%ymm16 # 1111 0001 即前3组64位 高位置0,最后一组为 原先的[64-127]位
	
	vmovq	%xmm16,	%rbx
	and		$0x1,	%rbx
	shl $63, %rbx
	vpermq $0xF1,%ymm16,%ymm16 # 1111 0001 即前3组64位 高位置0,最后一组为 原先的[64-127]位
	
	vpsrlq $1, %xmm16,%xmm16{%k3}
    vmovq  %rbx ,%xmm17
	vporq %xmm16,%xmm17,%xmm16{%k1}

	and		$0x1,	%rax
	subq	$1,		%rax

	jb 		7f

	restore_B

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	call montmul1024
	store_A

7:
	
	vmovq	%xmm31,	%rcx
	addq	$256,	%rcx
	vmovdqu64   (%rcx),		A0
	vmovdqu64   32(%rcx),		A1
	vmovdqu64   64(%rcx),		A2
	vmovdqu64   96(%rcx),		A3
	vmovdqu64   128(%rcx),		B0
	vmovdqu64   160(%rcx),		B1
	vmovdqu64   192(%rcx),		B2
	vmovdqu64   224(%rcx),		B3

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	call montsqu1024

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
	xorq	%rax,	%rax	

	.endr

 .endr	

	restore_A	

	
	
	

##################################################################################################
	###							###	
	### 	montexp1024 END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################

#.endm

	ret
	.size	montexp1024, .-montexp1024

