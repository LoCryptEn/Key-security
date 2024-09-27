#include "aesni.S"
#include "rsa_head.S"

.file	"Comcq.S"
.text



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


.macro	montmul_1st_movq

/* 16 256bit vector registers */
#########################################################
	
	#########################################
	#	A0 	A1	A2	A3 	#		
	#					#
	# 	B[8]	B[10]	B[12]	B[14]	#	
	# 	A[8]	A[10]	A[12]	A[14]	#
	# 	B[0]	B[2]	B[4]	B[6]	#
	# 	A[0]	A[2]	A[4]	A[6]	#				
	#########################################
	#	B0 	B1	B2	B3 	#		
	#					#
	# 	B[9]	B[11]	B[13]	B[15]	#	
	# 	A[9]	A[11]	A[13]	A[15]	#
	# 	B[1]	B[3]	B[5]	B[7]	#
	# 	A[1]	A[3]	A[5]	A[7]	#
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[8]	M[10]	M[12]	M[14]	#
	# 	M[0]	M[2]	M[4]	M[6]	#
	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[9]	M[11]	M[13]	M[15]	#
	# 	M[1]	M[3]	M[5]	M[7]	#
	#########################################

#########################################################

##################################################################################################
	###							###	
	### 	1st part: A[0-7]*B[0-7] + M[0-7]*(q0-q7) 	###
	###							###
	###	sum 576=65+73*7					###
	###							###
##################################################################################################
	###							###
	### 	1st_0: A[0-7]*B[0] + M[0-7]*q0 			###
	###	sum 65=11+3+17*3				###
	###							###
	###########################################################

	##### A[0 2 4 6]*B[0] #####
	xorq		s8, s8
	xorq		s9, s9

	vpextrq         $1, A0xmm, bi         	#B[0]

	vmovq           A0xmm, ai         	#A[0]
	mulx            bi, s0, s1          	#A[0]*B[0]
        
	vmovq           A1xmm, ai         	#A[2]
	mulx            bi, s2, s3        	#A[2]*B[0]

	vmovq           A2xmm, ai         	#A[4]
        mulx            bi, s4, s5        	#A[4]*B[0]

	vmovq           A3xmm, ai         	#A[6]
        mulx            bi, s6, s7        	#A[6]*B[0]

	##### q0 #####
	movq		n0, %rdx
        mulx            s0, q, rh		#q0=s0*n0
        movq            q, q0              	#q0

	##### M[0 2 4 6]*q0 #####
        vmovq           M0xmm, mi         	#M[0]
        mulx            q, rl, rh        	#M[0]*q0
        add             rl, s0
        adc             rh, s1

        vmovq           M1xmm, mi         	#M[2]
        mulx            q, rl, rh        	#M[2]*q0
        adc             rl, s2
        adc             rh, s3

	vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q0
        adc             rl, s4
        adc             rh, s5

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q0
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8

	##### A[1 3 5 7]*B[0] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[0]
	add		rl, s1
	adc		rh, s2

	vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[0]
        adc             rl, s3
        adc             rh, s4

	vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[0]
        adc             rl, s5
        adc             rh, s6

	vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[0]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9

	##### M[1 3 5 7]*q0 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q0
        add             rl, s1
        adc             rh, s2

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q0
        adc             rl, s3
        adc             rh, s4

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q0
        adc             rl, s5
        adc             rh, s6

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q0
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9


##################################################################################################
        ###                                                     ###
        ###     1st_1: A[0-7]*B[1] + M[0-7]*q1                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[1] #####
        xorq            s0, s0

        vpextrq         $1, B0xmm, bi           #B[1]

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[1]
	add		rl, s1
	adc		rh, s2

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[1]
        adc             rl, s3
        adc             rh, s4

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[1]
        adc             rl, s5
        adc             rh, s6

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[1]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	
        ##### q1 #####
        movq            n0, %rdx
        mulx            s1, q, rh               #q1=s1*n0
        movq            q, q1                   #q1
	
	##### M[0 2 4 6]*q1 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q1
        add             rl, s1
        adc             rh, s2

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q1
        adc             rl, s3
        adc             rh, s4

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q1
        adc             rl, s5
        adc             rh, s6

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q1
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

	##### A[1 3 5 7]*B[1] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[1]
        add             rl, s2
        adc             rh, s3

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[1]
        adc             rl, s4
        adc             rh, s5

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[1]
        adc             rl, s6
        adc             rh, s7

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[1]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

        ##### M[1 3 5 7]*q1 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q1
        add             rl, s2
        adc             rh, s3

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q1
        adc             rl, s4
        adc             rh, s5

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q1
        adc             rl, s6
        adc             rh, s7

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q1
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0


##################################################################################################
        ###                                                     ###
        ###     1st_2: A[0-7]*B[2] + M[0-7]*q2                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[2] #####
        xorq            s1, s1

        vpextrq         $1, A1xmm, bi           #B[2]

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[2]
	add		rl, s2
	adc		rh, s3

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[2]
        adc             rl, s4
        adc             rh, s5

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[2]
        adc             rl, s6
        adc             rh, s7

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[2]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	
        ##### q2 #####
        movq            n0, %rdx
        mulx            s2, q, rh               #q2=s2*n0
        movq            q, q2                   #q2
	
	##### M[0 2 4 6]*q2 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q2
        add             rl, s2
        adc             rh, s3

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q2
        adc             rl, s4
        adc             rh, s5

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q2
        adc             rl, s6
        adc             rh, s7

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q2
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	##### A[1 3 5 7]*B[2] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[2]
        add             rl, s3
        adc             rh, s4

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[2]
        adc             rl, s5
        adc             rh, s6

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[2]
        adc             rl, s7
        adc             rh, s8

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[2]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

        ##### M[1 3 5 7]*q2 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q2
        add             rl, s3
        adc             rh, s4

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q2
        adc             rl, s5
        adc             rh, s6

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q2
        adc             rl, s7
        adc             rh, s8

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q2
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1


##################################################################################################
        ###                                                     ###
        ###     1st_3: A[0-7]*B[3] + M[0-7]*q3                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[3] #####
        xorq            s2, s2

        vpextrq         $1, B1xmm, bi           #B[3]

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[3]
	add		rl, s3
	adc		rh, s4

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[3]
        adc             rl, s5
        adc             rh, s6

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[3]
        adc             rl, s7
        adc             rh, s8

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[3]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	
        ##### q3 #####
        movq            n0, %rdx
        mulx            s3, q, rh               #q3=s3*n0
        movq            q, q3                   #q3
	
	##### M[0 2 4 6]*q3 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q3
        add             rl, s3
        adc             rh, s4

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q3
        adc             rl, s5
        adc             rh, s6

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q3
        adc             rl, s7
        adc             rh, s8

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q3
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

	##### A[1 3 5 7]*B[3] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[3]
        add             rl, s4
        adc             rh, s5

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[3]
        adc             rl, s6
        adc             rh, s7

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[3]
        adc             rl, s8
        adc             rh, s9

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[3]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

        ##### M[1 3 5 7]*q3 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q3
        add             rl, s4
        adc             rh, s5

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q3
        adc             rl, s6
        adc             rh, s7

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q3
        adc             rl, s8
        adc             rh, s9

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q3
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2


##################################################################################################
        ###                                                     ###
        ###     1st_4: A[0-7]*B[4] + M[0-7]*q4                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[4] #####
        xorq            s3, s3

        vpextrq         $1, A2xmm, bi           #B[4]

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[4]
	add		rl, s4
	adc		rh, s5

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[4]
        adc             rl, s6
        adc             rh, s7

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[4]
        adc             rl, s8
        adc             rh, s9

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[4]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	
        ##### q4 #####
        movq            n0, %rdx
        mulx            s4, q, rh               #q4=s4*n0
        movq            q, q4                   #q4
	
	##### M[0 2 4 6]*q4 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q4
        add             rl, s4
        adc             rh, s5

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q4
        adc             rl, s6
        adc             rh, s7

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q4
        adc             rl, s8
        adc             rh, s9

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q4
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

	##### A[1 3 5 7]*B[4] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[4]
        add             rl, s5
        adc             rh, s6

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[4]
        adc             rl, s7
        adc             rh, s8

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[4]
        adc             rl, s9
        adc             rh, s0

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[4]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

        ##### M[1 3 5 7]*q4 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q4
        add             rl, s5
        adc             rh, s6

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q4
        adc             rl, s7
        adc             rh, s8

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q4
        adc             rl, s9
        adc             rh, s0

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q4
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3


##################################################################################################
        ###                                                     ###
        ###     1st_5: A[0-7]*B[5] + M[0-7]*q5                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[5] #####
        xorq            s4, s4

        vpextrq         $1, B2xmm, bi           #B[5]

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[5]
	add		rl, s5
	adc		rh, s6

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[5]
        adc             rl, s7
        adc             rh, s8

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[5]
        adc             rl, s9
        adc             rh, s0

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[5]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	
        ##### q5 #####
        movq            n0, %rdx
        mulx            s5, q, rh               #q5=s5*n0
        movq            q, q5                   #q5
	
	##### M[0 2 4 6]*q5 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q5
        add             rl, s5
        adc             rh, s6

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q5
        adc             rl, s7
        adc             rh, s8

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q5
        adc             rl, s9
        adc             rh, s0

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q5
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

	##### A[1 3 5 7]*B[5] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[5]
        add             rl, s6
        adc             rh, s7

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[5]
        adc             rl, s8
        adc             rh, s9

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[5]
        adc             rl, s0
        adc             rh, s1

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[5]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

        ##### M[1 3 5 7]*q5 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q5
        add             rl, s6
        adc             rh, s7

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q5
        adc             rl, s8
        adc             rh, s9

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q5
        adc             rl, s0
        adc             rh, s1

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q5
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4


##################################################################################################
        ###                                                     ###
        ###     1st_6: A[0-7]*B[6] + M[0-7]*q6                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[6] #####
        xorq            s5, s5

        vpextrq         $1, A3xmm, bi           #B[6]

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[6]
	add		rl, s6
	adc		rh, s7

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[6]
        adc             rl, s8
        adc             rh, s9

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[6]
        adc             rl, s0
        adc             rh, s1

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[6]
        adc             rl, s2
        adc             rh, s3
	adc		$0, s4
	
        ##### q6 #####
        movq            n0, %rdx
        mulx            s6, q, rh               #q6=s6*n0
        movq            q, q6                   #q6
	
	##### M[0 2 4 6]*q6 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q6
        add             rl, s6
        adc             rh, s7

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q6
        adc             rl, s8
        adc             rh, s9

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q6
        adc             rl, s0
        adc             rh, s1

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q6
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

	##### A[1 3 5 7]*B[6] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[6]
        add             rl, s7
        adc             rh, s8

        vmovq           B1xmm, ai          	#A[3]
        mulx            bi, rl, rh              #A[3]*B[6]
        adc             rl, s9
        adc             rh, s0

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[6]
        adc             rl, s1
        adc             rh, s2

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[6]
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5

        ##### M[1 3 5 7]*q6 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q6
        add             rl, s7
        adc             rh, s8

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q6
        adc             rl, s9
        adc             rh, s0

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q6
        adc             rl, s1
        adc             rh, s2

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q6
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5


##################################################################################################
        ###                                                     ###
        ###     1st_7: A[0-7]*B[7] + M[0-7]*q7                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[7] #####
        xorq            s6, s6

        vpextrq         $1, B3xmm, bi           #B[7]

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[7]
	add		rl, s7
	adc		rh, s8

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[7]
        adc             rl, s9
        adc             rh, s0

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[7]
        adc             rl, s1
        adc             rh, s2

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[7]
        adc             rl, s3
        adc             rh, s4
	adc		$0, s5
	
        ##### q7 #####
        movq            n0, %rdx
        mulx            s7, q, rh               #q7=s7*n0
        movq            q, q7                   #q7
	
	##### M[0 2 4 6]*q7 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q7
        add             rl, s7
        adc             rh, s8

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q7
        adc             rl, s9
        adc             rh, s0

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q7
        adc             rl, s1
        adc             rh, s2

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q7
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5

	##### A[1 3 5 7]*B[7] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[7]
        add             rl, s8
        adc             rh, s9

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[7]
        adc             rl, s0
        adc             rh, s1

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[7]
        adc             rl, s2
        adc             rh, s3

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[7]
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

        ##### M[1 3 5 7]*q7 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q7
        add             rl, s8
        adc             rh, s9

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q7
        adc             rl, s0
        adc             rh, s1

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q7
        adc             rl, s2
        adc             rh, s3

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q7
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

##################################################################################################
	###							###	
	### 	1st part END 					###
	###							###
	###	low			high			###
	###							###
	###	s8 s9 s0 s1 s2 s3 s4 s5 s6			###
	###							###
##################################################################################################

.endm


.macro	montmul_2nd_movq

##################################################################################################
	###										###	
	### 	2nd part: 								###
	### 	A[8-15]*B[0-7] + M[8-15]*(q0-q7) + A[0-7]*B[8-15] + M[0-7]*(q8-q15) 	###
	###										###
	###	sum 1248=56+149*8							###
	###										###
##################################################################################################
        ###                                                     ###
        ###     2nd_arrange_vector		                ###
        ###     sum 8                                 	        ###
        ###                                                     ###
        ###########################################################

	vpermq		$0x8D, A0, A0			#imm=3120
	vpermq		$0x8D, A1, A1			#imm=3120
	vpermq		$0x8D, A2, A2			#imm=3120
	vpermq		$0x8D, A3, A3			#imm=3120
	vpermq		$0x8D, B0, B0			#imm=3120
	vpermq		$0x8D, B1, B1			#imm=3120
	vpermq		$0x8D, B2, B2			#imm=3120
	vpermq		$0x8D, B3, B3			#imm=3120


/* 16 256bit vector registers */
#########################################################
	
	#########################################
	#	A0 	A1	A2	A3 	#		
	#					#
	# 	B[8]	B[10]	B[12]	B[14]	#	
	# 	B[0]	B[2]	B[4]	B[6]	#
	# 	A[8]	A[10]	A[12]	A[14]	#
	# 	A[0]	A[2]	A[4]	A[6]	#				
	#########################################
	#	B0 	B1	B2	B3 	#		
	#					#
	# 	B[9]	B[11]	B[13]	B[15]	#	
	# 	B[1]	B[3]	B[5]	B[7]	#
	# 	A[9]	A[11]	A[13]	A[15]	#
	# 	A[1]	A[3]	A[5]	A[7]	#
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[8]	M[10]	M[12]	M[14]	#
	# 	M[0]	M[2]	M[4]	M[6]	#
	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[9]	M[11]	M[13]	M[15]	#
	# 	M[1]	M[3]	M[5]	M[7]	#
	#########################################

#########################################################

##################################################################################################
        ###								###	
	### 	2nd_0: 							###
	### 	A[8-15]*B[0] + M[8-15]*q0 + A[0-7]*B[8] + M[0-7]*q8 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[0] #####
        xorq            s7, s7

	vperm2i128	$1, A0, A0, A0		#imm=01
        vmovq           A0xmm, bi               #B[0]
	vperm2i128	$1, A0, A0, A0		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[0]
	add		rl, s8
	adc		rh, s9

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[0]
        adc             rl, s0
        adc             rh, s1

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[0]
        adc             rl, s2
        adc             rh, s3

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[0]
        adc             rl, s4
        adc             rh, s5
	adc		$0, s6
	
        ##### q0 #####
        movq            q0, q                  
	
	##### M[8 10 12 14]*q0 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q0
        add             rl, s8
        adc             rh, s9

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q0
        adc             rl, s0
        adc             rh, s1

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q0
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q0
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

	##### A[9 11 13 15]*B[0] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[0]
        add             rl, s9
        adc             rh, s0

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[0]
        adc             rl, s1
        adc             rh, s2

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[0]
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[0]
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

        ##### M[9 11 13 15]*q0 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q0
        add             rl, s9
        adc             rh, s0

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q0
        adc             rl, s1
        adc             rh, s2

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q0
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q0
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[8] #####
	vperm2i128	$1, A0, A0, A0		#imm=01
        vpextrq         $1, A0xmm, bi           #B[8]
	vperm2i128	$1, A0, A0, A0		#imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[8]
	add		rl, s8
	adc		rh, s9

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[8]
        adc             rl, s0
        adc             rh, s1

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[8]
        adc             rl, s2
        adc             rh, s3

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[8]
        adc             rl, s4
        adc             rh, s5
	adc		$0, s6
	adc		$0, s7
	
        ##### q8 #####
        movq            n0, %rdx
        mulx            s8, q, rh               #q8=s8*n0
        movq            q, q8                   #q8
	
	##### M[0 2 4 6]*q8 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q8
        add             rl, s8
        adc             rh, s9

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q8
        adc             rl, s0
        adc             rh, s1

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q8
        adc             rl, s2
        adc             rh, s3

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q8
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6
	adc		$0, s7

	##### A[1 3 5 7]*B[8] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[8]
        add             rl, s9
        adc             rh, s0

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[8]
        adc             rl, s1
        adc             rh, s2

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[8]
        adc             rl, s3
        adc             rh, s4

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[8]
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

        ##### M[1 3 5 7]*q8 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q8
        add             rl, s9
        adc             rh, s0

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q8
        adc             rl, s1
        adc             rh, s2

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q8
        adc             rl, s3
        adc             rh, s4

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q8
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7


##################################################################################################
        ###								###	
	### 	2nd_1: 							###
	### 	A[8-15]*B[1] + M[8-15]*q1 + A[0-7]*B[9] + M[0-7]*q9 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[1] #####
        xorq            s8, s8

	vperm2i128	$1, B0, B0, B0		#imm=01
        vmovq           B0xmm, bi               #B[1]
	vperm2i128	$1, B0, B0, B0		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[1]
	add		rl, s9
	adc		rh, s0

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[1]
        adc             rl, s1
        adc             rh, s2

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[1]
        adc             rl, s3
        adc             rh, s4

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[1]
        adc             rl, s5
        adc             rh, s6
	adc		$0, s7
	
        ##### q1 #####
        movq            q1, q                  
	
	##### M[8 10 12 14]*q1 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q1
        add             rl, s9
        adc             rh, s0

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q1
        adc             rl, s1
        adc             rh, s2

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q1
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q1
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

	##### A[9 11 13 15]*B[1] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[1]
        add             rl, s0
        adc             rh, s1

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[1]
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[1]
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[1]
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

        ##### M[9 11 13 15]*q1 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q1
        add             rl, s0
        adc             rh, s1

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q1
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q1
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q1
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[9] #####
	vperm2i128	$1, B0, B0, B0	        #imm=01
        vpextrq         $1, B0xmm, bi           #B[9]
	vperm2i128	$1, B0, B0, B0	        #imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[9]
	add		rl, s9
	adc		rh, s0

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[9]
        adc             rl, s1
        adc             rh, s2

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[9]
        adc             rl, s3
        adc             rh, s4

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[9]
        adc             rl, s5
        adc             rh, s6
	adc		$0, s7
	adc		$0, s8
	
        ##### q9 #####
        movq            n0, %rdx
        mulx            s9, q, rh               #q9=s9*n0
        movq            q, q9                   #q9
	
	##### M[0 2 4 6]*q9 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q9
        add             rl, s9
        adc             rh, s0

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q9
        adc             rl, s1
        adc             rh, s2

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q9
        adc             rl, s3
        adc             rh, s4

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q9
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7
	adc		$0, s8

	##### A[1 3 5 7]*B[9] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[9]
        add             rl, s0
        adc             rh, s1

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[9]
        adc             rl, s2
        adc             rh, s3

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[9]
        adc             rl, s4
        adc             rh, s5

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[9]
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

        ##### M[1 3 5 7]*q9 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q9
        add             rl, s0
        adc             rh, s1

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q9
        adc             rl, s2
        adc             rh, s3

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q9
        adc             rl, s4
	adc             rh, s5

	vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q9
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8
	

##################################################################################################
        ###								###	
	### 	2nd_2: 							###
	### 	A[8-15]*B[2] + M[8-15]*q2 + A[0-7]*B[10] + M[0-7]*q10 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[2] #####
        xorq            s9, s9

	vperm2i128	$1, A1, A1, A1	        #imm=01
        vmovq           A1xmm, bi               #B[2]
	vperm2i128	$1, A1, A1, A1	        #imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[2]
	add		rl, s0
	adc		rh, s1

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[2]
        adc             rl, s2
        adc             rh, s3

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[2]
        adc             rl, s4
        adc             rh, s5

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[2]
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8
	
        ##### q2 #####
        movq            q2, q                  
	
	##### M[8 10 12 14]*q2 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q2
        add             rl, s0
        adc             rh, s1

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q2
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q2
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q2
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

	##### A[9 11 13 15]*B[2] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[2]
        add             rl, s1
        adc             rh, s2

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[2]
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[2]
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[2]
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

        ##### M[9 11 13 15]*q2 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q2
        add             rl, s1
        adc             rh, s2

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q2
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q2
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q2
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[10] #####
	vperm2i128	$1, A1, A1, A1	        #imm=01
        vpextrq         $1, A1xmm, bi           #B[10]
	vperm2i128	$1, A1, A1, A1	        #imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[10]
	add		rl, s0
	adc		rh, s1

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[10]
        adc             rl, s2
        adc             rh, s3

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[10]
        adc             rl, s4
        adc             rh, s5

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[10]
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8
	adc		$0, s9
	
        ##### q10 #####
        movq            n0, %rdx
        mulx            s0, q, rh               #q10=s0*n0
        movq            q, q10                  #q10
	
	##### M[0 2 4 6]*q10 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q10
        add             rl, s0
        adc             rh, s1

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q10
        adc             rl, s2
        adc             rh, s3

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q10
        adc             rl, s4
        adc             rh, s5

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q10
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8
	adc		$0, s9

	##### A[1 3 5 7]*B[10] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[10]
        add             rl, s1
        adc             rh, s2

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[10]
        adc             rl, s3
        adc             rh, s4

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[10]
        adc             rl, s5
        adc             rh, s6

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[10]
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

        ##### M[1 3 5 7]*q10 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q10
        add             rl, s1
        adc             rh, s2

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q10
        adc             rl, s3
        adc             rh, s4

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q10
        adc             rl, s5
        adc             rh, s6

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q10
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9


##################################################################################################
        ###								###	
	### 	2nd_3: 							###
	### 	A[8-15]*B[3] + M[8-15]*q3 + A[0-7]*B[11] + M[0-7]*q11 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[3] #####
        xorq            s0, s0

	vperm2i128	$1, B1, B1, B1	        #imm=01
        vmovq           B1xmm, bi               #B[3]
	vperm2i128	$1, B1, B1, B1	        #imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[3]
	add		rl, s1
	adc		rh, s2

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[3]
        adc             rl, s3
        adc             rh, s4

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[3]
        adc             rl, s5
        adc             rh, s6

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[3]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	
        ##### q3 #####
        movq            q3, q                  
	
	##### M[8 10 12 14]*q3 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q3
        add             rl, s1
        adc             rh, s2

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q3
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q3
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q3
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

	##### A[9 11 13 15]*B[3] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[3]
        add             rl, s2
        adc             rh, s3

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[3]
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[3]
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[3]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

        ##### M[9 11 13 15]*q3 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q3
        add             rl, s2
        adc             rh, s3

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q3
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q3
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q3
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[11] #####
	vperm2i128	$1, B1, B1, B1	        #imm=01
        vpextrq         $1, B1xmm, bi           #B[11]
	vperm2i128	$1, B1, B1, B1	        #imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[11]
	add		rl, s1
	adc		rh, s2

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[11]
        adc             rl, s3
        adc             rh, s4

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[11]
        adc             rl, s5
        adc             rh, s6

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[11]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	adc		$0, s0
	
        ##### q11 #####
        movq            n0, %rdx
        mulx            s1, q, rh               #q11=s1*n0
        movq            q, q11                  #q11
	
	##### M[0 2 4 6]*q11 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q11
        add             rl, s1
        adc             rh, s2

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q11
        adc             rl, s3
        adc             rh, s4

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q11
        adc             rl, s5
        adc             rh, s6

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q11
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9
	adc		$0, s0

	##### A[1 3 5 7]*B[11] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[11]
        add             rl, s2
        adc             rh, s3

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[11]
        adc             rl, s4
        adc             rh, s5

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[11]
        adc             rl, s6
        adc             rh, s7

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[11]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

        ##### M[1 3 5 7]*q11 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q11
        add             rl, s2
        adc             rh, s3

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q11
        adc             rl, s4
        adc             rh, s5

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q11
        adc             rl, s6
        adc             rh, s7

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q11
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0


##################################################################################################
        ###								###	
	### 	2nd_4: 							###
	### 	A[8-15]*B[4] + M[8-15]*q4 + A[0-7]*B[12] + M[0-7]*q12 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[4] #####
        xorq            s1, s1

	vperm2i128	$1, A2, A2, A2	        #imm=01
        vmovq           A2xmm, bi               #B[4]
	vperm2i128	$1, A2, A2, A2	        #imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[4]
	add		rl, s2
	adc		rh, s3

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[4]
        adc             rl, s4
        adc             rh, s5

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[4]
        adc             rl, s6
        adc             rh, s7

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[4]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	
        ##### q4 #####
        movq            q4, q                  
	
	##### M[8 10 12 14]*q4 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q4
        add             rl, s2
        adc             rh, s3

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q4
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q4
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q4
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	##### A[9 11 13 15]*B[4] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[4]
        add             rl, s3
        adc             rh, s4

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[4]
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[4]
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[4]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

        ##### M[9 11 13 15]*q4 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q4
        add             rl, s3
        adc             rh, s4

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q4
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q4
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q4
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[12] #####
	vperm2i128	$1, A2, A2, A2	        #imm=01
        vpextrq         $1, A2xmm, bi           #B[12]
	vperm2i128	$1, A2, A2, A2	        #imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[12]
	add		rl, s2
	adc		rh, s3

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[12]
        adc             rl, s4
        adc             rh, s5

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[12]
        adc             rl, s6
        adc             rh, s7

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[12]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	adc		$0, s1
	
        ##### q12 #####
        movq            n0, %rdx
        mulx            s2, q, rh               #q12=s2*n0
        movq            q, q12                  #q12
	
	##### M[0 2 4 6]*q12 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q12
        add             rl, s2
        adc             rh, s3

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q12
        adc             rl, s4
        adc             rh, s5

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q12
        adc             rl, s6
        adc             rh, s7

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q12
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0
	adc		$0, s1

	##### A[1 3 5 7]*B[12] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[12]
        add             rl, s3
        adc             rh, s4

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[12]
        adc             rl, s5
        adc             rh, s6

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[12]
        adc             rl, s7
        adc             rh, s8

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[12]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

        ##### M[1 3 5 7]*q12 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q12
        add             rl, s3
        adc             rh, s4

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q12
        adc             rl, s5
        adc             rh, s6

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q12
        adc             rl, s7
        adc             rh, s8

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q12
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1


##################################################################################################
        ###								###	
	### 	2nd_5: 							###
	### 	A[8-15]*B[5] + M[8-15]*q5 + A[0-7]*B[13] + M[0-7]*q13 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[5] #####
        xorq            s2, s2

	vperm2i128	$1, B2, B2, B2	        #imm=01
        vmovq           B2xmm, bi               #B[5]
	vperm2i128	$1, B2, B2, B2	        #imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[5]
	add		rl, s3
	adc		rh, s4

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[5]
        adc             rl, s5
        adc             rh, s6

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[5]
        adc             rl, s7
        adc             rh, s8

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[5]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	
        ##### q5 #####
        movq            q5, q                  
	
	##### M[8 10 12 14]*q5 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q5
        add             rl, s3
        adc             rh, s4

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q5
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q5
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q5
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

	##### A[9 11 13 15]*B[5] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[5]
        add             rl, s4
        adc             rh, s5

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[5]
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[5]
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[5]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

        ##### M[9 11 13 15]*q5 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q5
        add             rl, s4
        adc             rh, s5

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q5
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q5
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q5
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[13] #####
	vperm2i128	$1, B2, B2, B2	        #imm=01
        vpextrq         $1, B2xmm, bi           #B[13]
	vperm2i128	$1, B2, B2, B2	        #imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[13]
	add		rl, s3
	adc		rh, s4

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[13]
        adc             rl, s5
        adc             rh, s6

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[13]
        adc             rl, s7
        adc             rh, s8

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[13]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	adc		$0, s2
	
        ##### q13 #####
        movq            n0, %rdx
        mulx            s3, q, rh               #q13=s3*n0
        movq            q, q13                  #q13
	
	##### M[0 2 4 6]*q13 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q13
        add             rl, s3
        adc             rh, s4

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q13
        adc             rl, s5
        adc             rh, s6

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q13
        adc             rl, s7
        adc             rh, s8

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q13
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1
	adc		$0, s2

	##### A[1 3 5 7]*B[13] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[13]
        add             rl, s4
        adc             rh, s5

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[13]
        adc             rl, s6
        adc             rh, s7

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[13]
        adc             rl, s8
        adc             rh, s9

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[13]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

        ##### M[1 3 5 7]*q13 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q13
        add             rl, s4
        adc             rh, s5

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q13
        adc             rl, s6
        adc             rh, s7

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q13
        adc             rl, s8
        adc             rh, s9

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q13
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2


##################################################################################################
        ###								###	
	### 	2nd_6: 							###
	### 	A[8-15]*B[6] + M[8-15]*q6 + A[0-7]*B[14] + M[0-7]*q14 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[6] #####
        xorq            s3, s3

	vperm2i128	$1, A3, A3, A3	        #imm=01
        vmovq           A3xmm, bi               #B[6]
	vperm2i128	$1, A3, A3, A3	        #imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[6]
	add		rl, s4
	adc		rh, s5

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[6]
        adc             rl, s6
        adc             rh, s7

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[6]
        adc             rl, s8
        adc             rh, s9

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[6]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	
        ##### q6 #####
        movq            q6, q                  
	
	##### M[8 10 12 14]*q6 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q6
        add             rl, s4
        adc             rh, s5

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q6
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q6
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q6
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

	##### A[9 11 13 15]*B[6] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[6]
        add             rl, s5
        adc             rh, s6

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[6]
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[6]
        adc             rl, s9
        adc             rh, s0

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[6]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

        ##### M[9 11 13 15]*q6 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q6
        add             rl, s5
        adc             rh, s6

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q6
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q6
        adc             rl, s9
        adc             rh, s0

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q6
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[14] #####
	vperm2i128	$1, A3, A3, A3	        #imm=01
        vpextrq         $1, A3xmm, bi           #B[14]
	vperm2i128	$1, A3, A3, A3  	#imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[14]
	add		rl, s4
	adc		rh, s5

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[14]
        adc             rl, s6
        adc             rh, s7

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[14]
        adc             rl, s8
        adc             rh, s9

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[14]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	adc		$0, s3
	
        ##### q14 #####
        movq            n0, %rdx
        mulx            s4, q, rh               #q14=s4*n0
        movq            q, q14                  #q14
	
	##### M[0 2 4 6]*q14 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q14
        add             rl, s4
        adc             rh, s5

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q14
        adc             rl, s6
        adc             rh, s7

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q14
        adc             rl, s8
        adc             rh, s9

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q14
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2
	adc		$0, s3

	##### A[1 3 5 7]*B[14] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[14]
        add             rl, s5
        adc             rh, s6

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[14]
        adc             rl, s7
        adc             rh, s8

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[14]
        adc             rl, s9
        adc             rh, s0

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[14]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

        ##### M[1 3 5 7]*q14 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q14
        add             rl, s5
        adc             rh, s6

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q14
        adc             rl, s7
        adc             rh, s8

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q14
        adc             rl, s9
        adc             rh, s0

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q14
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3


##################################################################################################
        ###								###	
	### 	2nd_7: 							###
	### 	A[8-15]*B[7] + M[8-15]*q7 + A[0-7]*B[15] + M[0-7]*q15 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[7] #####
        xorq            s4, s4

	vperm2i128	$1, B3, B3, B3	        #imm=01
        vmovq           B3xmm, bi               #B[7]
	vperm2i128	$1, B3, B3, B3	        #imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[7]
	add		rl, s5
	adc		rh, s6

	vpextrq         $1, A1xmm, ai           #A[10]
        mulx            bi, rl, rh              #A[10]*B[7]
        adc             rl, s7
        adc             rh, s8

	vpextrq         $1, A2xmm, ai           #A[12]
        mulx            bi, rl, rh              #A[12]*B[7]
        adc             rl, s9
        adc             rh, s0

	vpextrq         $1, A3xmm, ai           #A[14]
        mulx            bi, rl, rh              #A[14]*B[7]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	
        ##### q7 #####
        movq            q7, q                  
	
	##### M[8 10 12 14]*q7 #####
        vpextrq         $1, M0xmm, mi           #M[8]
        mulx            q, rl, rh               #M[8]*q7
        add             rl, s5
        adc             rh, s6

        vpextrq         $1, M1xmm, mi           #M[10]
        mulx            q, rl, rh               #M[10]*q7
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, M2xmm, mi           #M[12]
        mulx            q, rl, rh               #M[12]*q7
        adc             rl, s9
        adc             rh, s0

        vpextrq         $1, M3xmm, mi           #M[14]
        mulx            q, rl, rh               #M[14]*q7
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

	##### A[9 11 13 15]*B[7] #####
        vpextrq         $1, B0xmm, ai           #A[9]
        mulx            bi, rl, rh              #A[9]*B[7]
        add             rl, s6
        adc             rh, s7

        vpextrq         $1, B1xmm, ai           #A[11]
        mulx            bi, rl, rh              #A[11]*B[7]
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, B2xmm, ai           #A[13]
        mulx            bi, rl, rh              #A[13]*B[7]
        adc             rl, s0
        adc             rh, s1

        vpextrq         $1, B3xmm, ai           #A[15]
        mulx            bi, rl, rh              #A[15]*B[7]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

        ##### M[9 11 13 15]*q7 #####
        vpextrq         $1, T0xmm, mi           #M[9]
        mulx            q, rl, rh               #M[9]*q7
        add             rl, s6
        adc             rh, s7

        vpextrq         $1, T1xmm, mi           #M[11]
        mulx            q, rl, rh               #M[11]*q7
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, T2xmm, mi           #M[13]
        mulx            q, rl, rh               #M[13]*q7
        adc             rl, s0
        adc             rh, s1

        vpextrq         $1, T3xmm, mi           #M[15]
        mulx            q, rl, rh               #M[15]*q7
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[15] #####
	vperm2i128	$1, B3, B3, B3	        #imm=01
        vpextrq         $1, B3xmm, bi           #B[15]
	vperm2i128	$1, B3, B3, B3	        #imm=01

        vmovq           A0xmm, ai               #A[0]
        mulx            bi, rl, rh              #A[0]*B[15]
	add		rl, s5
	adc		rh, s6

	vmovq           A1xmm, ai               #A[2]
        mulx            bi, rl, rh              #A[2]*B[15]
        adc             rl, s7
        adc             rh, s8

	vmovq           A2xmm, ai               #A[4]
        mulx            bi, rl, rh              #A[4]*B[15]
        adc             rl, s9
        adc             rh, s0

	vmovq           A3xmm, ai               #A[6]
        mulx            bi, rl, rh              #A[6]*B[15]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	adc		$0, s4
	
        ##### q15 #####
        movq            n0, %rdx
        mulx            s5, q, rh               #q15=s5*n0
        movq            q, q15                  #q15
	
	##### M[0 2 4 6]*q15 #####
        vmovq           M0xmm, mi               #M[0]
        mulx            q, rl, rh               #M[0]*q15
        add             rl, s5
        adc             rh, s6

        vmovq           M1xmm, mi               #M[2]
        mulx            q, rl, rh               #M[2]*q15
        adc             rl, s7
        adc             rh, s8

        vmovq           M2xmm, mi               #M[4]
        mulx            q, rl, rh               #M[4]*q15
        adc             rl, s9
        adc             rh, s0

        vmovq           M3xmm, mi               #M[6]
        mulx            q, rl, rh               #M[6]*q15
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3
	adc		$0, s4

	##### A[1 3 5 7]*B[15] #####
        vmovq           B0xmm, ai               #A[1]
        mulx            bi, rl, rh              #A[1]*B[15]
        add             rl, s6
        adc             rh, s7

        vmovq           B1xmm, ai               #A[3]
        mulx            bi, rl, rh              #A[3]*B[15]
        adc             rl, s8
        adc             rh, s9

        vmovq           B2xmm, ai               #A[5]
        mulx            bi, rl, rh              #A[5]*B[15]
        adc             rl, s0
        adc             rh, s1

        vmovq           B3xmm, ai               #A[7]
        mulx            bi, rl, rh              #A[7]*B[15]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

        ##### M[1 3 5 7]*q15 #####
        vmovq           T0xmm, mi               #M[1]
        mulx            q, rl, rh               #M[1]*q15
        add             rl, s6
        adc             rh, s7

        vmovq           T1xmm, mi               #M[3]
        mulx            q, rl, rh               #M[3]*q15
        adc             rl, s8
        adc             rh, s9

        vmovq           T2xmm, mi               #M[5]
        mulx            q, rl, rh               #M[5]*q15
        adc             rl, s0
        adc             rh, s1

        vmovq           T3xmm, mi               #M[7]
        mulx            q, rl, rh               #M[7]*q15
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4


##################################################################################################
	###							###	
	### 	2nd part END 					###
	###							###
	###	low			high			###
	###							###
	###	s6 s7 s8 s9 s0 s1 s2 s3 s4			###
	###							###
##################################################################################################

.endm


.macro  montmul_3rd_movq

##################################################################################################
	###							###	
	### 	3rd part: A[8-15]*B[8-15] + M[8-15]*(q8-q15) 	###
	###							###
	###	sum 628=52+72*8					###
	###							###
##################################################################################################
        ###                                                     ###
        ###     3rd_arrange_vector		                ###
        ###     sum 52=7*4+6*4                                 	###
        ###                                                     ###
        ###########################################################



        vpermq		$0x8D, A0, A0			#imm=2031
	vpermq		$0x8D, A1, A1			#imm=2031
	vpermq		$0x8D, A2, A2			#imm=2031
	vpermq		$0x8D, A3, A3			#imm=2031
	vpermq		$0x8D, B0, B0			#imm=2031
	vpermq		$0x8D, B1, B1			#imm=2031
	vpermq		$0x8D, B2, B2			#imm=2031
	vpermq		$0x8D, B3, B3			#imm=2031

/*
	vpermq		$0x72, A0, A0			#imm=01 11 00 10
	vpermq		$0x72, A1, A1			#imm=01 11 00 10
	vpermq		$0x72, A2, A2			#imm=01 11 00 10
	vpermq		$0x72, A3, A3			#imm=01 11 00 10
	vpermq		$0x72, B0, B0			#imm=01 11 00 10
	vpermq		$0x72, B1, B1			#imm=01 11 00 10
	vpermq		$0x72, B2, B2			#imm=01 11 00 10
	vpermq		$0x72, B3, B3			#imm=01 11 00 10
*/

	### inverse M ###
	vshufpd		$0x05, M0, M0, M0		#imm=0101
	vshufpd		$0x05, M1, M1, M1		#imm=0101
	vshufpd		$0x05, M2, M2, M2		#imm=0101
	vshufpd		$0x05, M3, M3, M3		#imm=0101
	vshufpd		$0x05, T0, T0, T0		#imm=0101
	vshufpd		$0x05, T1, T1, T1		#imm=0101
	vshufpd		$0x05, T2, T2, T2		#imm=0101
	vshufpd		$0x05, T3, T3, T3		#imm=0101
 

 /* 16 256bit vector registers */
#########################################################
	
	#########################################
	#	A0 	A1	A2	A3 	#		
	#					#
	# 	B[0]	B[2]	B[4]	B[6]	#	
	# 	A[0]	A[2]	A[4]	A[6]	#
	# 	B[8]	B[10]	B[12]	B[14]	#
	# 	A[8]	A[10]	A[12]	A[14]	#				
	#########################################
	#	B0 	B1	B2	B3 	#		
	#					#
	# 	B[1]	B[3]	B[5]	B[7]	#	
	# 	A[1]	A[3]	A[5]	A[7]	#
	# 	B[9]	B[11]	B[13]	B[15]	#
	# 	A[9]	A[11]	A[13]	A[15]	#
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[0]	M[2]	M[4]	M[6]	#
	# 	M[8]	M[10]	M[12]	M[14]	#
	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[1]	M[3]	M[5]	M[7]	#
	# 	M[9]	M[11]	M[13]	M[15]	#
	#########################################

#########################################################


##################################################################################################
        ###								###	
	### 	3rd_0: 							###
	### 	A[8-15]*B[8] + M[8-15]*q8 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[8] #####
        xorq            s5, s5

        vpextrq         $1, A0xmm, bi          	#B[8]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[8]
	add		rl, s6
	adc		rh, s7

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[8]
        adc             rl, s8
        adc             rh, s9

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[8]
        adc             rl, s0
        adc             rh, s1

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[8]
        adc             rl, s2
        adc             rh, s3
	adc		$0, s4
	
        ##### q8 #####
        movq            q8, q                  
	
	##### M[8 10 12 14]*q8 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q8
        add             rl, s6
        adc             rh, s7

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q8
        adc             rl, s8
        adc             rh, s9

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q8
        adc             rl, s0
        adc             rh, s1

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q8
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

	##### A[9 11 13 15]*B[8] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[8]
        add             rl, s7
        adc             rh, s8

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[8]
        adc             rl, s9
        adc             rh, s0

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[8]
        adc             rl, s1
        adc             rh, s2

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[8]
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5

        ##### M[9 11 13 15]*q8 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q8
        add             rl, s7
        adc             rh, s8

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q8
        adc             rl, s9
        adc             rh, s0

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q8
        adc             rl, s1
        adc             rh, s2

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q8
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5

	movq		s6, r0			#result[0]


##################################################################################################
        ###								###	
	### 	3rd_1: 							###
	### 	A[8-15]*B[9] + M[8-15]*q9 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[9] #####
        xorq            s6, s6

        vpextrq         $1, B0xmm, bi          	#B[9]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[9]
	add		rl, s7
	adc		rh, s8

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[9]
        adc             rl, s9
        adc             rh, s0

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[9]
        adc             rl, s1
        adc             rh, s2

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[9]
        adc             rl, s3
        adc             rh, s4
	adc		$0, s5
	
        ##### q9 #####
        movq            q9, q                  
	
	##### M[8 10 12 14]*q9 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q9
        add             rl, s7
        adc             rh, s8

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q9
        adc             rl, s9
        adc             rh, s0

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q9
        adc             rl, s1
        adc             rh, s2

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q9
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5

	##### A[9 11 13 15]*B[9] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[9]
        add             rl, s8
        adc             rh, s9

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[9]
        adc             rl, s0
        adc             rh, s1

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[9]
        adc             rl, s2
        adc             rh, s3

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[9]
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

        ##### M[9 11 13 15]*q9 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q9
        add             rl, s8
        adc             rh, s9

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q9
        adc             rl, s0
        adc             rh, s1

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q9
        adc             rl, s2
        adc             rh, s3

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q9
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

	movq		s7, r1			#result[1]


##################################################################################################
        ###								###	
	### 	3rd_2: 							###
	### 	A[8-15]*B[10] + M[8-15]*q10 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[10] #####
        xorq            s7, s7

        vpextrq         $1, A1xmm, bi          	#B[10]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[10]
	add		rl, s8
	adc		rh, s9

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[10]
        adc             rl, s0
        adc             rh, s1

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[10]
        adc             rl, s2
        adc             rh, s3

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[10]
        adc             rl, s4
        adc             rh, s5
	adc		$0, s6
	
        ##### q10 #####
        movq            q10, q                  
	
	##### M[8 10 12 14]*q10 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q10
        add             rl, s8
        adc             rh, s9

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q10
        adc             rl, s0
        adc             rh, s1

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q10
        adc             rl, s2
        adc             rh, s3

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q10
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

	##### A[9 11 13 15]*B[10] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[10]
        add             rl, s9
        adc             rh, s0

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[10]
        adc             rl, s1
        adc             rh, s2

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[10]
        adc             rl, s3
        adc             rh, s4

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[10]
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

        ##### M[9 11 13 15]*q10 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q10
        add             rl, s9
        adc             rh, s0

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q10
        adc             rl, s1
        adc             rh, s2

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q10
        adc             rl, s3
        adc             rh, s4

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q10
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

	movq		s8, r2			#result[2]


##################################################################################################
        ###								###	
	### 	3rd_3: 							###
	### 	A[8-15]*B[11] + M[8-15]*q11 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[11] #####
        xorq            s8, s8

        vpextrq         $1, B1xmm, bi          	#B[11]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[11]
	add		rl, s9
	adc		rh, s0

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[11]
        adc             rl, s1
        adc             rh, s2

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[11]
        adc             rl, s3
        adc             rh, s4

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[11]
        adc             rl, s5
        adc             rh, s6
	adc		$0, s7
	
        ##### q11 #####
        movq            q11, q                  
	
	##### M[8 10 12 14]*q11 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q11
        add             rl, s9
        adc             rh, s0

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q11
        adc             rl, s1
        adc             rh, s2

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q11
        adc             rl, s3
        adc             rh, s4

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q11
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

	##### A[9 11 13 15]*B[11] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[11]
        add             rl, s0
        adc             rh, s1

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[11]
        adc             rl, s2
        adc             rh, s3

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[11]
        adc             rl, s4
        adc             rh, s5

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[11]
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

        ##### M[9 11 13 15]*q11 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q11
        add             rl, s0
        adc             rh, s1

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q11
        adc             rl, s2
        adc             rh, s3

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q11
        adc             rl, s4
        adc             rh, s5

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q11
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

	movq		s9, r3			#result[3]


##################################################################################################
        ###								###	
	### 	3rd_4: 							###
	### 	A[8-15]*B[12] + M[8-15]*q12 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[12] #####
        xorq            s9, s9

        vpextrq         $1, A2xmm, bi          	#B[12]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[12]
	add		rl, s0
	adc		rh, s1

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[12]
        adc             rl, s2
        adc             rh, s3

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[12]
        adc             rl, s4
        adc             rh, s5

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[12]
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8
	
        ##### q12 #####
        movq            q12, q                  
	
	##### M[8 10 12 14]*q12 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q12
        add             rl, s0
        adc             rh, s1

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q12
        adc             rl, s2
        adc             rh, s3

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q12
        adc             rl, s4
        adc             rh, s5

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q12
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

	##### A[9 11 13 15]*B[12] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[12]
        add             rl, s1
        adc             rh, s2

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[12]
        adc             rl, s3
        adc             rh, s4

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[12]
        adc             rl, s5
        adc             rh, s6

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[12]
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

        ##### M[9 11 13 15]*q12 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q12
        add             rl, s1
        adc             rh, s2

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q12
        adc             rl, s3
        adc             rh, s4

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q12
        adc             rl, s5
        adc             rh, s6

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q12
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

	movq		s0, r4			#result[4]


##################################################################################################
        ###								###	
	### 	3rd_5: 							###
	### 	A[8-15]*B[13] + M[8-15]*q13 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[13] #####
        xorq            s0, s0

        vpextrq         $1, B2xmm, bi          	#B[13]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[13]
	add		rl, s1
	adc		rh, s2

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[13]
        adc             rl, s3
        adc             rh, s4

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[13]
        adc             rl, s5
        adc             rh, s6

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[13]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	
        ##### q13 #####
        movq            q13, q                  
	
	##### M[8 10 12 14]*q13 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q13
        add             rl, s1
        adc             rh, s2

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q13
        adc             rl, s3
        adc             rh, s4

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q13
        adc             rl, s5
        adc             rh, s6

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q13
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

	##### A[9 11 13 15]*B[13] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[13]
        add             rl, s2
        adc             rh, s3

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[13]
        adc             rl, s4
        adc             rh, s5

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[13]
        adc             rl, s6
        adc             rh, s7

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[13]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

        ##### M[9 11 13 15]*q13 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q13
        add             rl, s2
        adc             rh, s3

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q13
        adc             rl, s4
        adc             rh, s5

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q13
        adc             rl, s6
        adc             rh, s7

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q13
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	movq		s1, r5			#result[5]


##################################################################################################
        ###								###	
	### 	3rd_6: 							###
	### 	A[8-15]*B[14] + M[8-15]*q14 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[14] #####
        xorq            s1, s1

        vpextrq         $1, A3xmm, bi          	#B[14]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[14]
	add		rl, s2
	adc		rh, s3

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[14]
        adc             rl, s4
        adc             rh, s5

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[14]
        adc             rl, s6
        adc             rh, s7

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[14]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	
        ##### q14 #####
        movq            q14, q                  
	
	##### M[8 10 12 14]*q14 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q14
        add             rl, s2
        adc             rh, s3

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q14
        adc             rl, s4
        adc             rh, s5

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q14
        adc             rl, s6
        adc             rh, s7

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q14
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	##### A[9 11 13 15]*B[14] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[14]
        add             rl, s3
        adc             rh, s4

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[14]
        adc             rl, s5
        adc             rh, s6

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[14]
        adc             rl, s7
        adc             rh, s8

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[14]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

        ##### M[9 11 13 15]*q14 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q14
        add             rl, s3
        adc             rh, s4

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q14
        adc             rl, s5
        adc             rh, s6

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q14
        adc             rl, s7
        adc             rh, s8

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q14
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

	movq		s2, r6			#result[6]


##################################################################################################
        ###								###	
	### 	3rd_7: 							###
	### 	A[8-15]*B[15] + M[8-15]*q15 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[15] #####
        xorq            s2, s2

        vpextrq         $1, B3xmm, bi          	#B[15]

        vmovq           A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[15]
	add		rl, s3
	adc		rh, s4

	vmovq           A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[15]
        adc             rl, s5
        adc             rh, s6

	vmovq           A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[15]
        adc             rl, s7
        adc             rh, s8

	vmovq           A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[15]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	
        ##### q15 #####
        movq            q15, q                  
	
	##### M[8 10 12 14]*q15 #####
        vmovq           M0xmm, mi          	#M[8]
        mulx            q, rl, rh               #M[8]*q15
        add             rl, s3
        adc             rh, s4

        vmovq           M1xmm, mi          	#M[10]
        mulx            q, rl, rh               #M[10]*q15
        adc             rl, s5
        adc             rh, s6

        vmovq           M2xmm, mi          	#M[12]
        mulx            q, rl, rh               #M[12]*q15
        adc             rl, s7
        adc             rh, s8

        vmovq           M3xmm, mi          	#M[14]
        mulx            q, rl, rh               #M[14]*q15
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

	##### A[9 11 13 15]*B[15] #####
        vmovq           B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[15]
        add             rl, s4
        adc             rh, s5

        vmovq           B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[15]
        adc             rl, s6
        adc             rh, s7

        vmovq           B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[15]
        adc             rl, s8
        adc             rh, s9

        vmovq           B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[15]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

        ##### M[9 11 13 15]*q15 #####
        vmovq           T0xmm, mi          	#M[9]
        mulx            q, rl, rh               #M[9]*q15
        add             rl, s4
        adc             rh, s5

        vmovq           T1xmm, mi          	#M[11]
        mulx            q, rl, rh               #M[11]*q15
        adc             rl, s6
        adc             rh, s7

        vmovq           T2xmm, mi          	#M[13]
        mulx            q, rl, rh               #M[13]*q15
        adc             rl, s8
        adc             rh, s9

        vmovq           T3xmm, mi          	#M[15]
        mulx            q, rl, rh               #M[15]*q15
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

	movq		s3, r7			#result[7]


##################################################################################################

	### reverse M ###
	vshufpd		$0x05, M0, M0, M0		#imm=0101
	vshufpd		$0x05, M1, M1, M1		#imm=0101
	vshufpd		$0x05, M2, M2, M2		#imm=0101
	vshufpd		$0x05, M3, M3, M3		#imm=0101
	vshufpd		$0x05, T0, T0, T0		#imm=0101
	vshufpd		$0x05, T1, T1, T1		#imm=0101
	vshufpd		$0x05, T2, T2, T2		#imm=0101
	vshufpd		$0x05, T3, T3, T3		#imm=0101

/* 16 256bit vector registers */
#########################################################
	
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[8]	M[10]	M[12]	M[14]	#
	# 	M[0]	M[2]	M[4]	M[6]	#
	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[9]	M[11]	M[13]	M[15]	#
	# 	M[1]	M[3]	M[5]	M[7]	#
	#########################################

#########################################################


##################################################################################################
	###							###	
	### 	3rd part END 					###
	###							###
	###	low			high			###
	###							###
	###	s4 s5 s6 s7 s8 s9 s0 s1 s2			###
	###							###
##################################################################################################

.endm


.macro  montmul_last_movq

##################################################################################################
	###							###	
	### 	last part: reduce and store result		###
	###							###
	###	sum 102=8+94					###
	###							###
##################################################################################################
        ###                                                     ###
        ###     reduce		                		###
        ###     sum 94=4+62+28                                 	###
        ###                                                     ###
        ###########################################################


	xorq	rh, rh
	movq	s2, rh
	subq	$1, rh
	
	#jb	.montmul_last_end
	jb 	1f
	

#.montmul_last_sub_1$:

	### r0-r7 ###

	movq         	r0, rl			#R[0]          	
	vmovq           M0xmm, rh
	subq		rh, rl
	movq		rl, r0

	movq         	r1, rl			#R[1]          	
	vmovq           T0xmm, rh
	sbbq		rh, rl
	movq		rl, r1

	movq         	r2, rl			#R[2]          	
	vmovq           M1xmm, rh
	sbbq		rh, rl
	movq		rl, r2

	movq         	r3, rl			#R[3]          	
	vmovq           T1xmm, rh
	sbbq		rh, rl
	movq		rl, r3

	movq         	r4, rl			#R[4]          	
	vmovq           M2xmm, rh
	sbbq		rh, rl
	movq		rl, r4

	movq         	r5, rl			#R[5]          	
	vmovq           T2xmm, rh
	sbbq		rh, rl
	movq		rl, r5

	movq         	r6, rl			#R[6]          	
	vmovq           M3xmm, rh
	sbbq		rh, rl
	movq		rl, r6

	movq         	r7, rl			#R[7]          	
	vmovq           T3xmm, rh
	sbbq		rh, rl
	movq		rl, r7


	### r8-r15 ###

	vpextrq         $1, M0xmm, rh           #R[8] 
	sbbq		rh, r8

	vpextrq         $1, T0xmm, rh		#R[9] 
	sbbq		rh, r9
	
	vpextrq         $1, M1xmm, rh		#R[10] 
	sbbq		rh, r10

	vpextrq         $1, T1xmm, rh		#R[11] 
	sbbq		rh, r11

	vpextrq         $1, M2xmm, rh		#R[12] 
	sbbq		rh, r12

	vpextrq         $1, T2xmm, rh		#R[13] 
	sbbq		rh, r13
	
	vpextrq         $1, M3xmm, rh		#R[14] 
	sbbq		rh, r14

	vpextrq         $1, T3xmm, rh		#R[15] 
	sbbq		rh, r15

	sbbq		$0, s2


	xorq	rh, rh
	movq	s2, rh
	subq	$1, rh
	
	jb 	1f

	
#.montmul_last_sub_2:

	### r0-r7 ###

	movq         	r0, rl			#R[0]          	
	vmovq           M0xmm, rh
	subq		rh, rl
	movq		rl, r0

	movq         	r1, rl			#R[1]          	
	vmovq           T0xmm, rh
	sbbq		rh, rl
	movq		rl, r1

	movq         	r2, rl			#R[2]          	
	vmovq           M1xmm, rh
	sbbq		rh, rl
	movq		rl, r2

	movq         	r3, rl			#R[3]          	
	vmovq           T1xmm, rh
	sbbq		rh, rl
	movq		rl, r3

	movq         	r4, rl			#R[4]          	
	vmovq           M2xmm, rh
	sbbq		rh, rl
	movq		rl, r4

	movq         	r5, rl			#R[5]          	
	vmovq           T2xmm, rh
	sbbq		rh, rl
	movq		rl, r5

	movq         	r6, rl			#R[6]          	
	vmovq           M3xmm, rh
	sbbq		rh, rl
	movq		rl, r6

	movq         	r7, rl			#R[7]          	
	vmovq           T3xmm, rh
	sbbq		rh, rl
	movq		rl, r7


	### r8-r15 ###

	vpextrq         $1, M0xmm, rh           #R[8] 
	sbbq		rh, r8

	vpextrq         $1, T0xmm, rh		#R[9] 
	sbbq		rh, r9
	
	vpextrq         $1, M1xmm, rh		#R[10] 
	sbbq		rh, r10

	vpextrq         $1, T1xmm, rh		#R[11] 
	sbbq		rh, r11

	vpextrq         $1, M2xmm, rh		#R[12] 
	sbbq		rh, r12

	vpextrq         $1, T2xmm, rh		#R[13] 
	sbbq		rh, r13
	
	vpextrq         $1, M3xmm, rh		#R[14] 
	sbbq		rh, r14

	vpextrq         $1, T3xmm, rh		#R[15] 
	sbbq		rh, r15

	sbbq		$0, s2


#.montmul_last_end$:
1:	
        vpxorq  %zmm18, %zmm18, %zmm18
        vpxorq  %zmm19, %zmm19, %zmm19
        vpxorq  %zmm20, %zmm20, %zmm20

        movq    r0,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        movq    r1,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        movq    r2,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        movq    r3,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        movq    r4,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        movq    r5,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        movq    r6,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        movq    r7,     rl
        vmovq   rl,     %xmm20
        valignq  $1,   %zmm19,   %zmm20, %zmm19

        vmovq   r8,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   r9,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   r10,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   r11,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   r12,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   r13,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   r14,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   r15,     %xmm20
        valignq  $1,   %zmm18,   %zmm20, %zmm18


        ### r0-r7 ###

	movq         	r0, rl			#R[0]          	
	vmovq           M0xmm, rh
	subq		rh, rl
	movq		rl, r0

	movq         	r1, rl			#R[1]          	
	vmovq           T0xmm, rh
	sbbq		rh, rl
	movq		rl, r1

	movq         	r2, rl			#R[2]          	
	vmovq           M1xmm, rh
	sbbq		rh, rl
	movq		rl, r2

	movq         	r3, rl			#R[3]          	
	vmovq           T1xmm, rh
	sbbq		rh, rl
	movq		rl, r3

	movq         	r4, rl			#R[4]          	
	vmovq           M2xmm, rh
	sbbq		rh, rl
	movq		rl, r4

	movq         	r5, rl			#R[5]          	
	vmovq           T2xmm, rh
	sbbq		rh, rl
	movq		rl, r5

	movq         	r6, rl			#R[6]          	
	vmovq           M3xmm, rh
	sbbq		rh, rl
	movq		rl, r6

	movq         	r7, rl			#R[7]          	
	vmovq           T3xmm, rh
	sbbq		rh, rl
	movq		rl, r7


	### r8-r15 ###

	vpextrq         $1, M0xmm, rh           #R[8] 
	sbbq		rh, r8

	vpextrq         $1, T0xmm, rh		#R[9] 
	sbbq		rh, r9
	
	vpextrq         $1, M1xmm, rh		#R[10] 
	sbbq		rh, r10

	vpextrq         $1, T1xmm, rh		#R[11] 
	sbbq		rh, r11

	vpextrq         $1, M2xmm, rh		#R[12] 
	sbbq		rh, r12

	vpextrq         $1, T2xmm, rh		#R[13] 
	sbbq		rh, r13
	
	vpextrq         $1, M3xmm, rh		#R[14] 
	sbbq		rh, r14

	vpextrq         $1, T3xmm, rh		#R[15] 
	sbbq		rh, r15

        jb     3f      

        vperm2i128	$1, T3, T3, T3	        #imm=01
        vblendpd	$0x3, T2, T3, T2	#imm=0011
        vpxor           T3, T3, T3

        vpxor           A0, A0, A0
	vmovq		r8, T3xmm		#R[8]
	vblendpd	$0x1, T3, A0, A0	#imm=0001

	vperm2i128	$0x1, A0, A0, A0	#imm=1	
	movq		r0, rl	        	#R[0]
        vmovq		rl, T3xmm		#R[0]
	vblendpd	$0x1, T3, A0, A0	#imm=0001


        vpxor           B0, B0, B0
	vmovq		r9, T3xmm		#R[9]
	vblendpd	$0x1, T3, B0, B0	#imm=0001

	vperm2i128	$0x1, B0, B0, B0	#imm=1
        movq		r1, rl		        #R[1]
	vmovq		rl, T3xmm		#R[1]
	vblendpd	$0x1, T3, B0, B0	#imm=0001


        vpxor           A1, A1, A1
	vmovq		r10, T3xmm		#R[10]
	vblendpd	$0x1, T3, A1, A1	#imm=0001

	vperm2i128	$0x1, A1, A1, A1	#imm=1
	movq		r2, rl		        #R[2]
        vmovq		rl, T3xmm		#R[2]
	vblendpd	$0x1, T3, A1, A1	#imm=0001	

	
        vpxor           B1, B1, B1
	vmovq		r11, T3xmm		#R[11]
	vblendpd	$0x1, T3, B1, B1	#imm=0001

	vperm2i128	$0x1, B1, B1, B1	#imm=1
	movq		r3, rl		        #R[3]
        vmovq		rl, T3xmm		#R[3]
	vblendpd	$0x1, T3, B1, B1	#imm=0001


        vpxor           A2, A2, A2
	vmovq		r12, T3xmm		#R[12]
	vblendpd	$0x1, T3, A2, A2	#imm=0001

	vperm2i128	$0x1, A2, A2, A2	#imm=1
	movq		r4, rl		        #R[4]
        vmovq		rl, T3xmm		#R[4]
	vblendpd	$0x1, T3, A2, A2	#imm=0001


        vpxor           B2, B2, B2
	vmovq		r13, T3xmm		#R[13]
	vblendpd	$0x1, T3, B2, B2	#imm=0001

	vperm2i128	$0x1, B2, B2, B2	#imm=1
	movq		r5, rl		        #R[5]
        vmovq		rl, T3xmm		#R[5]
	vblendpd	$0x1, T3, B2, B2	#imm=0001


        vpxor           A3, A3, A3
	vmovq		r14, T3xmm		#R[14]
	vblendpd	$0x1, T3, A3, A3	#imm=0001

	vperm2i128	$0x1, A3, A3, A3	#imm=1
	movq		r6, rl		        #R[6]
        vmovq           rl, T3xmm		#R[6]
	vblendpd	$0x1, T3, A3, A3	#imm=0001


        vpxor           B3, B3, B3
	vmovq		r15, T3xmm		#R[15]
	vblendpd	$0x1, T3, B3, B3	#imm=0001

	vperm2i128	$0x1, B3, B3, B3	#imm=1
        movq		r7, rl		        #R[7]
	vmovq		rl, T3xmm		#R[7]	
	vblendpd	$0x1, T3, B3, B3	#imm=0001


        vpxor           T3, T3, T3
        vblendpd	$0x3, T3, T2, T3	#imm=0011
        vperm2i128	$1, T3, T3, T3	        #imm=01
        vblendpd	$0x3, T2, T3, T2	#imm=0011

        jmp     4f


 3:
        vpxorq  %zmm20, %zmm20, %zmm20
        vmovq   %xmm19, rl
        movq    rl,     r0
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        vmovq   %xmm19, rl
        movq    rl,     r1
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        vmovq   %xmm19, rl
        movq    rl,     r2
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        vmovq   %xmm19, rl
        movq    rl,     r3
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        vmovq   %xmm19, rl
        movq    rl,     r4
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        vmovq   %xmm19, rl
        movq    rl,     r5
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        vmovq   %xmm19, rl
        movq    rl,     r6
        valignq  $1,   %zmm19,   %zmm20, %zmm19
        vmovq   %xmm19, rl
        movq    rl,     r7
        valignq  $1,   %zmm19,   %zmm20, %zmm19

        vpxorq  %zmm20, %zmm20, %zmm20
        vmovq   %xmm18, r8
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   %xmm18, r9
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   %xmm18, r10
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   %xmm18, r11
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   %xmm18, r12
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   %xmm18, r13
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   %xmm18, r14
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        vmovq   %xmm18, r15
        valignq  $1,   %zmm18,   %zmm20, %zmm18
        
        vperm2i128	$1, T3, T3, T3	        #imm=01
        vblendpd	$0x3, T2, T3, T2	#imm=0011
        vpxor           T3, T3, T3

        vpxor           A0, A0, A0
	vmovq		r8, T3xmm		#R[8]
	vblendpd	$0x1, T3, A0, A0	#imm=0001

	vperm2i128	$0x1, A0, A0, A0	#imm=1	
	movq		r0, rl	        	#R[0]
        vmovq		rl, T3xmm		#R[0]
	vblendpd	$0x1, T3, A0, A0	#imm=0001


        vpxor           B0, B0, B0
	vmovq		r9, T3xmm		#R[9]
	vblendpd	$0x1, T3, B0, B0	#imm=0001

	vperm2i128	$0x1, B0, B0, B0	#imm=1
        movq		r1, rl		        #R[1]
	vmovq		rl, T3xmm		#R[1]
	vblendpd	$0x1, T3, B0, B0	#imm=0001


        vpxor           A1, A1, A1
	vmovq		r10, T3xmm		#R[10]
	vblendpd	$0x1, T3, A1, A1	#imm=0001

	vperm2i128	$0x1, A1, A1, A1	#imm=1
	movq		r2, rl		        #R[2]
        vmovq		rl, T3xmm		#R[2]
	vblendpd	$0x1, T3, A1, A1	#imm=0001	

	
        vpxor           B1, B1, B1
	vmovq		r11, T3xmm		#R[11]
	vblendpd	$0x1, T3, B1, B1	#imm=0001

	vperm2i128	$0x1, B1, B1, B1	#imm=1
	movq		r3, rl		        #R[3]
        vmovq		rl, T3xmm		#R[3]
	vblendpd	$0x1, T3, B1, B1	#imm=0001


        vpxor           A2, A2, A2
	vmovq		r12, T3xmm		#R[12]
	vblendpd	$0x1, T3, A2, A2	#imm=0001

	vperm2i128	$0x1, A2, A2, A2	#imm=1
	movq		r4, rl		        #R[4]
        vmovq		rl, T3xmm		#R[4]
	vblendpd	$0x1, T3, A2, A2	#imm=0001


        vpxor           B2, B2, B2
	vmovq		r13, T3xmm		#R[13]
	vblendpd	$0x1, T3, B2, B2	#imm=0001

	vperm2i128	$0x1, B2, B2, B2	#imm=1
	movq		r5, rl		        #R[5]
        vmovq		rl, T3xmm		#R[5]
	vblendpd	$0x1, T3, B2, B2	#imm=0001


        vpxor           A3, A3, A3
	vmovq		r14, T3xmm		#R[14]
	vblendpd	$0x1, T3, A3, A3	#imm=0001

	vperm2i128	$0x1, A3, A3, A3	#imm=1
	movq		r6, rl		        #R[6]
        vmovq           rl, T3xmm		#R[6]
	vblendpd	$0x1, T3, A3, A3	#imm=0001


        vpxor           B3, B3, B3
	vmovq		r15, T3xmm		#R[15]
	vblendpd	$0x1, T3, B3, B3	#imm=0001

	vperm2i128	$0x1, B3, B3, B3	#imm=1
        movq		r7, rl		        #R[7]
	vmovq		rl, T3xmm		#R[7]	
	vblendpd	$0x1, T3, B3, B3	#imm=0001


        vpxor           T3, T3, T3
        vblendpd	$0x3, T3, T2, T3	#imm=0011
        vperm2i128	$1, T3, T3, T3	        #imm=01
        vblendpd	$0x3, T2, T3, T2	#imm=0011       

4:

/* 16 256bit vector registers */
#########################################################
	
	#########################################
	#	A0 	A1	A2	A3 	#		
	#					#
	# 	x	x	x	x	#	
	# 	R[8]	R[10]	R[12]	R[14]	#
	# 	x	x	x	x	#
	# 	R[0]	R[2]	R[4]	R[6]	#				
	#########################################
	#	B0 	B1	B2	B3 	#		
	#					#
	# 	x	x	x	x	#	
	# 	R[9]	R[11]	R[13]	R[15]	#
	# 	x	x	x	x	#
	# 	R[1]	R[3]	R[5]	R[7]	#
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[8]	M[10]	M[12]	M[14]	#
	# 	M[0]	M[2]	M[4]	M[6]	#
	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	#       x	x	x	x	#
	#       x	x	x	x	#	
	# 	M[9]	M[11]	M[13]	M[15]	#
	# 	M[1]	M[3]	M[5]	M[7]	#
	#########################################

#########################################################

##################################################################################################
	###							###	
	### 	last part END 					###
	###							###
	###	result A0 A1 A2 A3 B0 B1 B2 B3			###
	###							###
##################################################################################################

.endm


.globl 	Comcq
.type  	Comcq, @function
.align 	64

Comcq:

    subq		$512, %rsp

    movq		%rbx, (%rsp)
	movq		%rbp, 8(%rsp)
	movq		%r12, 16(%rsp)
	movq		%r13, 24(%rsp)
	movq		%r14, 32(%rsp)
	movq		%r15, 40(%rsp)
    movq		%rdi, 48(%rsp)
	movq		%rsi, 64(%rsp)

    ##q(0-127) c2(127-255)  r3r(256-383)  c1(384-511)  r2r(512-639)  q0(640)##
/*
    vmovdqu		(%rsi), A0xmm		#M[0] M[1]
	vmovdqu		16(%rsi), A1xmm		#M[2] M[3]
	vmovdqu		32(%rsi), A2xmm		#M[4] M[5]
	vmovdqu		48(%rsi), A3xmm		#M[6] M[7]
	vmovdqu		64(%rsi), B0xmm		#M[8] M[9]
	vmovdqu		80(%rsi), B1xmm		#M[10] M[11]
	vmovdqu		96(%rsi), B2xmm		#M[12] M[13]
	vmovdqu		112(%rsi), B3xmm	#M[14] M[15]
*/
    movq    640(%rsi), %rax
    movq	%rax, n0

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

    ### rerange q to M ###

	vperm2i128	$0x20, B0, A0, M0
	vperm2i128	$0x20, B1, A1, M1
	vperm2i128	$0x20, B2, A2, M2
	vperm2i128	$0x20, B3, A3, M3

	vpermq		$0xD8, M0, M0		#imm=3120
	vpermq		$0xD8, M1, M1		#imm=3120
	vpermq		$0xD8, M2, M2		#imm=3120
	vpermq		$0xD8, M3, M3		#imm=3120

### load r3r ###

    movq		64(%rsp), %rsi
    addq		$256, %rsi
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3
    subq		$256, %rsi

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

    store_A

 ### load c2 ###   

    movq		64(%rsp), %rsi
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

    vmovdqu64   A0, %ymm18
    vmovdqu64   A1, %ymm19
    vmovdqu64   A2, %ymm20
    vmovdqu64   A3, %ymm21
    vmovdqu64   B0, %ymm22
    vmovdqu64   B1, %ymm23
    vmovdqu64   B2, %ymm24
    vmovdqu64   B3, %ymm25

    #### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

    ## c2 mod q ##

    vmovq   A0xmm,  rl           #R[0]
    vmovq           M0xmm, rh
	subq		rh, rl
	movq		rl, r0

    vpextrq         $1, A0xmm, rl          #R[1]
    vmovq           T0xmm, rh
	sbbq		rh, rl
	movq		rl, r1

    vmovq   A1xmm,  rl           #R[2]
    vmovq           M1xmm, rh
	sbbq		rh, rl
	movq		rl, r2

    vpextrq         $1, A1xmm, rl          #R[3]
    vmovq           T1xmm, rh
	sbbq		rh, rl
	movq		rl, r3

    vmovq   A2xmm,  rl           #R[4]
    vmovq           M2xmm, rh
	sbbq		rh, rl
	movq		rl, r4

    vpextrq         $1, A2xmm, rl          #R[5]
    vmovq           T2xmm, rh
	sbbq		rh, rl
	movq		rl, r5

    vmovq   A3xmm,  rl           #R[6]
    vmovq           M3xmm, rh
	sbbq		rh, rl
	movq		rl, r6

    vpextrq         $1, A3xmm, rl          #R[7]
    vmovq           T3xmm, rh
	sbbq		rh, rl
	movq		rl, r7

    vmovq   B0xmm,  rl           #R[8]
    vpextrq         $1, M0xmm, rh
	sbbq		rh, rl
	movq		rl, r8

    vpextrq         $1, B0xmm, rl          #R[9]
    vpextrq         $1, T0xmm, rh
	sbbq		rh, rl
	movq		rl, r9

    vmovq   B1xmm,  rl           #R[10]
    vpextrq         $1, M1xmm, rh
	sbbq		rh, rl
	movq		rl, r10

    vpextrq         $1, B1xmm, rl          #R[11]
    vpextrq         $1, T1xmm, rh
	sbbq		rh, rl
	movq		rl, r11

    vmovq   B2xmm,  rl           #R[12]
    vpextrq         $1, M2xmm, rh
	sbbq		rh, rl
	movq		rl, r12

    vpextrq         $1, B2xmm, rl          #R[13]
    vpextrq         $1, T2xmm, rh
	sbbq		rh, rl
	movq		rl, r13

    vmovq   B3xmm,  rl           #R[14]
    vpextrq         $1, M3xmm, rh
	sbbq		rh, rl
	movq		rl, r14

    vpextrq         $1, B3xmm, rl          #R[15]
    vpextrq         $1, T3xmm, rh
	sbbq		rh, rl
    movq		rl, r15
	
    jb      8f

    vpxor           T3, T3, T3

    vpxor           A0, A0, A0
	vmovq		r8, T3xmm		#R[8]
	vblendpd	$0x1, T3, A0, A0	#imm=0001

	vperm2i128	$0x1, A0, A0, A0	#imm=1	
	movq		r0, rl	        	#R[0]
    vmovq		rl, T3xmm		#R[0]
	vblendpd	$0x1, T3, A0, A0	#imm=0001


    vpxor           B0, B0, B0
	vmovq		r9, T3xmm		#R[9]
	vblendpd	$0x1, T3, B0, B0	#imm=0001

	vperm2i128	$0x1, B0, B0, B0	#imm=1
    movq		r1, rl		        #R[1]
	vmovq		rl, T3xmm		#R[1]
	vblendpd	$0x1, T3, B0, B0	#imm=0001


    vpxor           A1, A1, A1
	vmovq		r10, T3xmm		#R[10]
	vblendpd	$0x1, T3, A1, A1	#imm=0001

	vperm2i128	$0x1, A1, A1, A1	#imm=1
	movq		r2, rl		        #R[2]
    vmovq		rl, T3xmm		#R[2]
	vblendpd	$0x1, T3, A1, A1	#imm=0001	

	
    vpxor           B1, B1, B1
	vmovq		r11, T3xmm		#R[11]
	vblendpd	$0x1, T3, B1, B1	#imm=0001

	vperm2i128	$0x1, B1, B1, B1	#imm=1
	movq		r3, rl		        #R[3]
    vmovq		rl, T3xmm		#R[3]
	vblendpd	$0x1, T3, B1, B1	#imm=0001


    vpxor           A2, A2, A2
	vmovq		r12, T3xmm		#R[12]
	vblendpd	$0x1, T3, A2, A2	#imm=0001

	vperm2i128	$0x1, A2, A2, A2	#imm=1
	movq		r4, rl		        #R[4]
    vmovq		rl, T3xmm		#R[4]
	vblendpd	$0x1, T3, A2, A2	#imm=0001


    vpxor           B2, B2, B2
	vmovq		r13, T3xmm		#R[13]
	vblendpd	$0x1, T3, B2, B2	#imm=0001

	vperm2i128	$0x1, B2, B2, B2	#imm=1
	movq		r5, rl		        #R[5]
    vmovq		rl, T3xmm		#R[5]
	vblendpd	$0x1, T3, B2, B2	#imm=0001


    vpxor           A3, A3, A3
	vmovq		r14, T3xmm		#R[14]
	vblendpd	$0x1, T3, A3, A3	#imm=0001

	vperm2i128	$0x1, A3, A3, A3	#imm=1
	movq		r6, rl		        #R[6]
    vmovq           rl, T3xmm		#R[6]
	vblendpd	$0x1, T3, A3, A3	#imm=0001


    vpxor           B3, B3, B3
	vmovq		r15, T3xmm		#R[15]
	vblendpd	$0x1, T3, B3, B3	#imm=0001

	vperm2i128	$0x1, B3, B3, B3	#imm=1
    movq		r7, rl		        #R[7]
	vmovq		rl, T3xmm		#R[7]	
	vblendpd	$0x1, T3, B3, B3	#imm=0001


    vpxor           T3, T3, T3

    jmp 9f


8:

    vmovdqu64   %ymm18, A0
    vmovdqu64   %ymm19, A1
    vmovdqu64   %ymm20, A2
    vmovdqu64   %ymm21, A3
    vmovdqu64   %ymm22, B0
    vmovdqu64   %ymm23, B1
    vmovdqu64   %ymm24, B2
    vmovdqu64   %ymm25, B3

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

    vpxor           T3, T3, T3


9:

    #### restore B ####
	restore_B

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


    ##call montmul1024
    montmul_1st_movq	
	montmul_2nd_movq
	montmul_3rd_movq
	montmul_last_movq


        movq    48(%rsp),   %rdi
        vmovdqu64 	A0, (%rdi)
	vmovdqu64 	B0, 32(%rdi)
	vmovdqu64 	A1, 64(%rdi)
	vmovdqu64 	B1, 96(%rdi)
	vmovdqu64 	A2, 128(%rdi)
	vmovdqu64 	B2, 160(%rdi)
	vmovdqu64 	A3, 192(%rdi)
	vmovdqu64 	B3, 224(%rdi)


        ### load r2r ###

    movq		64(%rsp), %rsi
    addq		$512, %rsi
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3
    subq		$512, %rsi

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

    store_A

        ### load c1 ###   
    movq		64(%rsp), %rsi
    addq		$384, %rsi
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3
	subq		$384, %rsi

    vmovdqu64   A0, %ymm18
    vmovdqu64   A1, %ymm19
    vmovdqu64   A2, %ymm20
    vmovdqu64   A3, %ymm21
    vmovdqu64   B0, %ymm22
    vmovdqu64   B1, %ymm23
    vmovdqu64   B2, %ymm24
    vmovdqu64   B3, %ymm25

    #### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

    ## c1 mod q ##

    vmovq   A0xmm,  rl           #R[0]
    vmovq           M0xmm, rh
	subq		rh, rl
	movq		rl, r0

    vpextrq         $1, A0xmm, rl          #R[1]
    vmovq           T0xmm, rh
	sbbq		rh, rl
	movq		rl, r1

    vmovq   A1xmm,  rl           #R[2]
    vmovq           M1xmm, rh
	sbbq		rh, rl
	movq		rl, r2

    vpextrq         $1, A1xmm, rl          #R[3]
    vmovq           T1xmm, rh
	sbbq		rh, rl
	movq		rl, r3

    vmovq   A2xmm,  rl           #R[4]
    vmovq           M2xmm, rh
	sbbq		rh, rl
	movq		rl, r4

    vpextrq         $1, A2xmm, rl          #R[5]
    vmovq           T2xmm, rh
	sbbq		rh, rl
	movq		rl, r5

    vmovq   A3xmm,  rl           #R[6]
    vmovq           M3xmm, rh
	sbbq		rh, rl
	movq		rl, r6

    vpextrq         $1, A3xmm, rl          #R[7]
    vmovq           T3xmm, rh
	sbbq		rh, rl
	movq		rl, r7

    vmovq   B0xmm,  rl           #R[8]
    vpextrq         $1, M0xmm, rh
	sbbq		rh, rl
	movq		rl, r8

    vpextrq         $1, B0xmm, rl          #R[9]
    vpextrq         $1, T0xmm, rh
	sbbq		rh, rl
	movq		rl, r9

    vmovq   B1xmm,  rl           #R[10]
    vpextrq         $1, M1xmm, rh
	sbbq		rh, rl
	movq		rl, r10

    vpextrq         $1, B1xmm, rl          #R[11]
    vpextrq         $1, T1xmm, rh
	sbbq		rh, rl
	movq		rl, r11

    vmovq   B2xmm,  rl           #R[12]
    vpextrq         $1, M2xmm, rh
	sbbq		rh, rl
	movq		rl, r12

    vpextrq         $1, B2xmm, rl          #R[13]
    vpextrq         $1, T2xmm, rh
	sbbq		rh, rl
	movq		rl, r13

    vmovq   B3xmm,  rl           #R[14]
    vpextrq         $1, M3xmm, rh
	sbbq		rh, rl
	movq		rl, r14

    vpextrq         $1, B3xmm, rl          #R[15]
    vpextrq         $1, T3xmm, rh
	sbbq		rh, rl
    movq		rl, r15
	
    jb      6f

    vpxor           T3, T3, T3

    vpxor           A0, A0, A0
	vmovq		r8, T3xmm		#R[8]
	vblendpd	$0x1, T3, A0, A0	#imm=0001

	vperm2i128	$0x1, A0, A0, A0	#imm=1	
	movq		r0, rl	        	#R[0]
    vmovq		rl, T3xmm		#R[0]
	vblendpd	$0x1, T3, A0, A0	#imm=0001


    vpxor           B0, B0, B0
	vmovq		r9, T3xmm		#R[9]
	vblendpd	$0x1, T3, B0, B0	#imm=0001

	vperm2i128	$0x1, B0, B0, B0	#imm=1
    movq		r1, rl		        #R[1]
	vmovq		rl, T3xmm		#R[1]
	vblendpd	$0x1, T3, B0, B0	#imm=0001


    vpxor           A1, A1, A1
	vmovq		r10, T3xmm		#R[10]
	vblendpd	$0x1, T3, A1, A1	#imm=0001

	vperm2i128	$0x1, A1, A1, A1	#imm=1
	movq		r2, rl		        #R[2]
    vmovq		rl, T3xmm		#R[2]
	vblendpd	$0x1, T3, A1, A1	#imm=0001	

	
    vpxor           B1, B1, B1
	vmovq		r11, T3xmm		#R[11]
	vblendpd	$0x1, T3, B1, B1	#imm=0001

	vperm2i128	$0x1, B1, B1, B1	#imm=1
	movq		r3, rl		        #R[3]
    vmovq		rl, T3xmm		#R[3]
	vblendpd	$0x1, T3, B1, B1	#imm=0001


    vpxor           A2, A2, A2
	vmovq		r12, T3xmm		#R[12]
	vblendpd	$0x1, T3, A2, A2	#imm=0001

	vperm2i128	$0x1, A2, A2, A2	#imm=1
	movq		r4, rl		        #R[4]
    vmovq		rl, T3xmm		#R[4]
	vblendpd	$0x1, T3, A2, A2	#imm=0001


    vpxor           B2, B2, B2
	vmovq		r13, T3xmm		#R[13]
	vblendpd	$0x1, T3, B2, B2	#imm=0001

	vperm2i128	$0x1, B2, B2, B2	#imm=1
	movq		r5, rl		        #R[5]
    vmovq		rl, T3xmm		#R[5]
	vblendpd	$0x1, T3, B2, B2	#imm=0001


    vpxor           A3, A3, A3
	vmovq		r14, T3xmm		#R[14]
	vblendpd	$0x1, T3, A3, A3	#imm=0001

	vperm2i128	$0x1, A3, A3, A3	#imm=1
	movq		r6, rl		        #R[6]
    vmovq           rl, T3xmm		#R[6]
	vblendpd	$0x1, T3, A3, A3	#imm=0001


    vpxor           B3, B3, B3
	vmovq		r15, T3xmm		#R[15]
	vblendpd	$0x1, T3, B3, B3	#imm=0001

	vperm2i128	$0x1, B3, B3, B3	#imm=1
    movq		r7, rl		        #R[7]
	vmovq		rl, T3xmm		#R[7]	
	vblendpd	$0x1, T3, B3, B3	#imm=0001


    vpxor           T3, T3, T3

    jmp 7f


6:

    vmovdqu64   %ymm18, A0
    vmovdqu64   %ymm19, A1
    vmovdqu64   %ymm20, A2
    vmovdqu64   %ymm21, A3
    vmovdqu64   %ymm22, B0
    vmovdqu64   %ymm23, B1
    vmovdqu64   %ymm24, B2
    vmovdqu64   %ymm25, B3

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

    vpxor           T3, T3, T3


7:

    #### restore B ####
	restore_B

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


    ##call montmul1024
    montmul_1st_movq	
	montmul_2nd_movq
	montmul_3rd_movq
	montmul_last_movq

        store_A

        movq    48(%rsp),   %rdi
        vmovdqu64 	(%rdi), A0
        vmovdqu64 	32(%rdi), B0
        vmovdqu64 	64(%rdi), A1
        vmovdqu64 	96(%rdi), B1
        vmovdqu64 	128(%rdi), A2
        vmovdqu64 	160(%rdi), B2
        vmovdqu64 	192(%rdi), A3
        vmovdqu64 	224(%rdi), B3

        restore_B

        ### add & mod q ###

        xorq		bi, bi

        vpextrq         $0, A0xmm, rh
	vpextrq         $1, A0xmm, rl
	addq		rl, rh
	movq		rh, r0			#R[0]

	vpextrq         $0, B0xmm, rh
	vpextrq         $1, B0xmm, rl
	adcq		rl, rh
	movq		rh, r1			#R[1]

	vpextrq         $0, A1xmm, rh
	vpextrq         $1, A1xmm, rl
	adcq		rl, rh
	movq		rh, r2			#R[2]	

	vpextrq         $0, B1xmm, rh
	vpextrq         $1, B1xmm, rl
	adcq		rl, rh
	movq		rh, r3			#R[3]	

	vpextrq         $0, A2xmm, rh
	vpextrq         $1, A2xmm, rl
	adcq		rl, rh
	movq		rh, r4			#R[4]	

	vpextrq         $0, B2xmm, rh
	vpextrq         $1, B2xmm, rl
	adcq		rl, rh
	movq		rh, r5       		#R[5]	

	vpextrq         $0, A3xmm, rh
	vpextrq         $1, A3xmm, rl
	adcq		rl, rh
	movq		rh, r6			#R[6]	

	vpextrq         $0, B3xmm, rh
	vpextrq         $1, B3xmm, rl
	adcq		rl, rh
	movq		rh, r7       		#R[7]	
	
	
	vperm2i128	$0x1, A0, A0, A0			
	vperm2i128	$0x1, A1, A1, A1		
	vperm2i128	$0x1, A2, A2, A2			 
	vperm2i128	$0x1, A3, A3, A3

	vperm2i128	$0x1, B0, B0, B0			
	vperm2i128	$0x1, B1, B1, B1		
	vperm2i128	$0x1, B2, B2, B2			 
	vperm2i128	$0x1, B3, B3, B3


	vpextrq         $0, A0xmm, rh
	vpextrq         $1, A0xmm, rl
	adcq		rl, rh
	movq		rh, r8			#R[8]

	vpextrq         $0, B0xmm, rh
	vpextrq         $1, B0xmm, rl
	adcq		rl, rh
	movq		rh, r9			#R[9]

	vpextrq         $0, A1xmm, rh
	vpextrq         $1, A1xmm, rl
	adcq		rl, rh
	movq		rh, r10			#R[10]	

	vpextrq         $0, B1xmm, rh
	vpextrq         $1, B1xmm, rl
	adcq		rl, rh
	movq		rh, r11			#R[11]	

	vpextrq         $0, A2xmm, rh
	vpextrq         $1, A2xmm, rl
	adcq		rl, rh
	movq		rh, r12			#R[12]	

	vpextrq         $0, B2xmm, rh
	vpextrq         $1, B2xmm, rl
	adcq		rl, rh
	movq		rh, r13       		#R[13]	

	vpextrq         $0, A3xmm, rh
	vpextrq         $1, A3xmm, rl
	adcq		rl, rh
	movq		rh, r14			#R[14]	

	vpextrq         $0, B3xmm, rh
	vpextrq         $1, B3xmm, rl
	adcq		rl, rh
	movq		rh, r15       		#R[15]	

        adcq		$0, bi

        movq    r12,    %rbx

        movq    48(%rsp),   %rdi
        movq		r0, rl
        movq		rl, (%rdi)
        movq		r1, rl
        movq		rl, 8(%rdi)
        movq		r2, rl
        movq		rl, 16(%rdi)
        movq		r3, rl
        movq		rl, 24(%rdi)
        movq		r4, rl
        movq		rl, 32(%rdi)
        movq		r5, rl
        movq		rl, 40(%rdi)
        movq		r6, rl
        movq		rl, 48(%rdi)
        movq		r7, rl
        movq		rl, 56(%rdi)

        movq		r8, 64(%rdi)
        movq		r9, 72(%rdi)
        movq		r10, 80(%rdi)
        movq		r11, 88(%rdi)
        movq		%rbx, 96(%rdi)
        movq		r13, 104(%rdi)
        movq		r14, 112(%rdi)
        movq		r15, 120(%rdi)

        #### mod q ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

        movq		%rbx, r12

        vpextrq         $0, M0xmm, rl
	movq		r0, rh
	subq		rl, rh
	movq		rh, r0

	vpextrq         $0, T0xmm, rl
	movq		r1, rh
	sbbq		rl, rh
	movq		rh, r1

	vpextrq         $0, M1xmm, rl
	movq		r2, rh
	sbbq		rl, rh
	movq		rh, r2

	vpextrq         $0, T1xmm, rl
	movq		r3, rh
	sbbq		rl, rh
	movq		rh, r3

	vpextrq         $0, M2xmm, rl
	movq		r4, rh
	sbbq		rl, rh
	movq		rh, r4

	vpextrq         $0, T2xmm, rl
	movq		r5, rh
	sbbq		rl, rh
	movq		rh, r5

	vpextrq         $0, M3xmm, rl
	movq		r6, rh
	sbbq		rl, rh
	movq		rh, r6

	vpextrq         $0, T3xmm, rl
	movq		r7, rh
	sbbq		rl, rh
	movq		rh, r7


	vpextrq         $1, M0xmm, rl
	sbbq		rl, r8

	vpextrq         $1, T0xmm, rl
	sbbq		rl, r9

	vpextrq         $1, M1xmm, rl
	sbbq		rl, r10

	vpextrq         $1, T1xmm, rl
	sbbq		rl, r11

	vpextrq         $1, M2xmm, rl
	sbbq		rl, r12

	vpextrq         $1, T2xmm, rl
	sbbq		rl, r13

	vpextrq         $1, M3xmm, rl
	sbbq		rl, r14

	vpextrq         $1, T3xmm, rl
	sbbq		rl, r15

        sbbq		$0, bi

        jb      5f

        movq    r12,    %rbx
        movq    48(%rsp),   %rdi
        movq		r0, rl
        movq		rl, (%rdi)
        movq		r1, rl
        movq		rl, 8(%rdi)
        movq		r2, rl
        movq		rl, 16(%rdi)
        movq		r3, rl
        movq		rl, 24(%rdi)
        movq		r4, rl
        movq		rl, 32(%rdi)
        movq		r5, rl
        movq		rl, 40(%rdi)
        movq		r6, rl
        movq		rl, 48(%rdi)
        movq		r7, rl
        movq		rl, 56(%rdi)

        movq		r8, 64(%rdi)
        movq		r9, 72(%rdi)
        movq		r10, 80(%rdi)
        movq		r11, 88(%rdi)
        movq		%rbx, 96(%rdi)
        movq		r13, 104(%rdi)
        movq		r14, 112(%rdi)
        movq		r15, 120(%rdi)

        jmp     2f

5:

2:    
    movq		(%rsp), %rbx
	movq		8(%rsp), %rbp
	movq		16(%rsp), %r12
	movq		24(%rsp), %r13
	movq		32(%rsp), %r14
	movq		40(%rsp), %r15
    movq    48(%rsp),   %rdi
    movq    64(%rsp),   %rsi

    addq		$512, %rsp

/*
        vmovdqu64 	A0, (%rdi)
	vmovdqu64 	B0, 32(%rdi)
	vmovdqu64 	A1, 64(%rdi)
	vmovdqu64 	B1, 96(%rdi)
	vmovdqu64 	A2, 128(%rdi)
	vmovdqu64 	B2, 160(%rdi)
	vmovdqu64 	A3, 192(%rdi)
	vmovdqu64 	B3, 224(%rdi)
 */ 


ret
.size	Comcq, .-Comcq

