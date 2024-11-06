	#include "montmul.S"
	#include "montsqu.S"

	#include "aes.S"

	//#include "montmul_raw.S"
	//#include "montsqu_raw.S"	
	

	.file	"montexp.S"
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





.macro	enc_table_6bit	


##################################################################################################
	###							###	
	### 	enc_table_6bit					###
	###							###
	###	sum 						###
	###							###
##################################################################################################


	##################################################################
	#### store B ####
	# store_B



	##################################################################
	#### prepare result for enc ####
/*
	vperm2i128	$0x01, A0, A0, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, A0, A0		#imm=0110

	vperm2i128	$0x01, A1, A1, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, A1, A1		#imm=0110

	vperm2i128	$0x01, A2, A2, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, A2, A2		#imm=0110

	vperm2i128	$0x01, A3, A3, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, A3, A3		#imm=0110

	vperm2i128	$0x01, B0, B0, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, B0, B0		#imm=0110

	vperm2i128	$0x01, B1, B1, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, B1, B1		#imm=0110

	vperm2i128	$0x01, B2, B2, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, B2, B2		#imm=0110

	vperm2i128	$0x01, B3, B3, T3
	vshufpd		$0x05, T3, T3, T3		#imm=0101
	vblendpd	$0x06, T3, B3, B3		#imm=0110
*/	

/*	##################################################################
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
	##################################################################
	#### store the result

	vpermq		$0x08, A0, A0			#imm=0020
	vpermq		$0x08, A1, A1			#imm=0020
	vpermq		$0x08, A2, A2			#imm=0020
	vpermq		$0x08, A3, A3			#imm=0020
	vpermq		$0x08, B0, B0			#imm=0020
	vpermq		$0x08, B1, B1			#imm=0020
	vpermq		$0x08, B2, B2			#imm=0020
	vpermq		$0x08, B3, B3			#imm=0020


	vmovdqu			A0xmm, (%rsp)
	vmovdqu			A1xmm, 16(%rsp)	
	vmovdqu			A2xmm, 32(%rsp)
	vmovdqu			A3xmm, 48(%rsp)
	vmovdqu			B0xmm, 64(%rsp)
	vmovdqu			B1xmm, 80(%rsp)
	vmovdqu			B2xmm, 96(%rsp)
	vmovdqu			B3xmm, 112(%rsp)


	addq	$128, %rsp


	##################################################################
	#### restore B ####
	restore_B



##################################################################################################
	###							###	
	### 	enc_table_6bit 					###
	###							###
	###	result 						###
	###							###
##################################################################################################

.endm






.macro	compute_table_6bit	


##################################################################################################
	###							###	
	### 	compute_table_6bit				###
	###							###
	###	sum 						###
	###							###
##################################################################################################

	#### table[0] tabke[1] have be stored ####
	addq	$256, %rsp


	#### table[2] -- tabke[63] ####


	.rept	62
/*
	#### prepare M ####
	vperm2i128	$0x31, T0, M0, T0
	vperm2i128	$0x31, T1, M1, T1
	vperm2i128	$0x31, T2, M2, T2
	vperm2i128	$0x31, T3, M3, T3
*/
	#### compute result ####
	store_B

### new add ###
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3
#############	

	call montmul1024


	#### enc and store result ####
	enc_table_6bit
	# restore_B

	.endr


	#### restore %rsp ####
	subq	$8192, %rsp		#128*64




##################################################################################################
	###							###	
	### 	compute_table_6bit 				###
	###							###
	###	result 						###
	###							###
##################################################################################################

.endm




.macro	montexp_64bit_1st	position exp_xmm exp	


##################################################################################################
	###										###	
	### 	montexp_64bit: exponentiation for one 64bit word exponent		###
	###										###
	###	sum 2522=576+1216+628+102						###
	###										###
##################################################################################################


	#################################################################################
	#################################################################################
	#################################################################################
	#### 1st round #####


	#### store A ####
	store_A
	

	#### get exp ###
	vpextrq         $\position, \exp_xmm, %rax
	

	#### compute index ###
	movq		%rax, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
	movq		$6, %rcx 
	shrxq		%rcx, %rax, %rax
		
	#### store new exp ###	
	vpinsrq         $\position, %rax, \exp_xmm, \exp_xmm


	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

	
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
	 
	
	#### restore A ####
	restore_A


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################


	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1



	#################################################################################
	#################################################################################
	#################################################################################
	#### 9 round #####

	.rept	9

	###############################################
	#### compute 6 SQU ####

	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

	###############################################


	#### store A ####
	store_A
	

	#### get exp ###
	vpextrq         $\position, \exp_xmm, %rax
	

	#### compute index ###
	movq		%rax, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
	movq		$6, %rcx 
	shrxq		%rcx, %rax, %rax
		
	#### store new exp ###	
	vpinsrq         $\position, %rax, \exp_xmm, \exp_xmm


	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

	
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
	 
	
	#### restore A ####
	restore_A


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################


	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1


	.endr	
	

	#################################################################################
	#################################################################################
	#################################################################################
	#### last round #####
	#### 4 bit ####


	###############################################
	#### compute 4 SQU ####

	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

	###############################################


	#### store A ####
	store_A
	

	#### get exp ###
	vpextrq         $\position, \exp_xmm, %rax
	

	#### compute index ###
	movq		%rax, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
	

	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

	
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
	 
	
	#### restore A ####
	restore_A


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################


	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1



##################################################################################################
	###							###	
	### 	montexp_64bit END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################

.endm




.macro	montexp_64bit_After	position exp_xmm exp	


##################################################################################################
	###										###	
	### 	montexp_64bit: exponentiation for one 64bit word exponent		###
	###										###
	###	sum 2522=576+1216+628+102						###
	###										###
##################################################################################################


	#################################################################################
	#################################################################################
	#################################################################################
	#### first 10 round #####

	.rept	10

	###############################################
	#### compute 6 SQU ####

	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

	###############################################


	#### store A ####
	store_A
	

	#### get exp ###
	vpextrq         $\position, \exp_xmm, %rax
	

	#### compute index ###
	movq		%rax, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
	movq		$6, %rcx 
	shrxq		%rcx, %rax, %rax
		
	#### store new exp ###	
	vpinsrq         $\position, %rax, \exp_xmm, \exp_xmm


	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm		#high 128nit zero
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

	
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
	 
	
	#### restore A ####
	restore_A


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################


	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1


	.endr	
	

	#################################################################################
	#################################################################################
	#################################################################################
	#### last round #####
	#### 4 bit ####


	###############################################
	#### compute 4 SQU ####

	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

	###############################################


	#### store A ####
	store_A
	

	#### get exp ###
	vpextrq         $\position, \exp_xmm, %rax
	

	#### compute index ###
	movq		%rax, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
	

	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

	
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
	 
	
	#### restore A ####
	restore_A


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################


	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1


##################################################################################################
	###							###	
	### 	montexp_64bit END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################

.endm






.macro	montexp_256bit_1st		


##################################################################################################
	###										###	
	### 	montexp_64bit: exponentiation for one 64bit word exponent		###
	###										###
	###	sum 2522=576+1216+628+102						###
	###										###
##################################################################################################


	#################################################################################
	#################################################################################
	#################################################################################
	#### 1st round #####


	#### store A ####
	# store_A
	

	#### get exp ###
	/*
	vpextrq         $0, T0xmm, %r8
	vpextrq         $1, T0xmm, %r9
	vpextrq         $0, T1xmm, %r10
	vpextrq         $1, T1xmm, %r11
	*/

	vpextrq         $0, T0xmm, %r11
	vpextrq         $1, T0xmm, %r10
	vpextrq         $0, T1xmm, %r9
	vpextrq         $1, T1xmm, %r8

/*
	vmovdqu64 	T0, %ymm24
	vmovdqu64 	T1, %ymm25
	vmovdqu64 	T2, %ymm26
	vmovdqu64 	T3, %ymm27
*/

/*
	xorq		%r12, %r12
	shrdq		$6, %r9, %r8
	shrdq		$6, %r10, %r9
	shrdq		$6, %r11, %r10
	shrdq		$6, %r12, %r11
	
	#### store new exp ###	
	vpinsrq         $0, %r8, T0xmm, T0xmm
	vpinsrq         $1, %r9, T0xmm, T0xmm
	vpinsrq         $0, %r10, T1xmm, T1xmm
	vpinsrq         $1, %r11, T1xmm, T1xmm

*/

	#### compute index ###
	movq		%r8, %rbx
	movq		$58, %rcx  	
	# shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
/*
	xorq		%r12, %r12
	shldq		$6, %r9, %r8
	shldq		$6, %r10, %r9
	shldq		$6, %r11, %r10
	shldq		$6, %r12, %r11
*/
	vpxorq	%ymm23,	 %ymm23,	%ymm23
	vmovq	%r8,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r9,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r10,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r11,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22

/*
	vmovq	%rbx,	%xmm24
*/



	#### load B from table ####
	imulq		$128, %rbx, %rbx
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		104(%rsp), B3xmm
	#vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

/*
	vmovdqu64 	B0, %ymm24
	vmovdqu64 	B1, %ymm25
	vmovdqu64 	B2, %ymm26
	vmovdqu64 	B3, %ymm27
*/


	vpermq		$0x14, A0, A0			#imm=0110
	vpermq		$0x14, A1, A1			#imm=0110
	vpermq		$0x14, A2, A2			#imm=0110
	vpermq		$0x14, A3, A3			#imm=0110
	vpermq		$0x14, B0, B0			#imm=0110
	vpermq		$0x14, B1, B1			#imm=0110
	vpermq		$0x14, B2, B2			#imm=0110
	vpermq		$0x14, B3, B3			#imm=0110



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
	#### restore A ####
#	restore_A


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


/*
	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################


	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1

*/

	#################################################################################
	#################################################################################
	#################################################################################
	#### 41 round #####

	.rept	42

	###############################################
	#### compute 6 SQU ####


	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

/*	vmovdqu64 	A0, %ymm24
	vmovdqu64 	A1, %ymm25
	vmovdqu64 	A2, %ymm26
	vmovdqu64 	A3, %ymm27
*/


	###############################################


	#### store A ####
	store_A

	vmovq	%xmm22,	%r8
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%xmm22,	%r9
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%xmm22,	%r10
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%xmm22,	%r11
	valignq  $1,   %ymm22,   %ymm23, %ymm22

	xorq		%r12, %r12
	shldq		$6, %r9, %r8
	shldq		$6, %r10, %r9
	shldq		$6, %r11, %r10
	shldq		$6, %r12, %r11

	#### compute index ###
	movq		%r8, %rbx
	movq		$58, %rcx  	
	# shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
/*
	xorq		%r12, %r12
	shldq		$6, %r9, %r8
	shldq		$6, %r10, %r9
	shldq		$6, %r11, %r10
	shldq		$6, %r12, %r11
*/
	vpxorq	%ymm23,	 %ymm23,	%ymm23
	vmovq	%r8,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r9,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r10,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r11,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	
/*
	#### get exp ###
	vpextrq         $0, T0xmm, %r8
	vpextrq         $1, T0xmm, %r9
	vpextrq         $0, T1xmm, %r10
	vpextrq         $1, T1xmm, %r11
	
	xorq		%r12, %r12
	shrdq		$6, %r9, %r8
	shrdq		$6, %r10, %r9
	shrdq		$6, %r11, %r10
	shrdq		$6, %r12, %r11
	
	#### store new exp ###	
	vpinsrq         $0, %r8, T0xmm, T0xmm
	vpinsrq         $1, %r9, T0xmm, T0xmm
	vpinsrq         $0, %r10, T1xmm, T1xmm
	vpinsrq         $1, %r11, T1xmm, T1xmm


	#### compute index ###
	movq		%r8, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
*/

	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		104(%rsp), B3xmm
	# vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp


	vpermq		$0x14, A0, A0			#imm=0110
	vpermq		$0x14, A1, A1			#imm=0110
	vpermq		$0x14, A2, A2			#imm=0110
	vpermq		$0x14, A3, A3			#imm=0110
	vpermq		$0x14, B0, B0			#imm=0110
	vpermq		$0x14, B1, B1			#imm=0110
	vpermq		$0x14, B2, B2			#imm=0110
	vpermq		$0x14, B3, B3			#imm=0110

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
	
	#### restore A ####
	# restore_A
	restore_B


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################

/*
	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1
*/

	.endr	
	

	#################################################################################
	#################################################################################
	#################################################################################
	#### last round #####
	#### 4 bit ####


	###############################################
	#### compute 4 SQU ####

	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

	###############################################


	#### store A ####
	store_A
	

	#### get exp ###
	# vpextrq         $0, T0xmm, %rax
	vmovq	%xmm22,	%r8
	

	#### compute index ###
	/*
	movq		%rax, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
	*/
	movq		%r8, %rbx
	movq		$60, %rcx  	
	# shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx

	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		104(%rsp), B3xmm
	# vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

	vpermq		$0x14, A0, A0			#imm=0110
	vpermq		$0x14, A1, A1			#imm=0110
	vpermq		$0x14, A2, A2			#imm=0110
	vpermq		$0x14, A3, A3			#imm=0110
	vpermq		$0x14, B0, B0			#imm=0110
	vpermq		$0x14, B1, B1			#imm=0110
	vpermq		$0x14, B2, B2			#imm=0110
	vpermq		$0x14, B3, B3			#imm=0110

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
	
	#### restore A ####
	# restore_A
	restore_B


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################

/*
	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1
*/
/*
	vmovdqu64 	B0, %ymm24
	vmovdqu64 	B1, %ymm25
	vmovdqu64 	B2, %ymm26
	vmovdqu64 	B3, %ymm27	
*/

##################################################################################################
	###							###	
	### 	montexp_256bit_1st END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################

.endm




.macro	montexp_256bit_After	position exp_xmm exp	


##################################################################################################
	###										###	
	### 	montexp_64bit: exponentiation for one 64bit word exponent		###
	###										###
	###	sum 2522=576+1216+628+102						###
	###										###
##################################################################################################


	#################################################################################
	#################################################################################
	#################################################################################
	
	#### get exp ###
	vpextrq         $0, T0xmm, %r11
	vpextrq         $1, T0xmm, %r10
	vpextrq         $0, T1xmm, %r9
	vpextrq         $1, T1xmm, %r8

	vpxorq	%ymm23,	 %ymm23,	%ymm23
	vmovq	%r8,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r9,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r10,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r11,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3
	
	#### first 42 round #####

	.rept	42

	###############################################
	#### compute 6 SQU ####

	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

	###############################################


	#### store A ####
	store_A
	
	vmovq	%xmm22,	%r8
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%xmm22,	%r9
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%xmm22,	%r10
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%xmm22,	%r11
	valignq  $1,   %ymm22,   %ymm23, %ymm22


	#### compute index ###
	movq		%r8, %rbx
	movq		$58, %rcx  	
	# shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx

	xorq		%r12, %r12
	shldq		$6, %r9, %r8
	shldq		$6, %r10, %r9
	shldq		$6, %r11, %r10
	shldq		$6, %r12, %r11

	vpxorq	%ymm23,	 %ymm23,	%ymm23
	vmovq	%r8,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r9,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r10,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22
	vmovq	%r11,	%xmm23
	valignq  $1,   %ymm22,   %ymm23, %ymm22

/*
	#### get exp ###
	vpextrq         $0, T0xmm, %r8
	vpextrq         $1, T0xmm, %r9
	vpextrq         $0, T1xmm, %r10
	vpextrq         $1, T1xmm, %r11
	
	xorq		%r12, %r12
	shrdq		$6, %r9, %r8
	shrdq		$6, %r10, %r9
	shrdq		$6, %r11, %r10
	shrdq		$6, %r12, %r11
	
	#### store new exp ###	
	vpinsrq         $0, %r8, T0xmm, T0xmm
	vpinsrq         $1, %r9, T0xmm, T0xmm
	vpinsrq         $0, %r10, T1xmm, T1xmm
	vpinsrq         $1, %r11, T1xmm, T1xmm


	#### compute index ###
	movq		%r8, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx

*/

	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm		#high 128bit zero
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		104(%rsp), B3xmm
	# vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp


	vpermq		$0x14, A0, A0			#imm=0110
	vpermq		$0x14, A1, A1			#imm=0110
	vpermq		$0x14, A2, A2			#imm=0110
	vpermq		$0x14, A3, A3			#imm=0110
	vpermq		$0x14, B0, B0			#imm=0110
	vpermq		$0x14, B1, B1			#imm=0110
	vpermq		$0x14, B2, B2			#imm=0110
	vpermq		$0x14, B3, B3			#imm=0110

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
	#### restore A ####
	# restore_A
	restore_B


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################

/*
	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1
*/

	.endr	
	

	#################################################################################
	#################################################################################
	#################################################################################
	#### last round #####
	#### 4 bit ####


	###############################################
	#### compute 4 SQU ####

	call montsqu1024
	call montsqu1024
	call montsqu1024
	call montsqu1024

	###############################################


	#### store A ####
	store_A
	

	#### get exp ###
	# vpextrq         $0, T0xmm, %rax
	vmovq	%xmm22,	%r8
	

	#### compute index ###
	/*
	movq		%rax, %rbx
	movq		$58, %rcx  	
	shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx
	*/
	movq		%r8, %rbx
	movq		$60, %rcx  	
	# shlxq		%rcx, %rbx, %rbx
	shrxq		%rcx, %rbx, %rbx

	#### load B from table ####
	imulq		$128, %rbx, %rbx
	
	addq		%rbx, %rsp
	vmovdqu		(%rsp), A0xmm
	vmovdqu		16(%rsp), A1xmm
	vmovdqu		32(%rsp), A2xmm
	vmovdqu		48(%rsp), A3xmm
	vmovdqu		64(%rsp), B0xmm
	vmovdqu		80(%rsp), B1xmm
	vmovdqu		96(%rsp), B2xmm
	vmovdqu		104(%rsp), B3xmm
	# vmovdqu		112(%rsp), B3xmm
	subq		%rbx, %rsp

	vpermq		$0x14, A0, A0			#imm=0110
	vpermq		$0x14, A1, A1			#imm=0110
	vpermq		$0x14, A2, A2			#imm=0110
	vpermq		$0x14, A3, A3			#imm=0110
	vpermq		$0x14, B0, B0			#imm=0110
	vpermq		$0x14, B1, B1			#imm=0110
	vpermq		$0x14, B2, B2			#imm=0110
	vpermq		$0x14, B3, B3			#imm=0110

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
	#### restore A ####
	# restore_A
	restore_B


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	###############################################
	#### compute 1 MUL ####

	call montmul1024
	###############################################

/*
	#### reverse T0 T1 for exp ####
	vperm2i128	$0x1, T0, T0, T0
	vperm2i128	$0x1, T1, T1, T1
*/

##################################################################################################
	###							###	
	### 	montexp_256bit_after END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################

.endm




.macro	decexp_T0xmm_T1xmm	


##################################################################################################
	###										###	
	### 	decexp_64bit								###
	###										###
	###	sum 									###
	###										###
##################################################################################################

	
	### load key ###
	vperm2i128	$0x10, M0, M0, T2

	#### dec load arg ####
	key_schedule_128_128bit
	
	#### dec ####
	#10
	vpxor 				rk_128, T0xmm, T0xmm
	vpxor 				rk_128, T1xmm, T1xmm

	#9
	inv_key_expansion_128_128bit	rk_128 0x36 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm

	#8
	inv_key_expansion_128_128bit	rk_128 0x1b rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm

	#7
	inv_key_expansion_128_128bit	rk_128 0x80 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm


	#6
	inv_key_expansion_128_128bit	rk_128 0x40 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm


	#5
	inv_key_expansion_128_128bit	rk_128 0x20 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm


	#4
	inv_key_expansion_128_128bit	rk_128 0x10 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm


	#3
	inv_key_expansion_128_128bit	rk_128 0x8 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm


	#2
	inv_key_expansion_128_128bit	rk_128 0x4 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm


	#1
	inv_key_expansion_128_128bit	rk_128 0x2 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdec 			rhelp_128, T0xmm, T0xmm
	vaesdec 			rhelp_128, T1xmm, T1xmm


	#0
	inv_key_expansion_128_128bit	rk_128 0x1 rhelp_128
	vaesimc				rk_128, rhelp_128
	vaesdeclast  			rhelp_128, T0xmm, T0xmm
	vaesdeclast  			rhelp_128, T1xmm, T1xmm


##################################################################################################
	###							###	
	### 	decexp_64bit 					###
	###							###
	###	result 						###
	###							###
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

/*
	vpxorq		%zmm15,	%zmm15,	%zmm15
	vmovdqu64		%xmm16,	%xmm0
	valignq  $2,   %zmm16,   %zmm15, %zmm16
	vmovdqu64		%xmm16,	%xmm1
	valignq  $2,   %zmm16,   %zmm15, %zmm16
	vmovdqu64		%xmm16,	%xmm2
	valignq  $2,   %zmm16,   %zmm15, %zmm16
	vmovdqu64		%xmm16,	%xmm3
	valignq  $2,   %zmm16,   %zmm15, %zmm16
	vmovdqu64		%xmm17,	%xmm4
	valignq  $2,   %zmm17,   %zmm15, %zmm17
	vmovdqu64		%xmm17,	%xmm5
	valignq  $2,   %zmm17,   %zmm15, %zmm17
	vmovdqu64		%xmm17,	%xmm6
	valignq  $2,   %zmm17,   %zmm15, %zmm17
	vmovdqu64		%xmm17,	%xmm7
	valignq  $2,   %zmm17,   %zmm15, %zmm17
	

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

	vmovq	%rsi,	%xmm17

 .rept	16
	
	vmovq	%xmm17,	%rdx
	movq		384(%rdx), %rbx
	movq    $0x0123456789ABCDEF,    %rax
	xorq	%rax,	%rbx
	vmovq	%rbx,	%xmm16
	addq	$8,	%rdx
	vmovq	%rdx,	%xmm17

	.rept	64

	vmovq	%xmm16,	%rbx
	movq	%rbx,	%rax
	shr 	$1,		%rbx
	vmovq	%rbx,	%xmm16
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

