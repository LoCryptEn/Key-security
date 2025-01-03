	
	#include "montexp_AES.S"


	.file	"RSA_function.S"
	.text

	

##################################################################################################
	###							###	
	### 	mul1024(A,B):					###
	###							###	
	###	R=A*B 						###
	###							###
	###							###
##################################################################################################



/* Argument only use A0-A3 and B0-B3, M0-M3 for tmp storage */
#########################################################
	
	#########################################
	#	A0 	A1	A2	A3 	#		
	#					#
	# A[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#				
	#########################################
	#	B0 	B1	B2	B3 	#		
	#					#
	# B[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	# M[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#
	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	# T[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#
	#########################################

#########################################################




/* result store in A and B, R[0]-R[15] store in A, R[16]-R[32] store in B*/
#########################################################
	
	#########################################
	#	A0 	A1	A2	A3 	#		
	#					#
	# A[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#				
	#########################################
	#	B0 	B1	B2	B3 	#		
	#					#
	# B[i]  25	27	29	31	#	
	# 	24	26	28	30	#
	# 	17	19	21	23	#
	# 	16	18	20	22	#
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	# M[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#
	#########################################
	# 	T0 	T1	T2	T3 	#		
	#					#
	# T[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#
	#########################################

#########################################################




.macro	mul1024_1st

##################################################################################################
	###							###	
	### 	1st part: A[0-7]*B[0-7]				###
	###							###
	###	sum 576=65+73*7					###
	###							###
##################################################################################################
	###							###
	### 	1st_0: A[0-7]*B[0]				###
	###	sum 65=11+3+17*3				###
	###							###
	###########################################################

	##### A[0 2 4 6]*B[0] #####
	xorq		s8, s8
	xorq		s9, s9

	vpextrq         $1, A0xmm, bi         	#B[0]

	vmovq           A0xmm, ai                 	#A[0]
	mulx            bi, s0, s1          	#A[0]*B[0]
        
	vmovq           A1xmm, ai                 	#A[2]
	mulx            bi, s2, s3        	#A[2]*B[0]

	vmovq           A2xmm, ai                 	#A[4]
        mulx            bi, s4, s5        	#A[4]*B[0]

	vmovq           A3xmm, ai                 	#A[6]
        mulx            bi, s6, s7        	#A[6]*B[0]

	
	##### A[1 3 5 7]*B[0] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[0]
	add		rl, s1
	adc		rh, s2

	vmovq           B1xmm, ai                   #A[3]
        mulx            bi, rl, rh              #A[3]*B[0]
        adc             rl, s3
        adc             rh, s4

	vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[0]
        adc             rl, s5
        adc             rh, s6

	vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[0]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9

	vmovq		s0, M0xmm		#R[0]		


##################################################################################################
        ###                                                     ###
        ###     1st_1: A[0-7]*B[1] + M[0-7]*q1                  ###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[1] #####
        xorq            s0, s0
        vpextrq         $1, B0xmm, bi           #B[1]

        vmovq           A0xmm, ai                   #A[0]
        mulx            bi, rl, rh              #A[0]*B[1]
	add		rl, s1
	adc		rh, s2

	vmovq           A1xmm, ai                   #A[2]
        mulx            bi, rl, rh              #A[2]*B[1]
        adc             rl, s3
        adc             rh, s4

	vmovq           A2xmm, ai                   #A[4]
        mulx            bi, rl, rh              #A[4]*B[1]
        adc             rl, s5
        adc             rh, s6

	vmovq           A3xmm, ai                   #A[6]
        mulx            bi, rl, rh              #A[6]*B[1]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	
        
	##### A[1 3 5 7]*B[1] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[1]
        add             rl, s2
        adc             rh, s3

        vmovq           B1xmm, ai                   #A[3]
        mulx            bi, rl, rh              #A[3]*B[1]
        adc             rl, s4
        adc             rh, s5

        vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[1]
        adc             rl, s6
        adc             rh, s7

        vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[1]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	
	vmovq		s1, T0xmm		#R[1]
        
	
##################################################################################################
        ###                                                     ###
        ###     1st_2: A[0-7]*B[2]                 		###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[2] #####
        xorq            s1, s1
        vpextrq         $1, A1xmm, bi           #B[2]

        vmovq           A0xmm, ai                   #A[0]
        mulx            bi, rl, rh              #A[0]*B[2]
	add		rl, s2
	adc		rh, s3

	vmovq           A1xmm, ai                   #A[2]
        mulx            bi, rl, rh              #A[2]*B[2]
        adc             rl, s4
        adc             rh, s5

	vmovq           A2xmm, ai                   #A[4]
        mulx            bi, rl, rh              #A[4]*B[2]
        adc             rl, s6
        adc             rh, s7

	vmovq           A3xmm, ai                   #A[6]
        mulx            bi, rl, rh              #A[6]*B[2]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	

	##### A[1 3 5 7]*B[2] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[2]
        add             rl, s3
        adc             rh, s4

        vmovq           B1xmm, ai                   #A[3]
        mulx            bi, rl, rh              #A[3]*B[2]
        adc             rl, s5
        adc             rh, s6

        vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[2]
        adc             rl, s7
        adc             rh, s8

        vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[2]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1


	vmovq		s2, M1xmm		#R[2]
        

##################################################################################################
        ###                                                     ###
        ###     1st_3: A[0-7]*B[3]                  		###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[3] #####
        xorq            s2, s2
        vpextrq         $1, B1xmm, bi           #B[3]

        vmovq           A0xmm, ai                   #A[0]
        mulx            bi, rl, rh              #A[0]*B[3]
	add		rl, s3
	adc		rh, s4

	vmovq           A1xmm, ai                   #A[2]
        mulx            bi, rl, rh              #A[2]*B[3]
        adc             rl, s5
        adc             rh, s6

	vmovq           A2xmm, ai                   #A[4]
        mulx            bi, rl, rh              #A[4]*B[3]
        adc             rl, s7
        adc             rh, s8

	vmovq           A3xmm, ai                   #A[6]
        mulx            bi, rl, rh              #A[6]*B[3]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	

	##### A[1 3 5 7]*B[3] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[3]
        add             rl, s4
        adc             rh, s5

        vmovq           B1xmm, ai                   #A[3]
        mulx            bi, rl, rh              #A[3]*B[3]
        adc             rl, s6
        adc             rh, s7

        vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[3]
        adc             rl, s8
        adc             rh, s9

        vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[3]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2


	vmovq		s3, T1xmm		#R[3]

        
##################################################################################################
        ###                                                     ###
        ###     1st_4: A[0-7]*B[4]                  		###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[4] #####
        xorq            s3, s3
        vpextrq         $1, A2xmm, bi           #B[4]

        vmovq           A0xmm, ai                   #A[0]
        mulx            bi, rl, rh              #A[0]*B[4]
	add		rl, s4
	adc		rh, s5

	vmovq           A1xmm, ai                   #A[2]
        mulx            bi, rl, rh              #A[2]*B[4]
        adc             rl, s6
        adc             rh, s7

	vmovq           A2xmm, ai                   #A[4]
        mulx            bi, rl, rh              #A[4]*B[4]
        adc             rl, s8
        adc             rh, s9

	vmovq           A3xmm, ai                   #A[6]
        mulx            bi, rl, rh              #A[6]*B[4]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	

	##### A[1 3 5 7]*B[4] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[4]
        add             rl, s5
        adc             rh, s6

        vmovq           B1xmm, ai                   #A[3]
        mulx            bi, rl, rh              #A[3]*B[4]
        adc             rl, s7
        adc             rh, s8

        vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[4]
        adc             rl, s9
        adc             rh, s0

        vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[4]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3


	vmovq		s4, M2xmm		#R[4]


##################################################################################################
        ###                                                     ###
        ###     1st_5: A[0-7]*B[5]                  		###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[5] #####
        xorq            s4, s4
        vpextrq         $1, B2xmm, bi           #B[5]

        vmovq           A0xmm, ai                   #A[0]
        mulx            bi, rl, rh              #A[0]*B[5]
	add		rl, s5
	adc		rh, s6

	vmovq           A1xmm, ai                   #A[2]
        mulx            bi, rl, rh              #A[2]*B[5]
        adc             rl, s7
        adc             rh, s8

	vmovq           A2xmm, ai                   #A[4]
        mulx            bi, rl, rh              #A[4]*B[5]
        adc             rl, s9
        adc             rh, s0

	vmovq           A3xmm, ai                   #A[6]
        mulx            bi, rl, rh              #A[6]*B[5]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	

	##### A[1 3 5 7]*B[5] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[5]
        add             rl, s6
        adc             rh, s7

        vmovq           B1xmm, ai                   #A[3]
        mulx            bi, rl, rh              #A[3]*B[5]
        adc             rl, s8
        adc             rh, s9

        vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[5]
        adc             rl, s0
        adc             rh, s1

        vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[5]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4


	vmovq		s5, T2xmm		#R[5]


##################################################################################################
        ###                                                     ###
        ###     1st_6: A[0-7]*B[6]                  		###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[6] #####
        xorq            s5, s5
        vpextrq         $1, A3xmm, bi           #B[6]

        vmovq           A0xmm, ai                   #A[0]
        mulx            bi, rl, rh              #A[0]*B[6]
	add		rl, s6
	adc		rh, s7

	vmovq           A1xmm, ai                   #A[2]
        mulx            bi, rl, rh              #A[2]*B[6]
        adc             rl, s8
        adc             rh, s9

	vmovq           A2xmm, ai                   #A[4]
        mulx            bi, rl, rh              #A[4]*B[6]
        adc             rl, s0
        adc             rh, s1

	vmovq           A3xmm, ai                   #A[6]
        mulx            bi, rl, rh              #A[6]*B[6]
        adc             rl, s2
        adc             rh, s3
	adc		$0, s4
	
       
	##### A[1 3 5 7]*B[6] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[6]
        add             rl, s7
        adc             rh, s8

        vmovq           B1xmm, ai                  	#A[3]
        mulx            bi, rl, rh              #A[3]*B[6]
        adc             rl, s9
        adc             rh, s0

        vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[6]
        adc             rl, s1
        adc             rh, s2

        vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[6]
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5


	vmovq		s6, M3xmm		#R[6]


##################################################################################################
        ###                                                     ###
        ###     1st_7: A[0-7]*B[7]                  		###
        ###     sum 73=2+3+17*4                                 ###
        ###                                                     ###
        ###########################################################

	##### A[0 2 4 6]*B[7] #####
        xorq            s6, s6
        vpextrq         $1, B3xmm, bi           #B[7]

        vmovq           A0xmm, ai                   #A[0]
        mulx            bi, rl, rh              #A[0]*B[7]
	add		rl, s7
	adc		rh, s8

	vmovq           A1xmm, ai                   #A[2]
        mulx            bi, rl, rh              #A[2]*B[7]
        adc             rl, s9
        adc             rh, s0

	vmovq           A2xmm, ai                   #A[4]
        mulx            bi, rl, rh              #A[4]*B[7]
        adc             rl, s1
        adc             rh, s2

	vmovq           A3xmm, ai                   #A[6]
        mulx            bi, rl, rh              #A[6]*B[7]
        adc             rl, s3
        adc             rh, s4
	adc		$0, s5
	
        
	##### A[1 3 5 7]*B[7] #####
        vmovq           B0xmm, ai                   #A[1]
        mulx            bi, rl, rh              #A[1]*B[7]
        add             rl, s8
        adc             rh, s9

        vmovq           B1xmm, ai                   #A[3]
        mulx            bi, rl, rh              #A[3]*B[7]
        adc             rl, s0
        adc             rh, s1

        vmovq           B2xmm, ai                   #A[5]
        mulx            bi, rl, rh              #A[5]*B[7]
        adc             rl, s2
        adc             rh, s3

        vmovq           B3xmm, ai                   #A[7]
        mulx            bi, rl, rh              #A[7]*B[7]
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6


	vmovq		s7, T3xmm		#R[7]
        

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

		


##################################################################################################


/* 16 256bit vector registers */
#########################################################
	
	### al ah can be used for temporary storage, for vector value exchange ###
	### bi q also can be used ###

	#################################################################################
	#	AL0 	AL1	AL2	AL3 	#	BL0 	BL1	BL2	BL3 	#		
	#					#					#
	# A[i]  X	X	X	X	# B[i]	1	3	5	7	#	
	# 	X	X	X	X	#	0	2	4	6	#
	# 	1	3	5	7	#	X	X	X	X	#
	# 	0	2	4	6	#	X	X	X	X	#				
	#################################################################################
	#	AH0 	AH1	AH2	AH3 	#	BH0 	BH1	BH2	BH3 	#		
	#					#					#
	# A[i]  X	X	X	X	# B[i]	9	11	13	15	#
	#	X	X	X	X	#	8	10	12	14	#
	#	9	11	13	15	#	X	X	X	X	#	
	# 	8	10	12	14	#	X	X	X	X	#
	#################################################################################
	# 	ML0 	ML1	ML2	ML3 	#	TL0	TL1	TL2	TL3	#		
	#					#					#
	# M[i]  X	X	X	X	# T[i]	1	3	5	7	#	
	# 	X	X	X	X	#	0	2	4	6	#
	# 	1	3	5	7	#	X	X	X	X	#
	# 	0	2	4	6	#	X	X	X	X	#
	#################################################################################
	# 	MH0 	MH1	MH2	MH3 	#	TH0	TH1	TH2	TH3	#		
	#					#					#
	# M[i]  X	X	X	X	# T[i]	9	11	13	15	#
	# 	X	X	X	X	#	8	10	12	14	#
	# 	9	11	13	15	#	X	X	X	X	#
	# 	8	10	12	14	#	X	X	X	X	#
	#################################################################################	

#########################################################



.macro	mul1024_2nd

##################################################################################################
	###										###	
	### 	2nd part: 								###
	### 	A[8-15]*B[0-7] + A[0-7]*B[8-15] 					###
	###										###
	###	sum 1248=56+149*8							###
	###										###
##################################################################################################
        ###                                                     ###
        ###     2nd_arrange_vector		                ###
        ###     sum 56=7*8                                 	###
        ###                                                     ###
        ###########################################################

	vpermq		$0xD8, A0, A0			#imm=3120
	vpermq		$0xD8, A1, A1			#imm=3120
	vpermq		$0xD8, A2, A2			#imm=3120
	vpermq		$0xD8, A3, A3			#imm=3120
	vpermq		$0xD8, B0, B0			#imm=3120
	vpermq		$0xD8, B1, B1			#imm=3120
	vpermq		$0xD8, B2, B2			#imm=3120
	vpermq		$0xD8, B3, B3			#imm=3120

 
##################################################################################################
        ###								###	
	### 	2nd_0: 							###
	### 	A[8-15]*B[0] + A[0-7]*B[8]				###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[0] #####
        xorq            s7, s7

	vperm2i128	$1, A0, A0, A0		#imm=01
        vmovq		A0xmm, bi          	#B[0]
	vperm2i128	$1, A0, A0, A0		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[0]
	add		rl, s8
	adc		rh, s9

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[0]
        adc             rl, s0
        adc             rh, s1

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[0]
        adc             rl, s2
        adc             rh, s3

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[0]
        adc             rl, s4
        adc             rh, s5
	adc		$0, s6
	

	##### A[9 11 13 15]*B[0] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[0]
        add             rl, s9
        adc             rh, s0

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[0]
        adc             rl, s1
        adc             rh, s2

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[0]
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[0]
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[8] #####
	vperm2i128	$1, A0, A0, A0		#imm=01
        vpextrq         $1, A0xmm, bi          #B[8]
	vperm2i128	$1, A0, A0, A0		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[8]
	add		rl, s8
	adc		rh, s9

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[8]
        adc             rl, s0
        adc             rh, s1

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[8]
        adc             rl, s2
        adc             rh, s3

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[8]
        adc             rl, s4
        adc             rh, s5
	adc		$0, s6
	adc		$0, s7
	

	##### A[1 3 5 7]*B[8] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[8]
        add             rl, s9
        adc             rh, s0

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[8]
        adc             rl, s1
        adc             rh, s2

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[8]
        adc             rl, s3
        adc             rh, s4

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[8]
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

	vpinsrq		$1, s8, M0xmm, M0xmm	#R[8]


##################################################################################################
        ###								###	
	### 	2nd_1: 							###
	### 	A[8-15]*B[1] + A[0-7]*B[9]			 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[1] #####
        xorq            s8, s8

	vperm2i128	$1, B0, B0, B0		#imm=01
        vmovq		B0xmm, bi          	#B[1]
	vperm2i128	$1, B0, B0, B0		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[1]
	add		rl, s9
	adc		rh, s0

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[1]
        adc             rl, s1
        adc             rh, s2

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[1]
        adc             rl, s3
        adc             rh, s4

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[1]
        adc             rl, s5
        adc             rh, s6
	adc		$0, s7
	
       
	##### A[9 11 13 15]*B[1] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[1]
        add             rl, s0
        adc             rh, s1

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[1]
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[1]
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[1]
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

        
	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[9] #####
	vperm2i128	$1, B0, B0, B0		#imm=01
        vpextrq         $1, B0xmm, bi          #B[9]
	vperm2i128	$1, B0, B0, B0		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[9]
	add		rl, s9
	adc		rh, s0

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[9]
        adc             rl, s1
        adc             rh, s2

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[9]
        adc             rl, s3
        adc             rh, s4

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[9]
        adc             rl, s5
        adc             rh, s6
	adc		$0, s7
	adc		$0, s8
	
      
	##### A[1 3 5 7]*B[9] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[9]
        add             rl, s0
        adc             rh, s1

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[9]
        adc             rl, s2
        adc             rh, s3

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[9]
        adc             rl, s4
        adc             rh, s5

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[9]
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

	vpinsrq		$1, s9, T0xmm, T0xmm	#R[9]

##################################################################################################
        ###								###	
	### 	2nd_2: 							###
	### 	A[8-15]*B[2] + A[0-7]*B[10]			 	###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[2] #####
        xorq            s9, s9

	vperm2i128	$1, A1, A1, A1		#imm=01
        vmovq		A1xmm, bi          	#B[2]
	vperm2i128	$1, A1, A1, A1		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[2]
	add		rl, s0
	adc		rh, s1

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[2]
        adc             rl, s2
        adc             rh, s3

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[2]
        adc             rl, s4
        adc             rh, s5

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[2]
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8
	
       
	##### A[9 11 13 15]*B[2] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[2]
        add             rl, s1
        adc             rh, s2

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[2]
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[2]
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[2]
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[10] #####
	vperm2i128	$1, A1, A1, A1		#imm=01
        vpextrq         $1, A1xmm, bi          #B[10]
	vperm2i128	$1, A1, A1, A1		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[10]
	add		rl, s0
	adc		rh, s1

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[10]
        adc             rl, s2
        adc             rh, s3

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[10]
        adc             rl, s4
        adc             rh, s5

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[10]
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8
	adc		$0, s9
	
        
	##### A[1 3 5 7]*B[10] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[10]
        add             rl, s1
        adc             rh, s2

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[10]
        adc             rl, s3
        adc             rh, s4

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[10]
        adc             rl, s5
        adc             rh, s6

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[10]
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9


	vpinsrq		$1, s0, M1xmm, M1xmm		#R[10]
        
##################################################################################################
        ###								###	
	### 	2nd_3: 							###
	### 	A[8-15]*B[3]+ A[0-7]*B[11] 				###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[3] #####
        xorq            s0, s0

	vperm2i128	$1, B1, B1, B1		#imm=01
        vmovq		B1xmm, bi          	#B[3]
	vperm2i128	$1, B1, B1, B1		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[3]
	add		rl, s1
	adc		rh, s2

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[3]
        adc             rl, s3
        adc             rh, s4

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[3]
        adc             rl, s5
        adc             rh, s6

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[3]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	

	##### A[9 11 13 15]*B[3] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[3]
        add             rl, s2
        adc             rh, s3

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[3]
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[3]
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[3]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

        
	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[11] #####
	vperm2i128	$1, B1, B1, B1		#imm=01
        vpextrq         $1, B1xmm, bi          #B[11]
	vperm2i128	$1, B1, B1, B1		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[11]
	add		rl, s1
	adc		rh, s2

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[11]
        adc             rl, s3
        adc             rh, s4

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[11]
        adc             rl, s5
        adc             rh, s6

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[11]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	adc		$0, s0
	
        
	##### A[1 3 5 7]*B[11] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[11]
        add             rl, s2
        adc             rh, s3

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[11]
        adc             rl, s4
        adc             rh, s5

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[11]
        adc             rl, s6
        adc             rh, s7

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[11]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	vpinsrq		$1, s1, T1xmm, T1xmm		#R[11]

##################################################################################################
        ###								###	
	### 	2nd_4: 							###
	### 	A[8-15]*B[4] + A[0-7]*B[12] 				###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[4] #####
        xorq            s1, s1

	vperm2i128	$1, A2, A2, A2		#imm=01
        vmovq		A2xmm, bi          	#B[4]
	vperm2i128	$1, A2, A2, A2		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[4]
	add		rl, s2
	adc		rh, s3

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[4]
        adc             rl, s4
        adc             rh, s5

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[4]
        adc             rl, s6
        adc             rh, s7

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[4]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	
    
	##### A[9 11 13 15]*B[4] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[4]
        add             rl, s3
        adc             rh, s4

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[4]
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[4]
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[4]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

       
	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[12] #####
	vperm2i128	$1, A2, A2, A2		#imm=01
        vpextrq         $1, A2xmm, bi          #B[12]
	vperm2i128	$1, A2, A2, A2		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[12]
	add		rl, s2
	adc		rh, s3

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[12]
        adc             rl, s4
        adc             rh, s5

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[12]
        adc             rl, s6
        adc             rh, s7

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[12]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	adc		$0, s1
	
        
	##### A[1 3 5 7]*B[12] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[12]
        add             rl, s3
        adc             rh, s4

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[12]
        adc             rl, s5
        adc             rh, s6

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[12]
        adc             rl, s7
        adc             rh, s8

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[12]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

	
	vpinsrq		$1, s2, M2xmm, M2xmm		#R[12]
       
##################################################################################################
        ###								###	
	### 	2nd_5: 							###
	### 	A[8-15]*B[5] + A[0-7]*B[13]				###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[5] #####
        xorq            s2, s2

	vperm2i128	$1, B2, B2, B2		#imm=01
        vmovq		B2xmm, bi          	#B[5]
	vperm2i128	$1, B2, B2, B2		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[5]
	add		rl, s3
	adc		rh, s4

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[5]
        adc             rl, s5
        adc             rh, s6

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[5]
        adc             rl, s7
        adc             rh, s8

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[5]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	
        
	##### A[9 11 13 15]*B[5] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[5]
        add             rl, s4
        adc             rh, s5

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[5]
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[5]
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[5]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

        
	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[13] #####
	vperm2i128	$1, B2, B2, B2		#imm=01
        vpextrq         $1, B2xmm, bi          #B[13]
	vperm2i128	$1, B2, B2, B2		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[13]
	add		rl, s3
	adc		rh, s4

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[13]
        adc             rl, s5
        adc             rh, s6

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[13]
        adc             rl, s7
        adc             rh, s8

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[13]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	adc		$0, s2
	
        
	##### A[1 3 5 7]*B[13] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[13]
        add             rl, s4
        adc             rh, s5

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[13]
        adc             rl, s6
        adc             rh, s7

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[13]
        adc             rl, s8
        adc             rh, s9

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[13]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2


	vpinsrq		$1, s3, T2xmm, T2xmm		#R[13]

       
##################################################################################################
        ###								###	
	### 	2nd_6: 							###
	### 	A[8-15]*B[6] + A[0-7]*B[14] 				###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[6] #####
        xorq            s3, s3

	vperm2i128	$1, A3, A3, A3		#imm=01
        vmovq		A3xmm, bi          	#B[6]
	vperm2i128	$1, A3, A3, A3		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[6]
	add		rl, s4
	adc		rh, s5

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[6]
        adc             rl, s6
        adc             rh, s7

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[6]
        adc             rl, s8
        adc             rh, s9

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[6]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	
        
	##### A[9 11 13 15]*B[6] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[6]
        add             rl, s5
        adc             rh, s6

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[6]
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[6]
        adc             rl, s9
        adc             rh, s0

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[6]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

        

	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[14] #####
	vperm2i128	$1, A3, A3, A3		#imm=01
        vpextrq         $1, A3xmm, bi          #B[14]
	vperm2i128	$1, A3, A3, A3		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[14]
	add		rl, s4
	adc		rh, s5

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[14]
        adc             rl, s6
        adc             rh, s7

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[14]
        adc             rl, s8
        adc             rh, s9

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[14]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	adc		$0, s3
	
        
	##### A[1 3 5 7]*B[14] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[14]
        add             rl, s5
        adc             rh, s6

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[14]
        adc             rl, s7
        adc             rh, s8

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[14]
        adc             rl, s9
        adc             rh, s0

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[14]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3


	vpinsrq		$1, s4, M3xmm, M3xmm		#R[14]

        
##################################################################################################
        ###								###	
	### 	2nd_7: 							###
	### 	A[8-15]*B[7] + A[0-7]*B[15] 				###
	###								###
	###	sum 149=21+18+17+17+76					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[7] #####
        xorq            s4, s4

	vperm2i128	$1, B3, B3, B3		#imm=01
        vmovq		B3xmm, bi          	#B[7]
	vperm2i128	$1, B3, B3, B3		#imm=01

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[7]
	add		rl, s5
	adc		rh, s6

	vpextrq         $1, A1xmm, ai		#A[10]
        mulx            bi, rl, rh              #A[10]*B[7]
        adc             rl, s7
        adc             rh, s8

	vpextrq         $1, A2xmm, ai		#A[12]
        mulx            bi, rl, rh              #A[12]*B[7]
        adc             rl, s9
        adc             rh, s0

	vpextrq         $1, A3xmm, ai		#A[14]
        mulx            bi, rl, rh              #A[14]*B[7]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	
        
	##### A[9 11 13 15]*B[7] #####
        vpextrq         $1, B0xmm, ai          #A[9]
        mulx            bi, rl, rh              #A[9]*B[7]
        add             rl, s6
        adc             rh, s7

        vpextrq         $1, B1xmm, ai          #A[11]
        mulx            bi, rl, rh              #A[11]*B[7]
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, B2xmm, ai          #A[13]
        mulx            bi, rl, rh              #A[13]*B[7]
        adc             rl, s0
        adc             rh, s1

        vpextrq         $1, B3xmm, ai          #A[15]
        mulx            bi, rl, rh              #A[15]*B[7]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[15] #####
	vperm2i128	$1, B3, B3, B3		#imm=01
        vpextrq         $1, B3xmm, bi          #B[15]
	vperm2i128	$1, B3, B3, B3		#imm=01

        movq            A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[15]
	add		rl, s5
	adc		rh, s6

	movq            A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[15]
        adc             rl, s7
        adc             rh, s8

	movq            A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[15]
        adc             rl, s9
        adc             rh, s0

	movq            A3xmm, ai          #A[6]
        mulx            bi, rl, rh              #A[6]*B[15]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	adc		$0, s4
	
        
	##### A[1 3 5 7]*B[15] #####
        movq            B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[15]
        add             rl, s6
        adc             rh, s7

        movq            B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[15]
        adc             rl, s8
        adc             rh, s9

        movq            B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[15]
        adc             rl, s0
        adc             rh, s1

        movq            B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[15]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4


	vpinsrq		$1, s5, T3xmm, T3xmm		#R[15]

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







##################################################################################################


#########################################################
	
	#########################################
	#	A0 	A1	A2	A3 	#		
	#					#
	# A[i]  1	3	5	7	#	
	# 	0	2	4	6	#
	# 	9	11	13	15	#
	# 	8	10	12	14	#				
	#########################################
	#	B0 	B1	B2	B3 	#		
	#					#
	# B[i]  1	3	5	7	#	
	# 	0	2	4	6	#
	# 	9	11	13	15	#
	# 	8	10	12	14	#
	#########################################
	# 	M0 	M1	M2	M3 	#		
	#					#
	# M[i]	1	3	5	7	#
	#   	0	2	4	6	#
	#	9	11	13	15	#
	# 	8	10	12	14	#
	#########################################
	#	T0	T1	T2	T3	#
	#					#
	# T[i]  9	11	13	15	#	
	# 	8	10	12	14	#
	# 	1	3	5	7	#
	# 	0	2	4	6	#
	#########################################

#########################################################







.macro  mul1024_3rd


##################################################################################################
	###							###	
	### 	3rd part: A[8-15]*B[8-15] 			###
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


##################################################################################################
        ###								###	
	### 	3rd_0: 							###
	### 	A[8-15]*B[8] 						###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[8] #####
        xorq            s5, s5
        vpextrq         $1, A0xmm, bi          	#B[8]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[8]
	add		rl, s6
	adc		rh, s7

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[8]
        adc             rl, s8
        adc             rh, s9

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[8]
        adc             rl, s0
        adc             rh, s1

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[8]
        adc             rl, s2
        adc             rh, s3
	adc		$0, s4
	
 
	##### A[9 11 13 15]*B[8] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[8]
        add             rl, s7
        adc             rh, s8

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[8]
        adc             rl, s9
        adc             rh, s0

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[8]
        adc             rl, s1
        adc             rh, s2

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[8]
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5


	movq		s6, r0			#R[16]


##################################################################################################
        ###								###	
	### 	3rd_1: 							###
	### 	A[8-15]*B[9]						###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[9] #####
        xorq            s6, s6
        vpextrq         $1, B0xmm, bi          	#B[9]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[9]
	add		rl, s7
	adc		rh, s8

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[9]
        adc             rl, s9
        adc             rh, s0

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[9]
        adc             rl, s1
        adc             rh, s2

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[9]
        adc             rl, s3
        adc             rh, s4
	adc		$0, s5
	
        
	##### A[9 11 13 15]*B[9] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[9]
        add             rl, s8
        adc             rh, s9

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[9]
        adc             rl, s0
        adc             rh, s1

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[9]
        adc             rl, s2
        adc             rh, s3

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[9]
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

        
	movq		s7, r1			#R[17]


##################################################################################################
        ###								###	
	### 	3rd_2: 							###
	### 	A[8-15]*B[10]						###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[10] #####
        xorq            s7, s7
        vpextrq         $1, A1xmm, bi          	#B[10]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[10]
	add		rl, s8
	adc		rh, s9

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[10]
        adc             rl, s0
        adc             rh, s1

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[10]
        adc             rl, s2
        adc             rh, s3

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[10]
        adc             rl, s4
        adc             rh, s5
	adc		$0, s6
	
        
	##### A[9 11 13 15]*B[10] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[10]
        add             rl, s9
        adc             rh, s0

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[10]
        adc             rl, s1
        adc             rh, s2

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[10]
        adc             rl, s3
        adc             rh, s4

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[10]
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

           
	movq		s8, r2			#R[18]
    

##################################################################################################
        ###								###	
	### 	3rd_3: 							###
	### 	A[8-15]*B[11]						###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[11] #####
        xorq            s8, s8
        vpextrq         $1, B1xmm, bi          	#B[11]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[11]
	add		rl, s9
	adc		rh, s0

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[11]
        adc             rl, s1
        adc             rh, s2

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[11]
        adc             rl, s3
        adc             rh, s4

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[11]
        adc             rl, s5
        adc             rh, s6
	adc		$0, s7
	
        
	##### A[9 11 13 15]*B[11] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[11]
        add             rl, s0
        adc             rh, s1

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[11]
        adc             rl, s2
        adc             rh, s3

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[11]
        adc             rl, s4
        adc             rh, s5

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[11]
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

           
	movq		s9, r3			#R[19]

    
##################################################################################################
        ###								###	
	### 	3rd_4: 							###
	### 	A[8-15]*B[12]		 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[12] #####
        xorq            s9, s9
        vpextrq         $1, A2xmm, bi          	#B[12]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[12]
	add		rl, s0
	adc		rh, s1

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[12]
        adc             rl, s2
        adc             rh, s3

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[12]
        adc             rl, s4
        adc             rh, s5

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[12]
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8
	
        
	##### A[9 11 13 15]*B[12] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[12]
        add             rl, s1
        adc             rh, s2

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[12]
        adc             rl, s3
        adc             rh, s4

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[12]
        adc             rl, s5
        adc             rh, s6

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[12]
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

       
	movq		s0, r4			#R[20]


##################################################################################################
        ###								###	
	### 	3rd_5: 							###
	### 	A[8-15]*B[13]		 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[13] #####
        xorq            s0, s0
        vpextrq         $1, B2xmm, bi          	#B[13]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[13]
	add		rl, s1
	adc		rh, s2

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[13]
        adc             rl, s3
        adc             rh, s4

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[13]
        adc             rl, s5
        adc             rh, s6

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[13]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	
       
	##### A[9 11 13 15]*B[13] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[13]
        add             rl, s2
        adc             rh, s3

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[13]
        adc             rl, s4
        adc             rh, s5

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[13]
        adc             rl, s6
        adc             rh, s7

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[13]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

       
	movq		s1, r5			#R[21]


##################################################################################################
        ###								###	
	### 	3rd_6: 							###
	### 	A[8-15]*B[14]		 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[14] #####
        xorq            s1, s1
        vpextrq         $1, A3xmm, bi          	#B[14]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[14]
	add		rl, s2
	adc		rh, s3

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[14]
        adc             rl, s4
        adc             rh, s5

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[14]
        adc             rl, s6
        adc             rh, s7

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[14]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	
        
	##### A[9 11 13 15]*B[14] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[14]
        add             rl, s3
        adc             rh, s4

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[14]
        adc             rl, s5
        adc             rh, s6

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[14]
        adc             rl, s7
        adc             rh, s8

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[14]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1


	movq		s2, r6			#R[22]


##################################################################################################
        ###								###	
	### 	3rd_7: 							###
	### 	A[8-15]*B[15]		 				###
	###								###
	###	sum 72=19+18+17+18					###
	###								###
        ###################################################################

	##### A[8 10 12 14]*B[15] #####
        xorq            s2, s2
        vpextrq         $1, B3xmm, bi          	#B[15]

        movq            A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[15]
	add		rl, s3
	adc		rh, s4

	movq            A1xmm, ai          	#A[10]
        mulx            bi, rl, rh              #A[10]*B[15]
        adc             rl, s5
        adc             rh, s6

	movq            A2xmm, ai          	#A[12]
        mulx            bi, rl, rh              #A[12]*B[15]
        adc             rl, s7
        adc             rh, s8

	movq            A3xmm, ai          	#A[14]
        mulx            bi, rl, rh              #A[14]*B[15]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	
        
	##### A[9 11 13 15]*B[15] #####
        movq            B0xmm, ai          	#A[9]
        mulx            bi, rl, rh              #A[9]*B[15]
        add             rl, s4
        adc             rh, s5

        movq            B1xmm, ai          	#A[11]
        mulx            bi, rl, rh              #A[11]*B[15]
        adc             rl, s6
        adc             rh, s7

        movq            B2xmm, ai          	#A[13]
        mulx            bi, rl, rh              #A[13]*B[15]
        adc             rl, s8
        adc             rh, s9

        movq            B3xmm, ai          	#A[15]
        mulx            bi, rl, rh              #A[15]*B[15]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2


	movq		s3, r7			#R[23]


##################################################################################################

	###last result###



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





.globl 	mul1024
	.type  	mul1024, @function
	.align 	64

mul1024:

#.macro	mul1024


##################################################################################################
	###							###	
	### 	mul1024: 1st 2nd 3rd last 			###
	###							###
	###	result store in A B				###
	###							###
##################################################################################################

	movq	%rsp, rsp	#mm7

	mul1024_1st
	
	mul1024_2nd

	mul1024_3rd


	movq	rsp, %rsp	#mm7

##################################################################################################
	###							###	
	### 	mul1024 END 					###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################


#.endm

	ret
	.size	mul1024, .-mul1024









##################################################################################################
##################################################################################################
##################################################################################################




.globl 	sub_mp_mq
	.type  	sub_mp_mq, @function
	.align 	64

sub_mp_mq:

	### Rp:result of montexp1024_AES_p ### 
	### Rq:result of montexp1024_AES_q ### 	

/*
	movq		%mm0, %rsi			#for RRp
	movq		%mm1, %rax			#for Rq Rq
	### store the %rax, %rax will be altered in function montmul1024 ###
	pushq		%rax

	#####################################################################

	
	### load RRp to A B and Dec ###

	addq		$256, %rsi
	vmovdqu		(%rsi), A0
	vmovdqu		16(%rsi), A1
	vmovdqu		32(%rsi), A2
	vmovdqu		48(%rsi), A3
	vmovdqu		64(%rsi), B0
	vmovdqu		80(%rsi), B1
	vmovdqu		96(%rsi), B2
	vmovdqu		112(%rsi), B3

	
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


	#### store B ####
	store_B


	#####################################################################
	#####################################################################

	popq		%rax
	pushq		%rax
	

	### load Rq to A B ###
	vmovdqu 	128(%rax), A0xmm
	vmovdqu 	16+128(%rax), A1xmm
	vmovdqu 	32+128(%rax), A2xmm
	vmovdqu 	48+128(%rax), A3xmm
	vmovdqu 	64+128(%rax), B0xmm
	vmovdqu 	80+128(%rax), B1xmm
	vmovdqu 	96+128(%rax), B2xmm
	vmovdqu 	112+128(%rax), B3xmm

	
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


	### rerange Rq to A ###
 
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


	### Transfer Rq to montgomery form in p ###
	### Compute Rq'=Rq*RRp*R^(-1)mod p ###		
	call montmul1024


	### movq Rq to B ###
	vshufpd		$0x05, A0, A0, A0		#imm=0101
	vshufpd		$0x05, A1, A1, A1		#imm=0101
	vshufpd		$0x05, A2, A2, A2		#imm=0101
	vshufpd		$0x05, A3, A3, A3		#imm=0101
	vshufpd		$0x05, B0, B0, B0		#imm=0101
	vshufpd		$0x05, B1, B1, B1		#imm=0101
	vshufpd		$0x05, B2, B2, B2		#imm=0101
	vshufpd		$0x05, B3, B3, B3		#imm=0101


	#####################################################################
	#####################################################################

	#### store B ####
	store_B

	popq		%rax

	
	### load Rp to A B ###
	vmovdqu 	256(%rax), A0xmm
	vmovdqu 	16+256(%rax), A1xmm
	vmovdqu 	32+256(%rax), A2xmm
	vmovdqu 	48+256(%rax), A3xmm
	vmovdqu 	64+256(%rax), B0xmm
	vmovdqu 	80+256(%rax), B1xmm
	vmovdqu 	96+256(%rax), B2xmm
	vmovdqu 	112+256(%rax), B3xmm


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



	### rerange Rp to A ###
 
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

*/

	#####################################################################
	#####################################################################
	### A sub B store in A ###
	### (Rp-Rq)mod p ###

	### A=A-B ### 
	xorq		bi, bi

	vpextrq         $0, A0xmm, rh
	vpextrq         $1, A0xmm, rl
	subq		rl, rh
	movq		rh, r0			#R[0]

	vpextrq         $0, B0xmm, rh
	vpextrq         $1, B0xmm, rl
	sbbq		rl, rh
	movq		rh, r1			#R[1]

	vpextrq         $0, A1xmm, rh
	vpextrq         $1, A1xmm, rl
	sbbq		rl, rh
	movq		rh, r2			#R[2]	

	vpextrq         $0, B1xmm, rh
	vpextrq         $1, B1xmm, rl
	sbbq		rl, rh
	movq		rh, r3			#R[3]	

	vpextrq         $0, A2xmm, rh
	vpextrq         $1, A2xmm, rl
	sbbq		rl, rh
	movq		rh, r4			#R[4]	

	vpextrq         $0, B2xmm, rh
	vpextrq         $1, B2xmm, rl
	sbbq		rl, rh
	movq		rh, r5       		#R[5]	

	vpextrq         $0, A3xmm, rh
	vpextrq         $1, A3xmm, rl
	sbbq		rl, rh
	movq		rh, r6			#R[6]	

	vpextrq         $0, B3xmm, rh
	vpextrq         $1, B3xmm, rl
	sbbq		rl, rh
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
	sbbq		rl, rh
	movq		rh, r8			#R[8]

	vpextrq         $0, B0xmm, rh
	vpextrq         $1, B0xmm, rl
	sbbq		rl, rh
	movq		rh, r9			#R[9]

	vpextrq         $0, A1xmm, rh
	vpextrq         $1, A1xmm, rl
	sbbq		rl, rh
	movq		rh, r10			#R[10]	

	vpextrq         $0, B1xmm, rh
	vpextrq         $1, B1xmm, rl
	sbbq		rl, rh
	movq		rh, r11			#R[11]	

	vpextrq         $0, A2xmm, rh
	vpextrq         $1, A2xmm, rl
	sbbq		rl, rh
	movq		rh, r12			#R[12]	

	vpextrq         $0, B2xmm, rh
	vpextrq         $1, B2xmm, rl
	sbbq		rl, rh
	movq		rh, r13       		#R[13]	

	vpextrq         $0, A3xmm, rh
	vpextrq         $1, A3xmm, rl
	sbbq		rl, rh
	movq		rh, r14			#R[14]	

	vpextrq         $0, B3xmm, rh
	vpextrq         $1, B3xmm, rl
	sbbq		rl, rh
	movq		rh, r15       		#R[15]	


	sbbq		$0, bi
	jnb		1f
	

#.sub_mp_mq_1:

	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	### R=R+P ### 

	xorq		bi, bi

	vpextrq         $0, M0xmm, rl
	movq		r0, rh
	addq		rl, rh
	movq		rh, r0

	vpextrq         $0, T0xmm, rl
	movq		r1, rh
	adcq		rl, rh
	movq		rh, r1

	vpextrq         $0, M1xmm, rl
	movq		r2, rh
	adcq		rl, rh
	movq		rh, r2

	vpextrq         $0, T1xmm, rl
	movq		r3, rh
	adcq		rl, rh
	movq		rh, r3

	vpextrq         $0, M2xmm, rl
	movq		r4, rh
	adcq		rl, rh
	movq		rh, r4

	vpextrq         $0, T2xmm, rl
	movq		r5, rh
	adcq		rl, rh
	movq		rh, r5

	vpextrq         $0, M3xmm, rl
	movq		r6, rh
	adcq		rl, rh
	movq		rh, r6

	vpextrq         $0, T3xmm, rl
	movq		r7, rh
	adcq		rl, rh
	movq		rh, r7


	vpextrq         $1, M0xmm, rl
	adcq		rl, r8

	vpextrq         $1, T0xmm, rl
	adcq		rl, r9

	vpextrq         $1, M1xmm, rl
	adcq		rl, r10

	vpextrq         $1, T1xmm, rl
	adcq		rl, r11

	vpextrq         $1, M2xmm, rl
	adcq		rl, r12

	vpextrq         $1, T2xmm, rl
	adcq		rl, r13

	vpextrq         $1, M3xmm, rl
	adcq		rl, r14

	vpextrq         $1, T3xmm, rl
	adcq		rl, r15

/*
	adcq		$0, bi

	subq		$1, bi
	jnb		1f


	
#.sub_mp_mq_2:

	### R=R+P ### 

	xorq		bi, bi

	vpextrq         $0, M0xmm, rl
	movq		rh, r0
	addq		rl, rh

	vpextrq         $0, T0xmm, rl
	movq		rh, r1
	addq		rl, rh

	vpextrq         $0, M1xmm, rl
	movq		rh, r2
	addq		rl, rh

	vpextrq         $0, T1xmm, rl
	movq		rh, r3
	addq		rl, rh

	vpextrq         $0, M2xmm, rl
	movq		rh, r4
	addq		rl, rh

	vpextrq         $0, T2xmm, rl
	movq		rh, r5
	addq		rl, rh

	vpextrq         $0, M3xmm, rl
	movq		rh, r6
	addq		rl, rh

	vpextrq         $0, T3xmm, rl
	movq		rh, r7
	addq		rl, rh


	vpextrq         $1, M0xmm, rl
	adcq		rl, r8

	vpextrq         $1, T0xmm, rl
	adcq		rl, r9

	vpextrq         $1, M1xmm, rl
	adcq		rl, r10

	vpextrq         $1, T1xmm, rl
	adcq		rl, r11

	vpextrq         $1, M2xmm, rl
	adcq		rl, r12

	vpextrq         $1, T2xmm, rl
	adcq		rl, r13

	vpextrq         $1, M3xmm, rl
	adcq		rl, r14

	vpextrq         $1, T3xmm, rl
	adcq		rl, r15
*/

#.sub_mp_mq_end$:
1:	

	####################################################################
	####################################################################
	#### restore sub result to A ####

	movq		r0, rl
	vmovq		rl, A0xmm
	vpinsrq		$1, r8, A0xmm, A0xmm
	
	movq		r1, rl
	vmovq		rl, B0xmm
	vpinsrq		$1, r9, B0xmm, B0xmm

	movq		r2, rl
	vmovq		rl, A1xmm
	vpinsrq		$1, r10, A1xmm, A1xmm

	movq		r3, rl
	vmovq		rl, B1xmm
	vpinsrq		$1, r11, B1xmm, B1xmm

	movq		r4, rl
	vmovq		rl, A2xmm
	vpinsrq		$1, r12, A2xmm, A2xmm

	movq		r5, rl
	vmovq		rl, B2xmm
	vpinsrq		$1, r13, B2xmm, B2xmm

	movq		r6, rl
	vmovq		rl, A3xmm
	vpinsrq		$1, r14, A3xmm, A3xmm

	movq		r7, rl
	vmovq		rl, B3xmm
	vpinsrq		$1, r15, B3xmm, B3xmm

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

	ret
	.size	sub_mp_mq, .-sub_mp_mq
	



########################################################################################
########################################################################################
########################################################################################
########################################################################################



	.globl 	mul_qinv
	.type  	mul_qinv, @function
	.align 	64

mul_qinv:
/*
	### R=(m1-m2)mod p, stored in A ### 
	movq		%mm1, %rax			#for Rp-Rq
	pushq		%rax	
	
	movq		%mm0, %rsi
	pushq		%rsi
*/

	#####################################################################
	#####################################################################
	### load qinv to A B and Dec ###

	addq		$1280, %rsi	# for qinv which stored in 1280(%rsi)

	vmovdqu		(%rsi), A0xmm		
	vmovdqu		16(%rsi), A1xmm		
	vmovdqu		32(%rsi), A2xmm		
	vmovdqu		48(%rsi), A3xmm		
	vmovdqu		64(%rsi), B0xmm		
	vmovdqu		80(%rsi), B1xmm		
	vmovdqu		96(%rsi), B2xmm		
	vmovdqu		112(%rsi), B3xmm	

	### rerange qinv to A ###

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

	call montmul1024


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

	### store qinv ###
	vmovq		B0xmm, s0			#q0=B[0]  s0=B[8]
	vpextrq         $1, B0xmm, s1

	vmovq		B1xmm, s2
	vpextrq         $1, B1xmm, s3

	vmovq		B2xmm, s4
	vpextrq         $1, B2xmm, s5

	vmovq		B3xmm, s6
	vpextrq         $1, B3xmm, s7
	
	vmovq		A0xmm, rl
	movq		rl, q0
	vpextrq         $1, A0xmm, rl
	movq		rl, q1

	vmovq		A1xmm, rl
	movq		rl, q2
	vpextrq         $1, A1xmm, rl
	movq		rl, q3

	vmovq		A2xmm, rl
	movq		rl, q4
	vpextrq         $1, A2xmm, rl
	movq		rl, q5

	vmovq		A3xmm, rl
	movq		rl, q6
	vpextrq         $1, A3xmm, rl
	movq		rl, q7


	#####################################################################
	#####################################################################
	popq		%rsi

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


	
	### rerange RRp to A ###
 
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


	### Transfer qinv to montgomery form in p ###
	### qinv*RRp*R^(-1)mod p ###
	call montmul1024



	####################################################################
	####################################################################

	#### store A ####
	store_A


	#### load sub result ####
	popq	%rax


	### load Rq to A B ###
	vmovdqu 	256(%rax), A0xmm
	vmovdqu 	16+256(%rax), A1xmm
	vmovdqu 	32+256(%rax), A2xmm
	vmovdqu 	48+256(%rax), A3xmm
	vmovdqu 	64+256(%rax), B0xmm
	vmovdqu 	80+256(%rax), B1xmm
	vmovdqu 	96+256(%rax), B2xmm
	vmovdqu 	112+256(%rax), B3xmm

	
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


	### rerange RRp to B ###
 
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

		
	#### restore A ####
	restore_A


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3

	
	### compute R*qinv ###
	call montmul1024


	####################################################################
	####################################################################

	### rerange RRp to B ###
 	vshufpd		$0x05, A0, A0, A0		#imm=0101
	vshufpd		$0x05, A1, A1, A1		#imm=0101
	vshufpd		$0x05, A2, A2, A2		#imm=0101
	vshufpd		$0x05, A3, A3, A3		#imm=0101
	vshufpd		$0x05, B0, B0, B0		#imm=0101
	vshufpd		$0x05, B1, B1, B1		#imm=0101
	vshufpd		$0x05, B2, B2, B2		#imm=0101
	vshufpd		$0x05, B3, B3, B3		#imm=0101


	### set A to 1 ###
	vpxor		T3, T3, T3
	vblendpd	$0x05, T3, A1, A1		#imm=0101
	vblendpd	$0x05, T3, A2, A2		#imm=0101
	vblendpd	$0x05, T3, A3, A3		#imm=0101
	vblendpd	$0x05, T3, B0, B0		#imm=0101
	vblendpd	$0x05, T3, B1, B1		#imm=0101
	vblendpd	$0x05, T3, B2, B2		#imm=0101
	vblendpd	$0x05, T3, B3, B3		#imm=0101	

	movq		$1, %rax
	vmovq		%rax, T3xmm
	vblendpd	$0x01, T3, A0, A0		#imm=0001	


	#### prepare M ####
	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3


	### compute result*1*R^(-1)mod p ###
	call montmul1024

*/

	ret
	.size	mul_qinv, .-mul_qinv





########################################################################################
########################################################################################
########################################################################################
########################################################################################



	.globl 	mul_h_q_add_Rq
	.type  	mul_h_q_add_Rq, @function
	.align 	64

mul_h_q_add_Rq:

	### h stored in A ### 
/*
	movq		%mm0, %rsi
	movq		%mm1, %rax
	pushq		%rax
*/

	########################################################################################
	########################################################################################
	#### load q ####

	#### store A ####
	store_A


	#####################################################################
	### load q to A B and Dec ###
	vpxorq  %ymm1,     %ymm1,     %ymm1
    movq    $0x0123456789ABCDEF,    %rax
    vmovq   %rax,   %xmm1
    valignq     $1, %ymm0, %ymm1,  %ymm0
    movq    $0xFEDCBA9876543210,    %rax
    vmovq   %rax,   %xmm1
    valignq     $3, %ymm0, %ymm1,  %ymm0

	vmovdqu64 %zmm15 ,%zmm7 # no forget !!!!!

	vmovdqu64 (%rsi), %zmm16
	vmovdqu64 64(%rsi), %zmm17

    
    mov   $0x03, %eax # 0000 0011
    kmovd %eax, %k1    
    mov   $0x0C, %eax # 0000 1100
    kmovd %eax, %k2
    mov   $0x30, %eax # 0011 0000
    kmovd %eax, %k3
    mov   $0xC0, %eax # 1100 0000
    kmovd %eax, %k4

    vpcompressq %zmm16,%zmm15 {%k1}{z}
	aes_dec
	vpexpandq %zmm15,%zmm16 {%k1}

	vpcompressq %zmm16,%zmm15 {%k2}{z}
	aes_dec
	vpexpandq %zmm15,%zmm16 {%k2}

    vpcompressq %zmm16,%zmm15 {%k3}{z}
	aes_dec
	vpexpandq %zmm15,%zmm16 {%k3}

    vpcompressq %zmm16,%zmm15 {%k4}{z}
	aes_dec
	vpexpandq %zmm15,%zmm16 {%k4}

	vpcompressq %zmm17,%zmm15 {%k1}{z}
	aes_dec
	vpexpandq %zmm15,%zmm17 {%k1}

	vpcompressq %zmm17,%zmm15 {%k2}{z}
	aes_dec
	vpexpandq %zmm15,%zmm17 {%k2}

    vpcompressq %zmm17,%zmm15 {%k3}{z}
	aes_dec
	vpexpandq %zmm15,%zmm17 {%k3}

    vpcompressq %zmm17,%zmm15 {%k4}{z}
	aes_dec
	vpexpandq %zmm15,%zmm17 {%k4}
	
	vmovdqu64 %zmm7 ,%zmm15

	### load p to A B ###
    
    vpxorq  %zmm0,     %zmm0,     %zmm0
	valignq $0x00,%zmm16 ,%zmm0, %zmm0{%k1}{z} #shift 0*64

    vpxorq  %zmm1,     %zmm1,     %zmm1
	valignq $0x02,%zmm16 ,%zmm1, %zmm1{%k1}{z} #shift 2*64

	vpxorq  %zmm2,     %zmm2,     %zmm2
	valignq $0x04,%zmm16,%zmm2, %zmm2{%k1}{z} #shift 4*64

    vpxorq  %zmm3,     %zmm3,     %zmm3
	valignq $0x06,%zmm16,%zmm3, %zmm3{%k1}{z} #shift 6*64

	vpxorq  %zmm4,     %zmm4,     %zmm4
	valignq $0x00,%zmm17,%zmm4, %zmm4{%k1}{z} #shift 0*64

    vpxorq  %zmm5,     %zmm5,     %zmm5
	valignq $0x02,%zmm17,%zmm5, %zmm5{%k1}{z} #shift 2*64

	vpxorq  %zmm6,     %zmm6,     %zmm6
	valignq $0x04,%zmm17, %zmm6, %zmm6{%k1}{z} #shift 4*64

    vpxorq  %zmm7,     %zmm7,     %zmm7
	valignq $0x06,%zmm17,%zmm7, %zmm7{%k1}{z} #shift 6*64

	#################################
	/*#调试用：
	vmovdqu64		A0xmm,		(%rsi)
	vmovdqu64		A1xmm,		16(%rsi)
	vmovdqu64		A2xmm,		32(%rsi)
	vmovdqu64		A3xmm,		48(%rsi)
	vmovdqu64		B0xmm,		64(%rsi)
	vmovdqu64		B1xmm,		80(%rsi)
	vmovdqu64		B2xmm,		96(%rsi)
	vmovdqu64		B3xmm,		112(%rsi)
*/

	###############################

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

	### rerange q to B ###
 
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


	#### restore A ####
	restore_A
/*
	vmovdqu64 	A0, %ymm24
	vmovdqu64 	A1, %ymm25
	vmovdqu64 	A2, %ymm26
	vmovdqu64 	A3, %ymm27
*/
		
	### compute m*h ###
	call mul1024

/*	### rerange mul result to M ###

	vperm2i128	$0x20, T0, M0, M0
	vperm2i128	$0x20, T1, M1, M1
	vperm2i128	$0x20, T2, M2, M2
	vperm2i128	$0x20, T3, M3, M3
*/
/*
	vmovdqu64 	M0, %ymm24  ##R[0] R[8] 0 0 
	vmovdqu64 	M1, %ymm25
	vmovdqu64 	M2, %ymm26
	vmovdqu64 	M3, %ymm27
*/

	########################################################################################
	########################################################################################
#	popq	%rax

	### load Rq to A B ###
	vmovdqu64	%zmm21,		%zmm24
	vmovdqu64	%zmm27,		%zmm25


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

	/*
	vmovdqu 	128(%rax), A0xmm
	vmovdqu 	16+128(%rax), A1xmm
	vmovdqu 	32+128(%rax), A2xmm
	vmovdqu 	48+128(%rax), A3xmm
	vmovdqu 	64+128(%rax), B0xmm
	vmovdqu 	80+128(%rax), B1xmm
	vmovdqu 	96+128(%rax), B2xmm
	vmovdqu 	112+128(%rax), B3xmm
	*/
	
/*	#### load key ####
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


	########################################################################################
	########################################################################################
	### add Rq and result(A,B) ###

	### rerange mul result from M to M T ###

	vperm2i128	$0x21, T0, M0, T0
	vperm2i128	$0x21, T1, M1, T1
	vperm2i128	$0x21, T2, M2, T2
	vperm2i128	$0x21, T3, M3, T3
*/

	### A=A+P ### 
	xorq		%rcx, %rcx
	movq	s8,	%rcx
	vmovq		%xmm31, %rdi

	### low 1024bit ###
	vmovq		A0xmm, %rax
	vmovq		M0xmm, %rbx
	addq		%rbx, %rax
	# vpinsrq		$0, %rax, A0xmm, A0xmm		#R[0]
	movq	%rax,	(%rdi)

	vmovq		B0xmm, %rax
	vmovq		T0xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$0, %rax, B0xmm, B0xmm		#R[1]
	movq	%rax,	8(%rdi)

	vmovq		A1xmm, %rax
	vmovq		M1xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$0, %rax, A1xmm, A1xmm		#R[2]
	movq	%rax,	16(%rdi)	

	vmovq		B1xmm, %rax
	vmovq		T1xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$0, %rax, B1xmm, B1xmm		#R[3]
	movq	%rax,	24(%rdi)	

	vmovq		A2xmm, %rax
	vmovq		M2xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$0, %rax, A2xmm, A2xmm		#R[4]
	movq	%rax,	32(%rdi)	

	vmovq		B2xmm, %rax
	vmovq		T2xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$0, %rax, B2xmm, B2xmm		#R[5]	
	movq	%rax,	40(%rdi)

	vmovq		A3xmm, %rax
	vmovq		M3xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$0, %rax, A3xmm, A3xmm		#R[6]	
	movq	%rax,	48(%rdi)

	vmovq		B3xmm, %rax
	vmovq		T3xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$0, %rax, B3xmm, B3xmm		#R[7]	
	movq	%rax,	56(%rdi)	

	
	vpextrq         $1, A0xmm, %rax
	vpextrq         $1, M0xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, A0xmm, A0xmm		#R[8]
	movq	%rax,	64(%rdi)

	vpextrq         $1, B0xmm, %rax
	vpextrq         $1, T0xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, B0xmm, B0xmm			#R[9]
	movq	%rax,	72(%rdi)

	vpextrq         $1, A1xmm, %rax
	vpextrq         $1, M1xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, A1xmm, A1xmm			#R[10]
	movq	%rax,	80(%rdi)	

	vpextrq         $1, B1xmm, %rax
	vpextrq         $1, T1xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, B1xmm, B1xmm			#R[11]	
	movq	%rax,	88(%rdi)

	vpextrq         $1, A2xmm, %rax
	vpextrq         $1, M2xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, A2xmm, A2xmm			#R[12]
	movq	%rax,	96(%rdi)	

	vpextrq         $1, B2xmm, %rax
	vpextrq         $1, T2xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, B2xmm, B2xmm			#R[13]
	movq	%rax,	104(%rdi)	

	vpextrq         $1, A3xmm, %rax
	vpextrq         $1, M3xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, A3xmm, A3xmm			#R[14]	
	movq	%rax,	112(%rdi)

	vpextrq         $1, B3xmm, %rax
	vpextrq         $1, T3xmm, %rbx
	adcq		%rbx, %rax
	# vpinsrq		$1, %rax, B3xmm, B3xmm			#R[15]
	movq	%rax,	120(%rdi)		


	################################

	### high 1024bit, for carry ###
	movq		r0, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, M0xmm, M0xmm		#R[16]
	movq	%rax,	128(%rdi)

	movq		r1, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, T0xmm, T0xmm		#R[17]
	movq	%rax,	136(%rdi)

	movq		r2, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, M1xmm, M1xmm		#R[18]
	movq	%rax,	144(%rdi)	

	movq		r3, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, T1xmm, T1xmm		#R[19]	
	movq	%rax,	152(%rdi)

	movq		r4, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, M2xmm, M2xmm		#R[20]	
	movq	%rax,	160(%rdi)

	movq		r5, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, T2xmm, T2xmm			#R[21]	
	movq	%rax,	168(%rdi)

	movq		r6, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, M3xmm, M3xmm		#R[22]	
	movq	%rax,	176(%rdi)

	movq		r7, %rax
	adcq		$0, %rax
	# vpinsrq		$0, %rax, T3xmm, T3xmm		#R[23]	
	movq	%rax,	184(%rdi)	


	adcq		$0, s4
	# vpinsrq		$1, s4, M0xmm, M0xmm		#R[24]
	movq	s4,	192(%rdi)

	adcq		$0, s5
	# vpinsrq		$1, s5, T0xmm, T0xmm		#R[25]
	movq	s5,	200(%rdi)

	adcq		$0, s6
	# vpinsrq		$1, s6, M1xmm, M1xmm		#R[26]	
	movq	s6,	208(%rdi)

	adcq		$0, s7
	# vpinsrq		$1, s7, T1xmm, T1xmm		#R[27]	
	movq	s7,	216(%rdi)

	adcq		$0, %rcx
	# vpinsrq		$1, s8, M2xmm, M2xmm		#R[28]
	movq	%rcx,	224(%rdi)	

	adcq		$0, s9
	# vpinsrq		$1, s9, T2xmm, T2xmm		#R[29]	
	movq	s9,	232(%rdi)

	adcq		$0, s0
	# vpinsrq		$1, s0, M3xmm, M3xmm		#R[30]	
	movq	s0,	240(%rdi)

	adcq		$0, s1
	# vpinsrq		$1, s1, T3xmm, T3xmm		#R[31]	
	movq	s1,	248(%rdi)	
/*
	vmovdqu64 	A0, %ymm24
	vmovdqu64 	A1, %ymm25
	vmovdqu64 	A2, %ymm26
	vmovdqu64 	A3, %ymm27
*/
/*
	### rerange final result ###

	vperm2i128	$0x20, B0, A0, A0
	vperm2i128	$0x20, B1, A1, A1
	vperm2i128	$0x20, B2, A2, A2
	vperm2i128	$0x20, B3, A3, A3

	vperm2i128	$0x20, T0, M0, M0
	vperm2i128	$0x20, T1, M1, M1
	vperm2i128	$0x20, T2, M2, M2
	vperm2i128	$0x20, T3, M3, M3

	vpermq		$0xD8, A0, A0			#imm=3120
	vpermq		$0xD8, A1, A1			#imm=3120
	vpermq		$0xD8, A2, A2			#imm=3120
	vpermq		$0xD8, A3, A3			#imm=3120
	vpermq		$0xD8, M0, M0			#imm=3120
	vpermq		$0xD8, M1, M1			#imm=3120
	vpermq		$0xD8, M2, M2			#imm=3120
	vpermq		$0xD8, M3, M3			#imm=3120

	vmovdqa		M0, B0
	vmovdqa		M1, B1
	vmovdqa		M2, B2
	vmovdqa		M3, B3
	
*/
	ret
	.size	mul_h_q_add_Rq, .-mul_h_q_add_Rq

