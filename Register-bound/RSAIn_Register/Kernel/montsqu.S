	#include "rsa_head.S"	

	.file	"montsqu.S"
	.text


	

##################################################################################################
	###							###	
	### 	montsqu(A,M,n0):				###
	###							###	
	###	R=A*A*R^(-1) mod M 				###
	###							###
	###							###
##################################################################################################



/* 16 256bit vector registers */
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




##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################




.macro	montsqu_1st_movq

##################################################################################################
	###							###	
	### 	1st part: A[0-7]*A[0-7] + M[0-7]*(q0-q7) 	###
	###							###
	###	sum 576=65+73*7					###
	###							###
##################################################################################################
	###							###
	### 	1st_0: A[0-7]*A[0] + M[0-7]*q0 			###
	###	sum 65=11+3+17*3				###
	###							###
	###########################################################

	##### A[0 2 4 6]*B[0] #####
	xorq		s8, s8
	xorq		s9, s9

	vmovq           A0xmm, bi         	#A[0]

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

	vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q0
        adc             rl, s4
        adc             rh, s5

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q0
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8

	##### A[1 3 5 7]*B[0] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[0]
	add		rl, s1
	adc		rh, s2

	vmovq           B1xmm, ai           #A[3]
        mulx            bi, rl, rh              #A[3]*B[0]
        adc             rl, s3
        adc             rh, s4

	vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[0]
        adc             rl, s5
        adc             rh, s6

	vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[0]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9

	##### M[1 3 5 7]*q0 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q0
        add             rl, s1
        adc             rh, s2

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q0
        adc             rl, s3
        adc             rh, s4

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q0
        adc             rl, s5
        adc             rh, s6

        vmovq           T3xmm, mi           #M[7]
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
        vmovq           B0xmm, bi         	#A[1]

        vmovq           A0xmm, ai           #A[0]
        mulx            bi, rl, rh              #A[0]*B[1]
	add		rl, s1
	adc		rh, s2

	vmovq           A1xmm, ai           #A[2]
        mulx            bi, rl, rh              #A[2]*B[1]
        adc             rl, s3
        adc             rh, s4

	vmovq           A2xmm, ai           #A[4]
        mulx            bi, rl, rh              #A[4]*B[1]
        adc             rl, s5
        adc             rh, s6

	vmovq           A3xmm, ai           #A[6]
        mulx            bi, rl, rh              #A[6]*B[1]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	
        ##### q1 #####
        movq            n0, %rdx
        mulx            s1, q, rh               #q1=s1*n0
        movq            q, q1                   #q1
	
	##### M[0 2 4 6]*q1 #####
        vmovq           M0xmm, mi           #M[0]
        mulx            q, rl, rh               #M[0]*q1
        add             rl, s1
        adc             rh, s2

        vmovq           M1xmm, mi           #M[2]
        mulx            q, rl, rh               #M[2]*q1
        adc             rl, s3
        adc             rh, s4

        vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q1
        adc             rl, s5
        adc             rh, s6

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q1
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

	##### A[1 3 5 7]*B[1] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[1]
        add             rl, s2
        adc             rh, s3

        vmovq           B1xmm, ai           #A[3]
        mulx            bi, rl, rh              #A[3]*B[1]
        adc             rl, s4
        adc             rh, s5

        vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[1]
        adc             rl, s6
        adc             rh, s7

        vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[1]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

        ##### M[1 3 5 7]*q1 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q1
        add             rl, s2
        adc             rh, s3

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q1
        adc             rl, s4
        adc             rh, s5

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q1
        adc             rl, s6
        adc             rh, s7

        vmovq           T3xmm, mi           #M[7]
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
        vmovq           A1xmm, bi         	#A[2]

        vmovq           A0xmm, ai           #A[0]
        mulx            bi, rl, rh              #A[0]*B[2]
	add		rl, s2
	adc		rh, s3

	vmovq           A1xmm, ai           #A[2]
        mulx            bi, rl, rh              #A[2]*B[2]
        adc             rl, s4
        adc             rh, s5

	vmovq           A2xmm, ai           #A[4]
        mulx            bi, rl, rh              #A[4]*B[2]
        adc             rl, s6
        adc             rh, s7

	vmovq           A3xmm, ai           #A[6]
        mulx            bi, rl, rh              #A[6]*B[2]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	
        ##### q2 #####
        movq            n0, %rdx
        mulx            s2, q, rh               #q2=s2*n0
        movq            q, q2                   #q2
	
	##### M[0 2 4 6]*q2 #####
        vmovq           M0xmm, mi           #M[0]
        mulx            q, rl, rh               #M[0]*q2
        add             rl, s2
        adc             rh, s3

        vmovq           M1xmm, mi           #M[2]
        mulx            q, rl, rh               #M[2]*q2
        adc             rl, s4
        adc             rh, s5

        vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q2
        adc             rl, s6
        adc             rh, s7

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q2
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

	##### A[1 3 5 7]*B[2] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[2]
        add             rl, s3
        adc             rh, s4

        vmovq           B1xmm, ai           #A[3]
        mulx            bi, rl, rh              #A[3]*B[2]
        adc             rl, s5
        adc             rh, s6

        vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[2]
        adc             rl, s7
        adc             rh, s8

        vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[2]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

        ##### M[1 3 5 7]*q2 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q2
        add             rl, s3
        adc             rh, s4

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q2
        adc             rl, s5
        adc             rh, s6

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q2
        adc             rl, s7
        adc             rh, s8

        vmovq           T3xmm, mi           #M[7]
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
        vmovq           B1xmm, bi         	#A[3]

        vmovq           A0xmm, ai           #A[0]
        mulx            bi, rl, rh              #A[0]*B[3]
	add		rl, s3
	adc		rh, s4

	vmovq           A1xmm, ai           #A[2]
        mulx            bi, rl, rh              #A[2]*B[3]
        adc             rl, s5
        adc             rh, s6

	vmovq           A2xmm, ai           #A[4]
        mulx            bi, rl, rh              #A[4]*B[3]
        adc             rl, s7
        adc             rh, s8

	vmovq           A3xmm, ai           #A[6]
        mulx            bi, rl, rh              #A[6]*B[3]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	
        ##### q3 #####
        movq            n0, %rdx
        mulx            s3, q, rh               #q3=s3*n0
        movq            q, q3                   #q3
	
	##### M[0 2 4 6]*q3 #####
        vmovq           M0xmm, mi           #M[0]
        mulx            q, rl, rh               #M[0]*q3
        add             rl, s3
        adc             rh, s4

        vmovq           M1xmm, mi           #M[2]
        mulx            q, rl, rh               #M[2]*q3
        adc             rl, s5
        adc             rh, s6

        vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q3
        adc             rl, s7
        adc             rh, s8

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q3
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

	##### A[1 3 5 7]*B[3] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[3]
        add             rl, s4
        adc             rh, s5

        vmovq           B1xmm, ai           #A[3]
        mulx            bi, rl, rh              #A[3]*B[3]
        adc             rl, s6
        adc             rh, s7

        vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[3]
        adc             rl, s8
        adc             rh, s9

        vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[3]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

        ##### M[1 3 5 7]*q3 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q3
        add             rl, s4
        adc             rh, s5

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q3
        adc             rl, s6
        adc             rh, s7

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q3
        adc             rl, s8
        adc             rh, s9

        vmovq           T3xmm, mi           #M[7]
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
        vmovq           A2xmm, bi         	#A[4]

        vmovq           A0xmm, ai           #A[0]
        mulx            bi, rl, rh              #A[0]*B[4]
	add		rl, s4
	adc		rh, s5

	vmovq           A1xmm, ai           #A[2]
        mulx            bi, rl, rh              #A[2]*B[4]
        adc             rl, s6
        adc             rh, s7

	vmovq           A2xmm, ai           #A[4]
        mulx            bi, rl, rh              #A[4]*B[4]
        adc             rl, s8
        adc             rh, s9

	vmovq           A3xmm, ai           #A[6]
        mulx            bi, rl, rh              #A[6]*B[4]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	
        ##### q4 #####
        movq            n0, %rdx
        mulx            s4, q, rh               #q4=s4*n0
        movq            q, q4                   #q4
	
	##### M[0 2 4 6]*q4 #####
        vmovq           M0xmm, mi           #M[0]
        mulx            q, rl, rh               #M[0]*q4
        add             rl, s4
        adc             rh, s5

        vmovq           M1xmm, mi           #M[2]
        mulx            q, rl, rh               #M[2]*q4
        adc             rl, s6
        adc             rh, s7

        vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q4
        adc             rl, s8
        adc             rh, s9

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q4
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

	##### A[1 3 5 7]*B[4] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[4]
        add             rl, s5
        adc             rh, s6

        vmovq           B1xmm, ai           #A[3]
        mulx            bi, rl, rh              #A[3]*B[4]
        adc             rl, s7
        adc             rh, s8

        vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[4]
        adc             rl, s9
        adc             rh, s0

        vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[4]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

        ##### M[1 3 5 7]*q4 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q4
        add             rl, s5
        adc             rh, s6

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q4
        adc             rl, s7
        adc             rh, s8

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q4
        adc             rl, s9
        adc             rh, s0

        vmovq           T3xmm, mi           #M[7]
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
        vmovq           B2xmm, bi         	#A[5]

        vmovq           A0xmm, ai           #A[0]
        mulx            bi, rl, rh              #A[0]*B[5]
	add		rl, s5
	adc		rh, s6

	vmovq           A1xmm, ai           #A[2]
        mulx            bi, rl, rh              #A[2]*B[5]
        adc             rl, s7
        adc             rh, s8

	vmovq           A2xmm, ai           #A[4]
        mulx            bi, rl, rh              #A[4]*B[5]
        adc             rl, s9
        adc             rh, s0

	vmovq           A3xmm, ai           #A[6]
        mulx            bi, rl, rh              #A[6]*B[5]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	
        ##### q5 #####
        movq            n0, %rdx
        mulx            s5, q, rh               #q5=s5*n0
        movq            q, q5                   #q5
	
	##### M[0 2 4 6]*q5 #####
        vmovq           M0xmm, mi           #M[0]
        mulx            q, rl, rh               #M[0]*q5
        add             rl, s5
        adc             rh, s6

        vmovq           M1xmm, mi           #M[2]
        mulx            q, rl, rh               #M[2]*q5
        adc             rl, s7
        adc             rh, s8

        vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q5
        adc             rl, s9
        adc             rh, s0

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q5
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

	##### A[1 3 5 7]*B[5] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[5]
        add             rl, s6
        adc             rh, s7

        vmovq           B1xmm, ai           #A[3]
        mulx            bi, rl, rh              #A[3]*B[5]
        adc             rl, s8
        adc             rh, s9

        vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[5]
        adc             rl, s0
        adc             rh, s1

        vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[5]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

        ##### M[1 3 5 7]*q5 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q5
        add             rl, s6
        adc             rh, s7

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q5
        adc             rl, s8
        adc             rh, s9

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q5
        adc             rl, s0
        adc             rh, s1

        vmovq           T3xmm, mi           #M[7]
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
        vmovq           A3xmm, bi         	#A[6]

        vmovq           A0xmm, ai           #A[0]
        mulx            bi, rl, rh              #A[0]*B[6]
	add		rl, s6
	adc		rh, s7

	vmovq           A1xmm, ai           #A[2]
        mulx            bi, rl, rh              #A[2]*B[6]
        adc             rl, s8
        adc             rh, s9

	vmovq           A2xmm, ai           #A[4]
        mulx            bi, rl, rh              #A[4]*B[6]
        adc             rl, s0
        adc             rh, s1

	vmovq           A3xmm, ai           #A[6]
        mulx            bi, rl, rh              #A[6]*B[6]
        adc             rl, s2
        adc             rh, s3
	adc		$0, s4
	
        ##### q6 #####
        movq            n0, %rdx
        mulx            s6, q, rh               #q6=s6*n0
        movq            q, q6                   #q6
	
	##### M[0 2 4 6]*q6 #####
        vmovq           M0xmm, mi           #M[0]
        mulx            q, rl, rh               #M[0]*q6
        add             rl, s6
        adc             rh, s7

        vmovq           M1xmm, mi           #M[2]
        mulx            q, rl, rh               #M[2]*q6
        adc             rl, s8
        adc             rh, s9

        vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q6
        adc             rl, s0
        adc             rh, s1

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q6
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

	##### A[1 3 5 7]*B[6] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[6]
        add             rl, s7
        adc             rh, s8

        vmovq           B1xmm, ai          	#A[3]
        mulx            bi, rl, rh              #A[3]*B[6]
        adc             rl, s9
        adc             rh, s0

        vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[6]
        adc             rl, s1
        adc             rh, s2

        vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[6]
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5

        ##### M[1 3 5 7]*q6 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q6
        add             rl, s7
        adc             rh, s8

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q6
        adc             rl, s9
        adc             rh, s0

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q6
        adc             rl, s1
        adc             rh, s2

        vmovq           T3xmm, mi           #M[7]
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
        vmovq           B3xmm, bi         	#A[7]

        vmovq           A0xmm, ai           #A[0]
        mulx            bi, rl, rh              #A[0]*B[7]
	add		rl, s7
	adc		rh, s8

	vmovq           A1xmm, ai           #A[2]
        mulx            bi, rl, rh              #A[2]*B[7]
        adc             rl, s9
        adc             rh, s0

	vmovq           A2xmm, ai           #A[4]
        mulx            bi, rl, rh              #A[4]*B[7]
        adc             rl, s1
        adc             rh, s2

	vmovq           A3xmm, ai           #A[6]
        mulx            bi, rl, rh              #A[6]*B[7]
        adc             rl, s3
        adc             rh, s4
	adc		$0, s5
	
        ##### q7 #####
        movq            n0, %rdx
        mulx            s7, q, rh               #q7=s7*n0
        movq            q, q7                   #q7
	
	##### M[0 2 4 6]*q7 #####
        vmovq           M0xmm, mi           #M[0]
        mulx            q, rl, rh               #M[0]*q7
        add             rl, s7
        adc             rh, s8

        vmovq           M1xmm, mi           #M[2]
        mulx            q, rl, rh               #M[2]*q7
        adc             rl, s9
        adc             rh, s0

        vmovq           M2xmm, mi           #M[4]
        mulx            q, rl, rh               #M[4]*q7
        adc             rl, s1
        adc             rh, s2

        vmovq           M3xmm, mi           #M[6]
        mulx            q, rl, rh               #M[6]*q7
        adc             rl, s3
        adc             rh, s4
        adc             $0, s5

	##### A[1 3 5 7]*B[7] #####
        vmovq           B0xmm, ai           #A[1]
        mulx            bi, rl, rh              #A[1]*B[7]
        add             rl, s8
        adc             rh, s9

        vmovq           B1xmm, ai           #A[3]
        mulx            bi, rl, rh              #A[3]*B[7]
        adc             rl, s0
        adc             rh, s1

        vmovq           B2xmm, ai           #A[5]
        mulx            bi, rl, rh              #A[5]*B[7]
        adc             rl, s2
        adc             rh, s3

        vmovq           B3xmm, ai           #A[7]
        mulx            bi, rl, rh              #A[7]*B[7]
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

        ##### M[1 3 5 7]*q7 #####
        vmovq           T0xmm, mi           #M[1]
        mulx            q, rl, rh               #M[1]*q7
        add             rl, s8
        adc             rh, s9

        vmovq           T1xmm, mi           #M[3]
        mulx            q, rl, rh               #M[3]*q7
        adc             rl, s0
        adc             rh, s1

        vmovq           T2xmm, mi           #M[5]
        mulx            q, rl, rh               #M[5]*q7
        adc             rl, s2
        adc             rh, s3

        vmovq           T3xmm, mi           #M[7]
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






##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################



.macro	montsqu_2nd_movq

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



	### store T3 ###
	# vperm2i128	$0x20, T3, T0, T0
	/*
	vmovq		T3xmm, bi
	vpextrq         $1, T3xmm, q
	vperm2i128	$0x01, T3, T3, T3
	vmovq		T3xmm, rl
	vpextrq         $1, T3xmm, rh
	*/
	
	
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


	### restore T3 ###
	# vperm2i128	$0x31, T3, T0, T3
	/*
	vmovq		rl, T3xmm
	vpinsrq		$1, rh, T3xmm, T3xmm
	vperm2i128	$0x01, T3, T3, T3
	pinsrq		$0, bi, T3xmm
	pinsrq		$1, q, T3xmm
	*/


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

        vmovq           A0xmm, bi          #B[0]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[0]
	add		rl, s8
	adc		rh, s9

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[0]
        adc             rl, s0
        adc             rh, s1

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[0]
        adc             rl, s2
        adc             rh, s3

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[0]
        adc             rl, s4
        adc             rh, s5
	adc		$0, s6
	
        ##### q0 #####
        movq            q0, q                  
	
	##### M[8 10 12 14]*q0 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q0
        add             rl, s8
        adc             rh, s9

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q0
        adc             rl, s0
        adc             rh, s1

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q0
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q0
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6

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

        ##### M[9 11 13 15]*q0 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q0
        add             rl, s9
        adc             rh, s0

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q0
        adc             rl, s1
        adc             rh, s2

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q0
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q0
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[8] #####
        vpextrq         $1, A0xmm, bi          #B[8]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[8]
	add		rl, s8
	adc		rh, s9

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[8]
        adc             rl, s0
        adc             rh, s1

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[8]
        adc             rl, s2
        adc             rh, s3

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q8
        add             rl, s8
        adc             rh, s9

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q8
        adc             rl, s0
        adc             rh, s1

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q8
        adc             rl, s2
        adc             rh, s3

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q8
        adc             rl, s4
        adc             rh, s5
        adc             $0, s6
	adc		$0, s7

	##### A[1 3 5 7]*B[8] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[8]
        add             rl, s9
        adc             rh, s0

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[8]
        adc             rl, s1
        adc             rh, s2

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[8]
        adc             rl, s3
        adc             rh, s4

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[8]
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

        ##### M[1 3 5 7]*q8 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q8
        add             rl, s9
        adc             rh, s0

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q8
        adc             rl, s1
        adc             rh, s2

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q8
        adc             rl, s3
        adc             rh, s4

        vmovq           T3xmm, mi          #M[7]
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

        vmovq           B0xmm, bi          #A[1]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[1]
	add		rl, s9
	adc		rh, s0

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[1]
        adc             rl, s1
        adc             rh, s2

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[1]
        adc             rl, s3
        adc             rh, s4

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[1]
        adc             rl, s5
        adc             rh, s6
	adc		$0, s7
	
        ##### q1 #####
        movq            q1, q                  
	
	##### M[8 10 12 14]*q1 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q1
        add             rl, s9
        adc             rh, s0

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q1
        adc             rl, s1
        adc             rh, s2

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q1
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q1
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7

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

        ##### M[9 11 13 15]*q1 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q1
        add             rl, s0
        adc             rh, s1

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q1
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q1
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q1
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[9] #####
        vpextrq         $1, B0xmm, bi          #A[9]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[9]
	add		rl, s9
	adc		rh, s0

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[9]
        adc             rl, s1
        adc             rh, s2

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[9]
        adc             rl, s3
        adc             rh, s4

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q9
        add             rl, s9
        adc             rh, s0

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q9
        adc             rl, s1
        adc             rh, s2

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q9
        adc             rl, s3
        adc             rh, s4

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q9
        adc             rl, s5
        adc             rh, s6
        adc             $0, s7
	adc		$0, s8

	##### A[1 3 5 7]*B[9] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[9]
        add             rl, s0
        adc             rh, s1

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[9]
        adc             rl, s2
        adc             rh, s3

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[9]
        adc             rl, s4
        adc             rh, s5

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[9]
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

        ##### M[1 3 5 7]*q9 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q9
        add             rl, s0
        adc             rh, s1

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q9
        adc             rl, s2
        adc             rh, s3

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q9
        adc             rl, s4
	adc             rh, s5

	vmovq           T3xmm, mi          #M[7]
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

        vmovq           A1xmm, bi          #B[2]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[2]
	add		rl, s0
	adc		rh, s1

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[2]
        adc             rl, s2
        adc             rh, s3

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[2]
        adc             rl, s4
        adc             rh, s5

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[2]
        adc             rl, s6
        adc             rh, s7
	adc		$0, s8
	
        ##### q2 #####
        movq            q2, q                  
	
	##### M[8 10 12 14]*q2 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q2
        add             rl, s0
        adc             rh, s1

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q2
        adc             rl, s2
        adc             rh, s3

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q2
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q2
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8

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

        ##### M[9 11 13 15]*q2 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q2
        add             rl, s1
        adc             rh, s2

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q2
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q2
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q2
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[10] #####
        vpextrq         $1, A1xmm, bi          #B[10]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[10]
	add		rl, s0
	adc		rh, s1

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[10]
        adc             rl, s2
        adc             rh, s3

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[10]
        adc             rl, s4
        adc             rh, s5

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q10
        add             rl, s0
        adc             rh, s1

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q10
        adc             rl, s2
        adc             rh, s3

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q10
        adc             rl, s4
        adc             rh, s5

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q10
        adc             rl, s6
        adc             rh, s7
        adc             $0, s8
	adc		$0, s9

	##### A[1 3 5 7]*B[10] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[10]
        add             rl, s1
        adc             rh, s2

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[10]
        adc             rl, s3
        adc             rh, s4

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[10]
        adc             rl, s5
        adc             rh, s6

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[10]
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

        ##### M[1 3 5 7]*q10 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q10
        add             rl, s1
        adc             rh, s2

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q10
        adc             rl, s3
        adc             rh, s4

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q10
        adc             rl, s5
        adc             rh, s6

        vmovq           T3xmm, mi          #M[7]
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

        vmovq           B1xmm, bi          #B[3]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[3]
	add		rl, s1
	adc		rh, s2

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[3]
        adc             rl, s3
        adc             rh, s4

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[3]
        adc             rl, s5
        adc             rh, s6

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[3]
        adc             rl, s7
        adc             rh, s8
	adc		$0, s9
	
        ##### q3 #####
        movq            q3, q                  
	
	##### M[8 10 12 14]*q3 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q3
        add             rl, s1
        adc             rh, s2

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q3
        adc             rl, s3
        adc             rh, s4

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q3
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q3
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9

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

        ##### M[9 11 13 15]*q3 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q3
        add             rl, s2
        adc             rh, s3

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q3
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q3
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q3
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[11] #####
        vpextrq         $1, B1xmm, bi          #B[11]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[11]
	add		rl, s1
	adc		rh, s2

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[11]
        adc             rl, s3
        adc             rh, s4

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[11]
        adc             rl, s5
        adc             rh, s6

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q11
        add             rl, s1
        adc             rh, s2

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q11
        adc             rl, s3
        adc             rh, s4

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q11
        adc             rl, s5
        adc             rh, s6

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q11
        adc             rl, s7
        adc             rh, s8
        adc             $0, s9
	adc		$0, s0

	##### A[1 3 5 7]*B[11] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[11]
        add             rl, s2
        adc             rh, s3

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[11]
        adc             rl, s4
        adc             rh, s5

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[11]
        adc             rl, s6
        adc             rh, s7

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[11]
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

        ##### M[1 3 5 7]*q11 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q11
        add             rl, s2
        adc             rh, s3

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q11
        adc             rl, s4
        adc             rh, s5

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q11
        adc             rl, s6
        adc             rh, s7

        vmovq           T3xmm, mi          #M[7]
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

        vmovq           A2xmm, bi          #B[4]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[4]
	add		rl, s2
	adc		rh, s3

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[4]
        adc             rl, s4
        adc             rh, s5

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[4]
        adc             rl, s6
        adc             rh, s7

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[4]
        adc             rl, s8
        adc             rh, s9
	adc		$0, s0
	
        ##### q4 #####
        movq            q4, q                  
	
	##### M[8 10 12 14]*q4 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q4
        add             rl, s2
        adc             rh, s3

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q4
        adc             rl, s4
        adc             rh, s5

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q4
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q4
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0

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

        ##### M[9 11 13 15]*q4 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q4
        add             rl, s3
        adc             rh, s4

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q4
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q4
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q4
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[12] #####
        vpextrq         $1, A2xmm, bi          #B[12]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[12]
	add		rl, s2
	adc		rh, s3

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[12]
        adc             rl, s4
        adc             rh, s5

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[12]
        adc             rl, s6
        adc             rh, s7

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q12
        add             rl, s2
        adc             rh, s3

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q12
        adc             rl, s4
        adc             rh, s5

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q12
        adc             rl, s6
        adc             rh, s7

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q12
        adc             rl, s8
        adc             rh, s9
        adc             $0, s0
	adc		$0, s1

	##### A[1 3 5 7]*B[12] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[12]
        add             rl, s3
        adc             rh, s4

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[12]
        adc             rl, s5
        adc             rh, s6

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[12]
        adc             rl, s7
        adc             rh, s8

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[12]
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

        ##### M[1 3 5 7]*q12 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q12
        add             rl, s3
        adc             rh, s4

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q12
        adc             rl, s5
        adc             rh, s6

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q12
        adc             rl, s7
        adc             rh, s8

        vmovq           T3xmm, mi          #M[7]
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

        vmovq           B2xmm, bi          #B[5]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[5]
	add		rl, s3
	adc		rh, s4

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[5]
        adc             rl, s5
        adc             rh, s6

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[5]
        adc             rl, s7
        adc             rh, s8

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[5]
        adc             rl, s9
        adc             rh, s0
	adc		$0, s1
	
        ##### q5 #####
        movq            q5, q                  
	
	##### M[8 10 12 14]*q5 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q5
        add             rl, s3
        adc             rh, s4

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q5
        adc             rl, s5
        adc             rh, s6

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q5
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q5
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1

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

        ##### M[9 11 13 15]*q5 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q5
        add             rl, s4
        adc             rh, s5

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q5
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q5
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q5
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[13] #####
        vpextrq         $1, B2xmm, bi          #B[13]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[13]
	add		rl, s3
	adc		rh, s4

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[13]
        adc             rl, s5
        adc             rh, s6

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[13]
        adc             rl, s7
        adc             rh, s8

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q13
        add             rl, s3
        adc             rh, s4

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q13
        adc             rl, s5
        adc             rh, s6

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q13
        adc             rl, s7
        adc             rh, s8

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q13
        adc             rl, s9
        adc             rh, s0
        adc             $0, s1
	adc		$0, s2

	##### A[1 3 5 7]*B[13] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[13]
        add             rl, s4
        adc             rh, s5

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[13]
        adc             rl, s6
        adc             rh, s7

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[13]
        adc             rl, s8
        adc             rh, s9

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[13]
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

        ##### M[1 3 5 7]*q13 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q13
        add             rl, s4
        adc             rh, s5

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q13
        adc             rl, s6
        adc             rh, s7

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q13
        adc             rl, s8
        adc             rh, s9

        vmovq           T3xmm, mi          #M[7]
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

        vmovq           A3xmm, bi          #B[6]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[6]
	add		rl, s4
	adc		rh, s5

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[6]
        adc             rl, s6
        adc             rh, s7

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[6]
        adc             rl, s8
        adc             rh, s9

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[6]
        adc             rl, s0
        adc             rh, s1
	adc		$0, s2
	
        ##### q6 #####
        movq            q6, q                  
	
	##### M[8 10 12 14]*q6 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q6
        add             rl, s4
        adc             rh, s5

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q6
        adc             rl, s6
        adc             rh, s7

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q6
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q6
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2

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

        ##### M[9 11 13 15]*q6 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q6
        add             rl, s5
        adc             rh, s6

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q6
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q6
        adc             rl, s9
        adc             rh, s0

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q6
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[14] #####
        vpextrq         $1, A3xmm, bi          #B[14]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[14]
	add		rl, s4
	adc		rh, s5

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[14]
        adc             rl, s6
        adc             rh, s7

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[14]
        adc             rl, s8
        adc             rh, s9

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q14
        add             rl, s4
        adc             rh, s5

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q14
        adc             rl, s6
        adc             rh, s7

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q14
        adc             rl, s8
        adc             rh, s9

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q14
        adc             rl, s0
        adc             rh, s1
        adc             $0, s2
	adc		$0, s3

	##### A[1 3 5 7]*B[14] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[14]
        add             rl, s5
        adc             rh, s6

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[14]
        adc             rl, s7
        adc             rh, s8

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[14]
        adc             rl, s9
        adc             rh, s0

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[14]
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

        ##### M[1 3 5 7]*q14 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q14
        add             rl, s5
        adc             rh, s6

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q14
        adc             rl, s7
        adc             rh, s8

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q14
        adc             rl, s9
        adc             rh, s0

        vmovq           T3xmm, mi          #M[7]
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

        vmovq           B3xmm, bi          #B[7]

        vpextrq         $1, A0xmm, ai		#A[8]
        mulx            bi, rl, rh              #A[8]*B[7]
	add		rl, s5
	adc		rh, s6

	vpextrq         $1, A1xmm, ai          #A[10]
        mulx            bi, rl, rh              #A[10]*B[7]
        adc             rl, s7
        adc             rh, s8

	vpextrq         $1, A2xmm, ai          #A[12]
        mulx            bi, rl, rh              #A[12]*B[7]
        adc             rl, s9
        adc             rh, s0

	vpextrq         $1, A3xmm, ai          #A[14]
        mulx            bi, rl, rh              #A[14]*B[7]
        adc             rl, s1
        adc             rh, s2
	adc		$0, s3
	
        ##### q7 #####
        movq            q7, q                  
	
	##### M[8 10 12 14]*q7 #####
        vpextrq         $1, M0xmm, mi          #M[8]
        mulx            q, rl, rh               #M[8]*q7
        add             rl, s5
        adc             rh, s6

        vpextrq         $1, M1xmm, mi          #M[10]
        mulx            q, rl, rh               #M[10]*q7
        adc             rl, s7
        adc             rh, s8

        vpextrq         $1, M2xmm, mi          #M[12]
        mulx            q, rl, rh               #M[12]*q7
        adc             rl, s9
        adc             rh, s0

        vpextrq         $1, M3xmm, mi          #M[14]
        mulx            q, rl, rh               #M[14]*q7
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3

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

        ##### M[9 11 13 15]*q7 #####
        vpextrq         $1, T0xmm, mi          #M[9]
        mulx            q, rl, rh               #M[9]*q7
        add             rl, s6
        adc             rh, s7

        vpextrq         $1, T1xmm, mi          #M[11]
        mulx            q, rl, rh               #M[11]*q7
        adc             rl, s8
        adc             rh, s9

        vpextrq         $1, T2xmm, mi          #M[13]
        mulx            q, rl, rh               #M[13]*q7
        adc             rl, s0
        adc             rh, s1

        vpextrq         $1, T3xmm, mi          #M[15]
        mulx            q, rl, rh               #M[15]*q7
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4


	###################################################################
	###################################################################

	##### A[0 2 4 6]*B[15] #####
        vpextrq         $1, B3xmm, bi          #B[15]

        vmovq           A0xmm, ai          #A[0]
        mulx            bi, rl, rh              #A[0]*B[15]
	add		rl, s5
	adc		rh, s6

	vmovq           A1xmm, ai          #A[2]
        mulx            bi, rl, rh              #A[2]*B[15]
        adc             rl, s7
        adc             rh, s8

	vmovq           A2xmm, ai          #A[4]
        mulx            bi, rl, rh              #A[4]*B[15]
        adc             rl, s9
        adc             rh, s0

	vmovq           A3xmm, ai          #A[6]
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
        vmovq           M0xmm, mi          #M[0]
        mulx            q, rl, rh               #M[0]*q15
        add             rl, s5
        adc             rh, s6

        vmovq           M1xmm, mi          #M[2]
        mulx            q, rl, rh               #M[2]*q15
        adc             rl, s7
        adc             rh, s8

        vmovq           M2xmm, mi          #M[4]
        mulx            q, rl, rh               #M[4]*q15
        adc             rl, s9
        adc             rh, s0

        vmovq           M3xmm, mi          #M[6]
        mulx            q, rl, rh               #M[6]*q15
        adc             rl, s1
        adc             rh, s2
        adc             $0, s3
	adc		$0, s4

	##### A[1 3 5 7]*B[15] #####
        vmovq           B0xmm, ai          #A[1]
        mulx            bi, rl, rh              #A[1]*B[15]
        add             rl, s6
        adc             rh, s7

        vmovq           B1xmm, ai          #A[3]
        mulx            bi, rl, rh              #A[3]*B[15]
        adc             rl, s8
        adc             rh, s9

        vmovq           B2xmm, ai          #A[5]
        mulx            bi, rl, rh              #A[5]*B[15]
        adc             rl, s0
        adc             rh, s1

        vmovq           B3xmm, ai          #A[7]
        mulx            bi, rl, rh              #A[7]*B[15]
        adc             rl, s2
        adc             rh, s3
        adc             $0, s4

        ##### M[1 3 5 7]*q15 #####
        vmovq           T0xmm, mi          #M[1]
        mulx            q, rl, rh               #M[1]*q15
        add             rl, s6
        adc             rh, s7

        vmovq           T1xmm, mi          #M[3]
        mulx            q, rl, rh               #M[3]*q15
        adc             rl, s8
        adc             rh, s9

        vmovq           T2xmm, mi          #M[5]
        mulx            q, rl, rh               #M[5]*q15
        adc             rl, s0
        adc             rh, s1

        vmovq           T3xmm, mi          #M[7]
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



##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################




.macro  montsqu_3rd_movq


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


	/*

	### store T3 ###
	vperm2i128	$0x20, T3, T0, T0

	vperm2i128	$0x01, A0, A0, T3
	vshufpd		$0x05, A0, A0, A0		#imm=0101
	vblendpd	$0x06, A0, T3, A0		#imm=0110

	vperm2i128	$0x01, A1, A1, T3
	vshufpd		$0x05, A1, A1, A1		#imm=0101
	vblendpd	$0x06, A1, T3, A1		#imm=0110

	vperm2i128	$0x01, A2, A2, T3
	vshufpd		$0x05, A2, A2, A2		#imm=0101
	vblendpd	$0x06, A2, T3, A2		#imm=0110

	vperm2i128	$0x01, A3, A3, T3
	vshufpd		$0x05, A3, A3, A3		#imm=0101
	vblendpd	$0x06, A3, T3, A3		#imm=0110

	vperm2i128	$0x01, B0, B0, T3
	vshufpd		$0x05, B0, B0, B0		#imm=0101
	vblendpd	$0x06, B0, T3, B0		#imm=0110

	vperm2i128	$0x01, B1, B1, T3
	vshufpd		$0x05, B1, B1, B1		#imm=0101
	vblendpd	$0x06, B1, T3, B1		#imm=0110

	vperm2i128	$0x01, B2, B2, T3
	vshufpd		$0x05, B2, B2, B2		#imm=0101
	vblendpd	$0x06, B2, T3, B2		#imm=0110

	vperm2i128	$0x01, B3, B3, T3
	vshufpd		$0x05, B3, B3, B3		#imm=0101
	vblendpd	$0x06, B3, T3, B3		#imm=0110
	

	### restore T3 ###
	vperm2i128	$0x31, T3, T0, T3

	*/



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
        vmovq           A0xmm, bi         	#A[8]

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

	#vpinsrq	$0, s6, T0xmm, T0xmm	#result[0]
	#pinsrq		$0, s6, T0xmm		#result[0]


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
        vmovq           B0xmm, bi         	#A[9]

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

	#vpinsrq	$1, s7, T0xmm, T0xmm	#result[1]
	#pinsrq		$1, s7, T0xmm		#result[1]


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
        vmovq           A1xmm, bi         	#A[10]

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

	#vpinsrq	$0, s8, T1xmm, T1xmm	#result[2]
	#pinsrq		$0, s8, T1xmm		#result[2]


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
        vmovq           B1xmm, bi         	#A[11]

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

	#vpinsrq	$1, s9, T1xmm, T1xmm	#result[3]
	#pinsrq		$1, s9, T1xmm		#result[3]


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
        vmovq           A2xmm, bi         	#A[12]

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
	
	#vpinsrq	$0, s0, T2xmm, T2xmm	#result[4]
	#pinsrq		$0, s0, T2xmm		#result[4]


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
        vmovq           B2xmm, bi         	#A[13]

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

	#vpinsrq	$1, s1, T2xmm, T2xmm	#result[5]
	#pinsrq		$1, s1, T2xmm		#result[5]


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
        vmovq           A3xmm, bi         	#A[14]

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

	#vpinsrq	$0, s2, T3xmm, T3xmm	#result[6]
	#pinsrq		$0, s2, T3xmm		#result[6]


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
        vmovq           B3xmm, bi         	#A[15]

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

	#vpinsrq	$1, s3, T3xmm, T3xmm	#result[7]
	#pinsrq		$1, s3, T3xmm		#result[7]


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





##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################




.macro  montsqu_last_movq


##################################################################################################
	###							###	
	### 	last part: reduce and store result		###
	###							###
	###	sum 102=8+94					###
	###							###
##################################################################################################
        ###                                                     ###
        ###     last_arrange_vector		                ###
        ###     sum 8                                 		###
        ###                                                     ###
        ###########################################################

	

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
	

#.montsqu_last_sub_1$:

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
	
	#jb	.montmul_last_end
	jb 	1f

	
#.montsqu_last_sub_2:

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


#.montsqu_last_end$:
1:	
	/*
	vmovq		r8, T3xmm		#R[8]
	vblendpd	$0x1, T3, A0, A0	#imm=0001

	vperm2i128	$0x1, A0, A0, A0	#imm=1	
	movq		r0, r8
	vmovq		r8, T3xmm		#R[0]
	vblendpd	$0x1, T3, A0, A0	#imm=0001


	vmovq		r9, T3xmm		#R[9]
	vblendpd	$0x1, T3, A1, A1	#imm=0001

	vperm2i128	$0x1, A1, A1, A1	#imm=1
	movq		r1, r9
	vmovq		r9, T3xmm		#R[1]
	vblendpd	$0x1, T3, A1, A1	#imm=0001



	vmovq		r10, T3xmm		#R[10]
	vblendpd	$0x1, T3, A2, A2	#imm=0001

	vperm2i128	$0x1, A2, A2, A2	#imm=1
	movq		r2, r10
	vmovq		r10, T3xmm		#R[2]
	vblendpd	$0x1, T3, A2, A2	#imm=0001	

	
	vmovq		r11, T3xmm		#R[11]
	vblendpd	$0x1, T3, A3, A3	#imm=0001

	vperm2i128	$0x1, A3, A3, A3	#imm=1
	movq		r3, r11
	vmovq		r11, T3xmm		#R[3]
	vblendpd	$0x1, T3, A3, A3	#imm=0001




	vmovq		r12, T3xmm		#R[12]
	vblendpd	$0x1, T3, B0, B0	#imm=0001

	vperm2i128	$0x1, B0, B0, B0	#imm=1
	movq		r4, r12
	vmovq		r12, T3xmm		#R[4]
	vblendpd	$0x1, T3, B0, B0	#imm=0001


	vmovq		r13, T3xmm		#R[13]
	vblendpd	$0x1, T3, B1, B1	#imm=0001

	vperm2i128	$0x1, B1, B1, B1	#imm=1
	movq		r5, r13
	vmovq		r13, T3xmm		#R[5]
	vblendpd	$0x1, T3, B1, B1	#imm=0001


	vmovq		r14, T3xmm		#R[14]
	vblendpd	$0x1, T3, B2, B2	#imm=0001

	vperm2i128	$0x1, B2, B2, B2	#imm=1
	movq		r6, r14
	vmovq		r14, T3xmm		#R[6]
	vblendpd	$0x1, T3, B2, B2	#imm=0001


	vmovq		r15, T3xmm		#R[15]
	vblendpd	$0x1, T3, B3, B3	#imm=0001

	vperm2i128	$0x1, B3, B3, B3	#imm=1
	vmovq		r7, T3xmm		#R[7]		#q15 rbp
	vblendpd	$0x1, T3, B3, B3	#imm=0001
	//*/



	/*
	###################################################################
	#### for all reg exp ####

	### B3 can be used ###
	vshufpd		$0xF, B3, B2, B2	#1111


	vmovq		r8, B3xmm		#R[8]
	vblendpd	$0x1, B3, A0, A0	#imm=0001

	vperm2i128	$0x1, A0, A0, A0	#imm=1	
	movq		r0, r8
	vmovq		r8, B3xmm		#R[0]
	vblendpd	$0x1, B3, A0, A0	#imm=0001


	vmovq		r9, B3xmm		#R[9]
	vblendpd	$0x1, B3, A1, A1	#imm=0001

	vperm2i128	$0x1, A1, A1, A1	#imm=1	
	movq		r1, r9
	vmovq		r9, B3xmm		#R[1]
	vblendpd	$0x1, B3, A1, A1	#imm=0001


	vmovq		r10, B3xmm		#R[10]
	vblendpd	$0x1, B3, A2, A2	#imm=0001

	vperm2i128	$0x1, A2, A2, A2	#imm=1	
	movq		r2, r10
	vmovq		r10, B3xmm		#R[2]
	vblendpd	$0x1, B3, A2, A2	#imm=0001

	
	vmovq		r11, B3xmm		#R[11]
	vblendpd	$0x1, B3, A3, A3	#imm=0001

	vperm2i128	$0x1, A3, A3, A3	#imm=1	
	movq		r3, r11
	vmovq		r11, B3xmm		#R[3]
	vblendpd	$0x1, B3, A3, A3	#imm=0001


	vmovq		r12, B3xmm		#R[12]
	vblendpd	$0x1, B3, B0, B0	#imm=0001

	vperm2i128	$0x1, B0, B0, B0	#imm=1	
	movq		r4, r12
	vmovq		r12, B3xmm		#R[4]
	vblendpd	$0x1, B3, B0, B0	#imm=0001


	vmovq		r13, B3xmm		#R[13]
	vblendpd	$0x1, B3, B1, B1	#imm=0001

	vperm2i128	$0x1, B1, B1, B1	#imm=1	
	movq		r5, r13
	vmovq		r13, B3xmm		#R[5]
	vblendpd	$0x1, B3, B1, B1	#imm=0001


	vmovq		r15, B3xmm		#R[15]
	movq		r7, r15
	vpinsrq		$0x1, r15, B3xmm, B3xmm  #R[7]
	vpermq		$0x10, B3, B3		#imm=0100
	vblendpd	$0x5, B3, B2, B3	#imm=0101
	vperm2i128	$0x1, B3, B3, B3	#imm=1	
	

	vshufpd		$0x05, B2, B2, B2	#imm=0101
	pinsrq		$0x0, r14, B2xmm  	#R[14]
	vperm2i128	$0x1, B2, B2, B2	#imm=1
	movq		r6, r14	
	pinsrq		$0x0, r14, B2xmm  	#R[6]
	*/

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


##################################################################################################
	###							###	
	### 	last part END 					###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################

.endm




##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################
##################################################################################################



.globl 	montsqu1024
	.type  	montsqu1024, @function
	.align 	64

montsqu1024:

#.macro	montsqu1024


##################################################################################################
	###							###	
	### 	montsqu1024: 1st 2nd 3rd last 			###
	###							###
	###	sum 2554=576+1248+628+102			###
	###							###
##################################################################################################

	# movq	%rsp, rsp	#mm7

	/*
	montmul_1st

	montmul_2nd
	
	montmul_3rd

	montmul_last

	*/



	montsqu_1st_movq
	
	montsqu_2nd_movq

	montsqu_3rd_movq

	montsqu_last_movq
	

	/*
	
	//montmul_1st

	//montmul_1st_movq



	//first
	pinsrq		$0, s8, A0xmm		#R[0]
	pinsrq		$0, s9, A1xmm		#R[1]
	pinsrq		$0, s0, A2xmm		#R[2]
	pinsrq		$0, s1, A3xmm		#R[3]
	pinsrq		$0, s2, B0xmm		#R[4]
	pinsrq		$0, s3, B1xmm		#R[5]
	pinsrq		$0, s4, B2xmm		#R[6]
	pinsrq		$0, s5, B3xmm		#R[7]

	
	//montmul_2nd


	//Second
	pinsrq		$0, s6, A0xmm		#R[0]
	pinsrq		$0, s7, A1xmm		#R[1]
	pinsrq		$0, s8, A2xmm		#R[2]
	pinsrq		$0, s9, A3xmm		#R[3]
	pinsrq		$0, s0, B0xmm		#R[4]
	pinsrq		$0, s1, B1xmm		#R[5]
	pinsrq		$0, s2, B2xmm		#R[6]
	pinsrq		$0, s3, B3xmm		#R[7]


	//montmul_3rd

	//third
	pinsrq		$0, s4, A0xmm		#R[0]
	pinsrq		$0, s5, A1xmm		#R[1]
	pinsrq		$0, s6, A2xmm		#R[2]
	pinsrq		$0, s7, A3xmm		#R[3]
	pinsrq		$0, s8, B0xmm		#R[4]
	pinsrq		$0, s9, B1xmm		#R[5]
	pinsrq		$0, s0, B2xmm		#R[6]
	pinsrq		$0, s1, B3xmm		#R[7]
	*/


	# montmul_1st

	# movq	rsp, %rsp	#mm7  ## old fold have this

##################################################################################################
	###							###	
	### 	montsqu1024 END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################


#.endm

	ret
	.size	montsqu1024, .-montsqu1024








