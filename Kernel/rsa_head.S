	.file	"rsa_head.S"
	.text





##################################################################################################
	###										###	
	### 	montmul_1st montsqu_1st 						###
	###										###
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

/* A0-A3 */
.set	A0,	%ymm0
.set	A1,	%ymm1
.set	A2,	%ymm2
.set	A3,	%ymm3

/* B0-B3 */ 
.set 	B0,	%ymm4
.set	B1,	%ymm5
.set	B2,	%ymm6
.set	B3,	%ymm7

/* M0-M3 */
.set	M0,	%ymm8
.set	M1,	%ymm9
.set	M2,	%ymm10
.set	M3,	%ymm11

/* T0-T3 Exponent */
.set	T0,	%ymm12
.set	T1,	%ymm13
.set	T2,	%ymm14
.set	T3,	%ymm15


##### A0xmm is the xmm register, low 128bit of ymm register #####
##### A0xmm is used for vpextrq #####

/* A0-A3 */
.set	A0xmm,	%xmm0
.set	A1xmm,	%xmm1
.set	A2xmm,	%xmm2
.set	A3xmm,	%xmm3

/* B0-B3 */ 
.set 	B0xmm,	%xmm4
.set	B1xmm,	%xmm5
.set	B2xmm,	%xmm6
.set	B3xmm,	%xmm7

/* M0-M3 */
.set	M0xmm,	%xmm8
.set	M1xmm,	%xmm9
.set	M2xmm,	%xmm10
.set	M3xmm,	%xmm11

/* T0-T3 Exponent */
.set	T0xmm,	%xmm12
.set	T1xmm,	%xmm13
.set	T2xmm,	%xmm14
.set	T3xmm,	%xmm15



/* 8 64bit mmx registers */
/* q0-q7 */ 
.set	q0,	%mm0
.set    q1,	%mm1
.set    q2,	%mm2
.set    q3,	%mm3
.set    q4,	%mm4
.set    q5,	%mm5
#.set    q6,	%rbp
#.set    q7,	%rsp
.set	q6,	%mm6
.set	q7,	%rbp


.set	q8,	%mm0
.set    q9,	%mm1
.set    q10,	%mm2
.set    q11,	%mm3
.set    q12,	%mm4
.set    q13,	%mm5
#.set    q14,	%rbp
#.set    q15,	%rsp
.set	q14,	%mm6
.set	q15,	%rbp

#.set	n0,	%mm6	#n0=M'[0]
#.set	rsp,	%mm7	#%rsp

.set	n0,	%mm7
.set	rsp,	%rsp	#for montmul montsqu to be function


/* 16 64bit scalar registers */
/* B */
.set	bi,	%rax

/* q */
.set	q,	%rbx

/* A M */
.set	ai,	%rdx
.set	mi,	%rdx

/* rl rh */
.set	rl,	%rcx
.set	rh,	%rdx

/* s0-s9 */ 
.set	s0,	%r8
.set    s1,	%r9
.set    s2,	%r10
.set    s3,	%r11
.set    s4,	%r12
.set    s5,	%r13
.set    s6,	%r14
.set    s7,	%r15
.set    s8,	%rdi
.set    s9,	%rsi


##################################################################################################








##################################################################################################
	###										###	
	### 	montmul_1st montsqu_1st 						###
	###										###
##################################################################################################



/* 16 256bit vector registers */
##################################################################################################
	
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

/* AL0-AL3 */
.set	AL0,	A0
.set	AL1,	A1
.set	AL2,	A2
.set	AL3,	A3

/* AH0-AH3 */
.set	AH0,	B0
.set	AH1,	B1
.set	AH2,	B2
.set	AH3,	B3

/* BL0-BL3 */
.set	BL0,	A0
.set	BL1,	A1
.set	BL2,	A2
.set	BL3,	A3

/* BH0-BH3 */
.set	BH0,	B0
.set	BH1,	B1
.set	BH2,	B2
.set	BH3,	B3

/* ML0-ML3 */ 
.set 	ML0,	M0
.set	ML1,	M1
.set	ML2,	M2
.set	ML3,	M3

/* MH0-MH3 */
.set	MH0,	T0
.set	MH1,	T1
.set	MH2,	T2
.set	MH3,	T3

/* TL0-TL3 */ 
.set 	TL0,	M0
.set	TL1,	M1
.set	TL2,	M2
.set	TL3,	M3

/* TH0-TH3 */
.set	TH0,	T0
.set	TH1,	T1
.set	TH2,	T2
.set	TH3,	T3



##### AL0xmm is the xmm register, low 128bit of ymm register #####
##### AL0xmm is used for vpextrq #####

/*** T just exponent storage, not used for montmul1024 compute, so Txmm is not needed ***/

/* AL0-AL3 */
.set	AL0xmm,	A0xmm
.set	AL1xmm,	A1xmm
.set	AL2xmm,	A2xmm
.set	AL3xmm,	A3xmm

/* AH0-AH3 */
.set	AH0xmm,	B0xmm
.set	AH1xmm,	B1xmm
.set	AH2xmm,	B2xmm
.set	AH3xmm,	B3xmm

/* BL0-BL3 */
.set	BL0xmm,	A0xmm
.set	BL1xmm,	A1xmm
.set	BL2xmm,	A2xmm
.set	BL3xmm,	A3xmm

/* BH0-BH3 */
.set	BH0xmm,	B0xmm
.set	BH1xmm,	B1xmm
.set	BH2xmm,	B2xmm
.set	BH3xmm,	B3xmm

/* ML0-ML3 */ 
.set 	ML0xmm,	M0xmm
.set	ML1xmm,	M1xmm
.set	ML2xmm,	M2xmm
.set	ML3xmm,	M3xmm

/* MH0-MH3 */
.set	MH0xmm,	T0xmm
.set	MH1xmm,	T1xmm
.set	MH2xmm,	T2xmm
.set	MH3xmm,	T3xmm






##################################################################################################
	###										###	
	### 	montmul_3rd montsqu_3rd 						###
	###										###
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


/* r0-r15 montmul1024 result*/ 
.set	r0,	q8
.set    r1,	q9
.set    r2,	q10
.set    r3,	q11
.set    r4,	q12
.set    r5,	q13
.set    r6,	q14
.set    r7,	q15		#rbp

.set	r8,	s4
.set    r9,	s5
.set    r10,	s6
.set    r11,	s7
.set    r12,	s8
.set    r13,	s9
.set    r14,	s0
.set    r15,	s1


