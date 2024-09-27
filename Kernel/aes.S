	.file	"aes.S"
	.text





.set	rk0,	T0xmm		/* round key  0 */
.set	rk1,	T1xmm		/* round key  1 */
.set	rhelp,	T2xmm		/* helping register */







.macro	keyxor_A_B_M_n0
	
	###n0 stored in T3[0]###

	pxor 				rk0, A0xmm
	pxor 				rk0, A1xmm
	pxor 				rk0, A2xmm
	pxor 				rk0, A3xmm
	pxor 				rk0, B0xmm
	pxor 				rk0, B1xmm
	pxor 				rk0, B2xmm
	pxor 				rk0, B3xmm
	pxor 				rk0, M0xmm
	pxor 				rk0, M1xmm
	pxor 				rk0, M2xmm
	pxor 				rk0, M3xmm
	pxor 				rk0, T3xmm
	vperm2i128			$0x1, A0, A0, A0		
	vperm2i128			$0x1, A1, A1, A1		 
	vperm2i128			$0x1, A2, A2, A2	
	vperm2i128			$0x1, A3, A3, A3
	vperm2i128			$0x1, B0, B0, B0		
	vperm2i128			$0x1, B1, B1, B1		 
	vperm2i128			$0x1, B2, B2, B2	
	vperm2i128			$0x1, B3, B3, B3
	vperm2i128			$0x1, M0, M0, M0		
	vperm2i128			$0x1, M1, M1, M1		 
	vperm2i128			$0x1, M2, M2, M2	
	vperm2i128			$0x1, M3, M3, M3
	pxor 				rk0, A0xmm
	pxor 				rk0, A1xmm
	pxor 				rk0, A2xmm
	pxor 				rk0, A3xmm
	pxor 				rk0, B0xmm
	pxor 				rk0, B1xmm
	pxor 				rk0, B2xmm
	pxor 				rk0, B3xmm
	pxor 				rk0, M0xmm
	pxor 				rk0, M1xmm
	pxor 				rk0, M2xmm
	pxor 				rk0, M3xmm
	vperm2i128			$0x1, A0, A0, A0		
	vperm2i128			$0x1, A1, A1, A1		 
	vperm2i128			$0x1, A2, A2, A2	
	vperm2i128			$0x1, A3, A3, A3
	vperm2i128			$0x1, B0, B0, B0		
	vperm2i128			$0x1, B1, B1, B1		 
	vperm2i128			$0x1, B2, B2, B2	
	vperm2i128			$0x1, B3, B3, B3
	vperm2i128			$0x1, M0, M0, M0		
	vperm2i128			$0x1, M1, M1, M1		 
	vperm2i128			$0x1, M2, M2, M2	
	vperm2i128			$0x1, M3, M3, M3		

.endm



.macro	aesdec_A_B_M_n0

	###n0 stored in T3[0]###

	aesdec 				rhelp, A0xmm
	aesdec 				rhelp, A1xmm
	aesdec 				rhelp, A2xmm
	aesdec 				rhelp, A3xmm
	aesdec 				rhelp, B0xmm
	aesdec 				rhelp, B1xmm
	aesdec 				rhelp, B2xmm
	aesdec 				rhelp, B3xmm
	aesdec				rhelp, M0xmm
	aesdec 				rhelp, M1xmm
	aesdec 				rhelp, M2xmm
	aesdec 				rhelp, M3xmm
	aesdec 				rhelp, T3xmm
	vperm2i128			$0x1, A0, A0, A0		
	vperm2i128			$0x1, A1, A1, A1		 
	vperm2i128			$0x1, A2, A2, A2	
	vperm2i128			$0x1, A3, A3, A3
	vperm2i128			$0x1, B0, B0, B0		
	vperm2i128			$0x1, B1, B1, B1		 
	vperm2i128			$0x1, B2, B2, B2	
	vperm2i128			$0x1, B3, B3, B3
	vperm2i128			$0x1, M0, M0, M0		
	vperm2i128			$0x1, M1, M1, M1		 
	vperm2i128			$0x1, M2, M2, M2	
	vperm2i128			$0x1, M3, M3, M3
	aesdec 				rhelp, A0xmm
	aesdec 				rhelp, A1xmm
	aesdec 				rhelp, A2xmm
	aesdec 				rhelp, A3xmm
	aesdec 				rhelp, B0xmm
	aesdec 				rhelp, B1xmm
	aesdec 				rhelp, B2xmm
	aesdec 				rhelp, B3xmm
	aesdec				rhelp, M0xmm
	aesdec 				rhelp, M1xmm
	aesdec 				rhelp, M2xmm
	aesdec 				rhelp, M3xmm
	vperm2i128			$0x1, A0, A0, A0		
	vperm2i128			$0x1, A1, A1, A1		 
	vperm2i128			$0x1, A2, A2, A2	
	vperm2i128			$0x1, A3, A3, A3
	vperm2i128			$0x1, B0, B0, B0		
	vperm2i128			$0x1, B1, B1, B1		 
	vperm2i128			$0x1, B2, B2, B2	
	vperm2i128			$0x1, B3, B3, B3
	vperm2i128			$0x1, M0, M0, M0		
	vperm2i128			$0x1, M1, M1, M1		 
	vperm2i128			$0x1, M2, M2, M2	
	vperm2i128			$0x1, M3, M3, M3	
		
.endm


.macro	aesdeclast_A_B_M_n0

	###n0 stored in T3[0]###

	aesdeclast 			rhelp, A0xmm
	aesdeclast 			rhelp, A1xmm
	aesdeclast 			rhelp, A2xmm
	aesdeclast 			rhelp, A3xmm
	aesdeclast 			rhelp, B0xmm
	aesdeclast 			rhelp, B1xmm
	aesdeclast 			rhelp, B2xmm
	aesdeclast 			rhelp, B3xmm
	aesdeclast			rhelp, M0xmm
	aesdeclast 			rhelp, M1xmm
	aesdeclast 			rhelp, M2xmm
	aesdeclast 			rhelp, M3xmm
	aesdeclast 			rhelp, T3xmm
	vperm2i128			$0x1, A0, A0, A0		
	vperm2i128			$0x1, A1, A1, A1		 
	vperm2i128			$0x1, A2, A2, A2	
	vperm2i128			$0x1, A3, A3, A3
	vperm2i128			$0x1, B0, B0, B0		
	vperm2i128			$0x1, B1, B1, B1		 
	vperm2i128			$0x1, B2, B2, B2	
	vperm2i128			$0x1, B3, B3, B3
	vperm2i128			$0x1, M0, M0, M0		
	vperm2i128			$0x1, M1, M1, M1		 
	vperm2i128			$0x1, M2, M2, M2	
	vperm2i128			$0x1, M3, M3, M3
	aesdeclast 			rhelp, A0xmm
	aesdeclast 			rhelp, A1xmm
	aesdeclast 			rhelp, A2xmm
	aesdeclast 			rhelp, A3xmm
	aesdeclast 			rhelp, B0xmm
	aesdeclast 			rhelp, B1xmm
	aesdeclast 			rhelp, B2xmm
	aesdeclast 			rhelp, B3xmm
	aesdeclast			rhelp, M0xmm
	aesdeclast 			rhelp, M1xmm
	aesdeclast 			rhelp, M2xmm
	aesdeclast 			rhelp, M3xmm
	vperm2i128			$0x1, A0, A0, A0		
	vperm2i128			$0x1, A1, A1, A1		 
	vperm2i128			$0x1, A2, A2, A2	
	vperm2i128			$0x1, A3, A3, A3
	vperm2i128			$0x1, B0, B0, B0		
	vperm2i128			$0x1, B1, B1, B1		 
	vperm2i128			$0x1, B2, B2, B2	
	vperm2i128			$0x1, B3, B3, B3
	vperm2i128			$0x1, M0, M0, M0		
	vperm2i128			$0x1, M1, M1, M1		 
	vperm2i128			$0x1, M2, M2, M2	
	vperm2i128			$0x1, M3, M3, M3	
		
.endm



.macro	keyxor_arg			arg0 arg1 arg2 arg3 arg0xmm arg1xmm arg2xmm arg3xmm

	pxor 				rk0, \arg0xmm
	pxor 				rk0, \arg1xmm
	pxor 				rk0, \arg2xmm
	pxor 				rk0, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3
	pxor 				rk0, \arg0xmm
	pxor 				rk0, \arg1xmm
	pxor 				rk0, \arg2xmm
	pxor 				rk0, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3	

.endm


.macro	aesdec_arg			arg0 arg1 arg2 arg3 arg0xmm arg1xmm arg2xmm arg3xmm

	aesdec 				rhelp, \arg0xmm
	aesdec 				rhelp, \arg1xmm
	aesdec 				rhelp, \arg2xmm
	aesdec 				rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3
	aesdec 				rhelp, \arg0xmm
	aesdec 				rhelp, \arg1xmm
	aesdec 				rhelp, \arg2xmm
	aesdec 				rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3	

.endm




.macro	aesdeclast_arg			arg0 arg1 arg2 arg3 arg0xmm arg1xmm arg2xmm arg3xmm

	aesdeclast 			rhelp, \arg0xmm
	aesdeclast 			rhelp, \arg1xmm
	aesdeclast 			rhelp, \arg2xmm
	aesdeclast 			rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3
	aesdeclast 			rhelp, \arg0xmm
	aesdeclast 			rhelp, \arg1xmm
	aesdeclast 			rhelp, \arg2xmm
	aesdeclast 			rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3	

.endm


.macro	aesdec_arg_128bit		arg0 arg1 arg2 arg3 arg0xmm arg1xmm arg2xmm arg3xmm

	vaesdec 			rhelp, \arg0xmm, \arg0xmm
	vaesdec 			rhelp, \arg0xmm, \arg1xmm
	vaesdec 			rhelp, \arg0xmm, \arg2xmm
	vaesdec 			rhelp, \arg0xmm, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3
	vaesdec 			rhelp, \arg0xmm, \arg0xmm
	vaesdec 			rhelp, \arg0xmm, \arg1xmm
	vaesdec 			rhelp, \arg0xmm, \arg2xmm
	vaesdec 			rhelp, \arg0xmm, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3	

.endm



.macro	aesdeclast_arg_128bit		arg0 arg1 arg2 arg3 arg0xmm arg1xmm arg2xmm arg3xmm

	vaesdeclast 			rhelp, \arg0xmm, \arg0xmm
	vaesdeclast 			rhelp, \arg0xmm, \arg1xmm
	vaesdeclast 			rhelp, \arg0xmm, \arg2xmm
	vaesdeclast 			rhelp, \arg0xmm, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3
	vaesdeclast 			rhelp, \arg0xmm, \arg0xmm
	vaesdeclast 			rhelp, \arg0xmm, \arg1xmm
	vaesdeclast 			rhelp, \arg0xmm, \arg2xmm
	vaesdeclast 			rhelp, \arg0xmm, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3	

.endm


#### rhelp wrong ####
.macro	aesenc_arg			arg0 arg1 arg2 arg3 arg0xmm arg1xmm arg2xmm arg3xmm

	aesenc 				rhelp, \arg0xmm
	aesenc 				rhelp, \arg1xmm
	aesenc 				rhelp, \arg2xmm
	aesenc 				rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3
	aesenc 				rhelp, \arg0xmm
	aesenc 				rhelp, \arg1xmm
	aesenc 				rhelp, \arg2xmm
	aesenc 				rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3	

.endm


.macro	aesenclast_arg			arg0 arg1 arg2 arg3 arg0xmm arg1xmm arg2xmm arg3xmm

	aesenclast 			rhelp, \arg0xmm
	aesenclast 			rhelp, \arg1xmm
	aesenclast 			rhelp, \arg2xmm
	aesenclast 			rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3
	aesenclast 			rhelp, \arg0xmm
	aesenclast 			rhelp, \arg1xmm
	aesenclast 			rhelp, \arg2xmm
	aesenclast 			rhelp, \arg3xmm
	vperm2i128			$0x1, \arg0, \arg0, \arg0		
	vperm2i128			$0x1, \arg1, \arg1, \arg1		 
	vperm2i128			$0x1, \arg2, \arg2, \arg2	
	vperm2i128			$0x1, \arg3, \arg3, \arg3	

.endm









/*
### have douhao ","###
.macro	key_expansion_128	r0, rcon, rhelp

	aeskeygenassist		$\rcon, \r0, \rhelp
		
	pshufd			$0xff, \rhelp, \rhelp	
	pxor			\r0, \rhelp		#rhelp	:T3+w3, T3+w2, T3+w1, T3+20

	pslldq			$0x4, \r0		#r0	:w2, w1, w0, 0
	pxor			\r0, \rhelp		#rhelp	:T3+w3+w2, T3+w2+w1, T3+w1+w0, T3+w0
			
	pslldq			$0x4, \r0		#r0	:w1, w0, 0, 0
	pxor			\r0, \rhelp		#rhelp	:T3+w3+w2+w1, T3+w2+w1+w0, T3+w1+w0, T3+w0

	pslldq			$0x4, \r0		#r0	:w0, 0, 0, 0
	pxor			\rhelp, \r0		#r0	:T3+w3+w2+w1+w0, T3+w2+w1+w0, T3+w1+w0, T3+w0

.endm



.macro	key_schedule_128

	key_expansion_128	rk0, 0x1
	key_expansion_128	rk0, 0x2
	key_expansion_128	rk0, 0x4
	key_expansion_128	rk0, 0x8
	key_expansion_128	rk0, 0x10
	key_expansion_128	rk0, 0x20
	key_expansion_128	rk0, 0x40
	key_expansion_128	rk0, 0x80
	key_expansion_128	rk0, 0x1b
	key_expansion_128	rk0, 0x36

.endm
*/

### no douhao ","###
.macro	key_expansion_128	r0 rcon rhelp

	aeskeygenassist		$\rcon, \r0, \rhelp
		
	pshufd			$0xff, \rhelp, \rhelp	
	pxor			\r0, \rhelp		#rhelp	:T3+w3, T3+w2, T3+w1, T3+20

	pslldq			$0x4, \r0		#r0	:w2, w1, w0, 0
	pxor			\r0, \rhelp		#rhelp	:T3+w3+w2, T3+w2+w1, T3+w1+w0, T3+w0
			
	pslldq			$0x4, \r0		#r0	:w1, w0, 0, 0
	pxor			\r0, \rhelp		#rhelp	:T3+w3+w2+w1, T3+w2+w1+w0, T3+w1+w0, T3+w0

	pslldq			$0x4, \r0		#r0	:w0, 0, 0, 0
	pxor			\rhelp, \r0		#r0	:T3+w3+w2+w1+w0, T3+w2+w1+w0, T3+w1+w0, T3+w0

.endm


### use for key schedule ###
.macro	key_schedule_128	rk0 rhelp

	key_expansion_128	\rk0 0x1 \rhelp
	key_expansion_128	\rk0 0x2 \rhelp
	key_expansion_128	\rk0 0x4 \rhelp
	key_expansion_128	\rk0 0x8 \rhelp
	key_expansion_128	\rk0 0x10 \rhelp
	key_expansion_128	\rk0 0x20 \rhelp
	key_expansion_128	\rk0 0x40 \rhelp
	key_expansion_128	\rk0 0x80 \rhelp
	key_expansion_128	\rk0 0x1b \rhelp
	key_expansion_128	\rk0 0x36 \rhelp

.endm


/*
### all version ###
.macro	key_expansion_256	r0 r1 rcon rhelp

	aeskeygenassist		$\rcon, \r1, \rhelp	#T7
	
	### r0=w8 w9 w10 w11 ###
	
	pshufd			$0xff, \rhelp, \rhelp	
	pxor			\r0, \rhelp		#rhelp	:T7+w3, T7+w2, T7+w1, T7+w0

	pslldq			$0x4, \r0		#r0	:w2, w1, w0, 0
	pxor			\r0, \rhelp		#rhelp	:T7+w3+w2, T7+w2+w1, T7+w1+w0, T7+w0
			
	pslldq			$0x4, \r0		#r0	:w1, w0, 0, 0
	pxor			\r0, \rhelp		#rhelp	:T7+w3+w2+w1, T7+w2+w1+w0, T7+w1+w0, T7+w0

	pslldq			$0x4, \r0		#r0	:w0, 0, 0, 0
	pxor			\rhelp, \r0		#r0	:T7+w3+w2+w1+w0, T7+w2+w1+w0, T7+w1+w0, T7+w0


	### r1=w12 w13 w14 w15 ###
	### w11=T7+w3+w2+w1+w0

	pshufd			$0xff, r0, \rhelp	#w8
	pxor			\r1, \rhelp		#rhelp	:w11+w7, w11+w6, w11+w5, w11+w4

	pslldq			$0x4, \r1		#r0	:w6, w5, w4, 0
	pxor			\r1, \rhelp		#rhelp	:w11+w7+w6, w11+w6+w5, w11+w5+w4, w11+w4
			
	pslldq			$0x4, \r1		#r0	:w5, w4, 0, 0
	pxor			\r1, \rhelp		#rhelp	:w11+w7+w6+w5, w11+w6+w5+w4, w11+w5+w4, w11+w4

	pslldq			$0x4, \r1		#r0	:w4, 0, 0, 0
	pxor			\rhelp, \r1		#r0	:w11+w7+w6+w5+w4, w11+w6+w5+w4, w11+w5+w4, w11+w4

.endm
*/



### AES256 key expansion first part ###
### compute r0 ###
.macro	key_expansion_256_1st	r0 r1 rcon rhelp

	aeskeygenassist		$\rcon, \r1, \rhelp	#T7
	
	### r0=w8 w9 w10 w11 ###
	
	pshufd			$0xff, \rhelp, \rhelp	
	pxor			\r0, \rhelp		#rhelp	:T7+w3, T7+w2, T7+w1, T7+w0

	pslldq			$0x4, \r0		#r0	:w2, w1, w0, 0
	pxor			\r0, \rhelp		#rhelp	:T7+w3+w2, T7+w2+w1, T7+w1+w0, T7+w0
			
	pslldq			$0x4, \r0		#r0	:w1, w0, 0, 0
	pxor			\r0, \rhelp		#rhelp	:T7+w3+w2+w1, T7+w2+w1+w0, T7+w1+w0, T7+w0

	pslldq			$0x4, \r0		#r0	:w0, 0, 0, 0
	pxor			\rhelp, \r0		#r0	:T7+w3+w2+w1+w0, T7+w2+w1+w0, T7+w1+w0, T7+w0

.endm

### AES256 key expansion second part ###
### compute r1 ###
### rcon=0x0 ###
.macro	key_expansion_256_2nd	r0 r1 rcon rhelp

	### r1=w12 w13 w14 w15 ###
	### w11=T7+w3+w2+w1+w0

	aeskeygenassist		$\rcon, \r0, \rhelp	#T7

	pshufd			$0xaa, \rhelp, \rhelp	#w8
	pxor			\r1, \rhelp		#rhelp	:w11+w7, w11+w6, w11+w5, w11+w4

	pslldq			$0x4, \r1		#r0	:w6, w5, w4, 0
	pxor			\r1, \rhelp		#rhelp	:w11+w7+w6, w11+w6+w5, w11+w5+w4, w11+w4
			
	pslldq			$0x4, \r1		#r0	:w5, w4, 0, 0
	pxor			\r1, \rhelp		#rhelp	:w11+w7+w6+w5, w11+w6+w5+w4, w11+w5+w4, w11+w4

	pslldq			$0x4, \r1		#r0	:w4, 0, 0, 0
	pxor			\rhelp, \r1		#r0	:w11+w7+w6+w5+w4, w11+w6+w5+w4, w11+w5+w4, w11+w4

.endm


.macro	key_schedule_256	rk0 rk1 rhelp

	key_expansion_256_1st	\rk0 \rk1 0x1 \rhelp
	key_expansion_256_2nd	\rk0 \rk1 0x0 \rhelp 

	key_expansion_256_1st	\rk0 \rk1 0x2 \rhelp
	key_expansion_256_2nd	\rk0 \rk1 0x0 \rhelp

	key_expansion_256_1st	\rk0 \rk1 0x4 \rhelp
	key_expansion_256_2nd	\rk0 \rk1 0x0 \rhelp

	key_expansion_256_1st	\rk0 \rk1 0x8 \rhelp
	key_expansion_256_2nd	\rk0 \rk1 0x0 \rhelp

	key_expansion_256_1st	\rk0 \rk1 0x10 \rhelp
	key_expansion_256_2nd	\rk0 \rk1 0x0 \rhelp

	key_expansion_256_1st	\rk0 \rk1 0x20 \rhelp
	key_expansion_256_2nd	\rk0 \rk1 0x0 \rhelp

	key_expansion_256_1st	\rk0 \rk1 0x40 \rhelp

.endm





.macro	inv_key_expansion_128	r0 rcon rhelp

	movdqa			\r0, \rhelp
	pslldq			$0x4, \rhelp	
	pxor			\rhelp, \r0
	aeskeygenassist 	$\rcon, \r0, \rhelp
	psrldq			$0xC, \rhelp
	pxor			\rhelp, \r0
	
.endm


### r0 r1 situation, position of r0 < position of r1 ###

### inv AES256 key expansion first part ###
### compute r1 ###
### rcon=0x0 ###
.macro	inv_key_expansion_256_1st	r0 r1 rcon rhelp

	movdqa			\r1, \rhelp
	pslldq			$0x4, \rhelp	
	pxor			\rhelp, \r1
	aeskeygenassist 	$\rcon, \r0, \rhelp
	pslldq			$0x4, \rhelp
	psrldq			$0xC, \rhelp
	pxor			\rhelp, \r1

.endm



### inv AES256 key expansion seconnd part ###
### compute r0 ###
.macro	inv_key_expansion_256_2nd	r0 r1 rcon rhelp

	### r1 is prior one, r0 is high than r1 ###

	movdqa			\r0, \rhelp
	pslldq			$0x4, \rhelp	
	pxor			\rhelp, \r0
	aeskeygenassist 	$\rcon, \r1, \rhelp
	psrldq			$0xC, \rhelp
	pxor			\rhelp, \r0

.endm



###########################################################################
###########################################################################
### 128bit ###

.set	rk_128,	T2xmm		/* AES-128 round key */
.set	rhelp_128,	T3xmm		/* helping register */


.macro	key_expansion_128_128bit  r0 rcon rhelp

	vaeskeygenassist	$\rcon, \r0, \rhelp
		
	vpshufd			$0xff, \rhelp, \rhelp	
	vpxor			\r0, \rhelp, \rhelp	#rhelp	:T3+w3, T3+w2, T3+w1, T3+20

	vpslldq			$0x4, \r0, \r0		#r0	:w2, w1, w0, 0
	vpxor			\r0, \rhelp, \rhelp	#rhelp	:T3+w3+w2, T3+w2+w1, T3+w1+w0, T3+w0
			
	vpslldq			$0x4, \r0, \r0		#r0	:w1, w0, 0, 0
	vpxor			\r0, \rhelp, \rhelp	#rhelp	:T3+w3+w2+w1, T3+w2+w1+w0, T3+w1+w0, T3+w0

	vpslldq			$0x4, \r0, \r0		#r0	:w0, 0, 0, 0
	vpxor			\rhelp, \r0, \r0	#r0	:T3+w3+w2+w1+w0, T3+w2+w1+w0, T3+w1+w0, T3+w0

.endm


### use for key schedule ###
.macro	key_schedule_128_128bit	

	key_expansion_128	rk_128 0x1 rhelp_128
	key_expansion_128	rk_128 0x2 rhelp_128
	key_expansion_128	rk_128 0x4 rhelp_128
	key_expansion_128	rk_128 0x8 rhelp_128
	key_expansion_128	rk_128 0x10 rhelp_128
	key_expansion_128	rk_128 0x20 rhelp_128
	key_expansion_128	rk_128 0x40 rhelp_128
	key_expansion_128	rk_128 0x80 rhelp_128
	key_expansion_128	rk_128 0x1b rhelp_128
	key_expansion_128	rk_128 0x36 rhelp_128

.endm


.macro	inv_key_expansion_128_128bit	r0 rcon rhelp

	#movdqa			\r0, \rhelp
	vpslldq			$0x4, \r0, \rhelp	
	vpxor			\rhelp, \r0, \r0
	vaeskeygenassist 	$\rcon, \r0, \rhelp
	vpsrldq			$0xC, \rhelp, \rhelp
	vpxor			\rhelp, \r0, \r0
	
.endm



.macro	xor_arg_128_128bit

	vpxor 				rk_128, A0xmm, A0xmm
	vpxor 				rk_128, A1xmm, A1xmm
	vpxor 				rk_128, A2xmm, A2xmm
	vpxor 				rk_128, A3xmm, A3xmm
	vpxor 				rk_128, B0xmm, B0xmm
	vpxor 				rk_128, B1xmm, B1xmm
	vpxor 				rk_128, B2xmm, B2xmm
	vpxor 				rk_128, B3xmm, B3xmm
	
.endm



.macro	aesdec_arg_128_128bit				

	vaesdec 			rhelp_128, A0xmm, A0xmm
	vaesdec 			rhelp_128, A1xmm, A1xmm
	vaesdec 			rhelp_128, A2xmm, A2xmm
	vaesdec 			rhelp_128, A3xmm, A3xmm
	vaesdec 			rhelp_128, B0xmm, B0xmm
	vaesdec 			rhelp_128, B1xmm, B1xmm
	vaesdec 			rhelp_128, B2xmm, B2xmm
	vaesdec 			rhelp_128, B3xmm, B3xmm
	
.endm


.macro	aesdeclast_arg_128_128bit	

	vaesdeclast  			rhelp_128, A0xmm, A0xmm
	vaesdeclast  			rhelp_128, A1xmm, A1xmm
	vaesdeclast  			rhelp_128, A2xmm, A2xmm
	vaesdeclast  			rhelp_128, A3xmm, A3xmm
	vaesdeclast  			rhelp_128, B0xmm, B0xmm
	vaesdeclast  			rhelp_128, B1xmm, B1xmm
	vaesdeclast  			rhelp_128, B2xmm, B2xmm
	vaesdeclast  			rhelp_128, B3xmm, B3xmm

.endm


.macro	aesenc_arg_128_128bit				

	vaesenc 			rk_128, A0xmm, A0xmm
	vaesenc 			rk_128, A1xmm, A1xmm
	vaesenc 			rk_128, A2xmm, A2xmm
	vaesenc 			rk_128, A3xmm, A3xmm
	vaesenc 			rk_128, B0xmm, B0xmm
	vaesenc 			rk_128, B1xmm, B1xmm
	vaesenc 			rk_128, B2xmm, B2xmm
	vaesenc 			rk_128, B3xmm, B3xmm
	
.endm


.macro	aesenclast_arg_128_128bit	

	vaesenclast  			rk_128, A0xmm, A0xmm
	vaesenclast  			rk_128, A1xmm, A1xmm
	vaesenclast  			rk_128, A2xmm, A2xmm
	vaesenclast  			rk_128, A3xmm, A3xmm
	vaesenclast  			rk_128, B0xmm, B0xmm
	vaesenclast  			rk_128, B1xmm, B1xmm
	vaesenclast  			rk_128, B2xmm, B2xmm
	vaesenclast  			rk_128, B3xmm, B3xmm

.endm



