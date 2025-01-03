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


    ###########AES_DEC###########
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


	






	### load p0 to M0 and Dec ###
	addq		$512, %rsi
	vmovdqu		(%rsi), M0xmm



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

	#####################################################################
	### Enc and Store R ###
	
	#### store B ####
	# store_B
	store_A #A在存之前是R

	vmovq	%xmm31,	%rcx
	vmovdqu64 	A0, (%rcx)
	vmovdqu64 	A1, 32(%rcx)
	vmovdqu64 	A2, 64(%rcx)
	vmovdqu64 	A3, 96(%rcx)
	vmovdqu64 	B0, 128(%rcx)
	vmovdqu64 	B1, 160(%rcx)
	vmovdqu64 	B2, 192(%rcx)
	vmovdqu64 	B3, 224(%rcx)


	

	##################################################################
	##################################################################
	### load Cp*R to A B and Dec ###

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


	
	### rerange Cp*R to A ###
 
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

	### Compute CpR=CpR * Rp*R^(-1)mod p ###	
	#Cp*R in A, and result CpR store in A	
	call montmul1024 #Cp*R现在在 A里

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
    
	subq $640, %rsi
    ### new add-- aes-dec-- ###



	########## aes_dec end###############
	addq $640, %rsi
	### new add-- aes-dec-- ###
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
	
	########## aes_dec end###############

	


	### load q0 to M0 and Dec ###
	addq		$512, %rsi
	vmovdqu		(%rsi), M0xmm


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







	##################################################################
	
	#### transfer %rsi ####
	popq		%rsi
	movq		%rsi, %mm0

	### compute Cq^imq1 mod p ###
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


	
##################################################################################################
	###							###	
	### 	montexp1024_AES_q END 				###
	###							###
	###	result A0 A1 A2 A3				###
	###							###
##################################################################################################


	ret
	.size	montexp1024_AES_q, .-montexp1024_AES_q



