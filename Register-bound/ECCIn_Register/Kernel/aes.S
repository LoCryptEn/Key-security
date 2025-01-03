.file	"aes.S"
.text

.set    rstate,     %xmm0  //AES state
.set    rhelp,     %xmm1  //helping reg 1
.set    rhelp2,     %xmm13  //helping reg 2
.set    rk0,     %xmm2  //round key 0
.set    rk1,     %xmm3  //round key 1
.set    rk2,     %xmm4  //round key 2
.set    rk3,     %xmm5  //round key 3
.set    rk4,     %xmm6  //round key 4
.set    rk5,     %xmm7  //round key 5
.set    rk6,     %xmm8  //round key 6
.set    rk7,     %xmm9  //round key 7
.set    rk8,     %xmm10  //round key 8
.set    rk9,     %xmm11  //round key 9
.set    rk10,     %xmm12  //round key 10
.set    mes,      %xmm15 //message

.macro      key_shedule     r0      r1      rcon
    pxor    rhelp,      rhelp
    movdqu      \r0,    \r1
    shufps      $0x1f,      \r1,    rhelp   
    pxor    rhelp,      \r1  
    shufps      $0x8c,      \r1,    rhelp
    pxor    rhelp,      \r1  
    aeskeygenassist      $\rcon,      \r0,    rhelp
    shufps      $0xff,      rhelp,    rhelp
    pxor    rhelp,      \r1 
.endm

.macro      aes_enc
    key_shedule     rstate     rk1     0x1      
    key_shedule     rk1     rk2     0x2
    key_shedule     rk2     rk3     0x4
    key_shedule     rk3     rk4     0x8
    key_shedule     rk4     rk5     0x10
    key_shedule     rk5     rk6     0x20
    key_shedule     rk6     rk7     0x40
    key_shedule     rk7     rk8     0x80
    key_shedule     rk8     rk9     0x1b
    key_shedule     rk9     rk10     0x36

    pxor    rstate,     mes
    aesenc     rk1,     mes 
    aesenc     rk2,     mes
    aesenc     rk3,     mes
    aesenc     rk4,     mes
    aesenc     rk5,     mes
    aesenc     rk6,     mes
    aesenc     rk7,     mes
    aesenc     rk8,     mes
    aesenc     rk9,     mes
    aesenclast     rk10,     mes
.endm

.macro      aes_dec

    key_shedule     rstate     rk1     0x1      
    key_shedule     rk1     rk2     0x2
    key_shedule     rk2     rk3     0x4
    key_shedule     rk3     rk4     0x8
    key_shedule     rk4     rk5     0x10
    key_shedule     rk5     rk6     0x20
    key_shedule     rk6     rk7     0x40
    key_shedule     rk7     rk8     0x80
    key_shedule     rk8     rk9     0x1b
    key_shedule     rk9     rk10     0x36

    aesimc  rk1,    rk1
    aesimc  rk2,    rk2
    aesimc  rk3,    rk3
    aesimc  rk4,    rk4
    aesimc  rk5,    rk5
    aesimc  rk6,    rk6
    aesimc  rk7,    rk7
    aesimc  rk8,    rk8
    aesimc  rk9,    rk9

    pxor    rk10,     mes
    aesdec     rk9,     mes 
    aesdec     rk8,     mes
    aesdec     rk7,     mes
    aesdec     rk6,     mes
    aesdec     rk5,     mes
    aesdec     rk4,     mes
    aesdec     rk3,     mes
    aesdec     rk2,     mes
    aesdec     rk1,     mes
    aesdeclast     rstate,     mes
.endm