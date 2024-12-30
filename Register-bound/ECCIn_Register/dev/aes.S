.file   "aes.S"
.text

// Register assignments
.set    rstate,  %xmm0  // AES state (message)
.set    rk0,     %xmm1  // Round key 0 (initial key)
.set    rk1,     %xmm2  // Round key 1
.set    rk2,     %xmm3  // Round key 2
.set    rk3,     %xmm4  // Round key 3
.set    rk4,     %xmm5  // Round key 4
.set    rk5,     %xmm6  // Round key 5
.set    rk6,     %xmm7  // Round key 6
.set    rk7,     %xmm8  // Round key 7
.set    rk8,     %xmm9  // Round key 8
.set    rk9,     %xmm10 // Round key 9
.set    rk10,    %xmm11 // Round key 10
.set    rhelp,   %xmm12 // Helping register for key schedule

// Key schedule macro (reusable)
.macro key_schedule r0, r1, rcon
    pxor    rhelp,      rhelp
    movdqu  \r0,        \r1
    shufps  $0x1f,      \r1,    rhelp   
    pxor    rhelp,      \r1  
    shufps  $0x8c,      \r1,    rhelp
    pxor    rhelp,      \r1  
    aeskeygenassist      $\rcon, \r0, rhelp
    shufps  $0xff,      rhelp,  rhelp
    pxor    rhelp,      \r1
.endm

// AES_ENC function: Encrypt the message using the provided key
// Arguments:
//   - key (first argument): passed in %xmm1
//   - message (second argument): passed in %xmm0
// Output: 
//   - encrypted message in %xmm0

.globl AES_ENC
AES_ENC:

    // Generate the round keys using the key_schedule macro
    key_schedule rk0, rk1, 0x1
    key_schedule rk1, rk2, 0x2
    key_schedule rk2, rk3, 0x4
    key_schedule rk3, rk4, 0x8
    key_schedule rk4, rk5, 0x10
    key_schedule rk5, rk6, 0x20
    key_schedule rk6, rk7, 0x40
    key_schedule rk7, rk8, 0x80
    key_schedule rk8, rk9, 0x1b
    key_schedule rk9, rk10, 0x36

    // Encryption rounds
    pxor    rk0, rstate       // Initial XOR with first round key
    aesenc  rk1, rstate       // Encryption rounds
    aesenc  rk2, rstate
    aesenc  rk3, rstate
    aesenc  rk4, rstate
    aesenc  rk5, rstate
    aesenc  rk6, rstate
    aesenc  rk7, rstate
    aesenc  rk8, rstate
    aesenc  rk9, rstate
    aesenclast rk10, rstate   // Last round of AES

    // Return encrypted message in %xmm0 (rstate)
    ret

.global AES_DEC
AES_DEC:

    // Generate the round keys using the key_schedule macro
    key_schedule rk0, rk1, 0x1
    key_schedule rk1, rk2, 0x2
    key_schedule rk2, rk3, 0x4
    key_schedule rk3, rk4, 0x8
    key_schedule rk4, rk5, 0x10
    key_schedule rk5, rk6, 0x20
    key_schedule rk6, rk7, 0x40
    key_schedule rk7, rk8, 0x80
    key_schedule rk8, rk9, 0x1b
    key_schedule rk9, rk10, 0x36

    // 对轮密钥应用 aesimc 进行逆向处理
    aesimc  rk1, rk1
    aesimc  rk2, rk2
    aesimc  rk3, rk3
    aesimc  rk4, rk4
    aesimc  rk5, rk5
    aesimc  rk6, rk6
    aesimc  rk7, rk7
    aesimc  rk8, rk8
    aesimc  rk9, rk9

    // 初始 XOR 操作
    pxor    rk10, rstate       // Initial XOR with last round key

    // 解密轮
    aesdec  rk9, rstate
    aesdec  rk8, rstate
    aesdec  rk7, rstate
    aesdec  rk6, rstate
    aesdec  rk5, rstate
    aesdec  rk4, rstate
    aesdec  rk3, rstate
    aesdec  rk2, rstate
    aesdec  rk1, rstate

    // 最后一轮解密
    aesdeclast rk0, rstate

    // 返回解密后的消息在 %xmm0 (rstate)
    ret
