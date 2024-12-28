#ifndef SMS4_HEADER_FDA90FJA09H___FDA98SFHA____FD98ASFH__
#define SMS4_HEADER_FDA90FJA09H___FDA98SFHA____FD98ASFH__

#define SMS4_KEY_LENGTH				(128/8)
#define SMS4_BLOCK_LENGTH			(128/8)
#define SMS4_ROUND					32


#define ECB				  0x00000001
#define CBC				  0x00000002

typedef unsigned char BYTE;

int SM4EncryptWithMode(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV, unsigned char *IV, int mode, BYTE *Key);
int SM4DecryptWithMode(BYTE *Cipher, int CipherLength, BYTE *Plain, int hasIV, unsigned char *IV, int mode, BYTE *Key);
int SM4EncryptWithModePad(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV, unsigned char *IV, int mode, BYTE *Key);
int SM4DecryptWithModePad(BYTE *Cipher, int CipherLength, BYTE *Plain, int hasIV, unsigned char *IV, int mode, BYTE *Key);
void sm4_cypher_128_test(void);


#endif // SMS4_HEADER_FDA90FJA09H___FDA98SFHA____FD98ASFH__