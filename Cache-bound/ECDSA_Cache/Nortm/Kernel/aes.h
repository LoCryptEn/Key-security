
typedef enum {
    AES_CYPHER_128,
    AES_CYPHER_192,
    AES_CYPHER_256,
} AES_CYPHER_T;

#define ECB				  0x00000001
#define CBC				  0x00000002

typedef unsigned char  uint8_t;
typedef unsigned int   uint32_t;


int AESEncryptWithMode(uint8_t *Plain, int PlainLength, uint8_t *Cipher, int CipherLength,unsigned char *IV, int mode, uint8_t *Key);
int AESDecryptWithMode(uint8_t *Cipher, int CipherLength, uint8_t *Plain ,int PlainLength,unsigned char *IV, int mode, uint8_t *Key);
