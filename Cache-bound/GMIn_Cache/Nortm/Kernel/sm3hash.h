#ifndef DCS_ECC_HEADER_SM3
#define DCS_ECC_HEADER_SM3
// length = 256 bits = 32 bytes
#define SM3_HASH_256				32	
/*
#ifndef bool
#define bool char
#endif


#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif
*/


// 一次性完成, 输出在pOut, 长度是SM3_HASH_256
int Sm3Hash(unsigned char *pOut, const unsigned char *pIn, unsigned int iInLen /* in bytes */);


// 多次调用
typedef struct _SM3_HASH_STATE {
    unsigned int H[8];
    unsigned char BB[64];
    unsigned long long u64Length;
    int H_encrypted;
    int in_encrypted;
    int out_encrypted;
} SM3_HASH_STATE;

void Sm3HashInit(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen);
void Sm3HashPending(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen);
int Sm3HashFinal(unsigned char *pOut, SM3_HASH_STATE *pState);



unsigned int Sm3KDF(unsigned char *pKeyOut, unsigned int iLenOfOut /* in bytes */, const unsigned char *pSecret, unsigned int iLenOfSecret /* in bytes */);



// ----------------------------------------------------------------------
// SM3 HMAC
#define HMAC_B_LENGTH		64
#define HMAC_IPAD			0x36
#define HMAC_OPAD			0x5c

int Sm3Hmac(unsigned char *pOut, const unsigned char *pMsg, unsigned int iLenOfMsg, const unsigned char *pSecret, int iLenOfSecret);

typedef struct _SM3_HMAC_STATE {
    unsigned char padding [HMAC_B_LENGTH];
    SM3_HASH_STATE hashState;
} SM3_HMAC_STATE;

void Sm3HmacInit(SM3_HMAC_STATE *pState, const unsigned char *pSecret, int iLenOfSecret);
void Sm3HmacPending(SM3_HMAC_STATE *pState, const unsigned char *pIn, unsigned int iInLen);
int Sm3HmacFinal(unsigned char *pOut, SM3_HMAC_STATE *pState);

#endif
