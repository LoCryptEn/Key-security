#ifndef IOC_H
#define IOC_H


#ifndef __KERNEL__
#define __user
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif



#define IsoToken_IOC_ID 'T'

//#define MAX_PLAIN_LEN	4096
#define SM2_MAX_PLAIN_LEN	32
#define MAX_PLAIN_LEN	4096
#define SM2_KEY_LEN 	32
#define SM4_KEY_LEN 	16
#define SM3_DIGEST_LEN	32

#define SM2_KEYGEN	_IOWR(IsoToken_IOC_ID,1,int)
#define SM2_SIGN	_IOWR(IsoToken_IOC_ID,2,int)
#define SM2_DEC		_IOWR(IsoToken_IOC_ID,3,int)
#define SM2_VERIFY	_IOWR(IsoToken_IOC_ID,4,int)
#define SM2_ENC		_IOWR(IsoToken_IOC_ID,5,int)

#define SM3_DIGEST	_IOWR(IsoToken_IOC_ID,6,int)
#define SM3_INIT	_IOWR(IsoToken_IOC_ID,7,int)
#define SM3_UPDATE	_IOWR(IsoToken_IOC_ID,8,int)
#define SM3_FINAL	_IOWR(IsoToken_IOC_ID,9,int)

#define SM4_OP		_IOWR(IsoToken_IOC_ID,10,int)

#define SM2_SAFE_DEC _IOWR(IsoToken_IOC_ID,11,int)

#define SM3_SAFE_INIT _IOWR(IsoToken_IOC_ID,12,int)
#define SM3_SAFE_UPDATE _IOWR(IsoToken_IOC_ID,13,int)
#define SM3_SAFE_FINAL _IOWR(IsoToken_IOC_ID,14,int)

#define HMAC_FINAL_DEC _IOWR(IsoToken_IOC_ID,15,int)
#define SAFE_IPAD _IOWR(IsoToken_IOC_ID,16,int)
#define SAFE_OPAD _IOWR(IsoToken_IOC_ID,17,int)

#define INIT _IOWR(IsoToken_IOC_ID,18,int)
#define SELF_TEST _IOWR(IsoToken_IOC_ID,19,int)

#define SM2_SAFE_SIGN  _IOWR(IsoToken_IOC_ID,22,int)
#define SM2_SAFE_KEYGEN _IOWR(IsoToken_IOC_ID, 23, int)

#define SM2_ENC_TEST	_IOWR(IsoToken_IOC_ID,25,int)
#define SM2_SIGN_TEST	_IOWR(IsoToken_IOC_ID,26,int)

#define HMAC_INIT	_IOWR(IsoToken_IOC_ID,30,int)
#define HMAC_UPDATE	_IOWR(IsoToken_IOC_ID,31,int)
#define HMAC_FINAL	_IOWR(IsoToken_IOC_ID,32,int)

#define SM4_OP_PAD		_IOWR(IsoToken_IOC_ID,35,int)

#define GM_HMAC_MD_CBLOCK_SIZE      64 //144
#define PRE_MASTER_KEY_SIZE			48

#define H_LEN						(sizeof(unsigned int)*8/sizeof(char))
#define LOG_FLAGS					O_RDWR|O_CREAT|O_APPEND
#define LOG_PERMISSION				0666


#define SIGN_FILE 					"/cryptomodule.signatue"
#define SIGN_FLAGS 					O_RDWR
#define SIGN_PERMISSION 			0444

#define MOD_FLAGS					O_RDWR
#define MOD_PERMISSION 				0444

#define USER_NAME_SIZE 				32
#define PIN_LEN 					8
#define SALT_LEN 					3
//the size of password for generate the master key
#define MASTER_KEY_SIZE 32
typedef struct {
	unsigned char pad[GM_HMAC_MD_CBLOCK_SIZE];
	int len;
	unsigned char pin[PIN_LEN];
}GM_PAD;

typedef struct {
	unsigned int H[8];
    unsigned char BB[64];
    unsigned long long u64Length;
	unsigned long long pad;
}SM3_STATE_CIPHER;

typedef struct {
	SM3_STATE_CIPHER state;
	unsigned char key[GM_HMAC_MD_CBLOCK_SIZE];
	uint8_t digest[SM3_DIGEST_LEN];
	unsigned char pin[PIN_LEN];
	int klen, plainlen;
	uint8_t plain[MAX_PLAIN_LEN];
}GM_HMAC;

typedef struct {
	SM3_STATE_CIPHER state;
	unsigned char key[GM_HMAC_MD_CBLOCK_SIZE];
	uint8_t digest[SM3_DIGEST_LEN];
	unsigned char pin[PIN_LEN];
	int klen, plainlen;
}GM_HMAC_KER;

typedef struct _INIT_Para{
	uint8_t masterKey[MASTER_KEY_SIZE];
	uint8_t pin[PIN_LEN];
}INIT_Para;

typedef struct _Gen_Key_Para{
	uint8_t d[SM2_KEY_LEN];
	uint8_t x[SM2_KEY_LEN];
	uint8_t y[SM2_KEY_LEN];
	unsigned char pin[PIN_LEN]; 
}Gen_Key_Para;

typedef struct _SM2_Para{
	int     len;					//the length of plain or cipher
	uint8_t d[SM2_KEY_LEN];
	uint8_t x[SM2_KEY_LEN];
	uint8_t y[SM2_KEY_LEN];
	uint8_t plain[SM2_MAX_PLAIN_LEN+SM4_KEY_LEN];
	uint8_t cipher[1+SM2_KEY_LEN*3+SM2_MAX_PLAIN_LEN];
	unsigned char pin[PIN_LEN];
}SM2_Para;

typedef struct _SM2_SIG_Para{
	int len;					//the length of message
	uint8_t d[SM2_KEY_LEN];
	uint8_t x[SM2_KEY_LEN];
	uint8_t y[SM2_KEY_LEN];
	uint8_t message[SM2_MAX_PLAIN_LEN];
	uint8_t sign[SM2_KEY_LEN*2 + 1]; //max lenth is 64
	uint8_t pUserName[SM2_MAX_PLAIN_LEN];
	int LenOfpUserName;
	int LenOfsign;
	unsigned char pin[PIN_LEN];
}SM2_SIGN_Para;
typedef struct _SM3_State {
    unsigned int H[8];
    unsigned char BB[64];
    unsigned long long u64Length;
    int H_encrypted;
    int in_encrypted;
    int out_encrypted;
} SM3_State;

typedef struct _SM3_Para
{
	int 	plainLen;
	SM3_State	state;			
	uint8_t plain[MAX_PLAIN_LEN];
	uint8_t digest[SM3_DIGEST_LEN];
	unsigned char pin[PIN_LEN];
}SM3_Para;

typedef struct _SM4_Para
{
	int 	len;					//the length of plain or cipher
	int 	lastlen;				//the length of last
	int 	mode;					//1:ecb  	2:cbc
	int 	flag;					//0:dec 	1:enc 
	int 	hasiv;					//0:no iv	1:has iv
	uint8_t key[SM4_KEY_LEN];
	uint8_t	iniv[SM4_KEY_LEN];
	uint8_t	iv[SM4_KEY_LEN];
	uint8_t cipher[MAX_PLAIN_LEN];
	uint8_t plain[MAX_PLAIN_LEN];
	unsigned char pin[PIN_LEN];
	uint8_t last[SM4_KEY_LEN];	//don't need to encrypt
}SM4_Para;

//for TSX

//the flag whether MASTER key is inited, 1 inited, 0 not
int Inited = 0;
//whether the module is ok for crypto invocation, 1 ok, 0 not
int ServiceAvailable = 0;
//whether the code integrity of module, 1 ok, 0 not
int IntegrityVerifed = 0;
//the number of continus PIN error
static int PIN_Error = 0;
#define MAX_PIN_ERROR 3

unsigned char pin_list[32]; 
unsigned char salt[SALT_LEN] = {0x61,0x62,0x63};


#endif
