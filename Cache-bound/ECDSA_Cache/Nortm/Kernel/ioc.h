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
#define MAX_PLAIN_LEN	4096
#define SM4_KEY_LEN 	16
#define SM3_DIGEST_LEN	32

#define ECDSA_KEY_LEN	32

#define ECDSA_KEYGEN	_IOWR(IsoToken_IOC_ID,1,int)
#define ECDSA_SAFE_KEYGEN _IOWR(IsoToken_IOC_ID, 2, int)

#define ECDSA_SIGN	_IOWR(IsoToken_IOC_ID,3,int)
#define ECDSA_SAFE_SIGN  _IOWR(IsoToken_IOC_ID,4,int)

#define ECDSA_VERIFY	_IOWR(IsoToken_IOC_ID,5,int)

#define INIT _IOWR(IsoToken_IOC_ID,6,int)


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

typedef struct _INIT_Para{
	uint8_t masterKey[MASTER_KEY_SIZE];
}INIT_Para;

typedef struct _Gen_Key_Para{
	uint8_t d[ECDSA_KEY_LEN];
	uint8_t x[ECDSA_KEY_LEN];
	uint8_t y[ECDSA_KEY_LEN];
	unsigned char pin[PIN_LEN]; 
}Gen_Key_Para;



typedef struct _ECDSA_SIG_Para{
	int msg_len;					//the length of message
	uint8_t d[ECDSA_KEY_LEN];       //private key
	uint8_t p[ECDSA_KEY_LEN * 2];       //public key
	uint8_t x[ECDSA_KEY_LEN];
	uint8_t y[ECDSA_KEY_LEN];
	uint8_t message[MAX_PLAIN_LEN];
	uint8_t sign[ECDSA_KEY_LEN*2];
	int LenOfsign;	
}ECDSA_SIGN_Para;


typedef struct _SM4_Para
{
	int 	len;					//the length of plain or cipher
	int 	mode;					//1:ecb  	2:cbc
	int 	flag;					//0:dec 	1:enc 
	uint8_t key[SM4_KEY_LEN];
	uint8_t	iv[SM4_KEY_LEN];
	uint8_t plain[MAX_PLAIN_LEN];
	uint8_t cipher[MAX_PLAIN_LEN];
	unsigned char pin[PIN_LEN];
}SM4_Para;

//for TSX

//the flag whether MASTER key is inited, 1 inited, 0 not
int Inited = 0;

//the number of continus PIN error
//static int PIN_Error = 0;
#define MAX_PIN_ERROR 3

unsigned char pin_list[32]; 
unsigned char salt[SALT_LEN] = {0x61,0x62,0x63};


#endif
