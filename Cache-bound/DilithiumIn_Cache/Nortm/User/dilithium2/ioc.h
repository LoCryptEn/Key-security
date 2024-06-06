#ifndef IOC_H
#define IOC_H


#ifndef __KERNEL__
#define __user
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif

#include "params.h"


#define IsoToken_IOC_ID 'T'

#define SM4_KEY_LEN 	16
#define SM3_DIGEST_LEN	32

#define MAX_MESSAGE_LEN 4096


#define INIT _IOWR(IsoToken_IOC_ID,1,int)

#define DILITHIUM_KEYGEN _IOWR(IsoToken_IOC_ID,2,int)
#define DILITHIUM_SAFE_KEYGEN _IOWR(IsoToken_IOC_ID,3,int)
#define DILITHIUM_SIGN _IOWR(IsoToken_IOC_ID,4,int)
#define DILITHIUM_SAFE_SIGN _IOWR(IsoToken_IOC_ID,5,int)


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

typedef struct _INIT_Para{
	uint8_t masterKey[MASTER_KEY_SIZE];
}INIT_Para;

typedef struct _KEYGEN_Para{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
}KEYGEN_Para;

typedef struct _SIGN_Para{
    uint8_t m[MAX_MESSAGE_LEN];                   //message
    size_t mlen;
    uint8_t sm[CRYPTO_BYTES + MAX_MESSAGE_LEN];   //sig+message
    size_t smlen;
    uint8_t sk[CRYPTO_SECRETKEYBYTES];            //secret key
}SIGN_Para;


//for TSX

//the flag whether MASTER key is inited, 1 inited, 0 not
int Inited = 0;

//the number of continus PIN error
//static int PIN_Error = 0;
#define MAX_PIN_ERROR 3

unsigned char pin_list[32]; 
unsigned char salt[SALT_LEN] = {0x61,0x62,0x63};


#endif
