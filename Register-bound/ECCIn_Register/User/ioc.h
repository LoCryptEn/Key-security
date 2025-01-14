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


#define ECDSA_OP		_IOWR(IsoToken_IOC_ID,10,int)
#define INIT _IOWR(IsoToken_IOC_ID,18,int)
#define SELF_TEST _IOWR(IsoToken_IOC_ID,19,int)


#define H_LEN						(sizeof(unsigned int)*8/sizeof(char))
#define LOG_FLAGS					O_RDWR|O_CREAT|O_APPEND
#define LOG_PERMISSION				0666


#define MOD_FLAGS					O_RDWR
#define MOD_PERMISSION 				0444

#define USER_NAME_SIZE 				32
#define PIN_LEN 					8
#define SALT_LEN 					3
//the size of password for generate the master key
#define SM4_KEY_SIZE 16


typedef struct _INIT_Para{
	uint8_t sm4Key[AES_KEY_SIZE];
}INIT_Para;

typedef struct _ECDSA_Para{
	unsigned long long  messages[25];
}ECDSA_Para;

typedef struct _SM4_Para
{
	int 	len;					//the length of plain or cipher
	int 	mode;					//1:ecb  	2:cbc
	int 	flag;					//0:dec 	1:enc 
	uint8_t key[AES_KEY_LEN];
	uint8_t	iv[AES_KEY_LEN];
	uint8_t plain[MAX_PLAIN_LEN];
	uint8_t cipher[MAX_PLAIN_LEN];
	unsigned char pin[PIN_LEN];
}SM4_Para;


//the flag whether MASTER key is inited, 1 inited, 0 not
int Inited = 0;
//whether the module is ok for crypto invocation, 1 ok, 0 not
int ServiceAvailable = 0;
//whether the code integrity of module, 1 ok, 0 not
int IntegrityVerifed = 0;


#endif
