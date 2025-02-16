#ifndef IOC_H
#define IOC_H


#ifndef __KERNEL__
#define __user
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif



#define IsoToken_IOC_ID 'T'

#define MAX_PLAIN_LEN	4096
#define AES_KEY_LEN 	16


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
#define AES_KEY_SIZE 16
#define ECDSA_SIG_SIZE 192

typedef struct _INIT_Para{
	unsigned char aesKey[AES_KEY_SIZE];
}INIT_Para;

typedef struct _ECDSA_Para{
	unsigned char message[ECDSA_SIG_SIZE];
}ECDSA_Para;

//the flag whether MASTER key is inited, 1 inited, 0 not
int Inited = 0;
//whether the module is ok for crypto invocation, 1 ok, 0 not
int ServiceAvailable = 0;
//whether the code integrity of module, 1 ok, 0 not
int IntegrityVerifed = 0;


#endif
