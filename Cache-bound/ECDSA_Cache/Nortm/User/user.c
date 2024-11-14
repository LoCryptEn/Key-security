#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>
#include <termios.h>

#include "aes.h"
#include "ecc.h"
#include "ioc.h"
#include "pbkdf_sha256.h"

//gcc -g -o user user.c EllipticCurve.c Mpi.c sm3hash.c -lpthread
int debugFlag = 1;
unsigned int succ_count = 0;

#define ECHOFLAGS (ECHO | ECHOE | ECHOK | ECHONL)

ECDSA_SIGN_Para ecdsa_para;
char key[MASTER_KEY_SIZE], verify[MASTER_KEY_SIZE];
unsigned char pubkey[64];
unsigned char prikey[32];
unsigned char prikey_cipher[32];
// #define MESBUFLEN 1025
// unsigned char message[MESBUFLEN] = {0x6d,0x65,0x73,0x73,0x61,0x67,0x65,0x20,0x64,0x69,0x67,0x65,0x73,0x74};
unsigned char sig[64];

unsigned char un_pubkey[64];
unsigned char un_prikey[32];

int init_flag = 0;
int keygen_flag_normal = 0;
int keygen_flag_safe = 0;

void printhex(unsigned char * output, int len)
{
    for(int i = 0; i < len; i++){
		if (i == 32) {
            printf("\n");
        }
        printf("%02x ", output[i]);
    }
    printf("\n");
}

int saferead(char *s, int size)
{
	int n=0;
	char c;
	while((c = getchar()) == '\n');	// read last '\n'
	for(; n<size; )
	{
		s[n++] = c;
		if((c = getchar()) == '\n')
			break;
	}
	if(c != '\n')		// we get last chars
	{
		while(getchar()!='\n');
	}
	return n;
}

int safereadstring(char *s, int size)
{
	int n = saferead(s, size-1);
	s[n] = '\0';
	return n;
}

int set_disp_mode(int fd,int option)
{
   int err;
   struct termios term;
   if(tcgetattr(fd,&term)==-1){
     printf("Cannot get the attribution of the terminal\n");
     return 1;
   }
   if(option)
        term.c_lflag|=ECHOFLAGS;
   else
        term.c_lflag &=~ECHOFLAGS;
   err=tcsetattr(fd,TCSAFLUSH,&term);
   if(err==-1 && err==EINTR){
        printf("Cannot set the attribution of the terminal");
        return 1;
   }
   return 0;
}

int getpasswd(char *passwd, int size){
	int c;
	int n = 0;
	set_disp_mode(STDIN_FILENO,0);
	n = saferead(passwd, size);
	set_disp_mode(STDIN_FILENO,1);
	return n;
}

int InitModule()
{
    int i=0;

	INIT_Para para;
	int fd;

	if(debugFlag)
	{
		memset(key,0,MASTER_KEY_SIZE);
		memcpy(key,"12345678",8);
	}
	else
	{
		while(1){
	        memset(key,0x0,MASTER_KEY_SIZE);
	        memset(verify,0x0,MASTER_KEY_SIZE);
			printf("Please input MASTER KEY[%d max]:\n",MASTER_KEY_SIZE);
			getpasswd(key,MASTER_KEY_SIZE);

			printf("Please input MASTER KEY again[%d max]:\n",MASTER_KEY_SIZE);
			getpasswd(verify,MASTER_KEY_SIZE);
			if(strncmp(key, verify, MASTER_KEY_SIZE)==0){
				break;
			}else{
				printf("two input master key is different, please input again\n");
			}
		}
	}
	
	memcpy(para.masterKey,key,MASTER_KEY_SIZE);
	fd = open("/dev/nortm", O_RDWR, 0);
	if(fd<0){
		printf("Error while access Kernel Module\n");
		return 0;
	}
	if(ioctl(fd, INIT, &para) == -1){
		printf("Error while init MASTER KEY\n");
		return 0;
	}
	memset(key,0x0,MASTER_KEY_SIZE);
	memset(verify,0x0,MASTER_KEY_SIZE);
	memset(&para,0,sizeof(para));
	printf("Init MASTER KEY succeed\n");
	init_flag=1;

	close(fd);

	return 1;
}

int ecdsa_normal_keygen(){
	//ç”Ÿæˆå…?ç§é’¥å¯?
    if (ecc_make_key(un_pubkey, un_prikey)){
		printf("\n############## private key ###############\n");
		printhex(un_prikey,32);
   	 	printf("\n");
    	printf("############## public key ###############\n");
		printhex(un_pubkey,64);
		printf("\n");
		keygen_flag_normal = 1;
		return 1;
    }
	return 0;
}

int ecdsa_safe_keygen(){
	//ç”Ÿæˆå…?ç§é’¥å¯?
    if (ecc_make_key(pubkey, prikey)){
		unsigned char outtemp[16];	
		memset(key,0,MASTER_KEY_SIZE);
		memcpy(key,"12345678",8);
		unsigned char salt[8] = {0x1,0x2,0x3,0x3,0x5,0x6,0x7,0x8};
		//outtempä¸ºaesç§˜é’¥ï¼Œç”¨äºŽåŠ å¯†ecdsaç§é’¥
		pbkdf2_sha256(key, MASTER_KEY_SIZE, salt, 8, 1000, outtemp, 16);
		//ç”¨outtempåŠ å¯†prikeyï¼Œå¾—åˆ°prikey_cipher
		AESEncryptWithMode(prikey, 32, prikey_cipher, 32, NULL, ECB, outtemp);
		memset(prikey, 0, 32);
		printf("\n############## private key (encrypted) ###############\n");
		printhex(prikey_cipher,32);
   	 	printf("\n");
    	printf("############## public key ###############\n");
		printhex(pubkey,64);
		printf("\n");
		keygen_flag_safe = 1;
		return 1;
    }
	return 0;
}

int ecdsa_normal_sign_user(ECDSA_SIGN_Para *ecdsapara_u){

	int signRes;
	//user -> kernel
	signRes = SignMessage(ecdsapara_u->d,ecdsapara_u->message,ecdsapara_u->sign,ecdsapara_u->msg_len);

	//vfree(ecdsapara_k);

	return signRes;
}

int verify_sign(ECDSA_SIGN_Para *ecdsapara_u){
	int verifyRes;
	verifyRes = VerifySign(ecdsapara_u->p,ecdsapara_u->message,ecdsapara_u->sign,ecdsapara_u->msg_len);
	return verifyRes;
}

int main(int argc, char **argv){
	int ret,i;
	int fd = -1;
	struct timeval beg,end;
	int type;

	fd = open("/dev/nortm", O_RDWR, 0);
	if (fd < 0) {
		perror("open /dev/nortm failed");
		return 0;
	}

	printf("Input a num: \n");
	printf("\t--1 Init the module (setting the master key)\n");
	printf("\t--2 KeyGen \t\t --3 SafeKeyGen \n "); 
	printf("\t--4 Sign \t\t --5 Safe Sign \n ");
	printf("\t--6 Quit \n");

	while(1){
		scanf("%d",&type);
		switch(type){
			case 1: {
				if(InitModule()){
					printf("Init module OK\n");
				}
				else{
					printf("Init module fail\n");
					return 0;
				}
				break;
			}
			case 2: {
				if(init_flag == 0){
					printf("please init module first\n");
				}
				else if(!ecdsa_normal_keygen()){
					printf("ecdsa_normal_keygen failure\n");
					return 0;
				}
				break;
			}
			case 3: {
				if(init_flag == 0){
					printf("please init module first\n");
				}
				else if(!ecdsa_safe_keygen()){
					printf("ecdsa_safe_keygen failure\n");
					return 0;
				}
				break;
			}
			//normal sign
			case 4: {
				if(init_flag == 0){
					printf("please init module first\n");
				}
				else if(keygen_flag_normal == 0){
					printf("please generate normal key first\n");
				}
				else{
					// printf("%s\n", ecdsa_para.message);
					gettimeofday(&beg,NULL);
					memcpy(ecdsa_para.d,un_prikey,32);

					printf("Input a message, max len is %d: ", MAX_PLAIN_LEN-1);
					ecdsa_para.msg_len = safereadstring(ecdsa_para.message, MAX_PLAIN_LEN-1);
					printf("Message is :%s\n", ecdsa_para.message);
					// memcpy(ecdsa_para.message,message, 14);
					// ecdsa_para.msg_len = 14;
					if(ioctl(fd,ECDSA_SIGN, &ecdsa_para) == -1){
						printf("sign err\n");
						return 0;
					}
					else{
						printf("\nnormal sign success\n");
						printhex(ecdsa_para.sign,64);
						__sync_fetch_and_add(&succ_count,1);
					}
					gettimeofday(&end,NULL);
					memcpy(ecdsa_para.p,un_pubkey,64);
					ret = verify_sign(&ecdsa_para);
					if(ret == 1){
						printf("\nverify success\n");
					}
					else{
						printf("verify failed\n");
					}
					printf("sign speed: \t %f\n", (float)1000000/(end.tv_usec-beg.tv_usec+1000000*(end.tv_sec-beg.tv_sec)));
				}
				break;
			}
			//safe sign
			case 5: {
				if(init_flag == 0){
					printf("please init module first\n");
				}
				else if(keygen_flag_safe == 0){
					printf("please generate safe key first\n");
				}
				else{
					// printf("%s\n", ecdsa_para.message);
					gettimeofday(&beg,NULL);
					memcpy(ecdsa_para.d,prikey_cipher,32);

					printf("Input a message, max len is %d: ", MAX_PLAIN_LEN-1);
					ecdsa_para.msg_len = safereadstring(ecdsa_para.message, MAX_PLAIN_LEN-1);
					printf("Message is :%s\n", ecdsa_para.message);
					// memcpy(ecdsa_para.message,message, 14);
					// ecdsa_para.msg_len = 14;
					if(ioctl(fd,ECDSA_SAFE_SIGN, &ecdsa_para) == -1){
						printf("sign err\n");
					}
					else{
						printf("\nsafe sign success\n");
						printhex(ecdsa_para.sign,64);
						__sync_fetch_and_add(&succ_count,1);
					}
					gettimeofday(&end,NULL);
					memcpy(ecdsa_para.p,pubkey,64);
					ret = verify_sign(&ecdsa_para);
					if (ret == 1){
						printf("\nverify success\n");
					} 
					else{
						printf("verify failed\n");
					}
					printf("sign speed: \t %f\n", (float)1000000/(end.tv_usec-beg.tv_usec+1000000*(end.tv_sec-beg.tv_sec)));
				break;
				}
			}
			case 6: {
				return 0;
			}
		}
	}
	close(fd);

	//char typechar[4][15] = {"Sign","SafeSign"};
	//printf("success cout is \t %d \t type \t %s \t speed: \t %f\n", succ_count,typechar[type-4], (float)(succ_count)*1000000/(end.tv_usec-beg.tv_usec+1000000*(end.tv_sec-beg.tv_sec)));
	return 0;
}
