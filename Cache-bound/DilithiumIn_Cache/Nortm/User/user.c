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

#include "ioc.h"
#include "ecc.h"
#include "pbkdf_sha256.h"
#include "SMS4.h"

int TOTAL_THREAD = 1;
int LOOP = 1;
int ELOOPS = 1;
int type = 1;
int debugFlag = 0;

SM2_SIGN_Para testsm2sign;
unsigned int succ_count = 0;

//gcc -g -o user user.c EllipticCurve.c Mpi.c sm3hash.c -lpthread

void printhex(unsigned char * output, int len)
{
    int i = 0;
    for(i = 0; i < len; i++)
    {
        printf(" %02x", output[i]);
    }
    printf("\n");
}

void *testthread(void *para1){
	int i,j,fd = -1;
	size_t ret = 0;
	
	KYBER_ENC_Para kyberenc_para;
	KYBER_DEC_Para kyberdec_para;

	type = *(int *)para1;
	
	fd = open("/dev/nortm", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/nortm)");
		return NULL;
	}

	for(i=0;i<LOOP;++i){
		switch(type){

				//SM2 DEC
			case 6: {
				testsm2.len = 116;
				memcpy(testsm2.d,pRandomUser,32);
				memcpy(testsm2.x,sm2x,32);
				memcpy(testsm2.y,sm2y,32);
				memcpy(testsm2.cipher,sm2cipher,116);
				memset(testsm2.plain,0,SM2_MAX_PLAIN_LEN);
				memcpy(testsm2.pin,pin,PIN_LEN);
				if(ioctl(fd,SM2_DEC,&testsm2) == -1){
					if(debugFlag)
						printf("dec err\n");
				}
				else{
					if(debugFlag)
						printf("%s\n",testsm2.plain );
					__sync_fetch_and_add(&succ_count,1);
				}
				break;
			}
				

			default: {
				break;
			}
		}
	}
	if (close(fd)) {
		perror("close(fd)");
		return NULL;
	}
	return NULL;
}

#define ECHOFLAGS (ECHO | ECHOE | ECHOK | ECHONL)

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
	scanf("%s",passwd);
	set_disp_mode(STDIN_FILENO,1);
	return n;
}
 /*init the module
 *obtain the master key
 */
int InitModule()
{
    int i=0;
   
	INIT_Para para;
	char key[MASTER_KEY_SIZE], verify[MASTER_KEY_SIZE];
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

	close(fd);

	return 1;
}


int main(int argc, char **argv){
	int i,res,t;
	if(argc == 6 || argc == 5){
		TOTAL_THREAD = atoi(argv[1]);
		LOOP = atoi(argv[2]);
		ELOOPS = atoi(argv[3]);
		type = atoi(argv[4]);
		if(argc == 6)
			debugFlag = atoi(argv[5]);
	}else
	{
		printf("./user: theads perThreadsLoop eloop type debug(0:no debug default, 1:debug)\n");
		printf("type: \n");
		printf("\t--1 Init the module (setting the master key)\n");
		printf("\t--2 Kyber Enc \t\t --3 Kyber Dec \n "); 
		return -1;
	}

	if(type ==1)
	{
		printf("Init the module\n");
		InitModule();
		return 0;
	}

	struct timeval beg,end;
	pthread_t *th;

	th = (pthread_t *)malloc(TOTAL_THREAD * sizeof(pthread_t));
	//void *th_result;
	printf("TOTAL_THREAD \t %d \t LOOP \t %d \t ELOOPS \t %d \t type \t %d \t",TOTAL_THREAD, LOOP, ELOOPS,type);
	succ_count = 0;
    gettimeofday(&beg,NULL);
	for(i=0;i<ELOOPS;++i){	
		for(t= 0;t< TOTAL_THREAD;++t){
			res = pthread_create(th+t,NULL,testthread,(void *)&type);
			if(res != 0){
				perror("thread create error\n");
				exit(-1);
			}
		}
		for(t= 0;t< TOTAL_THREAD;++t){
			//pthread_join(*(th+t),&th_result);
			pthread_join(*(th+t),(void *)NULL);
		}
		
	}
	free(th);
	gettimeofday(&end,NULL);
	
	char typechar[2][15] = {"KyberEnc","KyberDec"};
	printf("success cout is \t %d \t type \t %s \t speed: \t %f\n", succ_count,typechar[type-2], (float)(succ_count)*1000000/(end.tv_usec-beg.tv_usec+1000000*(end.tv_sec-beg.tv_sec)));		
	return 0;
}

