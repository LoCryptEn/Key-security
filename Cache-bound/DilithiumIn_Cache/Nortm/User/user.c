#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "randombytes.h"
#include "sign.h"
#include "aes.h"

#define MLEN 8
#define NTESTS 10

//#define MLEN 59
//#define NTESTS 10000

/* add by mlj */

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>
#include <termios.h>

#include "ioc.h"
#include "pbkdf_sha256.h"

int LOOP = 0;
int debugFlag = 0;

typedef struct _Main_Para
{
	char * infile;
	char * outfile;
	char * statefile;
	int type;
}Main_Para;

char typechar[5][15] = {"KeyGen","SafeKeyGen", "Sign","SafeSign","Verify"};

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
	int n = 0;
	char c;
	set_disp_mode(STDIN_FILENO,0);
	//scanf("%s",passwd);
	for(; n<size; n++)
	{
		c = getchar();
		if(c == '\n')
			break;
		passwd[n] = c;
	}
	if(c != '\n')		// we get last chars
	{
		while(getchar()!='\n');
	}
	set_disp_mode(STDIN_FILENO,1);
	return n;
}

/* add by mlj */
void printhex(unsigned char * output, int len)
{
    int i = 0;
    for(i = 0; i < len; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
}

int getnum(char c)
{
	if ('0'<= c && c <= '9')
		return c-'0';
	if ('a'<=c && c<='f' )
		return c-'a'+10;
	if ('A'<=c && c<='F')
		return c-'A'+10;
	return -1;
}

int writehex(char * output, const unsigned char * input, int len)
{
	int i = 0, loc = 0;
	for(i = 0; i < len; i++)
    {
        loc += sprintf(output+loc, "%02x", input[i]);
    }
	output[loc] = 0;
	return loc;
}

int readhex(unsigned char * output, const char * input, int len)
{
	if(len&1)	//hex format must be even
		return -1;
	int a, b;
	for(int i=0; i<len; i+=2)
	{	
		if( ((a=getnum(input[i]))<0) || ((b = getnum(input[i|1]))<0) )
			return -1;
		output[i>>1] = (a<<4)|b;
	}
	return len>>1;
}

 /*init the module
 *obtain the master key
 */
int InitModule()
{
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
			if(strncmp(key, verify, MASTER_KEY_SIZE)==0) {
				break;
			} else {
				printf("two input master key is different, please input again\n");
			}
		}
	}

	memcpy(para.masterKey,key,MASTER_KEY_SIZE);
	fd = open("/dev/nortm", O_RDWR, 0);
	if(fd < 0){
		printf("Error while access Kernel Module\n");
		return 0;
	}

	if(ioctl(fd, INIT, &para) == -1){
		// printf("Error while init MASTER KEY\n");
		return 0;
	}

	printf("Init MASTER KEY succeed\n");

	memset(key,0x0,MASTER_KEY_SIZE);
	memset(verify,0x0,MASTER_KEY_SIZE);
	memset(&para,0,sizeof(para));
	
	close(fd);

	return 1;
}

int genkey(int fd, unsigned long int cmd, char * out){
	KEYGEN_Para genkey;
	uint8_t buff[CRYPTO_PUBLICKEYBYTES+CRYPTO_SECRETKEYBYTES];
	// uint8_t buff1[CRYPTO_PUBLICKEYBYTES+CRYPTO_SECRETKEYBYTES];
	int ret = -1;
	// unsigned char *key = buff+CRYPTO_PUBLICKEYBYTES+SEEDBYTES;
	// unsigned char *s0 = buff+CRYPTO_PUBLICKEYBYTES+SEEDBYTES+SEEDBYTES+CRHBYTES;
	// unsigned char *s1 = buff+CRYPTO_PUBLICKEYBYTES+SEEDBYTES+SEEDBYTES+CRHBYTES + L*POLYETA_PACKEDBYTES;
	// unsigned char *t0 = buff+CRYPTO_PUBLICKEYBYTES+SEEDBYTES+SEEDBYTES+CRHBYTES + L*POLYETA_PACKEDBYTES + K*POLYETA_PACKEDBYTES;
	// crypto_sign_keypair(buff, buff+CRYPTO_PUBLICKEYBYTES);				//SYX: Currently in user space
	// if(cmd == DILITHIUM_SAFE_KEYGEN)
	// {
	// 	AESEncryptWithMode(key, , key, 0, NULL, ECB, );
	// }
	//printf("Currently unsupport\n");

	// randombytes(genkey.pk, SEEDBYTES);
	// memcpy(buff1, genkey.pk, SEEDBYTES);
	
	// crypto_sign_keypair(buff1, buff1+CRYPTO_PUBLICKEYBYTES);
	// printhex(buff1, CRYPTO_PUBLICKEYBYTES+CRYPTO_SECRETKEYBYTES);

	do{
		LOOP --; 
		ret = ioctl(fd, cmd, &genkey);
		// printf("1\n");
		if(ret != -1)
		{
			// printf("%d\n", ret);
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("dilithium Key Gen failed\n");
		return -1;
	}
	memcpy(buff, genkey.pk, CRYPTO_PUBLICKEYBYTES);
	memcpy(buff+CRYPTO_PUBLICKEYBYTES, genkey.sk, CRYPTO_SECRETKEYBYTES);

	// printhex(buff, CRYPTO_PUBLICKEYBYTES+CRYPTO_SECRETKEYBYTES);
	//*/
	return writehex(out, buff, CRYPTO_PUBLICKEYBYTES+CRYPTO_SECRETKEYBYTES);
}

int verify(int fd, unsigned long int cmd, char * message,  int messlen, unsigned char * signature, int signlen, unsigned char * key, int keylen)
{
	int ret = -1;
	if(keylen < CRYPTO_PUBLICKEYBYTES)
	{
		printf("dilithium key error: not a dilithium public key\n");
		return -1;
	}
	if(signlen != CRYPTO_BYTES + messlen)
	{
		printf("dilithium signature error: not a signature\n");
		return -1;
	}
	// don't need to use kernel
	if(!memcmp(message, signature, messlen))	//is signature prefix same with message
		return -1;
	if(!crypto_sign_open(message, messlen, signature, signlen, key))
		ret = 1;
	LOOP --;
	return ret;
}

int sign(int fd, unsigned long int cmd, char * message,  int messlen, unsigned char * key, int keylen, char * out)
{
	SIGN_Para testsign;
	int ret = -1;

	if(keylen < CRYPTO_PUBLICKEYBYTES+CRYPTO_SECRETKEYBYTES)
	{
		printf("dilithium key error: not a dilithium private key\n");
		return -1;
	}
	
	testsign.mlen = messlen;
	memcpy(testsign.m, message, messlen);
	memcpy(testsign.sk, key+CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES);

	do{
		LOOP --; 
		ret = ioctl(fd, cmd, &testsign);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("dilithium Sign failed\n");
		return -1;
	}
	return writehex(out, testsign.sm, testsign.smlen);
}

void showhelp(void)
{
	printf("./user: type [-l] Loopnum(0:loop until success default) [-d] debug(0:no debug default, 1:debug)\n");
	printf("type: \n");
	//printf("\t--0 generage the signature of the module\n");
	printf("\t--1 self test and init the module (setting the master key and the PIN)\n");
	printf("\t--2 KeyGen \t\t --3 Safe KeyGen\n "); 
	printf("\t--4 Sign \t\t --5 Safe Sign\n ");
	printf("\t--6 Verify\n");
}

void * testthread(void *para1){
	size_t ret = 0;
	int openmod;
	int type = ((Main_Para *)para1)->type;
	char * infile = ((Main_Para *)para1)->infile;
	char * outfile = ((Main_Para *)para1)->outfile;
	char * statefile = ((Main_Para *)para1)->statefile;
	int infd = -1, outfd = -1, sfd = -1 ,fd = -1;
	char buff[65536];		//SYX : for DILITHIUM, is it enough
	unsigned char signature[65536], message[65536], key[65536], out[65536];
	int signlen = -1, messlen = -1, keylen = -1, outlen = -1;

	fd = open("/dev/nortm", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/nortm)");
		return NULL;
	}

	//check param
	switch(type){
		case 4: case 5: 
		case 6:
		//in out key
		if(!statefile){
			printf("%s need a key file, use -k /path/to/file\n", typechar[type-2]);
			goto err3;
		}
		sfd = open(statefile, O_RDONLY);
		if (sfd < 0) {
			perror(statefile);
			goto err3;
		}
		keylen = read(sfd, buff, sizeof(buff));
		keylen = readhex(key, buff, keylen);
		// printf("%d\n", keylen);
		close(sfd);
		if(keylen < 0)
			goto err3;

		// in out
		if(!infile){
			printf("%s need a message file, use -i /path/to/file\n", typechar[type-2]);
			goto err3;
		}
		infd = open(infile, O_RDONLY);
		if (infd < 0) {
			perror(infile);
			goto err3;
		}

		case 2: case 3:
		//out 
		if(!outfile){
			if(type == 6)
				printf("%s need an signature file, use -o /path/to/file\n", typechar[type-2]);
			else
				printf("%s need an output file, use -o /path/to/file\n", typechar[type-2]);
			goto err2;
		}
		if(type == 6)
			openmod = O_RDWR|O_CREAT;
		else
			openmod = O_RDWR|O_CREAT|O_TRUNC;

		outfd = open(outfile, openmod, 0664);
		if (outfd < 0) {
			perror(outfile);
			goto err2;
		}
	}

	if(type == 2 || type == 3)	//gen key
	{
		if(type == 2)
			outlen = genkey(fd, DILITHIUM_KEYGEN, out);
		else
			outlen = genkey(fd, DILITHIUM_SAFE_KEYGEN, out);
		// printf("%s", out);
	} else if (type == 6) {		// verify
		signlen = read(outfd, buff, sizeof(buff));
		signlen = readhex(signature, buff, signlen);
		
		messlen = read(infd, message, sizeof(message));
		if(messlen > MAX_MESSAGE_LEN)
		{
			printf("too long message, not longer than %d \n", MAX_MESSAGE_LEN);
			ret = 0;
		}

		ret = verify(fd, DILITHIUM_VERIFY, message, messlen, signature, signlen, key, keylen);
		if(ret == -1)
		{
			printf("verify err in the process\n");
			ret = 0;
		}
		else if(ret == 1)
		{
			printf("verify success\n");
		} 
		else
		{
			printf("error signature\n");
			ret = 0;
		}
	} else {
		if(type == 4 || type == 5) // sign
		{
			messlen = read(infd, message, sizeof(message));
			if(messlen > MAX_MESSAGE_LEN)
			{
				printf("too long message, not longer than %d \n", MAX_MESSAGE_LEN);
				ret = 0;
			}
			if(type == 4)
				outlen = sign(fd, DILITHIUM_SIGN, message, messlen, key, keylen, out);
			else
				outlen = sign(fd, DILITHIUM_SAFE_SIGN, message, messlen, key, keylen, out);
		}
	}

	// end
	if(type != 6)
	{
		if(outlen > 0){
			write(outfd, out, outlen);
			ret = 1;
			// printf("%s %d\n", out, openmod&O_TRUNC);
		}
	}

	//normal exit
	if(type != 2 && type !=3)
	{
		if (close(infd)) {
			perror(infile);
		}
	}
	if (close(outfd)) {
		perror(outfile);
	}
	if (close(fd)) {
		perror("close(/dev/Nortm)");
	}
	return (void *)ret;

err1:	//have opened the outputfile
	if (close(outfd)) {
		perror(outfile);
	}
err2:	//have opende the inputfile
	if (close(infd)) {
		perror(infile);
	}
err3:	//have opened the /dev/Nortm
	if (close(fd)) {
		perror("close(/dev/Nortm)");
	}
	return (void *)ret;

}

int main(int argc, char **argv)
{
	int cur=LOOP;
	if(argc < 2)
	{
		showhelp();
		return -1;
	}

	int type = atoi(argv[1]);
	if(type < 0 || type > 14) 
	{
		showhelp();
		return -1;
	}

	int optc;
	Main_Para mpara={NULL, NULL, NULL, type};
	while((optc = getopt(argc, argv, "hdl:i:o:k:")) != -1)
	{
		switch(optc){
			case 'd':
				debugFlag = 1;
				break;
			case 'l':
				cur = LOOP = atoi(optarg);
				break;
			case 'i':
				mpara.infile = optarg;
				break;
			case 'o':
				mpara.outfile = optarg;
				break;
			case 'k':
				mpara.statefile = optarg;
				break;
			case 'h':
				showhelp();
				return 0;
			case '?':
				return -1;
			default:
				printf("unknown opt %c\n", optc);
				return -1;
		}
	}

	if(type == 0)
	{
		printf("Generate the signature of the kernel module and set it in /cryptomodule.signature\n");
		//GenSigOfModule();
		printf("Currently unsupport\n");
		return 0;
	}
	if(type ==1)
	{
		printf("Init the module\n");
		if(!InitModule())
		{
			printf("Already init\n");
		}
		return 0;
	}

	
	struct timeval beg,end;


	gettimeofday(&beg,NULL);

	if(!testthread((void *)&mpara))
		return -1;

	gettimeofday(&end,NULL);
	
	if(debugFlag)
		printf("LOOP: %d \t type: %s \t time: %.3fms\n", cur - LOOP, typechar[type-2], 1.0*(end.tv_usec-beg.tv_usec)/1000 + 1.0*(end.tv_sec-beg.tv_sec)*1000);		
	return 0;
}
