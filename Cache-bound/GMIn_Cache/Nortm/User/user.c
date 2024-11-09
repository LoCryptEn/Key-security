#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include "ioc.h"

#include <errno.h>
#include <termios.h>
#include "EllipticCurve.h"
#include "pbkdf.h"
#include "SMS4.h"

int LOOP = 0;
int debugFlag = 0;
// SM2_SIGN_Para testsm2sign;
char pin[PIN_LEN]="12345678";

typedef struct _Main_Para
{
	char * infile;
	char * outfile;
	char * statefile;
	char * username;
	int type;
}Main_Para;

char typechar[13][15] = {"SM2KeyGen","SM2SafeKeyGen", "Sign","SafeSign","SM2Dec","SM2SafeDec","SM2Enc","SM2Verify","SM3Digest","SM3IUF","SafeSM3IUF","SafeSM4","SafeHMAC"};

//gcc -g -o user user.c EllipticCurve.c Mpi.c sm3hash.c -lpthread

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
	//int c;
	int n = 0;	//SYX: what's for n
	set_disp_mode(STDIN_FILENO,0);
	scanf("%s",passwd);	//SYX: this is unsafe
	set_disp_mode(STDIN_FILENO,1);
	return n;
}

void getpin()
{
	char pinVerify[PIN_LEN];
	while(1){
		memset(pin,0x0,PIN_LEN);
		memset(pinVerify,0x0,PIN_LEN);
		printf("Please input PIN[%d max]:\n",PIN_LEN);
		getpasswd(pin,PIN_LEN);

		printf("Please input PIN KEY again[%d max]:\n",PIN_LEN);
		getpasswd(pinVerify,PIN_LEN);
		if(strncmp(pin, pinVerify, PIN_LEN)==0){
			break;
		}else{
			printf("two input PIN is different, please input again\n");
		}
	}
	memset(pinVerify,0,PIN_LEN);
}

//only for debug
int SelfTestCompl()
{
	unsigned char message[32+16];
	int i,fd;
	Gen_Key_Para sm2genkey;
	SM2_SIGN_Para testsm2sign;
	SM2_Para      testsm2;
	SM4_Para	  testsm4;
	SM3_Para	  testsm3,testsafesm3;
	unsigned char outtemp[16];
	unsigned char pUserName[16] = { '1','2','3','4','5','6','7','8','1','2','3','4','5','6','7','8' };
	unsigned char key[MASTER_KEY_SIZE];
	unsigned char salt[8] = {0x1,0x2,0x3,0x3,0x5,0x6,0x7,0x8};
	memset(key,0,MASTER_KEY_SIZE);
	memcpy(key,"12345678",8);
	PBKDF2(outtemp, key, MASTER_KEY_SIZE, salt, 8, 1000, 16);

	fd = open("/dev/nortm", O_RDWR, 0);

	for(i=0;i<32;i++)
		message[i] = random();
	memcpy(sm2genkey.pin,pin,PIN_LEN);
	while(ioctl(fd, SM2_SAFE_KEYGEN, &sm2genkey)==-1);
	printf("SM2_SAFE_KEYGEN success\n");
	testsm2sign.len = 32;
	memcpy(testsm2sign.x,sm2genkey.x,32);
	memcpy(testsm2sign.y,sm2genkey.y,32);
	memcpy(testsm2sign.d,sm2genkey.d,32);
	memcpy(testsm2sign.message,message, 14);
	memcpy(testsm2sign.pUserName, pUserName, 16);
	memcpy(testsm2sign.pin,pin,PIN_LEN);
	testsm2sign.LenOfpUserName = 16;

	while(ioctl(fd, SM2_SAFE_SIGN, &testsm2sign)==-1);
	printf("SM2_SAFE_SIGN success\n");
	// if(ioctl(fd, SM2_SAFE_SIGN, &testsm2sign)==-1)
	// 	printf("SM2_SAFE_SIGN fail\n");
	if(ioctl(fd, SM2_VERIFY, &testsm2sign) == 1)
		printf("SM2 Safe Sign Normal Verify OK\n");

	testsm2.len = 32;
	memcpy(testsm2.d,sm2genkey.d,32);
	memcpy(testsm2.x,sm2genkey.x,32);
	memcpy(testsm2.y,sm2genkey.y,32);
	memcpy(testsm2.plain,message,32);
	memset(testsm2.cipher,0,1+SM2_KEY_LEN*3+SM2_MAX_PLAIN_LEN);
	memcpy(testsm2.pin,pin,PIN_LEN);


	if(ioctl(fd,SM2_ENC,&testsm2)==-1)
		printf("SM2_ENC fail\n");

	while(ioctl(fd,SM2_SAFE_DEC,&testsm2) == -1);
	printf("SM2_SAFE_DEC success\n");
	// if(ioctl(fd,SM2_SAFE_DEC,&testsm2) == -1)
	// 	printf("SM2_SAFE_DEC fail\n");
	SM4DecryptWithMode(testsm2.plain, testsm2.len, testsm2.plain, testsm2.len, NULL, ECB, outtemp);
	if(memcmp(testsm2.plain,message,32)==0)
		printf("SM2 Normal Enc, Safe Dec OK\n");
	else
		printf("SM2 Normal Enc, Safe Dec fail\n");

	testsm3.plainLen = 0;
	memcpy(testsm3.pin,pin,PIN_LEN);
	if(ioctl(fd,SM3_INIT,&testsm3) == -1)
		printf("Normal SM3 init fail\n");
	testsm3.plainLen = 32;
	memcpy(testsm3.plain,message,testsm3.plainLen);
	if(ioctl(fd,SM3_UPDATE,&testsm3) == -1)
		printf("Normal SM3 update fail\n");	
	if(ioctl(fd,SM3_FINAL,&testsm3) == -1)
		printf("Normal SM3 final fail\n");	
	testsafesm3.plainLen = 0;
	memcpy(testsafesm3.pin,pin,PIN_LEN);
	if(ioctl(fd,SM3_INIT,&testsafesm3) == -1)
		printf("Normal SM3 init fail\n");
	testsafesm3.plainLen = 32;
	memcpy(testsafesm3.plain,message,testsafesm3.plainLen);
	if(ioctl(fd,SM3_UPDATE,&testsafesm3) == -1)
		printf("Normal SM3 update fail\n");	
	if(ioctl(fd,SM3_FINAL,&testsafesm3) == -1)
		printf("Normal SM3 final fail\n");	

	if(memcmp(testsafesm3.digest,testsm3.digest,SM3_DIGEST_LEN)==0)
		printf("SM3 Normal Digest, Safe Digest OK\n");
	else
		printf("SM3 Normal Digest, Safe Digest fail\n");

	testsm4.len = 32;
	testsm4.mode = 1; //ECB
	testsm4.flag = 1; //Enc
	memcpy(testsm4.key,message,16);
	memcpy(testsm4.plain,message,32);
	memcpy(testsm4.pin,pin,PIN_LEN);
	if(ioctl(fd,SM4_OP,&testsm4) == -1)
		printf("SM4 Normal ECB Enc fail\n");
	testsm4.flag = 0; //Dec
	if(ioctl(fd,SM4_OP,&testsm4) == -1)
		printf("SM4 Normal ECB Enc fail\n");
	if(memcmp(testsm4.plain,message,32)==0)
		printf("SM4 ECB: Safe Enc, Safe Dec OK\n");

	testsm4.len = 32;
	testsm4.mode = 2; //CBC
	testsm4.flag = 1; //Enc
	memcpy(testsm4.key,message,16);
	memcpy(testsm4.iv,message,16);
	memcpy(testsm4.plain,message,32);
	memcpy(testsm4.pin,pin,PIN_LEN);
	if(ioctl(fd,SM4_OP,&testsm4) == -1)
		printf("SM4 Normal CBC Enc fail\n");
	testsm4.flag = 0; //Dec
	memcpy(testsm4.iv,message,16);
	if(ioctl(fd,SM4_OP,&testsm4) == -1)
		printf("SM4 Normal CBC Enc fail\n");
	if(memcmp(testsm4.plain,message,32)==0)
		printf("SM4 CBC: Safe Enc, Safe Dec OK\n");
	close(fd);

}

void printhex(unsigned char * output, int len)
{
    int i = 0;
    for(i = 0; i < len; i++)
    {
        printf(" %02x", output[i]);
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

int gensm2key(int fd, unsigned long int cmd, char * out){
	Gen_Key_Para sm2genkey;
	uint8_t buff[SM2_KEY_LEN*3];
	int ret = -1;
	memcpy(sm2genkey.pin,pin,PIN_LEN);
	do{
		LOOP --; 
		ret = ioctl(fd, cmd, &sm2genkey);
		// printf("1\n");
		if(ret != -1)
		{
			// printf("%d\n", ret);
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("SM2 Key Gen failed\n");
		return -1;
	}
	memcpy(buff, sm2genkey.x, SM2_KEY_LEN);
	memcpy(buff+SM2_KEY_LEN, sm2genkey.y, SM2_KEY_LEN);
	memcpy(buff+2*SM2_KEY_LEN, sm2genkey.d, SM2_KEY_LEN);
	return writehex(out, buff, SM2_KEY_LEN*3);
}

int sm2verify(int fd, unsigned long int cmd, char * message,  int messlen, char * username, unsigned char * signature, int signlen, unsigned char * key, int keylen)
{
	SM2_SIGN_Para testsm2sign;
	// uint8_t buff[SM2_KEY_LEN*3];
	int ret = -1;
	if(keylen < 2*SM2_KEY_LEN)
	{
		printf("sm2 key error: not a sm2 public key\n");
		return -1;
	}
	if(signlen != 2*SM2_KEY_LEN)
	{
		printf("sm2 signature error: not a signature\n");
		return -1;
	}
	
	// SYX: DBG
	// printf("%d : %s\n", messlen, message );
	// printhex(signature, signlen);

	memcpy(testsm2sign.pin,pin,PIN_LEN);
	testsm2sign.len = messlen;
	memcpy(testsm2sign.message, message, messlen);
	memcpy(testsm2sign.x, key, SM2_KEY_LEN);
	memcpy(testsm2sign.y, key + SM2_KEY_LEN, SM2_KEY_LEN);
	testsm2sign.LenOfpUserName = strlen(username);
	memcpy(testsm2sign.pUserName, username, testsm2sign.LenOfpUserName);
	testsm2sign.LenOfsign = signlen;
	memcpy(testsm2sign.sign, signature, signlen);

	do{
		LOOP --; 
		ret = ioctl(fd, SM2_VERIFY, &testsm2sign);
		if(ret != -1) {
			break;
		}
	} while(LOOP);

	return ret;
}

int sm2sign(int fd, unsigned long int cmd, char * message,  int messlen, char * username, unsigned char * key, int keylen, char * out)
{
	SM2_SIGN_Para testsm2sign;
	// uint8_t buff[SM2_KEY_LEN*3];
	int ret = -1;
	if(keylen < 3*SM2_KEY_LEN)
	{
		printf("sm2 key error: not a sm2 private key\n");
		return -1;
	}
	
	memcpy(testsm2sign.pin,pin,PIN_LEN);
	testsm2sign.len = messlen;
	memcpy(testsm2sign.message, message, messlen);
	memcpy(testsm2sign.x, key, SM2_KEY_LEN);
	memcpy(testsm2sign.y, key + SM2_KEY_LEN, SM2_KEY_LEN);
	memcpy(testsm2sign.d, key + 2*SM2_KEY_LEN, SM2_KEY_LEN);
	testsm2sign.LenOfpUserName = strlen(username);
	memcpy(testsm2sign.pUserName, username, testsm2sign.LenOfpUserName);

	do{
		LOOP --; 
		ret = ioctl(fd, cmd, &testsm2sign);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("SM2 Sign failed\n");
		return -1;
	}
	return writehex(out, testsm2sign.sign, testsm2sign.LenOfsign);
}

int sm2dec(int fd, unsigned long int cmd, unsigned char * message,  int messlen, unsigned char * key, int keylen, char * out, unsigned char * outtemp)
{
	SM2_Para testsm2;
	// uint8_t buff[SM2_KEY_LEN*3];
	int ret = -1;
	if(keylen < 3*SM2_KEY_LEN)
	{
		printf("sm2 key error: not a sm2 private key\n");
		return -1;
	}
	if(messlen > 1+SM2_KEY_LEN*3+SM2_MAX_PLAIN_LEN)
	{
		printf("sm2 cipher error: too long cipher, not longer than %d\n", 1+SM2_KEY_LEN*3+SM2_MAX_PLAIN_LEN);
		return -1;
	}
	memcpy(testsm2.pin,pin,PIN_LEN);
	memcpy(testsm2.x, key, SM2_KEY_LEN);
	memcpy(testsm2.y, key + SM2_KEY_LEN, SM2_KEY_LEN);
	memcpy(testsm2.d, key + 2*SM2_KEY_LEN, SM2_KEY_LEN);
	testsm2.len = messlen;
	memcpy(testsm2.cipher, message ,messlen);
	memset(testsm2.plain,0,SM2_MAX_PLAIN_LEN);
	
	do{
		LOOP --; 
		ret = ioctl(fd, cmd, &testsm2);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("SM2 Dec failed\n");
		return -1;
	}
	if(cmd == SM2_SAFE_DEC && debugFlag)
	{
		testsm2.len = SM4DecryptWithMode(testsm2.plain, testsm2.len, testsm2.plain, testsm2.len, NULL, ECB, outtemp);
	}
	memcpy(out, testsm2.plain, testsm2.len);
	return testsm2.len;
}

int sm2enc(int fd, unsigned long int cmd, char * message,  int messlen, unsigned char * key, int keylen, char * out)
{
	SM2_Para testsm2;
	int ret = -1;
	if(keylen < 2*SM2_KEY_LEN)
	{
		printf("sm2 key error: not a sm2 public key\n");
		return -1;
	}
	memcpy(testsm2.pin,pin,PIN_LEN);
	memcpy(testsm2.x, key, SM2_KEY_LEN);
	memcpy(testsm2.y, key + SM2_KEY_LEN, SM2_KEY_LEN);
	testsm2.len = messlen;
	memcpy(testsm2.plain, message, messlen);
	memset(testsm2.cipher, 0, 1+SM2_KEY_LEN*3+SM2_MAX_PLAIN_LEN);

	do{
		LOOP --; 
		ret = ioctl(fd, cmd, &testsm2);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("SM2 Enc failed\n");
		return -1;
	}
	return writehex(out, testsm2.cipher, testsm2.len);
}

// hmac inner hash output need to be encrypted
int sm3hmac(int fd, int infd, unsigned char * key, int keylen, char * out)
{
	GM_PAD	 testpad;
	SM3_Para testsm3;
	unsigned char hmacdigest[32];
	int ret = -1, cur= LOOP;
	if(keylen > GM_HMAC_MD_CBLOCK_SIZE)
		keylen = GM_HMAC_MD_CBLOCK_SIZE;
	

	memcpy(testpad.pin,pin,PIN_LEN);
	memcpy(testsm3.pin,pin,PIN_LEN);

	//ipad
	testpad.len = keylen;
	memcpy(testpad.pad, key, keylen);
	do{
		LOOP --; 
		ret = ioctl(fd, SAFE_IPAD, &testpad);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("Hmac failed\n");
		return -1;
	}

	// sm3 init
	testsm3.plainLen = 0;
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, SM3_SAFE_INIT ,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}
	//sm3 ipad block
	testsm3.state.in_encrypted = 1;
	testsm3.state.out_encrypted = 1;
	testsm3.plainLen = GM_HMAC_MD_CBLOCK_SIZE;
	memcpy(testsm3.plain,testpad.pad,testsm3.plainLen);
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, SM3_SAFE_UPDATE ,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}

	//sm3 update
	int length;
	while((length = read(infd, testsm3.plain ,MAX_PLAIN_LEN) ) > 0)
	{
		testsm3.plainLen = length;
		LOOP = cur;
		do{
			LOOP --; 
			ret = ioctl(fd, SM3_SAFE_UPDATE ,&testsm3);
			if(ret != -1) {
				break;
			}
		} while(LOOP);
		if(ret == -1){
			printf("HMAC failed\n");
			return -1;
		}
	}

	//sm3 final
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd,SM3_SAFE_FINAL,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}

	memcpy(hmacdigest,testsm3.digest,SM3_DIGEST_LEN);

	//opad
	testpad.len = keylen;
	memcpy(testpad.pad, key, keylen);
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, SAFE_OPAD, &testpad);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("Hmac failed\n");
		return -1;
	}

	// sm3 init
	testsm3.plainLen = 0;
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, SM3_SAFE_INIT ,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}

	//sm3 opad block
	testsm3.state.in_encrypted = 1;
	testsm3.state.out_encrypted = 1;
	testsm3.plainLen = GM_HMAC_MD_CBLOCK_SIZE;
	memcpy(testsm3.plain,testpad.pad,testsm3.plainLen);
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, SM3_SAFE_UPDATE ,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}

	//sm3 update
	testsm3.state.in_encrypted = 1;
	testsm3.state.out_encrypted = 1;
	testsm3.plainLen = SM3_DIGEST_LEN;
	memcpy(testsm3.plain,hmacdigest,testsm3.plainLen);
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, SM3_SAFE_UPDATE ,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}

	//sm3 final
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, SM3_SAFE_FINAL, &testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}

	// hmac val in encrypted
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd, HMAC_FINAL_DEC, &testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("HMAC failed\n");
		return -1;
	}

	return writehex(out, testsm3.digest, SM3_DIGEST_LEN);
}

int sm3hash(int fd, int mode, int infd, char * out)
{
	unsigned long int start, mid, end, cur= LOOP; 
	SM3_Para testsm3;
	int ret = -1;

	if(mode == 0){	//normal
		start = SM3_INIT;
		mid = SM3_UPDATE;
		end = SM3_FINAL;
	} else { //safe
		start = SM3_SAFE_INIT;
		mid = SM3_SAFE_UPDATE;
		end = SM3_SAFE_FINAL;
	}
	memcpy(testsm3.pin,pin,PIN_LEN);

	testsm3.plainLen = 0;
	do{
		LOOP --; 
		ret = ioctl(fd, start ,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("SM3 failed\n");
		return -1;
	}
	int length;
	while((length = read(infd, testsm3.plain ,MAX_PLAIN_LEN) ) > 0)
	{
		testsm3.plainLen = length;
		LOOP = cur;
		do{
			LOOP --; 
			ret = ioctl(fd, mid ,&testsm3);
			if(ret != -1) {
				break;
			}
		} while(LOOP);
		if(ret == -1){
			printf("SM3 failed\n");
			return -1;
		}
	}
	LOOP = cur;
	do{
		LOOP --; 
		ret = ioctl(fd,end,&testsm3);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("SM3 failed\n");
		return -1;
	}

	return writehex(out, testsm3.digest, SM3_DIGEST_LEN);
}

int sm4opt(int fd, int mode, char * message,  int messlen, unsigned char * key, int keylen, char * out)
{
	SM4_Para testsm4;
	int ret = -1;
	if(keylen != SM4_KEY_LEN)
	{
		printf("sm4 key error: not a sm4 key\n");
		return -1;
	}

	memcpy(testsm4.pin,pin,PIN_LEN);
	testsm4.mode = 1; //ECB
	testsm4.flag = mode;
	memcpy(testsm4.key, key, SM4_KEY_LEN);
	testsm4.len = messlen;
	if(mode == 0)	//dec
	{
		memcpy(testsm4.cipher, message, messlen);
	} else {	//enc
		memcpy(testsm4.plain, message, messlen);
	}
	
	do{
		LOOP --; 
		ret = ioctl(fd, SM4_OP, &testsm4);
		if(ret != -1) {
			break;
		}
	} while(LOOP);
	if(ret == -1){
		printf("SM4 failed\n");
		return -1;
	}

	if(mode == 0)	//dec
	{
		ret = testsm4.len;
		memcpy(out, testsm4.plain, testsm4.len);
	} else {	//enc
		ret = writehex(out, testsm4.cipher, testsm4.len);
	}
	return ret;
}

// this will compute the key in cpu in debug mode
void fordebug(unsigned char * outtemp)
{
	unsigned char key[MASTER_KEY_SIZE];
	memset(key,0,MASTER_KEY_SIZE);
	memcpy(key,"12345678",8);
	unsigned char salt[8] = {0x1,0x2,0x3,0x3,0x5,0x6,0x7,0x8};
	PBKDF2(outtemp, key, MASTER_KEY_SIZE, salt, 8, 1000, 16);
}

void *testthread(void *para1){
	
	SM2_SIGN_Para testsm2sign;
	SM2_Para testsm2;
	SM3_Para testsm3;
	SM4_Para testsm4;
	GM_PAD	 testpad,testpad2;
	unsigned char hmacdigest[32];
	Gen_Key_Para sm2genkey;


	size_t ret = 0, cur=0;
	int openmod;
	int type = ((Main_Para *)para1)->type;
	char * infile = ((Main_Para *)para1)->infile;
	char * outfile = ((Main_Para *)para1)->outfile;
	char * statefile = ((Main_Para *)para1)->statefile;
	char * username = ((Main_Para *)para1)->username;
	int infd = -1, outfd = -1, sfd = -1 ,fd = -1;
	char buff[1024];
	unsigned char signature[1024], message[1024], key[1024], out[2048];
	int signlen = -1, messlen = -1, keylen = -1, outlen = -1;
	
	unsigned char outtemp[16];
	if(debugFlag)
	{
		fordebug(outtemp);
	}

	fd = open("/dev/nortm", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/nortm)");
		return NULL;
	}

	//check param
	switch(type){
		case 4: case 5: 
		case 9:
		//in key username out
		if(!username){
			printf("%s need a username, use -u \"username\" \n", typechar[type-2]);
			goto err3;
		}
		if(strlen(username) > SM2_MAX_PLAIN_LEN)
		{
			printf("too long username, not longer than %d \n", SM2_MAX_PLAIN_LEN);
			goto err3;
		}
		case 6: case 7: case 8:
		case 12: case 13: case 14:
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

		case 10: case 11:
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
			if(type == 9)
				printf("%s need an signature file, use -o /path/to/file\n", typechar[type-2]);
			else
				printf("%s need an output file, use -o /path/to/file\n", typechar[type-2]);
			goto err2;
		}
		if(type == 9)
			openmod = O_RDWR|O_CREAT;
		else
			openmod = O_RDWR|O_CREAT|O_TRUNC;

		outfd = open(outfile, openmod, 0664);
		if (outfd < 0) {
			perror(outfile);
			goto err2;
		}
	}

	if(!debugFlag)
		getpin();

	if(type == 2 || type == 3)	//gen key
	{
		if(type == 2)
			outlen = gensm2key(fd, SM2_KEYGEN, out);
		else
			outlen = gensm2key(fd, SM2_SAFE_KEYGEN, out);
		// printf("%s", out);
	} else if (type == 9) {		// verify
		signlen = read(outfd, buff, sizeof(buff));
		signlen = readhex(signature, buff, signlen);

		messlen = read(infd, message, sizeof(message));
		if(messlen > SM2_MAX_PLAIN_LEN)
		{
			printf("too long message, not longer than %d \n", SM2_MAX_PLAIN_LEN);
			ret = 0;
		}

		ret = sm2verify(fd, SM2_VERIFY, message, messlen, username, signature, signlen, key, keylen);
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
	} else if (type == 10 || type == 11 || type == 14) {	//hash and HMAC
		if(type == 14)
			outlen = sm3hmac(fd, infd, key, keylen, out);
		if(type == 10)
			outlen = sm3hash(fd, 0, infd, out);
		if(type == 11)
			outlen = sm3hash(fd, 1, infd, out);
	} else {
		if(type == 4 || type == 5) // sign
		{
			messlen = read(infd, message, sizeof(message));
			if(messlen > SM2_MAX_PLAIN_LEN)
			{
				printf("too long message, not longer than %d \n", SM2_MAX_PLAIN_LEN);
				ret = 0;
			}
			if(type == 4)
				outlen = sm2sign(fd, SM2_SIGN, message, messlen, username, key, keylen, out);
			else
				outlen = sm2sign(fd, SM2_SAFE_SIGN, message, messlen, username, key, keylen, out);
		}

		if(type == 6 || type == 7 || type == 8)	//SM2 DEC / ENC
		{
			if(type == 6 || type == 7)	//DEC
			{
				messlen = read(infd, buff, sizeof(buff));
				messlen = readhex(message, buff, messlen);
				if(type == 6)
					outlen = sm2dec(fd, SM2_DEC, message, messlen, key, keylen, out, outtemp);
				else
					outlen = sm2dec(fd, SM2_SAFE_DEC, message, messlen, key, keylen, out, outtemp);
			}
			else{
				messlen = read(infd, message, sizeof(message));
				if(messlen > SM2_MAX_PLAIN_LEN)
				{
					printf("too long message, not longer than %d \n", SM2_MAX_PLAIN_LEN);
					ret = 0;
				}
				outlen = sm2enc(fd, SM2_ENC, message, messlen, key, keylen, out);
			}
		}

		if(type == 12 || type == 13)	//SM4 ENC/ DEC
		{
			if(type == 12){
				messlen = read(infd, message, sizeof(message));
				outlen = sm4opt(fd, 1, message, messlen, key, keylen, out); //ENC
			}
			else{
				messlen = read(infd, buff, sizeof(buff));
				messlen = readhex(message, buff, messlen);
				outlen = sm4opt(fd, 0, message, messlen, key, keylen, out); //DEC
			}
		}
	}

	// end
	if(type != 9)
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



 /*init the module
 *obtain the master key and PIN
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
		memcpy(pin,"12345678",8);
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
		getpin();
	}
	
	memcpy(para.masterKey,key,MASTER_KEY_SIZE);
	memcpy(para.pin,pin,PIN_LEN);
	fd = open("/dev/nortm", O_RDWR, 0);
	if(fd<0){
		printf("Error while access Kernel Module\n");
		return 0;
	}
	if(ioctl(fd, INIT, &para) == -1){
		printf("Error while init MASTER KEY\n");
		return 0;
	}

	printf("Init MASTER KEY succeed\n");

	if(!debugFlag)		//we clear this when no dbg
	{
		memset(key,0x0,MASTER_KEY_SIZE);
		memset(verify,0x0,MASTER_KEY_SIZE);
		memset(pin,0,PIN_LEN);
		memset(&para,0,sizeof(para));
	}

	close(fd);

	return 1;
}

int SelfTest()
{
	int fd;
	fd = open("/dev/nortm", O_RDWR, 0);
	if(fd<0){
		printf("Error while access Kernel Module\n");
		return 0;
	}
	if(ioctl(fd, SELF_TEST, NULL) == -1){
		printf("Error while SELF_TEST\n");
		return 0;
	}
	close(fd);

	return 1;
}

int GenSigOfModule(void){
	FILE *fp;
	CECCPrivateKey sk;
	unsigned char digest[HASH_256];
	HASH_STATE hashState;
	int count;
	unsigned char priv_key[96];
	unsigned char mod[4096];
	unsigned char signature[256];
	unsigned char user_name[USER_NAME_SIZE] = {0x00,0xe5,0x8b,0xaf,0xf7,0x7e,0x6e,0x3d,0x4a,0xa1,0x3f,0x49,0xb5,0x28,0xcc,0xc1,0xe1,0x0c,0xa1,0x62,0x9e,0xcf,0x08,0xd9,0x41,0xe4,0xd4,0x0a,0x76,0x76,0xe1,0x4c};
	unsigned char rand[] = {0x00,0xe5,0x8b,0xaf,0xf7,0x7e,0x6e,0x3d,0x4a,0xa1,0x3f,0x49,0xb5,0x28,0xcc,0xc1,0xe1,0x0c,0xa1,0x62,0x9e,0xcf,0x08,0xd9,0x41,0xe4,0xd4,0x0a,0x76,0x76,0xe1,0x4c};
	size_t key_len;
	int ret;

	fp = fopen("./mod_sign.key","r");
	if(fp){
		key_len = fread(priv_key, sizeof(unsigned char), 96, fp);
		if(key_len<=0){
			printf("No content read from private key file\n");
			return 0;
		}
	}else{
		printf("Can't read private key file\n");
		return 0;
	}
	fclose(fp);
	CEllipticCurveInitParam();
	CMpiInit(&(sk.m_pntPx));
	CMpiInit(&(sk.m_pntPy));
	CMpiInit(&(sk.m_paramD));
	if(GenerateKey(&sk, priv_key+64, 32)==0){
		printf("Error while generage key\n");
		return 0;
	}
	PriHashUserId(&sk,digest, user_name, USER_NAME_SIZE);
	HashInit(&hashState, digest, HASH_256);
	fp = fopen("./nortm.ko","r");
	if(fp){
		do{
			count = fread(mod, sizeof(unsigned char), 4096, fp);
			HashPending(&hashState, mod, count);
		}while(count>0);
		HashFinal(digest, &hashState);	
	}else{
		printf("Can't read Module file\n");
		return 0;
	}
	fclose(fp);
	ret = Sign(&sk, signature, digest, HASH_256, rand, sizeof(rand));

	fp = fopen("/cryptomodule.signatue","w");
	if(fp){
		fwrite(signature, sizeof(unsigned char), ret, fp);
		printf("sign file generage Done\n");
	}else{
		printf("Can't open sign file\n");
		return 0;
	}
	fclose(fp);
	fp = NULL;
}

void showhelp(void)
{
	printf("./user: type [-l] Loopnum(0:loop until success default) [-d] debug(0:no debug default, 1:debug)\n");
	printf("type: \n");
	printf("\t--0 generage the signature of the module\n");
	printf("\t--1 self test and init the module (setting the master key and the PIN)\n");
	printf("\t--2 SM2 KeyGen \t\t --3 Safe SM2 KeyGen\n "); 
	printf("\t--4 SM2 Sign \t\t --5 Safe SM2 Sign\n ");
	printf("\t--6 SM2 Dec \t\t --7 Safe SM2 Dec\n");
	printf("\t--8 SM2 Enc \n");
	printf("\t--9 SM2 Verify\n");
	printf("\t--10 SM3 Digest \t\t --11 Safe SM3 Digest\n");
	printf("\t--12 Safe SM4 Enc\n");
	printf("\t--13 Safe SM4 Dec\n");
	printf("\t--14 Safe HMAC\n");
	// printf("\t--15 Self Test\n");
}

//SYX : no need for thread? 
//SYX : SM2_SAFE_DEC too slow
int main(int argc, char **argv){
	int i,res,t, cur=LOOP;
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

	//TODO: flat the param

	int optc;
	Main_Para mpara={NULL, NULL, NULL, NULL, type};
	while((optc = getopt(argc, argv, "hdl:i:o:k:u:")) != -1)
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
			case 'u':
				mpara.username = optarg;
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
		GenSigOfModule();
		return 0;
	}
	if(type ==1)
	{
		printf("SelfTest the module\n");
		SelfTest();
		printf("SelfTest OK\n");
		InitModule();
		if(debugFlag)
			SelfTestCompl();
		return 0;
	}

	
	struct timeval beg,end;


	gettimeofday(&beg,NULL);

	if(!testthread((void *)&mpara))
		return -1;

	gettimeofday(&end,NULL);
	
	printf("LOOP \t %d \t type \t %d \t\n", cur - LOOP, type);
	printf("type \t %s \t speed: \t %f\n", typechar[type-2], (float)1000000/(end.tv_usec-beg.tv_usec+1000000*(end.tv_sec-beg.tv_sec)));		
	return 0;
}

