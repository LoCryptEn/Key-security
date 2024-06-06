#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include "ioc.h"

#include <errno.h>
#include <termios.h>
#include "EllipticCurve.h"
#include "pbkdf.h"
#include "SMS4.h"

int TOTAL_THREAD = 1;
int LOOP = 1;
int ELOOPS = 1;
int type = 1;
int debugFlag = 0;
SM2_SIGN_Para testsm2sign;
unsigned int succ_count = 0;
char pin[PIN_LEN]="12345678";

//gcc -g -o user user.c EllipticCurve.c Mpi.c sm3hash.c -lpthread

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
	ioctl(fd, SM2_SAFE_KEYGEN, &sm2genkey);
	testsm2sign.len = 32;
	memcpy(testsm2sign.x,sm2genkey.x,32);
	memcpy(testsm2sign.y,sm2genkey.y,32);
	memcpy(testsm2sign.d,sm2genkey.d,32);
	memcpy(testsm2sign.message,message, 14);
	memcpy(testsm2sign.pUserName, pUserName, 16);
	memcpy(testsm2sign.pin,pin,PIN_LEN);
	testsm2sign.LenOfpUserName = 16;
	if(ioctl(fd, SM2_SAFE_SIGN, &testsm2sign)==-1)
		printf("SM2_SAFE_SIGN fail\n");
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
	if(ioctl(fd,SM2_SAFE_DEC,&testsm2) == -1)
		printf("SM2_SAFE_DEC fail\n");
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

void *testthread(void *para1){
	int i,j,fd = -1;
	long sign_ret = 0;
	unsigned char kk[32] = {0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D,0xCC,0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21};
	char buf[100];
	size_t ret = 0;
	//private key
	unsigned char pRandomUser[32] = {0x39,0x45,0x20,0x8f,0x7b,0x21,0x44,0xb1,0x3f,0x36,0xe3,0x8a,0xc6,0xd3,0x9f,0x95,
									 0x88,0x93,0x93,0x69,0x28,0x60,0xb5,0x1a,0x42,0xfb,0x81,0xef,0x4d,0xf7,0xc5,0xb8};
	unsigned char prikey_cipher[32];//use SM4OP to encrypt the pRandomUser
	//for sign and verify test
	unsigned char message[14] = {0x6d,0x65,0x73,0x73,0x61,0x67,0x65,0x20,0x64,0x69,0x67,0x65,0x73,0x74};
	unsigned char prand[32] = {0x59,0x27,0x6e,0x27,0xd5,0x06,0x86,0x1a,0x16,0x68,0x0f,0x3a,0xd9,0xc0,0x2d,0xcc,0xef,0x3c,0xc1,0xfa,0x3c,0xdb,0xe4,0xce,0x6d,0x54,0xb8,0x0d,0xea,0xc1,0xbc,0x21};
	unsigned char sig[128];
	unsigned char pout[128];
	unsigned char pUserName[16] = { '1','2','3','4','5','6','7','8','1','2','3','4','5','6','7','8' };
	//for encrypt and decrypt
	unsigned char sm2x[32] = {0x09,0xF9,0xDF,0x31,0x1E,0x54,0x21,0xA1,0x50,0xDD,0x7D,0x16,0x1E,0x4B,0xC5,0xC6,0x72,0x17,0x9F,0xAD,0x18,0x33,0xFC,0x07,0x6B,0xB0,0x8F,0xF3,0x56,0xF3,0x50,0x20};
	unsigned char sm2y[32] = {0xCC,0xEA,0x49,0x0C,0xE2,0x67,0x75,0xA5,0x2D,0xC6,0xEA,0x71,0x8C,0xC1,0xAA,0x60,0x0A,0xED,0x05,0xFB,0xF3,0x5E,0x08,0x4A,0x66,0x32,0xF6,0x07,0x2D,0xA9,0xAD,0x13};
	unsigned char sm2message[19] = {'e','n','c','r','y','p','t','i','o','n',' ','s','t','a','n','d','a','r','d'};
	unsigned char cipher[32*5];
	unsigned char sm2cipher[116] = {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98, 0x62, 0x4, 0x32, 0x26, 0x8e, 0x77, 0xfe, 0xb6, 0x41, 0x5e, 0x2e, 0xde, 0xe, 0x7, 0x3c, 0xf, 0x4f, 0x64, 0xe, 0xcd, 0x2e, 0x14, 0x9a, 0x73, 0xe8, 0x58, 0xf9, 0xd8, 0x1e, 0x54, 0x30, 0xa5, 0x7b, 0x36, 0xda, 0xab, 0x8f, 0x95, 0xa, 0x3c, 0x64, 0xe6, 0xee, 0x6a, 0x63, 0x9, 0x4d, 0x99, 0x28, 0x3a, 0xff, 0x76, 0x7e, 0x12, 0x4d, 0xf0, 0x59, 0x98, 0x3c, 0x18, 0xf8, 0x9, 0xe2, 0x62, 0x92, 0x3c, 0x53, 0xae, 0xc2, 0x95, 0xd3, 0x3, 0x83, 0xb5, 0x4e, 0x39, 0xd6, 0x9, 0xd1, 0x60, 0xaf, 0xcb, 0x19, 0x8, 0xd0, 0xbd, 0x87, 0x66, 0x21, 0x88, 0x6c, 0xa9, 0x89, 0xca, 0x9c, 0x7d, 0x58, 0x8, 0x73, 0x7, 0xca, 0x93, 0x9, 0x2d, 0x65, 0x1e, 0xfa};

	//sm4 para
	unsigned char sm4plain[16] = {0x01, 0x23, 0x45, 0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	unsigned char sm4key[16] = {0x01, 0x23, 0x45, 0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	unsigned char sm4cipher[48];

	unsigned char sm3plain1[3] = {0x61,0x62,0x63};
	unsigned char sm3plain2[64] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};
	unsigned char digest[32];

	unsigned char outtemp[16];
	
	SM2_SIGN_Para testsm2sign;
	SM2_Para testsm2;
	SM3_Para testsm3;
	SM4_Para testsm4;
	GM_PAD	 testpad,testpad2;
	unsigned char hmacdigest[32];
	Gen_Key_Para sm2genkey;
	type = *(int *)para1;
	
	fd = open("/dev/nortm", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/nortm)");
		return NULL;
	}
	if(type == 9)
	{	
		//SM2 verify, here prepare the signature;
		memcpy(testsm2sign.pin,pin,PIN_LEN);
		testsm2sign.len = 14;
		memcpy(testsm2sign.x,sm2x,32);
		memcpy(testsm2sign.y,sm2y,32);
		memcpy(testsm2sign.d,pRandomUser,32);
		memcpy(testsm2sign.message,message, 14);
		memcpy(testsm2sign.pUserName, pUserName, 16);
		testsm2sign.LenOfpUserName = 16;
		if(ioctl(fd, SM2_SIGN, &testsm2sign) == -1)
		{
			if(debugFlag)
				printf(" sign err\n");
		}
		else
		{
			if(debugFlag)
			{
				printf("\n sm2 sign success\n");
				printhex(testsm2sign.sign,64);
			}	
		}
	}
	{//generate the cipher of the SM2 private Key.
		
		unsigned char key[MASTER_KEY_SIZE];
		memset(key,0,MASTER_KEY_SIZE);
		memcpy(key,"12345678",8);
		unsigned char salt[8] = {0x1,0x2,0x3,0x3,0x5,0x6,0x7,0x8};
		PBKDF2(outtemp, key, MASTER_KEY_SIZE, salt, 8, 1000, 16);
		SM4EncryptWithMode(pRandomUser, 32, prikey_cipher, 32, NULL, ECB, outtemp);
	}

	for(i=0;i<LOOP;++i){
		switch(type){
				//Gen SM2 Key
			case 2: {
				memcpy(sm2genkey.pin,pin,PIN_LEN);
				ret = ioctl(fd, SM2_KEYGEN, &sm2genkey);
				if(ret == -1)
				{
					if(debugFlag)
						printf("key gen error\n");
				}
				else
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag){
						printhex(sm2genkey.d, 32);
						printhex(sm2genkey.x, 32);
						printhex(sm2genkey.y, 32);
					}
				}
				break;
			}

				//Gen SM2 Key with TSX
			case 3: {
				memcpy(sm2genkey.pin,pin,PIN_LEN);
				ret = ioctl(fd, SM2_SAFE_KEYGEN, &sm2genkey);
				if(ret == -1)
				{
					if(debugFlag)
						printf("key gen error\n");
					
				}
				else
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag){
						printhex(sm2genkey.d, 32);
						printhex(sm2genkey.x, 32);
						printhex(sm2genkey.y, 32);
					}
				}
				break;
			}

				//SIGN
			case 4: {
				memcpy(testsm2sign.pin,pin,PIN_LEN);
				testsm2sign.len = 14;
				memcpy(testsm2sign.x,sm2x,32);
				memcpy(testsm2sign.y,sm2y,32);
				memcpy(testsm2sign.d,pRandomUser,32);
				memcpy(testsm2sign.message,message, 14);
				memcpy(testsm2sign.pUserName, pUserName, 16);
				testsm2sign.LenOfpUserName = 16;
				if(ioctl(fd, SM2_SIGN, &testsm2sign) == -1){
					if(debugFlag)
						printf("sign err\n");
				}
				else{
					if(debugFlag)
						printhex(testsm2sign.sign,64);
					__sync_fetch_and_add(&succ_count,1);
				}
				break;
			}

				//SM2 SIGN with TSX
			case 5: {
				testsm2sign.len = 14;
				memcpy(testsm2sign.x,sm2x,32);
				memcpy(testsm2sign.y,sm2y,32);
				memcpy(testsm2sign.d,prikey_cipher,32);
				memcpy(testsm2sign.message,message, 14);
				memcpy(testsm2sign.pUserName, pUserName, 16);
				memcpy(testsm2sign.pin,pin,PIN_LEN);

				testsm2sign.LenOfpUserName = 16;
				if(ioctl(fd, SM2_SAFE_SIGN, &testsm2sign) == -1){
					if(debugFlag)
						printf(" sign err\n");
				}
				else{
					if(debugFlag)
						printhex(testsm2sign.sign,64);
					__sync_fetch_and_add(&succ_count,1);
				}
				break;
			}

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

				//SM2 DEC with TSX
			case 7: {
				testsm2.len = 116;
				memcpy(testsm2.x,sm2x,32);
				memcpy(testsm2.y,sm2y,32);
				memcpy(testsm2.d,prikey_cipher,32);
				memcpy(testsm2.cipher,sm2cipher,116);
				memset(testsm2.plain,0,SM2_MAX_PLAIN_LEN);
				memcpy(testsm2.pin,pin,PIN_LEN);
				if(ioctl(fd,SM2_SAFE_DEC,&testsm2) == -1){
					if(debugFlag)
						printf("dec err\n");
				}
				else{
					if(debugFlag)
					{
						SM4DecryptWithMode(testsm2.plain, testsm2.len, testsm2.plain, testsm2.len, NULL, ECB, outtemp);
						printf("%s\n",testsm2.plain );
					}	
					__sync_fetch_and_add(&succ_count,1);
				}
				break;
			}


				//SM2 ENC
			case 8: {
				testsm2.len = 19;
				memcpy(testsm2.x,sm2x,32);
				memcpy(testsm2.y,sm2y,32);
				memcpy(testsm2.plain,sm2message,19);
				memset(testsm2.cipher,0,1+SM2_KEY_LEN*3+SM2_MAX_PLAIN_LEN);
				memcpy(testsm2.pin,pin,PIN_LEN);
				if(ioctl(fd,SM2_ENC,&testsm2) == -1){
					if(debugFlag)
						printf("enc err\n");
				}
				else{
					if(debugFlag){
						printf("enc return len is %d\n", testsm2.len);
						printhex(testsm2.cipher,testsm2.len);
					}
					__sync_fetch_and_add(&succ_count,1);
				}
				break;
			}
				//VERIFY
			case 9: {
				testsm2sign.len = 14;
				memcpy(testsm2sign.d,prikey_cipher,32);
				memcpy(testsm2sign.message,message, 14);
				memcpy(testsm2sign.pUserName, pUserName, 16);
				testsm2sign.LenOfpUserName = 16;
				memcpy(testsm2sign.pin,pin,PIN_LEN);
				testsm2sign.LenOfsign = 64;
				memcpy(testsm2sign.x,sm2x,32);
				memcpy(testsm2sign.y,sm2y,32); //as pin already be set in the sign operation
				ret = ioctl(fd, SM2_VERIFY, &testsm2sign);
				if(ret == -1)
				{
					if(debugFlag)
						printf(" verify err in the process\n");
				}
				else if(ret == 1)
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag)
						printf(" verify success\n");
				} 
				else
				{
					if(debugFlag)
						printf(" error signature\n");
				}
				break;
			}
				//SM3 Digest
			case 10: {
				testsm3.plainLen = 3;
				memcpy(testsm3.plain,sm3plain1,testsm3.plainLen);
				memcpy(testsm3.pin,pin,PIN_LEN);
				if(ioctl(fd,SM3_DIGEST,&testsm3) == -1){
					if(debugFlag)
						printf("digest err\n");
				}
				else
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag){
						printf("\ndigest success %d\n",SM3_DIGEST_LEN);
						for(j=0;j<SM3_DIGEST_LEN;j++)
							printf("%2x ", testsm3.digest[j]);
					}
				}
				break;
			}
				//Sm3 init update fin
			case 11: {
				testsm3.plainLen = 0;
				memcpy(testsm3.pin,pin,PIN_LEN);
				if(ioctl(fd,SM3_INIT,&testsm3) == -1){
					if(debugFlag)
						printf("digest err\n");
				}
				else
				{
					if(debugFlag)
						printf("\ndigest init success\n");
				}
				//sm3 update
				testsm3.plainLen = 64;
				memcpy(testsm3.plain,sm3plain2,testsm3.plainLen);
				if(ioctl(fd,SM3_UPDATE,&testsm3) == -1){
					if(debugFlag)
						printf("digest err\n");
				}
				else
				{
					if(debugFlag)
						printf("digest update success\n");
				}
				//sm3 final
				if(ioctl(fd,SM3_FINAL,&testsm3) == -1){
					if(debugFlag)
						printf("digest err\n");
				}
				else
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag)
					{
						printf("\ndigest final success %d\n",SM3_DIGEST_LEN);
						printhex(testsm3.digest,SM3_DIGEST_LEN);
					}	
				}
				break;
			}


				//SM3 SAFE init update fin
			case 12: {
				testsm3.plainLen = 0;
				memcpy(testsm3.pin,pin,PIN_LEN);
				if(ioctl(fd,SM3_SAFE_INIT,&testsm3) == -1){
					break;
				}
				
				//sm3 update
				testsm3.plainLen = 64;
				memcpy(testsm3.plain,sm3plain2,testsm3.plainLen);
				if(ioctl(fd,SM3_SAFE_UPDATE,&testsm3) == -1){
					break;
				}
				
				//sm3 final
				if(ioctl(fd,SM3_SAFE_FINAL,&testsm3) == -1){
					break;
				}
				else
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag)
					{
						printf("\ndigest final success %d\n",SM3_DIGEST_LEN);
						printhex(testsm3.digest,SM3_DIGEST_LEN);
					}	
				}
				break;
			}
				//SM4
			case 13: {
				testsm4.len = 16;
				testsm4.mode = 1; //ECB
				testsm4.flag = 1; //Enc
				memcpy(testsm4.key,sm4key,16);
				memcpy(testsm4.plain,sm4plain,16);
				memcpy(testsm4.pin,pin,PIN_LEN);
				if(ioctl(fd,SM4_OP,&testsm4) == -1){
					if(debugFlag)
						printf("sm4 enc err\n");
				}
				else
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag)
					{
						printf("\n sm4 enc  success %d\n",testsm4.len);
						printhex(testsm4.cipher,testsm4.len);
					}	
				}	
				break;
			}
			//HMAC
			case 14: {
				memset(testpad.pad,1,GM_HMAC_MD_CBLOCK_SIZE);
				memset(testpad2.pad,1,GM_HMAC_MD_CBLOCK_SIZE);
				memset(testpad.pad,0,GM_HMAC_MD_CBLOCK_SIZE/2);
				memset(testpad2.pad,0,GM_HMAC_MD_CBLOCK_SIZE/2);
				SM4EncryptWithMode(testpad2.pad, GM_HMAC_MD_CBLOCK_SIZE, testpad2.pad, GM_HMAC_MD_CBLOCK_SIZE, NULL, ECB, outtemp);
				SM4EncryptWithMode(testpad.pad, GM_HMAC_MD_CBLOCK_SIZE, testpad.pad, GM_HMAC_MD_CBLOCK_SIZE, NULL, ECB, outtemp);

				memcpy(testpad.pin,pin,PIN_LEN);
				memcpy(testpad2.pin,pin,PIN_LEN);
				testpad.len = GM_HMAC_MD_CBLOCK_SIZE;
				testpad2.len = GM_HMAC_MD_CBLOCK_SIZE;
				if(ioctl(fd,SAFE_IPAD,&testpad) == -1){
					if(debugFlag)
						printf("safe_ipad err\n");
				}
				if(ioctl(fd,SAFE_OPAD,&testpad2) == -1){
					if(debugFlag)
						printf("safe_opad err\n");
				}
				testsm3.plainLen = 0;
				memcpy(testsm3.pin,pin,PIN_LEN);
				if(ioctl(fd,SM3_SAFE_INIT,&testsm3) == -1){
					break;
				}
				//sm3 update
				testsm3.state.in_encrypted = 1;
				testsm3.state.out_encrypted = 1;
				testsm3.plainLen = GM_HMAC_MD_CBLOCK_SIZE;
				memcpy(testsm3.plain,testpad.pad,testsm3.plainLen);
				if(ioctl(fd,SM3_SAFE_UPDATE,&testsm3) == -1){
					break;
				}
				testsm3.plainLen = 64;
				memcpy(testsm3.plain,sm3plain2,testsm3.plainLen);
				if(ioctl(fd,SM3_SAFE_UPDATE,&testsm3) == -1){
					break;
				}		
				//sm3 final
				if(ioctl(fd,SM3_SAFE_FINAL,&testsm3) == -1){
					break;
				}
				memcpy(hmacdigest,testsm3.digest,SM3_DIGEST_LEN);

				testsm3.plainLen = 0;
				memcpy(testsm3.pin,pin,PIN_LEN);
				if(ioctl(fd,SM3_SAFE_INIT,&testsm3) == -1){
					break;
				}
				//sm3 update
				testsm3.state.in_encrypted = 1;
				testsm3.state.out_encrypted = 1;
				testsm3.plainLen = GM_HMAC_MD_CBLOCK_SIZE;
				memcpy(testsm3.plain,testpad2.pad,testsm3.plainLen);
				if(ioctl(fd,SM3_SAFE_UPDATE,&testsm3) == -1){
					break;
				}
				testsm3.state.in_encrypted = 1;
				testsm3.state.out_encrypted = 1;
				testsm3.plainLen = SM3_DIGEST_LEN;
				memcpy(testsm3.plain,hmacdigest,testsm3.plainLen);
				if(ioctl(fd,SM3_SAFE_UPDATE,&testsm3) == -1){
					break;
				}		
				//sm3 final
				if(ioctl(fd,SM3_SAFE_FINAL,&testsm3) == -1){
					break;
				}
				if(ioctl(fd,HMAC_FINAL_DEC,&testsm3) == -1){
					break;
				}
				else
				{
					__sync_fetch_and_add(&succ_count,1);
					if(debugFlag)
					{
						printf("\n HMAC  success\n");
						printhex(testsm3.digest,SM3_DIGEST_LEN);
					}	
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
 *obtain the master key and PIN
 */
int InitModule()
{
    int i=0;
   
	INIT_Para para;
	char key[MASTER_KEY_SIZE], verify[MASTER_KEY_SIZE];
	char pinVerify[PIN_LEN];
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
	memset(key,0x0,MASTER_KEY_SIZE);
	memset(verify,0x0,MASTER_KEY_SIZE);
	memset(pinVerify,0,PIN_LEN);
	//memset(pin,0,PIN_LEN);
	memset(&para,0,sizeof(para));
	printf("Init MASTER KEY succeed\n");

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
		printf("\t--0 generage the signature of the module\n");
		printf("\t--1 self test and init the module (setting the master key and the PIN)\n");
		printf("\t--2 SM2KeyGen \t\t --3 SafeKeyGen \n "); 
		printf("\t--4 Sign \t\t --5 Safe Sign \n ");
		printf("\t--6 SM2 Dec \t\t --7 Safe SM2 Dec\n");
		printf("\t--8 SM2 Enc \n");
		printf("\t--9 SM2 Verify\n");
		printf("\t--10 SM3 Digest\n");
		printf("\t--11 SM3 Init Update & Final \t\t -- 12 Safe SM3 Init Update & Final\n");
		printf("\t--13 Safe SM4 Enc/Dec\n");
		printf("\t--14 Safe HMAC\n");
		printf("\t--15 Self Test\n");
		return -1;
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
		return 0;
	}
	if(type == 15)
	{
		SelfTestCompl();
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
	
	char typechar[13][15] = {"SM2KeyGen","SM2SafeKeyGen", "Sign","SafeSign","SM2Dec","SM2SafeDec","SM2Enc","SM2Verify","SM3Digest","SM3IUF","SafeSM3IUF","SafeSM4","SafeHMAC"};
	printf("success cout is \t %d \t type \t %s \t speed: \t %f\n", succ_count,typechar[type-2], (float)(succ_count)*1000000/(end.tv_usec-beg.tv_usec+1000000*(end.tv_sec-beg.tv_sec)));		
	return 0;
}

