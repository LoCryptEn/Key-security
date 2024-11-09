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

int type = 1;
#define USER_HELPER

#ifdef USER_HELPER
#include"user_helper.h"
/*C1,C2 :C=C_2 * R + C_1*/
uint64_t C_1_from_extern[16];
uint64_t C_2_from_extern[16];
#endif
uint64_t rdtsc()
{
        uint32_t lo,hi;


        __asm__ __volatile__
        (
         "rdtsc":"=a"(lo),"=d"(hi)
        );
        return (uint64_t)hi<<32|lo;
}

void printchar(unsigned char * output, int len)
{
    int i = 0;
    for(i = 0; i < len; i++)
    {
        printf(" %c", output[i]);
    }
    printf("\n");
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

///*	
int FuncTestCompl1()
{
	//new added
	clock_t  start,  finish;
	uint64_t startcc,  finishcc;

    double  duration;
	uint64_t  durationcc;
	//
	int i,fd;

	fd = open("/dev/nortm", O_RDWR, 0);

	RSA_Para para;
	
	unsigned long long message[500] = {0};
	unsigned long long Res[100] = {0};

/*
	for(i=0; i<500; ++i)
	{
		message[i]=rand();
		message[i] = message[i] << 32;
		message[i] = message[i] | rand();
		para.messages[i] = message[i];
	}
	*/


message[0] = 0xfd9cafcc3c045c26; /*p(+16 lines 1024 bit)*/
message[1] = 0x32ef097e0535be96; /*p 每128bit分组 被密钥{0x0123456789ABCDEF, 0xFEDCBA9876543210}异或*/
message[2] = 0x6c0497dcf7f56738;
message[3] = 0xde34a27ed307fe31;
message[4] = 0x96c3675f530df01f;
message[5] = 0x9b87e0880fbe58db;
message[6] = 0x6ea5483e79481b2d;
message[7] = 0xcf69efcba61e2545;
message[8] = 0xfa66443cf2c54c1f;
message[9] = 0x91a636d09e5326d4;
message[10] = 0xe8360376b8d9f509;
message[11] = 0x67e0b4b79df3d136;
message[12] = 0x71cf6321fa2fdec5;
message[13] = 0xc9d10b89cc635181;
message[14] = 0x67aca100bfc3bfa8;
message[15] = 0x692da5df8d2d0e48;
for(i=0; i<16; ++i)
{
	para.messages[i] = message[i];
}


// c2  Cp R
#ifndef USER_HELPER
message[16] = 0xb95d16811b5e5931;/*c2 (+16 lines)密文C的高1024比特*/
message[17] = 0xd1f4a5ac3c6586fd; /*C1,C2 :C=C_2 * R + C_1*/
message[18] = 0x82383eb7bf7e0def; /*R=2^1024*/
message[19] = 0x5249b50e33dcb0de;
message[20] = 0x673e3bc626cc414d;
message[21] = 0x5c88258cc3b1096e;
message[22] = 0xbf987bd2caf769e5;
message[23] = 0xb8c0d9d29dacc4b7;
message[24] = 0x9be2e6141a6d5306;
message[25] = 0xd93fcf90df5a93be;
message[26] = 0x5d939313507b3c2d;
message[27] = 0xf008a162bf9f0d35;
message[28] = 0xe4c52867dfc3d675;
message[29] = 0xddb4c52ec48b194d;
message[30] = 0xd6c2e23edcad58f0;
message[31] = 0x14265d15f006ce6a;
#else
for(i=16; i<32; ++i)
{
	message[i]=C_2_from_extern[i-16];
}
#endif//USER_HELPER
for(i=16; i<32; ++i)
{
	para.messages[i] = message[i];
}


message[32] = 0xc697354528a7221d;/*RRp(+16 lines)R^2 mod p*/
message[33] = 0xd04318c74fc4e105;
message[34] = 0x507b74a8fe85db5c;
message[35] = 0x6b90489ff59276db;
message[36] = 0x713d4fdcadac7719;
message[37] = 0x8221930c67af0b72;
message[38] = 0x70d962ecdd0add09;
message[39] = 0x529c51aba220954c;
message[40] = 0xf6c622237221a540;
message[41] = 0x241ecb6374b6d63e;
message[42] = 0x3f0cd0c1f2da0ca5;
message[43] = 0xdaaac6d08cff9876;
message[44] = 0xa2184fb0236af9bf;
message[45] = 0xc29ffa0049f8a6b8;
message[46] = 0x7afa631a107c1457;
message[47] = 0x0b80229a17179d33;
for(i=32; i<48; ++i)
{
	para.messages[i] = message[i];
}


message[48] = 0x9f0aba313b3fb3f6;/*dmp1(+16 lines)d mod p-1*/
message[49] = 0xbd90634d2e8b8b58;/*dmp1和dmq1的每64比特分组被密钥0x0123456789ABCDEF异或*/
message[50] = 0xccb3fc02a64331ac;
message[51] = 0x4cf039f815cb543a;
message[52] = 0x3e25befea59cfa75;
message[53] = 0x2005deb80899339a;
message[54] = 0xcc2c133790cc2aa4;
message[55] = 0x55c01df88a0e2e19;
message[56] = 0x81c9184f434d2669;
message[57] = 0x8d47727d39f7e9db;
message[58] = 0xda2f3f4d1a1158e2;
message[59] = 0x94ee28146b787046;
message[60] = 0xe8b95b571387d025;
message[61] = 0x25e5b733a36fd9d2;
message[62] = 0x5b8f35010afac267;
message[63] = 0x5b2d7dc0ee6986dd;
for(i=48; i<64; ++i)
{
	para.messages[i] = message[i];
}



message[64]=0x51b08be00dd0a787;/*p0 (+1 line) -p^{-1} mod 2^64*/
para.messages[64] = message[64];



//enc-q//
message[80] = 0xd17dc21c42760588;/*q (+16 lines 1024 bit)*/
message[81] = 0xcf47ab0e698ffa1d;/*q被密钥{0x0123456789ABCDEF, 0xFEDCBA9876543210}AES加密*/
message[82] = 0x2cd2609ebe844674;
message[83] = 0x98883a6912756664;
message[84] = 0xf0a6d3d16eeb4ccf;
message[85] = 0xa8d229f570c07090;
message[86] = 0x446451e76acc42d9;
message[87] = 0xa72983ec415a791d;
message[88] = 0x41231c88dcd8100b;
message[89] = 0x1cefc2a0efa05033;
message[90] = 0x64ce55c4a3bc654b;
message[91] = 0x5b8ca345b5ad8e04;
message[92] = 0x15cf7213c53cb526;
message[93] = 0xa11dce113e711dfa;
message[94] = 0x4d3c000642903cfa;
message[95] = 0x3c3b91e6f58ecdbd;
for(i=80; i<96; ++i)
{
	para.messages[i] = message[i];
}
//---//
#ifndef USER_HELPER
message[96] = 0xd3ebab218c09ed9e;/*c1 (+16 lines)密文C的低1024比特*/
message[97] = 0x2ec78f42950ac8b9;/*C1,C2 :C=C_2 * R + C_1*/
message[98] = 0xc45c81281c37fd33;
message[99] = 0x1dfca9c5207ae0a1;
message[100] = 0xc7cd3466eb7261a6;
message[101] = 0xea81c73004cb78cb;
message[102] = 0x73fe1ade0771a1c2;
message[103] = 0xb14fe0ea50370208;
message[104] = 0x97b79c82d5925cbd;
message[105] = 0x4b3fb69517b7ef3c;
message[106] = 0x30a68013400e53a2;
message[107] = 0x6139330cea70a6cf;
message[108] = 0x3bb59161fcff0f3c;
message[109] = 0xec55b647a6a10ff5;
message[110] = 0x88db3111373e31de;
message[111] = 0xd30b951fac6fb31d;
#else
for(i=96; i<112; ++i)
{
	message[i]=C_1_from_extern[i-96];
}
#endif//USER_HELPER
for(i=96; i<112; ++i)
{
	para.messages[i] = message[i];
}

message[112] = 0x8a891b1a6db05376;/*RRq(+16 lines)R^2 mod q*/
message[113] = 0x591aa942354479ad;
message[114] = 0x3b3a0808af09ee93;
message[115] = 0xb80e2538b4a302cf;
message[116] = 0xbc2df11d88abcc04;
message[117] = 0x91724ed375f76f78;
message[118] = 0x85471c846606aba3;
message[119] = 0x4c1c0bbfc996d074;
message[120] = 0xc84b978795c7b0bf;
message[121] = 0x1e57e0267727577f;
message[122] = 0xf1acda2e6451b4f1;
message[123] = 0x218aa3f1b167e5f7;
message[124] = 0x26c3675b3796d8dd;
message[125] = 0x4f62dad58b04a953;
message[126] = 0x0e5b1db87764b57d;
message[127] = 0x3686fdcf1acfa5f4;
for(i=112; i<128; ++i)
{
	para.messages[i] = message[i];
}

message[128] = 0xebe146bf1611ebc6;/*dmq1(+16 lines)d mod q-1*/
message[129] = 0x378eee3e741c9b8b;/*dmp1和dmq1的每64比特分组被密钥0x0123456789ABCDEF异或*/
message[130] = 0xee384d1b92d5bd46;
message[131] = 0x5e3355dd86b8ca40;
message[132] = 0x45ebc0d86b81980a;
message[133] = 0xa3dcb2217d5e4593;
message[134] = 0xfca74009d2468e65;
message[135] = 0x8db8273bea220ebb;
message[136] = 0x245bdf1d6055c56e;
message[137] = 0x81d5ce7395a65310;
message[138] = 0x41c26d242f63acc5;
message[139] = 0xd17b59e121b1d9b0;
message[140] = 0x9aa6c94e7e63a210;
message[141] = 0xcecb2a4530a6eec6;
message[142] = 0xfd38a34a2d30d7b4;
message[143] = 0x4bbfd830279330ce;
for(i=128; i<144; ++i)
{
	para.messages[i] = message[i];
}


message[144]=0x30b922942b001ae7;/*q0 (+1 line) -q^{-1} mod 2^64*/
para.messages[144] = message[144];


message[160] = 0xa7cc614d5197c537;/*iqmp(+16 lines) q-1 mod p*/
message[161] = 0xb6f1be85e23c279e;
message[162] = 0x14cfa343bd937442;
message[163] = 0x4fa2515a87e75add;
message[164] = 0x7f7e61238a7d7268;
message[165] = 0x96bcccdb03d178e3;
message[166] = 0x78b1ceb925d6281e;
message[167] = 0x111f8fbd39e32aa8;
message[168] = 0x2b8319a74d26a314;
message[169] = 0xd553e8ca3dc9e3b3;
message[170] = 0xf96158d571c75f3a;
message[171] = 0xabb5cc5731fcd0cf;
message[172] = 0x955c3b60d7f7d0f7;
message[173] = 0xdb2fa973c10d663c;
message[174] = 0x10e56d1a70364d64;
message[175] = 0x3b77875466a3ba2c;
for(i=160; i<176; ++i)
{
	para.messages[i] = message[i];
}



	//new added
	start = clock();
	startcc = rdtsc();
	//
//for(int j=0; j<1000; ++j)	
//{	
	if(ioctl(fd,RSA_OP,&para) == -1)
		printf("RSA Dec fail\n");
//}		
	//new added
	finish = clock();
	finishcc = rdtsc();

    duration = (double) (finish - start)/CLOCKS_PER_SEC;
	durationcc = (uint64_t)(finishcc - startcc);
	//duration = duration/1000;
	//durationcc = durationcc/1000;


    printf("The duration time is :  %.16f  seconds\n", duration);
	//printf("The duration cycles is :  %llu cycles \n", durationcc);	
	//
///*
	for(i=0; i<32; ++i)/*(+5 lines)收到解密结果，即明文*/
	{
		Res[i] = para.messages[i];
		printf ("Res[%d]:        %llx\n",i,Res[i]);
	}
//*/
	close(fd);

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
	//scanf("%s",passwd);
	int i;
	for(i = 0; i < size; i++)
		scanf("%x", &passwd[i]);
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
	unsigned char key[SM4_KEY_SIZE], verify[SM4_KEY_SIZE];
	int fd;

	//Import the SM4 key
	
	unsigned char import_key[SM4_KEY_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,
		    0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	
	//unsigned char import_key[SM4_KEY_SIZE] = {0x43, 0x72, 0x79, 0x70,0x74,0x6F,0x67,0x72,
	//	0x61,0x70,0x68,0x79,0x54,0x65,0x73,0x74};
		
	memset(key,0,SM4_KEY_SIZE);
	memcpy(key,import_key,SM4_KEY_SIZE);
	//printf("Import AES-SM4 128-bits KEY\n");
	memset(import_key,0,SM4_KEY_SIZE);
	
	memcpy(para.sm4Key,key,SM4_KEY_SIZE);
    
	printf("Import AES/SM4 128-bits KEY\n");
	fd = open("/dev/nortm", O_RDWR, 0);
	if(fd<0){
		printf("Error while access Kernel Module\n");
		return 0;
	}
	if(ioctl(fd, INIT, &para) == -1){
		printf("Error while init MASTER KEY\n");
		return 0;
	}
	memset(key,0x0,SM4_KEY_SIZE);
	memset(verify,0x0,SM4_KEY_SIZE);
	memset(&para,0,sizeof(para));
	printf("Init AES/SM4 128-bits KEY succeed\n");

	close(fd);

	return 1;
}

int main(int argc, char **argv){
	type = atoi(argv[4]);
	int i,res,t;


	if(type == 1)
	{
		printf("Put the AES/SM4 128 bits key into debug registers dr0 && dr1\n");
		InitModule();
		return 0;
	}
	if(type == 2)
	{

		printf("RSA operation in CPU-Bound\n");
		user_helper();
		FuncTestCompl1();

		return 0;
	}
	
	return 0;
}

