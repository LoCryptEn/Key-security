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
#include <string.h>

#include <errno.h>
#include <termios.h>
#include<openssl/bn.h>
#include<openssl/ec.h>
#include<openssl/objects.h>
#include <openssl/evp.h>

int type = 1;

u_int64_t rdtsc()
{
        u_int32_t lo,hi;


        __asm__ __volatile__
        (
         "rdtsc":"=a"(lo),"=d"(hi)
        );
        return (u_int64_t)hi<<32|lo;
}

void BN_2_ulong(BIGNUM *a,  unsigned long b[] ){

    BIGNUM *c =BN_new();

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[0]=BN_get_word(c);
    BN_rshift(a, a, 64);  //192

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[1]=BN_get_word(c);
    BN_rshift(a, a, 64); //128

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[2]=BN_get_word(c);
    BN_rshift(a, a, 64); //64

    b[3]=BN_get_word(a);

    free(c);
 }

 void Ulong_2_BN(unsigned long b[], BIGNUM *a){

    BIGNUM *c =BN_new();

    BN_set_word(a, b[3]);  //64
    BN_lshift(a, a, 64);  //128

    BN_add_word(a, b[2]);
    BN_lshift(a, a, 64); //192

    BN_add_word(a, b[1]);
    BN_lshift(a, a, 64); //256

    BN_add_word(a, b[0]);

    free(c);
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

    u_int64_t startcc,  finishcc;
    clock_t  start,  finish;
    u_int64_t  durationcc;
    double duration;

    const char message[] ="hello world!";
    EVP_MD_CTX   *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;
    char* algorithm="sha256";
    char* msg ="hello world!";
    BIGNUM *p_z = BN_new();
    //const char pri_key[]="DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F";
    //const char pri_key[]="DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";
    //BIGNUM *p_privkey;
    EC_GROUP *group;
    EC_POINT * p_pubkey;
    EC_KEY  * ec_key_temp;
    BN_CTX *ctx = BN_CTX_new();
    size_t  buf_len = 0x21;

    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();

    // AES-NI ENC Pk
    const char pk_str[] = "d471b173df7b29aa0c5b667074a2b37a7d5bdb0f8a4c9f141534cff30cba0ea9";
    //
    BIGNUM *prikenc = BN_new();
    BN_hex2bn(&prikenc, pk_str);

    //-----------------------------set key--------------------------------------------------------//
    //p_privkey = BN_new();
    //BN_hex2bn(&p_privkey, pri_key);
    group=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    p_pubkey=EC_POINT_new(group);
    //EC_POINT_mul(group, p_pubkey, p_privkey, NULL, NULL, NULL);

    unsigned char bufQ[33] = {0x3, 0x75, 0xf7, 0x16, 0xed, 0x6, 0x49, 0x35, 0x9b, 0x6, 0xf5, 0xfb, 0x7a, 0x25, 0xdb, 0x62, 0x6c, 0x89, 0x10, 0x7f, 0xc, 0x9, 0x12, 0x86, 0x4b, 0xec, 0x4e, 0x30, 0x23, 0xb7, 0xcd, 0xaf, 0x39};
    EC_POINT_oct2point(group, p_pubkey, bufQ,  buf_len, ctx); 


    ec_key_temp= EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    //EC_KEY_set_private_key(ec_key_temp, p_privkey);
    EC_KEY_set_private_key(ec_key_temp, NULL);
    EC_KEY_set_public_key(ec_key_temp, p_pubkey);
    //-----------------------------------------------------------------------------------------//

    //-------------------------INIT------------calculate public parameters K1*G----------------------//
    //const char K1[]="1234567890ABCDEFFEDCBA09876543211234567890ABCDEFFEDCBA0987654321";
    //BIGNUM *p_k1 = BN_new();
    //BN_hex2bn(&p_k1, K1);

    EC_POINT * p_pubk1=EC_POINT_new(group);
    //EC_POINT_mul(group, p_pubk1, p_k1, NULL, NULL, NULL);

    unsigned char bufk1G[33]={0x3, 0x93, 0x98, 0x69, 0xc3, 0xe7, 0x6b, 0xbb, 0x89, 0xd6, 0xb5, 0xca, 0x2b, 0x6c, 0x4b, 0x65, 0x3d, 0xa8, 0xec, 0x95, 0xd2, 0xe2, 0x81, 0xe5, 0xbd, 0x18, 0xa6, 0x1, 0xc1, 0x10, 0xec, 0x6f, 0xf9};
    
    EC_POINT_oct2point(group, p_pubk1, bufk1G,  buf_len, ctx);         



    // AES-NI ENC K1
    const char K1Enc[]="8c24f784a6285db7487b9a4f1df3c8db8c24f784a6285db7487b9a4f1df3c8db";
    //
    BIGNUM *p_kenc = BN_new();
    BN_hex2bn(&p_kenc, K1Enc);


/*
    //Another method to set key by generate key in memory
    EC_KEY  * ec_key_temp;
    ec_key_temp= EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec_key_temp);
 */  

    BIGNUM *K2 = BN_new();
    BIGNUM *Kc = BN_new();
    BIGNUM *Kcinv = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *ed = BN_new();
    BIGNUM *zed = BN_new();
    BIGNUM *s = BN_new();
    EC_POINT * k2G;
    EC_POINT * kG;
    const BIGNUM *order;
    BIGNUM *X = BN_new();
    //BN_MONT_CTX * montctx = BN_MONT_CTX_new();
    //BN_CTX *ctx = BN_CTX_new();
    char *rs;

    order = EC_GROUP_get0_order(group);
    BIGNUM *r_copy =BN_new();

    k2G=EC_POINT_new(group);
    kG=EC_POINT_new(group);

    unsigned long Res[15]={0};
    unsigned long RA[4]={0};  //r
    unsigned long DA[4]={0};  //d
    unsigned long ZA[8]={0};  //k=(k1+k2) mod n, k1 && k2
    unsigned long ZA2[4]={0};

    Res[4] = 0x1ad9ebe442a1dac3;
    Res[5] = 0x3248292129c2f40b;  // hidden factor

    int i, j, fd;
    ECDSA_Para para;


    start = clock();
    startcc = rdtsc();
    //----------------- compute digest--------------------------------//

    OpenSSL_add_all_digests();

    md=EVP_get_digestbyname(algorithm);

    if(!md){
        printf("unknown message digest\n");
    }

    mdctx=EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg,  strlen(msg));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    //EVP_MD_CTX_cleanup(&mdctx);

    BN_bin2bn(md_value, 32, p_z);
    //-------------------------------------------------------------------------------------------------//
 



    do{    
    if (!BN_priv_rand_range(K2, order)) {
        printf("generate K2 fail.\n");
        }

    //generate k2//
    //unsigned long k2array = 0x134569787123;
    //BN_set_word(K2, k2array);
    //add finish

    EC_POINT_mul(group, k2G, K2, NULL, NULL, NULL);  //calculate k2*G

    EC_POINT_add(group, kG, p_pubk1, k2G, NULL);  //calculate k1*G+k2*G=k*G

    EC_POINT_get_affine_coordinates(group, kG, X, NULL,NULL);

    BN_nnmod(r, X, order, ctx); //get r
    }while(BN_is_zero(r));   

    BN_copy(r_copy, r);

    BN_2_ulong(r, RA);
    BN_2_ulong(prikenc, DA);
    BN_2_ulong(p_kenc, ZA);
    BN_2_ulong(K2, ZA2);
    BN_2_ulong(p_z, Res);  // Res[0]-Res[3] = z


    /*
    unsigned long findorder[4] = {0};
    BIGNUM *order_copy =BN_new();
    BN_copy(order_copy, order);
    BN_2_ulong(order_copy, findorder);
    printf("order: \n");
    for(int i=0; i<4; ++i)
    {
        printf("%lx\n", findorder[i]);
    }
    //add finish
    */

    BIGNUM *umq = BN_new();
    BIGNUM* rrr = BN_new();
    BN_hex2bn(&rrr, "10000000000000000000000000000000000000000000000000000000000000000");
    //printf("length of RR: %d\n", BN_num_bits(rrr));

    BN_mod_inverse(umq, order, rrr, ctx);    // M^-1 mod R
    BIGNUM *ZEROQ = BN_new();
    BN_zero(ZEROQ);
    BN_mod_sub(umq, ZEROQ, umq, rrr, ctx);  //-M^-1 mod R
    BN_mask_bits(umq, 64);
    unsigned long uq;
    uq=BN_get_word(umq);
    //printf("uq: %lx\n", uq);

    ZA[4]=ZA2[0];
    ZA[5]=ZA2[1];
    ZA[6]=ZA2[2];
    ZA[7]=ZA2[3];

    fd = open("/dev/nortm", O_RDWR, 0);

    para.messages[0]=RA[0];
    para.messages[1]=RA[1];
    para.messages[2]=RA[2];
    para.messages[3]=RA[3];

    para.messages[4]=DA[0];
    para.messages[5]=DA[1];
    para.messages[6]=DA[2];
    para.messages[7]=DA[3];

    para.messages[8]=ZA[0];
    para.messages[9]=ZA[1];
    para.messages[10]=ZA[2];
    para.messages[11]=ZA[3]; 
    para.messages[12]=ZA[4];
    para.messages[13]=ZA[5];
    para.messages[14]=ZA[6];
    para.messages[15]=ZA[7]; 

    para.messages[16]=Res[0]; 
    para.messages[17]=Res[1]; 
    para.messages[18]=Res[2]; 
    para.messages[19]=Res[3]; 

    para.messages[20]=Res[4]; 
    para.messages[21]=Res[5]; 
    para.messages[22]=uq; 

    for(i=23; i<25; ++i)
	{
		para.messages[i] = 0;
	}

    if(ioctl(fd,ECDSA_OP,&para) == -1)
	{
		printf("ECDSA signing fail\n");
	}
    for(i=0; i<15; ++i)
	{
		Res[i] = para.messages[i];
	}
    //printf("sign: %lx\n", Res[14]);

    BN_set_word(zed, Res[9]);  
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[8]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[7]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[6]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[5]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[4]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[3]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[2]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[1]); 
    BN_lshift(zed, zed, 64);  

    BN_add_word(zed, Res[0]);
    BN_mod(zed, zed, order, ctx);

    //-------------------------------------------------------//

    BN_set_word(Kc, Res[14]); 
    BN_lshift(Kc, Kc, 64);  

    BN_add_word(Kc, Res[13]);  
    BN_lshift(Kc, Kc, 64);  

    BN_add_word(Kc, Res[12]);
    BN_lshift(Kc, Kc, 64); 

    BN_add_word(Kc, Res[11]);
    BN_lshift(Kc, Kc, 64); 

    BN_add_word(Kc, Res[10]);
    BN_mod_inverse(Kcinv,Kc,order,ctx); 
    BN_mod_mul(s, Kcinv, zed, order, ctx); 

    finish = clock();
    finishcc = rdtsc();

    duration = (double) (finish - start)/CLOCKS_PER_SEC;
    durationcc = (u_int64_t)(finishcc - startcc);
  
 
    ECDSA_SIG_set0(ecdsa_sig, r_copy, s); 
    if ( ECDSA_do_verify(md_value, md_len, ecdsa_sig, ec_key_temp))
    {
        printf("verify success\n");
    }
 

    printf("The duration time is :  %.16f  seconds\n", duration);
    printf("The duration cycles is :  %lu cycles \n", durationcc);

    EC_KEY_free(ec_key_temp);

    if(ecdsa_sig= NULL)
    {
        printf("Sign Error\n");
    }

    printf("Sign Success\n");

    close(fd);

    BN_free(p_z);
    BN_CTX_free(ctx);
    BN_free(prikenc);
    EC_POINT_free(p_pubkey);
    ECDSA_SIG_free(ecdsa_sig);
    EC_POINT_free(p_pubk1);
    BN_free(p_kenc);
    BN_free(K2);
    BN_free(Kc);
    BN_free(Kcinv);
    BN_free(r);
    BN_free(ed);
    BN_free(zed);
    BN_free(s);
    EC_POINT_free(k2G);
    EC_POINT_free(kG);
    BN_free(order);
    BN_free(X);
    BN_free(r_copy);
}
//*/

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


int InitModule()
{
    int i=0;
   
	INIT_Para para;
	unsigned char key[SM4_KEY_SIZE], verify[SM4_KEY_SIZE];
	int fd;

	//Import the AES/SM4 key

    unsigned char import_key[SM4_KEY_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,
		    0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	
	memset(key,0,SM4_KEY_SIZE);
	memcpy(key,import_key,SM4_KEY_SIZE);

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

		printf("ECDSA signing in CPU-Bound\n");

            FuncTestCompl1();


		return 0;
	}
	
	return 0;
}

