#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "randombytes.h"
#include "sign.h"

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
#include "SMS4.h"

int debugFlag = 1;
//unsigned int succ_count = 0;

/* add by mlj */
void printhex(unsigned char * output, int len)
{
    int i = 0;
    for(i = 0; i < len; i++)
    {
        printf(" %02x", output[i]);
    }
    printf("\n");
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
  if(fd < 0){
    printf("Error while access Kernel Module\n");
    return 0;
  }
  if(ioctl(fd, INIT, &para) == -1){
    // printf("Error while init MASTER KEY\n");
    return 0;
  }
  memset(key,0x0,MASTER_KEY_SIZE);
  memset(verify,0x0,MASTER_KEY_SIZE);
  memset(&para,0,sizeof(para));
  printf("Init MASTER KEY succeed\n");

  close(fd);

  return 1;
}


int main(void)
{
  unsigned int i, j;
  int ret;
  int succ_count = 0; // Count for Successful Sign 
  size_t mlen, smlen;
  //uint8_t m[MLEN] = {0};
  uint8_t m[MLEN] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68};
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];



  /* add by mlj */
  SIGN_Para sign_para;

  int fd = -1;
  printf("Init the module\n");
  InitModule();
  
  crypto_sign_keypair(pk, sk);

  for(i = 0; i < NTESTS; ++i) {

    // crypto_sign_keypair(pk, sk);
    // printf("m:");
    // printhex(m, MLEN);
    // crypto_sign(sm, &smlen, m, MLEN, sk);
    // printf("sm:");
    // printhex(sm, 32);

    // add by mlj 
    fd = open("/dev/nortm", O_RDWR, 0);
    if (fd < 0) {
      perror("open(/dev/nortm)");
      return -1;
    }
    
    sign_para.mlen = MLEN;
    memcpy(sign_para.m, m, MLEN);
    memcpy(sign_para.sk, sk, CRYPTO_SECRETKEYBYTES);

    // printf("signpara.mlen:%lu\n", sign_para.mlen);
    // printf("sign_para.m:\n");
    // printhex(sign_para.m, MLEN);

    if(ioctl(fd, DILITHIUM_SAFE_SIGN, &sign_para) == -1){
      if(debugFlag)
        printf("sign err\n");
    }
    else {
      __sync_fetch_and_add(&succ_count,1);
    }

    printf("signpara.smlen:%lu\n", sign_para.smlen);
    printf("sign_para.sm:\n");
    printhex(sign_para.sm, 32);

    close(fd);

    smlen = sign_para.smlen;
    memcpy(sm, sign_para.sm, smlen);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }

    if(mlen != MLEN) {
      fprintf(stderr, "Message lengths don't match\n");
      return -1;
    }

    for(j = 0; j < mlen; ++j) {
      if(m[j] != m2[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }
  }
  
  printf("Succ_count:%d\n", succ_count);
  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

  return 0;
}
