#include <stdint.h>
#include "sign.h"
#include "poly.h"
#include "polyvec.h"
#include "params.h"
#include "cpucycles.h"
#include "speed_print.h"

#define MLEN 8
#define NTESTS 10000

uint64_t t[NTESTS];

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
  unsigned int i;
  size_t siglen;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  uint8_t seed[CRHBYTES];
  polyvecl mat[K];
  /* add by mlj */
  int succ_count = 0;

  // for(i = 0; i < NTESTS; ++i) {
  //   t[i] = cpucycles();
  //   crypto_sign_keypair(pk, sk);
  // }
  // print_results("Keypair:", t, NTESTS);

  /* add by mlj */
  SIGN_Para sign_para;

  int fd = -1;
  printf("Init the module\n");
  InitModule();
  
  crypto_sign_keypair(pk, sk);

    // add by mlj 
    fd = open("/dev/nortm", O_RDWR, 0);
    if (fd < 0) {
      perror("open(/dev/nortm)");
      return -1;
    }
    
    sign_para.mlen = CRHBYTES;
    memcpy(sign_para.m, sig, CRHBYTES);
    memcpy(sign_para.sk, sk, CRYPTO_SECRETKEYBYTES);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();

    if(ioctl(fd, DILITHIUM_SAFE_SIGN, &sign_para) != 0){
    //if(ioctl(fd, DILITHIUM_SIGN, &sign_para) == -1){
      // printf("Sign Err\n");
    }
    else {
      __sync_fetch_and_add(&succ_count,1);
    }
  }
  
  printf("Succ_count:%d\n", succ_count);
  print_results("Sign:", t, NTESTS);

  // for(i = 0; i < NTESTS; ++i) {
  //   t[i] = cpucycles();
  //   crypto_sign_signature(sig, &siglen, sig, CRHBYTES, sk);
  // }
  // print_results("Sign:", t, NTESTS);

  // for(i = 0; i < NTESTS; ++i) {
  //   t[i] = cpucycles();
  //   crypto_sign_verify(sig, CRYPTO_BYTES, sig, CRHBYTES, pk);
  // }
  // print_results("Verify:", t, NTESTS);

  close(fd);
  return 0;
}
