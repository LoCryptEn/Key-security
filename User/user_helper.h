#ifndef USER_HELPER_H
#define USER_HELPER_H
#include<stdio.h>
#include<stdint.h>
#include<openssl/bn.h>
#include<openssl/bio.h>

void BN_2_ulong(BIGNUM *a,  unsigned long b[] );
void Ulong_2_BN(unsigned long b[], BIGNUM *a);
void BN2048_2_ulong(BIGNUM *a,  unsigned long b[] );
extern uint64_t C_1_from_extern[];
extern uint64_t C_2_from_extern[];
int rsa_used_for_test_enc(const char* parameter_e,const char*parameter_d,const char*parameter_n,const char* parameter_m ,size_t parameter_e_len,size_t parameter_d_len,size_t parameter_n_len,size_t parameter_m_len, uint64_t* c_1,uint64_t* c_2,size_t c_1_len, size_t c_2_len, uint64_t* ciphertext,size_t ciphertext_len);
int user_helper();
#endif // #ifndef USER_HELPER_H