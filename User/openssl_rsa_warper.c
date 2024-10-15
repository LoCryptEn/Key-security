#include "user_helpers.h"
#include <cstddef>
void BN_2_ulong(BIGNUM *a,  unsigned long b[] ){

    BIGNUM *c =BN_new();

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[0]=BN_get_word(c);
    BN_rshift(a, a, 64);  //960

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[1]=BN_get_word(c);
    BN_rshift(a, a, 64); //896

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[2]=BN_get_word(c);
    BN_rshift(a, a, 64); //832

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[3]=BN_get_word(c);
    BN_rshift(a, a, 64);  //768

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[4]=BN_get_word(c);
    BN_rshift(a, a, 64); //704

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[5]=BN_get_word(c);
    BN_rshift(a, a, 64); //640

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[6]=BN_get_word(c);
    BN_rshift(a, a, 64);  //576

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[7]=BN_get_word(c);
    BN_rshift(a, a, 64); //512

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[8]=BN_get_word(c);
    BN_rshift(a, a, 64); //448

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[9]=BN_get_word(c);
    BN_rshift(a, a, 64);  //384

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[10]=BN_get_word(c);
    BN_rshift(a, a, 64); //320

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[11]=BN_get_word(c);
    BN_rshift(a, a, 64); //256

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[12]=BN_get_word(c);
    BN_rshift(a, a, 64);  //192

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[13]=BN_get_word(c);
    BN_rshift(a, a, 64); //128

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[14]=BN_get_word(c);
    BN_rshift(a, a, 64); //64

    b[15]=BN_get_word(a);

    free(c);
 }

 void Ulong_2_BN(unsigned long b[], BIGNUM *a){

    BIGNUM *c =BN_new();

    BN_set_word(a, b[15]);  
    BN_lshift(a, a, 64);  

    BN_add_word(a, b[14]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[13]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[12]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[11]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[10]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[9]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[8]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[7]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[6]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[5]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[4]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[3]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[2]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[1]);
    BN_lshift(a, a, 64); 

    BN_add_word(a, b[0]);

    free(c);
 }
 void BN2048_2_ulong(BIGNUM *a,  unsigned long b[] ){

    BIGNUM *c =BN_new();

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[0]=BN_get_word(c);
    BN_rshift(a, a, 64);  //1*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[1]=BN_get_word(c);
    BN_rshift(a, a, 64); //2*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[2]=BN_get_word(c);
    BN_rshift(a, a, 64); //3*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[3]=BN_get_word(c);
    BN_rshift(a, a, 64);  //4*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[4]=BN_get_word(c);
    BN_rshift(a, a, 64); //5*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[5]=BN_get_word(c);
    BN_rshift(a, a, 64); //6*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[6]=BN_get_word(c);
    BN_rshift(a, a, 64);  //7*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[7]=BN_get_word(c);
    BN_rshift(a, a, 64); //8*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[8]=BN_get_word(c);
    BN_rshift(a, a, 64); //9*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[9]=BN_get_word(c);
    BN_rshift(a, a, 64);  //10*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[10]=BN_get_word(c);
    BN_rshift(a, a, 64); //11*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[11]=BN_get_word(c);
    BN_rshift(a, a, 64); //12*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[12]=BN_get_word(c);
    BN_rshift(a, a, 64);  //13*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[13]=BN_get_word(c);
    BN_rshift(a, a, 64); //14*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[14]=BN_get_word(c);
    BN_rshift(a, a, 64); //15*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[15]=BN_get_word(c);
    BN_rshift(a, a, 64); //16*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[16]=BN_get_word(c);
    BN_rshift(a, a, 64); //17*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[17]=BN_get_word(c);
    BN_rshift(a, a, 64); //18*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[18]=BN_get_word(c);
    BN_rshift(a, a, 64); //19*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[19]=BN_get_word(c);
    BN_rshift(a, a, 64); //20*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[20]=BN_get_word(c);
    BN_rshift(a, a, 64); //21*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[21]=BN_get_word(c);
    BN_rshift(a, a, 64); //22*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[22]=BN_get_word(c);
    BN_rshift(a, a, 64); //23*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[23]=BN_get_word(c);
    BN_rshift(a, a, 64); //24*64

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[24]=BN_get_word(c);
    BN_rshift(a, a, 64); 

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[25]=BN_get_word(c);
    BN_rshift(a, a, 64); 

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[26]=BN_get_word(c);
    BN_rshift(a, a, 64); 

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[27]=BN_get_word(c);
    BN_rshift(a, a, 64); 

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[28]=BN_get_word(c);
    BN_rshift(a, a, 64); 

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[29]=BN_get_word(c);
    BN_rshift(a, a, 64); 

    BN_copy(c, a);
    BN_mask_bits(c, 64);
    b[30]=BN_get_word(c);
    BN_rshift(a, a, 64); 

    b[31]=BN_get_word(a);

    free(c);
 }

//----------------------------------------------------------------
//Input:parameter_e ,parameter_d, parameter_n, parameter_m
//Output:
//Input & Output:
//ret:   
#define DEBUG_rsa_used_for_test_enc
#undef TEST_rsa_used_for_test_enc
int rsa_used_for_test_enc(const char* parameter_e,const char*parameter_d,const char*parameter_n,const char* parameter_m \
    ,size_t parameter_e_len,size_t parameter_d_len,size_t parameter_n_len,size_t parameter_m_len, \
    u_int64_t* c_1,u_int64_t* c_2,size_t c_1_len, size_t c_2_len, u_int64_t* ciphertext,size_t ciphertext_len)
{
#ifdef TEST_rsa_used_for_test_enc
    BIGNUM *e =BN_new();
    BN_hex2bn(&e,"0f31");
    printf("length of e: %d\n", BN_num_bits(e));

    BIGNUM *d =BN_new();
    BN_hex2bn(&d,"928ae599a94444bbf412b41c9791328de405ea74d7ef5a5f72c8e7cdfddb5fdb4d7e1cab9cdecdd634b7ed481550bc99864f6a71a4ffcc6b6b31b21bac8d21f46f5a6176cc7ad28bad388565e076d5e6eb0c577dddd9d7f55cd83330cb01677896ee37d598734eb10e95af997ddb08949d171a68629de9622a5bbcce01ccbfcda8ce93f779eb474362f917ed74eb1f823d81ec11f444a8773a071a632ea5efb4b0945680a6ad70f45c3d2612b7d090a79c282d81ebbd433ae01af0c96be73c846d8b00b8900875d92f31ee00614bc0a3be54ece2167b12128f8ea671e0fdc3c5868b6b4bdf314dc8e9c51350f35ac7a0d05d532340f8070fa8d41cc1b1f3b91");
    printf("length of d: %d\n", BN_num_bits(d));

    BIGNUM *n =BN_new();
    BN_hex2bn(&n,"7a66ee12a844f4220cb0d502fd0f377a253910a5011e857e05358e279ab0e9be28b311ade9ae71c1b599d90d6b189ae44d7d9ad55b3f72632e27798d1bba482ec0a368d4c4a3120f9bd8d507f41090af8efe98e9f4f6032c569f404fa0c432698206a54a1b52ad3849d15f0b25e1035f8a784cfc3f750d8c8d0eb6f07827ff00b2c91451e2c4afd78fc32caec1f27d48394261489f8edb0859d61f0726a2ee0f349c8e663e373bcb5ba60f3bc63d1731ea9eb6b703e815bfecc14023d84a708856094ede6958568ad440bf66a2da6c171b4d21db2b4f6c4ddf00152c0f3c7dce416bdfe7b9fcf674a71d99d1fd198cb2775541de2f47c274afa6a3f868f97831");
    printf("length of n: %d\n", BN_num_bits(n));

    BN_MONT_CTX* mont = BN_MONT_CTX_new();
    BN_CTX * ctx = BN_CTX_new();

    //BN_MONT_CTX_set(mont,   mm, ctx);

    BIGNUM *c =BN_new();
    BIGNUM *res =BN_new();

    BIGNUM *m =BN_new();
    BN_hex2bn(&m,"234182782666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666609a1");
    
    printf("length of m: %d\n", BN_num_bits(m));
#else
    BIGNUM *e =BN_new();
    BIGNUM *d =BN_new();
    BIGNUM *n =BN_new();
    BIGNUM *m =BN_new();
    BIGNUM *c =BN_new();

    BN_CTX * ctx = BN_CTX_new();

    BN_hex2bn(&e,parameter_e);
    BN_hex2bn(&d,parameter_d);
    BN_hex2bn(&n,parameter_n);
    BN_hex2bn(&m,parameter_m);

#endif

    BN_mod_exp(c, m, e, n, ctx);
#ifdef DEBUG_rsa_used_for_test_enc
     // 创建一个 BIO 对象，用于标准输出
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    printf("length of e: %d\n", BN_num_bits(e));
    parameter_e_len=BN_num_bits(e) ;
    printf("length of d: %d\n", BN_num_bits(d));
    parameter_d_len=BN_num_bits(d) ;
    printf("length of n: %d\n", BN_num_bits(n));
    parameter_n_len=BN_num_bits(n) ;
    printf("length of m: %d\n", BN_num_bits(m));
    parameter_m_len=BN_num_bits(m) ;

    printf("length of m: %d\n", BN_num_bits(c));
    parameter_c_len=BN_num_bits(c) ;

    // 使用 BN_print 函数将 BIGNUM 打印到 BIO 流中
    printf("bio, e: ");
    if (BN_print(bio, e) <= 0) {
        fprintf(stderr, "Failed to print BIGNUM\n");
    }
    printf("\n");
    printf("bio, d: ");
    if (BN_print(bio, d) <= 0) {
        fprintf(stderr, "Failed to print BIGNUM\n");
    }
    printf("\n");
    printf("bio, n: ");
    if (BN_print(bio, n) <= 0) {
        fprintf(stderr, "Failed to print BIGNUM\n");
    }
    printf("\n");
    printf("bio, m: ");
    if (BN_print(bio, m) <= 0) {
        fprintf(stderr, "Failed to print BIGNUM\n");
    }
    printf("\n");
    printf("bio, c: ");
    if (BN_print(bio, c) <= 0) {
        fprintf(stderr, "Failed to print BIGNUM\n");
    }
    printf("\n");
#endif
    
    u_int64_t ciphertext[32]={0};


    BN2048_2_ulong(c, ciphertext);
    {
        int j=0;
        for(j=0; j<16; ++j){ //暂时用幻数16
            c_1[j]=ciphertext[j];
            c_2[j]=ciphertext[j+16];
        }/* C1,C2 :C=C_2 * R + C_1 ; R=2^1024 */ 
    }
#ifdef DEBUG_rsa_used_for_test_enc
    {
        int i=0;
        for(i=0;i<16;i++){
            printf("HIGH: C_2[%d] = 0x%llx;\n", i+16,c_2[i]);
        }
        for(i=0;i<16;i++){
            printf("LOW : C_1[%d] = 0x%llx;\n", i+16,c_1[i]);
        }

    }
#endif

return 0;


}