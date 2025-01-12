#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/objects.h>

const char* N_hex = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
BIGNUM *N = NULL;

extern void dosecsig(uint8_t *inputdata, uint64_t *outputdata);

int main()
{

    BN_hex2bn(&N, N_hex);
    // Data Frame
    // | struct of Data        | Notation    |  Length   |
    // |-----------------------|-------------|-----------|
    // |        [0]-[3]        |    Enc(k1)  |     256   |
    // |        [4]-[7]        |    k2       |     256   |
    // |        [8]-[11]       |    Enc(a)   |     256   |
    // |        [12]-[15]      |    Enc(d)   |     256   |
    // |        [16]-[19]      |    r        |     256   |
    // |        [20]-[21]      |    H(m)     |     256   |

    // k1:
    // 4d bb 0c 7d da 65 c6 f3 a5 9c 33 b8 d4 28 42 be ed af 5b 99 07 bc d1 44 2c 51 c9 f0 e4 6a e1 14
    // d:
    // 09 f3 87 2f b9 81 0c 17 e3 82 f4 5f 87 e9 0a 69 05 65 72 0b 98 f2 8b 8e 84 94 8d e1 a6 ee 1e f5
    // a:
    // 2c 34 f8 3d 55 ab 58 04 74 d1 6e 65 12 7a f7 36 6f 79 0b 72 13 e4 d4 ef 9a 7b fa 86 b9 47 00 56
    // k2:
    // AB8508E6459A3994AB05AD9AA3D37E42D393996BA5FA77911D7BF81856132CC2
    // d=0x09f3872fb9810c17e382f45f87e90a690565720b98f28b8e84948de1a6ee1ef5
    // r=0xF3452AD7410757D668363A21F2B3BE4A679337BE55670585852AA0F1538EEEE7
    // n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    // z=0xB2BD111F2A661E9159B03B01B1B9EDA668F6039B670BE4B8F88A4B2EEA67D44F


    // read from file to uint8_t array
    // uint8_t buffer[32];
    // FILE *fp = fopen("enc_k1.bin", "r");
    // if (fp == NULL)
    // {
    //     printf("Error opening file\n");
    //     return 1;
    // }

    // fread(buffer, 1, 32, fp);
    // for (int i = 0; i < 32; i++)
    // {
    //     printf("%02x ", buffer[i]);
    // }
    // printf("\n");

    uint8_t enc_k1[32] = {
        0x58, 0x36, 0x08, 0xbb, 0xf6, 0x2d, 0x8d, 0x54,
        0xba, 0xf4, 0x7e, 0x74, 0xff, 0xce, 0x4c, 0x88,
        0x70, 0xcf, 0x6f, 0x08, 0x8d, 0xfa, 0xed, 0xb8,
        0x2e, 0xc3, 0xd7, 0x78, 0xd2, 0xfd, 0x86, 0xe9};

    uint8_t k2[32] = {0};

    uint8_t enc_d[32] = {
        0xb0, 0x4d, 0x6c, 0xc1, 0x49, 0x87, 0x73, 0x45,
        0x6a, 0xf6, 0x00, 0x3e, 0x41, 0x06, 0x89, 0xf3,
        0x31, 0x84, 0x4f, 0x9f, 0x07, 0x09, 0xb5, 0x3f,
        0xda, 0x0d, 0xe3, 0x2b, 0x83, 0xd3, 0xa5, 0x2f};

    uint8_t enc_a[32] = {
        0x97, 0xed, 0xc6, 0x78, 0x34, 0xa8, 0x65, 0xc8,
        0xa4, 0xf5, 0xe6, 0x59, 0xe3, 0x89, 0xfe, 0x95,
        0xa4, 0xbe, 0x57, 0xed, 0xc3, 0x1f, 0x35, 0x40,
        0x4d, 0x47, 0x47, 0x71, 0xde, 0xed, 0xa7, 0x5c};

    uint8_t r[32] = {0};
    uint8_t h_m[32] = {0};

    BN_CTX *ctx = BN_CTX_new();
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont, N, ctx);

    char *r_str = "F3452AD7410757D668363A21F2B3BE4A679337BE55670585852AA0F1538EEEE7";
    BIGNUM *r_bn = BN_new();
    BIGNUM *r_mont = BN_new();
    BN_hex2bn(&r_bn, r_str);
    BN_to_montgomery(r_mont, r_bn, mont, ctx);

    BN_bn2binpad(r_mont, r, 32);

    char *h_m_str = "B2BD111F2A661E9159B03B01B1B9EDA668F6039B670BE4B8F88A4B2EEA67D44F";
    BIGNUM *h_m_bn = BN_new();
    BN_hex2bn(&h_m_bn, h_m_str);
    BN_bn2lebinpad(h_m_bn, (uint8_t *)h_m, 32);

    char *k2_str = "AB8508E6459A3994AB05AD9AA3D37E42D393996BA5FA77911D7BF81856132CC2";
    BIGNUM *k2_bn = BN_new();
    BN_hex2bn(&k2_bn, k2_str);

    BN_bn2lebinpad(k2_bn, k2, 32);
    uint8_t *inputdata = malloc(32 * 6);
    memset(inputdata, 0, 32 * 6);
    memcpy(inputdata, enc_k1, 32);
    memcpy(inputdata + 32, k2, 32);
    memcpy(inputdata + 64, enc_a, 32);
    memcpy(inputdata + 96, enc_d, 32);
    memcpy(inputdata + 128, r, 32);
    memcpy(inputdata + 160, h_m, 32);

    uint64_t *outputdata = malloc(8 * sizeof(uint64_t));
    memset(outputdata, 0, 8 * sizeof(uint64_t));
    dosecsig(inputdata, outputdata);

    printf("Output: ");
    for (int i = 7; i >= 0; i--)
    {
        printf("%016lx ", outputdata[i]);
    }


    // output[3-0] to a BN
    BIGNUM *ak_mont = BN_new();
    BIGNUM *ak = BN_new();
    BN_lebin2bn((uint8_t *)outputdata, 32, ak_mont);
    BN_to_montgomery(ak, ak_mont, mont, ctx);
    // print the BN

    char *bn_str = BN_bn2hex(ak);
    printf("\nak: %s\n", bn_str);

    BIGNUM *as_mont = BN_new();
    BIGNUM *as = BN_new();
    BN_lebin2bn((uint8_t *)outputdata + 32, 32, as_mont);
    BN_to_montgomery(as, as_mont, mont, ctx);

    char *as_str = BN_bn2hex(as);
    printf("as: %s\n", as_str);
    


    BN_free(N);
    BN_free(r_bn);
    BN_free(r_mont);
    BN_free(h_m_bn);
    BN_free(k2_bn);
    BN_free(ak_mont);
    BN_free(ak);
    BN_free(as_mont);
    BN_free(as);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);
    
    free(inputdata);
    free(outputdata);
    
}
