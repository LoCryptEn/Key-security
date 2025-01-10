#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include <string.h>

extern void dosecsig(uint8_t *inputdata, uint64_t *outputdata);

int main()
{
    // Data Frame
    // | struct of Data        | Notation    |  Length   |
    // |-----------------------|-------------|-----------|
    // |        [0]-[3]        |     r       |     256   |
    // |        [4]-[7]        |    Enc(d)   |     256   |
    // |        [8]-[11]       |    Enc(k1)  |     256   |
    // |        [12]-[15]      |    k2       |     256   |
    // |        [16]-[19]      |    H(m)     |     256   |
    // |        [20]-[21]      |    Enc(a)   |     256   |
    // |        [22]-[23]      |-M^{-1} mod R|     256   |
    // |        [24]-[25]      |   None      |     128   |

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

    uint8_t enc_k1[32] = {
        0x58, 0x36, 0x08, 0xbb, 0xf6, 0x2d, 0x8d, 0x54,
        0xba, 0xf4, 0x7e, 0x74, 0xff, 0xce, 0x4c, 0x88,
        0x70, 0xcf, 0x6f, 0x08, 0x8d, 0xfa, 0xed, 0xb8,
        0x2e, 0xc3, 0xd7, 0x78, 0xd2, 0xfd, 0x86, 0xe9};

    uint8_t k2[32] = {
        0xab, 0x85, 0x08, 0xe6, 0x45, 0x9a, 0x39, 0x94,
        0xab, 0x05, 0xad, 0x9a, 0xa3, 0xd3, 0x7e, 0x42,
        0xd3, 0x93, 0x99, 0x6b, 0xa5, 0xfa, 0x77, 0x91,
        0x1d, 0x7b, 0xf8, 0x18, 0x56, 0x13, 0x2c, 0xc2};

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

    uint8_t r[32] = {
        0xF3, 0x45, 0x2A, 0xD7, 0x41, 0x07, 0x57, 0xD6,
        0x68, 0x36, 0x3A, 0x21, 0xF2, 0xB3, 0xBE, 0x4A,
        0x67, 0x93, 0x37, 0xBE, 0x55, 0x67, 0x05, 0x85,
        0x85, 0x2A, 0xA0, 0xF1, 0x53, 0x8E, 0xEE, 0xE7};

    uint64_t h_m[4] = {
        0xB2BD111F2A661E91,
        0x59B03B01B1B9EDA6,
        0x68F6039B670BE4B8,
        0xF88A4B2EEA67D44F};

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
    free(inputdata);
    free(outputdata);
    
}
