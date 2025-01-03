#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include <string.h>

extern __m256i dosecsig(uint64_t param1_lo, uint64_t param1_hi, uint8_t *data);

int main()
{
    // Real key = [k1 | k2], key in reg: [(k2) | (k1)]
    uint64_t key_lo = 0x12f77eab184a154d;
    uint64_t key_hi = 0xab02184b420cf058;

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

    // k1 = 0x9230a0fbd91bef0fa57b985176c5b8268305e13e361d6de5c96d322b68314ebd
    // d:
    // ee 55 db 49 05 4a 11 6d 6c 77 0a 8c 71 d8 9c 7a 68 51 7c 32 b7 07 71 f4 f7 54 52 d2 34 5d 1d 6d
    // a:
    // de 10 c6 37 80 b2 ed 68 ee 09 f5 c0 08 b4 26 d8 38 18 73 86 85 d3 51 47 5f 0c ec b7 dc 5c 4d e5
    // k2:

    // k2 = 0xE201B19B802AEBB98F308249E17DA4DEB45E6960AC546791ACA3B8264217147F

    uint8_t enc_k1[32] = {0x6e,0xeb,0x52,0xd8,0x2f,0x75,0xaa,0xd2,0xa3,0x06,0x16,0x50,0x5d,0xed,0x8f,0x76,0x06,0x87,0xee,0x39,0x89,0xea,0xc5,0x07,0xfb,0x9b,0xe8,0x2a,0xa6,0xc1,0x23,0xb5};
    uint8_t k2[32] = {0xE2,0x01,0xB1,0x9B,0x80,0x2A,0xEB,0xB9,0x8F,0x30,0x82,0x49,0xE1,0x7D,0xA4,0xDE,0xB4,0x5E,0x69,0x60,0xAC,0x54,0x67,0x91,0xAC,0xA3,0xB8,0x26,0x42,0x17,0x14,0x7F};
    uint8_t enc_a[32] = {0xfd,0x17,0x36,0x30,0x8a,0x6d,0xb1,0xc7,0x31,0xed,0xae,0xae,0x48,0x56,0x5a,0xc4,0x16,0x70,0xb2,0xdc,0x5a,0xa3,0xc4,0x77,0x91,0xa1,0x17,0x32,0xd8,0x1b,0xc9,0x43};

    uint8_t data[32 * 3] = {0};
    memcpy(data, enc_k1, 32);
    memcpy(data + 32, k2, 32);
    memcpy(data + 64, enc_a, 32);

    __m256i result = dosecsig(key_lo, key_hi, data);

}
