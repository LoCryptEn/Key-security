#include "ecc.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    uint8_t public_key[ECC_BYTES * 2];
    uint8_t private_key[ECC_BYTES];
    uint8_t hash[ECC_BYTES] = {0x2};
    uint8_t signature[ECC_BYTES * 2];
    int ret = 0;
    uint32_t i = 0;

    ret = ecc_make_key(public_key, private_key);
    if (ret == 0) {
        printf("ecc_make_key failure\n");
    }

    printf("##############public key###############\n");
    for (i = 0;i < ECC_BYTES * 2;i++) {
        if (i == ECC_BYTES) {
            printf("\n");
        }
        printf("%02x ", public_key[i]);
    }

    printf("\n\n");
    printf("##############private key###############\n");
    for (i = 0;i < ECC_BYTES;i++) {
        printf("%02x ", private_key[i]);
    }
    printf("\n\n");

    ret = ecdsa_sign(private_key, hash, signature);
    if (ret == 0) {
        printf("ecdsa_sign failure\n");
    }

//    hash[0] = 0x3;
    ret = ecdsa_verify(public_key, hash, signature);
    if (ret == 1) {
        printf("verify passed\n");
    } else {
        printf("verify failed\n");
    }

    return 0;
}