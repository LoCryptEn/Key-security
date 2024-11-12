#include "pbkdf_sha256.h"
#include <stdio.h>
#include <string.h>

void main(){
	unsigned char dest[32] = {0};
	uint8_t key[8] = "12345678";
	uint8_t msg[8] = "12345678";
	sha256(dest, msg, 8);
	for(int i=0;i<32;i++){
		printf(" %02x", dest[i]);
	}
	hmac_sha256(dest, key, 8, msg, 8);
    for(int i=0;i<32;i++){
		printf(" %02x", dest[i]);
	}

}