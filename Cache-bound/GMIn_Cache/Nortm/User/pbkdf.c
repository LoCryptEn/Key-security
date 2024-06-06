#include "pbkdf.h"

#define U_LEN 32
#define H_LEN 32
#define T_LEN 32

void XOR(unsigned char* head, unsigned char* tail, int len){
	int i;
	for(i = 0; i < len; i++)
		head[i] ^= tail[i];
}

// small Endian to big Endian
uint32_t SE2BE(uint32_t value){
	return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 | (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
}

int F(unsigned char* out, unsigned char* passwd, int passwd_len, unsigned char* salt, int salt_len, int count, uint32_t iter){
	int i;
	unsigned char U_head[U_LEN];
	unsigned char U_tail[U_LEN];
	unsigned char* salt_temp;
	uint32_t temp;
	salt_temp = (unsigned char*)malloc(salt_len + 4);
	memcpy(salt_temp, salt, salt_len);
	temp = SE2BE(iter);
	memcpy(salt_temp + salt_len, (unsigned char*)(&temp), 4);
	Sm3Hmac(U_head, salt_temp, salt_len + 4, passwd, passwd_len); // U1
	free(salt_temp);
	for(i = 2; i <= count; i++){
		Sm3Hmac(U_tail, U_head, U_LEN, passwd, passwd_len);
		XOR(U_head, U_tail, U_LEN);
	}
	memcpy(out, U_head, U_LEN);
	return U_LEN;
}

int PBKDF2(unsigned char* out, unsigned char* passwd, int passwd_len, unsigned char* salt, int salt_len, int count, int dk_len){
	unsigned char T[T_LEN];
	uint32_t i;
	int pos = 0;
	uint32_t iter = dk_len / H_LEN + ((dk_len % H_LEN) > 0 ? 1 : 0);

	for(i = 1; i < iter; i++){
		F(T, passwd, passwd_len, salt, salt_len, count, i);
		memcpy(out + pos , T, T_LEN);
		pos += T_LEN;
	}
	F(T, passwd, passwd_len, salt, salt_len, count, i);
	memcpy(out + pos, T, dk_len % H_LEN);
	pos += dk_len % H_LEN;
	return pos;
}