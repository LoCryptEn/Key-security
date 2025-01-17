#include "SMS4.h"
#include <memory.h>

void Sms4ExtendKey(unsigned int *subkey, const unsigned char *key);
void Sms4Encrypt(unsigned char *cipher, const unsigned char *plain, const unsigned int *subkey);
void Sms4Decrypt(unsigned char *plain, const unsigned char *cipher, const unsigned int *subkey);
int PKCS7UnPad(BYTE *out, int outLength, BYTE *Plain);
int PKCS7Pad(BYTE *Plain, int PlainLength, BYTE* in);
unsigned int Sms4F(unsigned int w0, unsigned int w1, unsigned int w2, unsigned int w3, unsigned int rkey);
unsigned int Sms4FinExtendedKey(unsigned int w0, unsigned int w1, unsigned int w2, unsigned int w3, unsigned int ck);


unsigned int sms4_ck[SMS4_ROUND] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 };

unsigned int sms4_fk[SMS4_KEY_LENGTH/4] = {
	0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

void Sms4ExtendKey(unsigned int *subkey, const unsigned char *key)
{
	unsigned int wkey[SMS4_KEY_LENGTH/4];
	int i;
	for (i = 0; i < SMS4_KEY_LENGTH/4; i++)
		wkey[i] = (key[4*i] << 24)|(key[4*i+1] << 16)|(key[4*i+2] << 8)|key[4*i+3];

	for (i = 0; i < SMS4_KEY_LENGTH/4; i++)
		wkey[i] ^= sms4_fk[i];

	i = 0;
	subkey[i++] = Sms4FinExtendedKey(wkey[0], wkey[1], wkey[2], wkey[3], sms4_ck[0]);
	subkey[i++] = Sms4FinExtendedKey(wkey[1], wkey[2], wkey[3], subkey[0], sms4_ck[1]);
	subkey[i++] = Sms4FinExtendedKey(wkey[2], wkey[3], subkey[0], subkey[1], sms4_ck[2]);
	subkey[i++] = Sms4FinExtendedKey(wkey[3], subkey[0], subkey[1], subkey[2], sms4_ck[3]);

	for (; i < SMS4_ROUND; i++)
		subkey[i] = Sms4FinExtendedKey(subkey[i-4], subkey[i-3], subkey[i-2], subkey[i-1], sms4_ck[i]);
}

void Sms4Encrypt(unsigned char *cipher, const unsigned char *plain, const unsigned int *subkey)
{
	unsigned int wplain[SMS4_KEY_LENGTH/4];
	int i;
	for (i = 0; i < SMS4_KEY_LENGTH/4; i++)
		wplain[i] = (plain[4*i] << 24)|(plain[4*i+1] << 16)|(plain[4*i+2] << 8)|plain[4*i+3];

	for (i = 0; i < SMS4_ROUND; )
	{
		wplain[0] = Sms4F(wplain[0], wplain[1], wplain[2], wplain[3], subkey[i++]);
		wplain[1] = Sms4F(wplain[1], wplain[2], wplain[3], wplain[0], subkey[i++]);
		wplain[2] = Sms4F(wplain[2], wplain[3], wplain[0], wplain[1], subkey[i++]);
		wplain[3] = Sms4F(wplain[3], wplain[0], wplain[1], wplain[2], subkey[i++]);
	}

	for (i = 0; i < SMS4_BLOCK_LENGTH; i++)
		cipher[SMS4_BLOCK_LENGTH-1-i] = wplain[i/4] >> (8*(i%4));
}

void Sms4Decrypt(unsigned char *plain, const unsigned char *cipher, const unsigned int *subkey)
{
	unsigned int wcipher[SMS4_KEY_LENGTH/4];
	int i;
	for (i = 0; i < SMS4_KEY_LENGTH/4; i++)
		wcipher[i] = (cipher[4*i] << 24)|(cipher[4*i+1] << 16)|(cipher[4*i+2] << 8)|cipher[4*i+3];

	for (i = SMS4_ROUND-1; i >= 0; )
	{
		wcipher[0] = Sms4F(wcipher[0], wcipher[1], wcipher[2], wcipher[3], subkey[i--]);
		wcipher[1] = Sms4F(wcipher[1], wcipher[2], wcipher[3], wcipher[0], subkey[i--]);
		wcipher[2] = Sms4F(wcipher[2], wcipher[3], wcipher[0], wcipher[1], subkey[i--]);
		wcipher[3] = Sms4F(wcipher[3], wcipher[0], wcipher[1], wcipher[2], subkey[i--]);
	}

	for (i = 0; i < SMS4_BLOCK_LENGTH; i++)
		plain[SMS4_BLOCK_LENGTH-1-i] = wcipher[i/4] >> (8*(i%4));
}

#define ROTL(x,y)	(((x)<<(y&(32-1))) | ((x)>>(32-(y&(32-1)))))
static unsigned char sms4_sbox[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48 };

unsigned int Sms4F(unsigned int w0, unsigned int w1, unsigned int w2, unsigned int w3, unsigned int rkey)
{
	unsigned int t = w1^w2^w3^rkey;

	unsigned char *pchar = (unsigned char *)&t;
	pchar[0] = sms4_sbox[pchar[0]];
	pchar[1] = sms4_sbox[pchar[1]];
	pchar[2] = sms4_sbox[pchar[2]];
	pchar[3] = sms4_sbox[pchar[3]];

	w0 ^= t;
	w0 ^= ROTL(t, 2);
	w0 ^= ROTL(t, 10);
	w0 ^= ROTL(t, 18);
	return w0 ^= ROTL(t, 24);
}

unsigned int Sms4FinExtendedKey(unsigned int w0, unsigned int w1, unsigned int w2, unsigned int w3, unsigned int ck)
{
	unsigned int t = w1^w2^w3^ck;

	unsigned char *pchar = (unsigned char *)&t;
	pchar[0] = sms4_sbox[pchar[0]];
	pchar[1] = sms4_sbox[pchar[1]];
	pchar[2] = sms4_sbox[pchar[2]];
	pchar[3] = sms4_sbox[pchar[3]];

	w0 ^= t;
	w0 ^= ROTL(t, 13);
	return w0 ^= ROTL(t, 23);
}

void xorArray(unsigned char *buf1,unsigned char *buf2,int len){
	int i;
	unsigned int *a = (unsigned int *)buf1;
	unsigned int *b = (unsigned int *)buf2;
	int len1 = len >>2;
	for(i=0;i<len1;++i)
		a[i]^= b[i];

}

void SM4Encrypt(BYTE *Plain, int PlainLength, BYTE *Cipher, BYTE *Key)
{
	unsigned int subkey[SMS4_ROUND];
    int i;
	Sms4ExtendKey(subkey,Key);
    for(i = 0;i < PlainLength / SMS4_BLOCK_LENGTH;i++)
    {
		Sms4Encrypt(Cipher + i * SMS4_BLOCK_LENGTH,Plain + i * SMS4_BLOCK_LENGTH,subkey);
    }
}

void SM4EncryptCBC(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV, unsigned char *IV, BYTE *Key)
{
    unsigned char preBlock[SMS4_BLOCK_LENGTH];
	unsigned int subkey[SMS4_ROUND];
    int i;
    
	Sms4ExtendKey(subkey,Key);
    memcpy(preBlock,IV,SMS4_BLOCK_LENGTH);
    for(i = 0;i < PlainLength / SMS4_BLOCK_LENGTH;i++)
    {
        xorArray(preBlock,Plain+i*SMS4_BLOCK_LENGTH, SMS4_BLOCK_LENGTH);
		Sms4Encrypt(Cipher+i*SMS4_BLOCK_LENGTH,preBlock,subkey);
        memcpy(preBlock,Cipher+i*SMS4_BLOCK_LENGTH, SMS4_BLOCK_LENGTH);
    }
}

void SM4Decrypt(BYTE *Cipher, int CipherLength, BYTE *Plain, BYTE *Key)
{
	unsigned int subkey[SMS4_ROUND];
    int i;
	Sms4ExtendKey(subkey,Key);
    for(i = 0;i < CipherLength / SMS4_BLOCK_LENGTH;i++)
    {
		Sms4Decrypt(Plain + i * SMS4_BLOCK_LENGTH,Cipher + i * SMS4_BLOCK_LENGTH,subkey);
    }
}

int SM4DecryptCBC(BYTE *Cipher, int CipherLength, BYTE *Plain, int hasIV, unsigned char *IV, BYTE *Key)
{
	unsigned int subkey[SMS4_ROUND];
    unsigned char preBlock[SMS4_BLOCK_LENGTH*2];
    int i = 0 , j=0, loc = 0;
    if(hasIV)
        memcpy(preBlock,IV,SMS4_BLOCK_LENGTH);
    else{
        i = 1;
        memcpy(preBlock, Cipher, SMS4_BLOCK_LENGTH);
    }
	Sms4ExtendKey(subkey,Key);
    for(; i < CipherLength / SMS4_BLOCK_LENGTH; i++, j++)
    {
		memcpy(preBlock + (loc^1)*SMS4_BLOCK_LENGTH, Cipher + i * SMS4_BLOCK_LENGTH, SMS4_BLOCK_LENGTH);
		Sms4Decrypt(Plain+j*SMS4_BLOCK_LENGTH,Cipher+i*SMS4_BLOCK_LENGTH,subkey); //first decrypt
        xorArray(Plain+j*SMS4_BLOCK_LENGTH, preBlock + loc*SMS4_BLOCK_LENGTH, SMS4_BLOCK_LENGTH);
        loc ^= 1;
    }
    return j*SMS4_BLOCK_LENGTH;
}


int SM4EncryptWithMode(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV,unsigned char *IV, int mode, BYTE *Key)
{
	if(PlainLength & (SMS4_BLOCK_LENGTH - 1)) //check Block
        return 0;
    if(mode == ECB) {
    	SM4Encrypt(Plain,PlainLength,Cipher,Key);
    } else if(mode == CBC) {
       SM4EncryptCBC(Plain,PlainLength,Cipher,hasIV, IV,Key);
    }
	else	
		return 0;
	return PlainLength;
}

int SM4DecryptWithMode(BYTE *Cipher, int CipherLength, BYTE *Plain, int hasIV, unsigned char *IV, int mode, BYTE *Key)
{
	if(!CipherLength || (CipherLength & (SMS4_BLOCK_LENGTH - 1)))   //check Block
        return 0;
    if(mode == ECB) {
    	SM4Decrypt(Cipher,CipherLength,Plain,Key);
	} else if(mode == CBC) {
       SM4DecryptCBC(Cipher,CipherLength,Plain,hasIV, IV,Key);
    } 
	else
        return 0;
    return CipherLength;
}

//PKCS 7 
int PKCS7Pad(BYTE *Plain, int PlainLength, BYTE* in)
{
    int pad, inLength;
    inLength = (PlainLength + SMS4_BLOCK_LENGTH)/ SMS4_BLOCK_LENGTH  * SMS4_BLOCK_LENGTH;
    memcpy(in,Plain,PlainLength);
    pad = inLength - PlainLength;
    memset(in+PlainLength, pad, pad);
    return inLength;
}

//SYX : UnPad dont need to check integrity
int PKCS7UnPad(BYTE *out, int outLength, BYTE *Plain)
{
    int len;
    if((unsigned int)out[outLength-1] <= SMS4_BLOCK_LENGTH)
    {
        len = outLength - out[outLength-1];
    } else {
        len = outLength;
    }
    memcpy(Plain, out, len);
    return len;
}

/*
* this two function provide padding
* need to check length?
*/
int SM4EncryptWithModePad(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV,unsigned char *IV, int mode, BYTE *Key)
{
    BYTE PlainAndPad[PlainLength+SMS4_BLOCK_LENGTH];
    int len = PKCS7Pad(Plain,PlainLength,PlainAndPad);

    if(mode == ECB) {
    	SM4Encrypt(PlainAndPad,len,Cipher,Key);
    } else if((mode == CBC) && IV) {
    	SM4EncryptCBC(PlainAndPad,len,Cipher,hasIV,IV,Key);
    }
    else
        len = 0;
    memset(PlainAndPad, 0, len);
    return len;
}

int SM4DecryptWithModePad(BYTE *Cipher, int CipherLength, BYTE *Plain, int hasIV, unsigned char *IV, int mode, BYTE *Key)
{
    int len;
    BYTE PlainAndPad[CipherLength];

    if(!CipherLength || (CipherLength & (SMS4_BLOCK_LENGTH - 1)))   //check Block
        return 0;
    if(mode == ECB){
    	SM4Decrypt(Cipher,CipherLength,PlainAndPad,Key);
    }
    else if(mode == CBC){
    	CipherLength = SM4DecryptCBC(Cipher,CipherLength,PlainAndPad,hasIV,IV,Key);
    }
    else
        return 0;
    len = PKCS7UnPad(PlainAndPad,CipherLength,Plain); //SYX: error and unpad to zero ??
    memset(PlainAndPad, 0, CipherLength);
    return len;
}


void sm4_cypher_128_test(void)
{
	unsigned char key[20]= "0123456789abcdef", iv[20]= "0123456789abcdef";
	unsigned char testp[1024];
	char testm[1024] = "this is a message, we will test the ebc and cbc in different length, plain and cipher point to the same place\n";
	int cipherlen, plainlen;
	for(int i=1; i< strlen(testm); i++)
	{
		if(i%16 == 0)
		{
			memcpy(testp, testm, strlen(testm));
			cipherlen = SM4EncryptWithMode(testp, i, testp, 0, NULL, ECB, key);
			plainlen = SM4DecryptWithMode(testp, cipherlen, testp, 0, NULL, ECB, key);
			testp[plainlen] = 0;
			printf("ECB no pad: %s\n", testp);

			memcpy(testp, testm, strlen(testm));
			cipherlen = SM4EncryptWithMode(testp, i, testp, 1, iv, CBC, key);
			plainlen = SM4DecryptWithMode(testp, cipherlen, testp, 1, iv, CBC, key);
			testp[plainlen] = 0;
			printf("CBC no pad: %s\n", testp);
		}
		memcpy(testp, testm, strlen(testm));
		cipherlen = SM4EncryptWithModePad(testp, i, testp, 0, NULL, ECB, key);
		plainlen = SM4DecryptWithModePad(testp, cipherlen, testp, 0, NULL, ECB, key);
		testp[plainlen] = 0;
		printf("ECB with pad: %s\n", testp);

		memcpy(testp, testm, strlen(testm));
		cipherlen = SM4EncryptWithModePad(testp, i, testp, 1, iv, CBC, key);
		plainlen = SM4DecryptWithModePad(testp, cipherlen, testp, 1, iv, CBC, key);
		testp[plainlen] = 0;
		printf("CBC with pad: %s\n", testp);
	}
}