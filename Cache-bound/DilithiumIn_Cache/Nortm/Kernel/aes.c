#include <linux/memory.h>

#include "aes.h"
extern int aes_enc(unsigned char *key, unsigned char  *input, unsigned char *output);
extern int aes_dec(unsigned char *key, unsigned char  *input, unsigned char *output);
extern int aes_enc_master(unsigned char  *input, unsigned char *output);
extern int aes_dec_master(unsigned char  *input, unsigned char *output);

/**************************************************INNER Interface*************************************************/

/*
 * Encryption Rounds
 */
int g_aes_key_bits[] = {
    /* AES_CYPHER_128 */ 128,
    /* AES_CYPHER_192 */ 192,
    /* AES_CYPHER_256 */ 256,
};

int g_aes_rounds[] = {
    /* AES_CYPHER_128 */  10,
    /* AES_CYPHER_192 */  12,
    /* AES_CYPHER_256 */  14,
};

int g_aes_nk[] = {
    /* AES_CYPHER_128 */  4,
    /* AES_CYPHER_192 */  6,
    /* AES_CYPHER_256 */  8,
};

int g_aes_nb[] = {
    /* AES_CYPHER_128 */  4,
    /* AES_CYPHER_192 */  4,
    /* AES_CYPHER_256 */  4,
};


/**************************************************Padding*************************************************/

//PKCS 7 
int PKCS7Pad(uint8_t *Plain, int PlainLength, uint8_t* in, int blocklength)
{
    int pad, inLength;
    inLength = (PlainLength + blocklength)/ blocklength  * blocklength;
    memcpy(in,Plain,PlainLength);
    pad = inLength - PlainLength;
    memset(in+PlainLength, pad, pad);
    return inLength;
}

//SYX : UnPad dont need to check integrity
int PKCS7UnPad(uint8_t *out, int outLength, uint8_t *Plain, int blocklength)
{
    int len;
    if((unsigned int)out[outLength-1] <= blocklength)
    {
        len = outLength - out[outLength-1];
    } else {
        len = outLength;
    }
    memcpy(Plain, out, len);
    return len;
}

void xorArray(unsigned char *to, unsigned char *from, int len){
	int i;
	unsigned int *a = (unsigned int *)to;
	unsigned int *b = (unsigned int *)from;
	int len1 = len >> 2;
	for(i=0; i<len1; ++i)
		a[i] ^= b[i];
}

// void printhex(unsigned char * output, int len)
// {
//     for(int i = 0; i < len; i++){
// 		if (i == 32) {
//             printf("\n");
//         }
//         printf("%02x ", output[i]);
//     }
//     printf("\n");
// }



void AESEncryptECB_Reg(AES_CYPHER_T mode,uint8_t *Plain, int PlainLength, uint8_t *Cipher, uint8_t *Key)
{
    int i;
    int blocklength = g_aes_key_bits[mode] >> 3;
    for(i = 0; i < PlainLength / blocklength; i++)
    {
        if(Key==NULL)
            aes_enc_master(Plain+i*blocklength, Cipher+i*blocklength);
        else
            aes_enc(Key, Plain+i*blocklength, Cipher+i*blocklength);
    }
}

void AESEncryptCBC_Reg(AES_CYPHER_T mode, uint8_t *Plain, int PlainLength, uint8_t *Cipher, int hasIV, unsigned char *IV, uint8_t *Key)
{
	int i;
    int blocklength = g_aes_key_bits[mode] >> 3;
    unsigned char preBlock[blocklength];
    
    memcpy(preBlock, IV, blocklength);

    for(i = 0;i < PlainLength / blocklength;i++)
    {
		xorArray(preBlock, Plain + i * blocklength, blocklength);
        if(Key==NULL)
            aes_enc_master(preBlock, Cipher+i*blocklength);
        else
            aes_enc(Key, preBlock, Cipher+i*blocklength);
		memcpy(preBlock, Cipher+i*blocklength, blocklength);
    }
}

void AESDecryptECB_Reg(AES_CYPHER_T mode, uint8_t *Cipher, int CipherLength, uint8_t *Plain, uint8_t *Key)
{
    int i;
    int blocklength = g_aes_key_bits[mode] >> 3;
    for(i = 0; i < CipherLength / blocklength; i++)
    {
        if(Key==NULL)
            aes_dec_master(Cipher+i*blocklength, Plain+i*blocklength);
        else
           aes_dec(Key, Cipher+i*blocklength, Plain+i*blocklength);   
    }
}


int AESDecryptCBC_Reg(AES_CYPHER_T mode,uint8_t *Cipher, int CipherLength, uint8_t *Plain, int hasIV, uint8_t *IV, uint8_t *Key)
{
	int i = 0, j = 0, loc = 0;
    int blocklength = g_aes_key_bits[mode] >> 3;
	unsigned char preBlock[blocklength*2];
    
    if(hasIV)
        memcpy(preBlock, IV, blocklength);
    else{
        i = 1;
        memcpy(preBlock, Cipher, blocklength);
    }

    for(;i < CipherLength / blocklength; i++, j++)
    {
        memcpy(preBlock + (loc^1)*blocklength, Cipher + i * blocklength, blocklength);
        if(Key==NULL)
            aes_dec_master(Cipher + i*blocklength, Plain + j*blocklength);
        else
            aes_dec(Key, Cipher + i*blocklength, Plain + j*blocklength);
        xorArray(Plain + j*blocklength , preBlock + loc*blocklength, blocklength);
	    loc ^= 1;
    }
    return j*blocklength;
}

/**************************************************OUT Interface*************************************************/

/*
* this two function do not padding, only for PlainLength is Block*n
*/
int AESEncryptWithMode(uint8_t *Plain, int PlainLength, uint8_t *Cipher, int hasIV,unsigned char *IV, int mode, uint8_t *Key)
{
    int blocklength = g_aes_key_bits[AES_CYPHER_128] >> 3;
    if(PlainLength % blocklength) //check Block, consider 192 bits, we need use %
        return 0;
    if(mode == ECB) {
    	AESEncryptECB_Reg(AES_CYPHER_128, Plain, PlainLength, Cipher, Key);
    }    
    else if((mode == CBC) && IV) {
    	AESEncryptCBC_Reg(AES_CYPHER_128, Plain, PlainLength, Cipher, hasIV, IV, Key);
    }
    else
        return 0;
    return PlainLength;
}
int AESDecryptWithMode(uint8_t *Cipher, int CipherLength, uint8_t *Plain, int hasIV, unsigned char *IV, int mode, uint8_t *Key)
{
    int blocklength = g_aes_key_bits[AES_CYPHER_128] >> 3;
    if(!CipherLength || (CipherLength % blocklength))   //check Block
        return 0;
    if(mode == ECB) {
    	AESDecryptECB_Reg(AES_CYPHER_128, Cipher, CipherLength, Plain, Key);
    } else if(mode == CBC) {
    	CipherLength = AESDecryptCBC_Reg(AES_CYPHER_128, Cipher, CipherLength, Plain, hasIV, IV, Key);      //SYX: error and consider first block  as iv ??
    }
    else
        return 0;
    return CipherLength;
}

void aes_cypher_128_test(void)
{
    int i;
    unsigned char key[20]= "0123456789abcdef", iv[20]= "0123456789abcdef";
	unsigned char testp[1024];
	char testm[1024] = "this is a message, we will test the ebc and cbc in different length, plain and cipher point to the same place\n";
	int cipherlen, plainlen;
	for(i=1; i< strlen(testm); i++)
	{
		if(i%16 == 0)
		{
            memcpy(testp, testm, strlen(testm));
			cipherlen = AESEncryptWithMode(testp, i, testp, 0, NULL, ECB, key);
			plainlen = AESDecryptWithMode(testp, cipherlen, testp, 0, NULL, ECB, key);
			testp[plainlen] = 0;
			printk("ECB no pad: %s\n", testp);

            memcpy(testp, testm, strlen(testm));
			cipherlen = AESEncryptWithMode(testp, i, testp, 1, iv, CBC, key);
			plainlen = AESDecryptWithMode(testp, cipherlen, testp, 1, iv, CBC, key);
			testp[plainlen] = 0;
			printk("CBC no pad: %s\n", testp);

            memcpy(testp, testm, strlen(testm));
            cipherlen = AESEncryptWithMode(testp, i, testp, 0, NULL, ECB, NULL);
			plainlen = AESDecryptWithMode(testp, cipherlen, testp, 0, NULL, ECB, NULL);
			testp[plainlen] = 0;
			printk("ECB no pad key in cpu: %s\n", testp);

            memcpy(testp, testm, strlen(testm));
			cipherlen = AESEncryptWithMode(testp, i, testp, 1, iv, CBC, NULL);
			plainlen = AESDecryptWithMode(testp, cipherlen, testp, 1, iv, CBC, NULL);
			testp[plainlen] = 0;
			printk("CBC no pad key in cpu: %s\n", testp);
		}
	}
}
