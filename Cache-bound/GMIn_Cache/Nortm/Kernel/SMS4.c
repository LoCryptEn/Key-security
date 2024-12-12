#include "SMS4.h"
#include "eltt2.h"
#include <linux/memory.h>

int SM4UnPad(BYTE *out, int outLength, BYTE *Plain);
int SM4Pad(BYTE *out, int outLength, BYTE *Plain);

// Register related function
int sm4_enc(BYTE *key ,BYTE *input, BYTE *output);
int sm4_dec(BYTE *key ,BYTE *input, BYTE *output);
int sm4_enc_master(BYTE *key, BYTE *input, BYTE *output);
int sm4_dec_master(BYTE *key, BYTE *input, BYTE *ouput);


//PKCS 7 
int SM4Pad(BYTE *Plain, int PlainLength, BYTE* in)
{
    int pad, inLength;
    inLength = (PlainLength + SMS4_BLOCK_LENGTH)/ SMS4_BLOCK_LENGTH  * SMS4_BLOCK_LENGTH;
    memcpy(in,Plain,PlainLength);
    pad = inLength - PlainLength;
    memset(in+PlainLength, pad, pad);
    return inLength;
}

//SYX : UnPad dont need to check integrity
int SM4UnPad(BYTE *out, int outLength, BYTE *Plain)
{
    int len;
    if((unsigned int)out[outLength-1] <= 16)
    {
        len = outLength - out[outLength-1];
    } else {
        len = outLength;
    }
    memcpy(Plain, out, len);
    return len;
}

void xorArray(unsigned char *buf1,unsigned char *buf2,int len){
	int i;
	unsigned int *a = (unsigned int *)buf1;
	unsigned int *b = (unsigned int *)buf2;
	int len1 = len >>2;
	for(i=0;i<len1;++i)
		a[i]^= b[i];

}

void SM4Encrypt_Reg(BYTE *Plain, int PlainLength, BYTE *Cipher, BYTE *Key)
{
    int i;
    for(i = 0;i < PlainLength / SMS4_BLOCK_LENGTH;i++)
    {
        if(Key==NULL)
            sm4_enc_master(NULL, Plain+i*SMS4_BLOCK_LENGTH, Cipher+i*SMS4_BLOCK_LENGTH);
        else
            sm4_enc(Key, Plain+i*SMS4_BLOCK_LENGTH, Cipher+i*SMS4_BLOCK_LENGTH);
    }
}

void SM4EncryptCBC_Reg(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV, unsigned char *IV, BYTE *Key)
{
    unsigned char preBlock[SMS4_BLOCK_LENGTH];
    int i;

    // if(!hasIV)           //in tsx, not a good choice
    //     tpm_gen_random(SMS4_BLOCK_LENGTH, IV);
    
    memcpy(preBlock,IV,SMS4_BLOCK_LENGTH);
    for(i = 0;i < PlainLength / SMS4_BLOCK_LENGTH;i++)
    {
        xorArray(preBlock,Plain+i*SMS4_BLOCK_LENGTH, SMS4_BLOCK_LENGTH);
        if(Key==NULL)
            sm4_enc_master(NULL, preBlock, Cipher+i*SMS4_BLOCK_LENGTH);
        else
            sm4_enc(Key, preBlock, Cipher+i*SMS4_BLOCK_LENGTH);
        memcpy(preBlock,Cipher+i*SMS4_BLOCK_LENGTH, SMS4_BLOCK_LENGTH);
    }
}

void SM4Decrypt_Reg(BYTE *Cipher, int CipherLength, BYTE *Plain, BYTE *Key)
{
    int i;
    for(i = 0;i < CipherLength / SMS4_BLOCK_LENGTH;i++)
    {
        if(Key==NULL){
            sm4_dec_master(NULL, Cipher+i*SMS4_BLOCK_LENGTH, Plain+i*SMS4_BLOCK_LENGTH);
        }
        else
            sm4_dec(Key, Cipher+i*SMS4_BLOCK_LENGTH, Plain+i*SMS4_BLOCK_LENGTH);
    }
}

int SM4DecryptCBC_Reg(BYTE *Cipher, int CipherLength, BYTE *Plain, int hasIV, unsigned char *IV, BYTE *Key)
{
    unsigned char preBlock[SMS4_BLOCK_LENGTH];
    int i = 0 , j=0;
    if(hasIV)
        memcpy(preBlock,IV,SMS4_BLOCK_LENGTH);
    else{
        i = 1;
        memcpy(preBlock, Cipher, SMS4_BLOCK_LENGTH);
    }
    for(; i < CipherLength / SMS4_BLOCK_LENGTH; i++, j++)
    {
        if(Key==NULL)
            sm4_dec_master(NULL, Cipher+i*SMS4_BLOCK_LENGTH, Plain+j*SMS4_BLOCK_LENGTH);
        else
            sm4_dec(Key, Cipher+i*SMS4_BLOCK_LENGTH, Plain+j*SMS4_BLOCK_LENGTH);
        xorArray(Plain+j*SMS4_BLOCK_LENGTH, preBlock, SMS4_BLOCK_LENGTH);
        memcpy(preBlock, Cipher+i*SMS4_BLOCK_LENGTH, SMS4_BLOCK_LENGTH);
    }
    return j*SMS4_BLOCK_LENGTH;
}


/*
* this two function do not padding, only for PlainLength is Block*n
*/
int SM4EncryptWithMode(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV,unsigned char *IV, int mode, BYTE *Key)
{
    if(PlainLength & (SMS4_BLOCK_LENGTH - 1)) //check Block
        return 0;
    if(mode == ECB) {
    	SM4Encrypt_Reg(Plain,PlainLength,Cipher,Key);
    }    
    else if((mode == CBC) && IV) {
    	SM4EncryptCBC_Reg(Plain,PlainLength,Cipher,hasIV,IV,Key);
    }
    else
        return 0;
    return PlainLength;
}
int SM4DecryptWithMode(BYTE *Cipher, int CipherLength, BYTE *Plain, int hasIV, unsigned char *IV, int mode, BYTE *Key)
{
    if(!CipherLength || (CipherLength & (SMS4_BLOCK_LENGTH - 1)))   //check Block
        return 0;
    if(mode == ECB){
    	SM4Decrypt_Reg(Cipher,CipherLength,Plain,Key);
    } else if(mode == CBC) {
    	CipherLength = SM4DecryptCBC_Reg(Cipher,CipherLength,Plain,hasIV,IV,Key);      //SYX: error and consider first block  as iv ??
    }
    else
        return 0;
    return CipherLength;
}


/*
* this two function provide padding
* need to check length?
*/
int SM4EncryptWithModePad(BYTE *Plain, int PlainLength, BYTE *Cipher, int hasIV,unsigned char *IV, int mode, BYTE *Key)
{
    BYTE PlainAndPad[PlainLength+SMS4_BLOCK_LENGTH];
    int len = SM4Pad(Plain,PlainLength,PlainAndPad);

    if(mode == ECB) {
    	SM4Encrypt_Reg(PlainAndPad,len,Cipher,Key);
    } else if((mode == CBC) && IV) {
    	SM4EncryptCBC_Reg(PlainAndPad,len,Cipher,hasIV,IV,Key);
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
    	SM4Decrypt_Reg(Cipher,CipherLength,PlainAndPad,Key);
    }
    else if(mode == CBC){
    	CipherLength = SM4DecryptCBC_Reg(Cipher,CipherLength,PlainAndPad,hasIV,IV,Key);
    }
    else
        return 0;
    len = SM4UnPad(PlainAndPad,CipherLength,Plain); //SYX: error and unpad to zero ??
    memset(PlainAndPad, 0, CipherLength);
    return len;
}
