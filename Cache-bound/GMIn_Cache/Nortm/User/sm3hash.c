#include "sm3hash.h"

    unsigned int test[8] = {
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E
    };

void Sm3HashCF(unsigned int *pH, const unsigned char *pMsg);	// 叠代函数
void Sm3MS(unsigned int *pW, const unsigned int *pMsg);

//#ifdef __x86_64__
#define ROTL(x,y)	((((x)<<(y&(32-1))) | ((x)>>(32-(y&(32-1))))) & 0xFFFFFFFF)
//#else
//#define ROTL(x,y)	(((x)<<(y&(32-1))) | ((x)>>(32-(y&(32-1)))))
//#endif

unsigned int Sm3KDF(unsigned char *pKeyOut, unsigned int iLenOfOut /* in bytes */, const unsigned char *pSecret, unsigned int iLenOfSecret /* in bytes */) {
    unsigned int ct = 1;
    unsigned int tmp;
    unsigned int i, iRound = iLenOfOut/SM3_HASH_256;
    SM3_HASH_STATE state;
    unsigned char acHashResult[SM3_HASH_256];
    i=3;
    test[i] = 0x1;
    test[1] = 0x0;
    for (i = 0; i < iRound; i++) {
        Sm3HashInit(&state, pSecret, iLenOfSecret);
        tmp = (ct << 24) | ((ct&0x0000ff00) << 8) | ((ct&0x00ff0000) >> 8) | (ct >> 24);
        Sm3HashPending(&state, (unsigned char *)&tmp, sizeof(tmp));
        if (!Sm3HashFinal(pKeyOut + i*SM3_HASH_256, &state))
            return 0;	// error
        ct++;
    }


    if (0 != iLenOfOut % SM3_HASH_256) {
        Sm3HashInit(&state, pSecret, iLenOfSecret);
        tmp = (ct << 24) | ((ct&0x0000ff00) << 8) | ((ct&0x00ff0000) >> 8) | (ct >> 24);
        Sm3HashPending(&state, (unsigned char *)&tmp, sizeof(tmp));
        if (!Sm3HashFinal(acHashResult, &state))
            return 0;	// error

        for (i = 0; i < iLenOfOut % SM3_HASH_256; i++)
            pKeyOut[iLenOfOut - (iLenOfOut % SM3_HASH_256) + i] = acHashResult[i];
        ct++;
    }

    return iLenOfOut;
}



int Sm3Hash(unsigned char *pOut, const unsigned char *pIn, unsigned int iInLen) {


    unsigned int i;
    unsigned char BB2[128];
    unsigned int low,high;
    unsigned int H[8] = {
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E
    };
	low = 0; high = 0;
    // 每次处理64 bytes = 512 bits
    for (i = 0; i < iInLen/64; i++) {
        Sm3HashCF(H, pIn+i*64);
    }


    for (i = 0; i < sizeof(BB2); i++)
        BB2[i] = 0x00;

    for (i = 0; i < (iInLen & 63); i++) {
        BB2[i] = pIn[(iInLen&0xffffffc0)+i];
    }

    // in bytes ==> in bits

    high = iInLen >> 29;
    high = (high >> 24)
           | ((high&0x00ff0000) >> 8)
           | ((high&0x0000ff00) << 8)
           | (high << 24);
    low = iInLen << 3;
    low = (low >> 24)
          | ((low&0x00ff0000) >> 8)
          | ((low&0x0000ff00) << 8)
          | (low << 24);

    if ((iInLen & 63) < 56) {
        // 1 block
        BB2[i] = 0x80;

        // BB[56 .. 63]
        *(unsigned int *)(BB2+56) = high;
        *(unsigned int *)(BB2+60) = low;

        Sm3HashCF(H, BB2);
    } else {
        // 2 block
        BB2[i] = 0x80;
        Sm3HashCF(H, BB2);

        // BB[120 .. 127]
        *(unsigned int *)(BB2+120) = high;
        *(unsigned int *)(BB2+124) = low;

        Sm3HashCF(H, BB2+64);
    }

    for (i = 0; i < 8; i++) {
        pOut[i*4] = (unsigned char)(H[i] >> 24);
        pOut[i*4+1] = (unsigned char)(H[i] >> 16);
        pOut[i*4+2] = (unsigned char)(H[i] >> 8);
        pOut[i*4+3] = (unsigned char)H[i];
    }

    return 1;
}

void Sm3HashCF(unsigned int *pH, const unsigned char *pMsg) {
    unsigned int A = pH[0],
                     B = pH[1],
                         C = pH[2],
                             D = pH[3],
                                 E = pH[4],
                                     F = pH[5],
                                         G = pH[6],
                                                 H = pH[7];
    unsigned int w[68+64];
    // w[0..67] for W
    // w[68+0 .. 68+63] for W'

    int j;
    unsigned int SS1, SS2, TT1, TT2;
    unsigned int T = 0x79CC4519;
    // unsigned char --> unsigned int
    unsigned int BB[16];
    for (j = 0; j < 16; j++)
        BB[j] = (pMsg[4*j] << 24)
                | (pMsg[4*j+1] << 16)
                | (pMsg[4*j+2] << 8)
                | pMsg[4*j+3];

    Sm3MS(w, BB);	// 消息扩展


    for (j = 0; j < 16; j++) {
        SS1 = ROTL(A, 12) + E + ROTL(T, j);
        SS1 = ROTL(SS1, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = ((A^B^C) + D + SS2) + w[j+68];
        TT2 = ((E^F^G) + H + SS1) + w[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = TT2 ^ ROTL(TT2, 9) ^ ROTL(TT2, 17);
    }

    T = 0x7A879D8A;
    for (; j < 64; j++) {
        SS1 = ROTL(A, 12) + E + ROTL(T, j);
        SS1 = ROTL(SS1, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = (((A&B) | (A&C) | (B&C)) + D + SS2) + w[j+68];
        TT2 = (((E&F) | ((~E)&G)) + H + SS1) + w[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = TT2 ^ ROTL(TT2, 9) ^ ROTL(TT2, 17);
    }

    pH[0] ^= A;
    pH[1] ^= B;
    pH[2] ^= C;
    pH[3] ^= D;
    pH[4] ^= E;
    pH[5] ^= F;
    pH[6] ^= G;
    pH[7] ^= H;
}

void Sm3MS(unsigned int *pW, const unsigned int *pMsg) {
    // pW[i] for Wi
    // pW[68+i] for Wi'
    int j;
    for (j = 0; j < 16; j++)
        pW[j] = pMsg[j];

    for (; j < 68; j++) {
        pW[j] = pW[j-16] ^ pW[j-9] ^ ROTL(pW[j-3], 15);
        pW[j] ^= (ROTL(pW[j], 15) ^ ROTL(pW[j], 23));
        pW[j] ^= ((ROTL(pW[j-13], 7) ^ pW[j-6]));
    }

    for (j = 0; j < 64; j++)
        pW[68+j] = pW[j] ^ pW[j+4];
}


void Sm3HashInit(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen) {

    unsigned int i;
    // 状态寄存器
    pState->H[0] = 0x7380166F;
    pState->H[1] = 0x4914B2B9;
    pState->H[2] = 0x172442D7;
    pState->H[3] = 0xDA8A0600;
    pState->H[4] = 0xA96F30BC;
    pState->H[5] = 0x163138AA;
    pState->H[6] = 0xE38DEE4D;
    pState->H[7] = 0xB0FB0E4E;

    for(i = 0;i < 64;i++)
        pState->BB[i] = 0;

    pState->u64Length = iInLen;


    for (i = 0; i < iInLen/64; i++) {
        Sm3HashCF(pState->H, pIn+i*64);
    }


    for (i = 0; i < (iInLen & 63); i++)
        pState->BB[i] = pIn[(iInLen&0xffffffc0)+i];

    // pState->num = iInLen & 63;
}

void Sm3HashPending(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen) {
    unsigned int iCurPos = (unsigned int)(pState->u64Length % 64);
    unsigned int i;
    unsigned int iMin = (64-iCurPos < iInLen) ? (64-iCurPos) : (iInLen);

    for (i = 0; i < iMin; i++)
        pState->BB[i+iCurPos] = pIn[i];

    pState->u64Length += iInLen;

    if (iInLen >= 64-iCurPos) {
        Sm3HashCF(pState->H, pState->BB);

        iInLen -= (64-iCurPos);
        pIn += (64-iCurPos);
        for (i = 0; i < iInLen/64; i++) {
            Sm3HashCF(pState->H, pIn+i*64);
        }

        for (i = 0; i < (iInLen & 63); i++)
            pState->BB[i] = pIn[(iInLen&0xffffffc0)+i];
    }
    for(i = pState->u64Length % 64;i<64;i++)
        pState->BB[i] = 0;
}

int Sm3HashFinal(unsigned char *pOut, SM3_HASH_STATE *pState) {
    unsigned int i;
    unsigned char BB2[128];
    unsigned int low = 0, high = 0;
    for (i = 0; i < sizeof(BB2); i++)
        BB2[i] = 0x00;

    for (i = 0; i < (pState->u64Length & 63); i++) {
        BB2[i] = pState->BB[i];
    }

    // in bytes ==> in bits

    high = (unsigned int)(pState->u64Length >> 29);
    high = (high >> 24)
           | ((high&0x00ff0000) >> 8)
           | ((high&0x0000ff00) << 8)
           | (high << 24);
    low = (unsigned int)(pState->u64Length << 3);
    low = (low >> 24)
          | ((low&0x00ff0000) >> 8)
          | ((low&0x0000ff00) << 8)
          | (low << 24);

    if ((pState->u64Length & 63) < 56) {
        // 1 block
        BB2[i] = 0x80;

        // BB[56 .. 63]
        *(unsigned int *)(BB2+56) = high;
        *(unsigned int *)(BB2+60) = low;

        Sm3HashCF(pState->H, BB2);
    } else {
        // 2 block
        BB2[i] = 0x80;
        Sm3HashCF(pState->H, BB2);

        // BB[120 .. 127]
        *(unsigned int *)(BB2+120) = high;
        *(unsigned int *)(BB2+124) = low;

        Sm3HashCF(pState->H, BB2+64);
    }

    for (i = 0; i < 8; i++) {
        pOut[i*4] = (unsigned char)(pState->H[i] >> 24);
        pOut[i*4+1] = (unsigned char)(pState->H[i] >> 16);
        pOut[i*4+2] = (unsigned char)(pState->H[i] >> 8);
        pOut[i*4+3] = (unsigned char)(pState->H[i]);
    }

    return 1;
}

// B=64
// ipad = the byte 0x36 repeated B times
// opad = the byte 0x5C repeated B times
// H(K XOR opad, H(K XOR ipad, text))
int Sm3Hmac(unsigned char *pOut, const unsigned char *pMsg, unsigned int iLenOfMsg, const unsigned char *pSecret, int iLenOfSecret) {
    unsigned char keyPadded[HMAC_B_LENGTH];
    SM3_HASH_STATE state;
    int i = 0;
    do {
        keyPadded[i++] = 0;
    } while (i < HMAC_B_LENGTH);

    if (iLenOfSecret > HMAC_B_LENGTH)
        Sm3Hash(keyPadded, pSecret, iLenOfSecret);
    else {
        i = 0;
        while (i < iLenOfSecret) {
            keyPadded[i] = pSecret[i];
            i++;
        }
    }

    for (i = 0; i < HMAC_B_LENGTH; i++)
        keyPadded[i] ^= HMAC_IPAD;


    Sm3HashInit(&state, keyPadded, HMAC_B_LENGTH);
    Sm3HashPending(&state, pMsg, iLenOfMsg);
    Sm3HashFinal(pOut, &state);


    for (i = 0; i < HMAC_B_LENGTH; i++)
        keyPadded[i] ^= (HMAC_IPAD^HMAC_OPAD);

    Sm3HashInit(&state, keyPadded, HMAC_B_LENGTH);
    Sm3HashPending(&state, pOut, SM3_HASH_256);
    Sm3HashFinal(pOut, &state);

    return 1;
}

void Sm3HmacInit(SM3_HMAC_STATE *pState, const unsigned char *pSecret, int iLenOfSecret) {
    int i = 0;
    do {
        pState->padding[i++] = 0;
    } while (i < HMAC_B_LENGTH);

    if (iLenOfSecret > HMAC_B_LENGTH)
        Sm3Hash(pState->padding, pSecret, iLenOfSecret);
    else {
        i = 0;
        while (i < iLenOfSecret) {
            pState->padding[i] = pSecret[i];
            i++;
        }
    }

    for (i = 0; i < HMAC_B_LENGTH; i++)
        pState->padding[i] ^= HMAC_IPAD;

    Sm3HashInit(&pState->hashState, pState->padding, HMAC_B_LENGTH);
}

void Sm3HmacPending(SM3_HMAC_STATE *pState, const unsigned char *pIn, unsigned int iInLen) {
    Sm3HashPending(&pState->hashState, pIn, iInLen);
}

int Sm3HmacFinal(unsigned char *pOut, SM3_HMAC_STATE *pState) {
    int i;
    Sm3HashFinal(pOut, &pState->hashState);


    for (i = 0; i < HMAC_B_LENGTH; i++)
        pState->padding[i] ^= (HMAC_IPAD^HMAC_OPAD);

    Sm3HashInit(&pState->hashState, pState->padding, HMAC_B_LENGTH);
    Sm3HashPending(&pState->hashState, pOut, SM3_HASH_256);
    return Sm3HashFinal(pOut, &pState->hashState);
}



