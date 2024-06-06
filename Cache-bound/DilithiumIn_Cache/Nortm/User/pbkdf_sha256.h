#include <string.h>

#ifndef PBKDF2_SHA256_INCLUDE
#define PBKDF2_SHA256_INCLUDE
 
#define SHA256_BLOCKLEN  64ul //size of message block buffer
#define SHA256_DIGESTLEN 32ul //size of digest in uint8
#define SHA256_DIGESTINT 8ul  //size of digest in uint32
 
// #ifndef PBKDF2_SHA256_STATIC
// #define PBKDF2_SHA256_DEF extern
// #else
// #define PBKDF2_SHA256_DEF static
// #endif
 
//#include "stdint.h"

/* Unsigned.  */
typedef unsigned char		uint8;

typedef unsigned int		uint32;

typedef unsigned long int	uint64;
//#define PBKDF2_SHA256_DEF extern
 
typedef struct sha256_ctx_t
{
	uint64 len;                 // processed message length
	uint32 h[SHA256_DIGESTINT]; // hash state
	uint8 buf[SHA256_BLOCKLEN]; // message block buffer
} SHA256_CTX;
 
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8 *m, uint32 mlen);
// resets state: calls sha256_init
void sha256_final(SHA256_CTX *ctx, uint8 *md);

void sha256(uint8* dest, const uint8 *msg, uint32 mlen);

typedef struct hmac_sha256_ctx_t
{
	uint8 buf[SHA256_BLOCKLEN]; // key block buffer, not needed after init
	uint32 h_inner[SHA256_DIGESTINT];
	uint32 h_outer[SHA256_DIGESTINT];
	SHA256_CTX sha;
} HMAC_SHA256_CTX;
 
void hmac_sha256_init(HMAC_SHA256_CTX *hmac, const uint8 *key, uint32 keylen);
void hmac_sha256_update(HMAC_SHA256_CTX *hmac, const uint8 *m, uint32 mlen);
// resets state to hmac_sha256_init
void hmac_sha256_final(HMAC_SHA256_CTX *hmac, uint8 *md);

void hmac_sha256(uint8* dest, const uint8 *key, uint32 klen, const uint8 *msg, uint32 mlen);

void pbkdf2_sha256(
    const uint8 *key, uint32 keylen, const uint8 *salt, uint32 saltlen, uint32 rounds,
    uint8 *dk, uint32 dklen);
 

#endif // PBKDF2_SHA256_INCLUDE
