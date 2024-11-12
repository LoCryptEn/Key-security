#ifndef _EASY_ECC_H_
#define _EASY_ECC_H_

//#include <stdint.h>
typedef unsigned char  uint8;
/* Curve selection options. */
#define secp128r1 16
#define secp192r1 24
#define secp256r1 32
#define secp384r1 48
#define ECC_CURVE   secp256r1
#ifndef ECC_CURVE
    #define ECC_CURVE secp256r1
#endif

#define MSG_LEN 4096

#if (ECC_CURVE != secp128r1 && ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 && ECC_CURVE != secp384r1)
    #error "Must define ECC_CURVE to one of the available curves"
#endif

#define ECC_BYTES ECC_CURVE

#ifdef __cplusplus
extern "C"
{
#endif

/* ecc_make_key() function.
Create a public/private key pair.
    
Outputs:
    p_publicKey  - Will be filled in with the public key.
    p_privateKey - Will be filled in with the private key.

Returns 1 if the key pair was generated successfully, 0 if an error occurred.
*/
int ecc_make_key(uint8 p_publicKey[ECC_BYTES * 2], uint8 p_privateKey[ECC_BYTES]);

/* ecdh_shared_secret() function.
Compute a shared secret given your secret key and someone else's public key.
Note: It is recommended that you hash the result of ecdh_shared_secret before using it for symmetric encryption or HMAC.

Inputs:
    p_publicKey  - The public key of the remote party.
    p_privateKey - Your private key.

Outputs:
    p_secret - Will be filled in with the shared secret value.

Returns 1 if the shared secret was generated successfully, 0 if an error occurred.
*/
int ecdh_shared_secret(const uint8 p_publicKey[ECC_BYTES+1], const uint8 p_privateKey[ECC_BYTES], uint8 p_secret[ECC_BYTES]);

/* ecdsa_sign() function.
Generate an ECDSA signature for a given hash value.

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
this function along with your private key.

Inputs:
    p_privateKey - Your private key.
    p_hash       - The message hash to sign.

Outputs:
    p_signature  - Will be filled in with the signature value.

Returns 1 if the signature generated successfully, 0 if an error occurred.
*/
int ecdsa_sign(const uint8 p_privateKey[ECC_BYTES], const uint8 p_hash[ECC_BYTES], uint8 p_signature[ECC_BYTES*2]);

int ecdsa_sign_safe(uint8 p_privateKey[ECC_BYTES], const uint8 p_hash[ECC_BYTES], uint8 p_signature[ECC_BYTES*2]);
/* ecdsa_verify() function.
Verify an ECDSA signature.

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).

Inputs:
    p_publicKey - The signer's public key
    p_hash      - The hash of the signed data.
    p_signature - The signature value.

Returns 1 if the signature is valid, 0 if it is invalid.
*/
int ecdsa_verify(const uint8 p_publicKey[ECC_BYTES * 2], const uint8 p_hash[ECC_BYTES], const uint8 p_signature[ECC_BYTES*2]);


int SignMessage( uint8 *p_privateKey, uint8 *p_msg, uint8 *p_signature, int p_len);
int SignMessageSafe( uint8 p_privateKey[ECC_BYTES], uint8 p_msg[MSG_LEN], uint8 p_signature[ECC_BYTES*2], int p_len);
int VerifySign(const uint8 p_publicKey[ECC_BYTES * 2], uint8 p_msg[MSG_LEN], const uint8 p_signature[ECC_BYTES*2],int p_len);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _EASY_ECC_H_ */