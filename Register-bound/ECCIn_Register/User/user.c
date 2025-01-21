#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include <string.h>
#include <unistd.h> 
#include <fcntl.h>
#include "ioc.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/objects.h>

#define MAX_PLAIN_LEN	4096

const char* N_hex = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
BIGNUM *N = NULL;
extern __m128i AES_ENC(__m128i message, __m128i key);

unsigned char *encrypt(unsigned char *key, unsigned char *message, size_t length)
{  
    __m128i key128 = _mm_loadu_si128((const __m128i *)key);

    for (size_t i = 0; i < length; i += 16) {
        __m128i message_block = _mm_loadu_si128((const __m128i *)(message + i));
        message_block = AES_ENC(message_block, key128);
        _mm_storeu_si128((__m128i *)(message + i), message_block);
    }

    return message;
}

int SecSig()
{

    uint8_t enc_k1[32] = {0};
    uint8_t enc_d[32] = {0};
    uint8_t enc_a[32] = {0};
    uint8_t k2[32] = {0};
    uint8_t r[32] = {0};
    uint8_t h_m[32] = {0};

    uint8_t buffer[32];

    char message[MAX_PLAIN_LEN];
    printf("> Please input the message to be signed: ");
    fgets(message, MAX_PLAIN_LEN, stdin);
    message[strlen(message) - 1] = '\0';

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;
    char *algorithm = "sha256";
    char *msg = message;

    BN_hex2bn(&N, N_hex);
    BN_CTX *ctx = BN_CTX_new();
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    EC_GROUP *group;    
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_MONT_CTX_set(mont, N, ctx);
    const BIGNUM *order;
    BIGNUM *X = BN_new();
    order = EC_GROUP_get0_order(group);

    size_t buf_len = 0x21;
    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    BIGNUM *K2 = BN_new();
    BIGNUM *R = BN_new();
    BIGNUM *S = BN_new();
    EC_POINT *k2G;
    EC_POINT *kG;
    k2G = EC_POINT_new(group);
    kG = EC_POINT_new(group);

    // 1: load pub_key
    printf("> Load Pub\n");
    FILE *pub_file = fopen("Pub.bin", "rb");
    if (pub_file == NULL)
    {
        printf("Failed to open Pub.bin\n");
        return 0;
    }
    unsigned char buf_Q[buf_len];
    fread(buf_Q, 1, buf_len, pub_file);
    fclose(pub_file);

    EC_POINT *pub_key = EC_POINT_new(group);
    EC_POINT_oct2point(group, pub_key, buf_Q, buf_len, ctx);
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_private_key(ec_key, NULL);
    EC_KEY_set_public_key(ec_key, pub_key);

    // 2: load k1*G
    printf("> Load k1*G\n");
    FILE *k1G_file = fopen("k1G.bin", "rb");
    if (k1G_file == NULL)
    {
        printf("Failed to open k1G.bin\n");
        return 0;
    }
    unsigned char bufK1G[33];
    fread(bufK1G, 1, 33, k1G_file);
    fclose(k1G_file);

    EC_POINT *k1_G = EC_POINT_new(group);
    EC_POINT_oct2point(group, k1_G, bufK1G, buf_len, ctx);


    // 3: load Enc(k1), Enc(d)

    printf("> Load Enc(k1), Enc(d)\n");
    FILE *fp = fopen("enc_k1.bin", "r");
    if (fp == NULL)
    {
        printf("Error opening file\n");
        return 1;
    }

    fread(buffer, 1, 32, fp);
    fclose(fp);
    memcpy(enc_k1, buffer, 32);

    fp = fopen("enc_d.bin", "r");
    if (fp == NULL)
    {
        printf("Error opening file\n");
        return 1;
    }

    fread(buffer, 1, 32, fp);
    fclose(fp);
    memcpy(enc_d, buffer, 32);

    fp = fopen("enc_a.bin", "r");
    if (fp == NULL)
    {
        printf("Error opening file\n");
        return 1;
    }

    fread(buffer, 1, 32, fp);
    fclose(fp);
    memcpy(enc_a, buffer, 32);


    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname(algorithm);

    if (!md)
    {
        printf("! unknown message digest\n");
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg, strlen(msg));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);


    memcpy(h_m, md_value, 32);

    do
    {
        // Generate k2
        if (!BN_priv_rand_range(K2, order))
        {
            printf("! generate K2 fail.\n");
        }

        EC_POINT_mul(group, k2G, K2, NULL, NULL, NULL); // calculate k2*G

        EC_POINT_add(group, kG, k1_G, k2G, NULL); // calculate k1*G+k2*G=k*G

        EC_POINT_get_affine_coordinates(group, kG, X, NULL, NULL);

        BN_nnmod(R, X, order, ctx); // get r

    } while (BN_is_zero(R));


    // print the r
    char *r_str = BN_bn2hex(R);
    printf("> r: %s\n", r_str);


    BIGNUM *r_mont = BN_new();
    BN_to_montgomery(r_mont, R, mont, ctx);
    BN_bn2binpad(r_mont, r, 32);

    BN_bn2lebinpad(K2, k2, 32);

    // | struct of Data        | Notation    |  Length   |
    // |-----------------------|-------------|-----------|
    // |        [0]-[3]        |    Enc(k1)  |     256   |
    // |        [4]-[7]        |    k2       |     256   |
    // |        [8]-[11]       |    Enc(a)   |     256   |
    // |        [12]-[15]      |    Enc(d)   |     256   |
    // |        [16]-[19]      |    r        |     256   |
    // |        [20]-[21]      |    H(m)     |     256   |

    unsigned char *inputdata = malloc(32 * 6);
    memset(inputdata, 0, 32 * 6);
    memcpy(inputdata, enc_k1, 32);
    memcpy(inputdata + 32, k2, 32);
    memcpy(inputdata + 64, enc_a, 32);
    memcpy(inputdata + 96, enc_d, 32);
    memcpy(inputdata + 128, r, 32);
    memcpy(inputdata + 160, h_m, 32);


    ECDSA_Para eccmessage;
    memcpy(eccmessage.message, inputdata, 32 * 6);

    int fd = open("/dev/nortm", O_RDWR, 0);
    if (fd < 0)
    {
        printf("Error while access Kernel Module\n");
        return 0;
    }
    if (ioctl(fd, ECDSA_OP, &eccmessage) == -1)
    {
        printf("Error while signing\n");
        return 0;
    }
    close(fd);
    unsigned char *outputdata = malloc(64 * sizeof(uint8_t));
    memset(outputdata, 0, 64 * sizeof(uint8_t));
    memcpy(outputdata, eccmessage.message, 32 * 2);
    
    // output[3-0] to a BN
    BIGNUM *ak_mont = BN_new();
    BIGNUM *ak = BN_new();
    BN_lebin2bn((uint8_t *)outputdata, 32, ak_mont);
    BN_to_montgomery(ak, ak_mont, mont, ctx);

    BIGNUM *as_mont = BN_new();
    BIGNUM *as = BN_new();
    BN_lebin2bn((uint8_t *)outputdata + 32, 32, as_mont);
    BN_to_montgomery(as, as_mont, mont, ctx);

    
    BIGNUM *ak_inv = BN_new();
    BN_mod_inverse(ak_inv, ak, order, ctx);

    BN_mod_mul(S, ak_inv, as, order, ctx);

    char *s_str = BN_bn2hex(S);
    printf("> s: %s\n", s_str);

    ECDSA_SIG_set0(ecdsa_sig, R, S);


    if (ECDSA_do_verify(md_value, md_len, ecdsa_sig, ec_key))
    {
        printf("> OpenSSL verify success\n");
    }
    else
    {
        printf("> OpenSSL verify fail\n");
    }


    BN_free(N);
    BN_free(r_mont);
    BN_free(ak_mont);
    BN_free(ak);
    BN_free(as_mont);
    BN_free(as);
    BN_free(X);
    BN_free(K2);
    BN_free(R);
    BN_free(S);
    EC_POINT_free(k2G);
    EC_POINT_free(kG);
    EC_POINT_free(pub_key);
    EC_POINT_free(k1_G);
    EC_GROUP_free(group);
    EC_KEY_free(ec_key);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);
    EVP_MD_CTX_free(mdctx);
    
    free(inputdata);
    free(outputdata);
    
}

int InitModule()
{
    // --------------------------------------------------------//
    // Generate the AES/SM4 128-bits key

    INIT_Para para;
    unsigned char key[AES_KEY_SIZE], verify[AES_KEY_SIZE];

    if (!RAND_bytes(key, AES_KEY_SIZE))
    {
        printf("Failed to generate random key using OpenSSL\n");
        return 1;
    }
    // print the key
    printf("> AES/SM4 128-bits KEY: ");
    for (int i = 0; i < AES_KEY_SIZE; i++)
    {
        printf("%02x", key[i]);
    }

    memcpy(para.aesKey, key, AES_KEY_SIZE);
    printf("> Generate AES/SM4 128-bits KEY\n");

    // --------------------------------------------------------//
    // Generate k1, k1*G, Enc(k1), Enc(d), Enc(a)
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k1 = BN_new();
    BIGNUM *d = BN_new(); // secret key
    BIGNUM *a = BN_new();
    EC_GROUP *group;
    size_t buf_len = 0x21;
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if (!BN_rand(k1, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        fprintf(stderr, "! Error generating random k1\n");
        return 1;
    }
    printf("> Generate k1\n");

    if (!BN_rand(d, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        fprintf(stderr, "! Error generating random d\n");
        return 1;
    }

    printf("> Generate secret key d\n");
    EC_POINT *Q = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Q, d, NULL, NULL, ctx))
    {
        fprintf(stderr, "! Error calculating d * G\n");
        return 1;
    }
    unsigned char bufQ[33];
    if (!EC_POINT_point2oct(group, Q, POINT_CONVERSION_COMPRESSED, bufQ, buf_len, ctx))
    {
        fprintf(stderr, "! Error converting d * G to octets\n");
        return 1;
    }
    // write d*G to file
    FILE *dG_file = fopen("Pub.bin", "wb");
    if (dG_file == NULL)
    {
        printf("Failed to open Pub.bin\n");
        return 0;
    }
    fwrite(bufQ, 1, buf_len, dG_file);
    fclose(dG_file);

    EC_POINT *k1_G = EC_POINT_new(group);
    if (!EC_POINT_mul(group, k1_G, k1, NULL, NULL, ctx))
    {
        fprintf(stderr, "! Error calculating k1 * G\n");
        return 1;
    }

    unsigned char bufk1G[33];
    if (!EC_POINT_point2oct(group, k1_G, POINT_CONVERSION_COMPRESSED, bufk1G, buf_len, ctx))
    {
        fprintf(stderr, "! Error converting k1 * G to octets\n");
        return 1;
    }
    // write k1*G to file
    FILE *k1G_file = fopen("k1G.bin", "wb");
    if (k1G_file == NULL)
    {
        printf("Failed to open k1G.bin\n");
        return 0;
    }
    fwrite(bufk1G, 1, buf_len, k1G_file);
    fclose(k1G_file);

    // AES ENC k1
    unsigned char k1_bytes[32];
    BN_bn2bin(k1, k1_bytes);
    // print the k1
    char *k1_str = BN_bn2hex(k1);
    printf("> k1: %s\n", k1_str);

    printf("> Generate Enc(k1) \n");
    unsigned char *enc_k1 = encrypt(key, k1_bytes, 32);

    // write Enc(k1) to file
    FILE *enc_k1_file = fopen("enc_k1.bin", "wb");
    if (enc_k1_file == NULL)
    {
        printf("Failed to open enc_k1.bin\n");
        return 0;
    }
    fwrite(enc_k1, 1, 32, enc_k1_file);
    fclose(enc_k1_file);

    // AES ENC d
    unsigned char d_bytes[32];
    BN_bn2bin(d, d_bytes);

    // print d
    char *d_str = BN_bn2hex(d);
    printf("> d: %s\n", d_str);
    
    printf("> Generate Enc(d) \n");
    unsigned char *enc_d = encrypt(key, d_bytes, 32);

    // write Enc(d) to file
    FILE *enc_d_file = fopen("enc_d.bin", "wb");
    if (enc_d_file == NULL)
    {
        printf("Failed to open enc_d.bin\n");
        return 0;
    }
    fwrite(enc_d, 1, 32, enc_d_file);
    fclose(enc_d_file);

    if (!BN_rand(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        fprintf(stderr, "! Error generating random a\n");
        return 1;
    }
    // AES ENC a
    unsigned char a_bytes[32];
    BN_bn2bin(a, a_bytes);

    // print a
    char *a_str = BN_bn2hex(a);
    printf("> a: %s\n", a_str);

    unsigned char *enc_a = encrypt(key, a_bytes, 32);

    FILE *enc_a_file = fopen("enc_a.bin", "wb");
    if (enc_a_file == NULL)
    {
        printf("Failed to open enc_a.bin\n");
        return 0;
    }
    fwrite(enc_a, 1, 32, enc_a_file);
    fclose(enc_a_file);


    BN_CTX_free(ctx);
    BN_free(k1);
    BN_free(d);
    BN_free(a);
    EC_POINT_free(k1_G);
    EC_GROUP_free(group);

    int fd;
    fd = open("/dev/nortm", O_RDWR, 0);
    if (fd < 0)
    {
        printf("Error while access Kernel Module\n");
        return 0;
    }
    if (ioctl(fd, INIT, &para) == -1)
    {
        printf("Error while init MASTER KEY\n");
        return 0;
    }
    memset(key, 0x0, AES_KEY_SIZE);
    memset(verify, 0x0, AES_KEY_SIZE);
    memset(&para, 0, sizeof(para));
    printf("> Init AES/SM4 128-bits KEY succeed\n");

    close(fd);

    return 1;
}
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: %s [1|2]\n", argv[0]);
        printf("  1 => Initialize module (set up AES key)\n");
        printf("  2 => Create a secure ECDSA signature\n");
        return 1;
    }

    int type = atoi(argv[1]);
    if (type == 1)
    {
        printf("* Stage 1: Module Initialization\n");
        printf("--------------------------------------------------------------\n");
        InitModule();
        printf("--------------------------------------------------------------\n");
    }
    else if (type == 2)
    {
        printf("* Stage 2: Secure ECDSA Signing\n");
        printf("--------------------------------------------------------------\n");
        SecSig();
        printf("--------------------------------------------------------------\n");
    }
    else
    {
        printf("Invalid option. Please choose 1 or 2.\n");
        return 1;
    }

    return 0;
}
