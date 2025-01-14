#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/objects.h>

#define MAX_PLAIN_LEN	4096

const char* N_hex = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
BIGNUM *N = NULL;
extern void dosecsig(uint8_t *inputdata, uint64_t *outputdata);

int main()
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

    uint8_t *inputdata = malloc(32 * 6);
    memset(inputdata, 0, 32 * 6);
    memcpy(inputdata, enc_k1, 32);
    memcpy(inputdata + 32, k2, 32);
    memcpy(inputdata + 64, enc_a, 32);
    memcpy(inputdata + 96, enc_d, 32);
    memcpy(inputdata + 128, r, 32);
    memcpy(inputdata + 160, h_m, 32);

    uint64_t *outputdata = malloc(8 * sizeof(uint64_t));
    memset(outputdata, 0, 8 * sizeof(uint64_t));
    dosecsig(inputdata, outputdata);

    // printf("Output: ");
    // for (int i = 7; i >= 0; i--)
    // {
    //     printf("%016lx ", outputdata[i]);
    // }

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
        printf("> verify success\n");
    }
    else
    {
        printf("> verify fail\n");
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
