#include <linux/types.h>
#include <linux/kernel.h>  // printk
#include <linux/vmalloc.h> // vmalloc
#include <linux/sched.h>   // 

#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

#include "tsx.h"
#include "rtm.h"
#include "aes.h"

#define MAX_SIGN_TIME 100

void printinfohex(char *info, unsigned char * output, int len);

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t seedbuf[3*SEEDBYTES];
  uint8_t tr[CRHBYTES];
  const uint8_t *rho, *rhoprime, *key;

  polyvecl *mat = NULL;
  mat = vmalloc(K * sizeof(polyvecl));
  if(mat == NULL) {
    return -1;
  }

  polyvecl *s1 = NULL;
  s1 = vmalloc(sizeof(polyvecl));
  if(s1 == NULL) {
    return -1;
  }
	
  polyvecl *s1hat = NULL;
  s1hat = vmalloc(sizeof(polyvecl));
  if(s1hat == NULL) {
    return -1;
  }

  polyveck *s2 = NULL;
  s2 = vmalloc(sizeof(polyveck));
  if(s2 == NULL) {
    return -1;
  }

  polyveck *t0 = NULL;
  t0 = vmalloc(sizeof(polyveck));
  if(t0 == NULL) {
    return -1;
  }

  polyveck *t1 = NULL;
  t1 = vmalloc(sizeof(polyveck));
  if(t1 == NULL) {
    return -1;
  }

  /* Get randomness for rho, rhoprime and key */
  randombytes(seedbuf, SEEDBYTES);
	//memcpy(seedbuf, pk, SEEDBYTES);
  shake256(seedbuf, 3*SEEDBYTES, seedbuf, SEEDBYTES);
  rho = seedbuf;
  rhoprime = seedbuf + SEEDBYTES;
  key = seedbuf + 2*SEEDBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(s1, rhoprime, 0);
  polyveck_uniform_eta(s2, rhoprime, L);

  /* Matrix-vector multiplication */
  memcpy(s1hat, s1, sizeof(polyvecl));
  polyvecl_ntt(s1hat);
  polyvec_matrix_pointwise_montgomery(t1, mat, s1hat);
  polyveck_reduce(t1);
  polyveck_invntt_tomont(t1);

  /* Add error vector s2 */
  polyveck_add(t1, t1, s2);

  /* Extract t1 and write public key */
  polyveck_caddq(t1);
  polyveck_power2round(t1, t0, t1);
  pack_pk(pk, rho, t1);

  /* Compute CRH(rho, t1) and write secret key */
  crh(tr, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, t0, s1, s2);

  vfree(mat);
  vfree(s1);
  vfree(s1hat);
  vfree(s2);
  vfree(t0);
  vfree(t1);

  return 0;
}

int encrypt_sk(uint8_t *sk) {
	unsigned char *a[4];
	int len[4] = {SEEDBYTES, L*POLYETA_PACKEDBYTES, K*POLYETA_PACKEDBYTES, K*POLYT0_PACKEDBYTES};
	unsigned char buff[K*POLYT0_PACKEDBYTES];
	int i;
#ifdef TSX_ENABLE
	unsigned long flags;
	unsigned int status,tsxflag = 0;
	int try;
#endif

	a[0] = sk + SEEDBYTES;
	a[1] = sk + SEEDBYTES+SEEDBYTES+CRHBYTES;
	a[2] = sk + SEEDBYTES+SEEDBYTES+CRHBYTES + L*POLYETA_PACKEDBYTES;
	a[3] = sk + SEEDBYTES+SEEDBYTES+CRHBYTES + L*POLYETA_PACKEDBYTES + K*POLYETA_PACKEDBYTES;

	for(i=0; i<4; i++)
	{
		memcpy(buff, a[i], len[i]);
#ifdef TSX_ENABLE
		tsxflag = 0;
		try = 0;
		while(!tsxflag) {
			get_cpu();
			local_irq_save(flags);
			preempt_disable();
			while(1) {
				if(++try == TSX_MAX_TIMES) {
					local_irq_restore(flags);
					put_cpu();
					preempt_enable();
					if(_xtest()){
						_xend();
					}
					printk("encrypt key %d\n", try);
					return -2;
				} 
				status = _xbegin();
				if (status == _XBEGIN_STARTED)
					break;
			}
#endif
		// printinfohex("genpack before" , buff, len[i]);
		AESEncryptWithMode(buff, len[i], buff, 0, NULL, ECB, NULL);
		// printinfohex("genpack after" , buff, len[i]);

#ifdef TSX_ENABLE
			tsxflag = 1;
			if(_xtest()){
				_xend();
			}
			local_irq_restore(flags);
			put_cpu();
			preempt_enable();
		}
#endif
		memcpy(a[i], buff, len[i]);
	}

	return 0;
}


/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[2*SEEDBYTES + 3*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  // polyvecl mat[K], s1, y, z;
  // polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;
  
  polyvecl *mat = NULL;
  mat = vmalloc(K * sizeof(polyvecl));
  if(mat == NULL) {
    return -1;
  }

  polyvecl *s1 = NULL;
  s1 = vmalloc(sizeof(polyvecl));
  if(s1 == NULL) {
    return -1;
  }

  polyvecl *y = NULL;
  y = vmalloc(sizeof(polyvecl));
  if(y == NULL) {
    return -1;
  }

  polyvecl *z = NULL;
  z = vmalloc(sizeof(polyvecl));
  if(z == NULL) {
    return -1;
  }

  polyveck *s2 = NULL;
  s2 = vmalloc(sizeof(polyveck));
  if(s2 == NULL) {
    return -1;
  }

  polyveck *t0 = NULL;
  t0 = vmalloc(sizeof(polyveck));
  if(t0 == NULL) {
    return -1;
  }

  polyveck *w1 = NULL;
  w1 = vmalloc(sizeof(polyveck));
  if(w1 == NULL) {
    return -1;
  }

  polyveck *w0 = NULL;
  w0 = vmalloc(sizeof(polyveck));
  if(w0 == NULL) {
    return -1;
  }

  polyveck *h = NULL;
  h = vmalloc(sizeof(polyveck));
  if(h == NULL) {
    return -1;
  }

	rho = seedbuf;              //len rho SEEDBYTES
	tr = rho + SEEDBYTES;       //len tr CRHBYTES
	key = tr + CRHBYTES;        //len key SEEDBYTES
	mu = key + SEEDBYTES;       //len mu CRHBYTES
	rhoprime = mu + CRHBYTES;   //len rho' CRHBYTES
  unpack_sk(rho, tr, key, t0, s1, s2, sk);

  // Compute CRH(tr, msg)
  shake256_init(&state);
  shake256_absorb(&state, tr, CRHBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else

  crh(rhoprime, key, SEEDBYTES + CRHBYTES);

#endif
  
  // Expand matrix and transform vectors 
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(s1);
  polyveck_ntt(s2);
  polyveck_ntt(t0);
  
rej:
  // Sample intermediate vector y 
  polyvecl_uniform_gamma1(y, rhoprime, nonce++);
  *z = *y;
  polyvecl_ntt(z);

  // Matrix-vector multiplication 
  polyvec_matrix_pointwise_montgomery(w1, mat, z);
  polyveck_reduce(w1);
  polyveck_invntt_tomont(w1);

  // Decompose w and call the random oracle 
  polyveck_caddq(w1);
  polyveck_decompose(w1, w0, w1);
  polyveck_pack_w1(sig, w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, SEEDBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  // Compute z, reject if it reveals secret 
  polyvecl_pointwise_poly_montgomery(z, &cp, s1);
  polyvecl_invntt_tomont(z);
  polyvecl_add(z, z, y);
  polyvecl_reduce(z);
  if(polyvecl_chknorm(z, GAMMA1 - BETA))
    goto rej;

  // Check that subtracting cs2 does not change high bits of w and low bits
  // do not reveal secret information 
  polyveck_pointwise_poly_montgomery(h, &cp, s2);
  polyveck_invntt_tomont(h);
  polyveck_sub(w0, w0, h);
  polyveck_reduce(w0);
  if(polyveck_chknorm(w0, GAMMA2 - BETA))
    goto rej;

  // Compute hints for w1 
  polyveck_pointwise_poly_montgomery(h, &cp, t0);
  polyveck_invntt_tomont(h);
  polyveck_reduce(h);
  if(polyveck_chknorm(h, GAMMA2))
    goto rej;

  polyveck_add(w0, w0, h);
  polyveck_caddq(w0);
  n = polyveck_make_hint(h, w0, w1);
  if(n > OMEGA)
    goto rej;

  // Write signature 
  pack_sig(sig, sig, z, h);

  printk("crypto_sign_signature-----mlj\n");
  
  *siglen = CRYPTO_BYTES;
  vfree(mat);
  vfree(s1);
  vfree(y);
  vfree(z);
  vfree(t0);
  vfree(s2);
  vfree(w1);
  vfree(w0);
  vfree(h);
  return 0;
}

int crypto_safe_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  unsigned int n, i;
  uint8_t seedbuf[2*SEEDBYTES + 3*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;

  poly cp;
  keccak_state state;
  int err_ret = -1;

#ifdef TSX_ENABLE
  unsigned long flags;
  unsigned int status,tsxflag = 0;
  int try = 0;
#endif
  
  polyvecl *mat = NULL;
  mat = vmalloc(K * sizeof(polyvecl));
  if(mat == NULL) {
    return -1;
  }

  polyvecl *s1 = NULL;
  s1 = vmalloc(sizeof(polyvecl));
  if(s1 == NULL) {
    return -1;
  }

  polyvecl *y = NULL;
  y = vmalloc(sizeof(polyvecl));
  if(y == NULL) {
    return -1;
  }

  polyvecl *z = NULL;
  z = vmalloc(sizeof(polyvecl));
  if(z == NULL) {
    return -1;
  }

  polyveck *s2 = NULL;
  s2 = vmalloc(sizeof(polyveck));
  if(s2 == NULL) {
    return -1;
  }

  polyveck *t0 = NULL;
  t0 = vmalloc(sizeof(polyveck));
  if(t0 == NULL) {
    return -1;
  }

  polyveck *w1 = NULL;
  w1 = vmalloc(sizeof(polyveck));
  if(w1 == NULL) {
    return -1;
  }

  polyveck *w0 = NULL;
  w0 = vmalloc(sizeof(polyveck));
  if(w0 == NULL) {
    return -1;
  }

  polyveck *h = NULL;
  h = vmalloc(sizeof(polyveck));
  if(h == NULL) {
    return -1;
  }

//----------------------------------------------------------------------------
  //data in this range must not change in every round
	rho = seedbuf;    //plain
	tr = rho + SEEDBYTES;   //plain
	key = tr + CRHBYTES;    //cipher
	mu = key + SEEDBYTES;   //plain
	rhoprime = mu + CRHBYTES;   //cipher

	err_ret = safe_unpack_sk(rho, tr, key, t0, s1, s2, sk);
	if(err_ret != 0)
		goto err;
//----------------------------------------------------------------------------
	// printinfohex("rho", (unsigned char *)rho, SEEDBYTES);
	// printinfohex("tr", (unsigned char *)tr, CRHBYTES);
	// printinfohex("key", (unsigned char *)key, SEEDBYTES);
	// printinfohex("t0", (unsigned char *)t0, sizeof(*t0));
	// printinfohex("s1", (unsigned char *)s1, sizeof(*s1));
	// printinfohex("s2", (unsigned char *)s2, sizeof(*s2));

// 	rho = sk + SEEDBYTES+SEEDBYTES+CRHBYTES;
// 	AESDecryptWithMode(rho, L*POLYETA_PACKEDBYTES, rho, 0, NULL, ECB, NULL);
// 	rho = sk + SEEDBYTES+SEEDBYTES+CRHBYTES + L*POLYETA_PACKEDBYTES;
// 	AESDecryptWithMode(rho, K*POLYETA_PACKEDBYTES, rho, 0, NULL, ECB, NULL);
// 	rho = sk + SEEDBYTES+SEEDBYTES+CRHBYTES + L*POLYETA_PACKEDBYTES + K*POLYETA_PACKEDBYTES;
// 	AESDecryptWithMode(rho, K*POLYT0_PACKEDBYTES, rho, 0, NULL, ECB, NULL);



  // Compute mu = CRH(tr, msg)
  shake256_init(&state);
  shake256_absorb(&state, tr, CRHBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  // Compute rhoprime = CRH(K, mu)
#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("crh failed \n");
        err_ret = -2;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif

	AESDecryptWithMode(key, SEEDBYTES, key, 0, NULL, ECB, NULL);
	crh(rhoprime, key, SEEDBYTES + CRHBYTES);
  AESEncryptWithMode(key, SEEDBYTES, key, 0, NULL, ECB, NULL);
	// memset(key, 0, SEEDBYTES);
	AESEncryptWithMode(rhoprime, CRHBYTES, rhoprime, 0, NULL, ECB, NULL);

#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
  }
#endif

#endif


  
  // Expand matrix and transform vectors 
  polyvec_matrix_expand(mat, rho);
  
  err_ret = polyvecl_ntt_tsx(s1);
  if(err_ret != 0)
		goto err;
  err_ret = polyveck_ntt_tsx(s2);
  if(err_ret != 0)
		goto err;
  err_ret = polyveck_ntt_tsx(t0);
  if(err_ret != 0)
		goto err;

rej:
	
	if(nonce == MAX_SIGN_TIME)	//may not dead loop in kernel
	{
		printk("signature too many times failed\n");
		goto err;
	}
		
  // Sample intermediate vector y 

  // if(polyvecl_uniform_gamma1_tsx(y, rhoprime, nonce++) != 0){
  //   err_ret = -8;
  //   goto err;
  // };

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("uniform rhoprime failed\n");
        err_ret = -3;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif

	AESDecryptWithMode(rhoprime, CRHBYTES, rhoprime, 0, NULL, ECB, NULL);
	polyvecl_uniform_gamma1(y, rhoprime, nonce++);
  AESEncryptWithMode(rhoprime, CRHBYTES, rhoprime, 0, NULL, ECB, NULL);
	// memset(rhoprime, 0, CRHBYTES);
	for(i=0; i<L; i++)
	{
		AESEncryptWithMode((uint8_t *)&y->vec[i], sizeof(poly), (uint8_t *)&y->vec[i], 0, NULL, ECB, NULL);
	}

#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif

  *z = *y;
// polyvecl_ntt(z);    //SYX : likely lose

  err_ret = polyvecl_ntt_tsx(z);
  if(err_ret != 0)
		goto err;


	// Matrix-vector multiplication 

	// polyvec_matrix_pointwise_montgomery(w1, mat, z);
	if(polyvec_matrix_pointwise_montgomery_tsx(w1, mat, z) != 0) {
		err_ret = -7;
		goto err;
	};
  

  // Decompose w and call the random oracle 
#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("reduce w failed\n");
        err_ret = -3;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&w1->vec[i], sizeof(poly), (uint8_t *)&w1->vec[i], 0, NULL, ECB, NULL);
	}
  polyveck_reduce(w1); 
  for(i=0; i<K; i++)
	{
		AESEncryptWithMode((uint8_t *)&w1->vec[i], sizeof(poly), (uint8_t *)&w1->vec[i], 0, NULL, ECB, NULL);
	}
#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif
  err_ret = polyveck_invntt_tomont_tsx(w1);
  if(err_ret != 0)
		goto err;

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("decompose w failed\n");
        err_ret = -3;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&w1->vec[i], sizeof(poly), (uint8_t *)&w1->vec[i], 0, NULL, ECB, NULL);
	}
  polyveck_caddq(w1);
  polyveck_decompose(w1, w0, w1);
  for(i=0; i<K; i++)
	{
    AESEncryptWithMode((uint8_t *)&w0->vec[i], sizeof(poly), (uint8_t *)&w0->vec[i], 0, NULL, ECB, NULL);
    AESEncryptWithMode((uint8_t *)&w1->vec[i], sizeof(poly), (uint8_t *)&w1->vec[i], 0, NULL, ECB, NULL);
	}
#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif


#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("challenge failed\n");
        err_ret = -3;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&w1->vec[i], sizeof(poly), (uint8_t *)&w1->vec[i], 0, NULL, ECB, NULL);
	}
  polyveck_pack_w1(sig, w1);
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, SEEDBYTES, &state); //SYX : sig is plain, state is plain too?

  poly_challenge(&cp, sig);

  AESEncryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
  for(i=0; i<K; i++)
	{
		AESEncryptWithMode((uint8_t *)&w1->vec[i], sizeof(poly), (uint8_t *)&w1->vec[i], 0, NULL, ECB, NULL);
	}

#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("cp ntt failed\n");
        err_ret = -3;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  AESDecryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
  poly_ntt(&cp);
  AESEncryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif
  // Compute z, reject if it reveals secret 

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("cp*s1 failed\n");
        err_ret = -5;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  for(i=0; i<L; i++)
	{
		AESDecryptWithMode((uint8_t *)&s1->vec[i], sizeof(poly), (uint8_t *)&s1->vec[i], 0, NULL, ECB, NULL);
	}
  AESDecryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
  polyvecl_pointwise_poly_montgomery(z, &cp, s1); 
  // memset(s1, 0, sizeof(polyvecl)); 
  AESEncryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
  for(i=0; i<L; i++)
	{
		AESEncryptWithMode((uint8_t *)&s1->vec[i], sizeof(poly), (uint8_t *)&s1->vec[i], 0, NULL, ECB, NULL);
    AESEncryptWithMode((uint8_t *)&z->vec[i], sizeof(poly), (uint8_t *)&z->vec[i], 0, NULL, ECB, NULL);
	}
#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif
  
  err_ret = polyvecl_invntt_tomont_tsx(z);  //SYX : need in last tsx
  if(err_ret != 0)
		goto err;

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("reduce z+y failed\n");
        err_ret = -5;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
	for(i=0; i<L; i++)
	{
		AESDecryptWithMode((uint8_t *)&y->vec[i], sizeof(poly), (uint8_t *)&y->vec[i], 0, NULL, ECB, NULL);
    AESDecryptWithMode((uint8_t *)&z->vec[i], sizeof(poly), (uint8_t *)&z->vec[i], 0, NULL, ECB, NULL);
	}
  polyvecl_add(z, z, y);    //SYX: tsx  end
  polyvecl_reduce(z);     //z is plain
	memset(y, 0, sizeof(polyvecl));
#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif

  if(polyvecl_chknorm(z, GAMMA1 - BETA))
    goto rej;

  // Check that subtracting cs2 does not change high bits of w and low bits
  // do not reveal secret information 
#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("cp*s2 failed\n");
        err_ret = -6;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif

  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&s2->vec[i], sizeof(poly), (uint8_t *)&s2->vec[i], 0, NULL, ECB, NULL);
	}
  AESDecryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
  polyveck_pointwise_poly_montgomery(h, &cp, s2);
  AESEncryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
  for(i=0; i<K; i++)
	{
		AESEncryptWithMode((uint8_t *)&s2->vec[i], sizeof(poly), (uint8_t *)&s2->vec[i], 0, NULL, ECB, NULL);
    AESEncryptWithMode((uint8_t *)&h->vec[i], sizeof(poly), (uint8_t *)&h->vec[i], 0, NULL, ECB, NULL);
	}

#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif

  err_ret = polyveck_invntt_tomont_tsx(h);
  if(err_ret != 0)
		goto err;

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("reduce w0 failed\n");
        err_ret = -6;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&h->vec[i], sizeof(poly), (uint8_t *)&h->vec[i], 0, NULL, ECB, NULL);
    AESDecryptWithMode((uint8_t *)&w0->vec[i], sizeof(poly), (uint8_t *)&w0->vec[i], 0, NULL, ECB, NULL);
	}
  polyveck_sub(w0, w0, h);
  polyveck_reduce(w0);
  memset(h, 0, sizeof(polyveck));
  for(i=0; i<K; i++)
	{
    AESEncryptWithMode((uint8_t *)&w0->vec[i], sizeof(poly), (uint8_t *)&w0->vec[i], 0, NULL, ECB, NULL);
	}
#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif


  if(polyveck_chknorm_tsx(w0, GAMMA2 - BETA))
  {
    goto rej;
  }


  // Compute hints for w1 
#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("cp * t0 failed\n");
        err_ret = -6;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif

  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&t0->vec[i], sizeof(poly), (uint8_t *)&t0->vec[i], 0, NULL, ECB, NULL);
	}
  
  AESDecryptWithMode((uint8_t *)&cp, sizeof(poly), (uint8_t *)&cp, 0, NULL, ECB, NULL);
  polyveck_pointwise_poly_montgomery(h, &cp, t0);
  memset(&cp, 0, sizeof(poly));
  for(i=0; i<K; i++)
	{
		AESEncryptWithMode((uint8_t *)&t0->vec[i], sizeof(poly), (uint8_t *)&t0->vec[i], 0, NULL, ECB, NULL);
    AESEncryptWithMode((uint8_t *)&h->vec[i], sizeof(poly), (uint8_t *)&h->vec[i], 0, NULL, ECB, NULL);
	}

#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif

  err_ret = polyveck_invntt_tomont_tsx(h);
  if(err_ret != 0)
		goto err;

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("reduce h failed\n");
        err_ret = -6;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&h->vec[i], sizeof(poly), (uint8_t *)&h->vec[i], 0, NULL, ECB, NULL);
	}
  polyveck_reduce(h);
  for(i=0; i<K; i++)
	{
		AESEncryptWithMode((uint8_t *)&h->vec[i], sizeof(poly), (uint8_t *)&h->vec[i], 0, NULL, ECB, NULL);
	}
#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif

  if(polyveck_chknorm_tsx(h, GAMMA2))
    goto rej;

#ifdef TSX_ENABLE
  tsxflag = 0;
  try = 0;
  while(!tsxflag ){
    get_cpu();
    local_irq_save(flags);
    preempt_disable();
    while(1){
      if(++try == TSX_MAX_TIMES){
        local_irq_restore(flags);
        put_cpu();
        preempt_enable();
        if(_xtest()){
          _xend();
        }
        printk("make hint failed\n");
        err_ret = -6;
        goto err;
      } 
      status = _xbegin();
      if (status == _XBEGIN_STARTED)
        break;
    }
#endif
  for(i=0; i<K; i++)
	{
		AESDecryptWithMode((uint8_t *)&w1->vec[i], sizeof(poly), (uint8_t *)&w1->vec[i], 0, NULL, ECB, NULL);
    AESDecryptWithMode((uint8_t *)&w0->vec[i], sizeof(poly), (uint8_t *)&w0->vec[i], 0, NULL, ECB, NULL);
    AESDecryptWithMode((uint8_t *)&h->vec[i], sizeof(poly), (uint8_t *)&h->vec[i], 0, NULL, ECB, NULL);
	}
  polyveck_add(w0, w0, h);
  polyveck_caddq(w0);
  n = polyveck_make_hint(h, w0, w1);

  memset(w0, 0, sizeof(polyveck));
  memset(w1, 0, sizeof(polyveck));

#ifdef TSX_ENABLE
    tsxflag = 1;
    if(_xtest()){
      _xend();
    }
    local_irq_restore(flags);
    put_cpu();
    preempt_enable();
    // if(!tsxflag){/////wait for a while///////////////////////
    //   set_current_state(TASK_INTERRUPTIBLE);
    //   schedule_timeout(10);
    // }
  }
#endif

  if(n > OMEGA)
    goto rej;

  // Write signature 
  pack_sig(sig, sig, z, h);

  //printk("SS %d %d %d %d %d\n", try[0], try[1], try[2], try[3], try[4]);
  
  *siglen = CRYPTO_BYTES;
  vfree(mat);
  vfree(s1);
  vfree(y);
  vfree(z);
  vfree(t0);
  vfree(s2);
  vfree(w1);
  vfree(w0);
  vfree(h);
  return 0;

err:
  vfree(mat);
  vfree(s1);
  vfree(y);
  vfree(z);
  vfree(t0);
  vfree(s2);
  vfree(w1);
  vfree(w0);
  vfree(h);
  *siglen = CRYPTO_BYTES;
  return err_ret;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];

  crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  
  *smlen += mlen;
  return 0;
}

int crypto_safe_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  

  int err = 0;
  if((err = crypto_safe_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk)) < 0)
  {
      printk("err = %d, mlen:%lu\n", err, mlen);
      printk("slen:%lu\n", *smlen);
      return err;
  }

  *smlen += mlen;

  // printk("smlen:%lu\n", *smlen);
  // printk("sm:\n");
  // printhex(sm, 32);
  
  return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  keccak_state state;

  if(siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(CRH(rho, t1), msg) */
  crh(mu, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, SEEDBYTES, &state);
  for(i = 0; i < SEEDBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}


