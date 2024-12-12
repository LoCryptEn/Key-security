//-------------"Defines"-------------

#define RAND_DEBUG

#ifdef RAND_DEBUG
	#define init_random() do{} while(0);
#else 
	void init_random(void);
#endif

/*
 *generate the random through TPM
 *success: the length of generated random, fail : 0
 */
int tpm_gen_random(int lenth, unsigned char *response);