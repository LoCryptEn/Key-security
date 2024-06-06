
//-------------"Defines"-------------
#define ERR_COMMUNICATION		-1	///< Return error check for read and write to the TPM.
#define PRINT_RESPONSE_WITHOUT_HEADER		12	///< Prints the response buffer from byte 12.
static const unsigned char tpm2_getrandom[] = {
	0x80, 0x01,			// TPM_ST_NO_SESSIONS
	0x00, 0x00, 0x00, 0x0C,		// commandSize
	0x00, 0x00, 0x01, 0x7B,		// TPM_CC_GetRandom
	0x00, 0x00			// bytesRequested (will be set later)
};
int tpm_gen_random(int lenth, unsigned char *response);