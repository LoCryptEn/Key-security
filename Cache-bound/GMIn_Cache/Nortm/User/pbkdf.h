#include <stdint.h>
#include "sm3hash.h"
#include <string.h>
#include <stdlib.h>

int PBKDF2(unsigned char* out, unsigned char* passwd, int passwd_len, unsigned char* salt, int salt_len, int count, int dk_len);