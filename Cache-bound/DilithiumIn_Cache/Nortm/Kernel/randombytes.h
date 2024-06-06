#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <linux/types.h>

void randombytes(uint8_t *out, size_t outlen);

#endif
