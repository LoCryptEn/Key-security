#include <stddef.h>
#include <linux/types.h>
#include <linux/random.h>

#include "randombytes.h"

/* Generate the random in kernel module. */
void randombytes(uint8_t *out, size_t outlen) {
  get_random_bytes(out, outlen);
}

