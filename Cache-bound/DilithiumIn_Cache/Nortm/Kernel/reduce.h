#ifndef REDUCE_H
#define REDUCE_H

#include <linux/types.h>
#include "params.h"

// mod is 8380417
#define MONT -4186625 // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

#define montgomery_reduce DILITHIUM_NAMESPACE(_montgomery_reduce)
int32_t montgomery_reduce(int64_t a);

#define reduce32 DILITHIUM_NAMESPACE(_reduce32)
int32_t reduce32(int32_t a);

#define caddq DILITHIUM_NAMESPACE(_caddq)
int32_t caddq(int32_t a);

#define freeze DILITHIUM_NAMESPACE(_freeze)
int32_t freeze(int32_t a);

#endif
