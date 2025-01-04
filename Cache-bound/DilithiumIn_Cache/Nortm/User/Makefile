CC ?= /usr/bin/cc
# CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
#   -Wshadow -Wvla -Wpointer-arith -O3 -g -march=native -mtune=native
# CFLAGS += -Wall -Wextra -Wpedantic -Wredundant-decls \
#   -Wshadow -Wvla -Wpointer-arith -O3 -g -march=native -mtune=native
NISTFLAGS += -Wno-unused-result -O3
SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c
HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h randombytes.h
KECCAK_SOURCES = $(SOURCES) fips202.c symmetric-shake.c
KECCAK_HEADERS = $(HEADERS) fips202.h
AES_SOURCES = $(SOURCES) fips202.c aes256ctr.c symmetric-aes.c
AES_HEADERS = $(HEADERS) fips202.h aes256ctr.h

.PHONY: all clean

all: user

user: user.c randombytes.c $(KECCAK_SOURCES) $(KECCAK_HEADERS)
	$(CC) $(CFLAGS)  -g -o $@ $< randombytes.c $(KECCAK_SOURCES)


clean:
	rm -f user

