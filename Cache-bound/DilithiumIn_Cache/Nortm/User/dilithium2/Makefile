CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -O3 -g -march=native -mtune=native
NISTFLAGS += -Wno-unused-result -O3
SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c
HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h randombytes.h
KECCAK_SOURCES = $(SOURCES) fips202.c symmetric-shake.c
KECCAK_HEADERS = $(HEADERS) fips202.h
AES_SOURCES = $(SOURCES) fips202.c aes256ctr.c symmetric-aes.c
AES_HEADERS = $(HEADERS) fips202.h aes256ctr.h

.PHONY: all shared clean

all: \
	dili_test \
	test_speed3 \
# 	test_speed2 \
# 	test_speed5 \

shared: \
  libpqcrystals_dilithium2_ref.so \
  libpqcrystals_dilithium3_ref.so \
  libpqcrystals_dilithium5_ref.so \
  libpqcrystals_dilithium2aes_ref.so \
  libpqcrystals_dilithium3aes_ref.so \
  libpqcrystals_dilithium5aes_ref.so \
  libpqcrystals_fips202_ref.so \
  libpqcrystals_aes256ctr_ref.so

dili_test: test_dilithium.c randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	-g -o $@ $< randombytes.c $(KECCAK_SOURCES)

libpqcrystals_fips202_ref.so: fips202.c fips202.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

libpqcrystals_aes256ctr_ref.so: aes256ctr.c aes256ctr.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

libpqcrystals_dilithium2_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $(SOURCES) symmetric-shake.c

libpqcrystals_dilithium3_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $(SOURCES) symmetric-shake.c

libpqcrystals_dilithium5_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $(SOURCES) symmetric-shake.c

libpqcrystals_dilithium2aes_ref.so: $(SOURCES) $(HEADERS) symmetric-aes.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	   -o $@ $(SOURCES) symmetric-aes.c

libpqcrystals_dilithium3aes_ref.so: $(SOURCES) $(HEADERS) symmetric-aes.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	   -o $@ $(SOURCES) symmetric-aes.c

libpqcrystals_dilithium5aes_ref.so: $(SOURCES) $(HEADERS) symmetric-aes.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	   -o $@ $(SOURCES) symmetric-aes.c

test_dilithium2: test_dilithium.c randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< randombytes.c $(KECCAK_SOURCES)

test_dilithium3: test_dilithium.c randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< randombytes.c $(KECCAK_SOURCES)

test_dilithium5: test_dilithium.c randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< randombytes.c $(KECCAK_SOURCES)

test_dilithium2aes: test_dilithium.c randombytes.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	  -o $@ $< randombytes.c $(AES_SOURCES)

test_dilithium3aes: test_dilithium.c randombytes.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< randombytes.c $(AES_SOURCES)

test_dilithium5aes: test_dilithium.c randombytes.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	  -o $@ $< randombytes.c $(AES_SOURCES)

test_vectors2: test_vectors.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< $(KECCAK_SOURCES)

test_vectors3: test_vectors.c $(KECCAK_SOURCES) $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< $(KECCAK_SOURCES)

test_vectors5: test_vectors.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< $(KECCAK_SOURCES)

test_vectors2aes: test_vectors.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	  -o $@ $< $(AES_SOURCES)

test_vectors3aes: test_vectors.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< $(AES_SOURCES)

test_vectors5aes: test_vectors.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	  -o $@ $< $(AES_SOURCES)

test_speed2: test_speed.c speed_print.c speed_print.h \
  cpucycles.c cpucycles.h randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< speed_print.c cpucycles.c randombytes.c \
	  $(KECCAK_SOURCES)

test_speed3: test_speed.c speed_print.c speed_print.h \
  cpucycles.c cpucycles.h randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< speed_print.c cpucycles.c randombytes.c \
	  $(KECCAK_SOURCES)

test_speed5: test_speed.c speed_print.c speed_print.h \
  cpucycles.c cpucycles.h randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< speed_print.c cpucycles.c randombytes.c \
	  $(KECCAK_SOURCES)

test_speed2aes: test_speed.c speed_print.c speed_print.h \
  cpucycles.c cpucycles.h randombytes.c $(AES_SOURCES) $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	  -o $@ $< speed_print.c cpucycles.c randombytes.c \
	  $(AES_SOURCES)

test_speed3aes: test_speed.c speed_print.c speed_print.h \
  cpucycles.c cpucycles.h randombytes.c $(AES_SOURCES) $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< speed_print.c cpucycles.c randombytes.c \
	  $(AES_SOURCES)

test_speed5aes: test_speed.c speed_print.c speed_print.h \
  cpucycles.c cpucycles.h randombytes.c $(AES_SOURCES) $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	  -o $@ $< speed_print.c cpucycles.c randombytes.c \
	  $(AES_SOURCES)

test_mul: test_mul.c randombytes.c $(KECCAK_SOURCES) $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -UDBENCH -o $@ $< randombytes.c $(KECCAK_SOURCES)


clean:
# 	rm -f *~ *~ *.gcno *.gcda *.lcov
# 	rm -f libpqcrystals_dilithium2_ref.so
# 	rm -f libpqcrystals_dilithium3_ref.so
# 	rm -f libpqcrystals_dilithium5_ref.so
# 	rm -f libpqcrystals_dilithium2aes_ref.so
# 	rm -f libpqcrystals_dilithium3aes_ref.so
# 	rm -f libpqcrystals_dilithium5aes_ref.so
# 	rm -f libpqcrystals_fips202_ref.so
# 	rm -f libpqcrystals_aes256ctr_ref.so
# 	rm -f test_dilithium2
# 	rm -f test_dilithium3
# 	rm -f test_dilithium5
# 	rm -f test_dilithium2aes
# 	rm -f test_dilithium3aes
# 	rm -f test_dilithium5aes
# 	rm -f test_vectors2
# 	rm -f test_vectors3
# 	rm -f test_vectors5
# 	rm -f test_vectors2aes
# 	rm -f test_vectors3aes
# 	rm -f test_vectors5aes
# 	rm -f test_speed2
# 	rm -f test_speed3
# 	rm -f test_speed5
# 	rm -f test_speed2aes
# 	rm -f test_speed3aes
# 	rm -f test_speed5aes
# 	rm -f test_mul
# 	rm -f PQCgenKAT_sign2
# 	rm -f PQCgenKAT_sign3
# 	rm -f PQCgenKAT_sign5
# 	rm -f PQCgenKAT_sign2aes
# 	rm -f PQCgenKAT_sign3aes
# 	rm -f PQCgenKAT_sign5aes
	rm -f dili_test
	rm -f test_speed3
# 	rm -f test_speed3
# 	rm -f test_speed5
