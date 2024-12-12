CFLAGS += -Wall -Wextra -Wpedantic -Wredundant-decls \
  -Wshadow -Wvla -O3 -g -march=native -mtune=native

all:
	gcc $(CFLAGS) -o user user.c sm3hash.c SMS4.c pbkdf.c EllipticCurve.c Mpi.c
clean:
	rm -rf user *.o
