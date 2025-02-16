all:
	gcc -mavx512f -g -o user aes.S user.c -lpthread -lcrypto -lssl
clean:
	rm -rf user
	rm -rf *.bin

