obj-m += nortm.o 
nortm-objs := template_c.o SMS4.o pbkdf_sha256.o sm4_enc.o \
              sm4_dec.o sm4_enc_master.o sm4_dec_master.o reg_init.o \
              aes256ctr.o fips202.o ntt.o packing.o poly.o \
              polyvec.o reduce.o rounding.o symmetric-aes.o symmetric-shake.o \
              sign.o randombytes.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
install:
	insmod nortm.ko
	chmod 777 /dev/nortm
uninstall:
	rmmod nortm

