CONFIG_MODULE_SIG=n

obj-m += nortm.o 
nortm-objs := template_c.o sign.o  reg_init.o randombytes.o \
			  ntt.o reduce.o rounding.o poly.o polyvec.o packing.o aes.o aesni.o \
              fips202.o pbkdf_sha256.o \
			  symmetric-shake.o symmetric-aes.o aes256ctr.o
			

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
install:
	sudo insmod nortm.ko
	sudo chmod 777 /dev/nortm
uninstall:
	sudo rmmod nortm

