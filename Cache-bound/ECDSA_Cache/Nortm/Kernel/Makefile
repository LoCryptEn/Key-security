obj-m += nortm.o 
nortm-objs := template_c.o aes.o pbkdf_sha256.o ecc.o aesni.o reg_init.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
install:
	sudo insmod nortm.ko
	sudo chmod 777 /dev/nortm
uninstall:
	sudo rmmod nortm

