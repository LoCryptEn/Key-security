CONFIG_MODULE_SIG=n

obj-m += nortm.o 
nortm-objs := template_c.o SMS4.o sm3hash.o Mpi.o EllipticCurve.o  sm4_enc.o sm4_dec.o sm4_enc_master.o sm4_dec_master.o reg_init.o pbkdf.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
install:
	sudo insmod nortm.ko
	sudo chmod 777 /dev/nortm
uninstall:
	sudo rmmod nortm

