obj-m += nortm.o 
nortm-objs := template_c.o reg_init.o aes.o SecSig.o montmul_n256_xmm.o

ccflags-y += -mavx512f

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod nortm.ko
	chmod 777 /dev/nortm

uninstall:
	rmmod nortm
