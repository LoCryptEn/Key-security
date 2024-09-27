obj-m += nortm.o 
nortm-objs := template_c.o reg_init.o VIRSA.o Comcp.o Comcq.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
install:
	insmod nortm.ko
	chmod 777 /dev/nortm
uninstall:
	rmmod nortm

