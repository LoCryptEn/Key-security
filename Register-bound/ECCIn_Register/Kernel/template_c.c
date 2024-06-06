#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <asm/io.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/tty.h>
#include <stdarg.h>
#include <linux/vt_kern.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/ioport.h>
#include <asm/io.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <asm/mtrr.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/rtc.h>

#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/vmalloc.h>

#include "ioc.h"


MODULE_AUTHOR("<>");
MODULE_DESCRIPTION("Crypto engine driver");
MODULE_LICENSE("GPL");

struct Template_dev{
	struct miscdevice *cdev;		
};

unsigned long   do_secsig(unsigned long *result, unsigned long  *r, unsigned long  *d, unsigned long  *z  );
static void __init init_template__dev(void);
static long template_ioctl(struct file *, unsigned int, unsigned long);

static const struct file_operations template_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = template_ioctl,
};

static struct Template_dev template_dev;
static struct miscdevice innerDev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "nortm",
	.fops = &template_fops,
};

static void __init init_template__dev(void){
	template_dev.cdev = &innerDev;
}

char *module_name = "nortm";

struct semaphore sem;
//module_param(debug, bool,S_IRUSR);



void printhex(unsigned char * output, int len){
    int i = 0;
    for(i = 0; i < len; i++)
    {
        printk(" %02x", output[i]);
    }
}

int __init init_template(void){
	int rc;
	init_template__dev();
	rc = misc_register(template_dev.cdev);
	sema_init(&sem,1);
	
	return 0;
}

void reg_init(void *key);

int init_hsm(unsigned char *key){
	
	unsigned char outtemp[16];

	if(Inited!=0){
	 	printk(KERN_INFO "Error:MASTER_KEY Already Inited\n");
	 	return 0;
	}
	memcpy(outtemp, key, 16);
	on_each_cpu(reg_init,(void*)outtemp,1);

	//cleanup
	memset(key, 0x0, SM4_KEY_SIZE);
	memset(outtemp, 0x0, 16);
	Inited = 1;
	return 1;
}

static long template_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	
	if((cmd!=INIT && cmd!=SELF_TEST) &&(ServiceAvailable!=1 && Inited !=1))
	{
		goto err;
	}	
	switch(cmd){
		case INIT:{
			unsigned char key[SM4_KEY_SIZE];
			INIT_Para *initarg_u = (INIT_Para *)arg;
			memset(key,0,SM4_KEY_SIZE);
			if(copy_from_user(key, initarg_u->sm4Key, SM4_KEY_SIZE)){
			    printk("Error:Copy master key from user to kernel\n");
				goto err;
			}
			if(init_hsm(key) != 1)
				goto err;	
			break;
		}
		
		case ECDSA_OP:{			
			////
			ECDSA_Para *ecdsamessage = (ECDSA_Para *) arg;
			unsigned long flags;
			int i;
			unsigned long  A[25] __attribute__((aligned(64))) = { 0 };
			unsigned long  Res[15]  = { 0 };
			copy_from_user(A, ecdsamessage->messages, 200);

			unsigned long RA[4]={0};  
			unsigned long DA[4]={0};  
    		unsigned long ZA[8]={0};  

			RA[0]=A[0];
			RA[1]=A[1];
			RA[2]=A[2];
			RA[3]=A[3];


			DA[0]=A[4];
			DA[1]=A[5];
			DA[2]=A[6];
			DA[3]=A[7];
	

			ZA[0]=A[8];
			ZA[1]=A[9];
			ZA[2]=A[10];
			ZA[3]=A[11];
			ZA[4]=A[12];
    		ZA[5]=A[13];
    		ZA[6]=A[14];
    		ZA[7]=A[15];

			Res[0]=A[16];
			Res[1]=A[17];
			Res[2]=A[18];
			Res[3]=A[19];

			Res[4]=A[20];
			Res[5]=A[21];
			Res[6]=A[22];

			preempt_disable();
			get_cpu();
			local_irq_save(flags);

			do_secsig(Res, RA, DA, ZA); // the value of Res:  Sig
			/*
    	 	for(i=0; i<15; ++i)
			{
			printk ("Res[%d]:        %lx\n",i,Res[i]);
			}	
			*/			
			
			local_irq_restore(flags);
			put_cpu();
			preempt_enable();

			A[0]=Res[0];
			A[1]=Res[1];
			A[2]=Res[2];
			A[3]=Res[3];
			A[4]=Res[4];
			A[5]=Res[5];
			A[6]=Res[6];
			A[7]=Res[7];
			A[8]=Res[8];
			A[9]=Res[9];
			A[10]=Res[10];
			A[11]=Res[11];
			A[12]=Res[12];
			A[13]=Res[13];
			A[14]=Res[14];

			copy_to_user(ecdsamessage->messages, A, 200);
			
			break;
			
		}
		default:
			goto err;	
		
	}
	return 0;
err:
	return -ENOTTY;
}


void __exit cleanup_template(void)
{
	misc_deregister(template_dev.cdev);
	printk(KERN_DEBUG "dirver %s unloaded\n",module_name );
}
module_init(init_template);
module_exit(cleanup_template);
