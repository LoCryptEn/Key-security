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

struct Template_dev
{
	struct miscdevice *cdev;
};

extern void dosecsig(unsigned char *inputdata, unsigned char *outputdata);

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

static void __init init_template__dev(void)
{
	template_dev.cdev = &innerDev;
}

char *module_name = "nortm";

struct semaphore sem;

void printhex(unsigned char *output, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
	{
		printk(" %02x", output[i]);
	}
}

int __init init_template(void)
{
	int rc;
	init_template__dev();
	rc = misc_register(template_dev.cdev);
	sema_init(&sem, 1);

	return 0;
}

void reg_init(void *key);

int init_hsm(unsigned char *key)
{

	unsigned char outtemp[16];

	if (Inited != 0)
	{
		printk(KERN_INFO "Error: MASTER_KEY Already Inited\n");
		return 0;
	}
	memcpy(outtemp, key, 16);
	on_each_cpu(reg_init, (void *)outtemp, 1);

	// cleanup
	memset(key, 0x0, AES_KEY_SIZE);
	memset(outtemp, 0x0, 16);
	Inited = 1;
	return 1;
}

static long template_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

    if ((cmd != INIT && cmd != SELF_TEST) && 
        (ServiceAvailable != 1 && Inited != 1)) {
        printk(KERN_ERR "Service not available or not initialized\n");
        return -EINVAL;
    }

	switch (cmd)
	{
		case INIT:
		{
			unsigned char key[AES_KEY_SIZE];
			INIT_Para *initarg_u = (INIT_Para *)arg;
			memset(key, 0, AES_KEY_SIZE);
			if (copy_from_user(key, initarg_u->aesKey, AES_KEY_SIZE)) {
				printk(KERN_ERR "Error: Copy master key from user to kernel\n");
				return -EFAULT;
			}

			if (init_hsm(key) != 1) {
				printk(KERN_ERR "HSM initialization failed\n");
				return -EINVAL;
			}
			break;
		}

		case ECDSA_OP:
		{
			unsigned long flags;
			int i = 0;
			ECDSA_Para *eccmessage = (ECDSA_Para *)arg;
			unsigned char buffer[ECDSA_SIG_SIZE] __attribute__((aligned(16))) = {0};	
			unsigned char inputdata[ECDSA_SIG_SIZE] __attribute__((aligned(16))) = {0};
			unsigned char outputdata[ECDSA_SIG_SIZE] __attribute__((aligned(16))) = {0};

			// Copy input data from user space
			if (copy_from_user(buffer, eccmessage->message, ECDSA_SIG_SIZE))
			{
				printk(KERN_ERR "Failed to copy input data from user space\n");
				return -EFAULT;
			}

			preempt_disable();
			get_cpu();
			local_irq_save(flags);

			// Call dosecsig function
			for (i = 0; i < ECDSA_SIG_SIZE; ++i)
			{
				inputdata[i] = buffer[i];
			}
			
			dosecsig(inputdata, outputdata);

			local_irq_restore(flags);
			put_cpu();
			preempt_enable();
			
			for (i = 0; i < ECDSA_SIG_SIZE; ++i)
			{
				buffer[i] = outputdata[i];
			}

			// Copy result back to user space
			copy_to_user(eccmessage->message, buffer, ECDSA_SIG_SIZE);
			
			break;
		}
	
	}

	return 0;
}

void __exit cleanup_template(void)
{
	misc_deregister(template_dev.cdev);
	printk(KERN_DEBUG "dirver %s unloaded\n", module_name);
}
module_init(init_template);
module_exit(cleanup_template);
