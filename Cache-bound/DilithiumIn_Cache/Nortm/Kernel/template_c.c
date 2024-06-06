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
// get_file_path
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/vmalloc.h>

#include "ioc.h"
#include "SMS4.h"
#include "pbkdf_sha256.h"
#include "rtm.h"
#include "tsx.h"

// Dilithium Sign
#include "sign.h"

MODULE_AUTHOR("<DACAS>");
MODULE_DESCRIPTION("Crypto engine driver");
MODULE_LICENSE("GPL");
#define DEBUG

struct Template_dev{
	struct miscdevice *cdev;		
};

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

/*obtain the path of the type (ko, log or pin.list)
 *the path is returned in the var file
 */
void get_file_path(char *file, char *type){
	char *dir=NULL;
	struct path pwd, root; 
	char buf[100];
	pwd = current->fs->pwd;
	path_get(&pwd);
	root=  current->fs->root;
	path_get(&root);
	dir = d_path(&pwd,buf,100*sizeof(char));
	strcpy(file, dir);
	strcat(file, "/");
	if(strncmp(type,".ko",3)==0)
		strcat(file, module_name);
	strcat(file, type);
}


/*write the log information into LOG_FILE
*return value: 1 for success, 0 for fail
*/
int WriteLogFile(char * loginfo){
	char logPath[100];
	struct timex txc;
	struct rtc_time tm;
	struct file *file_st;
	mm_segment_t fs;
	unsigned char buf[128];
	int len;
	// open log file
	get_file_path(logPath,"nortm.log");
	file_st = filp_open(logPath, LOG_FLAGS, LOG_PERMISSION);
	if(IS_ERR(file_st)){
		printk("Error:Can't open log file\n");
		return 0;
	}
	fs = get_fs(); 
	set_fs(KERNEL_DS);
	// write current time to log file
	/*
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec,&tm);
	len = snprintf(buf, 128,"[UTC time:%d-%d-%d %d:%d:%d]\t", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	kernel_write(file_st, buf, len, &(file_st->f_pos));
	*/

	memset(buf,0x0,128);
	len = snprintf(buf,128,loginfo);
	kernel_write(file_st, buf, len, &(file_st->f_pos));
	memset(buf,0x0,128);
	set_fs(fs);
	filp_close(file_st, NULL);
	return 1;
}


void printhex(unsigned char * output, int len)
{
 	int i;
    for(i = 0; i < len; i++){
		if (i == 32) {
             printk("\n");
        }
        printk("%02x ", output[i]);
     }
     printk("\n");
}


int __init init_template(void){
	int rc;
	init_template__dev();
	rc = misc_register(template_dev.cdev);
	sema_init(&sem,1);
	return 0;

}

void reg_init(void *key);
int init_test(BYTE *out);

/*
*generate the master key from the input key
* PBKDF2 with the salt (specified in code) for 1000 times to generate the 128 bit master key
* the master key is set in each cpu
* 1 for success, 0 for fail
*/
int init_hsm(unsigned char *key){
	
	unsigned char outtemp[16];
	unsigned char salt[8] = {0x1,0x2,0x3,0x3,0x5,0x6,0x7,0x8};
	int count = 1000;

	if(Inited!=0){
	 	printk(KERN_INFO "Error:MASTER_KEY Already Inited\n");
	 	//WriteLogFile("Error:MASTER_KEY Already Inited\n");
	 	return 0;
	}
	pbkdf2_sha256(key, MASTER_KEY_SIZE, salt, 8, count, outtemp, 16);

	on_each_cpu(reg_init,(void*)outtemp,1);

	//cleanup
	memset(key, 0x0, MASTER_KEY_SIZE);
	memset(outtemp, 0x0, 16);
	Inited = 1;
	//WriteLogFile("Success:Init MAKTER_KEY\n");
	return 1;
}

/*Perform the dili's sign function out of TSX
* success: 1, fail :0
*/
int dili_normal_sign(SIGN_Para *signpara_u){
	SIGN_Para *signpara_k = NULL;
	signpara_k = vmalloc(sizeof(SIGN_Para));
    
	if(signpara_k == NULL)
		return 0;
    
    if(copy_from_user((unsigned char *)(&(signpara_k->mlen)),(unsigned char *)(&(signpara_u->mlen)),sizeof(size_t)))
	{
		vfree(signpara_k);
		return 0;
	}

	if(signpara_k->mlen > MAX_MESSAGE_LEN)
	{
		vfree(signpara_k);
		return 0;
	}

	if(copy_from_user((unsigned char *)(signpara_k->m),(unsigned char *)(signpara_u->m),signpara_k->mlen))
	{
		vfree(signpara_k);
		return 0;
	}

	if(copy_from_user((unsigned char *)(signpara_k->sk),(unsigned char *)(signpara_u->sk),CRYPTO_SECRETKEYBYTES))
	{
		vfree(signpara_k);
		return 0;
	}

    if(crypto_sign(signpara_k->sm, &(signpara_k->smlen), signpara_k->m, signpara_k->mlen, signpara_k->sk) != 0)
    {
    	vfree(signpara_k);
		return 0;
    }

    if(copy_to_user((unsigned char *)(&(signpara_u->smlen)), (unsigned int *)(&(signpara_k->smlen)),sizeof(size_t)))
	{
		vfree(signpara_k);
		return 0;
	}

	printk("signpara_k->smlen:%lu\n", signpara_k->smlen);
    
	if(copy_to_user((unsigned char *)(signpara_u->sm),(unsigned char *)(signpara_k->sm), signpara_k->smlen))
	{
		vfree(signpara_k);
		return 0;
	}

	return 1;
}

/*Perform the dili's sign function in TSX
* success: 1, fail :0
*/
int dili_safe_sign(SIGN_Para *signpara_u){
	SIGN_Para *signpara_k = NULL;
	signpara_k = vmalloc(sizeof(SIGN_Para));
    
	if(signpara_k == NULL)
		return 0;
    
    if(copy_from_user((unsigned char *)(&(signpara_k->mlen)),(unsigned char *)(&(signpara_u->mlen)),sizeof(size_t)))
	{
		vfree(signpara_k);
		return 0;
	}

	if(signpara_k->mlen > MAX_MESSAGE_LEN)
	{
		vfree(signpara_k);
		return 0;
	}

	if(copy_from_user((unsigned char *)(signpara_k->m),(unsigned char *)(signpara_u->m),signpara_k->mlen))
	{
		vfree(signpara_k);
		return 0;
	}

	if(copy_from_user((unsigned char *)(signpara_k->sk),(unsigned char *)(signpara_u->sk),CRYPTO_SECRETKEYBYTES))
	{
		vfree(signpara_k);
		return 0;
	}

    if(crypto_safe_sign(signpara_k->sm, &(signpara_k->smlen), signpara_k->m, signpara_k->mlen, signpara_k->sk) != 0)
    {
    	vfree(signpara_k);
		return 0;
    }

    if(copy_to_user((unsigned char *)(&(signpara_u->smlen)), (unsigned char *)(&(signpara_k->smlen)),sizeof(size_t)))
	{
		vfree(signpara_k);
		return 0;
	}

	// printk("signpara_k->smlen:%lu\n", signpara_k->smlen);
    
	if(copy_to_user((unsigned char *)(signpara_u->sm),(unsigned char *)(signpara_k->sm), signpara_k->smlen))
	{
		vfree(signpara_k);
		return 0;
	}

	return 1;
}

static long template_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{	
	switch(cmd){
		case INIT:{
			unsigned char key[MASTER_KEY_SIZE];
			INIT_Para *initarg_u = (INIT_Para *)arg;
			memset(key,0,MASTER_KEY_SIZE);
			if(copy_from_user(key, initarg_u->masterKey, MASTER_KEY_SIZE)){
			    printk("Error:Copy master key from user to kernel\n");
				//WriteLogFile("Error:Copy master key from user to kernel\n");
				goto err;
			}
			if(init_hsm(key) != 1)
				goto err;
	
			break;
		}

		case DILITHIUM_SIGN:{
			SIGN_Para *signpara_u = (SIGN_Para *)arg;
			if(dili_normal_sign(signpara_u)!=1)
				goto err;
			break;
		}

	case DILITHIUM_SAFE_SIGN:{
			SIGN_Para *signpara_u = (SIGN_Para *)arg;
			if(dili_safe_sign(signpara_u)!=1)
				goto err;
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
	printk(KERN_DEBUG "driver %s unloaded\n",module_name );
}
module_init(init_template);
module_exit(cleanup_template);
