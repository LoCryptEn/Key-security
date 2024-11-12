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

#include "ecc.h"
#include "rtm.h"
#include "ioc.h"
//#include "eltt2.h"
#include "pbkdf_sha256.h"
#include "tsx.h"

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
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec,&tm);
	len = snprintf(buf, 128,"[UTC time:%d-%d-%d %d:%d:%d]\t", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	kernel_write(file_st, buf, len, &(file_st->f_pos));

	memset(buf,0x0,128);
	len = snprintf(buf,128,loginfo);
	kernel_write(file_st, buf, len, &(file_st->f_pos));
	memset(buf,0x0,128);
	set_fs(fs);
	filp_close(file_st, NULL);
	return 1;
}


// void printhex(unsigned char * output, int len)
// {
// 	int i;
//     for(i = 0; i < len; i++){
// 		if (i == 32) {
//             printk("\n");
//         }
//         printk("%02x ", output[i]);
//     }
//     printk("\n");
// }

/*
 *generate the random through TPM
 *success: the length of generated random, fail : 0
 */
int tpm_gen_random(int length, unsigned char *return_random){
	/*{
		unsigned char pRandomUser[32] = {0x39,0x45,0x20,0x8f,0x7b,0x21,0x44,0xb1,0x3f,0x36,0xe3,0x8a,0xc6,0xd3,0x9f,0x95,0x88,0x93,0x93,0x69,0x28,0x60,0xb5,0x1a,0x42,0xfb,0x81,0xef,0x4d,0xf7,0xc5,0xb8};
		SM4EncryptWithMode(pRandomUser,32,pRandomUser,32,NULL,ECB,NULL);
		memcpy(return_random,pRandomUser,32);
		//get_random_bytes(return_random, length);
		return length;
	}*///For correctness test
#ifdef DEBUG
	{
		get_random_bytes(return_random, length);
		return length;
	}
#else
	{
		struct file *dev_tpm;
		mm_segment_t fs;
		loff_t pos = 0;
		int transmit_size = 0;	// Amount of bytes sent to / received from the TPM.
		unsigned char send_buf[sizeof(tpm2_getrandom)];
		unsigned char response[PRINT_RESPONSE_WITHOUT_HEADER+32];
		int send_buf_lenth = 0;
		memset(response, 0, sizeof(tpm2_getrandom));
		memset(send_buf, 0, PRINT_RESPONSE_WITHOUT_HEADER+32);

		send_buf_lenth = sizeof(tpm2_getrandom);
		memcpy(send_buf, tpm2_getrandom, sizeof(tpm2_getrandom));
		send_buf[sizeof(tpm2_getrandom) - 1] = length;

		if(down_interruptible(&sem) ==-EINTR)
			return 0;
		// ---------- Open TPM device ----------
		dev_tpm = filp_open("/dev/tpm0", O_RDWR, 0644);
		if (IS_ERR(dev_tpm))
		{
#ifdef DEBUG
				printk("Error opening the device.\n");
#endif
			up(&sem);
			return 0;
		}
		if(length > 32)
		{
#ifdef DEBUG
				printk("The max length of random  string obtained from TPM is 32.\n");
#endif
			up(&sem);
			return 0;
		}
		// Send request data to TPM.
		fs = get_fs();
		set_fs(KERNEL_DS);
		transmit_size = kernel_write(dev_tpm, send_buf, send_buf_lenth, &pos);
		if (transmit_size == ERR_COMMUNICATION || send_buf_lenth != transmit_size)
		{
			//ret_val = errno;
#ifdef DEBUG
				printk("Error sending request to TPM.\n");
#endif
			up(&sem);
			return 0;
		}

		// Read the TPM response header.
		pos = 0;
		transmit_size = kernel_read(dev_tpm, response, PRINT_RESPONSE_WITHOUT_HEADER+32,&pos);
		if (transmit_size == ERR_COMMUNICATION)
		{
			//ret_val = errno;
#ifdef DEBUG
				printk("Error reading response from TPM.\n");
#endif
			up(&sem);
			return 0;
		}
		
		memcpy(return_random, response + PRINT_RESPONSE_WITHOUT_HEADER, length);

		// ---------- Close TPM device ----------
		
		filp_close(dev_tpm, NULL);
		set_fs(fs);
		up(&sem);
		return (transmit_size-PRINT_RESPONSE_WITHOUT_HEADER);
	}
#endif
}



int __init init_template(void){
	int rc;
	init_template__dev();
	rc = misc_register(template_dev.cdev);
	sema_init(&sem,1);
	//CEllipticCurveInitParam();
	//IntegrityVerifed = verify_mod_sign();
    //IntegrityVerifed = 1;
	return 0;

}

void reg_init(void *key);
int init_test(unsigned char *out);

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

	// if(Inited!=0){
	//  	printk(KERN_INFO "Error:MASTER_KEY Already Inited\n");
	//  	WriteLogFile("Error:MASTER_KEY Already Inited\n");
	//  	return 0;
	// }
	pbkdf2_sha256(key, MASTER_KEY_SIZE, salt, 8, count, outtemp, 16);

	// unsigned ueax,uebx,uecx,uedx;
    // asm 
    // (
    //     "movl %%rax, %[val1]\n\t"
    //     "movl %%rbx, %[val2]\n\t"
    //     "movl %%rcx, %[val3]\n\t"
    //     "movl %%rdx, %[val4]"
	// 	:[val1] "=r" (ueax),[val2] "=r" (uebx),[val3] "=r" (uecx),[val4] "=r" (uedx)
	// );
    // printk("eax=%x\tebx=%x\tecx=%x\tedx=%x\n", ueax, uebx, uecx, uedx);

	on_each_cpu(reg_init,(void*)outtemp,1);

	// asm 
    // (
    //     "movl %%rax, %[val1]\n\t"
    //     "movl %%rbx, %[val2]\n\t"
    //     "movl %%rcx, %[val3]\n\t"
    //     "movl %%rdx, %[val4]"
	// 	:[val1] "=r" (ueax),[val2] "=r" (uebx),[val3] "=r" (uecx),[val4] "=r" (uedx)
	// );
    // printk("eax=%x\tebx=%x\tecx=%x\tedx=%x\n", ueax, uebx, uecx, uedx);

	//cleanup
	memset(key, 0x0, MASTER_KEY_SIZE);
	memset(outtemp, 0x0, 16);
	Inited = 1;
	WriteLogFile("Success:Init MAKTER_KEY\n");
	return 1;
}

/*sign the message out of TSX
* success: 1, fail :0
*/
int ecdsa_normal_sign(ECDSA_SIGN_Para *ecdsapara_u){

	ECDSA_SIGN_Para *ecdsapara_k = NULL;
	ecdsapara_k = vmalloc(sizeof(ECDSA_SIGN_Para));

	if(ecdsapara_k == NULL)
		return 0;
	if(copy_from_user((unsigned int *)(&(ecdsapara_k->msg_len)),(unsigned int *)(&(ecdsapara_u->msg_len)),sizeof(int)))
	{
		vfree(ecdsapara_k);
		return 0;
	}
	if(ecdsapara_k->msg_len > MAX_PLAIN_LEN)
	{
		vfree(ecdsapara_k);
		return 0;
	}			
	if(copy_from_user((unsigned char *)(ecdsapara_k->d),(unsigned char *)(ecdsapara_u->d),32))
	{
		vfree(ecdsapara_k);
		return 0;
	}		
	if(copy_from_user((unsigned char *)(ecdsapara_k->message),(unsigned char *)(ecdsapara_u->message),ecdsapara_k->msg_len))
	{
		vfree(ecdsapara_k);
		return 0;
	}

	if(SignMessage(ecdsapara_k->d,ecdsapara_k->message,ecdsapara_k->sign,ecdsapara_k->msg_len)!=1){
		vfree(ecdsapara_k);
		return 0;
	}

	if(copy_to_user(ecdsapara_u->sign,ecdsapara_k->sign,64)){
		vfree(ecdsapara_k);
		return 0;
	}

	return 1; 
}


/*sign the message in the TSX
* success: 1, fail :0
*/
int ecdsa_safe_sign(ECDSA_SIGN_Para *ecdsapara_u){
	
	ECDSA_SIGN_Para *ecdsapara_k = NULL;
	ecdsapara_k = vmalloc(sizeof(ECDSA_SIGN_Para));

	if(ecdsapara_k == NULL)
		return 0;
	if(copy_from_user((unsigned int *)(&(ecdsapara_k->msg_len)),(unsigned int *)(&(ecdsapara_u->msg_len)),sizeof(int)))
	{
		vfree(ecdsapara_k);
		return 0;
	}
	if(ecdsapara_k->msg_len > MAX_PLAIN_LEN)
	{
		vfree(ecdsapara_k);
		return 0;
	}			
	if(copy_from_user((unsigned char *)(ecdsapara_k->d),(unsigned char *)(ecdsapara_u->d),32))
	{
		vfree(ecdsapara_k);
		return 0;
	}		
	if(copy_from_user((unsigned char *)(ecdsapara_k->message),(unsigned char *)(ecdsapara_u->message),ecdsapara_k->msg_len))
	{
		vfree(ecdsapara_k);
		return 0;
	}

	if(SignMessageSafe(ecdsapara_k->d,ecdsapara_k->message,ecdsapara_k->sign,ecdsapara_k->msg_len)!=1){
		vfree(ecdsapara_k);
		return 0;
	}

	if(copy_to_user(ecdsapara_u->sign,ecdsapara_k->sign,64)){
		vfree(ecdsapara_k);
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
				WriteLogFile("Error:Copy master key from user to kernel\n");
				goto err;
			}
			if(init_hsm(key) != 1)
				goto err;
	
			break;
		}
		case ECDSA_SIGN:{
			ECDSA_SIGN_Para *ecdsapara_u = (ECDSA_SIGN_Para *)arg;
			if(ecdsa_normal_sign(ecdsapara_u)!=1)
				goto err;
			break;	
		}

		case ECDSA_SAFE_SIGN:{
			ECDSA_SIGN_Para *ecdsapara_u = (ECDSA_SIGN_Para *)arg;
			if(Inited !=1)
			{
				WriteLogFile("The module has not been inited or not ready for service\n");
				goto err;
			}	
			if(ecdsa_safe_sign(ecdsapara_u)!=1)
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
	printk(KERN_DEBUG "dirver %s unloaded\n",module_name );
}
module_init(init_template);
module_exit(cleanup_template);
