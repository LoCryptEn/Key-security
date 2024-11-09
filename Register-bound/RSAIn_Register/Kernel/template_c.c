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
//#include <stdarg.h>
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

//#include "SMS4.h"
#include "ioc.h"


MODULE_AUTHOR("<>");
MODULE_DESCRIPTION("Crypto engine driver");
MODULE_LICENSE("GPL");

struct Template_dev{
	struct miscdevice *cdev;		
};

int VIRSA(unsigned long long *R, unsigned long long *Arg);
//int test(unsigned long long *R, unsigned long long *Arg,	unsigned long long *P);
int Comcp(unsigned long *pcp, unsigned long *temp);
int Comcq(unsigned long *qcq, unsigned long *temp);
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
//int init_test(BYTE *out);

int init_hsm(unsigned char *key){
	
	unsigned char outtemp[16];

	if(Inited!=0){
	 	printk(KERN_INFO "Error:MASTER_KEY Already Inited\n");
	 	//WriteLogFile("Error:MASTER_KEY Already Inited\n");
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
		
		case RSA_OP:{			
			////
			RSA_Para *rsamessage = (RSA_Para *) arg;
			unsigned long flags;
			int i;
			unsigned long long A[500] __attribute__((aligned(64))) = { 0 };
			unsigned long long R[100] __attribute__((aligned(64))) = { 0 };
			copy_from_user(A, rsamessage->messages, 4000);/*收到的用户态数据存到数组A中*/

			unsigned long pcp[80]={0};
unsigned long qcq[80]={0};
unsigned long temp[96]={0};

//p c2 r3r c1 r2r//

//encp//
temp[0] = 0xfd9cafcc3c045c26;/*(+65 lines) 计算CRT运算需要的Cp*R，*//*p(+16 lines 1024 bit)*/
temp[1] = 0x32ef097e0535be96; /*p 每128bit分组 被密钥{0x0123456789ABCDEF, 0xFEDCBA9876543210}异或*/
temp[2] = 0x6c0497dcf7f56738;
temp[3] = 0xde34a27ed307fe31;
temp[4] = 0x96c3675f530df01f;
temp[5] = 0x9b87e0880fbe58db;
temp[6] = 0x6ea5483e79481b2d;
temp[7] = 0xcf69efcba61e2545;
temp[8] = 0xfa66443cf2c54c1f;
temp[9] = 0x91a636d09e5326d4;
temp[10] = 0xe8360376b8d9f509;
temp[11] = 0x67e0b4b79df3d136;
temp[12] = 0x71cf6321fa2fdec5;
temp[13] = 0xc9d10b89cc635181;
temp[14] = 0x67aca100bfc3bfa8;
temp[15] = 0x692da5df8d2d0e48;

int j;
// A[j+16] store c2, A[j+96] store c1, (c2, c1) is a 2048 bit cipher//
for(j=0; j<16; ++j)/*c2 (+3 lines)密文C的高1024比特*/ /*C1,C2 :C=C_2 * R + C_1*/
{
	temp[j+16] = A[j+16];
}

temp[32]=0x428a64af4dffabd2;/*RRRp (+16 lines)  R^3 mod p*/
temp[33]=0xb65c26be8a7c509d;
temp[34]=0x8a6b46b07c0e0764;
temp[35]=0x8befb224c302cfe9;
temp[36]=0xc7bfdf4a1ed1f8cf;
temp[37]=0xb9fd7a16a0b94528;
temp[38]=0x47b7a6e59af48ebe;
temp[39]=0xd9b50277c27b62cd;
temp[40]=0x224747b235cfa9ed;
temp[41]=0x8f09cacee8b5b2d1;
temp[42]=0x3f2dc74bd69dc333;
temp[43]=0xce2a60aa323bf2da;
temp[44]=0x2239bc95f1c4a31e;
temp[45]=0xda55f7498523cd86;
temp[46]=0x1949c851098a4418;
temp[47]=0x4f68b348391556ea;

for(j=0; j<16; ++j)/*c1 (+3 lines)密文C的低1024比特*/ /*C1,C2 :C=C_2 * R + C_1*/
{
	temp[j+48] = A[j+96];
}

temp[64] = 0xc697354528a7221d;/*RRp(+16 lines) R^2 mod p*/
temp[65] = 0xd04318c74fc4e105;
temp[66] = 0x507b74a8fe85db5c;
temp[67] = 0x6b90489ff59276db;
temp[68] = 0x713d4fdcadac7719;
temp[69] = 0x8221930c67af0b72;
temp[70] = 0x70d962ecdd0add09;
temp[71] = 0x529c51aba220954c;
temp[72] = 0xf6c622237221a540;
temp[73] = 0x241ecb6374b6d63e;
temp[74]= 0x3f0cd0c1f2da0ca5;
temp[75] = 0xdaaac6d08cff9876;
temp[76] = 0xa2184fb0236af9bf;
temp[77] = 0xc29ffa0049f8a6b8;
temp[78] = 0x7afa631a107c1457;
temp[79] = 0x0b80229a17179d33;

temp[80]=0x51b08be00dd0a787;/*p0 (+1 line) -p^{-1} mod 2^64*/

Comcp(pcp, temp);/*第一个参数保存在rdi ,第二个参数保存在rsi*/ /*c mod p = c2*R mod p + c1 mod p*/

//q c2 r3r c1 r2r//

//encq//
temp[0] = 0xd17dc21c42760588; /*(+65 lines) 计算CRT运算需要的Cq*R，*/
temp[1] = 0xcf47ab0e698ffa1d;
temp[2] = 0x2cd2609ebe844674;
temp[3] = 0x98883a6912756664;
temp[4] = 0xf0a6d3d16eeb4ccf;
temp[5] = 0xa8d229f570c07090;
temp[6] = 0x446451e76acc42d9;
temp[7] = 0xa72983ec415a791d;
temp[8] = 0x41231c88dcd8100b;
temp[9] = 0x1cefc2a0efa05033;
temp[10] = 0x64ce55c4a3bc654b;
temp[11] = 0x5b8ca345b5ad8e04;
temp[12] = 0x15cf7213c53cb526;
temp[13] = 0xa11dce113e711dfa;
temp[14] = 0x4d3c000642903cfa;
temp[15] = 0x3c3b91e6f58ecdbd;


for(j=0; j<16; ++j)/*c2 (+3 lines)密文C的高1024比特*/ /*C1,C2 :C=C_2 * R + C_1*/
{
	temp[j+16] = A[j+16];
}


temp[32]=0x27967f6d786bcf0c;/*RRRq (+16 lines)  R^3 mod q*/
temp[33]=0x4458856139010b8f;
temp[34]=0x1339ec28cf7ee79b;
temp[35]=0x73f627a4fba7c432;
temp[36]=0x5f78703898ebfa21;
temp[37]=0xfedceb7d2607a5a8;
temp[38]=0x290b521d8144f688;
temp[39]=0x1e006f2cc31539ea;
temp[40]=0xd163693c1ea5d615;
temp[41]=0x39d9916a5525d91d;
temp[42]=0xbdc6ac4228a0fee0;
temp[43]=0xc2e2a8915d16d845;
temp[44]=0xf92eff71a4d41f40;
temp[45]=0x5978c3e8707a43c6;
temp[46]=0xef5261c4bc9b9a1b;
temp[47]=0x3ebf598e777cc342;

for(j=0; j<16; ++j)/*c1 (+3 lines)密文C的低1024比特*/ /*C1,C2 :C=C_2 * R + C_1*/
{
	temp[j+48] = A[j+96];
}

temp[64] = 0x8a891b1a6db05376;/*RRq(+16 lines) R^2 mod q*/
temp[65] = 0x591aa942354479ad;
temp[66] = 0x3b3a0808af09ee93;
temp[67] = 0xb80e2538b4a302cf;
temp[68] = 0xbc2df11d88abcc04;
temp[69] = 0x91724ed375f76f78;
temp[70] = 0x85471c846606aba3;
temp[71] = 0x4c1c0bbfc996d074;
temp[72] = 0xc84b978795c7b0bf;
temp[73] = 0x1e57e0267727577f;
temp[74] = 0xf1acda2e6451b4f1;
temp[75] = 0x218aa3f1b167e5f7;
temp[76] = 0x26c3675b3796d8dd;
temp[77] = 0x4f62dad58b04a953;
temp[78] = 0x0e5b1db87764b57d;
temp[79] = 0x3686fdcf1acfa5f4;

temp[80]=0x30b922942b001ae7;/*q0 (+1 line) -q^{-1} mod 2^64*/

Comcq(qcq, temp);/**/

for(i=0; i<16; ++i)/*(+4 lines) c*R mod p 的计算结果Cp取代原来c2的位置*/
{
	A[i+16]=pcp[i];
}

for(i=0; i<16; ++i)
{
	A[i+96]=qcq[i];   
}
						
			preempt_disable();
			get_cpu();
			local_irq_save(flags);

			VIRSA(R, A);
///*
			for(i=0; i<32; ++i)
			{
				printk ("R[%d]:        %llx\n",i,R[i]);
			}
//*/
			local_irq_restore(flags);
			put_cpu();
			preempt_enable();
///*
			for(i=0; i<32; ++i)
			{
				A[i] = R[i];
			}

			copy_to_user(rsamessage->messages, A, 4000);
//*/			
			break;
			////
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
