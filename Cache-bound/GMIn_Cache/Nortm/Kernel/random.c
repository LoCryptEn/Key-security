#include "eltt2.h"

#ifdef RAND_DEBUG

#include <linux/random.h>

int tpm_gen_random(int length, unsigned char *return_random){
    get_random_bytes(return_random, length);
    return length;
}

#elif

#include<linux/semaphore.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include<asm/uaccess.h>

#define ERR_COMMUNICATION		-1	///< Return error check for read and write to the TPM.
#define PRINT_RESPONSE_WITHOUT_HEADER		12	///< Prints the response buffer from byte 12.

static const unsigned char tpm2_getrandom[] = {
	0x80, 0x01,			// TPM_ST_NO_SESSIONS
	0x00, 0x00, 0x00, 0x0C,		// commandSize
	0x00, 0x00, 0x01, 0x7B,		// TPM_CC_GetRandom
	0x00, 0x00			// bytesRequested (will be set later)
};
struct semaphore sem;

void init_random(void)
{
    sema_init(&sem,1);
}

int tpm_gen_random(int length, unsigned char *return_random){
    struct file *dev_tpm;
    mm_segment_t fs;
    loff_t pos = 0;
    int transmit_size = 0;	// Amount of bytes sent to / received from the TPM.
    unsigned char send_buf[sizeof(tpm2_getrandom)];
    unsigned char response[PRINT_RESPONSE_WITHOUT_HEADER+32];
    int send_buf_lenth = 0;
    memset(response, 0, PRINT_RESPONSE_WITHOUT_HEADER+32);
    memset(send_buf, 0, sizeof(tpm2_getrandom));

    send_buf_lenth = sizeof(tpm2_getrandom);
    memcpy(send_buf, tpm2_getrandom, sizeof(tpm2_getrandom));
    send_buf[sizeof(tpm2_getrandom) - 1] = length;

    if(down_interruptible(&sem) == -EINTR)
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
