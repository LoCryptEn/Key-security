#ifndef _RTM_H
#define _RTM_H 1

/*
 * Copyright (c) 2012,2013 Intel Corporation
 * Author: Andi Kleen
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Official RTM intrinsics interface matching gcc/icc, but works
   on older gcc compatible compilers and binutils. */

#define _XBEGIN_STARTED		(~0u)
#define _XABORT_EXPLICIT	(1 << 0)
#define _XABORT_RETRY		(1 << 1)
#define _XABORT_CONFLICT	(1 << 2)
#define _XABORT_CAPACITY	(1 << 3)
#define _XABORT_DEBUG		(1 << 4)
#define _XABORT_NESTED		(1 << 5)
#define _XABORT_CODE(x)		(((x) >> 24) & 0xff)

#define TSX_MAX_TIMES 1000
//#define PRINT_DBG
//#define DEBUG  1

#define __rtm_force_inline __attribute__((__always_inline__)) inline

static __rtm_force_inline int _xbegin(void)
{
	int ret = _XBEGIN_STARTED;
	asm volatile(".byte 0xc7,0xf8 ; .long 0" : "+a" (ret) :: "memory");
	return ret;
}

static __rtm_force_inline void _xend(void)
{
	 asm volatile(".byte 0x0f,0x01,0xd5" ::: "memory");
}

/* This is a macro because some compilers do not propagate the constant
 * through an inline with optimization disabled.
 */
#define _xabort(status) \
	asm volatile(".byte 0xc6,0xf8,%P0" :: "i" (status) : "memory")

static __rtm_force_inline int _xtest(void)
{
	unsigned char out;
	asm volatile(".byte 0x0f,0x01,0xd6 ; setnz %0" : "=r" (out) :: "memory");
	return out;
}

# define TSX_FAIL -128

/* 
 * tsxflag 0 for TSX abort, 1 for TSX success
*/

/*
#define tsx_var(tsxflag, flags, try, status)	\
	#ifdef TSX_ENABLE	\
		int tsxflag = 0;	\
		int status,try = 0;	\
		unsigned long flags;	\
	#endif
*/

#define tsx_header(transaction, i, tsxflag, flags, try, status) \
	tsxflag = 0;	\
	try = 0;	\
	while(!tsxflag ){	\
		get_cpu();	\
		local_irq_save(flags);	\
		while(1){	\
			if(++try == TSX_MAX_TIMES){	\
				local_irq_restore(flags);	\
				put_cpu();	\
				if(_xtest()){	\
					_xend();	\
				}	\
				printk("DEBUG: %s %d aborted %d times\n", transaction, i, try);	\
				return TSX_FAIL;	\
			}	\
			status = _xbegin();	\
			if (status == _XBEGIN_STARTED)	\
				break;	\
		}

#define tsx_normal_tailer(tsxflag, flags) \
		tsxflag = 1; 	\
		if(_xtest()){ 	\
			_xend(); 	\
		}	\
		local_irq_restore(flags);	\
		put_cpu();	\
		if(!tsxflag){	\
			set_current_state(TASK_INTERRUPTIBLE);	\
			schedule_timeout(10);	\
		}	\
	}
// need to add:?
// if(!tsxflag)
//		return TSX_FAIL;
//

#define tsx_error_tailer(flags)	\
	local_irq_restore(flags);	\
	put_cpu();	\
	if(_xtest()){	\
		_xend();	\
	}

#endif
