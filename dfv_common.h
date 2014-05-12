/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_common.h
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * Originally based on the Device Virtualization project
 *
 * Copyright (c) 2010 Nokia Research Center, Palo Alto, USA
 * All rights reserved.
 *
 * Authors: Sreekumar Nair
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#include <linux/fs.h>

#define DFV_PATH_LENGTH    32

/*
 * Data structures to communicate between dfvserver and dfvclient modules:
 * These should match the operations supported on the corresponding
 * version of Linux.
 */
/* File operations: */
#define DFV_FILE_OPERATIONS			\
	DFVFO(llseek)				\
	DFVFO(read)				\
	DFVFO(write)				\
	DFVFO(aio_read)				\
	DFVFO(aio_write)			\
	DFVFO(readdir)				\
	DFVFO(poll)				\
	DFVFO(unlocked_ioctl)			\
	DFVFO(compat_ioctl)			\
	DFVFO(mmap)				\
	DFVFO(open)				\
	DFVFO(flush)				\
	DFVFO(release)				\
	DFVFO(fsync)				\
	DFVFO(aio_fsync)			\
	DFVFO(fasync)				\
	DFVFO(lock)				\
	DFVFO(sendpage)				\
	DFVFO(get_unmapped_area)		\
	DFVFO(check_flags)			\
	DFVFO(flock)				\
	DFVFO(splice_write)			\
	DFVFO(splice_read)			\
	DFVFO(setlease)				\
	DFVFO(fallocate)

/* VM operations (mmap support): */
#ifdef CONFIG_NUMA
#define DFV_VM_OPERATIONS			\
	DFVVMO(open)				\
	DFVVMO(close)				\
	DFVVMO(fault)				\
	DFVVMO(page_mkwrite)			\
	DFVVMO(access)				\
	DFVVMO(set_policy)			\
	DFVVMO(get_policy)			\
	DFVVMO(migrate)
#else /* CONFIG_NUMA */
#define DFV_VM_OPERATIONS			\
	DFVVMO(open)				\
	DFVVMO(close)				\
	DFVVMO(fault)				\
	DFVVMO(page_mkwrite)			\
	DFVVMO(access)
#endif /* CONFIG_NUMA */

/*
 * This enum enumerates the file operations. It includes 'all' file operations,
 * and not only the operations in the corresponding linux version. This enum
 * should be maintained with care, and new entries MUST only be added to its
 * end, and not between the existing entries.
 */
enum dfv_op {
        DFV_VMOP_open = 0,
        DFV_VMOP_close = 1,
        DFV_VMOP_fault = 2,
        DFV_VMOP_page_mkwrite = 3,
        DFV_VMOP_access = 4,
        DFV_VMOP_set_policy = 5,
        DFV_VMOP_get_policy = 6,
        DFV_VMOP_migrate = 7,

        DFV_EOP_fault1 = 8,
        DFV_EOP_fault2 = 9,

        DFV_FOP_llseek = 10,
        DFV_FOP_read = 11,
        DFV_FOP_write = 12,
        DFV_FOP_aio_read = 13,
        DFV_FOP_aio_write = 14,
        DFV_FOP_readdir = 15,
        DFV_FOP_poll = 16,
        DFV_FOP_ioctl = 17,
        DFV_FOP_unlocked_ioctl = 18,
        DFV_FOP_compat_ioctl = 19,
	DFV_FOP_mmap = 20,
	DFV_FOP_open = 21,
	DFV_FOP_flush = 22,
	DFV_FOP_release = 23,
	DFV_FOP_fsync = 24,
	DFV_FOP_aio_fsync = 25,
	DFV_FOP_fasync = 26,
	DFV_FOP_lock = 27,
	DFV_FOP_sendpage = 28,
	DFV_FOP_get_unmapped_area = 29,
	DFV_FOP_check_flags = 30,
	DFV_FOP_flock = 31,
	DFV_FOP_splice_write = 32,
	DFV_FOP_splice_read = 33,
	DFV_FOP_setlease = 34,
	DFV_FOP_fallocate = 35,
	DFV_OP_custom = 36,
	DFV_OP_numops = 37,
	DFV_OP_invalid = 38
};

struct dfvbitmap {
	int bitmap_index;
};

/*
 * This bitmap is used to communicate from the server to the client which
 * operations are supported for a specific file that is opened.
 */
extern struct dfvbitmap dfvbitmap[];

struct dfv_op_all_args {
	unsigned long req_arg_1;
	unsigned long req_arg_2;
	unsigned long req_arg_3;
	unsigned long req_arg_4;
	unsigned long req_arg_5;
	unsigned long req_arg_6;
	unsigned long res_arg_1;
	unsigned long res_arg_2;
	unsigned long res_arg_3;
	unsigned long res_arg_4;
	unsigned long res_arg_5;
	unsigned long res_arg_6;
};

struct dfv_op_args {
	unsigned long arg_1;
	unsigned long arg_2;
	unsigned long arg_3;
	unsigned long arg_4;
	unsigned long arg_5;
	unsigned long arg_6;
};

#define REQ_ARG_1			req_args->arg_1
#define REQ_ARG_2			req_args->arg_2
#define REQ_ARG_3			req_args->arg_3
#define REQ_ARG_4			req_args->arg_4
#define REQ_ARG_5			req_args->arg_5
#define REQ_ARG_6			req_args->arg_6

#define RES_ARG_1			res_args->arg_1
#define RES_ARG_2			res_args->arg_2
#define RES_ARG_3			res_args->arg_3
#define RES_ARG_4			res_args->arg_4
#define RES_ARG_5			res_args->arg_5
#define RES_ARG_6			res_args->arg_6

/* Common arguments: */
/*
 * only for 32 bit systems. The lower 16 bits is for serverfd and the upper
 * 16 bits is for op. Therefore op and serverfd cannot be larger
 * than 2^16
 */
#define OPREQ_OP_SERVERFD		REQ_ARG_1

/*
 * only for 32 bit systems. The lower 16 bits for thread id and the upper
 * 16 bits for process id. Therefore thread and process id cannot be larger
 * than 2^16
 */
#define OPREQ_ID			REQ_ARG_2
#define OPRES_POSITION			RES_ARG_1

/* Operation specific arguments: */

#define FAULT1_STARTADDR		REQ_ARG_3
#define FAULT1_ENDADDR			REQ_ARG_4
#define FAULT1_VMFLAGS			REQ_ARG_5
#define FAULT1_PGOFF			REQ_ARG_6
#define FAULT1_RESULT			RES_ARG_2

#define FAULT2_FLAGS			REQ_ARG_3
#define FAULT2_PGOFF			REQ_ARG_4
#define FAULT2_VIRTADDR			REQ_ARG_5
#define FAULT2_RESULT			RES_ARG_2

#define FLUSH_RESULT			RES_ARG_2

#define LLSEEK_OFFSET			REQ_ARG_3
#define LLSEEK_DIRECTION		REQ_ARG_4
#define LLSEEK_RESULT			RES_ARG_2

#define MMAP_STARTADDR			REQ_ARG_3
#define MMAP_ENDADDR			REQ_ARG_4
#define MMAP_PGOFF			REQ_ARG_5
#define MMAP_VMFLAGS			REQ_ARG_6
#define MMAP_RESULT			RES_ARG_2
#define MMAP_NEWVMFLAGS			RES_ARG_3
#define MMAP_SERVERVMOPS		RES_ARG_4

#define OPEN_PATHNAME			REQ_ARG_3
#define OPEN_FLAGS			REQ_ARG_4
#define OPEN_MODE			REQ_ARG_5
#define OPEN_RESULT			RES_ARG_2
#define OPEN_SERVERFD			RES_ARG_3
#define OPEN_SERVERFOPS			RES_ARG_4

#define POLL_KEY			REQ_ARG_3
#define POLL_NULLKEY			REQ_ARG_4
#define POLL_WAIT_TIME			REQ_ARG_5
#define POLL_SLACK			REQ_ARG_6
#define POLL_RESULT			RES_ARG_2

#define READ_BUF			REQ_ARG_3
#define READ_COUNT			REQ_ARG_4
#define READ_OFFSET			REQ_ARG_5
#define READ_RESULT			RES_ARG_2
#define READ_NEWOFFSET			RES_ARG_3

#define RELEASE_RESULT			RES_ARG_2

#define UNLOCKED_IOCTL_ARG		REQ_ARG_3
#define UNLOCKED_IOCTL_CMD		REQ_ARG_4
#define UNLOCKED_IOCTL_RESULT		RES_ARG_2

#define WRITE_BUF			REQ_ARG_3
#define WRITE_COUNT			REQ_ARG_4
#define WRITE_OFFSET			REQ_ARG_5
#define WRITE_RESULT			RES_ARG_2
#define WRITE_NEWOFFSET			RES_ARG_3

#define FASYNC_FD			REQ_ARG_3
#define FASYNC_ON			REQ_ARG_4
#define FASYNC_RESULT			RES_ARG_2

#define VM_CLOSE_STARTADDR		REQ_ARG_3
#define VM_CLOSE_ENDADDR		REQ_ARG_4
#define VM_CLOSE_PGOFF			REQ_ARG_5
#define VM_CLOSE_VMFLAGS		REQ_ARG_6

#define VM_OPEN_STARTADDR		REQ_ARG_3
#define VM_OPEN_ENDADDR			REQ_ARG_4
#define VM_OPEN_PGOFF			REQ_ARG_5
#define VM_OPEN_VMFLAGS			REQ_ARG_6

#define CUSTOM_REQ_ARG1			REQ_ARG_3
#define CUSTOM_REQ_ARG2			REQ_ARG_4
#define CUSTOM_REQ_ARG3			REQ_ARG_5
#define CUSTOM_REQ_ARG4			REQ_ARG_6
#define CUSTOM_RES_ARG1			RES_ARG_2
#define CUSTOM_RES_ARG2			RES_ARG_3
#define CUSTOM_RES_ARG3			RES_ARG_4
#define CUSTOM_RES_ARG4			RES_ARG_5
#define CUSTOM_RES_ARG5			RES_ARG_6

#define POLL_INFINITE_WAIT		~0UL

#define DFVPRINTK(fmt, args...) pr_debug(KERN_INFO "%s: " fmt, __func__, ##args)

#define DFVPRINTK_ERR(fmt, args...) printk(KERN_ERR "%s: " fmt, __func__, ##args)
/*
 * There are a few cases that some error messages are fired but they don't
 * break anything (that we see) and we don't know the root cause of the errors
 * yet. We use this macro for them so that we can enable them only when we
 * want to debug them.
 */
#define DFVPRINTK_ERR2(fmt, args...) pr_debug(KERN_ERR "%s: " fmt, __func__, ##args)

/* irq related stuff */

#define DFV_IRQ_NUM_ARGS 3
/* irq page fields */
#define DFV_IRQ_TYPE 0
#define DFV_IRQ_PROCESS_TGID 1
#define DFV_IRQ_THREAD_PID 2
/* irq field values for type */
#define DFV_IRQ_POLL 1
#define DFV_IRQ_SIGIO 2

struct dfv_file_struct
{
	char *filename;
	int abs_name;
	struct list_head list;
};
extern struct list_head dfv_file_list;

int add_file_to_dfv_file_list(char *filename, int type);
void empty_dfv_file_list(void);
int get_abs_name_from_pathname(const char *pathname);
char *get_pathname_from_abs_name(int abs_name);

long sys_open_kernel(const char __user * pathname, int flags, int mode,
							struct file **_f);

extern struct attribute_group dfv_attr_group;
