/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_client.c
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

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include "dfv_common.h"
#include "dfv_client.h"

struct task_struct *current_dfv_task;
EXPORT_SYMBOL(current_dfv_task);

struct list_head dfvprocess_list;
struct list_head dfvthread_list;

static DEFINE_MUTEX(dfvmutex);
#define ENTER_CRITICAL_REGION mutex_lock(&dfvmutex)
#define EXIT_CRITICAL_REGION mutex_unlock(&dfvmutex)

static void (*init_dfvprocess)(struct dfvprocess_struct *dfvprocess);
static void (*init_dfvthread)(struct dfvthread_struct *dfvthread);

int set_init_dfvprocess(void (*func)(struct dfvprocess_struct *dfvprocess))
{
	if (init_dfvprocess) {
		DFVPRINTK_ERR("Error: init_dfvprocess has been set before\n");
		return -EPERM;
	}

	init_dfvprocess = func;

	return 0;
}
EXPORT_SYMBOL(set_init_dfvprocess);

int set_init_dfvthread(void (*func)(struct dfvthread_struct *dfvthread))
{
	if (init_dfvthread) {
		DFVPRINTK_ERR("Error: init_dfvthread has been set before\n");
		return -EPERM;
	}

	init_dfvthread = func;

	return 0;
}
EXPORT_SYMBOL(set_init_dfvthread);

struct dfvprocess_struct *add_dfvprocess(pid_t process_id)
{
	struct dfvprocess_struct *dfvprocess;

	dfvprocess = kzalloc(sizeof(*dfvprocess), GFP_KERNEL);
	if (!dfvprocess) {
		DFVPRINTK_ERR("Error: could not allocate memory\n");
		return NULL;
	}
	dfvprocess->process_id = process_id;
	dfvprocess->num_open_fds = 0;

	if (!init_dfvprocess) {
		DFVPRINTK_ERR("Error: init_dfvprocess is NULL.\n");
		kfree(dfvprocess);
		return NULL;
	}

	(*init_dfvprocess)(dfvprocess);

	list_add(&dfvprocess->list, &dfvprocess_list);

	return dfvprocess;
}

struct dfvprocess_struct *get_dfvprocess(pid_t process_id)
{
	struct dfvprocess_struct *dfvprocess = NULL;

	list_for_each_entry(dfvprocess, &dfvprocess_list, list) {

		if (dfvprocess->process_id == process_id) {
			return dfvprocess;
		}
	}

	return NULL;
}

void remove_dfvprocess(struct dfvprocess_struct *_dfvprocess)
{
	struct dfvprocess_struct *dfvprocess = NULL, *tmp;

	list_for_each_entry_safe(dfvprocess, tmp, &dfvprocess_list, list) 	{

		if (dfvprocess == _dfvprocess && dfvprocess->num_open_fds <= 0) {			
			list_del(&dfvprocess->list);
			kfree(dfvprocess);
		}
	}
}

struct dfvthread_struct *add_dfvthread(pid_t thread_id, pid_t process_id)
{
	struct dfvthread_struct *dfvthread;
	struct dfvprocess_struct *dfvprocess;
	static DECLARE_WAIT_QUEUE_HEAD(wait_queue);

	dfvprocess = get_dfvprocess(process_id);
	if (dfvprocess == NULL) {
		dfvprocess = add_dfvprocess(process_id);
		if (dfvprocess == NULL) {
			DFVPRINTK_ERR("Error: dfvprocess could not be added\n");
			return NULL;
		}
	}

	dfvthread = kzalloc(sizeof(*dfvthread), GFP_KERNEL);
	if (!dfvthread) {
		DFVPRINTK_ERR("Error: could not allocate memory\n");

		goto err_out;
	}
	dfvthread->thread_id = thread_id;
	dfvthread->process_id = process_id;
	dfvthread->dfvprocess = dfvprocess;
	dfvthread->wait_queue = &wait_queue;
	dfvthread->num_open_fds = 0;

	if (!init_dfvthread) {
		DFVPRINTK_ERR("Error: init_dfvthread is NULL.\n");
		kfree(dfvthread);

		goto err_out;
	}

	(*init_dfvthread)(dfvthread);

	list_add(&dfvthread->list, &dfvthread_list);

	return dfvthread;

err_out:
	remove_dfvprocess(dfvprocess);

	return NULL;
}
EXPORT_SYMBOL(add_dfvthread);

struct dfvthread_struct *get_dfvthread(pid_t thread_id, pid_t process_id)
{
	struct dfvthread_struct *dfvthread = NULL;
	struct dfvprocess_struct *dfvprocess = NULL;

	list_for_each_entry(dfvthread, &dfvthread_list, list) {

		if (dfvthread->thread_id == thread_id &&
		    dfvthread->process_id == process_id) {
			return dfvthread;
		}
	}

	/*
	 * We could not find the thread, but the process might have been
	 * created before. If that's the case, create the thread here.
	 */
	list_for_each_entry(dfvprocess, &dfvprocess_list, list) {

		if (dfvprocess->process_id == process_id) {
			/* process exists */
			dfvthread = add_dfvthread(thread_id, process_id);
			if (dfvthread) {
				return dfvthread;
			}
			else {
				DFVPRINTK_ERR("Error: dfvthread could not be added\n");
				return NULL;
			}
		}
	}

	return NULL;
}
EXPORT_SYMBOL(get_dfvthread);

void remove_dfvthread(struct dfvthread_struct *_dfvthread)
{
	struct dfvthread_struct *dfvthread = NULL, *tmp;
	struct dfvprocess_struct *dfvprocess = NULL;

	list_for_each_entry_safe(dfvthread, tmp, &dfvthread_list, list) {

		if (dfvthread == _dfvthread && dfvthread->num_open_fds <= 0) {
			dfvprocess = dfvthread->dfvprocess;
			list_del(&dfvthread->list);
			if (dfvthread->clean_dfvthread)
				(*dfvthread->clean_dfvthread)(dfvthread);
			kfree(dfvthread);
			remove_dfvprocess(dfvprocess);
		}
	}
}
EXPORT_SYMBOL(remove_dfvthread);

/* File operations implementation: */

static loff_t dfv_fop_llseek(struct file *file, loff_t off, int dir)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_FOP_llseek, local_args, req_args, res_args);

	LLSEEK_OFFSET = off;
	LLSEEK_DIRECTION = dir;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	file->f_pos = OPRES_POSITION;
	return LLSEEK_RESULT;
}

static ssize_t dfv_fop_read(struct file *file, char __user *buf,
	size_t size, loff_t *off)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return 0;
	}

	INIT_OP(dfvthread, file, DFV_FOP_read, local_args, req_args, res_args);

	READ_BUF = (unsigned long) buf;
	READ_COUNT = size;
	READ_OFFSET = *off;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	file->f_pos = OPRES_POSITION;
	*off = READ_NEWOFFSET;

	return READ_RESULT;
}

static ssize_t dfv_fop_write(struct file *file, const char __user *buf,
	size_t size, loff_t *off)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return 0;
	}

	INIT_OP(dfvthread, file, DFV_FOP_write, local_args, req_args, res_args);

	WRITE_BUF = (unsigned long) buf;
	WRITE_COUNT = size;
	WRITE_OFFSET = *off;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	file->f_pos = OPRES_POSITION;
	*off = WRITE_NEWOFFSET;

	return WRITE_RESULT;
}

static ssize_t dfv_fop_aio_read(struct kiocb *iocb, const struct iovec *iov,
	unsigned long nr_segs, loff_t pos)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static ssize_t dfv_fop_aio_write(struct kiocb * iocb, const struct iovec *iov,
	unsigned long nr_segs, loff_t pos)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static int dfv_fop_readdir(struct file *file, void * cookie, filldir_t filldir)
{

	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static unsigned int dfv_fop_poll(struct file *file,
				struct poll_table_struct *wait)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;
	unsigned long nullkey = wait ? 0 : 1;
	unsigned long key = wait ? wait->key : ~0UL;
	struct timespec *end_time = (struct timespec *) current->dfvdata[0];
	unsigned long wait_time;
	ktime_t expire;

	current->dfvdata[0] = NULL;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_FOP_poll, local_args, req_args, res_args);

	POLL_KEY = key;
	POLL_NULLKEY = nullkey;

	if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
		wait_time = 0;
	} else if (end_time) {
		expire = timespec_to_ktime(*end_time);

		wait_time = (unsigned long) ktime_to_ns(ktime_sub(expire,
								ktime_get()));

		/*
		 * Since we are overloading the POLL_WAIT_TIME both as an
		 * indicator of infite wait and as the amount of wait, we
		 * have to do this check. Otherwise , a wait time of
		 * POLL_INFIITE_WAIT will be interpreted as infinite wait
		 * by the server.
		 */
		if (wait_time == POLL_INFINITE_WAIT)
			wait_time--;

	} else { /* end_time == NULL */
		wait_time = POLL_INFINITE_WAIT;
	}

	POLL_WAIT_TIME = wait_time;

	if (end_time)
		POLL_SLACK = select_estimate_accuracy(end_time);
	else
		POLL_SLACK = 0;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	if (dfvthread->use_non_blocking_poll) {
		if (wait && !POLL_RESULT)
			poll_wait(file, dfvthread->wait_queue, wait);

	}

	return POLL_RESULT;
}

static long dfv_fop_unlocked_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_FOP_unlocked_ioctl, local_args, req_args, res_args);

	UNLOCKED_IOCTL_CMD = cmd;
	UNLOCKED_IOCTL_ARG = arg;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	file->f_pos = OPRES_POSITION;

	return UNLOCKED_IOCTL_RESULT;
}

static long dfv_fop_compat_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static int dfv_fop_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;
	unsigned long startaddr = vma ? vma->vm_start : 0;
	unsigned long endaddr   = vma ? vma->vm_end : 0;
	unsigned long vmflags   = vma ? vma->vm_flags : 0;
	unsigned long pgoff     = vma ? vma->vm_pgoff : 0;
	long servervmops = 0;
	int index = 0;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_FOP_mmap, local_args, req_args, res_args);

	MMAP_STARTADDR = startaddr;
	MMAP_ENDADDR = endaddr;
	MMAP_VMFLAGS = vmflags;
	MMAP_PGOFF = pgoff;

	dfvthread->dispatch(dfvthread, req_args, res_args, (void *) vma);

	servervmops = MMAP_SERVERVMOPS;

	vma->vm_flags = MMAP_NEWVMFLAGS;

	vma->vm_file = file;

	vma->vm_ops = kmalloc(sizeof(struct vm_operations_struct), GFP_KERNEL);
	if (!vma->vm_ops) {
		DFVPRINTK_ERR("Error: dfv_fop_mmap: ran out of memory\n");

		return -ENOMEM;
	} else {

		*(struct vm_operations_struct *) vma->vm_ops = dfvvmops;
	}

	/*
	 * If a VM operation is not defined on the server,
	 * then it should be null on the client as well.
	 */
	#define DFVVMO(x) {						\
		index = dfvbitmap[DFV_VMOP_ ## x].bitmap_index;		\
		if ((servervmops & (1 << index)) == 0) {		\
			DFVPRINTK("VM operation \"" #x "\" "		\
				"not defined on server - preserving "	\
				"the same state on client\n");		\
			((struct vm_operations_struct *)		\
				vma->vm_ops)->x=NULL;			\
		}							\
	}
	DFV_VM_OPERATIONS
	#undef DFVVMO

	return MMAP_RESULT;
}

static int dfv_fop_open(struct inode *inode, struct file *file)
{
	const char __user *pathname = current->dfvdata[0];
	int flags = (int) current->dfvdata[1];
	int mode = (int) current->dfvdata[2];
	long serverfops = 0;
	int index = 0;
	int abs_name;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;
	int ret;

	/* Not to carry over this data to next ops */
	current->dfvdata[0] = NULL;
	current->dfvdata[1] = NULL;
	current->dfvdata[2] = NULL;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		dfvthread = add_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
		if (dfvthread == NULL) {
			DFVPRINTK_ERR("Error: dfvthread could not be added\n");
			return -EINVAL;
		}
	}

	INIT_OP(dfvthread, file, DFV_FOP_open, local_args, req_args, res_args);

	abs_name = get_abs_name_from_pathname(pathname);

	if (abs_name < 0) {
		DFVPRINTK_ERR("Error: No equivalent abstract name was found.\n");

		ret = -EINVAL;
		goto err_out;
	}

	OPEN_PATHNAME = (unsigned long) abs_name;
	OPEN_FLAGS = flags;
	OPEN_MODE = mode;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	if (OPEN_RESULT) {
		DFVPRINTK_ERR("Error: open failed on the server\n");
		ret = OPEN_RESULT;
		goto err_out;
	}

	serverfops = OPEN_SERVERFOPS;

	file->serverfd = OPEN_SERVERFD;
	file->f_pos = OPRES_POSITION;

	file->f_op = kmalloc(sizeof(*file->f_op), GFP_KERNEL);
	if (!file->f_op) {
		DFVPRINTK_ERR("Error: ran out of memory\n");

		ret = -ENOMEM;
		goto err_out;
	} else {
		*(struct file_operations *) file->f_op = dfvfops;
	}

	dfvthread->num_open_fds++;
	dfvthread->dfvprocess->num_open_fds++;

	/*
	 * If a file operation is not defined on the server,
	 *  then it should be null on the client as well!
	 */
	#define DFVFO(x) {						\
		index = dfvbitmap[DFV_FOP_ ## x].bitmap_index;		\
		if ((serverfops & (1 << index)) == 0) {			\
			DFVPRINTK("file operation \"" #x		\
				"\" not defined on server - "		\
				"preserving the same state "		\
				"on client\n");				\
			((struct file_operations *)file->f_op)->x=NULL;	\
		}							\
	}
	DFV_FILE_OPERATIONS
	#undef DFVFO

	return 0;

err_out:
	remove_dfvthread(dfvthread);

	return ret;
}

static int dfv_fop_flush(struct file *file, fl_owner_t id)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_FOP_flush, local_args, req_args, res_args);

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	file->f_pos = OPRES_POSITION;

	return FLUSH_RESULT;
}

static int dfv_fop_release(struct inode *inode, struct file *file)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;
	struct dfvprocess_struct *dfvprocess;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	dfvprocess = dfvthread->dfvprocess;

	INIT_OP(dfvthread, file, DFV_FOP_release, local_args, req_args, res_args);

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	file->f_pos = OPRES_POSITION;

	/*
	 * We only release the resources if the file was properly closed
	 * on the server.
	 * FIXME: this can be abused by a malicious server. Why not just
	 * release the resource no matter what happened on the server?
	 */
	if (!RELEASE_RESULT) {
		dfvthread->num_open_fds--;
		dfvprocess->num_open_fds--;
		remove_dfvthread(dfvthread);
		kfree(file->f_op);
		file->f_op = NULL;
	}

	return RELEASE_RESULT;
}

static int dfv_fop_fsync(struct file *file, loff_t off1, loff_t off2, int datasync)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static int dfv_fop_aio_fsync(struct kiocb * iocb, int datasync)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

struct fasync_struct *dfv_fasync;
EXPORT_SYMBOL(dfv_fasync);

static int dfv_fop_fasync(int fd, struct file *file, int on)
{
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_FOP_fasync, local_args, req_args, res_args);

	FASYNC_FD = (unsigned long) fd;
	FASYNC_ON = (unsigned long) on;

	fasync_helper(fd, file, on, &dfv_fasync);

	/*
	 * we use current_dfv_task for sending SIGUSR1 to when switching the
	 * virtual console back to the VM.
	 */
	current_dfv_task = current;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	return FASYNC_RESULT;
}

static int dfv_fop_lock(struct file *file, int cmd, struct file_lock *lock)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static ssize_t dfv_fop_sendpage(struct file *file, struct page *page,
	int off, size_t size, loff_t *end, int flags)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static unsigned long dfv_fop_get_unmapped_area(struct file *file,
	unsigned long addr, unsigned long len, unsigned long pgoff,
	unsigned long flags)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static int dfv_fop_check_flags(int flags)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static int dfv_fop_flock(struct file *file, int cmd, struct file_lock *lock)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static ssize_t dfv_fop_splice_write(struct pipe_inode_info *pipe,
	struct file *file, loff_t *ppos, size_t len, unsigned int flags)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static ssize_t dfv_fop_splice_read(struct file *file, loff_t *ppos,
	struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static int dfv_fop_setlease(struct file *file, long arg,
	struct file_lock **lease)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static long dfv_fop_fallocate(struct file *file, int mode, loff_t offset,
	loff_t len)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

/* Support for mmap: */

static void dfv_vmop_open(struct vm_area_struct *vma)
{
	unsigned long startaddr = vma ? vma->vm_start : 0;
	unsigned long endaddr   = vma ? vma->vm_end : 0;
	unsigned long vmflags   = vma ? vma->vm_flags : 0;
	unsigned long pgoff     = vma ? vma->vm_pgoff : 0;
	struct file *file      = vma ? vma->vm_file : NULL;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return;
	}

	INIT_OP(dfvthread, file, DFV_VMOP_open, local_args, req_args, res_args);

	VM_OPEN_STARTADDR = startaddr;
	VM_OPEN_ENDADDR = endaddr;
	VM_OPEN_VMFLAGS = vmflags;
	VM_OPEN_PGOFF = pgoff;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);
}

static void dfv_vmop_close(struct vm_area_struct *vma)
{
	unsigned long startaddr = vma ? vma->vm_start : 0;
	unsigned long endaddr   = vma ? vma->vm_end : 0;
	unsigned long vmflags   = vma ? vma->vm_flags : 0;
	unsigned long pgoff     = vma ? vma->vm_pgoff : 0;
	struct file *file      = vma ? vma->vm_file : NULL;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		/*
		 * FIXME: We've spotted a case that this error is strangely
		 * fired. When logging into Ubuntu on a virtual GPU, it
		 * seems like a whole new process (compiz-decorator) invokes the
		 * dfv_vmop_close(). Not sure how to handle that.
		 */
		DFVPRINTK_ERR2("Error: dfvthread was not found\n");
		return;
	}

	INIT_OP(dfvthread, file, DFV_VMOP_close, local_args, req_args, res_args);

	VM_CLOSE_STARTADDR = startaddr;
	VM_CLOSE_ENDADDR = endaddr;
	VM_CLOSE_VMFLAGS = vmflags;
	VM_CLOSE_PGOFF = pgoff;

	dfvthread->dispatch(dfvthread, req_args, res_args, (void *) vma);

	kfree(vma->vm_ops);
	vma->vm_ops = NULL;
}

static int dfv_eop_fault1(struct file *file, struct vm_area_struct *vma)
{
	unsigned long vma_startaddr      = vma ? vma->vm_start : 0;
	unsigned long vma_endaddr        = vma ? vma->vm_end : 0;
	unsigned long vma_vmflags        = vma ? vma->vm_flags : 0;
	unsigned long vma_pgoff          = vma ? vma->vm_pgoff : 0;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_EOP_fault1, local_args, req_args, res_args);

	FAULT1_STARTADDR = vma_startaddr;
	FAULT1_ENDADDR = vma_endaddr;
	FAULT1_VMFLAGS = vma_vmflags;
	FAULT1_PGOFF = vma_pgoff;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	return FAULT1_RESULT;
}

static int dfv_eop_fault2(struct file *file, struct vm_fault *vmf,
						struct vm_area_struct *vma)
{
	unsigned int vmf_flags           = vmf ? vmf->flags : 0;
	pgoff_t vmf_pgoff                = vmf ? vmf->pgoff : 0;
	void __user *vmf_virtual_address = vmf ? vmf->virtual_address : 0;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		DFVPRINTK_ERR("Error: dfvthread was not found\n");
		return -EINVAL;
	}

	INIT_OP(dfvthread, file, DFV_EOP_fault2, local_args, req_args, res_args);

	FAULT2_VIRTADDR = (unsigned long) vmf_virtual_address;
	FAULT2_FLAGS = vmf_flags;
	FAULT2_PGOFF = vmf_pgoff;

	dfvthread->dispatch(dfvthread, req_args, res_args, vma);

	return FAULT2_RESULT;
}

/*
 * We forward the fault arguments to the dfv_server in two messages.
 * dfv_eop_fault1() and dfv_eop_fault2() implement these two. This is
 * due to some legacy reasons: in the implementation for KVM, our hypercall
 * would only take 6 arguments, which was not enough to pass all the fault
 * arguments, and that's why we did two hypercalls.
 */
static int dfv_vmop_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct file *file = vma ? vma->vm_file : NULL;
	int status = 0;

	if (!file) {
		DFVPRINTK_ERR("Error: dfv_vmop_fault: null file "
			"descriptor: vma=%#x\n", (unsigned int) vma);

		return VM_FAULT_ERROR;
	}

	if ((status = dfv_eop_fault1(file, vma)) != 0) {
		DFVPRINTK_ERR("Error: dfv_vmop_fault: failed in "
			"dfv_eop_fault1: status=%#x\n", (unsigned int) status);

		return status;
	}

	if ((status = dfv_eop_fault2(file, vmf, vma)) != VM_FAULT_NOPAGE) {
		DFVPRINTK_ERR("Error: dfv_vmop_fault: failed in "
			"dfv_eop_fault2: status=%#x\n", (unsigned int) status);

		return status;
	}

	return VM_FAULT_NOPAGE;
}

static int dfv_vmop_page_mkwrite(struct vm_area_struct *vma,
	struct vm_fault *vmf)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static int dfv_vmop_access(struct vm_area_struct *vma, unsigned long addr,
	void *buf, int len, int write)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

#ifdef CONFIG_NUMA
static int dfv_vmop_set_policy(struct vm_area_struct *vma,
	struct mempolicy *new)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}

static struct mempolicy *dfv_vmop_get_policy(struct vm_area_struct *vma,
	unsigned long addr)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return NULL;
}

static int dfv_vmop_migrate(struct vm_area_struct *vma, const nodemask_t *from,
	const nodemask_t *to, unsigned long flags)
{
	DFVPRINTK_ERR("Error: not unsupported\n");

	return -EINVAL;
}
#endif /* CONFIG_NUMA */

int dfv_alloc_pages(void **virt_addr_ptr, void **phys_addr_ptr, int nr_pages)
{
	size_t size = nr_pages * PAGE_SIZE;
	unsigned long phys_addr;

	(*virt_addr_ptr) =
		alloc_pages_exact(size, GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
	if (*virt_addr_ptr) {

		phys_addr = virt_to_phys((*virt_addr_ptr));

		/* phys_addr must be page aligned */

		if (phys_addr & ~PAGE_MASK) {
			DFVPRINTK_ERR("Error: phys_addr is not page aligned\n");
			return -EINVAL;
		}

		*phys_addr_ptr = (void *) phys_addr;
	}
	else {
		DFVPRINTK_ERR("Error: could not allocate page(s)\n");
		return ENOMEM;
	}

	return 0;
}
EXPORT_SYMBOL(dfv_alloc_pages);

struct file_operations dfvfops = {
	.owner                = THIS_MODULE,
	.llseek               = dfv_fop_llseek,
	.read                 = dfv_fop_read,
	.write                = dfv_fop_write,
	.aio_read             = dfv_fop_aio_read,
	.aio_write            = dfv_fop_aio_write,
	.readdir              = dfv_fop_readdir,
	.poll                 = dfv_fop_poll,
	.unlocked_ioctl       = dfv_fop_unlocked_ioctl,
	.compat_ioctl         = dfv_fop_compat_ioctl,
	.mmap                 = dfv_fop_mmap,
	.open                 = dfv_fop_open,
	.flush                = dfv_fop_flush,
	.release              = dfv_fop_release,
	.fsync                = dfv_fop_fsync,
	.aio_fsync            = dfv_fop_aio_fsync,
	.fasync               = dfv_fop_fasync,
	.lock                 = dfv_fop_lock,
	.sendpage             = dfv_fop_sendpage,
	.get_unmapped_area    = dfv_fop_get_unmapped_area,
	.check_flags          = dfv_fop_check_flags,
	.flock                = dfv_fop_flock,
	.splice_write         = dfv_fop_splice_write,
	.splice_read          = dfv_fop_splice_read,
	.setlease             = dfv_fop_setlease,
	.fallocate	      = dfv_fop_fallocate,
};
EXPORT_SYMBOL(dfvfops);

struct vm_operations_struct dfvvmops = {
	.open	      = dfv_vmop_open,
	.close	      = dfv_vmop_close,
	.fault	      = dfv_vmop_fault,
	.page_mkwrite = dfv_vmop_page_mkwrite,
	.access       = dfv_vmop_access
};
EXPORT_SYMBOL(dfvvmops);

static struct kobject *dfv_client_kobj;

static int __init dfv_client_init(void)
{
	int retval;

	INIT_LIST_HEAD(&dfv_file_list);
	INIT_LIST_HEAD(&dfvthread_list);
	INIT_LIST_HEAD(&dfvprocess_list);

	dfv_client_kobj = kobject_create_and_add("control",
						&(THIS_MODULE->mkobj.kobj));
	if (!dfv_client_kobj)
		return -EFAULT;

	retval = sysfs_create_group(dfv_client_kobj, &dfv_attr_group);
	if (retval) {
		kobject_put(dfv_client_kobj);
		return  -EFAULT;
	}

	return 0;
}

static void __exit dfv_client_exit(void)
{

	empty_dfv_file_list();

	kobject_put(dfv_client_kobj);
}

module_init(dfv_client_init);
module_exit(dfv_client_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Core client module for Device File-based I/O Virtualization");
MODULE_LICENSE("Dual BSD/GPL");
