/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server.c
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
#include <linux/pagemap.h>
#include "dfv_linux_code.h"
#include "dfv_common.h"
#include "dfv_server.h"
#include "dfv_drm.h"

struct list_head guest_vm_list;
struct list_head guest_list;
struct list_head guest_thread_list;

static struct dfv_state *add_dfvstate(struct guest_struct *guest)
{
	struct dfv_state *dfvstate = NULL;
	dfvstate = kmalloc(sizeof(*dfvstate), GFP_KERNEL);
	dfvstate->serverfd = guest->serverfd;

	list_add(&dfvstate->list, &guest->dfv_device_list);

	return dfvstate;
}

static struct dfv_state *get_dfvstate(struct guest_struct *guest, int sfd)
{
	struct dfv_state *dfvstate = NULL;

	list_for_each_entry(dfvstate, &guest->dfv_device_list, list) {

		if (dfvstate->serverfd == sfd) {
			return dfvstate;
		}
	}

	return NULL;
}

static int remove_dfvstate(struct guest_struct *guest, int sfd)
{
	struct dfv_state *dfvstate = NULL, *d_tmp;

	if (!guest) {
		DFVPRINTK_ERR("Error: guest is NULL\n");
		return -EINVAL;
	}

	list_for_each_entry_safe(dfvstate, d_tmp, &guest->dfv_device_list, list) {

		if (dfvstate->serverfd == sfd) {
			list_del(&dfvstate->list);
			kfree(dfvstate);
			return 0;
		}
	}

	return -EINVAL;
}

static void dfv_fop_open(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int fd;
	int index = 0;
	struct file *file = NULL;
	struct inode *inode = NULL;
	char *dfvpathname;
	struct dfv_state *new_dfvstate;
	struct guest_struct *guest = guest_thread->guest;

	/*
	 * Preventing a overflow. The serverfd is passed to the client using
	 * a 32-bit entry (for 32-bit architectures that we support currently).
	 * While serverfd of 0xFFFFFFFF is still valid (it is
	 * the last one before we overflow), we throw error at this point to
	 * prevent the overflow in the next open.
	 *
	 * TODO: we should reclaim the released serverfds in the release
	 * file operation.
	 */
	if (guest->serverfd == 0xFFFFFFFF) {
		DFVPRINTK_ERR("Error: serverfd is too large.\n");
		OPEN_RESULT = -EINVAL;
		return;
	}

	dfvpathname = get_pathname_from_abs_name((int) OPEN_PATHNAME);

	if (dfvpathname == NULL) {
		DFVPRINTK_ERR("Error: No equivalent pathname was found.\n");
		OPEN_RESULT = -EINVAL;
		return;
	}

	fd = sys_open_kernel(dfvpathname, OPEN_FLAGS, OPEN_MODE, &file);
	inode = file->f_path.dentry->d_inode;

	OPEN_SERVERFD = guest->serverfd;

	new_dfvstate = add_dfvstate(guest);
	if (new_dfvstate == NULL) {
		DFVPRINTK_ERR("Error: could not create new_dfvstate\n");
		OPEN_RESULT = -EFAULT;
		goto out_err;
	}

	new_dfvstate->file     = file;
	new_dfvstate->inode    = inode;
	new_dfvstate->fdtable  = current->files;
	new_dfvstate->fd = fd;

	guest_thread->num_open_fds++;
	guest->num_open_fds++;
	guest->guest_vm->num_open_fds++;

	guest->serverfd++;

	/*
	 * If a file operation is not defined on the server,
	 * then it should be null on the client as well!
	 */
	OPEN_SERVERFOPS = 0;
	#define DFVFO(x) {						\
		index = dfvbitmap[DFV_FOP_ ## x].bitmap_index;		\
		DFVPRINTK("file operation: " #x "=%#x\n",		\
			(unsigned int) file->f_op->x);			\
		if ((file->f_op->x) != NULL) {				\
			OPEN_SERVERFOPS |= (1 << index);		\
		}							\
	}
	DFV_FILE_OPERATIONS
	#undef DFVFO

	OPEN_RESULT = 0;
	OPRES_POSITION = 0;

	return;

/*
 * The num_open_fds of guest_thread, guest, and guest VM should not
 * have been increased before jumping here. Otherwise, we need
 * to revert that.
 */
out_err:
	remove_dfvstate(guest, guest->serverfd);
	remove_guest_thread(guest_thread);

	if (file->f_op->release)
		file->f_op->release(inode, file);

}

static void dfv_fop_read(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct file *file;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		READ_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;

	if ((!file) || (!file->f_op) || (!file->f_op->read)) {
		DFVPRINTK_ERR("Error: device read function not specified.\n");
		READ_RESULT = -EINVAL;
		return;
	}

	result = file->f_op->read(file,
		(char __user *) READ_BUF,
		(size_t) READ_COUNT,
		(loff_t *) &READ_OFFSET);

	OPRES_POSITION = file->f_pos;
	READ_RESULT = result;
	READ_NEWOFFSET = READ_OFFSET;
}

static void dfv_fop_write(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct file *file;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		WRITE_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;

	if ((!file) || (!file->f_op) || (!file->f_op->write)) {
		DFVPRINTK_ERR("Error: device write function not specified.\n");
		WRITE_RESULT = -EINVAL;
		return;
	}

	result = file->f_op->write(file,
		(char __user *) WRITE_BUF,
		(size_t) WRITE_COUNT,
		(loff_t *) &WRITE_OFFSET);

	OPRES_POSITION = file->f_pos;
	WRITE_NEWOFFSET = WRITE_OFFSET;
	WRITE_RESULT = result;
}

static inline bool is_valid_poll_result(int result, unsigned int key)
{
	if ( ((key & POLLIN_SET) && (result & POLLIN_SET))
	  || ((key & POLLIN_SET) && (result & POLLIN_SET))
	  || ((key & POLLIN_SET) && (result & POLLIN_SET)) )
		return true;

	return false;
}

static void dfv_fop_poll(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	ktime_t expires, *to = NULL;
	struct file *file;
	unsigned int key = POLL_KEY;
	unsigned long slack = 0;
	int timed_out = 0;
	poll_table *wait = NULL;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		POLL_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;

	if ((!file) || (!file->f_op) || (!file->f_op->poll)) {
		DFVPRINTK_ERR("Error: device poll function not specified\n");
		POLL_RESULT = -EINVAL;
		return;
	}

	if (guest_thread->use_non_blocking_poll && guest_thread->poll_sleep &&
	    POLL_NULLKEY == 0) {

		wake_up(guest_thread->poll_wait_queue);
	}

	if (POLL_NULLKEY == 0) {

		guest_thread->table = kmalloc(sizeof(*guest_thread->table),
								GFP_KERNEL);

		poll_initwait(guest_thread->table);
		wait = &guest_thread->table->pt;

		wait->key = key;

		if (guest_thread->use_non_blocking_poll)
			poll_wait(file, guest_thread->poll_wait_queue, wait);
	}

	result = file->f_op->poll(file, wait);

	/*
	 * Blocking poll is useful if the communication latency between the
	 * client and the server is high.
	 */
	if (!guest_thread->use_non_blocking_poll && POLL_NULLKEY == 0) {

	  	if (is_valid_poll_result(result, key)) {
			goto no_wait;
	  	}

		slack = POLL_SLACK;
		timed_out = 0;

		if (POLL_WAIT_TIME != POLL_INFINITE_WAIT) {
			/*
			 * Yes, we are ignoring the latency of communication from
			 * the client to the server, which is a few to a few tens
			 * of microseconds.
			 */
			expires = ktime_add_ns(ktime_get(), POLL_WAIT_TIME);

			to = &expires;
		}

		if (!poll_schedule_timeout(guest_thread->table,
						TASK_INTERRUPTIBLE, to, slack))
			timed_out = 1;

		if (!timed_out) {

			/*
			 * Technically, we should call file->f_op->poll()
			 * here to get the result. Given that there was no
			 * time-out, it makes sense to directly return the
			 * result (unless the driver returns something else
			 * other than (POLLIN | POLLRDNORM), in which case
			 * this code will be wrong). Directly returning the
			 * result helped with the accelerometer
			 * in Rio, since calling the poll returns 0 due to the
			 * fact that the server itself calls poll first. Ideally,
			 * we should disable the server from using the sensor
			 * at the exact same time, but this technique of
			 * returning the result directly here gives us the
			 * ability to support both the server and the client
			 * at the same time.
			 */
			result = POLLIN | POLLRDNORM;

		}

no_wait:

		poll_freewait(guest_thread->table);
		kfree(guest_thread->table);
		guest_thread->table = NULL;
	}
	else if (guest_thread->use_non_blocking_poll && POLL_NULLKEY == 0) {

		if (!is_valid_poll_result(result, key)) {

			guest_thread->need_poll_wait = true;
			guest_thread->poll_wait_time = POLL_WAIT_TIME;
			guest_thread->poll_slack = POLL_SLACK;
			guest_thread->poll_file = file;
			guest_thread->poll_key = key;
		}
		else {

			poll_freewait(guest_thread->table);
			kfree(guest_thread->table);
			guest_thread->table = NULL;
			guest_thread->need_poll_wait = false;
		}
	}

	OPRES_POSITION = file->f_pos;
	POLL_RESULT = result;
}

void wait_for_poll(struct guest_thread_struct *guest_thread)
{
	int timed_out = 0;
	ktime_t expires, *to = NULL;
	unsigned long slack = guest_thread->poll_slack;
	int result;
	struct poll_wqueues *table;

	/*
	 * guest->thread->table might change so we use table in the rest of this
	 * function.
	 * FIXME: The next two lines need to be done atomically.
	 * preempt_*able() is not enough.
	 */
	preempt_disable();
	table = guest_thread->table;
	guest_thread->table = NULL;
	preempt_enable();

	if (guest_thread->poll_wait_time != POLL_INFINITE_WAIT) {
		expires = ktime_add_ns(ktime_get(), guest_thread->poll_wait_time);
		to = &expires;
	}
	guest_thread->poll_sleep = true; /* FIXME: need a lock here */
	if (!poll_schedule_timeout(table, TASK_INTERRUPTIBLE, to, slack)) {
		timed_out = 1;

	}
	guest_thread->poll_sleep = false;

	poll_freewait(table);
	kfree(table);

	if (!timed_out) {
		result = guest_thread->poll_file->f_op->poll(
						guest_thread->poll_file, NULL);
		if (is_valid_poll_result(result, guest_thread->poll_key)) {

			guest_thread->guest_vm->send_poll_notification(guest_thread);
		}
	}
}
EXPORT_SYMBOL(wait_for_poll);

static int dfv_insert_vma(struct guest_struct *guest,
						struct vm_area_struct *new_vma)
{
	struct vma_list_struct *vma_entry = kmalloc(sizeof(*vma_entry),
								GFP_KERNEL);

	vma_entry->vma = new_vma;
	INIT_LIST_HEAD(&vma_entry->gfn_list);
	INIT_LIST_HEAD(&vma_entry->pfn_list);
	list_add(&vma_entry->list, &guest->vma_list);

	return 1;
}

int __dfv_add_vma(struct vm_area_struct *vma)
{
	struct guest_struct *guest = NULL;
	struct guest_thread_struct *guest_thread = NULL;
	guest = (struct guest_struct *) current->dfvguest;
	guest_thread = (struct guest_thread_struct *) current->dfvguest_thread;
	dfv_insert_vma(guest, vma);

	return 0;
}

static struct vm_area_struct *dfv_find_vma_by_range(struct guest_struct *guest,
			unsigned long startaddr, unsigned long endaddr)
{
	struct vma_list_struct *vma_entry = NULL;
	list_for_each_entry(vma_entry, &guest->vma_list, list) {

		 if (vma_entry->vma->vm_start == startaddr
		 && vma_entry->vma->vm_end == endaddr) {

			return vma_entry->vma;
		}
	}

	DFVPRINTK_ERR("Error: could not find the vma\n");
	return NULL;
}

static int dfv_remove_vma(struct guest_struct *guest, unsigned long startaddr,
				unsigned long endaddr)
{
	struct vma_list_struct *vma_entry = NULL, *v_tmp;

	list_for_each_entry_safe(vma_entry, v_tmp, &guest->vma_list, list) {

		 if (vma_entry->vma->vm_start == startaddr
		 && vma_entry->vma->vm_end == endaddr) {

			list_del(&vma_entry->list);
			kfree(vma_entry->vma);
			kfree(vma_entry);
			return 1;
		}
	}

	DFVPRINTK_ERR("Error: could not find the vma\n");
	return 0;
}

struct vma_list_struct *get_vma_entry(struct guest_struct *guest,
				       struct vm_area_struct *vma)
{
	struct vma_list_struct *vma_entry = NULL;
	list_for_each_entry(vma_entry, &guest->vma_list, list) {

		if (vma_entry->vma == vma) {
			return vma_entry;
		}
	}

	DFVPRINTK_ERR("Error: could not find the vma_entry\n");
	return NULL;
}
EXPORT_SYMBOL(get_vma_entry);

struct vma_list_struct *get_vma_entry_by_addr(struct guest_struct *guest,
						unsigned long addr)
{
	struct vma_list_struct *vma_entry = NULL;
	struct vm_area_struct *vma;

	list_for_each_entry(vma_entry, &guest->vma_list, list) {

		vma = vma_entry->vma;

		if (addr >= vma->vm_start && addr < vma->vm_end) {
			return vma_entry;
		}
	}

	DFVPRINTK_ERR("Error: could not find the vma_entry\n");
	return NULL;
}
/* FIXME: might not be needed. */
EXPORT_SYMBOL(get_vma_entry_by_addr);

static void dfv_fop_mmap(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int index = 0;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct vm_area_struct *vma = NULL;
	unsigned long startaddr = MMAP_STARTADDR;
	unsigned long endaddr   = MMAP_ENDADDR;
	unsigned long vmflags   = MMAP_VMFLAGS;
	unsigned long pgoff     = MMAP_PGOFF;
	struct file *file;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		MMAP_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;

	if ((!file) || (!file->f_op) || (!file->f_op->mmap)) {
		DFVPRINTK_ERR("Error: device mmap function not specified.\n");
		MMAP_RESULT = -EINVAL;
		return;
	}

	vma = kmalloc(sizeof(*vma), GFP_KERNEL);

	if (!vma) {
		DFVPRINTK_ERR("Error: out of memory\n");
		MMAP_RESULT = -ENOMEM;
		return;
	}

	vma->vm_mm = current->mm;
	vma->vm_start = startaddr;
	vma->vm_end = endaddr;
	vma->vm_flags = vmflags;
	vma->vm_page_prot = vm_get_page_prot(vmflags);
	vma->vm_pgoff = pgoff;
	vma->vm_file = file;

	dfv_insert_vma(guest, vma);

	result = file->f_op->mmap(file, vma);

	MMAP_SERVERVMOPS = 0;

	/* Don't continue if mmap failed. */
	if (result) {
		MMAP_RESULT = result;
		goto err_out;
	}

	if (!vma->vm_ops) {
		goto add_close;
	}

	#define DFVVMO(x) {						\
		index = dfvbitmap[DFV_VMOP_ ## x].bitmap_index;		\
		DFVPRINTK("VM operation: " #x "=%#x\n",			\
			(unsigned int) vma->vm_ops->x);			\
		if ((vma->vm_ops->x) != NULL) {				\
			MMAP_SERVERVMOPS |= (1 << index);		\
		}							\
	}
	DFV_VM_OPERATIONS
	#undef DFVVMO

	/*
	 * We need our dfv_vmop_close to be called, regardless of whether the
	 * driver implements the vma_ops->close operation or not. We need it so
	 * that we can clean up the mmapped pages.
	 */
add_close:
	index = dfvbitmap[DFV_VMOP_close].bitmap_index;
	MMAP_SERVERVMOPS |= (1 << index);

	OPRES_POSITION = file->f_pos;
	MMAP_RESULT = result;
	MMAP_NEWVMFLAGS = vma->vm_flags;

err_out:

	return;
}

static void dfv_fop_unlocked_ioctl(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	unsigned int cmd = UNLOCKED_IOCTL_CMD;
	unsigned long arg = UNLOCKED_IOCTL_ARG;
	struct file *file;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate, "
			   "guest_vm_id=%d, guest_id = %d, sfd=%d\n",
			   guest->guest_vm_id, guest->guest_id, sfd);
		UNLOCKED_IOCTL_RESULT = -EINVAL;

		return;
	}

	file = proxy->file;

	if ((!file) || (!file->f_op) || (!file->f_op->unlocked_ioctl)) {
		DFVPRINTK_ERR("Error: device unlocked_ioctl function not specified\n");
		UNLOCKED_IOCTL_RESULT = -EINVAL;
		return;
	}

	result = file->f_op->unlocked_ioctl(file, cmd, arg);

	OPRES_POSITION = file->f_pos;
	UNLOCKED_IOCTL_RESULT = result;

}

static void dfv_fop_llseek(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct file *file;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("dfv_fop_llseek: Error: could not find dfvstate\n");
		LLSEEK_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;

	if ((!file) || (!file->f_op) || (!file->f_op->llseek)) {
		DFVPRINTK_ERR("Error: device llseek function not specified\n");
		LLSEEK_RESULT = -EINVAL;
		return;
	}

	result = file->f_op->llseek(file,
		(loff_t) LLSEEK_OFFSET,
		(int) LLSEEK_DIRECTION);

	OPRES_POSITION = file->f_pos;
	LLSEEK_RESULT = result;
}

static void dfv_fop_flush(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct file *file;
	fl_owner_t id;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		FLUSH_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;
	id = proxy->fdtable;

	if ((!file) || (!file->f_op) || (!file->f_op->flush)) {
		DFVPRINTK_ERR("Error: device flush function not specified\n");
		FLUSH_RESULT = -EINVAL;
		return;
	}

	result = file->f_op->flush(file, id);

	OPRES_POSITION = file->f_pos;
	FLUSH_RESULT = result;
}

static void dfv_fop_release(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int remove_result;
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct file *file;
	struct inode *inode;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		RELEASE_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;
	inode = proxy->inode;

	if ((!file) || (!file->f_op) || (!file->f_op->release)) {
		DFVPRINTK_ERR("Error: device release function not specified\n");
		RELEASE_RESULT = -EINVAL;
		return;
	}

	result = file->f_op->release(inode, file);

	remove_result = remove_dfvstate(guest, sfd);
	if (remove_result) {
		DFVPRINTK_ERR("Error: could not remove dfvstate\n");
	}

	guest_thread->num_open_fds--;
	guest->num_open_fds--;
	guest->guest_vm->num_open_fds--;
	remove_guest_thread(guest_thread);

	OPRES_POSITION = file->f_pos;
	RELEASE_RESULT = result;
}

static void mark_file_as_dfv(struct file *filp)
{
	struct fown_struct *fown;

	if (filp) {
                fown = &filp->f_owner;
		fown->dfv_own = 1;
	}     
}

static void dfv_fop_fasync(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct file *file;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		FASYNC_RESULT = -EINVAL;
		return;
	}

	file = proxy->file;

	mark_file_as_dfv(file);

	if ((!file) || (!file->f_op) || (!file->f_op->fasync)) {
		DFVPRINTK_ERR("Error: device fasync function not specified\n");
		FASYNC_RESULT = -EINVAL;
		return;
	}

	if (!file->private_data)
		DFVPRINTK_ERR("Error: no private_data!\n");

	result = file->f_op->fasync(proxy->fd, file, (int) FASYNC_ON);

	FASYNC_RESULT = result;
}

/*
 * FIXME: for now, we share this work between all guests. This is because
 * the work is used for injecting sigio interrupts to the foreground guest
 * only, and there will be no contention. If this model changes at any time, the
 * work can be moved to the guest_struct or guest_vm_struct to be specific
 * to each guest or guest_vm.
 */
static struct work_struct dfv_sigio_wq; /* work for sigio interrupts */

static void dfv_send_sigio_wq(struct work_struct *work)
{
#ifdef CONFIG_X86
	struct guest_struct *fg_guest = NULL;

	if (get_fg_guest)
		fg_guest = (*get_fg_guest)();
	else
		DFVPRINTK_ERR("Error: get_fg_guest is NULL\n");

	if (fg_guest)
		fg_guest->guest_vm->send_sigio(fg_guest);
#endif /* CONFIG_X86 */
}

/*
 * This routine gets called in interrupt context. Therefore, it cannot
 * contain code that may sleep.
 */
void __dfv_send_sigio(struct fown_struct *fown, int fd, int band)
{
	schedule_work(&dfv_sigio_wq);
}

#define UNSUPPORTED_FOP_FUNCTION(func) 						\
	static void func(struct guest_thread_struct *guest_thread, 		\
		struct dfv_op_args *req_args, struct dfv_op_args *res_args)	\
	{									\
		DFVPRINTK_ERR("Error: unsupported file operation: "		\
			#func "\n");						\
	}

UNSUPPORTED_FOP_FUNCTION(dfv_fop_aio_read)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_aio_write)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_readdir)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_ioctl)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_compat_ioctl)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_fsync)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_aio_fsync)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_lock)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_sendpage)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_get_unmapped_area)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_check_flags)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_flock)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_splice_write)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_splice_read)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_setlease)
UNSUPPORTED_FOP_FUNCTION(dfv_fop_fallocate)

/* Support for mmap ops: */

static void dfv_vmop_open(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct guest_struct *guest = guest_thread->guest;
	struct vm_area_struct * vma = NULL;
	unsigned long startaddr = VM_OPEN_STARTADDR;
	unsigned long endaddr   = VM_OPEN_ENDADDR;
	unsigned long vmflags   = VM_OPEN_VMFLAGS;
	unsigned long pgoff     = VM_OPEN_PGOFF;

	vma = dfv_find_vma_by_range(guest, startaddr, endaddr);

	if (vma) {
		if ((!vma->vm_ops) || (!vma->vm_ops->open)) {
			DFVPRINTK_ERR("Error: vmop open not specified.\n");
			return;
		}

		vma->vm_flags = vmflags;
		vma->vm_page_prot = vm_get_page_prot(vmflags);
		vma->vm_pgoff = pgoff;
		vma->vm_ops->open(vma);
	} else {
		DFVPRINTK_ERR("Error: operation failed\n");
	}
}

static void dfv_vmop_close(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct guest_struct *guest = guest_thread->guest;
	struct vm_area_struct * vma = NULL;
	unsigned long startaddr = VM_CLOSE_STARTADDR;
	unsigned long endaddr   = VM_CLOSE_ENDADDR;
	unsigned long vmflags   = VM_CLOSE_VMFLAGS;
	unsigned long pgoff     = VM_CLOSE_PGOFF;

	vma = dfv_find_vma_by_range(guest, startaddr, endaddr);

	/*
	 * FIXME: This shouldn't happen, but shouldn't we call
	 * revert_pgtables() even if vma is NULL?
	 */
	if (vma) {

		vma->vm_flags = vmflags;
		vma->vm_page_prot = vm_get_page_prot(vmflags);
		vma->vm_pgoff = pgoff;

		if (vma->vm_ops && vma->vm_ops->close)
			vma->vm_ops->close(vma);

		guest_thread->guest_vm->revert_pgtables(guest_thread, guest,
						vma, startaddr, endaddr-1);

		dfv_remove_vma(guest, startaddr, endaddr);
	} else {
		DFVPRINTK_ERR("Error: operation failed\n");
	}
}

static void dfv_eop_fault1(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	unsigned long vma_startaddr      = FAULT1_STARTADDR;
	unsigned long vma_endaddr        = FAULT1_ENDADDR;
	unsigned long vma_vmflags        = FAULT1_VMFLAGS;
	unsigned long vma_pgoff          = FAULT1_PGOFF;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		FAULT1_RESULT = -EINVAL;
		return;
	}

	guest_thread->dfvvma = dfv_find_vma_by_range(guest, vma_startaddr, vma_endaddr);

	if (guest_thread->dfvvma) {
		guest_thread->dfvvma->vm_flags = vma_vmflags;
		guest_thread->dfvvma->vm_page_prot = vm_get_page_prot(vma_vmflags);
		guest_thread->dfvvma->vm_pgoff = vma_pgoff;
		FAULT1_RESULT = 0;
	} else {
		FAULT1_RESULT = VM_FAULT_ERROR;
	}
}

static void dfv_eop_fault2(struct guest_thread_struct *guest_thread,
			struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int result = -EFAULT;
	struct vm_fault vmf;
	unsigned int vmf_flags           = FAULT2_FLAGS;
	pgoff_t vmf_pgoff                = FAULT2_PGOFF;
	unsigned long vmf_virtual_address = FAULT2_VIRTADDR;
	int sfd = OPREQ_SERVERFD;
	struct guest_struct *guest = guest_thread->guest;
	struct dfv_state *proxy = get_dfvstate(guest, sfd);

	if (proxy == NULL) {
		DFVPRINTK_ERR("Error: could not find dfvstate\n");
		FAULT2_RESULT = -EINVAL;
		return;
	}

	if (guest_thread->dfvvma) {
		if ((!guest_thread->dfvvma->vm_ops) ||
				(!guest_thread->dfvvma->vm_ops->fault)) {
			DFVPRINTK_ERR("Error: vmop fault not specified.\n");
			FAULT2_RESULT = VM_FAULT_ERROR;
			return;
		}

		vmf.virtual_address = (void __user *) vmf_virtual_address;
		vmf.flags = vmf_flags;
		vmf.pgoff = vmf_pgoff;
		vmf.page = NULL;

		result = guest_thread->dfvvma->vm_ops->fault(guest_thread->dfvvma,
									&vmf);

		/*
		 * the fault handler might return the page rather than
		 * installing it. In this case, we install the page here
		 */
		 /* FIXME: we should merge the first two cases. */
		if (result & VM_FAULT_LOCKED) {
			int insert_ret;
			unsigned long pfn;

			pfn = page_to_pfn(vmf.page);
			guest_thread->dfvvma->vm_flags |= VM_MIXEDMAP;
			guest_thread->dfvvma->vm_flags |= VM_WRITE;
			pgprot_val(guest_thread->dfvvma->vm_page_prot) |= VM_WRITE;
			guest_thread->dfvvma->vm_mm = current->mm;

			insert_ret = vm_insert_mixed(guest_thread->dfvvma,
						vmf_virtual_address, pfn);

			if (!insert_ret) {
				FAULT2_RESULT = VM_FAULT_NOPAGE;

			}
			else {
				FAULT2_RESULT = VM_FAULT_ERROR;
			}

			if (PageLocked(vmf.page)) {
				unlock_page(vmf.page);
			}

		}
		else if (result == 0 && vmf.page) {
			int insert_ret;
			unsigned long pfn;

			pfn = page_to_pfn(vmf.page);
			guest_thread->dfvvma->vm_flags |= VM_MIXEDMAP;
			guest_thread->dfvvma->vm_flags |= VM_WRITE;
			pgprot_val(guest_thread->dfvvma->vm_page_prot) |= VM_WRITE;
			guest_thread->dfvvma->vm_mm = current->mm;

			insert_ret = vm_insert_mixed(guest_thread->dfvvma,
						vmf_virtual_address, pfn);

			if (!insert_ret) {
				FAULT2_RESULT = VM_FAULT_NOPAGE;

			}
			else {
				FAULT2_RESULT = VM_FAULT_ERROR;
			}

			put_page(vmf.page);

			if (PageLocked(vmf.page)) {
				unlock_page(vmf.page);
			}

		}
		else {
			FAULT2_RESULT = result;
		}

	} else {
		FAULT2_RESULT = VM_FAULT_ERROR;
	}
}

#define UNSUPPORTED_VMOP_FUNCTION(func) 					\
	static void func(struct guest_thread_struct *guest_thread,		\
		struct dfv_op_args *req_args, struct dfv_op_args *res_args)	\
	{									\
		DFVPRINTK_ERR("Error: unsupported vm operation: "		\
			#func "\n");						\
	}

UNSUPPORTED_VMOP_FUNCTION(dfv_vmop_page_mkwrite)
UNSUPPORTED_VMOP_FUNCTION(dfv_vmop_access)
#ifdef CONFIG_NUMA
UNSUPPORTED_VMOP_FUNCTION(dfv_vmop_set_policy)
UNSUPPORTED_VMOP_FUNCTION(dfv_vmop_get_policy)
UNSUPPORTED_VMOP_FUNCTION(dfv_vmop_migrate)
#endif
UNSUPPORTED_VMOP_FUNCTION(dfv_vmop_fault)

unsigned long dfv_server_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{

	DFVPRINTK_ERR("Error: Not supported.\n");

	return -ENOMEM;
}

void dfv_server_unmap_area(struct mm_struct *mm, unsigned long addr)
{
	DFVPRINTK_ERR("Error: Not supported.\n");

}

struct dfvdispatchcontrol dfvdispatchcontrol[] = {
#ifdef CONFIG_NUMA
	{dfv_vmop_open},
	{dfv_vmop_close},
	{dfv_vmop_fault},
	{dfv_vmop_page_mkwrite},
	{dfv_vmop_access},
	{dfv_vmop_set_policy},
	{dfv_vmop_get_policy},
	{dfv_vmop_migrate},
#else
	{dfv_vmop_open},
	{dfv_vmop_close},
	{dfv_vmop_fault},
	{dfv_vmop_page_mkwrite},
	{dfv_vmop_access},
	{NULL},
	{NULL},
	{NULL},
#endif

	{dfv_eop_fault1},
	{dfv_eop_fault2},

	{dfv_fop_llseek},
	{dfv_fop_read},
	{dfv_fop_write},
	{dfv_fop_aio_read},
	{dfv_fop_aio_write},
	{dfv_fop_readdir},
	{dfv_fop_poll},
	{dfv_fop_ioctl},
	{dfv_fop_unlocked_ioctl},
	{dfv_fop_compat_ioctl},
	{dfv_fop_mmap},
	{dfv_fop_open},
	{dfv_fop_flush},
	{dfv_fop_release},
	{dfv_fop_fsync},
	{dfv_fop_aio_fsync},
	{dfv_fop_fasync},
	{dfv_fop_lock},
	{dfv_fop_sendpage},
	{dfv_fop_get_unmapped_area},
	{dfv_fop_check_flags},
	{dfv_fop_flock},
	{dfv_fop_splice_write},
	{dfv_fop_splice_read},
	{dfv_fop_setlease},
	{dfv_fop_fallocate},
};
/* FIXME: might not be needed. */
EXPORT_SYMBOL(dfvdispatchcontrol);

struct guest_vm_struct *add_guest_vm(pid_t guest_vm_id)
{
	struct guest_vm_struct *guest_vm;

	guest_vm = kzalloc(sizeof(struct guest_vm_struct), GFP_KERNEL);
	guest_vm->guest_vm_id = guest_vm_id;
	guest_vm->num_open_fds = 0;

	list_add(&guest_vm->list, &guest_vm_list);

	return guest_vm;
}
/* FIXME: might not be needed. */
EXPORT_SYMBOL(add_guest_vm);

struct guest_vm_struct *get_guest_vm(pid_t guest_vm_id)
{
	struct guest_vm_struct *guest_vm = NULL;

	list_for_each_entry(guest_vm, &guest_vm_list, list) {

		if (guest_vm->guest_vm_id == guest_vm_id) {
			return guest_vm;
		}
	}

	return NULL;
}
/* FIXME: might not be needed. */
EXPORT_SYMBOL(get_guest_vm);

void remove_guest_vm(struct guest_vm_struct *_guest_vm)
{
	struct guest_vm_struct *guest_vm = NULL, *tmp;

	list_for_each_entry_safe(guest_vm, tmp, &guest_vm_list, list) {

		if (guest_vm == _guest_vm && guest_vm->num_open_fds <= 0) {
			list_del(&guest_vm->list);
			kfree(guest_vm);
		}
	}
}
EXPORT_SYMBOL(remove_guest_vm);

struct guest_struct *add_guest(pid_t guest_vm_id, pid_t guest_id)
{
	struct guest_struct *guest;

	guest = kzalloc(sizeof(struct guest_struct), GFP_KERNEL);
	guest->guest_vm_id = guest_vm_id;
	guest->guest_id = guest_id;
	guest->serverfd = 0;
	guest->num_open_fds = 0;

	guest->guest_vm = get_guest_vm(guest_vm_id);
	if (guest->guest_vm == NULL) {
		guest->guest_vm = add_guest_vm(guest_vm_id);
		if (guest->guest_vm == NULL) {
			DFVPRINTK_ERR("Error: new guest_vm cound not be added, "
				   "guest_vm_id = %d\n", guest_vm_id);
			return NULL;
		}
	}
	else {
	}

	INIT_LIST_HEAD(&guest->vma_list);
	INIT_LIST_HEAD(&guest->dfv_device_list);
	list_add(&guest->list, &guest_list);

	return guest;
}

struct guest_struct *get_guest(pid_t guest_vm_id, pid_t guest_id)
{
	struct guest_struct *guest = NULL;

	list_for_each_entry(guest, &guest_list, list) {

		if (guest->guest_vm_id == guest_vm_id &&
		    guest->guest_id == guest_id) {
			return guest;
		}
	}

	return NULL;
}

void remove_guest(struct guest_struct *_guest)
{
	struct guest_struct *guest = NULL, *tmp;
	struct guest_vm_struct *guest_vm;

	list_for_each_entry_safe(guest, tmp, &guest_list, list) {

		if (guest == _guest && guest->num_open_fds <= 0) {
			guest_vm = guest->guest_vm;
			list_del(&guest->list);
			kfree(guest);
			remove_guest_vm(guest_vm);
		}
	}
}

struct guest_thread_struct *add_guest_thread(pid_t guest_vm_id,
				pid_t guest_id, pid_t guest_thread_id)
{
	struct guest_thread_struct *guest_thread;
	static DECLARE_WAIT_QUEUE_HEAD(wait_queue);

	guest_thread = kzalloc(sizeof(struct guest_thread_struct), GFP_KERNEL);
	guest_thread->guest_vm_id = guest_vm_id;
	guest_thread->guest_id = guest_id;
	guest_thread->guest_thread_id = guest_thread_id;
	guest_thread->num_open_fds = 0;
	guest_thread->poll_wait_queue = &wait_queue;

	guest_thread->guest = get_guest(guest_vm_id, guest_id);
	if (guest_thread->guest == NULL) {
		guest_thread->guest = add_guest(guest_vm_id, guest_id);
		if (guest_thread->guest == NULL) {
			DFVPRINTK_ERR("Error: new guest could not be added, "
				"guest_vm_id = %d, guest_id = %d\n",
				guest_vm_id, guest_id);
			return NULL;
		}
	}
	guest_thread->guest_vm = guest_thread->guest->guest_vm;

	list_add(&guest_thread->list, &guest_thread_list);

	return guest_thread;
}
/* FIXME: might not be needed. */
EXPORT_SYMBOL(add_guest_thread);

struct guest_thread_struct *get_guest_thread(pid_t guest_vm_id,
				pid_t guest_id, pid_t guest_thread_id)
{
	struct guest_thread_struct *guest_thread = NULL;

	list_for_each_entry(guest_thread, &guest_thread_list, list) {

		if (guest_thread->guest_vm_id == guest_vm_id &&
		    guest_thread->guest_id == guest_id &&
		    guest_thread->guest_thread_id == guest_thread_id) {
			return guest_thread;
		}
	}

	return NULL;
}
/* FIXME: might not be needed. */
EXPORT_SYMBOL(get_guest_thread);

void remove_guest_thread(struct guest_thread_struct *_guest_thread)
{
	struct guest_thread_struct *guest_thread = NULL, *tmp;
	struct guest_struct *guest;

	list_for_each_entry_safe(guest_thread, tmp, &guest_thread_list, list) {

		if (guest_thread == _guest_thread &&
		    guest_thread->num_open_fds <= 0) {
			guest = guest_thread->guest;
			list_del(&guest_thread->list);
			if (guest_thread->clean_guest_thread)
				(*guest_thread->clean_guest_thread)(guest_thread);
			kfree(guest_thread);
			remove_guest(guest);
		}
	}
}
EXPORT_SYMBOL(remove_guest_thread);

unsigned long __dfv_copy_from_user(void *to, const void __user *from,
							unsigned long n)
{
	unsigned long ret, success_len;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	current->dfvcontext = false;

	success_len = guest_vm->copy_from_user(guest_thread, guest, to, from, n);

	ret = n - success_len;

	/* TODO: add check for case success_len > n. Is it possible at all? */
	/* TODO: if success_len < n, copy_from_user needs to zero the remainder
	 * of the kernel memory */

	current->dfvcontext = true;
	return ret;
}

unsigned long __dfv_copy_to_user(void __user *to, const void *from,
							unsigned long n)
{
	unsigned long ret, success_len;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	current->dfvcontext = false;

	success_len = guest_vm->copy_to_user(guest_thread, guest, to, from, n);

	ret = n - success_len;

	/* TODO: add check for case success_len > n. Is it possible at all? */

	current->dfvcontext = true;
	return ret;
}

int __dfv_get_user(void *to, const void __user *from, unsigned long n)
{
	int ret;
	unsigned long success_len;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	current->dfvcontext = false;

	success_len = guest_vm->copy_from_user(guest_thread, guest, to, from, n);

	if (success_len == n)
		ret = 0;
	else
		ret = -EFAULT;

	current->dfvcontext = true;
	return ret;
}

int __dfv_put_user(void __user *to, const void *from, unsigned long n)
{
	int ret;
	unsigned long success_len;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	current->dfvcontext = false;

	success_len = guest_vm->copy_to_user(guest_thread, guest, to, from, n);

	if (success_len == n)
		ret = 0;
	else
		ret = -EFAULT;

	current->dfvcontext = true;
	return ret;
}

long __dfv_strncpy_from_user(char *dst, const char __user *src, long count)
{
	long ret;
	unsigned long success_len;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	current->dfvcontext = false;

	success_len = guest_vm->copy_from_user(guest_thread, guest, (void *) dst,
			(const void __user *) src, count);

	ret = count - 1;

	/*
	 * FIXME: strncpy_from_user returns the size of the copied bytes
	 * ignoring the NUL terminator. Here we don't check for NUL terminator
	 * at all and return count-1. Besides, we are doing extra copy
	 * if the NUL terminator comes before count bytes.
	 */

	current->dfvcontext = true;
	return ret;
}

unsigned long __dfv_clear_user(void __user *to, unsigned long n)
{
	current->dfvcontext = false;

	DFVPRINTK_ERR("Error: not implemented\n");

	/* returns the number of bytes that failed to get clear */
	current->dfvcontext = true;
	return n;
}

long __dfv_strnlen_user(const char __user *s, long n)
{
	current->dfvcontext = false;

	DFVPRINTK_ERR("Error: not implemented\n");

	/* if NUL terminator is not found within n bytes,
	 * n is returned. */
	 current->dfvcontext = true;
	return n;
}

int __dfv_insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page, pgprot_t prot)
{
	int ret;
	unsigned long pfn;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	current->dfvcontext = false;

	pfn = page_to_pfn(page);

	ret = guest_vm->insert_pfn(guest_thread, guest, vma, addr, pfn, prot);

	current->dfvcontext = true;

	return ret;
}

int __dfv_insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, pgprot_t prot)
{
	int ret;
	struct page *page;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	current->dfvcontext = false;

	page = pfn_to_page(pfn);

	ret = guest_vm->insert_pfn(guest_thread, guest, vma, addr, pfn, prot);

	page = pfn_to_page(pfn);

	current->dfvcontext = true;

	return ret;
}

int __dfv_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long pfn, unsigned long size, pgprot_t prot)
{
	unsigned long cur_pfn = pfn, cur_addr = addr;
	int ret = 0;
	struct guest_thread_struct *guest_thread = current->dfvguest_thread;
	struct guest_struct *guest = guest_thread->guest;
	struct guest_vm_struct *guest_vm = guest->guest_vm;

	while (cur_addr < addr + size) {

		ret = guest_vm->insert_pfn(guest_thread, guest, vma, cur_addr,
							cur_pfn, prot);

		cur_addr += PAGE_SIZE;
		cur_pfn++;
	}

	return ret;
}

unsigned long __dfv_range_not_ok(const void __user *addr, long size)
{

	/* FIXME: For now, we assume the address range is OK. Need to check. */
	return 0;
}

unsigned long __dfv_copy_from_user_inatomic(void *to, const void __user *from,
							unsigned long n)
{

	return __dfv_copy_from_user(to, from, n);
}

unsigned long __dfv_copy_from_user_ll_nocache_nozero(void *to,
				const void __user *from, unsigned long n)
{

	return __dfv_copy_from_user(to, from, n);
}

unsigned long __dfv_copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
{

	return __dfv_copy_to_user(to, from, n);
}
/* helper routines for fault handlers for drivers - end */

int parse_op_args(struct dfv_op_args *req_args, int _guest_vm_id,
		  struct parse_args *pargs)
{
	struct guest_thread_struct *guest_thread = NULL;
	pid_t guest_thread_id, guest_id, guest_vm_id;
	bool new_guest_thread = false;
	enum dfv_op op;

	guest_vm_id = (pid_t) _guest_vm_id;

	guest_id = OPREQ_ID & 0xffff0000;
	guest_id = guest_id >> 16;
	guest_id = guest_id & 0x0000ffff;
	guest_thread_id = OPREQ_ID & 0x0000ffff;

	guest_thread = get_guest_thread(guest_vm_id, guest_id,
							guest_thread_id);

	if (guest_thread == NULL) {
		guest_thread = add_guest_thread(guest_vm_id, guest_id,
							guest_thread_id);
		if (guest_thread == NULL) {
			DFVPRINTK_ERR("Error: guest_thread could not be added\n");

			return -EFAULT;
		}
		new_guest_thread = true;
	}

	OPREQ_OP = OPREQ_OP_SERVERFD & 0xffff0000;
	OPREQ_OP = OPREQ_OP >> 16;
	OPREQ_OP = OPREQ_OP & 0x0000ffff;
	OPREQ_SERVERFD = OPREQ_OP_SERVERFD & 0x0000ffff;

	op = OPREQ_OP;

	if (op >= DFV_OP_numops) {
		DFVPRINTK_ERR("Error: invalid op = %d\n", (unsigned int) op);
		return -EINVAL;
	}

	pargs->guest_thread = guest_thread;
	pargs->new_guest_thread = new_guest_thread;
	pargs->op = op;

	return 0;
}
EXPORT_SYMBOL(parse_op_args);

void dispatch_dfv_op(struct dfv_op_args *req_args, struct dfv_op_args *res_args,
		    struct parse_args *pargs)
{

	current->dfvguest = pargs->guest_thread->guest;
	current->dfvguest_thread = pargs->guest_thread;

	current->dfvcontext = true;

	dfvdispatchcontrol[pargs->op].func(pargs->guest_thread,
						req_args, res_args);

	current->dfvcontext = false;
}
EXPORT_SYMBOL(dispatch_dfv_op);

static struct kobject *dfv_server_kobj;

static int __init dfv_server_init(void)
{
	int retval;

	dfv_copy_from_user = __dfv_copy_from_user;
	dfv_copy_to_user = __dfv_copy_to_user;
	dfv_get_user = __dfv_get_user;
	dfv_put_user = __dfv_put_user;
	dfv_strncpy_from_user = __dfv_strncpy_from_user;
	dfv_clear_user = __dfv_clear_user;
	dfv_strnlen_user = __dfv_strnlen_user;
	dfv_insert_page = __dfv_insert_page;
	dfv_insert_pfn = __dfv_insert_pfn;
	dfv_remap_pfn_range = __dfv_remap_pfn_range;
	dfv_range_not_ok = __dfv_range_not_ok;
	dfv_copy_from_user_inatomic = __dfv_copy_from_user_inatomic;
	dfv_copy_from_user_ll_nocache_nozero =
					__dfv_copy_from_user_ll_nocache_nozero;
	dfv_copy_to_user_inatomic = __dfv_copy_to_user_inatomic;
#ifdef CONFIG_X86
	dfv_send_sigio = __dfv_send_sigio;
#endif /* CONFIG_X86 */

	INIT_LIST_HEAD(&dfv_file_list);
	INIT_LIST_HEAD(&guest_vm_list);
	INIT_LIST_HEAD(&guest_list);
	INIT_LIST_HEAD(&guest_thread_list);
	INIT_WORK(&dfv_sigio_wq, dfv_send_sigio_wq);

	dfv_server_kobj = kobject_create_and_add("control",
						&(THIS_MODULE->mkobj.kobj));
	if (!dfv_server_kobj)
		return -EFAULT;

	retval = sysfs_create_group(dfv_server_kobj, &dfv_attr_group);
	if (retval) {
		kobject_put(dfv_server_kobj);
		return -EFAULT;
	}

	return 0;
}

static void __exit dfv_server_exit(void)
{

	empty_dfv_file_list();

	kobject_put(dfv_server_kobj);

}

module_init(dfv_server_init);
module_exit(dfv_server_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Core server module for Device File-based I/O Virtualization");
MODULE_LICENSE("Dual BSD/GPL");
