/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_client_kvm.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include "dfv_common.h"
#include "dfv_client.h"
#include "dfv_common_kvm.h"
#include "dfv_client_kvm.h"

static DEFINE_MUTEX(dfv_client_kvm_mutex);
#define ENTER_CRIT_SEC mutex_lock(&dfv_client_kvm_mutex)
#define EXIT_CRIT_SEC mutex_unlock(&dfv_client_kvm_mutex)
static DEFINE_MUTEX(dfv_client_kvm_mutex2);
#define ENTER_CRIT_SEC2 mutex_lock(&dfv_client_kvm_mutex2)
#define EXIT_CRIT_SEC2 mutex_unlock(&dfv_client_kvm_mutex2)

/* For now, we use one global waitqueue for all dfvthreads. */
static DECLARE_WAIT_QUEUE_HEAD(dfvthread_wait_queue);

static int apply_to_ptes_fn(pte_t *pte, pgtable_t token,
		unsigned long addr, void *data)
{
	return 0;
}

static void dfvk_dispatch(struct dfvthread_struct *dfvthread,
	struct dfv_op_args *req_args, struct dfv_op_args *res_args, void *data)
{
	unsigned long *sh_page = dfvthread->private_data;
	long hret;
	enum dfv_op op = ((req_args->arg_1 & 0xffff0000) >> 16) & 0x0000ffff;

	ENTER_CRIT_SEC;

	if (op == DFV_FOP_mmap) {

		struct vm_area_struct *vma = data;

		/*
		 * This will ensure that all page table entries, except
		 * for the last level, are populated.
		 */
		if (!vma || apply_to_page_range(vma->vm_mm, vma->vm_start,
					   vma->vm_end - vma->vm_start,
					   apply_to_ptes_fn, NULL)) {
			DFVPRINTK_ERR("Error: apply_to_page_range() failed.\n");
			MMAP_RESULT = -EFAULT;
			return;
		}
	}

	DFVK_RES_ARGS_READY = 0;
	DFVK_REQ_ARG_5 = req_args->arg_5;
	DFVK_REQ_ARG_6 = req_args->arg_6;
	smp_mb(); /* FIXME: do we need this here? */

	hret = kvm_hypercall4(KVM_HC_DFV_OP, req_args->arg_1, req_args->arg_2,
		       req_args->arg_3, req_args->arg_4);

	wait_event(dfvthread_wait_queue, DFVK_RES_ARGS_READY);

	EXIT_CRIT_SEC;
}

void dfvk_init_op(struct dfvthread_struct *dfvthread,
		struct dfv_op_all_args *local_args, struct dfv_op_args **req_args,
		struct dfv_op_args **res_args)
{
	unsigned long *sh_page = dfvthread->private_data;

	*req_args = (struct dfv_op_args *) local_args;
	*res_args = (struct dfv_op_args *) (sh_page + DFVK_SH_PAGE_RES_OFF);
}

/* allocate and share a page with the host */
int dfvk_share_page(struct dfvthread_struct *dfvthread)
{
	void *virt_addr;
	void *phys_addr;
	pfn_t pfn;
	int ret;
	struct file dummy_file;
	struct file *dummy_filp = &dummy_file;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;

	ret = dfv_alloc_pages(&virt_addr, &phys_addr, 1);
	if (ret) {
		DFVPRINTK_ERR("Error: could not allocate a page\n");
			return -1;
	}
	pfn = ((unsigned long)phys_addr) >> PAGE_SHIFT;

	dfvthread->private_data = virt_addr;

	dummy_filp->private_data = NULL;
	INIT_OP(dfvthread, dummy_filp, DFV_OP_custom, local_args, req_args,
								res_args);

	DFVK_CUSTOM_OP = DFVK_CUSTOM_OP_SHARE_PAGE;

	DFVK_CUSTOM_SHARE_PAGE_GFN = pfn;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	if (DFVK_CUSTOM_SHARE_PAGE_RESULT == -1) {
		DFVPRINTK_ERR("Error: could not share page with "
			   "the host\n");
		return -1;
	}

	return 0;
}

unsigned long *irq_page = NULL;

int dfvk_set_up_irq_page(void)
{
	int ret, retval = 0;
	void *irq_page_virt_addr, *irq_page_phys_addr;
	pfn_t irq_pfn;
	struct file dummy_file;
	struct file *dummy_filp = &dummy_file;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;
	bool dfvthread_added = false;

	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		dfvthread = add_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
		if (dfvthread == NULL) {
			DFVPRINTK_ERR("Error: dfvthread could not be added\n");
			return -EINVAL;
		}
		dfvthread_added = true;
	}

	ret = dfv_alloc_pages(&irq_page_virt_addr, &irq_page_phys_addr, 1);
	if (ret) {
		DFVPRINTK_ERR("Error: could not allocate a page\n");
		retval = -1;
		goto out;
	}

	irq_pfn = ((unsigned long)irq_page_phys_addr) >> PAGE_SHIFT;
	irq_page = irq_page_virt_addr;

	memset(irq_page, 0x0, PAGE_SIZE);

	dummy_filp->private_data = NULL;
	INIT_OP(dfvthread, dummy_filp, DFV_OP_custom, local_args, req_args,
								res_args);

	DFVK_CUSTOM_OP = DFVK_CUSTOM_OP_IRQ_PAGE;
	DFVK_CUSTOM_IRQ_PAGE_GFN = irq_pfn;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	if (DFVK_CUSTOM_IRQ_PAGE_RESULT == -1) {
		DFVPRINTK_ERR("Error: could not share page with "
			   "the host\n");
		retval = -1;
		goto out;
	}

	retval = 0;
out:
	if (dfvthread_added)
		remove_dfvthread(dfvthread);

	return retval;
}

static int dfvk_finish_vm(void)
{
	struct file dummy_file;
	struct file *dummy_filp = &dummy_file;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;
	bool dfvthread_added = false;

	/*
	 * We will clean up this dfvthread soon after we're done in here.
	 */
	dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
	if (dfvthread == NULL) {
		dfvthread = add_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
		if (dfvthread == NULL) {
			DFVPRINTK_ERR("Error: dfvthread could not be added\n");
			return -EINVAL;
		}
		dfvthread_added = true;
	}

	dummy_filp->private_data = NULL;
	INIT_OP(dfvthread, dummy_filp, DFV_OP_custom, local_args, req_args,
								res_args);

	DFVK_CUSTOM_OP = DFVK_CUSTOM_OP_FINISH_VM;

	dfvthread->dispatch(dfvthread, req_args, res_args, NULL);

	if (dfvthread_added)
		remove_dfvthread(dfvthread);

	return 0;
}

static void dfvk_clean_dfvthread(struct dfvthread_struct *dfvthread)
{
	free_pages_exact(dfvthread->private_data, PAGE_SIZE); /* the shared page */
}

static void dfvk_init_dfvprocess(struct dfvprocess_struct *dfvprocess)
{
	/* Nothing to do here for now */
}

static void dfvk_init_dfvthread(struct dfvthread_struct *dfvthread)
{
	dfvthread->dispatch = dfvk_dispatch;
	dfvthread->init_op = dfvk_init_op;
	dfvthread->clean_dfvthread = dfvk_clean_dfvthread;
	dfvthread->use_non_blocking_poll = true;
	if (dfvk_share_page(dfvthread) == -1) {
		kfree(dfvthread);
		DFVPRINTK_ERR("Error: dfvk_share_page failed\n");
		return;
	}
}

unsigned long irq_custom_counter = 0;
unsigned long irq_poll_counter = 0;
unsigned long irq_sigio_counter = 0;
unsigned long irq_drm_foregrnd_counter = 0;
unsigned long irq_drm_backgrnd_counter = 0;

static irqreturn_t dfvk_irq_handler(int irq, void *dev_id)
{
	unsigned long irq_process_id;
	unsigned long irq_thread_id;
	struct dfvthread_struct *dfvthread;

	ENTER_CRIT_SEC2;

	/* NULL irq_page happens on the first share_page op before the irq_page op */
	if (!irq_page) {

		wake_up(&dfvthread_wait_queue);
		goto out;
	}

	if (irq_page[DFV_IRQ_CUSTOM + DFVK_IRQ_TYPE_OFF] != irq_custom_counter) {

		irq_custom_counter = irq_page[DFV_IRQ_CUSTOM + DFVK_IRQ_TYPE_OFF];
		wake_up(&dfvthread_wait_queue);

	}

	if (irq_page[DFV_IRQ_POLL + DFVK_IRQ_TYPE_OFF] != irq_poll_counter) {

		irq_poll_counter = irq_page[DFV_IRQ_POLL + DFVK_IRQ_TYPE_OFF];
		irq_process_id = *(irq_page + DFV_IRQ_PROCESS_ID);
		irq_thread_id = *(irq_page + DFV_IRQ_THREAD_ID);
		dfvthread = get_dfvthread(irq_thread_id, irq_process_id);
		if (dfvthread == NULL)
			DFVPRINTK_ERR("Error: dfvthread was not found\n");
		else
			wake_up_interruptible(dfvthread->wait_queue);

	}

	if (irq_page[DFV_IRQ_SIGIO + DFVK_IRQ_TYPE_OFF] != irq_sigio_counter) {

		irq_sigio_counter = irq_page[DFV_IRQ_SIGIO + DFVK_IRQ_TYPE_OFF];
		kill_fasync(&dfv_fasync, SIGIO, POLL_IN);

	}

	if (irq_page[DFV_IRQ_DRM_FOREGRND + DFVK_IRQ_TYPE_OFF]
						!= irq_drm_foregrnd_counter) {

		irq_drm_foregrnd_counter =
			irq_page[DFV_IRQ_DRM_FOREGRND + DFVK_IRQ_TYPE_OFF];
		/* FIXME: SIGUSR1 might only work with X Server */
		if (current_dfv_task) {
			send_sig_info(SIGCONT, SEND_SIG_FORCED, current_dfv_task);
			send_sig_info(SIGUSR1, SEND_SIG_FORCED, current_dfv_task);
		} else {
			DFVPRINTK_ERR("Error: current_dfv_task is NULL");
		}

	}

	if (irq_page[DFV_IRQ_DRM_BACKGRND + DFVK_IRQ_TYPE_OFF]
						!= irq_drm_backgrnd_counter) {

		irq_drm_backgrnd_counter =
			irq_page[DFV_IRQ_DRM_BACKGRND + DFVK_IRQ_TYPE_OFF];
		if (current_dfv_task) {
			send_sig_info(SIGSTOP, SEND_SIG_FORCED, current_dfv_task);
		}
		else {
			DFVPRINTK_ERR("Error: current_dfv_task is NULL");
		}

	}

out:
	EXIT_CRIT_SEC2;

	return IRQ_HANDLED;
}

static int __init dfv_client_kvm_init(void)
{
	unsigned long flags = 0;
	const char *dev_name = "dfvclient";
	void *dev_id = NULL;
	int ret;

	request_irq(DFVK_IRQ_NUM, dfvk_irq_handler, flags, dev_name, dev_id);

	ret = set_init_dfvprocess(dfvk_init_dfvprocess);
	if (ret) {
		DFVPRINTK_ERR("Error: could not set init_dfvprocess\n");
		return ret;
	}

	ret = set_init_dfvthread(dfvk_init_dfvthread);
	if (ret) {
		DFVPRINTK_ERR("Error: could not set init_dfvthread\n");
		return ret;
	}

	dfvk_set_up_irq_page();

	return 0;
}

static void __exit dfv_client_kvm_exit(void)
{

	void *dev_id = NULL;

	dfvk_finish_vm();

	free_irq(DFVK_IRQ_NUM, dev_id);
}

module_init(dfv_client_kvm_init);
module_exit(dfv_client_kvm_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Client support for KVM for Device File-based I/O "
		   "Virtualization");
MODULE_LICENSE("GPL");
