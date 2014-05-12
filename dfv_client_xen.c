/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_client_xen.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * Used help from Xen netfront driver for setting up, tearing down, and using
 * the Xen ring and event channel:
 *
 * Virtual network driver for conversing with remote driver backends.
 *
 * Copyright (c) 2002-2005, K A Fraser
 * Copyright (c) 2005, XenSource Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/page.h>
#include "dfv_common.h"
#include "dfv_client.h"
#include "dfv_common_xen.h"
#include "dfv_client_xen.h"

static struct dfv_client_xen_info *ginfo = NULL;
static DECLARE_WAIT_QUEUE_HEAD(wqueue);
static bool results_ready = false;

static DEFINE_MUTEX(dfv_client_xen_mutex);
#define ENTER_CRIT_SEC mutex_lock(&dfv_client_xen_mutex)
#define EXIT_CRIT_SEC mutex_unlock(&dfv_client_xen_mutex)
static DEFINE_MUTEX(dfv_client_xen_mutex2);
#define ENTER_CRIT_SEC2 mutex_lock(&dfv_client_xen_mutex2)
#define EXIT_CRIT_SEC2 mutex_unlock(&dfv_client_xen_mutex2)

struct dfv_gnttab_entry *dfv_gnttab;
DECLARE_BITMAP(dfv_gnttab_bitmap, NR_DFV_GNTTAB_ENTRIES);

static int get_empty_dfv_gnttab_entry_ref(void)
{
	int ref;

	ref = find_first_zero_bit(dfv_gnttab_bitmap, NR_DFV_GNTTAB_ENTRIES);
	if (IS_VALID_REF(ref)) {
		set_bit(ref, dfv_gnttab_bitmap);
		return ref;
	} else {
		return -ENOMEM;
	}
}

static int write_entry_to_dfv_gnttab(int ref, uint64_t start_addr, uint64_t size,
				unsigned long cr3, domid_t domid, uint16_t type,
				uint32_t next_ref)
{
	struct dfv_gnttab_entry *entry;

	if (!IS_VALID_REF(ref)) {
		DFVPRINTK_ERR("Error: invalid ref number (%d)\n", ref);
		return -EINVAL;
	}

	entry = &dfv_gnttab[ref];

	entry->start_addr = start_addr;
	entry->size = size;
	entry->cr3 = cr3;
	entry->domid = domid;
	entry->type = type;
	entry->next_ref = next_ref;

	wmb();

	return 0;
}

static int put_dfv_gnttab_entry(int ref)
{
	struct dfv_gnttab_entry *entry;
	int current_ref;

	current_ref = ref;

	if (!IS_VALID_REF(ref)) {
		DFVPRINTK_ERR("Error: invalid ref number (%d)\n", ref);
		return -EINVAL;
	}

	while (IS_VALID_REF(current_ref)) {

		entry = &dfv_gnttab[current_ref];
		entry->start_addr = 0;
		entry->size = 0;
		entry->domid = 0;
		entry->type = 0;

		clear_bit(current_ref, dfv_gnttab_bitmap);

		current_ref = entry->next_ref;
		entry->next_ref = 0;
	}

	wmb();

	return 0;
}

static unsigned long get_grant(struct dfvthread_struct *dfvthread,
			       struct dfv_xen_req *req, domid_t domid,
			       int *grant_acquired)
{
	int ref;
	int ret = 0;
	unsigned long grant = INVALID_DFV_GNTTAB_REF;

	*grant_acquired = 0;

	switch ((enum dfv_op)(((req->arg1 & 0xffff0000) >> 16) & 0x0000ffff))
	{
	case DFV_FOP_read:
		ref = get_empty_dfv_gnttab_entry_ref();
		ret = write_entry_to_dfv_gnttab(ref, req->arg3, req->arg4,
				(unsigned long) native_read_cr3(), domid,
				GNTTAB_TYPE_COPY_TO_USER,
				INVALID_DFV_GNTTAB_REF);
		if (ret) {
			DFVPRINTK_ERR("Error: write_entry_to_dfv_gnttab for "
				   "read operation failed.\n");
			break;
		}
		grant = (unsigned long) ref;
		*grant_acquired = 1;
		break;

	case DFV_FOP_write:
		ref = get_empty_dfv_gnttab_entry_ref();
		ret = write_entry_to_dfv_gnttab(ref, req->arg3, req->arg4,
				(unsigned long) native_read_cr3(), domid,
				GNTTAB_TYPE_COPY_FROM_USER,
				INVALID_DFV_GNTTAB_REF);
		if (ret) {
			DFVPRINTK_ERR("Error: write_entry_to_dfv_gnttab for "
				   "write operation failed.\n");
			break;
		}
		grant = (unsigned long) ref;
		*grant_acquired = 1;
		break;

	case DFV_FOP_unlocked_ioctl:
	{
		/*
		 * This is the easy but unsecure solution. It basically allows
		 * any memory operation to be executed for ioctl by the driver.
		 */
		ref = get_empty_dfv_gnttab_entry_ref();
		ret = write_entry_to_dfv_gnttab(ref, 0, 0,
				(unsigned long) native_read_cr3(), domid,
				GNTTAB_TYPE_ALL,
				INVALID_DFV_GNTTAB_REF);
		if (ret) {
			DFVPRINTK_ERR("Error: write_entry_to_dfv_gnttab for "
				   "open operation failed.\n");
			break;
		}
		grant = (unsigned long) ref;
		*grant_acquired = 1;
		break;
	}

	case DFV_FOP_mmap:

		ref = get_empty_dfv_gnttab_entry_ref();
		ret = write_entry_to_dfv_gnttab(ref, req->arg3,
				req->arg4 - req->arg3,
				(unsigned long) native_read_cr3(), domid,
				GNTTAB_TYPE_MMAP,
				INVALID_DFV_GNTTAB_REF);
		if (ret) {
			DFVPRINTK_ERR("Error: write_entry_to_dfv_gnttab for "
				   "open operation failed.\n");
			break;
		}
		grant = (unsigned long) ref;
		*grant_acquired = 1;
		break;

	case DFV_EOP_fault1:

		ref = get_empty_dfv_gnttab_entry_ref();
		ret = write_entry_to_dfv_gnttab(ref, req->arg3,
				req->arg4 - req->arg3,
				(unsigned long) native_read_cr3(), domid,
				GNTTAB_TYPE_MMAP,
				INVALID_DFV_GNTTAB_REF);
		if (ret) {
			DFVPRINTK_ERR("Error: write_entry_to_dfv_gnttab for "
				   "open operation failed.\n");
			break;
		}

		dfvthread->private_data = (void *) ref;

		break;

	case DFV_EOP_fault2:

		grant = (unsigned long) dfvthread->private_data;
		*grant_acquired = 1;

		break;

	case DFV_VMOP_close:

		ref = get_empty_dfv_gnttab_entry_ref();
		ret = write_entry_to_dfv_gnttab(ref, req->arg3,
				req->arg4 - req->arg3,
				(unsigned long) native_read_cr3(), domid,
				GNTTAB_TYPE_MUNMAP,
				INVALID_DFV_GNTTAB_REF);
		if (ret) {
			DFVPRINTK_ERR("Error: write_entry_to_dfv_gnttab for "
				   "open operation failed.\n");
			break;
		}
		grant = (unsigned long) ref;
		*grant_acquired = 1;
		break;

	default:

		break;
	}

	return grant;
}

static int release_grant(unsigned long grant)
{
	int ref, ret;

	ref = (int) grant;

	ret = put_dfv_gnttab_entry(ref);

	if (ret) {
		DFVPRINTK_ERR("Error: put_dfv_gnttab_entry failed, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static int init_dfv_gnttab(void)
{
	void *virt_addr, *phys_addr;
	unsigned long paddr;
	int ret;
	struct gnttab_setup_dfv_table hdata;

	bitmap_zero(dfv_gnttab_bitmap, NR_DFV_GNTTAB_ENTRIES);

	dfv_alloc_pages(&virt_addr, &phys_addr, NR_DFV_GNTTAB_PAGES);
	paddr = (unsigned long) phys_addr;

	dfv_gnttab = (struct dfv_gnttab_entry *) virt_addr;

	hdata.gfn = (uint64_t) paddr >> PAGE_SHIFT;
	hdata.nr_frames = 1;

	ret = HYPERVISOR_grant_table_op(GNTTABOP_setup_dfv_table, &hdata, 1);

	if (ret) {
		DFVPRINTK_ERR("Error: dfv grant table hypercall failed, "
			   "ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static int dfv_client_xen_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	struct dfv_client_xen_info *info;

	info = kzalloc(sizeof(struct dfv_client_xen_info), GFP_KERNEL);
	if (!info) {
		DFVPRINTK_ERR("Error: allocating dfv_client_xen_info failed.\n");
		return -ENOMEM;
	}

	dev_set_drvdata(&dev->dev, info);

	return 0;
}

static int dfv_client_xen_resume(struct xenbus_device *dev)
{

	return 0;
}

static irqreturn_t dfv_client_evtchn_handler(int irq, void *dev_id)
{

	results_ready = true;
	wake_up_locked(&wqueue);

	return IRQ_HANDLED;
}

static void service_notification(unsigned long type, unsigned long thread_id,
				 unsigned long process_id)
{

	switch (type) {

	case DFV_IRQ_POLL:
	{
		struct dfvthread_struct *dfvthread;

		dfvthread = get_dfvthread(thread_id, process_id);
		if (dfvthread == NULL) {
			DFVPRINTK_ERR("Error: dfvthread was not found\n");
			break;
		}

		wake_up(dfvthread->wait_queue);

		break;
	}

	case DFV_IRQ_SIGIO:
		kill_fasync(&dfv_fasync, SIGIO, POLL_IN);
		break;
	default:
		DFVPRINTK_ERR("Error: wrong type\n");
		break;
	}
}

static struct work_struct dfvx_notifications_wk;

static void dfvx_handle_notifications(struct work_struct *work)
{
	RING_IDX rsp_ind;
	struct dfv2_xen_rsp *rsp;
	int counter = 0;

	ENTER_CRIT_SEC2;
	while (RING_HAS_UNCONSUMED_RESPONSES(&ginfo->fring2)) {

		counter++;
		rsp_ind = ginfo->fring2.rsp_cons;
		rsp = RING_GET_RESPONSE(&ginfo->fring2, rsp_ind);
		ginfo->fring2.rsp_cons = rsp_ind + 1;
		service_notification(rsp->type, rsp->thread_id, rsp->process_id);
	}
	EXIT_CRIT_SEC2;

}

static irqreturn_t dfv_client_evtchn2_handler(int irq, void *dev_id)
{

	schedule_work(&dfvx_notifications_wk);

	return IRQ_HANDLED;
}

static int destroy_connection(struct dfv_client_xen_info *info)
{

	/*
	 * TODO: double check to make sure this is the correct sequence of
	 * cleaning up.
	 */

	if (info->irq) {
		unbind_from_irqhandler(info->irq, info);
	}

	info->evtchn = 0;
	info->irq = 0;

	if (info->irq2) {
		unbind_from_irqhandler(info->irq2, info);
	}

	info->evtchn2 = 0;
	info->irq2 = 0;

	if (info->ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(info->ring_ref, 0,
					(unsigned long)info->fring.sring);

	info->ring_ref = GRANT_INVALID_REF;
	info->fring.sring = NULL;

	if (info->ring_ref2 != GRANT_INVALID_REF)
		gnttab_end_foreign_access(info->ring_ref2, 0,
					(unsigned long)info->fring2.sring);

	info->ring_ref2 = GRANT_INVALID_REF;
	info->fring2.sring = NULL;

	kfree(info);

	return 0;
}

static int write_config_to_store(struct xenbus_device *dev,
						struct dfv_client_xen_info *info)
{
	const char *message;
	struct xenbus_transaction xbt;
	int err;

repeat:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_ring;
	}

	err = xenbus_printf(xbt, dev->nodename, "ring-ref", "%u",
			    info->ring_ref);
	if (err) {
		message = "writing ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename, "ring-ref2", "%u",
			    info->ring_ref2);
	if (err) {
		message = "writing ring-ref2";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename,
			    "event-channel", "%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename,
			    "event-channel2", "%u", info->evtchn2);
	if (err) {
		message = "writing event-channel2";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto repeat;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_ring;
	}

	return 0;

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, err, "%s", message);
destroy_ring:
	destroy_connection(info);
	return err;
}

static int dfv_client_setup_connection(struct xenbus_device *dev,
						struct dfv_client_xen_info *info)
{
	struct dfv_sring *ring;
	struct dfv2_sring *ring2;
	int err;

	info->ring_ref = GRANT_INVALID_REF;
	info->fring.sring = NULL;
	info->irq = 0;
	info->ring_ref2 = GRANT_INVALID_REF;
	info->fring2.sring = NULL;
	info->irq2 = 0;

	ring = (struct dfv_sring *)get_zeroed_page(GFP_NOIO | __GFP_HIGH);
	if (!ring) {
		err = -ENOMEM;
		DFVPRINTK_ERR("Error: Allocating ring page failed.\n");
		xenbus_dev_fatal(dev, err, "allocating ring page");
		goto fail;
	}
	SHARED_RING_INIT(ring);
	FRONT_RING_INIT(&info->fring, ring, PAGE_SIZE);

	ring2 = (struct dfv2_sring *)get_zeroed_page(GFP_NOIO | __GFP_HIGH);
	if (!ring2) {
		err = -ENOMEM;
		DFVPRINTK_ERR("Error: Allocating ring2 page failed.\n");
		xenbus_dev_fatal(dev, err, "allocating ring2 page");
		goto fail;
	}
	SHARED_RING_INIT(ring2);
	FRONT_RING_INIT(&info->fring2, ring2, PAGE_SIZE);

	info->otherend_id = dev->otherend_id;

	err = xenbus_grant_ring(dev, virt_to_mfn(info->fring.sring));
	if (err < 0) {
		free_page((unsigned long)ring);
		DFVPRINTK_ERR("Error: xenbus_grant_ring failed, "
						"err = %d.\n", err);
		goto fail;
	}
	info->ring_ref = err;

	err = xenbus_grant_ring(dev, virt_to_mfn(info->fring2.sring));
	if (err < 0) {
		free_page((unsigned long)ring2);
		DFVPRINTK_ERR("Error: xenbus_grant_ring (ring2) failed, "
						"err = %d.\n", err);
		goto fail;
	}
	info->ring_ref2 = err;

	err = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (err) {
		DFVPRINTK_ERR("Error: xenbus_alloc_evtchn failed, "
						"err = %d.\n", err);
		goto fail;
	}

	err = bind_evtchn_to_irqhandler(info->evtchn, dfv_client_evtchn_handler,
					0, "dfv_client_xen", info);
	if (err < 0) {
		DFVPRINTK_ERR("Error: bind_evtchn_to_irq failed, "
						"err = %d.\n", err);
		goto fail;
	}

	info->irq = err;

	err = xenbus_alloc_evtchn(dev, &info->evtchn2);
	if (err) {
		DFVPRINTK_ERR("Error: xenbus_alloc_evtchn (evtchn2) failed, "
						"err = %d.\n", err);
		goto fail;
	}

	err = bind_evtchn_to_irqhandler(info->evtchn2, dfv_client_evtchn2_handler,
					0, "dfv_client_notifications", info);
	if (err < 0) {
		DFVPRINTK_ERR("Error: bind_evtchn_to_irq failed (evtchn2), "
						"err = %d.\n", err);
		goto fail;
	}

	info->irq2 = err;

	err = write_config_to_store(dev, info);
	if (err) {
		DFVPRINTK_ERR("Error: write_config_to_store failed, "
						"err = %d.\n", err);
		goto fail;
	}

	ginfo = info;

	return 0;

fail:
	return err;
}

static void dfv_server_xen_changed(struct xenbus_device *dev,
			    enum xenbus_state backend_state)
{
	struct dfv_client_xen_info *info = dev_get_drvdata(&dev->dev);

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
		break;

	case XenbusStateConnected:

		printk(KERN_INFO "dfv_client is connected to the backend\n");
		break;

	case XenbusStateInitWait:
		if (dev->state != XenbusStateInitialising) {
			/*
			 * FIXME: This has been spotted to fire even if the
			 * connection was correctly setup. Look into it.
			 */
			DFVPRINTK_ERR2("Error: wrong state.\n");
			break;
		}
		if (dfv_client_setup_connection(dev, info) != 0) {
			DFVPRINTK_ERR("Error: setup connection failed.\n");
			break;
		}
		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateClosing:
	case XenbusStateClosed:
		if (dev->state == XenbusStateClosed) {
			break;
		}

		xenbus_switch_state(dev, XenbusStateClosed);
		break;

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at backend",
				 backend_state);
		break;
	}

}

static int dfv_client_xen_remove(struct xenbus_device *dev)
{
	struct dfv_client_xen_info *info = (struct dfv_client_xen_info *)
						dev_get_drvdata(&dev->dev);
	return destroy_connection(info);
}

static struct xenbus_device_id dfv_client_xen_ids[] = {
	{ "dfv" },
	{ "" }
};

static struct xenbus_driver dfv_client_xen = {
	.name = "dfv",
	.owner = THIS_MODULE,
	.ids = dfv_client_xen_ids,
	.probe = dfv_client_xen_probe,
	.remove = dfv_client_xen_remove,
	.resume = dfv_client_xen_resume,
	.otherend_changed = dfv_server_xen_changed,
};

static int forward_operation(struct dfvthread_struct *dfvthread,
			struct dfv_xen_req *ireq, struct dfv_xen_rsp *irsp)
{
	RING_IDX req_ind, rsp_ind;
	struct dfv_xen_req *req;
	struct dfv_xen_rsp *rsp;
	int notify, final_check;
	bool got_rsp = false;
	unsigned long grant;
	int ret, grant_acquired;

	if (!ginfo) {
		DFVPRINTK_ERR("Error: the ring/evtchn are not set up yet.\n");
		return -EFAULT;
	}

	ENTER_CRIT_SEC;
	req_ind = ginfo->fring.req_prod_pvt;
	req = RING_GET_REQUEST(&ginfo->fring, req_ind);
	ginfo->fring.req_prod_pvt = req_ind + 1;
	copy_dfv_req(req, ireq);

	grant = get_grant(dfvthread, req, ginfo->otherend_id, &grant_acquired);
	req->grant = grant;

	spin_lock_irq(&wqueue.lock);

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&ginfo->fring, notify);

	if (notify) {
		notify_remote_via_irq(ginfo->irq);
	}

	/* if no response was received, sleep and wait for notifications */
	if (!got_rsp) {
wait:
		results_ready = false;

		wait_event_interruptible_locked_irq(wqueue, results_ready);
		if (!RING_HAS_UNCONSUMED_RESPONSES(&ginfo->fring)) {
			goto wait;
		}
		spin_unlock_irq(&wqueue.lock);
	}

	rsp_ind = ginfo->fring.rsp_cons;
	rsp = RING_GET_RESPONSE(&ginfo->fring, rsp_ind);
	ginfo->fring.rsp_cons = rsp_ind + 1;
	copy_dfv_rsp(irsp, rsp);

	if (grant_acquired) {
		ret = release_grant(grant);
		if (ret) {
			DFVPRINTK_ERR("Error: release_grant failed, ret = %d.\n", ret);
		}
	}

	RING_FINAL_CHECK_FOR_RESPONSES(&ginfo->fring, final_check);
	if (final_check) {
		DFVPRINTK_ERR("Error: there are unconsumed responses in the ring!\n");
	}

	EXIT_CRIT_SEC;

	return 0;
}

static int apply_to_ptes_fn(pte_t *pte, pgtable_t token,
		unsigned long addr, void *data)
{
	return 0;
}

void dfvx_dispatch(struct dfvthread_struct *dfvthread,
	struct dfv_op_args *req_args, struct dfv_op_args *res_args, void *data)
{
	enum dfv_op op = ((req_args->arg_1 & 0xffff0000) >> 16) & 0x0000ffff;

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

	forward_operation(dfvthread, (struct dfv_xen_req *) req_args,
			 (struct dfv_xen_rsp *) res_args);

}

void dfvx_init_op(struct dfvthread_struct *dfvthread,
		struct dfv_op_all_args *local_args, struct dfv_op_args **req_args,
		struct dfv_op_args **res_args)
{

	*req_args = (struct dfv_op_args *) local_args;
	*res_args = (struct dfv_op_args *) &(local_args->res_arg_1);
}

void dfvx_init_dfvprocess(struct dfvprocess_struct *dfvprocess)
{
	/* Nothing to do for now */
}

void dfvx_init_dfvthread(struct dfvthread_struct *dfvthread)
{

	dfvthread->dispatch = dfvx_dispatch;
	dfvthread->init_op = dfvx_init_op;
	dfvthread->use_non_blocking_poll = true;
}

static int __init dfv_client_xen_init(void)
{
	int ret = 0;

	ret = xenbus_register_frontend(&dfv_client_xen);
	if (ret) {
		DFVPRINTK_ERR("Error: xenbus_register_frontend failed "
							"(ret = %d)\n", ret);
		return ret;
	}

	INIT_WORK(&dfvx_notifications_wk, dfvx_handle_notifications);

	ret = init_dfv_gnttab();
	if (ret) {
		DFVPRINTK_ERR("Error: Initializing dfv_gnttab failed.\n");
		return ret;
	}

	ret = set_init_dfvprocess(dfvx_init_dfvprocess);
	if (ret) {
		DFVPRINTK_ERR("Error: could not set init_dfvprocess\n");
		return ret;
	}

	ret = set_init_dfvthread(dfvx_init_dfvthread);
	if (ret) {
		DFVPRINTK_ERR("Error: could not set init_dfvthread\n");
		return ret;
	}

	return 0;
}

static void __exit dfv_client_xen_exit(void)
{
	xenbus_unregister_driver(&dfv_client_xen);
}

module_init(dfv_client_xen_init);
module_exit(dfv_client_xen_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Client support for Xen for Device File-based I/O "
		   "Virtualization");
MODULE_LICENSE("GPL");
