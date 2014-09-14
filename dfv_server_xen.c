/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server_xen.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * Used help from Xen netback driver for setting up, tearing down, and using
 * the Xen ring and event channel:
 *
 * Copyright (c) 2002-2005, K A Fraser
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
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/interface/memory.h>
#include "dfv_common.h"
#include "dfv_server.h"
#include "dfv_common_xen.h"
#include "dfv_server_xen.h"

static DEFINE_MUTEX(dfv_server_xen_mutex);
#define ENTER_CRIT_SEC mutex_lock(&dfv_server_xen_mutex)
#define EXIT_CRIT_SEC mutex_unlock(&dfv_server_xen_mutex)
static DEFINE_MUTEX(dfv_server_xen_mutex2);
#define ENTER_CRIT_SEC2 mutex_lock(&dfv_server_xen_mutex2)
#define EXIT_CRIT_SEC2 mutex_unlock(&dfv_server_xen_mutex2)

static int dfv_server_xen_probe(struct xenbus_device *dev,
			 const struct xenbus_device_id *id)
{
	int err = 0;
	struct dfv_server_xen_info *info =
			kzalloc(sizeof(struct dfv_server_xen_info), GFP_KERNEL);
	if (!info) {
		DFVPRINTK_ERR("Error: allocating backend_info failed\n");
		xenbus_dev_fatal(dev, -ENOMEM,
				 "allocating backend_info structure");
		return -ENOMEM;
	}

	dev_set_drvdata(&dev->dev, info);

	if (dev->state != XenbusStateInitialising) {
		DFVPRINTK_ERR("Error: wrong state.\n");
		goto fail;
	}

	err = xenbus_switch_state(dev, XenbusStateInitWait);
	if (err) {
		DFVPRINTK_ERR("Error: xenbus_switch_state failed.\n");
		goto fail;
	}

	return 0;

fail:
	kfree(info);
	return err;
}

static int dfv_server_xen_uevent(struct xenbus_device *xdev,
			  struct kobj_uevent_env *env)
{

	return 0;
}

static int dfv_unmap_ring(struct xenbus_device *dev,
						struct dfv_server_xen_info *info)
{
	if (info->bring.sring) {

		xenbus_unmap_ring(dev, info->handle, info->bring.sring);
		kfree(info->bring.sring);
	}

#ifdef CONFIG_DFV_TWO_RINGS
	if (info->bring2.sring) {

		xenbus_unmap_ring(dev, info->handle2, info->bring2.sring);
		kfree(info->bring2.sring);
	}
#endif

	return 0;
}

/* Returns the number of successfully copied bytes. */
static unsigned long dfvx_copy_client_user_core(unsigned int cmd,
	struct guest_thread_struct *guest_thread, uint64_t to,
	uint64_t from, uint64_t n, uint16_t flags)
{
	struct xen_copy_domain_user hdata;
	unsigned long grant = (unsigned long) guest_thread->private_data;
	int ret;

	hdata.domid = (domid_t) guest_thread->guest_vm_id;
	hdata.from = (uint64_t) from;
	hdata.to = (uint64_t) to;
	hdata.n = (uint64_t) n;
	hdata.flags = (uint16_t) flags;
	hdata.grant = (uint64_t) grant;

	ret = HYPERVISOR_memory_op(cmd, &hdata);

	if (!ret)
		DFVPRINTK_ERR("Error: 0 bytes were copied.\n");

	return ret;
}

unsigned long dfvx_copy_from_client_user(struct guest_thread_struct *guest_thread,
					struct guest_struct *guest, void *to,
					const void __user *from, unsigned long n)
{
	unsigned long _from = (unsigned long) from;

	return dfvx_copy_client_user_core(XENMEM_copy_from_domain_user,
		guest_thread, (const uint64_t) virt_to_phys(to),
		(uint64_t) _from, (uint64_t) n,
		HVMCOPY_dst_phys | HVMCOPY_src_virt);
}

unsigned long dfvx_copy_to_client_user(struct guest_thread_struct *guest_thread,
				      struct guest_struct *guest, void __user *to,
				      const void *from, unsigned long n)
{
	unsigned long _to = (unsigned long) to;
	void *_from = (void *) from;

	return dfvx_copy_client_user_core(XENMEM_copy_to_domain_user,
		guest_thread, (const uint64_t) _to,
		(uint64_t) virt_to_phys(_from),
		(uint64_t) n, HVMCOPY_dst_virt | HVMCOPY_src_phys);
}

int dfvx_insert_pfn(struct guest_thread_struct *guest_thread,
			  struct guest_struct *guest, struct vm_area_struct *vma,
			  unsigned long addr, unsigned long pfn, pgprot_t prot)
{
	struct xen_map_page_to_domain_user hdata;
	int ret;
	struct vma_map_entry_struct *map_entry;
	struct vma_list_struct *vma_entry;
	pte_t gfn_prot;
	unsigned long grant = (unsigned long) guest_thread->private_data;

	gfn_prot = pte_mkspecial(pfn_pte(0, prot));

	vma_entry = get_vma_entry(guest, vma);
	if (!vma_entry) {
		DFVPRINTK_ERR("Error: could not find the vma_entry\n");
		return -ENOMEM;
	}

	hdata.domid = (domid_t) guest->guest_vm_id;
	hdata.gfn = (uint64_t) pfn;
	hdata.vaddr = (uint64_t) addr;
	hdata.flags = (uint64_t) gfn_prot.pte;
	hdata.grant = (uint64_t) grant;

	ret = HYPERVISOR_memory_op(XENMEM_map_page_to_domain_user, &hdata);

	if (!ret) {
		DFVPRINTK_ERR("Error: dfvx_insert_pfn failed.\n");
		return -ENOMEM;
	}

	map_entry = kmalloc(sizeof(*map_entry),  GFP_KERNEL);
	if (!map_entry) {
		DFVPRINTK_ERR("Error: map_entry allocation failed.\n");
		return -ENOMEM;
	}

	map_entry->addr = addr;
	map_entry->gfn = (unsigned long) ret;
	list_add(&map_entry->list, &vma_entry->gfn_list);

	return 0;
}

int dfvx_revert_pgtables(struct guest_thread_struct *guest_thread,
			struct guest_struct *guest, struct vm_area_struct *vma,
			unsigned long start_addr, unsigned long end_addr)
{
	struct xen_unmap_page_from_domain_user hdata;
	int hret, ret = 0;
	struct vma_map_entry_struct *map_entry, *m_tmp;
	struct vma_list_struct *vma_entry;
	unsigned long grant = (unsigned long) guest_thread->private_data;

	vma_entry = get_vma_entry(guest, vma);
	if (!vma_entry) {
		DFVPRINTK_ERR("Error: could not find the vma_entry\n");
		return -EFAULT;
	}

	hdata.domid = (domid_t) guest->guest_vm_id;
	hdata.grant = (uint64_t) grant;

	list_for_each_entry_safe(map_entry, m_tmp, &vma_entry->gfn_list, list) {

		if (!(map_entry->addr >= start_addr &&
		      map_entry->addr < end_addr))
			continue;

		hdata.gfn = (uint64_t) map_entry->gfn;

		hret = HYPERVISOR_memory_op(XENMEM_unmap_page_from_domain_user,
								&hdata);

		if (hret) {
			DFVPRINTK_ERR("Error: dfvx_revert_pgtables failed.\n");
			ret = -EFAULT;
		}

		list_del(&map_entry->list);
		kfree(map_entry);
	}

	return ret;
}

static int forward_notification(struct guest_struct *guest,
				pid_t guest_thread_id, 	unsigned long type)
{
	RING_IDX rsp_ind;
	struct dfv2_xen_rsp *rsp;
	struct dfv_server_xen_info *ginfo = guest->guest_vm->private_data;

#ifdef CONFIG_DFV_TWO_RINGS

	ENTER_CRIT_SEC2;
	rsp_ind = ginfo->bring2.rsp_prod_pvt;
	rsp = RING_GET_RESPONSE(&ginfo->bring2, rsp_ind);
	ginfo->bring2.rsp_prod_pvt = rsp_ind + 1;

	rsp->type = type;
	rsp->thread_id = guest_thread_id;
	rsp->process_id = guest->guest_id;

	RING_PUSH_RESPONSES(&ginfo->bring2);

	notify_remote_via_irq(ginfo->irq2);
	EXIT_CRIT_SEC2;

#endif

	return 0;
}

void dfvx_send_sigio(struct guest_struct *guest)
{

	forward_notification(guest, 0, DFV_IRQ_SIGIO);
}

void dfvx_send_poll_notification(struct guest_thread_struct *guest_thread)
{

	forward_notification(guest_thread->guest,
				guest_thread->guest_thread_id, DFV_IRQ_POLL);
}

static void dfvx_init_guest_vm(struct guest_vm_struct *guest_vm,
				struct dfv_server_xen_info *ginfo)
{

	/*
	 * This function will be called every time there is a new thread.
	 * Fortunately, the content of this function is re-entrant and has
	 * caused no problems in the past. But that might change in the future.
	 * Therefore, it's best to (test and) use the following two lines
	 * to return immediately after the first call.
	 */

	guest_vm->send_sigio = dfvx_send_sigio;
	guest_vm->copy_from_user = dfvx_copy_from_client_user;
	guest_vm->copy_to_user = dfvx_copy_to_client_user;
	guest_vm->insert_pfn = dfvx_insert_pfn;
	guest_vm->revert_pgtables = dfvx_revert_pgtables;
	guest_vm->send_poll_notification = dfvx_send_poll_notification;

	guest_vm->private_data = (void *) ginfo;
}

static void dfvx_init_guest_thread(struct guest_thread_struct *guest_thread)
{
	guest_thread->use_non_blocking_poll = true;

	guest_thread->need_poll_wait = false;
	guest_thread->poll_sleep = false;
}

static int dfvx_dispatch(struct dfv_xen_req *req, struct dfv_xen_rsp *rsp,
			  int _guest_vm_id,
			  struct guest_thread_struct **guest_thread,
			  struct dfv_server_xen_info *ginfo)
{
	struct parse_args pargs;
	int err;

	err = parse_op_args((struct dfv_op_args *) req, _guest_vm_id, &pargs);

	if (err) {
		DFVPRINTK_ERR("Error: parse_op_args failed.\n");
		return -EFAULT;
	}

	if (pargs.new_guest_thread) {
		dfvx_init_guest_thread(pargs.guest_thread);

		dfvx_init_guest_vm(pargs.guest_thread->guest_vm, ginfo);
	}

	pargs.guest_thread->private_data = (void *) req->grant;

	dispatch_dfv_op((struct dfv_op_args *) req,
		       (struct dfv_op_args *) &(rsp->arg1), &pargs);

	*guest_thread = 	pargs.guest_thread;

	return 0;
}

static void do_work(struct work_struct *work)
{
	RING_IDX req_ind, rsp_ind;
	struct dfv_xen_req lreq, *req;
	struct dfv_xen_rsp lrsp, *rsp;
	int notify, final_check;
	struct guest_thread_struct *guest_thread = NULL;
	bool need_poll_wait = false;
	struct dfv_server_xen_info *ginfo;
	struct dfv_work_struct *dfv_work =
			container_of(work, struct dfv_work_struct, work);

	if (dfv_work == NULL) {
		DFVPRINTK_ERR("Error: dfv_work is NULL\n");
		return;
	}

	ginfo = dfv_work->info;

	ENTER_CRIT_SEC;
	if (!RING_HAS_UNCONSUMED_REQUESTS(&ginfo->bring)) {
		EXIT_CRIT_SEC;
		dfv_work->busy = false;
		return;
	}
	req_ind = ginfo->bring.req_cons;
	req = RING_GET_REQUEST(&ginfo->bring, req_ind);
	ginfo->bring.req_cons = req_ind + 1;
	RING_FINAL_CHECK_FOR_REQUESTS(&ginfo->bring, final_check);
	if (final_check) {
		DFVPRINTK_ERR("Error: there are unconsumed requests "
							"in the ring!\n");
	}
	copy_dfv_req(&lreq, req);

	dfvx_dispatch(&lreq, &lrsp, (int) ginfo->frontend_id, &guest_thread,
									ginfo);

	NEED_POLL_WAIT(guest_thread, need_poll_wait);

	rsp_ind = ginfo->bring.rsp_prod_pvt;
	rsp = RING_GET_RESPONSE(&ginfo->bring, rsp_ind);
	ginfo->bring.rsp_prod_pvt = rsp_ind + 1;
	copy_dfv_rsp(rsp, &lrsp);

	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&ginfo->bring, notify);
	if (notify) {
		notify_remote_via_irq(ginfo->irq);
	}

	EXIT_CRIT_SEC;

	if (need_poll_wait)
		wait_for_poll(guest_thread);
	/* We actively wait a bit for the next operation. */
	/*
	counter = 40;
	while (counter) {
		if (RING_HAS_UNCONSUMED_REQUESTS(&ginfo->bring)) {

		}

		udelay(5);
		counter--;
	}
	*/
	dfv_work->busy = false;
}

static irqreturn_t dfv_server_evtchn_handler(int irq, void *dev_id)
{
	struct work_struct *wrk;
	int work_index;
	struct dfv_server_xen_info *info = (struct dfv_server_xen_info *) dev_id;

	if (info == NULL) {
		DFVPRINTK_ERR("Error: info is NULL\n");
		return IRQ_HANDLED;
	}

again:
	work_index = info->works_counter % NUM_WORKS;
	info->works_counter++;

	if (info->works[work_index].busy) {
		goto again;
	}

	info->works[work_index].busy = true;

	wrk = &info->works[work_index].work;

	queue_work(info->wq, wrk);

	return IRQ_HANDLED;
}

#ifdef CONFIG_DFV_TWO_RINGS

static irqreturn_t dfv_server_evtchn2_handler(int irq, void *dev_id)
{

	return IRQ_HANDLED;
}

#endif

static int setup_ring_and_evtchn(struct xenbus_device *dev,
			struct dfv_server_xen_info *info)
{
	void *addr, *addr2;
	struct dfv_sring *ring;
	struct dfv2_sring *ring2;
	unsigned long paddr, paddr2;
	int err = -ENOMEM;

	/*
	 * FIXME: We don't need to allocate a page here. The ring is already
	 * allocated on the client. When we map the ring, we might actually lose
	 * access to the underlying mfn for the page allocated here. This can
	 * cause crashes later if the kernel reallocates the same page and
	 * tries to use it after we kfree it.
	 */
	addr = kmalloc(PAGE_SIZE, GFP_KERNEL);

	paddr = virt_to_phys(addr);

	err = xenbus_map_ring(dev, info->ring_ref,
					&info->handle, (void *) paddr);

	if (err) {
		DFVPRINTK_ERR("Error: xenbus_map_ring failed, err = %d.\n", err);
		goto err;
	}

	ring = (struct dfv_sring *) addr;
	BACK_RING_INIT(&info->bring, ring, PAGE_SIZE);

#ifdef CONFIG_DFV_TWO_RINGS

	addr2 = kmalloc(PAGE_SIZE, GFP_KERNEL);

	paddr2 = virt_to_phys(addr2);

	err = xenbus_map_ring(dev, info->ring_ref2,
					&info->handle2, (void *) paddr2);

	if (err) {
		DFVPRINTK_ERR("Error: xenbus_map_ring (ring2) failed, "
							"err = %d.\n", err);
		goto err;
	}

	ring2 = (struct dfv2_sring *) addr2;
	BACK_RING_INIT(&info->bring2, ring2, PAGE_SIZE);

#endif

	err = bind_interdomain_evtchn_to_irqhandler(
		info->frontend_id, info->evtchn, dfv_server_evtchn_handler, 0,
		"dfv_server_xen", info);
	if (err < 0) {
		DFVPRINTK_ERR("Error: bind_interdomain_evtchn_to_irqhandler "
					"failed, err = %d\n", err);
		goto err;
	}

	info->irq = err;

#ifdef CONFIG_DFV_TWO_RINGS

	err = bind_interdomain_evtchn_to_irqhandler(
		info->frontend_id, info->evtchn2, dfv_server_evtchn2_handler, 0,
		"dfv_server_xen_sigio", info);
	if (err < 0) {
		DFVPRINTK_ERR("Error: bind_interdomain_evtchn_to_irqhandler "
				"failed (evtchn2), err = %d\n", err);
		goto err;
	}

	info->irq2 = err;

#endif

	return 0;
err:
	dfv_unmap_ring(dev, info);
	return err;
}

static int dfv_server_setup_connection(struct xenbus_device *dev,
						struct dfv_server_xen_info *info)
{
	unsigned long ring_ref, ring_ref2;
	unsigned int evtchn, evtchn2;
	int err, i;

	info->wq = alloc_workqueue("dfv", WQ_HIGHPRI, NUM_WORKS);
	if (!info->wq) {
		DFVPRINTK_ERR("Error: could not create workqueue.\n");
		return -EFAULT;
	}

	for (i = 0; i < NUM_WORKS; i++) {
		INIT_WORK(&info->works[i].work, do_work);
		info->works[i].info = info;
		info->works[i].busy = false;
	}

	mutex_init(&info->mtx1);
	mutex_init(&info->mtx2);

	err = xenbus_gather(XBT_NIL, dev->otherend,
			    "ring-ref", "%lu", &ring_ref,			
			    "event-channel", "%u", &evtchn,
#ifdef CONFIG_DFV_TWO_RINGS		
			    "ring-ref2", "%lu", &ring_ref2,
			    "event-channel2", "%u", &evtchn2,
#endif			
			    NULL);
	if (err) {
		DFVPRINTK_ERR("Error: xenbus_gather failed, err = %d\n", err);
		xenbus_dev_fatal(dev, err,
				 "reading %s/ring-ref and event-channels",
				 dev->otherend);
		return err;
	}

	info->ring_ref = (int) ring_ref;
	info->evtchn = evtchn;
	info->frontend_id = dev->otherend_id;

#ifdef CONFIG_DFV_TWO_RINGS
	info->ring_ref2 = (int) ring_ref2;
	info->evtchn2 = evtchn2;

#endif
	err = setup_ring_and_evtchn(dev, info);
	if (err) {
		DFVPRINTK_ERR("Error: setup_ring_and_evtchn failed, "
						"err = %d.\n", err);
		xenbus_dev_fatal(dev, err, "mapping shared-frames");

		return err;
	}

	return 0;
}

static void dfv_client_xen_changed(struct xenbus_device *dev,
			     enum xenbus_state frontend_state)
{
	struct dfv_server_xen_info *info = (struct dfv_server_xen_info *)
						dev_get_drvdata(&dev->dev);
	if (!info) {
		DFVPRINTK_ERR("Error: info is NULL\n");
		return;
	}

	switch (frontend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
		break;

	case XenbusStateConnected:
		if (dev->state == XenbusStateConnected) {
			DFVPRINTK("frontend is in connected state\n");		
			break;
		}
		if (dev->state != XenbusStateInitWait) {
			DFVPRINTK_ERR("Error: wrong state.\n");
			break;
		}
		dfv_server_setup_connection(dev, info);
		xenbus_switch_state(dev, XenbusStateConnected);
		/* We've reached the state that we want. */
		printk(KERN_INFO "dfv_server is connected to the frontend\n");
		break;

	case XenbusStateClosing:
	case XenbusStateClosed:
		if (dev->state == XenbusStateClosed) {
			break;
		}
		xenbus_switch_state(dev, XenbusStateClosed);

		/* fall through if not online */

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at frontend",
				 frontend_state);
		break;
	}
}

static int dfv_server_xen_remove(struct xenbus_device *dev)
{
	struct dfv_server_xen_info *info = (struct dfv_server_xen_info *)
						dev_get_drvdata(&dev->dev);
	if (!info) {
		DFVPRINTK_ERR("Error: info is NULL\n");
		return -EFAULT;
	}

	if (info->irq) {

		unbind_from_irqhandler(info->irq, info);
	}

	info->evtchn = 0;
	info->irq = 0;

	if (info->ring_ref != GRANT_INVALID_REF && info->bring.sring) {

		xenbus_unmap_ring(dev, info->handle, info->bring.sring);
		kfree(info->bring.sring);

	}

	info->ring_ref = GRANT_INVALID_REF;
	info->bring.sring = NULL;

#ifdef CONFIG_DFV_TWO_RINGS

	if (info->irq2) {

		unbind_from_irqhandler(info->irq2, info);
	}

	info->evtchn2 = 0;
	info->irq2 = 0;

	if (info->ring_ref2 != GRANT_INVALID_REF && info->bring2.sring) {

		xenbus_unmap_ring(dev, info->handle2, info->bring2.sring);
		kfree(info->bring2.sring);
	}

	info->ring_ref2 = GRANT_INVALID_REF;
	info->bring2.sring = NULL;

#endif

	destroy_workqueue(info->wq);

	kfree(info);

	return 0;
}

static struct xenbus_device_id dfv_server_xen_ids[] = {
	{ "dfv" },
	{ "" }
};

static struct xenbus_driver dfv_server_xen = {
	.name = "dfv",
	.owner = THIS_MODULE,
	.ids = dfv_server_xen_ids,
	.probe = dfv_server_xen_probe,
	.uevent = dfv_server_xen_uevent,
	.otherend_changed = dfv_client_xen_changed,
	.remove = dfv_server_xen_remove,
};

static int __init dfv_server_xen_init(void)
{
	int ret = 0;

	ret = xenbus_register_backend(&dfv_server_xen);
	if (ret) {
		DFVPRINTK_ERR("Error: xenbus_register_backend failed "
							"(ret = %d)\n", ret);
		return ret;
	}

	return 0;
}

static void __exit dfv_server_xen_exit(void)
{
	xenbus_unregister_driver(&dfv_server_xen);
}

module_init(dfv_server_xen_init);
module_exit(dfv_server_xen_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Server support for Xen for Device File-based I/O "
		   "Virtualization");
MODULE_LICENSE("GPL");
