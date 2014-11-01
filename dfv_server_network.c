/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server_network.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *          Bojun Wang <bwang0202@gmail.com>
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
#include <net/sock.h>
#include "dfv_common.h"
#include "ksocket.h"
#include "dfv_common_network.h"
#include "dfv_dsm.h"
#include "dfv_server.h"
#include "dfv_server_network.h"
#ifdef CONFIG_DFV_SUPPORT_ION
#include <linux/ion.h>
#include <linux/omap_ion.h>
#endif /* CONFIG_DFV_SUPPORT_ION */

static int port = 4444;
module_param(port, int, 0444);

static ksocket_t sockfd_srv;
/*
 * FIXME: these two globals are the reason we can't support two guests
 * at the same time. Get rid of them.
 */
struct guest_struct *gguest;
static ksocket_t g_sockfd_cli;

#ifdef CONFIG_DFV_SUPPORT_ION
struct ion_client *dfv_ion_client = NULL;
struct list_head dfv_ion_list;
#endif /* CONFIG_DFV_SUPPORT_ION */

static int send_to_client(struct dfvn_guest_thread_data *thread_data,
							char *buffer, int len)
{
	int ret;
	bool orig_dfvcontext;

	orig_dfvcontext = current->dfvcontext;
	current->dfvcontext = false; /* ksend() has user memory reference */
	ret = dfvn_send(thread_data->sockfd, buffer, len);
	current->dfvcontext = orig_dfvcontext;

	return ret;
}

static int receive_from_client(struct dfvn_guest_thread_data *thread_data,
							char *buffer, int len)
{
	int ret;
	bool orig_dfvcontext;

	orig_dfvcontext = current->dfvcontext;
	current->dfvcontext = false; /* krecv() has user memory reference */
	ret = dfvn_receive(thread_data->sockfd, buffer, len);
	current->dfvcontext = orig_dfvcontext;

	return ret;
}

static int dfvserver_send_dsm_msg(void *buffer, int len, void **data)
{
	struct dfvn_guest_thread_data *thread_data = *data;
	struct guest_thread_struct *guest_thread;

	if (!thread_data) {

		guest_thread = current->dfvguest_thread;
		if (!guest_thread) {
			DFVPRINTK_ERR("Error: Could not find guest_thread\n");
			return -EINVAL;
		}

		thread_data = guest_thread->private_data;
		*data = thread_data;
	}

	return send_to_client(thread_data, (char *) buffer, len);
}

static int dfvserver_receive_dsm_msg(void *buffer, int len, void **data)
{
	struct dfvn_guest_thread_data *thread_data = *data;
	struct guest_thread_struct *guest_thread;

	if (!thread_data) {

		guest_thread = current->dfvguest_thread;
		if (!guest_thread) {
			DFVPRINTK_ERR("Error: Could not find guest_thread\n");
			return -EINVAL;
		}

		thread_data = guest_thread->private_data;
		*data = thread_data;
	}

	return receive_from_client(thread_data, (char *) buffer, len);
}

static int get_from_prefetched_data(struct dfvn_data_struct *dds,
			void *to, const void __user *from, unsigned long n)
{
	int i;
	unsigned long offset, _from = (unsigned long) from;

	for(i = 0; i < DFVN_DATA_MAX_ENTRIES; i++) {
		if (((__u64) _from)  >= dds[i].addr &&
		    ((__u64) (_from + n)) <= (dds[i].addr + dds[i].size)) {
			offset = _from - dds[i].addr;
			memcpy(to, dds[i].ptr+offset, n);

			return n;
		    }
	}

	DFVPRINTK_ERR("Error: did not find the data\n");

	return -EFAULT;
}

static int update_prefetched_data(struct dfvn_data_struct *dds,
			void __user *to, const void *from, unsigned long n)
{
	int i;
	unsigned long offset, _to = (unsigned long) to;

	for(i = 0; i < DFVN_DATA_MAX_ENTRIES; i++) {
		if (((__u64) _to) >= dds[i].addr &&
		    ((__u64) (_to + n)) <= (dds[i].addr + dds[i].size)) {
			offset = (unsigned long) (_to - dds[i].addr);
			memcpy(dds[i].ptr + offset, from, n);
			return n;
		    }
	}

	return -EFAULT;
}

/* Returns the number of successfully copied bytes */
unsigned long dfvn_copy_from_client_user(struct guest_thread_struct *guest_thread,
					struct guest_struct *guest, void *to,
					const void __user *from, unsigned long n)
{
	int ret;
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;
	unsigned long success_n;
	struct dfvn_guest_thread_data *thread_data =
			(struct dfvn_guest_thread_data *) guest_thread->private_data;

	if (thread_data->dds_ready) {
		success_n = get_from_prefetched_data(thread_data->dds, to,
								from, n);
		if (success_n == n)
			return success_n;
	}

	/* The data was not completely/at all prefetched. Let's ask the client. */

	dfvnpacket->type = DFVN_OPTYPE_COPY_FROM_CLIENT;
	DFVN_ARGS_GUEST_ID = guest->guest_id;
	DFVN_ARGS_GUEST_THREAD_ID = guest_thread->guest_thread_id;
	DFVN_ARGS_COPY_FROM_CLIENT_FROM = (unsigned long) from;
	DFVN_ARGS_COPY_FROM_CLIENT_COUNT = n;

	ret = send_to_client(thread_data, (char *) dfvnpacket, sizeof(struct dfvn_packet));
	if (ret)
		goto err;
	ret = receive_from_client(thread_data, (char *) to, (int) n);

	if (ret)
		goto err;

	return n;

err:
	DFVPRINTK_ERR("Error: error sending/receiving\n");
	return ret;
}

static int add_to_batch(struct dfvn_data_struct **ddst_p,
		 	struct dfvn_data_struct **ddst_root_p, void __user *to,
			const void *from, unsigned long n)
{
	struct dfvn_data_struct *ddst = *ddst_p;
	struct dfvn_data_struct *ddst_root = *ddst_root_p;

	if (ddst == NULL) {
		ddst = kzalloc(sizeof(*ddst), GFP_KERNEL);
		if (!ddst)
			goto err;
		ddst_root = ddst;
		ddst->prev = NULL;
	} else {
		ddst->next = kzalloc(sizeof(*(ddst->next)), GFP_KERNEL);
		if (!ddst->next)
			goto err;
		ddst->next->prev = ddst;
		ddst = ddst->next;
	}

	ddst->ptr = kmalloc(n, GFP_KERNEL);
	memcpy(ddst->ptr, (const void *) from, (size_t) n);
	ddst->addr = (__u64) ((unsigned long) to);
	ddst->size = n;

	*ddst_p = ddst;
	*ddst_root_p = ddst_root;

	return n;

err:
	DFVPRINTK_ERR("Error: ran out of memory.\n");
	return -ENOMEM;
}

/* Returns the number of successfully copied bytes */
unsigned long dfvn_copy_to_client_user(struct guest_thread_struct *guest_thread,
				      struct guest_struct *guest, void __user *to,
				      const void *from, unsigned long n)
{
	struct dfvn_guest_thread_data *thread_data =
			(struct dfvn_guest_thread_data *) guest_thread->private_data;

	if (thread_data->dds_ready)
		update_prefetched_data(thread_data->dds, to, from, n);

	return add_to_batch(&thread_data->ddst, &thread_data->ddst_root,
				to, from, n);
}

#ifdef CONFIG_DFV_SUPPORT_ION

struct ion_handles_struct *get_ion_handles(struct ion_handle *server_handle)
{
	struct ion_handles_struct *handles = NULL, *tmp = NULL;

	list_for_each_entry_safe(handles, tmp, &dfv_ion_list, list)
	{
		 if (handles->server_handle == server_handle)
		 	 return handles;
	}

	return NULL;
}

struct ion_handles_struct *get_ion_handles2(struct ion_handle *client_handle)
{
	struct ion_handles_struct *handles = NULL, *tmp = NULL;

	list_for_each_entry_safe(handles, tmp, &dfv_ion_list, list)
	{
		 if (handles->client_handle == client_handle)
		 	 return handles;
	}

	return NULL;
}

int remove_ion_handles(struct ion_handle *client_handle)
{
	struct ion_handles_struct *handles = NULL, *tmp = NULL;
	int i;

	list_for_each_entry_safe(handles, tmp, &dfv_ion_list, list) {

		if (handles->client_handle == client_handle) {
			if (handles->vaddrs) {
				if (handles->contig) {
					__arch_iounmap(handles->vaddrs[0]);
				} else {
					for (i = 0; i < handles->num_pages; i++)
						__arch_iounmap(handles->vaddrs[i]);
				}
				kfree(handles->vaddrs);
			}	

			if (dfv_ion_client)
				ion_free(dfv_ion_client, handles->server_handle);
			else
				DFVPRINTK_ERR("Error: dfv_ion_client is NULL!\n");

			list_del(&handles->list);
			kfree(handles);
			return 0;
		}
	}

	return -EINVAL;
}

static struct ion_handle *__dfv_get_ion_handle(struct ion_handle *client_handle,
						struct ion_client **client)
{
	struct ion_handles_struct *handles = NULL, *tmp = NULL;

	if (!dfv_ion_client) {
		return NULL;
	}

	if (client)
		*client = dfv_ion_client;

	if (!(((unsigned int) client_handle) & PAGE_MASK)) {
		BUG();
	}

	list_for_each_entry_safe(handles, tmp, &dfv_ion_list, list) {

		 if (handles->client_handle == client_handle ||

		     handles->client_addr == (unsigned long) client_handle)
		 	 return handles->server_handle;
	}

	return NULL;
}

static int add_ion_handles(struct ion_handle *server_handle,

					struct ion_handle *client_handle)
{
	struct ion_handles_struct *handles;

	handles = kzalloc(sizeof(*handles), GFP_KERNEL);
	if (!handles) {
		DFVPRINTK_ERR("Error: memory allocation failed.\n");
		return -ENOMEM;
	}

	handles->server_handle = server_handle;
	handles->client_handle = client_handle;

	INIT_LIST_HEAD(&handles->list);
	list_add(&handles->list, &dfv_ion_list);

	return 0;
}

static struct ion_handles_struct *get_ion_handles_mapped(
				struct ion_handle *server_handle,
				int write, struct ion_client *ion_client)
{
	u32 *phys_addrs;
	int n_phys_pages, i;
	void *vaddr;
	struct ion_handles_struct *handles;
	/*
	 * FIXME:
	 * @contig determines whether the physical pages of the ion buffer are
	 * contiguous or not. For now, we hardcode it to be true. But we should
	 * get it from ion itself.
	 */
	bool contig = true;

	handles = get_ion_handles(server_handle);

	if (!handles) {
	    DFVPRINTK_ERR("Error: couldn't find server_handle = %#x\n",
	    					(unsigned int) server_handle);
	    return NULL;
	}

	if (handles->vaddrs) {
		goto mapped;
	}

	current->dfvcontext_network = true;
	ion_phys(ion_client, server_handle, (ion_phys_addr_t *) &phys_addrs,
								&n_phys_pages);
	current->dfvcontext_network = false;

	handles->num_pages = n_phys_pages;
	handles->contig = contig;

	if (contig)

		handles->vaddrs = kmalloc(sizeof(*(handles->vaddrs)), GFP_KERNEL);
	else

		handles->vaddrs = kmalloc(n_phys_pages * sizeof(*(handles->vaddrs)),
								GFP_KERNEL);

	if (!handles->vaddrs) {
		DFVPRINTK_ERR("Error: could not allocate memory.\n");
		return NULL;
	}

	if (contig) {

		vaddr = __arch_ioremap(phys_addrs[0], n_phys_pages * PAGE_SIZE,
			      DFV_IOREMAP_TYPE);

		if (!vaddr) {
			DFVPRINTK_ERR("Error1: mapping failed.\n");
			return NULL;;
		}

		handles->vaddrs[0] = vaddr;
	} else {
		for (i = 0; i < n_phys_pages; i++) {

			vaddr = __arch_ioremap(phys_addrs[i], PAGE_SIZE,
				      DFV_IOREMAP_TYPE);

			if (!vaddr) {
				DFVPRINTK_ERR("Error2: mapping failed.\n");
				continue;
			}

			handles->vaddrs[i] = vaddr;

		}
	}

mapped:

	return handles;
}

void init_ion_buf(struct ion_handle *server_handle)
{
	struct ion_handles_struct *handles;
	int i;

	handles = get_ion_handles_mapped(server_handle, 1, dfv_ion_client);

	if (!handles) {
		DFVPRINTK_ERR("Error: get_ion_handles_mapped failed\n");
		return;
	}

	/*
	 * Setting the ion buffers initial value to 0xFF seems to fix the
	 * color distortation problem we had for the camera.
	 */
	if (handles->contig) {
		memset(handles->vaddrs[0], 0xFF, handles->num_pages * PAGE_SIZE);
	} else {
		/* Not tested */
		for (i = 0; i < handles->num_pages; i++)
			memset(handles->vaddrs[i], 0xFF, PAGE_SIZE);
	}

}

static void dfv_ion_tiler_alloc(struct guest_thread_struct *guest_thread,
		      struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct omap_ion_tiler_alloc_data data;
	int ret;

	data.h = (size_t) (DFVN_ION_TILER_ALLOC_W_H & 0x0000ffff);
	data.w = (size_t) ((DFVN_ION_TILER_ALLOC_W_H & 0xffff0000) >> 16);
	data.fmt = (int) (DFVN_ION_TILER_ALLOC_FMT);

	if (!dfv_ion_client) {
		dfv_ion_client =
			ion_client_create(omap_ion_device, -1,
					"dfv_ion_client");
		if (!dfv_ion_client) {
			DFVPRINTK_ERR("Error: could not create ion client\n");
			return;
		}
		INIT_LIST_HEAD(&dfv_ion_list);
	}

	ret = omap_ion_tiler_alloc(dfv_ion_client, &data);

	DFVN_ION_TILER_ALLOC_STRIDE = data.stride;
	DFVN_ION_TILER_ALLOC_OFFSET = data.offset;

	if (!ret) {
		ret = add_ion_handles(data.handle, (struct ion_handle *)

						DFVN_ION_TILER_ALLOC_HANDLE);
		init_ion_buf(data.handle);
	}

	DFVN_ION_TILER_ALLOC_RESULT = ret;
}

static void dfv_ion_normal_alloc(struct guest_thread_struct *guest_thread,
		      struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct ion_allocation_data data;
	int ret;

	data.len = (size_t) DFVN_ION_ALLOC_LEN;
	data.align = (size_t) (DFVN_ION_ALLOC_FLAGS_ALIGN & 0x0000ffff);
	data.flags = (unsigned int)
			((DFVN_ION_ALLOC_FLAGS_ALIGN & 0xffff0000) >> 16);

	if (!dfv_ion_client) {
		dfv_ion_client =
			ion_client_create(omap_ion_device, -1,
					"dfv_ion_client");
		if (!dfv_ion_client) {
			DFVPRINTK_ERR("Error: could not create ion client\n");
			return;
		}
		INIT_LIST_HEAD(&dfv_ion_list);
	}

	data.handle = ion_alloc(dfv_ion_client, data.len, data.align,
					     data.flags);

	if (data.handle)
		ret = 0;
	else
		ret = -EFAULT;

	if (!ret) {
		ret = add_ion_handles(data.handle, (struct ion_handle *)
							DFVN_ION_ALLOC_HANDLE);

		init_ion_buf(data.handle);
	}

	DFVN_ION_ALLOC_RESULT = ret;
}

static void dfv_ion_map(struct guest_thread_struct *guest_thread,
		      struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct ion_handles_struct *handles;
	int ret;

	handles = get_ion_handles2((struct ion_handle *) DFVN_ION_MAP_HANDLE);

	if (!handles) {
		ret = -EINVAL;
		goto out;
	}

	handles->client_addr = DFVN_ION_MAP_ADDR;
	ret = 0;

out:
	DFVN_ION_MAP_RESULT = ret;
}

static void dfv_ion_free(struct guest_thread_struct *guest_thread,
		      struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	int ret;

	ret = remove_ion_handles((struct ion_handle *)
						DFVN_ION_FREE_HANDLE);

	DFVN_ION_FREE_RESULT = ret;
}

static void dfvn_custom_op(struct guest_thread_struct *guest_thread,
		      struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{

	switch (DFVN_CUSTOM_OP) {

	case DFVN_CUSTOM_OP_ION_ALLOC:

		dfv_ion_normal_alloc(guest_thread, req_args, res_args);
		break;

	case DFVN_CUSTOM_OP_ION_TILER_ALLOC:

		dfv_ion_tiler_alloc(guest_thread, req_args, res_args);
		break;

	case DFVN_CUSTOM_OP_ION_MAP:

		dfv_ion_map(guest_thread, req_args, res_args);
		break;

	case DFVN_CUSTOM_OP_ION_FREE:

		dfv_ion_free(guest_thread, req_args, res_args);
		break;

	default:
		DFVPRINTK_ERR("Error: Unsupported custom op %d\n",
							(int) DFVN_CUSTOM_OP);
		break;
	}
}

#endif /* CONFIG_DFV_SUPPORT_ION */

static struct page *dfv_vmalloc_to_page(const void *vmalloc_addr)
{
	struct page *page;
	pte_t *ptep;

	ptep = walk_page_tables((unsigned long) vmalloc_addr, NULL);

	page = pte_page(*ptep);

	return page;
}

static bool is_ion_page(unsigned long pfn)
{
	int i = 0;
	unsigned long paddr = pfn << PAGE_SHIFT;

	for (i = 0; i < 4; i++) {
		if (paddr >= dfv_heap_base[i] &&
		    paddr < dfv_heap_base[i] + dfv_heap_size[i])
			return true;
	}

	return false;
}

unsigned long get_vaddr(unsigned long pfn, int *type)
{
	struct page *temp_page;    

	unsigned long phys_addr;
	unsigned long vaddr;

	phys_addr = (unsigned long) pfn << PAGE_SHIFT;
	if (phys_addr < __pa(PAGE_OFFSET)) {

		if(!PageHighMem(pfn_to_page(pfn))) {

                		vaddr = (unsigned long) __va(phys_addr);
               		*type = DFVN_KMALLOC_TYPE;
                		return vaddr;
		} else {
#ifdef CONFIG_ARM
			/*
			 * We haven't added kernel support for ARM for highmem
			 * yet.
			 */
			BUG();
#endif /* CONFIG_ARM */
			temp_page = pfn_to_page(pfn);
			vaddr = (unsigned long) (temp_page->dfv_flag);
			*type = DFVN_HIGHMEM_TYPE;
			return vaddr;

		}
#ifdef CONFIG_DFV_SUPPORT_ION
	} else if (is_ion_page(pfn)) {
		/* Not supported */
		BUG();
#endif /* CONFIG_DFV_SUPPORT_ION */
	} else {
		temp_page = pfn_to_page(pfn);
		vaddr = (unsigned long) (temp_page->dfv_flag);
		*type = DFVN_VMALLOC_TYPE;
		return vaddr;
	}
}

static int
add_to_map_batch(struct dfvn_data_struct **ddsm_p,
	       struct dfvn_data_struct **ddsm_root_p, unsigned long addr)
{
	struct dfvn_data_struct *ddsm = *ddsm_p;
	struct dfvn_data_struct *ddsm_root = *ddsm_root_p;

	if (!ddsm) {
		ddsm = kzalloc(sizeof(*ddsm), GFP_KERNEL);
		if (!ddsm)
			goto err;
		ddsm_root = ddsm;
		ddsm->prev = NULL;
	} else {

		ddsm->next = kzalloc(sizeof(*(ddsm->next)), GFP_KERNEL);
		if (!ddsm->next)
			goto err;
		ddsm->next->prev = ddsm;
		ddsm = ddsm->next;
	}

	ddsm->ptr = NULL;
	ddsm->addr = (__u64) addr;
	ddsm->size = 0;

	*ddsm_p = ddsm;
	*ddsm_root_p = ddsm_root;

	return 0;

err:
	DFVPRINTK_ERR("Error: ran out of memory.\n");
	return -ENOMEM;

}

int dfvn_insert_pfn(struct guest_thread_struct *guest_thread,
			  struct guest_struct *guest, struct vm_area_struct *vma,
			  unsigned long addr, unsigned long pfn, pgprot_t prot)
{
	struct page *page;
	unsigned long vaddr;
	struct local_addr_info *entry;
	struct vma_list_struct *vma_entry;
	int vaddr_type;
	struct dfvn_guest_thread_data *thread_data =
                        (struct dfvn_guest_thread_data *) guest_thread->private_data;

	vma_entry = get_vma_entry(guest, vma);
	if (!vma_entry) {
		DFVPRINTK_ERR("Error: could not find the vma_entry\n");
	}

	vaddr = get_vaddr(pfn, &vaddr_type);
	if(vaddr == 0){
	}
	page = pfn_to_page(pfn);
	if (!page) {
		DFVPRINTK_ERR("Error: page is NULL\n");
	}

	entry = kmalloc(sizeof(*entry),  GFP_KERNEL);
	if (!entry) {
		DFVPRINTK_ERR("Error: memory allocation failed.\n");
		goto err_out;
	}

	entry->local_addr = vaddr;
	entry->msg_addr = addr;
	entry->pfn = pfn;
	entry->type = vaddr_type;
	entry->state = DFV_MODIFIED;

	INIT_LIST_HEAD(&entry->list);
	list_add(&entry->list, &vma_entry->gfn_list);
	add_to_map_batch(&thread_data->ddsm, &thread_data->ddsm_root, addr);

	page->is_dfv_page = true;
	page->dfv_data = (void *) entry;

	gguest = guest;

	return 0;

err_out:
	return -ENOMEM;
}

void dfvn_send_sigio(struct guest_struct *guest)
{
	DFVPRINTK_ERR("Error: not implemented\n");
}

static int dfvn_revert_pgtables(struct guest_thread_struct *guest_thread,
			 struct guest_struct *guest, struct vm_area_struct *vma,
			 unsigned long start_addr, unsigned long end_addr)
{
	struct local_addr_info *entry, *tmp;
	struct vma_list_struct *vma_entry;
	struct page *page;

	vma_entry = get_vma_entry(guest, vma);
	if (!vma_entry) {
		DFVPRINTK_ERR("Error: could not find the vma_entry\n");
		return -EFAULT;
	}

	list_for_each_entry_safe(entry, tmp, &vma_entry->gfn_list, list) {

		if (!(entry->msg_addr >= start_addr &&
		      entry->msg_addr < end_addr))
			continue;

		page = pfn_to_page(entry->pfn);

		page->is_dfv_page = false;
		page->dfv_data = NULL;

		list_del(&entry->list);
		kfree(entry);
	}

	return 0;
}

static void dfvn_init_guest_vm(struct guest_vm_struct *guest_vm)
{
	guest_vm->send_sigio = dfvn_send_sigio;
	guest_vm->copy_from_user = dfvn_copy_from_client_user;
	guest_vm->copy_to_user = dfvn_copy_to_client_user;
	guest_vm->insert_pfn = dfvn_insert_pfn;
	guest_vm->revert_pgtables = dfvn_revert_pgtables;
}

static void dfvn_clean_guest_thread(struct guest_thread_struct *guest_thread)
{
	struct dfvn_guest_thread_data *thread_data = guest_thread->private_data;

	thread_data->receive_packets = false;

	if (thread_data->ddst)
		kfree(thread_data->ddst);
}

static void dfvn_init_guest_thread(struct guest_thread_struct *guest_thread,
				   struct dfvn_guest_thread_data *thread_data)
{
	guest_thread->use_non_blocking_poll = false;
	guest_thread->need_poll_wait = false;
	guest_thread->poll_sleep = false;

	guest_thread->private_data = (void *) thread_data;
	guest_thread->clean_guest_thread = dfvn_clean_guest_thread;
}

static int dispatch_op(int _guest_vm_id, struct dfvn_packet *dfvnpacket_req,
				struct dfvn_packet *dfvnpacket_res,
				struct dfvn_guest_thread_data *thread_data)
{
	struct parse_args pargs;
	int err;
	struct dfv_op_args *req_args, *res_args;

	req_args = (struct dfv_op_args *) &dfvnpacket_req->arg_1;
	res_args = (struct dfv_op_args *) &dfvnpacket_res->arg_1;

	err = parse_op_args(req_args, _guest_vm_id, &pargs);

	if (err) {
		DFVPRINTK_ERR("Error: parse_op_args failed.\n");
		return -EFAULT;
	}

	if (pargs.new_guest_thread) {
		dfvn_init_guest_thread(pargs.guest_thread, thread_data);

		dfvn_init_guest_vm(pargs.guest_thread->guest_vm);
	}

	if (pargs.op == DFV_OP_custom)
		dfvn_custom_op(pargs.guest_thread, req_args, res_args);
	else
		dispatch_dfv_op(req_args, res_args, &pargs);

	return 0;
}

static int unmarshall_prefetched_data(char *buffer, struct dfvn_data_struct *dds,
						unsigned long prefetch_size)
{
	unsigned long offset = 0, total_size = 0;
	__u64 addr, size;
	int i = 0;

	for (i = 0; total_size < prefetch_size; i++) {

		if (i >= DFVN_DATA_MAX_ENTRIES) {
			DFVPRINTK_ERR("Error: more levels than expected.\n");
			goto err;
		}

		if (i > 0)
			dds[i-1].next = &dds[i];

		memcpy(&addr, buffer+offset, sizeof(__u64));
		offset += sizeof(__u64);
		total_size += sizeof(__u64);
		memcpy(&size, buffer+offset, sizeof(__u64));
		offset += sizeof(__u64);
		total_size += sizeof(__u64);

		dds[i].ptr = kmalloc(size, GFP_KERNEL);
		memcpy(dds[i].ptr, buffer+offset, size);
		offset += size;
		total_size += size;
		dds[i].addr = addr;
		dds[i].size = size;
		dds[i].next = NULL;
	}

	return 0;

err:
	for (; i >= 0; i--)
		kfree(dds[i].ptr);

	return -EFAULT;
}

static int marshall_batched_data(struct dfvn_guest_thread_data *thread_data)
{
	struct dfvn_data_struct *l_ddst;
	struct dfvn_data_struct *l_ddsm;
	unsigned long offset_a;
	unsigned long total_size = 0, total_size2 = 0;
	void *src;
	unsigned long offset, size;
	__u64 size2, dst;

	l_ddst = thread_data->ddst_root;
	l_ddsm = thread_data->ddsm_root;

	while (l_ddst) {
		total_size += 2 * sizeof(__u64);
		total_size += (unsigned long) l_ddst->size;
		l_ddst = l_ddst->next;
	}
	if (l_ddsm){
		total_size += 2 * sizeof(__u64);
	}
	while (l_ddsm) {
		total_size += sizeof(__u64);
		l_ddsm = l_ddsm->next;
	}

	if (resize_data_buffer(total_size, &thread_data->databuffer,
		&thread_data->databuffersize)) {
		DFVPRINTK_ERR("Error: could not resize databuffer to size = %d\n",
							(int) total_size);
		return -1;
	}

	l_ddst = thread_data->ddst_root;
	offset = 0;
	l_ddsm = thread_data->ddsm_root;
	offset_a = 0;

	while (l_ddst) {
		/* headers */
		dst = (__u64) l_ddst->addr;
		size2 = (__u64) l_ddst->size;
		if ((total_size2 + 2*sizeof(__u64) + (unsigned long) size2) > total_size) {
			break;
		}
		memcpy(thread_data->databuffer + offset, &dst, sizeof(__u64));
		offset += sizeof(__u64);
		total_size2 += sizeof(__u64);
		memcpy(thread_data->databuffer + offset, &size2, sizeof(__u64));
		offset += sizeof(__u64);
		total_size2 += sizeof(__u64);
		/* data */
		src = l_ddst->ptr;
		size = (unsigned long) l_ddst->size;
		memcpy((void *) (thread_data->databuffer + offset), src, size);
		offset += size;
		total_size2 += size;

		l_ddst = l_ddst->next;
	}
	if (l_ddsm) {
		dst = (__u64)0;
        	size2 = (__u64)0;                                                     
        	if ((total_size2 + 2*sizeof(__u64)) > total_size) {       
        	        return total_size2;                                                                    
        	}
		memcpy(thread_data->databuffer + offset, &dst, sizeof(__u64));              
        	offset += sizeof(__u64);                                                          
        	total_size2 += sizeof(__u64);
        	memcpy(thread_data->databuffer + offset, &size2, sizeof(__u64));            
        	offset += sizeof(__u64);
        	total_size2 += sizeof(__u64);
	}
	while (l_ddsm) {

		dst = (__u64) l_ddsm->addr;
                if ((total_size2 + sizeof(__u64)) > total_size) {       
                        break;                                                                    
                }

                memcpy(thread_data->databuffer + offset, &dst, sizeof(__u64));              
                offset += sizeof(__u64);                                                          
                total_size2 += sizeof(__u64);
		l_ddsm = l_ddsm->next;
	}

	return total_size2;
}

static void cleanup_dds(struct dfvn_data_struct *dds)
{
	struct dfvn_data_struct *l_dds, *tmp;

	l_dds = dds;
	do {
		kfree(l_dds->ptr);
		l_dds->addr = 0;
		l_dds->size = 0;

		tmp = l_dds->next;
		l_dds->next = NULL;
		l_dds = tmp;
	} while (l_dds != NULL);
}

static void cleanup_ddst(struct dfvn_data_struct *ddst,
			 struct dfvn_data_struct *ddst_root)
{
	while (ddst) {
		kfree(ddst->ptr);
		if (ddst->next)
			kfree(ddst->next);
		ddst = ddst->prev;
	}
}

static void cleanup_ddsm(struct dfvn_data_struct *ddsm,
			 struct dfvn_data_struct *ddsm_root)
{
	while (ddsm) {

		if (ddsm->next)
			kfree(ddsm->next);
		ddsm = ddsm->prev;
	}
}

static int dfvn_dispatch(void *data)
{
	struct dfv_server_dispatch_data *ddata = data;
	unsigned long guest_vm_id = ddata->guest_vm_id;
	ksocket_t sockfd = ddata->sockfd;
	struct dfvn_packet dfvnpacket_req, dfvnpacket_res;
	struct dfvn_guest_thread_data *thread_data;
	struct dfvn_data_struct dds[DFVN_DATA_MAX_ENTRIES];

	thread_data = kzalloc (sizeof(*thread_data), GFP_KERNEL);

	thread_data->sockfd = sockfd;
	thread_data->dds = dds;
	thread_data->receive_packets = true;

	while (thread_data->receive_packets) {

		if (receive_from_client(thread_data, (char *) &dfvnpacket_req,
						sizeof(struct dfvn_packet)))
			break;

		switch (dfvnpacket_req.type) {
		case DFVN_OPTYPE_REQUEST:
			if (dfvnpacket_req.prefetch_size) {

				if (resize_data_buffer(dfvnpacket_req.prefetch_size,
					&thread_data->databuffer,
					&thread_data->databuffersize)) {
					DFVPRINTK_ERR("Error: could not resize data buffer.\n");
					prepare_error_response_packet(&dfvnpacket_res);
					break;
				}

				receive_from_client(thread_data,
						thread_data->databuffer,
						dfvnpacket_req.prefetch_size);
				if (!unmarshall_prefetched_data(thread_data->databuffer,
					thread_data->dds,
					dfvnpacket_req.prefetch_size)) {
						thread_data->dds_ready = true;
				} else {
					DFVPRINTK_ERR("Error: unmarshall_prefetched_data failed!\n");
				}
			}

			dispatch_op(guest_vm_id, &dfvnpacket_req,
						&dfvnpacket_res, thread_data);
			if (thread_data->dds_ready) {
				thread_data->dds_ready = false;
				cleanup_dds(thread_data->dds);
			}
			break;

		case DFVN_OPTYPE_DSM:

			dfvdsm_handle_req(&dfvnpacket_req, (void **) &thread_data);
			/*
			 * No need to send a response. Just go back to the
			 * beginning of the loop.
			 */
			continue;

		default:
			DFVPRINTK_ERR("Error: unsupported operation: optype=%d\n",
				dfvnpacket_req.type);
			break;
		}

		dfvnpacket_res.prefetch_size = 0;

		if ((thread_data->ddst) || (thread_data->ddsm)) {

			thread_data->databuffercontentsize =
					marshall_batched_data(thread_data);
			if (thread_data->databuffercontentsize == -1) {
				DFVPRINTK_ERR("Error: marshall_batched_data failed.\n");
				prepare_error_response_packet(&dfvnpacket_res);
			} else {
				dfvnpacket_res.prefetch_size =
					thread_data->databuffercontentsize;
			}
			cleanup_ddst(thread_data->ddst, thread_data->ddst_root);
			cleanup_ddsm(thread_data->ddsm, thread_data->ddsm_root);

			thread_data->ddst_root = NULL;
			thread_data->ddst = NULL;

			thread_data->ddsm_root = NULL;
			thread_data->ddsm = NULL;

		}

		dfvnpacket_res.type = DFVN_OPTYPE_RESULT;

		send_to_client(thread_data, (char *) &dfvnpacket_res,
						sizeof(struct dfvn_packet));

		if (dfvnpacket_res.prefetch_size) {
			/* current->dfvcontext is already false here. */

			send_to_client(thread_data,
						thread_data->databuffer,
						dfvnpacket_res.prefetch_size);
		}

	}

	kclose(sockfd);

	if (thread_data->databuffer)
		kfree(thread_data->databuffer);

	kfree(thread_data);
	kfree(data);

	return 0;
}

static ksocket_t dfvn_listen_for_clients(const char *name, ksocket_t sockfd_srv,

							unsigned long *cli_id)
{
	ksocket_t sockfd_cli;
	int addr_len;
	struct sockaddr_in addr_cli;
	char *tmp;

	memset(&addr_cli, 0, sizeof(addr_cli));

	sockfd_cli = NULL;
	if (klisten(sockfd_srv, 10) < 0) {
		return (ksocket_t) -1;
	}

	sockfd_cli = kaccept(sockfd_srv, (struct sockaddr *)&addr_cli, &addr_len);
	if (sockfd_cli == NULL) 	{
		return (ksocket_t) -1;
	}

	tmp = inet_ntoa(&addr_cli.sin_addr);
	*cli_id = (unsigned long) inet_addr(tmp);
	kfree(tmp);

	return sockfd_cli;
}

static int socket_handler(void *unused)
{
	ksocket_t sockfd_cli;
	unsigned long cli_id = 0;
	struct dfv_server_dispatch_data *ddata;

	for (;;) {
		sockfd_cli = dfvn_listen_for_clients("dfvserver", sockfd_srv,

								&cli_id);

		if (g_sockfd_cli == NULL) {
			g_sockfd_cli = sockfd_cli;
			continue;
		}

		ddata = kmalloc(sizeof(*ddata), GFP_KERNEL);
		ddata->guest_vm_id = cli_id;
		ddata->sockfd = sockfd_cli;
		kernel_thread(dfvn_dispatch, (void *) ddata, 0);

	}

	return 0;
}

static int dfvserver_is_dfvn_addr(unsigned long addr, struct vm_area_struct *vma,
				 int is_user_addr, unsigned long error_code)
{
	struct page *page;
	unsigned long pfn;

	/*
	 * We return as quickly as possible for user faults.
	 */
	if (is_user_addr){
		return 0;
	}

	if (is_vmalloc_or_module_addr((const void *) addr)) {
		page = dfv_vmalloc_to_page((const void *) addr);

	} else {
		/* FIXME: How about higmem? */
		pfn = __pa(addr) >> PAGE_SHIFT;
		page = pfn_to_page(pfn);
	}

	if (!page)
		return 0;

	if (!page->is_dfv_page)
		return 0;

	return 1;
}

static int dfvserver_is_write_permitted(unsigned long addr, struct vm_area_struct *vma)
{
	return 1;
}

static unsigned long dfvserver_translate_to_local_addr(unsigned long msg_addr,
							int *is_user_addr)
{
	struct local_addr_info *entry, *tmp;
	struct vma_list_struct *vma_entry;

	*is_user_addr = 0;

	if (!gguest) {
		return 0;
	}
	vma_entry = get_vma_entry_by_addr(gguest, msg_addr);
	if (!vma_entry) {
		DFVPRINTK_ERR("Error: could not find the vma_entry\n");
		return 0;
	}

	list_for_each_entry_safe(entry, tmp, &vma_entry->gfn_list, list) {

		if (entry->msg_addr != msg_addr)
			continue;

		return entry->local_addr;
	}

	DFVPRINTK_ERR("Error: could not find the local address for "
				"msg addr = %#x\n", (unsigned int) msg_addr);
	return 0;
}

static struct local_addr_info *local_addr_to_info(unsigned long local_addr)
{
	struct vma_list_struct *vma_entry, *vma_tmp = NULL;
	struct local_addr_info *entry, *tmp;

 	if (!gguest) {
		DFVPRINTK_ERR("gguest is NULL\n");
		goto out_err;
	}

	list_for_each_entry_safe(vma_entry, vma_tmp, &gguest->vma_list, list) {

		list_for_each_entry_safe(entry, tmp, &vma_entry->gfn_list, list) {

			if (entry->local_addr != local_addr)
				continue;

			return entry;
		}
	}

out_err:
	DFVPRINTK_ERR("Error: could not find the local_address_info for "
				"local_addr %#x\n", (unsigned int) local_addr);
	return NULL;

}

static unsigned long dfvserver_translate_to_msg_addr(unsigned long local_addr)
{
	struct local_addr_info *info;

	info = local_addr_to_info(local_addr);

	if (!info) {
		DFVPRINTK_ERR("Error: info is NULL.\n");
		return 0;
	}

	return info->msg_addr;

}

/*
 * FIXME: in dfvserver_set_state and dfvserver_get_state, we should call
 * different functions based on the type of the local_addr.
 */
static int dfvserver_set_state(unsigned long local_addr, int state, void **data)
{
	struct local_addr_info *info;

	info = local_addr_to_info(local_addr);

	if (!info) {
		DFVPRINTK_ERR("Error: info is NULL.\n");
		return -EINVAL;
	}

	info->state = state;

	return user_set_state(local_addr, state, data);

}

static int dfvserver_get_state(unsigned long local_addr, void *data)
{
	struct local_addr_info *info;

	info = local_addr_to_info(local_addr);

	if (!info) {
		DFVPRINTK_ERR("Error: info is NULL.\n");
		return -EINVAL;
	}

	return user_get_state(local_addr, data);

}

static void *dfvserver_request_init(unsigned long id, int type,
						unsigned long local_addr)
{

	return NULL;
}

static void dfvserver_request_fini(unsigned long id, int type, void *data)
{

	return;
}

#ifdef CONFIG_DFV_SUPPORT_ION

static int __dfv_sync_ion_bufs(struct ion_buf_handles *handles, int write)
{
	int i;
	struct ion_handle *server_handle;
	struct ion_handles_struct *dfv_handles[2];
	int num_buffers_to_sync = 0;
	struct guest_thread_struct *guest_thread;
	struct dfvn_guest_thread_data _dummy_thread_data;
	struct dfvn_guest_thread_data *dummy_thread_data = &_dummy_thread_data;

	for (i = 0; i < 2; i++) {

		server_handle = (struct ion_handle *) handles->buffer[i];

		if (!server_handle)
			continue;

		dfv_handles[i] = get_ion_handles_mapped(server_handle, write,
							handles->client);

		if (!dfv_handles[i])
		    continue;

		num_buffers_to_sync++;
	}

	guest_thread = current->dfvguest_thread;
	if (guest_thread) {
		sync_ion_buffers(dfv_handles, num_buffers_to_sync,
						&(guest_thread->private_data));
	} else {
		dummy_thread_data->sockfd = g_sockfd_cli;
		sync_ion_buffers(dfv_handles, num_buffers_to_sync,
						(void **) &dummy_thread_data);
	}

	return 0;
}

#endif /* CONFIG_DFV_SUPPORT_ION */

/*
 * Translates a vaddr in the guest to corresponding paddr in the server.
 * The vaddr should have been mapped by the server before.
 */
static unsigned long __dfv_virt2phys(long vaddr)
{
	unsigned long local_addr;
	struct local_addr_info *info;
	int unused;

	local_addr = dfvserver_translate_to_local_addr(vaddr, &unused);

	info = local_addr_to_info(local_addr);

	if (!info) {
		DFVPRINTK_ERR("Error: info is NULL. vaddr = %#x\n",
							(unsigned int) vaddr);
		return 0;
	}

	return (info->pfn << PAGE_SHIFT);
}

static ksocket_t dfvn_open_server_sock(const char *name, int port)
{
	ksocket_t sockfd_srv;
	struct sockaddr_in addr_srv;
	int addr_len;

	sockfd_srv = NULL;
	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_port = htons(port);
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_len = sizeof(struct sockaddr_in);

	sockfd_srv = ksocket(AF_INET, SOCK_STREAM, 0);
	if (sockfd_srv == NULL) 	{
		return (ksocket_t) -1;
	}
	if (kbind(sockfd_srv, (struct sockaddr *)&addr_srv, addr_len) < 0) {
		return (ksocket_t) -1;
	}

	return sockfd_srv;
}

struct dfvdsm_operations dfvserver_dsm_ops = {
	.is_dfvn_addr = dfvserver_is_dfvn_addr,
	.is_write_permitted = dfvserver_is_write_permitted,
	.translate_to_local_addr = dfvserver_translate_to_local_addr,
	.translate_to_msg_addr = dfvserver_translate_to_msg_addr,
	.set_state = dfvserver_set_state,
	.get_state = dfvserver_get_state,
	.request_init = dfvserver_request_init,
	.request_fini = dfvserver_request_fini,
	.send_msg = dfvserver_send_dsm_msg,
	.receive_msg = dfvserver_receive_dsm_msg,
};

static int __init dfv_server_network_init(void)
{

	sockfd_srv = dfvn_open_server_sock("dfvserver", port);

	kernel_thread(socket_handler, NULL, 0);
	dfvdsm_init(&dfvserver_dsm_ops);

#ifdef CONFIG_DFV_SUPPORT_ION
	dfv_virt2phys = __dfv_virt2phys;
	dfv_get_ion_handle = __dfv_get_ion_handle;
	dfv_sync_ion_bufs = __dfv_sync_ion_bufs;
#endif /* CONFIG_DFV_SUPPORT_ION */

	return 0;
}

static void __exit dfv_server_network_exit(void)
{

	if (sockfd_srv != NULL)
		kclose(sockfd_srv);

	dfvdsm_exit();

#ifdef CONFIG_DFV_SUPPORT_ION
	dfv_virt2phys = NULL;
	dfv_get_ion_handle = NULL;
	dfv_sync_ion_bufs = NULL;

	if (dfv_ion_client)
		ion_client_destroy(dfv_ion_client);
#endif /* CONFIG_DFV_SUPPORT_ION */
}

module_init(dfv_server_network_init);
module_exit(dfv_server_network_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Server support for Device File-based I/O Virtualization "
		   "over a network connection");
MODULE_LICENSE("Dual BSD/GPL");
