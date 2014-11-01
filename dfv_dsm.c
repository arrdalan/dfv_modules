/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_dsm.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * Originally based on the Remote Memory Map (RMM) project
 *
 * Copyright (c) 2013 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Kevin Boos <kevinaboos@gmail.com>
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
#include <net/sock.h>
#include "dfv_common.h"
#include "ksocket.h"
#include "dfv_common_network.h"
#include "dfv_linux_code.h"
#include "dfv_dsm.h"

struct dfvdsm_operations *current_ops;

static int send_invalidation_response(int status, void **private_data)
{
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;

	dfvnpacket->type = DFVN_OPTYPE_DSM;
	dfvnpacket->prefetch_size = 0;
	DFVN_ARGS_DSM_TYPE = INVALIDATION_RESPONSE;
	DFVN_ARGS_DSM_INVAL_RSP_STATUS = (unsigned long) status;

	current_ops->send_msg(dfvnpacket, sizeof(*dfvnpacket), private_data);

	return 0;
}

static int send_flush_response(int status, void **private_data)
{
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;

	dfvnpacket->type = DFVN_OPTYPE_DSM;
	dfvnpacket->prefetch_size = 0;
	DFVN_ARGS_DSM_TYPE = FLUSH_RESPONSE;
	DFVN_ARGS_DSM_FLUSH_RSP_STATUS = (unsigned long) status;

	current_ops->send_msg(dfvnpacket, sizeof(*dfvnpacket), private_data);

	return 0;
}

#ifdef CONFIG_DFV_SUPPORT_ION
static int send_ion_sync_response(int status, void **private_data)
{
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;

	dfvnpacket->type = DFVN_OPTYPE_DSM;
	dfvnpacket->prefetch_size = 0;
	DFVN_ARGS_DSM_TYPE = ION_SYNC_RESPONSE;
	DFVN_ARGS_DSM_ION_RSP_STATUS = (unsigned long) status;

	current_ops->send_msg(dfvnpacket, sizeof(*dfvnpacket), private_data);

	return 0;
}
#endif /* CONFIG_DFV_SUPPORT_ION */

static int receive_update_response(struct dfv_dsm_data *update_data,
				     int length, void **private_data)
{
	void *rcvd_data;

	if (length == 0) {

		return -ENOMEM;
	}

	rcvd_data = kmalloc(length, GFP_KERNEL);
	if (!rcvd_data) {
		DFVPRINTK_ERR("Error: could not allocate rcvd_data\n");
		return -ENOMEM;
	}

	current_ops->receive_msg(rcvd_data, length, private_data);

	update_data->rcvd_data = rcvd_data;
	return 0;
}

#ifdef CONFIG_ARM

pte_t *walk_page_tables(unsigned long address, struct mm_struct *mm)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *ptep;

	if (mm == NULL) { /* kernel addresses. */

		pgd = pgd_offset_k(address);
	} else {
		pgd = pgd_offset(mm, address);
	}

	if (pgd_present(*pgd)) {
		pmd = pmd_offset(pgd, address);

		if (pmd_present(*pmd)) {
			ptep = pte_offset_map(pmd, address);

			if (!pte_none(*ptep)) {

				DFVPRINTK_ERR("Error: pte was none for "
					"addr=%#x\n", (unsigned int) address);
			}

			return ptep;
		} else {
			DFVPRINTK_ERR("Error: pmd was not present\n");
		}
	} else {
		DFVPRINTK_ERR("Error: pgd was not present\n");
	}

	return NULL;

}

#else /* CONFIG_ARM */

/* adopted and modified from arch/x86/mm/fault.c */
pte_t *walk_page_tables(unsigned long address, struct mm_struct *mm)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte = NULL;

	if (mm == NULL) { /* kernel addresses. */

		pgd = pgd_offset_k(address);
	} else
		pgd = pgd_offset(mm, address);

#ifdef CONFIG_X86_PAE
	if (!low_pfn(pgd_val(*pgd) >> PAGE_SHIFT) || !pgd_present(*pgd)) {
		goto out;
	}
#endif /* CONFIG_X86_PAE */

	pmd = pmd_offset(pud_offset(pgd, address), address);

	if (!low_pfn(pmd_pfn(*pmd)) || !pmd_present(*pmd) || pmd_large(*pmd)) {
		goto out;
	}

	pte = pte_offset_kernel(pmd, address);

	if (!pte) {
		return NULL;
	}
	else {

		return pte;
	}

out:
	return NULL;
}
#endif /* CONFIG_ARM */

int handle_update_response(unsigned long local_addr, size_t length, char *data,
			   int is_user_addr)
{
	int retval;
	pte_t *ptep;
	struct page *page;
	void *vaddr;

	if (is_user_addr == 1) {
		ptep = walk_page_tables(local_addr, current->mm);

		page = pte_page(*ptep);
		/* FIXME: we are assuming kmalloced page here */
		vaddr = __va((page_to_pfn(page)) << PAGE_SHIFT);

		/*
		 * FIXME: this memcpy sometimes does not do what we want. When
		 * the user app reads the value, it is still the old value.
		 * I don't know what the reason is.
		 */
		memcpy(vaddr, data, length);

	} else {

		/* FIXME: for highmem, we need to call kmap before memcpy */
		memcpy((void *) local_addr, data, length);

	}

	return 0;

	return retval;
}

static int send_update_core(int msg_type, unsigned long local_addr, size_t len,
			    int is_user_addr, unsigned long msg_addr,
			    void **private_data)
{
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;
	void *data;

	dfvnpacket->type = DFVN_OPTYPE_DSM;
	dfvnpacket->prefetch_size = 0;

	data = kmalloc(len, GFP_KERNEL);
	if (!data) {
		DFVPRINTK_ERR("Error: allocating data failed\n");
		return -ENOMEM;
	}

	if (is_user_addr) {

		if (copy_from_user(data, (char *) local_addr, len))
			return -EFAULT;
	} else {

		memcpy(data, (void *) local_addr, len);
	}

	DFVN_ARGS_DSM_TYPE = msg_type;
	DFVN_ARGS_DSM_UPDATE_RSP_ADDR = msg_addr;
	DFVN_ARGS_DSM_UPDATE_RSP_LEN = len;

	current_ops->send_msg(dfvnpacket, sizeof(*dfvnpacket), private_data);

	current_ops->send_msg(data, len, private_data);

	kfree(data);

	return 0;
}

int send_update_response(unsigned long local_addr, size_t len, int is_user_addr,
							unsigned long msg_addr)
{
	void *private_data = NULL;

	return send_update_core(UPDATE_RESPONSE, local_addr, len,
				is_user_addr, msg_addr, &private_data);
}

int dfvdsm_handle_req(struct dfvn_packet *dfvnpacket, void **private_data)
{
	unsigned long local_addr;
	int retval;
	int is_user_addr, state, i, status;
	void *data;
	int num_pages;
	void **vaddrs;
	bool contig;
	int total_num_pages, j;
	struct dfv_dsm_data update_data;
#ifdef CONFIG_DFV_SUPPORT_ION
	struct ion_handle *client_handle;
#endif /* CONFIG_DFV_SUPPORT_ION */

	switch (DFVN_ARGS_DSM_TYPE) {

	case UPDATE_REQUEST:	

		local_addr = current_ops->translate_to_local_addr(
				DFVN_ARGS_DSM_UPDATE_REQ_ADDR	, &is_user_addr);

		data = current_ops->request_init(0, DFVN_ARGS_DSM_TYPE, local_addr);

		state = current_ops->get_state(local_addr, data);

		if (state != DFV_MODIFIED) {
			DFVPRINTK_ERR("Error: bad state = %d (must be "
					"modified %d)\n", state, DFV_MODIFIED);
			retval = -EINVAL;
		} else {
			retval = current_ops->set_state(local_addr, DFV_SHARED,
									&data);
		}
		if (!local_addr || retval)
		{

			send_update_response(local_addr, 0, is_user_addr,
						DFVN_ARGS_DSM_UPDATE_REQ_ADDR);

			break;
		}

		retval = send_update_response(local_addr, DFVN_ARGS_DSM_UPDATE_REQ_LEN,
					is_user_addr, DFVN_ARGS_DSM_UPDATE_REQ_ADDR);

		current_ops->request_fini(0, DFVN_ARGS_DSM_TYPE, data);

		break;

	case INVALIDATION_REQUEST:

		local_addr = current_ops->translate_to_local_addr(

					DFVN_ARGS_DSM_INVAL_REQ_ADDR, &is_user_addr);

		data = current_ops->request_init(0, DFVN_ARGS_DSM_TYPE, local_addr);

		status = current_ops->set_state(local_addr, DFV_INVALID, &data);

		send_invalidation_response(status, private_data);

		break;

	case FLUSH_REQUEST:

		update_data.msg_addr = DFVN_ARGS_DSM_UPDATE_RSP_ADDR;
		update_data.length = DFVN_ARGS_DSM_UPDATE_RSP_LEN;
		update_data.rcvd_data = NULL;

		retval = receive_update_response(&update_data,
					DFVN_ARGS_DSM_UPDATE_RSP_LEN, private_data);

		local_addr = current_ops->translate_to_local_addr(
				update_data.msg_addr, &is_user_addr);
		data = current_ops->request_init(0, DFVN_ARGS_DSM_TYPE, local_addr);

		state = current_ops->get_state(local_addr, &data);

		retval = current_ops->set_state(local_addr,
							DFV_MODIFIED, &data);

		if (state == DFV_INVALID) {
			retval = handle_update_response(local_addr,
					update_data.length,
					update_data.rcvd_data,
					is_user_addr);

		}

		send_flush_response(retval, private_data);

		if (update_data.rcvd_data)
			kfree(update_data.rcvd_data);
		break;

#ifdef CONFIG_DFV_SUPPORT_ION
	case ION_SYNC_REQUEST:

		total_num_pages = 0;

		if (!get_ion_buffer_vaddrs) {
			DFVPRINTK_ERR("Error: get_ion_buffers_vaddrs() not defined.\n");
			goto ion_sync_request_err;
		}

		if (DFVN_ARGS_DSM_ION_REQ_NUM_BUFS > 2) {
			DFVPRINTK_ERR("Error: We don't support %d buffers "
				" in one request.\n", (int) DFVN_ARGS_DSM_ION_REQ_NUM_BUFS);
			goto ion_sync_request_err;
		}

		for (j = 0; j < DFVN_ARGS_DSM_ION_REQ_NUM_BUFS; j++) {

			if (j == 0)
				client_handle = (struct ion_handle *) DFVN_ARGS_DSM_ION_REQ_HANDLE_1;
			else if (j == 1)
				client_handle = (struct ion_handle *) DFVN_ARGS_DSM_ION_REQ_HANDLE_2;
			else
				goto ion_sync_request_err;

			vaddrs = (*get_ion_buffer_vaddrs)(client_handle,

							&num_pages, &contig);

			if (!vaddrs) {
				DFVPRINTK_ERR("Error: vaddrs is NULL.\n");

				continue;
			}

			if ((total_num_pages + num_pages) > DFVN_ARGS_DSM_ION_REQ_NUM_PAGES) {
				DFVPRINTK_ERR("Error: buffers have more pages "
					   " that is being sent\n");
				goto ion_sync_request_err;
			}

			if (contig) {
				current_ops->receive_msg(vaddrs[0],

					num_pages * PAGE_SIZE, private_data);

			} else {

				for(i = 0; i < num_pages; i++) {		

					current_ops->receive_msg(vaddrs[i],
							PAGE_SIZE, private_data);					

				}
			}

			total_num_pages += num_pages;
		}

		if (total_num_pages < DFVN_ARGS_DSM_ION_REQ_NUM_PAGES) {
			DFVPRINTK_ERR("Error: did not get all pages!\n");
			goto ion_sync_request_err;
		}

		send_ion_sync_response(0, private_data);

		break;

	ion_sync_request_err:
		/*
		 * FIXME: What to do here? The server is about to send
		 * us the pages. We need to at least receive them on
		 * some dummy page before we send him the response.
		 */
		BUG();

		break;
#endif /* CONFIG_DFV_SUPPORT_ION */

	default:

		BUG();

	}

	return 0;
}

int dfvdsm_flush(unsigned long local_addr, size_t len, unsigned long msg_addr,
		int state, int is_user_addr, void **private_data)
{
	int retval;
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;

	if (state != DFV_MODIFIED) {
		return 0;
	}

	retval = send_update_core(FLUSH_REQUEST, local_addr, len, is_user_addr,
							msg_addr, private_data);

	/*
	 * It's important to use a flush response message to avoid data race.
	 * The data race we faced was that the client sends the next op,
	 * which is vmop_close, to the server before the server is even done
	 * with handling the flush.
	 */
	current_ops->receive_msg(dfvnpacket, sizeof(*dfvnpacket), private_data);

	if (DFVN_ARGS_DSM_TYPE != FLUSH_RESPONSE) {
		DFVPRINTK_ERR("Error: unexpected message\n");
		return -EINVAL;
	}

	retval = DFVN_ARGS_DSM_FLUSH_RSP_STATUS;

	return retval;
}

int user_set_state(unsigned long local_addr, int state, void **data)
{
	pte_t *ptep = walk_page_tables(local_addr, current->mm);

	if (!ptep)
		goto error_no_pte;

	switch (state) {

	case DFV_SHARED:
		/* grant read-only permissions to the PTE, aka SHARED state */
		set_pte_ext(ptep, pte_mkpresent(*ptep), 0);
		set_pte_ext(ptep, pte_wrprotect(*ptep), 0);

		break;

	case DFV_MODIFIED:
		set_pte_ext(ptep, pte_mkpresent(*ptep), 0);
		set_pte_ext(ptep, pte_mkwrite(*ptep), 0);

		break;

	case DFV_INVALID:
		set_pte_ext(ptep, pte_mknotpresent(*ptep), 0);
		set_pte_ext(ptep, pte_wrprotect(*ptep), 0);

		break;

	default:
		DFVPRINTK_ERR("Error: unknown state.\n");
		break;
	}

	flush_tlb_all();

	return 0;

error_no_pte:
	DFVPRINTK_ERR("Error: PTE is NULL \n");
	return -EFAULT;
}

int user_get_state(unsigned long local_addr, void *data)
{
	pte_t *ptep = walk_page_tables(local_addr, current->mm);

	if (!ptep)
		goto error_no_pte;

	if (!dfv_pte_present(*ptep))
		return DFV_INVALID;
	else {
		if (pte_write(*ptep))
			return DFV_MODIFIED;
		else
			return DFV_SHARED;
	}

error_no_pte:
	DFVPRINTK_ERR("Error: PTE is NULL \n");
	return -EFAULT;
}

void *user_request_init(unsigned long id, int type, unsigned long local_addr)
{
	pte_t *ptep;

	ptep = walk_page_tables(local_addr, current->mm);

	if (!ptep)
		goto error_no_pte;

	return (void *) ptep;

error_no_pte:
	DFVPRINTK_ERR("Error: couldn't find a PTE for local_addr=%#x \n",
						(unsigned int) local_addr);
	return NULL;
}

void user_request_fini(unsigned long id, int type, void *data)
{
	pte_t *ptep = (pte_t *) data;

	if (!ptep){

		goto error_no_pte;
	}

#ifdef CONFIG_ARM
	pte_unmap(*ptep);
#endif /* CONFIG_ARM */

error_no_pte:
	DFVPRINTK_ERR("Error: PTE is NULL \n");
}

static int send_update_request(unsigned long msg_addr, unsigned long length,
				struct dfv_dsm_data *update_data)
{
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;
	void *private_data = NULL;
	int retval;

	dfvnpacket->type = DFVN_OPTYPE_DSM;
	dfvnpacket->prefetch_size = 0;

	DFVN_ARGS_DSM_TYPE = UPDATE_REQUEST;
	DFVN_ARGS_DSM_UPDATE_REQ_ADDR	 = msg_addr;
	DFVN_ARGS_DSM_UPDATE_REQ_LEN = PAGE_SIZE;
	current_ops->send_msg(dfvnpacket, sizeof(*dfvnpacket), &private_data);

	/* reusing dfvpacket here */

	current_ops->receive_msg(dfvnpacket, sizeof(*dfvnpacket), &private_data);

	if (DFVN_ARGS_DSM_TYPE != UPDATE_RESPONSE) {
		DFVPRINTK_ERR("Error: unexpected message\n");
		return -EINVAL;
	}

	update_data->msg_addr = DFVN_ARGS_DSM_UPDATE_RSP_ADDR;
	update_data->length = DFVN_ARGS_DSM_UPDATE_RSP_LEN;
	retval = receive_update_response(update_data,
				(int) DFVN_ARGS_DSM_UPDATE_RSP_LEN, &private_data);
	update_data->value = retval;

	return 0;
}

static int send_invalidation(unsigned long msg_addr)
{
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;
	int response_status;
	void *private_data = NULL;

	dfvnpacket->type = DFVN_OPTYPE_DSM;
	dfvnpacket->prefetch_size = 0;

	DFVN_ARGS_DSM_TYPE = INVALIDATION_REQUEST;
	DFVN_ARGS_DSM_INVAL_REQ_ADDR = msg_addr;
	current_ops->send_msg(dfvnpacket, sizeof(*dfvnpacket), &private_data);

	/* reusing dfvpacket here */

	current_ops->receive_msg(dfvnpacket, sizeof(*dfvnpacket), &private_data);

	if (DFVN_ARGS_DSM_TYPE != INVALIDATION_RESPONSE) {
		DFVPRINTK_ERR("Error: unexpected message\n");
		return -EINVAL;
	}

	response_status = DFVN_ARGS_DSM_INVAL_RSP_STATUS;

	return response_status;
}

int dfvn_access_check_core(unsigned long local_addr, int state, int write,
						int is_user_addr, void **data)
{
	int retval;
	unsigned long msg_addr;
	int fault = VM_FAULT_BADACCESS;
	struct dfv_dsm_data update_data;

	if ((local_addr & ~PAGE_MASK) != 0) {
		/* Just a warning for now. */
		DFVPRINTK_ERR("Error: addr is not page aligned.\n");
	}

	if (state == DFV_MODIFIED || (state == DFV_SHARED && !write)) {

		return 0;
	}

	msg_addr = current_ops->translate_to_msg_addr(local_addr);

	update_data.rcvd_data = NULL;

	if (state == DFV_INVALID) {

		send_update_request(msg_addr, PAGE_SIZE, &update_data);

		retval = handle_update_response(local_addr,
			update_data.length,
			update_data.rcvd_data, is_user_addr);

		if (retval != 0)
		{
			fault = VM_FAULT_BADACCESS;
			goto out;
		}

		current_ops->set_state(local_addr, DFV_SHARED, data);

		fault = 0;

		if (write) {

			retval = send_invalidation(msg_addr);

			/* means that the other machines invalidated their copies */
			if (retval == 0)
				retval = current_ops->set_state(local_addr,
							DFV_MODIFIED, data);

			fault = (retval == 0) ? 0 : VM_FAULT_BADACCESS;

		} else {
		}

		goto out;
	} else {

		if (write) {
			retval = send_invalidation(msg_addr);

			/* means that the other machines invalidated their copies */
			if (retval == 0)
				retval = current_ops->set_state(local_addr,
							DFV_MODIFIED, data);

			fault = (retval == 0) ? 0 : VM_FAULT_BADACCESS;

		}
		/* This cannot happen. We check in the beginning. */
		else
		{

			DFVPRINTK_ERR("Error: This should not have happened.\n");
			fault = 0;
		}
	}

out:
	if (update_data.rcvd_data)
		kfree(update_data.rcvd_data);

	return fault;
}

#ifdef CONFIG_DFV_SUPPORT_ION

void **(*get_ion_buffer_vaddrs)(struct ion_handle *client_handle, int *num_pages,
							bool *contig);

int sync_ion_buffers(struct ion_handles_struct **handles, int num_buffers,
							void **private_data)
{
	int response_status;
	int i, j, total_num_pages = 0;
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;

	if (num_buffers > 2) {
		DFVPRINTK_ERR("Error: We currently don't support %d buffers in "
			   "one request.\n", num_buffers);
		return -EINVAL;
	}

	dfvnpacket->type = DFVN_OPTYPE_DSM;
	dfvnpacket->prefetch_size = 0;

	DFVN_ARGS_DSM_TYPE = ION_SYNC_REQUEST;

	for (i = 0; i < num_buffers; i++) {

		if (i == 0)
			DFVN_ARGS_DSM_ION_REQ_HANDLE_1 =
				(unsigned long) handles[i]->client_handle;
		else if (i == 1)
			DFVN_ARGS_DSM_ION_REQ_HANDLE_2 =
				(unsigned long) handles[i]->client_handle;
		else
			/* Should not happen since we check num_buffers earlier */
			BUG();
		total_num_pages += handles[i]->num_pages;
	}

	DFVN_ARGS_DSM_ION_REQ_NUM_BUFS = num_buffers;
	DFVN_ARGS_DSM_ION_REQ_NUM_PAGES = total_num_pages;

	current_ops->send_msg(dfvnpacket, sizeof(*dfvnpacket), private_data);

	for (i = 0; i < num_buffers; i++) {

		if (handles[i]->contig)

			current_ops->send_msg(handles[i]->vaddrs[0],
				handles[i]->num_pages * PAGE_SIZE, private_data);
		else {
			for(j = 0; j < handles[i]->num_pages; j++) {

				current_ops->send_msg(handles[i]->vaddrs[j],
							PAGE_SIZE, private_data);

			}
		}
	}

	current_ops->receive_msg(dfvnpacket, sizeof(*dfvnpacket), private_data);

	if (DFVN_ARGS_DSM_TYPE != ION_SYNC_RESPONSE) {
		DFVPRINTK_ERR("Error: unexpected message\n");
		return -EINVAL;
	}

	response_status = DFVN_ARGS_DSM_ION_RSP_STATUS;

	return response_status;
}

#endif /* CONFIG_DFV_SUPPORT_ION */

#ifdef CONFIG_ARM
int dfvn_access_check(unsigned long local_addr, unsigned int fsr,
				struct vm_area_struct *vma, int is_user_addr)
#else /* CONFIG_ARM */
int dfvn_access_check(unsigned long local_addr, unsigned long error_code,
				struct vm_area_struct *vma, int is_user_addr)
#endif /* CONFIG_ARM */
{
	int write = 0, state, err;
	bool found = false;
	pte_t *ptep;

#ifdef CONFIG_ARM
	found = current_ops->is_dfvn_addr(local_addr, vma, is_user_addr,
							(unsigned long) fsr);
#else /* CONFIG_ARM */
	found = current_ops->is_dfvn_addr(local_addr, vma, is_user_addr,
							error_code);
#endif /* CONFIG_ARM */

	if (!found){

		goto err_out;
	}

	local_addr &= PAGE_MASK;

#ifdef CONFIG_ARM
	if (fsr & FSR_WRITE)
#else /* CONFIG_ARM */
	if (error_code & PF_WRITE)
#endif /* CONFIG_ARM */
	{
		write = 1;
	}

	if (write && !current_ops->is_write_permitted(local_addr, vma)) {

		goto err_out;
	}
	ptep = walk_page_tables(local_addr, current->mm);

	state = current_ops->get_state(local_addr, (void *) ptep);

	/* We cannot be in Modified state. */
	if (state == DFV_MODIFIED) {
		DFVPRINTK_ERR("Error: wrong state\n");
		goto err_out;
	}

	err = dfvn_access_check_core(local_addr, state, write, is_user_addr,
								(void **) &ptep);
	if (ptep) {

	} else {
	}

#ifdef CONFIG_ARM
	pte_unmap(*ptep);
#endif /* CONFIG_ARM */

	if (err)
		return VM_FAULT_BADACCESS;
	return 0;

err_out:
	return VM_FAULT_BADACCESS;
}

int dfvdsm_init(	struct dfvdsm_operations *ops)
{
	int retval;

	if (!ops->is_dfvn_addr || !ops->is_write_permitted ||
	    !ops->translate_to_local_addr || !ops->translate_to_msg_addr ||
	    !ops->set_state || !ops->get_state || !ops->request_init ||
	    !ops->request_fini || !ops->send_msg || !ops->receive_msg) {
		DFVPRINTK_ERR("Error:dfvdsm operations cannot be NULL\n");
		return -EFAULT;
	}

	current_ops = ops;

	dfv_access_check = dfvn_access_check;

	return retval;
}

void dfvdsm_exit(void)
{
	dfv_access_check = NULL;
	/* Nothing to be done here for now */

	return;
}
