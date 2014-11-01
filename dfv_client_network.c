/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_client_network.c
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
#include "dfv_client.h"
#include "ksocket.h"
#include "dfv_common_network.h"
#include "dfv_dsm.h"
#include "dfv_client_network.h"
#include "dfv_ioctl_info.h"
#ifdef CONFIG_DFV_SUPPORT_ION
#include <linux/ion.h>
#include <linux/omap_ion.h>
#endif /* CONFIG_DFV_SUPPORT_ION */

static char host[DFVN_IP_LENGTH];
static int port = 4444; /* default value is 4444 */
module_param_string(host, host, sizeof(host), 0444);
module_param(port, int, 444);

static ksocket_t g_sockfd = NULL;

#define CONFIG_DFV_EMULATE_DISCONNECT		1

#ifdef CONFIG_DFV_EMULATE_DISCONNECT
#include <linux/delay.h>

static int disconnect1 = 0;
static int disconnect2 = 1;
module_param(disconnect1, int, 444);
module_param(disconnect2, int, 444);
#endif /* CONFIG_DFV_EMULATE_DISCONNECT */

static inline int send_to_server(struct dfvn_thread_data *thread_data,
						char *buffer, int len)
{
	return dfvn_send(thread_data->sockfd, buffer, len);
}

static inline int receive_from_server(struct dfvn_thread_data *thread_data,
						char *buffer, int len)
{
	return dfvn_receive(thread_data->sockfd, buffer, len);
}

static int dfvclient_send_dsm_msg(void *buffer, int len, void **data)
{
	struct dfvn_thread_data *thread_data = *data;
	struct dfvthread_struct *dfvthread;

	if (!thread_data) {

		dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
		if (!dfvthread) {
			DFVPRINTK_ERR("Error: Could not find dfvthread\n");
			return -EINVAL;

		}

		thread_data = dfvthread->private_data;
		*data = thread_data;
	}

	return send_to_server(thread_data, (char *) buffer, len);
}

static int dfvclient_receive_dsm_msg(void *buffer, int len, void **data)
{
	struct dfvn_thread_data *thread_data = *data;
	struct dfvthread_struct *dfvthread;

	if (!thread_data) {

		dfvthread = get_dfvthread(DFVTHREAD_PID, DFVPROCESS_TGID);
		if (!dfvthread) {
			DFVPRINTK_ERR("Error: Could not find dfvthread\n");
			return -EINVAL;
		}

		thread_data = dfvthread->private_data;
		*data = thread_data;
	}

	return receive_from_server(thread_data, (char *) buffer, len);
}

/* Request dfvserver to perform an operation */
static int send_request_to_dfvserver(struct dfvthread_struct *dfvthread,
						struct dfvn_packet *dfvnpacket)
{
	unsigned long prefetch_size = 0;
	bool prefetch = false;
	struct dfvn_thread_data *thread_data =
			(struct dfvn_thread_data *) dfvthread->private_data;

	dfvnpacket->type = DFVN_OPTYPE_REQUEST;
	dfvnpacket->prefetch_size = 0;

	if (thread_data->buffer_ready) {
		dfvnpacket->prefetch_size = thread_data->databuffercontentsize;
		prefetch_size = thread_data->databuffercontentsize;
		prefetch = true;
		thread_data->buffer_ready = false;
	}

	send_to_server(thread_data, (char *) dfvnpacket,
						sizeof(struct dfvn_packet));

	if (prefetch) {

		send_to_server(thread_data, thread_data->databuffer,
							dfvnpacket->prefetch_size);
	}

	return 0;
}

static int unmarshall_batched_data(char *buffer, unsigned long batch_size,
			int *size_read_p, int *ddsa_flag_p, int *batch_size_p)
{
	unsigned long offset = *size_read_p, total_size = *size_read_p;
	__u64 addr, size;
	int ddsa_flag = *ddsa_flag_p;

	*batch_size_p = batch_size;

	while (total_size < batch_size) {
		if (ddsa_flag == 0){
			memcpy(&addr, buffer+offset, sizeof(__u64));
			offset += sizeof(__u64);
			total_size += sizeof(__u64);
			memcpy(&size, buffer+offset, sizeof(__u64));
			offset += sizeof(__u64);
			total_size += sizeof(__u64);
		} else {

			BUG();
		}

		if (ddsa_flag == 0) {
			if ((addr == 0) && (size == 0)){
				ddsa_flag = 1;
				*ddsa_flag_p = ddsa_flag;
				*size_read_p = total_size;
				return 0;
			} else {
				if (copy_to_user((void __user *) ((unsigned long) addr),
					(const void *) buffer + offset, (unsigned long) size)) {
					DFVPRINTK_ERR("Error: copy_to_user failed.\n");
					return -1;
				}
				offset += size;
				total_size += size;
			}
		} else {

			BUG();
		}
	}
	*ddsa_flag_p = 0;
	*size_read_p = total_size;
	return 0;
}

static int receive_response_from_dfvserver(struct dfvthread_struct *dfvthread,
							struct dfvn_packet *dfvnpacket)
{
	bool done = false;
	int count = 0;
	const void *from = NULL;
	struct dfvn_thread_data *thread_data =
			(struct dfvn_thread_data *) dfvthread->private_data;

	while (!done) {

		receive_from_server(thread_data, (char *) dfvnpacket,
						sizeof(struct dfvn_packet));
		switch (dfvnpacket->type) {
		case DFVN_OPTYPE_RESULT:
			done = true;
			if (dfvnpacket->prefetch_size) {
				if (resize_data_buffer(dfvnpacket->prefetch_size,
					&thread_data->databuffer,
					&thread_data->databuffersize)) {
					DFVPRINTK_ERR("Error1: could not resize data buffer.\n");
					prepare_error_response_packet(dfvnpacket);
					break;
				}	

				receive_from_server(thread_data,
					thread_data->databuffer, dfvnpacket->prefetch_size);

				thread_data->size_read = 0;
				thread_data->ddsa_flag = 0;
				thread_data->batch_size = 0;

				if (unmarshall_batched_data(thread_data->databuffer,
						dfvnpacket->prefetch_size, &thread_data->size_read, &thread_data->ddsa_flag, &thread_data->batch_size)) {
					DFVPRINTK_ERR("Error2: unmarshall failed.\n");
					prepare_error_response_packet(dfvnpacket);
					break;
				}
			}
			break;

		case DFVN_OPTYPE_COPY_FROM_CLIENT:

			from = (void *) DFVN_ARGS_COPY_FROM_CLIENT_FROM;
			count = DFVN_ARGS_COPY_FROM_CLIENT_COUNT;
			resize_data_buffer(count, &thread_data->databuffer,
				&thread_data->databuffersize);

			if (copy_from_user(thread_data->databuffer, from, count))
				DFVPRINTK_ERR("Error: copy_from_user failed\n");

			send_to_server(thread_data,
					thread_data->databuffer, count);

			break;

			break;

		case DFVN_OPTYPE_DSM:
			dfvdsm_handle_req(dfvnpacket, (void **) &thread_data);

			break;

		default:
			DFVPRINTK_ERR("Error: invalid operation, "
				"dfvnpacket->type=%d\n", dfvnpacket->type);
			break;
		}
	}

	return 0;
}

/* Perform the current operation on the server */
static int talk_to_dfvserver(struct dfvthread_struct *dfvthread,
			struct dfvn_packet *dfvnpacket_req, struct dfvn_packet *dfvnpacket_res)
{

	send_request_to_dfvserver(dfvthread, dfvnpacket_req);

	receive_response_from_dfvserver(dfvthread, dfvnpacket_res);

	return 0;
}

static int dfvn_fop_alloc_mmap(struct dfvthread_struct *dfvthread,
		struct dfv_op_args *req_args, struct dfv_op_args *res_args,
		void *data, unsigned long start_addr)
{
	unsigned long addr = start_addr;
	unsigned long end_addr = addr + PAGE_SIZE;
	int counter = 0;
	unsigned long pfn, src_addr;
	struct page *page;
	int retval = 0, insert_retval;
	struct vm_area_struct *vma = data;
	pgprot_t orig_vm_page_prot, new_vm_page_prot;
#ifdef CONFIG_ARM
	pte_t *ptep;
#endif /* CONFIG_ARM */

	/* If the mmap has failed on the server, let's not bother here. */

	/*
	 * FIXME: I don't like using alloc_pages_exact() here since we don't
	 * really need contiguous pages.
	 */
	src_addr = (unsigned long) alloc_pages_exact(end_addr - addr,
					GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
	if (!src_addr) {
		DFVPRINTK_ERR("Error: Allocating memory failed.\n");
		retval = -ENOMEM;
		goto err_out;
	}

	vma->vm_private_data = (void *) src_addr;

	orig_vm_page_prot = vma->vm_page_prot;
	new_vm_page_prot = vma->vm_page_prot;

#ifdef CONFIG_X86
	/* Removing the the permissions here so that we fault on first access. */
	pgprot_val(new_vm_page_prot) &= ~_PAGE_RW;

	pgprot_val(new_vm_page_prot) &= ~_PAGE_PRESENT;
#endif /* CONFIG_X86 */

	vma->vm_page_prot = new_vm_page_prot;

	while (addr < end_addr) {

		counter++;
		pfn = virt_to_phys((void *) src_addr) >> PAGE_SHIFT;

		page = pfn_to_page(pfn);

		if (!page) {
			retval = -EFAULT;
			goto err_out;
		}
		insert_retval = vm_insert_page(vma, addr, page);

#ifdef CONFIG_ARM

		ptep = walk_page_tables(addr, current->mm);
		set_pte_ext(ptep, pte_mknotpresent(*ptep), 0);
		set_pte_ext(ptep, pte_wrprotect(*ptep), 0);

#endif /* CONFIG_ARM */

		addr += PAGE_SIZE;
		src_addr += PAGE_SIZE;
	}

	/* Putting the vma original prot back. */
	vma->vm_page_prot = orig_vm_page_prot;

	return 0;

err_out:
	/* First, we fail the mmap operation. */
	MMAP_RESULT = retval;
	/*
	 * FIXME: This is tricky: we technically need to inform the server
	 * as it might need to undo the mmap, but how?
	 */
	return retval;
}

/*
 * Here, we flush the content of the buffer to the server if we are in
 * Modified state, and then release the local memory allocated in
 * dfvn_fop_alloc_mmap().
 */
static int dfvn_vmop_close(struct dfvthread_struct *dfvthread,
		struct dfv_op_args *req_args, struct dfv_op_args *res_args,
		void *data)
{
	unsigned long addr = VM_CLOSE_STARTADDR;
	unsigned long end_addr = VM_CLOSE_ENDADDR;
	struct vm_area_struct *vma = data;
	unsigned long src_addr;

	src_addr = (unsigned long) vma->vm_private_data;

	/*
	 * We need the state here, but we don't have it since page
	 * table entries of vma are gone. Therefore, we pass DFV_MODIFIED
	 * to force the flush.The server will reject the flush if it was
	 * in the Modified state.
	  */
	dfvdsm_flush(src_addr, (size_t) end_addr - addr, addr, DFV_MODIFIED, 0,
					(void **) &dfvthread->private_data);

	return 0;
}

/*
 * Here, we prefetch the data needed for copy_from_user() calls in the server.
 */
static int dfvn_fop_unlocked_ioctl(struct dfvthread_struct *dfvthread,
	struct dfv_op_args *req_args, struct dfv_op_args *res_args, void *data)
{
	int i, num_ops, ret, offset = 0;
	struct ioctl_mem_op *entry, *entries;
	unsigned long ioctl_arg = (unsigned long) UNLOCKED_IOCTL_ARG;
	unsigned long ioctl_cmd = (unsigned long) UNLOCKED_IOCTL_CMD;
	unsigned long total_size = 0;
	__u64 size, src;
	struct dfvn_thread_data *thread_data =
			(struct dfvn_thread_data *) dfvthread->private_data;
	struct file *file = data;

	num_ops = get_ioctl_mem_ops(file, ioctl_cmd, ioctl_arg, &entries);
	if (num_ops == 0)
		return 0;

	for (i = 0; i < num_ops; i++) {

		entry = &entries[i];

		if (entry->type >= DFV_MMAP) {
			DFVPRINTK_ERR("Error: unsupported ioctl mem op\n");
			continue;
		}

		/* We don't care about copy_to_user()'s here. */
		if (entry->type == DFV_COPY_TO_USER)
			continue;

		total_size += 2 * sizeof(__u64);
		total_size += (unsigned long) entry->size;
	}

	if (resize_data_buffer(total_size, &thread_data->databuffer,
		&thread_data->databuffersize)) {
		DFVPRINTK_ERR("Error3: could not resize databuffer to size = %d\n",
			(int) total_size);
		return -EFAULT;
	}
	thread_data->databuffercontentsize = total_size;

	for (i = 0; i < num_ops; i++) {

		entry = &entries[i];
		if (entry->type == DFV_COPY_TO_USER)
			continue;

		/* headers */
		src = (__u64) (ioctl_arg + entry->arg_off);
		size = (__u64) entry->size;
		memcpy(thread_data->databuffer + offset, &src, sizeof(__u64));
		offset += sizeof(__u64);
		memcpy(thread_data->databuffer + offset, &size, sizeof(__u64));
		offset += sizeof(__u64);
		/* data */
		ret = copy_from_user((void *) (thread_data->databuffer + offset),
					(void *) ((unsigned long) src), size);
		if (ret) {
			DFVPRINTK_ERR("Error: copy_from_user failed.\n");
			return -EFAULT;
		}
		offset += size;
	}

	put_ioctl_mem_ops(entries);

	thread_data->buffer_ready = true;

	return 0;
}

/**
 * Here, we prefetch the data needed for copy_from_user() calls in the server.
 */
static int dfvn_fop_write(struct dfvthread_struct *dfvthread,
		struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	__u64 size = (__u64) WRITE_COUNT;
	__u64 buf = (__u64) WRITE_BUF;
	int ret, offset = 0;
	struct dfvn_thread_data *thread_data =
			(struct dfvn_thread_data *) dfvthread->private_data;

	if (resize_data_buffer(size, &thread_data->databuffer,
		&thread_data->databuffersize)) {
		DFVPRINTK_ERR("Error: could not resize databuffer to size = %d\n",
			(int) size);
		return -EFAULT;
	}
	thread_data->databuffercontentsize = (2 * sizeof(__u64)) + size;

	/* headers */
	memcpy(thread_data->databuffer + offset, &buf, sizeof(__u64));
	offset += sizeof(__u64);
	memcpy(thread_data->databuffer + offset, &size, sizeof(__u64));
	offset += sizeof(__u64);
	/* data */
	ret = copy_from_user((void *) (thread_data->databuffer + offset),
				(const void __user *) ((unsigned long) buf),
				(unsigned long) size);
	if (ret) {
		DFVPRINTK_ERR("Error: copy_from_user failed.\n");
		return -EFAULT;
	}

	thread_data->buffer_ready = true;

	return 0;
}

/* Dispatch function: */
void dfvn_dispatch(struct dfvthread_struct *dfvthread,
	struct dfv_op_args *req_args, struct dfv_op_args *res_args, void *data)
{
	enum dfv_op op = ((req_args->arg_1 & 0xffff0000) >> 16) & 0x0000ffff;
	struct dfvn_thread_data *eds;
        int flag;
#ifdef CONFIG_DFV_EMULATE_DISCONNECT
	if (disconnect1) {
		while(disconnect2) {
			udelay(1);
		}
		return;
	}
#endif /* CONFIG_DFV_EMULATE_DISCONNECT */

	switch(op)
	{
	case DFV_VMOP_close:
		dfvn_vmop_close(dfvthread, req_args, res_args, data);
		break;

	case DFV_FOP_unlocked_ioctl:
		dfvn_fop_unlocked_ioctl(dfvthread, req_args, res_args, data);
		break;

	case DFV_FOP_write:
		dfvn_fop_write(dfvthread, req_args, res_args);
		break;

	default:
		break;
	}
	talk_to_dfvserver(dfvthread, (struct dfvn_packet *) req_args, (struct dfvn_packet *) res_args);

	switch(op)
	{
	case DFV_EOP_fault2:
	case DFV_FOP_mmap:

		eds = (struct dfvn_thread_data *) dfvthread->private_data;
		flag = eds->ddsa_flag;
		if (flag) {
			int batch_size = eds->batch_size;
			int total_size = eds->size_read;
			int offset = eds->size_read;
			char *buffer = eds->databuffer;
			__u64 addr = 0;

			while (total_size < batch_size) {
				memcpy(&addr, buffer+offset, sizeof(__u64));
				offset += sizeof(__u64);
				total_size += sizeof(__u64);
				dfvn_fop_alloc_mmap(dfvthread, req_args, res_args, data, (unsigned long)addr);
			}
		}

		break;

	default:
		break;
	}

}

void dfvn_init_op(struct dfvthread_struct *dfvthread,
		struct dfv_op_all_args *local_args, struct dfv_op_args **req_args,
		struct dfv_op_args **res_args)
{
	struct dfvn_thread_data *thread_data =
			(struct dfvn_thread_data *) dfvthread->private_data;

	*req_args = (struct dfv_op_args *) &(thread_data->dfvnpacket_req.arg_1);
	*res_args = (struct dfv_op_args *) &(thread_data->dfvnpacket_res.arg_1);
}

static int dfvclient_is_write_permitted(unsigned long addr,
						struct vm_area_struct *vma)
{
#ifdef CONFIG_X86
	if (pgprot_val(vma->vm_page_prot) & _PAGE_RW) {
#else /* CONFIG_X86 */
	if (!(pgprot_val(vma->vm_page_prot) & L_PTE_RDONLY)) {
#endif/* CONFIG_X86 */
		return 1;
	}

	return 0;
}

static int dfvclient_is_dfvn_addr(unsigned long addr, struct vm_area_struct *vma,
							int is_user_addr, unsigned long error_code)
{
	pte_t *ptep;
	/*
	 * We return as quickly as possible for kernel faults.
	 */
	if (!is_user_addr){

		return 0;
	}

	if (vma && vma->vm_ops && vma->vm_ops->close == dfvvmops.close) {

		ptep = walk_page_tables(addr, current->mm);
		if ((unsigned long) pte_val(*ptep) == 0) {
			return 0;
		}

		return 1;
	}

	return 0;
}

static unsigned long dfvclient_translate_to_local_addr(unsigned long msg_addr,
							int *is_user_addr)
{
	*is_user_addr = 1;
	return msg_addr;
}

static unsigned long dfvclient_translate_to_msg_addr(unsigned long local_addr)
{
	return local_addr;
}

struct dfvdsm_operations dfvclient_dsm_ops = {
	.is_dfvn_addr = dfvclient_is_dfvn_addr,
	.is_write_permitted = dfvclient_is_write_permitted,
	.translate_to_local_addr = dfvclient_translate_to_local_addr,
	.translate_to_msg_addr = dfvclient_translate_to_msg_addr,
	.set_state = user_set_state,
	.get_state = user_get_state,
	.request_init = user_request_init,
	.request_fini = user_request_fini,
	.send_msg = dfvclient_send_dsm_msg,
	.receive_msg = dfvclient_receive_dsm_msg,
};

void dfvn_init_dfvprocess(struct dfvprocess_struct *dfvprocess)
{
	/* Nothing to do here for now */
}

static void dfvn_clean_dfvthread(struct dfvthread_struct *dfvthread)
{
	struct dfvn_thread_data *thread_data = dfvthread->private_data;

	if (thread_data->sockfd && thread_data->sockfd != g_sockfd)
		kclose(thread_data->sockfd);

	if (thread_data->databuffer)
		kfree(thread_data->databuffer);

	kfree(thread_data);
}

static ksocket_t dfvn_open_client_sock(const char *name, const char *host,
								int port)
{
	ksocket_t sockfd_cli;
	struct sockaddr_in addr_srv;
	int addr_len;
	char *tmp;

	sockfd_cli = NULL;
	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_port = htons(port);
	addr_srv.sin_addr.s_addr = inet_addr((char *) host);;
	addr_len = sizeof(struct sockaddr_in);

	sockfd_cli = ksocket(AF_INET, SOCK_STREAM, 0);
	if (sockfd_cli == NULL) 	{
		return (ksocket_t) -1;
	}
	if (kconnect(sockfd_cli, (struct sockaddr*)&addr_srv, addr_len) < 0) {
		return (ksocket_t) -1;
	}

	tmp = inet_ntoa(&addr_srv.sin_addr);
	kfree(tmp);

	return sockfd_cli;
}

void dfvn_init_dfvthread(struct dfvthread_struct *dfvthread)
{
	struct dfvn_thread_data *thread_data;

	dfvthread->dispatch = dfvn_dispatch;
	dfvthread->init_op = dfvn_init_op;
	dfvthread->clean_dfvthread = dfvn_clean_dfvthread;
	dfvthread->use_non_blocking_poll = false;

	thread_data = kzalloc(sizeof(*thread_data), GFP_KERNEL);
	if (!thread_data) {
		DFVPRINTK_ERR("Error: could not allocate thread_data\n");
		BUG();
	}

	thread_data->sockfd = dfvn_open_client_sock("dfvclient", host, port);

	/*
	 * FIXME: It seems like sometimes opening a socket
	 * here fails. For now, we're using this trick to fix the
	 * problem, but we need to look into this more carefully later.
	 */
	if (!g_sockfd)
		g_sockfd = dfvn_open_client_sock("dfvclient", host, port);

	if (thread_data->sockfd == (ksocket_t) - 1) {
		thread_data->sockfd = g_sockfd;
	}

	dfvthread->private_data = (void *) thread_data;
}

#ifdef CONFIG_DFV_SUPPORT_ION
struct list_head dfvclient_ion_list;

static int add_ion_handle_info(struct ion_handle *client_handle)
{
	struct ion_client_handle_info *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		DFVPRINTK_ERR("Error: memory allocation failed.\n");
		return -ENOMEM;
	}

	info->client_handle = client_handle;

	INIT_LIST_HEAD(&info->list);
	list_add(&info->list, &dfvclient_ion_list);

	return 0;
}

static struct ion_client_handle_info *get_ion_client_handle_info(
					struct ion_handle *client_handle)
{
	struct ion_client_handle_info *info = NULL, *tmp = NULL;

	list_for_each_entry_safe(info, tmp, &dfvclient_ion_list, list) {
		 if (info->client_handle == client_handle)
		 	 return info;
	}

	return NULL;

}

static int dfv_ion_tiler_alloc(void *data, struct dfvthread_struct *dfvthread,
	struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct omap_ion_tiler_alloc_data *_data =
				(struct omap_ion_tiler_alloc_data *) data;

	if (_data->w > 0xffff || _data->h > 0xffff) {
		DFVPRINTK_ERR("Error: larger thatn width or height that we can "
								"handle.\n");
		return -EINVAL;
	}

	DFVN_ION_TILER_ALLOC_W_H = (unsigned long) _data->h;
	DFVN_ION_TILER_ALLOC_W_H |=
			((((unsigned long) _data->w) << 16) & 0xffff0000);
	DFVN_ION_TILER_ALLOC_FMT = (unsigned long) _data->fmt;
	DFVN_ION_TILER_ALLOC_HANDLE = (unsigned long) _data->handle;

	dfvn_dispatch(dfvthread, req_args, res_args, NULL);

	/* FIXME: are STRIDE and OFFSET used anywhere? */

	if (!DFVN_ION_TILER_ALLOC_RESULT)
		add_ion_handle_info(_data->handle);

	return DFVN_ION_TILER_ALLOC_RESULT;
}

static int dfv_ion_normal_alloc(void *data, struct dfvthread_struct *dfvthread,
	struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct ion_allocation_data *_data =
				(struct ion_allocation_data *) data;

	if (_data->align > 0xffff || _data->flags > 0xffff) {
		DFVPRINTK_ERR("Error: larger align or flags that we can handle.\n");
		return -EINVAL;
	}

	DFVN_ION_ALLOC_LEN = (unsigned long) _data->len;
	DFVN_ION_ALLOC_FLAGS_ALIGN = (unsigned long) _data->align;
	DFVN_ION_ALLOC_FLAGS_ALIGN |=
			((((unsigned long) _data->flags) << 16) & 0xffff0000);
	DFVN_ION_ALLOC_HANDLE = (unsigned long) _data->handle;

	dfvn_dispatch(dfvthread, req_args, res_args, NULL);

	if (!DFVN_ION_ALLOC_RESULT)
		add_ion_handle_info(_data->handle);

	return DFVN_ION_ALLOC_RESULT;
}

struct dfv_ion_map_data {
	struct ion_handle *handle;
	unsigned long addr;
};

static int dfv_ion_map(void *data, struct dfvthread_struct *dfvthread,
	struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct dfv_ion_map_data *_data =
				(struct dfv_ion_map_data *) data;

	if (!get_ion_client_handle_info(_data->handle)) {
		return -EINVAL;
	}

	DFVN_ION_MAP_HANDLE = (unsigned long) _data->handle;
	DFVN_ION_MAP_ADDR = (unsigned long) _data->addr;

	dfvn_dispatch(dfvthread, req_args, res_args, NULL);

	return DFVN_ION_MAP_RESULT;
}

static int __dfv_ion_alloc(void *data, int type)
{
	struct file dummy_file;
	struct file *dummy_filp = &dummy_file;
	struct dfv_op_all_args local_args;
	struct dfv_op_args *req_args, *res_args;
	struct dfvthread_struct *dfvthread;
	int retval;
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

	dummy_filp->private_data = NULL;
	INIT_OP(dfvthread, dummy_filp, DFV_OP_custom, local_args, req_args,
								res_args);

	DFVN_CUSTOM_OP = type;

	switch (type) {

	case DFVN_CUSTOM_OP_ION_ALLOC:

		retval = dfv_ion_normal_alloc(data, dfvthread, req_args, res_args);
		break;

	case DFVN_CUSTOM_OP_ION_TILER_ALLOC:

		retval = dfv_ion_tiler_alloc(data, dfvthread, req_args, res_args);
		break;

	case DFVN_CUSTOM_OP_ION_MAP:

		retval = dfv_ion_map(data, dfvthread, req_args, res_args);
		break;

	default:
		DFVPRINTK_ERR("Error: Unsupported alloc type %d\n", type);
		retval = -EINVAL;
		break;
	}

	if (dfvthread_added)
		remove_dfvthread(dfvthread);

	return retval;
}

static void dfv_ion_free_server(struct ion_handle *handle)
{
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

			return;
		}
		dfvthread_added = true;
	}

	dummy_filp->private_data = NULL;
	INIT_OP(dfvthread, dummy_filp, DFV_OP_custom, local_args, req_args,
								res_args);

	DFVN_CUSTOM_OP = DFVN_CUSTOM_OP_ION_FREE;
	DFVN_ION_FREE_HANDLE = (unsigned long) handle;

	dfvn_dispatch(dfvthread, req_args, res_args, NULL);

	if (dfvthread_added)
		remove_dfvthread(dfvthread);
}

static int __dfv_ion_free(struct ion_handle *handle)
{
	struct ion_client_handle_info *info = NULL, *tmp = NULL;
	int i;

	list_for_each_entry_safe(info, tmp, &dfvclient_ion_list, list) {

		if (info->client_handle == handle) {

			if (info->vaddrs) {
				if (info->contig) {
					__arch_iounmap(info->vaddrs[0]);
				} else {
					for (i = 0; i < info->num_pages; i++)
						__arch_iounmap(info->vaddrs[i]);
				}
				kfree(info->vaddrs);
			}
			list_del(&info->list);
			kfree(info);

			dfv_ion_free_server(handle);
			return 0;
		}
	}

	return -EINVAL;
}

/*
 * FIXME: For now, we hardcode the ion client here. Later, we should grab
 * it in ion_alloc and store it in our ion_client_handle_info struct.
 */
extern struct ion_client *gpsIONClient;

void **__get_ion_buffer_vaddrs(struct ion_handle *client_handle, int *num_pages,
			       bool *_contig)
{
	u32 *phys_addrs;
	int n_phys_pages, i;
	void *vaddr;
	struct ion_client_handle_info *info;
	/*
	 * FIXME:
	 * @contig determines whether the physical pages of the ion buffer are
	 * contiguous or not. For now, we hardcode it to be true. But we should
	 * get it from ion itself.
	 */
	bool contig = true;

	info = get_ion_client_handle_info(client_handle);

	if (info->vaddrs) {
		goto mapped;
	}

	current->dfvcontext_network = true;
	ion_phys(NULL, client_handle, (ion_phys_addr_t *) &phys_addrs,
								&n_phys_pages);
	current->dfvcontext_network = false;

	info->num_pages = n_phys_pages;
	info->contig = contig;

	if (contig)

		info->vaddrs = kmalloc(sizeof(*(info->vaddrs)), GFP_KERNEL);
	else

		info->vaddrs = kmalloc(n_phys_pages * sizeof(*(info->vaddrs)),
								GFP_KERNEL);

	if (!info->vaddrs) {
		DFVPRINTK_ERR("Error: could not allocate memory.\n");
		return NULL;
	}

	if (contig) {

		vaddr = __arch_ioremap(phys_addrs[0], n_phys_pages * PAGE_SIZE,
			      		DFV_IOREMAP_TYPE);

		if (!vaddr) {
			DFVPRINTK_ERR("Error1: mapping failed.\n");
			return NULL;
		}

		info->vaddrs[0] = vaddr;

	} else {
		for (i = 0; i < n_phys_pages; i++) {

			vaddr = __arch_ioremap(phys_addrs[i], PAGE_SIZE,
				      DFV_IOREMAP_TYPE);

			if (!vaddr) {
				DFVPRINTK_ERR("Error2: mapping failed.\n");
				continue;
			}

			info->vaddrs[i] = vaddr;

		}
	}

mapped:
	*num_pages = info->num_pages;

	*_contig = contig;

	return info->vaddrs;
}
#endif /* CONFIG_DFV_SUPPORT_ION */

bool listen_for_dsm_messages = true;

static int handle_dsm_messages(void *data)
{
	ksocket_t dsm_sockfd;
	struct dfvn_packet dfvnpkt;
	struct dfvn_packet *dfvnpacket = &dfvnpkt;
	struct dfvn_thread_data *dummy_thread_data;

	dsm_sockfd = dfvn_open_client_sock("dfvclient", host, port);
	if (dsm_sockfd == (ksocket_t) -1) {
		DFVPRINTK_ERR("Error: creating dsm_sock failed\n");
		return -EFAULT;
	}

	dummy_thread_data = kmalloc(sizeof(*dummy_thread_data), GFP_KERNEL);
	if (!dummy_thread_data) {
		DFVPRINTK_ERR("Error: ccould not allocate dummy_thread_data\n");
		return -ENOMEM;
	}

	dummy_thread_data->sockfd = dsm_sockfd;

	while (listen_for_dsm_messages) {

		receive_from_server(dummy_thread_data,
			(char *) dfvnpacket, sizeof(struct dfvn_packet));

		switch (dfvnpacket->type) {
		case DFVN_OPTYPE_DSM:
			dfvdsm_handle_req(dfvnpacket, (void **) &dummy_thread_data);

			break;

		default:
			DFVPRINTK_ERR("Error: invalid operation, "
				"dfvnpacket->type=%d\n", dfvnpacket->type);
			break;
		}
	}

	kfree(dummy_thread_data);

	return 0;
}

#ifdef CONFIG_DFV_SUPPORT_ION
extern struct ion_handle *PVRSRVExportFDToIONHandle(int fd,
						struct ion_client **client);
static int pvr_fd = 108;

static ssize_t dfv_client_pvr_read(struct file *file, char __user *buf,
						size_t size, loff_t *off)
{
	struct ion_handle *handle;
	struct ion_client *pvr_ion_client;

	handle = PVRSRVExportFDToIONHandle(pvr_fd, &pvr_ion_client);

	if (copy_to_user(buf, &handle, sizeof(int))) {
		DFVPRINTK_ERR("Error: copy_to_user failed\n");
		return 0;
	}

	return sizeof(int);
}

static ssize_t dfv_client_pvr_write(struct file *file, const char __user *buf,
						size_t size, loff_t *off)
{

	if (copy_from_user(&pvr_fd, buf, sizeof(int))) {
		DFVPRINTK_ERR("Error: copy_from_user failed\n");
		return 0;
	}

	return sizeof(int);
}

struct file_operations dfv_client_pvr_fops = {
	.owner                = THIS_MODULE,
	.read                 = dfv_client_pvr_read,
	.write                = dfv_client_pvr_write,
};
#endif /* CONFIG_DFV_SUPPORT_ION */

static int __init dfv_client_network_init(void)
{
	int ret;

#ifdef CONFIG_DFV_SUPPORT_ION
	dfv_ion_alloc = __dfv_ion_alloc;
	dfv_ion_free = __dfv_ion_free;
	get_ion_buffer_vaddrs = __get_ion_buffer_vaddrs;
	INIT_LIST_HEAD(&dfvclient_ion_list);
#endif /* CONFIG_DFV_SUPPORT_ION */

	dfvdsm_init(&dfvclient_dsm_ops);

	ret = set_init_dfvprocess(dfvn_init_dfvprocess);
	if (ret) {
		DFVPRINTK_ERR("Error: could not set init_dfvprocess\n");
		return ret;
	}

	ret = set_init_dfvthread(dfvn_init_dfvthread);
	if (ret) {
		DFVPRINTK_ERR("Error: could not set init_dfvthread\n");
		return ret;
	}

	kernel_thread(handle_dsm_messages, NULL, 0);

#ifdef CONFIG_DFV_SUPPORT_ION
	ret = register_chrdev(80, "/dev/dfvclient_pvr", &dfv_client_pvr_fops);
	if (ret < 0) {
		DFVPRINTK_ERR("Error: cannot obtain major number 80\n");
		return ret;
	}
#endif /* CONFIG_DFV_SUPPORT_ION */

	return 0;
}

static void __exit dfv_client_network_exit(void)
{
	listen_for_dsm_messages = false;

	dfvdsm_exit();

#ifdef CONFIG_DFV_SUPPORT_ION
	dfv_ion_alloc = NULL;
	dfv_ion_free = NULL;
	get_ion_buffer_vaddrs = NULL;
#endif /* CONFIG_DFV_SUPPORT_ION */

}

module_init(dfv_client_network_init);
module_exit(dfv_client_network_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Client support for Device File-based I/O Virtualization "
		   "over a network connection");
MODULE_LICENSE("Dual BSD/GPL");
