/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server_network.h
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

#include "ksocket.h"

struct dfvn_guest_thread_data {
	ksocket_t sockfd;
	char *databuffer;
	int databuffersize;
	int databuffercontentsize;
	bool buffer_ready;
	int packet_num;
	struct dfvn_data_struct *dds;
	bool dds_ready;
	bool receive_packets;
	struct dfvn_data_struct *ddst_root;
	struct dfvn_data_struct *ddst;
	struct dfvn_data_struct *ddsm_root;
	struct dfvn_data_struct *ddsm;
};

enum dfvn_alloc_type {
	DFVN_KMALLOC_TYPE = 0, /* identity-mapped segment */
	DFVN_VMALLOC_TYPE = 1,
	DFVN_HIGHMEM_TYPE = 2,
 	DFVN_ION_TYPE = 3
};

struct local_addr_info {
	unsigned long local_addr;
	unsigned long msg_addr;
	int type;
	unsigned long pfn;
	int state;
	struct list_head list;
};

struct dfvn_data_struct {
	void *ptr;
	__u64 addr;
	__u64 size;
	struct dfvn_data_struct *next;
	struct dfvn_data_struct *prev;
};

struct dfv_server_dispatch_data {
	unsigned long guest_vm_id;
	ksocket_t sockfd;
};

#ifdef CONFIG_DFV_SUPPORT_ION
struct ion_buf_handles {
	u32 remote_buffer;
	u32 buffer[3];
	struct ion_client *client;
};

extern unsigned long dfv_heap_base[5];
extern size_t dfv_heap_size[5];

extern int (*dfv_sync_ion_bufs)(struct ion_buf_handles *handles, int write);
extern unsigned long (*dfv_virt2phys)(long vaddr);
extern struct ion_handle *(*dfv_get_ion_handle)(struct ion_handle *client_handle,
						struct ion_client **client);
#endif /* CONFIG_DFV_SUPPORT_ION */

int __dfv_sync_memory(unsigned long paddr, size_t size, unsigned long offset,
								int write);
