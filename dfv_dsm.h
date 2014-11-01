/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_dsm.h
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

#ifndef _DFV_DSM_H_
#define _DFV_DSM_H_

#include <asm/tlbflush.h>

/*
 * Turning on ION support for all ARM platforms. Might need to be disabled for
 * some platforms.
 */
#ifdef CONFIG_ARM
#define CONFIG_DFV_SUPPORT_ION		1
#endif /* CONFIG_ARM */

#ifdef CONFIG_X86
#define set_pte_ext(ptep, pte, ext) set_pte(ptep, pte)
#define pte_mkpresent(ptep)         pte_set_flags(ptep, _PAGE_PRESENT)
#define pte_mknotpresent(ptep)      pte_clear_flags(ptep, _PAGE_PRESENT)
#define PF_WRITE			    1 << 1
static inline int dfv_pte_present(pte_t a)
{
	return pte_flags(a) & (_PAGE_PRESENT);
}
#else /* CONFIG_X86 */
PTE_BIT_FUNC(mkpresent, |= L_PTE_PRESENT);
PTE_BIT_FUNC(mknotpresent, &= ~L_PTE_PRESENT);
#define dfv_pte_present pte_present
#endif /* CONFIG_X86 */

enum DFVDSM_STATES {
	DFV_INVALID = 0,
	DFV_SHARED = 1,
	DFV_MODIFIED = 2
};

struct dfvdsm_operations {
	/*
	 * Returns 1 if the addr is an DFVN address, 0 otherwise.
	 */
	int (*is_dfvn_addr)(unsigned long addr, struct vm_area_struct *vma,
				int is_user_addr, unsigned long error_code);
	/*
	 * Returns 1 if writing to addr is permitted at all, 0 otherwise.
	 */
	int (*is_write_permitted)(unsigned long addr, struct vm_area_struct *vma);
	/*
	 * Returns the local_addr corresponding to the msg_addr. msg_addr
	 * is the addr used for communication between the modules using
	 * dfvdsm. If the local_addr is a user addr, *is_user_addr should be
	 * set to 1, otherwise to 0.
	 */
	unsigned long (*translate_to_local_addr)(unsigned long msg_addr,
							int *is_user_addr);
	/*
	 * The reverse of translate_to_local_addr.
	 */
	unsigned long (*translate_to_msg_addr)(unsigned long local_addr);
	/*
	 * Sets the DSM state for local_addr. The granularity is a page.
	 * data is used to reduce the overhead of operations that need to be
	 * repeated for a couple of dfvdsm operations, i.e., walking the
	 * page table.
	 */
	int (*set_state)(unsigned long local_addr, int state, void **data);
	/*
	 * Returns the DSM state for local_addr. The granularity is a page.
	 */
	int (*get_state)(unsigned long local_addr, void *data);
	/*
	 * Called before handling an update or invalidation request.
	 * The returned pointer will be passed to subsequent calls to
	 * set_state, get_state, and request_fini.
	 * it can be used for distinguishing between different client processes.
	 * type is the type of the request, e.g., invalidation, or update.
	 */
	void *(*request_init)(unsigned long id, int type,
						unsigned long local_addr);
	/*
	 * Called after handling an update or invalidation request.
	 */
	void (*request_fini)(unsigned long id, int type, void *data);
	/*
	 * Send a message to the client or server.
	 */
	int (*send_msg)(void *buffer, int len, void **data);
	/*
	 * Send a message from the client or server.
	 */
	int (*receive_msg)(void *buffer, int len, void **data);
};

struct dfv_dsm_data {
	int value;
	unsigned long msg_addr;
	size_t length;
	char *rcvd_data;
};

#ifdef CONFIG_DFV_SUPPORT_ION
struct ion_handles_struct {
	struct ion_handle *server_handle;
	struct ion_handle *client_handle;
	unsigned long client_addr;
	void **vaddrs;
	int num_pages;
	bool contig;
	struct list_head list;
};
#endif /* CONFIG_DFV_SUPPORT_ION */

#define translation_in_range(translation, addr, len, which_addr) \
	((translation != NULL) && \
	(len <= translation->length) && \
	(addr >= translation->which_addr) && \
	(addr + len <= translation->which_addr + translation->length))

enum MSG_TYPE {
	UPDATE_REQUEST = 0,
	UPDATE_RESPONSE = 1,
	INVALIDATION_REQUEST = 2,
	INVALIDATION_RESPONSE = 3,
	FLUSH_REQUEST = 4,
	FLUSH_RESPONSE = 5,
#ifdef CONFIG_DFV_SUPPORT_ION
	ION_SYNC_REQUEST = 6,
	ION_SYNC_RESPONSE = 7
#endif /* CONFIG_DFV_SUPPORT_ION */
};

#define DFVN_ARGS_DSM_TYPE				dfvnpacket->arg_1

#define DFVN_ARGS_DSM_UPDATE_REQ_ADDR			dfvnpacket->arg_2
#define DFVN_ARGS_DSM_UPDATE_REQ_LEN			dfvnpacket->arg_3

#define DFVN_ARGS_DSM_UPDATE_RSP_ADDR			dfvnpacket->arg_2
#define DFVN_ARGS_DSM_UPDATE_RSP_LEN			dfvnpacket->arg_3

#define DFVN_ARGS_DSM_INVAL_REQ_ADDR			dfvnpacket->arg_2

#define DFVN_ARGS_DSM_INVAL_RSP_STATUS			dfvnpacket->arg_2

/*
 * FLUSH_REQUEST reuses code from UPDATE_RESPONSE, therefore we don't need
 * to define its args separately.
 */

#define DFVN_ARGS_DSM_FLUSH_RSP_STATUS			dfvnpacket->arg_2

#define DFVN_ARGS_DSM_ION_REQ_HANDLE_1			dfvnpacket->arg_2
#define DFVN_ARGS_DSM_ION_REQ_HANDLE_2			dfvnpacket->arg_3
#define DFVN_ARGS_DSM_ION_REQ_NUM_BUFS			dfvnpacket->arg_4
#define DFVN_ARGS_DSM_ION_REQ_NUM_PAGES			dfvnpacket->arg_5

#define DFVN_ARGS_DSM_ION_RSP_STATUS			dfvnpacket->arg_2

#ifdef CONFIG_ARM
extern int (*dfv_access_check) (unsigned long addr, unsigned int fsr,
				struct vm_area_struct *vma, int is_user_addr);
#else /* CONFIG_ARM */
extern int (*dfv_access_check) (unsigned long address, unsigned long error_code,
				struct vm_area_struct *vma, int is_user_addr);
#endif /* CONFIG_ARM */

pte_t *walk_page_tables(unsigned long address, struct mm_struct *mm);
int user_set_state(unsigned long local_addr, int state, void **data);
int user_get_state(unsigned long local_addr, void *data);
void *user_request_init(unsigned long id, int type, unsigned long local_addr);
void user_request_fini(unsigned long id, int type, void *data);
int dfvdsm_flush(unsigned long local_addr, size_t len, unsigned long msg_addr,
		int state, int is_user_addr, void **private_data);
int dfvdsm_handle_req(struct dfvn_packet *dfvn_packet, void **private_data);
extern void **(*get_ion_buffer_vaddrs)(struct ion_handle *client_handle,
						int *num_pages, bool *_contig);
#ifdef CONFIG_DFV_SUPPORT_ION
int sync_ion_buffers(struct ion_handles_struct **handles, int num_buffers,
							void **private_data);
#endif /* CONFIG_DFV_SUPPORT_ION */

int dfvdsm_init(	struct dfvdsm_operations *ops);
void dfvdsm_exit(void);

#endif /* _DFV_DSM_H_ */
