/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server.h
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

#include <linux/poll.h>

#define OPREQ_OP				guest_thread->request_op
#define OPREQ_SERVERFD				guest_thread->request_serverfd

extern void (*dfv_send_sigio)(struct fown_struct *fown, int fd, int band);
extern bool (*dfv_is_fg)(void);

extern unsigned long (*dfv_copy_from_user)(void *to, const void __user *from,
							unsigned long n);
extern unsigned long (*dfv_copy_to_user)(void __user *to, const void *from,
							unsigned long n);
extern int (*dfv_get_user) (void *to, const void __user *from, unsigned long n);
extern int (*dfv_put_user) (void __user *to, const void *from, unsigned long n);
extern long (*dfv_strncpy_from_user) (char *dst, const char __user *src, long count);
extern unsigned long (*dfv_clear_user) (void __user *to, unsigned long n);
extern long (*dfv_strnlen_user) (const char __user *s, long n);
extern int (*dfv_insert_page)(struct vm_area_struct *vma, unsigned long addr,
			struct page *page, pgprot_t prot);
extern int (*dfv_insert_pfn)(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, pgprot_t prot);
extern int (*dfv_remap_pfn_range)(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long pfn, unsigned long size, pgprot_t prot);
extern unsigned long (*dfv_range_not_ok)(const void __user *addr, long size);
extern unsigned long (*dfv_copy_from_user_inatomic) (void *to,
				const void __user *from, unsigned long n);
extern unsigned long (*dfv_copy_from_user_ll_nocache_nozero) (void *to,
				const void __user *from, unsigned long n);
extern unsigned long (*dfv_copy_to_user_inatomic) (void __user *to,
				const void *from, unsigned long n);

long sys_open_kernel(const char __user * pathname, int flags, int mode,
							struct file **_f);

struct dfv_state {
	struct file *file;
	struct inode *inode;
	fl_owner_t fdtable;
	int serverfd;
	int fd; /* The fd in the host; not to be confused with serverfd,
		 * which is just a counter, sent to and used by the client */
	struct list_head list;
};

struct vma_list_struct
{
	struct vm_area_struct *vma;
	struct list_head gfn_list;
	struct list_head pfn_list;
	struct list_head list;
};

struct guest_struct;
struct guest_thread_struct;

/* guest_vm_struct is for each guest VM that talks to the server */
struct guest_vm_struct {
	pid_t guest_vm_id; /* the tgid of the guest VM in the host */
	bool fg;
	int num_open_fds;
	void *private_data;
	struct list_head list;

	void (*send_sigio)(struct guest_struct *guest);
	unsigned long (*copy_from_user)(struct guest_thread_struct *guest_thread,
					struct guest_struct *guest, void *to,
					const void __user *from, unsigned long n);
	unsigned long (*copy_to_user)(struct guest_thread_struct *guest_thread,
				      struct guest_struct *guest, void __user *to,
				      const void *from, unsigned long n);
	int (*insert_pfn)(struct guest_thread_struct *guest_thread,
			  struct guest_struct *guest, struct vm_area_struct *vma,
			  unsigned long addr, unsigned long pfn, pgprot_t prot);
	int (*revert_pgtables)(struct guest_thread_struct *guest_thread,
			struct guest_struct *guest, struct vm_area_struct *vma,
			unsigned long start_addr, unsigned long end_addr);
	void (*send_poll_notification)(struct guest_thread_struct *guest_thread);
};
extern struct list_head guest_vm_list;

/* guest_struct is per process in the guest VM */
struct guest_struct {
	pid_t guest_vm_id; /* the tgid of the guest VM in the host */
	pid_t guest_id; /* the tgid of the guest process in the guest */
	struct guest_vm_struct *guest_vm;
	int num_open_fds;
	int serverfd;
	struct list_head dfv_device_list;
	struct list_head vma_list;
	void *private_data;
	struct list_head list;
};
extern struct list_head guest_list;

/* guest_thread_struct is per thread in the guest VM */
struct guest_thread_struct {
	pid_t guest_vm_id; /* the tgid of the guest VM in the host */
	pid_t guest_id; /* the tgid of the guest process in the guest */
	pid_t guest_thread_id; /* the pid of the guest thread in the guest */
	struct guest_struct *guest;
	struct guest_vm_struct *guest_vm;
	struct vm_area_struct *dfvvma; /* Temporary store for vma across the two-
				       * step fault handling: */
	int num_open_fds;				   
	unsigned long request_op;
	unsigned long request_serverfd;
	bool use_non_blocking_poll;
	bool need_poll_wait;
	bool poll_sleep;
	unsigned long poll_wait_time;
	unsigned long poll_slack;
	wait_queue_head_t *poll_wait_queue;
	struct file *poll_file;
	unsigned long poll_key;
	struct poll_wqueues *table;
	void *private_data;
	struct list_head list;
};
extern struct list_head guest_thread_list;

struct dfvdispatchcontrol {
	void (*func)(struct guest_thread_struct *guest_thread,
		     struct dfv_op_args *req_args, struct dfv_op_args *res_args);
};

extern struct dfvdispatchcontrol dfvdispatchcontrol[];

struct parse_args {
	struct guest_thread_struct *guest_thread;
	bool new_guest_thread;
	enum dfv_op op;
};

/*
 * This must be used to check whether we need to wait for poll events or not.
 * Do not directly check the guest_thread->need_poll_wait since you might
 * forget to set it to false, which will cause a data race.
 * Moreover, this should be used before returning back the dfvclient.
 */
#define NEED_POLL_WAIT(guest_thread, need_poll_wait) {			\
	need_poll_wait = guest_thread->need_poll_wait;			\
	guest_thread->need_poll_wait = false;				\
}									\

struct vma_list_struct *get_vma_entry(struct guest_struct *guest,
				       struct vm_area_struct *vma);
struct vma_list_struct *get_vma_entry_by_addr(struct guest_struct *guest,
						unsigned long addr);
struct guest_vm_struct *add_guest_vm(pid_t guest_vm_id);
struct guest_vm_struct *get_guest_vm(pid_t guest_vm_id);
void remove_guest_vm(struct guest_vm_struct *_guest_vm);
struct guest_struct *get_guest(pid_t guest_vm_id, pid_t guest_id);
void remove_guest(struct guest_struct *_guest);
struct guest_thread_struct *add_guest_thread(pid_t guest_vm_id,
				pid_t guest_id, pid_t guest_thread_id);
struct guest_thread_struct *get_guest_thread(pid_t guest_vm_id,
				pid_t guest_id, pid_t guest_thread_id);
void remove_guest_thread(struct guest_thread_struct *_guest_thread);
int parse_op_args(struct dfv_op_args *req_args, int _guest_vm_id,
			 struct parse_args *pargs);
void dispatch_dfv_op(struct dfv_op_args *req_args,
			struct dfv_op_args *res_args, struct parse_args *pargs);
void wait_for_poll(struct guest_thread_struct *guest_thread);
