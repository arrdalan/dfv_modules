/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_client.h
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

extern struct file_operations dfvfops;
extern struct vm_operations_struct dfvvmops;

#define DFVTHREAD_PID current->pid
#define DFVPROCESS_TGID current->tgid

/* This struct is of not much use at this time, but might be useful later on */
struct dfvprocess_struct {
	pid_t process_id;
	int num_open_fds;
	struct list_head list;
};
extern struct list_head dfvprocess_list;

struct dfvthread_struct {
	pid_t thread_id;
	pid_t process_id;
	int num_open_fds;
	struct dfvprocess_struct *dfvprocess;
	wait_queue_head_t *wait_queue;
	bool use_non_blocking_poll;
	void (*dispatch)(struct dfvthread_struct *dfvthread,
		struct dfv_op_args *req_args, struct dfv_op_args *res_args, void *data);
	void (*init_op)(struct dfvthread_struct *dfvthread,
		struct dfv_op_all_args *local_args, struct dfv_op_args **req_args,
		struct dfv_op_args **res_args);
	void (*clean_dfvthread)(struct dfvthread_struct *dfvthread);
	void *private_data;

	struct list_head list;
};
extern struct list_head dfvthread_list;

extern struct task_struct *current_dfv_task;
extern struct fasync_struct *dfv_fasync;

struct dfvthread_struct *get_dfvthread(pid_t thread_id, pid_t process_id);
struct dfvthread_struct *add_dfvthread(pid_t thread_id, pid_t process_id);
void remove_dfvthread(struct dfvthread_struct *_dfvthread);
int set_init_dfvprocess(void (*func)(struct dfvprocess_struct *dfvprocess));
int set_init_dfvthread(void (*func)(struct dfvthread_struct *dfvthread));
int dfv_alloc_pages(void **virt_addr_ptr, void **phys_addr_ptr, int nr_pages);

#define INIT_OP(dfvthread, f, oper, local_args, req_args, res_args)		\
	dfvthread->init_op(dfvthread, &local_args, &req_args, &res_args); 	\
	DFVPRINTK("initializing operation: " #oper				\
		" file=%#x serverfd=%d\n", (unsigned int) f,			\
		f ? f->serverfd : -1);						\
	DFVPRINTK("tgid = %d, pid = %d\n", current->tgid, current->pid);	\
	OPREQ_OP_SERVERFD = oper;						\
	OPREQ_OP_SERVERFD = OPREQ_OP_SERVERFD << 16;				\
	OPREQ_OP_SERVERFD &= 0xffff0000;					\
	OPREQ_OP_SERVERFD |= ((f ? f->serverfd : -1) & 0x0000ffff);		\
	OPREQ_ID = current->tgid;						\
	OPREQ_ID = OPREQ_ID << 16;						\
	OPREQ_ID &= 0xffff0000;							\
	OPREQ_ID |= (current->pid & 0x0000ffff);				\

