/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server_xen.h
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
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

/*
 * This should almost always be defined.
 * When not defined, we don't set up the second ring that is used for
 * sending notifications from the server to the client, which can be
 * useful for development.
 */
#define CONFIG_DFV_TWO_RINGS	1

/*
 * This is the number of work items per guest VM. Given that we currently
 * serialize the operations, this should not have much impact on the
 * performance. It will be important if we start supporting file operations
 * in parallel. In that case, it can be a safety knob that allows the server
 * to make sure a client cannot mount a DoS attack by issuing too many
 * operations.
 */
#define NUM_WORKS	100

struct dfv_server_xen_info;

struct dfv_work_struct {
	struct dfv_server_xen_info *info;
	struct work_struct work;
	bool busy;
};

struct dfv_server_xen_info {
	unsigned int evtchn;
	unsigned long irq;
	spinlock_t   irq_lock;
	struct dfv_back_ring bring;
	int ring_ref;
	grant_handle_t handle;
#ifdef CONFIG_DFV_TWO_RINGS
	unsigned int evtchn2;
	unsigned long irq2;
	struct dfv2_back_ring bring2;
	int ring_ref2;
	grant_handle_t handle2;
#endif
	domid_t frontend_id;
	struct dfv_work_struct works[NUM_WORKS];
	int works_counter;
	struct workqueue_struct *wq;
	struct mutex mtx1;
	struct mutex mtx2;
};

struct vma_map_entry_struct {
	unsigned long addr;
	unsigned long gfn;
	struct list_head list;
};
