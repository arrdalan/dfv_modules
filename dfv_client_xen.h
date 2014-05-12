/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_client_xen.h
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

struct dfv_client_xen_info {
	unsigned int evtchn;
	unsigned long irq;
	unsigned int evtchn2;
	unsigned long irq2;
	spinlock_t   irq_lock;
	struct dfv_front_ring fring;
	int ring_ref;
	struct dfv2_front_ring fring2;
	int ring_ref2;
	int otherend_id;
};

enum gnttab_entry_types {
	GNTTAB_TYPE_COPY_FROM_USER = 0,
	GNTTAB_TYPE_COPY_TO_USER = 1,
	GNTTAB_TYPE_MMAP = 2,
	GNTTAB_TYPE_MUNMAP = 3,
	/*
	 * Don't use this one unless you know what you're doing. It's a
	 * security threat for the client.
	 */
	GNTTAB_TYPE_ALL = 4
};

/* This struct must be identical to the one used in the hypervisor */
struct dfv_gnttab_entry {
	uint64_t start_addr;
	uint64_t size;
	uint64_t cr3;
	uint64_t debug;
	uint32_t next_ref;
	domid_t domid;
	uint16_t type;
};

#define NR_REFS_PER_PAGE     (PAGE_SIZE / sizeof(struct dfv_gnttab_entry))
#define NR_DFV_GNTTAB_PAGES   1 /* Currently, we only support 1 page for the
				  dfv grant-table. */
#define NR_DFV_GNTTAB_ENTRIES  NR_REFS_PER_PAGE
#define INVALID_DFV_GNTTAB_REF NR_DFV_GNTTAB_ENTRIES

#define IS_VALID_REF(ref) (ref < NR_DFV_GNTTAB_ENTRIES && ref >= 0)

void dfvx_init_dfvthread(struct dfvthread_struct *dfvthread);
