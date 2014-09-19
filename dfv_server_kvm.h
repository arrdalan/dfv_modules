/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server_kvm.h
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
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

#include <linux/kvm_host.h>
#include "dfv_linux_code.h"

#define DFV_PGTABLE_MEM_SLOT_NR_PAGES 	64 /* must be a power of two */
#define DFV_IO_MEM_SLOT_NR_PAGES 100000

struct vma_gfn_list_struct {
	gfn_t gfn;
	struct list_head list;
};

struct vma_pfn_list_struct {
	pfn_t pfn;
	struct list_head list;
};

#define DFVK_RES_ARGS_READY			*(thread_data->sh_page)
#define DFVK_REQ_ARG_5				*(thread_data->sh_page + 1)
#define DFVK_REQ_ARG_6				*(thread_data->sh_page + 2)

struct dfv_io_mem_bitmap_struct {
	DECLARE_BITMAP(dfv_slot_bitmap, DFV_IO_MEM_SLOT_NR_PAGES);
};

struct dfv_pgtable_mem_bitmap_struct {
	DECLARE_BITMAP(dfv_slot_bitmap, DFV_PGTABLE_MEM_SLOT_NR_PAGES);
};

struct kvm_slot_sort {
	gfn_t base_gfn;
	unsigned long npages;
};

struct dfv_mem_slot_struct {
	bool has_slot;
	struct kvm_userspace_memory_region mem;
	struct kvm_memory_slot *dfv_slot;
	int nr_pages;
	gfn_t base_gfn;
	unsigned long *dfv_slot_bitmap;
};

struct dfvk_dispatch_args {
	struct parse_args *pargs;
	struct dfv_op_args *req;
	pt_element_t cr3;
	struct kvm_vcpu *vcpu;
	struct mm_struct *mm;
};

#define DFVK_NUM_WORKS			100

struct dfvk_work_struct {
	struct dfvk_dispatch_args *args;
	struct work_struct work;
	bool busy;
};

struct dfvk_guest_vm_data {
	struct dfv_mem_slot_struct dfv_io_mem;
	struct dfv_io_mem_bitmap_struct *io_bitmap;
	gfn_t irq_gfn;
	void *irq_vaddr;
	struct page *irq_page_ptr;
	struct kvm_vcpu *current_vcpu;
	struct dfvk_work_struct works[DFVK_NUM_WORKS];
	int works_counter;
	struct workqueue_struct *wq;
	struct guest_vm_struct *guest_vm;
};

#define DFVK_NUM_ARGS			9

struct dfvk_guest_thread_data {
	unsigned long sh_page[DFVK_NUM_ARGS];
	gfn_t sh_page_gfn;
	void *sh_page_vaddr;
	struct page *sh_page_ptr;
	struct kvm_vcpu *current_vcpu;
	bool must_clean;
	struct guest_thread_struct *guest_thread;
};

extern int (*dfv_kvm_op_handler)(struct kvm_vcpu *vcpu, unsigned long a0,
		                 unsigned long a1, unsigned long a2,
				 unsigned long a3);
