/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_server_kvm.c
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

#include <linux/module.h>
#include <asm/mmu_context.h>
#include <linux/kvm_host.h>
#include <linux/sort.h>
#include "dfv_common.h"
#include "dfv_server.h"
#include "dfv_common_kvm.h"
#include "dfv_server_kvm.h"
#include "dfv_linux_code.h"
#include "dfv_drm.h"

static DEFINE_MUTEX(dfv_server_kvm_mutex);
#define ENTER_CRIT_SEC mutex_lock(&dfv_server_kvm_mutex)
#define EXIT_CRIT_SEC mutex_unlock(&dfv_server_kvm_mutex)
static DEFINE_MUTEX(dfv_server_kvm_mutex2);
#define ENTER_CRIT_SEC2 mutex_lock(&dfv_server_kvm_mutex2)
#define EXIT_CRIT_SEC2 mutex_unlock(&dfv_server_kvm_mutex2)
static DEFINE_MUTEX(dfv_server_kvm_mutex3);
#define ENTER_CRIT_SEC3 mutex_lock(&dfv_server_kvm_mutex3)
#define EXIT_CRIT_SEC3 mutex_unlock(&dfv_server_kvm_mutex3)
static spinlock_t dfv_server_kvm_spinlock;

static int __dfvk_inject_interrupt(struct kvm *kvm, int irq_num)
{
	int irq_return1, irq_return2;

	irq_return1 = kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irq_num, 1);
	irq_return2 = kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irq_num, 0);

	return 0;
}

int irq_ring_index = 0;

static int dfvk_inject_interrupt(struct kvm *kvm, int irq_type,
				 struct dfvk_guest_vm_data *vm_data,
				 struct guest_thread_struct *guest_thread)
{
	int ret;
	unsigned long *irq_page;

	ENTER_CRIT_SEC3;

	if (!vm_data->irq_vaddr) {
		DFVPRINTK_ERR("Error: vm_data->irq_vaddr is NULL\n");
		goto inject;
	}

	irq_page = vm_data->irq_vaddr;

	if (guest_thread && irq_type == DFV_IRQ_POLL) { /* only used for DFV_IRQ_POLL now */

		irq_page[DFV_IRQ_PROCESS_ID] = guest_thread->guest_id;
		irq_page[DFV_IRQ_THREAD_ID] = guest_thread->guest_thread_id;
	}

	irq_page[irq_type + DFVK_IRQ_TYPE_OFF] =
				irq_page[irq_type + DFVK_IRQ_TYPE_OFF] + 1;

	/*
	 * This general (read-write) barrier is important here to ensure that
	 * the guest thread sees the correct value of the irq page after
	 * it is called by the interrupt that we are about to inject into the
	 * the guest.
	 */
	smp_mb();

inject:
	ret = __dfvk_inject_interrupt(kvm, DFVK_IRQ_NUM);

	EXIT_CRIT_SEC3;

	return ret;
}

static void dfvk_send_poll_notification(struct guest_thread_struct *guest_thread)
{
	struct dfvk_guest_thread_data *thread_data = guest_thread->private_data;

	dfvk_inject_interrupt(thread_data->current_vcpu->kvm, DFV_IRQ_POLL,
			guest_thread->guest_vm->private_data, guest_thread);
}

static void dfvk_send_drm_notification(struct guest_struct *guest, int type)
{
	struct dfvk_guest_vm_data *vm_data = guest->guest_vm->private_data;

	dfvk_inject_interrupt(vm_data->current_vcpu->kvm, type, 	vm_data, NULL);
}

static void dfvk_send_sigio(struct guest_struct *guest)
{
	struct dfvk_guest_vm_data *vm_data = guest->guest_vm->private_data;

	dfvk_inject_interrupt(vm_data->current_vcpu->kvm, DFV_IRQ_SIGIO,
								vm_data, NULL);
}

static void dfvk_share_page(struct guest_thread_struct *guest_thread,
		     struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	unsigned long addr;
	int ret;
	struct page *page;
	u32 access;
	struct dfvk_guest_thread_data *thread_data = guest_thread->private_data;

	access = 0;

	thread_data->sh_page_gfn = (gfn_t) DFVK_CUSTOM_SHARE_PAGE_GFN;

	addr = gfn_to_hva(thread_data->current_vcpu->kvm, thread_data->sh_page_gfn);
	if (kvm_is_error_hva(addr)) {
		DFVPRINTK_ERR("Error: gfn_to_hva failed\n");
		DFVK_CUSTOM_SHARE_PAGE_RESULT = -1;
		return;
	}

	ret = get_user_pages(current, current->mm, addr, 1, 1, 0, &page, NULL);
	if (ret != 1) {
        		DFVPRINTK_ERR("Error: Could not pin the page.\n");
        		DFVK_CUSTOM_SHARE_PAGE_RESULT = -1;
		return;
        }
        thread_data->sh_page_ptr = page;

        thread_data->sh_page_vaddr = vmap(&page, 1, 0, PAGE_KERNEL);
        if (!thread_data->sh_page_vaddr) {
        		DFVPRINTK_ERR("Error: Could not map in the page in the kernel.\n");
        		DFVK_CUSTOM_SHARE_PAGE_RESULT = -1;
        		put_page(page);
		return;
        }

	DFVK_CUSTOM_SHARE_PAGE_RESULT = 0;

	return;
}

void dfvk_set_up_irq_page(struct guest_thread_struct *guest_thread,
		     struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	unsigned long addr;
	int ret;
	struct page *page;
	struct dfvk_guest_vm_data *vm_data = guest_thread->guest_vm->private_data;

	vm_data->irq_gfn = DFVK_CUSTOM_IRQ_PAGE_GFN;

	addr = gfn_to_hva(vm_data->current_vcpu->kvm, vm_data->irq_gfn);
	if (kvm_is_error_hva(addr)) {
		DFVPRINTK_ERR("Error: gfn_to_hva failed\n");
		goto err_out;
	}

	ret = get_user_pages(current, current->mm, addr, 1, 1, 0, &page, NULL);
	if (ret != 1) {
        		DFVPRINTK_ERR("Error: Could not pin the page.\n");
        		goto err_out;
        }
        vm_data->irq_page_ptr = page;

        vm_data->irq_vaddr = vmap(&page, 1, 0, PAGE_KERNEL);
        if (!vm_data->irq_vaddr) {
        		DFVPRINTK_ERR("Error: Could not map in the page in the kernel.\n");
        		put_page(page);
        		goto err_out;
        }

	/*
	 * What is this for? This is a trick to avoid the core dfvserver module
	 * to remove the guest_vm_struct object. If all the open files are
	 * closed, the remove_guest_vm() will clear the guest_vm object. This
	 * normally causes no problem (e.g., with the Xen implementation) as a
	 * new guest_vm object will be allocated the next time there is a new
	 * op. But here, we set up the irq_page only once and we want it to
	 * stay. We will decrement this counter manually later in
	 * dfvk_clean_guest_vm().
	 */
	guest_thread->guest_vm->num_open_fds++;
	DFVK_CUSTOM_IRQ_PAGE_RESULT = 0;
	remove_guest_thread(guest_thread);
	return;
err_out:
	/* We couldn't map the page but we got the gfn */
	guest_thread->guest_vm->num_open_fds++;
	DFVK_CUSTOM_IRQ_PAGE_RESULT = -1;
	remove_guest_thread(guest_thread);
	return;
}

static void dfvk_clean_guest_vm(struct guest_vm_struct *guest_vm)
{
	struct dfvk_guest_vm_data *data = guest_vm->private_data;

	vunmap(data->irq_vaddr);
	put_page(data->irq_page_ptr);
	kfree(data->io_bitmap);
	kfree(data);
	guest_vm->num_open_fds--;
}

static void dfvk_finish_vm(struct guest_thread_struct *guest_thread,
		     struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	struct guest_vm_struct *guest_vm = guest_thread->guest_vm;

	dfvk_clean_guest_vm(guest_vm);
	remove_guest_thread(guest_thread);
	guest_vm->num_open_fds--;
	remove_guest_vm(guest_vm);
}

static void dfvk_custom_op(struct guest_thread_struct *guest_thread,
		      struct dfv_op_args *req_args, struct dfv_op_args *res_args)
{
	switch (DFVK_CUSTOM_OP) {

	case DFVK_CUSTOM_OP_SHARE_PAGE:

		dfvk_share_page(guest_thread, req_args, res_args);
		break;

	case DFVK_CUSTOM_OP_IRQ_PAGE:

		dfvk_set_up_irq_page(guest_thread, req_args, res_args);
		break;

	case DFVK_CUSTOM_OP_FINISH_VM:

		dfvk_finish_vm(guest_thread, req_args, res_args);
		break;

	default:
		DFVPRINTK_ERR("Error: Unsupported dfvk custom op %d\n",
						(int) DFVK_CUSTOM_OP);
		break;
	}
}

static int dfvk_init_guest_thread(struct guest_thread_struct *guest_thread);
static void __dfvk_clean_guest_thread(struct dfvk_guest_thread_data *thread_data);

static void dfvk_dispatch(struct work_struct *work)
{
	struct dfvk_dispatch_args *args;
	struct parse_args *pargs;
	struct guest_struct *guest;
	struct guest_thread_struct *guest_thread;
	struct kvm_vcpu *vcpu;
	enum dfv_op op;
	int irq_return, ret;
	struct dfv_op_args *req_args, *res_args;
	struct dfvk_guest_thread_data *thread_data = NULL;
	struct dfvk_guest_vm_data *vm_data;
	bool need_poll_wait = false;
	struct mm_struct *old_mm = NULL;
	struct dfvk_work_struct *dfvk_work =
			container_of(work, struct dfvk_work_struct, work);

	ENTER_CRIT_SEC2;

	args = dfvk_work->args;
	if (!args) {
		DFVPRINTK_ERR("Error: args is NULL!\n");
		dfvk_work->busy = false;
		goto err_out;
	}

	if (current->mm != args->mm) {
		old_mm = current->active_mm;
		current->mm = args->mm;
		current->active_mm = args->mm;
		activate_mm(old_mm, args->mm);
	}

	pargs = args->pargs;

	req_args = args->req;

	if (pargs->new_guest_thread) {
		ret = dfvk_init_guest_thread(pargs->guest_thread);
		if (ret) {
			DFVPRINTK_ERR("Error: dfvk_init_guest_thread failed\n");
			goto err_out;
		}
	}

	pargs->guest_thread->guest->private_data = (void *) args->cr3;

	/* FIMXE: we can update these only for mmap and fault. */

	guest_thread = pargs->guest_thread;
	guest = guest_thread->guest;
	thread_data = guest_thread->private_data;
	vm_data = guest_thread->guest_vm->private_data;
	current->dfvguest = guest;
	current->dfvguest_thread = guest_thread;
	vcpu = args->vcpu;
	op = pargs->op;

	if (thread_data->sh_page_vaddr) {
		memcpy(thread_data->sh_page, thread_data->sh_page_vaddr,
					DFVK_NUM_ARGS * sizeof(unsigned long));
	} else if (thread_data->sh_page_gfn) {

		ret = kvm_read_guest_page(vcpu->kvm, thread_data->sh_page_gfn,
					thread_data->sh_page, 0,
					DFVK_NUM_ARGS * sizeof(unsigned long));
		if (ret)
			DFVPRINTK_ERR("Error: kvm_read_guest_page failed\n");
	} else {
		/* Only a problem for file ops with more than 4 req args */
		if (pargs->op == DFV_EOP_fault1 || pargs->op == DFV_EOP_fault2 ||
		    pargs->op == DFV_FOP_mmap || pargs->op == DFV_FOP_open ||
		    pargs->op == DFV_FOP_poll || pargs->op == DFV_FOP_read ||
		    pargs->op == DFV_FOP_write || pargs->op == DFV_VMOP_close ||
		    pargs->op == DFV_VMOP_open) {
			DFVPRINTK_ERR("Error: couldn't read the shared page\n");
		    	goto err_out;
		}
	}

	req_args->arg_5 = DFVK_REQ_ARG_5;
	req_args->arg_6 = DFVK_REQ_ARG_6;

	thread_data->current_vcpu = args->vcpu;
	vm_data->current_vcpu = args->vcpu;

	res_args = (struct dfv_op_args *) (thread_data->sh_page +
							DFVK_SH_PAGE_RES_OFF);

	if (op == DFV_OP_custom)
		dfvk_custom_op(guest_thread, req_args, res_args);
	else
		dispatch_dfv_op(req_args, res_args, pargs);

	DFVK_RES_ARGS_READY = 1;

	if (thread_data && thread_data->sh_page_vaddr) {
		memcpy(thread_data->sh_page_vaddr, thread_data->sh_page,
					DFVK_NUM_ARGS * sizeof(unsigned long));
	} else if (thread_data && thread_data->sh_page_gfn) {
		ret = kvm_write_guest_page(vcpu->kvm, thread_data->sh_page_gfn,
					thread_data->sh_page, 0,
					DFVK_NUM_ARGS*sizeof(unsigned long));
		if (ret)
			DFVPRINTK_ERR("Error: kvm_write_guest_page failed!\n");
	} else {
		DFVPRINTK_ERR("Error: couldn't write the results!\n");
	}

	/*
	 * This general (read-write) barrier is important here to ensure that
	 * the guest thread sees the correct value of the shared page after
	 * it is woken by the interrupt that we are about to inject into the
	 * the guest.
	 */
	smp_mb();

	irq_return = dfvk_inject_interrupt(vcpu->kvm, DFV_IRQ_CUSTOM,
			guest_thread->guest_vm->private_data, NULL);

	NEED_POLL_WAIT(guest_thread, need_poll_wait);

	if (current->mm) {
		current->mm = NULL;
		current->active_mm = old_mm;

	}

	EXIT_CRIT_SEC2;

	if (need_poll_wait)
		wait_for_poll(guest_thread);

	goto out;
err_out:
	EXIT_CRIT_SEC2;
out:
	kfree(args->pargs);
	kfree(args->req);
	kfree(args);
	dfvk_work->busy = false;

	/*
	 * These test and set must be done atomically, since multiple
	 * threads might be executing this at the same time and we only want
	 * one of them to clean the thread_data.
	 */
	spin_lock(&dfv_server_kvm_spinlock);
	if (thread_data && thread_data->must_clean) {
		thread_data->must_clean = false;
		__dfvk_clean_guest_thread(thread_data);
	}
	spin_unlock(&dfv_server_kvm_spinlock);

	return;
}

static unsigned long dfvk_core_copy_from_user(struct guest_thread_struct *guest_thread,
					struct guest_struct *guest, void *to,
					const void __user *from, unsigned long n)
{
	gpa_t gpa;
	gva_t gva = (gva_t) from;
	gfn_t gfn;
	int offset = offset_in_page(gva);
	int ret, seg;
	struct kvm_vcpu *vcpu;
	unsigned long len = n;
	unsigned long success_len = 0;
	u32 access;
	int counter = 0;
	int idx;
	struct dfvk_guest_thread_data *thread_data = guest_thread->private_data;

	vcpu = thread_data->current_vcpu;

	access = 0;

	while ((seg = next_segment(len, offset)) != 0) {

		gpa = vcpu->arch.walk_mmu->gva_to_gpa_preempted(vcpu, gva,
			access, NULL, (unsigned long) guest->private_data);
		if (gpa == UNMAPPED_GVA) {
			DFVPRINTK_ERR("Error: gva_to_gpa failed!\n");
			goto out;
		}
		gfn = gpa >> PAGE_SHIFT;

		counter++;

		/* FIXME: do we need this lock? */
		idx = srcu_read_lock(&vcpu->kvm->srcu);
		ret = kvm_read_guest_page(vcpu->kvm, gfn, to, offset, seg);
		srcu_read_unlock(&vcpu->kvm->srcu, idx);
		if (ret) {
			DFVPRINTK_ERR("Error: kvm_read_guest_page failed!\n");
			goto out;
		}
		offset = 0;
		len -= seg;
		to += seg;
		success_len += seg;
		gva += seg;
	}
out:
	return success_len;
}

static unsigned long dfvk_core_copy_to_user(struct guest_thread_struct *guest_thread,
				      struct guest_struct *guest, void __user *to,
				      const void *from, unsigned long n)
{
	gpa_t gpa;
	gva_t gva = (gva_t) to;
	gfn_t gfn;
	int offset = offset_in_page(gva);
	int ret, seg;
	struct kvm_vcpu *vcpu;
	unsigned long len = n;
	unsigned long success_len = 0;
	u32 access;
	int counter = 0;
	int idx;
	struct dfvk_guest_thread_data *thread_data = guest_thread->private_data;

	vcpu = thread_data->current_vcpu;

	access = 0;

	while ((seg = next_segment(len, offset)) != 0) {
		gpa = vcpu->arch.walk_mmu->gva_to_gpa_preempted(vcpu, gva,
			access, NULL, (unsigned long) guest->private_data);
		if (gpa == UNMAPPED_GVA) {
			DFVPRINTK_ERR("Error: gva_to_gpa failed!\n");
			goto out;
		}
		gfn = gpa >> PAGE_SHIFT;

		counter++;

		/* FIXME: do we need this lock? */
		idx = srcu_read_lock(&vcpu->kvm->srcu);
		ret = kvm_write_guest_page(vcpu->kvm, gfn, from, offset, seg);
		srcu_read_unlock(&vcpu->kvm->srcu, idx);
		if (ret) {
			DFVPRINTK_ERR("Error: kvm_write_guest_page failed!\n");
		}
		offset = 0;
		len -= seg;
		from += seg;
		success_len += seg;
		gva += seg;
	}
out:
	return success_len;
}

static void dfv_put_io_gfn(struct guest_struct *guest, gfn_t gfn);

/*
 * We get here as a result of munmapping a vma by the guest process.
 * The guest itself cleans up its own page tables. Here, we need to
 * clean up the gfn's used for this mapping (vma).
 */
/* FIXME: how about cleaning up the EPT? */
static int dfvk_revert_pgtables(struct guest_thread_struct *guest_thread,
			struct guest_struct *guest, struct vm_area_struct *vma,
			unsigned long start_addr, unsigned long end_addr)
{
	struct vma_list_struct *vma_entry;
	struct vma_gfn_list_struct *gfn_entry = NULL, *g_tmp;
	struct kvm_memory_slot *dfv_slot;
	struct vma_pfn_list_struct *pfn_entry = NULL, *p_tmp;
	struct page *page;
	struct dfvk_guest_vm_data *vm_data = guest->guest_vm->private_data;

	/* clean our own bitmap */
	vma_entry = get_vma_entry(guest, vma);
	if (!vma_entry) {
		DFVPRINTK_ERR("Error: could not find the vma_entry\n");
	} else {

		dfv_slot = vm_data->dfv_io_mem.dfv_slot;
		list_for_each_entry_safe(gfn_entry, g_tmp,
						&vma_entry->gfn_list, list) {

			dfv_put_io_gfn(guest, gfn_entry->gfn);
			list_del(&gfn_entry->list);
			kfree(gfn_entry);
		}
		list_for_each_entry_safe(pfn_entry, p_tmp,
						&vma_entry->pfn_list, list) {

			page = pfn_to_page(pfn_entry->pfn);
			list_del(&pfn_entry->list);
			kfree(pfn_entry);
		}
	}

	return 0;
}

static int cmp_slots(const void *elem1, const void *elem2)
{
	struct kvm_slot_sort *slot1, *slot2;

	slot1 = (struct kvm_slot_sort *) elem1;
	slot2 = (struct kvm_slot_sort *) elem2;

	return (int)(slot1->base_gfn - slot2->base_gfn);
}

#define MAX_GFN 0xfffff /* for 32 bit architecture */

static int init_guest_dfv_mem_slot(struct kvm_vcpu *vcpu,
					struct dfv_mem_slot_struct *dfv_mem)
{
	struct kvm_userspace_memory_region *mem;
	gfn_t guest_slot_start_gfn = (gfn_t) 0;
	int i, ret;
	struct kvm_slot_sort slots_sort[vcpu->kvm->memslots->nmemslots + 1];

	mem = &dfv_mem->mem;

	for (i = 0; i < vcpu->kvm->memslots->nmemslots; i++) {
		struct kvm_memory_slot *s =
			&vcpu->kvm->memslots->memslots[i];

		slots_sort[i].base_gfn = s->base_gfn;
		slots_sort[i].npages = s->npages;
	}
	slots_sort[vcpu->kvm->memslots->nmemslots].base_gfn = MAX_GFN;
	slots_sort[vcpu->kvm->memslots->nmemslots].npages = 0;

	sort(slots_sort, vcpu->kvm->memslots->nmemslots,
	     sizeof(struct kvm_slot_sort), cmp_slots, NULL);

	/*
	 * FIXME: Do we need some form of synchronization for this? If someone
	 * else requests this slot number from now until we request it,
	 * then we're in trouble.
	 */
	mem->slot = vcpu->kvm->memslots->nmemslots;
	mem->memory_size = dfv_mem->nr_pages * PAGE_SIZE;

	guest_slot_start_gfn = 0;
	for (i = 0; i <= vcpu->kvm->memslots->nmemslots; i++) {
		struct kvm_slot_sort *s = &slots_sort[i];

		if (guest_slot_start_gfn + dfv_mem->nr_pages < s->base_gfn &&
		    guest_slot_start_gfn != 0)
			break;

		guest_slot_start_gfn = s->base_gfn + s->npages;
		/*
		 * FIXME: do we need to make sure our gfn's don't
		 * overlap with the guest MMIO addresses or is it already
		 * taken care of?
		 */
	}

	if (guest_slot_start_gfn == MAX_GFN || guest_slot_start_gfn == 0) {
		DFVPRINTK_ERR("Error: could not find a contiguous set of "
		        "%d pages in guest for dfv mem slot\n",

		        dfv_mem->nr_pages);

		return -1;
	}

	mem->guest_phys_addr = guest_slot_start_gfn << PAGE_SHIFT;

	/* FIXME: we need to release the mem region in dfvk_clean_guest_vm() */
	ret = kvm_set_memory_region(vcpu->kvm, mem, 0);

	if (ret) {
		DFVPRINTK_ERR("Error: could not allocate a memory "
			"region for dfv pages\n");
		return -1;
	}

	dfv_mem->has_slot = true;
	dfv_mem->dfv_slot = &vcpu->kvm->memslots->memslots[mem->slot];

	return 0;
}

static gfn_t dfv_get_gfn_core(struct kvm_vcpu *vcpu,
					struct dfv_mem_slot_struct *dfv_mem)
{
	struct kvm_memory_slot *dfv_slot;
	int ret, page_nr;
	gfn_t gfn;

	if (!dfv_mem->has_slot) {
		/*
		 * This is the first time we want to map a pfn into user pages,
		 * and we have not allocated a mem slot in the guest for it,
		 * which we do now.
		 */
		ret = init_guest_dfv_mem_slot(vcpu, dfv_mem);

		if (ret == -1)
			goto err_out;
	}

	/* Now we get one gfn from the dfv_mem_slot for this pfn */
	dfv_slot = dfv_mem->dfv_slot;
	/*
	 * FIXME: we need a lock here until after set_bit. This is
	 * to make sure that different threads get different gfn's.
	 */
	page_nr = find_first_zero_bit(dfv_mem->dfv_slot_bitmap, dfv_mem->nr_pages);
	if (page_nr >= dfv_mem->nr_pages) {
		DFVPRINTK_ERR("Error: no more free pages.in dfv mem\n");

		goto err_out;
	}
	gfn = dfv_slot->base_gfn + page_nr;

	set_bit(page_nr, dfv_mem->dfv_slot_bitmap);

	return gfn;

err_out:
	return 0;
}

static gfn_t dfv_get_io_gfn(struct guest_struct *guest, struct kvm_vcpu *vcpu)
{
	struct dfvk_guest_vm_data *vm_data = guest->guest_vm->private_data;

	return dfv_get_gfn_core(vcpu, &vm_data->dfv_io_mem);
}

static void dfv_put_io_gfn(struct guest_struct *guest, gfn_t gfn)
{
	int page_nr;
	struct dfvk_guest_vm_data *vm_data = guest->guest_vm->private_data;
	struct kvm_memory_slot *dfv_slot = vm_data->dfv_io_mem.dfv_slot;

	page_nr = gfn - dfv_slot->base_gfn;
	clear_bit(page_nr, vm_data->dfv_io_mem.dfv_slot_bitmap);
}

static int dfvk_core_insert_pfn(struct guest_thread_struct *guest_thread,
			  struct guest_struct *guest, struct vm_area_struct *vma,
			  unsigned long addr, unsigned long pfn, pgprot_t prot)
{
	struct guest_walker walker;
	int r, ret;
	u32 uaccess = 1;
	struct kvm_vcpu *vcpu;
	int offset;
	pt_element_t __user *uninitialized_var(ptep_user);
	unsigned long host_addr;
	pte_t gfn_prot;
	gfn_t gfn;
	gpa_t gpa;
	struct vma_list_struct *vma_entry;
	struct dfvk_guest_thread_data *thread_data = guest_thread->private_data;
	int write, dir_level;
	bool map_writable, prefault;
	struct vma_pfn_list_struct *pfn_entry;
	struct vma_gfn_list_struct *gfn_entry;

	current->dfvcontext_kvm = true;

	vcpu = thread_data->current_vcpu;

	gfn = dfv_get_io_gfn(guest, vcpu);

	if (gfn == 0) {
		DFVPRINTK_ERR("Error: gfn is NULL\n");
		goto err_out1;
	}

	gpa = (gfn << PAGE_SHIFT) + (addr  & ~PAGE_MASK);

	vma_entry = get_vma_entry(guest, vma);
	if (vma_entry) {

		gfn_entry = kmalloc(sizeof(*gfn_entry), GFP_KERNEL);
		if (!gfn_entry) {
			DFVPRINTK_ERR("Error: could not allocate gfn_entry\n");
			goto err_out2;
		}
		gfn_entry->gfn = gfn;
		INIT_LIST_HEAD(&gfn_entry->list);
		list_add(&gfn_entry->list, &vma_entry->gfn_list);

		pfn_entry = kmalloc(sizeof(*pfn_entry), GFP_KERNEL);
		if (!pfn_entry) {
			DFVPRINTK_ERR("Error: could not allocate pfn_entry\n");
			goto err_out3;
		}
		pfn_entry->pfn = pfn;
		INIT_LIST_HEAD(&pfn_entry->list);
		list_add(&pfn_entry->list, &vma_entry->pfn_list);
	} else {
		DFVPRINTK_ERR("Error: could not find the vma_entry\n");
		goto err_out2;
	}

	gfn_prot = pte_mkspecial(pfn_pte(gfn, prot));

	r = vcpu->arch.walk_mmu->walk_addr_preempted(&walker, vcpu, addr,
				uaccess, (unsigned long) guest->private_data);

	if (walker.level == 0) {
		/*
		 * FIXME: if we got here, it means that the address is already
		 * mapped. Will this ever happen? If yes, how to handle?
		 */
		 DFVPRINTK_ERR("Error: walker.level == 0\n");
		 goto err_out4;
	}

	if (walker.level > 1) {
		/*
		 * This should not happen as the client is supposed to fix
		 * its page tables before we get here.
		 */
		 DFVPRINTK_ERR("Error: walker.level > 1\n");
		 goto err_out4;
	}

	offset = walker.pte_gpa[0] & ~PAGE_MASK;
	host_addr = gfn_to_hva(vcpu->kvm, walker.table_gfn[0]);
	ptep_user = (pt_element_t __user *) ((void *) host_addr + offset);
	__copy_to_user(ptep_user, &gfn_prot, sizeof(unsigned long));

	write = prot.pgprot & _PAGE_RW;
	map_writable = true;
	prefault = false;
	dir_level = 1;

	ret = vcpu->arch.walk_mmu->__direct_map(vcpu, gpa, write, map_writable,
						dir_level, gfn, pfn, prefault);

	if (ret < 0) {
		DFVPRINTK_ERR("Error: unsuccessful __direct_map, "
			   "ret = %d\n", ret);
		goto err_out4;
	}

	current->dfvcontext_kvm = false;
	return 0;

err_out4:
	list_del(&pfn_entry->list);
	kfree(pfn_entry);
err_out3:
	list_del(&gfn_entry->list);
	kfree(gfn_entry);
err_out2:
	dfv_put_io_gfn(guest, gfn);
err_out1:
	current->dfvcontext_kvm = false;
	return -ENOMEM;
}

static int dfvk_init_guest_vm(struct guest_vm_struct *guest_vm)
{
	int i;
	struct dfvk_guest_vm_data *data;
	struct dfv_io_mem_bitmap_struct *io_bitmap;

	if (guest_vm->private_data)
		return 0;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		DFVPRINTK_ERR("Error: could not allocate data\n");
		return -ENOMEM;
	}

	data->dfv_io_mem.has_slot = false;
	data->dfv_io_mem.nr_pages = DFV_IO_MEM_SLOT_NR_PAGES;
	io_bitmap = kmalloc(sizeof(*io_bitmap), GFP_KERNEL);
	if (!io_bitmap) {
		DFVPRINTK_ERR("Error: could not allocate io_bitmap\n");
		return -ENOMEM;
	}
	data->dfv_io_mem.dfv_slot_bitmap =
				(unsigned long *) &io_bitmap->dfv_slot_bitmap;
	data->io_bitmap = io_bitmap;
	bitmap_zero(data->dfv_io_mem.dfv_slot_bitmap, DFV_IO_MEM_SLOT_NR_PAGES);

	guest_vm->private_data = (void *) data;
	guest_vm->send_sigio = dfvk_send_sigio;
	guest_vm->copy_from_user = dfvk_core_copy_from_user;
	guest_vm->copy_to_user = dfvk_core_copy_to_user;
	guest_vm->insert_pfn = dfvk_core_insert_pfn;
	guest_vm->revert_pgtables = dfvk_revert_pgtables;
	guest_vm->send_poll_notification = dfvk_send_poll_notification;
	guest_vm->send_drm_notification = dfvk_send_drm_notification;

	data->wq = alloc_workqueue("dfv", WQ_HIGHPRI, DFVK_NUM_WORKS);
	if (!data->wq) {
		DFVPRINTK_ERR("Error: could not create workqueue.\n");
		return -EFAULT;
	}

	for (i = 0; i < DFVK_NUM_WORKS; i++) {
		INIT_WORK(&data->works[i].work, dfvk_dispatch);

		data->works[i].busy = false;
	}

	return 0;
}

static void __dfvk_clean_guest_thread(struct dfvk_guest_thread_data *data)
{
	vunmap(data->sh_page_vaddr);
	put_page(data->sh_page_ptr);
	kfree(data);
}

static void dfvk_clean_guest_thread(struct guest_thread_struct *guest_thread)
{
	struct dfvk_guest_thread_data *data = guest_thread->private_data;

	data->must_clean = true;
}

static int dfvk_init_guest_thread(struct guest_thread_struct *guest_thread)
{
	struct dfvk_guest_thread_data *data;

	if (guest_thread->private_data)
		return 0;

	guest_thread->use_non_blocking_poll = true;
	guest_thread->need_poll_wait = false;
	guest_thread->poll_sleep = false;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		DFVPRINTK_ERR("Error: could not allocate data\n");
		return -ENOMEM;
	}
	guest_thread->private_data = (void *) data;
	guest_thread->clean_guest_thread = dfvk_clean_guest_thread;

	return 0;
}

static int __dfv_kvm_op_handler(struct kvm_vcpu *vcpu, unsigned long a0,
		                unsigned long a1, unsigned long a2,
				unsigned long a3)
{
	struct parse_args *pargs;
	int err;
	pt_element_t current_cr3;

	struct dfvk_guest_vm_data *vm_data;
	struct dfv_op_args *req;
	struct dfvk_dispatch_args *args;
	struct work_struct *wrk;
	int work_index;
	struct workqueue_struct *wq;
	int retval = 0;

	ENTER_CRIT_SEC;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		DFVPRINTK_ERR("Error: could not allocate memory for req\n");
		retval = -KVM_EFAULT;
		goto err_out;
	}

	pargs = kzalloc(sizeof(*pargs), GFP_KERNEL);
	if (!pargs) {
		DFVPRINTK_ERR("Error: could not allocate memory for pargs\n");
		retval = -KVM_EFAULT;
		goto err_out2;
	}

	req->arg_1 = a0;
	req->arg_2 = a1;
	req->arg_3 = a2;
	req->arg_4 = a3;

	err = parse_op_args(req, current->tgid, pargs);
	if (err) {
		DFVPRINTK_ERR("Error: parse_op_args failed\n");
		retval = -KVM_EFAULT;
		goto err_out3;
	}

	err = dfvk_init_guest_vm(pargs->guest_thread->guest_vm);
	if (err) {
		DFVPRINTK_ERR("Error: dfvk_init_guest_vm failed\n");
		retval = -KVM_EFAULT;
		goto err_out3;
	}
	vm_data = pargs->guest_thread->guest_vm->private_data;

	/*
	 * In the case of non-blocking calls, the page table info of the guest
	 * process cannot be directly read from the vcpu whenever needed, since
	 * the guest thread might be preempted. Therefore, we store the page
	 * table references that we need, e.g., the CR3 register value, and use
	 * it later, when needed.
	 */
	current_cr3 = vcpu->arch.mmu.get_cr3(vcpu);

	args = kmalloc(sizeof(*args), GFP_KERNEL);
	if (!args) {
		DFVPRINTK_ERR("Error: could not allocate args\n");
		retval = -KVM_EFAULT;
		goto err_out3;
	}

	args->pargs = pargs;
	args->req = req;
	args->cr3 = current_cr3;
	args->vcpu = vcpu;
	args->mm = current->mm;

again:
	work_index = vm_data->works_counter % DFVK_NUM_WORKS;
	vm_data->works_counter++;

	if (vm_data->works[work_index].busy) {
		goto again;
	}

	vm_data->works[work_index].busy = true;
	vm_data->works[work_index].args = args;

	wrk = &vm_data->works[work_index].work;
	wq = vm_data->wq;

	if (vm_data->wq)
		queue_work(wq, wrk);
	else
		DFVPRINTK_ERR("Error: wq is NULL\n");

	EXIT_CRIT_SEC;

	if (pargs->op == DFV_OP_custom && req->arg_3 == DFVK_CUSTOM_OP_FINISH_VM) {
		destroy_workqueue(wq);
	}

	return 0;

err_out3:
	kfree(pargs);
err_out2:
	kfree(req);
err_out:
	EXIT_CRIT_SEC;
	return retval;
}

static int __init dfv_server_kvm_init(void)
{
	dfv_kvm_op_handler = __dfv_kvm_op_handler;
	spin_lock_init(&dfv_server_kvm_spinlock);
	dfv_drm_use_full();

	return 0;
}

static void __exit dfv_server_kvm_exit(void)
{
	/* Nothing to be done here for now */
}

module_init(dfv_server_kvm_init);
module_exit(dfv_server_kvm_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Server support for KVM for Device File-based I/O "
		   "Virtualization");
MODULE_LICENSE("GPL");
