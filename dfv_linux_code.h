/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_linux_code.h
 *
 * This file contains code copied from Linux.
 * For licensing, please refer to the original Linux files.
 */

#ifndef _DFV_LINUX_CODE_H_
#define _DFV_LINUX_CODE_H_
/* The next three are from fs/select.c */
#define POLLIN_SET (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR)
#define POLLOUT_SET (POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR)
#define POLLEX_SET (POLLPRI)

#include <linux/kvm_host.h>
/* from arch/x86/kvm/mmu.c */
#define PTE_PREFETCH_NUM		8

/* from arch/x86/kvm/paging_tmpl.h (unitl and including the guest_walker) */
#ifdef CONFIG_X86_64
#define PT_MAX_FULL_LEVELS 4
#define pt_element_t u64
#else
#define PT_MAX_FULL_LEVELS 2
#define pt_element_t u32
#endif

struct guest_walker {
	int level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t ptes[PT_MAX_FULL_LEVELS];
	pt_element_t prefetch_ptes[PTE_PREFETCH_NUM];
	gpa_t pte_gpa[PT_MAX_FULL_LEVELS];
	unsigned pt_access;
	unsigned pte_access;
	gfn_t gfn;
	struct x86_exception fault;
};


/* from virt/kvm/kvm_main.c */
int next_segment(unsigned long len, int offset)
{
	if (len > PAGE_SIZE - offset)
		return PAGE_SIZE - offset;
	else
		return len;
}

#endif /* _DFV_LINUX_CODE_H_ */
