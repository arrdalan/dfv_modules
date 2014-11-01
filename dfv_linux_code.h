/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_linux_code.h
 *
 * This file contains code copied from Linux.
 * For licensing, please refer to the original Linux files.
 */

#ifndef _DFV_LINUX_CODE_H_
#define _DFV_LINUX_CODE_H_

#ifdef CONFIG_X86
#include <linux/kvm_host.h>
#include <linux/bootmem.h> /* max_low_pfn */
#endif /* CONFIG_X86 */

/* The next three are from fs/select.c */
#define POLLIN_SET (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR)
#define POLLOUT_SET (POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR)
#define POLLEX_SET (POLLPRI)

#ifdef CONFIG_X86
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

/* adopted from arch/x86/mm/fault.c */
static bool low_pfn(unsigned long pfn)
{
	return pfn < max_low_pfn;
}
#endif /* CONFIG_X86 */

#ifdef CONFIG_ARM
/* from arch/arm/mm/fault.c */
#define FSR_WRITE               (1 << 11)
#define VM_FAULT_BADACCESS      0x020000

/* For sound ioctls - start */
/* from include/sound/asound.h */
typedef unsigned long snd_pcm_uframes_t;
typedef signed long snd_pcm_sframes_t;


struct snd_xferi {
	snd_pcm_sframes_t result;
	void __user *buf;
	snd_pcm_uframes_t frames;
};

#define SNDRV_PCM_IOCTL_WRITEI_FRAMES	_IOW('A', 0x50, struct snd_xferi)
/* For sound ioctls - end */

#endif /* CONFIG_ARM */

#endif /* _DFV_LINUX_CODE_H_ */
