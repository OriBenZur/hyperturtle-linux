// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * MMU support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 */

#include "irq.h"
#include "ioapic.h"
#include "mmu.h"
#include "mmu_internal.h"
#include "tdp_mmu.h"
#include "x86.h"
#include "kvm_cache_regs.h"
#include "kvm_emulate.h"
#include "cpuid.h"
#include "spte.h"

#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/compiler.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/kern_levels.h>
#include <linux/kthread.h>

#include <asm/page.h>
#include <asm/memtype.h>
#include <asm/cmpxchg.h>
#include <asm/io.h>
#include <asm/set_memory.h>
#include <asm/vmx.h>
#include <asm/kvm_page_track.h>
#include "trace.h"

#include "paging.h"
#include "../vmx/nested.h"

extern bool itlb_multihit_kvm_mitigation;

int __read_mostly nx_huge_pages = -1;
static uint __read_mostly nx_huge_pages_recovery_period_ms;
#ifdef CONFIG_PREEMPT_RT
/* Recovery can cause latency spikes, disable it for PREEMPT_RT.  */
static uint __read_mostly nx_huge_pages_recovery_ratio = 0;
#else
static uint __read_mostly nx_huge_pages_recovery_ratio = 60;
#endif

static int set_nx_huge_pages(const char *val, const struct kernel_param *kp);
static int set_nx_huge_pages_recovery_param(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops nx_huge_pages_ops = {
	.set = set_nx_huge_pages,
	.get = param_get_bool,
};

static const struct kernel_param_ops nx_huge_pages_recovery_param_ops = {
	.set = set_nx_huge_pages_recovery_param,
	.get = param_get_uint,
};

module_param_cb(nx_huge_pages, &nx_huge_pages_ops, &nx_huge_pages, 0644);
__MODULE_PARM_TYPE(nx_huge_pages, "bool");
module_param_cb(nx_huge_pages_recovery_ratio, &nx_huge_pages_recovery_param_ops,
		&nx_huge_pages_recovery_ratio, 0644);
__MODULE_PARM_TYPE(nx_huge_pages_recovery_ratio, "uint");
module_param_cb(nx_huge_pages_recovery_period_ms, &nx_huge_pages_recovery_param_ops,
		&nx_huge_pages_recovery_period_ms, 0644);
__MODULE_PARM_TYPE(nx_huge_pages_recovery_period_ms, "uint");

static bool __read_mostly force_flush_and_sync_on_reuse;
module_param_named(flush_on_reuse, force_flush_and_sync_on_reuse, bool, 0644);

/*
 * When setting this variable to true it enables Two-Dimensional-Paging
 * where the hardware walks 2 page tables:
 * 1. the guest-virtual to guest-physical
 * 2. while doing 1. it walks guest-physical to host-physical
 * If the hardware supports that we don't need to do shadow paging.
 */
bool tdp_enabled = false;

static int max_huge_page_level __read_mostly;
static int tdp_root_level __read_mostly;
static int max_tdp_level __read_mostly;

enum {
	AUDIT_PRE_PAGE_FAULT,
	AUDIT_POST_PAGE_FAULT,
	AUDIT_PRE_PTE_WRITE,
	AUDIT_POST_PTE_WRITE,
	AUDIT_PRE_SYNC,
	AUDIT_POST_SYNC
};

#ifdef MMU_DEBUG
bool dbg = 0;
module_param(dbg, bool, 0644);
#endif

#define PTE_PREFETCH_NUM		8

#define PT32_LEVEL_BITS 10

#define PT32_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT32_LEVEL_BITS)

#define PT32_LVL_OFFSET_MASK(level) \
	(PT32_BASE_ADDR_MASK & ((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT32_LEVEL_BITS))) - 1))

#define PT32_INDEX(address, level)\
	(((address) >> PT32_LEVEL_SHIFT(level)) & ((1 << PT32_LEVEL_BITS) - 1))


#define PT32_BASE_ADDR_MASK PAGE_MASK
#define PT32_DIR_BASE_ADDR_MASK \
	(PAGE_MASK & ~((1ULL << (PAGE_SHIFT + PT32_LEVEL_BITS)) - 1))
#define PT32_LVL_ADDR_MASK(level) \
	(PAGE_MASK & ~((1ULL << (PAGE_SHIFT + (((level) - 1) \
					    * PT32_LEVEL_BITS))) - 1))

#include <trace/events/kvm.h>

/* make pte_list_desc fit well in cache lines */
#define PTE_LIST_EXT 14

/*
 * Slight optimization of cacheline layout, by putting `more' and `spte_count'
 * at the start; then accessing it will only use one single cacheline for
 * either full (entries==PTE_LIST_EXT) case or entries<=6.
 */
struct pte_list_desc {
	struct pte_list_desc *more;
	/*
	 * Stores number of entries stored in the pte_list_desc.  No need to be
	 * u64 but just for easier alignment.  When PTE_LIST_EXT, means full.
	 */
	u64 spte_count;
	u64 *sptes[PTE_LIST_EXT];
};

struct kvm_shadow_walk_iterator {
	u64 addr;
	hpa_t shadow_addr;
	u64 *sptep;
	int level;
	unsigned index;
};

#define for_each_shadow_entry_using_root(_vcpu, _root, _addr, _walker)     \
	for (shadow_walk_init_using_root(&(_walker), (_vcpu),              \
					 (_root), (_addr));                \
	     shadow_walk_okay(&(_walker));			           \
	     shadow_walk_next(&(_walker)))

#define for_each_shadow_entry(_vcpu, _addr, _walker)            \
	for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
	     shadow_walk_okay(&(_walker));			\
	     shadow_walk_next(&(_walker)))

#define for_each_shadow_entry_lockless(_vcpu, _addr, _walker, spte)	\
	for (shadow_walk_init(&(_walker), _vcpu, _addr);		\
	     shadow_walk_okay(&(_walker)) &&				\
		({ spte = mmu_spte_get_lockless(_walker.sptep); 1; });	\
	     __shadow_walk_next(&(_walker), spte))

static struct kmem_cache *pte_list_desc_cache;
struct kmem_cache *mmu_page_header_cache;
static struct percpu_counter kvm_total_used_mmu_pages;

static void mmu_spte_set(u64 *sptep, u64 spte);
static union kvm_mmu_page_role
kvm_mmu_calc_root_page_role(struct kvm_vcpu *vcpu);

struct kvm_mmu_role_regs {
	const unsigned long cr0;
	const unsigned long cr4;
	const u64 efer;
};

#define CREATE_TRACE_POINTS
#include "mmutrace.h"

/*
 * Yes, lot's of underscores.  They're a hint that you probably shouldn't be
 * reading from the role_regs.  Once the mmu_role is constructed, it becomes
 * the single source of truth for the MMU's state.
 */
#define BUILD_MMU_ROLE_REGS_ACCESSOR(reg, name, flag)			\
static inline bool __maybe_unused ____is_##reg##_##name(struct kvm_mmu_role_regs *regs)\
{									\
	return !!(regs->reg & flag);					\
}
BUILD_MMU_ROLE_REGS_ACCESSOR(cr0, pg, X86_CR0_PG);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr0, wp, X86_CR0_WP);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, pse, X86_CR4_PSE);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, pae, X86_CR4_PAE);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, smep, X86_CR4_SMEP);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, smap, X86_CR4_SMAP);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, pke, X86_CR4_PKE);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, la57, X86_CR4_LA57);
BUILD_MMU_ROLE_REGS_ACCESSOR(efer, nx, EFER_NX);
BUILD_MMU_ROLE_REGS_ACCESSOR(efer, lma, EFER_LMA);

/*
 * The MMU itself (with a valid role) is the single source of truth for the
 * MMU.  Do not use the regs used to build the MMU/role, nor the vCPU.  The
 * regs don't account for dependencies, e.g. clearing CR4 bits if CR0.PG=1,
 * and the vCPU may be incorrect/irrelevant.
 */
#define BUILD_MMU_ROLE_ACCESSOR(base_or_ext, reg, name)		\
static inline bool __maybe_unused is_##reg##_##name(struct kvm_mmu *mmu)	\
{								\
	return !!(mmu->mmu_role. base_or_ext . reg##_##name);	\
}
BUILD_MMU_ROLE_ACCESSOR(ext,  cr0, pg);
BUILD_MMU_ROLE_ACCESSOR(base, cr0, wp);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, pse);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, pae);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, smep);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, smap);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, pke);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, la57);
BUILD_MMU_ROLE_ACCESSOR(base, efer, nx);

static struct kvm_mmu_role_regs vcpu_to_role_regs(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_role_regs regs = {
		.cr0 = kvm_read_cr0_bits(vcpu, KVM_MMU_CR0_ROLE_BITS),
		.cr4 = kvm_read_cr4_bits(vcpu, KVM_MMU_CR4_ROLE_BITS),
		.efer = vcpu->arch.efer,
	};

	return regs;
}

static int role_regs_to_root_level(struct kvm_mmu_role_regs *regs)
{
	if (!____is_cr0_pg(regs))
		return 0;
	else if (____is_efer_lma(regs))
		return ____is_cr4_la57(regs) ? PT64_ROOT_5LEVEL :
					       PT64_ROOT_4LEVEL;
	else if (____is_cr4_pae(regs))
		return PT32E_ROOT_LEVEL;
	else
		return PT32_ROOT_LEVEL;
}

static inline bool kvm_available_flush_tlb_with_range(void)
{
	return kvm_x86_ops.tlb_remote_flush_with_range;
}

static void kvm_flush_remote_tlbs_with_range(struct kvm *kvm,
		struct kvm_tlb_range *range)
{
	int ret = -ENOTSUPP;

	if (range && kvm_x86_ops.tlb_remote_flush_with_range)
		ret = static_call(kvm_x86_tlb_remote_flush_with_range)(kvm, range);

	if (ret)
		kvm_flush_remote_tlbs(kvm);
}

void kvm_flush_remote_tlbs_with_address(struct kvm *kvm,
		u64 start_gfn, u64 pages)
{
	struct kvm_tlb_range range;

	range.start_gfn = start_gfn;
	range.pages = pages;

	kvm_flush_remote_tlbs_with_range(kvm, &range);
}
EXPORT_SYMBOL_GPL(kvm_flush_remote_tlbs_with_address);


static void mark_mmio_spte(struct kvm_vcpu *vcpu, u64 *sptep, u64 gfn,
			   unsigned int access)
{
	u64 spte = make_mmio_spte(vcpu, gfn, access);

	trace_mark_mmio_spte(sptep, gfn, spte);
	mmu_spte_set(sptep, spte);
}

static gfn_t get_mmio_spte_gfn(u64 spte)
{
	u64 gpa = spte & shadow_nonpresent_or_rsvd_lower_gfn_mask;

	gpa |= (spte >> SHADOW_NONPRESENT_OR_RSVD_MASK_LEN)
	       & shadow_nonpresent_or_rsvd_mask;

	return gpa >> PAGE_SHIFT;
}

static unsigned get_mmio_spte_access(u64 spte)
{
	return spte & shadow_mmio_access_mask;
}

static bool check_mmio_spte(struct kvm_vcpu *vcpu, u64 spte)
{
	u64 kvm_gen, spte_gen, gen;

	gen = kvm_vcpu_memslots(vcpu)->generation;
	if (unlikely(gen & KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS))
		return false;

	kvm_gen = gen & MMIO_SPTE_GEN_MASK;
	spte_gen = get_mmio_spte_generation(spte);

	trace_check_mmio_spte(spte, kvm_gen, spte_gen);
	return likely(kvm_gen == spte_gen);
}

static gpa_t translate_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, u32 access,
                                  struct x86_exception *exception)
{
        return gpa;
}

static int is_cpuid_PSE36(void)
{
	return 1;
}

static gfn_t pse36_gfn_delta(u32 gpte)
{
	int shift = 32 - PT32_DIR_PSE36_SHIFT - PAGE_SHIFT;

	return (gpte & PT32_DIR_PSE36_MASK) << shift;
}

#ifdef CONFIG_X86_64
static void __set_spte(u64 *sptep, u64 spte)
{
	WRITE_ONCE(*sptep, spte);
}

static void __update_clear_spte_fast(u64 *sptep, u64 spte)
{
	WRITE_ONCE(*sptep, spte);
}

static u64 __update_clear_spte_slow(u64 *sptep, u64 spte)
{
	return xchg(sptep, spte);
}

static u64 __get_spte_lockless(u64 *sptep)
{
	return READ_ONCE(*sptep);
}
#else
union split_spte {
	struct {
		u32 spte_low;
		u32 spte_high;
	};
	u64 spte;
};

static void count_spte_clear(u64 *sptep, u64 spte)
{
	struct kvm_mmu_page *sp =  sptep_to_sp(sptep);

	if (is_shadow_present_pte(spte))
		return;

	/* Ensure the spte is completely set before we increase the count */
	smp_wmb();
	sp->clear_spte_count++;
}

static void __set_spte(u64 *sptep, u64 spte)
{
	union split_spte *ssptep, sspte;

	ssptep = (union split_spte *)sptep;
	sspte = (union split_spte)spte;

	ssptep->spte_high = sspte.spte_high;

	/*
	 * If we map the spte from nonpresent to present, We should store
	 * the high bits firstly, then set present bit, so cpu can not
	 * fetch this spte while we are setting the spte.
	 */
	smp_wmb();

	WRITE_ONCE(ssptep->spte_low, sspte.spte_low);
}

static void __update_clear_spte_fast(u64 *sptep, u64 spte)
{
	union split_spte *ssptep, sspte;

	ssptep = (union split_spte *)sptep;
	sspte = (union split_spte)spte;

	WRITE_ONCE(ssptep->spte_low, sspte.spte_low);

	/*
	 * If we map the spte from present to nonpresent, we should clear
	 * present bit firstly to avoid vcpu fetch the old high bits.
	 */
	smp_wmb();

	ssptep->spte_high = sspte.spte_high;
	count_spte_clear(sptep, spte);
}

static u64 __update_clear_spte_slow(u64 *sptep, u64 spte)
{
	union split_spte *ssptep, sspte, orig;

	ssptep = (union split_spte *)sptep;
	sspte = (union split_spte)spte;

	/* xchg acts as a barrier before the setting of the high bits */
	orig.spte_low = xchg(&ssptep->spte_low, sspte.spte_low);
	orig.spte_high = ssptep->spte_high;
	ssptep->spte_high = sspte.spte_high;
	count_spte_clear(sptep, spte);

	return orig.spte;
}

/*
 * The idea using the light way get the spte on x86_32 guest is from
 * gup_get_pte (mm/gup.c).
 *
 * An spte tlb flush may be pending, because kvm_set_pte_rmapp
 * coalesces them and we are running out of the MMU lock.  Therefore
 * we need to protect against in-progress updates of the spte.
 *
 * Reading the spte while an update is in progress may get the old value
 * for the high part of the spte.  The race is fine for a present->non-present
 * change (because the high part of the spte is ignored for non-present spte),
 * but for a present->present change we must reread the spte.
 *
 * All such changes are done in two steps (present->non-present and
 * non-present->present), hence it is enough to count the number of
 * present->non-present updates: if it changed while reading the spte,
 * we might have hit the race.  This is done using clear_spte_count.
 */
static u64 __get_spte_lockless(u64 *sptep)
{
	struct kvm_mmu_page *sp =  sptep_to_sp(sptep);
	union split_spte spte, *orig = (union split_spte *)sptep;
	int count;

retry:
	count = sp->clear_spte_count;
	smp_rmb();

	spte.spte_low = orig->spte_low;
	smp_rmb();

	spte.spte_high = orig->spte_high;
	smp_rmb();

	if (unlikely(spte.spte_low != orig->spte_low ||
	      count != sp->clear_spte_count))
		goto retry;

	return spte.spte;
}
#endif

static bool spte_has_volatile_bits(u64 spte)
{
	if (!is_shadow_present_pte(spte))
		return false;

	/*
	 * Always atomically update spte if it can be updated
	 * out of mmu-lock, it can ensure dirty bit is not lost,
	 * also, it can help us to get a stable is_writable_pte()
	 * to ensure tlb flush is not missed.
	 */
	if (spte_can_locklessly_be_made_writable(spte) ||
	    is_access_track_spte(spte))
		return true;

	if (spte_ad_enabled(spte)) {
		if ((spte & shadow_accessed_mask) == 0 ||
	    	    (is_writable_pte(spte) && (spte & shadow_dirty_mask) == 0))
			return true;
	}

	return false;
}

/* Rules for using mmu_spte_set:
 * Set the sptep from nonpresent to present.
 * Note: the sptep being assigned *must* be either not present
 * or in a state where the hardware will not attempt to update
 * the spte.
 */
static void mmu_spte_set(u64 *sptep, u64 new_spte)
{
	WARN_ON(is_shadow_present_pte(*sptep));
	__set_spte(sptep, new_spte);
}

/*
 * Update the SPTE (excluding the PFN), but do not track changes in its
 * accessed/dirty status.
 */
static u64 mmu_spte_update_no_track(u64 *sptep, u64 new_spte)
{
	u64 old_spte = *sptep;

	WARN_ON(!is_shadow_present_pte(new_spte));

	if (!is_shadow_present_pte(old_spte)) {
		mmu_spte_set(sptep, new_spte);
		return old_spte;
	}

	if (!spte_has_volatile_bits(old_spte))
		__update_clear_spte_fast(sptep, new_spte);
	else
		old_spte = __update_clear_spte_slow(sptep, new_spte);

	WARN_ON(spte_to_pfn(old_spte) != spte_to_pfn(new_spte));

	return old_spte;
}

/* Rules for using mmu_spte_update:
 * Update the state bits, it means the mapped pfn is not changed.
 *
 * Whenever we overwrite a writable spte with a read-only one we
 * should flush remote TLBs. Otherwise rmap_write_protect
 * will find a read-only spte, even though the writable spte
 * might be cached on a CPU's TLB, the return value indicates this
 * case.
 *
 * Returns true if the TLB needs to be flushed
 */
static bool mmu_spte_update(u64 *sptep, u64 new_spte)
{
	bool flush = false;
	u64 old_spte = mmu_spte_update_no_track(sptep, new_spte);

	if (!is_shadow_present_pte(old_spte))
		return false;

	/*
	 * For the spte updated out of mmu-lock is safe, since
	 * we always atomically update it, see the comments in
	 * spte_has_volatile_bits().
	 */
	if (spte_can_locklessly_be_made_writable(old_spte) &&
	      !is_writable_pte(new_spte))
		flush = true;

	/*
	 * Flush TLB when accessed/dirty states are changed in the page tables,
	 * to guarantee consistency between TLB and page tables.
	 */

	if (is_accessed_spte(old_spte) && !is_accessed_spte(new_spte)) {
		flush = true;
		kvm_set_pfn_accessed(spte_to_pfn(old_spte));
	}

	if (is_dirty_spte(old_spte) && !is_dirty_spte(new_spte)) {
		flush = true;
		kvm_set_pfn_dirty(spte_to_pfn(old_spte));
	}

	return flush;
}

/*
 * Rules for using mmu_spte_clear_track_bits:
 * It sets the sptep from present to nonpresent, and track the
 * state bits, it is used to clear the last level sptep.
 * Returns the old PTE.
 */
static int mmu_spte_clear_track_bits(struct kvm *kvm, u64 *sptep)
{
	kvm_pfn_t pfn;
	u64 old_spte = *sptep;
	int level = sptep_to_sp(sptep)->role.level;

	if (!spte_has_volatile_bits(old_spte))
		__update_clear_spte_fast(sptep, 0ull);
	else
		old_spte = __update_clear_spte_slow(sptep, 0ull);

	if (!is_shadow_present_pte(old_spte))
		return old_spte;

	kvm_update_page_stats(kvm, level, -1);

	pfn = spte_to_pfn(old_spte);

	/*
	 * KVM does not hold the refcount of the page used by
	 * kvm mmu, before reclaiming the page, we should
	 * unmap it from mmu first.
	 */
	WARN_ON(!kvm_is_reserved_pfn(pfn) && !page_count(pfn_to_page(pfn)));

	if (is_accessed_spte(old_spte))
		kvm_set_pfn_accessed(pfn);

	if (is_dirty_spte(old_spte))
		kvm_set_pfn_dirty(pfn);

	return old_spte;
}

/*
 * Rules for using mmu_spte_clear_no_track:
 * Directly clear spte without caring the state bits of sptep,
 * it is used to set the upper level spte.
 */
static void mmu_spte_clear_no_track(u64 *sptep)
{
	__update_clear_spte_fast(sptep, 0ull);
}

static u64 mmu_spte_get_lockless(u64 *sptep)
{
	return __get_spte_lockless(sptep);
}

/* Restore an acc-track PTE back to a regular PTE */
static u64 restore_acc_track_spte(u64 spte)
{
	u64 new_spte = spte;
	u64 saved_bits = (spte >> SHADOW_ACC_TRACK_SAVED_BITS_SHIFT)
			 & SHADOW_ACC_TRACK_SAVED_BITS_MASK;

	WARN_ON_ONCE(spte_ad_enabled(spte));
	WARN_ON_ONCE(!is_access_track_spte(spte));

	new_spte &= ~shadow_acc_track_mask;
	new_spte &= ~(SHADOW_ACC_TRACK_SAVED_BITS_MASK <<
		      SHADOW_ACC_TRACK_SAVED_BITS_SHIFT);
	new_spte |= saved_bits;

	return new_spte;
}

/* Returns the Accessed status of the PTE and resets it at the same time. */
static bool mmu_spte_age(u64 *sptep)
{
	u64 spte = mmu_spte_get_lockless(sptep);

	if (!is_accessed_spte(spte))
		return false;

	if (spte_ad_enabled(spte)) {
		clear_bit((ffs(shadow_accessed_mask) - 1),
			  (unsigned long *)sptep);
	} else {
		/*
		 * Capture the dirty status of the page, so that it doesn't get
		 * lost when the SPTE is marked for access tracking.
		 */
		if (is_writable_pte(spte))
			kvm_set_pfn_dirty(spte_to_pfn(spte));

		spte = mark_spte_for_access_track(spte);
		mmu_spte_update_no_track(sptep, spte);
	}

	return true;
}

static void walk_shadow_page_lockless_begin(struct kvm_vcpu *vcpu)
{
	if (is_tdp_mmu(vcpu->arch.mmu)) {
		kvm_tdp_mmu_walk_lockless_begin();
	} else {
		/*
		 * Prevent page table teardown by making any free-er wait during
		 * kvm_flush_remote_tlbs() IPI to all active vcpus.
		 */
		local_irq_disable();

		/*
		 * Make sure a following spte read is not reordered ahead of the write
		 * to vcpu->mode.
		 */
		smp_store_mb(vcpu->mode, READING_SHADOW_PAGE_TABLES);
	}
}

static void walk_shadow_page_lockless_end(struct kvm_vcpu *vcpu)
{
	if (is_tdp_mmu(vcpu->arch.mmu)) {
		kvm_tdp_mmu_walk_lockless_end();
	} else {
		/*
		 * Make sure the write to vcpu->mode is not reordered in front of
		 * reads to sptes.  If it does, kvm_mmu_commit_zap_page() can see us
		 * OUTSIDE_GUEST_MODE and proceed to free the shadow page table.
		 */
		smp_store_release(&vcpu->mode, OUTSIDE_GUEST_MODE);
		local_irq_enable();
	}
}

static int mmu_topup_memory_caches(struct kvm_vcpu *vcpu, bool maybe_indirect)
{
	int r;

	/* 1 rmap, 1 parent PTE per level, and the prefetched rmaps. */
	r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache,
				       1 + PT64_ROOT_MAX_LEVEL + PTE_PREFETCH_NUM);
	if (r)
		return r;
	r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_shadow_page_cache,
				       PT64_ROOT_MAX_LEVEL);
	if (r)
		return r;
	if (maybe_indirect) {
		r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_gfn_array_cache,
					       PT64_ROOT_MAX_LEVEL);
		if (r)
			return r;
	}
	return kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_page_header_cache,
					  PT64_ROOT_MAX_LEVEL);
}

static void mmu_free_memory_caches(struct kvm_vcpu *vcpu)
{
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache);
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_shadow_page_cache);
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_gfn_array_cache);
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_page_header_cache);
}

static struct pte_list_desc *mmu_alloc_pte_list_desc(struct kvm_vcpu *vcpu)
{
	return kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_pte_list_desc_cache);
}

static void mmu_free_pte_list_desc(struct pte_list_desc *pte_list_desc)
{
	kmem_cache_free(pte_list_desc_cache, pte_list_desc);
}

static gfn_t kvm_mmu_page_get_gfn(struct kvm_mmu_page *sp, int index)
{
	if (!sp->role.direct)
		return sp->gfns[index];

	return sp->gfn + (index << ((sp->role.level - 1) * PT64_LEVEL_BITS));
}

static void kvm_mmu_page_set_gfn(struct kvm_mmu_page *sp, int index, gfn_t gfn)
{
	if (!sp->role.direct) {
		sp->gfns[index] = gfn;
		return;
	}

	if (WARN_ON(gfn != kvm_mmu_page_get_gfn(sp, index)))
		pr_err_ratelimited("gfn mismatch under direct page %llx "
				   "(expected %llx, got %llx)\n",
				   sp->gfn,
				   kvm_mmu_page_get_gfn(sp, index), gfn);
}

/*
 * Return the pointer to the large page information for a given gfn,
 * handling slots that are not large page aligned.
 */
static struct kvm_lpage_info *lpage_info_slot(gfn_t gfn,
		const struct kvm_memory_slot *slot, int level)
{
	unsigned long idx;

	idx = gfn_to_index(gfn, slot->base_gfn, level);
	return &slot->arch.lpage_info[level - 2][idx];
}

static void update_gfn_disallow_lpage_count(const struct kvm_memory_slot *slot,
					    gfn_t gfn, int count)
{
	struct kvm_lpage_info *linfo;
	int i;

	for (i = PG_LEVEL_2M; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
		linfo = lpage_info_slot(gfn, slot, i);
		linfo->disallow_lpage += count;
		WARN_ON(linfo->disallow_lpage < 0);
	}
}

void kvm_mmu_gfn_disallow_lpage(const struct kvm_memory_slot *slot, gfn_t gfn)
{
	update_gfn_disallow_lpage_count(slot, gfn, 1);
}

void kvm_mmu_gfn_allow_lpage(const struct kvm_memory_slot *slot, gfn_t gfn)
{
	update_gfn_disallow_lpage_count(slot, gfn, -1);
}

static void account_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	gfn_t gfn;

	kvm->arch.indirect_shadow_pages++;
	gfn = sp->gfn;
	slots = kvm_memslots_for_spte_role(kvm, sp->role);
	slot = __gfn_to_memslot(slots, gfn);

	/* the non-leaf shadow pages are keeping readonly. */
	if (sp->role.level > PG_LEVEL_4K)
		return kvm_slot_page_track_add_page(kvm, slot, gfn,
						    KVM_PAGE_TRACK_WRITE);

	kvm_mmu_gfn_disallow_lpage(slot, gfn);
}

void account_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	if (sp->lpage_disallowed)
		return;

	++kvm->stat.nx_lpage_splits;
	list_add_tail(&sp->lpage_disallowed_link,
		      &kvm->arch.lpage_disallowed_mmu_pages);
	sp->lpage_disallowed = true;
}

static void unaccount_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	gfn_t gfn;

	kvm->arch.indirect_shadow_pages--;
	gfn = sp->gfn;
	slots = kvm_memslots_for_spte_role(kvm, sp->role);
	slot = __gfn_to_memslot(slots, gfn);
	if (sp->role.level > PG_LEVEL_4K)
		return kvm_slot_page_track_remove_page(kvm, slot, gfn,
						       KVM_PAGE_TRACK_WRITE);

	kvm_mmu_gfn_allow_lpage(slot, gfn);
}

void unaccount_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	--kvm->stat.nx_lpage_splits;
	sp->lpage_disallowed = false;
	list_del(&sp->lpage_disallowed_link);
}

static struct kvm_memory_slot *
gfn_to_memslot_dirty_bitmap(struct kvm_vcpu *vcpu, gfn_t gfn,
			    bool no_dirty_log)
{
	struct kvm_memory_slot *slot;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return NULL;
	if (no_dirty_log && kvm_slot_dirty_track_enabled(slot))
		return NULL;

	return slot;
}

/*
 * About rmap_head encoding:
 *
 * If the bit zero of rmap_head->val is clear, then it points to the only spte
 * in this rmap chain. Otherwise, (rmap_head->val & ~1) points to a struct
 * pte_list_desc containing more mappings.
 */

/*
 * Returns the number of pointers in the rmap chain, not counting the new one.
 */
static int pte_list_add(struct kvm_vcpu *vcpu, u64 *spte,
			struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	int count = 0;

	if (!rmap_head->val) {
		rmap_printk("%p %llx 0->1\n", spte, *spte);
		rmap_head->val = (unsigned long)spte;
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("%p %llx 1->many\n", spte, *spte);
		desc = mmu_alloc_pte_list_desc(vcpu);
		desc->sptes[0] = (u64 *)rmap_head->val;
		desc->sptes[1] = spte;
		desc->spte_count = 2;
		rmap_head->val = (unsigned long)desc | 1;
		++count;
	} else {
		rmap_printk("%p %llx many->many\n", spte, *spte);
		desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
		while (desc->spte_count == PTE_LIST_EXT) {
			count += PTE_LIST_EXT;
			if (!desc->more) {
				desc->more = mmu_alloc_pte_list_desc(vcpu);
				desc = desc->more;
				desc->spte_count = 0;
				break;
			}
			desc = desc->more;
		}
		count += desc->spte_count;
		desc->sptes[desc->spte_count++] = spte;
	}
	return count;
}

static void
pte_list_desc_remove_entry(struct kvm_rmap_head *rmap_head,
			   struct pte_list_desc *desc, int i,
			   struct pte_list_desc *prev_desc)
{
	int j = desc->spte_count - 1;

	desc->sptes[i] = desc->sptes[j];
	desc->sptes[j] = NULL;
	desc->spte_count--;
	if (desc->spte_count)
		return;
	if (!prev_desc && !desc->more)
		rmap_head->val = 0;
	else
		if (prev_desc)
			prev_desc->more = desc->more;
		else
			rmap_head->val = (unsigned long)desc->more | 1;
	mmu_free_pte_list_desc(desc);
}

static void __pte_list_remove(u64 *spte, struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	struct pte_list_desc *prev_desc;
	int i;

	if (!rmap_head->val) {
		pr_err("%s: %p 0->BUG\n", __func__, spte);
		BUG();
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("%p 1->0\n", spte);
		if ((u64 *)rmap_head->val != spte) {
			pr_err("%s:  %p 1->BUG\n", __func__, spte);
			BUG();
		}
		rmap_head->val = 0;
	} else {
		rmap_printk("%p many->many\n", spte);
		desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
		prev_desc = NULL;
		while (desc) {
			for (i = 0; i < desc->spte_count; ++i) {
				if (desc->sptes[i] == spte) {
					pte_list_desc_remove_entry(rmap_head,
							desc, i, prev_desc);
					return;
				}
			}
			prev_desc = desc;
			desc = desc->more;
		}
		pr_err("%s: %p many->many\n", __func__, spte);
		BUG();
	}
}

static void pte_list_remove(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			    u64 *sptep)
{
	mmu_spte_clear_track_bits(kvm, sptep);
	__pte_list_remove(sptep, rmap_head);
}

/* Return true if rmap existed, false otherwise */
static bool pte_list_destroy(struct kvm *kvm, struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc, *next;
	int i;

	if (!rmap_head->val)
		return false;

	if (!(rmap_head->val & 1)) {
		mmu_spte_clear_track_bits(kvm, (u64 *)rmap_head->val);
		goto out;
	}

	desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);

	for (; desc; desc = next) {
		for (i = 0; i < desc->spte_count; i++)
			mmu_spte_clear_track_bits(kvm, desc->sptes[i]);
		next = desc->more;
		mmu_free_pte_list_desc(desc);
	}
out:
	/* rmap_head is meaningless now, remember to reset it */
	rmap_head->val = 0;
	return true;
}

unsigned int pte_list_count(struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	unsigned int count = 0;

	if (!rmap_head->val)
		return 0;
	else if (!(rmap_head->val & 1))
		return 1;

	desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);

	while (desc) {
		count += desc->spte_count;
		desc = desc->more;
	}

	return count;
}

static struct kvm_rmap_head *gfn_to_rmap(gfn_t gfn, int level,
					 const struct kvm_memory_slot *slot)
{
	unsigned long idx;

	idx = gfn_to_index(gfn, slot->base_gfn, level);
	return &slot->arch.rmap[level - PG_LEVEL_4K][idx];
}

static bool rmap_can_add(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_memory_cache *mc;

	mc = &vcpu->arch.mmu_pte_list_desc_cache;
	return kvm_mmu_memory_cache_nr_free_objects(mc);
}

static void rmap_remove(struct kvm *kvm, u64 *spte)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	struct kvm_mmu_page *sp;
	gfn_t gfn;
	struct kvm_rmap_head *rmap_head;

	sp = sptep_to_sp(spte);
	gfn = kvm_mmu_page_get_gfn(sp, spte - sp->spt);

	/*
	 * Unlike rmap_add, rmap_remove does not run in the context of a vCPU
	 * so we have to determine which memslots to use based on context
	 * information in sp->role.
	 */
	slots = kvm_memslots_for_spte_role(kvm, sp->role);

	slot = __gfn_to_memslot(slots, gfn);
	rmap_head = gfn_to_rmap(gfn, sp->role.level, slot);

	__pte_list_remove(spte, rmap_head);
}

/*
 * Used by the following functions to iterate through the sptes linked by a
 * rmap.  All fields are private and not assumed to be used outside.
 */
struct rmap_iterator {
	/* private fields */
	struct pte_list_desc *desc;	/* holds the sptep if not NULL */
	int pos;			/* index of the sptep */
};

/*
 * Iteration must be started by this function.  This should also be used after
 * removing/dropping sptes from the rmap link because in such cases the
 * information in the iterator may not be valid.
 *
 * Returns sptep if found, NULL otherwise.
 */
static u64 *rmap_get_first(struct kvm_rmap_head *rmap_head,
			   struct rmap_iterator *iter)
{
	u64 *sptep;

	if (!rmap_head->val)
		return NULL;

	if (!(rmap_head->val & 1)) {
		iter->desc = NULL;
		sptep = (u64 *)rmap_head->val;
		goto out;
	}

	iter->desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
	iter->pos = 0;
	sptep = iter->desc->sptes[iter->pos];
out:
	BUG_ON(!is_shadow_present_pte(*sptep));
	return sptep;
}

/*
 * Must be used with a valid iterator: e.g. after rmap_get_first().
 *
 * Returns sptep if found, NULL otherwise.
 */
static u64 *rmap_get_next(struct rmap_iterator *iter)
{
	u64 *sptep;

	if (iter->desc) {
		if (iter->pos < PTE_LIST_EXT - 1) {
			++iter->pos;
			sptep = iter->desc->sptes[iter->pos];
			if (sptep)
				goto out;
		}

		iter->desc = iter->desc->more;

		if (iter->desc) {
			iter->pos = 0;
			/* desc->sptes[0] cannot be NULL */
			sptep = iter->desc->sptes[iter->pos];
			goto out;
		}
	}

	return NULL;
out:
	BUG_ON(!is_shadow_present_pte(*sptep));
	return sptep;
}

#define for_each_rmap_spte(_rmap_head_, _iter_, _spte_)			\
	for (_spte_ = rmap_get_first(_rmap_head_, _iter_);		\
	     _spte_; _spte_ = rmap_get_next(_iter_))

static void drop_spte(struct kvm *kvm, u64 *sptep)
{
	u64 old_spte = mmu_spte_clear_track_bits(kvm, sptep);

	if (is_shadow_present_pte(old_spte))
		rmap_remove(kvm, sptep);
}


static bool __drop_large_spte(struct kvm *kvm, u64 *sptep)
{
	if (is_large_pte(*sptep)) {
		WARN_ON(sptep_to_sp(sptep)->role.level == PG_LEVEL_4K);
		drop_spte(kvm, sptep);
		return true;
	}

	return false;
}

static void drop_large_spte(struct kvm_vcpu *vcpu, u64 *sptep)
{
	if (__drop_large_spte(vcpu->kvm, sptep)) {
		struct kvm_mmu_page *sp = sptep_to_sp(sptep);

		kvm_flush_remote_tlbs_with_address(vcpu->kvm, sp->gfn,
			KVM_PAGES_PER_HPAGE(sp->role.level));
	}
}

/*
 * Write-protect on the specified @sptep, @pt_protect indicates whether
 * spte write-protection is caused by protecting shadow page table.
 *
 * Note: write protection is difference between dirty logging and spte
 * protection:
 * - for dirty logging, the spte can be set to writable at anytime if
 *   its dirty bitmap is properly set.
 * - for spte protection, the spte can be writable only after unsync-ing
 *   shadow page.
 *
 * Return true if tlb need be flushed.
 */
static bool spte_write_protect(u64 *sptep, bool pt_protect)
{
	u64 spte = *sptep;

	if (!is_writable_pte(spte) &&
	      !(pt_protect && spte_can_locklessly_be_made_writable(spte)))
		return false;

	rmap_printk("spte %p %llx\n", sptep, *sptep);

	if (pt_protect)
		spte &= ~shadow_mmu_writable_mask;
	spte = spte & ~PT_WRITABLE_MASK;

	return mmu_spte_update(sptep, spte);
}

static bool __rmap_write_protect(struct kvm *kvm,
				 struct kvm_rmap_head *rmap_head,
				 bool pt_protect)
{
	u64 *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		flush |= spte_write_protect(sptep, pt_protect);

	return flush;
}

static bool spte_clear_dirty(u64 *sptep)
{
	u64 spte = *sptep;

	rmap_printk("spte %p %llx\n", sptep, *sptep);

	MMU_WARN_ON(!spte_ad_enabled(spte));
	spte &= ~shadow_dirty_mask;
	return mmu_spte_update(sptep, spte);
}

static bool spte_wrprot_for_clear_dirty(u64 *sptep)
{
	bool was_writable = test_and_clear_bit(PT_WRITABLE_SHIFT,
					       (unsigned long *)sptep);
	if (was_writable && !spte_ad_enabled(*sptep))
		kvm_set_pfn_dirty(spte_to_pfn(*sptep));

	return was_writable;
}

/*
 * Gets the GFN ready for another round of dirty logging by clearing the
 *	- D bit on ad-enabled SPTEs, and
 *	- W bit on ad-disabled SPTEs.
 * Returns true iff any D or W bits were cleared.
 */
static bool __rmap_clear_dirty(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			       const struct kvm_memory_slot *slot)
{
	u64 *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		if (spte_ad_need_write_protect(*sptep))
			flush |= spte_wrprot_for_clear_dirty(sptep);
		else
			flush |= spte_clear_dirty(sptep);

	return flush;
}

/**
 * kvm_mmu_write_protect_pt_masked - write protect selected PT level pages
 * @kvm: kvm instance
 * @slot: slot to protect
 * @gfn_offset: start of the BITS_PER_LONG pages we care about
 * @mask: indicates which pages we should protect
 *
 * Used when we do not need to care about huge page mappings.
 */
static void kvm_mmu_write_protect_pt_masked(struct kvm *kvm,
				     struct kvm_memory_slot *slot,
				     gfn_t gfn_offset, unsigned long mask)
{
	struct kvm_rmap_head *rmap_head;

	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_clear_dirty_pt_masked(kvm, slot,
				slot->base_gfn + gfn_offset, mask, true);

	if (!kvm_memslots_have_rmaps(kvm))
		return;

	while (mask) {
		rmap_head = gfn_to_rmap(slot->base_gfn + gfn_offset + __ffs(mask),
					PG_LEVEL_4K, slot);
		__rmap_write_protect(kvm, rmap_head, false);

		/* clear the first set bit */
		mask &= mask - 1;
	}
}

/**
 * kvm_mmu_clear_dirty_pt_masked - clear MMU D-bit for PT level pages, or write
 * protect the page if the D-bit isn't supported.
 * @kvm: kvm instance
 * @slot: slot to clear D-bit
 * @gfn_offset: start of the BITS_PER_LONG pages we care about
 * @mask: indicates which pages we should clear D-bit
 *
 * Used for PML to re-log the dirty GPAs after userspace querying dirty_bitmap.
 */
static void kvm_mmu_clear_dirty_pt_masked(struct kvm *kvm,
					 struct kvm_memory_slot *slot,
					 gfn_t gfn_offset, unsigned long mask)
{
	struct kvm_rmap_head *rmap_head;

	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_clear_dirty_pt_masked(kvm, slot,
				slot->base_gfn + gfn_offset, mask, false);

	if (!kvm_memslots_have_rmaps(kvm))
		return;

	while (mask) {
		rmap_head = gfn_to_rmap(slot->base_gfn + gfn_offset + __ffs(mask),
					PG_LEVEL_4K, slot);
		__rmap_clear_dirty(kvm, rmap_head, slot);

		/* clear the first set bit */
		mask &= mask - 1;
	}
}

/**
 * kvm_arch_mmu_enable_log_dirty_pt_masked - enable dirty logging for selected
 * PT level pages.
 *
 * It calls kvm_mmu_write_protect_pt_masked to write protect selected pages to
 * enable dirty logging for them.
 *
 * We need to care about huge page mappings: e.g. during dirty logging we may
 * have such mappings.
 */
void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
				struct kvm_memory_slot *slot,
				gfn_t gfn_offset, unsigned long mask)
{
	/*
	 * Huge pages are NOT write protected when we start dirty logging in
	 * initially-all-set mode; must write protect them here so that they
	 * are split to 4K on the first write.
	 *
	 * The gfn_offset is guaranteed to be aligned to 64, but the base_gfn
	 * of memslot has no such restriction, so the range can cross two large
	 * pages.
	 */
	if (kvm_dirty_log_manual_protect_and_init_set(kvm)) {
		gfn_t start = slot->base_gfn + gfn_offset + __ffs(mask);
		gfn_t end = slot->base_gfn + gfn_offset + __fls(mask);

		kvm_mmu_slot_gfn_write_protect(kvm, slot, start, PG_LEVEL_2M);

		/* Cross two large pages? */
		if (ALIGN(start << PAGE_SHIFT, PMD_SIZE) !=
		    ALIGN(end << PAGE_SHIFT, PMD_SIZE))
			kvm_mmu_slot_gfn_write_protect(kvm, slot, end,
						       PG_LEVEL_2M);
	}

	/* Now handle 4K PTEs.  */
	if (kvm_x86_ops.cpu_dirty_log_size)
		kvm_mmu_clear_dirty_pt_masked(kvm, slot, gfn_offset, mask);
	else
		kvm_mmu_write_protect_pt_masked(kvm, slot, gfn_offset, mask);
}

int kvm_cpu_dirty_log_size(void)
{
	return kvm_x86_ops.cpu_dirty_log_size;
}

bool kvm_mmu_slot_gfn_write_protect(struct kvm *kvm,
				    struct kvm_memory_slot *slot, u64 gfn,
				    int min_level)
{
	struct kvm_rmap_head *rmap_head;
	int i;
	bool write_protected = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		for (i = min_level; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
			rmap_head = gfn_to_rmap(gfn, i, slot);
			write_protected |= __rmap_write_protect(kvm, rmap_head, true);
		}
	}

	if (is_tdp_mmu_enabled(kvm))
		write_protected |=
			kvm_tdp_mmu_write_protect_gfn(kvm, slot, gfn, min_level);

	return write_protected;
}

static bool rmap_write_protect(struct kvm_vcpu *vcpu, u64 gfn)
{
	struct kvm_memory_slot *slot;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	return kvm_mmu_slot_gfn_write_protect(vcpu->kvm, slot, gfn, PG_LEVEL_4K);
}

static bool kvm_zap_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			  const struct kvm_memory_slot *slot)
{
	return pte_list_destroy(kvm, rmap_head);
}

static bool kvm_unmap_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			    struct kvm_memory_slot *slot, gfn_t gfn, int level,
			    pte_t unused)
{
	return kvm_zap_rmapp(kvm, rmap_head, slot);
}

static bool kvm_set_pte_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			      struct kvm_memory_slot *slot, gfn_t gfn, int level,
			      pte_t pte)
{
	u64 *sptep;
	struct rmap_iterator iter;
	int need_flush = 0;
	u64 new_spte;
	kvm_pfn_t new_pfn;

	WARN_ON(pte_huge(pte));
	new_pfn = pte_pfn(pte);

restart:
	for_each_rmap_spte(rmap_head, &iter, sptep) {
		rmap_printk("spte %p %llx gfn %llx (%d)\n",
			    sptep, *sptep, gfn, level);

		need_flush = 1;

		if (pte_write(pte)) {
			pte_list_remove(kvm, rmap_head, sptep);
			goto restart;
		} else {
			new_spte = kvm_mmu_changed_pte_notifier_make_spte(
					*sptep, new_pfn);

			mmu_spte_clear_track_bits(kvm, sptep);
			mmu_spte_set(sptep, new_spte);
		}
	}

	if (need_flush && kvm_available_flush_tlb_with_range()) {
		kvm_flush_remote_tlbs_with_address(kvm, gfn, 1);
		return 0;
	}

	return need_flush;
}

struct slot_rmap_walk_iterator {
	/* input fields. */
	const struct kvm_memory_slot *slot;
	gfn_t start_gfn;
	gfn_t end_gfn;
	int start_level;
	int end_level;

	/* output fields. */
	gfn_t gfn;
	struct kvm_rmap_head *rmap;
	int level;

	/* private field. */
	struct kvm_rmap_head *end_rmap;
};

static void
rmap_walk_init_level(struct slot_rmap_walk_iterator *iterator, int level)
{
	iterator->level = level;
	iterator->gfn = iterator->start_gfn;
	iterator->rmap = gfn_to_rmap(iterator->gfn, level, iterator->slot);
	iterator->end_rmap = gfn_to_rmap(iterator->end_gfn, level, iterator->slot);
}

static void
slot_rmap_walk_init(struct slot_rmap_walk_iterator *iterator,
		    const struct kvm_memory_slot *slot, int start_level,
		    int end_level, gfn_t start_gfn, gfn_t end_gfn)
{
	iterator->slot = slot;
	iterator->start_level = start_level;
	iterator->end_level = end_level;
	iterator->start_gfn = start_gfn;
	iterator->end_gfn = end_gfn;

	rmap_walk_init_level(iterator, iterator->start_level);
}

static bool slot_rmap_walk_okay(struct slot_rmap_walk_iterator *iterator)
{
	return !!iterator->rmap;
}

static void slot_rmap_walk_next(struct slot_rmap_walk_iterator *iterator)
{
	if (++iterator->rmap <= iterator->end_rmap) {
		iterator->gfn += (1UL << KVM_HPAGE_GFN_SHIFT(iterator->level));
		return;
	}

	if (++iterator->level > iterator->end_level) {
		iterator->rmap = NULL;
		return;
	}

	rmap_walk_init_level(iterator, iterator->level);
}

#define for_each_slot_rmap_range(_slot_, _start_level_, _end_level_,	\
	   _start_gfn, _end_gfn, _iter_)				\
	for (slot_rmap_walk_init(_iter_, _slot_, _start_level_,		\
				 _end_level_, _start_gfn, _end_gfn);	\
	     slot_rmap_walk_okay(_iter_);				\
	     slot_rmap_walk_next(_iter_))

typedef bool (*rmap_handler_t)(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			       struct kvm_memory_slot *slot, gfn_t gfn,
			       int level, pte_t pte);

static __always_inline bool kvm_handle_gfn_range(struct kvm *kvm,
						 struct kvm_gfn_range *range,
						 rmap_handler_t handler)
{
	struct slot_rmap_walk_iterator iterator;
	bool ret = false;

	for_each_slot_rmap_range(range->slot, PG_LEVEL_4K, KVM_MAX_HUGEPAGE_LEVEL,
				 range->start, range->end - 1, &iterator)
		ret |= handler(kvm, iterator.rmap, range->slot, iterator.gfn,
			       iterator.level, range->pte);

	return ret;
}

bool kvm_unmap_gfn_range(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm))
		flush = kvm_handle_gfn_range(kvm, range, kvm_unmap_rmapp);

	if (is_tdp_mmu_enabled(kvm))
		flush = kvm_tdp_mmu_unmap_gfn_range(kvm, range, flush);

	return flush;
}

bool kvm_set_spte_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm))
		flush = kvm_handle_gfn_range(kvm, range, kvm_set_pte_rmapp);

	if (is_tdp_mmu_enabled(kvm))
		flush |= kvm_tdp_mmu_set_spte_gfn(kvm, range);

	return flush;
}

static bool kvm_age_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			  struct kvm_memory_slot *slot, gfn_t gfn, int level,
			  pte_t unused)
{
	u64 *sptep;
	struct rmap_iterator iter;
	int young = 0;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		young |= mmu_spte_age(sptep);

	return young;
}

static bool kvm_test_age_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			       struct kvm_memory_slot *slot, gfn_t gfn,
			       int level, pte_t unused)
{
	u64 *sptep;
	struct rmap_iterator iter;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		if (is_accessed_spte(*sptep))
			return 1;
	return 0;
}

#define RMAP_RECYCLE_THRESHOLD 1000

static void rmap_add(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
		     u64 *spte, gfn_t gfn)
{
	struct kvm_mmu_page *sp;
	struct kvm_rmap_head *rmap_head;
	int rmap_count;

	sp = sptep_to_sp(spte);
	kvm_mmu_page_set_gfn(sp, spte - sp->spt, gfn);
	rmap_head = gfn_to_rmap(gfn, sp->role.level, slot);
	rmap_count = pte_list_add(vcpu, spte, rmap_head);

	if (rmap_count > RMAP_RECYCLE_THRESHOLD) {
		kvm_unmap_rmapp(vcpu->kvm, rmap_head, NULL, gfn, sp->role.level, __pte(0));
		kvm_flush_remote_tlbs_with_address(
				vcpu->kvm, sp->gfn, KVM_PAGES_PER_HPAGE(sp->role.level));
	}
}

bool kvm_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool young = false;

	if (kvm_memslots_have_rmaps(kvm))
		young = kvm_handle_gfn_range(kvm, range, kvm_age_rmapp);

	if (is_tdp_mmu_enabled(kvm))
		young |= kvm_tdp_mmu_age_gfn_range(kvm, range);

	return young;
}

bool kvm_test_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool young = false;

	if (kvm_memslots_have_rmaps(kvm))
		young = kvm_handle_gfn_range(kvm, range, kvm_test_age_rmapp);

	if (is_tdp_mmu_enabled(kvm))
		young |= kvm_tdp_mmu_test_age_gfn(kvm, range);

	return young;
}

#ifdef MMU_DEBUG
static int is_empty_shadow_page(u64 *spt)
{
	u64 *pos;
	u64 *end;

	for (pos = spt, end = pos + PAGE_SIZE / sizeof(u64); pos != end; pos++)
		if (is_shadow_present_pte(*pos)) {
			printk(KERN_ERR "%s: %p %llx\n", __func__,
			       pos, *pos);
			return 0;
		}
	return 1;
}
#endif

/*
 * This value is the sum of all of the kvm instances's
 * kvm->arch.n_used_mmu_pages values.  We need a global,
 * aggregate version in order to make the slab shrinker
 * faster
 */
static inline void kvm_mod_used_mmu_pages(struct kvm *kvm, long nr)
{
	kvm->arch.n_used_mmu_pages += nr;
	percpu_counter_add(&kvm_total_used_mmu_pages, nr);
}

static void kvm_mmu_free_page(struct kvm_mmu_page *sp)
{
	MMU_WARN_ON(!is_empty_shadow_page(sp->spt));
	hlist_del(&sp->hash_link);
	list_del(&sp->link);
	free_page((unsigned long)sp->spt);
	if (!sp->role.direct)
		free_page((unsigned long)sp->gfns);
	kmem_cache_free(mmu_page_header_cache, sp);
}

static unsigned kvm_page_table_hashfn(gfn_t gfn)
{
	return hash_64(gfn, KVM_MMU_HASH_SHIFT);
}

static void mmu_page_add_parent_pte(struct kvm_vcpu *vcpu,
				    struct kvm_mmu_page *sp, u64 *parent_pte)
{
	if (!parent_pte)
		return;

	pte_list_add(vcpu, parent_pte, &sp->parent_ptes);
}

static void mmu_page_remove_parent_pte(struct kvm_mmu_page *sp,
				       u64 *parent_pte)
{
	__pte_list_remove(parent_pte, &sp->parent_ptes);
}

static void drop_parent_pte(struct kvm_mmu_page *sp,
			    u64 *parent_pte)
{
	mmu_page_remove_parent_pte(sp, parent_pte);
	mmu_spte_clear_no_track(parent_pte);
}

static struct kvm_mmu_page *kvm_mmu_alloc_page(struct kvm_vcpu *vcpu, int direct)
{
	struct kvm_mmu_page *sp;

	sp = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache);
	sp->spt = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_shadow_page_cache);
	if (!direct)
		sp->gfns = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_gfn_array_cache);
	set_page_private(virt_to_page(sp->spt), (unsigned long)sp);

	/*
	 * active_mmu_pages must be a FIFO list, as kvm_zap_obsolete_pages()
	 * depends on valid pages being added to the head of the list.  See
	 * comments in kvm_zap_obsolete_pages().
	 */
	sp->mmu_valid_gen = vcpu->kvm->arch.mmu_valid_gen;
	list_add(&sp->link, &vcpu->kvm->arch.active_mmu_pages);
	kvm_mod_used_mmu_pages(vcpu->kvm, +1);
	return sp;
}

static void mark_unsync(u64 *spte);
static void kvm_mmu_mark_parents_unsync(struct kvm_mmu_page *sp)
{
	u64 *sptep;
	struct rmap_iterator iter;

	for_each_rmap_spte(&sp->parent_ptes, &iter, sptep) {
		mark_unsync(sptep);
	}
}

static void mark_unsync(u64 *spte)
{
	struct kvm_mmu_page *sp;
	unsigned int index;

	sp = sptep_to_sp(spte);
	index = spte - sp->spt;
	if (__test_and_set_bit(index, sp->unsync_child_bitmap))
		return;
	if (sp->unsync_children++)
		return;
	kvm_mmu_mark_parents_unsync(sp);
}

static int nonpaging_sync_page(struct kvm_vcpu *vcpu,
			       struct kvm_mmu_page *sp)
{
	return -1;
}

#define KVM_PAGE_ARRAY_NR 16

struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page *sp;
		unsigned int idx;
	} page[KVM_PAGE_ARRAY_NR];
	unsigned int nr;
};

static int mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp,
			 int idx)
{
	int i;

	if (sp->unsync)
		for (i=0; i < pvec->nr; i++)
			if (pvec->page[i].sp == sp)
				return 0;

	pvec->page[pvec->nr].sp = sp;
	pvec->page[pvec->nr].idx = idx;
	pvec->nr++;
	return (pvec->nr == KVM_PAGE_ARRAY_NR);
}

static inline void clear_unsync_child_bit(struct kvm_mmu_page *sp, int idx)
{
	--sp->unsync_children;
	WARN_ON((int)sp->unsync_children < 0);
	__clear_bit(idx, sp->unsync_child_bitmap);
}

static int __mmu_unsync_walk(struct kvm_mmu_page *sp,
			   struct kvm_mmu_pages *pvec)
{
	int i, ret, nr_unsync_leaf = 0;

	for_each_set_bit(i, sp->unsync_child_bitmap, 512) {
		struct kvm_mmu_page *child;
		u64 ent = sp->spt[i];

		if (!is_shadow_present_pte(ent) || is_large_pte(ent)) {
			clear_unsync_child_bit(sp, i);
			continue;
		}

		child = to_shadow_page(ent & PT64_BASE_ADDR_MASK);

		if (child->unsync_children) {
			if (mmu_pages_add(pvec, child, i))
				return -ENOSPC;

			ret = __mmu_unsync_walk(child, pvec);
			if (!ret) {
				clear_unsync_child_bit(sp, i);
				continue;
			} else if (ret > 0) {
				nr_unsync_leaf += ret;
			} else
				return ret;
		} else if (child->unsync) {
			nr_unsync_leaf++;
			if (mmu_pages_add(pvec, child, i))
				return -ENOSPC;
		} else
			clear_unsync_child_bit(sp, i);
	}

	return nr_unsync_leaf;
}

#define INVALID_INDEX (-1)

static int mmu_unsync_walk(struct kvm_mmu_page *sp,
			   struct kvm_mmu_pages *pvec)
{
	pvec->nr = 0;
	if (!sp->unsync_children)
		return 0;

	mmu_pages_add(pvec, sp, INVALID_INDEX);
	return __mmu_unsync_walk(sp, pvec);
}

static void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	WARN_ON(!sp->unsync);
	trace_kvm_mmu_sync_page(sp);
	sp->unsync = 0;
	--kvm->stat.mmu_unsync;
}

static bool kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				     struct list_head *invalid_list);
static void kvm_mmu_commit_zap_page(struct kvm *kvm,
				    struct list_head *invalid_list);

#define for_each_valid_sp(_kvm, _sp, _list)				\
	hlist_for_each_entry(_sp, _list, hash_link)			\
		if (is_obsolete_sp((_kvm), (_sp))) {			\
		} else

#define for_each_gfn_indirect_valid_sp(_kvm, _sp, _gfn)			\
	for_each_valid_sp(_kvm, _sp,					\
	  &(_kvm)->arch.mmu_page_hash[kvm_page_table_hashfn(_gfn)])	\
		if ((_sp)->gfn != (_gfn) || (_sp)->role.direct) {} else

static bool kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			 struct list_head *invalid_list)
{
	int ret = vcpu->arch.mmu->sync_page(vcpu, sp);

	if (ret < 0) {
		kvm_mmu_prepare_zap_page(vcpu->kvm, sp, invalid_list);
		return false;
	}

	return !!ret;
}

static bool kvm_mmu_remote_flush_or_zap(struct kvm *kvm,
					struct list_head *invalid_list,
					bool remote_flush)
{
	if (!remote_flush && list_empty(invalid_list))
		return false;

	if (!list_empty(invalid_list))
		kvm_mmu_commit_zap_page(kvm, invalid_list);
	else
		kvm_flush_remote_tlbs(kvm);
	return true;
}

#ifdef CONFIG_KVM_MMU_AUDIT
#include "mmu_audit.c"
#else
static void kvm_mmu_audit(struct kvm_vcpu *vcpu, int point) { }
static void mmu_audit_disable(void) { }
#endif

static bool is_obsolete_sp(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	if (sp->role.invalid)
		return true;

	/* TDP MMU pages due not use the MMU generation. */
	return !sp->tdp_mmu_page &&
	       unlikely(sp->mmu_valid_gen != kvm->arch.mmu_valid_gen);
}

struct mmu_page_path {
	struct kvm_mmu_page *parent[PT64_ROOT_MAX_LEVEL];
	unsigned int idx[PT64_ROOT_MAX_LEVEL];
};

#define for_each_sp(pvec, sp, parents, i)			\
		for (i = mmu_pages_first(&pvec, &parents);	\
			i < pvec.nr && ({ sp = pvec.page[i].sp; 1;});	\
			i = mmu_pages_next(&pvec, &parents, i))

static int mmu_pages_next(struct kvm_mmu_pages *pvec,
			  struct mmu_page_path *parents,
			  int i)
{
	int n;

	for (n = i+1; n < pvec->nr; n++) {
		struct kvm_mmu_page *sp = pvec->page[n].sp;
		unsigned idx = pvec->page[n].idx;
		int level = sp->role.level;

		parents->idx[level-1] = idx;
		if (level == PG_LEVEL_4K)
			break;

		parents->parent[level-2] = sp;
	}

	return n;
}

static int mmu_pages_first(struct kvm_mmu_pages *pvec,
			   struct mmu_page_path *parents)
{
	struct kvm_mmu_page *sp;
	int level;

	if (pvec->nr == 0)
		return 0;

	WARN_ON(pvec->page[0].idx != INVALID_INDEX);

	sp = pvec->page[0].sp;
	level = sp->role.level;
	WARN_ON(level == PG_LEVEL_4K);

	parents->parent[level-2] = sp;

	/* Also set up a sentinel.  Further entries in pvec are all
	 * children of sp, so this element is never overwritten.
	 */
	parents->parent[level-1] = NULL;
	return mmu_pages_next(pvec, parents, 0);
}

static void mmu_pages_clear_parents(struct mmu_page_path *parents)
{
	struct kvm_mmu_page *sp;
	unsigned int level = 0;

	do {
		unsigned int idx = parents->idx[level];
		sp = parents->parent[level];
		if (!sp)
			return;

		WARN_ON(idx == INVALID_INDEX);
		clear_unsync_child_bit(sp, idx);
		level++;
	} while (!sp->unsync_children);
}

static int mmu_sync_children(struct kvm_vcpu *vcpu,
			     struct kvm_mmu_page *parent, bool can_yield)
{
	int i;
	struct kvm_mmu_page *sp;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;
	LIST_HEAD(invalid_list);
	bool flush = false;

	while (mmu_unsync_walk(parent, &pages)) {
		bool protected = false;

		for_each_sp(pages, sp, parents, i)
			protected |= rmap_write_protect(vcpu, sp->gfn);

		if (protected) {
			kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, true);
			flush = false;
		}

		for_each_sp(pages, sp, parents, i) {
			kvm_unlink_unsync_page(vcpu->kvm, sp);
			flush |= kvm_sync_page(vcpu, sp, &invalid_list);
			mmu_pages_clear_parents(&parents);
		}
		if (need_resched() || rwlock_needbreak(&vcpu->kvm->mmu_lock)) {
			kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, flush);
			if (!can_yield) {
				kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);
				return -EINTR;
			}

			cond_resched_rwlock_write(&vcpu->kvm->mmu_lock);
			flush = false;
		}
	}

	kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, flush);
	return 0;
}

static void __clear_sp_write_flooding_count(struct kvm_mmu_page *sp)
{
	atomic_set(&sp->write_flooding_count,  0);
}

static void clear_sp_write_flooding_count(u64 *spte)
{
	__clear_sp_write_flooding_count(sptep_to_sp(spte));
}

static struct kvm_mmu_page *kvm_mmu_get_page(struct kvm_vcpu *vcpu,
					     gfn_t gfn,
					     gva_t gaddr,
					     unsigned level,
					     int direct,
					     unsigned int access)
{
	bool direct_mmu = vcpu->arch.mmu->direct_map;
	union kvm_mmu_page_role role;
	struct hlist_head *sp_list;
	unsigned quadrant;
	struct kvm_mmu_page *sp;
	int collisions = 0;
	LIST_HEAD(invalid_list);

	role = vcpu->arch.mmu->mmu_role.base;
	role.level = level;
	role.direct = direct;
	if (role.direct)
		role.gpte_is_8_bytes = true;
	role.access = access;
	if (!direct_mmu && vcpu->arch.mmu->root_level <= PT32_ROOT_LEVEL) {
		quadrant = gaddr >> (PAGE_SHIFT + (PT64_PT_BITS * level));
		quadrant &= (1 << ((PT32_PT_BITS - PT64_PT_BITS) * level)) - 1;
		role.quadrant = quadrant;
	}

	sp_list = &vcpu->kvm->arch.mmu_page_hash[kvm_page_table_hashfn(gfn)];
	for_each_valid_sp(vcpu->kvm, sp, sp_list) {
		if (sp->gfn != gfn) {
			collisions++;
			continue;
		}

		if (sp->role.word != role.word) {
			/*
			 * If the guest is creating an upper-level page, zap
			 * unsync pages for the same gfn.  While it's possible
			 * the guest is using recursive page tables, in all
			 * likelihood the guest has stopped using the unsync
			 * page and is installing a completely unrelated page.
			 * Unsync pages must not be left as is, because the new
			 * upper-level page will be write-protected.
			 */
			if (level > PG_LEVEL_4K && sp->unsync)
				kvm_mmu_prepare_zap_page(vcpu->kvm, sp,
							 &invalid_list);
			continue;
		}

		if (direct_mmu)
			goto trace_get_page;

		if (sp->unsync) {
			/*
			 * The page is good, but is stale.  kvm_sync_page does
			 * get the latest guest state, but (unlike mmu_unsync_children)
			 * it doesn't write-protect the page or mark it synchronized!
			 * This way the validity of the mapping is ensured, but the
			 * overhead of write protection is not incurred until the
			 * guest invalidates the TLB mapping.  This allows multiple
			 * SPs for a single gfn to be unsync.
			 *
			 * If the sync fails, the page is zapped.  If so, break
			 * in order to rebuild it.
			 */
			if (!kvm_sync_page(vcpu, sp, &invalid_list))
				break;

			WARN_ON(!list_empty(&invalid_list));
			kvm_flush_remote_tlbs(vcpu->kvm);
		}

		__clear_sp_write_flooding_count(sp);

trace_get_page:
		trace_kvm_mmu_get_page(sp, false);
		goto out;
	}

	++vcpu->kvm->stat.mmu_cache_miss;

	sp = kvm_mmu_alloc_page(vcpu, direct);

	sp->gfn = gfn;
	sp->role = role;
	hlist_add_head(&sp->hash_link, sp_list);
	if (!direct) {
		account_shadowed(vcpu->kvm, sp);
		if (level == PG_LEVEL_4K && rmap_write_protect(vcpu, gfn))
			kvm_flush_remote_tlbs_with_address(vcpu->kvm, gfn, 1);
	}
	trace_kvm_mmu_get_page(sp, true);
out:
	kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);

	if (collisions > vcpu->kvm->stat.max_mmu_page_hash_collisions)
		vcpu->kvm->stat.max_mmu_page_hash_collisions = collisions;
	return sp;
}

static void shadow_walk_init_using_root(struct kvm_shadow_walk_iterator *iterator,
					struct kvm_vcpu *vcpu, hpa_t root,
					u64 addr)
{
	iterator->addr = addr;
	iterator->shadow_addr = root;
	iterator->level = vcpu->arch.mmu->shadow_root_level;

	if (iterator->level >= PT64_ROOT_4LEVEL &&
	    vcpu->arch.mmu->root_level < PT64_ROOT_4LEVEL &&
	    !vcpu->arch.mmu->direct_map)
		iterator->level = PT32E_ROOT_LEVEL;

	if (iterator->level == PT32E_ROOT_LEVEL) {
		/*
		 * prev_root is currently only used for 64-bit hosts. So only
		 * the active root_hpa is valid here.
		 */
		BUG_ON(root != vcpu->arch.mmu->root_hpa);

		iterator->shadow_addr
			= vcpu->arch.mmu->pae_root[(addr >> 30) & 3];
		iterator->shadow_addr &= PT64_BASE_ADDR_MASK;
		--iterator->level;
		if (!iterator->shadow_addr)
			iterator->level = 0;
	}
}

static void shadow_walk_init(struct kvm_shadow_walk_iterator *iterator,
			     struct kvm_vcpu *vcpu, u64 addr)
{
	shadow_walk_init_using_root(iterator, vcpu, vcpu->arch.mmu->root_hpa,
				    addr);
}

static bool shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator)
{
	if (iterator->level < PG_LEVEL_4K)
		return false;

	iterator->index = SHADOW_PT_INDEX(iterator->addr, iterator->level);
	iterator->sptep	= ((u64 *)__va(iterator->shadow_addr)) + iterator->index;
	return true;
}

static void __shadow_walk_next(struct kvm_shadow_walk_iterator *iterator,
			       u64 spte)
{
	if (!is_shadow_present_pte(spte) || is_last_spte(spte, iterator->level)) {
		iterator->level = 0;
		return;
	}

	iterator->shadow_addr = spte & PT64_BASE_ADDR_MASK;
	--iterator->level;
}

static void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator)
{
	__shadow_walk_next(iterator, *iterator->sptep);
}

static void link_shadow_page(struct kvm_vcpu *vcpu, u64 *sptep,
			     struct kvm_mmu_page *sp)
{
	u64 spte;

	BUILD_BUG_ON(VMX_EPT_WRITABLE_MASK != PT_WRITABLE_MASK);

	spte = make_nonleaf_spte(sp->spt, sp_ad_disabled(sp));

	mmu_spte_set(sptep, spte);

	mmu_page_add_parent_pte(vcpu, sp, sptep);

	if (sp->unsync_children || sp->unsync)
		mark_unsync(sptep);
}

static void validate_direct_spte(struct kvm_vcpu *vcpu, u64 *sptep,
				   unsigned direct_access)
{
	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep)) {
		struct kvm_mmu_page *child;

		/*
		 * For the direct sp, if the guest pte's dirty bit
		 * changed form clean to dirty, it will corrupt the
		 * sp's access: allow writable in the read-only sp,
		 * so we should update the spte at this point to get
		 * a new sp with the correct access.
		 */
		child = to_shadow_page(*sptep & PT64_BASE_ADDR_MASK);
		if (child->role.access == direct_access)
			return;

		drop_parent_pte(child, sptep);
		kvm_flush_remote_tlbs_with_address(vcpu->kvm, child->gfn, 1);
	}
}

/* Returns the number of zapped non-leaf child shadow pages. */
static int mmu_page_zap_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
			    u64 *spte, struct list_head *invalid_list)
{
	u64 pte;
	struct kvm_mmu_page *child;

	pte = *spte;
	if (is_shadow_present_pte(pte)) {
		if (is_last_spte(pte, sp->role.level)) {
			drop_spte(kvm, spte);
		} else {
			child = to_shadow_page(pte & PT64_BASE_ADDR_MASK);
			drop_parent_pte(child, spte);

			/*
			 * Recursively zap nested TDP SPs, parentless SPs are
			 * unlikely to be used again in the near future.  This
			 * avoids retaining a large number of stale nested SPs.
			 */
			if (tdp_enabled && invalid_list &&
			    child->role.guest_mode && !child->parent_ptes.val)
				return kvm_mmu_prepare_zap_page(kvm, child,
								invalid_list);
		}
	} else if (is_mmio_spte(pte)) {
		mmu_spte_clear_no_track(spte);
	}
	return 0;
}

static int kvm_mmu_page_unlink_children(struct kvm *kvm,
					struct kvm_mmu_page *sp,
					struct list_head *invalid_list)
{
	int zapped = 0;
	unsigned i;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i)
		zapped += mmu_page_zap_pte(kvm, sp, sp->spt + i, invalid_list);

	return zapped;
}

static void kvm_mmu_unlink_parents(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	u64 *sptep;
	struct rmap_iterator iter;

	while ((sptep = rmap_get_first(&sp->parent_ptes, &iter)))
		drop_parent_pte(sp, sptep);
}

static int mmu_zap_unsync_children(struct kvm *kvm,
				   struct kvm_mmu_page *parent,
				   struct list_head *invalid_list)
{
	int i, zapped = 0;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	if (parent->role.level == PG_LEVEL_4K)
		return 0;

	while (mmu_unsync_walk(parent, &pages)) {
		struct kvm_mmu_page *sp;

		for_each_sp(pages, sp, parents, i) {
			kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);
			mmu_pages_clear_parents(&parents);
			zapped++;
		}
	}

	return zapped;
}

static bool __kvm_mmu_prepare_zap_page(struct kvm *kvm,
				       struct kvm_mmu_page *sp,
				       struct list_head *invalid_list,
				       int *nr_zapped)
{
	bool list_unstable;

	trace_kvm_mmu_prepare_zap_page(sp);
	++kvm->stat.mmu_shadow_zapped;
	*nr_zapped = mmu_zap_unsync_children(kvm, sp, invalid_list);
	*nr_zapped += kvm_mmu_page_unlink_children(kvm, sp, invalid_list);
	kvm_mmu_unlink_parents(kvm, sp);

	/* Zapping children means active_mmu_pages has become unstable. */
	list_unstable = *nr_zapped;

	if (!sp->role.invalid && !sp->role.direct)
		unaccount_shadowed(kvm, sp);

	if (sp->unsync)
		kvm_unlink_unsync_page(kvm, sp);
	if (!sp->root_count) {
		/* Count self */
		(*nr_zapped)++;

		/*
		 * Already invalid pages (previously active roots) are not on
		 * the active page list.  See list_del() in the "else" case of
		 * !sp->root_count.
		 */
		if (sp->role.invalid)
			list_add(&sp->link, invalid_list);
		else
			list_move(&sp->link, invalid_list);
		kvm_mod_used_mmu_pages(kvm, -1);
	} else {
		/*
		 * Remove the active root from the active page list, the root
		 * will be explicitly freed when the root_count hits zero.
		 */
		list_del(&sp->link);

		/*
		 * Obsolete pages cannot be used on any vCPUs, see the comment
		 * in kvm_mmu_zap_all_fast().  Note, is_obsolete_sp() also
		 * treats invalid shadow pages as being obsolete.
		 */
		if (!is_obsolete_sp(kvm, sp))
			kvm_reload_remote_mmus(kvm);
	}

	if (sp->lpage_disallowed)
		unaccount_huge_nx_page(kvm, sp);

	sp->role.invalid = 1;
	return list_unstable;
}

static bool kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				     struct list_head *invalid_list)
{
	int nr_zapped;

	__kvm_mmu_prepare_zap_page(kvm, sp, invalid_list, &nr_zapped);
	return nr_zapped;
}

static void kvm_mmu_commit_zap_page(struct kvm *kvm,
				    struct list_head *invalid_list)
{
	struct kvm_mmu_page *sp, *nsp;

	if (list_empty(invalid_list))
		return;

	/*
	 * We need to make sure everyone sees our modifications to
	 * the page tables and see changes to vcpu->mode here. The barrier
	 * in the kvm_flush_remote_tlbs() achieves this. This pairs
	 * with vcpu_enter_guest and walk_shadow_page_lockless_begin/end.
	 *
	 * In addition, kvm_flush_remote_tlbs waits for all vcpus to exit
	 * guest mode and/or lockless shadow page table walks.
	 */
	kvm_flush_remote_tlbs(kvm);

	list_for_each_entry_safe(sp, nsp, invalid_list, link) {
		WARN_ON(!sp->role.invalid || sp->root_count);
		kvm_mmu_free_page(sp);
	}
}

static unsigned long kvm_mmu_zap_oldest_mmu_pages(struct kvm *kvm,
						  unsigned long nr_to_zap)
{
	unsigned long total_zapped = 0;
	struct kvm_mmu_page *sp, *tmp;
	LIST_HEAD(invalid_list);
	bool unstable;
	int nr_zapped;

	if (list_empty(&kvm->arch.active_mmu_pages))
		return 0;

restart:
	list_for_each_entry_safe_reverse(sp, tmp, &kvm->arch.active_mmu_pages, link) {
		/*
		 * Don't zap active root pages, the page itself can't be freed
		 * and zapping it will just force vCPUs to realloc and reload.
		 */
		if (sp->root_count)
			continue;

		unstable = __kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list,
						      &nr_zapped);
		total_zapped += nr_zapped;
		if (total_zapped >= nr_to_zap)
			break;

		if (unstable)
			goto restart;
	}

	kvm_mmu_commit_zap_page(kvm, &invalid_list);

	kvm->stat.mmu_recycled += total_zapped;
	return total_zapped;
}

static inline unsigned long kvm_mmu_available_pages(struct kvm *kvm)
{
	if (kvm->arch.n_max_mmu_pages > kvm->arch.n_used_mmu_pages)
		return kvm->arch.n_max_mmu_pages -
			kvm->arch.n_used_mmu_pages;

	return 0;
}

static int make_mmu_pages_available(struct kvm_vcpu *vcpu)
{
	unsigned long avail = kvm_mmu_available_pages(vcpu->kvm);

	if (likely(avail >= KVM_MIN_FREE_MMU_PAGES))
		return 0;

	kvm_mmu_zap_oldest_mmu_pages(vcpu->kvm, KVM_REFILL_PAGES - avail);

	/*
	 * Note, this check is intentionally soft, it only guarantees that one
	 * page is available, while the caller may end up allocating as many as
	 * four pages, e.g. for PAE roots or for 5-level paging.  Temporarily
	 * exceeding the (arbitrary by default) limit will not harm the host,
	 * being too aggressive may unnecessarily kill the guest, and getting an
	 * exact count is far more trouble than it's worth, especially in the
	 * page fault paths.
	 */
	if (!kvm_mmu_available_pages(vcpu->kvm))
		return -ENOSPC;
	return 0;
}

/*
 * Changing the number of mmu pages allocated to the vm
 * Note: if goal_nr_mmu_pages is too small, you will get dead lock
 */
void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned long goal_nr_mmu_pages)
{
	write_lock(&kvm->mmu_lock);

	if (kvm->arch.n_used_mmu_pages > goal_nr_mmu_pages) {
		kvm_mmu_zap_oldest_mmu_pages(kvm, kvm->arch.n_used_mmu_pages -
						  goal_nr_mmu_pages);

		goal_nr_mmu_pages = kvm->arch.n_used_mmu_pages;
	}

	kvm->arch.n_max_mmu_pages = goal_nr_mmu_pages;

	write_unlock(&kvm->mmu_lock);
}

int kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	int r;

	pgprintk("%s: looking for gfn %llx\n", __func__, gfn);
	r = 0;
	write_lock(&kvm->mmu_lock);
	for_each_gfn_indirect_valid_sp(kvm, sp, gfn) {
		pgprintk("%s: gfn %llx role %x\n", __func__, gfn,
			 sp->role.word);
		r = 1;
		kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
	}
	kvm_mmu_commit_zap_page(kvm, &invalid_list);
	write_unlock(&kvm->mmu_lock);

	return r;
}

static int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	int r;

	if (vcpu->arch.mmu->direct_map)
		return 0;

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, NULL);

	r = kvm_mmu_unprotect_page(vcpu->kvm, gpa >> PAGE_SHIFT);

	return r;
}

static void kvm_unsync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	trace_kvm_mmu_unsync_page(sp);
	++vcpu->kvm->stat.mmu_unsync;
	sp->unsync = 1;

	kvm_mmu_mark_parents_unsync(sp);
}

/*
 * Attempt to unsync any shadow pages that can be reached by the specified gfn,
 * KVM is creating a writable mapping for said gfn.  Returns 0 if all pages
 * were marked unsync (or if there is no shadow page), -EPERM if the SPTE must
 * be write-protected.
 */
int mmu_try_to_unsync_pages(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			    gfn_t gfn, bool can_unsync, bool prefetch)
{
	struct kvm_mmu_page *sp;
	bool locked = false;

	/*
	 * Force write-protection if the page is being tracked.  Note, the page
	 * track machinery is used to write-protect upper-level shadow pages,
	 * i.e. this guards the role.level == 4K assertion below!
	 */
	if (kvm_slot_page_track_is_active(vcpu, slot, gfn, KVM_PAGE_TRACK_WRITE))
		return -EPERM;

	/*
	 * The page is not write-tracked, mark existing shadow pages unsync
	 * unless KVM is synchronizing an unsync SP (can_unsync = false).  In
	 * that case, KVM must complete emulation of the guest TLB flush before
	 * allowing shadow pages to become unsync (writable by the guest).
	 */
	for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
		if (!can_unsync)
			return -EPERM;

		if (sp->unsync)
			continue;

		if (prefetch)
			return -EEXIST;

		/*
		 * TDP MMU page faults require an additional spinlock as they
		 * run with mmu_lock held for read, not write, and the unsync
		 * logic is not thread safe.  Take the spinklock regardless of
		 * the MMU type to avoid extra conditionals/parameters, there's
		 * no meaningful penalty if mmu_lock is held for write.
		 */
		if (!locked) {
			locked = true;
			spin_lock(&vcpu->kvm->arch.mmu_unsync_pages_lock);

			/*
			 * Recheck after taking the spinlock, a different vCPU
			 * may have since marked the page unsync.  A false
			 * positive on the unprotected check above is not
			 * possible as clearing sp->unsync _must_ hold mmu_lock
			 * for write, i.e. unsync cannot transition from 0->1
			 * while this CPU holds mmu_lock for read (or write).
			 */
			if (READ_ONCE(sp->unsync))
				continue;
		}

		WARN_ON(sp->role.level != PG_LEVEL_4K);
		kvm_unsync_page(vcpu, sp);
	}
	if (locked)
		spin_unlock(&vcpu->kvm->arch.mmu_unsync_pages_lock);

	/*
	 * We need to ensure that the marking of unsync pages is visible
	 * before the SPTE is updated to allow writes because
	 * kvm_mmu_sync_roots() checks the unsync flags without holding
	 * the MMU lock and so can race with this. If the SPTE was updated
	 * before the page had been marked as unsync-ed, something like the
	 * following could happen:
	 *
	 * CPU 1                    CPU 2
	 * ---------------------------------------------------------------------
	 * 1.2 Host updates SPTE
	 *     to be writable
	 *                      2.1 Guest writes a GPTE for GVA X.
	 *                          (GPTE being in the guest page table shadowed
	 *                           by the SP from CPU 1.)
	 *                          This reads SPTE during the page table walk.
	 *                          Since SPTE.W is read as 1, there is no
	 *                          fault.
	 *
	 *                      2.2 Guest issues TLB flush.
	 *                          That causes a VM Exit.
	 *
	 *                      2.3 Walking of unsync pages sees sp->unsync is
	 *                          false and skips the page.
	 *
	 *                      2.4 Guest accesses GVA X.
	 *                          Since the mapping in the SP was not updated,
	 *                          so the old mapping for GVA X incorrectly
	 *                          gets used.
	 * 1.1 Host marks SP
	 *     as unsync
	 *     (sp->unsync = true)
	 *
	 * The write barrier below ensures that 1.1 happens before 1.2 and thus
	 * the situation in 2.4 does not arise.  It pairs with the read barrier
	 * in is_unsync_root(), placed between 2.1's load of SPTE.W and 2.3.
	 */
	smp_wmb();

	return 0;
}

static int mmu_set_spte(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			u64 *sptep, unsigned int pte_access, gfn_t gfn,
			kvm_pfn_t pfn, struct kvm_page_fault *fault)
{
	struct kvm_mmu_page *sp = sptep_to_sp(sptep);
	int level = sp->role.level;
	int was_rmapped = 0;
	int ret = RET_PF_FIXED;
	bool flush = false;
	bool wrprot;
	u64 spte;

	/* Prefetching always gets a writable pfn.  */
	bool host_writable = !fault || fault->map_writable;
	bool prefetch = !fault || fault->prefetch;
	bool write_fault = fault && fault->write;

	pgprintk("%s: spte %llx write_fault %d gfn %llx\n", __func__,
		 *sptep, write_fault, gfn);

	if (unlikely(is_noslot_pfn(pfn))) {
		mark_mmio_spte(vcpu, sptep, gfn, pte_access);
		return RET_PF_EMULATE;
	}

	if (is_shadow_present_pte(*sptep)) {
		/*
		 * If we overwrite a PTE page pointer with a 2MB PMD, unlink
		 * the parent of the now unreachable PTE.
		 */
		if (level > PG_LEVEL_4K && !is_large_pte(*sptep)) {
			struct kvm_mmu_page *child;
			u64 pte = *sptep;

			child = to_shadow_page(pte & PT64_BASE_ADDR_MASK);
			drop_parent_pte(child, sptep);
			flush = true;
		} else if (pfn != spte_to_pfn(*sptep)) {
			pgprintk("hfn old %llx new %llx\n",
				 spte_to_pfn(*sptep), pfn);
			drop_spte(vcpu->kvm, sptep);
			flush = true;
		} else
			was_rmapped = 1;
	}

	wrprot = make_spte(vcpu, sp, slot, pte_access, gfn, pfn, *sptep, prefetch,
			   true, host_writable, &spte);

	if (*sptep == spte) {
		ret = RET_PF_SPURIOUS;
	} else {
		trace_kvm_mmu_set_spte(level, gfn, sptep);
		flush |= mmu_spte_update(sptep, spte);
	}

	if (wrprot) {
		if (write_fault)
			ret = RET_PF_EMULATE;
	}

	if (flush)
		kvm_flush_remote_tlbs_with_address(vcpu->kvm, gfn,
				KVM_PAGES_PER_HPAGE(level));

	pgprintk("%s: setting spte %llx\n", __func__, *sptep);

	if (!was_rmapped) {
		WARN_ON_ONCE(ret == RET_PF_SPURIOUS);
		kvm_update_page_stats(vcpu->kvm, level, 1);
		rmap_add(vcpu, slot, sptep, gfn);
	}

	return ret;
}

static int direct_pte_prefetch_many(struct kvm_vcpu *vcpu,
				    struct kvm_mmu_page *sp,
				    u64 *start, u64 *end)
{
	struct page *pages[PTE_PREFETCH_NUM];
	struct kvm_memory_slot *slot;
	unsigned int access = sp->role.access;
	int i, ret;
	gfn_t gfn;

	gfn = kvm_mmu_page_get_gfn(sp, start - sp->spt);
	slot = gfn_to_memslot_dirty_bitmap(vcpu, gfn, access & ACC_WRITE_MASK);
	if (!slot)
		return -1;

	ret = gfn_to_page_many_atomic(slot, gfn, pages, end - start);
	if (ret <= 0)
		return -1;

	for (i = 0; i < ret; i++, gfn++, start++) {
		mmu_set_spte(vcpu, slot, start, access, gfn,
			     page_to_pfn(pages[i]), NULL);
		put_page(pages[i]);
	}

	return 0;
}

static void __direct_pte_prefetch(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *sptep)
{
	u64 *spte, *start = NULL;
	int i;

	WARN_ON(!sp->role.direct);

	i = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (is_shadow_present_pte(*spte) || spte == sptep) {
			if (!start)
				continue;
			if (direct_pte_prefetch_many(vcpu, sp, start, spte) < 0)
				return;
			start = NULL;
		} else if (!start)
			start = spte;
	}
	if (start)
		direct_pte_prefetch_many(vcpu, sp, start, spte);
}

static void direct_pte_prefetch(struct kvm_vcpu *vcpu, u64 *sptep)
{
	struct kvm_mmu_page *sp;

	sp = sptep_to_sp(sptep);

	/*
	 * Without accessed bits, there's no way to distinguish between
	 * actually accessed translations and prefetched, so disable pte
	 * prefetch if accessed bits aren't available.
	 */
	if (sp_ad_disabled(sp))
		return;

	if (sp->role.level > PG_LEVEL_4K)
		return;

	/*
	 * If addresses are being invalidated, skip prefetching to avoid
	 * accidentally prefetching those addresses.
	 */
	if (unlikely(vcpu->kvm->mmu_notifier_count))
		return;

	__direct_pte_prefetch(vcpu, sp, sptep);
}

static int host_pfn_mapping_level(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
				  const struct kvm_memory_slot *slot)
{
	unsigned long hva;
	pte_t *pte;
	int level;

	if (!PageCompound(pfn_to_page(pfn)) && !kvm_is_zone_device_pfn(pfn))
		return PG_LEVEL_4K;

	/*
	 * Note, using the already-retrieved memslot and __gfn_to_hva_memslot()
	 * is not solely for performance, it's also necessary to avoid the
	 * "writable" check in __gfn_to_hva_many(), which will always fail on
	 * read-only memslots due to gfn_to_hva() assuming writes.  Earlier
	 * page fault steps have already verified the guest isn't writing a
	 * read-only memslot.
	 */
	hva = __gfn_to_hva_memslot(slot, gfn);

	pte = lookup_address_in_mm(kvm->mm, hva, &level);
	if (unlikely(!pte))
		return PG_LEVEL_4K;

	return level;
}

int kvm_mmu_max_mapping_level(struct kvm *kvm,
			      const struct kvm_memory_slot *slot, gfn_t gfn,
			      kvm_pfn_t pfn, int max_level)
{
	struct kvm_lpage_info *linfo;
	int host_level;

	max_level = min(max_level, max_huge_page_level);
	for ( ; max_level > PG_LEVEL_4K; max_level--) {
		linfo = lpage_info_slot(gfn, slot, max_level);
		if (!linfo->disallow_lpage)
			break;
	}

	if (max_level == PG_LEVEL_4K)
		return PG_LEVEL_4K;

	host_level = host_pfn_mapping_level(kvm, gfn, pfn, slot);
	return min(host_level, max_level);
}

void kvm_mmu_hugepage_adjust(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_memory_slot *slot = fault->slot;
	kvm_pfn_t mask;

	fault->huge_page_disallowed = fault->exec && fault->nx_huge_page_workaround_enabled;

	if (unlikely(fault->max_level == PG_LEVEL_4K))
		return;

	if (is_error_noslot_pfn(fault->pfn) || kvm_is_reserved_pfn(fault->pfn))
		return;

	if (kvm_slot_dirty_track_enabled(slot))
		return;

	/*
	 * Enforce the iTLB multihit workaround after capturing the requested
	 * level, which will be used to do precise, accurate accounting.
	 */
	fault->req_level = kvm_mmu_max_mapping_level(vcpu->kvm, slot,
						     fault->gfn, fault->pfn,
						     fault->max_level);
	if (fault->req_level == PG_LEVEL_4K || fault->huge_page_disallowed)
		return;

	/*
	 * mmu_notifier_retry() was successful and mmu_lock is held, so
	 * the pmd can't be split from under us.
	 */
	fault->goal_level = fault->req_level;
	mask = KVM_PAGES_PER_HPAGE(fault->goal_level) - 1;
	VM_BUG_ON((fault->gfn & mask) != (fault->pfn & mask));
	fault->pfn &= ~mask;
}

void disallowed_hugepage_adjust(struct kvm_page_fault *fault, u64 spte, int cur_level)
{
	if (cur_level > PG_LEVEL_4K &&
	    cur_level == fault->goal_level &&
	    is_shadow_present_pte(spte) &&
	    !is_large_pte(spte)) {
		/*
		 * A small SPTE exists for this pfn, but FNAME(fetch)
		 * and __direct_map would like to create a large PTE
		 * instead: just force them to go down another level,
		 * patching back for them into pfn the next 9 bits of
		 * the address.
		 */
		u64 page_mask = KVM_PAGES_PER_HPAGE(cur_level) -
				KVM_PAGES_PER_HPAGE(cur_level - 1);
		fault->pfn |= fault->gfn & page_mask;
		fault->goal_level--;
	}
}

static int __direct_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_shadow_walk_iterator it;
	struct kvm_mmu_page *sp;
	int ret;
	gfn_t base_gfn = fault->gfn;

	kvm_mmu_hugepage_adjust(vcpu, fault);

	trace_kvm_mmu_spte_requested(fault);
	for_each_shadow_entry(vcpu, fault->addr, it) {
		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, *it.sptep, it.level);

		base_gfn = fault->gfn & ~(KVM_PAGES_PER_HPAGE(it.level) - 1);
		if (it.level == fault->goal_level)
			break;

		drop_large_spte(vcpu, it.sptep);
		if (is_shadow_present_pte(*it.sptep))
			continue;

		sp = kvm_mmu_get_page(vcpu, base_gfn, it.addr,
				      it.level - 1, true, ACC_ALL);

		link_shadow_page(vcpu, it.sptep, sp);
		if (fault->is_tdp && fault->huge_page_disallowed &&
		    fault->req_level >= it.level)
			account_huge_nx_page(vcpu->kvm, sp);
	}

	if (WARN_ON_ONCE(it.level != fault->goal_level))
		return -EFAULT;

	ret = mmu_set_spte(vcpu, fault->slot, it.sptep, ACC_ALL,
			   base_gfn, fault->pfn, fault);
	if (ret == RET_PF_SPURIOUS)
		return ret;

	direct_pte_prefetch(vcpu, it.sptep);
	++vcpu->stat.pf_fixed;
	return ret;
}

static void kvm_send_hwpoison_signal(unsigned long address, struct task_struct *tsk)
{
	send_sig_mceerr(BUS_MCEERR_AR, (void __user *)address, PAGE_SHIFT, tsk);
}

static int kvm_handle_bad_page(struct kvm_vcpu *vcpu, gfn_t gfn, kvm_pfn_t pfn)
{
	/*
	 * Do not cache the mmio info caused by writing the readonly gfn
	 * into the spte otherwise read access on readonly gfn also can
	 * caused mmio page fault and treat it as mmio access.
	 */
	if (pfn == KVM_PFN_ERR_RO_FAULT)
		return RET_PF_EMULATE;

	if (pfn == KVM_PFN_ERR_HWPOISON) {
		kvm_send_hwpoison_signal(kvm_vcpu_gfn_to_hva(vcpu, gfn), current);
		return RET_PF_RETRY;
	}

	return -EFAULT;
}

static bool handle_abnormal_pfn(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
				unsigned int access, int *ret_val)
{
	/* The pfn is invalid, report the error! */
	if (unlikely(is_error_pfn(fault->pfn))) {
		*ret_val = kvm_handle_bad_page(vcpu, fault->gfn, fault->pfn);
		return true;
	}

	if (unlikely(!fault->slot)) {
		gva_t gva = fault->is_tdp ? 0 : fault->addr;

		vcpu_cache_mmio_info(vcpu, gva, fault->gfn,
				     access & shadow_mmio_access_mask);
		/*
		 * If MMIO caching is disabled, emulate immediately without
		 * touching the shadow page tables as attempting to install an
		 * MMIO SPTE will just be an expensive nop.
		 */
		if (unlikely(!shadow_mmio_value)) {
			*ret_val = RET_PF_EMULATE;
			return true;
		}
	}

	return false;
}

static bool page_fault_can_be_fast(struct kvm_page_fault *fault)
{
	/*
	 * Do not fix the mmio spte with invalid generation number which
	 * need to be updated by slow page fault path.
	 */
	if (fault->rsvd)
		return false;

	/* See if the page fault is due to an NX violation */
	if (unlikely(fault->exec && fault->present))
		return false;

	/*
	 * #PF can be fast if:
	 * 1. The shadow page table entry is not present, which could mean that
	 *    the fault is potentially caused by access tracking (if enabled).
	 * 2. The shadow page table entry is present and the fault
	 *    is caused by write-protect, that means we just need change the W
	 *    bit of the spte which can be done out of mmu-lock.
	 *
	 * However, if access tracking is disabled we know that a non-present
	 * page must be a genuine page fault where we have to create a new SPTE.
	 * So, if access tracking is disabled, we return true only for write
	 * accesses to a present page.
	 */

	return shadow_acc_track_mask != 0 || (fault->write && fault->present);
}

/*
 * Returns true if the SPTE was fixed successfully. Otherwise,
 * someone else modified the SPTE from its original value.
 */
static bool
fast_pf_fix_direct_spte(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			u64 *sptep, u64 old_spte, u64 new_spte)
{
	/*
	 * Theoretically we could also set dirty bit (and flush TLB) here in
	 * order to eliminate unnecessary PML logging. See comments in
	 * set_spte. But fast_page_fault is very unlikely to happen with PML
	 * enabled, so we do not do this. This might result in the same GPA
	 * to be logged in PML buffer again when the write really happens, and
	 * eventually to be called by mark_page_dirty twice. But it's also no
	 * harm. This also avoids the TLB flush needed after setting dirty bit
	 * so non-PML cases won't be impacted.
	 *
	 * Compare with set_spte where instead shadow_dirty_mask is set.
	 */
	if (cmpxchg64(sptep, old_spte, new_spte) != old_spte)
		return false;

	if (is_writable_pte(new_spte) && !is_writable_pte(old_spte))
		mark_page_dirty_in_slot(vcpu->kvm, fault->slot, fault->gfn);

	return true;
}

static bool is_access_allowed(struct kvm_page_fault *fault, u64 spte)
{
	if (fault->exec)
		return is_executable_pte(spte);

	if (fault->write)
		return is_writable_pte(spte);

	/* Fault was on Read access */
	return spte & PT_PRESENT_MASK;
}

/*
 * Returns the last level spte pointer of the shadow page walk for the given
 * gpa, and sets *spte to the spte value. This spte may be non-preset. If no
 * walk could be performed, returns NULL and *spte does not contain valid data.
 *
 * Contract:
 *  - Must be called between walk_shadow_page_lockless_{begin,end}.
 *  - The returned sptep must not be used after walk_shadow_page_lockless_end.
 */
static u64 *fast_pf_get_last_sptep(struct kvm_vcpu *vcpu, gpa_t gpa, u64 *spte)
{
	struct kvm_shadow_walk_iterator iterator;
	u64 old_spte;
	u64 *sptep = NULL;

	for_each_shadow_entry_lockless(vcpu, gpa, iterator, old_spte) {
		sptep = iterator.sptep;
		*spte = old_spte;
	}

	return sptep;
}

/*
 * Returns one of RET_PF_INVALID, RET_PF_FIXED or RET_PF_SPURIOUS.
 */
static int fast_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_mmu_page *sp;
	int ret = RET_PF_INVALID;
	u64 spte = 0ull;
	u64 *sptep = NULL;
	uint retry_count = 0;

	if (!page_fault_can_be_fast(fault))
		return ret;

	walk_shadow_page_lockless_begin(vcpu);

	do {
		u64 new_spte;

		if (is_tdp_mmu(vcpu->arch.mmu))
			sptep = kvm_tdp_mmu_fast_pf_get_last_sptep(vcpu, fault->addr, &spte);
		else
			sptep = fast_pf_get_last_sptep(vcpu, fault->addr, &spte);

		if (!is_shadow_present_pte(spte))
			break;

		sp = sptep_to_sp(sptep);
		if (!is_last_spte(spte, sp->role.level))
			break;

		/*
		 * Check whether the memory access that caused the fault would
		 * still cause it if it were to be performed right now. If not,
		 * then this is a spurious fault caused by TLB lazily flushed,
		 * or some other CPU has already fixed the PTE after the
		 * current CPU took the fault.
		 *
		 * Need not check the access of upper level table entries since
		 * they are always ACC_ALL.
		 */
		if (is_access_allowed(fault, spte)) {
			ret = RET_PF_SPURIOUS;
			break;
		}

		new_spte = spte;

		if (is_access_track_spte(spte))
			new_spte = restore_acc_track_spte(new_spte);

		/*
		 * Currently, to simplify the code, write-protection can
		 * be removed in the fast path only if the SPTE was
		 * write-protected for dirty-logging or access tracking.
		 */
		if (fault->write &&
		    spte_can_locklessly_be_made_writable(spte)) {
			new_spte |= PT_WRITABLE_MASK;

			/*
			 * Do not fix write-permission on the large spte when
			 * dirty logging is enabled. Since we only dirty the
			 * first page into the dirty-bitmap in
			 * fast_pf_fix_direct_spte(), other pages are missed
			 * if its slot has dirty logging enabled.
			 *
			 * Instead, we let the slow page fault path create a
			 * normal spte to fix the access.
			 */
			if (sp->role.level > PG_LEVEL_4K &&
			    kvm_slot_dirty_track_enabled(fault->slot))
				break;
		}

		/* Verify that the fault can be handled in the fast path */
		if (new_spte == spte ||
		    !is_access_allowed(fault, new_spte))
			break;

		/*
		 * Currently, fast page fault only works for direct mapping
		 * since the gfn is not stable for indirect shadow page. See
		 * Documentation/virt/kvm/locking.rst to get more detail.
		 */
		if (fast_pf_fix_direct_spte(vcpu, fault, sptep, spte, new_spte)) {
			ret = RET_PF_FIXED;
			break;
		}

		if (++retry_count > 4) {
			printk_once(KERN_WARNING
				"kvm: Fast #PF retrying more than 4 times.\n");
			break;
		}

	} while (true);

	trace_fast_page_fault(vcpu, fault, sptep, spte, ret);
	walk_shadow_page_lockless_end(vcpu);

	return ret;
}

static void mmu_free_root_page(struct kvm *kvm, hpa_t *root_hpa,
			       struct list_head *invalid_list)
{
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(*root_hpa))
		return;

	sp = to_shadow_page(*root_hpa & PT64_BASE_ADDR_MASK);

	if (is_tdp_mmu_page(sp))
		kvm_tdp_mmu_put_root(kvm, sp, false);
	else if (!--sp->root_count && sp->role.invalid)
		kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);

	*root_hpa = INVALID_PAGE;
}

/* roots_to_free must be some combination of the KVM_MMU_ROOT_* flags */
void kvm_mmu_free_roots(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			ulong roots_to_free)
{
	struct kvm *kvm = vcpu->kvm;
	int i;
	LIST_HEAD(invalid_list);
	bool free_active_root = roots_to_free & KVM_MMU_ROOT_CURRENT;

	BUILD_BUG_ON(KVM_MMU_NUM_PREV_ROOTS >= BITS_PER_LONG);

	/* Before acquiring the MMU lock, see if we need to do any real work. */
	if (!(free_active_root && VALID_PAGE(mmu->root_hpa))) {
		for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
			if ((roots_to_free & KVM_MMU_ROOT_PREVIOUS(i)) &&
			    VALID_PAGE(mmu->prev_roots[i].hpa))
				break;

		if (i == KVM_MMU_NUM_PREV_ROOTS)
			return;
	}

	write_lock(&kvm->mmu_lock);

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		if (roots_to_free & KVM_MMU_ROOT_PREVIOUS(i))
			mmu_free_root_page(kvm, &mmu->prev_roots[i].hpa,
					   &invalid_list);

	if (free_active_root) {
		if (mmu->shadow_root_level >= PT64_ROOT_4LEVEL &&
		    (mmu->root_level >= PT64_ROOT_4LEVEL || mmu->direct_map)) {
			mmu_free_root_page(kvm, &mmu->root_hpa, &invalid_list);
		} else if (mmu->pae_root) {
			for (i = 0; i < 4; ++i) {
				if (!IS_VALID_PAE_ROOT(mmu->pae_root[i]))
					continue;

				mmu_free_root_page(kvm, &mmu->pae_root[i],
						   &invalid_list);
				mmu->pae_root[i] = INVALID_PAE_ROOT;
			}
		}
		mmu->root_hpa = INVALID_PAGE;
		mmu->root_pgd = 0;
	}

	kvm_mmu_commit_zap_page(kvm, &invalid_list);
	write_unlock(&kvm->mmu_lock);
}
EXPORT_SYMBOL_GPL(kvm_mmu_free_roots);

void kvm_mmu_free_guest_mode_roots(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu)
{
	unsigned long roots_to_free = 0;
	hpa_t root_hpa;
	int i;

	/*
	 * This should not be called while L2 is active, L2 can't invalidate
	 * _only_ its own roots, e.g. INVVPID unconditionally exits.
	 */
	WARN_ON_ONCE(mmu->mmu_role.base.guest_mode);

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		root_hpa = mmu->prev_roots[i].hpa;
		if (!VALID_PAGE(root_hpa))
			continue;

		if (!to_shadow_page(root_hpa) ||
			to_shadow_page(root_hpa)->role.guest_mode)
			roots_to_free |= KVM_MMU_ROOT_PREVIOUS(i);
	}

	kvm_mmu_free_roots(vcpu, mmu, roots_to_free);
}
EXPORT_SYMBOL_GPL(kvm_mmu_free_guest_mode_roots);


static int mmu_check_root(struct kvm_vcpu *vcpu, gfn_t root_gfn)
{
	int ret = 0;

	if (!kvm_vcpu_is_visible_gfn(vcpu, root_gfn)) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		ret = 1;
	}

	return ret;
}

static hpa_t mmu_alloc_root(struct kvm_vcpu *vcpu, gfn_t gfn, gva_t gva,
			    u8 level, bool direct)
{
	struct kvm_mmu_page *sp;

	sp = kvm_mmu_get_page(vcpu, gfn, gva, level, direct, ACC_ALL);
	++sp->root_count;

	return __pa(sp->spt);
}

static int mmu_alloc_direct_roots(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u8 shadow_root_level = mmu->shadow_root_level;
	hpa_t root;
	unsigned i;
	int r;

	write_lock(&vcpu->kvm->mmu_lock);
	r = make_mmu_pages_available(vcpu);
	if (r < 0)
		goto out_unlock;

	if (is_tdp_mmu_enabled(vcpu->kvm)) {
		root = kvm_tdp_mmu_get_vcpu_root_hpa(vcpu);
		mmu->root_hpa = root;
	} else if (shadow_root_level >= PT64_ROOT_4LEVEL) {
		root = mmu_alloc_root(vcpu, 0, 0, shadow_root_level, true);
		mmu->root_hpa = root;
	} else if (shadow_root_level == PT32E_ROOT_LEVEL) {
		if (WARN_ON_ONCE(!mmu->pae_root)) {
			r = -EIO;
			goto out_unlock;
		}

		for (i = 0; i < 4; ++i) {
			WARN_ON_ONCE(IS_VALID_PAE_ROOT(mmu->pae_root[i]));

			root = mmu_alloc_root(vcpu, i << (30 - PAGE_SHIFT),
					      i << 30, PT32_ROOT_LEVEL, true);
			mmu->pae_root[i] = root | PT_PRESENT_MASK |
					   shadow_me_mask;
		}
		mmu->root_hpa = __pa(mmu->pae_root);
	} else {
		WARN_ONCE(1, "Bad TDP root level = %d\n", shadow_root_level);
		r = -EIO;
		goto out_unlock;
	}

	/* root_pgd is ignored for direct MMUs. */
	mmu->root_pgd = 0;
out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);
	return r;
}

static int mmu_first_shadow_root_alloc(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	int r = 0, i;

	/*
	 * Check if this is the first shadow root being allocated before
	 * taking the lock.
	 */
	if (kvm_shadow_root_allocated(kvm))
		return 0;

	mutex_lock(&kvm->slots_arch_lock);

	/* Recheck, under the lock, whether this is the first shadow root. */
	if (kvm_shadow_root_allocated(kvm))
		goto out_unlock;

	/*
	 * Check if anything actually needs to be allocated, e.g. all metadata
	 * will be allocated upfront if TDP is disabled.
	 */
	if (kvm_memslots_have_rmaps(kvm) &&
	    kvm_page_track_write_tracking_enabled(kvm))
		goto out_success;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(slot, slots) {
			/*
			 * Both of these functions are no-ops if the target is
			 * already allocated, so unconditionally calling both
			 * is safe.  Intentionally do NOT free allocations on
			 * failure to avoid having to track which allocations
			 * were made now versus when the memslot was created.
			 * The metadata is guaranteed to be freed when the slot
			 * is freed, and will be kept/used if userspace retries
			 * KVM_RUN instead of killing the VM.
			 */
			r = memslot_rmap_alloc(slot, slot->npages);
			if (r)
				goto out_unlock;
			r = kvm_page_track_write_tracking_alloc(slot);
			if (r)
				goto out_unlock;
		}
	}

	/*
	 * Ensure that shadow_root_allocated becomes true strictly after
	 * all the related pointers are set.
	 */
out_success:
	smp_store_release(&kvm->arch.shadow_root_allocated, true);

out_unlock:
	mutex_unlock(&kvm->slots_arch_lock);
	return r;
}

static int mmu_alloc_shadow_roots(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u64 pdptrs[4], pm_mask;
	gfn_t root_gfn, root_pgd;
	hpa_t root;
	unsigned i;
	int r;

	root_pgd = mmu->get_guest_pgd(vcpu);
	root_gfn = root_pgd >> PAGE_SHIFT;

	if (mmu_check_root(vcpu, root_gfn))
		return 1;

	/*
	 * On SVM, reading PDPTRs might access guest memory, which might fault
	 * and thus might sleep.  Grab the PDPTRs before acquiring mmu_lock.
	 */
	if (mmu->root_level == PT32E_ROOT_LEVEL) {
		for (i = 0; i < 4; ++i) {
			pdptrs[i] = mmu->get_pdptr(vcpu, i);
			if (!(pdptrs[i] & PT_PRESENT_MASK))
				continue;

			if (mmu_check_root(vcpu, pdptrs[i] >> PAGE_SHIFT))
				return 1;
		}
	}

	r = mmu_first_shadow_root_alloc(vcpu->kvm);
	if (r)
		return r;

	write_lock(&vcpu->kvm->mmu_lock);
	r = make_mmu_pages_available(vcpu);
	if (r < 0)
		goto out_unlock;

	/*
	 * Do we shadow a long mode page table? If so we need to
	 * write-protect the guests page table root.
	 */
	if (mmu->root_level >= PT64_ROOT_4LEVEL) {
		root = mmu_alloc_root(vcpu, root_gfn, 0,
				      mmu->shadow_root_level, false);
		mmu->root_hpa = root;
		goto set_root_pgd;
	}

	if (WARN_ON_ONCE(!mmu->pae_root)) {
		r = -EIO;
		goto out_unlock;
	}

	/*
	 * We shadow a 32 bit page table. This may be a legacy 2-level
	 * or a PAE 3-level page table. In either case we need to be aware that
	 * the shadow page table may be a PAE or a long mode page table.
	 */
	pm_mask = PT_PRESENT_MASK | shadow_me_mask;
	if (mmu->shadow_root_level >= PT64_ROOT_4LEVEL) {
		pm_mask |= PT_ACCESSED_MASK | PT_WRITABLE_MASK | PT_USER_MASK;

		if (WARN_ON_ONCE(!mmu->pml4_root)) {
			r = -EIO;
			goto out_unlock;
		}
		mmu->pml4_root[0] = __pa(mmu->pae_root) | pm_mask;

		if (mmu->shadow_root_level == PT64_ROOT_5LEVEL) {
			if (WARN_ON_ONCE(!mmu->pml5_root)) {
				r = -EIO;
				goto out_unlock;
			}
			mmu->pml5_root[0] = __pa(mmu->pml4_root) | pm_mask;
		}
	}

	for (i = 0; i < 4; ++i) {
		WARN_ON_ONCE(IS_VALID_PAE_ROOT(mmu->pae_root[i]));

		if (mmu->root_level == PT32E_ROOT_LEVEL) {
			if (!(pdptrs[i] & PT_PRESENT_MASK)) {
				mmu->pae_root[i] = INVALID_PAE_ROOT;
				continue;
			}
			root_gfn = pdptrs[i] >> PAGE_SHIFT;
		}

		root = mmu_alloc_root(vcpu, root_gfn, i << 30,
				      PT32_ROOT_LEVEL, false);
		mmu->pae_root[i] = root | pm_mask;
	}

	if (mmu->shadow_root_level == PT64_ROOT_5LEVEL)
		mmu->root_hpa = __pa(mmu->pml5_root);
	else if (mmu->shadow_root_level == PT64_ROOT_4LEVEL)
		mmu->root_hpa = __pa(mmu->pml4_root);
	else
		mmu->root_hpa = __pa(mmu->pae_root);

set_root_pgd:
	mmu->root_pgd = root_pgd;
out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);

	return 0;
}

static int mmu_alloc_special_roots(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	bool need_pml5 = mmu->shadow_root_level > PT64_ROOT_4LEVEL;
	u64 *pml5_root = NULL;
	u64 *pml4_root = NULL;
	u64 *pae_root;

	/*
	 * When shadowing 32-bit or PAE NPT with 64-bit NPT, the PML4 and PDP
	 * tables are allocated and initialized at root creation as there is no
	 * equivalent level in the guest's NPT to shadow.  Allocate the tables
	 * on demand, as running a 32-bit L1 VMM on 64-bit KVM is very rare.
	 */
	if (mmu->direct_map || mmu->root_level >= PT64_ROOT_4LEVEL ||
	    mmu->shadow_root_level < PT64_ROOT_4LEVEL)
		return 0;

	/*
	 * NPT, the only paging mode that uses this horror, uses a fixed number
	 * of levels for the shadow page tables, e.g. all MMUs are 4-level or
	 * all MMus are 5-level.  Thus, this can safely require that pml5_root
	 * is allocated if the other roots are valid and pml5 is needed, as any
	 * prior MMU would also have required pml5.
	 */
	if (mmu->pae_root && mmu->pml4_root && (!need_pml5 || mmu->pml5_root))
		return 0;

	/*
	 * The special roots should always be allocated in concert.  Yell and
	 * bail if KVM ends up in a state where only one of the roots is valid.
	 */
	if (WARN_ON_ONCE(!tdp_enabled || mmu->pae_root || mmu->pml4_root ||
			 (need_pml5 && mmu->pml5_root)))
		return -EIO;

	/*
	 * Unlike 32-bit NPT, the PDP table doesn't need to be in low mem, and
	 * doesn't need to be decrypted.
	 */
	pae_root = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!pae_root)
		return -ENOMEM;

#ifdef CONFIG_X86_64
	pml4_root = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!pml4_root)
		goto err_pml4;

	if (need_pml5) {
		pml5_root = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
		if (!pml5_root)
			goto err_pml5;
	}
#endif

	mmu->pae_root = pae_root;
	mmu->pml4_root = pml4_root;
	mmu->pml5_root = pml5_root;

	return 0;

#ifdef CONFIG_X86_64
err_pml5:
	free_page((unsigned long)pml4_root);
err_pml4:
	free_page((unsigned long)pae_root);
	return -ENOMEM;
#endif
}

static bool is_unsync_root(hpa_t root)
{
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(root))
		return false;

	/*
	 * The read barrier orders the CPU's read of SPTE.W during the page table
	 * walk before the reads of sp->unsync/sp->unsync_children here.
	 *
	 * Even if another CPU was marking the SP as unsync-ed simultaneously,
	 * any guest page table changes are not guaranteed to be visible anyway
	 * until this VCPU issues a TLB flush strictly after those changes are
	 * made.  We only need to ensure that the other CPU sets these flags
	 * before any actual changes to the page tables are made.  The comments
	 * in mmu_try_to_unsync_pages() describe what could go wrong if this
	 * requirement isn't satisfied.
	 */
	smp_rmb();
	sp = to_shadow_page(root);
	if (sp->unsync || sp->unsync_children)
		return true;

	return false;
}

void kvm_mmu_sync_roots(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_mmu_page *sp;

	if (vcpu->arch.mmu->direct_map)
		return;

	if (!VALID_PAGE(vcpu->arch.mmu->root_hpa))
		return;

	vcpu_clear_mmio_info(vcpu, MMIO_GVA_ANY);

	if (vcpu->arch.mmu->root_level >= PT64_ROOT_4LEVEL) {
		hpa_t root = vcpu->arch.mmu->root_hpa;
		sp = to_shadow_page(root);

		if (!is_unsync_root(root))
			return;

		write_lock(&vcpu->kvm->mmu_lock);
		kvm_mmu_audit(vcpu, AUDIT_PRE_SYNC);

		mmu_sync_children(vcpu, sp, true);

		kvm_mmu_audit(vcpu, AUDIT_POST_SYNC);
		write_unlock(&vcpu->kvm->mmu_lock);
		return;
	}

	write_lock(&vcpu->kvm->mmu_lock);
	kvm_mmu_audit(vcpu, AUDIT_PRE_SYNC);

	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu->pae_root[i];

		if (IS_VALID_PAE_ROOT(root)) {
			root &= PT64_BASE_ADDR_MASK;
			sp = to_shadow_page(root);
			mmu_sync_children(vcpu, sp, true);
		}
	}

	kvm_mmu_audit(vcpu, AUDIT_POST_SYNC);
	write_unlock(&vcpu->kvm->mmu_lock);
}

void kvm_mmu_sync_prev_roots(struct kvm_vcpu *vcpu)
{
	unsigned long roots_to_free = 0;
	int i;

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		if (is_unsync_root(vcpu->arch.mmu->prev_roots[i].hpa))
			roots_to_free |= KVM_MMU_ROOT_PREVIOUS(i);

	/* sync prev_roots by simply freeing them */
	kvm_mmu_free_roots(vcpu, vcpu->arch.mmu, roots_to_free);
}

static gpa_t nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, gpa_t vaddr,
				  u32 access, struct x86_exception *exception)
{
	if (exception)
		exception->error_code = 0;
	return vaddr;
}

static gpa_t nonpaging_gva_to_gpa_nested(struct kvm_vcpu *vcpu, gpa_t vaddr,
					 u32 access,
					 struct x86_exception *exception)
{
	if (exception)
		exception->error_code = 0;
	return vcpu->arch.nested_mmu.translate_gpa(vcpu, vaddr, access, exception);
}

static bool mmio_info_in_cache(struct kvm_vcpu *vcpu, u64 addr, bool direct)
{
	/*
	 * A nested guest cannot use the MMIO cache if it is using nested
	 * page tables, because cr2 is a nGPA while the cache stores GPAs.
	 */
	if (mmu_is_nested(vcpu))
		return false;

	if (direct)
		return vcpu_match_mmio_gpa(vcpu, addr);

	return vcpu_match_mmio_gva(vcpu, addr);
}

/*
 * Return the level of the lowest level SPTE added to sptes.
 * That SPTE may be non-present.
 *
 * Must be called between walk_shadow_page_lockless_{begin,end}.
 */
static int get_walk(struct kvm_vcpu *vcpu, u64 addr, u64 *sptes, int *root_level)
{
	struct kvm_shadow_walk_iterator iterator;
	int leaf = -1;
	u64 spte;

	for (shadow_walk_init(&iterator, vcpu, addr),
	     *root_level = iterator.level;
	     shadow_walk_okay(&iterator);
	     __shadow_walk_next(&iterator, spte)) {
		leaf = iterator.level;
		spte = mmu_spte_get_lockless(iterator.sptep);

		sptes[leaf] = spte;
	}

	return leaf;
}

/* return true if reserved bit(s) are detected on a valid, non-MMIO SPTE. */
static bool get_mmio_spte(struct kvm_vcpu *vcpu, u64 addr, u64 *sptep)
{
	u64 sptes[PT64_ROOT_MAX_LEVEL + 1];
	struct rsvd_bits_validate *rsvd_check;
	int root, leaf, level;
	bool reserved = false;

	walk_shadow_page_lockless_begin(vcpu);

	if (is_tdp_mmu(vcpu->arch.mmu))
		leaf = kvm_tdp_mmu_get_walk(vcpu, addr, sptes, &root);
	else
		leaf = get_walk(vcpu, addr, sptes, &root);

	walk_shadow_page_lockless_end(vcpu);

	if (unlikely(leaf < 0)) {
		*sptep = 0ull;
		return reserved;
	}

	*sptep = sptes[leaf];

	/*
	 * Skip reserved bits checks on the terminal leaf if it's not a valid
	 * SPTE.  Note, this also (intentionally) skips MMIO SPTEs, which, by
	 * design, always have reserved bits set.  The purpose of the checks is
	 * to detect reserved bits on non-MMIO SPTEs. i.e. buggy SPTEs.
	 */
	if (!is_shadow_present_pte(sptes[leaf]))
		leaf++;

	rsvd_check = &vcpu->arch.mmu->shadow_zero_check;

	for (level = root; level >= leaf; level--)
		reserved |= is_rsvd_spte(rsvd_check, sptes[level], level);

	if (reserved) {
		pr_err("%s: reserved bits set on MMU-present spte, addr 0x%llx, hierarchy:\n",
		       __func__, addr);
		for (level = root; level >= leaf; level--)
			pr_err("------ spte = 0x%llx level = %d, rsvd bits = 0x%llx",
			       sptes[level], level,
			       get_rsvd_bits(rsvd_check, sptes[level], level));
	}

	return reserved;
}

static int handle_mmio_page_fault(struct kvm_vcpu *vcpu, u64 addr, bool direct)
{
	u64 spte;
	bool reserved;

	if (mmio_info_in_cache(vcpu, addr, direct))
		return RET_PF_EMULATE;

	reserved = get_mmio_spte(vcpu, addr, &spte);
	if (WARN_ON(reserved))
		return -EINVAL;

	if (is_mmio_spte(spte)) {
		gfn_t gfn = get_mmio_spte_gfn(spte);
		unsigned int access = get_mmio_spte_access(spte);

		if (!check_mmio_spte(vcpu, spte))
			return RET_PF_INVALID;

		if (direct)
			addr = 0;

		trace_handle_mmio_page_fault(addr, gfn, access);
		vcpu_cache_mmio_info(vcpu, addr, gfn, access);
		return RET_PF_EMULATE;
	}

	/*
	 * If the page table is zapped by other cpus, let CPU fault again on
	 * the address.
	 */
	return RET_PF_RETRY;
}

static bool page_fault_handle_page_track(struct kvm_vcpu *vcpu,
					 struct kvm_page_fault *fault)
{
	if (unlikely(fault->rsvd))
		return false;

	if (!fault->present || !fault->write)
		return false;

	/*
	 * guest is writing the page which is write tracked which can
	 * not be fixed by page fault handler.
	 */
	if (kvm_slot_page_track_is_active(vcpu, fault->slot, fault->gfn, KVM_PAGE_TRACK_WRITE))
		return true;

	return false;
}

static void shadow_page_table_clear_flood(struct kvm_vcpu *vcpu, gva_t addr)
{
	struct kvm_shadow_walk_iterator iterator;
	u64 spte;

	walk_shadow_page_lockless_begin(vcpu);
	for_each_shadow_entry_lockless(vcpu, addr, iterator, spte)
		clear_sp_write_flooding_count(iterator.sptep);
	walk_shadow_page_lockless_end(vcpu);
}

static bool kvm_arch_setup_async_pf(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
				    gfn_t gfn)
{
	struct kvm_arch_async_pf arch;

	arch.token = (vcpu->arch.apf.id++ << 12) | vcpu->vcpu_id;
	arch.gfn = gfn;
	arch.direct_map = vcpu->arch.mmu->direct_map;
	arch.cr3 = vcpu->arch.mmu->get_guest_pgd(vcpu);

	return kvm_setup_async_pf(vcpu, cr2_or_gpa,
				  kvm_vcpu_gfn_to_hva(vcpu, gfn), &arch);
}

static bool kvm_faultin_pfn(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault, int *r)
{
	struct kvm_memory_slot *slot = fault->slot;
	bool async;

	/*
	 * Retry the page fault if the gfn hit a memslot that is being deleted
	 * or moved.  This ensures any existing SPTEs for the old memslot will
	 * be zapped before KVM inserts a new MMIO SPTE for the gfn.
	 */
	if (slot && (slot->flags & KVM_MEMSLOT_INVALID))
		goto out_retry;

	if (!kvm_is_visible_memslot(slot)) {
		/* Don't expose private memslots to L2. */
		if (is_guest_mode(vcpu)) {
			fault->slot = NULL;
			fault->pfn = KVM_PFN_NOSLOT;
			fault->map_writable = false;
			return false;
		}
		/*
		 * If the APIC access page exists but is disabled, go directly
		 * to emulation without caching the MMIO access or creating a
		 * MMIO SPTE.  That way the cache doesn't need to be purged
		 * when the AVIC is re-enabled.
		 */
		if (slot && slot->id == APIC_ACCESS_PAGE_PRIVATE_MEMSLOT &&
		    !kvm_apicv_activated(vcpu->kvm)) {
			*r = RET_PF_EMULATE;
			return true;
		}
	}

	async = false;
	fault->pfn = __gfn_to_pfn_memslot(slot, fault->gfn, false, &async,
					  fault->write, &fault->map_writable,
					  &fault->hva);
	if (!async)
		return false; /* *pfn has correct page already */

	if (!fault->prefetch && kvm_can_do_async_pf(vcpu)) {
		trace_kvm_try_async_get_page(fault->addr, fault->gfn);
		if (kvm_find_async_pf_gfn(vcpu, fault->gfn)) {
			trace_kvm_async_pf_doublefault(fault->addr, fault->gfn);
			kvm_make_request(KVM_REQ_APF_HALT, vcpu);
			goto out_retry;
		} else if (kvm_arch_setup_async_pf(vcpu, fault->addr, fault->gfn))
			goto out_retry;
	}

	fault->pfn = __gfn_to_pfn_memslot(slot, fault->gfn, false, NULL,
					  fault->write, &fault->map_writable,
					  &fault->hva);
	return false;

out_retry:
	*r = RET_PF_RETRY;
	return true;
}

/*
 * Returns true if the page fault is stale and needs to be retried, i.e. if the
 * root was invalidated by a memslot update or a relevant mmu_notifier fired.
 */
static bool is_page_fault_stale(struct kvm_vcpu *vcpu,
				struct kvm_page_fault *fault, int mmu_seq)
{
	struct kvm_mmu_page *sp = to_shadow_page(vcpu->arch.mmu->root_hpa);

	/* Special roots, e.g. pae_root, are not backed by shadow pages. */
	if (sp && is_obsolete_sp(vcpu->kvm, sp))
		return true;

	/*
	 * Roots without an associated shadow page are considered invalid if
	 * there is a pending request to free obsolete roots.  The request is
	 * only a hint that the current root _may_ be obsolete and needs to be
	 * reloaded, e.g. if the guest frees a PGD that KVM is tracking as a
	 * previous root, then __kvm_mmu_prepare_zap_page() signals all vCPUs
	 * to reload even if no vCPU is actively using the root.
	 */
	if (!sp && kvm_test_request(KVM_REQ_MMU_RELOAD, vcpu))
		return true;

	return fault->slot &&
	       mmu_notifier_retry_hva(vcpu->kvm, mmu_seq, fault->hva);
}

static int direct_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	bool is_tdp_mmu_fault = is_tdp_mmu(vcpu->arch.mmu);

	unsigned long mmu_seq;
	int r;

	fault->gfn = fault->addr >> PAGE_SHIFT;
	fault->slot = kvm_vcpu_gfn_to_memslot(vcpu, fault->gfn);

	// Ori: I think that a write to EPT12 goes through here
	// printk("page_fault_handle_page_track\n");
	if (page_fault_handle_page_track(vcpu, fault))
		return RET_PF_EMULATE;

	// printk("fast_page_fault\n");
	r = fast_page_fault(vcpu, fault);
	if (r != RET_PF_INVALID)
		return r;
	// printk("mmu_topup_memory_caches\n");
	r = mmu_topup_memory_caches(vcpu, false);
	if (r)
		return r;

	mmu_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();

	// printk("kvm_faultin_pfn\n");
	// Lets add bypass here, to see if it works
	if (kvm_faultin_pfn(vcpu, fault, &r))
		return r;

	// printk("handle_abnormal_pfn\n");
	if (handle_abnormal_pfn(vcpu, fault, ACC_ALL, &r))
		return r;

	r = RET_PF_RETRY;

	if (is_tdp_mmu_fault)
		read_lock(&vcpu->kvm->mmu_lock);
	else
		write_lock(&vcpu->kvm->mmu_lock);
	// printk("is_page_fault_stale\n");
	if (is_page_fault_stale(vcpu, fault, mmu_seq))
		goto out_unlock;
	// printk("make_mmu_pages_available\n");
	r = make_mmu_pages_available(vcpu);
	if (r)
		goto out_unlock;
	// printk("kvm_tdp_mmu_map\n");
	if (is_tdp_mmu_fault)
		r = kvm_tdp_mmu_map(vcpu, fault);
	else
		r = __direct_map(vcpu, fault);

out_unlock:
	if (is_tdp_mmu_fault)
		read_unlock(&vcpu->kvm->mmu_lock);
	else
		write_unlock(&vcpu->kvm->mmu_lock);

	kvm_release_pfn_clean(fault->pfn);
	return r;
}

static int nonpaging_page_fault(struct kvm_vcpu *vcpu,
				struct kvm_page_fault *fault)
{
	pgprintk("%s: gva %lx error %x\n", __func__, fault->addr, fault->error_code);

	/* This path builds a PAE pagetable, we can map 2mb pages at maximum. */
	fault->max_level = PG_LEVEL_2M;
	return direct_page_fault(vcpu, fault);
}

int kvm_handle_page_fault(struct kvm_vcpu *vcpu, u64 error_code,
				u64 fault_address, char *insn, int insn_len)
{
	int r = 1;
	u32 flags = vcpu->arch.apf.host_apf_flags;

#ifndef CONFIG_X86_64
	/* A 64-bit CR2 should be impossible on 32-bit KVM. */
	if (WARN_ON_ONCE(fault_address >> 32))
		return -EFAULT;
#endif

	vcpu->arch.l1tf_flush_l1d = true;
	if (!flags) {
		trace_kvm_page_fault(fault_address, error_code);

		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, fault_address);
		r = kvm_mmu_page_fault(vcpu, fault_address, error_code, insn,
				insn_len);
	} else if (flags & KVM_PV_REASON_PAGE_NOT_PRESENT) {
		vcpu->arch.apf.host_apf_flags = 0;
		local_irq_disable();
		kvm_async_pf_task_wait_schedule(fault_address);
		local_irq_enable();
	} else {
		WARN_ONCE(1, "Unexpected host async PF flags: %x\n", flags);
	}

	return r;
}
EXPORT_SYMBOL_GPL(kvm_handle_page_fault);

int kvm_tdp_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	while (fault->max_level > PG_LEVEL_4K) {
		int page_num = KVM_PAGES_PER_HPAGE(fault->max_level);
		gfn_t base = (fault->addr >> PAGE_SHIFT) & ~(page_num - 1);

		if (kvm_mtrr_check_gfn_range_consistency(vcpu, base, page_num))
			break;

		--fault->max_level;
	}

	return direct_page_fault(vcpu, fault);
}

static void nonpaging_init_context(struct kvm_mmu *context)
{
	context->page_fault = nonpaging_page_fault;
	context->gva_to_gpa = nonpaging_gva_to_gpa;
	context->sync_page = nonpaging_sync_page;
	context->invlpg = NULL;
	context->direct_map = true;
}

static inline bool is_root_usable(struct kvm_mmu_root_info *root, gpa_t pgd,
				  union kvm_mmu_page_role role)
{
	return (role.direct || pgd == root->pgd) &&
	       VALID_PAGE(root->hpa) && to_shadow_page(root->hpa) &&
	       role.word == to_shadow_page(root->hpa)->role.word;
}

/*
 * Find out if a previously cached root matching the new pgd/role is available.
 * The current root is also inserted into the cache.
 * If a matching root was found, it is assigned to kvm_mmu->root_hpa and true is
 * returned.
 * Otherwise, the LRU root from the cache is assigned to kvm_mmu->root_hpa and
 * false is returned. This root should now be freed by the caller.
 */
static bool cached_root_available(struct kvm_vcpu *vcpu, gpa_t new_pgd,
				  union kvm_mmu_page_role new_role)
{
	uint i;
	struct kvm_mmu_root_info root;
	struct kvm_mmu *mmu = vcpu->arch.mmu;

	root.pgd = mmu->root_pgd;
	root.hpa = mmu->root_hpa;

	if (is_root_usable(&root, new_pgd, new_role))
		return true;

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		swap(root, mmu->prev_roots[i]);

		if (is_root_usable(&root, new_pgd, new_role))
			break;
	}

	mmu->root_hpa = root.hpa;
	mmu->root_pgd = root.pgd;

	return i < KVM_MMU_NUM_PREV_ROOTS;
}

static bool fast_pgd_switch(struct kvm_vcpu *vcpu, gpa_t new_pgd,
			    union kvm_mmu_page_role new_role)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;

	/*
	 * For now, limit the fast switch to 64-bit hosts+VMs in order to avoid
	 * having to deal with PDPTEs. We may add support for 32-bit hosts/VMs
	 * later if necessary.
	 */
	if (mmu->shadow_root_level >= PT64_ROOT_4LEVEL &&
	    mmu->root_level >= PT64_ROOT_4LEVEL)
		return cached_root_available(vcpu, new_pgd, new_role);

	return false;
}

static void __kvm_mmu_new_pgd(struct kvm_vcpu *vcpu, gpa_t new_pgd,
			      union kvm_mmu_page_role new_role)
{
	if (!fast_pgd_switch(vcpu, new_pgd, new_role)) {
		kvm_mmu_free_roots(vcpu, vcpu->arch.mmu, KVM_MMU_ROOT_CURRENT);
		return;
	}

	/*
	 * It's possible that the cached previous root page is obsolete because
	 * of a change in the MMU generation number. However, changing the
	 * generation number is accompanied by KVM_REQ_MMU_RELOAD, which will
	 * free the root set here and allocate a new one.
	 */
	kvm_make_request(KVM_REQ_LOAD_MMU_PGD, vcpu);

	if (force_flush_and_sync_on_reuse) {
		kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);
		kvm_make_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu);
	}

	/*
	 * The last MMIO access's GVA and GPA are cached in the VCPU. When
	 * switching to a new CR3, that GVA->GPA mapping may no longer be
	 * valid. So clear any cached MMIO info even when we don't need to sync
	 * the shadow page tables.
	 */
	vcpu_clear_mmio_info(vcpu, MMIO_GVA_ANY);

	/*
	 * If this is a direct root page, it doesn't have a write flooding
	 * count. Otherwise, clear the write flooding count.
	 */
	if (!new_role.direct)
		__clear_sp_write_flooding_count(
				to_shadow_page(vcpu->arch.mmu->root_hpa));
}

void kvm_mmu_new_pgd(struct kvm_vcpu *vcpu, gpa_t new_pgd)
{
	__kvm_mmu_new_pgd(vcpu, new_pgd, kvm_mmu_calc_root_page_role(vcpu));
}
EXPORT_SYMBOL_GPL(kvm_mmu_new_pgd);

static unsigned long get_cr3(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr3(vcpu);
}

static bool sync_mmio_spte(struct kvm_vcpu *vcpu, u64 *sptep, gfn_t gfn,
			   unsigned int access)
{
	if (unlikely(is_mmio_spte(*sptep))) {
		if (gfn != get_mmio_spte_gfn(*sptep)) {
			mmu_spte_clear_no_track(sptep);
			return true;
		}

		mark_mmio_spte(vcpu, sptep, gfn, access);
		return true;
	}

	return false;
}

#include <asm/tlbflush.h>
// #include <asm/tlb.h>

#define PTTYPE_EPT 18 /* arbitrary */
#define PTTYPE PTTYPE_EPT
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 64
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 32
#include "paging_tmpl.h"
#undef PTTYPE

static void
__reset_rsvds_bits_mask(struct rsvd_bits_validate *rsvd_check,
			u64 pa_bits_rsvd, int level, bool nx, bool gbpages,
			bool pse, bool amd)
{
	u64 gbpages_bit_rsvd = 0;
	u64 nonleaf_bit8_rsvd = 0;
	u64 high_bits_rsvd;

	rsvd_check->bad_mt_xwr = 0;

	if (!gbpages)
		gbpages_bit_rsvd = rsvd_bits(7, 7);

	if (level == PT32E_ROOT_LEVEL)
		high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 62);
	else
		high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 51);

	/* Note, NX doesn't exist in PDPTEs, this is handled below. */
	if (!nx)
		high_bits_rsvd |= rsvd_bits(63, 63);

	/*
	 * Non-leaf PML4Es and PDPEs reserve bit 8 (which would be the G bit for
	 * leaf entries) on AMD CPUs only.
	 */
	if (amd)
		nonleaf_bit8_rsvd = rsvd_bits(8, 8);

	switch (level) {
	case PT32_ROOT_LEVEL:
		/* no rsvd bits for 2 level 4K page table entries */
		rsvd_check->rsvd_bits_mask[0][1] = 0;
		rsvd_check->rsvd_bits_mask[0][0] = 0;
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];

		if (!pse) {
			rsvd_check->rsvd_bits_mask[1][1] = 0;
			break;
		}

		if (is_cpuid_PSE36())
			/* 36bits PSE 4MB page */
			rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(17, 21);
		else
			/* 32 bits PSE 4MB page */
			rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(13, 21);
		break;
	case PT32E_ROOT_LEVEL:
		rsvd_check->rsvd_bits_mask[0][2] = rsvd_bits(63, 63) |
						   high_bits_rsvd |
						   rsvd_bits(5, 8) |
						   rsvd_bits(1, 2);	/* PDPTE */
		rsvd_check->rsvd_bits_mask[0][1] = high_bits_rsvd;	/* PDE */
		rsvd_check->rsvd_bits_mask[0][0] = high_bits_rsvd;	/* PTE */
		rsvd_check->rsvd_bits_mask[1][1] = high_bits_rsvd |
						   rsvd_bits(13, 20);	/* large page */
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];
		break;
	case PT64_ROOT_5LEVEL:
		rsvd_check->rsvd_bits_mask[0][4] = high_bits_rsvd |
						   nonleaf_bit8_rsvd |
						   rsvd_bits(7, 7);
		rsvd_check->rsvd_bits_mask[1][4] =
			rsvd_check->rsvd_bits_mask[0][4];
		fallthrough;
	case PT64_ROOT_4LEVEL:
		rsvd_check->rsvd_bits_mask[0][3] = high_bits_rsvd |
						   nonleaf_bit8_rsvd |
						   rsvd_bits(7, 7);
		rsvd_check->rsvd_bits_mask[0][2] = high_bits_rsvd |
						   gbpages_bit_rsvd;
		rsvd_check->rsvd_bits_mask[0][1] = high_bits_rsvd;
		rsvd_check->rsvd_bits_mask[0][0] = high_bits_rsvd;
		rsvd_check->rsvd_bits_mask[1][3] =
			rsvd_check->rsvd_bits_mask[0][3];
		rsvd_check->rsvd_bits_mask[1][2] = high_bits_rsvd |
						   gbpages_bit_rsvd |
						   rsvd_bits(13, 29);
		rsvd_check->rsvd_bits_mask[1][1] = high_bits_rsvd |
						   rsvd_bits(13, 20); /* large page */
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];
		break;
	}
}

static bool guest_can_use_gbpages(struct kvm_vcpu *vcpu)
{
	/*
	 * If TDP is enabled, let the guest use GBPAGES if they're supported in
	 * hardware.  The hardware page walker doesn't let KVM disable GBPAGES,
	 * i.e. won't treat them as reserved, and KVM doesn't redo the GVA->GPA
	 * walk for performance and complexity reasons.  Not to mention KVM
	 * _can't_ solve the problem because GVA->GPA walks aren't visible to
	 * KVM once a TDP translation is installed.  Mimic hardware behavior so
	 * that KVM's is at least consistent, i.e. doesn't randomly inject #PF.
	 */
	return tdp_enabled ? boot_cpu_has(X86_FEATURE_GBPAGES) :
			     guest_cpuid_has(vcpu, X86_FEATURE_GBPAGES);
}

static void reset_rsvds_bits_mask(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	__reset_rsvds_bits_mask(&context->guest_rsvd_check,
				vcpu->arch.reserved_gpa_bits,
				context->root_level, is_efer_nx(context),
				guest_can_use_gbpages(vcpu),
				is_cr4_pse(context),
				guest_cpuid_is_amd_or_hygon(vcpu));
}

static void
__reset_rsvds_bits_mask_ept(struct rsvd_bits_validate *rsvd_check,
			    u64 pa_bits_rsvd, bool execonly)
{
	u64 high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 51);
	u64 bad_mt_xwr;

	rsvd_check->rsvd_bits_mask[0][4] = high_bits_rsvd | rsvd_bits(3, 7);
	rsvd_check->rsvd_bits_mask[0][3] = high_bits_rsvd | rsvd_bits(3, 7);
	rsvd_check->rsvd_bits_mask[0][2] = high_bits_rsvd | rsvd_bits(3, 6);
	rsvd_check->rsvd_bits_mask[0][1] = high_bits_rsvd | rsvd_bits(3, 6);
	rsvd_check->rsvd_bits_mask[0][0] = high_bits_rsvd;

	/* large page */
	rsvd_check->rsvd_bits_mask[1][4] = rsvd_check->rsvd_bits_mask[0][4];
	rsvd_check->rsvd_bits_mask[1][3] = rsvd_check->rsvd_bits_mask[0][3];
	rsvd_check->rsvd_bits_mask[1][2] = high_bits_rsvd | rsvd_bits(12, 29);
	rsvd_check->rsvd_bits_mask[1][1] = high_bits_rsvd | rsvd_bits(12, 20);
	rsvd_check->rsvd_bits_mask[1][0] = rsvd_check->rsvd_bits_mask[0][0];

	bad_mt_xwr = 0xFFull << (2 * 8);	/* bits 3..5 must not be 2 */
	bad_mt_xwr |= 0xFFull << (3 * 8);	/* bits 3..5 must not be 3 */
	bad_mt_xwr |= 0xFFull << (7 * 8);	/* bits 3..5 must not be 7 */
	bad_mt_xwr |= REPEAT_BYTE(1ull << 2);	/* bits 0..2 must not be 010 */
	bad_mt_xwr |= REPEAT_BYTE(1ull << 6);	/* bits 0..2 must not be 110 */
	if (!execonly) {
		/* bits 0..2 must not be 100 unless VMX capabilities allow it */
		bad_mt_xwr |= REPEAT_BYTE(1ull << 4);
	}
	rsvd_check->bad_mt_xwr = bad_mt_xwr;
}

static void reset_rsvds_bits_mask_ept(struct kvm_vcpu *vcpu,
		struct kvm_mmu *context, bool execonly)
{
	__reset_rsvds_bits_mask_ept(&context->guest_rsvd_check,
				    vcpu->arch.reserved_gpa_bits, execonly);
}

static inline u64 reserved_hpa_bits(void)
{
	return rsvd_bits(shadow_phys_bits, 63);
}

/*
 * the page table on host is the shadow page table for the page
 * table in guest or amd nested guest, its mmu features completely
 * follow the features in guest.
 */
static void reset_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context)
{
	/*
	 * KVM uses NX when TDP is disabled to handle a variety of scenarios,
	 * notably for huge SPTEs if iTLB multi-hit mitigation is enabled and
	 * to generate correct permissions for CR0.WP=0/CR4.SMEP=1/EFER.NX=0.
	 * The iTLB multi-hit workaround can be toggled at any time, so assume
	 * NX can be used by any non-nested shadow MMU to avoid having to reset
	 * MMU contexts.  Note, KVM forces EFER.NX=1 when TDP is disabled.
	 */
	bool uses_nx = is_efer_nx(context) || !tdp_enabled;

	/* @amd adds a check on bit of SPTEs, which KVM shouldn't use anyways. */
	bool is_amd = true;
	/* KVM doesn't use 2-level page tables for the shadow MMU. */
	bool is_pse = false;
	struct rsvd_bits_validate *shadow_zero_check;
	int i;

	WARN_ON_ONCE(context->shadow_root_level < PT32E_ROOT_LEVEL);

	shadow_zero_check = &context->shadow_zero_check;
	__reset_rsvds_bits_mask(shadow_zero_check, reserved_hpa_bits(),
				context->shadow_root_level, uses_nx,
				guest_can_use_gbpages(vcpu), is_pse, is_amd);

	if (!shadow_me_mask)
		return;

	for (i = context->shadow_root_level; --i >= 0;) {
		shadow_zero_check->rsvd_bits_mask[0][i] &= ~shadow_me_mask;
		shadow_zero_check->rsvd_bits_mask[1][i] &= ~shadow_me_mask;
	}

}

static inline bool boot_cpu_is_amd(void)
{
	WARN_ON_ONCE(!tdp_enabled);
	return shadow_x_mask == 0;
}

/*
 * the direct page table on host, use as much mmu features as
 * possible, however, kvm currently does not do execution-protection.
 */
static void
reset_tdp_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
				struct kvm_mmu *context)
{
	struct rsvd_bits_validate *shadow_zero_check;
	int i;

	shadow_zero_check = &context->shadow_zero_check;

	if (boot_cpu_is_amd())
		__reset_rsvds_bits_mask(shadow_zero_check, reserved_hpa_bits(),
					context->shadow_root_level, false,
					boot_cpu_has(X86_FEATURE_GBPAGES),
					false, true);
	else
		__reset_rsvds_bits_mask_ept(shadow_zero_check,
					    reserved_hpa_bits(), false);

	if (!shadow_me_mask)
		return;

	for (i = context->shadow_root_level; --i >= 0;) {
		shadow_zero_check->rsvd_bits_mask[0][i] &= ~shadow_me_mask;
		shadow_zero_check->rsvd_bits_mask[1][i] &= ~shadow_me_mask;
	}
}

/*
 * as the comments in reset_shadow_zero_bits_mask() except it
 * is the shadow page table for intel nested guest.
 */
static void
reset_ept_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
				struct kvm_mmu *context, bool execonly)
{
	__reset_rsvds_bits_mask_ept(&context->shadow_zero_check,
				    reserved_hpa_bits(), execonly);
}

#define BYTE_MASK(access) \
	((1 & (access) ? 2 : 0) | \
	 (2 & (access) ? 4 : 0) | \
	 (3 & (access) ? 8 : 0) | \
	 (4 & (access) ? 16 : 0) | \
	 (5 & (access) ? 32 : 0) | \
	 (6 & (access) ? 64 : 0) | \
	 (7 & (access) ? 128 : 0))


static void update_permission_bitmask(struct kvm_mmu *mmu, bool ept)
{
	unsigned byte;

	const u8 x = BYTE_MASK(ACC_EXEC_MASK);
	const u8 w = BYTE_MASK(ACC_WRITE_MASK);
	const u8 u = BYTE_MASK(ACC_USER_MASK);

	bool cr4_smep = is_cr4_smep(mmu);
	bool cr4_smap = is_cr4_smap(mmu);
	bool cr0_wp = is_cr0_wp(mmu);
	bool efer_nx = is_efer_nx(mmu);

	for (byte = 0; byte < ARRAY_SIZE(mmu->permissions); ++byte) {
		unsigned pfec = byte << 1;

		/*
		 * Each "*f" variable has a 1 bit for each UWX value
		 * that causes a fault with the given PFEC.
		 */

		/* Faults from writes to non-writable pages */
		u8 wf = (pfec & PFERR_WRITE_MASK) ? (u8)~w : 0;
		/* Faults from user mode accesses to supervisor pages */
		u8 uf = (pfec & PFERR_USER_MASK) ? (u8)~u : 0;
		/* Faults from fetches of non-executable pages*/
		u8 ff = (pfec & PFERR_FETCH_MASK) ? (u8)~x : 0;
		/* Faults from kernel mode fetches of user pages */
		u8 smepf = 0;
		/* Faults from kernel mode accesses of user pages */
		u8 smapf = 0;

		if (!ept) {
			/* Faults from kernel mode accesses to user pages */
			u8 kf = (pfec & PFERR_USER_MASK) ? 0 : u;

			/* Not really needed: !nx will cause pte.nx to fault */
			if (!efer_nx)
				ff = 0;

			/* Allow supervisor writes if !cr0.wp */
			if (!cr0_wp)
				wf = (pfec & PFERR_USER_MASK) ? wf : 0;

			/* Disallow supervisor fetches of user code if cr4.smep */
			if (cr4_smep)
				smepf = (pfec & PFERR_FETCH_MASK) ? kf : 0;

			/*
			 * SMAP:kernel-mode data accesses from user-mode
			 * mappings should fault. A fault is considered
			 * as a SMAP violation if all of the following
			 * conditions are true:
			 *   - X86_CR4_SMAP is set in CR4
			 *   - A user page is accessed
			 *   - The access is not a fetch
			 *   - Page fault in kernel mode
			 *   - if CPL = 3 or X86_EFLAGS_AC is clear
			 *
			 * Here, we cover the first three conditions.
			 * The fourth is computed dynamically in permission_fault();
			 * PFERR_RSVD_MASK bit will be set in PFEC if the access is
			 * *not* subject to SMAP restrictions.
			 */
			if (cr4_smap)
				smapf = (pfec & (PFERR_RSVD_MASK|PFERR_FETCH_MASK)) ? 0 : kf;
		}

		mmu->permissions[byte] = ff | uf | wf | smepf | smapf;
	}
}

/*
* PKU is an additional mechanism by which the paging controls access to
* user-mode addresses based on the value in the PKRU register.  Protection
* key violations are reported through a bit in the page fault error code.
* Unlike other bits of the error code, the PK bit is not known at the
* call site of e.g. gva_to_gpa; it must be computed directly in
* permission_fault based on two bits of PKRU, on some machine state (CR4,
* CR0, EFER, CPL), and on other bits of the error code and the page tables.
*
* In particular the following conditions come from the error code, the
* page tables and the machine state:
* - PK is always zero unless CR4.PKE=1 and EFER.LMA=1
* - PK is always zero if RSVD=1 (reserved bit set) or F=1 (instruction fetch)
* - PK is always zero if U=0 in the page tables
* - PKRU.WD is ignored if CR0.WP=0 and the access is a supervisor access.
*
* The PKRU bitmask caches the result of these four conditions.  The error
* code (minus the P bit) and the page table's U bit form an index into the
* PKRU bitmask.  Two bits of the PKRU bitmask are then extracted and ANDed
* with the two bits of the PKRU register corresponding to the protection key.
* For the first three conditions above the bits will be 00, thus masking
* away both AD and WD.  For all reads or if the last condition holds, WD
* only will be masked away.
*/
static void update_pkru_bitmask(struct kvm_mmu *mmu)
{
	unsigned bit;
	bool wp;

	mmu->pkru_mask = 0;

	if (!is_cr4_pke(mmu))
		return;

	wp = is_cr0_wp(mmu);

	for (bit = 0; bit < ARRAY_SIZE(mmu->permissions); ++bit) {
		unsigned pfec, pkey_bits;
		bool check_pkey, check_write, ff, uf, wf, pte_user;

		pfec = bit << 1;
		ff = pfec & PFERR_FETCH_MASK;
		uf = pfec & PFERR_USER_MASK;
		wf = pfec & PFERR_WRITE_MASK;

		/* PFEC.RSVD is replaced by ACC_USER_MASK. */
		pte_user = pfec & PFERR_RSVD_MASK;

		/*
		 * Only need to check the access which is not an
		 * instruction fetch and is to a user page.
		 */
		check_pkey = (!ff && pte_user);
		/*
		 * write access is controlled by PKRU if it is a
		 * user access or CR0.WP = 1.
		 */
		check_write = check_pkey && wf && (uf || wp);

		/* PKRU.AD stops both read and write access. */
		pkey_bits = !!check_pkey;
		/* PKRU.WD stops write access. */
		pkey_bits |= (!!check_write) << 1;

		mmu->pkru_mask |= (pkey_bits & 3) << pfec;
	}
}

static void reset_guest_paging_metadata(struct kvm_vcpu *vcpu,
					struct kvm_mmu *mmu)
{
	if (!is_cr0_pg(mmu))
		return;

	reset_rsvds_bits_mask(vcpu, mmu);
	update_permission_bitmask(mmu, false);
	update_pkru_bitmask(mmu);
}

static void paging64_init_context(struct kvm_mmu *context)
{
	context->page_fault = paging64_page_fault;
	context->gva_to_gpa = paging64_gva_to_gpa;
	context->sync_page = paging64_sync_page;
	context->invlpg = paging64_invlpg;
	context->direct_map = false;
}

static void paging32_init_context(struct kvm_mmu *context)
{
	context->page_fault = paging32_page_fault;
	context->gva_to_gpa = paging32_gva_to_gpa;
	context->sync_page = paging32_sync_page;
	context->invlpg = paging32_invlpg;
	context->direct_map = false;
}

static union kvm_mmu_extended_role kvm_calc_mmu_role_ext(struct kvm_vcpu *vcpu,
							 struct kvm_mmu_role_regs *regs)
{
	union kvm_mmu_extended_role ext = {0};

	if (____is_cr0_pg(regs)) {
		ext.cr0_pg = 1;
		ext.cr4_pae = ____is_cr4_pae(regs);
		ext.cr4_smep = ____is_cr4_smep(regs);
		ext.cr4_smap = ____is_cr4_smap(regs);
		ext.cr4_pse = ____is_cr4_pse(regs);

		/* PKEY and LA57 are active iff long mode is active. */
		ext.cr4_pke = ____is_efer_lma(regs) && ____is_cr4_pke(regs);
		ext.cr4_la57 = ____is_efer_lma(regs) && ____is_cr4_la57(regs);
		ext.efer_lma = ____is_efer_lma(regs);
	}

	ext.valid = 1;

	return ext;
}

static union kvm_mmu_role kvm_calc_mmu_role_common(struct kvm_vcpu *vcpu,
						   struct kvm_mmu_role_regs *regs,
						   bool base_only)
{
	union kvm_mmu_role role = {0};

	role.base.access = ACC_ALL;
	if (____is_cr0_pg(regs)) {
		role.base.efer_nx = ____is_efer_nx(regs);
		role.base.cr0_wp = ____is_cr0_wp(regs);
	}
	role.base.smm = is_smm(vcpu);
	role.base.guest_mode = is_guest_mode(vcpu);

	if (base_only)
		return role;

	role.ext = kvm_calc_mmu_role_ext(vcpu, regs);

	return role;
}

static inline int kvm_mmu_get_tdp_level(struct kvm_vcpu *vcpu)
{
	/* tdp_root_level is architecture forced level, use it if nonzero */
	if (tdp_root_level)
		return tdp_root_level;

	/* Use 5-level TDP if and only if it's useful/necessary. */
	if (max_tdp_level == 5 && cpuid_maxphyaddr(vcpu) <= 48)
		return 4;

	return max_tdp_level;
}

static union kvm_mmu_role
kvm_calc_tdp_mmu_root_page_role(struct kvm_vcpu *vcpu,
				struct kvm_mmu_role_regs *regs, bool base_only)
{
	union kvm_mmu_role role = kvm_calc_mmu_role_common(vcpu, regs, base_only);

	role.base.ad_disabled = (shadow_accessed_mask == 0);
	role.base.level = kvm_mmu_get_tdp_level(vcpu);
	role.base.direct = true;
	role.base.gpte_is_8_bytes = true;

	return role;
}

static void init_kvm_tdp_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.root_mmu;
	struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);
	union kvm_mmu_role new_role =
		kvm_calc_tdp_mmu_root_page_role(vcpu, &regs, false);

	if (new_role.as_u64 == context->mmu_role.as_u64)
		return;

	context->mmu_role.as_u64 = new_role.as_u64;
	context->page_fault = kvm_tdp_page_fault;
	context->sync_page = nonpaging_sync_page;
	context->invlpg = NULL;
	context->shadow_root_level = kvm_mmu_get_tdp_level(vcpu);
	context->direct_map = true;
	context->get_guest_pgd = get_cr3;
	context->get_pdptr = kvm_pdptr_read;
	context->inject_page_fault = kvm_inject_page_fault;
	context->root_level = role_regs_to_root_level(&regs);

	if (!is_cr0_pg(context))
		context->gva_to_gpa = nonpaging_gva_to_gpa;
	else if (is_cr4_pae(context))
		context->gva_to_gpa = paging64_gva_to_gpa;
	else
		context->gva_to_gpa = paging32_gva_to_gpa;

	reset_guest_paging_metadata(vcpu, context);
	reset_tdp_shadow_zero_bits_mask(vcpu, context);
}

static union kvm_mmu_role
kvm_calc_shadow_root_page_role_common(struct kvm_vcpu *vcpu,
				      struct kvm_mmu_role_regs *regs, bool base_only)
{
	union kvm_mmu_role role = kvm_calc_mmu_role_common(vcpu, regs, base_only);

	role.base.smep_andnot_wp = role.ext.cr4_smep && !____is_cr0_wp(regs);
	role.base.smap_andnot_wp = role.ext.cr4_smap && !____is_cr0_wp(regs);
	role.base.gpte_is_8_bytes = ____is_cr0_pg(regs) && ____is_cr4_pae(regs);

	return role;
}

static union kvm_mmu_role
kvm_calc_shadow_mmu_root_page_role(struct kvm_vcpu *vcpu,
				   struct kvm_mmu_role_regs *regs, bool base_only)
{
	union kvm_mmu_role role =
		kvm_calc_shadow_root_page_role_common(vcpu, regs, base_only);

	role.base.direct = !____is_cr0_pg(regs);

	if (!____is_efer_lma(regs))
		role.base.level = PT32E_ROOT_LEVEL;
	else if (____is_cr4_la57(regs))
		role.base.level = PT64_ROOT_5LEVEL;
	else
		role.base.level = PT64_ROOT_4LEVEL;

	return role;
}

static void shadow_mmu_init_context(struct kvm_vcpu *vcpu, struct kvm_mmu *context,
				    struct kvm_mmu_role_regs *regs,
				    union kvm_mmu_role new_role)
{
	if (new_role.as_u64 == context->mmu_role.as_u64)
		return;

	context->mmu_role.as_u64 = new_role.as_u64;

	if (!is_cr0_pg(context))
		nonpaging_init_context(context);
	else if (is_cr4_pae(context))
		paging64_init_context(context);
	else
		paging32_init_context(context);
	context->root_level = role_regs_to_root_level(regs);

	reset_guest_paging_metadata(vcpu, context);
	context->shadow_root_level = new_role.base.level;

	reset_shadow_zero_bits_mask(vcpu, context);
}

static void kvm_init_shadow_mmu(struct kvm_vcpu *vcpu,
				struct kvm_mmu_role_regs *regs)
{
	struct kvm_mmu *context = &vcpu->arch.root_mmu;
	union kvm_mmu_role new_role =
		kvm_calc_shadow_mmu_root_page_role(vcpu, regs, false);

	shadow_mmu_init_context(vcpu, context, regs, new_role);
}

static union kvm_mmu_role
kvm_calc_shadow_npt_root_page_role(struct kvm_vcpu *vcpu,
				   struct kvm_mmu_role_regs *regs)
{
	union kvm_mmu_role role =
		kvm_calc_shadow_root_page_role_common(vcpu, regs, false);

	role.base.direct = false;
	role.base.level = kvm_mmu_get_tdp_level(vcpu);

	return role;
}

void kvm_init_shadow_npt_mmu(struct kvm_vcpu *vcpu, unsigned long cr0,
			     unsigned long cr4, u64 efer, gpa_t nested_cr3)
{
	struct kvm_mmu *context = &vcpu->arch.guest_mmu;
	struct kvm_mmu_role_regs regs = {
		.cr0 = cr0,
		.cr4 = cr4 & ~X86_CR4_PKE,
		.efer = efer,
	};
	union kvm_mmu_role new_role;

	new_role = kvm_calc_shadow_npt_root_page_role(vcpu, &regs);

	__kvm_mmu_new_pgd(vcpu, nested_cr3, new_role.base);

	shadow_mmu_init_context(vcpu, context, &regs, new_role);
}
EXPORT_SYMBOL_GPL(kvm_init_shadow_npt_mmu);

static union kvm_mmu_role
kvm_calc_shadow_ept_root_page_role(struct kvm_vcpu *vcpu, bool accessed_dirty,
				   bool execonly, u8 level)
{
	union kvm_mmu_role role = {0};

	/* SMM flag is inherited from root_mmu */
	role.base.smm = vcpu->arch.root_mmu.mmu_role.base.smm;

	role.base.level = level;
	role.base.gpte_is_8_bytes = true;
	role.base.direct = false;
	role.base.ad_disabled = !accessed_dirty;
	role.base.guest_mode = true;
	role.base.access = ACC_ALL;

	/* EPT, and thus nested EPT, does not consume CR0, CR4, nor EFER. */
	role.ext.word = 0;
	role.ext.execonly = execonly;
	role.ext.valid = 1;

	return role;
}

void kvm_init_shadow_ept_mmu(struct kvm_vcpu *vcpu, bool execonly,
			     bool accessed_dirty, gpa_t new_eptp)
{
	struct kvm_mmu *context = &vcpu->arch.guest_mmu;
	u8 level = vmx_eptp_page_walk_level(new_eptp);
	union kvm_mmu_role new_role =
		kvm_calc_shadow_ept_root_page_role(vcpu, accessed_dirty,
						   execonly, level);

	__kvm_mmu_new_pgd(vcpu, new_eptp, new_role.base);

	if (new_role.as_u64 == context->mmu_role.as_u64)
		return;

	context->mmu_role.as_u64 = new_role.as_u64;

	context->shadow_root_level = level;

	context->ept_ad = accessed_dirty;
	context->page_fault = ept_page_fault;
	context->gva_to_gpa = ept_gva_to_gpa;
	context->sync_page = ept_sync_page;
	context->invlpg = ept_invlpg;
	context->root_level = level;
	context->direct_map = false;

	update_permission_bitmask(context, true);
	context->pkru_mask = 0;
	reset_rsvds_bits_mask_ept(vcpu, context, execonly);
	reset_ept_shadow_zero_bits_mask(vcpu, context, execonly);
}
EXPORT_SYMBOL_GPL(kvm_init_shadow_ept_mmu);

static void init_kvm_softmmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.root_mmu;
	struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);

	kvm_init_shadow_mmu(vcpu, &regs);

	context->get_guest_pgd     = get_cr3;
	context->get_pdptr         = kvm_pdptr_read;
	context->inject_page_fault = kvm_inject_page_fault;
}

static union kvm_mmu_role
kvm_calc_nested_mmu_role(struct kvm_vcpu *vcpu, struct kvm_mmu_role_regs *regs)
{
	union kvm_mmu_role role;

	role = kvm_calc_shadow_root_page_role_common(vcpu, regs, false);

	/*
	 * Nested MMUs are used only for walking L2's gva->gpa, they never have
	 * shadow pages of their own and so "direct" has no meaning.   Set it
	 * to "true" to try to detect bogus usage of the nested MMU.
	 */
	role.base.direct = true;
	role.base.level = role_regs_to_root_level(regs);
	return role;
}

static void init_kvm_nested_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);
	union kvm_mmu_role new_role = kvm_calc_nested_mmu_role(vcpu, &regs);
	struct kvm_mmu *g_context = &vcpu->arch.nested_mmu;

	if (new_role.as_u64 == g_context->mmu_role.as_u64)
		return;

	g_context->mmu_role.as_u64 = new_role.as_u64;
	g_context->get_guest_pgd     = get_cr3;
	g_context->get_pdptr         = kvm_pdptr_read;
	g_context->inject_page_fault = kvm_inject_page_fault;
	g_context->root_level        = new_role.base.level;

	/*
	 * L2 page tables are never shadowed, so there is no need to sync
	 * SPTEs.
	 */
	g_context->invlpg            = NULL;

	/*
	 * Note that arch.mmu->gva_to_gpa translates l2_gpa to l1_gpa using
	 * L1's nested page tables (e.g. EPT12). The nested translation
	 * of l2_gva to l1_gpa is done by arch.nested_mmu.gva_to_gpa using
	 * L2's page tables as the first level of translation and L1's
	 * nested page tables as the second level of translation. Basically
	 * the gva_to_gpa functions between mmu and nested_mmu are swapped.
	 */
	if (!is_paging(vcpu))
		g_context->gva_to_gpa = nonpaging_gva_to_gpa_nested;
	else if (is_long_mode(vcpu))
		g_context->gva_to_gpa = paging64_gva_to_gpa_nested;
	else if (is_pae(vcpu))
		g_context->gva_to_gpa = paging64_gva_to_gpa_nested;
	else
		g_context->gva_to_gpa = paging32_gva_to_gpa_nested;

	reset_guest_paging_metadata(vcpu, g_context);
}

void kvm_init_mmu(struct kvm_vcpu *vcpu)
{
	if (mmu_is_nested(vcpu))
		init_kvm_nested_mmu(vcpu);
	else if (tdp_enabled)
		init_kvm_tdp_mmu(vcpu);
	else
		init_kvm_softmmu(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_init_mmu);

static union kvm_mmu_page_role
kvm_mmu_calc_root_page_role(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);
	union kvm_mmu_role role;

	if (tdp_enabled)
		role = kvm_calc_tdp_mmu_root_page_role(vcpu, &regs, true);
	else
		role = kvm_calc_shadow_mmu_root_page_role(vcpu, &regs, true);

	return role.base;
}

void kvm_mmu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	/*
	 * Invalidate all MMU roles to force them to reinitialize as CPUID
	 * information is factored into reserved bit calculations.
	 *
	 * Correctly handling multiple vCPU models with respect to paging and
	 * physical address properties) in a single VM would require tracking
	 * all relevant CPUID information in kvm_mmu_page_role. That is very
	 * undesirable as it would increase the memory requirements for
	 * gfn_track (see struct kvm_mmu_page_role comments).  For now that
	 * problem is swept under the rug; KVM's CPUID API is horrific and
	 * it's all but impossible to solve it without introducing a new API.
	 */
	vcpu->arch.root_mmu.mmu_role.ext.valid = 0;
	vcpu->arch.guest_mmu.mmu_role.ext.valid = 0;
	vcpu->arch.nested_mmu.mmu_role.ext.valid = 0;
	kvm_mmu_reset_context(vcpu);

	/*
	 * Changing guest CPUID after KVM_RUN is forbidden, see the comment in
	 * kvm_arch_vcpu_ioctl().
	 */
	KVM_BUG_ON(vcpu->arch.last_vmentry_cpu != -1, vcpu->kvm);
}

void kvm_mmu_reset_context(struct kvm_vcpu *vcpu)
{
	kvm_mmu_unload(vcpu);
	kvm_init_mmu(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_mmu_reset_context);

int kvm_mmu_load(struct kvm_vcpu *vcpu)
{
	int r;

	r = mmu_topup_memory_caches(vcpu, !vcpu->arch.mmu->direct_map);
	if (r)
		goto out;
	r = mmu_alloc_special_roots(vcpu);
	if (r)
		goto out;
	if (vcpu->arch.mmu->direct_map)
		r = mmu_alloc_direct_roots(vcpu);
	else
		r = mmu_alloc_shadow_roots(vcpu);
	if (r)
		goto out;

	kvm_mmu_sync_roots(vcpu);

	kvm_mmu_load_pgd(vcpu);
	static_call(kvm_x86_tlb_flush_current)(vcpu);
out:
	return r;
}

void kvm_mmu_unload(struct kvm_vcpu *vcpu)
{
	kvm_mmu_free_roots(vcpu, &vcpu->arch.root_mmu, KVM_MMU_ROOTS_ALL);
	WARN_ON(VALID_PAGE(vcpu->arch.root_mmu.root_hpa));
	kvm_mmu_free_roots(vcpu, &vcpu->arch.guest_mmu, KVM_MMU_ROOTS_ALL);
	WARN_ON(VALID_PAGE(vcpu->arch.guest_mmu.root_hpa));
}

static bool need_remote_flush(u64 old, u64 new)
{
	if (!is_shadow_present_pte(old))
		return false;
	if (!is_shadow_present_pte(new))
		return true;
	if ((old ^ new) & PT64_BASE_ADDR_MASK)
		return true;
	old ^= shadow_nx_mask;
	new ^= shadow_nx_mask;
	return (old & ~new & PT64_PERM_MASK) != 0;
}

static u64 mmu_pte_write_fetch_gpte(struct kvm_vcpu *vcpu, gpa_t *gpa,
				    int *bytes)
{
	u64 gentry = 0;
	int r;

	/*
	 * Assume that the pte write on a page table of the same type
	 * as the current vcpu paging mode since we update the sptes only
	 * when they have the same mode.
	 */
	if (is_pae(vcpu) && *bytes == 4) {
		/* Handle a 32-bit guest writing two halves of a 64-bit gpte */
		*gpa &= ~(gpa_t)7;
		*bytes = 8;
	}

	if (*bytes == 4 || *bytes == 8) {
		r = kvm_vcpu_read_guest_atomic(vcpu, *gpa, &gentry, *bytes);
		if (r)
			gentry = 0;
	}

	return gentry;
}

/*
 * If we're seeing too many writes to a page, it may no longer be a page table,
 * or we may be forking, in which case it is better to unmap the page.
 */
static bool detect_write_flooding(struct kvm_mmu_page *sp)
{
	/*
	 * Skip write-flooding detected for the sp whose level is 1, because
	 * it can become unsync, then the guest page is not write-protected.
	 */
	if (sp->role.level == PG_LEVEL_4K)
		return false;

	atomic_inc(&sp->write_flooding_count);
	return atomic_read(&sp->write_flooding_count) >= 3;
}

/*
 * Misaligned accesses are too much trouble to fix up; also, they usually
 * indicate a page is not used as a page table.
 */
static bool detect_write_misaligned(struct kvm_mmu_page *sp, gpa_t gpa,
				    int bytes)
{
	unsigned offset, pte_size, misaligned;

	pgprintk("misaligned: gpa %llx bytes %d role %x\n",
		 gpa, bytes, sp->role.word);

	offset = offset_in_page(gpa);
	pte_size = sp->role.gpte_is_8_bytes ? 8 : 4;

	/*
	 * Sometimes, the OS only writes the last one bytes to update status
	 * bits, for example, in linux, andb instruction is used in clear_bit().
	 */
	if (!(offset & (pte_size - 1)) && bytes == 1)
		return false;

	misaligned = (offset ^ (offset + bytes - 1)) & ~(pte_size - 1);
	misaligned |= bytes < 4;

	return misaligned;
}

static u64 *get_written_sptes(struct kvm_mmu_page *sp, gpa_t gpa, int *nspte)
{
	unsigned page_offset, quadrant;
	u64 *spte;
	int level;

	page_offset = offset_in_page(gpa);
	level = sp->role.level;
	*nspte = 1;
	if (!sp->role.gpte_is_8_bytes) {
		page_offset <<= 1;	/* 32->64 */
		/*
		 * A 32-bit pde maps 4MB while the shadow pdes map
		 * only 2MB.  So we need to double the offset again
		 * and zap two pdes instead of one.
		 */
		if (level == PT32_ROOT_LEVEL) {
			page_offset &= ~7; /* kill rounding error */
			page_offset <<= 1;
			*nspte = 2;
		}
		quadrant = page_offset >> PAGE_SHIFT;
		page_offset &= ~PAGE_MASK;
		if (quadrant != sp->role.quadrant)
			return NULL;
	}

	spte = &sp->spt[page_offset / sizeof(*spte)];
	return spte;
}

static void kvm_mmu_pte_write(struct kvm_vcpu *vcpu, gpa_t gpa,
			      const u8 *new, int bytes,
			      struct kvm_page_track_notifier_node *node)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	u64 entry, gentry, *spte;
	int npte;
	bool flush = false;

	/*
	 * If we don't have indirect shadow pages, it means no page is
	 * write-protected, so we can exit simply.
	 */
	if (!READ_ONCE(vcpu->kvm->arch.indirect_shadow_pages))
		return;

	pgprintk("%s: gpa %llx bytes %d\n", __func__, gpa, bytes);

	/*
	 * No need to care whether allocation memory is successful
	 * or not since pte prefetch is skipped if it does not have
	 * enough objects in the cache.
	 */
	mmu_topup_memory_caches(vcpu, true);

	write_lock(&vcpu->kvm->mmu_lock);

	gentry = mmu_pte_write_fetch_gpte(vcpu, &gpa, &bytes);

	++vcpu->kvm->stat.mmu_pte_write;
	kvm_mmu_audit(vcpu, AUDIT_PRE_PTE_WRITE);

	for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
		if (detect_write_misaligned(sp, gpa, bytes) ||
		      detect_write_flooding(sp)) {
			kvm_mmu_prepare_zap_page(vcpu->kvm, sp, &invalid_list);
			++vcpu->kvm->stat.mmu_flooded;
			continue;
		}

		spte = get_written_sptes(sp, gpa, &npte);
		if (!spte)
			continue;

		while (npte--) {
			entry = *spte;
			mmu_page_zap_pte(vcpu->kvm, sp, spte, NULL);
			if (gentry && sp->role.level != PG_LEVEL_4K)
				++vcpu->kvm->stat.mmu_pde_zapped;
			if (need_remote_flush(entry, *spte))
				flush = true;
			++spte;
		}
	}
	kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, flush);
	kvm_mmu_audit(vcpu, AUDIT_POST_PTE_WRITE);
	write_unlock(&vcpu->kvm->mmu_lock);
}

int kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa, u64 error_code,
		       void *insn, int insn_len)
{
	int r, emulation_type = EMULTYPE_PF;
	bool direct = vcpu->arch.mmu->direct_map;
	// printk("kvm_mmu_page_fault is guest mode: %d gpa: %llx rsvd bits: %llx\n", (bool)(vcpu->arch.hflags & HF_GUEST_MASK), cr2_or_gpa, error_code & PFERR_RSVD_MASK);
	if (WARN_ON(!VALID_PAGE(vcpu->arch.mmu->root_hpa)))
		return RET_PF_RETRY;
	// printk("entered kvm_mmu_page_fault\n");
	r = RET_PF_INVALID;
	if (unlikely(error_code & PFERR_RSVD_MASK)) {
		// printk("trying handle_mmio_page_fault\n");
		r = handle_mmio_page_fault(vcpu, cr2_or_gpa, direct);
		if (r == RET_PF_EMULATE) {
			// printk("handle_mmio_page_fault lead to emulate\n");
			goto emulate;
		}
	}

	if (r == RET_PF_INVALID) {
		// printk("trying kvm_mmu_do_page_fault\n");
		r = kvm_mmu_do_page_fault(vcpu, cr2_or_gpa,
					  lower_32_bits(error_code), false);
		// printk("kvm_mmu_do_page_fault returned %d\n", r);
		if (KVM_BUG_ON(r == RET_PF_INVALID, vcpu->kvm))
			return -EIO;
	}

	if (r < 0)
		return r;
	if (r != RET_PF_EMULATE)
		return 1;

	/*
	 * Before emulating the instruction, check if the error code
	 * was due to a RO violation while translating the guest page.
	 * This can occur when using nested virtualization with nested
	 * paging in both guests. If true, we simply unprotect the page
	 * and resume the guest.
	 */
	if (vcpu->arch.mmu->direct_map &&
	    (error_code & PFERR_NESTED_GUEST_PAGE) == PFERR_NESTED_GUEST_PAGE) {
		kvm_mmu_unprotect_page(vcpu->kvm, gpa_to_gfn(cr2_or_gpa));
		return 1;
	}

	/*
	 * vcpu->arch.mmu.page_fault returned RET_PF_EMULATE, but we can still
	 * optimistically try to just unprotect the page and let the processor
	 * re-execute the instruction that caused the page fault.  Do not allow
	 * retrying MMIO emulation, as it's not only pointless but could also
	 * cause us to enter an infinite loop because the processor will keep
	 * faulting on the non-existent MMIO address.  Retrying an instruction
	 * from a nested guest is also pointless and dangerous as we are only
	 * explicitly shadowing L1's page tables, i.e. unprotecting something
	 * for L1 isn't going to magically fix whatever issue cause L2 to fail.
	 */
	if (!mmio_info_in_cache(vcpu, cr2_or_gpa, direct) && !is_guest_mode(vcpu)) {
		// printk("enabling retry from emulation error code: %llx gpa: %llx\n", error_code, cr2_or_gpa);
		emulation_type |= EMULTYPE_ALLOW_RETRY_PF;
	}
emulate:
	return x86_emulate_instruction(vcpu, cr2_or_gpa, emulation_type, insn,
				       insn_len);
}
EXPORT_SYMBOL_GPL(kvm_mmu_page_fault);

void kvm_mmu_invalidate_gva(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			    gva_t gva, hpa_t root_hpa)
{
	int i;
	/* It's actually a GPA for vcpu->arch.guest_mmu.  */
	if (mmu != &vcpu->arch.guest_mmu) {
		/* INVLPG on a non-canonical address is a NOP according to the SDM.  */
		if (is_noncanonical_address(gva, vcpu))
			return;

		static_call(kvm_x86_tlb_flush_gva)(vcpu, gva);
	}

	if (!mmu->invlpg)
		return;

	if (root_hpa == INVALID_PAGE) {
		mmu->invlpg(vcpu, gva, mmu->root_hpa);

		/*
		 * INVLPG is required to invalidate any global mappings for the VA,
		 * irrespective of PCID. Since it would take us roughly similar amount
		 * of work to determine whether any of the prev_root mappings of the VA
		 * is marked global, or to just sync it blindly, so we might as well
		 * just always sync it.
		 *
		 * Mappings not reachable via the current cr3 or the prev_roots will be
		 * synced when switching to that cr3, so nothing needs to be done here
		 * for them.
		 */
		for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
			if (VALID_PAGE(mmu->prev_roots[i].hpa))
				mmu->invlpg(vcpu, gva, mmu->prev_roots[i].hpa);
	} else {
		mmu->invlpg(vcpu, gva, root_hpa);
	}
}

void kvm_mmu_invlpg(struct kvm_vcpu *vcpu, gva_t gva)
{
	kvm_mmu_invalidate_gva(vcpu, vcpu->arch.walk_mmu, gva, INVALID_PAGE);
	++vcpu->stat.invlpg;
}
EXPORT_SYMBOL_GPL(kvm_mmu_invlpg);


void kvm_mmu_invpcid_gva(struct kvm_vcpu *vcpu, gva_t gva, unsigned long pcid)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	bool tlb_flush = false;
	uint i;

	if (pcid == kvm_get_active_pcid(vcpu)) {
		mmu->invlpg(vcpu, gva, mmu->root_hpa);
		tlb_flush = true;
	}

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		if (VALID_PAGE(mmu->prev_roots[i].hpa) &&
		    pcid == kvm_get_pcid(vcpu, mmu->prev_roots[i].pgd)) {
			mmu->invlpg(vcpu, gva, mmu->prev_roots[i].hpa);
			tlb_flush = true;
		}
	}

	if (tlb_flush)
		static_call(kvm_x86_tlb_flush_gva)(vcpu, gva);

	++vcpu->stat.invlpg;

	/*
	 * Mappings not reachable via the current cr3 or the prev_roots will be
	 * synced when switching to that cr3, so nothing needs to be done here
	 * for them.
	 */
}

void kvm_configure_mmu(bool enable_tdp, int tdp_forced_root_level,
		       int tdp_max_root_level, int tdp_huge_page_level)
{
	tdp_enabled = enable_tdp;
	tdp_root_level = tdp_forced_root_level;
	max_tdp_level = tdp_max_root_level;

	/*
	 * max_huge_page_level reflects KVM's MMU capabilities irrespective
	 * of kernel support, e.g. KVM may be capable of using 1GB pages when
	 * the kernel is not.  But, KVM never creates a page size greater than
	 * what is used by the kernel for any given HVA, i.e. the kernel's
	 * capabilities are ultimately consulted by kvm_mmu_hugepage_adjust().
	 */
	if (tdp_enabled)
		max_huge_page_level = tdp_huge_page_level;
	else if (boot_cpu_has(X86_FEATURE_GBPAGES))
		max_huge_page_level = PG_LEVEL_1G;
	else
		max_huge_page_level = PG_LEVEL_2M;
}
EXPORT_SYMBOL_GPL(kvm_configure_mmu);

/* The return value indicates if tlb flush on all vcpus is needed. */
typedef bool (*slot_level_handler) (struct kvm *kvm,
				    struct kvm_rmap_head *rmap_head,
				    const struct kvm_memory_slot *slot);

/* The caller should hold mmu-lock before calling this function. */
static __always_inline bool
slot_handle_level_range(struct kvm *kvm, const struct kvm_memory_slot *memslot,
			slot_level_handler fn, int start_level, int end_level,
			gfn_t start_gfn, gfn_t end_gfn, bool flush_on_yield,
			bool flush)
{
	struct slot_rmap_walk_iterator iterator;

	for_each_slot_rmap_range(memslot, start_level, end_level, start_gfn,
			end_gfn, &iterator) {
		if (iterator.rmap)
			flush |= fn(kvm, iterator.rmap, memslot);

		if (need_resched() || rwlock_needbreak(&kvm->mmu_lock)) {
			if (flush && flush_on_yield) {
				kvm_flush_remote_tlbs_with_address(kvm,
						start_gfn,
						iterator.gfn - start_gfn + 1);
				flush = false;
			}
			cond_resched_rwlock_write(&kvm->mmu_lock);
		}
	}

	return flush;
}

static __always_inline bool
slot_handle_level(struct kvm *kvm, const struct kvm_memory_slot *memslot,
		  slot_level_handler fn, int start_level, int end_level,
		  bool flush_on_yield)
{
	return slot_handle_level_range(kvm, memslot, fn, start_level,
			end_level, memslot->base_gfn,
			memslot->base_gfn + memslot->npages - 1,
			flush_on_yield, false);
}

static __always_inline bool
slot_handle_level_4k(struct kvm *kvm, const struct kvm_memory_slot *memslot,
		     slot_level_handler fn, bool flush_on_yield)
{
	return slot_handle_level(kvm, memslot, fn, PG_LEVEL_4K,
				 PG_LEVEL_4K, flush_on_yield);
}

static void free_mmu_pages(struct kvm_mmu *mmu)
{
	if (!tdp_enabled && mmu->pae_root)
		set_memory_encrypted((unsigned long)mmu->pae_root, 1);
	free_page((unsigned long)mmu->pae_root);
	free_page((unsigned long)mmu->pml4_root);
	free_page((unsigned long)mmu->pml5_root);
}

static int __kvm_mmu_create(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu)
{
	struct page *page;
	int i;

	mmu->root_hpa = INVALID_PAGE;
	mmu->root_pgd = 0;
	mmu->translate_gpa = translate_gpa;
	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		mmu->prev_roots[i] = KVM_MMU_ROOT_INFO_INVALID;

	/*
	 * When using PAE paging, the four PDPTEs are treated as 'root' pages,
	 * while the PDP table is a per-vCPU construct that's allocated at MMU
	 * creation.  When emulating 32-bit mode, cr3 is only 32 bits even on
	 * x86_64.  Therefore we need to allocate the PDP table in the first
	 * 4GB of memory, which happens to fit the DMA32 zone.  TDP paging
	 * generally doesn't use PAE paging and can skip allocating the PDP
	 * table.  The main exception, handled here, is SVM's 32-bit NPT.  The
	 * other exception is for shadowing L1's 32-bit or PAE NPT on 64-bit
	 * KVM; that horror is handled on-demand by mmu_alloc_shadow_roots().
	 */
	if (tdp_enabled && kvm_mmu_get_tdp_level(vcpu) > PT32E_ROOT_LEVEL)
		return 0;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_DMA32);
	if (!page)
		return -ENOMEM;

	mmu->pae_root = page_address(page);

	/*
	 * CR3 is only 32 bits when PAE paging is used, thus it's impossible to
	 * get the CPU to treat the PDPTEs as encrypted.  Decrypt the page so
	 * that KVM's writes and the CPU's reads get along.  Note, this is
	 * only necessary when using shadow paging, as 64-bit NPT can get at
	 * the C-bit even when shadowing 32-bit NPT, and SME isn't supported
	 * by 32-bit kernels (when KVM itself uses 32-bit NPT).
	 */
	if (!tdp_enabled)
		set_memory_decrypted((unsigned long)mmu->pae_root, 1);
	else
		WARN_ON_ONCE(shadow_me_mask);

	for (i = 0; i < 4; ++i)
		mmu->pae_root[i] = INVALID_PAE_ROOT;

	return 0;
}

int kvm_mmu_create(struct kvm_vcpu *vcpu)
{
	int ret;

	vcpu->arch.mmu_pte_list_desc_cache.kmem_cache = pte_list_desc_cache;
	vcpu->arch.mmu_pte_list_desc_cache.gfp_zero = __GFP_ZERO;

	vcpu->arch.mmu_page_header_cache.kmem_cache = mmu_page_header_cache;
	vcpu->arch.mmu_page_header_cache.gfp_zero = __GFP_ZERO;

	vcpu->arch.mmu_shadow_page_cache.gfp_zero = __GFP_ZERO;

	vcpu->arch.mmu = &vcpu->arch.root_mmu;
	vcpu->arch.walk_mmu = &vcpu->arch.root_mmu;

	vcpu->arch.nested_mmu.translate_gpa = translate_nested_gpa;

	ret = __kvm_mmu_create(vcpu, &vcpu->arch.guest_mmu);
	if (ret)
		return ret;

	ret = __kvm_mmu_create(vcpu, &vcpu->arch.root_mmu);
	if (ret)
		goto fail_allocate_root;

	return ret;
 fail_allocate_root:
	free_mmu_pages(&vcpu->arch.guest_mmu);
	return ret;
}

#define BATCH_ZAP_PAGES	10
static void kvm_zap_obsolete_pages(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *node;
	int nr_zapped, batch = 0;

restart:
	list_for_each_entry_safe_reverse(sp, node,
	      &kvm->arch.active_mmu_pages, link) {
		/*
		 * No obsolete valid page exists before a newly created page
		 * since active_mmu_pages is a FIFO list.
		 */
		if (!is_obsolete_sp(kvm, sp))
			break;

		/*
		 * Invalid pages should never land back on the list of active
		 * pages.  Skip the bogus page, otherwise we'll get stuck in an
		 * infinite loop if the page gets put back on the list (again).
		 */
		if (WARN_ON(sp->role.invalid))
			continue;

		/*
		 * No need to flush the TLB since we're only zapping shadow
		 * pages with an obsolete generation number and all vCPUS have
		 * loaded a new root, i.e. the shadow pages being zapped cannot
		 * be in active use by the guest.
		 */
		if (batch >= BATCH_ZAP_PAGES &&
		    cond_resched_rwlock_write(&kvm->mmu_lock)) {
			batch = 0;
			goto restart;
		}

		if (__kvm_mmu_prepare_zap_page(kvm, sp,
				&kvm->arch.zapped_obsolete_pages, &nr_zapped)) {
			batch += nr_zapped;
			goto restart;
		}
	}

	/*
	 * Trigger a remote TLB flush before freeing the page tables to ensure
	 * KVM is not in the middle of a lockless shadow page table walk, which
	 * may reference the pages.
	 */
	kvm_mmu_commit_zap_page(kvm, &kvm->arch.zapped_obsolete_pages);
}

/*
 * Fast invalidate all shadow pages and use lock-break technique
 * to zap obsolete pages.
 *
 * It's required when memslot is being deleted or VM is being
 * destroyed, in these cases, we should ensure that KVM MMU does
 * not use any resource of the being-deleted slot or all slots
 * after calling the function.
 */
static void kvm_mmu_zap_all_fast(struct kvm *kvm)
{
	lockdep_assert_held(&kvm->slots_lock);

	write_lock(&kvm->mmu_lock);
	trace_kvm_mmu_zap_all_fast(kvm);

	/*
	 * Toggle mmu_valid_gen between '0' and '1'.  Because slots_lock is
	 * held for the entire duration of zapping obsolete pages, it's
	 * impossible for there to be multiple invalid generations associated
	 * with *valid* shadow pages at any given time, i.e. there is exactly
	 * one valid generation and (at most) one invalid generation.
	 */
	kvm->arch.mmu_valid_gen = kvm->arch.mmu_valid_gen ? 0 : 1;

	/* In order to ensure all threads see this change when
	 * handling the MMU reload signal, this must happen in the
	 * same critical section as kvm_reload_remote_mmus, and
	 * before kvm_zap_obsolete_pages as kvm_zap_obsolete_pages
	 * could drop the MMU lock and yield.
	 */
	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_invalidate_all_roots(kvm);

	/*
	 * Notify all vcpus to reload its shadow page table and flush TLB.
	 * Then all vcpus will switch to new shadow page table with the new
	 * mmu_valid_gen.
	 *
	 * Note: we need to do this under the protection of mmu_lock,
	 * otherwise, vcpu would purge shadow page but miss tlb flush.
	 */
	kvm_reload_remote_mmus(kvm);

	kvm_zap_obsolete_pages(kvm);

	write_unlock(&kvm->mmu_lock);

	if (is_tdp_mmu_enabled(kvm)) {
		read_lock(&kvm->mmu_lock);
		kvm_tdp_mmu_zap_invalidated_roots(kvm);
		read_unlock(&kvm->mmu_lock);
	}
}

static bool kvm_has_zapped_obsolete_pages(struct kvm *kvm)
{
	return unlikely(!list_empty_careful(&kvm->arch.zapped_obsolete_pages));
}

static void kvm_mmu_invalidate_zap_pages_in_memslot(struct kvm *kvm,
			struct kvm_memory_slot *slot,
			struct kvm_page_track_notifier_node *node)
{
	kvm_mmu_zap_all_fast(kvm);
}

void kvm_mmu_init_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node = &kvm->arch.mmu_sp_tracker;

	spin_lock_init(&kvm->arch.mmu_unsync_pages_lock);

	kvm_mmu_init_tdp_mmu(kvm);

	node->track_write = kvm_mmu_pte_write;
	node->track_flush_slot = kvm_mmu_invalidate_zap_pages_in_memslot;
	kvm_page_track_register_notifier(kvm, node);
}

void kvm_mmu_uninit_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node = &kvm->arch.mmu_sp_tracker;

	kvm_page_track_unregister_notifier(kvm, node);

	kvm_mmu_uninit_tdp_mmu(kvm);
}

static bool __kvm_zap_rmaps(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end)
{
	const struct kvm_memory_slot *memslot;
	struct kvm_memslots *slots;
	bool flush = false;
	gfn_t start, end;
	int i;

	if (!kvm_memslots_have_rmaps(kvm))
		return flush;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(memslot, slots) {
			start = max(gfn_start, memslot->base_gfn);
			end = min(gfn_end, memslot->base_gfn + memslot->npages);
			if (start >= end)
				continue;

			flush = slot_handle_level_range(kvm, memslot, kvm_zap_rmapp,
							PG_LEVEL_4K, KVM_MAX_HUGEPAGE_LEVEL,
							start, end - 1, true, flush);
		}
	}

	return flush;
}

/*
 * Invalidate (zap) SPTEs that cover GFNs from gfn_start and up to gfn_end
 * (not including it)
 */
void kvm_zap_gfn_range(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end)
{
	bool flush;
	int i;

	write_lock(&kvm->mmu_lock);

	kvm_inc_notifier_count(kvm, gfn_start, gfn_end);

	flush = __kvm_zap_rmaps(kvm, gfn_start, gfn_end);

	if (is_tdp_mmu_enabled(kvm)) {
		for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
			flush = kvm_tdp_mmu_zap_gfn_range(kvm, i, gfn_start,
							  gfn_end, flush);
	}

	if (flush)
		kvm_flush_remote_tlbs_with_address(kvm, gfn_start,
						   gfn_end - gfn_start);

	kvm_dec_notifier_count(kvm, gfn_start, gfn_end);

	write_unlock(&kvm->mmu_lock);
}

static bool slot_rmap_write_protect(struct kvm *kvm,
				    struct kvm_rmap_head *rmap_head,
				    const struct kvm_memory_slot *slot)
{
	return __rmap_write_protect(kvm, rmap_head, false);
}

void kvm_mmu_slot_remove_write_access(struct kvm *kvm,
				      const struct kvm_memory_slot *memslot,
				      int start_level)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		write_lock(&kvm->mmu_lock);
		flush = slot_handle_level(kvm, memslot, slot_rmap_write_protect,
					  start_level, KVM_MAX_HUGEPAGE_LEVEL,
					  false);
		write_unlock(&kvm->mmu_lock);
	}

	if (is_tdp_mmu_enabled(kvm)) {
		read_lock(&kvm->mmu_lock);
		flush |= kvm_tdp_mmu_wrprot_slot(kvm, memslot, start_level);
		read_unlock(&kvm->mmu_lock);
	}

	/*
	 * We can flush all the TLBs out of the mmu lock without TLB
	 * corruption since we just change the spte from writable to
	 * readonly so that we only need to care the case of changing
	 * spte from present to present (changing the spte from present
	 * to nonpresent will flush all the TLBs immediately), in other
	 * words, the only case we care is mmu_spte_update() where we
	 * have checked Host-writable | MMU-writable instead of
	 * PT_WRITABLE_MASK, that means it does not depend on PT_WRITABLE_MASK
	 * anymore.
	 */
	if (flush)
		kvm_arch_flush_remote_tlbs_memslot(kvm, memslot);
}

static bool kvm_mmu_zap_collapsible_spte(struct kvm *kvm,
					 struct kvm_rmap_head *rmap_head,
					 const struct kvm_memory_slot *slot)
{
	u64 *sptep;
	struct rmap_iterator iter;
	int need_tlb_flush = 0;
	kvm_pfn_t pfn;
	struct kvm_mmu_page *sp;

restart:
	for_each_rmap_spte(rmap_head, &iter, sptep) {
		sp = sptep_to_sp(sptep);
		pfn = spte_to_pfn(*sptep);

		/*
		 * We cannot do huge page mapping for indirect shadow pages,
		 * which are found on the last rmap (level = 1) when not using
		 * tdp; such shadow pages are synced with the page table in
		 * the guest, and the guest page table is using 4K page size
		 * mapping if the indirect sp has level = 1.
		 */
		if (sp->role.direct && !kvm_is_reserved_pfn(pfn) &&
		    sp->role.level < kvm_mmu_max_mapping_level(kvm, slot, sp->gfn,
							       pfn, PG_LEVEL_NUM)) {
			pte_list_remove(kvm, rmap_head, sptep);

			if (kvm_available_flush_tlb_with_range())
				kvm_flush_remote_tlbs_with_address(kvm, sp->gfn,
					KVM_PAGES_PER_HPAGE(sp->role.level));
			else
				need_tlb_flush = 1;

			goto restart;
		}
	}

	return need_tlb_flush;
}

void kvm_mmu_zap_collapsible_sptes(struct kvm *kvm,
				   const struct kvm_memory_slot *slot)
{
	if (kvm_memslots_have_rmaps(kvm)) {
		write_lock(&kvm->mmu_lock);
		/*
		 * Zap only 4k SPTEs since the legacy MMU only supports dirty
		 * logging at a 4k granularity and never creates collapsible
		 * 2m SPTEs during dirty logging.
		 */
		if (slot_handle_level_4k(kvm, slot, kvm_mmu_zap_collapsible_spte, true))
			kvm_arch_flush_remote_tlbs_memslot(kvm, slot);
		write_unlock(&kvm->mmu_lock);
	}

	if (is_tdp_mmu_enabled(kvm)) {
		read_lock(&kvm->mmu_lock);
		kvm_tdp_mmu_zap_collapsible_sptes(kvm, slot);
		read_unlock(&kvm->mmu_lock);
	}
}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					const struct kvm_memory_slot *memslot)
{
	/*
	 * All current use cases for flushing the TLBs for a specific memslot
	 * related to dirty logging, and many do the TLB flush out of mmu_lock.
	 * The interaction between the various operations on memslot must be
	 * serialized by slots_locks to ensure the TLB flush from one operation
	 * is observed by any other operation on the same memslot.
	 */
	lockdep_assert_held(&kvm->slots_lock);
	kvm_flush_remote_tlbs_with_address(kvm, memslot->base_gfn,
					   memslot->npages);
}

void kvm_mmu_slot_leaf_clear_dirty(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		write_lock(&kvm->mmu_lock);
		/*
		 * Clear dirty bits only on 4k SPTEs since the legacy MMU only
		 * support dirty logging at a 4k granularity.
		 */
		flush = slot_handle_level_4k(kvm, memslot, __rmap_clear_dirty, false);
		write_unlock(&kvm->mmu_lock);
	}

	if (is_tdp_mmu_enabled(kvm)) {
		read_lock(&kvm->mmu_lock);
		flush |= kvm_tdp_mmu_clear_dirty_slot(kvm, memslot);
		read_unlock(&kvm->mmu_lock);
	}

	/*
	 * It's also safe to flush TLBs out of mmu lock here as currently this
	 * function is only used for dirty logging, in which case flushing TLB
	 * out of mmu lock also guarantees no dirty pages will be lost in
	 * dirty_bitmap.
	 */
	if (flush)
		kvm_arch_flush_remote_tlbs_memslot(kvm, memslot);
}

void kvm_mmu_zap_all(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *node;
	LIST_HEAD(invalid_list);
	int ign;

	write_lock(&kvm->mmu_lock);
restart:
	list_for_each_entry_safe(sp, node, &kvm->arch.active_mmu_pages, link) {
		if (WARN_ON(sp->role.invalid))
			continue;
		if (__kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list, &ign))
			goto restart;
		if (cond_resched_rwlock_write(&kvm->mmu_lock))
			goto restart;
	}

	kvm_mmu_commit_zap_page(kvm, &invalid_list);

	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_zap_all(kvm);

	write_unlock(&kvm->mmu_lock);
}

void kvm_mmu_invalidate_mmio_sptes(struct kvm *kvm, u64 gen)
{
	WARN_ON(gen & KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS);

	gen &= MMIO_SPTE_GEN_MASK;

	/*
	 * Generation numbers are incremented in multiples of the number of
	 * address spaces in order to provide unique generations across all
	 * address spaces.  Strip what is effectively the address space
	 * modifier prior to checking for a wrap of the MMIO generation so
	 * that a wrap in any address space is detected.
	 */
	gen &= ~((u64)KVM_ADDRESS_SPACE_NUM - 1);

	/*
	 * The very rare case: if the MMIO generation number has wrapped,
	 * zap all shadow pages.
	 */
	if (unlikely(gen == 0)) {
		kvm_debug_ratelimited("kvm: zapping shadow pages for mmio generation wraparound\n");
		kvm_mmu_zap_all_fast(kvm);
	}
}

static unsigned long
mmu_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct kvm *kvm;
	int nr_to_scan = sc->nr_to_scan;
	unsigned long freed = 0;

	mutex_lock(&kvm_lock);

	list_for_each_entry(kvm, &vm_list, vm_list) {
		int idx;
		LIST_HEAD(invalid_list);

		/*
		 * Never scan more than sc->nr_to_scan VM instances.
		 * Will not hit this condition practically since we do not try
		 * to shrink more than one VM and it is very unlikely to see
		 * !n_used_mmu_pages so many times.
		 */
		if (!nr_to_scan--)
			break;
		/*
		 * n_used_mmu_pages is accessed without holding kvm->mmu_lock
		 * here. We may skip a VM instance errorneosly, but we do not
		 * want to shrink a VM that only started to populate its MMU
		 * anyway.
		 */
		if (!kvm->arch.n_used_mmu_pages &&
		    !kvm_has_zapped_obsolete_pages(kvm))
			continue;

		idx = srcu_read_lock(&kvm->srcu);
		write_lock(&kvm->mmu_lock);

		if (kvm_has_zapped_obsolete_pages(kvm)) {
			kvm_mmu_commit_zap_page(kvm,
			      &kvm->arch.zapped_obsolete_pages);
			goto unlock;
		}

		freed = kvm_mmu_zap_oldest_mmu_pages(kvm, sc->nr_to_scan);

unlock:
		write_unlock(&kvm->mmu_lock);
		srcu_read_unlock(&kvm->srcu, idx);

		/*
		 * unfair on small ones
		 * per-vm shrinkers cry out
		 * sadness comes quickly
		 */
		list_move_tail(&kvm->vm_list, &vm_list);
		break;
	}

	mutex_unlock(&kvm_lock);
	return freed;
}

static unsigned long
mmu_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	return percpu_counter_read_positive(&kvm_total_used_mmu_pages);
}

static struct shrinker mmu_shrinker = {
	.count_objects = mmu_shrink_count,
	.scan_objects = mmu_shrink_scan,
	.seeks = DEFAULT_SEEKS * 10,
};

static void mmu_destroy_caches(void)
{
	kmem_cache_destroy(pte_list_desc_cache);
	kmem_cache_destroy(mmu_page_header_cache);
}

static bool get_nx_auto_mode(void)
{
	/* Return true when CPU has the bug, and mitigations are ON */
	return boot_cpu_has_bug(X86_BUG_ITLB_MULTIHIT) && !cpu_mitigations_off();
}

static void __set_nx_huge_pages(bool val)
{
	nx_huge_pages = itlb_multihit_kvm_mitigation = val;
}

static int set_nx_huge_pages(const char *val, const struct kernel_param *kp)
{
	bool old_val = nx_huge_pages;
	bool new_val;

	/* In "auto" mode deploy workaround only if CPU has the bug. */
	if (sysfs_streq(val, "off"))
		new_val = 0;
	else if (sysfs_streq(val, "force"))
		new_val = 1;
	else if (sysfs_streq(val, "auto"))
		new_val = get_nx_auto_mode();
	else if (strtobool(val, &new_val) < 0)
		return -EINVAL;

	__set_nx_huge_pages(new_val);

	if (new_val != old_val) {
		struct kvm *kvm;

		mutex_lock(&kvm_lock);

		list_for_each_entry(kvm, &vm_list, vm_list) {
			mutex_lock(&kvm->slots_lock);
			kvm_mmu_zap_all_fast(kvm);
			mutex_unlock(&kvm->slots_lock);

			wake_up_process(kvm->arch.nx_lpage_recovery_thread);
		}
		mutex_unlock(&kvm_lock);
	}

	return 0;
}

int kvm_mmu_module_init(void)
{
	int ret = -ENOMEM;

	if (nx_huge_pages == -1)
		__set_nx_huge_pages(get_nx_auto_mode());

	/*
	 * MMU roles use union aliasing which is, generally speaking, an
	 * undefined behavior. However, we supposedly know how compilers behave
	 * and the current status quo is unlikely to change. Guardians below are
	 * supposed to let us know if the assumption becomes false.
	 */
	BUILD_BUG_ON(sizeof(union kvm_mmu_page_role) != sizeof(u32));
	BUILD_BUG_ON(sizeof(union kvm_mmu_extended_role) != sizeof(u32));
	BUILD_BUG_ON(sizeof(union kvm_mmu_role) != sizeof(u64));

	kvm_mmu_reset_all_pte_masks();

	pte_list_desc_cache = kmem_cache_create("pte_list_desc",
					    sizeof(struct pte_list_desc),
					    0, SLAB_ACCOUNT, NULL);
	if (!pte_list_desc_cache)
		goto out;

	mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
						  sizeof(struct kvm_mmu_page),
						  0, SLAB_ACCOUNT, NULL);
	if (!mmu_page_header_cache)
		goto out;

	if (percpu_counter_init(&kvm_total_used_mmu_pages, 0, GFP_KERNEL))
		goto out;

	ret = register_shrinker(&mmu_shrinker);
	if (ret)
		goto out;

	return 0;

out:
	mmu_destroy_caches();
	return ret;
}

/*
 * Calculate mmu pages needed for kvm.
 */
unsigned long kvm_mmu_calculate_default_mmu_pages(struct kvm *kvm)
{
	unsigned long nr_mmu_pages;
	unsigned long nr_pages = 0;
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int i;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);

		kvm_for_each_memslot(memslot, slots)
			nr_pages += memslot->npages;
	}

	nr_mmu_pages = nr_pages * KVM_PERMILLE_MMU_PAGES / 1000;
	nr_mmu_pages = max(nr_mmu_pages, KVM_MIN_ALLOC_MMU_PAGES);

	return nr_mmu_pages;
}

void kvm_mmu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_mmu_unload(vcpu);
	free_mmu_pages(&vcpu->arch.root_mmu);
	free_mmu_pages(&vcpu->arch.guest_mmu);
	mmu_free_memory_caches(vcpu);
}

void kvm_mmu_module_exit(void)
{
	mmu_destroy_caches();
	percpu_counter_destroy(&kvm_total_used_mmu_pages);
	unregister_shrinker(&mmu_shrinker);
	mmu_audit_disable();
}

/*
 * Calculate the effective recovery period, accounting for '0' meaning "let KVM
 * select a halving time of 1 hour".  Returns true if recovery is enabled.
 */
static bool calc_nx_huge_pages_recovery_period(uint *period)
{
	/*
	 * Use READ_ONCE to get the params, this may be called outside of the
	 * param setters, e.g. by the kthread to compute its next timeout.
	 */
	bool enabled = READ_ONCE(nx_huge_pages);
	uint ratio = READ_ONCE(nx_huge_pages_recovery_ratio);

	if (!enabled || !ratio)
		return false;

	*period = READ_ONCE(nx_huge_pages_recovery_period_ms);
	if (!*period) {
		/* Make sure the period is not less than one second.  */
		ratio = min(ratio, 3600u);
		*period = 60 * 60 * 1000 / ratio;
	}
	return true;
}

static int set_nx_huge_pages_recovery_param(const char *val, const struct kernel_param *kp)
{
	bool was_recovery_enabled, is_recovery_enabled;
	uint old_period, new_period;
	int err;

	was_recovery_enabled = calc_nx_huge_pages_recovery_period(&old_period);

	err = param_set_uint(val, kp);
	if (err)
		return err;

	is_recovery_enabled = calc_nx_huge_pages_recovery_period(&new_period);

	if (is_recovery_enabled &&
	    (!was_recovery_enabled || old_period > new_period)) {
		struct kvm *kvm;

		mutex_lock(&kvm_lock);

		list_for_each_entry(kvm, &vm_list, vm_list)
			wake_up_process(kvm->arch.nx_lpage_recovery_thread);

		mutex_unlock(&kvm_lock);
	}

	return err;
}

static void kvm_recover_nx_lpages(struct kvm *kvm)
{
	unsigned long nx_lpage_splits = kvm->stat.nx_lpage_splits;
	int rcu_idx;
	struct kvm_mmu_page *sp;
	unsigned int ratio;
	LIST_HEAD(invalid_list);
	bool flush = false;
	ulong to_zap;

	rcu_idx = srcu_read_lock(&kvm->srcu);
	write_lock(&kvm->mmu_lock);

	ratio = READ_ONCE(nx_huge_pages_recovery_ratio);
	to_zap = ratio ? DIV_ROUND_UP(nx_lpage_splits, ratio) : 0;
	for ( ; to_zap; --to_zap) {
		if (list_empty(&kvm->arch.lpage_disallowed_mmu_pages))
			break;

		/*
		 * We use a separate list instead of just using active_mmu_pages
		 * because the number of lpage_disallowed pages is expected to
		 * be relatively small compared to the total.
		 */
		sp = list_first_entry(&kvm->arch.lpage_disallowed_mmu_pages,
				      struct kvm_mmu_page,
				      lpage_disallowed_link);
		WARN_ON_ONCE(!sp->lpage_disallowed);
		if (is_tdp_mmu_page(sp)) {
			flush |= kvm_tdp_mmu_zap_sp(kvm, sp);
		} else {
			kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
			WARN_ON_ONCE(sp->lpage_disallowed);
		}

		if (need_resched() || rwlock_needbreak(&kvm->mmu_lock)) {
			kvm_mmu_remote_flush_or_zap(kvm, &invalid_list, flush);
			cond_resched_rwlock_write(&kvm->mmu_lock);
			flush = false;
		}
	}
	kvm_mmu_remote_flush_or_zap(kvm, &invalid_list, flush);

	write_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, rcu_idx);
}

static long get_nx_lpage_recovery_timeout(u64 start_time)
{
	bool enabled;
	uint period;

	enabled = calc_nx_huge_pages_recovery_period(&period);

	return enabled ? start_time + msecs_to_jiffies(period) - get_jiffies_64()
		       : MAX_SCHEDULE_TIMEOUT;
}

static int kvm_nx_lpage_recovery_worker(struct kvm *kvm, uintptr_t data)
{
	u64 start_time;
	long remaining_time;

	while (true) {
		start_time = get_jiffies_64();
		remaining_time = get_nx_lpage_recovery_timeout(start_time);

		set_current_state(TASK_INTERRUPTIBLE);
		while (!kthread_should_stop() && remaining_time > 0) {
			schedule_timeout(remaining_time);
			remaining_time = get_nx_lpage_recovery_timeout(start_time);
			set_current_state(TASK_INTERRUPTIBLE);
		}

		set_current_state(TASK_RUNNING);

		if (kthread_should_stop())
			return 0;

		kvm_recover_nx_lpages(kvm);
	}
}

int kvm_mmu_post_init_vm(struct kvm *kvm)
{
	int err;

	err = kvm_vm_create_worker_thread(kvm, kvm_nx_lpage_recovery_worker, 0,
					  "kvm-nx-lpage-recovery",
					  &kvm->arch.nx_lpage_recovery_thread);
	if (!err)
		kthread_unpark(kvm->arch.nx_lpage_recovery_thread);

	return err;
}

void kvm_mmu_pre_destroy_vm(struct kvm *kvm)
{
	if (kvm->arch.nx_lpage_recovery_thread)
		kthread_stop(kvm->arch.nx_lpage_recovery_thread);
}
