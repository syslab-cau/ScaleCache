// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#include <linux/memblock.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kasan.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/oom.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>
#include <linux/vmstat.h>
#include <linux/mempolicy.h>
#include <linux/memremap.h>
#include <linux/stop_machine.h>
#include <linux/random.h>
#include <linux/sort.h>
#include <linux/pfn.h>
#include <linux/backing-dev.h>
#include <linux/fault-inject.h>
#include <linux/page-isolation.h>
#include <linux/debugobjects.h>
#include <linux/kmemleak.h>
#include <linux/compaction.h>
#include <trace/events/kmem.h>
#include <trace/events/oom.h>
#include <linux/prefetch.h>
#include <linux/mm_inline.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/sched/rt.h>
#include <linux/sched/mm.h>
#include <linux/page_owner.h>
#include <linux/kthread.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/lockdep.h>
#include <linux/nmi.h>
#include <linux/psi.h>
#include <linux/khugepaged.h>

#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/div64.h>
#include "internal.h"
#include "shuffle.h"

DECLARE_STATIC_KEY_TRUE(vm_numa_stat_key);

void prep_compound_page(struct page *page, unsigned int order)
{
	int i;
	int nr_pages = 1 << order;

	set_compound_page_dtor(page, COMPOUND_PAGE_DTOR);
	set_compound_order(page, order);
	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;
		set_page_count(p, 0);
		p->mapping = TAIL_MAPPING;
		set_compound_head(p, page);
	}
	atomic_set(compound_mapcount_ptr(page), -1);
}

/* work_structs for global per-cpu drains */
struct pcpu_drain {
        struct zone *zone;
        struct work_struct work;
};
extern struct mutex pcpu_drain_mutex;        
DECLARE_PER_CPU(struct pcpu_drain, pcpu_drain);	

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
/*
 * During boot we initialize deferred pages on-demand, as needed, but once
 * page_alloc_init_late() has finished, the deferred pages are all initialized,
 * and we can permanently disable that path.
 */
//static DEFINE_STATIC_KEY_TRUE(deferred_pages);

/*
 * Calling kasan_free_pages() only after deferred memory initialization
 * has completed. Poisoning pages during deferred memory init will greatly
 * lengthen the process and cause problem in large memory systems as the
 * deferred pages initialization is done with interrupt disabled.
 *
 * Assuming that there will be no reference to those newly initialized
 * pages before they are ever allocated, this should have no effect on
 * KASAN memory tracking as the poison will be properly inserted at page
 * allocation time. The only corner case is when pages are allocated by
 * on-demand allocation and then freed again before the deferred pages
 * initialization is done, but this is not likely to happen.
 */
static inline void kasan_free_nondeferred_pages(struct page *page, int order)
{
	if (!static_branch_unlikely(&deferred_pages))
		kasan_free_pages(page, order);
}

#else
#define kasan_free_nondeferred_pages(p, o)      kasan_free_pages(p, o)

#endif

/* Return a pointer to the bitmap storing bits affecting a block of pages */
static inline unsigned long *get_pageblock_bitmap(struct page *page,
							unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	return section_to_usemap(__pfn_to_section(pfn));
#else
	return page_zone(page)->pageblock_flags;
#endif /* CONFIG_SPARSEMEM */
}

static inline int pfn_to_bitidx(struct page *page, unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	pfn &= (PAGES_PER_SECTION-1);
	return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
#else
	pfn = pfn - round_down(page_zone(page)->zone_start_pfn, pageblock_nr_pages);
	return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
#endif /* CONFIG_SPARSEMEM */
}

/**
 * get_pfnblock_flags_mask - Return the requested group of flags for the pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @end_bitidx: The last bit of interest to retrieve
 * @mask: mask of bits that the caller is interested in
 *
 * Return: pageblock_bits flags
 */
static __always_inline unsigned long __get_pfnblock_flags_mask(struct page *page,
					unsigned long pfn,
					unsigned long end_bitidx,
					unsigned long mask)
{
	unsigned long *bitmap;
	unsigned long bitidx, word_bitidx;
	unsigned long word;

	bitmap = get_pageblock_bitmap(page, pfn);
	bitidx = pfn_to_bitidx(page, pfn);
	word_bitidx = bitidx / BITS_PER_LONG;
	bitidx &= (BITS_PER_LONG-1);

	word = bitmap[word_bitidx];
	bitidx += end_bitidx;
	return (word >> (BITS_PER_LONG - bitidx - 1)) & mask;
}

unsigned long get_pfnblock_flags_mask(struct page *page, unsigned long pfn,
					unsigned long end_bitidx,
					unsigned long mask)
{
	return __get_pfnblock_flags_mask(page, pfn, end_bitidx, mask);
}

static __always_inline int get_pfnblock_migratetype(struct page *page, unsigned long pfn)
{
	return __get_pfnblock_flags_mask(page, pfn, PB_migrate_end, MIGRATETYPE_MASK);
}

/*
 * A cached value of the page's pageblock's migratetype, used when the page is
 * put on a pcplist. Used to avoid the pageblock migratetype lookup when
 * freeing from pcplists in most cases, at the cost of possibly becoming stale.
 * Also the migratetype set in the page does not necessarily match the pcplist
 * index, e.g. page might have MIGRATE_CMA set but be on a pcplist with any
 * other index - this ensures that it will be put on the correct CMA freelist.
 */
static inline int get_pcppage_migratetype(struct page *page)
{
	return page->index;
}

static inline void set_pcppage_migratetype(struct page *page, int migratetype)
{
	page->index = migratetype;
}

#ifdef CONFIG_DEBUG_VM
static int page_outside_zone_boundaries(struct zone *zone, struct page *page)
{
	int ret = 0;
	unsigned seq;
	unsigned long pfn = page_to_pfn(page);
	unsigned long sp, start_pfn;

	do {
		seq = zone_span_seqbegin(zone);
		start_pfn = zone->zone_start_pfn;
		sp = zone->spanned_pages;
		if (!zone_spans_pfn(zone, pfn))
			ret = 1;
	} while (zone_span_seqretry(zone, seq));

	if (ret)
		pr_err("page 0x%lx outside node %d zone %s [ 0x%lx - 0x%lx ]\n",
			pfn, zone_to_nid(zone), zone->name,
			start_pfn, start_pfn + sp);

	return ret;
}

static int page_is_consistent(struct zone *zone, struct page *page)
{
	if (!pfn_valid_within(page_to_pfn(page)))
		return 0;
	if (zone != page_zone(page))
		return 0;

	return 1;
}
/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static int __maybe_unused bad_range(struct zone *zone, struct page *page)
{
	if (page_outside_zone_boundaries(zone, page))
		return 1;
	if (!page_is_consistent(zone, page))
		return 1;

	return 0;
}
#else
static inline int __maybe_unused bad_range(struct zone *zone, struct page *page)
{
	return 0;
}
#endif

static void bad_page(struct page *page, const char *reason,
		unsigned long bad_flags)
{
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			goto out;
		}
		if (nr_unshown) {
			pr_alert(
			      "BUG: Bad page state: %lu messages suppressed\n",
				nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
		resume = jiffies + 60 * HZ;

	pr_alert("BUG: Bad page state in process %s  pfn:%05lx\n",
		current->comm, page_to_pfn(page));
	__dump_page(page, reason);
	bad_flags &= page->flags;
	if (bad_flags)
		pr_alert("bad because of flags: %#lx(%pGp)\n",
						bad_flags, &bad_flags);
	dump_page_owner(page);

	print_modules();
	dump_stack();
out:
	/* Leave bad fields for debug, except PageBuddy could make trouble */
	page_mapcount_reset(page); /* remove PageBuddy */
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

#ifdef CONFIG_DEBUG_PAGEALLOC

static inline bool set_page_guard(struct zone *zone, struct page *page,
				unsigned int order, int migratetype)
{
	if (!debug_guardpage_enabled())
		return false;

	if (order >= debug_guardpage_minorder())
		return false;

	__SetPageGuard(page);
	INIT_LIST_HEAD(&page->lru);
	set_page_private(page, order);
	/* Guard pages are not available for any usage */
	__mod_zone_freepage_state(zone, -(1 << order), migratetype);

	return true;
}

static inline void clear_page_guard(struct zone *zone, struct page *page,
				unsigned int order, int migratetype)
{
	if (!debug_guardpage_enabled())
		return;

	__ClearPageGuard(page);

	set_page_private(page, 0);
	if (!is_migrate_isolate(migratetype))
		__mod_zone_freepage_state(zone, (1 << order), migratetype);
}
#else
static inline bool set_page_guard(struct zone *zone, struct page *page,
			unsigned int order, int migratetype) { return false; }
static inline void clear_page_guard(struct zone *zone, struct page *page,
				unsigned int order, int migratetype) {}
#endif

static inline void set_page_order(struct page *page, unsigned int order)
{
	set_page_private(page, order);
	__SetPageBuddy(page);
}

/*
 * This function checks whether a page is free && is the buddy
 * we can coalesce a page and its buddy if
 * (a) the buddy is not in a hole (check before calling!) &&
 * (b) the buddy is in the buddy system &&
 * (c) a page and its buddy have the same order &&
 * (d) a page and its buddy are in the same zone.
 *
 * For recording whether a page is in the buddy system, we set PageBuddy.
 * Setting, clearing, and testing PageBuddy is serialized by zone->lock.
 *
 * For recording page's order, we use page_private(page).
 */
static inline int page_is_buddy(struct page *page, struct page *buddy,
							unsigned int order)
{
	if (page_is_guard(buddy) && page_order(buddy) == order) {
		if (page_zone_id(page) != page_zone_id(buddy))
			return 0;

		VM_BUG_ON_PAGE(page_count(buddy) != 0, buddy);

		return 1;
	}

	if (PageBuddy(buddy) && page_order(buddy) == order) {
		/*
		 * zone check is done late to avoid uselessly
		 * calculating zone/node ids for pages that could
		 * never merge.
		 */
		if (page_zone_id(page) != page_zone_id(buddy))
			return 0;

		VM_BUG_ON_PAGE(page_count(buddy) != 0, buddy);

		return 1;
	}
	return 0;
}

#ifdef CONFIG_COMPACTION
static inline struct capture_control *task_capc(struct zone *zone)
{
	struct capture_control *capc = current->capture_control;

	return capc &&
		!(current->flags & PF_KTHREAD) &&
		!capc->page &&
		capc->cc->zone == zone &&
		capc->cc->direct_compaction ? capc : NULL;
}

static inline bool
compaction_capture(struct capture_control *capc, struct page *page,
		   int order, int migratetype)
{
	if (!capc || order != capc->cc->order)
		return false;

	/* Do not accidentally pollute CMA or isolated regions*/
	if (is_migrate_cma(migratetype) ||
	    is_migrate_isolate(migratetype))
		return false;

	/*
	 * Do not let lower order allocations polluate a movable pageblock.
	 * This might let an unmovable request use a reclaimable pageblock
	 * and vice-versa but no more than normal fallback logic which can
	 * have trouble finding a high-order free page.
	 */
	if (order < pageblock_order && migratetype == MIGRATE_MOVABLE)
		return false;

	capc->page = page;
	return true;
}

#else
static inline struct capture_control *task_capc(struct zone *zone)
{
	return NULL;
}

static inline bool
compaction_capture(struct capture_control *capc, struct page *page,
		   int order, int migratetype)
{
	return false;
}
#endif /* CONFIG_COMPACTION */

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped table
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep a list of pages, which are heads of continuous
 * free pages of length of (1 << order) and marked with PageBuddy.
 * Page's order is recorded in page_private(page) field.
 * So when we are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were
 * free, the remainder of the region must be split into blocks.
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.
 *
 * -- nyc
 */

static inline void __free_one_page(struct page *page,
		unsigned long pfn,
		struct zone *zone, unsigned int order,
		int migratetype)
{
	unsigned long combined_pfn;
	unsigned long uninitialized_var(buddy_pfn);
	struct page *buddy;
	unsigned int max_order;
	struct capture_control *capc = task_capc(zone);

	max_order = min_t(unsigned int, MAX_ORDER - 1, pageblock_order);

	VM_BUG_ON(!zone_is_initialized(zone));
	VM_BUG_ON_PAGE(page->flags & PAGE_FLAGS_CHECK_AT_PREP, page);

	VM_BUG_ON(migratetype == -1);
	if (likely(!is_migrate_isolate(migratetype)))
		__mod_zone_freepage_state(zone, 1 << order, migratetype);

	VM_BUG_ON_PAGE(pfn & ((1 << order) - 1), page);
	VM_BUG_ON_PAGE(bad_range(zone, page), page);

continue_merging:
	while (order < max_order) {
		if (compaction_capture(capc, page, order, migratetype)) {
			__mod_zone_freepage_state(zone, -(1 << order),
								migratetype);
			return;
		}
		buddy_pfn = __find_buddy_pfn(pfn, order);
		buddy = page + (buddy_pfn - pfn);

		if (!pfn_valid_within(buddy_pfn))
			goto done_merging;
		if (!page_is_buddy(page, buddy, order))
			goto done_merging;
		/*
		 * Our buddy is free or it is CONFIG_DEBUG_PAGEALLOC guard page,
		 * merge with it and move up one order.
		 */
		if (page_is_guard(buddy))
			clear_page_guard(zone, buddy, order, migratetype);
		else
			del_page_from_free_area(buddy, &zone->free_area[order]);
		combined_pfn = buddy_pfn & pfn;
		page = page + (combined_pfn - pfn);
		pfn = combined_pfn;
		order++;
	}
	if (order < MAX_ORDER - 1) {
		/* If we are here, it means order is >= pageblock_order.
		 * We want to prevent merge between freepages on isolate
		 * pageblock and normal pageblock. Without this, pageblock
		 * isolation could cause incorrect freepage or CMA accounting.
		 *
		 * We don't want to hit this code for the more frequent
		 * low-order merging.
		 */
		if (unlikely(has_isolate_pageblock(zone))) {
			int buddy_mt;

			buddy_pfn = __find_buddy_pfn(pfn, order);
			buddy = page + (buddy_pfn - pfn);
			buddy_mt = get_pageblock_migratetype(buddy);

			if (migratetype != buddy_mt
					&& (is_migrate_isolate(migratetype) ||
						is_migrate_isolate(buddy_mt)))
				goto done_merging;
		}
		max_order = order + 1;
		goto continue_merging;
	}

done_merging:
	set_page_order(page, order);

	/*
	 * If this is not the largest possible page, check if the buddy
	 * of the next-highest order is free. If it is, it's possible
	 * that pages are being freed that will coalesce soon. In case,
	 * that is happening, add the free page to the tail of the list
	 * so it's less likely to be used soon and more likely to be merged
	 * as a higher order page
	 */
	if ((order < MAX_ORDER-2) && pfn_valid_within(buddy_pfn)
			&& !is_shuffle_order(order)) {
		struct page *higher_page, *higher_buddy;
		combined_pfn = buddy_pfn & pfn;
		higher_page = page + (combined_pfn - pfn);
		buddy_pfn = __find_buddy_pfn(combined_pfn, order + 1);
		higher_buddy = higher_page + (buddy_pfn - combined_pfn);
		if (pfn_valid_within(buddy_pfn) &&
		    page_is_buddy(higher_page, higher_buddy, order + 1)) {
			add_to_free_area_tail(page, &zone->free_area[order],
					      migratetype);
			return;
		}
	}

	if (is_shuffle_order(order))
		add_to_free_area_random(page, &zone->free_area[order],
				migratetype);
	else
		add_to_free_area(page, &zone->free_area[order], migratetype);

}

/*
 * A bad page could be due to a number of fields. Instead of multiple branches,
 * try and check multiple fields with one check. The caller must do a detailed
 * check if necessary.
 */
static inline bool page_expected_state(struct page *page,
					unsigned long check_flags)
{
	if (unlikely(atomic_read(&page->_mapcount) != -1))
		return false;

	if (unlikely((unsigned long)page->mapping |
			page_ref_count(page) |
#ifdef CONFIG_MEMCG
			(unsigned long)page->mem_cgroup |
#endif
			(page->flags & check_flags)))
		return false;

	return true;
}

static void free_pages_check_bad(struct page *page)
{
	const char *bad_reason;
	unsigned long bad_flags;

	bad_reason = NULL;
	bad_flags = 0;

	if (unlikely(atomic_read(&page->_mapcount) != -1))
		bad_reason = "nonzero mapcount";
	if (unlikely(page->mapping != NULL))
		bad_reason = "non-NULL mapping";
	if (unlikely(page_ref_count(page) != 0))
		bad_reason = "nonzero _refcount";
	if (unlikely(page->flags & PAGE_FLAGS_CHECK_AT_FREE)) {
		bad_reason = "PAGE_FLAGS_CHECK_AT_FREE flag(s) set";
		bad_flags = PAGE_FLAGS_CHECK_AT_FREE;
	}
#ifdef CONFIG_MEMCG
	if (unlikely(page->mem_cgroup))
		bad_reason = "page still charged to cgroup";
#endif
	bad_page(page, bad_reason, bad_flags);
}

static inline int free_pages_check(struct page *page)
{
	if (likely(page_expected_state(page, PAGE_FLAGS_CHECK_AT_FREE)))
		return 0;

	/* Something has gone sideways, find it */
	free_pages_check_bad(page);
	return 1;
}

static int free_tail_pages_check(struct page *head_page, struct page *page)
{
	int ret = 1;

	/*
	 * We rely page->lru.next never has bit 0 set, unless the page
	 * is PageTail(). Let's make sure that's true even for poisoned ->lru.
	 */
	BUILD_BUG_ON((unsigned long)LIST_POISON1 & 1);

	if (!IS_ENABLED(CONFIG_DEBUG_VM)) {
		ret = 0;
		goto out;
	}
	switch (page - head_page) {
	case 1:
		/* the first tail page: ->mapping may be compound_mapcount() */
		if (unlikely(compound_mapcount(page))) {
			bad_page(page, "nonzero compound_mapcount", 0);
			goto out;
		}
		break;
	case 2:
		/*
		 * the second tail page: ->mapping is
		 * deferred_list.next -- ignore value.
		 */
		break;
	default:
		if (page->mapping != TAIL_MAPPING) {
			bad_page(page, "corrupted mapping in tail page", 0);
			goto out;
		}
		break;
	}
	if (unlikely(!PageTail(page))) {
		bad_page(page, "PageTail not set", 0);
		goto out;
	}
	if (unlikely(compound_head(page) != head_page)) {
		bad_page(page, "compound_head not consistent", 0);
		goto out;
	}
	ret = 0;
out:
	page->mapping = NULL;
	clear_compound_head(page);
	return ret;
}

static void kernel_init_free_pages(struct page *page, int numpages)
{
	int i;

	for (i = 0; i < numpages; i++)
		clear_highpage(page + i);
}

static __always_inline bool free_pages_prepare(struct page *page,
					unsigned int order, bool check_free)
{
	int bad = 0;

	VM_BUG_ON_PAGE(PageTail(page), page);

	//trace_mm_page_free(page, order);

	/*
	 * Check tail pages before head page information is cleared to
	 * avoid checking PageCompound for order-0 pages.
	 */
	if (unlikely(order)) {
		bool compound = PageCompound(page);
		int i;

		VM_BUG_ON_PAGE(compound && compound_order(page) != order, page);

		if (compound)
			ClearPageDoubleMap(page);
		for (i = 1; i < (1 << order); i++) {
			if (compound)
				bad += free_tail_pages_check(page, page + i);
			if (unlikely(free_pages_check(page + i))) {
				bad++;
				continue;
			}
			(page + i)->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
		}
	}
	if (PageMappingFlags(page))
		page->mapping = NULL;
	if (memcg_kmem_enabled() && PageKmemcg(page))
		__memcg_kmem_uncharge(page, order);
	if (check_free)
		bad += free_pages_check(page);
	if (bad)
		return false;

	page_cpupid_reset_last(page);
	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
	reset_page_owner(page, order);

	if (!PageHighMem(page)) {
		debug_check_no_locks_freed(page_address(page),
					   PAGE_SIZE << order);
		debug_check_no_obj_freed(page_address(page),
					   PAGE_SIZE << order);
	}
	if (want_init_on_free())
		kernel_init_free_pages(page, 1 << order);

	kernel_poison_pages(page, 1 << order, 0);
	/*
	 * arch_free_page() can make the page's contents inaccessible.  s390
	 * does this.  So nothing which can access the page's contents should
	 * happen after this.
	 */
	arch_free_page(page, order);

	if (debug_pagealloc_enabled_static())
		kernel_map_pages(page, 1 << order, 0);

	kasan_free_nondeferred_pages(page, order);

	return true;
}

#ifdef CONFIG_DEBUG_VM
/*
 * With DEBUG_VM enabled, order-0 pages are checked immediately when being freed
 * to pcp lists. With debug_pagealloc also enabled, they are also rechecked when
 * moved from pcp lists to free lists.
 */
static bool free_pcp_prepare(struct page *page)
{
	return free_pages_prepare(page, 0, true);
}

static bool bulkfree_pcp_prepare(struct page *page)
{
	if (debug_pagealloc_enabled_static())
		return free_pages_check(page);
	else
		return false;
}
#else
/*
 * With DEBUG_VM disabled, order-0 pages being freed are checked only when
 * moving from pcp lists to free list in order to reduce overhead. With
 * debug_pagealloc enabled, they are checked also immediately when being freed
 * to the pcp lists.
 */
static bool free_pcp_prepare(struct page *page)
{
	if (debug_pagealloc_enabled_static())
		return free_pages_prepare(page, 0, true);
	else
		return free_pages_prepare(page, 0, false);
}

static bool bulkfree_pcp_prepare(struct page *page)
{
	return free_pages_check(page);
}
#endif /* CONFIG_DEBUG_VM */

static inline void prefetch_buddy(struct page *page)
{
	unsigned long pfn = page_to_pfn(page);
	unsigned long buddy_pfn = __find_buddy_pfn(pfn, 0);
	struct page *buddy = page + (buddy_pfn - pfn);

	prefetch(buddy);
}

/*
 * Frees a number of pages from the PCP lists
 * Assumes all pages on list are in same zone, and of same order.
 * count is the number of pages to free.
 *
 * If the zone was previously in an "all pages pinned" state then look to
 * see if this freeing clears that state.
 *
 * And clear the zone's pages_scanned counter, to hold off the "all pages are
 * pinned" detection logic.
 */
static void free_pcppages_bulk(struct zone *zone, int count,
                                        struct per_cpu_pages *pcp)
{
	int migratetype = 0;
	int batch_free = 0;
	int prefetch_nr = 0;
	bool isolated_pageblocks;
	struct page *page, *tmp;
	LIST_HEAD(head);

	/*
	 * Ensure proper count is passed which otherwise would stuck in the
	 * below while (list_empty(list)) loop.
	 */
	count = min(pcp->count, count);
	while (count) {
		struct list_head *list;

		/*
		 * Remove pages from lists in a round-robin fashion. A
		 * batch_free count is maintained that is incremented when an
		 * empty list is encountered.  This is so more pages are freed
		 * off fuller lists instead of spinning excessively around empty
		 * lists
		 */
		do {
			batch_free++;
			if (++migratetype == MIGRATE_PCPTYPES)
				migratetype = 0;
			list = &pcp->lists[migratetype];
		} while (list_empty(list));

		/* This is the only non-empty list. Free them all. */
		if (batch_free == MIGRATE_PCPTYPES)
			batch_free = count;

		do {
			page = list_last_entry(list, struct page, lru);
			/* must delete to avoid corrupting pcp list */
			list_del(&page->lru);
			pcp->count--;

			if (bulkfree_pcp_prepare(page))
				continue;

			list_add_tail(&page->lru, &head);

			/*
			 * We are going to put the page back to the global
			 * pool, prefetch its buddy to speed up later access
			 * under zone->lock. It is believed the overhead of
			 * an additional test and calculating buddy_pfn here
			 * can be offset by reduced memory latency later. To
			 * avoid excessive prefetching due to large count, only
			 * prefetch buddy for the first pcp->batch nr of pages.
			 */
			if (prefetch_nr++ < pcp->batch)
				prefetch_buddy(page);
		} while (--count && --batch_free && !list_empty(list));
	}

	spin_lock(&zone->lock);
	isolated_pageblocks = has_isolate_pageblock(zone);

	/*
	 * Use safe version since after __free_one_page(),
	 * page->lru.next will not point to original list.
	 */
	list_for_each_entry_safe(page, tmp, &head, lru) {
		int mt = get_pcppage_migratetype(page);
		/* MIGRATE_ISOLATE page should not go to pcplists */
		VM_BUG_ON_PAGE(is_migrate_isolate(mt), page);
		/* Pageblock could have been isolated meanwhile */
		if (unlikely(isolated_pageblocks))
			mt = get_pageblock_migratetype(page);

		__free_one_page(page, page_to_pfn(page), zone, 0, mt);
		//trace_mm_page_pcpu_drain(page, 0, mt);
	}
	spin_unlock(&zone->lock);
}

static void free_one_page(struct zone *zone,
				struct page *page, unsigned long pfn,
				unsigned int order,
				int migratetype)
{
	spin_lock(&zone->lock);
	if (unlikely(has_isolate_pageblock(zone) ||
		is_migrate_isolate(migratetype))) {
		migratetype = get_pfnblock_migratetype(page, pfn);
	}
	__free_one_page(page, pfn, zone, order, migratetype);
	spin_unlock(&zone->lock);
}

/*
 * The order of subdivision here is critical for the IO subsystem.
 * Please do not alter this order without good reasons and regression
 * testing. Specifically, as large blocks of memory are subdivided,
 * the order in which smaller blocks are delivered depends on the order
 * they're subdivided in this function. This is the primary factor
 * influencing the order in which pages are delivered to the IO
 * subsystem according to empirical testing, and this is also justified
 * by considering the behavior of a buddy system containing a single
 * large block of memory acted on by a series of small allocations.
 * This behavior is a critical factor in sglist merging's success.
 *
 * -- nyc
 */
static inline void expand(struct zone *zone, struct page *page,
	int low, int high, struct free_area *area,
	int migratetype)
{
	unsigned long size = 1 << high;

	while (high > low) {
		area--;
		high--;
		size >>= 1;
		VM_BUG_ON_PAGE(bad_range(zone, &page[size]), &page[size]);

		/*
		 * Mark as guard pages (or page), that will allow to
		 * merge back to allocator when buddy will be freed.
		 * Corresponding page table entries will not be touched,
		 * pages will stay not present in virtual address space
		 */
		if (set_page_guard(zone, &page[size], high, migratetype))
			continue;

		add_to_free_area(&page[size], area, migratetype);
		set_page_order(&page[size], high);
	}
}

static void check_new_page_bad(struct page *page)
{
	const char *bad_reason = NULL;
	unsigned long bad_flags = 0;

	if (unlikely(atomic_read(&page->_mapcount) != -1))
		bad_reason = "nonzero mapcount";
	if (unlikely(page->mapping != NULL))
		bad_reason = "non-NULL mapping";
	if (unlikely(page_ref_count(page) != 0))
		bad_reason = "nonzero _refcount";
	if (unlikely(page->flags & __PG_HWPOISON)) {
		bad_reason = "HWPoisoned (hardware-corrupted)";
		bad_flags = __PG_HWPOISON;
		/* Don't complain about hwpoisoned pages */
		page_mapcount_reset(page); /* remove PageBuddy */
		return;
	}
	if (unlikely(page->flags & PAGE_FLAGS_CHECK_AT_PREP)) {
		bad_reason = "PAGE_FLAGS_CHECK_AT_PREP flag set";
		bad_flags = PAGE_FLAGS_CHECK_AT_PREP;
	}
#ifdef CONFIG_MEMCG
	if (unlikely(page->mem_cgroup))
		bad_reason = "page still charged to cgroup";
#endif
	bad_page(page, bad_reason, bad_flags);
}

/*
 * This page is about to be returned from the page allocator
 */
static inline int check_new_page(struct page *page)
{
	if (likely(page_expected_state(page,
				PAGE_FLAGS_CHECK_AT_PREP|__PG_HWPOISON)))
		return 0;

	check_new_page_bad(page);
	return 1;
}

static inline bool free_pages_prezeroed(void)
{
	return (IS_ENABLED(CONFIG_PAGE_POISONING_ZERO) &&
		page_poisoning_enabled()) || want_init_on_free();
}

#ifdef CONFIG_DEBUG_VM
/*
 * With DEBUG_VM enabled, order-0 pages are checked for expected state when
 * being allocated from pcp lists. With debug_pagealloc also enabled, they are
 * also checked when pcp lists are refilled from the free lists.
 */
static inline bool check_pcp_refill(struct page *page)
{
	if (debug_pagealloc_enabled_static())
		return check_new_page(page);
	else
		return false;
}

static inline bool check_new_pcp(struct page *page)
{
	return check_new_page(page);
}
#else
/*
 * With DEBUG_VM disabled, free order-0 pages are checked for expected state
 * when pcp lists are being refilled from the free lists. With debug_pagealloc
 * enabled, they are also checked when being allocated from the pcp lists.
 */
static inline bool check_pcp_refill(struct page *page)
{
	return check_new_page(page);
}
static inline bool check_new_pcp(struct page *page)
{
	if (debug_pagealloc_enabled_static())
		return check_new_page(page);
	else
		return false;
}
#endif /* CONFIG_DEBUG_VM */

inline void post_alloc_hook(struct page *page, unsigned int order,
				gfp_t gfp_flags)
{
	set_page_private(page, 0);
	set_page_refcounted(page);

	arch_alloc_page(page, order);
	if (debug_pagealloc_enabled_static())
		kernel_map_pages(page, 1 << order, 1);
	kasan_alloc_pages(page, order);
	kernel_poison_pages(page, 1 << order, 1);
	set_page_owner(page, order, gfp_flags);
}

/*
 * Go through the free lists for the given migratetype and remove
 * the smallest available page from the freelists
 */
static __always_inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	struct free_area *area;
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		area = &(zone->free_area[current_order]);
		page = get_page_from_free_area(area, migratetype);
		if (!page)
			continue;
		del_page_from_free_area(page, area);
		expand(zone, page, order, current_order, area, migratetype);
		set_pcppage_migratetype(page, migratetype);
		return page;
	}

	return NULL;
}


/*
 * This array describes the order lists are fallen back to when
 * the free lists for the desirable migrate type are depleted
 */
static int fallbacks[MIGRATE_TYPES][4] = {
	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE,   MIGRATE_TYPES },
	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE, MIGRATE_TYPES },
	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE,   MIGRATE_TYPES },
#ifdef CONFIG_CMA
	[MIGRATE_CMA]         = { MIGRATE_TYPES }, /* Never used */
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	[MIGRATE_ISOLATE]     = { MIGRATE_TYPES }, /* Never used */
#endif
};

#ifdef CONFIG_CMA
static __always_inline struct page *__rmqueue_cma_fallback(struct zone *zone,
					unsigned int order)
{
	return __rmqueue_smallest(zone, order, MIGRATE_CMA);
}
#else
static inline struct page *__rmqueue_cma_fallback(struct zone *zone,
					unsigned int order) { return NULL; }
#endif

/*
 * Move the free pages in a range to the free lists of the requested type.
 * Note that start_page and end_pages are not aligned on a pageblock
 * boundary. If alignment is required, use move_freepages_block()
 */
static int move_freepages(struct zone *zone,
			  struct page *start_page, struct page *end_page,
			  int migratetype, int *num_movable)
{
	struct page *page;
	unsigned int order;
	int pages_moved = 0;

	for (page = start_page; page <= end_page;) {
		if (!pfn_valid_within(page_to_pfn(page))) {
			page++;
			continue;
		}

		if (!PageBuddy(page)) {
			/*
			 * We assume that pages that could be isolated for
			 * migration are movable. But we don't actually try
			 * isolating, as that would be expensive.
			 */
			if (num_movable &&
					(PageLRU(page) || __PageMovable(page)))
				(*num_movable)++;

			page++;
			continue;
		}

		/* Make sure we are not inadvertently changing nodes */
		VM_BUG_ON_PAGE(page_to_nid(page) != zone_to_nid(zone), page);
		VM_BUG_ON_PAGE(page_zone(page) != zone, page);

		order = page_order(page);
		move_to_free_area(page, &zone->free_area[order], migratetype);
		page += 1 << order;
		pages_moved += 1 << order;
	}

	return pages_moved;
}

int move_freepages_block(struct zone *zone, struct page *page,
				int migratetype, int *num_movable)
{
	unsigned long start_pfn, end_pfn;
	struct page *start_page, *end_page;

	if (num_movable)
		*num_movable = 0;

	start_pfn = page_to_pfn(page);
	start_pfn = start_pfn & ~(pageblock_nr_pages-1);
	start_page = pfn_to_page(start_pfn);
	end_page = start_page + pageblock_nr_pages - 1;
	end_pfn = start_pfn + pageblock_nr_pages - 1;

	/* Do not cross zone boundaries */
	if (!zone_spans_pfn(zone, start_pfn))
		start_page = page;
	if (!zone_spans_pfn(zone, end_pfn))
		return 0;

	return move_freepages(zone, start_page, end_page, migratetype,
								num_movable);
}

static void change_pageblock_range(struct page *pageblock_page,
					int start_order, int migratetype)
{
	int nr_pageblocks = 1 << (start_order - pageblock_order);

	while (nr_pageblocks--) {
		set_pageblock_migratetype(pageblock_page, migratetype);
		pageblock_page += pageblock_nr_pages;
	}
}

/*
 * When we are falling back to another migratetype during allocation, try to
 * steal extra free pages from the same pageblocks to satisfy further
 * allocations, instead of polluting multiple pageblocks.
 *
 * If we are stealing a relatively large buddy page, it is likely there will
 * be more free pages in the pageblock, so try to steal them all. For
 * reclaimable and unmovable allocations, we steal regardless of page size,
 * as fragmentation caused by those allocations polluting movable pageblocks
 * is worse than movable allocations stealing from unmovable and reclaimable
 * pageblocks.
 */
static bool can_steal_fallback(unsigned int order, int start_mt)
{
	/*
	 * Leaving this order check is intended, although there is
	 * relaxed order check in next check. The reason is that
	 * we can actually steal whole pageblock if this condition met,
	 * but, below check doesn't guarantee it and that is just heuristic
	 * so could be changed anytime.
	 */
	if (order >= pageblock_order)
		return true;

	if (order >= pageblock_order / 2 ||
		start_mt == MIGRATE_RECLAIMABLE ||
		start_mt == MIGRATE_UNMOVABLE ||
		page_group_by_mobility_disabled)
		return true;

	return false;
}

static inline bool boost_watermark(struct zone *zone)
{
	unsigned long max_boost;

	if (!watermark_boost_factor)
		return false;
	/*
	 * Don't bother in zones that are unlikely to produce results.
	 * On small machines, including kdump capture kernels running
	 * in a small area, boosting the watermark can cause an out of
	 * memory situation immediately.
	 */
	if ((pageblock_nr_pages * 4) > zone_managed_pages(zone))
		return false;

	max_boost = mult_frac(zone->_watermark[WMARK_HIGH],
			watermark_boost_factor, 10000);

	/*
	 * high watermark may be uninitialised if fragmentation occurs
	 * very early in boot so do not boost. We do not fall
	 * through and boost by pageblock_nr_pages as failing
	 * allocations that early means that reclaim is not going
	 * to help and it may even be impossible to reclaim the
	 * boosted watermark resulting in a hang.
	 */
	if (!max_boost)
		return false;

	max_boost = max(pageblock_nr_pages, max_boost);

	zone->watermark_boost = min(zone->watermark_boost + pageblock_nr_pages,
		max_boost);

	return true;
}

/*
 * This function implements actual steal behaviour. If order is large enough,
 * we can steal whole pageblock. If not, we first move freepages in this
 * pageblock to our migratetype and determine how many already-allocated pages
 * are there in the pageblock with a compatible migratetype. If at least half
 * of pages are free or compatible, we can change migratetype of the pageblock
 * itself, so pages freed in the future will be put on the correct free list.
 */
static void steal_suitable_fallback(struct zone *zone, struct page *page,
		unsigned int alloc_flags, int start_type, bool whole_block)
{
	unsigned int current_order = page_order(page);
	struct free_area *area;
	int free_pages, movable_pages, alike_pages;
	int old_block_type;

	old_block_type = get_pageblock_migratetype(page);

	/*
	 * This can happen due to races and we want to prevent broken
	 * highatomic accounting.
	 */
	if (is_migrate_highatomic(old_block_type))
		goto single_page;

	/* Take ownership for orders >= pageblock_order */
	if (current_order >= pageblock_order) {
		change_pageblock_range(page, current_order, start_type);
		goto single_page;
	}

	/*
	 * Boost watermarks to increase reclaim pressure to reduce the
	 * likelihood of future fallbacks. Wake kswapd now as the node
	 * may be balanced overall and kswapd will not wake naturally.
	 */
	if (boost_watermark(zone) && (alloc_flags & ALLOC_KSWAPD))
		set_bit(ZONE_BOOSTED_WATERMARK, &zone->flags);

	/* We are not allowed to try stealing from the whole block */
	if (!whole_block)
		goto single_page;

	free_pages = move_freepages_block(zone, page, start_type,
						&movable_pages);
	/*
	 * Determine how many pages are compatible with our allocation.
	 * For movable allocation, it's the number of movable pages which
	 * we just obtained. For other types it's a bit more tricky.
	 */
	if (start_type == MIGRATE_MOVABLE) {
		alike_pages = movable_pages;
	} else {
		/*
		 * If we are falling back a RECLAIMABLE or UNMOVABLE allocation
		 * to MOVABLE pageblock, consider all non-movable pages as
		 * compatible. If it's UNMOVABLE falling back to RECLAIMABLE or
		 * vice versa, be conservative since we can't distinguish the
		 * exact migratetype of non-movable pages.
		 */
		if (old_block_type == MIGRATE_MOVABLE)
			alike_pages = pageblock_nr_pages
						- (free_pages + movable_pages);
		else
			alike_pages = 0;
	}

	/* moving whole block can fail due to zone boundary conditions */
	if (!free_pages)
		goto single_page;

	/*
	 * If a sufficient number of pages in the block are either free or of
	 * comparable migratability as our allocation, claim the whole block.
	 */
	if (free_pages + alike_pages >= (1 << (pageblock_order-1)) ||
			page_group_by_mobility_disabled)
		set_pageblock_migratetype(page, start_type);

	return;

single_page:
	area = &zone->free_area[current_order];
	move_to_free_area(page, area, start_type);
}

/*
 * Check whether there is a suitable fallback freepage with requested order.
 * If only_stealable is true, this function returns fallback_mt only if
 * we can steal other freepages all together. This would help to reduce
 * fragmentation due to mixed migratetype pages in one pageblock.
 */
int find_suitable_fallback(struct free_area *area, unsigned int order,
			int migratetype, bool only_stealable, bool *can_steal)
{
	int i;
	int fallback_mt;

	if (area->nr_free == 0)
		return -1;

	*can_steal = false;
	for (i = 0;; i++) {
		fallback_mt = fallbacks[migratetype][i];
		if (fallback_mt == MIGRATE_TYPES)
			break;

		if (free_area_empty(area, fallback_mt))
			continue;

		if (can_steal_fallback(order, migratetype))
			*can_steal = true;

		if (!only_stealable)
			return fallback_mt;

		if (*can_steal)
			return fallback_mt;
	}

	return -1;
}

/*
 * Reserve a pageblock for exclusive use of high-order atomic allocations if
 * there are no empty page blocks that contain a page with a suitable order
 */
// static void reserve_highatomic_pageblock(struct page *page, struct zone *zone,
// 				unsigned int alloc_order)
void reserve_highatomic_pageblock(struct page *page, struct zone *zone,
				unsigned int alloc_order)
{
	int mt;
	unsigned long max_managed, flags;

	/*
	 * Limit the number reserved to 1 pageblock or roughly 1% of a zone.
	 * Check is race-prone but harmless.
	 */
	max_managed = (zone_managed_pages(zone) / 100) + pageblock_nr_pages;
	if (zone->nr_reserved_highatomic >= max_managed)
		return;

	spin_lock_irqsave(&zone->lock, flags);

	/* Recheck the nr_reserved_highatomic limit under the lock */
	if (zone->nr_reserved_highatomic >= max_managed)
		goto out_unlock;

	/* Yoink! */
	mt = get_pageblock_migratetype(page);
	if (!is_migrate_highatomic(mt) && !is_migrate_isolate(mt)
	    && !is_migrate_cma(mt)) {
		zone->nr_reserved_highatomic += pageblock_nr_pages;
		set_pageblock_migratetype(page, MIGRATE_HIGHATOMIC);
		move_freepages_block(zone, page, MIGRATE_HIGHATOMIC, NULL);
	}

out_unlock:
	spin_unlock_irqrestore(&zone->lock, flags);
}

/*
 * Used when an allocation is about to fail under memory pressure. This
 * potentially hurts the reliability of high-order allocations when under
 * intense memory pressure but failed atomic allocations should be easier
 * to recover from than an OOM.
 *
 * If @force is true, try to unreserve a pageblock even though highatomic
 * pageblock is exhausted.
 */
static bool unreserve_highatomic_pageblock(const struct alloc_context *ac,
						bool force)
{
	struct zonelist *zonelist = ac->zonelist;
	unsigned long flags;
	struct zoneref *z;
	struct zone *zone;
	struct page *page;
	int order;
	bool ret;

	for_each_zone_zonelist_nodemask(zone, z, zonelist, ac->high_zoneidx,
								ac->nodemask) {
		/*
		 * Preserve at least one pageblock unless memory pressure
		 * is really high.
		 */
		if (!force && zone->nr_reserved_highatomic <=
					pageblock_nr_pages)
			continue;

		spin_lock_irqsave(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++) {
			struct free_area *area = &(zone->free_area[order]);

			page = get_page_from_free_area(area, MIGRATE_HIGHATOMIC);
			if (!page)
				continue;

			/*
			 * In page freeing path, migratetype change is racy so
			 * we can counter several free pages in a pageblock
			 * in this loop althoug we changed the pageblock type
			 * from highatomic to ac->migratetype. So we should
			 * adjust the count once.
			 */
			if (is_migrate_highatomic_page(page)) {
				/*
				 * It should never happen but changes to
				 * locking could inadvertently allow a per-cpu
				 * drain to add pages to MIGRATE_HIGHATOMIC
				 * while unreserving so be safe and watch for
				 * underflows.
				 */
				zone->nr_reserved_highatomic -= min(
						pageblock_nr_pages,
						zone->nr_reserved_highatomic);
			}

			/*
			 * Convert to ac->migratetype and avoid the normal
			 * pageblock stealing heuristics. Minimally, the caller
			 * is doing the work and needs the pages. More
			 * importantly, if the block was always converted to
			 * MIGRATE_UNMOVABLE or another type then the number
			 * of pageblocks that cannot be completely freed
			 * may increase.
			 */
			set_pageblock_migratetype(page, ac->migratetype);
			ret = move_freepages_block(zone, page, ac->migratetype,
									NULL);
			if (ret) {
				spin_unlock_irqrestore(&zone->lock, flags);
				return ret;
			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);
	}

	return false;
}

/*
 * Try finding a free buddy page on the fallback list and put it on the free
 * list of requested migratetype, possibly along with other pages from the same
 * block, depending on fragmentation avoidance heuristics. Returns true if
 * fallback was found so that __rmqueue_smallest() can grab it.
 *
 * The use of signed ints for order and current_order is a deliberate
 * deviation from the rest of this file, to make the for loop
 * condition simpler.
 */
static __always_inline bool
__rmqueue_fallback(struct zone *zone, int order, int start_migratetype,
						unsigned int alloc_flags)
{
	struct free_area *area;
	int current_order;
	int min_order = order;
	struct page *page;
	int fallback_mt;
	bool can_steal;

	/*
	 * Do not steal pages from freelists belonging to other pageblocks
	 * i.e. orders < pageblock_order. If there are no local zones free,
	 * the zonelists will be reiterated without ALLOC_NOFRAGMENT.
	 */
	if (alloc_flags & ALLOC_NOFRAGMENT)
		min_order = pageblock_order;

	/*
	 * Find the largest available free page in the other list. This roughly
	 * approximates finding the pageblock with the most free pages, which
	 * would be too costly to do exactly.
	 */
	for (current_order = MAX_ORDER - 1; current_order >= min_order;
				--current_order) {
		area = &(zone->free_area[current_order]);
		fallback_mt = find_suitable_fallback(area, current_order,
				start_migratetype, false, &can_steal);
		if (fallback_mt == -1)
			continue;

		/*
		 * We cannot steal all free pages from the pageblock and the
		 * requested migratetype is movable. In that case it's better to
		 * steal and split the smallest available page instead of the
		 * largest available page, because even if the next movable
		 * allocation falls back into a different pageblock than this
		 * one, it won't cause permanent fragmentation.
		 */
		if (!can_steal && start_migratetype == MIGRATE_MOVABLE
					&& current_order > order)
			goto find_smallest;

		goto do_steal;
	}

	return false;

find_smallest:
	for (current_order = order; current_order < MAX_ORDER;
							current_order++) {
		area = &(zone->free_area[current_order]);
		fallback_mt = find_suitable_fallback(area, current_order,
				start_migratetype, false, &can_steal);
		if (fallback_mt != -1)
			break;
	}

	/*
	 * This should not happen - we already found a suitable fallback
	 * when looking for the largest page.
	 */
	VM_BUG_ON(current_order == MAX_ORDER);

do_steal:
	page = get_page_from_free_area(area, fallback_mt);

	steal_suitable_fallback(zone, page, alloc_flags, start_migratetype,
								can_steal);

	//trace_mm_page_alloc_extfrag(page, order, current_order,
	//	start_migratetype, fallback_mt);

	return true;

}

#ifdef CONFIG_NUMA
/*
 * Called from the vmstat counter updater to drain pagesets of this
 * currently executing processor on remote nodes after they have
 * expired.
 *
 * Note that this function must be called with the thread pinned to
 * a single processor.
 */
void drain_zone_pages(struct zone *zone, struct per_cpu_pages *pcp)
{
	unsigned long flags;
	int to_drain, batch;

	local_irq_save(flags);
	batch = READ_ONCE(pcp->batch);
	to_drain = min(pcp->count, batch);
	if (to_drain > 0)
		free_pcppages_bulk(zone, to_drain, pcp);
	local_irq_restore(flags);
}
#endif

/*
 * Drain pcplists of the indicated processor and zone.
 *
 * The processor must either be the current processor and the
 * thread pinned to the current processor or a processor that
 * is not online.
 */
static void drain_pages_zone(unsigned int cpu, struct zone *zone)
{
	unsigned long flags;
	struct per_cpu_pageset *pset;
	struct per_cpu_pages *pcp;

	local_irq_save(flags);
	pset = per_cpu_ptr(zone->pageset, cpu);

	pcp = &pset->pcp;
	if (pcp->count)
		free_pcppages_bulk(zone, pcp->count, pcp);
	local_irq_restore(flags);
}

/*
 * Drain pcplists of all zones on the indicated processor.
 *
 * The processor must either be the current processor and the
 * thread pinned to the current processor or a processor that
 * is not online.
 */
static void drain_pages(unsigned int cpu)
{
	struct zone *zone;

	for_each_populated_zone(zone) {
		drain_pages_zone(cpu, zone);
	}
}

/*
 * Spill all of this CPU's per-cpu pages back into the buddy allocator.
 *
 * The CPU has to be pinned. When zone parameter is non-NULL, spill just
 * the single zone's pages.
 */
void drain_local_pages(struct zone *zone)
{
	int cpu = smp_processor_id();

	if (zone)
		drain_pages_zone(cpu, zone);
	else
		drain_pages(cpu);
}

static void drain_local_pages_wq(struct work_struct *work)
{
	struct pcpu_drain *drain;

	drain = container_of(work, struct pcpu_drain, work);

	/*
	 * drain_all_pages doesn't use proper cpu hotplug protection so
	 * we can race with cpu offline when the WQ can move this from
	 * a cpu pinned worker to an unbound one. We can operate on a different
	 * cpu which is allright but we also have to make sure to not move to
	 * a different one.
	 */
	preempt_disable();
	drain_local_pages(drain->zone);
	preempt_enable();
}

/*
 * Spill all the per-cpu pages from all CPUs back into the buddy allocator.
 *
 * When zone parameter is non-NULL, spill just the single zone's pages.
 *
 * Note that this can be extremely slow as the draining happens in a workqueue.
 */
void drain_all_pages(struct zone *zone)
{
	int cpu;

	/*
	 * Allocate in the BSS so we wont require allocation in
	 * direct reclaim path for CONFIG_CPUMASK_OFFSTACK=y
	 */
	static cpumask_t cpus_with_pcps;

	/*
	 * Make sure nobody triggers this path before mm_percpu_wq is fully
	 * initialized.
	 */
	if (WARN_ON_ONCE(!mm_percpu_wq))
		return;

	/*
	 * Do not drain if one is already in progress unless it's specific to
	 * a zone. Such callers are primarily CMA and memory hotplug and need
	 * the drain to be complete when the call returns.
	 */
	if (unlikely(!mutex_trylock(&pcpu_drain_mutex))) {
		if (!zone)
			return;
		mutex_lock(&pcpu_drain_mutex);
	}

	/*
	 * We don't care about racing with CPU hotplug event
	 * as offline notification will cause the notified
	 * cpu to drain that CPU pcps and on_each_cpu_mask
	 * disables preemption as part of its processing
	 */
	for_each_online_cpu(cpu) {
		struct per_cpu_pageset *pcp;
		struct zone *z;
		bool has_pcps = false;

		if (zone) {
			pcp = per_cpu_ptr(zone->pageset, cpu);
			if (pcp->pcp.count)
				has_pcps = true;
		} else {
			for_each_populated_zone(z) {
				pcp = per_cpu_ptr(z->pageset, cpu);
				if (pcp->pcp.count) {
					has_pcps = true;
					break;
				}
			}
		}

		if (has_pcps)
			cpumask_set_cpu(cpu, &cpus_with_pcps);
		else
			cpumask_clear_cpu(cpu, &cpus_with_pcps);
	}

	for_each_cpu(cpu, &cpus_with_pcps) {
		struct pcpu_drain *drain = per_cpu_ptr(&pcpu_drain, cpu);

		drain->zone = zone;
		INIT_WORK(&drain->work, drain_local_pages_wq);
		queue_work_on(cpu, mm_percpu_wq, &drain->work);
	}
	for_each_cpu(cpu, &cpus_with_pcps)
		flush_work(&per_cpu_ptr(&pcpu_drain, cpu)->work);

	mutex_unlock(&pcpu_drain_mutex);
}

#ifdef CONFIG_HIBERNATION

/*
 * Touch the watchdog for every WD_PAGE_COUNT pages.
 */
#define WD_PAGE_COUNT	(128*1024)

void mark_free_pages(struct zone *zone)
{
	unsigned long pfn, max_zone_pfn, page_count = WD_PAGE_COUNT;
	unsigned long flags;
	unsigned int order, t;
	struct page *page;

	if (zone_is_empty(zone))
		return;

	spin_lock_irqsave(&zone->lock, flags);

	max_zone_pfn = zone_end_pfn(zone);
	for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++)
		if (pfn_valid(pfn)) {
			page = pfn_to_page(pfn);

			if (!--page_count) {
				touch_nmi_watchdog();
				page_count = WD_PAGE_COUNT;
			}

			if (page_zone(page) != zone)
				continue;

			if (!swsusp_page_is_forbidden(page))
				swsusp_unset_page_free(page);
		}

	for_each_migratetype_order(order, t) {
		list_for_each_entry(page,
				&zone->free_area[order].free_list[t], lru) {
			unsigned long i;

			pfn = page_to_pfn(page);
			for (i = 0; i < (1UL << order); i++) {
				if (!--page_count) {
					touch_nmi_watchdog();
					page_count = WD_PAGE_COUNT;
				}
				swsusp_set_page_free(pfn_to_page(pfn + i));
			}
		}
	}
	spin_unlock_irqrestore(&zone->lock, flags);
}
#endif /* CONFIG_PM */

static bool free_unref_page_prepare(struct page *page, unsigned long pfn)
{
	int migratetype;

	if (!free_pcp_prepare(page))
		return false;

	migratetype = get_pfnblock_migratetype(page, pfn);
	set_pcppage_migratetype(page, migratetype);
	return true;
}

static void free_unref_page_commit(struct page *page, unsigned long pfn)
{
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	int migratetype;

	migratetype = get_pcppage_migratetype(page);
	__count_vm_event(PGFREE);

	/*
	 * We only track unmovable, reclaimable and movable on pcp lists.
	 * Free ISOLATE pages back to the allocator because they are being
	 * offlined but treat HIGHATOMIC as movable pages so we can get those
	 * areas back if necessary. Otherwise, we may have to free
	 * excessively into the page allocator
	 */
	if (migratetype >= MIGRATE_PCPTYPES) {
		if (unlikely(is_migrate_isolate(migratetype))) {
			free_one_page(zone, page, pfn, 0, migratetype);
			return;
		}
		migratetype = MIGRATE_MOVABLE;
	}

	pcp = &this_cpu_ptr(zone->pageset)->pcp;
	list_add(&page->lru, &pcp->lists[migratetype]);
	pcp->count++;
	if (pcp->count >= pcp->high) {
		unsigned long batch = READ_ONCE(pcp->batch);
		free_pcppages_bulk(zone, batch, pcp);
	}
}

/*
 * Free a 0-order page
 */
void free_unref_page(struct page *page)
{
	unsigned long flags;
	unsigned long pfn = page_to_pfn(page);

	if (!free_unref_page_prepare(page, pfn))
		return;

	local_irq_save(flags);
	free_unref_page_commit(page, pfn);
	local_irq_restore(flags);
}

/*
 * Free a list of 0-order pages
 */
void free_unref_page_list(struct list_head *list)
{
	struct page *page, *next;
	unsigned long flags, pfn;
	int batch_count = 0;

	/* Prepare pages for freeing */
	list_for_each_entry_safe(page, next, list, lru) {
		pfn = page_to_pfn(page);
		if (!free_unref_page_prepare(page, pfn))
			list_del(&page->lru);
		set_page_private(page, pfn);
	}

	local_irq_save(flags);
	list_for_each_entry_safe(page, next, list, lru) {
		unsigned long pfn = page_private(page);

		set_page_private(page, 0);
		//trace_mm_page_free_batched(page);
		free_unref_page_commit(page, pfn);

		/*
		 * Guard against excessive IRQ disabled times when we get
		 * a large list of pages to free.
		 */
		if (++batch_count == SWAP_CLUSTER_MAX) {
			local_irq_restore(flags);
			batch_count = 0;
			local_irq_save(flags);
		}
	}
	local_irq_restore(flags);
}

/*
 * split_page takes a non-compound higher-order page, and splits it into
 * n (1<<order) sub-pages: page[0..n]
 * Each sub-page must be freed individually.
 *
 * Note: this is probably too low level an operation for use in drivers.
 * Please consult with lkml before using this in your driver.
 */
void split_page(struct page *page, unsigned int order)
{
	int i;

	VM_BUG_ON_PAGE(PageCompound(page), page);
	VM_BUG_ON_PAGE(!page_count(page), page);

	for (i = 1; i < (1 << order); i++)
		set_page_refcounted(page + i);
	split_page_owner(page, 1 << order);
}

int __isolate_free_page(struct page *page, unsigned int order)
{
	struct free_area *area = &page_zone(page)->free_area[order];
	unsigned long watermark;
	struct zone *zone;
	int mt;

	BUG_ON(!PageBuddy(page));

	zone = page_zone(page);
	mt = get_pageblock_migratetype(page);

	if (!is_migrate_isolate(mt)) {
		/*
		 * Obey watermarks as if the page was being allocated. We can
		 * emulate a high-order watermark check with a raised order-0
		 * watermark, because we already know our high-order page
		 * exists.
		 */
		watermark = zone->_watermark[WMARK_MIN] + (1UL << order);
		if (!zone_watermark_ok(zone, 0, watermark, 0, ALLOC_CMA))
			return 0;

		__mod_zone_freepage_state(zone, -(1UL << order), mt);
	}

	/* Remove page from free list */

	del_page_from_free_area(page, area);

	/*
	 * Set the pageblock if the isolated page is at least half of a
	 * pageblock
	 */
	if (order >= pageblock_order - 1) {
		struct page *endpage = page + (1 << order) - 1;
		for (; page < endpage; page += pageblock_nr_pages) {
			int mt = get_pageblock_migratetype(page);
			if (!is_migrate_isolate(mt) && !is_migrate_cma(mt)
			    && !is_migrate_highatomic(mt))
				set_pageblock_migratetype(page,
							  MIGRATE_MOVABLE);
		}
	}


	return 1UL << order;
}

/*
 * Update NUMA hit/miss statistics
 *
 * Must be called with interrupts disabled.
 */
static inline void zone_statistics(struct zone *preferred_zone, struct zone *z)
{
#ifdef CONFIG_NUMA
	enum numa_stat_item local_stat = NUMA_LOCAL;

	/* skip numa counters update if numa stats is disabled */
	if (!static_branch_likely(&vm_numa_stat_key))
		return;

	if (zone_to_nid(z) != numa_node_id())
		local_stat = NUMA_OTHER;

	if (zone_to_nid(z) == zone_to_nid(preferred_zone))
		__inc_numa_state(z, NUMA_HIT);
	else {
		__inc_numa_state(z, NUMA_MISS);
		__inc_numa_state(preferred_zone, NUMA_FOREIGN);
	}
	__inc_numa_state(z, local_stat);
#endif
}

extern void reserve_highatomic_pageblock(struct page *page, struct zone *zone,
				unsigned int alloc_order);

extern struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags,
                                                const struct alloc_context *ac);

static inline enum zone_type scext4_gfp_zone(gfp_t flags)
{
	enum zone_type z;
	int bit = (__force int) (flags & GFP_ZONEMASK);

	z = (GFP_ZONE_TABLE >> (bit * GFP_ZONES_SHIFT)) &
					 ((1 << GFP_ZONES_SHIFT) - 1);
	VM_BUG_ON((GFP_ZONE_BAD >> bit) & 1);
	return z;
}

static inline struct page *
__alloc_pages_cpuset_fallback(gfp_t gfp_mask, unsigned int order,
			      unsigned int alloc_flags,
			      const struct alloc_context *ac)
{
	struct page *page;

	page = get_page_from_freelist(gfp_mask, order,
			alloc_flags|ALLOC_CPUSET, ac);
	/*
	 * fallback to ignore cpuset restriction if our nodes
	 * are depleted
	 */
	if (!page)
		page = get_page_from_freelist(gfp_mask, order,
				alloc_flags, ac);

	return page;
}

extern unsigned long scext4_try_to_free_pages(struct zonelist *zonelist, int order,
                                gfp_t gfp_mask, nodemask_t *nodemask);

/* Perform direct synchronous page reclaim */
static int
__perform_reclaim(gfp_t gfp_mask, unsigned int order,
					const struct alloc_context *ac)
{
	int progress;
	unsigned int noreclaim_flag;
	unsigned long pflags;
	
	cond_resched();

	/* We now go into synchronous reclaim */
	cpuset_memory_pressure_bump();
	psi_memstall_enter(&pflags);
	fs_reclaim_acquire(gfp_mask);
	noreclaim_flag = memalloc_noreclaim_save();
	
	progress = scext4_try_to_free_pages(ac->zonelist, order, gfp_mask,
								ac->nodemask);

	memalloc_noreclaim_restore(noreclaim_flag);
	fs_reclaim_release(gfp_mask);
	psi_memstall_leave(&pflags);

	cond_resched();

	return progress;
}

/* The really slow allocator path where we enter direct reclaim */
static inline struct page *
__alloc_pages_direct_reclaim(gfp_t gfp_mask, unsigned int order,
		unsigned int alloc_flags, const struct alloc_context *ac,
		unsigned long *did_some_progress)
{
	struct page *page = NULL;
	bool drained = false;

	*did_some_progress = __perform_reclaim(gfp_mask, order, ac);
	if (unlikely(!(*did_some_progress)))
		return NULL;

retry:
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);

	/*
	 * If an allocation failed after direct reclaim, it could be because
	 * pages are pinned on the per-cpu lists or in high alloc reserves.
	 * Shrink them them and try again
	 */
	if (!page && !drained) {
		unreserve_highatomic_pageblock(ac, false);
		drain_all_pages(NULL);
		drained = true;
		goto retry;
	}

	return page;
}

static void wake_all_kswapds(unsigned int order, gfp_t gfp_mask,
			     const struct alloc_context *ac)
{
	struct zoneref *z;
	struct zone *zone;
	pg_data_t *last_pgdat = NULL;
	enum zone_type high_zoneidx = ac->high_zoneidx;

	for_each_zone_zonelist_nodemask(zone, z, ac->zonelist, high_zoneidx,
					ac->nodemask) {
		if (last_pgdat != zone->zone_pgdat)
			wakeup_kswapd(zone, gfp_mask, order, high_zoneidx);
		last_pgdat = zone->zone_pgdat;
	}
}

static inline unsigned int
gfp_to_alloc_flags(gfp_t gfp_mask)
{
	unsigned int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;

	/* __GFP_HIGH is assumed to be the same as ALLOC_HIGH to save a branch. */
	BUILD_BUG_ON(__GFP_HIGH != (__force gfp_t) ALLOC_HIGH);

	/*
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (__GFP_ATOMIC) and ALLOC_HIGH (__GFP_HIGH).
	 */
	alloc_flags |= (__force int) (gfp_mask & __GFP_HIGH);

	if (gfp_mask & __GFP_ATOMIC) {
		/*
		 * Not worth trying to allocate harder for __GFP_NOMEMALLOC even
		 * if it can't schedule.
		 */
		if (!(gfp_mask & __GFP_NOMEMALLOC))
			alloc_flags |= ALLOC_HARDER;
		/*
		 * Ignore cpuset mems for GFP_ATOMIC rather than fail, see the
		 * comment for __cpuset_node_allowed().
		 */
		alloc_flags &= ~ALLOC_CPUSET;
	} else if (unlikely(rt_task(current)) && !in_interrupt())
		alloc_flags |= ALLOC_HARDER;

	if (gfp_mask & __GFP_KSWAPD_RECLAIM)
		alloc_flags |= ALLOC_KSWAPD;

#ifdef CONFIG_CMA
	if (gfpflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
#endif
	return alloc_flags;
}

static bool oom_reserves_allowed(struct task_struct *tsk)
{
	if (!tsk_is_oom_victim(tsk))
		return false;

	/*
	 * !MMU doesn't have oom reaper so give access to memory reserves
	 * only to the thread with TIF_MEMDIE set
	 */
	if (!IS_ENABLED(CONFIG_MMU) && !test_thread_flag(TIF_MEMDIE))
		return false;

	return true;
}


/*
 * Distinguish requests which really need access to full memory
 * reserves from oom victims which can live with a portion of it
 */
static inline int __gfp_pfmemalloc_flags(gfp_t gfp_mask)
{
	if (unlikely(gfp_mask & __GFP_NOMEMALLOC))
		return 0;
	if (gfp_mask & __GFP_MEMALLOC)
		return ALLOC_NO_WATERMARKS;
	if (in_serving_softirq() && (current->flags & PF_MEMALLOC))
		return ALLOC_NO_WATERMARKS;
	if (!in_interrupt()) {
		if (current->flags & PF_MEMALLOC)
			return ALLOC_NO_WATERMARKS;
		else if (oom_reserves_allowed(current))
			return ALLOC_OOM;
	}

	return 0;
}

bool gfp_pfmemalloc_allowed(gfp_t gfp_mask)
{
	return !!__gfp_pfmemalloc_flags(gfp_mask);
}

/*
 * Checks whether it makes sense to retry the reclaim to make a forward progress
 * for the given allocation request.
 *
 * We give up when we either have tried MAX_RECLAIM_RETRIES in a row
 * without success, or when we couldn't even meet the watermark if we
 * reclaimed all remaining pages on the LRU lists.
 *
 * Returns true if a retry is viable or false to enter the oom path.
 */
static inline bool
should_reclaim_retry(gfp_t gfp_mask, unsigned order,
		     struct alloc_context *ac, int alloc_flags,
		     bool did_some_progress, int *no_progress_loops)
{
	struct zone *zone;
	struct zoneref *z;
	bool ret = false;

	/*
	 * Costly allocations might have made a progress but this doesn't mean
	 * their order will become available due to high fragmentation so
	 * always increment the no progress counter for them
	 */
	if (did_some_progress && order <= PAGE_ALLOC_COSTLY_ORDER)
		*no_progress_loops = 0;
	else
		(*no_progress_loops)++;

	/*
	 * Make sure we converge to OOM if we cannot make any progress
	 * several times in the row.
	 */
	if (*no_progress_loops > MAX_RECLAIM_RETRIES) {
		/* Before OOM, exhaust highatomic_reserve */
		return unreserve_highatomic_pageblock(ac, true);
	}

	/*
	 * Keep reclaiming pages while there is a chance this will lead
	 * somewhere.  If none of the target zones can satisfy our allocation
	 * request even if all reclaimable pages are considered then we are
	 * screwed and have to go OOM.
	 */
	for_each_zone_zonelist_nodemask(zone, z, ac->zonelist, ac->high_zoneidx,
					ac->nodemask) {
		unsigned long available;
		unsigned long reclaimable;
		unsigned long min_wmark = min_wmark_pages(zone);
		bool wmark;

		available = reclaimable = zone_reclaimable_pages(zone);
		available += zone_page_state_snapshot(zone, NR_FREE_PAGES);

		/*
		 * Would the allocation succeed if we reclaimed all
		 * reclaimable pages?
		 */
		wmark = __zone_watermark_ok(zone, order, min_wmark,
				ac_classzone_idx(ac), alloc_flags, available);
		//trace_reclaim_retry_zone(z, order, reclaimable,
		//		available, min_wmark, *no_progress_loops, wmark);
		if (wmark) {
			/*
			 * If we didn't make any progress and have a lot of
			 * dirty + writeback pages then we should wait for
			 * an IO to complete to slow down the reclaim and
			 * prevent from pre mature OOM
			 */
			if (!did_some_progress) {
				unsigned long write_pending;

				write_pending = zone_page_state_snapshot(zone,
							NR_ZONE_WRITE_PENDING);

				if (2 * write_pending > reclaimable) {
					congestion_wait(BLK_RW_ASYNC, HZ/10);
					return true;
				}
			}

			ret = true;
			goto out;
		}
	}

out:
	/*
	 * Memory allocation/reclaim might be called from a WQ context and the
	 * current implementation of the WQ concurrency control doesn't
	 * recognize that a particular WQ is congested if the worker thread is
	 * looping without ever sleeping. Therefore we have to do a short sleep
	 * here rather than calling cond_resched().
	 */
	if (current->flags & PF_WQ_WORKER)
		schedule_timeout_uninterruptible(1);
	else
		cond_resched();
	return ret;
}

static inline bool
check_retry_cpuset(int cpuset_mems_cookie, struct alloc_context *ac)
{
	/*
	 * It's possible that cpuset's mems_allowed and the nodemask from
	 * mempolicy don't intersect. This should be normally dealt with by
	 * policy_nodemask(), but it's possible to race with cpuset update in
	 * such a way the check therein was true, and then it became false
	 * before we got our cpuset_mems_cookie here.
	 * This assumes that for all allocations, ac->nodemask can come only
	 * from MPOL_BIND mempolicy (whose documented semantics is to be ignored
	 * when it does not intersect with the cpuset restrictions) or the
	 * caller can deal with a violated nodemask.
	 */
	if (cpusets_enabled() && ac->nodemask &&
			!cpuset_nodemask_valid_mems_allowed(ac->nodemask)) {
		ac->nodemask = NULL;
		return true;
	}

	/*
	 * When updating a task's mems_allowed or mempolicy nodemask, it is
	 * possible to race with parallel threads in such a way that our
	 * allocation can fail while the mask is being updated. If we are about
	 * to fail, check if the cpuset changed during allocation and if so,
	 * retry.
	 */
	if (read_mems_allowed_retry(cpuset_mems_cookie))
		return true;

	return false;
}

extern inline struct page *
__alloc_pages_direct_compact(gfp_t gfp_mask, unsigned int order,
		unsigned int alloc_flags, const struct alloc_context *ac,
		enum compact_priority prio, enum compact_result *compact_result);

extern inline bool
should_compact_retry(struct alloc_context *ac, unsigned int order, int alloc_flags,
		     enum compact_result compact_result,
		     enum compact_priority *compact_priority,
		     int *compaction_retries);

extern inline struct page *
__alloc_pages_may_oom(gfp_t gfp_mask, unsigned int order,
	const struct alloc_context *ac, unsigned long *did_some_progress);

extern inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
		int preferred_nid, nodemask_t *nodemask,
		struct alloc_context *ac, gfp_t *alloc_mask,
		unsigned int *alloc_flags);

extern inline void finalise_ac(gfp_t gfp_mask, struct alloc_context *ac);

extern inline unsigned int
alloc_flags_nofragment(struct zone *zone, gfp_t gfp_mask);

static inline struct page *
__scext4_alloc_pages_slowpath(gfp_t gfp_mask, unsigned int order,
                                                struct alloc_context *ac)
{
	bool can_direct_reclaim = gfp_mask & __GFP_DIRECT_RECLAIM;
	const bool costly_order = order > PAGE_ALLOC_COSTLY_ORDER;
	struct page *page = NULL;
	unsigned int alloc_flags;
	unsigned long did_some_progress;
	enum compact_priority compact_priority;
	enum compact_result compact_result;
	int compaction_retries;
	int no_progress_loops;
	unsigned int cpuset_mems_cookie;
	int reserve_flags;

	/*
	 * We also sanity check to catch abuse of atomic reserves being used by
	 * callers that are not in atomic context.
	 */
	if (WARN_ON_ONCE((gfp_mask & (__GFP_ATOMIC|__GFP_DIRECT_RECLAIM)) ==
				(__GFP_ATOMIC|__GFP_DIRECT_RECLAIM)))
		gfp_mask &= ~__GFP_ATOMIC;

retry_cpuset:
	compaction_retries = 0;
	no_progress_loops = 0;
	compact_priority = DEF_COMPACT_PRIORITY;
	cpuset_mems_cookie = read_mems_allowed_begin();

	/*
	 * The fast path uses conservative alloc_flags to succeed only until
	 * kswapd needs to be woken up, and to avoid the cost of setting up
	 * alloc_flags precisely. So we do that now.
	 */
	alloc_flags = gfp_to_alloc_flags(gfp_mask);

	/*
	 * We need to recalculate the starting point for the zonelist iterator
	 * because we might have used different nodemask in the fast path, or
	 * there was a cpuset modification and we are retrying - otherwise we
	 * could end up iterating over non-eligible zones endlessly.
	 */
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->high_zoneidx, ac->nodemask);
	if (!ac->preferred_zoneref->zone)
		goto nopage;

	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	/*
	 * The adjusted alloc_flags might result in immediate success, so try
	 * that first
	 */
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	/*
	 * For costly allocations, try direct compaction first, as it's likely
	 * that we have enough base pages and don't need to reclaim. For non-
	 * movable high-order allocations, do that as well, as compaction will
	 * try prevent permanent fragmentation by migrating from blocks of the
	 * same migratetype.
	 * Don't try this for allocations that are allowed to ignore
	 * watermarks, as the ALLOC_NO_WATERMARKS attempt didn't yet happen.
	 */

	if (can_direct_reclaim &&
			(costly_order ||
			   (order > 0 && ac->migratetype != MIGRATE_MOVABLE))
			&& !gfp_pfmemalloc_allowed(gfp_mask)) {
		page = __alloc_pages_direct_compact(gfp_mask, order,
						alloc_flags, ac,
						INIT_COMPACT_PRIORITY,
						&compact_result);
		if (page)
			goto got_pg;

		 if (order >= pageblock_order && (gfp_mask & __GFP_IO) &&
		     !(gfp_mask & __GFP_RETRY_MAYFAIL)) {
			/*
			 * If allocating entire pageblock(s) and compaction
			 * failed because all zones are below low watermarks
			 * or is prohibited because it recently failed at this
			 * order, fail immediately unless the allocator has
			 * requested compaction and reclaim retry.
			 *
			 * Reclaim is
			 *  - potentially very expensive because zones are far
			 *    below their low watermarks or this is part of very
			 *    bursty high order allocations,
			 *  - not guaranteed to help because isolate_freepages()
			 *    may not iterate over freed pages as part of its
			 *    linear scan, and
			 *  - unlikely to make entire pageblocks free on its
			 *    own.
			 */
			if (compact_result == COMPACT_SKIPPED ||
			    compact_result == COMPACT_DEFERRED)
				goto nopage;
		 }

		/*
		 * Checks for costly allocations with __GFP_NORETRY, which
		 * includes THP page fault allocations
		 */
		if (costly_order && (gfp_mask & __GFP_NORETRY)) {
			/*
			 * If compaction is deferred for high-order allocations,
			 * it is because sync compaction recently failed. If
			 * this is the case and the caller requested a THP
			 * allocation, we do not want to heavily disrupt the
			 * system, so we fail the allocation instead of entering
			 * direct reclaim.
			 */
			if (compact_result == COMPACT_DEFERRED)
				 goto nopage;

			/*
			 * Looks like reclaim/compaction is worth trying, but
			 * sync compaction could be very expensive, so keep
			 * using async compaction.
			 */
			compact_priority = INIT_COMPACT_PRIORITY;
		}
	}

retry:
	/* Ensure kswapd doesn't accidentally go to sleep as long as we loop */
	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	reserve_flags = __gfp_pfmemalloc_flags(gfp_mask);
	if (reserve_flags)
		alloc_flags = reserve_flags;

	/*
	 * Reset the nodemask and zonelist iterators if memory policies can be
	 * ignored. These allocations are high priority and system rather than
	 * user oriented.
	 */
	if (!(alloc_flags & ALLOC_CPUSET) || reserve_flags) {
		ac->nodemask = NULL;
		ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
				ac->high_zoneidx, ac->nodemask);
	}

	/* Attempt with potentially adjusted zonelist and alloc_flags */
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	/* Caller is not willing to reclaim, we can't balance anything */
	if (!can_direct_reclaim)
		goto nopage;

	/* Avoid recursion of direct reclaim */
	if (current->flags & PF_MEMALLOC)
		goto nopage;

	/* Try direct reclaim and then allocating */
	page = __alloc_pages_direct_reclaim(gfp_mask, order, alloc_flags, ac,
							&did_some_progress);
	if (page)
		goto got_pg;

	/* Try direct compaction and then allocating */
	page = __alloc_pages_direct_compact(gfp_mask, order, alloc_flags, ac,
					compact_priority, &compact_result);
	if (page)
		goto got_pg;

	/* Do not loop if specifically requested */
	if (gfp_mask & __GFP_NORETRY)
		goto nopage;

	/*
	 * Do not retry costly high order allocations unless they are
	 * __GFP_RETRY_MAYFAIL
	 */
	if (costly_order && !(gfp_mask & __GFP_RETRY_MAYFAIL))
		goto nopage;

	if (should_reclaim_retry(gfp_mask, order, ac, alloc_flags,
				did_some_progress > 0, &no_progress_loops))
		goto retry;

	/*
	 * It doesn't make any sense to retry for the compaction if the order-0
	 * reclaim is not able to make any progress because the current
	 * implementation of the compaction depends on the sufficient amount
	 * of free memory (see __compaction_suitable)
	 */
	if (did_some_progress > 0 &&
			should_compact_retry(ac, order, alloc_flags,
				compact_result, &compact_priority,
				&compaction_retries))
		goto retry;


	/* Deal with possible cpuset update races before we start OOM killing */
	if (check_retry_cpuset(cpuset_mems_cookie, ac))
		goto retry_cpuset;

	/* Reclaim has failed us, start killing things */
	page = __alloc_pages_may_oom(gfp_mask, order, ac, &did_some_progress);
	if (page)
		goto got_pg;

	/* Avoid allocations with no watermarks from looping endlessly */
	if (tsk_is_oom_victim(current) &&
	    (alloc_flags == ALLOC_OOM ||
	     (gfp_mask & __GFP_NOMEMALLOC)))
		goto nopage;

	/* Retry as long as the OOM killer is making progress */
	if (did_some_progress) {
		no_progress_loops = 0;
		goto retry;
	}

nopage:
	/* Deal with possible cpuset update races before we fail */
	if (check_retry_cpuset(cpuset_mems_cookie, ac))
		goto retry_cpuset;

	/*
	 * Make sure that __GFP_NOFAIL request doesn't leak out and make sure
	 * we always retry
	 */
	if (gfp_mask & __GFP_NOFAIL) {
		/*
		 * All existing users of the __GFP_NOFAIL are blockable, so warn
		 * of any new users that actually require GFP_NOWAIT
		 */
		if (WARN_ON_ONCE(!can_direct_reclaim))
			goto fail;

		/*
		 * PF_MEMALLOC request from this context is rather bizarre
		 * because we cannot reclaim anything and only can loop waiting
		 * for somebody to do a work for us
		 */
		WARN_ON_ONCE(current->flags & PF_MEMALLOC);

		/*
		 * non failing costly orders are a hard requirement which we
		 * are not prepared for much so let's warn about these users
		 * so that we can identify them and convert them to something
		 * else.
		 */
		WARN_ON_ONCE(order > PAGE_ALLOC_COSTLY_ORDER);

		/*
		 * Help non-failing allocations by giving them access to memory
		 * reserves but do not use ALLOC_NO_WATERMARKS because this
		 * could deplete whole memory reserves which would just make
		 * the situation worse
		 */
		page = __alloc_pages_cpuset_fallback(gfp_mask, order, ALLOC_HARDER, ac);
		if (page)
			goto got_pg;

		cond_resched();
		goto retry;
	}
fail:
	warn_alloc(gfp_mask, ac->nodemask,
			"page allocation failure: order:%u", order);
got_pg:
	return page;
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page *
__scext4_alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order, int preferred_nid,
							nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_mask; /* The gfp_t that was actually used for allocation */
	struct alloc_context ac = { };

	/*
	 * There are several places where we assume that the order value is sane
	 * so bail out early if the request is out of bound.
	 */
	if (unlikely(order >= MAX_ORDER)) {
		WARN_ON_ONCE(!(gfp_mask & __GFP_NOWARN));
		return NULL;
	}

	gfp_mask &= gfp_allowed_mask;
	alloc_mask = gfp_mask;
	if (!prepare_alloc_pages(gfp_mask, order, preferred_nid, nodemask, &ac, &alloc_mask, &alloc_flags))
		return NULL;
	
	finalise_ac(gfp_mask, &ac);

	/*
	 * Forbid the first pass from falling back to types that fragment
	 * memory until all local zones are considered.
	 */
	alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp_mask);

	/* First allocation attempt */
	page = get_page_from_freelist(alloc_mask, order, alloc_flags, &ac);
	if (likely(page))
		goto out;

	/*
	 * Apply scoped allocation constraints. This is mainly about GFP_NOFS
	 * resp. GFP_NOIO which has to be inherited for all allocation requests
	 * from a particular context which has been marked by
	 * memalloc_no{fs,io}_{save,restore}.
	 */
	alloc_mask = current_gfp_context(gfp_mask);
	ac.spread_dirty_pages = false;

	/*
	 * Restore the original nodemask if it was potentially replaced with
	 * &cpuset_current_mems_allowed to optimize the fast-path attempt.
	 */
	if (unlikely(ac.nodemask != nodemask))
		ac.nodemask = nodemask;

	page = __scext4_alloc_pages_slowpath(alloc_mask, order, &ac);

out:
	if (memcg_kmem_enabled() && (gfp_mask & __GFP_ACCOUNT) && page &&
	    unlikely(__memcg_kmem_charge(page, gfp_mask, order) != 0)) {
		__free_pages(page, order);
		page = NULL;
	}

	//trace_mm_page_alloc(page, order, alloc_mask, ac.migratetype);

	return page;
}
