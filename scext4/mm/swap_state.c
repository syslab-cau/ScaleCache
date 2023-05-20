// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>
#include <linux/vmalloc.h>
#include <linux/swap_slots.h>
#include <linux/huge_mm.h>

#include <asm/pgtable.h>
#include "internal.h"

#include "../lf_xarray/lf_xarray.h"

#if 0
#define ADD_CACHE_INFO(x, nr)	do { swap_cache_info.x += (nr); } while (0)

extern struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
} swap_cache_info;
#endif
#define ADD_CACHE_INFO(x, nr)	do {  } while (0)

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache.
 */
void __scext4_delete_from_swap_cache(struct page *page, swp_entry_t entry)
{
	struct address_space *address_space = swap_address_space(entry);
	int i, nr = hpage_nr_pages(page);
	pgoff_t idx = swp_offset(entry);
	LF_XA_STATE(xas, &address_space->i_pages, idx);

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(PageWriteback(page), page);

	for (i = 0; i < nr; i++) {
		void *entry = lf_xas_store(&xas, NULL);
		VM_BUG_ON_PAGE(entry != page, entry);
		set_page_private(page + i, 0);
		lf_xas_next(&xas);
	}
	ClearPageSwapCache(page);
	address_space->nrpages -= nr;
	__mod_node_page_state(page_pgdat(page), NR_FILE_PAGES, -nr);
	ADD_CACHE_INFO(del_total, nr);
}
