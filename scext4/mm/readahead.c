// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/readahead.c - address_space-level file readahead.
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 09Apr2002	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/pagevec.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/mm_inline.h>
#include <linux/blk-cgroup.h>
#include <linux/fadvise.h>

#include "internal.h"

#include <linux/cc_xarray.h>

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 */
void
scext4_file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
	ra->ra_pages = inode_to_bdi(mapping->host)->ra_pages;
	ra->prev_pos = -1;
}
//EXPORT_SYMBOL_GPL(file_ra_state_init);

/*
 * see if a page needs releasing upon read_cache_pages() failure
 * - the caller of read_cache_pages() may have set PG_private or PG_fscache
 *   before calling, such as the NFS fs marking pages that are cached locally
 *   on disk, thus we need to give the fs a chance to clean up in the event of
 *   an error
 */
static void read_cache_pages_invalidate_page(struct address_space *mapping,
					     struct page *page)
{
	if (page_has_private(page)) {
		if (!trylock_page(page))
			BUG();
		page->mapping = mapping;
		do_invalidatepage(page, 0, PAGE_SIZE);
		page->mapping = NULL;
		unlock_page(page);
	}
	put_page(page);
}

/*
 * release a list of pages, invalidating them first if need be
 */
static void read_cache_pages_invalidate_pages(struct address_space *mapping,
					      struct list_head *pages)
{
	struct page *victim;

	while (!list_empty(pages)) {
		victim = lru_to_page(pages);
		list_del(&victim->lru);
		read_cache_pages_invalidate_page(mapping, victim);
	}
}


