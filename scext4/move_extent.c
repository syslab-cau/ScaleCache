// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) 2008,2009 NEC Software Tohoku, Ltd.
 * Written by Takashi Sato <t-sato@yk.jp.nec.com>
 *            Akira Fujita <a-fujita@rs.jp.nec.com>
 */

#include <linux/fs.h>
#include <linux/quotaops.h>
#include <linux/slab.h>
#include "scext4_jbd3.h"
#include "scext4.h"
#include "scext4_extents.h"

/**
 * get_ext_path() - Find an extent path for designated logical block number.
 * @inode:	inode to be searched
 * @lblock:	logical block number to find an extent path
 * @ppath:	pointer to an extent path pointer (for output)
 *
 * scext4_find_extent wrapper. Return 0 on success, or a negative error value
 * on failure.
 */
static inline int
get_ext_path(struct inode *inode, scext4_lblk_t lblock,
		struct scext4_ext_path **ppath)
{
	struct scext4_ext_path *path;

	path = scext4_find_extent(inode, lblock, ppath, SCEXT4_EX_NOCACHE);
	if (IS_ERR(path))
		return PTR_ERR(path);
	if (path[ext_depth(inode)].p_ext == NULL) {
		scext4_ext_drop_refs(path);
		kfree(path);
		*ppath = NULL;
		return -ENODATA;
	}
	*ppath = path;
	return 0;
}

/**
 * scext4_double_down_write_data_sem() - write lock two inodes's i_data_sem
 * @first: inode to be locked
 * @second: inode to be locked
 *
 * Acquire write lock of i_data_sem of the two inodes
 */
void
scext4_double_down_write_data_sem(struct inode *first, struct inode *second)
{
	if (first < second) {
		down_write(&SCEXT4_I(first)->i_data_sem);
		down_write_nested(&SCEXT4_I(second)->i_data_sem, I_DATA_SEM_OTHER);
	} else {
		down_write(&SCEXT4_I(second)->i_data_sem);
		down_write_nested(&SCEXT4_I(first)->i_data_sem, I_DATA_SEM_OTHER);

	}
}

/**
 * scext4_double_up_write_data_sem - Release two inodes' write lock of i_data_sem
 *
 * @orig_inode:		original inode structure to be released its lock first
 * @donor_inode:	donor inode structure to be released its lock second
 * Release write lock of i_data_sem of two inodes (orig and donor).
 */
void
scext4_double_up_write_data_sem(struct inode *orig_inode,
			      struct inode *donor_inode)
{
	up_write(&SCEXT4_I(orig_inode)->i_data_sem);
	up_write(&SCEXT4_I(donor_inode)->i_data_sem);
}

/**
 * mext_check_coverage - Check that all extents in range has the same type
 *
 * @inode:		inode in question
 * @from:		block offset of inode
 * @count:		block count to be checked
 * @unwritten:		extents expected to be unwritten
 * @err:		pointer to save error value
 *
 * Return 1 if all extents in range has expected type, and zero otherwise.
 */
static int
mext_check_coverage(struct inode *inode, scext4_lblk_t from, scext4_lblk_t count,
		    int unwritten, int *err)
{
	struct scext4_ext_path *path = NULL;
	struct scext4_extent *ext;
	int ret = 0;
	scext4_lblk_t last = from + count;
	while (from < last) {
		*err = get_ext_path(inode, from, &path);
		if (*err)
			goto out;
		ext = path[ext_depth(inode)].p_ext;
		if (unwritten != scext4_ext_is_unwritten(ext))
			goto out;
		from += scext4_ext_get_actual_len(ext);
		scext4_ext_drop_refs(path);
	}
	ret = 1;
out:
	scext4_ext_drop_refs(path);
	kfree(path);
	return ret;
}

/**
 * mext_page_double_lock - Grab and lock pages on both @inode1 and @inode2
 *
 * @inode1:	the inode structure
 * @inode2:	the inode structure
 * @index1:	page index
 * @index2:	page index
 * @page:	result page vector
 *
 * Grab two locked pages for inode's by inode order
 */
static int
mext_page_double_lock(struct inode *inode1, struct inode *inode2,
		      pgoff_t index1, pgoff_t index2, struct page *page[2])
{
	struct address_space *mapping[2];
	unsigned fl = AOP_FLAG_NOFS;

	BUG_ON(!inode1 || !inode2);
	if (inode1 < inode2) {
		mapping[0] = inode1->i_mapping;
		mapping[1] = inode2->i_mapping;
	} else {
		swap(index1, index2);
		mapping[0] = inode2->i_mapping;
		mapping[1] = inode1->i_mapping;
	}

	page[0] = grab_cache_page_write_begin(mapping[0], index1, fl);
	if (!page[0])
		return -ENOMEM;

	page[1] = grab_cache_page_write_begin(mapping[1], index2, fl);
	if (!page[1]) {
		unlock_page(page[0]);
		put_page(page[0]);
		return -ENOMEM;
	}
	/*
	 * grab_cache_page_write_begin() may not wait on page's writeback if
	 * BDI not demand that. But it is reasonable to be very conservative
	 * here and explicitly wait on page's writeback
	 */
	wait_on_page_writeback(page[0]);
	wait_on_page_writeback(page[1]);
	if (inode1 > inode2)
		swap(page[0], page[1]);

	return 0;
}

/* Force page buffers uptodate w/o dropping page's lock */
static int
mext_page_mkuptodate(struct page *page, unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	sector_t block;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize, block_start, block_end;
	int i, err,  nr = 0, partial = 0;
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (PageUptodate(page)) // ziggy: data in page and disk are the same
		return 0;

	blocksize = i_blocksize(inode);
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	head = page_buffers(page);
	// ziggy: the logical block that we used to generate the page index
	block = (sector_t)page->index << (PAGE_SHIFT - inode->i_blkbits);
	for (bh = head, block_start = 0; bh != head || !block_start;
	     block++, block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
			continue;
		}
		if (buffer_uptodate(bh))
			continue;
		if (!buffer_mapped(bh)) {
			err = scext4_get_block(inode, block, bh, 0);
			if (err) {
				SetPageError(page);
				return err;
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, block_start, blocksize);
				set_buffer_uptodate(bh);
				continue;
			}
		}
		BUG_ON(nr >= MAX_BUF_PER_PAGE);
		arr[nr++] = bh;
	}
	/* No io required */
	if (!nr)
		goto out;

	// ziggy: bh in arr[] are blocks that do not in memory.
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (!bh_uptodate_or_lock(bh)) {
			err = bh_submit_read(bh);
			if (err)
				return err;
		}
	}
out:
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

/* Force page buffers uptodate w/o dropping page's lock */
static int
mext_page_mkuptodate_nowait(struct page *page, unsigned from, unsigned to,
							struct buffer_head **bhpp, int *idx)
{
	struct inode *inode = page->mapping->host;
	sector_t block;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize, block_start, block_end;
	int i, err,  nr = 0, partial = 0;
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (PageUptodate(page)) // ziggy: data in page and disk are the same
		return 0;

	blocksize = i_blocksize(inode);
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	head = page_buffers(page);
	// ziggy: the logical block that we used to generate the page index
	block = (sector_t)page->index << (PAGE_SHIFT - inode->i_blkbits);
	for (bh = head, block_start = 0; bh != head || !block_start;
	     block++, block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
			continue;
		}
		if (buffer_uptodate(bh))
			continue;
		if (!buffer_mapped(bh)) {
			err = scext4_get_block(inode, block, bh, 0);
			if (err) {
				SetPageError(page);
				return err;
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, block_start, blocksize);
				set_buffer_uptodate(bh);
				continue;
			}
		}
		BUG_ON(nr >= MAX_BUF_PER_PAGE);
		arr[nr++] = bh;
	}
	/* No io required */
	if (!nr)
		goto out;

	// ziggy: bh in arr[] are blocks that do not in memory.
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (!bh_uptodate_or_lock(bh)) {
			BUG_ON(!buffer_locked(bh));

			if (buffer_uptodate(bh)) {
				unlock_buffer(bh);
				//return 0;
				continue;
			}

			get_bh(bh);
			bh->b_end_io = end_buffer_read_sync;
			submit_bh(REQ_OP_READ, 0, bh);

			bhpp[*idx] = bh;
			(*idx)++;

			if (err)
				return err;
		}
	}
out:
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

/**
 * move_extent_all_page - Move extent data in one time
 *
 * @o_filp:			file structure of original file
 * @donor_inode:		donor inode
 * @orig_page_offset:		page index on original file
 * @donor_page_offset:		page index on donor file
 * @data_offset_in_page:	block index where data swapping starts
 * @block_len_in_page:		the number of blocks to be swapped
 * @unwritten:			orig extent is unwritten or not
 * @err:			pointer to save return value
 *
 * Save the data in original inode blocks and replace original inode extents
 * with donor inode extents by calling scext4_swap_extents().
 * Finally, write out the saved data in new original inode blocks. Return
 * replaced block count.
 */
static int
move_extent_all_page(struct file *o_filp, struct inode *donor_inode,
					 scext4_lblk_t o_start, scext4_lblk_t o_end,
					 scext4_lblk_t d_start,
	//	     pgoff_t orig_page_offset, pgoff_t donor_page_offset,
		     //int data_offset_in_page,
					 //int block_len_in_page,
					 int *err)
{
	struct inode *orig_inode = file_inode(o_filp);
	//struct page *pagep[2] = {NULL, NULL};
	handle_t *handle;
	//scext4_lblk_t orig_blk_offset, donor_blk_offset;
	unsigned long blocksize = orig_inode->i_sb->s_blocksize;
	unsigned int tmp_data_size, data_size, replaced_size;
	int i, err2, jblocks, retries = 0;
	int replaced_count = 0;
	//int from = data_offset_in_page << orig_inode->i_blkbits;
	int blocks_per_page = PAGE_SIZE >> orig_inode->i_blkbits;
	struct super_block *sb = orig_inode->i_sb;
	struct buffer_head *bh = NULL;
	/////////////////////////////////////////////////////////
	struct scext4_extent *ex;  // ziggy: extent on-disk structure
	int unwritten;

	struct scext4_ext_path *path = NULL;
	int ret;
	int num_pages;
	struct page **pagepp;
	struct buffer_head **bhpp;
	int idx_pagepp;
	int idx_bhpp;

	scext4_lblk_t orig_start = o_start;

	//ziggy: only works for one block per page
	BUG_ON(blocks_per_page != 1);

	ret = get_ext_path(orig_inode, o_start, &path);
	if (ret)
		goto free_path;
	ex = path[path->p_depth].p_ext;  // ziggy: extent of target file
	unwritten = scext4_ext_is_unwritten(ex);

	// ziggy: prealloc array for pages to read
	//        this is ok, because in our system, page and block both are 4kb,
	//        number_pages is accurate.
	num_pages = (o_end - o_start) / blocks_per_page;
	pagepp = (struct page **)kmalloc(sizeof(struct page *) * num_pages, GFP_KERNEL);
	// TODO: ugly, only works for 4kb pages and blocks
	bhpp = (struct buffer_head **)kmalloc(sizeof(struct buffer_head *) * num_pages, GFP_KERNEL);

	*err = 0;
	jblocks = scext4_writepage_trans_blocks(orig_inode) * num_pages;  // num_pages is also the number of blks
	handle = scext4_journal_start(orig_inode, SCEXT4_HT_MOVE_EXTENTS, jblocks);
	if (IS_ERR(handle)) {
		*err = PTR_ERR(handle);
		//return 0;
		goto stop_journal;
	}

	/*
	 * Current extent is preallocated, which is empty.
	 * We do not need move data, simply change the mapping relation
	 * is enough.
	 */
	int num_total_blk = num_pages * blocks_per_page;  // actually we can only handle num_blks == num_pages
	if (unwritten) {
		scext4_double_down_write_data_sem(orig_inode, donor_inode);

		replaced_count = scext4_swap_extents(handle, orig_inode, donor_inode,
							o_start, d_start,
						num_total_blk, 1, err);

		scext4_double_up_write_data_sem(orig_inode, donor_inode);
		goto stop_journal;
	}

	idx_pagepp = 0;
	while (o_start < o_end) {  // ziggy: get page by index. From inode or from page cache
		scext4_lblk_t cur_blk, next_blk;
		pgoff_t orig_page_index, donor_page_index;
		int offset_in_page;
		int unwritten, cur_len;

		ret = get_ext_path(orig_inode, o_start, &path);
		if (ret)
			goto unlock_pages;
		ex = path[path->p_depth].p_ext;  // ziggy: extent of target file
		next_blk = scext4_ext_next_allocated_block(path);
		cur_blk = le32_to_cpu(ex->ee_block);  // ziggy: start logical blocks
		cur_len = scext4_ext_get_actual_len(ex);
		/* Check hole before the start pos */
		if (cur_blk + cur_len - 1 < o_start) {
			if (next_blk == EXT_MAX_BLOCKS) {
				o_start = o_end;
				ret = -ENODATA;
				goto unlock_pages;
			}
			d_start += next_blk - o_start;
			o_start = next_blk;
			continue;
		/* Check hole after the start pos */
		} else if (cur_blk > o_start) {
			/* Skip hole */
			d_start += cur_blk - o_start;
			o_start = cur_blk;
			/* Extent inside requested range ?*/
			if (cur_blk >= o_end)
				goto unlock_pages;
		} else { /* in_range(o_start, o_blk, o_len) */
			cur_len += cur_blk - o_start;
		}

		if (o_end - o_start < cur_len)
			cur_len = o_end - o_start;

		orig_page_index = o_start >> (PAGE_SHIFT -
					       orig_inode->i_blkbits);
		donor_page_index = d_start >> (PAGE_SHIFT -
					       donor_inode->i_blkbits);
		offset_in_page = o_start % blocks_per_page;
		if (cur_len > blocks_per_page- offset_in_page)
			cur_len = blocks_per_page - offset_in_page;  // ziggy: length must less than a page, in our situation, one block per page.

		struct address_space *mapping = orig_inode->i_mapping;
		pagepp[idx_pagepp] = grab_cache_page_write_begin(mapping, orig_page_index, AOP_FLAG_NOFS);
		wait_on_page_writeback(pagepp[idx_pagepp]);
		if (!pagepp[idx_pagepp]) {
			idx_pagepp++;  // to simplify the code, even error happends idx still point to next free slot
			goto unlock_pages;  // TODO need other cleaning part, like stop_journal
		}
		idx_pagepp++;

		o_start += cur_len;
		d_start += cur_len;
	}

	//int bsize = 1 << orig_inode->i_blkbits;  // TODO: ugly. only work for 4kb blocks and pages
	idx_bhpp = 0;
	//for (i = 0; i < num_pages; i++) {
	for (i = 0; i < idx_pagepp; i++) {
		*err = mext_page_mkuptodate_nowait(pagepp[i], 0, blocksize, bhpp, &idx_bhpp);
		if (*err)
			goto unlock_pages;
	}
	// wait
	for (i = 0; i < idx_bhpp; i++) {
			wait_on_buffer(bhpp[i]);
			if (buffer_uptodate(bhpp[i]))
				continue;
	}

	/* At this point all buffers in range are uptodate, old mapping layout
	 * is no longer required, try to drop it now. */
	for (i = 0; i < num_pages; i++) {
		if (page_has_private(pagepp[i]) && !try_to_release_page(pagepp[i], 0)) {
			*err = -EBUSY;
			goto unlock_pages;
		}
	}

	scext4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = scext4_swap_extents(handle, orig_inode, donor_inode,
					       orig_start, orig_start,
					  num_total_blk, 1, err);
	scext4_double_up_write_data_sem(orig_inode, donor_inode);
	if (*err) {
		if (replaced_count) {
			replaced_size = replaced_count << orig_inode->i_blkbits;
		} else
			goto unlock_pages;
	}

	// ziggy: debug
	//printk("defrag: num_pages = %d\n", num_pages);
	//printk("defrag: idx_pagepp = %d\n", idx_pagepp);
	//printk("defrag: idx_bhpp = %d\n\n", idx_bhpp);

	/* Perform all necessary steps similar write_begin()/write_end()
	 * but keeping in mind that i_size will not change */
	for (i = 0; i < num_pages; i++) {
		//debug
		//printk("defrag: round %d.\n", i);

		if (!page_has_buffers(pagepp[i]))
			create_empty_buffers(pagepp[i], 1 << orig_inode->i_blkbits, 0);
		bh = page_buffers(pagepp[i]);
		//debug
		//printk("defrag: round %d, get bh.\n", i);

		//for (i = 0; i < data_offset_in_page; i++)
		//	bh = bh->b_this_page;
		//for (i = 0; i < blocks_per_page; i++) {
			//*err = scext4_get_block(orig_inode, i, bh, 0);
			*err = scext4_get_block(orig_inode, 0, bh, 0);
			if (*err < 0)
				break;
			bh = bh->b_this_page;
		//}
		if (!*err)
			*err = block_commit_write(pagepp[i], 0, blocksize);
	}
	*err = scext4_jbd3_inode_add_write(handle, orig_inode,
			(loff_t)orig_start << PAGE_SHIFT, replaced_count << orig_inode->i_blkbits);

unlock_pages:
	for (i = 0; i < idx_pagepp; i++) {
		unlock_page(pagepp[i]);
		put_page(pagepp[i]);
	}
stop_journal:  // last goto
	scext4_journal_stop(handle);
	//return replaced_count;
free_arr:
	kfree(pagepp);
	kfree(bhpp);
free_path:
	scext4_ext_drop_refs(path);
	kfree(path);
	//scext4_double_up_write_data_sem(orig_inode, donor_inode);
	//unlock_two_nondirectories(orig_inode, donor_inode);
	return replaced_count;
}

/**
 * move_extent_per_page - Move extent data per page
 *
 * @o_filp:			file structure of original file
 * @donor_inode:		donor inode
 * @orig_page_offset:		page index on original file
 * @donor_page_offset:		page index on donor file
 * @data_offset_in_page:	block index where data swapping starts
 * @block_len_in_page:		the number of blocks to be swapped
 * @unwritten:			orig extent is unwritten or not
 * @err:			pointer to save return value
 *
 * Save the data in original inode blocks and replace original inode extents
 * with donor inode extents by calling scext4_swap_extents().
 * Finally, write out the saved data in new original inode blocks. Return
 * replaced block count.
 */
static int
move_extent_per_page(struct file *o_filp, struct inode *donor_inode,
		     pgoff_t orig_page_offset, pgoff_t donor_page_offset,
		     int data_offset_in_page,
		     int block_len_in_page, int unwritten, int *err)
{
	struct inode *orig_inode = file_inode(o_filp);
	struct page *pagep[2] = {NULL, NULL};
	handle_t *handle;
	scext4_lblk_t orig_blk_offset, donor_blk_offset;
	unsigned long blocksize = orig_inode->i_sb->s_blocksize;
	unsigned int tmp_data_size, data_size, replaced_size;
	int i, err2, jblocks, retries = 0;
	int replaced_count = 0;
	int from = data_offset_in_page << orig_inode->i_blkbits;
	int blocks_per_page = PAGE_SIZE >> orig_inode->i_blkbits;
	struct super_block *sb = orig_inode->i_sb;
	struct buffer_head *bh = NULL;

	/*
	 * It needs twice the amount of ordinary journal buffers because
	 * inode and donor_inode may change each different metadata blocks.
	 */
again:
	*err = 0;
	jblocks = scext4_writepage_trans_blocks(orig_inode) * 2;
	handle = scext4_journal_start(orig_inode, SCEXT4_HT_MOVE_EXTENTS, jblocks);
	if (IS_ERR(handle)) {
		*err = PTR_ERR(handle);
		return 0;
	}

	orig_blk_offset = orig_page_offset * blocks_per_page +
		data_offset_in_page;

	donor_blk_offset = donor_page_offset * blocks_per_page +
		data_offset_in_page;

	/* Calculate data_size */
	if ((orig_blk_offset + block_len_in_page - 1) ==
	    ((orig_inode->i_size - 1) >> orig_inode->i_blkbits)) {
		/* Replace the last block */
		tmp_data_size = orig_inode->i_size & (blocksize - 1);
		/*
		 * If data_size equal zero, it shows data_size is multiples of
		 * blocksize. So we set appropriate value.
		 */
		if (tmp_data_size == 0)
			tmp_data_size = blocksize;

		data_size = tmp_data_size +
			((block_len_in_page - 1) << orig_inode->i_blkbits);
	} else
		data_size = block_len_in_page << orig_inode->i_blkbits;

	replaced_size = data_size;

	// ziggy: get two page from page cache to pagep
	*err = mext_page_double_lock(orig_inode, donor_inode, orig_page_offset,
				     donor_page_offset, pagep);
	if (unlikely(*err < 0))
		goto stop_journal;
	/*
	 * If orig extent was unwritten it can become initialized
	 * at any time after i_data_sem was dropped, in order to
	 * serialize with delalloc we have recheck extent while we
	 * hold page's lock, if it is still the case data copy is not
	 * necessary, just swap data blocks between orig and donor.
	 */
	if (unwritten) {
		scext4_double_down_write_data_sem(orig_inode, donor_inode);
		/* If any of extents in range became initialized we have to
		 * fallback to data copying */
		unwritten = mext_check_coverage(orig_inode, orig_blk_offset,
						block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		unwritten &= mext_check_coverage(donor_inode, donor_blk_offset,
						 block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		if (!unwritten) {
			scext4_double_up_write_data_sem(orig_inode, donor_inode);
			goto data_copy;
		}
		if ((page_has_private(pagep[0]) &&
		     !try_to_release_page(pagep[0], 0)) ||
		    (page_has_private(pagep[1]) &&
		     !try_to_release_page(pagep[1], 0))) {
			*err = -EBUSY;
			goto drop_data_sem;
		}
		replaced_count = scext4_swap_extents(handle, orig_inode,
						   donor_inode, orig_blk_offset,
						   donor_blk_offset,
						   block_len_in_page, 1, err);
	drop_data_sem:
		scext4_double_up_write_data_sem(orig_inode, donor_inode);
		goto unlock_pages;
	}
data_copy:
	*err = mext_page_mkuptodate(pagep[0], from, from + replaced_size);
	if (*err)
		goto unlock_pages;

	/* At this point all buffers in range are uptodate, old mapping layout
	 * is no longer required, try to drop it now. */
	if ((page_has_private(pagep[0]) && !try_to_release_page(pagep[0], 0)) ||
	    (page_has_private(pagep[1]) && !try_to_release_page(pagep[1], 0))) {
		*err = -EBUSY;
		goto unlock_pages;
	}
	scext4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = scext4_swap_extents(handle, orig_inode, donor_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 1, err);
	scext4_double_up_write_data_sem(orig_inode, donor_inode);
	if (*err) {
		if (replaced_count) {
			block_len_in_page = replaced_count;
			replaced_size =
				block_len_in_page << orig_inode->i_blkbits;
		} else
			goto unlock_pages;
	}
	/* Perform all necessary steps similar write_begin()/write_end()
	 * but keeping in mind that i_size will not change */
	if (!page_has_buffers(pagep[0]))
		create_empty_buffers(pagep[0], 1 << orig_inode->i_blkbits, 0);
	bh = page_buffers(pagep[0]);
	for (i = 0; i < data_offset_in_page; i++)
		bh = bh->b_this_page;
	for (i = 0; i < block_len_in_page; i++) {
		*err = scext4_get_block(orig_inode, orig_blk_offset + i, bh, 0);
		if (*err < 0)
			break;
		bh = bh->b_this_page;
	}
	if (!*err)
		*err = block_commit_write(pagep[0], from, from + replaced_size);
// ziggy: until here, the core

	if (unlikely(*err < 0))
		goto repair_branches;

	/* Even in case of data=writeback it is reasonable to pin
	 * inode to transaction, to prevent unexpected data loss */
	*err = scext4_jbd3_inode_add_write(handle, orig_inode,
			(loff_t)orig_page_offset << PAGE_SHIFT, replaced_size);

unlock_pages:
	unlock_page(pagep[0]);
	put_page(pagep[0]);
	unlock_page(pagep[1]);
	put_page(pagep[1]);
stop_journal:
	scext4_journal_stop(handle);
	if (*err == -ENOSPC &&
	    scext4_should_retry_alloc(sb, &retries))
		goto again;
	/* Buffer was busy because probably is pinned to journal transaction,
	 * force transaction commit may help to free it. */
	if (*err == -EBUSY && retries++ < 4 && SCEXT4_SB(sb)->s_journal &&
	    jbd3_journal_force_commit_nested(SCEXT4_SB(sb)->s_journal))
		goto again;
	return replaced_count;

repair_branches:
	/*
	 * This should never ever happen!
	 * Extents are swapped already, but we are not able to copy data.
	 * Try to swap extents to it's original places
	 */
	scext4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = scext4_swap_extents(handle, donor_inode, orig_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 0, &err2);
	scext4_double_up_write_data_sem(orig_inode, donor_inode);
	if (replaced_count != block_len_in_page) {
		SCEXT4_ERROR_INODE_BLOCK(orig_inode, (sector_t)(orig_blk_offset),
				       "Unable to copy data block,"
				       " data will be lost.");
		*err = -EIO;
	}
	replaced_count = 0;
	goto unlock_pages;
}

/**
 * mext_check_arguments - Check whether move extent can be done
 *
 * @orig_inode:		original inode
 * @donor_inode:	donor inode
 * @orig_start:		logical start offset in block for orig
 * @donor_start:	logical start offset in block for donor
 * @len:		the number of blocks to be moved
 *
 * Check the arguments of scext4_move_extents() whether the files can be
 * exchanged with each other.
 * Return 0 on success, or a negative error value on failure.
 */
static int
mext_check_arguments(struct inode *orig_inode,
		     struct inode *donor_inode, __u64 orig_start,
		     __u64 donor_start, __u64 *len)
{
	__u64 orig_eof, donor_eof;
	unsigned int blkbits = orig_inode->i_blkbits;
	unsigned int blocksize = 1 << blkbits;

	orig_eof = (i_size_read(orig_inode) + blocksize - 1) >> blkbits;
	donor_eof = (i_size_read(donor_inode) + blocksize - 1) >> blkbits;


	if (donor_inode->i_mode & (S_ISUID|S_ISGID)) {
		scext4_debug("scext4 move extent: suid or sgid is set"
			   " to donor file [ino:orig %lu, donor %lu]\n",
			   orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	if (IS_IMMUTABLE(donor_inode) || IS_APPEND(donor_inode))
		return -EPERM;

	/* Ext4 move extent does not support swapfile */
	if (IS_SWAPFILE(orig_inode) || IS_SWAPFILE(donor_inode)) {
		scext4_debug("scext4 move extent: The argument files should "
			"not be swapfile [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EBUSY;
	}

	if (scext4_is_quota_file(orig_inode) && scext4_is_quota_file(donor_inode)) {
		scext4_debug("scext4 move extent: The argument files should "
			"not be quota files [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EBUSY;
	}

	/* Ext4 move extent supports only extent based file */
	if (!(scext4_test_inode_flag(orig_inode, SCEXT4_INODE_EXTENTS))) {
		scext4_debug("scext4 move extent: orig file is not extents "
			"based file [ino:orig %lu]\n", orig_inode->i_ino);
		return -EOPNOTSUPP;
	} else if (!(scext4_test_inode_flag(donor_inode, SCEXT4_INODE_EXTENTS))) {
		scext4_debug("scext4 move extent: donor file is not extents "
			"based file [ino:donor %lu]\n", donor_inode->i_ino);
		return -EOPNOTSUPP;
	}

	if ((!orig_inode->i_size) || (!donor_inode->i_size)) {
		scext4_debug("scext4 move extent: File size is 0 byte\n");
		return -EINVAL;
	}

	/* Start offset should be same */
	if ((orig_start & ~(PAGE_MASK >> orig_inode->i_blkbits)) !=
	    (donor_start & ~(PAGE_MASK >> orig_inode->i_blkbits))) {
		scext4_debug("scext4 move extent: orig and donor's start "
			"offsets are not aligned [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	if ((orig_start >= EXT_MAX_BLOCKS) ||
	    (donor_start >= EXT_MAX_BLOCKS) ||
	    (*len > EXT_MAX_BLOCKS) ||
	    (donor_start + *len >= EXT_MAX_BLOCKS) ||
	    (orig_start + *len >= EXT_MAX_BLOCKS))  {
		scext4_debug("scext4 move extent: Can't handle over [%u] blocks "
			"[ino:orig %lu, donor %lu]\n", EXT_MAX_BLOCKS,
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}
	if (orig_eof <= orig_start)
		*len = 0;
	else if (orig_eof < orig_start + *len - 1)
		*len = orig_eof - orig_start;
	if (donor_eof <= donor_start)
		*len = 0;
	else if (donor_eof < donor_start + *len - 1)
		*len = donor_eof - donor_start;
	if (!*len) {
		scext4_debug("scext4 move extent: len should not be 0 "
			"[ino:orig %lu, donor %lu]\n", orig_inode->i_ino,
			donor_inode->i_ino);
		return -EINVAL;
	}

	return 0;
}

/**
 * scext4_move_extents - Exchange the specified range of a file
 *
 * @o_filp:		file structure of the original file
 * @d_filp:		file structure of the donor file
 * @orig_blk:		start offset in block for orig
 * @donor_blk:		start offset in block for donor
 * @len:		the number of blocks to be moved
 * @moved_len:		moved block length
 *
 * This function returns 0 and moved block length is set in moved_len
 * if succeed, otherwise returns error value.
 *
 */
int
scext4_move_extents(struct file *o_filp, struct file *d_filp, __u64 orig_blk,
		  __u64 donor_blk, __u64 len, __u64 *moved_len)
{
	struct inode *orig_inode = file_inode(o_filp);
	struct inode *donor_inode = file_inode(d_filp);
	struct scext4_ext_path *path = NULL;
	int blocks_per_page = PAGE_SIZE >> orig_inode->i_blkbits;
	scext4_lblk_t o_end, o_start = orig_blk;
	scext4_lblk_t d_start = donor_blk;
	int ret;

	if (orig_inode->i_sb != donor_inode->i_sb) {
		scext4_debug("scext4 move extent: The argument files "
			"should be in same FS [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* orig and donor should be different inodes */
	if (orig_inode == donor_inode) {
		scext4_debug("scext4 move extent: The argument files should not "
			"be same inode [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* Regular file check */
	if (!S_ISREG(orig_inode->i_mode) || !S_ISREG(donor_inode->i_mode)) {
		scext4_debug("scext4 move extent: The argument files should be "
			"regular file [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* TODO: it's not obvious how to swap blocks for inodes with full
	   journaling enabled */
	if (scext4_should_journal_data(orig_inode) ||
	    scext4_should_journal_data(donor_inode)) {
		scext4_msg(orig_inode->i_sb, KERN_ERR,
			 "Online defrag not supported with data journaling");
		return -EOPNOTSUPP;
	}

	if (IS_ENCRYPTED(orig_inode) || IS_ENCRYPTED(donor_inode)) {
		scext4_msg(orig_inode->i_sb, KERN_ERR,
			 "Online defrag not supported for encrypted files");
		return -EOPNOTSUPP;
	}

	/* Protect orig and donor inodes against a truncate */
	lock_two_nondirectories(orig_inode, donor_inode);

	/* Wait for all existing dio workers */
	inode_dio_wait(orig_inode);
	inode_dio_wait(donor_inode);

	/* Protect extent tree against block allocations via delalloc */
	scext4_double_down_write_data_sem(orig_inode, donor_inode);
	/* Check the filesystem environment whether move_extent can be done */
	ret = mext_check_arguments(orig_inode, donor_inode, orig_blk,
				    donor_blk, &len);
	if (ret)
		goto out;
	o_end = o_start + len;  // ziggy: range of a donar extent

	while (o_start < o_end) {
		struct scext4_extent *ex;  // ziggy: extent on-disk structure
		scext4_lblk_t cur_blk, next_blk;
		pgoff_t orig_page_index, donor_page_index;
		int offset_in_page;
		int unwritten, cur_len;

		ret = get_ext_path(orig_inode, o_start, &path);
		if (ret)
			goto out;
		ex = path[path->p_depth].p_ext;  // ziggy: extent of target file
		next_blk = scext4_ext_next_allocated_block(path);  //TODO what is this?
		cur_blk = le32_to_cpu(ex->ee_block);  // ziggy: start logical blocks
		cur_len = scext4_ext_get_actual_len(ex);
		/* Check hole before the start pos */
		if (cur_blk + cur_len - 1 < o_start) {
			if (next_blk == EXT_MAX_BLOCKS) {
				o_start = o_end;
				ret = -ENODATA;
				goto out;
			}
			d_start += next_blk - o_start;
			o_start = next_blk;
			continue;
		/* Check hole after the start pos */
		} else if (cur_blk > o_start) {
			/* Skip hole */
			d_start += cur_blk - o_start;
			o_start = cur_blk;
			/* Extent inside requested range ?*/
			if (cur_blk >= o_end)
				goto out;
		} else { /* in_range(o_start, o_blk, o_len) */
			cur_len += cur_blk - o_start;
		}
		unwritten = scext4_ext_is_unwritten(ex);
		if (o_end - o_start < cur_len)
			cur_len = o_end - o_start;

		// TODO: important part! move per page
		orig_page_index = o_start >> (PAGE_SHIFT -
					       orig_inode->i_blkbits);
		donor_page_index = d_start >> (PAGE_SHIFT -
					       donor_inode->i_blkbits);
		offset_in_page = o_start % blocks_per_page;
		if (cur_len > blocks_per_page- offset_in_page)
			cur_len = blocks_per_page - offset_in_page;  // ziggy: length must less than a page, in our situation, one block per page.
		/*
		 * Up semaphore to avoid following problems:
		 * a. transaction deadlock among scext4_journal_start,
		 *    ->write_begin via pagefault, and jbd3_journal_commit
		 * b. racing with ->readpage, ->write_begin, and scext4_get_block
		 *    in move_extent_per_page
		 */
		scext4_double_up_write_data_sem(orig_inode, donor_inode);
		/* Swap original branches with new branches */
		move_extent_per_page(o_filp, donor_inode,
				     orig_page_index, donor_page_index,
				     offset_in_page, cur_len,
				     unwritten, &ret);
		scext4_double_down_write_data_sem(orig_inode, donor_inode);
		if (ret < 0)
			break;
		o_start += cur_len;
		d_start += cur_len;
	}
	*moved_len = o_start - orig_blk;
	if (*moved_len > len)
		*moved_len = len;

out:
	if (*moved_len) {
		scext4_discard_preallocations(orig_inode);
		scext4_discard_preallocations(donor_inode);
	}

	scext4_ext_drop_refs(path);
	kfree(path);
	scext4_double_up_write_data_sem(orig_inode, donor_inode);
	unlock_two_nondirectories(orig_inode, donor_inode);

	return ret;
}

/**
 * move_extent_per_page_async - Move extent data per page
 *
 * @o_filp:			file structure of original file
 * @donor_inode:		donor inode
 * @orig_page_offset:		page index on original file
 * @donor_page_offset:		page index on donor file
 * @data_offset_in_page:	block index where data swapping starts
 * @block_len_in_page:		the number of blocks to be swapped
 * @unwritten:			orig extent is unwritten or not
 * @err:			pointer to save return value
 *
 * Save the data in original inode blocks and replace original inode extents
 * with donor inode extents by calling scext4_swap_extents().
 * Finally, write out the saved data in new original inode blocks. Return
 * replaced block count.
 */
static int
move_extent_per_page_async(struct file *o_filp, struct inode *donor_inode,
		     pgoff_t orig_page_offset, pgoff_t donor_page_offset,
		     int data_offset_in_page,
		     int block_len_in_page, int unwritten, int *err)
{
	struct inode *orig_inode = file_inode(o_filp);
	struct page *pagep[2] = {NULL, NULL};
	handle_t *handle;
	scext4_lblk_t orig_blk_offset, donor_blk_offset;
	unsigned long blocksize = orig_inode->i_sb->s_blocksize;
	unsigned int tmp_data_size, data_size, replaced_size;
	int i, err2, jblocks, retries = 0;
	int replaced_count = 0;
	int from = data_offset_in_page << orig_inode->i_blkbits;
	int blocks_per_page = PAGE_SIZE >> orig_inode->i_blkbits;
	struct super_block *sb = orig_inode->i_sb;
	struct buffer_head *bh = NULL;

	/*
	 * It needs twice the amount of ordinary journal buffers because
	 * inode and donor_inode may change each different metadata blocks.
	 */
again:
	*err = 0;
	jblocks = scext4_writepage_trans_blocks(orig_inode) * 2;
	handle = scext4_journal_start(orig_inode, SCEXT4_HT_MOVE_EXTENTS, jblocks);
	if (IS_ERR(handle)) {
		*err = PTR_ERR(handle);
		return 0;
	}

	orig_blk_offset = orig_page_offset * blocks_per_page +
		data_offset_in_page;

	donor_blk_offset = donor_page_offset * blocks_per_page +
		data_offset_in_page;

	/* Calculate data_size */
	if ((orig_blk_offset + block_len_in_page - 1) ==
	    ((orig_inode->i_size - 1) >> orig_inode->i_blkbits)) {
		/* Replace the last block */
		tmp_data_size = orig_inode->i_size & (blocksize - 1);
		/*
		 * If data_size equal zero, it shows data_size is multiples of
		 * blocksize. So we set appropriate value.
		 */
		if (tmp_data_size == 0)
			tmp_data_size = blocksize;

		data_size = tmp_data_size +
			((block_len_in_page - 1) << orig_inode->i_blkbits);
	} else
		data_size = block_len_in_page << orig_inode->i_blkbits;

	replaced_size = data_size;

	// ziggy: get two page from page cache to pagep
	// page_offset is page_index that get from logical block numbers
	*err = mext_page_double_lock(orig_inode, donor_inode, orig_page_offset,
				     donor_page_offset, pagep);
	if (unlikely(*err < 0))
		goto stop_journal;
	/*
	 * If orig extent was unwritten it can become initialized
	 * at any time after i_data_sem was dropped, in order to
	 * serialize with delalloc we have recheck extent while we
	 * hold page's lock, if it is still the case data copy is not
	 * necessary, just swap data blocks between orig and donor.
	 */
	if (unwritten) {
		scext4_double_down_write_data_sem(orig_inode, donor_inode);
		/* If any of extents in range became initialized we have to
		 * fallback to data copying */
		unwritten = mext_check_coverage(orig_inode, orig_blk_offset,
						block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		unwritten &= mext_check_coverage(donor_inode, donor_blk_offset,
						 block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		if (!unwritten) {
			scext4_double_up_write_data_sem(orig_inode, donor_inode);
			goto data_copy;
		}
		if ((page_has_private(pagep[0]) &&
		     !try_to_release_page(pagep[0], 0)) ||
		    (page_has_private(pagep[1]) &&
		     !try_to_release_page(pagep[1], 0))) {
			*err = -EBUSY;
			goto drop_data_sem;
		}
		replaced_count = scext4_swap_extents(handle, orig_inode,
						   donor_inode, orig_blk_offset,
						   donor_blk_offset,
						   block_len_in_page, 1, err);
	drop_data_sem:
		scext4_double_up_write_data_sem(orig_inode, donor_inode);
		goto unlock_pages;
	}
data_copy:
	*err = mext_page_mkuptodate(pagep[0], from, from + replaced_size);
	if (*err)
		goto unlock_pages;

	/* At this point all buffers in range are uptodate, old mapping layout
	 * is no longer required, try to drop it now. */
	if ((page_has_private(pagep[0]) && !try_to_release_page(pagep[0], 0)) ||
	    (page_has_private(pagep[1]) && !try_to_release_page(pagep[1], 0))) {
		*err = -EBUSY;
		goto unlock_pages;
	}
	scext4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = scext4_swap_extents(handle, orig_inode, donor_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 1, err);
	scext4_double_up_write_data_sem(orig_inode, donor_inode);
	if (*err) {
		if (replaced_count) {
			block_len_in_page = replaced_count;
			replaced_size =
				block_len_in_page << orig_inode->i_blkbits;
		} else
			goto unlock_pages;
	}
	/* Perform all necessary steps similar write_begin()/write_end()
	 * but keeping in mind that i_size will not change */
	if (!page_has_buffers(pagep[0]))
		create_empty_buffers(pagep[0], 1 << orig_inode->i_blkbits, 0);
	bh = page_buffers(pagep[0]);
	for (i = 0; i < data_offset_in_page; i++)
		bh = bh->b_this_page;
	for (i = 0; i < block_len_in_page; i++) {
		*err = scext4_get_block(orig_inode, orig_blk_offset + i, bh, 0);
		if (*err < 0)
			break;
		bh = bh->b_this_page;
	}
	if (!*err)
		*err = block_commit_write(pagep[0], from, from + replaced_size);
// ziggy: until here, the core

	if (unlikely(*err < 0))
		goto repair_branches;

	/* Even in case of data=writeback it is reasonable to pin
	 * inode to transaction, to prevent unexpected data loss */
	*err = scext4_jbd3_inode_add_write(handle, orig_inode,
			(loff_t)orig_page_offset << PAGE_SHIFT, replaced_size);

unlock_pages:
	unlock_page(pagep[0]);
	put_page(pagep[0]);
	unlock_page(pagep[1]);
	put_page(pagep[1]);
stop_journal:
	scext4_journal_stop(handle);
	if (*err == -ENOSPC &&
	    scext4_should_retry_alloc(sb, &retries))
		goto again;
	/* Buffer was busy because probably is pinned to journal transaction,
	 * force transaction commit may help to free it. */
	if (*err == -EBUSY && retries++ < 4 && SCEXT4_SB(sb)->s_journal &&
	    jbd3_journal_force_commit_nested(SCEXT4_SB(sb)->s_journal))
		goto again;
	return replaced_count;

repair_branches:
	/*
	 * This should never ever happen!
	 * Extents are swapped already, but we are not able to copy data.
	 * Try to swap extents to it's original places
	 */
	scext4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = scext4_swap_extents(handle, donor_inode, orig_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 0, &err2);
	scext4_double_up_write_data_sem(orig_inode, donor_inode);
	if (replaced_count != block_len_in_page) {
		SCEXT4_ERROR_INODE_BLOCK(orig_inode, (sector_t)(orig_blk_offset),
				       "Unable to copy data block,"
				       " data will be lost.");
		*err = -EIO;
	}
	replaced_count = 0;
	goto unlock_pages;
}

/**
 * scext4_move_extents_async - Exchange the specified range of a file
 *
 * @o_filp:		file structure of the original file
 * @d_filp:		file structure of the donor file
 * @orig_blk:		start offset in block for orig
 * @donor_blk:		start offset in block for donor
 * @len:		the number of blocks to be moved
 * @moved_len:		moved block length
 *
 * This function returns 0 and moved block length is set in moved_len
 * if succeed, otherwise returns error value.
 *
 */
int
scext4_move_extents_async(struct file *o_filp, struct file *d_filp, __u64 orig_blk,
		  __u64 donor_blk, __u64 len, __u64 *moved_len)
{
	struct inode *orig_inode = file_inode(o_filp);
	struct inode *donor_inode = file_inode(d_filp);
	struct scext4_ext_path *path = NULL;
	int blocks_per_page = PAGE_SIZE >> orig_inode->i_blkbits;
	scext4_lblk_t o_end, o_start = orig_blk;
	scext4_lblk_t d_start = donor_blk;
	int ret;

	if (orig_inode->i_sb != donor_inode->i_sb) {
		scext4_debug("scext4 move extent: The argument files "
			"should be in same FS [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* orig and donor should be different inodes */
	if (orig_inode == donor_inode) {
		scext4_debug("scext4 move extent: The argument files should not "
			"be same inode [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* Regular file check */
	if (!S_ISREG(orig_inode->i_mode) || !S_ISREG(donor_inode->i_mode)) {
		scext4_debug("scext4 move extent: The argument files should be "
			"regular file [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* TODO: it's not obvious how to swap blocks for inodes with full
	   journaling enabled */
	if (scext4_should_journal_data(orig_inode) ||
	    scext4_should_journal_data(donor_inode)) {
		scext4_msg(orig_inode->i_sb, KERN_ERR,
			 "Online defrag not supported with data journaling");
		return -EOPNOTSUPP;
	}

	if (IS_ENCRYPTED(orig_inode) || IS_ENCRYPTED(donor_inode)) {
		scext4_msg(orig_inode->i_sb, KERN_ERR,
			 "Online defrag not supported for encrypted files");
		return -EOPNOTSUPP;
	}

	/* Protect orig and donor inodes against a truncate */
	lock_two_nondirectories(orig_inode, donor_inode);

	/* Wait for all existing dio workers */
	inode_dio_wait(orig_inode);
	inode_dio_wait(donor_inode);

	/* Protect extent tree against block allocations via delalloc */
	scext4_double_down_write_data_sem(orig_inode, donor_inode);
	/* Check the filesystem environment whether move_extent can be done */
	ret = mext_check_arguments(orig_inode, donor_inode, orig_blk,
				    donor_blk, &len);
	scext4_double_up_write_data_sem(orig_inode, donor_inode);

	if (ret)
		goto out;
	o_end = o_start + len;  // ziggy: range of a donar extent (in blk unit)

	move_extent_all_page(o_filp, donor_inode,
						 o_start, o_end,
						 d_start,
						 //cur_len,
						// unwritten,
						 &ret);
	// END

	//*moved_len = o_start - orig_blk;
	//if (*moved_len > len)
		*moved_len = len;

out:
	if (*moved_len) {
		scext4_discard_preallocations(orig_inode);
		scext4_discard_preallocations(donor_inode);
	}

	//scext4_ext_drop_refs(path);
	//kfree(path);
	//scext4_double_up_write_data_sem(orig_inode, donor_inode);
	unlock_two_nondirectories(orig_inode, donor_inode);

	return ret;
}
