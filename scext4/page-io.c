// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/scext4/page-io.c
 *
 * This contains the new page_io functions for scext4
 *
 * Written by Theodore Ts'o, 2010.
 */

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/mpage.h>
#include <linux/namei.h>
#include <linux/uio.h>
#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>

#include "scext4_jbd3.h"
#include "xattr.h"
#include "acl.h"

static struct kmem_cache *io_end_cachep;

int __init scext4_init_pageio(void)
{
	io_end_cachep = KMEM_CACHE(scext4_io_end, SLAB_RECLAIM_ACCOUNT);
	if (io_end_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void scext4_exit_pageio(void)
{
	kmem_cache_destroy(io_end_cachep);
}

/*
 * Print an buffer I/O error compatible with the fs/buffer.c.  This
 * provides compatibility with dmesg scrapers that look for a specific
 * buffer I/O error message.  We really need a unified error reporting
 * structure to userspace ala Digital Unix's uerf system, but it's
 * probably not going to happen in my lifetime, due to LKML politics...
 */
static void buffer_io_error(struct buffer_head *bh)
{
	printk_ratelimited(KERN_ERR "Buffer I/O error on device %pg, logical block %llu\n",
		       bh->b_bdev,
			(unsigned long long)bh->b_blocknr);
}

static void scext4_finish_bio(struct bio *bio)
{
	struct bio_vec *bvec;
	struct bvec_iter_all iter_all;

	bio_for_each_segment_all(bvec, bio, iter_all) {
		struct page *page = bvec->bv_page;
		struct page *bounce_page = NULL;
		struct buffer_head *bh, *head;
		unsigned bio_start = bvec->bv_offset;
		unsigned bio_end = bio_start + bvec->bv_len;
		unsigned under_io = 0;
		unsigned long flags;

		if (!page)
			continue;

		if (fscrypt_is_bounce_page(page)) {
			bounce_page = page;
			page = fscrypt_pagecache_page(bounce_page);
		}

		if (bio->bi_status) {
			SetPageError(page);
			mapping_set_error(page->mapping, -EIO);
		}
		bh = head = page_buffers(page);
		/*
		 * We check all buffers in the page under BH_Uptodate_Lock
		 * to avoid races with other end io clearing async_write flags
		 */
		local_irq_save(flags);
		bit_spin_lock(BH_Uptodate_Lock, &head->b_state);
		do {
			if (bh_offset(bh) < bio_start ||
			    bh_offset(bh) + bh->b_size > bio_end) {
				if (buffer_async_write(bh))
					under_io++;
				continue;
			}
			clear_buffer_async_write(bh);
			if (bio->bi_status)
				buffer_io_error(bh);
		} while ((bh = bh->b_this_page) != head);
		bit_spin_unlock(BH_Uptodate_Lock, &head->b_state);
		local_irq_restore(flags);
		if (!under_io) {
			fscrypt_free_bounce_page(bounce_page);
			cc_end_page_writeback(page);
		}
	}
}

static void scext4_release_io_end(scext4_io_end_t *io_end)
{
	struct bio *bio, *next_bio;

	BUG_ON(!list_empty(&io_end->list));
	BUG_ON(io_end->flag & SCEXT4_IO_END_UNWRITTEN);
	WARN_ON(io_end->handle);

	for (bio = io_end->bio; bio; bio = next_bio) {
		next_bio = bio->bi_private;
		scext4_finish_bio(bio);
		bio_put(bio);
	}
	kmem_cache_free(io_end_cachep, io_end);
}

/*
 * Check a range of space and convert unwritten extents to written. Note that
 * we are protected from truncate touching same part of extent tree by the
 * fact that truncate code waits for all DIO to finish (thus exclusion from
 * direct IO is achieved) and also waits for PageWriteback bits. Thus we
 * cannot get to scext4_ext_truncate() before all IOs overlapping that range are
 * completed (happens from scext4_free_ioend()).
 */
static int scext4_end_io(scext4_io_end_t *io)
{
	struct inode *inode = io->inode;
	loff_t offset = io->offset;
	ssize_t size = io->size;
	handle_t *handle = io->handle;
	int ret = 0;

	scext4_debug("scext4_end_io_nolock: io 0x%p from inode %lu,list->next 0x%p,"
		   "list->prev 0x%p\n",
		   io, inode->i_ino, io->list.next, io->list.prev);

	io->handle = NULL;	/* Following call will use up the handle */
	ret = scext4_convert_unwritten_extents(handle, inode, offset, size);
	if (ret < 0 && !scext4_forced_shutdown(SCEXT4_SB(inode->i_sb))) {
		scext4_msg(inode->i_sb, KERN_EMERG,
			 "failed to convert unwritten extents to written "
			 "extents -- potential data loss!  "
			 "(inode %lu, offset %llu, size %zd, error %d)",
			 inode->i_ino, offset, size, ret);
	}
	scext4_clear_io_unwritten_flag(io);
	scext4_release_io_end(io);
	return ret;
}

static void dump_completed_IO(struct inode *inode, struct list_head *head)
{
#ifdef	SCEXT4FS_DEBUG
	struct list_head *cur, *before, *after;
	scext4_io_end_t *io, *io0, *io1;

	if (list_empty(head))
		return;

	scext4_debug("Dump inode %lu completed io list\n", inode->i_ino);
	list_for_each_entry(io, head, list) {
		cur = &io->list;
		before = cur->prev;
		io0 = container_of(before, scext4_io_end_t, list);
		after = cur->next;
		io1 = container_of(after, scext4_io_end_t, list);

		scext4_debug("io 0x%p from inode %lu,prev 0x%p,next 0x%p\n",
			    io, inode->i_ino, io0, io1);
	}
#endif
}

/* Add the io_end to per-inode completed end_io list. */
static void scext4_add_complete_io(scext4_io_end_t *io_end)
{
	struct scext4_inode_info *ei = SCEXT4_I(io_end->inode);
	struct scext4_sb_info *sbi = SCEXT4_SB(io_end->inode->i_sb);
	struct workqueue_struct *wq;
	unsigned long flags;

	/* Only reserved conversions from writeback should enter here */
	WARN_ON(!(io_end->flag & SCEXT4_IO_END_UNWRITTEN));
	WARN_ON(!io_end->handle && sbi->s_journal);
	spin_lock_irqsave(&ei->i_completed_io_lock, flags);
	wq = sbi->rsv_conversion_wq;
	if (list_empty(&ei->i_rsv_conversion_list))
		queue_work(wq, &ei->i_rsv_conversion_work);
	list_add_tail(&io_end->list, &ei->i_rsv_conversion_list);
	spin_unlock_irqrestore(&ei->i_completed_io_lock, flags);
}

static int scext4_do_flush_completed_IO(struct inode *inode,
				      struct list_head *head)
{
	scext4_io_end_t *io;
	struct list_head unwritten;
	unsigned long flags;
	struct scext4_inode_info *ei = SCEXT4_I(inode);
	int err, ret = 0;

	spin_lock_irqsave(&ei->i_completed_io_lock, flags);
	dump_completed_IO(inode, head);
	list_replace_init(head, &unwritten);
	spin_unlock_irqrestore(&ei->i_completed_io_lock, flags);

	while (!list_empty(&unwritten)) {
		io = list_entry(unwritten.next, scext4_io_end_t, list);
		BUG_ON(!(io->flag & SCEXT4_IO_END_UNWRITTEN));
		list_del_init(&io->list);

		err = scext4_end_io(io);
		if (unlikely(!ret && err))
			ret = err;
	}
	return ret;
}

/*
 * work on completed IO, to convert unwritten extents to extents
 */
void scext4_end_io_rsv_work(struct work_struct *work)
{
	struct scext4_inode_info *ei = container_of(work, struct scext4_inode_info,
						  i_rsv_conversion_work);
	scext4_do_flush_completed_IO(&ei->vfs_inode, &ei->i_rsv_conversion_list);
}

scext4_io_end_t *scext4_init_io_end(struct inode *inode, gfp_t flags)
{
	scext4_io_end_t *io = kmem_cache_zalloc(io_end_cachep, flags);
	if (io) {
		io->inode = inode;
		INIT_LIST_HEAD(&io->list);
		atomic_set(&io->count, 1);
	}
	return io;
}

void scext4_put_io_end_defer(scext4_io_end_t *io_end)
{
	if (atomic_dec_and_test(&io_end->count)) {
		if (!(io_end->flag & SCEXT4_IO_END_UNWRITTEN) || !io_end->size) {
			scext4_release_io_end(io_end);
			return;
		}
		scext4_add_complete_io(io_end);
	}
}

int scext4_put_io_end(scext4_io_end_t *io_end)
{
	int err = 0;

	if (atomic_dec_and_test(&io_end->count)) {
		if (io_end->flag & SCEXT4_IO_END_UNWRITTEN) {
			err = scext4_convert_unwritten_extents(io_end->handle,
						io_end->inode, io_end->offset,
						io_end->size);
			io_end->handle = NULL;
			scext4_clear_io_unwritten_flag(io_end);
		}
		scext4_release_io_end(io_end);
	}
	return err;
}

scext4_io_end_t *scext4_get_io_end(scext4_io_end_t *io_end)
{
	atomic_inc(&io_end->count);
	return io_end;
}

/* BIO completion function for page writeback */
static void scext4_end_bio(struct bio *bio)
{
	scext4_io_end_t *io_end = bio->bi_private;
	sector_t bi_sector = bio->bi_iter.bi_sector;
	char b[BDEVNAME_SIZE];

	if (WARN_ONCE(!io_end, "io_end is NULL: %s: sector %Lu len %u err %d\n",
		      bio_devname(bio, b),
		      (long long) bio->bi_iter.bi_sector,
		      (unsigned) bio_sectors(bio),
		      bio->bi_status)) {
		scext4_finish_bio(bio);
		bio_put(bio);
		return;
	}
	bio->bi_end_io = NULL;

	if (bio->bi_status) {
		struct inode *inode = io_end->inode;

		scext4_warning(inode->i_sb, "I/O error %d writing to inode %lu "
			     "(offset %llu size %ld starting block %llu)",
			     bio->bi_status, inode->i_ino,
			     (unsigned long long) io_end->offset,
			     (long) io_end->size,
			     (unsigned long long)
			     bi_sector >> (inode->i_blkbits - 9));
		mapping_set_error(inode->i_mapping,
				blk_status_to_errno(bio->bi_status));
	}

	if (io_end->flag & SCEXT4_IO_END_UNWRITTEN) {
		/*
		 * Link bio into list hanging from io_end. We have to do it
		 * atomically as bio completions can be racing against each
		 * other.
		 */
		bio->bi_private = xchg(&io_end->bio, bio);
		scext4_put_io_end_defer(io_end);
	} else {
		/*
		 * Drop io_end reference early. Inode can get freed once
		 * we finish the bio.
		 */
		scext4_put_io_end_defer(io_end);
		scext4_finish_bio(bio);
		bio_put(bio);
	}
}

void scext4_io_submit(struct scext4_io_submit *io)
{
	struct bio *bio = io->io_bio;

	if (bio) {
		int io_op_flags = io->io_wbc->sync_mode == WB_SYNC_ALL ?
				  REQ_SYNC : 0;
		io->io_bio->bi_write_hint = io->io_end->inode->i_write_hint;
		bio_set_op_attrs(io->io_bio, REQ_OP_WRITE, io_op_flags);
		submit_bio(io->io_bio);
	}
	io->io_bio = NULL;
}

void scext4_io_submit_init(struct scext4_io_submit *io,
			 struct writeback_control *wbc)
{
	io->io_wbc = wbc;
	io->io_bio = NULL;
	io->io_end = NULL;
}

static int io_submit_init_bio(struct scext4_io_submit *io,
			      struct buffer_head *bh)
{
	struct bio *bio;

	bio = bio_alloc(GFP_NOIO, BIO_MAX_PAGES);
	if (!bio)
		return -ENOMEM;
	bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio_set_dev(bio, bh->b_bdev);
	bio->bi_end_io = scext4_end_bio;
	bio->bi_private = scext4_get_io_end(io->io_end);
	io->io_bio = bio;
	io->io_next_block = bh->b_blocknr;
	wbc_init_bio(io->io_wbc, bio);
	return 0;
}

static int io_submit_add_bh(struct scext4_io_submit *io,
			    struct inode *inode,
			    struct page *page,
			    struct buffer_head *bh)
{
	int ret;

	if (io->io_bio && bh->b_blocknr != io->io_next_block) {
submit_and_retry:
		scext4_io_submit(io); 
	}
	if (io->io_bio == NULL) {
		ret = io_submit_init_bio(io, bh);
		if (ret)
			return ret;
		io->io_bio->bi_write_hint = inode->i_write_hint;
	}
	ret = bio_add_page(io->io_bio, page, bh->b_size, bh_offset(bh));
	if (ret != bh->b_size)
		goto submit_and_retry;
	wbc_account_cgroup_owner(io->io_wbc, page, bh->b_size);
	io->io_next_block++;
	return 0;
}

int scext4_bio_write_page(struct scext4_io_submit *io,
			struct page *page,
			int len,
			struct writeback_control *wbc,
			bool keep_towrite)
{
	struct page *bounce_page = NULL;
	struct inode *inode = page->mapping->host;
	unsigned block_start;
	struct buffer_head *bh, *head;
	int ret = 0;
	int nr_submitted = 0;
	int nr_to_submit = 0;

	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (keep_towrite)
		cc_set_page_writeback_keepwrite(page);
	else
		cc_set_page_writeback(page);
	ClearPageError(page);

	/*
	 * Comments copied from block_write_full_page:
	 *
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	if (len < PAGE_SIZE)
		zero_user_segment(page, len, PAGE_SIZE);
	/*
	 * In the first loop we prepare and mark buffers to submit. We have to
	 * mark all buffers in the page before submitting so that
	 * end_page_writeback() cannot be called from scext4_bio_end_io() when IO
	 * on the first buffer finishes and we are still working on submitting
	 * the second buffer.
	 */
	bh = head = page_buffers(page);
	do {
		block_start = bh_offset(bh);
		if (block_start >= len) {
			clear_buffer_dirty(bh);
			set_buffer_uptodate(bh);
			continue;
		}
		if (!buffer_dirty(bh) || buffer_delay(bh) ||
		    !buffer_mapped(bh) || buffer_unwritten(bh)) {
			/* A hole? We can safely clear the dirty bit */
			if (!buffer_mapped(bh))
				clear_buffer_dirty(bh);
			if (io->io_bio)
				scext4_io_submit(io);
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		set_buffer_async_write(bh);
		nr_to_submit++;
	} while ((bh = bh->b_this_page) != head);

	bh = head = page_buffers(page);

	/*
	 * If any blocks are being written to an encrypted file, encrypt them
	 * into a bounce page.  For simplicity, just encrypt until the last
	 * block which might be needed.  This may cause some unneeded blocks
	 * (e.g. holes) to be unnecessarily encrypted, but this is rare and
	 * can't happen in the common case of blocksize == PAGE_SIZE.
	 */
	if (IS_ENCRYPTED(inode) && S_ISREG(inode->i_mode) && nr_to_submit) {
		gfp_t gfp_flags = GFP_NOFS;
		unsigned int enc_bytes = round_up(len, i_blocksize(inode));

		/*
		 * Since bounce page allocation uses a mempool, we can only use
		 * a waiting mask (i.e. request guaranteed allocation) on the
		 * first page of the bio.  Otherwise it can deadlock.
		 */
		if (io->io_bio)
			gfp_flags = GFP_NOWAIT | __GFP_NOWARN;
	retry_encrypt:
		bounce_page = fscrypt_encrypt_pagecache_blocks(page, enc_bytes,
							       0, gfp_flags);
		if (IS_ERR(bounce_page)) {
			ret = PTR_ERR(bounce_page);
			if (ret == -ENOMEM &&
			    (io->io_bio || wbc->sync_mode == WB_SYNC_ALL)) {
				gfp_flags = GFP_NOFS;
				if (io->io_bio)
					scext4_io_submit(io);
				else
					gfp_flags |= __GFP_NOFAIL;
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto retry_encrypt;
			}
			bounce_page = NULL;
			goto out;
		}
	}

	/* Now submit buffers to write */
	do {
		if (!buffer_async_write(bh))
			continue;
		ret = io_submit_add_bh(io, inode, bounce_page ?: page, bh);
		if (ret) {
			/*
			 * We only get here on ENOMEM.  Not much else
			 * we can do but mark the page as dirty, and
			 * better luck next time.
			 */
			break;
		}
		nr_submitted++;
		clear_buffer_dirty(bh);
	} while ((bh = bh->b_this_page) != head);

	/* Error stopped previous loop? Clean up buffers... */
	if (ret) {
	out:
		fscrypt_free_bounce_page(bounce_page);
		printk_ratelimited(KERN_ERR "%s: ret = %d\n", __func__, ret);
		redirty_page_for_writepage(wbc, page);
		do {
			clear_buffer_async_write(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	unlock_page(page);
	/* Nothing submitted - we have to end page writeback */
	if (!nr_submitted)
		cc_end_page_writeback(page);
	return ret;
}
