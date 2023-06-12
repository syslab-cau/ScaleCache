// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 Christoph Hellwig.
 */
#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_bmap.h"
#include "scxfs_iomap.h"

/*
 * Ensure that we do not have any outstanding pNFS layouts that can be used by
 * clients to directly read from or write to this inode.  This must be called
 * before every operation that can remove blocks from the extent map.
 * Additionally we call it during the write operation, where aren't concerned
 * about exposing unallocated blocks but just want to provide basic
 * synchronization between a local writer and pNFS clients.  mmap writes would
 * also benefit from this sort of synchronization, but due to the tricky locking
 * rules in the page fault path we don't bother.
 */
int
scxfs_break_leased_layouts(
	struct inode		*inode,
	uint			*iolock,
	bool			*did_unlock)
{
	struct scxfs_inode	*ip = SCXFS_I(inode);
	int			error;

	while ((error = break_layout(inode, false)) == -EWOULDBLOCK) {
		scxfs_iunlock(ip, *iolock);
		*did_unlock = true;
		error = break_layout(inode, true);
		*iolock &= ~SCXFS_IOLOCK_SHARED;
		*iolock |= SCXFS_IOLOCK_EXCL;
		scxfs_ilock(ip, *iolock);
	}

	return error;
}

/*
 * Get a unique ID including its location so that the client can identify
 * the exported device.
 */
int
scxfs_fs_get_uuid(
	struct super_block	*sb,
	u8			*buf,
	u32			*len,
	u64			*offset)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	printk_once(KERN_NOTICE
"SCXFS (%s): using experimental pNFS feature, use at your own risk!\n",
		mp->m_fsname);

	if (*len < sizeof(uuid_t))
		return -EINVAL;

	memcpy(buf, &mp->m_sb.sb_uuid, sizeof(uuid_t));
	*len = sizeof(uuid_t);
	*offset = offsetof(struct scxfs_dsb, sb_uuid);
	return 0;
}

/*
 * Get a layout for the pNFS client.
 */
int
scxfs_fs_map_blocks(
	struct inode		*inode,
	loff_t			offset,
	u64			length,
	struct iomap		*iomap,
	bool			write,
	u32			*device_generation)
{
	struct scxfs_inode	*ip = SCXFS_I(inode);
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_bmbt_irec	imap;
	scxfs_fileoff_t		offset_fsb, end_fsb;
	loff_t			limit;
	int			bmapi_flags = SCXFS_BMAPI_ENTIRE;
	int			nimaps = 1;
	uint			lock_flags;
	int			error = 0;

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	/*
	 * We can't export inodes residing on the realtime device.  The realtime
	 * device doesn't have a UUID to identify it, so the client has no way
	 * to find it.
	 */
	if (SCXFS_IS_REALTIME_INODE(ip))
		return -ENXIO;

	/*
	 * The pNFS block layout spec actually supports reflink like
	 * functionality, but the Linux pNFS server doesn't implement it yet.
	 */
	if (scxfs_is_reflink_inode(ip))
		return -ENXIO;

	/*
	 * Lock out any other I/O before we flush and invalidate the pagecache,
	 * and then hand out a layout to the remote system.  This is very
	 * similar to direct I/O, except that the synchronization is much more
	 * complicated.  See the comment near scxfs_break_leased_layouts
	 * for a detailed explanation.
	 */
	scxfs_ilock(ip, SCXFS_IOLOCK_EXCL);

	error = -EINVAL;
	limit = mp->m_super->s_maxbytes;
	if (!write)
		limit = max(limit, round_up(i_size_read(inode),
				     inode->i_sb->s_blocksize));
	if (offset > limit)
		goto out_unlock;
	if (offset > limit - length)
		length = limit - offset;

	error = filemap_write_and_wait(inode->i_mapping);
	if (error)
		goto out_unlock;
	error = invalidate_inode_pages2(inode->i_mapping);
	if (WARN_ON_ONCE(error))
		goto out_unlock;

	end_fsb = SCXFS_B_TO_FSB(mp, (scxfs_ufsize_t)offset + length);
	offset_fsb = SCXFS_B_TO_FSBT(mp, offset);

	lock_flags = scxfs_ilock_data_map_shared(ip);
	error = scxfs_bmapi_read(ip, offset_fsb, end_fsb - offset_fsb,
				&imap, &nimaps, bmapi_flags);
	scxfs_iunlock(ip, lock_flags);

	if (error)
		goto out_unlock;

	if (write) {
		enum scxfs_prealloc_flags	flags = 0;

		ASSERT(imap.br_startblock != DELAYSTARTBLOCK);

		if (!nimaps || imap.br_startblock == HOLESTARTBLOCK) {
			/*
			 * scxfs_iomap_write_direct() expects to take ownership of
			 * the shared ilock.
			 */
			scxfs_ilock(ip, SCXFS_ILOCK_SHARED);
			error = scxfs_iomap_write_direct(ip, offset, length,
						       &imap, nimaps);
			if (error)
				goto out_unlock;

			/*
			 * Ensure the next transaction is committed
			 * synchronously so that the blocks allocated and
			 * handed out to the client are guaranteed to be
			 * present even after a server crash.
			 */
			flags |= SCXFS_PREALLOC_SET | SCXFS_PREALLOC_SYNC;
		}

		error = scxfs_update_prealloc_flags(ip, flags);
		if (error)
			goto out_unlock;
	}
	scxfs_iunlock(ip, SCXFS_IOLOCK_EXCL);

	error = scxfs_bmbt_to_iomap(ip, iomap, &imap, false);
	*device_generation = mp->m_generation;
	return error;
out_unlock:
	scxfs_iunlock(ip, SCXFS_IOLOCK_EXCL);
	return error;
}

/*
 * Ensure the size update falls into a valid allocated block.
 */
static int
scxfs_pnfs_validate_isize(
	struct scxfs_inode	*ip,
	scxfs_off_t		isize)
{
	struct scxfs_bmbt_irec	imap;
	int			nimaps = 1;
	int			error = 0;

	scxfs_ilock(ip, SCXFS_ILOCK_SHARED);
	error = scxfs_bmapi_read(ip, SCXFS_B_TO_FSBT(ip->i_mount, isize - 1), 1,
				&imap, &nimaps, 0);
	scxfs_iunlock(ip, SCXFS_ILOCK_SHARED);
	if (error)
		return error;

	if (imap.br_startblock == HOLESTARTBLOCK ||
	    imap.br_startblock == DELAYSTARTBLOCK ||
	    imap.br_state == SCXFS_EXT_UNWRITTEN)
		return -EIO;
	return 0;
}

/*
 * Make sure the blocks described by maps are stable on disk.  This includes
 * converting any unwritten extents, flushing the disk cache and updating the
 * time stamps.
 *
 * Note that we rely on the caller to always send us a timestamp update so that
 * we always commit a transaction here.  If that stops being true we will have
 * to manually flush the cache here similar to what the fsync code path does
 * for datasyncs on files that have no dirty metadata.
 */
int
scxfs_fs_commit_blocks(
	struct inode		*inode,
	struct iomap		*maps,
	int			nr_maps,
	struct iattr		*iattr)
{
	struct scxfs_inode	*ip = SCXFS_I(inode);
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_trans	*tp;
	bool			update_isize = false;
	int			error, i;
	loff_t			size;

	ASSERT(iattr->ia_valid & (ATTR_ATIME|ATTR_CTIME|ATTR_MTIME));

	scxfs_ilock(ip, SCXFS_IOLOCK_EXCL);

	size = i_size_read(inode);
	if ((iattr->ia_valid & ATTR_SIZE) && iattr->ia_size > size) {
		update_isize = true;
		size = iattr->ia_size;
	}

	for (i = 0; i < nr_maps; i++) {
		u64 start, length, end;

		start = maps[i].offset;
		if (start > size)
			continue;

		end = start + maps[i].length;
		if (end > size)
			end = size;

		length = end - start;
		if (!length)
			continue;
	
		/*
		 * Make sure reads through the pagecache see the new data.
		 */
		error = invalidate_inode_pages2_range(inode->i_mapping,
					start >> PAGE_SHIFT,
					(end - 1) >> PAGE_SHIFT);
		WARN_ON_ONCE(error);

		error = scxfs_iomap_write_unwritten(ip, start, length, false);
		if (error)
			goto out_drop_iolock;
	}

	if (update_isize) {
		error = scxfs_pnfs_validate_isize(ip, size);
		if (error)
			goto out_drop_iolock;
	}

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_ichange, 0, 0, 0, &tp);
	if (error)
		goto out_drop_iolock;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

	scxfs_setattr_time(ip, iattr);
	if (update_isize) {
		i_size_write(inode, iattr->ia_size);
		ip->i_d.di_size = iattr->ia_size;
	}

	scxfs_trans_set_sync(tp);
	error = scxfs_trans_commit(tp);

out_drop_iolock:
	scxfs_iunlock(ip, SCXFS_IOLOCK_EXCL);
	return error;
}
