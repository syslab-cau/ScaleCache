// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_trans_priv.h"
#include "scxfs_inode_item.h"

#include <linux/iversion.h>

/*
 * Add a locked inode to the transaction.
 *
 * The inode must be locked, and it cannot be associated with any transaction.
 * If lock_flags is non-zero the inode will be unlocked on transaction commit.
 */
void
scxfs_trans_ijoin(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	uint			lock_flags)
{
	scxfs_inode_log_item_t	*iip;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	if (ip->i_itemp == NULL)
		scxfs_inode_item_init(ip, ip->i_mount);
	iip = ip->i_itemp;

	ASSERT(iip->ili_lock_flags == 0);
	iip->ili_lock_flags = lock_flags;
	ASSERT(!scxfs_iflags_test(ip, SCXFS_ISTALE));

	/*
	 * Get a log_item_desc to point at the new item.
	 */
	scxfs_trans_add_item(tp, &iip->ili_item);
}

/*
 * Transactional inode timestamp update. Requires the inode to be locked and
 * joined to the transaction supplied. Relies on the transaction subsystem to
 * track dirty state and update/writeback the inode accordingly.
 */
void
scxfs_trans_ichgtime(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			flags)
{
	struct inode		*inode = VFS_I(ip);
	struct timespec64 tv;

	ASSERT(tp);
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));

	tv = current_time(inode);

	if (flags & SCXFS_ICHGTIME_MOD)
		inode->i_mtime = tv;
	if (flags & SCXFS_ICHGTIME_CHG)
		inode->i_ctime = tv;
	if (flags & SCXFS_ICHGTIME_CREATE) {
		ip->i_d.di_crtime.t_sec = (int32_t)tv.tv_sec;
		ip->i_d.di_crtime.t_nsec = (int32_t)tv.tv_nsec;
	}
}

/*
 * This is called to mark the fields indicated in fieldmask as needing
 * to be logged when the transaction is committed.  The inode must
 * already be associated with the given transaction.
 *
 * The values for fieldmask are defined in scxfs_inode_item.h.  We always
 * log all of the core inode if any of it has changed, and we always log
 * all of the inline data/extents/b-tree root if any of them has changed.
 */
void
scxfs_trans_log_inode(
	scxfs_trans_t	*tp,
	scxfs_inode_t	*ip,
	uint		flags)
{
	struct inode	*inode = VFS_I(ip);

	ASSERT(ip->i_itemp != NULL);
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(!scxfs_iflags_test(ip, SCXFS_ISTALE));

	/*
	 * Don't bother with i_lock for the I_DIRTY_TIME check here, as races
	 * don't matter - we either will need an extra transaction in 24 hours
	 * to log the timestamps, or will clear already cleared fields in the
	 * worst case.
	 */
	if (inode->i_state & I_DIRTY_TIME) {
		spin_lock(&inode->i_lock);
		inode->i_state &= ~I_DIRTY_TIME;
		spin_unlock(&inode->i_lock);
	}

	/*
	 * Record the specific change for fdatasync optimisation. This
	 * allows fdatasync to skip log forces for inodes that are only
	 * timestamp dirty. We do this before the change count so that
	 * the core being logged in this case does not impact on fdatasync
	 * behaviour.
	 */
	ip->i_itemp->ili_fsync_fields |= flags;

	/*
	 * First time we log the inode in a transaction, bump the inode change
	 * counter if it is configured for this to occur. While we have the
	 * inode locked exclusively for metadata modification, we can usually
	 * avoid setting SCXFS_ILOG_CORE if no one has queried the value since
	 * the last time it was incremented. If we have SCXFS_ILOG_CORE already
	 * set however, then go ahead and bump the i_version counter
	 * unconditionally.
	 */
	if (!test_and_set_bit(SCXFS_LI_DIRTY, &ip->i_itemp->ili_item.li_flags) &&
	    IS_I_VERSION(VFS_I(ip))) {
		if (inode_maybe_inc_iversion(VFS_I(ip), flags & SCXFS_ILOG_CORE))
			flags |= SCXFS_ILOG_CORE;
	}

	tp->t_flags |= SCXFS_TRANS_DIRTY;

	/*
	 * Always OR in the bits from the ili_last_fields field.
	 * This is to coordinate with the scxfs_iflush() and scxfs_iflush_done()
	 * routines in the eventual clearing of the ili_fields bits.
	 * See the big comment in scxfs_iflush() for an explanation of
	 * this coordination mechanism.
	 */
	flags |= ip->i_itemp->ili_last_fields;
	ip->i_itemp->ili_fields |= flags;
}

int
scxfs_trans_roll_inode(
	struct scxfs_trans	**tpp,
	struct scxfs_inode	*ip)
{
	int			error;

	scxfs_trans_log_inode(*tpp, ip, SCXFS_ILOG_CORE);
	error = scxfs_trans_roll(tpp);
	if (!error)
		scxfs_trans_ijoin(*tpp, ip, 0);
	return error;
}
