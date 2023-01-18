// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * Copyright (C) 2010 Red Hat, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_extent_busy.h"
#include "scxfs_quota.h"
#include "scxfs_trans.h"
#include "scxfs_trans_priv.h"
#include "scxfs_log.h"
#include "scxfs_trace.h"
#include "scxfs_error.h"
#include "scxfs_defer.h"

kmem_zone_t	*scxfs_trans_zone;

#if defined(CONFIG_TRACEPOINTS)
static void
scxfs_trans_trace_reservations(
	struct scxfs_mount	*mp)
{
	struct scxfs_trans_res	resv;
	struct scxfs_trans_res	*res;
	struct scxfs_trans_res	*end_res;
	int			i;

	res = (struct scxfs_trans_res *)M_RES(mp);
	end_res = (struct scxfs_trans_res *)(M_RES(mp) + 1);
	for (i = 0; res < end_res; i++, res++)
		trace_scxfs_trans_resv_calc(mp, i, res);
	scxfs_log_get_max_trans_res(mp, &resv);
	trace_scxfs_trans_resv_calc(mp, -1, &resv);
}
#else
# define scxfs_trans_trace_reservations(mp)
#endif

/*
 * Initialize the precomputed transaction reservation values
 * in the mount structure.
 */
void
scxfs_trans_init(
	struct scxfs_mount	*mp)
{
	scxfs_trans_resv_calc(mp, M_RES(mp));
	scxfs_trans_trace_reservations(mp);
}

/*
 * Free the transaction structure.  If there is more clean up
 * to do when the structure is freed, add it here.
 */
STATIC void
scxfs_trans_free(
	struct scxfs_trans	*tp)
{
	scxfs_extent_busy_sort(&tp->t_busy);
	scxfs_extent_busy_clear(tp->t_mountp, &tp->t_busy, false);

	trace_scxfs_trans_free(tp, _RET_IP_);
	atomic_dec(&tp->t_mountp->m_active_trans);
	if (!(tp->t_flags & SCXFS_TRANS_NO_WRITECOUNT))
		sb_end_intwrite(tp->t_mountp->m_super);
	scxfs_trans_free_dqinfo(tp);
	kmem_zone_free(scxfs_trans_zone, tp);
}

/*
 * This is called to create a new transaction which will share the
 * permanent log reservation of the given transaction.  The remaining
 * unused block and rt extent reservations are also inherited.  This
 * implies that the original transaction is no longer allowed to allocate
 * blocks.  Locks and log items, however, are no inherited.  They must
 * be added to the new transaction explicitly.
 */
STATIC struct scxfs_trans *
scxfs_trans_dup(
	struct scxfs_trans	*tp)
{
	struct scxfs_trans	*ntp;

	trace_scxfs_trans_dup(tp, _RET_IP_);

	ntp = kmem_zone_zalloc(scxfs_trans_zone, 0);

	/*
	 * Initialize the new transaction structure.
	 */
	ntp->t_magic = SCXFS_TRANS_HEADER_MAGIC;
	ntp->t_mountp = tp->t_mountp;
	INIT_LIST_HEAD(&ntp->t_items);
	INIT_LIST_HEAD(&ntp->t_busy);
	INIT_LIST_HEAD(&ntp->t_dfops);
	ntp->t_firstblock = NULLFSBLOCK;

	ASSERT(tp->t_flags & SCXFS_TRANS_PERM_LOG_RES);
	ASSERT(tp->t_ticket != NULL);

	ntp->t_flags = SCXFS_TRANS_PERM_LOG_RES |
		       (tp->t_flags & SCXFS_TRANS_RESERVE) |
		       (tp->t_flags & SCXFS_TRANS_NO_WRITECOUNT);
	/* We gave our writer reference to the new transaction */
	tp->t_flags |= SCXFS_TRANS_NO_WRITECOUNT;
	ntp->t_ticket = scxfs_log_ticket_get(tp->t_ticket);

	ASSERT(tp->t_blk_res >= tp->t_blk_res_used);
	ntp->t_blk_res = tp->t_blk_res - tp->t_blk_res_used;
	tp->t_blk_res = tp->t_blk_res_used;

	ntp->t_rtx_res = tp->t_rtx_res - tp->t_rtx_res_used;
	tp->t_rtx_res = tp->t_rtx_res_used;
	ntp->t_pflags = tp->t_pflags;

	/* move deferred ops over to the new tp */
	scxfs_defer_move(ntp, tp);

	scxfs_trans_dup_dqinfo(tp, ntp);

	atomic_inc(&tp->t_mountp->m_active_trans);
	return ntp;
}

/*
 * This is called to reserve free disk blocks and log space for the
 * given transaction.  This must be done before allocating any resources
 * within the transaction.
 *
 * This will return ENOSPC if there are not enough blocks available.
 * It will sleep waiting for available log space.
 * The only valid value for the flags parameter is SCXFS_RES_LOG_PERM, which
 * is used by long running transactions.  If any one of the reservations
 * fails then they will all be backed out.
 *
 * This does not do quota reservations. That typically is done by the
 * caller afterwards.
 */
static int
scxfs_trans_reserve(
	struct scxfs_trans	*tp,
	struct scxfs_trans_res	*resp,
	uint			blocks,
	uint			rtextents)
{
	int		error = 0;
	bool		rsvd = (tp->t_flags & SCXFS_TRANS_RESERVE) != 0;

	/* Mark this thread as being in a transaction */
	current_set_flags_nested(&tp->t_pflags, PF_MEMALLOC_NOFS);

	/*
	 * Attempt to reserve the needed disk blocks by decrementing
	 * the number needed from the number available.  This will
	 * fail if the count would go below zero.
	 */
	if (blocks > 0) {
		error = scxfs_mod_fdblocks(tp->t_mountp, -((int64_t)blocks), rsvd);
		if (error != 0) {
			current_restore_flags_nested(&tp->t_pflags, PF_MEMALLOC_NOFS);
			return -ENOSPC;
		}
		tp->t_blk_res += blocks;
	}

	/*
	 * Reserve the log space needed for this transaction.
	 */
	if (resp->tr_logres > 0) {
		bool	permanent = false;

		ASSERT(tp->t_log_res == 0 ||
		       tp->t_log_res == resp->tr_logres);
		ASSERT(tp->t_log_count == 0 ||
		       tp->t_log_count == resp->tr_logcount);

		if (resp->tr_logflags & SCXFS_TRANS_PERM_LOG_RES) {
			tp->t_flags |= SCXFS_TRANS_PERM_LOG_RES;
			permanent = true;
		} else {
			ASSERT(tp->t_ticket == NULL);
			ASSERT(!(tp->t_flags & SCXFS_TRANS_PERM_LOG_RES));
		}

		if (tp->t_ticket != NULL) {
			ASSERT(resp->tr_logflags & SCXFS_TRANS_PERM_LOG_RES);
			error = scxfs_log_regrant(tp->t_mountp, tp->t_ticket);
		} else {
			error = scxfs_log_reserve(tp->t_mountp,
						resp->tr_logres,
						resp->tr_logcount,
						&tp->t_ticket, SCXFS_TRANSACTION,
						permanent);
		}

		if (error)
			goto undo_blocks;

		tp->t_log_res = resp->tr_logres;
		tp->t_log_count = resp->tr_logcount;
	}

	/*
	 * Attempt to reserve the needed realtime extents by decrementing
	 * the number needed from the number available.  This will
	 * fail if the count would go below zero.
	 */
	if (rtextents > 0) {
		error = scxfs_mod_frextents(tp->t_mountp, -((int64_t)rtextents));
		if (error) {
			error = -ENOSPC;
			goto undo_log;
		}
		tp->t_rtx_res += rtextents;
	}

	return 0;

	/*
	 * Error cases jump to one of these labels to undo any
	 * reservations which have already been performed.
	 */
undo_log:
	if (resp->tr_logres > 0) {
		scxfs_log_done(tp->t_mountp, tp->t_ticket, NULL, false);
		tp->t_ticket = NULL;
		tp->t_log_res = 0;
		tp->t_flags &= ~SCXFS_TRANS_PERM_LOG_RES;
	}

undo_blocks:
	if (blocks > 0) {
		scxfs_mod_fdblocks(tp->t_mountp, (int64_t)blocks, rsvd);
		tp->t_blk_res = 0;
	}

	current_restore_flags_nested(&tp->t_pflags, PF_MEMALLOC_NOFS);

	return error;
}

int
scxfs_trans_alloc(
	struct scxfs_mount	*mp,
	struct scxfs_trans_res	*resp,
	uint			blocks,
	uint			rtextents,
	uint			flags,
	struct scxfs_trans	**tpp)
{
	struct scxfs_trans	*tp;
	int			error;

	/*
	 * Allocate the handle before we do our freeze accounting and setting up
	 * GFP_NOFS allocation context so that we avoid lockdep false positives
	 * by doing GFP_KERNEL allocations inside sb_start_intwrite().
	 */
	tp = kmem_zone_zalloc(scxfs_trans_zone, 0);
	if (!(flags & SCXFS_TRANS_NO_WRITECOUNT))
		sb_start_intwrite(mp->m_super);

	/*
	 * Zero-reservation ("empty") transactions can't modify anything, so
	 * they're allowed to run while we're frozen.
	 */
	WARN_ON(resp->tr_logres > 0 &&
		mp->m_super->s_writers.frozen == SB_FREEZE_COMPLETE);
	atomic_inc(&mp->m_active_trans);

	tp->t_magic = SCXFS_TRANS_HEADER_MAGIC;
	tp->t_flags = flags;
	tp->t_mountp = mp;
	INIT_LIST_HEAD(&tp->t_items);
	INIT_LIST_HEAD(&tp->t_busy);
	INIT_LIST_HEAD(&tp->t_dfops);
	tp->t_firstblock = NULLFSBLOCK;

	error = scxfs_trans_reserve(tp, resp, blocks, rtextents);
	if (error) {
		scxfs_trans_cancel(tp);
		return error;
	}

	trace_scxfs_trans_alloc(tp, _RET_IP_);

	*tpp = tp;
	return 0;
}

/*
 * Create an empty transaction with no reservation.  This is a defensive
 * mechanism for routines that query metadata without actually modifying
 * them -- if the metadata being queried is somehow cross-linked (think a
 * btree block pointer that points higher in the tree), we risk deadlock.
 * However, blocks grabbed as part of a transaction can be re-grabbed.
 * The verifiers will notice the corrupt block and the operation will fail
 * back to userspace without deadlocking.
 *
 * Note the zero-length reservation; this transaction MUST be cancelled
 * without any dirty data.
 *
 * Callers should obtain freeze protection to avoid two conflicts with fs
 * freezing: (1) having active transactions trip the m_active_trans ASSERTs;
 * and (2) grabbing buffers at the same time that freeze is trying to drain
 * the buffer LRU list.
 */
int
scxfs_trans_alloc_empty(
	struct scxfs_mount		*mp,
	struct scxfs_trans		**tpp)
{
	struct scxfs_trans_res		resv = {0};

	return scxfs_trans_alloc(mp, &resv, 0, 0, SCXFS_TRANS_NO_WRITECOUNT, tpp);
}

/*
 * Record the indicated change to the given field for application
 * to the file system's superblock when the transaction commits.
 * For now, just store the change in the transaction structure.
 *
 * Mark the transaction structure to indicate that the superblock
 * needs to be updated before committing.
 *
 * Because we may not be keeping track of allocated/free inodes and
 * used filesystem blocks in the superblock, we do not mark the
 * superblock dirty in this transaction if we modify these fields.
 * We still need to update the transaction deltas so that they get
 * applied to the incore superblock, but we don't want them to
 * cause the superblock to get locked and logged if these are the
 * only fields in the superblock that the transaction modifies.
 */
void
scxfs_trans_mod_sb(
	scxfs_trans_t	*tp,
	uint		field,
	int64_t		delta)
{
	uint32_t	flags = (SCXFS_TRANS_DIRTY|SCXFS_TRANS_SB_DIRTY);
	scxfs_mount_t	*mp = tp->t_mountp;

	switch (field) {
	case SCXFS_TRANS_SB_ICOUNT:
		tp->t_icount_delta += delta;
		if (scxfs_sb_version_haslazysbcount(&mp->m_sb))
			flags &= ~SCXFS_TRANS_SB_DIRTY;
		break;
	case SCXFS_TRANS_SB_IFREE:
		tp->t_ifree_delta += delta;
		if (scxfs_sb_version_haslazysbcount(&mp->m_sb))
			flags &= ~SCXFS_TRANS_SB_DIRTY;
		break;
	case SCXFS_TRANS_SB_FDBLOCKS:
		/*
		 * Track the number of blocks allocated in the transaction.
		 * Make sure it does not exceed the number reserved. If so,
		 * shutdown as this can lead to accounting inconsistency.
		 */
		if (delta < 0) {
			tp->t_blk_res_used += (uint)-delta;
			if (tp->t_blk_res_used > tp->t_blk_res)
				scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		}
		tp->t_fdblocks_delta += delta;
		if (scxfs_sb_version_haslazysbcount(&mp->m_sb))
			flags &= ~SCXFS_TRANS_SB_DIRTY;
		break;
	case SCXFS_TRANS_SB_RES_FDBLOCKS:
		/*
		 * The allocation has already been applied to the
		 * in-core superblock's counter.  This should only
		 * be applied to the on-disk superblock.
		 */
		tp->t_res_fdblocks_delta += delta;
		if (scxfs_sb_version_haslazysbcount(&mp->m_sb))
			flags &= ~SCXFS_TRANS_SB_DIRTY;
		break;
	case SCXFS_TRANS_SB_FREXTENTS:
		/*
		 * Track the number of blocks allocated in the
		 * transaction.  Make sure it does not exceed the
		 * number reserved.
		 */
		if (delta < 0) {
			tp->t_rtx_res_used += (uint)-delta;
			ASSERT(tp->t_rtx_res_used <= tp->t_rtx_res);
		}
		tp->t_frextents_delta += delta;
		break;
	case SCXFS_TRANS_SB_RES_FREXTENTS:
		/*
		 * The allocation has already been applied to the
		 * in-core superblock's counter.  This should only
		 * be applied to the on-disk superblock.
		 */
		ASSERT(delta < 0);
		tp->t_res_frextents_delta += delta;
		break;
	case SCXFS_TRANS_SB_DBLOCKS:
		ASSERT(delta > 0);
		tp->t_dblocks_delta += delta;
		break;
	case SCXFS_TRANS_SB_AGCOUNT:
		ASSERT(delta > 0);
		tp->t_agcount_delta += delta;
		break;
	case SCXFS_TRANS_SB_IMAXPCT:
		tp->t_imaxpct_delta += delta;
		break;
	case SCXFS_TRANS_SB_REXTSIZE:
		tp->t_rextsize_delta += delta;
		break;
	case SCXFS_TRANS_SB_RBMBLOCKS:
		tp->t_rbmblocks_delta += delta;
		break;
	case SCXFS_TRANS_SB_RBLOCKS:
		tp->t_rblocks_delta += delta;
		break;
	case SCXFS_TRANS_SB_REXTENTS:
		tp->t_rextents_delta += delta;
		break;
	case SCXFS_TRANS_SB_REXTSLOG:
		tp->t_rextslog_delta += delta;
		break;
	default:
		ASSERT(0);
		return;
	}

	tp->t_flags |= flags;
}

/*
 * scxfs_trans_apply_sb_deltas() is called from the commit code
 * to bring the superblock buffer into the current transaction
 * and modify it as requested by earlier calls to scxfs_trans_mod_sb().
 *
 * For now we just look at each field allowed to change and change
 * it if necessary.
 */
STATIC void
scxfs_trans_apply_sb_deltas(
	scxfs_trans_t	*tp)
{
	scxfs_dsb_t	*sbp;
	scxfs_buf_t	*bp;
	int		whole = 0;

	bp = scxfs_trans_getsb(tp, tp->t_mountp);
	sbp = SCXFS_BUF_TO_SBP(bp);

	/*
	 * Check that superblock mods match the mods made to AGF counters.
	 */
	ASSERT((tp->t_fdblocks_delta + tp->t_res_fdblocks_delta) ==
	       (tp->t_ag_freeblks_delta + tp->t_ag_flist_delta +
		tp->t_ag_btree_delta));

	/*
	 * Only update the superblock counters if we are logging them
	 */
	if (!scxfs_sb_version_haslazysbcount(&(tp->t_mountp->m_sb))) {
		if (tp->t_icount_delta)
			be64_add_cpu(&sbp->sb_icount, tp->t_icount_delta);
		if (tp->t_ifree_delta)
			be64_add_cpu(&sbp->sb_ifree, tp->t_ifree_delta);
		if (tp->t_fdblocks_delta)
			be64_add_cpu(&sbp->sb_fdblocks, tp->t_fdblocks_delta);
		if (tp->t_res_fdblocks_delta)
			be64_add_cpu(&sbp->sb_fdblocks, tp->t_res_fdblocks_delta);
	}

	if (tp->t_frextents_delta)
		be64_add_cpu(&sbp->sb_frextents, tp->t_frextents_delta);
	if (tp->t_res_frextents_delta)
		be64_add_cpu(&sbp->sb_frextents, tp->t_res_frextents_delta);

	if (tp->t_dblocks_delta) {
		be64_add_cpu(&sbp->sb_dblocks, tp->t_dblocks_delta);
		whole = 1;
	}
	if (tp->t_agcount_delta) {
		be32_add_cpu(&sbp->sb_agcount, tp->t_agcount_delta);
		whole = 1;
	}
	if (tp->t_imaxpct_delta) {
		sbp->sb_imax_pct += tp->t_imaxpct_delta;
		whole = 1;
	}
	if (tp->t_rextsize_delta) {
		be32_add_cpu(&sbp->sb_rextsize, tp->t_rextsize_delta);
		whole = 1;
	}
	if (tp->t_rbmblocks_delta) {
		be32_add_cpu(&sbp->sb_rbmblocks, tp->t_rbmblocks_delta);
		whole = 1;
	}
	if (tp->t_rblocks_delta) {
		be64_add_cpu(&sbp->sb_rblocks, tp->t_rblocks_delta);
		whole = 1;
	}
	if (tp->t_rextents_delta) {
		be64_add_cpu(&sbp->sb_rextents, tp->t_rextents_delta);
		whole = 1;
	}
	if (tp->t_rextslog_delta) {
		sbp->sb_rextslog += tp->t_rextslog_delta;
		whole = 1;
	}

	scxfs_trans_buf_set_type(tp, bp, SCXFS_BLFT_SB_BUF);
	if (whole)
		/*
		 * Log the whole thing, the fields are noncontiguous.
		 */
		scxfs_trans_log_buf(tp, bp, 0, sizeof(scxfs_dsb_t) - 1);
	else
		/*
		 * Since all the modifiable fields are contiguous, we
		 * can get away with this.
		 */
		scxfs_trans_log_buf(tp, bp, offsetof(scxfs_dsb_t, sb_icount),
				  offsetof(scxfs_dsb_t, sb_frextents) +
				  sizeof(sbp->sb_frextents) - 1);
}

STATIC int
scxfs_sb_mod8(
	uint8_t			*field,
	int8_t			delta)
{
	int8_t			counter = *field;

	counter += delta;
	if (counter < 0) {
		ASSERT(0);
		return -EINVAL;
	}
	*field = counter;
	return 0;
}

STATIC int
scxfs_sb_mod32(
	uint32_t		*field,
	int32_t			delta)
{
	int32_t			counter = *field;

	counter += delta;
	if (counter < 0) {
		ASSERT(0);
		return -EINVAL;
	}
	*field = counter;
	return 0;
}

STATIC int
scxfs_sb_mod64(
	uint64_t		*field,
	int64_t			delta)
{
	int64_t			counter = *field;

	counter += delta;
	if (counter < 0) {
		ASSERT(0);
		return -EINVAL;
	}
	*field = counter;
	return 0;
}

/*
 * scxfs_trans_unreserve_and_mod_sb() is called to release unused reservations
 * and apply superblock counter changes to the in-core superblock.  The
 * t_res_fdblocks_delta and t_res_frextents_delta fields are explicitly NOT
 * applied to the in-core superblock.  The idea is that that has already been
 * done.
 *
 * If we are not logging superblock counters, then the inode allocated/free and
 * used block counts are not updated in the on disk superblock. In this case,
 * SCXFS_TRANS_SB_DIRTY will not be set when the transaction is updated but we
 * still need to update the incore superblock with the changes.
 */
void
scxfs_trans_unreserve_and_mod_sb(
	struct scxfs_trans	*tp)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	bool			rsvd = (tp->t_flags & SCXFS_TRANS_RESERVE) != 0;
	int64_t			blkdelta = 0;
	int64_t			rtxdelta = 0;
	int64_t			idelta = 0;
	int64_t			ifreedelta = 0;
	int			error;

	/* calculate deltas */
	if (tp->t_blk_res > 0)
		blkdelta = tp->t_blk_res;
	if ((tp->t_fdblocks_delta != 0) &&
	    (scxfs_sb_version_haslazysbcount(&mp->m_sb) ||
	     (tp->t_flags & SCXFS_TRANS_SB_DIRTY)))
	        blkdelta += tp->t_fdblocks_delta;

	if (tp->t_rtx_res > 0)
		rtxdelta = tp->t_rtx_res;
	if ((tp->t_frextents_delta != 0) &&
	    (tp->t_flags & SCXFS_TRANS_SB_DIRTY))
		rtxdelta += tp->t_frextents_delta;

	if (scxfs_sb_version_haslazysbcount(&mp->m_sb) ||
	     (tp->t_flags & SCXFS_TRANS_SB_DIRTY)) {
		idelta = tp->t_icount_delta;
		ifreedelta = tp->t_ifree_delta;
	}

	/* apply the per-cpu counters */
	if (blkdelta) {
		error = scxfs_mod_fdblocks(mp, blkdelta, rsvd);
		if (error)
			goto out;
	}

	if (idelta) {
		error = scxfs_mod_icount(mp, idelta);
		if (error)
			goto out_undo_fdblocks;
	}

	if (ifreedelta) {
		error = scxfs_mod_ifree(mp, ifreedelta);
		if (error)
			goto out_undo_icount;
	}

	if (rtxdelta == 0 && !(tp->t_flags & SCXFS_TRANS_SB_DIRTY))
		return;

	/* apply remaining deltas */
	spin_lock(&mp->m_sb_lock);
	if (rtxdelta) {
		error = scxfs_sb_mod64(&mp->m_sb.sb_frextents, rtxdelta);
		if (error)
			goto out_undo_ifree;
	}

	if (tp->t_dblocks_delta != 0) {
		error = scxfs_sb_mod64(&mp->m_sb.sb_dblocks, tp->t_dblocks_delta);
		if (error)
			goto out_undo_frextents;
	}
	if (tp->t_agcount_delta != 0) {
		error = scxfs_sb_mod32(&mp->m_sb.sb_agcount, tp->t_agcount_delta);
		if (error)
			goto out_undo_dblocks;
	}
	if (tp->t_imaxpct_delta != 0) {
		error = scxfs_sb_mod8(&mp->m_sb.sb_imax_pct, tp->t_imaxpct_delta);
		if (error)
			goto out_undo_agcount;
	}
	if (tp->t_rextsize_delta != 0) {
		error = scxfs_sb_mod32(&mp->m_sb.sb_rextsize,
				     tp->t_rextsize_delta);
		if (error)
			goto out_undo_imaxpct;
	}
	if (tp->t_rbmblocks_delta != 0) {
		error = scxfs_sb_mod32(&mp->m_sb.sb_rbmblocks,
				     tp->t_rbmblocks_delta);
		if (error)
			goto out_undo_rextsize;
	}
	if (tp->t_rblocks_delta != 0) {
		error = scxfs_sb_mod64(&mp->m_sb.sb_rblocks, tp->t_rblocks_delta);
		if (error)
			goto out_undo_rbmblocks;
	}
	if (tp->t_rextents_delta != 0) {
		error = scxfs_sb_mod64(&mp->m_sb.sb_rextents,
				     tp->t_rextents_delta);
		if (error)
			goto out_undo_rblocks;
	}
	if (tp->t_rextslog_delta != 0) {
		error = scxfs_sb_mod8(&mp->m_sb.sb_rextslog,
				     tp->t_rextslog_delta);
		if (error)
			goto out_undo_rextents;
	}
	spin_unlock(&mp->m_sb_lock);
	return;

out_undo_rextents:
	if (tp->t_rextents_delta)
		scxfs_sb_mod64(&mp->m_sb.sb_rextents, -tp->t_rextents_delta);
out_undo_rblocks:
	if (tp->t_rblocks_delta)
		scxfs_sb_mod64(&mp->m_sb.sb_rblocks, -tp->t_rblocks_delta);
out_undo_rbmblocks:
	if (tp->t_rbmblocks_delta)
		scxfs_sb_mod32(&mp->m_sb.sb_rbmblocks, -tp->t_rbmblocks_delta);
out_undo_rextsize:
	if (tp->t_rextsize_delta)
		scxfs_sb_mod32(&mp->m_sb.sb_rextsize, -tp->t_rextsize_delta);
out_undo_imaxpct:
	if (tp->t_rextsize_delta)
		scxfs_sb_mod8(&mp->m_sb.sb_imax_pct, -tp->t_imaxpct_delta);
out_undo_agcount:
	if (tp->t_agcount_delta)
		scxfs_sb_mod32(&mp->m_sb.sb_agcount, -tp->t_agcount_delta);
out_undo_dblocks:
	if (tp->t_dblocks_delta)
		scxfs_sb_mod64(&mp->m_sb.sb_dblocks, -tp->t_dblocks_delta);
out_undo_frextents:
	if (rtxdelta)
		scxfs_sb_mod64(&mp->m_sb.sb_frextents, -rtxdelta);
out_undo_ifree:
	spin_unlock(&mp->m_sb_lock);
	if (ifreedelta)
		scxfs_mod_ifree(mp, -ifreedelta);
out_undo_icount:
	if (idelta)
		scxfs_mod_icount(mp, -idelta);
out_undo_fdblocks:
	if (blkdelta)
		scxfs_mod_fdblocks(mp, -blkdelta, rsvd);
out:
	ASSERT(error == 0);
	return;
}

/* Add the given log item to the transaction's list of log items. */
void
scxfs_trans_add_item(
	struct scxfs_trans	*tp,
	struct scxfs_log_item	*lip)
{
	ASSERT(lip->li_mountp == tp->t_mountp);
	ASSERT(lip->li_ailp == tp->t_mountp->m_ail);
	ASSERT(list_empty(&lip->li_trans));
	ASSERT(!test_bit(SCXFS_LI_DIRTY, &lip->li_flags));

	list_add_tail(&lip->li_trans, &tp->t_items);
	trace_scxfs_trans_add_item(tp, _RET_IP_);
}

/*
 * Unlink the log item from the transaction. the log item is no longer
 * considered dirty in this transaction, as the linked transaction has
 * finished, either by abort or commit completion.
 */
void
scxfs_trans_del_item(
	struct scxfs_log_item	*lip)
{
	clear_bit(SCXFS_LI_DIRTY, &lip->li_flags);
	list_del_init(&lip->li_trans);
}

/* Detach and unlock all of the items in a transaction */
static void
scxfs_trans_free_items(
	struct scxfs_trans	*tp,
	bool			abort)
{
	struct scxfs_log_item	*lip, *next;

	trace_scxfs_trans_free_items(tp, _RET_IP_);

	list_for_each_entry_safe(lip, next, &tp->t_items, li_trans) {
		scxfs_trans_del_item(lip);
		if (abort)
			set_bit(SCXFS_LI_ABORTED, &lip->li_flags);
		if (lip->li_ops->iop_release)
			lip->li_ops->iop_release(lip);
	}
}

static inline void
scxfs_log_item_batch_insert(
	struct scxfs_ail		*ailp,
	struct scxfs_ail_cursor	*cur,
	struct scxfs_log_item	**log_items,
	int			nr_items,
	scxfs_lsn_t		commit_lsn)
{
	int	i;

	spin_lock(&ailp->ail_lock);
	/* scxfs_trans_ail_update_bulk drops ailp->ail_lock */
	scxfs_trans_ail_update_bulk(ailp, cur, log_items, nr_items, commit_lsn);

	for (i = 0; i < nr_items; i++) {
		struct scxfs_log_item *lip = log_items[i];

		if (lip->li_ops->iop_unpin)
			lip->li_ops->iop_unpin(lip, 0);
	}
}

/*
 * Bulk operation version of scxfs_trans_committed that takes a log vector of
 * items to insert into the AIL. This uses bulk AIL insertion techniques to
 * minimise lock traffic.
 *
 * If we are called with the aborted flag set, it is because a log write during
 * a CIL checkpoint commit has failed. In this case, all the items in the
 * checkpoint have already gone through iop_committed and iop_committing, which
 * means that checkpoint commit abort handling is treated exactly the same
 * as an iclog write error even though we haven't started any IO yet. Hence in
 * this case all we need to do is iop_committed processing, followed by an
 * iop_unpin(aborted) call.
 *
 * The AIL cursor is used to optimise the insert process. If commit_lsn is not
 * at the end of the AIL, the insert cursor avoids the need to walk
 * the AIL to find the insertion point on every scxfs_log_item_batch_insert()
 * call. This saves a lot of needless list walking and is a net win, even
 * though it slightly increases that amount of AIL lock traffic to set it up
 * and tear it down.
 */
void
scxfs_trans_committed_bulk(
	struct scxfs_ail		*ailp,
	struct scxfs_log_vec	*log_vector,
	scxfs_lsn_t		commit_lsn,
	bool			aborted)
{
#define LOG_ITEM_BATCH_SIZE	32
	struct scxfs_log_item	*log_items[LOG_ITEM_BATCH_SIZE];
	struct scxfs_log_vec	*lv;
	struct scxfs_ail_cursor	cur;
	int			i = 0;

	spin_lock(&ailp->ail_lock);
	scxfs_trans_ail_cursor_last(ailp, &cur, commit_lsn);
	spin_unlock(&ailp->ail_lock);

	/* unpin all the log items */
	for (lv = log_vector; lv; lv = lv->lv_next ) {
		struct scxfs_log_item	*lip = lv->lv_item;
		scxfs_lsn_t		item_lsn;

		if (aborted)
			set_bit(SCXFS_LI_ABORTED, &lip->li_flags);

		if (lip->li_ops->flags & SCXFS_ITEM_RELEASE_WHEN_COMMITTED) {
			lip->li_ops->iop_release(lip);
			continue;
		}

		if (lip->li_ops->iop_committed)
			item_lsn = lip->li_ops->iop_committed(lip, commit_lsn);
		else
			item_lsn = commit_lsn;

		/* item_lsn of -1 means the item needs no further processing */
		if (SCXFS_LSN_CMP(item_lsn, (scxfs_lsn_t)-1) == 0)
			continue;

		/*
		 * if we are aborting the operation, no point in inserting the
		 * object into the AIL as we are in a shutdown situation.
		 */
		if (aborted) {
			ASSERT(SCXFS_FORCED_SHUTDOWN(ailp->ail_mount));
			if (lip->li_ops->iop_unpin)
				lip->li_ops->iop_unpin(lip, 1);
			continue;
		}

		if (item_lsn != commit_lsn) {

			/*
			 * Not a bulk update option due to unusual item_lsn.
			 * Push into AIL immediately, rechecking the lsn once
			 * we have the ail lock. Then unpin the item. This does
			 * not affect the AIL cursor the bulk insert path is
			 * using.
			 */
			spin_lock(&ailp->ail_lock);
			if (SCXFS_LSN_CMP(item_lsn, lip->li_lsn) > 0)
				scxfs_trans_ail_update(ailp, lip, item_lsn);
			else
				spin_unlock(&ailp->ail_lock);
			if (lip->li_ops->iop_unpin)
				lip->li_ops->iop_unpin(lip, 0);
			continue;
		}

		/* Item is a candidate for bulk AIL insert.  */
		log_items[i++] = lv->lv_item;
		if (i >= LOG_ITEM_BATCH_SIZE) {
			scxfs_log_item_batch_insert(ailp, &cur, log_items,
					LOG_ITEM_BATCH_SIZE, commit_lsn);
			i = 0;
		}
	}

	/* make sure we insert the remainder! */
	if (i)
		scxfs_log_item_batch_insert(ailp, &cur, log_items, i, commit_lsn);

	spin_lock(&ailp->ail_lock);
	scxfs_trans_ail_cursor_done(&cur);
	spin_unlock(&ailp->ail_lock);
}

/*
 * Commit the given transaction to the log.
 *
 * SCXFS disk error handling mechanism is not based on a typical
 * transaction abort mechanism. Logically after the filesystem
 * gets marked 'SHUTDOWN', we can't let any new transactions
 * be durable - ie. committed to disk - because some metadata might
 * be inconsistent. In such cases, this returns an error, and the
 * caller may assume that all locked objects joined to the transaction
 * have already been unlocked as if the commit had succeeded.
 * Do not reference the transaction structure after this call.
 */
static int
__scxfs_trans_commit(
	struct scxfs_trans	*tp,
	bool			regrant)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	scxfs_lsn_t		commit_lsn = -1;
	int			error = 0;
	int			sync = tp->t_flags & SCXFS_TRANS_SYNC;

	trace_scxfs_trans_commit(tp, _RET_IP_);

	/*
	 * Finish deferred items on final commit. Only permanent transactions
	 * should ever have deferred ops.
	 */
	WARN_ON_ONCE(!list_empty(&tp->t_dfops) &&
		     !(tp->t_flags & SCXFS_TRANS_PERM_LOG_RES));
	if (!regrant && (tp->t_flags & SCXFS_TRANS_PERM_LOG_RES)) {
		error = scxfs_defer_finish_noroll(&tp);
		if (error)
			goto out_unreserve;
	}

	/*
	 * If there is nothing to be logged by the transaction,
	 * then unlock all of the items associated with the
	 * transaction and free the transaction structure.
	 * Also make sure to return any reserved blocks to
	 * the free pool.
	 */
	if (!(tp->t_flags & SCXFS_TRANS_DIRTY))
		goto out_unreserve;

	if (SCXFS_FORCED_SHUTDOWN(mp)) {
		error = -EIO;
		goto out_unreserve;
	}

	ASSERT(tp->t_ticket != NULL);

	/*
	 * If we need to update the superblock, then do it now.
	 */
	if (tp->t_flags & SCXFS_TRANS_SB_DIRTY)
		scxfs_trans_apply_sb_deltas(tp);
	scxfs_trans_apply_dquot_deltas(tp);

	scxfs_log_commit_cil(mp, tp, &commit_lsn, regrant);

	current_restore_flags_nested(&tp->t_pflags, PF_MEMALLOC_NOFS);
	scxfs_trans_free(tp);

	/*
	 * If the transaction needs to be synchronous, then force the
	 * log out now and wait for it.
	 */
	if (sync) {
		error = scxfs_log_force_lsn(mp, commit_lsn, SCXFS_LOG_SYNC, NULL);
		SCXFS_STATS_INC(mp, xs_trans_sync);
	} else {
		SCXFS_STATS_INC(mp, xs_trans_async);
	}

	return error;

out_unreserve:
	scxfs_trans_unreserve_and_mod_sb(tp);

	/*
	 * It is indeed possible for the transaction to be not dirty but
	 * the dqinfo portion to be.  All that means is that we have some
	 * (non-persistent) quota reservations that need to be unreserved.
	 */
	scxfs_trans_unreserve_and_mod_dquots(tp);
	if (tp->t_ticket) {
		commit_lsn = scxfs_log_done(mp, tp->t_ticket, NULL, regrant);
		if (commit_lsn == -1 && !error)
			error = -EIO;
		tp->t_ticket = NULL;
	}
	current_restore_flags_nested(&tp->t_pflags, PF_MEMALLOC_NOFS);
	scxfs_trans_free_items(tp, !!error);
	scxfs_trans_free(tp);

	SCXFS_STATS_INC(mp, xs_trans_empty);
	return error;
}

int
scxfs_trans_commit(
	struct scxfs_trans	*tp)
{
	return __scxfs_trans_commit(tp, false);
}

/*
 * Unlock all of the transaction's items and free the transaction.
 * The transaction must not have modified any of its items, because
 * there is no way to restore them to their previous state.
 *
 * If the transaction has made a log reservation, make sure to release
 * it as well.
 */
void
scxfs_trans_cancel(
	struct scxfs_trans	*tp)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	bool			dirty = (tp->t_flags & SCXFS_TRANS_DIRTY);

	trace_scxfs_trans_cancel(tp, _RET_IP_);

	if (tp->t_flags & SCXFS_TRANS_PERM_LOG_RES)
		scxfs_defer_cancel(tp);

	/*
	 * See if the caller is relying on us to shut down the
	 * filesystem.  This happens in paths where we detect
	 * corruption and decide to give up.
	 */
	if (dirty && !SCXFS_FORCED_SHUTDOWN(mp)) {
		SCXFS_ERROR_REPORT("scxfs_trans_cancel", SCXFS_ERRLEVEL_LOW, mp);
		scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
	}
#ifdef DEBUG
	if (!dirty && !SCXFS_FORCED_SHUTDOWN(mp)) {
		struct scxfs_log_item *lip;

		list_for_each_entry(lip, &tp->t_items, li_trans)
			ASSERT(!(lip->li_type == SCXFS_LI_EFD));
	}
#endif
	scxfs_trans_unreserve_and_mod_sb(tp);
	scxfs_trans_unreserve_and_mod_dquots(tp);

	if (tp->t_ticket) {
		scxfs_log_done(mp, tp->t_ticket, NULL, false);
		tp->t_ticket = NULL;
	}

	/* mark this thread as no longer being in a transaction */
	current_restore_flags_nested(&tp->t_pflags, PF_MEMALLOC_NOFS);

	scxfs_trans_free_items(tp, dirty);
	scxfs_trans_free(tp);
}

/*
 * Roll from one trans in the sequence of PERMANENT transactions to
 * the next: permanent transactions are only flushed out when
 * committed with scxfs_trans_commit(), but we still want as soon
 * as possible to let chunks of it go to the log. So we commit the
 * chunk we've been working on and get a new transaction to continue.
 */
int
scxfs_trans_roll(
	struct scxfs_trans	**tpp)
{
	struct scxfs_trans	*trans = *tpp;
	struct scxfs_trans_res	tres;
	int			error;

	trace_scxfs_trans_roll(trans, _RET_IP_);

	/*
	 * Copy the critical parameters from one trans to the next.
	 */
	tres.tr_logres = trans->t_log_res;
	tres.tr_logcount = trans->t_log_count;

	*tpp = scxfs_trans_dup(trans);

	/*
	 * Commit the current transaction.
	 * If this commit failed, then it'd just unlock those items that
	 * are not marked ihold. That also means that a filesystem shutdown
	 * is in progress. The caller takes the responsibility to cancel
	 * the duplicate transaction that gets returned.
	 */
	error = __scxfs_trans_commit(trans, true);
	if (error)
		return error;

	/*
	 * Reserve space in the log for the next transaction.
	 * This also pushes items in the "AIL", the list of logged items,
	 * out to disk if they are taking up space at the tail of the log
	 * that we want to use.  This requires that either nothing be locked
	 * across this call, or that anything that is locked be logged in
	 * the prior and the next transactions.
	 */
	tres.tr_logflags = SCXFS_TRANS_PERM_LOG_RES;
	return scxfs_trans_reserve(*tpp, &tres, 0, 0);
}
