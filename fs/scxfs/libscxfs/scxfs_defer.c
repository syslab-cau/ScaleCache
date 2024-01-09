// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_defer.h"
#include "scxfs_trans.h"
#include "scxfs_buf_item.h"
#include "scxfs_inode.h"
#include "scxfs_inode_item.h"
#include "scxfs_trace.h"

/*
 * Deferred Operations in SCXFS
 *
 * Due to the way locking rules work in SCXFS, certain transactions (block
 * mapping and unmapping, typically) have permanent reservations so that
 * we can roll the transaction to adhere to AG locking order rules and
 * to unlock buffers between metadata updates.  Prior to rmap/reflink,
 * the mapping code had a mechanism to perform these deferrals for
 * extents that were going to be freed; this code makes that facility
 * more generic.
 *
 * When adding the reverse mapping and reflink features, it became
 * necessary to perform complex remapping multi-transactions to comply
 * with AG locking order rules, and to be able to spread a single
 * refcount update operation (an operation on an n-block extent can
 * update as many as n records!) among multiple transactions.  SCXFS can
 * roll a transaction to facilitate this, but using this facility
 * requires us to log "intent" items in case log recovery needs to
 * redo the operation, and to log "done" items to indicate that redo
 * is not necessary.
 *
 * Deferred work is tracked in scxfs_defer_pending items.  Each pending
 * item tracks one type of deferred work.  Incoming work items (which
 * have not yet had an intent logged) are attached to a pending item
 * on the dop_intake list, where they wait for the caller to finish
 * the deferred operations.
 *
 * Finishing a set of deferred operations is an involved process.  To
 * start, we define "rolling a deferred-op transaction" as follows:
 *
 * > For each scxfs_defer_pending item on the dop_intake list,
 *   - Sort the work items in AG order.  SCXFS locking
 *     order rules require us to lock buffers in AG order.
 *   - Create a log intent item for that type.
 *   - Attach it to the pending item.
 *   - Move the pending item from the dop_intake list to the
 *     dop_pending list.
 * > Roll the transaction.
 *
 * NOTE: To avoid exceeding the transaction reservation, we limit the
 * number of items that we attach to a given scxfs_defer_pending.
 *
 * The actual finishing process looks like this:
 *
 * > For each scxfs_defer_pending in the dop_pending list,
 *   - Roll the deferred-op transaction as above.
 *   - Create a log done item for that type, and attach it to the
 *     log intent item.
 *   - For each work item attached to the log intent item,
 *     * Perform the described action.
 *     * Attach the work item to the log done item.
 *     * If the result of doing the work was -EAGAIN, ->finish work
 *       wants a new transaction.  See the "Requesting a Fresh
 *       Transaction while Finishing Deferred Work" section below for
 *       details.
 *
 * The key here is that we must log an intent item for all pending
 * work items every time we roll the transaction, and that we must log
 * a done item as soon as the work is completed.  With this mechanism
 * we can perform complex remapping operations, chaining intent items
 * as needed.
 *
 * Requesting a Fresh Transaction while Finishing Deferred Work
 *
 * If ->finish_item decides that it needs a fresh transaction to
 * finish the work, it must ask its caller (scxfs_defer_finish) for a
 * continuation.  The most likely cause of this circumstance are the
 * refcount adjust functions deciding that they've logged enough items
 * to be at risk of exceeding the transaction reservation.
 *
 * To get a fresh transaction, we want to log the existing log done
 * item to prevent the log intent item from replaying, immediately log
 * a new log intent item with the unfinished work items, roll the
 * transaction, and re-call ->finish_item wherever it left off.  The
 * log done item and the new log intent item must be in the same
 * transaction or atomicity cannot be guaranteed; defer_finish ensures
 * that this happens.
 *
 * This requires some coordination between ->finish_item and
 * defer_finish.  Upon deciding to request a new transaction,
 * ->finish_item should update the current work item to reflect the
 * unfinished work.  Next, it should reset the log done item's list
 * count to the number of items finished, and return -EAGAIN.
 * defer_finish sees the -EAGAIN, logs the new log intent item
 * with the remaining work items, and leaves the scxfs_defer_pending
 * item at the head of the dop_work queue.  Then it rolls the
 * transaction and picks up processing where it left off.  It is
 * required that ->finish_item must be careful to leave enough
 * transaction reservation to fit the new log intent item.
 *
 * This is an example of remapping the extent (E, E+B) into file X at
 * offset A and dealing with the extent (C, C+B) already being mapped
 * there:
 * +-------------------------------------------------+
 * | Unmap file X startblock C offset A length B     | t0
 * | Intent to reduce refcount for extent (C, B)     |
 * | Intent to remove rmap (X, C, A, B)              |
 * | Intent to free extent (D, 1) (bmbt block)       |
 * | Intent to map (X, A, B) at startblock E         |
 * +-------------------------------------------------+
 * | Map file X startblock E offset A length B       | t1
 * | Done mapping (X, E, A, B)                       |
 * | Intent to increase refcount for extent (E, B)   |
 * | Intent to add rmap (X, E, A, B)                 |
 * +-------------------------------------------------+
 * | Reduce refcount for extent (C, B)               | t2
 * | Done reducing refcount for extent (C, 9)        |
 * | Intent to reduce refcount for extent (C+9, B-9) |
 * | (ran out of space after 9 refcount updates)     |
 * +-------------------------------------------------+
 * | Reduce refcount for extent (C+9, B+9)           | t3
 * | Done reducing refcount for extent (C+9, B-9)    |
 * | Increase refcount for extent (E, B)             |
 * | Done increasing refcount for extent (E, B)      |
 * | Intent to free extent (C, B)                    |
 * | Intent to free extent (F, 1) (refcountbt block) |
 * | Intent to remove rmap (F, 1, REFC)              |
 * +-------------------------------------------------+
 * | Remove rmap (X, C, A, B)                        | t4
 * | Done removing rmap (X, C, A, B)                 |
 * | Add rmap (X, E, A, B)                           |
 * | Done adding rmap (X, E, A, B)                   |
 * | Remove rmap (F, 1, REFC)                        |
 * | Done removing rmap (F, 1, REFC)                 |
 * +-------------------------------------------------+
 * | Free extent (C, B)                              | t5
 * | Done freeing extent (C, B)                      |
 * | Free extent (D, 1)                              |
 * | Done freeing extent (D, 1)                      |
 * | Free extent (F, 1)                              |
 * | Done freeing extent (F, 1)                      |
 * +-------------------------------------------------+
 *
 * If we should crash before t2 commits, log recovery replays
 * the following intent items:
 *
 * - Intent to reduce refcount for extent (C, B)
 * - Intent to remove rmap (X, C, A, B)
 * - Intent to free extent (D, 1) (bmbt block)
 * - Intent to increase refcount for extent (E, B)
 * - Intent to add rmap (X, E, A, B)
 *
 * In the process of recovering, it should also generate and take care
 * of these intent items:
 *
 * - Intent to free extent (C, B)
 * - Intent to free extent (F, 1) (refcountbt block)
 * - Intent to remove rmap (F, 1, REFC)
 *
 * Note that the continuation requested between t2 and t3 is likely to
 * reoccur.
 */

static const struct scxfs_defer_op_type *defer_op_types[] = {
	[SCXFS_DEFER_OPS_TYPE_BMAP]	= &scxfs_bmap_update_defer_type,
	[SCXFS_DEFER_OPS_TYPE_REFCOUNT]	= &scxfs_refcount_update_defer_type,
	[SCXFS_DEFER_OPS_TYPE_RMAP]	= &scxfs_rmap_update_defer_type,
	[SCXFS_DEFER_OPS_TYPE_FREE]	= &scxfs_extent_free_defer_type,
	[SCXFS_DEFER_OPS_TYPE_AGFL_FREE]	= &scxfs_agfl_free_defer_type,
};

/*
 * For each pending item in the intake list, log its intent item and the
 * associated extents, then add the entire intake list to the end of
 * the pending list.
 */
STATIC void
scxfs_defer_create_intents(
	struct scxfs_trans		*tp)
{
	struct list_head		*li;
	struct scxfs_defer_pending	*dfp;
	const struct scxfs_defer_op_type	*ops;

	list_for_each_entry(dfp, &tp->t_dfops, dfp_list) {
		ops = defer_op_types[dfp->dfp_type];
		dfp->dfp_intent = ops->create_intent(tp, dfp->dfp_count);
		trace_scxfs_defer_create_intent(tp->t_mountp, dfp);
		list_sort(tp->t_mountp, &dfp->dfp_work, ops->diff_items);
		list_for_each(li, &dfp->dfp_work)
			ops->log_item(tp, dfp->dfp_intent, li);
	}
}

/* Abort all the intents that were committed. */
STATIC void
scxfs_defer_trans_abort(
	struct scxfs_trans		*tp,
	struct list_head		*dop_pending)
{
	struct scxfs_defer_pending	*dfp;
	const struct scxfs_defer_op_type	*ops;

	trace_scxfs_defer_trans_abort(tp, _RET_IP_);

	/* Abort intent items that don't have a done item. */
	list_for_each_entry(dfp, dop_pending, dfp_list) {
		ops = defer_op_types[dfp->dfp_type];
		trace_scxfs_defer_pending_abort(tp->t_mountp, dfp);
		if (dfp->dfp_intent && !dfp->dfp_done) {
			ops->abort_intent(dfp->dfp_intent);
			dfp->dfp_intent = NULL;
		}
	}
}

/* Roll a transaction so we can do some deferred op processing. */
STATIC int
scxfs_defer_trans_roll(
	struct scxfs_trans		**tpp)
{
	struct scxfs_trans		*tp = *tpp;
	struct scxfs_buf_log_item		*bli;
	struct scxfs_inode_log_item	*ili;
	struct scxfs_log_item		*lip;
	struct scxfs_buf			*bplist[SCXFS_DEFER_OPS_NR_BUFS];
	struct scxfs_inode		*iplist[SCXFS_DEFER_OPS_NR_INODES];
	int				bpcount = 0, ipcount = 0;
	int				i;
	int				error;

	list_for_each_entry(lip, &tp->t_items, li_trans) {
		switch (lip->li_type) {
		case SCXFS_LI_BUF:
			bli = container_of(lip, struct scxfs_buf_log_item,
					   bli_item);
			if (bli->bli_flags & SCXFS_BLI_HOLD) {
				if (bpcount >= SCXFS_DEFER_OPS_NR_BUFS) {
					ASSERT(0);
					return -EFSCORRUPTED;
				}
				scxfs_trans_dirty_buf(tp, bli->bli_buf);
				bplist[bpcount++] = bli->bli_buf;
			}
			break;
		case SCXFS_LI_INODE:
			ili = container_of(lip, struct scxfs_inode_log_item,
					   ili_item);
			if (ili->ili_lock_flags == 0) {
				if (ipcount >= SCXFS_DEFER_OPS_NR_INODES) {
					ASSERT(0);
					return -EFSCORRUPTED;
				}
				scxfs_trans_log_inode(tp, ili->ili_inode,
						    SCXFS_ILOG_CORE);
				iplist[ipcount++] = ili->ili_inode;
			}
			break;
		default:
			break;
		}
	}

	trace_scxfs_defer_trans_roll(tp, _RET_IP_);

	/*
	 * Roll the transaction.  Rolling always given a new transaction (even
	 * if committing the old one fails!) to hand back to the caller, so we
	 * join the held resources to the new transaction so that we always
	 * return with the held resources joined to @tpp, no matter what
	 * happened.
	 */
	error = scxfs_trans_roll(tpp);
	tp = *tpp;

	/* Rejoin the joined inodes. */
	for (i = 0; i < ipcount; i++)
		scxfs_trans_ijoin(tp, iplist[i], 0);

	/* Rejoin the buffers and dirty them so the log moves forward. */
	for (i = 0; i < bpcount; i++) {
		scxfs_trans_bjoin(tp, bplist[i]);
		scxfs_trans_bhold(tp, bplist[i]);
	}

	if (error)
		trace_scxfs_defer_trans_roll_error(tp, error);
	return error;
}

/*
 * Reset an already used dfops after finish.
 */
static void
scxfs_defer_reset(
	struct scxfs_trans	*tp)
{
	ASSERT(list_empty(&tp->t_dfops));

	/*
	 * Low mode state transfers across transaction rolls to mirror dfops
	 * lifetime. Clear it now that dfops is reset.
	 */
	tp->t_flags &= ~SCXFS_TRANS_LOWMODE;
}

/*
 * Free up any items left in the list.
 */
static void
scxfs_defer_cancel_list(
	struct scxfs_mount		*mp,
	struct list_head		*dop_list)
{
	struct scxfs_defer_pending	*dfp;
	struct scxfs_defer_pending	*pli;
	struct list_head		*pwi;
	struct list_head		*n;
	const struct scxfs_defer_op_type	*ops;

	/*
	 * Free the pending items.  Caller should already have arranged
	 * for the intent items to be released.
	 */
	list_for_each_entry_safe(dfp, pli, dop_list, dfp_list) {
		ops = defer_op_types[dfp->dfp_type];
		trace_scxfs_defer_cancel_list(mp, dfp);
		list_del(&dfp->dfp_list);
		list_for_each_safe(pwi, n, &dfp->dfp_work) {
			list_del(pwi);
			dfp->dfp_count--;
			ops->cancel_item(pwi);
		}
		ASSERT(dfp->dfp_count == 0);
		kmem_free(dfp);
	}
}

/*
 * Finish all the pending work.  This involves logging intent items for
 * any work items that wandered in since the last transaction roll (if
 * one has even happened), rolling the transaction, and finishing the
 * work items in the first item on the logged-and-pending list.
 *
 * If an inode is provided, relog it to the new transaction.
 */
int
scxfs_defer_finish_noroll(
	struct scxfs_trans		**tp)
{
	struct scxfs_defer_pending	*dfp;
	struct list_head		*li;
	struct list_head		*n;
	void				*state;
	int				error = 0;
	const struct scxfs_defer_op_type	*ops;
	LIST_HEAD(dop_pending);

	ASSERT((*tp)->t_flags & SCXFS_TRANS_PERM_LOG_RES);

	trace_scxfs_defer_finish(*tp, _RET_IP_);

	/* Until we run out of pending work to finish... */
	while (!list_empty(&dop_pending) || !list_empty(&(*tp)->t_dfops)) {
		/* log intents and pull in intake items */
		scxfs_defer_create_intents(*tp);
		list_splice_tail_init(&(*tp)->t_dfops, &dop_pending);

		/*
		 * Roll the transaction.
		 */
		error = scxfs_defer_trans_roll(tp);
		if (error)
			goto out;

		/* Log an intent-done item for the first pending item. */
		dfp = list_first_entry(&dop_pending, struct scxfs_defer_pending,
				       dfp_list);
		ops = defer_op_types[dfp->dfp_type];
		trace_scxfs_defer_pending_finish((*tp)->t_mountp, dfp);
		dfp->dfp_done = ops->create_done(*tp, dfp->dfp_intent,
				dfp->dfp_count);

		/* Finish the work items. */
		state = NULL;
		list_for_each_safe(li, n, &dfp->dfp_work) {
			list_del(li);
			dfp->dfp_count--;
			error = ops->finish_item(*tp, li, dfp->dfp_done,
					&state);
			if (error == -EAGAIN) {
				/*
				 * Caller wants a fresh transaction;
				 * put the work item back on the list
				 * and jump out.
				 */
				list_add(li, &dfp->dfp_work);
				dfp->dfp_count++;
				break;
			} else if (error) {
				/*
				 * Clean up after ourselves and jump out.
				 * scxfs_defer_cancel will take care of freeing
				 * all these lists and stuff.
				 */
				if (ops->finish_cleanup)
					ops->finish_cleanup(*tp, state, error);
				goto out;
			}
		}
		if (error == -EAGAIN) {
			/*
			 * Caller wants a fresh transaction, so log a
			 * new log intent item to replace the old one
			 * and roll the transaction.  See "Requesting
			 * a Fresh Transaction while Finishing
			 * Deferred Work" above.
			 */
			dfp->dfp_intent = ops->create_intent(*tp,
					dfp->dfp_count);
			dfp->dfp_done = NULL;
			list_for_each(li, &dfp->dfp_work)
				ops->log_item(*tp, dfp->dfp_intent, li);
		} else {
			/* Done with the dfp, free it. */
			list_del(&dfp->dfp_list);
			kmem_free(dfp);
		}

		if (ops->finish_cleanup)
			ops->finish_cleanup(*tp, state, error);
	}

out:
	if (error) {
		scxfs_defer_trans_abort(*tp, &dop_pending);
		scxfs_force_shutdown((*tp)->t_mountp, SHUTDOWN_CORRUPT_INCORE);
		trace_scxfs_defer_finish_error(*tp, error);
		scxfs_defer_cancel_list((*tp)->t_mountp, &dop_pending);
		scxfs_defer_cancel(*tp);
		return error;
	}

	trace_scxfs_defer_finish_done(*tp, _RET_IP_);
	return 0;
}

int
scxfs_defer_finish(
	struct scxfs_trans	**tp)
{
	int			error;

	/*
	 * Finish and roll the transaction once more to avoid returning to the
	 * caller with a dirty transaction.
	 */
	error = scxfs_defer_finish_noroll(tp);
	if (error)
		return error;
	if ((*tp)->t_flags & SCXFS_TRANS_DIRTY) {
		error = scxfs_defer_trans_roll(tp);
		if (error) {
			scxfs_force_shutdown((*tp)->t_mountp,
					   SHUTDOWN_CORRUPT_INCORE);
			return error;
		}
	}
	scxfs_defer_reset(*tp);
	return 0;
}

void
scxfs_defer_cancel(
	struct scxfs_trans	*tp)
{
	struct scxfs_mount	*mp = tp->t_mountp;

	trace_scxfs_defer_cancel(tp, _RET_IP_);
	scxfs_defer_cancel_list(mp, &tp->t_dfops);
}

/* Add an item for later deferred processing. */
void
scxfs_defer_add(
	struct scxfs_trans		*tp,
	enum scxfs_defer_ops_type		type,
	struct list_head		*li)
{
	struct scxfs_defer_pending	*dfp = NULL;
	const struct scxfs_defer_op_type	*ops;

	ASSERT(tp->t_flags & SCXFS_TRANS_PERM_LOG_RES);
	BUILD_BUG_ON(ARRAY_SIZE(defer_op_types) != SCXFS_DEFER_OPS_TYPE_MAX);

	/*
	 * Add the item to a pending item at the end of the intake list.
	 * If the last pending item has the same type, reuse it.  Else,
	 * create a new pending item at the end of the intake list.
	 */
	if (!list_empty(&tp->t_dfops)) {
		dfp = list_last_entry(&tp->t_dfops,
				struct scxfs_defer_pending, dfp_list);
		ops = defer_op_types[dfp->dfp_type];
		if (dfp->dfp_type != type ||
		    (ops->max_items && dfp->dfp_count >= ops->max_items))
			dfp = NULL;
	}
	if (!dfp) {
		dfp = kmem_alloc(sizeof(struct scxfs_defer_pending),
				KM_NOFS);
		dfp->dfp_type = type;
		dfp->dfp_intent = NULL;
		dfp->dfp_done = NULL;
		dfp->dfp_count = 0;
		INIT_LIST_HEAD(&dfp->dfp_work);
		list_add_tail(&dfp->dfp_list, &tp->t_dfops);
	}

	list_add_tail(li, &dfp->dfp_work);
	dfp->dfp_count++;
}

/*
 * Move deferred ops from one transaction to another and reset the source to
 * initial state. This is primarily used to carry state forward across
 * transaction rolls with pending dfops.
 */
void
scxfs_defer_move(
	struct scxfs_trans	*dtp,
	struct scxfs_trans	*stp)
{
	list_splice_init(&stp->t_dfops, &dtp->t_dfops);

	/*
	 * Low free space mode was historically controlled by a dfops field.
	 * This meant that low mode state potentially carried across multiple
	 * transaction rolls. Transfer low mode on a dfops move to preserve
	 * that behavior.
	 */
	dtp->t_flags |= (stp->t_flags & SCXFS_TRANS_LOWMODE);

	scxfs_defer_reset(stp);
}
