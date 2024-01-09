// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_shared.h"
#include "scxfs_mount.h"
#include "scxfs_defer.h"
#include "scxfs_trans.h"
#include "scxfs_trans_priv.h"
#include "scxfs_rmap_item.h"
#include "scxfs_log.h"
#include "scxfs_rmap.h"


kmem_zone_t	*scxfs_rui_zone;
kmem_zone_t	*scxfs_rud_zone;

static inline struct scxfs_rui_log_item *RUI_ITEM(struct scxfs_log_item *lip)
{
	return container_of(lip, struct scxfs_rui_log_item, rui_item);
}

void
scxfs_rui_item_free(
	struct scxfs_rui_log_item	*ruip)
{
	if (ruip->rui_format.rui_nextents > SCXFS_RUI_MAX_FAST_EXTENTS)
		kmem_free(ruip);
	else
		kmem_zone_free(scxfs_rui_zone, ruip);
}

/*
 * Freeing the RUI requires that we remove it from the AIL if it has already
 * been placed there. However, the RUI may not yet have been placed in the AIL
 * when called by scxfs_rui_release() from RUD processing due to the ordering of
 * committed vs unpin operations in bulk insert operations. Hence the reference
 * count to ensure only the last caller frees the RUI.
 */
void
scxfs_rui_release(
	struct scxfs_rui_log_item	*ruip)
{
	ASSERT(atomic_read(&ruip->rui_refcount) > 0);
	if (atomic_dec_and_test(&ruip->rui_refcount)) {
		scxfs_trans_ail_remove(&ruip->rui_item, SHUTDOWN_LOG_IO_ERROR);
		scxfs_rui_item_free(ruip);
	}
}

STATIC void
scxfs_rui_item_size(
	struct scxfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	struct scxfs_rui_log_item	*ruip = RUI_ITEM(lip);

	*nvecs += 1;
	*nbytes += scxfs_rui_log_format_sizeof(ruip->rui_format.rui_nextents);
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given rui log item. We use only 1 iovec, and we point that
 * at the rui_log_format structure embedded in the rui item.
 * It is at this point that we assert that all of the extent
 * slots in the rui item have been filled.
 */
STATIC void
scxfs_rui_item_format(
	struct scxfs_log_item	*lip,
	struct scxfs_log_vec	*lv)
{
	struct scxfs_rui_log_item	*ruip = RUI_ITEM(lip);
	struct scxfs_log_iovec	*vecp = NULL;

	ASSERT(atomic_read(&ruip->rui_next_extent) ==
			ruip->rui_format.rui_nextents);

	ruip->rui_format.rui_type = SCXFS_LI_RUI;
	ruip->rui_format.rui_size = 1;

	xlog_copy_iovec(lv, &vecp, XLOG_REG_TYPE_RUI_FORMAT, &ruip->rui_format,
			scxfs_rui_log_format_sizeof(ruip->rui_format.rui_nextents));
}

/*
 * The unpin operation is the last place an RUI is manipulated in the log. It is
 * either inserted in the AIL or aborted in the event of a log I/O error. In
 * either case, the RUI transaction has been successfully committed to make it
 * this far. Therefore, we expect whoever committed the RUI to either construct
 * and commit the RUD or drop the RUD's reference in the event of error. Simply
 * drop the log's RUI reference now that the log is done with it.
 */
STATIC void
scxfs_rui_item_unpin(
	struct scxfs_log_item	*lip,
	int			remove)
{
	struct scxfs_rui_log_item	*ruip = RUI_ITEM(lip);

	scxfs_rui_release(ruip);
}

/*
 * The RUI has been either committed or aborted if the transaction has been
 * cancelled. If the transaction was cancelled, an RUD isn't going to be
 * constructed and thus we free the RUI here directly.
 */
STATIC void
scxfs_rui_item_release(
	struct scxfs_log_item	*lip)
{
	scxfs_rui_release(RUI_ITEM(lip));
}

static const struct scxfs_item_ops scxfs_rui_item_ops = {
	.iop_size	= scxfs_rui_item_size,
	.iop_format	= scxfs_rui_item_format,
	.iop_unpin	= scxfs_rui_item_unpin,
	.iop_release	= scxfs_rui_item_release,
};

/*
 * Allocate and initialize an rui item with the given number of extents.
 */
struct scxfs_rui_log_item *
scxfs_rui_init(
	struct scxfs_mount		*mp,
	uint				nextents)

{
	struct scxfs_rui_log_item		*ruip;

	ASSERT(nextents > 0);
	if (nextents > SCXFS_RUI_MAX_FAST_EXTENTS)
		ruip = kmem_zalloc(scxfs_rui_log_item_sizeof(nextents), 0);
	else
		ruip = kmem_zone_zalloc(scxfs_rui_zone, 0);

	scxfs_log_item_init(mp, &ruip->rui_item, SCXFS_LI_RUI, &scxfs_rui_item_ops);
	ruip->rui_format.rui_nextents = nextents;
	ruip->rui_format.rui_id = (uintptr_t)(void *)ruip;
	atomic_set(&ruip->rui_next_extent, 0);
	atomic_set(&ruip->rui_refcount, 2);

	return ruip;
}

/*
 * Copy an RUI format buffer from the given buf, and into the destination
 * RUI format structure.  The RUI/RUD items were designed not to need any
 * special alignment handling.
 */
int
scxfs_rui_copy_format(
	struct scxfs_log_iovec		*buf,
	struct scxfs_rui_log_format	*dst_rui_fmt)
{
	struct scxfs_rui_log_format	*src_rui_fmt;
	uint				len;

	src_rui_fmt = buf->i_addr;
	len = scxfs_rui_log_format_sizeof(src_rui_fmt->rui_nextents);

	if (buf->i_len != len)
		return -EFSCORRUPTED;

	memcpy(dst_rui_fmt, src_rui_fmt, len);
	return 0;
}

static inline struct scxfs_rud_log_item *RUD_ITEM(struct scxfs_log_item *lip)
{
	return container_of(lip, struct scxfs_rud_log_item, rud_item);
}

STATIC void
scxfs_rud_item_size(
	struct scxfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	*nvecs += 1;
	*nbytes += sizeof(struct scxfs_rud_log_format);
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given rud log item. We use only 1 iovec, and we point that
 * at the rud_log_format structure embedded in the rud item.
 * It is at this point that we assert that all of the extent
 * slots in the rud item have been filled.
 */
STATIC void
scxfs_rud_item_format(
	struct scxfs_log_item	*lip,
	struct scxfs_log_vec	*lv)
{
	struct scxfs_rud_log_item	*rudp = RUD_ITEM(lip);
	struct scxfs_log_iovec	*vecp = NULL;

	rudp->rud_format.rud_type = SCXFS_LI_RUD;
	rudp->rud_format.rud_size = 1;

	xlog_copy_iovec(lv, &vecp, XLOG_REG_TYPE_RUD_FORMAT, &rudp->rud_format,
			sizeof(struct scxfs_rud_log_format));
}

/*
 * The RUD is either committed or aborted if the transaction is cancelled. If
 * the transaction is cancelled, drop our reference to the RUI and free the
 * RUD.
 */
STATIC void
scxfs_rud_item_release(
	struct scxfs_log_item	*lip)
{
	struct scxfs_rud_log_item	*rudp = RUD_ITEM(lip);

	scxfs_rui_release(rudp->rud_ruip);
	kmem_zone_free(scxfs_rud_zone, rudp);
}

static const struct scxfs_item_ops scxfs_rud_item_ops = {
	.flags		= SCXFS_ITEM_RELEASE_WHEN_COMMITTED,
	.iop_size	= scxfs_rud_item_size,
	.iop_format	= scxfs_rud_item_format,
	.iop_release	= scxfs_rud_item_release,
};

static struct scxfs_rud_log_item *
scxfs_trans_get_rud(
	struct scxfs_trans		*tp,
	struct scxfs_rui_log_item		*ruip)
{
	struct scxfs_rud_log_item		*rudp;

	rudp = kmem_zone_zalloc(scxfs_rud_zone, 0);
	scxfs_log_item_init(tp->t_mountp, &rudp->rud_item, SCXFS_LI_RUD,
			  &scxfs_rud_item_ops);
	rudp->rud_ruip = ruip;
	rudp->rud_format.rud_rui_id = ruip->rui_format.rui_id;

	scxfs_trans_add_item(tp, &rudp->rud_item);
	return rudp;
}

/* Set the map extent flags for this reverse mapping. */
static void
scxfs_trans_set_rmap_flags(
	struct scxfs_map_extent		*rmap,
	enum scxfs_rmap_intent_type	type,
	int				whichfork,
	scxfs_exntst_t			state)
{
	rmap->me_flags = 0;
	if (state == SCXFS_EXT_UNWRITTEN)
		rmap->me_flags |= SCXFS_RMAP_EXTENT_UNWRITTEN;
	if (whichfork == SCXFS_ATTR_FORK)
		rmap->me_flags |= SCXFS_RMAP_EXTENT_ATTR_FORK;
	switch (type) {
	case SCXFS_RMAP_MAP:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_MAP;
		break;
	case SCXFS_RMAP_MAP_SHARED:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_MAP_SHARED;
		break;
	case SCXFS_RMAP_UNMAP:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_UNMAP;
		break;
	case SCXFS_RMAP_UNMAP_SHARED:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_UNMAP_SHARED;
		break;
	case SCXFS_RMAP_CONVERT:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_CONVERT;
		break;
	case SCXFS_RMAP_CONVERT_SHARED:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_CONVERT_SHARED;
		break;
	case SCXFS_RMAP_ALLOC:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_ALLOC;
		break;
	case SCXFS_RMAP_FREE:
		rmap->me_flags |= SCXFS_RMAP_EXTENT_FREE;
		break;
	default:
		ASSERT(0);
	}
}

/*
 * Finish an rmap update and log it to the RUD. Note that the transaction is
 * marked dirty regardless of whether the rmap update succeeds or fails to
 * support the RUI/RUD lifecycle rules.
 */
static int
scxfs_trans_log_finish_rmap_update(
	struct scxfs_trans		*tp,
	struct scxfs_rud_log_item		*rudp,
	enum scxfs_rmap_intent_type	type,
	uint64_t			owner,
	int				whichfork,
	scxfs_fileoff_t			startoff,
	scxfs_fsblock_t			startblock,
	scxfs_filblks_t			blockcount,
	scxfs_exntst_t			state,
	struct scxfs_btree_cur		**pcur)
{
	int				error;

	error = scxfs_rmap_finish_one(tp, type, owner, whichfork, startoff,
			startblock, blockcount, state, pcur);

	/*
	 * Mark the transaction dirty, even on error. This ensures the
	 * transaction is aborted, which:
	 *
	 * 1.) releases the RUI and frees the RUD
	 * 2.) shuts down the filesystem
	 */
	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &rudp->rud_item.li_flags);

	return error;
}

/* Sort rmap intents by AG. */
static int
scxfs_rmap_update_diff_items(
	void				*priv,
	struct list_head		*a,
	struct list_head		*b)
{
	struct scxfs_mount		*mp = priv;
	struct scxfs_rmap_intent		*ra;
	struct scxfs_rmap_intent		*rb;

	ra = container_of(a, struct scxfs_rmap_intent, ri_list);
	rb = container_of(b, struct scxfs_rmap_intent, ri_list);
	return  SCXFS_FSB_TO_AGNO(mp, ra->ri_bmap.br_startblock) -
		SCXFS_FSB_TO_AGNO(mp, rb->ri_bmap.br_startblock);
}

/* Get an RUI. */
STATIC void *
scxfs_rmap_update_create_intent(
	struct scxfs_trans		*tp,
	unsigned int			count)
{
	struct scxfs_rui_log_item		*ruip;

	ASSERT(tp != NULL);
	ASSERT(count > 0);

	ruip = scxfs_rui_init(tp->t_mountp, count);
	ASSERT(ruip != NULL);

	/*
	 * Get a log_item_desc to point at the new item.
	 */
	scxfs_trans_add_item(tp, &ruip->rui_item);
	return ruip;
}

/* Log rmap updates in the intent item. */
STATIC void
scxfs_rmap_update_log_item(
	struct scxfs_trans		*tp,
	void				*intent,
	struct list_head		*item)
{
	struct scxfs_rui_log_item		*ruip = intent;
	struct scxfs_rmap_intent		*rmap;
	uint				next_extent;
	struct scxfs_map_extent		*map;

	rmap = container_of(item, struct scxfs_rmap_intent, ri_list);

	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &ruip->rui_item.li_flags);

	/*
	 * atomic_inc_return gives us the value after the increment;
	 * we want to use it as an array index so we need to subtract 1 from
	 * it.
	 */
	next_extent = atomic_inc_return(&ruip->rui_next_extent) - 1;
	ASSERT(next_extent < ruip->rui_format.rui_nextents);
	map = &ruip->rui_format.rui_extents[next_extent];
	map->me_owner = rmap->ri_owner;
	map->me_startblock = rmap->ri_bmap.br_startblock;
	map->me_startoff = rmap->ri_bmap.br_startoff;
	map->me_len = rmap->ri_bmap.br_blockcount;
	scxfs_trans_set_rmap_flags(map, rmap->ri_type, rmap->ri_whichfork,
			rmap->ri_bmap.br_state);
}

/* Get an RUD so we can process all the deferred rmap updates. */
STATIC void *
scxfs_rmap_update_create_done(
	struct scxfs_trans		*tp,
	void				*intent,
	unsigned int			count)
{
	return scxfs_trans_get_rud(tp, intent);
}

/* Process a deferred rmap update. */
STATIC int
scxfs_rmap_update_finish_item(
	struct scxfs_trans		*tp,
	struct list_head		*item,
	void				*done_item,
	void				**state)
{
	struct scxfs_rmap_intent		*rmap;
	int				error;

	rmap = container_of(item, struct scxfs_rmap_intent, ri_list);
	error = scxfs_trans_log_finish_rmap_update(tp, done_item,
			rmap->ri_type,
			rmap->ri_owner, rmap->ri_whichfork,
			rmap->ri_bmap.br_startoff,
			rmap->ri_bmap.br_startblock,
			rmap->ri_bmap.br_blockcount,
			rmap->ri_bmap.br_state,
			(struct scxfs_btree_cur **)state);
	kmem_free(rmap);
	return error;
}

/* Clean up after processing deferred rmaps. */
STATIC void
scxfs_rmap_update_finish_cleanup(
	struct scxfs_trans	*tp,
	void			*state,
	int			error)
{
	struct scxfs_btree_cur	*rcur = state;

	scxfs_rmap_finish_one_cleanup(tp, rcur, error);
}

/* Abort all pending RUIs. */
STATIC void
scxfs_rmap_update_abort_intent(
	void				*intent)
{
	scxfs_rui_release(intent);
}

/* Cancel a deferred rmap update. */
STATIC void
scxfs_rmap_update_cancel_item(
	struct list_head		*item)
{
	struct scxfs_rmap_intent		*rmap;

	rmap = container_of(item, struct scxfs_rmap_intent, ri_list);
	kmem_free(rmap);
}

const struct scxfs_defer_op_type scxfs_rmap_update_defer_type = {
	.max_items	= SCXFS_RUI_MAX_FAST_EXTENTS,
	.diff_items	= scxfs_rmap_update_diff_items,
	.create_intent	= scxfs_rmap_update_create_intent,
	.abort_intent	= scxfs_rmap_update_abort_intent,
	.log_item	= scxfs_rmap_update_log_item,
	.create_done	= scxfs_rmap_update_create_done,
	.finish_item	= scxfs_rmap_update_finish_item,
	.finish_cleanup = scxfs_rmap_update_finish_cleanup,
	.cancel_item	= scxfs_rmap_update_cancel_item,
};

/*
 * Process an rmap update intent item that was recovered from the log.
 * We need to update the rmapbt.
 */
int
scxfs_rui_recover(
	struct scxfs_mount		*mp,
	struct scxfs_rui_log_item		*ruip)
{
	int				i;
	int				error = 0;
	struct scxfs_map_extent		*rmap;
	scxfs_fsblock_t			startblock_fsb;
	bool				op_ok;
	struct scxfs_rud_log_item		*rudp;
	enum scxfs_rmap_intent_type	type;
	int				whichfork;
	scxfs_exntst_t			state;
	struct scxfs_trans		*tp;
	struct scxfs_btree_cur		*rcur = NULL;

	ASSERT(!test_bit(SCXFS_RUI_RECOVERED, &ruip->rui_flags));

	/*
	 * First check the validity of the extents described by the
	 * RUI.  If any are bad, then assume that all are bad and
	 * just toss the RUI.
	 */
	for (i = 0; i < ruip->rui_format.rui_nextents; i++) {
		rmap = &ruip->rui_format.rui_extents[i];
		startblock_fsb = SCXFS_BB_TO_FSB(mp,
				   SCXFS_FSB_TO_DADDR(mp, rmap->me_startblock));
		switch (rmap->me_flags & SCXFS_RMAP_EXTENT_TYPE_MASK) {
		case SCXFS_RMAP_EXTENT_MAP:
		case SCXFS_RMAP_EXTENT_MAP_SHARED:
		case SCXFS_RMAP_EXTENT_UNMAP:
		case SCXFS_RMAP_EXTENT_UNMAP_SHARED:
		case SCXFS_RMAP_EXTENT_CONVERT:
		case SCXFS_RMAP_EXTENT_CONVERT_SHARED:
		case SCXFS_RMAP_EXTENT_ALLOC:
		case SCXFS_RMAP_EXTENT_FREE:
			op_ok = true;
			break;
		default:
			op_ok = false;
			break;
		}
		if (!op_ok || startblock_fsb == 0 ||
		    rmap->me_len == 0 ||
		    startblock_fsb >= mp->m_sb.sb_dblocks ||
		    rmap->me_len >= mp->m_sb.sb_agblocks ||
		    (rmap->me_flags & ~SCXFS_RMAP_EXTENT_FLAGS)) {
			/*
			 * This will pull the RUI from the AIL and
			 * free the memory associated with it.
			 */
			set_bit(SCXFS_RUI_RECOVERED, &ruip->rui_flags);
			scxfs_rui_release(ruip);
			return -EIO;
		}
	}

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate,
			mp->m_rmap_maxlevels, 0, SCXFS_TRANS_RESERVE, &tp);
	if (error)
		return error;
	rudp = scxfs_trans_get_rud(tp, ruip);

	for (i = 0; i < ruip->rui_format.rui_nextents; i++) {
		rmap = &ruip->rui_format.rui_extents[i];
		state = (rmap->me_flags & SCXFS_RMAP_EXTENT_UNWRITTEN) ?
				SCXFS_EXT_UNWRITTEN : SCXFS_EXT_NORM;
		whichfork = (rmap->me_flags & SCXFS_RMAP_EXTENT_ATTR_FORK) ?
				SCXFS_ATTR_FORK : SCXFS_DATA_FORK;
		switch (rmap->me_flags & SCXFS_RMAP_EXTENT_TYPE_MASK) {
		case SCXFS_RMAP_EXTENT_MAP:
			type = SCXFS_RMAP_MAP;
			break;
		case SCXFS_RMAP_EXTENT_MAP_SHARED:
			type = SCXFS_RMAP_MAP_SHARED;
			break;
		case SCXFS_RMAP_EXTENT_UNMAP:
			type = SCXFS_RMAP_UNMAP;
			break;
		case SCXFS_RMAP_EXTENT_UNMAP_SHARED:
			type = SCXFS_RMAP_UNMAP_SHARED;
			break;
		case SCXFS_RMAP_EXTENT_CONVERT:
			type = SCXFS_RMAP_CONVERT;
			break;
		case SCXFS_RMAP_EXTENT_CONVERT_SHARED:
			type = SCXFS_RMAP_CONVERT_SHARED;
			break;
		case SCXFS_RMAP_EXTENT_ALLOC:
			type = SCXFS_RMAP_ALLOC;
			break;
		case SCXFS_RMAP_EXTENT_FREE:
			type = SCXFS_RMAP_FREE;
			break;
		default:
			error = -EFSCORRUPTED;
			goto abort_error;
		}
		error = scxfs_trans_log_finish_rmap_update(tp, rudp, type,
				rmap->me_owner, whichfork,
				rmap->me_startoff, rmap->me_startblock,
				rmap->me_len, state, &rcur);
		if (error)
			goto abort_error;

	}

	scxfs_rmap_finish_one_cleanup(tp, rcur, error);
	set_bit(SCXFS_RUI_RECOVERED, &ruip->rui_flags);
	error = scxfs_trans_commit(tp);
	return error;

abort_error:
	scxfs_rmap_finish_one_cleanup(tp, rcur, error);
	scxfs_trans_cancel(tp);
	return error;
}
