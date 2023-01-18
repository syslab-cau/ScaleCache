// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
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
#include "scxfs_extfree_item.h"
#include "scxfs_log.h"
#include "scxfs_btree.h"
#include "scxfs_rmap.h"
#include "scxfs_alloc.h"
#include "scxfs_bmap.h"
#include "scxfs_trace.h"


kmem_zone_t	*scxfs_efi_zone;
kmem_zone_t	*scxfs_efd_zone;

static inline struct scxfs_efi_log_item *EFI_ITEM(struct scxfs_log_item *lip)
{
	return container_of(lip, struct scxfs_efi_log_item, efi_item);
}

void
scxfs_efi_item_free(
	struct scxfs_efi_log_item	*efip)
{
	kmem_free(efip->efi_item.li_lv_shadow);
	if (efip->efi_format.efi_nextents > SCXFS_EFI_MAX_FAST_EXTENTS)
		kmem_free(efip);
	else
		kmem_zone_free(scxfs_efi_zone, efip);
}

/*
 * Freeing the efi requires that we remove it from the AIL if it has already
 * been placed there. However, the EFI may not yet have been placed in the AIL
 * when called by scxfs_efi_release() from EFD processing due to the ordering of
 * committed vs unpin operations in bulk insert operations. Hence the reference
 * count to ensure only the last caller frees the EFI.
 */
void
scxfs_efi_release(
	struct scxfs_efi_log_item	*efip)
{
	ASSERT(atomic_read(&efip->efi_refcount) > 0);
	if (atomic_dec_and_test(&efip->efi_refcount)) {
		scxfs_trans_ail_remove(&efip->efi_item, SHUTDOWN_LOG_IO_ERROR);
		scxfs_efi_item_free(efip);
	}
}

/*
 * This returns the number of iovecs needed to log the given efi item.
 * We only need 1 iovec for an efi item.  It just logs the efi_log_format
 * structure.
 */
static inline int
scxfs_efi_item_sizeof(
	struct scxfs_efi_log_item *efip)
{
	return sizeof(struct scxfs_efi_log_format) +
	       (efip->efi_format.efi_nextents - 1) * sizeof(scxfs_extent_t);
}

STATIC void
scxfs_efi_item_size(
	struct scxfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	*nvecs += 1;
	*nbytes += scxfs_efi_item_sizeof(EFI_ITEM(lip));
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given efi log item. We use only 1 iovec, and we point that
 * at the efi_log_format structure embedded in the efi item.
 * It is at this point that we assert that all of the extent
 * slots in the efi item have been filled.
 */
STATIC void
scxfs_efi_item_format(
	struct scxfs_log_item	*lip,
	struct scxfs_log_vec	*lv)
{
	struct scxfs_efi_log_item	*efip = EFI_ITEM(lip);
	struct scxfs_log_iovec	*vecp = NULL;

	ASSERT(atomic_read(&efip->efi_next_extent) ==
				efip->efi_format.efi_nextents);

	efip->efi_format.efi_type = SCXFS_LI_EFI;
	efip->efi_format.efi_size = 1;

	xlog_copy_iovec(lv, &vecp, XLOG_REG_TYPE_EFI_FORMAT,
			&efip->efi_format,
			scxfs_efi_item_sizeof(efip));
}


/*
 * The unpin operation is the last place an EFI is manipulated in the log. It is
 * either inserted in the AIL or aborted in the event of a log I/O error. In
 * either case, the EFI transaction has been successfully committed to make it
 * this far. Therefore, we expect whoever committed the EFI to either construct
 * and commit the EFD or drop the EFD's reference in the event of error. Simply
 * drop the log's EFI reference now that the log is done with it.
 */
STATIC void
scxfs_efi_item_unpin(
	struct scxfs_log_item	*lip,
	int			remove)
{
	struct scxfs_efi_log_item	*efip = EFI_ITEM(lip);
	scxfs_efi_release(efip);
}

/*
 * The EFI has been either committed or aborted if the transaction has been
 * cancelled. If the transaction was cancelled, an EFD isn't going to be
 * constructed and thus we free the EFI here directly.
 */
STATIC void
scxfs_efi_item_release(
	struct scxfs_log_item	*lip)
{
	scxfs_efi_release(EFI_ITEM(lip));
}

static const struct scxfs_item_ops scxfs_efi_item_ops = {
	.iop_size	= scxfs_efi_item_size,
	.iop_format	= scxfs_efi_item_format,
	.iop_unpin	= scxfs_efi_item_unpin,
	.iop_release	= scxfs_efi_item_release,
};


/*
 * Allocate and initialize an efi item with the given number of extents.
 */
struct scxfs_efi_log_item *
scxfs_efi_init(
	struct scxfs_mount	*mp,
	uint			nextents)

{
	struct scxfs_efi_log_item	*efip;
	uint			size;

	ASSERT(nextents > 0);
	if (nextents > SCXFS_EFI_MAX_FAST_EXTENTS) {
		size = (uint)(sizeof(scxfs_efi_log_item_t) +
			((nextents - 1) * sizeof(scxfs_extent_t)));
		efip = kmem_zalloc(size, 0);
	} else {
		efip = kmem_zone_zalloc(scxfs_efi_zone, 0);
	}

	scxfs_log_item_init(mp, &efip->efi_item, SCXFS_LI_EFI, &scxfs_efi_item_ops);
	efip->efi_format.efi_nextents = nextents;
	efip->efi_format.efi_id = (uintptr_t)(void *)efip;
	atomic_set(&efip->efi_next_extent, 0);
	atomic_set(&efip->efi_refcount, 2);

	return efip;
}

/*
 * Copy an EFI format buffer from the given buf, and into the destination
 * EFI format structure.
 * The given buffer can be in 32 bit or 64 bit form (which has different padding),
 * one of which will be the native format for this kernel.
 * It will handle the conversion of formats if necessary.
 */
int
scxfs_efi_copy_format(scxfs_log_iovec_t *buf, scxfs_efi_log_format_t *dst_efi_fmt)
{
	scxfs_efi_log_format_t *src_efi_fmt = buf->i_addr;
	uint i;
	uint len = sizeof(scxfs_efi_log_format_t) + 
		(src_efi_fmt->efi_nextents - 1) * sizeof(scxfs_extent_t);  
	uint len32 = sizeof(scxfs_efi_log_format_32_t) + 
		(src_efi_fmt->efi_nextents - 1) * sizeof(scxfs_extent_32_t);  
	uint len64 = sizeof(scxfs_efi_log_format_64_t) + 
		(src_efi_fmt->efi_nextents - 1) * sizeof(scxfs_extent_64_t);  

	if (buf->i_len == len) {
		memcpy((char *)dst_efi_fmt, (char*)src_efi_fmt, len);
		return 0;
	} else if (buf->i_len == len32) {
		scxfs_efi_log_format_32_t *src_efi_fmt_32 = buf->i_addr;

		dst_efi_fmt->efi_type     = src_efi_fmt_32->efi_type;
		dst_efi_fmt->efi_size     = src_efi_fmt_32->efi_size;
		dst_efi_fmt->efi_nextents = src_efi_fmt_32->efi_nextents;
		dst_efi_fmt->efi_id       = src_efi_fmt_32->efi_id;
		for (i = 0; i < dst_efi_fmt->efi_nextents; i++) {
			dst_efi_fmt->efi_extents[i].ext_start =
				src_efi_fmt_32->efi_extents[i].ext_start;
			dst_efi_fmt->efi_extents[i].ext_len =
				src_efi_fmt_32->efi_extents[i].ext_len;
		}
		return 0;
	} else if (buf->i_len == len64) {
		scxfs_efi_log_format_64_t *src_efi_fmt_64 = buf->i_addr;

		dst_efi_fmt->efi_type     = src_efi_fmt_64->efi_type;
		dst_efi_fmt->efi_size     = src_efi_fmt_64->efi_size;
		dst_efi_fmt->efi_nextents = src_efi_fmt_64->efi_nextents;
		dst_efi_fmt->efi_id       = src_efi_fmt_64->efi_id;
		for (i = 0; i < dst_efi_fmt->efi_nextents; i++) {
			dst_efi_fmt->efi_extents[i].ext_start =
				src_efi_fmt_64->efi_extents[i].ext_start;
			dst_efi_fmt->efi_extents[i].ext_len =
				src_efi_fmt_64->efi_extents[i].ext_len;
		}
		return 0;
	}
	return -EFSCORRUPTED;
}

static inline struct scxfs_efd_log_item *EFD_ITEM(struct scxfs_log_item *lip)
{
	return container_of(lip, struct scxfs_efd_log_item, efd_item);
}

STATIC void
scxfs_efd_item_free(struct scxfs_efd_log_item *efdp)
{
	kmem_free(efdp->efd_item.li_lv_shadow);
	if (efdp->efd_format.efd_nextents > SCXFS_EFD_MAX_FAST_EXTENTS)
		kmem_free(efdp);
	else
		kmem_zone_free(scxfs_efd_zone, efdp);
}

/*
 * This returns the number of iovecs needed to log the given efd item.
 * We only need 1 iovec for an efd item.  It just logs the efd_log_format
 * structure.
 */
static inline int
scxfs_efd_item_sizeof(
	struct scxfs_efd_log_item *efdp)
{
	return sizeof(scxfs_efd_log_format_t) +
	       (efdp->efd_format.efd_nextents - 1) * sizeof(scxfs_extent_t);
}

STATIC void
scxfs_efd_item_size(
	struct scxfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	*nvecs += 1;
	*nbytes += scxfs_efd_item_sizeof(EFD_ITEM(lip));
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given efd log item. We use only 1 iovec, and we point that
 * at the efd_log_format structure embedded in the efd item.
 * It is at this point that we assert that all of the extent
 * slots in the efd item have been filled.
 */
STATIC void
scxfs_efd_item_format(
	struct scxfs_log_item	*lip,
	struct scxfs_log_vec	*lv)
{
	struct scxfs_efd_log_item	*efdp = EFD_ITEM(lip);
	struct scxfs_log_iovec	*vecp = NULL;

	ASSERT(efdp->efd_next_extent == efdp->efd_format.efd_nextents);

	efdp->efd_format.efd_type = SCXFS_LI_EFD;
	efdp->efd_format.efd_size = 1;

	xlog_copy_iovec(lv, &vecp, XLOG_REG_TYPE_EFD_FORMAT,
			&efdp->efd_format,
			scxfs_efd_item_sizeof(efdp));
}

/*
 * The EFD is either committed or aborted if the transaction is cancelled. If
 * the transaction is cancelled, drop our reference to the EFI and free the EFD.
 */
STATIC void
scxfs_efd_item_release(
	struct scxfs_log_item	*lip)
{
	struct scxfs_efd_log_item	*efdp = EFD_ITEM(lip);

	scxfs_efi_release(efdp->efd_efip);
	scxfs_efd_item_free(efdp);
}

static const struct scxfs_item_ops scxfs_efd_item_ops = {
	.flags		= SCXFS_ITEM_RELEASE_WHEN_COMMITTED,
	.iop_size	= scxfs_efd_item_size,
	.iop_format	= scxfs_efd_item_format,
	.iop_release	= scxfs_efd_item_release,
};

/*
 * Allocate an "extent free done" log item that will hold nextents worth of
 * extents.  The caller must use all nextents extents, because we are not
 * flexible about this at all.
 */
static struct scxfs_efd_log_item *
scxfs_trans_get_efd(
	struct scxfs_trans		*tp,
	struct scxfs_efi_log_item		*efip,
	unsigned int			nextents)
{
	struct scxfs_efd_log_item		*efdp;

	ASSERT(nextents > 0);

	if (nextents > SCXFS_EFD_MAX_FAST_EXTENTS) {
		efdp = kmem_zalloc(sizeof(struct scxfs_efd_log_item) +
				(nextents - 1) * sizeof(struct scxfs_extent),
				0);
	} else {
		efdp = kmem_zone_zalloc(scxfs_efd_zone, 0);
	}

	scxfs_log_item_init(tp->t_mountp, &efdp->efd_item, SCXFS_LI_EFD,
			  &scxfs_efd_item_ops);
	efdp->efd_efip = efip;
	efdp->efd_format.efd_nextents = nextents;
	efdp->efd_format.efd_efi_id = efip->efi_format.efi_id;

	scxfs_trans_add_item(tp, &efdp->efd_item);
	return efdp;
}

/*
 * Free an extent and log it to the EFD. Note that the transaction is marked
 * dirty regardless of whether the extent free succeeds or fails to support the
 * EFI/EFD lifecycle rules.
 */
static int
scxfs_trans_free_extent(
	struct scxfs_trans		*tp,
	struct scxfs_efd_log_item		*efdp,
	scxfs_fsblock_t			start_block,
	scxfs_extlen_t			ext_len,
	const struct scxfs_owner_info	*oinfo,
	bool				skip_discard)
{
	struct scxfs_mount		*mp = tp->t_mountp;
	struct scxfs_extent		*extp;
	uint				next_extent;
	scxfs_agnumber_t			agno = SCXFS_FSB_TO_AGNO(mp, start_block);
	scxfs_agblock_t			agbno = SCXFS_FSB_TO_AGBNO(mp,
								start_block);
	int				error;

	trace_scxfs_bmap_free_deferred(tp->t_mountp, agno, 0, agbno, ext_len);

	error = __scxfs_free_extent(tp, start_block, ext_len,
				  oinfo, SCXFS_AG_RESV_NONE, skip_discard);
	/*
	 * Mark the transaction dirty, even on error. This ensures the
	 * transaction is aborted, which:
	 *
	 * 1.) releases the EFI and frees the EFD
	 * 2.) shuts down the filesystem
	 */
	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &efdp->efd_item.li_flags);

	next_extent = efdp->efd_next_extent;
	ASSERT(next_extent < efdp->efd_format.efd_nextents);
	extp = &(efdp->efd_format.efd_extents[next_extent]);
	extp->ext_start = start_block;
	extp->ext_len = ext_len;
	efdp->efd_next_extent++;

	return error;
}

/* Sort bmap items by AG. */
static int
scxfs_extent_free_diff_items(
	void				*priv,
	struct list_head		*a,
	struct list_head		*b)
{
	struct scxfs_mount		*mp = priv;
	struct scxfs_extent_free_item	*ra;
	struct scxfs_extent_free_item	*rb;

	ra = container_of(a, struct scxfs_extent_free_item, xefi_list);
	rb = container_of(b, struct scxfs_extent_free_item, xefi_list);
	return  SCXFS_FSB_TO_AGNO(mp, ra->xefi_startblock) -
		SCXFS_FSB_TO_AGNO(mp, rb->xefi_startblock);
}

/* Get an EFI. */
STATIC void *
scxfs_extent_free_create_intent(
	struct scxfs_trans		*tp,
	unsigned int			count)
{
	struct scxfs_efi_log_item		*efip;

	ASSERT(tp != NULL);
	ASSERT(count > 0);

	efip = scxfs_efi_init(tp->t_mountp, count);
	ASSERT(efip != NULL);

	/*
	 * Get a log_item_desc to point at the new item.
	 */
	scxfs_trans_add_item(tp, &efip->efi_item);
	return efip;
}

/* Log a free extent to the intent item. */
STATIC void
scxfs_extent_free_log_item(
	struct scxfs_trans		*tp,
	void				*intent,
	struct list_head		*item)
{
	struct scxfs_efi_log_item		*efip = intent;
	struct scxfs_extent_free_item	*free;
	uint				next_extent;
	struct scxfs_extent		*extp;

	free = container_of(item, struct scxfs_extent_free_item, xefi_list);

	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &efip->efi_item.li_flags);

	/*
	 * atomic_inc_return gives us the value after the increment;
	 * we want to use it as an array index so we need to subtract 1 from
	 * it.
	 */
	next_extent = atomic_inc_return(&efip->efi_next_extent) - 1;
	ASSERT(next_extent < efip->efi_format.efi_nextents);
	extp = &efip->efi_format.efi_extents[next_extent];
	extp->ext_start = free->xefi_startblock;
	extp->ext_len = free->xefi_blockcount;
}

/* Get an EFD so we can process all the free extents. */
STATIC void *
scxfs_extent_free_create_done(
	struct scxfs_trans		*tp,
	void				*intent,
	unsigned int			count)
{
	return scxfs_trans_get_efd(tp, intent, count);
}

/* Process a free extent. */
STATIC int
scxfs_extent_free_finish_item(
	struct scxfs_trans		*tp,
	struct list_head		*item,
	void				*done_item,
	void				**state)
{
	struct scxfs_extent_free_item	*free;
	int				error;

	free = container_of(item, struct scxfs_extent_free_item, xefi_list);
	error = scxfs_trans_free_extent(tp, done_item,
			free->xefi_startblock,
			free->xefi_blockcount,
			&free->xefi_oinfo, free->xefi_skip_discard);
	kmem_free(free);
	return error;
}

/* Abort all pending EFIs. */
STATIC void
scxfs_extent_free_abort_intent(
	void				*intent)
{
	scxfs_efi_release(intent);
}

/* Cancel a free extent. */
STATIC void
scxfs_extent_free_cancel_item(
	struct list_head		*item)
{
	struct scxfs_extent_free_item	*free;

	free = container_of(item, struct scxfs_extent_free_item, xefi_list);
	kmem_free(free);
}

const struct scxfs_defer_op_type scxfs_extent_free_defer_type = {
	.max_items	= SCXFS_EFI_MAX_FAST_EXTENTS,
	.diff_items	= scxfs_extent_free_diff_items,
	.create_intent	= scxfs_extent_free_create_intent,
	.abort_intent	= scxfs_extent_free_abort_intent,
	.log_item	= scxfs_extent_free_log_item,
	.create_done	= scxfs_extent_free_create_done,
	.finish_item	= scxfs_extent_free_finish_item,
	.cancel_item	= scxfs_extent_free_cancel_item,
};

/*
 * AGFL blocks are accounted differently in the reserve pools and are not
 * inserted into the busy extent list.
 */
STATIC int
scxfs_agfl_free_finish_item(
	struct scxfs_trans		*tp,
	struct list_head		*item,
	void				*done_item,
	void				**state)
{
	struct scxfs_mount		*mp = tp->t_mountp;
	struct scxfs_efd_log_item		*efdp = done_item;
	struct scxfs_extent_free_item	*free;
	struct scxfs_extent		*extp;
	struct scxfs_buf			*agbp;
	int				error;
	scxfs_agnumber_t			agno;
	scxfs_agblock_t			agbno;
	uint				next_extent;

	free = container_of(item, struct scxfs_extent_free_item, xefi_list);
	ASSERT(free->xefi_blockcount == 1);
	agno = SCXFS_FSB_TO_AGNO(mp, free->xefi_startblock);
	agbno = SCXFS_FSB_TO_AGBNO(mp, free->xefi_startblock);

	trace_scxfs_agfl_free_deferred(mp, agno, 0, agbno, free->xefi_blockcount);

	error = scxfs_alloc_read_agf(mp, tp, agno, 0, &agbp);
	if (!error)
		error = scxfs_free_agfl_block(tp, agno, agbno, agbp,
					    &free->xefi_oinfo);

	/*
	 * Mark the transaction dirty, even on error. This ensures the
	 * transaction is aborted, which:
	 *
	 * 1.) releases the EFI and frees the EFD
	 * 2.) shuts down the filesystem
	 */
	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &efdp->efd_item.li_flags);

	next_extent = efdp->efd_next_extent;
	ASSERT(next_extent < efdp->efd_format.efd_nextents);
	extp = &(efdp->efd_format.efd_extents[next_extent]);
	extp->ext_start = free->xefi_startblock;
	extp->ext_len = free->xefi_blockcount;
	efdp->efd_next_extent++;

	kmem_free(free);
	return error;
}

/* sub-type with special handling for AGFL deferred frees */
const struct scxfs_defer_op_type scxfs_agfl_free_defer_type = {
	.max_items	= SCXFS_EFI_MAX_FAST_EXTENTS,
	.diff_items	= scxfs_extent_free_diff_items,
	.create_intent	= scxfs_extent_free_create_intent,
	.abort_intent	= scxfs_extent_free_abort_intent,
	.log_item	= scxfs_extent_free_log_item,
	.create_done	= scxfs_extent_free_create_done,
	.finish_item	= scxfs_agfl_free_finish_item,
	.cancel_item	= scxfs_extent_free_cancel_item,
};

/*
 * Process an extent free intent item that was recovered from
 * the log.  We need to free the extents that it describes.
 */
int
scxfs_efi_recover(
	struct scxfs_mount	*mp,
	struct scxfs_efi_log_item	*efip)
{
	struct scxfs_efd_log_item	*efdp;
	struct scxfs_trans	*tp;
	int			i;
	int			error = 0;
	scxfs_extent_t		*extp;
	scxfs_fsblock_t		startblock_fsb;

	ASSERT(!test_bit(SCXFS_EFI_RECOVERED, &efip->efi_flags));

	/*
	 * First check the validity of the extents described by the
	 * EFI.  If any are bad, then assume that all are bad and
	 * just toss the EFI.
	 */
	for (i = 0; i < efip->efi_format.efi_nextents; i++) {
		extp = &efip->efi_format.efi_extents[i];
		startblock_fsb = SCXFS_BB_TO_FSB(mp,
				   SCXFS_FSB_TO_DADDR(mp, extp->ext_start));
		if (startblock_fsb == 0 ||
		    extp->ext_len == 0 ||
		    startblock_fsb >= mp->m_sb.sb_dblocks ||
		    extp->ext_len >= mp->m_sb.sb_agblocks) {
			/*
			 * This will pull the EFI from the AIL and
			 * free the memory associated with it.
			 */
			set_bit(SCXFS_EFI_RECOVERED, &efip->efi_flags);
			scxfs_efi_release(efip);
			return -EIO;
		}
	}

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error)
		return error;
	efdp = scxfs_trans_get_efd(tp, efip, efip->efi_format.efi_nextents);

	for (i = 0; i < efip->efi_format.efi_nextents; i++) {
		extp = &efip->efi_format.efi_extents[i];
		error = scxfs_trans_free_extent(tp, efdp, extp->ext_start,
					      extp->ext_len,
					      &SCXFS_RMAP_OINFO_ANY_OWNER, false);
		if (error)
			goto abort_error;

	}

	set_bit(SCXFS_EFI_RECOVERED, &efip->efi_flags);
	error = scxfs_trans_commit(tp);
	return error;

abort_error:
	scxfs_trans_cancel(tp);
	return error;
}
