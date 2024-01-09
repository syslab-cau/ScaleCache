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
#include "scxfs_alloc.h"
#include "scxfs_errortag.h"
#include "scxfs_error.h"
#include "scxfs_trace.h"
#include "scxfs_trans.h"
#include "scxfs_rmap_btree.h"
#include "scxfs_btree.h"
#include "scxfs_refcount_btree.h"
#include "scxfs_ialloc_btree.h"

/*
 * Per-AG Block Reservations
 *
 * For some kinds of allocation group metadata structures, it is advantageous
 * to reserve a small number of blocks in each AG so that future expansions of
 * that data structure do not encounter ENOSPC because errors during a btree
 * split cause the filesystem to go offline.
 *
 * Prior to the introduction of reflink, this wasn't an issue because the free
 * space btrees maintain a reserve of space (the AGFL) to handle any expansion
 * that may be necessary; and allocations of other metadata (inodes, BMBT,
 * dir/attr) aren't restricted to a single AG.  However, with reflink it is
 * possible to allocate all the space in an AG, have subsequent reflink/CoW
 * activity expand the refcount btree, and discover that there's no space left
 * to handle that expansion.  Since we can calculate the maximum size of the
 * refcount btree, we can reserve space for it and avoid ENOSPC.
 *
 * Handling per-AG reservations consists of three changes to the allocator's
 * behavior:  First, because these reservations are always needed, we decrease
 * the ag_max_usable counter to reflect the size of the AG after the reserved
 * blocks are taken.  Second, the reservations must be reflected in the
 * fdblocks count to maintain proper accounting.  Third, each AG must maintain
 * its own reserved block counter so that we can calculate the amount of space
 * that must remain free to maintain the reservations.  Fourth, the "remaining
 * reserved blocks" count must be used when calculating the length of the
 * longest free extent in an AG and to clamp maxlen in the per-AG allocation
 * functions.  In other words, we maintain a virtual allocation via in-core
 * accounting tricks so that we don't have to clean up after a crash. :)
 *
 * Reserved blocks can be managed by passing one of the enum scxfs_ag_resv_type
 * values via struct scxfs_alloc_arg or directly to the scxfs_free_extent
 * function.  It might seem a little funny to maintain a reservoir of blocks
 * to feed another reservoir, but the AGFL only holds enough blocks to get
 * through the next transaction.  The per-AG reservation is to ensure (we
 * hope) that each AG never runs out of blocks.  Each data structure wanting
 * to use the reservation system should update ask/used in scxfs_ag_resv_init.
 */

/*
 * Are we critically low on blocks?  For now we'll define that as the number
 * of blocks we can get our hands on being less than 10% of what we reserved
 * or less than some arbitrary number (maximum btree height).
 */
bool
scxfs_ag_resv_critical(
	struct scxfs_perag		*pag,
	enum scxfs_ag_resv_type		type)
{
	scxfs_extlen_t			avail;
	scxfs_extlen_t			orig;

	switch (type) {
	case SCXFS_AG_RESV_METADATA:
		avail = pag->pagf_freeblks - pag->pag_rmapbt_resv.ar_reserved;
		orig = pag->pag_meta_resv.ar_asked;
		break;
	case SCXFS_AG_RESV_RMAPBT:
		avail = pag->pagf_freeblks + pag->pagf_flcount -
			pag->pag_meta_resv.ar_reserved;
		orig = pag->pag_rmapbt_resv.ar_asked;
		break;
	default:
		ASSERT(0);
		return false;
	}

	trace_scxfs_ag_resv_critical(pag, type, avail);

	/* Critically low if less than 10% or max btree height remains. */
	return SCXFS_TEST_ERROR(avail < orig / 10 || avail < SCXFS_BTREE_MAXLEVELS,
			pag->pag_mount, SCXFS_ERRTAG_AG_RESV_CRITICAL);
}

/*
 * How many blocks are reserved but not used, and therefore must not be
 * allocated away?
 */
scxfs_extlen_t
scxfs_ag_resv_needed(
	struct scxfs_perag		*pag,
	enum scxfs_ag_resv_type		type)
{
	scxfs_extlen_t			len;

	len = pag->pag_meta_resv.ar_reserved + pag->pag_rmapbt_resv.ar_reserved;
	switch (type) {
	case SCXFS_AG_RESV_METADATA:
	case SCXFS_AG_RESV_RMAPBT:
		len -= scxfs_perag_resv(pag, type)->ar_reserved;
		break;
	case SCXFS_AG_RESV_NONE:
		/* empty */
		break;
	default:
		ASSERT(0);
	}

	trace_scxfs_ag_resv_needed(pag, type, len);

	return len;
}

/* Clean out a reservation */
static int
__scxfs_ag_resv_free(
	struct scxfs_perag		*pag,
	enum scxfs_ag_resv_type		type)
{
	struct scxfs_ag_resv		*resv;
	scxfs_extlen_t			oldresv;
	int				error;

	trace_scxfs_ag_resv_free(pag, type, 0);

	resv = scxfs_perag_resv(pag, type);
	if (pag->pag_agno == 0)
		pag->pag_mount->m_ag_max_usable += resv->ar_asked;
	/*
	 * RMAPBT blocks come from the AGFL and AGFL blocks are always
	 * considered "free", so whatever was reserved at mount time must be
	 * given back at umount.
	 */
	if (type == SCXFS_AG_RESV_RMAPBT)
		oldresv = resv->ar_orig_reserved;
	else
		oldresv = resv->ar_reserved;
	error = scxfs_mod_fdblocks(pag->pag_mount, oldresv, true);
	resv->ar_reserved = 0;
	resv->ar_asked = 0;
	resv->ar_orig_reserved = 0;

	if (error)
		trace_scxfs_ag_resv_free_error(pag->pag_mount, pag->pag_agno,
				error, _RET_IP_);
	return error;
}

/* Free a per-AG reservation. */
int
scxfs_ag_resv_free(
	struct scxfs_perag		*pag)
{
	int				error;
	int				err2;

	error = __scxfs_ag_resv_free(pag, SCXFS_AG_RESV_RMAPBT);
	err2 = __scxfs_ag_resv_free(pag, SCXFS_AG_RESV_METADATA);
	if (err2 && !error)
		error = err2;
	return error;
}

static int
__scxfs_ag_resv_init(
	struct scxfs_perag		*pag,
	enum scxfs_ag_resv_type		type,
	scxfs_extlen_t			ask,
	scxfs_extlen_t			used)
{
	struct scxfs_mount		*mp = pag->pag_mount;
	struct scxfs_ag_resv		*resv;
	int				error;
	scxfs_extlen_t			hidden_space;

	if (used > ask)
		ask = used;

	switch (type) {
	case SCXFS_AG_RESV_RMAPBT:
		/*
		 * Space taken by the rmapbt is not subtracted from fdblocks
		 * because the rmapbt lives in the free space.  Here we must
		 * subtract the entire reservation from fdblocks so that we
		 * always have blocks available for rmapbt expansion.
		 */
		hidden_space = ask;
		break;
	case SCXFS_AG_RESV_METADATA:
		/*
		 * Space taken by all other metadata btrees are accounted
		 * on-disk as used space.  We therefore only hide the space
		 * that is reserved but not used by the trees.
		 */
		hidden_space = ask - used;
		break;
	default:
		ASSERT(0);
		return -EINVAL;
	}
	error = scxfs_mod_fdblocks(mp, -(int64_t)hidden_space, true);
	if (error) {
		trace_scxfs_ag_resv_init_error(pag->pag_mount, pag->pag_agno,
				error, _RET_IP_);
		scxfs_warn(mp,
"Per-AG reservation for AG %u failed.  Filesystem may run out of space.",
				pag->pag_agno);
		return error;
	}

	/*
	 * Reduce the maximum per-AG allocation length by however much we're
	 * trying to reserve for an AG.  Since this is a filesystem-wide
	 * counter, we only make the adjustment for AG 0.  This assumes that
	 * there aren't any AGs hungrier for per-AG reservation than AG 0.
	 */
	if (pag->pag_agno == 0)
		mp->m_ag_max_usable -= ask;

	resv = scxfs_perag_resv(pag, type);
	resv->ar_asked = ask;
	resv->ar_orig_reserved = hidden_space;
	resv->ar_reserved = ask - used;

	trace_scxfs_ag_resv_init(pag, type, ask);
	return 0;
}

/* Create a per-AG block reservation. */
int
scxfs_ag_resv_init(
	struct scxfs_perag		*pag,
	struct scxfs_trans		*tp)
{
	struct scxfs_mount		*mp = pag->pag_mount;
	scxfs_agnumber_t			agno = pag->pag_agno;
	scxfs_extlen_t			ask;
	scxfs_extlen_t			used;
	int				error = 0;

	/* Create the metadata reservation. */
	if (pag->pag_meta_resv.ar_asked == 0) {
		ask = used = 0;

		error = scxfs_refcountbt_calc_reserves(mp, tp, agno, &ask, &used);
		if (error)
			goto out;

		error = scxfs_finobt_calc_reserves(mp, tp, agno, &ask, &used);
		if (error)
			goto out;

		error = __scxfs_ag_resv_init(pag, SCXFS_AG_RESV_METADATA,
				ask, used);
		if (error) {
			/*
			 * Because we didn't have per-AG reservations when the
			 * finobt feature was added we might not be able to
			 * reserve all needed blocks.  Warn and fall back to the
			 * old and potentially buggy code in that case, but
			 * ensure we do have the reservation for the refcountbt.
			 */
			ask = used = 0;

			mp->m_finobt_nores = true;

			error = scxfs_refcountbt_calc_reserves(mp, tp, agno, &ask,
					&used);
			if (error)
				goto out;

			error = __scxfs_ag_resv_init(pag, SCXFS_AG_RESV_METADATA,
					ask, used);
			if (error)
				goto out;
		}
	}

	/* Create the RMAPBT metadata reservation */
	if (pag->pag_rmapbt_resv.ar_asked == 0) {
		ask = used = 0;

		error = scxfs_rmapbt_calc_reserves(mp, tp, agno, &ask, &used);
		if (error)
			goto out;

		error = __scxfs_ag_resv_init(pag, SCXFS_AG_RESV_RMAPBT, ask, used);
		if (error)
			goto out;
	}

#ifdef DEBUG
	/* need to read in the AGF for the ASSERT below to work */
	error = scxfs_alloc_pagf_init(pag->pag_mount, tp, pag->pag_agno, 0);
	if (error)
		return error;

	ASSERT(scxfs_perag_resv(pag, SCXFS_AG_RESV_METADATA)->ar_reserved +
	       scxfs_perag_resv(pag, SCXFS_AG_RESV_RMAPBT)->ar_reserved <=
	       pag->pagf_freeblks + pag->pagf_flcount);
#endif
out:
	return error;
}

/* Allocate a block from the reservation. */
void
scxfs_ag_resv_alloc_extent(
	struct scxfs_perag		*pag,
	enum scxfs_ag_resv_type		type,
	struct scxfs_alloc_arg		*args)
{
	struct scxfs_ag_resv		*resv;
	scxfs_extlen_t			len;
	uint				field;

	trace_scxfs_ag_resv_alloc_extent(pag, type, args->len);

	switch (type) {
	case SCXFS_AG_RESV_AGFL:
		return;
	case SCXFS_AG_RESV_METADATA:
	case SCXFS_AG_RESV_RMAPBT:
		resv = scxfs_perag_resv(pag, type);
		break;
	default:
		ASSERT(0);
		/* fall through */
	case SCXFS_AG_RESV_NONE:
		field = args->wasdel ? SCXFS_TRANS_SB_RES_FDBLOCKS :
				       SCXFS_TRANS_SB_FDBLOCKS;
		scxfs_trans_mod_sb(args->tp, field, -(int64_t)args->len);
		return;
	}

	len = min_t(scxfs_extlen_t, args->len, resv->ar_reserved);
	resv->ar_reserved -= len;
	if (type == SCXFS_AG_RESV_RMAPBT)
		return;
	/* Allocations of reserved blocks only need on-disk sb updates... */
	scxfs_trans_mod_sb(args->tp, SCXFS_TRANS_SB_RES_FDBLOCKS, -(int64_t)len);
	/* ...but non-reserved blocks need in-core and on-disk updates. */
	if (args->len > len)
		scxfs_trans_mod_sb(args->tp, SCXFS_TRANS_SB_FDBLOCKS,
				-((int64_t)args->len - len));
}

/* Free a block to the reservation. */
void
scxfs_ag_resv_free_extent(
	struct scxfs_perag		*pag,
	enum scxfs_ag_resv_type		type,
	struct scxfs_trans		*tp,
	scxfs_extlen_t			len)
{
	scxfs_extlen_t			leftover;
	struct scxfs_ag_resv		*resv;

	trace_scxfs_ag_resv_free_extent(pag, type, len);

	switch (type) {
	case SCXFS_AG_RESV_AGFL:
		return;
	case SCXFS_AG_RESV_METADATA:
	case SCXFS_AG_RESV_RMAPBT:
		resv = scxfs_perag_resv(pag, type);
		break;
	default:
		ASSERT(0);
		/* fall through */
	case SCXFS_AG_RESV_NONE:
		scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_FDBLOCKS, (int64_t)len);
		return;
	}

	leftover = min_t(scxfs_extlen_t, len, resv->ar_asked - resv->ar_reserved);
	resv->ar_reserved += leftover;
	if (type == SCXFS_AG_RESV_RMAPBT)
		return;
	/* Freeing into the reserved pool only requires on-disk update... */
	scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_RES_FDBLOCKS, len);
	/* ...but freeing beyond that requires in-core and on-disk update. */
	if (len > leftover)
		scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_FDBLOCKS, len - leftover);
}
