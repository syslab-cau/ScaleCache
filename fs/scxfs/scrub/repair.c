// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_btree.h"
#include "scxfs_log_format.h"
#include "scxfs_trans.h"
#include "scxfs_sb.h"
#include "scxfs_inode.h"
#include "scxfs_alloc.h"
#include "scxfs_alloc_btree.h"
#include "scxfs_ialloc.h"
#include "scxfs_ialloc_btree.h"
#include "scxfs_rmap.h"
#include "scxfs_rmap_btree.h"
#include "scxfs_refcount_btree.h"
#include "scxfs_extent_busy.h"
#include "scxfs_ag_resv.h"
#include "scxfs_quota.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/repair.h"
#include "scrub/bitmap.h"

/*
 * Attempt to repair some metadata, if the metadata is corrupt and userspace
 * told us to fix it.  This function returns -EAGAIN to mean "re-run scrub",
 * and will set *fixed to true if it thinks it repaired anything.
 */
int
xrep_attempt(
	struct scxfs_inode	*ip,
	struct scxfs_scrub	*sc)
{
	int			error = 0;

	trace_xrep_attempt(ip, sc->sm, error);

	xchk_ag_btcur_free(&sc->sa);

	/* Repair whatever's broken. */
	ASSERT(sc->ops->repair);
	error = sc->ops->repair(sc);
	trace_xrep_done(ip, sc->sm, error);
	switch (error) {
	case 0:
		/*
		 * Repair succeeded.  Commit the fixes and perform a second
		 * scrub so that we can tell userspace if we fixed the problem.
		 */
		sc->sm->sm_flags &= ~SCXFS_SCRUB_FLAGS_OUT;
		sc->flags |= XREP_ALREADY_FIXED;
		return -EAGAIN;
	case -EDEADLOCK:
	case -EAGAIN:
		/* Tell the caller to try again having grabbed all the locks. */
		if (!(sc->flags & XCHK_TRY_HARDER)) {
			sc->flags |= XCHK_TRY_HARDER;
			return -EAGAIN;
		}
		/*
		 * We tried harder but still couldn't grab all the resources
		 * we needed to fix it.  The corruption has not been fixed,
		 * so report back to userspace.
		 */
		return -EFSCORRUPTED;
	default:
		return error;
	}
}

/*
 * Complain about unfixable problems in the filesystem.  We don't log
 * corruptions when IFLAG_REPAIR wasn't set on the assumption that the driver
 * program is scxfs_scrub, which will call back with IFLAG_REPAIR set if the
 * administrator isn't running scxfs_scrub in no-repairs mode.
 *
 * Use this helper function because _ratelimited silently declares a static
 * structure to track rate limiting information.
 */
void
xrep_failure(
	struct scxfs_mount	*mp)
{
	scxfs_alert_ratelimited(mp,
"Corruption not fixed during online repair.  Unmount and run scxfs_repair.");
}

/*
 * Repair probe -- userspace uses this to probe if we're willing to repair a
 * given mountpoint.
 */
int
xrep_probe(
	struct scxfs_scrub	*sc)
{
	int			error = 0;

	if (xchk_should_terminate(sc, &error))
		return error;

	return 0;
}

/*
 * Roll a transaction, keeping the AG headers locked and reinitializing
 * the btree cursors.
 */
int
xrep_roll_ag_trans(
	struct scxfs_scrub	*sc)
{
	int			error;

	/* Keep the AG header buffers locked so we can keep going. */
	if (sc->sa.agi_bp)
		scxfs_trans_bhold(sc->tp, sc->sa.agi_bp);
	if (sc->sa.agf_bp)
		scxfs_trans_bhold(sc->tp, sc->sa.agf_bp);
	if (sc->sa.agfl_bp)
		scxfs_trans_bhold(sc->tp, sc->sa.agfl_bp);

	/*
	 * Roll the transaction.  We still own the buffer and the buffer lock
	 * regardless of whether or not the roll succeeds.  If the roll fails,
	 * the buffers will be released during teardown on our way out of the
	 * kernel.  If it succeeds, we join them to the new transaction and
	 * move on.
	 */
	error = scxfs_trans_roll(&sc->tp);
	if (error)
		return error;

	/* Join AG headers to the new transaction. */
	if (sc->sa.agi_bp)
		scxfs_trans_bjoin(sc->tp, sc->sa.agi_bp);
	if (sc->sa.agf_bp)
		scxfs_trans_bjoin(sc->tp, sc->sa.agf_bp);
	if (sc->sa.agfl_bp)
		scxfs_trans_bjoin(sc->tp, sc->sa.agfl_bp);

	return 0;
}

/*
 * Does the given AG have enough space to rebuild a btree?  Neither AG
 * reservation can be critical, and we must have enough space (factoring
 * in AG reservations) to construct a whole btree.
 */
bool
xrep_ag_has_space(
	struct scxfs_perag	*pag,
	scxfs_extlen_t		nr_blocks,
	enum scxfs_ag_resv_type	type)
{
	return  !scxfs_ag_resv_critical(pag, SCXFS_AG_RESV_RMAPBT) &&
		!scxfs_ag_resv_critical(pag, SCXFS_AG_RESV_METADATA) &&
		pag->pagf_freeblks > scxfs_ag_resv_needed(pag, type) + nr_blocks;
}

/*
 * Figure out how many blocks to reserve for an AG repair.  We calculate the
 * worst case estimate for the number of blocks we'd need to rebuild one of
 * any type of per-AG btree.
 */
scxfs_extlen_t
xrep_calc_ag_resblks(
	struct scxfs_scrub		*sc)
{
	struct scxfs_mount		*mp = sc->mp;
	struct scxfs_scrub_metadata	*sm = sc->sm;
	struct scxfs_perag		*pag;
	struct scxfs_buf			*bp;
	scxfs_agino_t			icount = NULLAGINO;
	scxfs_extlen_t			aglen = NULLAGBLOCK;
	scxfs_extlen_t			usedlen;
	scxfs_extlen_t			freelen;
	scxfs_extlen_t			bnobt_sz;
	scxfs_extlen_t			inobt_sz;
	scxfs_extlen_t			rmapbt_sz;
	scxfs_extlen_t			refcbt_sz;
	int				error;

	if (!(sm->sm_flags & SCXFS_SCRUB_IFLAG_REPAIR))
		return 0;

	pag = scxfs_perag_get(mp, sm->sm_agno);
	if (pag->pagi_init) {
		/* Use in-core icount if possible. */
		icount = pag->pagi_count;
	} else {
		/* Try to get the actual counters from disk. */
		error = scxfs_ialloc_read_agi(mp, NULL, sm->sm_agno, &bp);
		if (!error) {
			icount = pag->pagi_count;
			scxfs_buf_relse(bp);
		}
	}

	/* Now grab the block counters from the AGF. */
	error = scxfs_alloc_read_agf(mp, NULL, sm->sm_agno, 0, &bp);
	if (!error) {
		aglen = be32_to_cpu(SCXFS_BUF_TO_AGF(bp)->agf_length);
		freelen = be32_to_cpu(SCXFS_BUF_TO_AGF(bp)->agf_freeblks);
		usedlen = aglen - freelen;
		scxfs_buf_relse(bp);
	}
	scxfs_perag_put(pag);

	/* If the icount is impossible, make some worst-case assumptions. */
	if (icount == NULLAGINO ||
	    !scxfs_verify_agino(mp, sm->sm_agno, icount)) {
		scxfs_agino_t	first, last;

		scxfs_agino_range(mp, sm->sm_agno, &first, &last);
		icount = last - first + 1;
	}

	/* If the block counts are impossible, make worst-case assumptions. */
	if (aglen == NULLAGBLOCK ||
	    aglen != scxfs_ag_block_count(mp, sm->sm_agno) ||
	    freelen >= aglen) {
		aglen = scxfs_ag_block_count(mp, sm->sm_agno);
		freelen = aglen;
		usedlen = aglen;
	}

	trace_xrep_calc_ag_resblks(mp, sm->sm_agno, icount, aglen,
			freelen, usedlen);

	/*
	 * Figure out how many blocks we'd need worst case to rebuild
	 * each type of btree.  Note that we can only rebuild the
	 * bnobt/cntbt or inobt/finobt as pairs.
	 */
	bnobt_sz = 2 * scxfs_allocbt_calc_size(mp, freelen);
	if (scxfs_sb_version_hassparseinodes(&mp->m_sb))
		inobt_sz = scxfs_iallocbt_calc_size(mp, icount /
				SCXFS_INODES_PER_HOLEMASK_BIT);
	else
		inobt_sz = scxfs_iallocbt_calc_size(mp, icount /
				SCXFS_INODES_PER_CHUNK);
	if (scxfs_sb_version_hasfinobt(&mp->m_sb))
		inobt_sz *= 2;
	if (scxfs_sb_version_hasreflink(&mp->m_sb))
		refcbt_sz = scxfs_refcountbt_calc_size(mp, usedlen);
	else
		refcbt_sz = 0;
	if (scxfs_sb_version_hasrmapbt(&mp->m_sb)) {
		/*
		 * Guess how many blocks we need to rebuild the rmapbt.
		 * For non-reflink filesystems we can't have more records than
		 * used blocks.  However, with reflink it's possible to have
		 * more than one rmap record per AG block.  We don't know how
		 * many rmaps there could be in the AG, so we start off with
		 * what we hope is an generous over-estimation.
		 */
		if (scxfs_sb_version_hasreflink(&mp->m_sb))
			rmapbt_sz = scxfs_rmapbt_calc_size(mp,
					(unsigned long long)aglen * 2);
		else
			rmapbt_sz = scxfs_rmapbt_calc_size(mp, usedlen);
	} else {
		rmapbt_sz = 0;
	}

	trace_xrep_calc_ag_resblks_btsize(mp, sm->sm_agno, bnobt_sz,
			inobt_sz, rmapbt_sz, refcbt_sz);

	return max(max(bnobt_sz, inobt_sz), max(rmapbt_sz, refcbt_sz));
}

/* Allocate a block in an AG. */
int
xrep_alloc_ag_block(
	struct scxfs_scrub		*sc,
	const struct scxfs_owner_info	*oinfo,
	scxfs_fsblock_t			*fsbno,
	enum scxfs_ag_resv_type		resv)
{
	struct scxfs_alloc_arg		args = {0};
	scxfs_agblock_t			bno;
	int				error;

	switch (resv) {
	case SCXFS_AG_RESV_AGFL:
	case SCXFS_AG_RESV_RMAPBT:
		error = scxfs_alloc_get_freelist(sc->tp, sc->sa.agf_bp, &bno, 1);
		if (error)
			return error;
		if (bno == NULLAGBLOCK)
			return -ENOSPC;
		scxfs_extent_busy_reuse(sc->mp, sc->sa.agno, bno,
				1, false);
		*fsbno = SCXFS_AGB_TO_FSB(sc->mp, sc->sa.agno, bno);
		if (resv == SCXFS_AG_RESV_RMAPBT)
			scxfs_ag_resv_rmapbt_alloc(sc->mp, sc->sa.agno);
		return 0;
	default:
		break;
	}

	args.tp = sc->tp;
	args.mp = sc->mp;
	args.oinfo = *oinfo;
	args.fsbno = SCXFS_AGB_TO_FSB(args.mp, sc->sa.agno, 0);
	args.minlen = 1;
	args.maxlen = 1;
	args.prod = 1;
	args.type = SCXFS_ALLOCTYPE_THIS_AG;
	args.resv = resv;

	error = scxfs_alloc_vextent(&args);
	if (error)
		return error;
	if (args.fsbno == NULLFSBLOCK)
		return -ENOSPC;
	ASSERT(args.len == 1);
	*fsbno = args.fsbno;

	return 0;
}

/* Initialize a new AG btree root block with zero entries. */
int
xrep_init_btblock(
	struct scxfs_scrub		*sc,
	scxfs_fsblock_t			fsb,
	struct scxfs_buf			**bpp,
	scxfs_btnum_t			btnum,
	const struct scxfs_buf_ops	*ops)
{
	struct scxfs_trans		*tp = sc->tp;
	struct scxfs_mount		*mp = sc->mp;
	struct scxfs_buf			*bp;

	trace_xrep_init_btblock(mp, SCXFS_FSB_TO_AGNO(mp, fsb),
			SCXFS_FSB_TO_AGBNO(mp, fsb), btnum);

	ASSERT(SCXFS_FSB_TO_AGNO(mp, fsb) == sc->sa.agno);
	bp = scxfs_trans_get_buf(tp, mp->m_ddev_targp, SCXFS_FSB_TO_DADDR(mp, fsb),
			SCXFS_FSB_TO_BB(mp, 1), 0);
	scxfs_buf_zero(bp, 0, BBTOB(bp->b_length));
	scxfs_btree_init_block(mp, bp, btnum, 0, 0, sc->sa.agno);
	scxfs_trans_buf_set_type(tp, bp, SCXFS_BLFT_BTREE_BUF);
	scxfs_trans_log_buf(tp, bp, 0, BBTOB(bp->b_length) - 1);
	bp->b_ops = ops;
	*bpp = bp;

	return 0;
}

/*
 * Reconstructing per-AG Btrees
 *
 * When a space btree is corrupt, we don't bother trying to fix it.  Instead,
 * we scan secondary space metadata to derive the records that should be in
 * the damaged btree, initialize a fresh btree root, and insert the records.
 * Note that for rebuilding the rmapbt we scan all the primary data to
 * generate the new records.
 *
 * However, that leaves the matter of removing all the metadata describing the
 * old broken structure.  For primary metadata we use the rmap data to collect
 * every extent with a matching rmap owner (bitmap); we then iterate all other
 * metadata structures with the same rmap owner to collect the extents that
 * cannot be removed (sublist).  We then subtract sublist from bitmap to
 * derive the blocks that were used by the old btree.  These blocks can be
 * reaped.
 *
 * For rmapbt reconstructions we must use different tactics for extent
 * collection.  First we iterate all primary metadata (this excludes the old
 * rmapbt, obviously) to generate new rmap records.  The gaps in the rmap
 * records are collected as bitmap.  The bnobt records are collected as
 * sublist.  As with the other btrees we subtract sublist from bitmap, and the
 * result (since the rmapbt lives in the free space) are the blocks from the
 * old rmapbt.
 *
 * Disposal of Blocks from Old per-AG Btrees
 *
 * Now that we've constructed a new btree to replace the damaged one, we want
 * to dispose of the blocks that (we think) the old btree was using.
 * Previously, we used the rmapbt to collect the extents (bitmap) with the
 * rmap owner corresponding to the tree we rebuilt, collected extents for any
 * blocks with the same rmap owner that are owned by another data structure
 * (sublist), and subtracted sublist from bitmap.  In theory the extents
 * remaining in bitmap are the old btree's blocks.
 *
 * Unfortunately, it's possible that the btree was crosslinked with other
 * blocks on disk.  The rmap data can tell us if there are multiple owners, so
 * if the rmapbt says there is an owner of this block other than @oinfo, then
 * the block is crosslinked.  Remove the reverse mapping and continue.
 *
 * If there is one rmap record, we can free the block, which removes the
 * reverse mapping but doesn't add the block to the free space.  Our repair
 * strategy is to hope the other metadata objects crosslinked on this block
 * will be rebuilt (atop different blocks), thereby removing all the cross
 * links.
 *
 * If there are no rmap records at all, we also free the block.  If the btree
 * being rebuilt lives in the free space (bnobt/cntbt/rmapbt) then there isn't
 * supposed to be a rmap record and everything is ok.  For other btrees there
 * had to have been an rmap entry for the block to have ended up on @bitmap,
 * so if it's gone now there's something wrong and the fs will shut down.
 *
 * Note: If there are multiple rmap records with only the same rmap owner as
 * the btree we're trying to rebuild and the block is indeed owned by another
 * data structure with the same rmap owner, then the block will be in sublist
 * and therefore doesn't need disposal.  If there are multiple rmap records
 * with only the same rmap owner but the block is not owned by something with
 * the same rmap owner, the block will be freed.
 *
 * The caller is responsible for locking the AG headers for the entire rebuild
 * operation so that nothing else can sneak in and change the AG state while
 * we're not looking.  We also assume that the caller already invalidated any
 * buffers associated with @bitmap.
 */

/*
 * Invalidate buffers for per-AG btree blocks we're dumping.  This function
 * is not intended for use with file data repairs; we have bunmapi for that.
 */
int
xrep_invalidate_blocks(
	struct scxfs_scrub	*sc,
	struct scxfs_bitmap	*bitmap)
{
	struct scxfs_bitmap_range	*bmr;
	struct scxfs_bitmap_range	*n;
	struct scxfs_buf		*bp;
	scxfs_fsblock_t		fsbno;

	/*
	 * For each block in each extent, see if there's an incore buffer for
	 * exactly that block; if so, invalidate it.  The buffer cache only
	 * lets us look for one buffer at a time, so we have to look one block
	 * at a time.  Avoid invalidating AG headers and post-EOFS blocks
	 * because we never own those; and if we can't TRYLOCK the buffer we
	 * assume it's owned by someone else.
	 */
	for_each_scxfs_bitmap_block(fsbno, bmr, n, bitmap) {
		/* Skip AG headers and post-EOFS blocks */
		if (!scxfs_verify_fsbno(sc->mp, fsbno))
			continue;
		bp = scxfs_buf_incore(sc->mp->m_ddev_targp,
				SCXFS_FSB_TO_DADDR(sc->mp, fsbno),
				SCXFS_FSB_TO_BB(sc->mp, 1), XBF_TRYLOCK);
		if (bp) {
			scxfs_trans_bjoin(sc->tp, bp);
			scxfs_trans_binval(sc->tp, bp);
		}
	}

	return 0;
}

/* Ensure the freelist is the correct size. */
int
xrep_fix_freelist(
	struct scxfs_scrub	*sc,
	bool			can_shrink)
{
	struct scxfs_alloc_arg	args = {0};

	args.mp = sc->mp;
	args.tp = sc->tp;
	args.agno = sc->sa.agno;
	args.alignment = 1;
	args.pag = sc->sa.pag;

	return scxfs_alloc_fix_freelist(&args,
			can_shrink ? 0 : SCXFS_ALLOC_FLAG_NOSHRINK);
}

/*
 * Put a block back on the AGFL.
 */
STATIC int
xrep_put_freelist(
	struct scxfs_scrub	*sc,
	scxfs_agblock_t		agbno)
{
	int			error;

	/* Make sure there's space on the freelist. */
	error = xrep_fix_freelist(sc, true);
	if (error)
		return error;

	/*
	 * Since we're "freeing" a lost block onto the AGFL, we have to
	 * create an rmap for the block prior to merging it or else other
	 * parts will break.
	 */
	error = scxfs_rmap_alloc(sc->tp, sc->sa.agf_bp, sc->sa.agno, agbno, 1,
			&SCXFS_RMAP_OINFO_AG);
	if (error)
		return error;

	/* Put the block on the AGFL. */
	error = scxfs_alloc_put_freelist(sc->tp, sc->sa.agf_bp, sc->sa.agfl_bp,
			agbno, 0);
	if (error)
		return error;
	scxfs_extent_busy_insert(sc->tp, sc->sa.agno, agbno, 1,
			SCXFS_EXTENT_BUSY_SKIP_DISCARD);

	return 0;
}

/* Dispose of a single block. */
STATIC int
xrep_reap_block(
	struct scxfs_scrub		*sc,
	scxfs_fsblock_t			fsbno,
	const struct scxfs_owner_info	*oinfo,
	enum scxfs_ag_resv_type		resv)
{
	struct scxfs_btree_cur		*cur;
	struct scxfs_buf			*agf_bp = NULL;
	scxfs_agnumber_t			agno;
	scxfs_agblock_t			agbno;
	bool				has_other_rmap;
	int				error;

	agno = SCXFS_FSB_TO_AGNO(sc->mp, fsbno);
	agbno = SCXFS_FSB_TO_AGBNO(sc->mp, fsbno);

	/*
	 * If we are repairing per-inode metadata, we need to read in the AGF
	 * buffer.  Otherwise, we're repairing a per-AG structure, so reuse
	 * the AGF buffer that the setup functions already grabbed.
	 */
	if (sc->ip) {
		error = scxfs_alloc_read_agf(sc->mp, sc->tp, agno, 0, &agf_bp);
		if (error)
			return error;
		if (!agf_bp)
			return -ENOMEM;
	} else {
		agf_bp = sc->sa.agf_bp;
	}
	cur = scxfs_rmapbt_init_cursor(sc->mp, sc->tp, agf_bp, agno);

	/* Can we find any other rmappings? */
	error = scxfs_rmap_has_other_keys(cur, agbno, 1, oinfo, &has_other_rmap);
	scxfs_btree_del_cursor(cur, error);
	if (error)
		goto out_free;

	/*
	 * If there are other rmappings, this block is cross linked and must
	 * not be freed.  Remove the reverse mapping and move on.  Otherwise,
	 * we were the only owner of the block, so free the extent, which will
	 * also remove the rmap.
	 *
	 * XXX: SCXFS doesn't support detecting the case where a single block
	 * metadata structure is crosslinked with a multi-block structure
	 * because the buffer cache doesn't detect aliasing problems, so we
	 * can't fix 100% of crosslinking problems (yet).  The verifiers will
	 * blow on writeout, the filesystem will shut down, and the admin gets
	 * to run scxfs_repair.
	 */
	if (has_other_rmap)
		error = scxfs_rmap_free(sc->tp, agf_bp, agno, agbno, 1, oinfo);
	else if (resv == SCXFS_AG_RESV_AGFL)
		error = xrep_put_freelist(sc, agbno);
	else
		error = scxfs_free_extent(sc->tp, fsbno, 1, oinfo, resv);
	if (agf_bp != sc->sa.agf_bp)
		scxfs_trans_brelse(sc->tp, agf_bp);
	if (error)
		return error;

	if (sc->ip)
		return scxfs_trans_roll_inode(&sc->tp, sc->ip);
	return xrep_roll_ag_trans(sc);

out_free:
	if (agf_bp != sc->sa.agf_bp)
		scxfs_trans_brelse(sc->tp, agf_bp);
	return error;
}

/* Dispose of every block of every extent in the bitmap. */
int
xrep_reap_extents(
	struct scxfs_scrub		*sc,
	struct scxfs_bitmap		*bitmap,
	const struct scxfs_owner_info	*oinfo,
	enum scxfs_ag_resv_type		type)
{
	struct scxfs_bitmap_range		*bmr;
	struct scxfs_bitmap_range		*n;
	scxfs_fsblock_t			fsbno;
	int				error = 0;

	ASSERT(scxfs_sb_version_hasrmapbt(&sc->mp->m_sb));

	for_each_scxfs_bitmap_block(fsbno, bmr, n, bitmap) {
		ASSERT(sc->ip != NULL ||
		       SCXFS_FSB_TO_AGNO(sc->mp, fsbno) == sc->sa.agno);
		trace_xrep_dispose_btree_extent(sc->mp,
				SCXFS_FSB_TO_AGNO(sc->mp, fsbno),
				SCXFS_FSB_TO_AGBNO(sc->mp, fsbno), 1);

		error = xrep_reap_block(sc, fsbno, oinfo, type);
		if (error)
			goto out;
	}

out:
	scxfs_bitmap_destroy(bitmap);
	return error;
}

/*
 * Finding per-AG Btree Roots for AGF/AGI Reconstruction
 *
 * If the AGF or AGI become slightly corrupted, it may be necessary to rebuild
 * the AG headers by using the rmap data to rummage through the AG looking for
 * btree roots.  This is not guaranteed to work if the AG is heavily damaged
 * or the rmap data are corrupt.
 *
 * Callers of xrep_find_ag_btree_roots must lock the AGF and AGFL
 * buffers if the AGF is being rebuilt; or the AGF and AGI buffers if the
 * AGI is being rebuilt.  It must maintain these locks until it's safe for
 * other threads to change the btrees' shapes.  The caller provides
 * information about the btrees to look for by passing in an array of
 * xrep_find_ag_btree with the (rmap owner, buf_ops, magic) fields set.
 * The (root, height) fields will be set on return if anything is found.  The
 * last element of the array should have a NULL buf_ops to mark the end of the
 * array.
 *
 * For every rmapbt record matching any of the rmap owners in btree_info,
 * read each block referenced by the rmap record.  If the block is a btree
 * block from this filesystem matching any of the magic numbers and has a
 * level higher than what we've already seen, remember the block and the
 * height of the tree required to have such a block.  When the call completes,
 * we return the highest block we've found for each btree description; those
 * should be the roots.
 */

struct xrep_findroot {
	struct scxfs_scrub		*sc;
	struct scxfs_buf			*agfl_bp;
	struct scxfs_agf			*agf;
	struct xrep_find_ag_btree	*btree_info;
};

/* See if our block is in the AGFL. */
STATIC int
xrep_findroot_agfl_walk(
	struct scxfs_mount	*mp,
	scxfs_agblock_t		bno,
	void			*priv)
{
	scxfs_agblock_t		*agbno = priv;

	return (*agbno == bno) ? -ECANCELED : 0;
}

/* Does this block match the btree information passed in? */
STATIC int
xrep_findroot_block(
	struct xrep_findroot		*ri,
	struct xrep_find_ag_btree	*fab,
	uint64_t			owner,
	scxfs_agblock_t			agbno,
	bool				*done_with_block)
{
	struct scxfs_mount		*mp = ri->sc->mp;
	struct scxfs_buf			*bp;
	struct scxfs_btree_block		*btblock;
	scxfs_daddr_t			daddr;
	int				block_level;
	int				error = 0;

	daddr = SCXFS_AGB_TO_DADDR(mp, ri->sc->sa.agno, agbno);

	/*
	 * Blocks in the AGFL have stale contents that might just happen to
	 * have a matching magic and uuid.  We don't want to pull these blocks
	 * in as part of a tree root, so we have to filter out the AGFL stuff
	 * here.  If the AGFL looks insane we'll just refuse to repair.
	 */
	if (owner == SCXFS_RMAP_OWN_AG) {
		error = scxfs_agfl_walk(mp, ri->agf, ri->agfl_bp,
				xrep_findroot_agfl_walk, &agbno);
		if (error == -ECANCELED)
			return 0;
		if (error)
			return error;
	}

	/*
	 * Read the buffer into memory so that we can see if it's a match for
	 * our btree type.  We have no clue if it is beforehand, and we want to
	 * avoid scxfs_trans_read_buf's behavior of dumping the DONE state (which
	 * will cause needless disk reads in subsequent calls to this function)
	 * and logging metadata verifier failures.
	 *
	 * Therefore, pass in NULL buffer ops.  If the buffer was already in
	 * memory from some other caller it will already have b_ops assigned.
	 * If it was in memory from a previous unsuccessful findroot_block
	 * call, the buffer won't have b_ops but it should be clean and ready
	 * for us to try to verify if the read call succeeds.  The same applies
	 * if the buffer wasn't in memory at all.
	 *
	 * Note: If we never match a btree type with this buffer, it will be
	 * left in memory with NULL b_ops.  This shouldn't be a problem unless
	 * the buffer gets written.
	 */
	error = scxfs_trans_read_buf(mp, ri->sc->tp, mp->m_ddev_targp, daddr,
			mp->m_bsize, 0, &bp, NULL);
	if (error)
		return error;

	/* Ensure the block magic matches the btree type we're looking for. */
	btblock = SCXFS_BUF_TO_BLOCK(bp);
	ASSERT(fab->buf_ops->magic[1] != 0);
	if (btblock->bb_magic != fab->buf_ops->magic[1])
		goto out;

	/*
	 * If the buffer already has ops applied and they're not the ones for
	 * this btree type, we know this block doesn't match the btree and we
	 * can bail out.
	 *
	 * If the buffer ops match ours, someone else has already validated
	 * the block for us, so we can move on to checking if this is a root
	 * block candidate.
	 *
	 * If the buffer does not have ops, nobody has successfully validated
	 * the contents and the buffer cannot be dirty.  If the magic, uuid,
	 * and structure match this btree type then we'll move on to checking
	 * if it's a root block candidate.  If there is no match, bail out.
	 */
	if (bp->b_ops) {
		if (bp->b_ops != fab->buf_ops)
			goto out;
	} else {
		ASSERT(!scxfs_trans_buf_is_dirty(bp));
		if (!uuid_equal(&btblock->bb_u.s.bb_uuid,
				&mp->m_sb.sb_meta_uuid))
			goto out;
		/*
		 * Read verifiers can reference b_ops, so we set the pointer
		 * here.  If the verifier fails we'll reset the buffer state
		 * to what it was before we touched the buffer.
		 */
		bp->b_ops = fab->buf_ops;
		fab->buf_ops->verify_read(bp);
		if (bp->b_error) {
			bp->b_ops = NULL;
			bp->b_error = 0;
			goto out;
		}

		/*
		 * Some read verifiers will (re)set b_ops, so we must be
		 * careful not to change b_ops after running the verifier.
		 */
	}

	/*
	 * This block passes the magic/uuid and verifier tests for this btree
	 * type.  We don't need the caller to try the other tree types.
	 */
	*done_with_block = true;

	/*
	 * Compare this btree block's level to the height of the current
	 * candidate root block.
	 *
	 * If the level matches the root we found previously, throw away both
	 * blocks because there can't be two candidate roots.
	 *
	 * If level is lower in the tree than the root we found previously,
	 * ignore this block.
	 */
	block_level = scxfs_btree_get_level(btblock);
	if (block_level + 1 == fab->height) {
		fab->root = NULLAGBLOCK;
		goto out;
	} else if (block_level < fab->height) {
		goto out;
	}

	/*
	 * This is the highest block in the tree that we've found so far.
	 * Update the btree height to reflect what we've learned from this
	 * block.
	 */
	fab->height = block_level + 1;

	/*
	 * If this block doesn't have sibling pointers, then it's the new root
	 * block candidate.  Otherwise, the root will be found farther up the
	 * tree.
	 */
	if (btblock->bb_u.s.bb_leftsib == cpu_to_be32(NULLAGBLOCK) &&
	    btblock->bb_u.s.bb_rightsib == cpu_to_be32(NULLAGBLOCK))
		fab->root = agbno;
	else
		fab->root = NULLAGBLOCK;

	trace_xrep_findroot_block(mp, ri->sc->sa.agno, agbno,
			be32_to_cpu(btblock->bb_magic), fab->height - 1);
out:
	scxfs_trans_brelse(ri->sc->tp, bp);
	return error;
}

/*
 * Do any of the blocks in this rmap record match one of the btrees we're
 * looking for?
 */
STATIC int
xrep_findroot_rmap(
	struct scxfs_btree_cur		*cur,
	struct scxfs_rmap_irec		*rec,
	void				*priv)
{
	struct xrep_findroot		*ri = priv;
	struct xrep_find_ag_btree	*fab;
	scxfs_agblock_t			b;
	bool				done;
	int				error = 0;

	/* Ignore anything that isn't AG metadata. */
	if (!SCXFS_RMAP_NON_INODE_OWNER(rec->rm_owner))
		return 0;

	/* Otherwise scan each block + btree type. */
	for (b = 0; b < rec->rm_blockcount; b++) {
		done = false;
		for (fab = ri->btree_info; fab->buf_ops; fab++) {
			if (rec->rm_owner != fab->rmap_owner)
				continue;
			error = xrep_findroot_block(ri, fab,
					rec->rm_owner, rec->rm_startblock + b,
					&done);
			if (error)
				return error;
			if (done)
				break;
		}
	}

	return 0;
}

/* Find the roots of the per-AG btrees described in btree_info. */
int
xrep_find_ag_btree_roots(
	struct scxfs_scrub		*sc,
	struct scxfs_buf			*agf_bp,
	struct xrep_find_ag_btree	*btree_info,
	struct scxfs_buf			*agfl_bp)
{
	struct scxfs_mount		*mp = sc->mp;
	struct xrep_findroot		ri;
	struct xrep_find_ag_btree	*fab;
	struct scxfs_btree_cur		*cur;
	int				error;

	ASSERT(scxfs_buf_islocked(agf_bp));
	ASSERT(agfl_bp == NULL || scxfs_buf_islocked(agfl_bp));

	ri.sc = sc;
	ri.btree_info = btree_info;
	ri.agf = SCXFS_BUF_TO_AGF(agf_bp);
	ri.agfl_bp = agfl_bp;
	for (fab = btree_info; fab->buf_ops; fab++) {
		ASSERT(agfl_bp || fab->rmap_owner != SCXFS_RMAP_OWN_AG);
		ASSERT(SCXFS_RMAP_NON_INODE_OWNER(fab->rmap_owner));
		fab->root = NULLAGBLOCK;
		fab->height = 0;
	}

	cur = scxfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno);
	error = scxfs_rmap_query_all(cur, xrep_findroot_rmap, &ri);
	scxfs_btree_del_cursor(cur, error);

	return error;
}

/* Force a quotacheck the next time we mount. */
void
xrep_force_quotacheck(
	struct scxfs_scrub	*sc,
	uint			dqtype)
{
	uint			flag;

	flag = scxfs_quota_chkd_flag(dqtype);
	if (!(flag & sc->mp->m_qflags))
		return;

	sc->mp->m_qflags &= ~flag;
	spin_lock(&sc->mp->m_sb_lock);
	sc->mp->m_sb.sb_qflags &= ~flag;
	spin_unlock(&sc->mp->m_sb_lock);
	scxfs_log_sb(sc->tp);
}

/*
 * Attach dquots to this inode, or schedule quotacheck to fix them.
 *
 * This function ensures that the appropriate dquots are attached to an inode.
 * We cannot allow the dquot code to allocate an on-disk dquot block here
 * because we're already in transaction context with the inode locked.  The
 * on-disk dquot should already exist anyway.  If the quota code signals
 * corruption or missing quota information, schedule quotacheck, which will
 * repair corruptions in the quota metadata.
 */
int
xrep_ino_dqattach(
	struct scxfs_scrub	*sc)
{
	int			error;

	error = scxfs_qm_dqattach_locked(sc->ip, false);
	switch (error) {
	case -EFSBADCRC:
	case -EFSCORRUPTED:
	case -ENOENT:
		scxfs_err_ratelimited(sc->mp,
"inode %llu repair encountered quota error %d, quotacheck forced.",
				(unsigned long long)sc->ip->i_ino, error);
		if (SCXFS_IS_UQUOTA_ON(sc->mp) && !sc->ip->i_udquot)
			xrep_force_quotacheck(sc, SCXFS_DQ_USER);
		if (SCXFS_IS_GQUOTA_ON(sc->mp) && !sc->ip->i_gdquot)
			xrep_force_quotacheck(sc, SCXFS_DQ_GROUP);
		if (SCXFS_IS_PQUOTA_ON(sc->mp) && !sc->ip->i_pdquot)
			xrep_force_quotacheck(sc, SCXFS_DQ_PROJ);
		/* fall through */
	case -ESRCH:
		error = 0;
		break;
	default:
		break;
	}

	return error;
}
