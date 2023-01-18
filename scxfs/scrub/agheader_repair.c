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
#include "scxfs_alloc.h"
#include "scxfs_alloc_btree.h"
#include "scxfs_ialloc.h"
#include "scxfs_ialloc_btree.h"
#include "scxfs_rmap.h"
#include "scxfs_rmap_btree.h"
#include "scxfs_refcount_btree.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/repair.h"
#include "scrub/bitmap.h"

/* Superblock */

/* Repair the superblock. */
int
xrep_superblock(
	struct scxfs_scrub	*sc)
{
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_buf		*bp;
	scxfs_agnumber_t		agno;
	int			error;

	/* Don't try to repair AG 0's sb; let scxfs_repair deal with it. */
	agno = sc->sm->sm_agno;
	if (agno == 0)
		return -EOPNOTSUPP;

	error = scxfs_sb_get_secondary(mp, sc->tp, agno, &bp);
	if (error)
		return error;

	/* Copy AG 0's superblock to this one. */
	scxfs_buf_zero(bp, 0, BBTOB(bp->b_length));
	scxfs_sb_to_disk(SCXFS_BUF_TO_SBP(bp), &mp->m_sb);

	/* Write this to disk. */
	scxfs_trans_buf_set_type(sc->tp, bp, SCXFS_BLFT_SB_BUF);
	scxfs_trans_log_buf(sc->tp, bp, 0, BBTOB(bp->b_length) - 1);
	return error;
}

/* AGF */

struct xrep_agf_allocbt {
	struct scxfs_scrub	*sc;
	scxfs_agblock_t		freeblks;
	scxfs_agblock_t		longest;
};

/* Record free space shape information. */
STATIC int
xrep_agf_walk_allocbt(
	struct scxfs_btree_cur		*cur,
	struct scxfs_alloc_rec_incore	*rec,
	void				*priv)
{
	struct xrep_agf_allocbt		*raa = priv;
	int				error = 0;

	if (xchk_should_terminate(raa->sc, &error))
		return error;

	raa->freeblks += rec->ar_blockcount;
	if (rec->ar_blockcount > raa->longest)
		raa->longest = rec->ar_blockcount;
	return error;
}

/* Does this AGFL block look sane? */
STATIC int
xrep_agf_check_agfl_block(
	struct scxfs_mount	*mp,
	scxfs_agblock_t		agbno,
	void			*priv)
{
	struct scxfs_scrub	*sc = priv;

	if (!scxfs_verify_agbno(mp, sc->sa.agno, agbno))
		return -EFSCORRUPTED;
	return 0;
}

/*
 * Offset within the xrep_find_ag_btree array for each btree type.  Avoid the
 * SCXFS_BTNUM_ names here to avoid creating a sparse array.
 */
enum {
	XREP_AGF_BNOBT = 0,
	XREP_AGF_CNTBT,
	XREP_AGF_RMAPBT,
	XREP_AGF_REFCOUNTBT,
	XREP_AGF_END,
	XREP_AGF_MAX
};

/* Check a btree root candidate. */
static inline bool
xrep_check_btree_root(
	struct scxfs_scrub		*sc,
	struct xrep_find_ag_btree	*fab)
{
	struct scxfs_mount		*mp = sc->mp;
	scxfs_agnumber_t			agno = sc->sm->sm_agno;

	return scxfs_verify_agbno(mp, agno, fab->root) &&
	       fab->height <= SCXFS_BTREE_MAXLEVELS;
}

/*
 * Given the btree roots described by *fab, find the roots, check them for
 * sanity, and pass the root data back out via *fab.
 *
 * This is /also/ a chicken and egg problem because we have to use the rmapbt
 * (rooted in the AGF) to find the btrees rooted in the AGF.  We also have no
 * idea if the btrees make any sense.  If we hit obvious corruptions in those
 * btrees we'll bail out.
 */
STATIC int
xrep_agf_find_btrees(
	struct scxfs_scrub		*sc,
	struct scxfs_buf			*agf_bp,
	struct xrep_find_ag_btree	*fab,
	struct scxfs_buf			*agfl_bp)
{
	struct scxfs_agf			*old_agf = SCXFS_BUF_TO_AGF(agf_bp);
	int				error;

	/* Go find the root data. */
	error = xrep_find_ag_btree_roots(sc, agf_bp, fab, agfl_bp);
	if (error)
		return error;

	/* We must find the bnobt, cntbt, and rmapbt roots. */
	if (!xrep_check_btree_root(sc, &fab[XREP_AGF_BNOBT]) ||
	    !xrep_check_btree_root(sc, &fab[XREP_AGF_CNTBT]) ||
	    !xrep_check_btree_root(sc, &fab[XREP_AGF_RMAPBT]))
		return -EFSCORRUPTED;

	/*
	 * We relied on the rmapbt to reconstruct the AGF.  If we get a
	 * different root then something's seriously wrong.
	 */
	if (fab[XREP_AGF_RMAPBT].root !=
	    be32_to_cpu(old_agf->agf_roots[SCXFS_BTNUM_RMAPi]))
		return -EFSCORRUPTED;

	/* We must find the refcountbt root if that feature is enabled. */
	if (scxfs_sb_version_hasreflink(&sc->mp->m_sb) &&
	    !xrep_check_btree_root(sc, &fab[XREP_AGF_REFCOUNTBT]))
		return -EFSCORRUPTED;

	return 0;
}

/*
 * Reinitialize the AGF header, making an in-core copy of the old contents so
 * that we know which in-core state needs to be reinitialized.
 */
STATIC void
xrep_agf_init_header(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agf_bp,
	struct scxfs_agf		*old_agf)
{
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agf_bp);

	memcpy(old_agf, agf, sizeof(*old_agf));
	memset(agf, 0, BBTOB(agf_bp->b_length));
	agf->agf_magicnum = cpu_to_be32(SCXFS_AGF_MAGIC);
	agf->agf_versionnum = cpu_to_be32(SCXFS_AGF_VERSION);
	agf->agf_seqno = cpu_to_be32(sc->sa.agno);
	agf->agf_length = cpu_to_be32(scxfs_ag_block_count(mp, sc->sa.agno));
	agf->agf_flfirst = old_agf->agf_flfirst;
	agf->agf_fllast = old_agf->agf_fllast;
	agf->agf_flcount = old_agf->agf_flcount;
	if (scxfs_sb_version_hascrc(&mp->m_sb))
		uuid_copy(&agf->agf_uuid, &mp->m_sb.sb_meta_uuid);

	/* Mark the incore AGF data stale until we're done fixing things. */
	ASSERT(sc->sa.pag->pagf_init);
	sc->sa.pag->pagf_init = 0;
}

/* Set btree root information in an AGF. */
STATIC void
xrep_agf_set_roots(
	struct scxfs_scrub		*sc,
	struct scxfs_agf			*agf,
	struct xrep_find_ag_btree	*fab)
{
	agf->agf_roots[SCXFS_BTNUM_BNOi] =
			cpu_to_be32(fab[XREP_AGF_BNOBT].root);
	agf->agf_levels[SCXFS_BTNUM_BNOi] =
			cpu_to_be32(fab[XREP_AGF_BNOBT].height);

	agf->agf_roots[SCXFS_BTNUM_CNTi] =
			cpu_to_be32(fab[XREP_AGF_CNTBT].root);
	agf->agf_levels[SCXFS_BTNUM_CNTi] =
			cpu_to_be32(fab[XREP_AGF_CNTBT].height);

	agf->agf_roots[SCXFS_BTNUM_RMAPi] =
			cpu_to_be32(fab[XREP_AGF_RMAPBT].root);
	agf->agf_levels[SCXFS_BTNUM_RMAPi] =
			cpu_to_be32(fab[XREP_AGF_RMAPBT].height);

	if (scxfs_sb_version_hasreflink(&sc->mp->m_sb)) {
		agf->agf_refcount_root =
				cpu_to_be32(fab[XREP_AGF_REFCOUNTBT].root);
		agf->agf_refcount_level =
				cpu_to_be32(fab[XREP_AGF_REFCOUNTBT].height);
	}
}

/* Update all AGF fields which derive from btree contents. */
STATIC int
xrep_agf_calc_from_btrees(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agf_bp)
{
	struct xrep_agf_allocbt	raa = { .sc = sc };
	struct scxfs_btree_cur	*cur = NULL;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agf_bp);
	struct scxfs_mount	*mp = sc->mp;
	scxfs_agblock_t		btreeblks;
	scxfs_agblock_t		blocks;
	int			error;

	/* Update the AGF counters from the bnobt. */
	cur = scxfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			SCXFS_BTNUM_BNO);
	error = scxfs_alloc_query_all(cur, xrep_agf_walk_allocbt, &raa);
	if (error)
		goto err;
	error = scxfs_btree_count_blocks(cur, &blocks);
	if (error)
		goto err;
	scxfs_btree_del_cursor(cur, error);
	btreeblks = blocks - 1;
	agf->agf_freeblks = cpu_to_be32(raa.freeblks);
	agf->agf_longest = cpu_to_be32(raa.longest);

	/* Update the AGF counters from the cntbt. */
	cur = scxfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			SCXFS_BTNUM_CNT);
	error = scxfs_btree_count_blocks(cur, &blocks);
	if (error)
		goto err;
	scxfs_btree_del_cursor(cur, error);
	btreeblks += blocks - 1;

	/* Update the AGF counters from the rmapbt. */
	cur = scxfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno);
	error = scxfs_btree_count_blocks(cur, &blocks);
	if (error)
		goto err;
	scxfs_btree_del_cursor(cur, error);
	agf->agf_rmap_blocks = cpu_to_be32(blocks);
	btreeblks += blocks - 1;

	agf->agf_btreeblks = cpu_to_be32(btreeblks);

	/* Update the AGF counters from the refcountbt. */
	if (scxfs_sb_version_hasreflink(&mp->m_sb)) {
		cur = scxfs_refcountbt_init_cursor(mp, sc->tp, agf_bp,
				sc->sa.agno);
		error = scxfs_btree_count_blocks(cur, &blocks);
		if (error)
			goto err;
		scxfs_btree_del_cursor(cur, error);
		agf->agf_refcount_blocks = cpu_to_be32(blocks);
	}

	return 0;
err:
	scxfs_btree_del_cursor(cur, error);
	return error;
}

/* Commit the new AGF and reinitialize the incore state. */
STATIC int
xrep_agf_commit_new(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agf_bp)
{
	struct scxfs_perag	*pag;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agf_bp);

	/* Trigger fdblocks recalculation */
	scxfs_force_summary_recalc(sc->mp);

	/* Write this to disk. */
	scxfs_trans_buf_set_type(sc->tp, agf_bp, SCXFS_BLFT_AGF_BUF);
	scxfs_trans_log_buf(sc->tp, agf_bp, 0, BBTOB(agf_bp->b_length) - 1);

	/* Now reinitialize the in-core counters we changed. */
	pag = sc->sa.pag;
	pag->pagf_btreeblks = be32_to_cpu(agf->agf_btreeblks);
	pag->pagf_freeblks = be32_to_cpu(agf->agf_freeblks);
	pag->pagf_longest = be32_to_cpu(agf->agf_longest);
	pag->pagf_levels[SCXFS_BTNUM_BNOi] =
			be32_to_cpu(agf->agf_levels[SCXFS_BTNUM_BNOi]);
	pag->pagf_levels[SCXFS_BTNUM_CNTi] =
			be32_to_cpu(agf->agf_levels[SCXFS_BTNUM_CNTi]);
	pag->pagf_levels[SCXFS_BTNUM_RMAPi] =
			be32_to_cpu(agf->agf_levels[SCXFS_BTNUM_RMAPi]);
	pag->pagf_refcount_level = be32_to_cpu(agf->agf_refcount_level);
	pag->pagf_init = 1;

	return 0;
}

/* Repair the AGF. v5 filesystems only. */
int
xrep_agf(
	struct scxfs_scrub		*sc)
{
	struct xrep_find_ag_btree	fab[XREP_AGF_MAX] = {
		[XREP_AGF_BNOBT] = {
			.rmap_owner = SCXFS_RMAP_OWN_AG,
			.buf_ops = &scxfs_bnobt_buf_ops,
		},
		[XREP_AGF_CNTBT] = {
			.rmap_owner = SCXFS_RMAP_OWN_AG,
			.buf_ops = &scxfs_cntbt_buf_ops,
		},
		[XREP_AGF_RMAPBT] = {
			.rmap_owner = SCXFS_RMAP_OWN_AG,
			.buf_ops = &scxfs_rmapbt_buf_ops,
		},
		[XREP_AGF_REFCOUNTBT] = {
			.rmap_owner = SCXFS_RMAP_OWN_REFC,
			.buf_ops = &scxfs_refcountbt_buf_ops,
		},
		[XREP_AGF_END] = {
			.buf_ops = NULL,
		},
	};
	struct scxfs_agf			old_agf;
	struct scxfs_mount		*mp = sc->mp;
	struct scxfs_buf			*agf_bp;
	struct scxfs_buf			*agfl_bp;
	struct scxfs_agf			*agf;
	int				error;

	/* We require the rmapbt to rebuild anything. */
	if (!scxfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	xchk_perag_get(sc->mp, &sc->sa);
	/*
	 * Make sure we have the AGF buffer, as scrub might have decided it
	 * was corrupt after scxfs_alloc_read_agf failed with -EFSCORRUPTED.
	 */
	error = scxfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
			SCXFS_AG_DADDR(mp, sc->sa.agno, SCXFS_AGF_DADDR(mp)),
			SCXFS_FSS_TO_BB(mp, 1), 0, &agf_bp, NULL);
	if (error)
		return error;
	agf_bp->b_ops = &scxfs_agf_buf_ops;
	agf = SCXFS_BUF_TO_AGF(agf_bp);

	/*
	 * Load the AGFL so that we can screen out OWN_AG blocks that are on
	 * the AGFL now; these blocks might have once been part of the
	 * bno/cnt/rmap btrees but are not now.  This is a chicken and egg
	 * problem: the AGF is corrupt, so we have to trust the AGFL contents
	 * because we can't do any serious cross-referencing with any of the
	 * btrees rooted in the AGF.  If the AGFL contents are obviously bad
	 * then we'll bail out.
	 */
	error = scxfs_alloc_read_agfl(mp, sc->tp, sc->sa.agno, &agfl_bp);
	if (error)
		return error;

	/*
	 * Spot-check the AGFL blocks; if they're obviously corrupt then
	 * there's nothing we can do but bail out.
	 */
	error = scxfs_agfl_walk(sc->mp, SCXFS_BUF_TO_AGF(agf_bp), agfl_bp,
			xrep_agf_check_agfl_block, sc);
	if (error)
		return error;

	/*
	 * Find the AGF btree roots.  This is also a chicken-and-egg situation;
	 * see the function for more details.
	 */
	error = xrep_agf_find_btrees(sc, agf_bp, fab, agfl_bp);
	if (error)
		return error;

	/* Start rewriting the header and implant the btrees we found. */
	xrep_agf_init_header(sc, agf_bp, &old_agf);
	xrep_agf_set_roots(sc, agf, fab);
	error = xrep_agf_calc_from_btrees(sc, agf_bp);
	if (error)
		goto out_revert;

	/* Commit the changes and reinitialize incore state. */
	return xrep_agf_commit_new(sc, agf_bp);

out_revert:
	/* Mark the incore AGF state stale and revert the AGF. */
	sc->sa.pag->pagf_init = 0;
	memcpy(agf, &old_agf, sizeof(old_agf));
	return error;
}

/* AGFL */

struct xrep_agfl {
	/* Bitmap of other OWN_AG metadata blocks. */
	struct scxfs_bitmap	agmetablocks;

	/* Bitmap of free space. */
	struct scxfs_bitmap	*freesp;

	struct scxfs_scrub	*sc;
};

/* Record all OWN_AG (free space btree) information from the rmap data. */
STATIC int
xrep_agfl_walk_rmap(
	struct scxfs_btree_cur	*cur,
	struct scxfs_rmap_irec	*rec,
	void			*priv)
{
	struct xrep_agfl	*ra = priv;
	scxfs_fsblock_t		fsb;
	int			error = 0;

	if (xchk_should_terminate(ra->sc, &error))
		return error;

	/* Record all the OWN_AG blocks. */
	if (rec->rm_owner == SCXFS_RMAP_OWN_AG) {
		fsb = SCXFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
				rec->rm_startblock);
		error = scxfs_bitmap_set(ra->freesp, fsb, rec->rm_blockcount);
		if (error)
			return error;
	}

	return scxfs_bitmap_set_btcur_path(&ra->agmetablocks, cur);
}

/*
 * Map out all the non-AGFL OWN_AG space in this AG so that we can deduce
 * which blocks belong to the AGFL.
 *
 * Compute the set of old AGFL blocks by subtracting from the list of OWN_AG
 * blocks the list of blocks owned by all other OWN_AG metadata (bnobt, cntbt,
 * rmapbt).  These are the old AGFL blocks, so return that list and the number
 * of blocks we're actually going to put back on the AGFL.
 */
STATIC int
xrep_agfl_collect_blocks(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agf_bp,
	struct scxfs_bitmap	*agfl_extents,
	scxfs_agblock_t		*flcount)
{
	struct xrep_agfl	ra;
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_btree_cur	*cur;
	struct scxfs_bitmap_range	*br;
	struct scxfs_bitmap_range	*n;
	int			error;

	ra.sc = sc;
	ra.freesp = agfl_extents;
	scxfs_bitmap_init(&ra.agmetablocks);

	/* Find all space used by the free space btrees & rmapbt. */
	cur = scxfs_rmapbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno);
	error = scxfs_rmap_query_all(cur, xrep_agfl_walk_rmap, &ra);
	if (error)
		goto err;
	scxfs_btree_del_cursor(cur, error);

	/* Find all blocks currently being used by the bnobt. */
	cur = scxfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			SCXFS_BTNUM_BNO);
	error = scxfs_bitmap_set_btblocks(&ra.agmetablocks, cur);
	if (error)
		goto err;
	scxfs_btree_del_cursor(cur, error);

	/* Find all blocks currently being used by the cntbt. */
	cur = scxfs_allocbt_init_cursor(mp, sc->tp, agf_bp, sc->sa.agno,
			SCXFS_BTNUM_CNT);
	error = scxfs_bitmap_set_btblocks(&ra.agmetablocks, cur);
	if (error)
		goto err;

	scxfs_btree_del_cursor(cur, error);

	/*
	 * Drop the freesp meta blocks that are in use by btrees.
	 * The remaining blocks /should/ be AGFL blocks.
	 */
	error = scxfs_bitmap_disunion(agfl_extents, &ra.agmetablocks);
	scxfs_bitmap_destroy(&ra.agmetablocks);
	if (error)
		return error;

	/*
	 * Calculate the new AGFL size.  If we found more blocks than fit in
	 * the AGFL we'll free them later.
	 */
	*flcount = 0;
	for_each_scxfs_bitmap_extent(br, n, agfl_extents) {
		*flcount += br->len;
		if (*flcount > scxfs_agfl_size(mp))
			break;
	}
	if (*flcount > scxfs_agfl_size(mp))
		*flcount = scxfs_agfl_size(mp);
	return 0;

err:
	scxfs_bitmap_destroy(&ra.agmetablocks);
	scxfs_btree_del_cursor(cur, error);
	return error;
}

/* Update the AGF and reset the in-core state. */
STATIC void
xrep_agfl_update_agf(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agf_bp,
	scxfs_agblock_t		flcount)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agf_bp);

	ASSERT(flcount <= scxfs_agfl_size(sc->mp));

	/* Trigger fdblocks recalculation */
	scxfs_force_summary_recalc(sc->mp);

	/* Update the AGF counters. */
	if (sc->sa.pag->pagf_init)
		sc->sa.pag->pagf_flcount = flcount;
	agf->agf_flfirst = cpu_to_be32(0);
	agf->agf_flcount = cpu_to_be32(flcount);
	agf->agf_fllast = cpu_to_be32(flcount - 1);

	scxfs_alloc_log_agf(sc->tp, agf_bp,
			SCXFS_AGF_FLFIRST | SCXFS_AGF_FLLAST | SCXFS_AGF_FLCOUNT);
}

/* Write out a totally new AGFL. */
STATIC void
xrep_agfl_init_header(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agfl_bp,
	struct scxfs_bitmap	*agfl_extents,
	scxfs_agblock_t		flcount)
{
	struct scxfs_mount	*mp = sc->mp;
	__be32			*agfl_bno;
	struct scxfs_bitmap_range	*br;
	struct scxfs_bitmap_range	*n;
	struct scxfs_agfl		*agfl;
	scxfs_agblock_t		agbno;
	unsigned int		fl_off;

	ASSERT(flcount <= scxfs_agfl_size(mp));

	/*
	 * Start rewriting the header by setting the bno[] array to
	 * NULLAGBLOCK, then setting AGFL header fields.
	 */
	agfl = SCXFS_BUF_TO_AGFL(agfl_bp);
	memset(agfl, 0xFF, BBTOB(agfl_bp->b_length));
	agfl->agfl_magicnum = cpu_to_be32(SCXFS_AGFL_MAGIC);
	agfl->agfl_seqno = cpu_to_be32(sc->sa.agno);
	uuid_copy(&agfl->agfl_uuid, &mp->m_sb.sb_meta_uuid);

	/*
	 * Fill the AGFL with the remaining blocks.  If agfl_extents has more
	 * blocks than fit in the AGFL, they will be freed in a subsequent
	 * step.
	 */
	fl_off = 0;
	agfl_bno = SCXFS_BUF_TO_AGFL_BNO(mp, agfl_bp);
	for_each_scxfs_bitmap_extent(br, n, agfl_extents) {
		agbno = SCXFS_FSB_TO_AGBNO(mp, br->start);

		trace_xrep_agfl_insert(mp, sc->sa.agno, agbno, br->len);

		while (br->len > 0 && fl_off < flcount) {
			agfl_bno[fl_off] = cpu_to_be32(agbno);
			fl_off++;
			agbno++;

			/*
			 * We've now used br->start by putting it in the AGFL,
			 * so bump br so that we don't reap the block later.
			 */
			br->start++;
			br->len--;
		}

		if (br->len)
			break;
		list_del(&br->list);
		kmem_free(br);
	}

	/* Write new AGFL to disk. */
	scxfs_trans_buf_set_type(sc->tp, agfl_bp, SCXFS_BLFT_AGFL_BUF);
	scxfs_trans_log_buf(sc->tp, agfl_bp, 0, BBTOB(agfl_bp->b_length) - 1);
}

/* Repair the AGFL. */
int
xrep_agfl(
	struct scxfs_scrub	*sc)
{
	struct scxfs_bitmap	agfl_extents;
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_buf		*agf_bp;
	struct scxfs_buf		*agfl_bp;
	scxfs_agblock_t		flcount;
	int			error;

	/* We require the rmapbt to rebuild anything. */
	if (!scxfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	xchk_perag_get(sc->mp, &sc->sa);
	scxfs_bitmap_init(&agfl_extents);

	/*
	 * Read the AGF so that we can query the rmapbt.  We hope that there's
	 * nothing wrong with the AGF, but all the AG header repair functions
	 * have this chicken-and-egg problem.
	 */
	error = scxfs_alloc_read_agf(mp, sc->tp, sc->sa.agno, 0, &agf_bp);
	if (error)
		return error;
	if (!agf_bp)
		return -ENOMEM;

	/*
	 * Make sure we have the AGFL buffer, as scrub might have decided it
	 * was corrupt after scxfs_alloc_read_agfl failed with -EFSCORRUPTED.
	 */
	error = scxfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
			SCXFS_AG_DADDR(mp, sc->sa.agno, SCXFS_AGFL_DADDR(mp)),
			SCXFS_FSS_TO_BB(mp, 1), 0, &agfl_bp, NULL);
	if (error)
		return error;
	agfl_bp->b_ops = &scxfs_agfl_buf_ops;

	/* Gather all the extents we're going to put on the new AGFL. */
	error = xrep_agfl_collect_blocks(sc, agf_bp, &agfl_extents, &flcount);
	if (error)
		goto err;

	/*
	 * Update AGF and AGFL.  We reset the global free block counter when
	 * we adjust the AGF flcount (which can fail) so avoid updating any
	 * buffers until we know that part works.
	 */
	xrep_agfl_update_agf(sc, agf_bp, flcount);
	xrep_agfl_init_header(sc, agfl_bp, &agfl_extents, flcount);

	/*
	 * Ok, the AGFL should be ready to go now.  Roll the transaction to
	 * make the new AGFL permanent before we start using it to return
	 * freespace overflow to the freespace btrees.
	 */
	sc->sa.agf_bp = agf_bp;
	sc->sa.agfl_bp = agfl_bp;
	error = xrep_roll_ag_trans(sc);
	if (error)
		goto err;

	/* Dump any AGFL overflow. */
	return xrep_reap_extents(sc, &agfl_extents, &SCXFS_RMAP_OINFO_AG,
			SCXFS_AG_RESV_AGFL);
err:
	scxfs_bitmap_destroy(&agfl_extents);
	return error;
}

/* AGI */

/*
 * Offset within the xrep_find_ag_btree array for each btree type.  Avoid the
 * SCXFS_BTNUM_ names here to avoid creating a sparse array.
 */
enum {
	XREP_AGI_INOBT = 0,
	XREP_AGI_FINOBT,
	XREP_AGI_END,
	XREP_AGI_MAX
};

/*
 * Given the inode btree roots described by *fab, find the roots, check them
 * for sanity, and pass the root data back out via *fab.
 */
STATIC int
xrep_agi_find_btrees(
	struct scxfs_scrub		*sc,
	struct xrep_find_ag_btree	*fab)
{
	struct scxfs_buf			*agf_bp;
	struct scxfs_mount		*mp = sc->mp;
	int				error;

	/* Read the AGF. */
	error = scxfs_alloc_read_agf(mp, sc->tp, sc->sa.agno, 0, &agf_bp);
	if (error)
		return error;
	if (!agf_bp)
		return -ENOMEM;

	/* Find the btree roots. */
	error = xrep_find_ag_btree_roots(sc, agf_bp, fab, NULL);
	if (error)
		return error;

	/* We must find the inobt root. */
	if (!xrep_check_btree_root(sc, &fab[XREP_AGI_INOBT]))
		return -EFSCORRUPTED;

	/* We must find the finobt root if that feature is enabled. */
	if (scxfs_sb_version_hasfinobt(&mp->m_sb) &&
	    !xrep_check_btree_root(sc, &fab[XREP_AGI_FINOBT]))
		return -EFSCORRUPTED;

	return 0;
}

/*
 * Reinitialize the AGI header, making an in-core copy of the old contents so
 * that we know which in-core state needs to be reinitialized.
 */
STATIC void
xrep_agi_init_header(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agi_bp,
	struct scxfs_agi		*old_agi)
{
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agi_bp);
	struct scxfs_mount	*mp = sc->mp;

	memcpy(old_agi, agi, sizeof(*old_agi));
	memset(agi, 0, BBTOB(agi_bp->b_length));
	agi->agi_magicnum = cpu_to_be32(SCXFS_AGI_MAGIC);
	agi->agi_versionnum = cpu_to_be32(SCXFS_AGI_VERSION);
	agi->agi_seqno = cpu_to_be32(sc->sa.agno);
	agi->agi_length = cpu_to_be32(scxfs_ag_block_count(mp, sc->sa.agno));
	agi->agi_newino = cpu_to_be32(NULLAGINO);
	agi->agi_dirino = cpu_to_be32(NULLAGINO);
	if (scxfs_sb_version_hascrc(&mp->m_sb))
		uuid_copy(&agi->agi_uuid, &mp->m_sb.sb_meta_uuid);

	/* We don't know how to fix the unlinked list yet. */
	memcpy(&agi->agi_unlinked, &old_agi->agi_unlinked,
			sizeof(agi->agi_unlinked));

	/* Mark the incore AGF data stale until we're done fixing things. */
	ASSERT(sc->sa.pag->pagi_init);
	sc->sa.pag->pagi_init = 0;
}

/* Set btree root information in an AGI. */
STATIC void
xrep_agi_set_roots(
	struct scxfs_scrub		*sc,
	struct scxfs_agi			*agi,
	struct xrep_find_ag_btree	*fab)
{
	agi->agi_root = cpu_to_be32(fab[XREP_AGI_INOBT].root);
	agi->agi_level = cpu_to_be32(fab[XREP_AGI_INOBT].height);

	if (scxfs_sb_version_hasfinobt(&sc->mp->m_sb)) {
		agi->agi_free_root = cpu_to_be32(fab[XREP_AGI_FINOBT].root);
		agi->agi_free_level = cpu_to_be32(fab[XREP_AGI_FINOBT].height);
	}
}

/* Update the AGI counters. */
STATIC int
xrep_agi_calc_from_btrees(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agi_bp)
{
	struct scxfs_btree_cur	*cur;
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agi_bp);
	struct scxfs_mount	*mp = sc->mp;
	scxfs_agino_t		count;
	scxfs_agino_t		freecount;
	int			error;

	cur = scxfs_inobt_init_cursor(mp, sc->tp, agi_bp, sc->sa.agno,
			SCXFS_BTNUM_INO);
	error = scxfs_ialloc_count_inodes(cur, &count, &freecount);
	if (error)
		goto err;
	scxfs_btree_del_cursor(cur, error);

	agi->agi_count = cpu_to_be32(count);
	agi->agi_freecount = cpu_to_be32(freecount);
	return 0;
err:
	scxfs_btree_del_cursor(cur, error);
	return error;
}

/* Trigger reinitialization of the in-core data. */
STATIC int
xrep_agi_commit_new(
	struct scxfs_scrub	*sc,
	struct scxfs_buf		*agi_bp)
{
	struct scxfs_perag	*pag;
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agi_bp);

	/* Trigger inode count recalculation */
	scxfs_force_summary_recalc(sc->mp);

	/* Write this to disk. */
	scxfs_trans_buf_set_type(sc->tp, agi_bp, SCXFS_BLFT_AGI_BUF);
	scxfs_trans_log_buf(sc->tp, agi_bp, 0, BBTOB(agi_bp->b_length) - 1);

	/* Now reinitialize the in-core counters if necessary. */
	pag = sc->sa.pag;
	pag->pagi_count = be32_to_cpu(agi->agi_count);
	pag->pagi_freecount = be32_to_cpu(agi->agi_freecount);
	pag->pagi_init = 1;

	return 0;
}

/* Repair the AGI. */
int
xrep_agi(
	struct scxfs_scrub		*sc)
{
	struct xrep_find_ag_btree	fab[XREP_AGI_MAX] = {
		[XREP_AGI_INOBT] = {
			.rmap_owner = SCXFS_RMAP_OWN_INOBT,
			.buf_ops = &scxfs_inobt_buf_ops,
		},
		[XREP_AGI_FINOBT] = {
			.rmap_owner = SCXFS_RMAP_OWN_INOBT,
			.buf_ops = &scxfs_finobt_buf_ops,
		},
		[XREP_AGI_END] = {
			.buf_ops = NULL
		},
	};
	struct scxfs_agi			old_agi;
	struct scxfs_mount		*mp = sc->mp;
	struct scxfs_buf			*agi_bp;
	struct scxfs_agi			*agi;
	int				error;

	/* We require the rmapbt to rebuild anything. */
	if (!scxfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	xchk_perag_get(sc->mp, &sc->sa);
	/*
	 * Make sure we have the AGI buffer, as scrub might have decided it
	 * was corrupt after scxfs_ialloc_read_agi failed with -EFSCORRUPTED.
	 */
	error = scxfs_trans_read_buf(mp, sc->tp, mp->m_ddev_targp,
			SCXFS_AG_DADDR(mp, sc->sa.agno, SCXFS_AGI_DADDR(mp)),
			SCXFS_FSS_TO_BB(mp, 1), 0, &agi_bp, NULL);
	if (error)
		return error;
	agi_bp->b_ops = &scxfs_agi_buf_ops;
	agi = SCXFS_BUF_TO_AGI(agi_bp);

	/* Find the AGI btree roots. */
	error = xrep_agi_find_btrees(sc, fab);
	if (error)
		return error;

	/* Start rewriting the header and implant the btrees we found. */
	xrep_agi_init_header(sc, agi_bp, &old_agi);
	xrep_agi_set_roots(sc, agi, fab);
	error = xrep_agi_calc_from_btrees(sc, agi_bp);
	if (error)
		goto out_revert;

	/* Reinitialize in-core state. */
	return xrep_agi_commit_new(sc, agi_bp);

out_revert:
	/* Mark the incore AGI state stale and revert the AGI. */
	sc->sa.pag->pagi_init = 0;
	memcpy(agi, &old_agi, sizeof(old_agi));
	return error;
}
