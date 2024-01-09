// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_btree.h"
#include "scxfs_bit.h"
#include "scxfs_log_format.h"
#include "scxfs_trans.h"
#include "scxfs_inode.h"
#include "scxfs_alloc.h"
#include "scxfs_bmap.h"
#include "scxfs_bmap_btree.h"
#include "scxfs_rmap.h"
#include "scxfs_rmap_btree.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"

/* Set us up with an inode's bmap. */
int
xchk_setup_inode_bmap(
	struct scxfs_scrub	*sc,
	struct scxfs_inode	*ip)
{
	int			error;

	error = xchk_get_inode(sc, ip);
	if (error)
		goto out;

	sc->ilock_flags = SCXFS_IOLOCK_EXCL | SCXFS_MMAPLOCK_EXCL;
	scxfs_ilock(sc->ip, sc->ilock_flags);

	/*
	 * We don't want any ephemeral data fork updates sitting around
	 * while we inspect block mappings, so wait for directio to finish
	 * and flush dirty data if we have delalloc reservations.
	 */
	if (S_ISREG(VFS_I(sc->ip)->i_mode) &&
	    sc->sm->sm_type == SCXFS_SCRUB_TYPE_BMBTD) {
		struct address_space	*mapping = VFS_I(sc->ip)->i_mapping;

		inode_dio_wait(VFS_I(sc->ip));

		/*
		 * Try to flush all incore state to disk before we examine the
		 * space mappings for the data fork.  Leave accumulated errors
		 * in the mapping for the writer threads to consume.
		 *
		 * On ENOSPC or EIO writeback errors, we continue into the
		 * extent mapping checks because write failures do not
		 * necessarily imply anything about the correctness of the file
		 * metadata.  The metadata and the file data could be on
		 * completely separate devices; a media failure might only
		 * affect a subset of the disk, etc.  We can handle delalloc
		 * extents in the scrubber, so leaving them in memory is fine.
		 */
		error = filemap_fdatawrite(mapping);
		if (!error)
			error = filemap_fdatawait_keep_errors(mapping);
		if (error && (error != -ENOSPC && error != -EIO))
			goto out;
	}

	/* Got the inode, lock it and we're ready to go. */
	error = xchk_trans_alloc(sc, 0);
	if (error)
		goto out;
	sc->ilock_flags |= SCXFS_ILOCK_EXCL;
	scxfs_ilock(sc->ip, SCXFS_ILOCK_EXCL);

out:
	/* scrub teardown will unlock and release the inode */
	return error;
}

/*
 * Inode fork block mapping (BMBT) scrubber.
 * More complex than the others because we have to scrub
 * all the extents regardless of whether or not the fork
 * is in btree format.
 */

struct xchk_bmap_info {
	struct scxfs_scrub	*sc;
	scxfs_fileoff_t		lastoff;
	bool			is_rt;
	bool			is_shared;
	bool			was_loaded;
	int			whichfork;
};

/* Look for a corresponding rmap for this irec. */
static inline bool
xchk_bmap_get_rmap(
	struct xchk_bmap_info	*info,
	struct scxfs_bmbt_irec	*irec,
	scxfs_agblock_t		agbno,
	uint64_t		owner,
	struct scxfs_rmap_irec	*rmap)
{
	scxfs_fileoff_t		offset;
	unsigned int		rflags = 0;
	int			has_rmap;
	int			error;

	if (info->whichfork == SCXFS_ATTR_FORK)
		rflags |= SCXFS_RMAP_ATTR_FORK;
	if (irec->br_state == SCXFS_EXT_UNWRITTEN)
		rflags |= SCXFS_RMAP_UNWRITTEN;

	/*
	 * CoW staging extents are owned (on disk) by the refcountbt, so
	 * their rmaps do not have offsets.
	 */
	if (info->whichfork == SCXFS_COW_FORK)
		offset = 0;
	else
		offset = irec->br_startoff;

	/*
	 * If the caller thinks this could be a shared bmbt extent (IOWs,
	 * any data fork extent of a reflink inode) then we have to use the
	 * range rmap lookup to make sure we get the correct owner/offset.
	 */
	if (info->is_shared) {
		error = scxfs_rmap_lookup_le_range(info->sc->sa.rmap_cur, agbno,
				owner, offset, rflags, rmap, &has_rmap);
		if (!xchk_should_check_xref(info->sc, &error,
				&info->sc->sa.rmap_cur))
			return false;
		goto out;
	}

	/*
	 * Otherwise, use the (faster) regular lookup.
	 */
	error = scxfs_rmap_lookup_le(info->sc->sa.rmap_cur, agbno, 0, owner,
			offset, rflags, &has_rmap);
	if (!xchk_should_check_xref(info->sc, &error,
			&info->sc->sa.rmap_cur))
		return false;
	if (!has_rmap)
		goto out;

	error = scxfs_rmap_get_rec(info->sc->sa.rmap_cur, rmap, &has_rmap);
	if (!xchk_should_check_xref(info->sc, &error,
			&info->sc->sa.rmap_cur))
		return false;

out:
	if (!has_rmap)
		xchk_fblock_xref_set_corrupt(info->sc, info->whichfork,
			irec->br_startoff);
	return has_rmap;
}

/* Make sure that we have rmapbt records for this extent. */
STATIC void
xchk_bmap_xref_rmap(
	struct xchk_bmap_info	*info,
	struct scxfs_bmbt_irec	*irec,
	scxfs_agblock_t		agbno)
{
	struct scxfs_rmap_irec	rmap;
	unsigned long long	rmap_end;
	uint64_t		owner;

	if (!info->sc->sa.rmap_cur || xchk_skip_xref(info->sc->sm))
		return;

	if (info->whichfork == SCXFS_COW_FORK)
		owner = SCXFS_RMAP_OWN_COW;
	else
		owner = info->sc->ip->i_ino;

	/* Find the rmap record for this irec. */
	if (!xchk_bmap_get_rmap(info, irec, agbno, owner, &rmap))
		return;

	/* Check the rmap. */
	rmap_end = (unsigned long long)rmap.rm_startblock + rmap.rm_blockcount;
	if (rmap.rm_startblock > agbno ||
	    agbno + irec->br_blockcount > rmap_end)
		xchk_fblock_xref_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	/*
	 * Check the logical offsets if applicable.  CoW staging extents
	 * don't track logical offsets since the mappings only exist in
	 * memory.
	 */
	if (info->whichfork != SCXFS_COW_FORK) {
		rmap_end = (unsigned long long)rmap.rm_offset +
				rmap.rm_blockcount;
		if (rmap.rm_offset > irec->br_startoff ||
		    irec->br_startoff + irec->br_blockcount > rmap_end)
			xchk_fblock_xref_set_corrupt(info->sc,
					info->whichfork, irec->br_startoff);
	}

	if (rmap.rm_owner != owner)
		xchk_fblock_xref_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	/*
	 * Check for discrepancies between the unwritten flag in the irec and
	 * the rmap.  Note that the (in-memory) CoW fork distinguishes between
	 * unwritten and written extents, but we don't track that in the rmap
	 * records because the blocks are owned (on-disk) by the refcountbt,
	 * which doesn't track unwritten state.
	 */
	if (owner != SCXFS_RMAP_OWN_COW &&
	    !!(irec->br_state == SCXFS_EXT_UNWRITTEN) !=
	    !!(rmap.rm_flags & SCXFS_RMAP_UNWRITTEN))
		xchk_fblock_xref_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	if (!!(info->whichfork == SCXFS_ATTR_FORK) !=
	    !!(rmap.rm_flags & SCXFS_RMAP_ATTR_FORK))
		xchk_fblock_xref_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);
	if (rmap.rm_flags & SCXFS_RMAP_BMBT_BLOCK)
		xchk_fblock_xref_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);
}

/* Cross-reference a single rtdev extent record. */
STATIC void
xchk_bmap_rt_iextent_xref(
	struct scxfs_inode	*ip,
	struct xchk_bmap_info	*info,
	struct scxfs_bmbt_irec	*irec)
{
	xchk_xref_is_used_rt_space(info->sc, irec->br_startblock,
			irec->br_blockcount);
}

/* Cross-reference a single datadev extent record. */
STATIC void
xchk_bmap_iextent_xref(
	struct scxfs_inode	*ip,
	struct xchk_bmap_info	*info,
	struct scxfs_bmbt_irec	*irec)
{
	struct scxfs_mount	*mp = info->sc->mp;
	scxfs_agnumber_t		agno;
	scxfs_agblock_t		agbno;
	scxfs_extlen_t		len;
	int			error;

	agno = SCXFS_FSB_TO_AGNO(mp, irec->br_startblock);
	agbno = SCXFS_FSB_TO_AGBNO(mp, irec->br_startblock);
	len = irec->br_blockcount;

	error = xchk_ag_init(info->sc, agno, &info->sc->sa);
	if (!xchk_fblock_process_error(info->sc, info->whichfork,
			irec->br_startoff, &error))
		return;

	xchk_xref_is_used_space(info->sc, agbno, len);
	xchk_xref_is_not_inode_chunk(info->sc, agbno, len);
	xchk_bmap_xref_rmap(info, irec, agbno);
	switch (info->whichfork) {
	case SCXFS_DATA_FORK:
		if (scxfs_is_reflink_inode(info->sc->ip))
			break;
		/* fall through */
	case SCXFS_ATTR_FORK:
		xchk_xref_is_not_shared(info->sc, agbno,
				irec->br_blockcount);
		break;
	case SCXFS_COW_FORK:
		xchk_xref_is_cow_staging(info->sc, agbno,
				irec->br_blockcount);
		break;
	}

	xchk_ag_free(info->sc, &info->sc->sa);
}

/*
 * Directories and attr forks should never have blocks that can't be addressed
 * by a scxfs_dablk_t.
 */
STATIC void
xchk_bmap_dirattr_extent(
	struct scxfs_inode	*ip,
	struct xchk_bmap_info	*info,
	struct scxfs_bmbt_irec	*irec)
{
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_fileoff_t		off;

	if (!S_ISDIR(VFS_I(ip)->i_mode) && info->whichfork != SCXFS_ATTR_FORK)
		return;

	if (!scxfs_verify_dablk(mp, irec->br_startoff))
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	off = irec->br_startoff + irec->br_blockcount - 1;
	if (!scxfs_verify_dablk(mp, off))
		xchk_fblock_set_corrupt(info->sc, info->whichfork, off);
}

/* Scrub a single extent record. */
STATIC int
xchk_bmap_iextent(
	struct scxfs_inode	*ip,
	struct xchk_bmap_info	*info,
	struct scxfs_bmbt_irec	*irec)
{
	struct scxfs_mount	*mp = info->sc->mp;
	scxfs_filblks_t		end;
	int			error = 0;

	/*
	 * Check for out-of-order extents.  This record could have come
	 * from the incore list, for which there is no ordering check.
	 */
	if (irec->br_startoff < info->lastoff)
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	xchk_bmap_dirattr_extent(ip, info, irec);

	/* There should never be a "hole" extent in either extent list. */
	if (irec->br_startblock == HOLESTARTBLOCK)
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	/*
	 * Check for delalloc extents.  We never iterate the ones in the
	 * in-core extent scan, and we should never see these in the bmbt.
	 */
	if (isnullstartblock(irec->br_startblock))
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	/* Make sure the extent points to a valid place. */
	if (irec->br_blockcount > MAXEXTLEN)
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);
	if (irec->br_startblock + irec->br_blockcount <= irec->br_startblock)
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);
	end = irec->br_startblock + irec->br_blockcount - 1;
	if (info->is_rt &&
	    (!scxfs_verify_rtbno(mp, irec->br_startblock) ||
	     !scxfs_verify_rtbno(mp, end)))
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);
	if (!info->is_rt &&
	    (!scxfs_verify_fsbno(mp, irec->br_startblock) ||
	     !scxfs_verify_fsbno(mp, end) ||
	     SCXFS_FSB_TO_AGNO(mp, irec->br_startblock) !=
				SCXFS_FSB_TO_AGNO(mp, end)))
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	/* We don't allow unwritten extents on attr forks. */
	if (irec->br_state == SCXFS_EXT_UNWRITTEN &&
	    info->whichfork == SCXFS_ATTR_FORK)
		xchk_fblock_set_corrupt(info->sc, info->whichfork,
				irec->br_startoff);

	if (info->sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT)
		return 0;

	if (info->is_rt)
		xchk_bmap_rt_iextent_xref(ip, info, irec);
	else
		xchk_bmap_iextent_xref(ip, info, irec);

	info->lastoff = irec->br_startoff + irec->br_blockcount;
	return error;
}

/* Scrub a bmbt record. */
STATIC int
xchk_bmapbt_rec(
	struct xchk_btree	*bs,
	union scxfs_btree_rec	*rec)
{
	struct scxfs_bmbt_irec	irec;
	struct scxfs_bmbt_irec	iext_irec;
	struct scxfs_iext_cursor	icur;
	struct xchk_bmap_info	*info = bs->private;
	struct scxfs_inode	*ip = bs->cur->bc_private.b.ip;
	struct scxfs_buf		*bp = NULL;
	struct scxfs_btree_block	*block;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, info->whichfork);
	uint64_t		owner;
	int			i;

	/*
	 * Check the owners of the btree blocks up to the level below
	 * the root since the verifiers don't do that.
	 */
	if (scxfs_sb_version_hascrc(&bs->cur->bc_mp->m_sb) &&
	    bs->cur->bc_ptrs[0] == 1) {
		for (i = 0; i < bs->cur->bc_nlevels - 1; i++) {
			block = scxfs_btree_get_block(bs->cur, i, &bp);
			owner = be64_to_cpu(block->bb_u.l.bb_owner);
			if (owner != ip->i_ino)
				xchk_fblock_set_corrupt(bs->sc,
						info->whichfork, 0);
		}
	}

	/*
	 * Check that the incore extent tree contains an extent that matches
	 * this one exactly.  We validate those cached bmaps later, so we don't
	 * need to check them here.  If the incore extent tree was just loaded
	 * from disk by the scrubber, we assume that its contents match what's
	 * on disk (we still hold the ILOCK) and skip the equivalence check.
	 */
	if (!info->was_loaded)
		return 0;

	scxfs_bmbt_disk_get_all(&rec->bmbt, &irec);
	if (!scxfs_iext_lookup_extent(ip, ifp, irec.br_startoff, &icur,
				&iext_irec) ||
	    irec.br_startoff != iext_irec.br_startoff ||
	    irec.br_startblock != iext_irec.br_startblock ||
	    irec.br_blockcount != iext_irec.br_blockcount ||
	    irec.br_state != iext_irec.br_state)
		xchk_fblock_set_corrupt(bs->sc, info->whichfork,
				irec.br_startoff);
	return 0;
}

/* Scan the btree records. */
STATIC int
xchk_bmap_btree(
	struct scxfs_scrub	*sc,
	int			whichfork,
	struct xchk_bmap_info	*info)
{
	struct scxfs_owner_info	oinfo;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(sc->ip, whichfork);
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_inode	*ip = sc->ip;
	struct scxfs_btree_cur	*cur;
	int			error;

	/* Load the incore bmap cache if it's not loaded. */
	info->was_loaded = ifp->if_flags & SCXFS_IFEXTENTS;
	if (!info->was_loaded) {
		error = scxfs_iread_extents(sc->tp, ip, whichfork);
		if (!xchk_fblock_process_error(sc, whichfork, 0, &error))
			goto out;
	}

	/* Check the btree structure. */
	cur = scxfs_bmbt_init_cursor(mp, sc->tp, ip, whichfork);
	scxfs_rmap_ino_bmbt_owner(&oinfo, ip->i_ino, whichfork);
	error = xchk_btree(sc, cur, xchk_bmapbt_rec, &oinfo, info);
	scxfs_btree_del_cursor(cur, error);
out:
	return error;
}

struct xchk_bmap_check_rmap_info {
	struct scxfs_scrub	*sc;
	int			whichfork;
	struct scxfs_iext_cursor	icur;
};

/* Can we find bmaps that fit this rmap? */
STATIC int
xchk_bmap_check_rmap(
	struct scxfs_btree_cur		*cur,
	struct scxfs_rmap_irec		*rec,
	void				*priv)
{
	struct scxfs_bmbt_irec		irec;
	struct xchk_bmap_check_rmap_info	*sbcri = priv;
	struct scxfs_ifork		*ifp;
	struct scxfs_scrub		*sc = sbcri->sc;
	bool				have_map;

	/* Is this even the right fork? */
	if (rec->rm_owner != sc->ip->i_ino)
		return 0;
	if ((sbcri->whichfork == SCXFS_ATTR_FORK) ^
	    !!(rec->rm_flags & SCXFS_RMAP_ATTR_FORK))
		return 0;
	if (rec->rm_flags & SCXFS_RMAP_BMBT_BLOCK)
		return 0;

	/* Now look up the bmbt record. */
	ifp = SCXFS_IFORK_PTR(sc->ip, sbcri->whichfork);
	if (!ifp) {
		xchk_fblock_set_corrupt(sc, sbcri->whichfork,
				rec->rm_offset);
		goto out;
	}
	have_map = scxfs_iext_lookup_extent(sc->ip, ifp, rec->rm_offset,
			&sbcri->icur, &irec);
	if (!have_map)
		xchk_fblock_set_corrupt(sc, sbcri->whichfork,
				rec->rm_offset);
	/*
	 * bmap extent record lengths are constrained to 2^21 blocks in length
	 * because of space constraints in the on-disk metadata structure.
	 * However, rmap extent record lengths are constrained only by AG
	 * length, so we have to loop through the bmbt to make sure that the
	 * entire rmap is covered by bmbt records.
	 */
	while (have_map) {
		if (irec.br_startoff != rec->rm_offset)
			xchk_fblock_set_corrupt(sc, sbcri->whichfork,
					rec->rm_offset);
		if (irec.br_startblock != SCXFS_AGB_TO_FSB(sc->mp,
				cur->bc_private.a.agno, rec->rm_startblock))
			xchk_fblock_set_corrupt(sc, sbcri->whichfork,
					rec->rm_offset);
		if (irec.br_blockcount > rec->rm_blockcount)
			xchk_fblock_set_corrupt(sc, sbcri->whichfork,
					rec->rm_offset);
		if (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT)
			break;
		rec->rm_startblock += irec.br_blockcount;
		rec->rm_offset += irec.br_blockcount;
		rec->rm_blockcount -= irec.br_blockcount;
		if (rec->rm_blockcount == 0)
			break;
		have_map = scxfs_iext_next_extent(ifp, &sbcri->icur, &irec);
		if (!have_map)
			xchk_fblock_set_corrupt(sc, sbcri->whichfork,
					rec->rm_offset);
	}

out:
	if (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT)
		return -ECANCELED;
	return 0;
}

/* Make sure each rmap has a corresponding bmbt entry. */
STATIC int
xchk_bmap_check_ag_rmaps(
	struct scxfs_scrub		*sc,
	int				whichfork,
	scxfs_agnumber_t			agno)
{
	struct xchk_bmap_check_rmap_info	sbcri;
	struct scxfs_btree_cur		*cur;
	struct scxfs_buf			*agf;
	int				error;

	error = scxfs_alloc_read_agf(sc->mp, sc->tp, agno, 0, &agf);
	if (error)
		return error;

	cur = scxfs_rmapbt_init_cursor(sc->mp, sc->tp, agf, agno);
	if (!cur) {
		error = -ENOMEM;
		goto out_agf;
	}

	sbcri.sc = sc;
	sbcri.whichfork = whichfork;
	error = scxfs_rmap_query_all(cur, xchk_bmap_check_rmap, &sbcri);
	if (error == -ECANCELED)
		error = 0;

	scxfs_btree_del_cursor(cur, error);
out_agf:
	scxfs_trans_brelse(sc->tp, agf);
	return error;
}

/* Make sure each rmap has a corresponding bmbt entry. */
STATIC int
xchk_bmap_check_rmaps(
	struct scxfs_scrub	*sc,
	int			whichfork)
{
	loff_t			size;
	scxfs_agnumber_t		agno;
	int			error;

	if (!scxfs_sb_version_hasrmapbt(&sc->mp->m_sb) ||
	    whichfork == SCXFS_COW_FORK ||
	    (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT))
		return 0;

	/* Don't support realtime rmap checks yet. */
	if (SCXFS_IS_REALTIME_INODE(sc->ip) && whichfork == SCXFS_DATA_FORK)
		return 0;

	/*
	 * Only do this for complex maps that are in btree format, or for
	 * situations where we would seem to have a size but zero extents.
	 * The inode repair code can zap broken iforks, which means we have
	 * to flag this bmap as corrupt if there are rmaps that need to be
	 * reattached.
	 */
	switch (whichfork) {
	case SCXFS_DATA_FORK:
		size = i_size_read(VFS_I(sc->ip));
		break;
	case SCXFS_ATTR_FORK:
		size = SCXFS_IFORK_Q(sc->ip);
		break;
	default:
		size = 0;
		break;
	}
	if (SCXFS_IFORK_FORMAT(sc->ip, whichfork) != SCXFS_DINODE_FMT_BTREE &&
	    (size == 0 || SCXFS_IFORK_NEXTENTS(sc->ip, whichfork) > 0))
		return 0;

	for (agno = 0; agno < sc->mp->m_sb.sb_agcount; agno++) {
		error = xchk_bmap_check_ag_rmaps(sc, whichfork, agno);
		if (error)
			return error;
		if (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT)
			break;
	}

	return 0;
}

/*
 * Scrub an inode fork's block mappings.
 *
 * First we scan every record in every btree block, if applicable.
 * Then we unconditionally scan the incore extent cache.
 */
STATIC int
xchk_bmap(
	struct scxfs_scrub	*sc,
	int			whichfork)
{
	struct scxfs_bmbt_irec	irec;
	struct xchk_bmap_info	info = { NULL };
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_inode	*ip = sc->ip;
	struct scxfs_ifork	*ifp;
	scxfs_fileoff_t		endoff;
	struct scxfs_iext_cursor	icur;
	int			error = 0;

	ifp = SCXFS_IFORK_PTR(ip, whichfork);

	info.is_rt = whichfork == SCXFS_DATA_FORK && SCXFS_IS_REALTIME_INODE(ip);
	info.whichfork = whichfork;
	info.is_shared = whichfork == SCXFS_DATA_FORK && scxfs_is_reflink_inode(ip);
	info.sc = sc;

	switch (whichfork) {
	case SCXFS_COW_FORK:
		/* Non-existent CoW forks are ignorable. */
		if (!ifp)
			goto out;
		/* No CoW forks on non-reflink inodes/filesystems. */
		if (!scxfs_is_reflink_inode(ip)) {
			xchk_ino_set_corrupt(sc, sc->ip->i_ino);
			goto out;
		}
		break;
	case SCXFS_ATTR_FORK:
		if (!ifp)
			goto out_check_rmap;
		if (!scxfs_sb_version_hasattr(&mp->m_sb) &&
		    !scxfs_sb_version_hasattr2(&mp->m_sb))
			xchk_ino_set_corrupt(sc, sc->ip->i_ino);
		break;
	default:
		ASSERT(whichfork == SCXFS_DATA_FORK);
		break;
	}

	/* Check the fork values */
	switch (SCXFS_IFORK_FORMAT(ip, whichfork)) {
	case SCXFS_DINODE_FMT_UUID:
	case SCXFS_DINODE_FMT_DEV:
	case SCXFS_DINODE_FMT_LOCAL:
		/* No mappings to check. */
		goto out;
	case SCXFS_DINODE_FMT_EXTENTS:
		if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
			xchk_fblock_set_corrupt(sc, whichfork, 0);
			goto out;
		}
		break;
	case SCXFS_DINODE_FMT_BTREE:
		if (whichfork == SCXFS_COW_FORK) {
			xchk_fblock_set_corrupt(sc, whichfork, 0);
			goto out;
		}

		error = xchk_bmap_btree(sc, whichfork, &info);
		if (error)
			goto out;
		break;
	default:
		xchk_fblock_set_corrupt(sc, whichfork, 0);
		goto out;
	}

	if (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT)
		goto out;

	/* Find the offset of the last extent in the mapping. */
	error = scxfs_bmap_last_offset(ip, &endoff, whichfork);
	if (!xchk_fblock_process_error(sc, whichfork, 0, &error))
		goto out;

	/* Scrub extent records. */
	info.lastoff = 0;
	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	for_each_scxfs_iext(ifp, &icur, &irec) {
		if (xchk_should_terminate(sc, &error) ||
		    (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT))
			goto out;
		if (isnullstartblock(irec.br_startblock))
			continue;
		if (irec.br_startoff >= endoff) {
			xchk_fblock_set_corrupt(sc, whichfork,
					irec.br_startoff);
			goto out;
		}
		error = xchk_bmap_iextent(ip, &info, &irec);
		if (error)
			goto out;
	}

out_check_rmap:
	error = xchk_bmap_check_rmaps(sc, whichfork);
	if (!xchk_fblock_xref_process_error(sc, whichfork, 0, &error))
		goto out;
out:
	return error;
}

/* Scrub an inode's data fork. */
int
xchk_bmap_data(
	struct scxfs_scrub	*sc)
{
	return xchk_bmap(sc, SCXFS_DATA_FORK);
}

/* Scrub an inode's attr fork. */
int
xchk_bmap_attr(
	struct scxfs_scrub	*sc)
{
	return xchk_bmap(sc, SCXFS_ATTR_FORK);
}

/* Scrub an inode's CoW fork. */
int
xchk_bmap_cow(
	struct scxfs_scrub	*sc)
{
	if (!scxfs_is_reflink_inode(sc->ip))
		return -ENOENT;

	return xchk_bmap(sc, SCXFS_COW_FORK);
}
