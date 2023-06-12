// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_defer.h"
#include "scxfs_dir2.h"
#include "scxfs_inode.h"
#include "scxfs_btree.h"
#include "scxfs_trans.h"
#include "scxfs_alloc.h"
#include "scxfs_bmap.h"
#include "scxfs_bmap_util.h"
#include "scxfs_bmap_btree.h"
#include "scxfs_rtalloc.h"
#include "scxfs_errortag.h"
#include "scxfs_error.h"
#include "scxfs_quota.h"
#include "scxfs_trans_space.h"
#include "scxfs_buf_item.h"
#include "scxfs_trace.h"
#include "scxfs_attr_leaf.h"
#include "scxfs_filestream.h"
#include "scxfs_rmap.h"
#include "scxfs_ag_resv.h"
#include "scxfs_refcount.h"
#include "scxfs_icache.h"


kmem_zone_t		*scxfs_bmap_free_item_zone;

/*
 * Miscellaneous helper functions
 */

/*
 * Compute and fill in the value of the maximum depth of a bmap btree
 * in this filesystem.  Done once, during mount.
 */
void
scxfs_bmap_compute_maxlevels(
	scxfs_mount_t	*mp,		/* file system mount structure */
	int		whichfork)	/* data or attr fork */
{
	int		level;		/* btree level */
	uint		maxblocks;	/* max blocks at this level */
	uint		maxleafents;	/* max leaf entries possible */
	int		maxrootrecs;	/* max records in root block */
	int		minleafrecs;	/* min records in leaf block */
	int		minnoderecs;	/* min records in node block */
	int		sz;		/* root block size */

	/*
	 * The maximum number of extents in a file, hence the maximum
	 * number of leaf entries, is controlled by the type of di_nextents
	 * (a signed 32-bit number, scxfs_extnum_t), or by di_anextents
	 * (a signed 16-bit number, scxfs_aextnum_t).
	 *
	 * Note that we can no longer assume that if we are in ATTR1 that
	 * the fork offset of all the inodes will be
	 * (scxfs_default_attroffset(ip) >> 3) because we could have mounted
	 * with ATTR2 and then mounted back with ATTR1, keeping the
	 * di_forkoff's fixed but probably at various positions. Therefore,
	 * for both ATTR1 and ATTR2 we have to assume the worst case scenario
	 * of a minimum size available.
	 */
	if (whichfork == SCXFS_DATA_FORK) {
		maxleafents = MAXEXTNUM;
		sz = SCXFS_BMDR_SPACE_CALC(MINDBTPTRS);
	} else {
		maxleafents = MAXAEXTNUM;
		sz = SCXFS_BMDR_SPACE_CALC(MINABTPTRS);
	}
	maxrootrecs = scxfs_bmdr_maxrecs(sz, 0);
	minleafrecs = mp->m_bmap_dmnr[0];
	minnoderecs = mp->m_bmap_dmnr[1];
	maxblocks = (maxleafents + minleafrecs - 1) / minleafrecs;
	for (level = 1; maxblocks > 1; level++) {
		if (maxblocks <= maxrootrecs)
			maxblocks = 1;
		else
			maxblocks = (maxblocks + minnoderecs - 1) / minnoderecs;
	}
	mp->m_bm_maxlevels[whichfork] = level;
}

STATIC int				/* error */
scxfs_bmbt_lookup_eq(
	struct scxfs_btree_cur	*cur,
	struct scxfs_bmbt_irec	*irec,
	int			*stat)	/* success/failure */
{
	cur->bc_rec.b = *irec;
	return scxfs_btree_lookup(cur, SCXFS_LOOKUP_EQ, stat);
}

STATIC int				/* error */
scxfs_bmbt_lookup_first(
	struct scxfs_btree_cur	*cur,
	int			*stat)	/* success/failure */
{
	cur->bc_rec.b.br_startoff = 0;
	cur->bc_rec.b.br_startblock = 0;
	cur->bc_rec.b.br_blockcount = 0;
	return scxfs_btree_lookup(cur, SCXFS_LOOKUP_GE, stat);
}

/*
 * Check if the inode needs to be converted to btree format.
 */
static inline bool scxfs_bmap_needs_btree(struct scxfs_inode *ip, int whichfork)
{
	return whichfork != SCXFS_COW_FORK &&
		SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_EXTENTS &&
		SCXFS_IFORK_NEXTENTS(ip, whichfork) >
			SCXFS_IFORK_MAXEXT(ip, whichfork);
}

/*
 * Check if the inode should be converted to extent format.
 */
static inline bool scxfs_bmap_wants_extents(struct scxfs_inode *ip, int whichfork)
{
	return whichfork != SCXFS_COW_FORK &&
		SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_BTREE &&
		SCXFS_IFORK_NEXTENTS(ip, whichfork) <=
			SCXFS_IFORK_MAXEXT(ip, whichfork);
}

/*
 * Update the record referred to by cur to the value given by irec
 * This either works (return 0) or gets an EFSCORRUPTED error.
 */
STATIC int
scxfs_bmbt_update(
	struct scxfs_btree_cur	*cur,
	struct scxfs_bmbt_irec	*irec)
{
	union scxfs_btree_rec	rec;

	scxfs_bmbt_disk_set_all(&rec.bmbt, irec);
	return scxfs_btree_update(cur, &rec);
}

/*
 * Compute the worst-case number of indirect blocks that will be used
 * for ip's delayed extent of length "len".
 */
STATIC scxfs_filblks_t
scxfs_bmap_worst_indlen(
	scxfs_inode_t	*ip,		/* incore inode pointer */
	scxfs_filblks_t	len)		/* delayed extent length */
{
	int		level;		/* btree level number */
	int		maxrecs;	/* maximum record count at this level */
	scxfs_mount_t	*mp;		/* mount structure */
	scxfs_filblks_t	rval;		/* return value */

	mp = ip->i_mount;
	maxrecs = mp->m_bmap_dmxr[0];
	for (level = 0, rval = 0;
	     level < SCXFS_BM_MAXLEVELS(mp, SCXFS_DATA_FORK);
	     level++) {
		len += maxrecs - 1;
		do_div(len, maxrecs);
		rval += len;
		if (len == 1)
			return rval + SCXFS_BM_MAXLEVELS(mp, SCXFS_DATA_FORK) -
				level - 1;
		if (level == 0)
			maxrecs = mp->m_bmap_dmxr[1];
	}
	return rval;
}

/*
 * Calculate the default attribute fork offset for newly created inodes.
 */
uint
scxfs_default_attroffset(
	struct scxfs_inode	*ip)
{
	struct scxfs_mount	*mp = ip->i_mount;
	uint			offset;

	if (mp->m_sb.sb_inodesize == 256) {
		offset = SCXFS_LITINO(mp, ip->i_d.di_version) -
				SCXFS_BMDR_SPACE_CALC(MINABTPTRS);
	} else {
		offset = SCXFS_BMDR_SPACE_CALC(6 * MINABTPTRS);
	}

	ASSERT(offset < SCXFS_LITINO(mp, ip->i_d.di_version));
	return offset;
}

/*
 * Helper routine to reset inode di_forkoff field when switching
 * attribute fork from local to extent format - we reset it where
 * possible to make space available for inline data fork extents.
 */
STATIC void
scxfs_bmap_forkoff_reset(
	scxfs_inode_t	*ip,
	int		whichfork)
{
	if (whichfork == SCXFS_ATTR_FORK &&
	    ip->i_d.di_format != SCXFS_DINODE_FMT_DEV &&
	    ip->i_d.di_format != SCXFS_DINODE_FMT_BTREE) {
		uint	dfl_forkoff = scxfs_default_attroffset(ip) >> 3;

		if (dfl_forkoff > ip->i_d.di_forkoff)
			ip->i_d.di_forkoff = dfl_forkoff;
	}
}

#ifdef DEBUG
STATIC struct scxfs_buf *
scxfs_bmap_get_bp(
	struct scxfs_btree_cur	*cur,
	scxfs_fsblock_t		bno)
{
	struct scxfs_log_item	*lip;
	int			i;

	if (!cur)
		return NULL;

	for (i = 0; i < SCXFS_BTREE_MAXLEVELS; i++) {
		if (!cur->bc_bufs[i])
			break;
		if (SCXFS_BUF_ADDR(cur->bc_bufs[i]) == bno)
			return cur->bc_bufs[i];
	}

	/* Chase down all the log items to see if the bp is there */
	list_for_each_entry(lip, &cur->bc_tp->t_items, li_trans) {
		struct scxfs_buf_log_item	*bip = (struct scxfs_buf_log_item *)lip;

		if (bip->bli_item.li_type == SCXFS_LI_BUF &&
		    SCXFS_BUF_ADDR(bip->bli_buf) == bno)
			return bip->bli_buf;
	}

	return NULL;
}

STATIC void
scxfs_check_block(
	struct scxfs_btree_block	*block,
	scxfs_mount_t		*mp,
	int			root,
	short			sz)
{
	int			i, j, dmxr;
	__be64			*pp, *thispa;	/* pointer to block address */
	scxfs_bmbt_key_t		*prevp, *keyp;

	ASSERT(be16_to_cpu(block->bb_level) > 0);

	prevp = NULL;
	for( i = 1; i <= scxfs_btree_get_numrecs(block); i++) {
		dmxr = mp->m_bmap_dmxr[0];
		keyp = SCXFS_BMBT_KEY_ADDR(mp, block, i);

		if (prevp) {
			ASSERT(be64_to_cpu(prevp->br_startoff) <
			       be64_to_cpu(keyp->br_startoff));
		}
		prevp = keyp;

		/*
		 * Compare the block numbers to see if there are dups.
		 */
		if (root)
			pp = SCXFS_BMAP_BROOT_PTR_ADDR(mp, block, i, sz);
		else
			pp = SCXFS_BMBT_PTR_ADDR(mp, block, i, dmxr);

		for (j = i+1; j <= be16_to_cpu(block->bb_numrecs); j++) {
			if (root)
				thispa = SCXFS_BMAP_BROOT_PTR_ADDR(mp, block, j, sz);
			else
				thispa = SCXFS_BMBT_PTR_ADDR(mp, block, j, dmxr);
			if (*thispa == *pp) {
				scxfs_warn(mp, "%s: thispa(%d) == pp(%d) %Ld",
					__func__, j, i,
					(unsigned long long)be64_to_cpu(*thispa));
				scxfs_err(mp, "%s: ptrs are equal in node\n",
					__func__);
				scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
			}
		}
	}
}

/*
 * Check that the extents for the inode ip are in the right order in all
 * btree leaves. THis becomes prohibitively expensive for large extent count
 * files, so don't bother with inodes that have more than 10,000 extents in
 * them. The btree record ordering checks will still be done, so for such large
 * bmapbt constructs that is going to catch most corruptions.
 */
STATIC void
scxfs_bmap_check_leaf_extents(
	scxfs_btree_cur_t		*cur,	/* btree cursor or null */
	scxfs_inode_t		*ip,		/* incore inode pointer */
	int			whichfork)	/* data or attr fork */
{
	struct scxfs_btree_block	*block;	/* current btree block */
	scxfs_fsblock_t		bno;	/* block # of "block" */
	scxfs_buf_t		*bp;	/* buffer for "block" */
	int			error;	/* error return value */
	scxfs_extnum_t		i=0, j;	/* index into the extents list */
	struct scxfs_ifork	*ifp;	/* fork structure */
	int			level;	/* btree level, for checking */
	scxfs_mount_t		*mp;	/* file system mount structure */
	__be64			*pp;	/* pointer to block address */
	scxfs_bmbt_rec_t		*ep;	/* pointer to current extent */
	scxfs_bmbt_rec_t		last = {0, 0}; /* last extent in prev block */
	scxfs_bmbt_rec_t		*nextp;	/* pointer to next extent */
	int			bp_release = 0;

	if (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE) {
		return;
	}

	/* skip large extent count inodes */
	if (ip->i_d.di_nextents > 10000)
		return;

	bno = NULLFSBLOCK;
	mp = ip->i_mount;
	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	block = ifp->if_broot;
	/*
	 * Root level must use BMAP_BROOT_PTR_ADDR macro to get ptr out.
	 */
	level = be16_to_cpu(block->bb_level);
	ASSERT(level > 0);
	scxfs_check_block(block, mp, 1, ifp->if_broot_bytes);
	pp = SCXFS_BMAP_BROOT_PTR_ADDR(mp, block, 1, ifp->if_broot_bytes);
	bno = be64_to_cpu(*pp);

	ASSERT(bno != NULLFSBLOCK);
	ASSERT(SCXFS_FSB_TO_AGNO(mp, bno) < mp->m_sb.sb_agcount);
	ASSERT(SCXFS_FSB_TO_AGBNO(mp, bno) < mp->m_sb.sb_agblocks);

	/*
	 * Go down the tree until leaf level is reached, following the first
	 * pointer (leftmost) at each level.
	 */
	while (level-- > 0) {
		/* See if buf is in cur first */
		bp_release = 0;
		bp = scxfs_bmap_get_bp(cur, SCXFS_FSB_TO_DADDR(mp, bno));
		if (!bp) {
			bp_release = 1;
			error = scxfs_btree_read_bufl(mp, NULL, bno, &bp,
						SCXFS_BMAP_BTREE_REF,
						&scxfs_bmbt_buf_ops);
			if (error)
				goto error_norelse;
		}
		block = SCXFS_BUF_TO_BLOCK(bp);
		if (level == 0)
			break;

		/*
		 * Check this block for basic sanity (increasing keys and
		 * no duplicate blocks).
		 */

		scxfs_check_block(block, mp, 0, 0);
		pp = SCXFS_BMBT_PTR_ADDR(mp, block, 1, mp->m_bmap_dmxr[1]);
		bno = be64_to_cpu(*pp);
		SCXFS_WANT_CORRUPTED_GOTO(mp,
					scxfs_verify_fsbno(mp, bno), error0);
		if (bp_release) {
			bp_release = 0;
			scxfs_trans_brelse(NULL, bp);
		}
	}

	/*
	 * Here with bp and block set to the leftmost leaf node in the tree.
	 */
	i = 0;

	/*
	 * Loop over all leaf nodes checking that all extents are in the right order.
	 */
	for (;;) {
		scxfs_fsblock_t	nextbno;
		scxfs_extnum_t	num_recs;


		num_recs = scxfs_btree_get_numrecs(block);

		/*
		 * Read-ahead the next leaf block, if any.
		 */

		nextbno = be64_to_cpu(block->bb_u.l.bb_rightsib);

		/*
		 * Check all the extents to make sure they are OK.
		 * If we had a previous block, the last entry should
		 * conform with the first entry in this one.
		 */

		ep = SCXFS_BMBT_REC_ADDR(mp, block, 1);
		if (i) {
			ASSERT(scxfs_bmbt_disk_get_startoff(&last) +
			       scxfs_bmbt_disk_get_blockcount(&last) <=
			       scxfs_bmbt_disk_get_startoff(ep));
		}
		for (j = 1; j < num_recs; j++) {
			nextp = SCXFS_BMBT_REC_ADDR(mp, block, j + 1);
			ASSERT(scxfs_bmbt_disk_get_startoff(ep) +
			       scxfs_bmbt_disk_get_blockcount(ep) <=
			       scxfs_bmbt_disk_get_startoff(nextp));
			ep = nextp;
		}

		last = *ep;
		i += num_recs;
		if (bp_release) {
			bp_release = 0;
			scxfs_trans_brelse(NULL, bp);
		}
		bno = nextbno;
		/*
		 * If we've reached the end, stop.
		 */
		if (bno == NULLFSBLOCK)
			break;

		bp_release = 0;
		bp = scxfs_bmap_get_bp(cur, SCXFS_FSB_TO_DADDR(mp, bno));
		if (!bp) {
			bp_release = 1;
			error = scxfs_btree_read_bufl(mp, NULL, bno, &bp,
						SCXFS_BMAP_BTREE_REF,
						&scxfs_bmbt_buf_ops);
			if (error)
				goto error_norelse;
		}
		block = SCXFS_BUF_TO_BLOCK(bp);
	}

	return;

error0:
	scxfs_warn(mp, "%s: at error0", __func__);
	if (bp_release)
		scxfs_trans_brelse(NULL, bp);
error_norelse:
	scxfs_warn(mp, "%s: BAD after btree leaves for %d extents",
		__func__, i);
	scxfs_err(mp, "%s: CORRUPTED BTREE OR SOMETHING", __func__);
	scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
	return;
}

/*
 * Validate that the bmbt_irecs being returned from bmapi are valid
 * given the caller's original parameters.  Specifically check the
 * ranges of the returned irecs to ensure that they only extend beyond
 * the given parameters if the SCXFS_BMAPI_ENTIRE flag was set.
 */
STATIC void
scxfs_bmap_validate_ret(
	scxfs_fileoff_t		bno,
	scxfs_filblks_t		len,
	int			flags,
	scxfs_bmbt_irec_t		*mval,
	int			nmap,
	int			ret_nmap)
{
	int			i;		/* index to map values */

	ASSERT(ret_nmap <= nmap);

	for (i = 0; i < ret_nmap; i++) {
		ASSERT(mval[i].br_blockcount > 0);
		if (!(flags & SCXFS_BMAPI_ENTIRE)) {
			ASSERT(mval[i].br_startoff >= bno);
			ASSERT(mval[i].br_blockcount <= len);
			ASSERT(mval[i].br_startoff + mval[i].br_blockcount <=
			       bno + len);
		} else {
			ASSERT(mval[i].br_startoff < bno + len);
			ASSERT(mval[i].br_startoff + mval[i].br_blockcount >
			       bno);
		}
		ASSERT(i == 0 ||
		       mval[i - 1].br_startoff + mval[i - 1].br_blockcount ==
		       mval[i].br_startoff);
		ASSERT(mval[i].br_startblock != DELAYSTARTBLOCK &&
		       mval[i].br_startblock != HOLESTARTBLOCK);
		ASSERT(mval[i].br_state == SCXFS_EXT_NORM ||
		       mval[i].br_state == SCXFS_EXT_UNWRITTEN);
	}
}

#else
#define scxfs_bmap_check_leaf_extents(cur, ip, whichfork)		do { } while (0)
#define	scxfs_bmap_validate_ret(bno,len,flags,mval,onmap,nmap)	do { } while (0)
#endif /* DEBUG */

/*
 * bmap free list manipulation functions
 */

/*
 * Add the extent to the list of extents to be free at transaction end.
 * The list is maintained sorted (by block number).
 */
void
__scxfs_bmap_add_free(
	struct scxfs_trans		*tp,
	scxfs_fsblock_t			bno,
	scxfs_filblks_t			len,
	const struct scxfs_owner_info	*oinfo,
	bool				skip_discard)
{
	struct scxfs_extent_free_item	*new;		/* new element */
#ifdef DEBUG
	struct scxfs_mount		*mp = tp->t_mountp;
	scxfs_agnumber_t			agno;
	scxfs_agblock_t			agbno;

	ASSERT(bno != NULLFSBLOCK);
	ASSERT(len > 0);
	ASSERT(len <= MAXEXTLEN);
	ASSERT(!isnullstartblock(bno));
	agno = SCXFS_FSB_TO_AGNO(mp, bno);
	agbno = SCXFS_FSB_TO_AGBNO(mp, bno);
	ASSERT(agno < mp->m_sb.sb_agcount);
	ASSERT(agbno < mp->m_sb.sb_agblocks);
	ASSERT(len < mp->m_sb.sb_agblocks);
	ASSERT(agbno + len <= mp->m_sb.sb_agblocks);
#endif
	ASSERT(scxfs_bmap_free_item_zone != NULL);

	new = kmem_zone_alloc(scxfs_bmap_free_item_zone, 0);
	new->xefi_startblock = bno;
	new->xefi_blockcount = (scxfs_extlen_t)len;
	if (oinfo)
		new->xefi_oinfo = *oinfo;
	else
		new->xefi_oinfo = SCXFS_RMAP_OINFO_SKIP_UPDATE;
	new->xefi_skip_discard = skip_discard;
	trace_scxfs_bmap_free_defer(tp->t_mountp,
			SCXFS_FSB_TO_AGNO(tp->t_mountp, bno), 0,
			SCXFS_FSB_TO_AGBNO(tp->t_mountp, bno), len);
	scxfs_defer_add(tp, SCXFS_DEFER_OPS_TYPE_FREE, &new->xefi_list);
}

/*
 * Inode fork format manipulation functions
 */

/*
 * Convert the inode format to extent format if it currently is in btree format,
 * but the extent list is small enough that it fits into the extent format.
 *
 * Since the extents are already in-core, all we have to do is give up the space
 * for the btree root and pitch the leaf block.
 */
STATIC int				/* error */
scxfs_bmap_btree_to_extents(
	struct scxfs_trans	*tp,	/* transaction pointer */
	struct scxfs_inode	*ip,	/* incore inode pointer */
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	int			*logflagsp, /* inode logging flags */
	int			whichfork)  /* data or attr fork */
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_btree_block	*rblock = ifp->if_broot;
	struct scxfs_btree_block	*cblock;/* child btree block */
	scxfs_fsblock_t		cbno;	/* child block number */
	scxfs_buf_t		*cbp;	/* child block's buffer */
	int			error;	/* error return value */
	__be64			*pp;	/* ptr to block address */
	struct scxfs_owner_info	oinfo;

	/* check if we actually need the extent format first: */
	if (!scxfs_bmap_wants_extents(ip, whichfork))
		return 0;

	ASSERT(cur);
	ASSERT(whichfork != SCXFS_COW_FORK);
	ASSERT(ifp->if_flags & SCXFS_IFEXTENTS);
	ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_BTREE);
	ASSERT(be16_to_cpu(rblock->bb_level) == 1);
	ASSERT(be16_to_cpu(rblock->bb_numrecs) == 1);
	ASSERT(scxfs_bmbt_maxrecs(mp, ifp->if_broot_bytes, 0) == 1);

	pp = SCXFS_BMAP_BROOT_PTR_ADDR(mp, rblock, 1, ifp->if_broot_bytes);
	cbno = be64_to_cpu(*pp);
#ifdef DEBUG
	SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp,
			scxfs_btree_check_lptr(cur, cbno, 1));
#endif
	error = scxfs_btree_read_bufl(mp, tp, cbno, &cbp, SCXFS_BMAP_BTREE_REF,
				&scxfs_bmbt_buf_ops);
	if (error)
		return error;
	cblock = SCXFS_BUF_TO_BLOCK(cbp);
	if ((error = scxfs_btree_check_block(cur, cblock, 0, cbp)))
		return error;
	scxfs_rmap_ino_bmbt_owner(&oinfo, ip->i_ino, whichfork);
	scxfs_bmap_add_free(cur->bc_tp, cbno, 1, &oinfo);
	ip->i_d.di_nblocks--;
	scxfs_trans_mod_dquot_byino(tp, ip, SCXFS_TRANS_DQ_BCOUNT, -1L);
	scxfs_trans_binval(tp, cbp);
	if (cur->bc_bufs[0] == cbp)
		cur->bc_bufs[0] = NULL;
	scxfs_iroot_realloc(ip, -1, whichfork);
	ASSERT(ifp->if_broot == NULL);
	ASSERT((ifp->if_flags & SCXFS_IFBROOT) == 0);
	SCXFS_IFORK_FMT_SET(ip, whichfork, SCXFS_DINODE_FMT_EXTENTS);
	*logflagsp |= SCXFS_ILOG_CORE | scxfs_ilog_fext(whichfork);
	return 0;
}

/*
 * Convert an extents-format file into a btree-format file.
 * The new file will have a root block (in the inode) and a single child block.
 */
STATIC int					/* error */
scxfs_bmap_extents_to_btree(
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* incore inode pointer */
	struct scxfs_btree_cur	**curp,		/* cursor returned to caller */
	int			wasdel,		/* converting a delayed alloc */
	int			*logflagsp,	/* inode logging flags */
	int			whichfork)	/* data or attr fork */
{
	struct scxfs_btree_block	*ablock;	/* allocated (child) bt block */
	struct scxfs_buf		*abp;		/* buffer for ablock */
	struct scxfs_alloc_arg	args;		/* allocation arguments */
	struct scxfs_bmbt_rec	*arp;		/* child record pointer */
	struct scxfs_btree_block	*block;		/* btree root block */
	struct scxfs_btree_cur	*cur;		/* bmap btree cursor */
	int			error;		/* error return value */
	struct scxfs_ifork	*ifp;		/* inode fork pointer */
	struct scxfs_bmbt_key	*kp;		/* root block key pointer */
	struct scxfs_mount	*mp;		/* mount structure */
	scxfs_bmbt_ptr_t		*pp;		/* root block address pointer */
	struct scxfs_iext_cursor	icur;
	struct scxfs_bmbt_irec	rec;
	scxfs_extnum_t		cnt = 0;

	mp = ip->i_mount;
	ASSERT(whichfork != SCXFS_COW_FORK);
	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_EXTENTS);

	/*
	 * Make space in the inode incore. This needs to be undone if we fail
	 * to expand the root.
	 */
	scxfs_iroot_realloc(ip, 1, whichfork);
	ifp->if_flags |= SCXFS_IFBROOT;

	/*
	 * Fill in the root.
	 */
	block = ifp->if_broot;
	scxfs_btree_init_block_int(mp, block, SCXFS_BUF_DADDR_NULL,
				 SCXFS_BTNUM_BMAP, 1, 1, ip->i_ino,
				 SCXFS_BTREE_LONG_PTRS);
	/*
	 * Need a cursor.  Can't allocate until bb_level is filled in.
	 */
	cur = scxfs_bmbt_init_cursor(mp, tp, ip, whichfork);
	cur->bc_private.b.flags = wasdel ? SCXFS_BTCUR_BPRV_WASDEL : 0;
	/*
	 * Convert to a btree with two levels, one record in root.
	 */
	SCXFS_IFORK_FMT_SET(ip, whichfork, SCXFS_DINODE_FMT_BTREE);
	memset(&args, 0, sizeof(args));
	args.tp = tp;
	args.mp = mp;
	scxfs_rmap_ino_bmbt_owner(&args.oinfo, ip->i_ino, whichfork);
	if (tp->t_firstblock == NULLFSBLOCK) {
		args.type = SCXFS_ALLOCTYPE_START_BNO;
		args.fsbno = SCXFS_INO_TO_FSB(mp, ip->i_ino);
	} else if (tp->t_flags & SCXFS_TRANS_LOWMODE) {
		args.type = SCXFS_ALLOCTYPE_START_BNO;
		args.fsbno = tp->t_firstblock;
	} else {
		args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
		args.fsbno = tp->t_firstblock;
	}
	args.minlen = args.maxlen = args.prod = 1;
	args.wasdel = wasdel;
	*logflagsp = 0;
	error = scxfs_alloc_vextent(&args);
	if (error)
		goto out_root_realloc;

	if (WARN_ON_ONCE(args.fsbno == NULLFSBLOCK)) {
		error = -ENOSPC;
		goto out_root_realloc;
	}

	/*
	 * Allocation can't fail, the space was reserved.
	 */
	ASSERT(tp->t_firstblock == NULLFSBLOCK ||
	       args.agno >= SCXFS_FSB_TO_AGNO(mp, tp->t_firstblock));
	tp->t_firstblock = args.fsbno;
	cur->bc_private.b.allocated++;
	ip->i_d.di_nblocks++;
	scxfs_trans_mod_dquot_byino(tp, ip, SCXFS_TRANS_DQ_BCOUNT, 1L);
	abp = scxfs_btree_get_bufl(mp, tp, args.fsbno);
	if (!abp) {
		error = -EFSCORRUPTED;
		goto out_unreserve_dquot;
	}

	/*
	 * Fill in the child block.
	 */
	abp->b_ops = &scxfs_bmbt_buf_ops;
	ablock = SCXFS_BUF_TO_BLOCK(abp);
	scxfs_btree_init_block_int(mp, ablock, abp->b_bn,
				SCXFS_BTNUM_BMAP, 0, 0, ip->i_ino,
				SCXFS_BTREE_LONG_PTRS);

	for_each_scxfs_iext(ifp, &icur, &rec) {
		if (isnullstartblock(rec.br_startblock))
			continue;
		arp = SCXFS_BMBT_REC_ADDR(mp, ablock, 1 + cnt);
		scxfs_bmbt_disk_set_all(arp, &rec);
		cnt++;
	}
	ASSERT(cnt == SCXFS_IFORK_NEXTENTS(ip, whichfork));
	scxfs_btree_set_numrecs(ablock, cnt);

	/*
	 * Fill in the root key and pointer.
	 */
	kp = SCXFS_BMBT_KEY_ADDR(mp, block, 1);
	arp = SCXFS_BMBT_REC_ADDR(mp, ablock, 1);
	kp->br_startoff = cpu_to_be64(scxfs_bmbt_disk_get_startoff(arp));
	pp = SCXFS_BMBT_PTR_ADDR(mp, block, 1, scxfs_bmbt_get_maxrecs(cur,
						be16_to_cpu(block->bb_level)));
	*pp = cpu_to_be64(args.fsbno);

	/*
	 * Do all this logging at the end so that
	 * the root is at the right level.
	 */
	scxfs_btree_log_block(cur, abp, SCXFS_BB_ALL_BITS);
	scxfs_btree_log_recs(cur, abp, 1, be16_to_cpu(ablock->bb_numrecs));
	ASSERT(*curp == NULL);
	*curp = cur;
	*logflagsp = SCXFS_ILOG_CORE | scxfs_ilog_fbroot(whichfork);
	return 0;

out_unreserve_dquot:
	scxfs_trans_mod_dquot_byino(tp, ip, SCXFS_TRANS_DQ_BCOUNT, -1L);
out_root_realloc:
	scxfs_iroot_realloc(ip, -1, whichfork);
	SCXFS_IFORK_FMT_SET(ip, whichfork, SCXFS_DINODE_FMT_EXTENTS);
	ASSERT(ifp->if_broot == NULL);
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);

	return error;
}

/*
 * Convert a local file to an extents file.
 * This code is out of bounds for data forks of regular files,
 * since the file data needs to get logged so things will stay consistent.
 * (The bmap-level manipulations are ok, though).
 */
void
scxfs_bmap_local_to_extents_empty(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork)
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);

	ASSERT(whichfork != SCXFS_COW_FORK);
	ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_LOCAL);
	ASSERT(ifp->if_bytes == 0);
	ASSERT(SCXFS_IFORK_NEXTENTS(ip, whichfork) == 0);

	scxfs_bmap_forkoff_reset(ip, whichfork);
	ifp->if_flags &= ~SCXFS_IFINLINE;
	ifp->if_flags |= SCXFS_IFEXTENTS;
	ifp->if_u1.if_root = NULL;
	ifp->if_height = 0;
	SCXFS_IFORK_FMT_SET(ip, whichfork, SCXFS_DINODE_FMT_EXTENTS);
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
}


STATIC int				/* error */
scxfs_bmap_local_to_extents(
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_inode_t	*ip,		/* incore inode pointer */
	scxfs_extlen_t	total,		/* total blocks needed by transaction */
	int		*logflagsp,	/* inode logging flags */
	int		whichfork,
	void		(*init_fn)(struct scxfs_trans *tp,
				   struct scxfs_buf *bp,
				   struct scxfs_inode *ip,
				   struct scxfs_ifork *ifp))
{
	int		error = 0;
	int		flags;		/* logging flags returned */
	struct scxfs_ifork *ifp;		/* inode fork pointer */
	scxfs_alloc_arg_t	args;		/* allocation arguments */
	scxfs_buf_t	*bp;		/* buffer for extent block */
	struct scxfs_bmbt_irec rec;
	struct scxfs_iext_cursor icur;

	/*
	 * We don't want to deal with the case of keeping inode data inline yet.
	 * So sending the data fork of a regular inode is invalid.
	 */
	ASSERT(!(S_ISREG(VFS_I(ip)->i_mode) && whichfork == SCXFS_DATA_FORK));
	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_LOCAL);

	if (!ifp->if_bytes) {
		scxfs_bmap_local_to_extents_empty(tp, ip, whichfork);
		flags = SCXFS_ILOG_CORE;
		goto done;
	}

	flags = 0;
	error = 0;
	ASSERT((ifp->if_flags & (SCXFS_IFINLINE|SCXFS_IFEXTENTS)) == SCXFS_IFINLINE);
	memset(&args, 0, sizeof(args));
	args.tp = tp;
	args.mp = ip->i_mount;
	scxfs_rmap_ino_owner(&args.oinfo, ip->i_ino, whichfork, 0);
	/*
	 * Allocate a block.  We know we need only one, since the
	 * file currently fits in an inode.
	 */
	if (tp->t_firstblock == NULLFSBLOCK) {
		args.fsbno = SCXFS_INO_TO_FSB(args.mp, ip->i_ino);
		args.type = SCXFS_ALLOCTYPE_START_BNO;
	} else {
		args.fsbno = tp->t_firstblock;
		args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
	}
	args.total = total;
	args.minlen = args.maxlen = args.prod = 1;
	error = scxfs_alloc_vextent(&args);
	if (error)
		goto done;

	/* Can't fail, the space was reserved. */
	ASSERT(args.fsbno != NULLFSBLOCK);
	ASSERT(args.len == 1);
	tp->t_firstblock = args.fsbno;
	bp = scxfs_btree_get_bufl(args.mp, tp, args.fsbno);

	/*
	 * Initialize the block, copy the data and log the remote buffer.
	 *
	 * The callout is responsible for logging because the remote format
	 * might differ from the local format and thus we don't know how much to
	 * log here. Note that init_fn must also set the buffer log item type
	 * correctly.
	 */
	init_fn(tp, bp, ip, ifp);

	/* account for the change in fork size */
	scxfs_idata_realloc(ip, -ifp->if_bytes, whichfork);
	scxfs_bmap_local_to_extents_empty(tp, ip, whichfork);
	flags |= SCXFS_ILOG_CORE;

	ifp->if_u1.if_root = NULL;
	ifp->if_height = 0;

	rec.br_startoff = 0;
	rec.br_startblock = args.fsbno;
	rec.br_blockcount = 1;
	rec.br_state = SCXFS_EXT_NORM;
	scxfs_iext_first(ifp, &icur);
	scxfs_iext_insert(ip, &icur, &rec, 0);

	SCXFS_IFORK_NEXT_SET(ip, whichfork, 1);
	ip->i_d.di_nblocks = 1;
	scxfs_trans_mod_dquot_byino(tp, ip,
		SCXFS_TRANS_DQ_BCOUNT, 1L);
	flags |= scxfs_ilog_fext(whichfork);

done:
	*logflagsp = flags;
	return error;
}

/*
 * Called from scxfs_bmap_add_attrfork to handle btree format files.
 */
STATIC int					/* error */
scxfs_bmap_add_attrfork_btree(
	scxfs_trans_t		*tp,		/* transaction pointer */
	scxfs_inode_t		*ip,		/* incore inode pointer */
	int			*flags)		/* inode logging flags */
{
	scxfs_btree_cur_t		*cur;		/* btree cursor */
	int			error;		/* error return value */
	scxfs_mount_t		*mp;		/* file system mount struct */
	int			stat;		/* newroot status */

	mp = ip->i_mount;
	if (ip->i_df.if_broot_bytes <= SCXFS_IFORK_DSIZE(ip))
		*flags |= SCXFS_ILOG_DBROOT;
	else {
		cur = scxfs_bmbt_init_cursor(mp, tp, ip, SCXFS_DATA_FORK);
		error = scxfs_bmbt_lookup_first(cur, &stat);
		if (error)
			goto error0;
		/* must be at least one entry */
		SCXFS_WANT_CORRUPTED_GOTO(mp, stat == 1, error0);
		if ((error = scxfs_btree_new_iroot(cur, flags, &stat)))
			goto error0;
		if (stat == 0) {
			scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
			return -ENOSPC;
		}
		cur->bc_private.b.allocated = 0;
		scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
	}
	return 0;
error0:
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
	return error;
}

/*
 * Called from scxfs_bmap_add_attrfork to handle extents format files.
 */
STATIC int					/* error */
scxfs_bmap_add_attrfork_extents(
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* incore inode pointer */
	int			*flags)		/* inode logging flags */
{
	scxfs_btree_cur_t		*cur;		/* bmap btree cursor */
	int			error;		/* error return value */

	if (ip->i_d.di_nextents * sizeof(scxfs_bmbt_rec_t) <= SCXFS_IFORK_DSIZE(ip))
		return 0;
	cur = NULL;
	error = scxfs_bmap_extents_to_btree(tp, ip, &cur, 0, flags,
					  SCXFS_DATA_FORK);
	if (cur) {
		cur->bc_private.b.allocated = 0;
		scxfs_btree_del_cursor(cur, error);
	}
	return error;
}

/*
 * Called from scxfs_bmap_add_attrfork to handle local format files. Each
 * different data fork content type needs a different callout to do the
 * conversion. Some are basic and only require special block initialisation
 * callouts for the data formating, others (directories) are so specialised they
 * handle everything themselves.
 *
 * XXX (dgc): investigate whether directory conversion can use the generic
 * formatting callout. It should be possible - it's just a very complex
 * formatter.
 */
STATIC int					/* error */
scxfs_bmap_add_attrfork_local(
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* incore inode pointer */
	int			*flags)		/* inode logging flags */
{
	struct scxfs_da_args	dargs;		/* args for dir/attr code */

	if (ip->i_df.if_bytes <= SCXFS_IFORK_DSIZE(ip))
		return 0;

	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		memset(&dargs, 0, sizeof(dargs));
		dargs.geo = ip->i_mount->m_dir_geo;
		dargs.dp = ip;
		dargs.total = dargs.geo->fsbcount;
		dargs.whichfork = SCXFS_DATA_FORK;
		dargs.trans = tp;
		return scxfs_dir2_sf_to_block(&dargs);
	}

	if (S_ISLNK(VFS_I(ip)->i_mode))
		return scxfs_bmap_local_to_extents(tp, ip, 1, flags,
						 SCXFS_DATA_FORK,
						 scxfs_symlink_local_to_remote);

	/* should only be called for types that support local format data */
	ASSERT(0);
	return -EFSCORRUPTED;
}

/* Set an inode attr fork off based on the format */
int
scxfs_bmap_set_attrforkoff(
	struct scxfs_inode	*ip,
	int			size,
	int			*version)
{
	switch (ip->i_d.di_format) {
	case SCXFS_DINODE_FMT_DEV:
		ip->i_d.di_forkoff = roundup(sizeof(scxfs_dev_t), 8) >> 3;
		break;
	case SCXFS_DINODE_FMT_LOCAL:
	case SCXFS_DINODE_FMT_EXTENTS:
	case SCXFS_DINODE_FMT_BTREE:
		ip->i_d.di_forkoff = scxfs_attr_shortform_bytesfit(ip, size);
		if (!ip->i_d.di_forkoff)
			ip->i_d.di_forkoff = scxfs_default_attroffset(ip) >> 3;
		else if ((ip->i_mount->m_flags & SCXFS_MOUNT_ATTR2) && version)
			*version = 2;
		break;
	default:
		ASSERT(0);
		return -EINVAL;
	}

	return 0;
}

/*
 * Convert inode from non-attributed to attributed.
 * Must not be in a transaction, ip must not be locked.
 */
int						/* error code */
scxfs_bmap_add_attrfork(
	scxfs_inode_t		*ip,		/* incore inode pointer */
	int			size,		/* space new attribute needs */
	int			rsvd)		/* xact may use reserved blks */
{
	scxfs_mount_t		*mp;		/* mount structure */
	scxfs_trans_t		*tp;		/* transaction pointer */
	int			blks;		/* space reservation */
	int			version = 1;	/* superblock attr version */
	int			logflags;	/* logging flags */
	int			error;		/* error return value */

	ASSERT(SCXFS_IFORK_Q(ip) == 0);

	mp = ip->i_mount;
	ASSERT(!SCXFS_NOT_DQATTACHED(mp, ip));

	blks = SCXFS_ADDAFORK_SPACE_RES(mp);

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_addafork, blks, 0,
			rsvd ? SCXFS_TRANS_RESERVE : 0, &tp);
	if (error)
		return error;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	error = scxfs_trans_reserve_quota_nblks(tp, ip, blks, 0, rsvd ?
			SCXFS_QMOPT_RES_REGBLKS | SCXFS_QMOPT_FORCE_RES :
			SCXFS_QMOPT_RES_REGBLKS);
	if (error)
		goto trans_cancel;
	if (SCXFS_IFORK_Q(ip))
		goto trans_cancel;
	if (ip->i_d.di_anextents != 0) {
		error = -EFSCORRUPTED;
		goto trans_cancel;
	}
	if (ip->i_d.di_aformat != SCXFS_DINODE_FMT_EXTENTS) {
		/*
		 * For inodes coming from pre-6.2 filesystems.
		 */
		ASSERT(ip->i_d.di_aformat == 0);
		ip->i_d.di_aformat = SCXFS_DINODE_FMT_EXTENTS;
	}

	scxfs_trans_ijoin(tp, ip, 0);
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
	error = scxfs_bmap_set_attrforkoff(ip, size, &version);
	if (error)
		goto trans_cancel;
	ASSERT(ip->i_afp == NULL);
	ip->i_afp = kmem_zone_zalloc(scxfs_ifork_zone, 0);
	ip->i_afp->if_flags = SCXFS_IFEXTENTS;
	logflags = 0;
	switch (ip->i_d.di_format) {
	case SCXFS_DINODE_FMT_LOCAL:
		error = scxfs_bmap_add_attrfork_local(tp, ip, &logflags);
		break;
	case SCXFS_DINODE_FMT_EXTENTS:
		error = scxfs_bmap_add_attrfork_extents(tp, ip, &logflags);
		break;
	case SCXFS_DINODE_FMT_BTREE:
		error = scxfs_bmap_add_attrfork_btree(tp, ip, &logflags);
		break;
	default:
		error = 0;
		break;
	}
	if (logflags)
		scxfs_trans_log_inode(tp, ip, logflags);
	if (error)
		goto trans_cancel;
	if (!scxfs_sb_version_hasattr(&mp->m_sb) ||
	   (!scxfs_sb_version_hasattr2(&mp->m_sb) && version == 2)) {
		bool log_sb = false;

		spin_lock(&mp->m_sb_lock);
		if (!scxfs_sb_version_hasattr(&mp->m_sb)) {
			scxfs_sb_version_addattr(&mp->m_sb);
			log_sb = true;
		}
		if (!scxfs_sb_version_hasattr2(&mp->m_sb) && version == 2) {
			scxfs_sb_version_addattr2(&mp->m_sb);
			log_sb = true;
		}
		spin_unlock(&mp->m_sb_lock);
		if (log_sb)
			scxfs_log_sb(tp);
	}

	error = scxfs_trans_commit(tp);
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return error;

trans_cancel:
	scxfs_trans_cancel(tp);
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return error;
}

/*
 * Internal and external extent tree search functions.
 */

/*
 * Read in extents from a btree-format inode.
 */
int
scxfs_iread_extents(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork)
{
	struct scxfs_mount	*mp = ip->i_mount;
	int			state = scxfs_bmap_fork_to_state(whichfork);
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	scxfs_extnum_t		nextents = SCXFS_IFORK_NEXTENTS(ip, whichfork);
	struct scxfs_btree_block	*block = ifp->if_broot;
	struct scxfs_iext_cursor	icur;
	struct scxfs_bmbt_irec	new;
	scxfs_fsblock_t		bno;
	struct scxfs_buf		*bp;
	scxfs_extnum_t		i, j;
	int			level;
	__be64			*pp;
	int			error;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));

	if (unlikely(SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE)) {
		SCXFS_ERROR_REPORT(__func__, SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}

	/*
	 * Root level must use BMAP_BROOT_PTR_ADDR macro to get ptr out.
	 */
	level = be16_to_cpu(block->bb_level);
	if (unlikely(level == 0)) {
		SCXFS_ERROR_REPORT(__func__, SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}
	pp = SCXFS_BMAP_BROOT_PTR_ADDR(mp, block, 1, ifp->if_broot_bytes);
	bno = be64_to_cpu(*pp);

	/*
	 * Go down the tree until leaf level is reached, following the first
	 * pointer (leftmost) at each level.
	 */
	while (level-- > 0) {
		error = scxfs_btree_read_bufl(mp, tp, bno, &bp,
				SCXFS_BMAP_BTREE_REF, &scxfs_bmbt_buf_ops);
		if (error)
			goto out;
		block = SCXFS_BUF_TO_BLOCK(bp);
		if (level == 0)
			break;
		pp = SCXFS_BMBT_PTR_ADDR(mp, block, 1, mp->m_bmap_dmxr[1]);
		bno = be64_to_cpu(*pp);
		SCXFS_WANT_CORRUPTED_GOTO(mp,
			scxfs_verify_fsbno(mp, bno), out_brelse);
		scxfs_trans_brelse(tp, bp);
	}

	/*
	 * Here with bp and block set to the leftmost leaf node in the tree.
	 */
	i = 0;
	scxfs_iext_first(ifp, &icur);

	/*
	 * Loop over all leaf nodes.  Copy information to the extent records.
	 */
	for (;;) {
		scxfs_bmbt_rec_t	*frp;
		scxfs_fsblock_t	nextbno;
		scxfs_extnum_t	num_recs;

		num_recs = scxfs_btree_get_numrecs(block);
		if (unlikely(i + num_recs > nextents)) {
			scxfs_warn(ip->i_mount,
				"corrupt dinode %Lu, (btree extents).",
				(unsigned long long) ip->i_ino);
			scxfs_inode_verifier_error(ip, -EFSCORRUPTED,
					__func__, block, sizeof(*block),
					__this_address);
			error = -EFSCORRUPTED;
			goto out_brelse;
		}
		/*
		 * Read-ahead the next leaf block, if any.
		 */
		nextbno = be64_to_cpu(block->bb_u.l.bb_rightsib);
		if (nextbno != NULLFSBLOCK)
			scxfs_btree_reada_bufl(mp, nextbno, 1,
					     &scxfs_bmbt_buf_ops);
		/*
		 * Copy records into the extent records.
		 */
		frp = SCXFS_BMBT_REC_ADDR(mp, block, 1);
		for (j = 0; j < num_recs; j++, frp++, i++) {
			scxfs_failaddr_t	fa;

			scxfs_bmbt_disk_get_all(frp, &new);
			fa = scxfs_bmap_validate_extent(ip, whichfork, &new);
			if (fa) {
				error = -EFSCORRUPTED;
				scxfs_inode_verifier_error(ip, error,
						"scxfs_iread_extents(2)",
						frp, sizeof(*frp), fa);
				goto out_brelse;
			}
			scxfs_iext_insert(ip, &icur, &new, state);
			trace_scxfs_read_extent(ip, &icur, state, _THIS_IP_);
			scxfs_iext_next(ifp, &icur);
		}
		scxfs_trans_brelse(tp, bp);
		bno = nextbno;
		/*
		 * If we've reached the end, stop.
		 */
		if (bno == NULLFSBLOCK)
			break;
		error = scxfs_btree_read_bufl(mp, tp, bno, &bp,
				SCXFS_BMAP_BTREE_REF, &scxfs_bmbt_buf_ops);
		if (error)
			goto out;
		block = SCXFS_BUF_TO_BLOCK(bp);
	}

	if (i != SCXFS_IFORK_NEXTENTS(ip, whichfork)) {
		error = -EFSCORRUPTED;
		goto out;
	}
	ASSERT(i == scxfs_iext_count(ifp));

	ifp->if_flags |= SCXFS_IFEXTENTS;
	return 0;

out_brelse:
	scxfs_trans_brelse(tp, bp);
out:
	scxfs_iext_destroy(ifp);
	return error;
}

/*
 * Returns the relative block number of the first unused block(s) in the given
 * fork with at least "len" logically contiguous blocks free.  This is the
 * lowest-address hole if the fork has holes, else the first block past the end
 * of fork.  Return 0 if the fork is currently local (in-inode).
 */
int						/* error */
scxfs_bmap_first_unused(
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* incore inode */
	scxfs_extlen_t		len,		/* size of hole to find */
	scxfs_fileoff_t		*first_unused,	/* unused block */
	int			whichfork)	/* data or attr fork */
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_bmbt_irec	got;
	struct scxfs_iext_cursor	icur;
	scxfs_fileoff_t		lastaddr = 0;
	scxfs_fileoff_t		lowest, max;
	int			error;

	ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_BTREE ||
	       SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_EXTENTS ||
	       SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_LOCAL);

	if (SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_LOCAL) {
		*first_unused = 0;
		return 0;
	}

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			return error;
	}

	lowest = max = *first_unused;
	for_each_scxfs_iext(ifp, &icur, &got) {
		/*
		 * See if the hole before this extent will work.
		 */
		if (got.br_startoff >= lowest + len &&
		    got.br_startoff - max >= len)
			break;
		lastaddr = got.br_startoff + got.br_blockcount;
		max = SCXFS_FILEOFF_MAX(lastaddr, lowest);
	}

	*first_unused = max;
	return 0;
}

/*
 * Returns the file-relative block number of the last block - 1 before
 * last_block (input value) in the file.
 * This is not based on i_size, it is based on the extent records.
 * Returns 0 for local files, as they do not have extent records.
 */
int						/* error */
scxfs_bmap_last_before(
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* incore inode */
	scxfs_fileoff_t		*last_block,	/* last block */
	int			whichfork)	/* data or attr fork */
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_bmbt_irec	got;
	struct scxfs_iext_cursor	icur;
	int			error;

	switch (SCXFS_IFORK_FORMAT(ip, whichfork)) {
	case SCXFS_DINODE_FMT_LOCAL:
		*last_block = 0;
		return 0;
	case SCXFS_DINODE_FMT_BTREE:
	case SCXFS_DINODE_FMT_EXTENTS:
		break;
	default:
		return -EIO;
	}

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			return error;
	}

	if (!scxfs_iext_lookup_extent_before(ip, ifp, last_block, &icur, &got))
		*last_block = 0;
	return 0;
}

int
scxfs_bmap_last_extent(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_bmbt_irec	*rec,
	int			*is_empty)
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_iext_cursor	icur;
	int			error;

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			return error;
	}

	scxfs_iext_last(ifp, &icur);
	if (!scxfs_iext_get_extent(ifp, &icur, rec))
		*is_empty = 1;
	else
		*is_empty = 0;
	return 0;
}

/*
 * Check the last inode extent to determine whether this allocation will result
 * in blocks being allocated at the end of the file. When we allocate new data
 * blocks at the end of the file which do not start at the previous data block,
 * we will try to align the new blocks at stripe unit boundaries.
 *
 * Returns 1 in bma->aeof if the file (fork) is empty as any new write will be
 * at, or past the EOF.
 */
STATIC int
scxfs_bmap_isaeof(
	struct scxfs_bmalloca	*bma,
	int			whichfork)
{
	struct scxfs_bmbt_irec	rec;
	int			is_empty;
	int			error;

	bma->aeof = false;
	error = scxfs_bmap_last_extent(NULL, bma->ip, whichfork, &rec,
				     &is_empty);
	if (error)
		return error;

	if (is_empty) {
		bma->aeof = true;
		return 0;
	}

	/*
	 * Check if we are allocation or past the last extent, or at least into
	 * the last delayed allocated extent.
	 */
	bma->aeof = bma->offset >= rec.br_startoff + rec.br_blockcount ||
		(bma->offset >= rec.br_startoff &&
		 isnullstartblock(rec.br_startblock));
	return 0;
}

/*
 * Returns the file-relative block number of the first block past eof in
 * the file.  This is not based on i_size, it is based on the extent records.
 * Returns 0 for local files, as they do not have extent records.
 */
int
scxfs_bmap_last_offset(
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		*last_block,
	int			whichfork)
{
	struct scxfs_bmbt_irec	rec;
	int			is_empty;
	int			error;

	*last_block = 0;

	if (SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_LOCAL)
		return 0;

	if (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE &&
	    SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS)
	       return -EIO;

	error = scxfs_bmap_last_extent(NULL, ip, whichfork, &rec, &is_empty);
	if (error || is_empty)
		return error;

	*last_block = rec.br_startoff + rec.br_blockcount;
	return 0;
}

/*
 * Returns whether the selected fork of the inode has exactly one
 * block or not.  For the data fork we check this matches di_size,
 * implying the file's range is 0..bsize-1.
 */
int					/* 1=>1 block, 0=>otherwise */
scxfs_bmap_one_block(
	scxfs_inode_t	*ip,		/* incore inode */
	int		whichfork)	/* data or attr fork */
{
	struct scxfs_ifork *ifp;		/* inode fork pointer */
	int		rval;		/* return value */
	scxfs_bmbt_irec_t	s;		/* internal version of extent */
	struct scxfs_iext_cursor icur;

#ifndef DEBUG
	if (whichfork == SCXFS_DATA_FORK)
		return SCXFS_ISIZE(ip) == ip->i_mount->m_sb.sb_blocksize;
#endif	/* !DEBUG */
	if (SCXFS_IFORK_NEXTENTS(ip, whichfork) != 1)
		return 0;
	if (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS)
		return 0;
	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	ASSERT(ifp->if_flags & SCXFS_IFEXTENTS);
	scxfs_iext_first(ifp, &icur);
	scxfs_iext_get_extent(ifp, &icur, &s);
	rval = s.br_startoff == 0 && s.br_blockcount == 1;
	if (rval && whichfork == SCXFS_DATA_FORK)
		ASSERT(SCXFS_ISIZE(ip) == ip->i_mount->m_sb.sb_blocksize);
	return rval;
}

/*
 * Extent tree manipulation functions used during allocation.
 */

/*
 * Convert a delayed allocation to a real allocation.
 */
STATIC int				/* error */
scxfs_bmap_add_extent_delay_real(
	struct scxfs_bmalloca	*bma,
	int			whichfork)
{
	struct scxfs_bmbt_irec	*new = &bma->got;
	int			error;	/* error return value */
	int			i;	/* temp state */
	struct scxfs_ifork	*ifp;	/* inode fork pointer */
	scxfs_fileoff_t		new_endoff;	/* end offset of new entry */
	scxfs_bmbt_irec_t		r[3];	/* neighbor extent entries */
					/* left is 0, right is 1, prev is 2 */
	int			rval=0;	/* return value (logging flags) */
	int			state = scxfs_bmap_fork_to_state(whichfork);
	scxfs_filblks_t		da_new; /* new count del alloc blocks used */
	scxfs_filblks_t		da_old; /* old count del alloc blocks used */
	scxfs_filblks_t		temp=0;	/* value for da_new calculations */
	int			tmp_rval;	/* partial logging flags */
	struct scxfs_mount	*mp;
	scxfs_extnum_t		*nextents;
	struct scxfs_bmbt_irec	old;

	mp = bma->ip->i_mount;
	ifp = SCXFS_IFORK_PTR(bma->ip, whichfork);
	ASSERT(whichfork != SCXFS_ATTR_FORK);
	nextents = (whichfork == SCXFS_COW_FORK ? &bma->ip->i_cnextents :
						&bma->ip->i_d.di_nextents);

	ASSERT(!isnullstartblock(new->br_startblock));
	ASSERT(!bma->cur ||
	       (bma->cur->bc_private.b.flags & SCXFS_BTCUR_BPRV_WASDEL));

	SCXFS_STATS_INC(mp, xs_add_exlist);

#define	LEFT		r[0]
#define	RIGHT		r[1]
#define	PREV		r[2]

	/*
	 * Set up a bunch of variables to make the tests simpler.
	 */
	scxfs_iext_get_extent(ifp, &bma->icur, &PREV);
	new_endoff = new->br_startoff + new->br_blockcount;
	ASSERT(isnullstartblock(PREV.br_startblock));
	ASSERT(PREV.br_startoff <= new->br_startoff);
	ASSERT(PREV.br_startoff + PREV.br_blockcount >= new_endoff);

	da_old = startblockval(PREV.br_startblock);
	da_new = 0;

	/*
	 * Set flags determining what part of the previous delayed allocation
	 * extent is being replaced by a real allocation.
	 */
	if (PREV.br_startoff == new->br_startoff)
		state |= BMAP_LEFT_FILLING;
	if (PREV.br_startoff + PREV.br_blockcount == new_endoff)
		state |= BMAP_RIGHT_FILLING;

	/*
	 * Check and set flags if this segment has a left neighbor.
	 * Don't set contiguous if the combined extent would be too large.
	 */
	if (scxfs_iext_peek_prev_extent(ifp, &bma->icur, &LEFT)) {
		state |= BMAP_LEFT_VALID;
		if (isnullstartblock(LEFT.br_startblock))
			state |= BMAP_LEFT_DELAY;
	}

	if ((state & BMAP_LEFT_VALID) && !(state & BMAP_LEFT_DELAY) &&
	    LEFT.br_startoff + LEFT.br_blockcount == new->br_startoff &&
	    LEFT.br_startblock + LEFT.br_blockcount == new->br_startblock &&
	    LEFT.br_state == new->br_state &&
	    LEFT.br_blockcount + new->br_blockcount <= MAXEXTLEN)
		state |= BMAP_LEFT_CONTIG;

	/*
	 * Check and set flags if this segment has a right neighbor.
	 * Don't set contiguous if the combined extent would be too large.
	 * Also check for all-three-contiguous being too large.
	 */
	if (scxfs_iext_peek_next_extent(ifp, &bma->icur, &RIGHT)) {
		state |= BMAP_RIGHT_VALID;
		if (isnullstartblock(RIGHT.br_startblock))
			state |= BMAP_RIGHT_DELAY;
	}

	if ((state & BMAP_RIGHT_VALID) && !(state & BMAP_RIGHT_DELAY) &&
	    new_endoff == RIGHT.br_startoff &&
	    new->br_startblock + new->br_blockcount == RIGHT.br_startblock &&
	    new->br_state == RIGHT.br_state &&
	    new->br_blockcount + RIGHT.br_blockcount <= MAXEXTLEN &&
	    ((state & (BMAP_LEFT_CONTIG | BMAP_LEFT_FILLING |
		       BMAP_RIGHT_FILLING)) !=
		      (BMAP_LEFT_CONTIG | BMAP_LEFT_FILLING |
		       BMAP_RIGHT_FILLING) ||
	     LEFT.br_blockcount + new->br_blockcount + RIGHT.br_blockcount
			<= MAXEXTLEN))
		state |= BMAP_RIGHT_CONTIG;

	error = 0;
	/*
	 * Switch out based on the FILLING and CONTIG state bits.
	 */
	switch (state & (BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG |
			 BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG)) {
	case BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG |
	     BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG:
		/*
		 * Filling in all of a previously delayed allocation extent.
		 * The left and right neighbors are both contiguous with new.
		 */
		LEFT.br_blockcount += PREV.br_blockcount + RIGHT.br_blockcount;

		scxfs_iext_remove(bma->ip, &bma->icur, state);
		scxfs_iext_remove(bma->ip, &bma->icur, state);
		scxfs_iext_prev(ifp, &bma->icur);
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &LEFT);
		(*nextents)--;

		if (bma->cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(bma->cur, &RIGHT, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_btree_delete(bma->cur, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_btree_decrement(bma->cur, 0, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(bma->cur, &LEFT);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING | BMAP_LEFT_CONTIG:
		/*
		 * Filling in all of a previously delayed allocation extent.
		 * The left neighbor is contiguous, the right is not.
		 */
		old = LEFT;
		LEFT.br_blockcount += PREV.br_blockcount;

		scxfs_iext_remove(bma->ip, &bma->icur, state);
		scxfs_iext_prev(ifp, &bma->icur);
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &LEFT);

		if (bma->cur == NULL)
			rval = SCXFS_ILOG_DEXT;
		else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(bma->cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(bma->cur, &LEFT);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG:
		/*
		 * Filling in all of a previously delayed allocation extent.
		 * The right neighbor is contiguous, the left is not. Take care
		 * with delay -> unwritten extent allocation here because the
		 * delalloc record we are overwriting is always written.
		 */
		PREV.br_startblock = new->br_startblock;
		PREV.br_blockcount += RIGHT.br_blockcount;
		PREV.br_state = new->br_state;

		scxfs_iext_next(ifp, &bma->icur);
		scxfs_iext_remove(bma->ip, &bma->icur, state);
		scxfs_iext_prev(ifp, &bma->icur);
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &PREV);

		if (bma->cur == NULL)
			rval = SCXFS_ILOG_DEXT;
		else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(bma->cur, &RIGHT, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(bma->cur, &PREV);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING:
		/*
		 * Filling in all of a previously delayed allocation extent.
		 * Neither the left nor right neighbors are contiguous with
		 * the new one.
		 */
		PREV.br_startblock = new->br_startblock;
		PREV.br_state = new->br_state;
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &PREV);

		(*nextents)++;
		if (bma->cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(bma->cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
			error = scxfs_btree_insert(bma->cur, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG:
		/*
		 * Filling in the first part of a previous delayed allocation.
		 * The left neighbor is contiguous.
		 */
		old = LEFT;
		temp = PREV.br_blockcount - new->br_blockcount;
		da_new = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(bma->ip, temp),
				startblockval(PREV.br_startblock));

		LEFT.br_blockcount += new->br_blockcount;

		PREV.br_blockcount = temp;
		PREV.br_startoff += new->br_blockcount;
		PREV.br_startblock = nullstartblock(da_new);

		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &PREV);
		scxfs_iext_prev(ifp, &bma->icur);
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &LEFT);

		if (bma->cur == NULL)
			rval = SCXFS_ILOG_DEXT;
		else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(bma->cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(bma->cur, &LEFT);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING:
		/*
		 * Filling in the first part of a previous delayed allocation.
		 * The left neighbor is not contiguous.
		 */
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, new);
		(*nextents)++;
		if (bma->cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(bma->cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
			error = scxfs_btree_insert(bma->cur, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}

		if (scxfs_bmap_needs_btree(bma->ip, whichfork)) {
			error = scxfs_bmap_extents_to_btree(bma->tp, bma->ip,
					&bma->cur, 1, &tmp_rval, whichfork);
			rval |= tmp_rval;
			if (error)
				goto done;
		}

		temp = PREV.br_blockcount - new->br_blockcount;
		da_new = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(bma->ip, temp),
			startblockval(PREV.br_startblock) -
			(bma->cur ? bma->cur->bc_private.b.allocated : 0));

		PREV.br_startoff = new_endoff;
		PREV.br_blockcount = temp;
		PREV.br_startblock = nullstartblock(da_new);
		scxfs_iext_next(ifp, &bma->icur);
		scxfs_iext_insert(bma->ip, &bma->icur, &PREV, state);
		scxfs_iext_prev(ifp, &bma->icur);
		break;

	case BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG:
		/*
		 * Filling in the last part of a previous delayed allocation.
		 * The right neighbor is contiguous with the new allocation.
		 */
		old = RIGHT;
		RIGHT.br_startoff = new->br_startoff;
		RIGHT.br_startblock = new->br_startblock;
		RIGHT.br_blockcount += new->br_blockcount;

		if (bma->cur == NULL)
			rval = SCXFS_ILOG_DEXT;
		else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(bma->cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(bma->cur, &RIGHT);
			if (error)
				goto done;
		}

		temp = PREV.br_blockcount - new->br_blockcount;
		da_new = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(bma->ip, temp),
			startblockval(PREV.br_startblock));

		PREV.br_blockcount = temp;
		PREV.br_startblock = nullstartblock(da_new);

		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &PREV);
		scxfs_iext_next(ifp, &bma->icur);
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &RIGHT);
		break;

	case BMAP_RIGHT_FILLING:
		/*
		 * Filling in the last part of a previous delayed allocation.
		 * The right neighbor is not contiguous.
		 */
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, new);
		(*nextents)++;
		if (bma->cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(bma->cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
			error = scxfs_btree_insert(bma->cur, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}

		if (scxfs_bmap_needs_btree(bma->ip, whichfork)) {
			error = scxfs_bmap_extents_to_btree(bma->tp, bma->ip,
				&bma->cur, 1, &tmp_rval, whichfork);
			rval |= tmp_rval;
			if (error)
				goto done;
		}

		temp = PREV.br_blockcount - new->br_blockcount;
		da_new = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(bma->ip, temp),
			startblockval(PREV.br_startblock) -
			(bma->cur ? bma->cur->bc_private.b.allocated : 0));

		PREV.br_startblock = nullstartblock(da_new);
		PREV.br_blockcount = temp;
		scxfs_iext_insert(bma->ip, &bma->icur, &PREV, state);
		scxfs_iext_next(ifp, &bma->icur);
		break;

	case 0:
		/*
		 * Filling in the middle part of a previous delayed allocation.
		 * Contiguity is impossible here.
		 * This case is avoided almost all the time.
		 *
		 * We start with a delayed allocation:
		 *
		 * +ddddddddddddddddddddddddddddddddddddddddddddddddddddddd+
		 *  PREV @ idx
		 *
	         * and we are allocating:
		 *                     +rrrrrrrrrrrrrrrrr+
		 *			      new
		 *
		 * and we set it up for insertion as:
		 * +ddddddddddddddddddd+rrrrrrrrrrrrrrrrr+ddddddddddddddddd+
		 *                            new
		 *  PREV @ idx          LEFT              RIGHT
		 *                      inserted at idx + 1
		 */
		old = PREV;

		/* LEFT is the new middle */
		LEFT = *new;

		/* RIGHT is the new right */
		RIGHT.br_state = PREV.br_state;
		RIGHT.br_startoff = new_endoff;
		RIGHT.br_blockcount =
			PREV.br_startoff + PREV.br_blockcount - new_endoff;
		RIGHT.br_startblock =
			nullstartblock(scxfs_bmap_worst_indlen(bma->ip,
					RIGHT.br_blockcount));

		/* truncate PREV */
		PREV.br_blockcount = new->br_startoff - PREV.br_startoff;
		PREV.br_startblock =
			nullstartblock(scxfs_bmap_worst_indlen(bma->ip,
					PREV.br_blockcount));
		scxfs_iext_update_extent(bma->ip, state, &bma->icur, &PREV);

		scxfs_iext_next(ifp, &bma->icur);
		scxfs_iext_insert(bma->ip, &bma->icur, &RIGHT, state);
		scxfs_iext_insert(bma->ip, &bma->icur, &LEFT, state);
		(*nextents)++;

		if (bma->cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(bma->cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
			error = scxfs_btree_insert(bma->cur, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}

		if (scxfs_bmap_needs_btree(bma->ip, whichfork)) {
			error = scxfs_bmap_extents_to_btree(bma->tp, bma->ip,
					&bma->cur, 1, &tmp_rval, whichfork);
			rval |= tmp_rval;
			if (error)
				goto done;
		}

		da_new = startblockval(PREV.br_startblock) +
			 startblockval(RIGHT.br_startblock);
		break;

	case BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
	case BMAP_RIGHT_FILLING | BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
	case BMAP_LEFT_FILLING | BMAP_RIGHT_CONTIG:
	case BMAP_RIGHT_FILLING | BMAP_LEFT_CONTIG:
	case BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
	case BMAP_LEFT_CONTIG:
	case BMAP_RIGHT_CONTIG:
		/*
		 * These cases are all impossible.
		 */
		ASSERT(0);
	}

	/* add reverse mapping unless caller opted out */
	if (!(bma->flags & SCXFS_BMAPI_NORMAP))
		scxfs_rmap_map_extent(bma->tp, bma->ip, whichfork, new);

	/* convert to a btree if necessary */
	if (scxfs_bmap_needs_btree(bma->ip, whichfork)) {
		int	tmp_logflags;	/* partial log flag return val */

		ASSERT(bma->cur == NULL);
		error = scxfs_bmap_extents_to_btree(bma->tp, bma->ip,
				&bma->cur, da_old > 0, &tmp_logflags,
				whichfork);
		bma->logflags |= tmp_logflags;
		if (error)
			goto done;
	}

	if (da_new != da_old)
		scxfs_mod_delalloc(mp, (int64_t)da_new - da_old);

	if (bma->cur) {
		da_new += bma->cur->bc_private.b.allocated;
		bma->cur->bc_private.b.allocated = 0;
	}

	/* adjust for changes in reserved delayed indirect blocks */
	if (da_new != da_old) {
		ASSERT(state == 0 || da_new < da_old);
		error = scxfs_mod_fdblocks(mp, (int64_t)(da_old - da_new),
				false);
	}

	scxfs_bmap_check_leaf_extents(bma->cur, bma->ip, whichfork);
done:
	if (whichfork != SCXFS_COW_FORK)
		bma->logflags |= rval;
	return error;
#undef	LEFT
#undef	RIGHT
#undef	PREV
}

/*
 * Convert an unwritten allocation to a real allocation or vice versa.
 */
int					/* error */
scxfs_bmap_add_extent_unwritten_real(
	struct scxfs_trans	*tp,
	scxfs_inode_t		*ip,	/* incore inode pointer */
	int			whichfork,
	struct scxfs_iext_cursor	*icur,
	scxfs_btree_cur_t		**curp,	/* if *curp is null, not a btree */
	scxfs_bmbt_irec_t		*new,	/* new data to add to file extents */
	int			*logflagsp) /* inode logging flags */
{
	scxfs_btree_cur_t		*cur;	/* btree cursor */
	int			error;	/* error return value */
	int			i;	/* temp state */
	struct scxfs_ifork	*ifp;	/* inode fork pointer */
	scxfs_fileoff_t		new_endoff;	/* end offset of new entry */
	scxfs_bmbt_irec_t		r[3];	/* neighbor extent entries */
					/* left is 0, right is 1, prev is 2 */
	int			rval=0;	/* return value (logging flags) */
	int			state = scxfs_bmap_fork_to_state(whichfork);
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_bmbt_irec	old;

	*logflagsp = 0;

	cur = *curp;
	ifp = SCXFS_IFORK_PTR(ip, whichfork);

	ASSERT(!isnullstartblock(new->br_startblock));

	SCXFS_STATS_INC(mp, xs_add_exlist);

#define	LEFT		r[0]
#define	RIGHT		r[1]
#define	PREV		r[2]

	/*
	 * Set up a bunch of variables to make the tests simpler.
	 */
	error = 0;
	scxfs_iext_get_extent(ifp, icur, &PREV);
	ASSERT(new->br_state != PREV.br_state);
	new_endoff = new->br_startoff + new->br_blockcount;
	ASSERT(PREV.br_startoff <= new->br_startoff);
	ASSERT(PREV.br_startoff + PREV.br_blockcount >= new_endoff);

	/*
	 * Set flags determining what part of the previous oldext allocation
	 * extent is being replaced by a newext allocation.
	 */
	if (PREV.br_startoff == new->br_startoff)
		state |= BMAP_LEFT_FILLING;
	if (PREV.br_startoff + PREV.br_blockcount == new_endoff)
		state |= BMAP_RIGHT_FILLING;

	/*
	 * Check and set flags if this segment has a left neighbor.
	 * Don't set contiguous if the combined extent would be too large.
	 */
	if (scxfs_iext_peek_prev_extent(ifp, icur, &LEFT)) {
		state |= BMAP_LEFT_VALID;
		if (isnullstartblock(LEFT.br_startblock))
			state |= BMAP_LEFT_DELAY;
	}

	if ((state & BMAP_LEFT_VALID) && !(state & BMAP_LEFT_DELAY) &&
	    LEFT.br_startoff + LEFT.br_blockcount == new->br_startoff &&
	    LEFT.br_startblock + LEFT.br_blockcount == new->br_startblock &&
	    LEFT.br_state == new->br_state &&
	    LEFT.br_blockcount + new->br_blockcount <= MAXEXTLEN)
		state |= BMAP_LEFT_CONTIG;

	/*
	 * Check and set flags if this segment has a right neighbor.
	 * Don't set contiguous if the combined extent would be too large.
	 * Also check for all-three-contiguous being too large.
	 */
	if (scxfs_iext_peek_next_extent(ifp, icur, &RIGHT)) {
		state |= BMAP_RIGHT_VALID;
		if (isnullstartblock(RIGHT.br_startblock))
			state |= BMAP_RIGHT_DELAY;
	}

	if ((state & BMAP_RIGHT_VALID) && !(state & BMAP_RIGHT_DELAY) &&
	    new_endoff == RIGHT.br_startoff &&
	    new->br_startblock + new->br_blockcount == RIGHT.br_startblock &&
	    new->br_state == RIGHT.br_state &&
	    new->br_blockcount + RIGHT.br_blockcount <= MAXEXTLEN &&
	    ((state & (BMAP_LEFT_CONTIG | BMAP_LEFT_FILLING |
		       BMAP_RIGHT_FILLING)) !=
		      (BMAP_LEFT_CONTIG | BMAP_LEFT_FILLING |
		       BMAP_RIGHT_FILLING) ||
	     LEFT.br_blockcount + new->br_blockcount + RIGHT.br_blockcount
			<= MAXEXTLEN))
		state |= BMAP_RIGHT_CONTIG;

	/*
	 * Switch out based on the FILLING and CONTIG state bits.
	 */
	switch (state & (BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG |
			 BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG)) {
	case BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG |
	     BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The left and right neighbors are both contiguous with new.
		 */
		LEFT.br_blockcount += PREV.br_blockcount + RIGHT.br_blockcount;

		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &LEFT);
		SCXFS_IFORK_NEXT_SET(ip, whichfork,
				SCXFS_IFORK_NEXTENTS(ip, whichfork) - 2);
		if (cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, &RIGHT, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_delete(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_decrement(cur, 0, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_delete(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_decrement(cur, 0, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &LEFT);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING | BMAP_LEFT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The left neighbor is contiguous, the right is not.
		 */
		LEFT.br_blockcount += PREV.br_blockcount;

		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &LEFT);
		SCXFS_IFORK_NEXT_SET(ip, whichfork,
				SCXFS_IFORK_NEXTENTS(ip, whichfork) - 1);
		if (cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, &PREV, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_delete(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_decrement(cur, 0, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &LEFT);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The right neighbor is contiguous, the left is not.
		 */
		PREV.br_blockcount += RIGHT.br_blockcount;
		PREV.br_state = new->br_state;

		scxfs_iext_next(ifp, icur);
		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &PREV);

		SCXFS_IFORK_NEXT_SET(ip, whichfork,
				SCXFS_IFORK_NEXTENTS(ip, whichfork) - 1);
		if (cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, &RIGHT, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_delete(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			if ((error = scxfs_btree_decrement(cur, 0, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &PREV);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * Neither the left nor right neighbors are contiguous with
		 * the new one.
		 */
		PREV.br_state = new->br_state;
		scxfs_iext_update_extent(ip, state, icur, &PREV);

		if (cur == NULL)
			rval = SCXFS_ILOG_DEXT;
		else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &PREV);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG:
		/*
		 * Setting the first part of a previous oldext extent to newext.
		 * The left neighbor is contiguous.
		 */
		LEFT.br_blockcount += new->br_blockcount;

		old = PREV;
		PREV.br_startoff += new->br_blockcount;
		PREV.br_startblock += new->br_blockcount;
		PREV.br_blockcount -= new->br_blockcount;

		scxfs_iext_update_extent(ip, state, icur, &PREV);
		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &LEFT);

		if (cur == NULL)
			rval = SCXFS_ILOG_DEXT;
		else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &PREV);
			if (error)
				goto done;
			error = scxfs_btree_decrement(cur, 0, &i);
			if (error)
				goto done;
			error = scxfs_bmbt_update(cur, &LEFT);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_FILLING:
		/*
		 * Setting the first part of a previous oldext extent to newext.
		 * The left neighbor is not contiguous.
		 */
		old = PREV;
		PREV.br_startoff += new->br_blockcount;
		PREV.br_startblock += new->br_blockcount;
		PREV.br_blockcount -= new->br_blockcount;

		scxfs_iext_update_extent(ip, state, icur, &PREV);
		scxfs_iext_insert(ip, icur, new, state);
		SCXFS_IFORK_NEXT_SET(ip, whichfork,
				SCXFS_IFORK_NEXTENTS(ip, whichfork) + 1);
		if (cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &PREV);
			if (error)
				goto done;
			cur->bc_rec.b = *new;
			if ((error = scxfs_btree_insert(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}
		break;

	case BMAP_RIGHT_FILLING | BMAP_RIGHT_CONTIG:
		/*
		 * Setting the last part of a previous oldext extent to newext.
		 * The right neighbor is contiguous with the new allocation.
		 */
		old = PREV;
		PREV.br_blockcount -= new->br_blockcount;

		RIGHT.br_startoff = new->br_startoff;
		RIGHT.br_startblock = new->br_startblock;
		RIGHT.br_blockcount += new->br_blockcount;

		scxfs_iext_update_extent(ip, state, icur, &PREV);
		scxfs_iext_next(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &RIGHT);

		if (cur == NULL)
			rval = SCXFS_ILOG_DEXT;
		else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &PREV);
			if (error)
				goto done;
			error = scxfs_btree_increment(cur, 0, &i);
			if (error)
				goto done;
			error = scxfs_bmbt_update(cur, &RIGHT);
			if (error)
				goto done;
		}
		break;

	case BMAP_RIGHT_FILLING:
		/*
		 * Setting the last part of a previous oldext extent to newext.
		 * The right neighbor is not contiguous.
		 */
		old = PREV;
		PREV.br_blockcount -= new->br_blockcount;

		scxfs_iext_update_extent(ip, state, icur, &PREV);
		scxfs_iext_next(ifp, icur);
		scxfs_iext_insert(ip, icur, new, state);

		SCXFS_IFORK_NEXT_SET(ip, whichfork,
				SCXFS_IFORK_NEXTENTS(ip, whichfork) + 1);
		if (cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &PREV);
			if (error)
				goto done;
			error = scxfs_bmbt_lookup_eq(cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
			if ((error = scxfs_btree_insert(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}
		break;

	case 0:
		/*
		 * Setting the middle part of a previous oldext extent to
		 * newext.  Contiguity is impossible here.
		 * One extent becomes three extents.
		 */
		old = PREV;
		PREV.br_blockcount = new->br_startoff - PREV.br_startoff;

		r[0] = *new;
		r[1].br_startoff = new_endoff;
		r[1].br_blockcount =
			old.br_startoff + old.br_blockcount - new_endoff;
		r[1].br_startblock = new->br_startblock + new->br_blockcount;
		r[1].br_state = PREV.br_state;

		scxfs_iext_update_extent(ip, state, icur, &PREV);
		scxfs_iext_next(ifp, icur);
		scxfs_iext_insert(ip, icur, &r[1], state);
		scxfs_iext_insert(ip, icur, &r[0], state);

		SCXFS_IFORK_NEXT_SET(ip, whichfork,
				SCXFS_IFORK_NEXTENTS(ip, whichfork) + 2);
		if (cur == NULL)
			rval = SCXFS_ILOG_CORE | SCXFS_ILOG_DEXT;
		else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			/* new right extent - oldext */
			error = scxfs_bmbt_update(cur, &r[1]);
			if (error)
				goto done;
			/* new left extent - oldext */
			cur->bc_rec.b = PREV;
			if ((error = scxfs_btree_insert(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			/*
			 * Reset the cursor to the position of the new extent
			 * we are about to insert as we can't trust it after
			 * the previous insert.
			 */
			error = scxfs_bmbt_lookup_eq(cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
			/* new middle extent - newext */
			if ((error = scxfs_btree_insert(cur, &i)))
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}
		break;

	case BMAP_LEFT_FILLING | BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
	case BMAP_RIGHT_FILLING | BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
	case BMAP_LEFT_FILLING | BMAP_RIGHT_CONTIG:
	case BMAP_RIGHT_FILLING | BMAP_LEFT_CONTIG:
	case BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
	case BMAP_LEFT_CONTIG:
	case BMAP_RIGHT_CONTIG:
		/*
		 * These cases are all impossible.
		 */
		ASSERT(0);
	}

	/* update reverse mappings */
	scxfs_rmap_convert_extent(mp, tp, ip, whichfork, new);

	/* convert to a btree if necessary */
	if (scxfs_bmap_needs_btree(ip, whichfork)) {
		int	tmp_logflags;	/* partial log flag return val */

		ASSERT(cur == NULL);
		error = scxfs_bmap_extents_to_btree(tp, ip, &cur, 0,
				&tmp_logflags, whichfork);
		*logflagsp |= tmp_logflags;
		if (error)
			goto done;
	}

	/* clear out the allocated field, done with it now in any case. */
	if (cur) {
		cur->bc_private.b.allocated = 0;
		*curp = cur;
	}

	scxfs_bmap_check_leaf_extents(*curp, ip, whichfork);
done:
	*logflagsp |= rval;
	return error;
#undef	LEFT
#undef	RIGHT
#undef	PREV
}

/*
 * Convert a hole to a delayed allocation.
 */
STATIC void
scxfs_bmap_add_extent_hole_delay(
	scxfs_inode_t		*ip,	/* incore inode pointer */
	int			whichfork,
	struct scxfs_iext_cursor	*icur,
	scxfs_bmbt_irec_t		*new)	/* new data to add to file extents */
{
	struct scxfs_ifork	*ifp;	/* inode fork pointer */
	scxfs_bmbt_irec_t		left;	/* left neighbor extent entry */
	scxfs_filblks_t		newlen=0;	/* new indirect size */
	scxfs_filblks_t		oldlen=0;	/* old indirect size */
	scxfs_bmbt_irec_t		right;	/* right neighbor extent entry */
	int			state = scxfs_bmap_fork_to_state(whichfork);
	scxfs_filblks_t		temp;	 /* temp for indirect calculations */

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	ASSERT(isnullstartblock(new->br_startblock));

	/*
	 * Check and set flags if this segment has a left neighbor
	 */
	if (scxfs_iext_peek_prev_extent(ifp, icur, &left)) {
		state |= BMAP_LEFT_VALID;
		if (isnullstartblock(left.br_startblock))
			state |= BMAP_LEFT_DELAY;
	}

	/*
	 * Check and set flags if the current (right) segment exists.
	 * If it doesn't exist, we're converting the hole at end-of-file.
	 */
	if (scxfs_iext_get_extent(ifp, icur, &right)) {
		state |= BMAP_RIGHT_VALID;
		if (isnullstartblock(right.br_startblock))
			state |= BMAP_RIGHT_DELAY;
	}

	/*
	 * Set contiguity flags on the left and right neighbors.
	 * Don't let extents get too large, even if the pieces are contiguous.
	 */
	if ((state & BMAP_LEFT_VALID) && (state & BMAP_LEFT_DELAY) &&
	    left.br_startoff + left.br_blockcount == new->br_startoff &&
	    left.br_blockcount + new->br_blockcount <= MAXEXTLEN)
		state |= BMAP_LEFT_CONTIG;

	if ((state & BMAP_RIGHT_VALID) && (state & BMAP_RIGHT_DELAY) &&
	    new->br_startoff + new->br_blockcount == right.br_startoff &&
	    new->br_blockcount + right.br_blockcount <= MAXEXTLEN &&
	    (!(state & BMAP_LEFT_CONTIG) ||
	     (left.br_blockcount + new->br_blockcount +
	      right.br_blockcount <= MAXEXTLEN)))
		state |= BMAP_RIGHT_CONTIG;

	/*
	 * Switch out based on the contiguity flags.
	 */
	switch (state & (BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG)) {
	case BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
		/*
		 * New allocation is contiguous with delayed allocations
		 * on the left and on the right.
		 * Merge all three into a single extent record.
		 */
		temp = left.br_blockcount + new->br_blockcount +
			right.br_blockcount;

		oldlen = startblockval(left.br_startblock) +
			startblockval(new->br_startblock) +
			startblockval(right.br_startblock);
		newlen = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(ip, temp),
					 oldlen);
		left.br_startblock = nullstartblock(newlen);
		left.br_blockcount = temp;

		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &left);
		break;

	case BMAP_LEFT_CONTIG:
		/*
		 * New allocation is contiguous with a delayed allocation
		 * on the left.
		 * Merge the new allocation with the left neighbor.
		 */
		temp = left.br_blockcount + new->br_blockcount;

		oldlen = startblockval(left.br_startblock) +
			startblockval(new->br_startblock);
		newlen = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(ip, temp),
					 oldlen);
		left.br_blockcount = temp;
		left.br_startblock = nullstartblock(newlen);

		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &left);
		break;

	case BMAP_RIGHT_CONTIG:
		/*
		 * New allocation is contiguous with a delayed allocation
		 * on the right.
		 * Merge the new allocation with the right neighbor.
		 */
		temp = new->br_blockcount + right.br_blockcount;
		oldlen = startblockval(new->br_startblock) +
			startblockval(right.br_startblock);
		newlen = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(ip, temp),
					 oldlen);
		right.br_startoff = new->br_startoff;
		right.br_startblock = nullstartblock(newlen);
		right.br_blockcount = temp;
		scxfs_iext_update_extent(ip, state, icur, &right);
		break;

	case 0:
		/*
		 * New allocation is not contiguous with another
		 * delayed allocation.
		 * Insert a new entry.
		 */
		oldlen = newlen = 0;
		scxfs_iext_insert(ip, icur, new, state);
		break;
	}
	if (oldlen != newlen) {
		ASSERT(oldlen > newlen);
		scxfs_mod_fdblocks(ip->i_mount, (int64_t)(oldlen - newlen),
				 false);
		/*
		 * Nothing to do for disk quota accounting here.
		 */
		scxfs_mod_delalloc(ip->i_mount, (int64_t)newlen - oldlen);
	}
}

/*
 * Convert a hole to a real allocation.
 */
STATIC int				/* error */
scxfs_bmap_add_extent_hole_real(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_iext_cursor	*icur,
	struct scxfs_btree_cur	**curp,
	struct scxfs_bmbt_irec	*new,
	int			*logflagsp,
	int			flags)
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_btree_cur	*cur = *curp;
	int			error;	/* error return value */
	int			i;	/* temp state */
	scxfs_bmbt_irec_t		left;	/* left neighbor extent entry */
	scxfs_bmbt_irec_t		right;	/* right neighbor extent entry */
	int			rval=0;	/* return value (logging flags) */
	int			state = scxfs_bmap_fork_to_state(whichfork);
	struct scxfs_bmbt_irec	old;

	ASSERT(!isnullstartblock(new->br_startblock));
	ASSERT(!cur || !(cur->bc_private.b.flags & SCXFS_BTCUR_BPRV_WASDEL));

	SCXFS_STATS_INC(mp, xs_add_exlist);

	/*
	 * Check and set flags if this segment has a left neighbor.
	 */
	if (scxfs_iext_peek_prev_extent(ifp, icur, &left)) {
		state |= BMAP_LEFT_VALID;
		if (isnullstartblock(left.br_startblock))
			state |= BMAP_LEFT_DELAY;
	}

	/*
	 * Check and set flags if this segment has a current value.
	 * Not true if we're inserting into the "hole" at eof.
	 */
	if (scxfs_iext_get_extent(ifp, icur, &right)) {
		state |= BMAP_RIGHT_VALID;
		if (isnullstartblock(right.br_startblock))
			state |= BMAP_RIGHT_DELAY;
	}

	/*
	 * We're inserting a real allocation between "left" and "right".
	 * Set the contiguity flags.  Don't let extents get too large.
	 */
	if ((state & BMAP_LEFT_VALID) && !(state & BMAP_LEFT_DELAY) &&
	    left.br_startoff + left.br_blockcount == new->br_startoff &&
	    left.br_startblock + left.br_blockcount == new->br_startblock &&
	    left.br_state == new->br_state &&
	    left.br_blockcount + new->br_blockcount <= MAXEXTLEN)
		state |= BMAP_LEFT_CONTIG;

	if ((state & BMAP_RIGHT_VALID) && !(state & BMAP_RIGHT_DELAY) &&
	    new->br_startoff + new->br_blockcount == right.br_startoff &&
	    new->br_startblock + new->br_blockcount == right.br_startblock &&
	    new->br_state == right.br_state &&
	    new->br_blockcount + right.br_blockcount <= MAXEXTLEN &&
	    (!(state & BMAP_LEFT_CONTIG) ||
	     left.br_blockcount + new->br_blockcount +
	     right.br_blockcount <= MAXEXTLEN))
		state |= BMAP_RIGHT_CONTIG;

	error = 0;
	/*
	 * Select which case we're in here, and implement it.
	 */
	switch (state & (BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG)) {
	case BMAP_LEFT_CONTIG | BMAP_RIGHT_CONTIG:
		/*
		 * New allocation is contiguous with real allocations on the
		 * left and on the right.
		 * Merge all three into a single extent record.
		 */
		left.br_blockcount += new->br_blockcount + right.br_blockcount;

		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &left);

		SCXFS_IFORK_NEXT_SET(ip, whichfork,
			SCXFS_IFORK_NEXTENTS(ip, whichfork) - 1);
		if (cur == NULL) {
			rval = SCXFS_ILOG_CORE | scxfs_ilog_fext(whichfork);
		} else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, &right, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_btree_delete(cur, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_btree_decrement(cur, 0, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &left);
			if (error)
				goto done;
		}
		break;

	case BMAP_LEFT_CONTIG:
		/*
		 * New allocation is contiguous with a real allocation
		 * on the left.
		 * Merge the new allocation with the left neighbor.
		 */
		old = left;
		left.br_blockcount += new->br_blockcount;

		scxfs_iext_prev(ifp, icur);
		scxfs_iext_update_extent(ip, state, icur, &left);

		if (cur == NULL) {
			rval = scxfs_ilog_fext(whichfork);
		} else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &left);
			if (error)
				goto done;
		}
		break;

	case BMAP_RIGHT_CONTIG:
		/*
		 * New allocation is contiguous with a real allocation
		 * on the right.
		 * Merge the new allocation with the right neighbor.
		 */
		old = right;

		right.br_startoff = new->br_startoff;
		right.br_startblock = new->br_startblock;
		right.br_blockcount += new->br_blockcount;
		scxfs_iext_update_extent(ip, state, icur, &right);

		if (cur == NULL) {
			rval = scxfs_ilog_fext(whichfork);
		} else {
			rval = 0;
			error = scxfs_bmbt_lookup_eq(cur, &old, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
			error = scxfs_bmbt_update(cur, &right);
			if (error)
				goto done;
		}
		break;

	case 0:
		/*
		 * New allocation is not contiguous with another
		 * real allocation.
		 * Insert a new entry.
		 */
		scxfs_iext_insert(ip, icur, new, state);
		SCXFS_IFORK_NEXT_SET(ip, whichfork,
			SCXFS_IFORK_NEXTENTS(ip, whichfork) + 1);
		if (cur == NULL) {
			rval = SCXFS_ILOG_CORE | scxfs_ilog_fext(whichfork);
		} else {
			rval = SCXFS_ILOG_CORE;
			error = scxfs_bmbt_lookup_eq(cur, new, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
			error = scxfs_btree_insert(cur, &i);
			if (error)
				goto done;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		}
		break;
	}

	/* add reverse mapping unless caller opted out */
	if (!(flags & SCXFS_BMAPI_NORMAP))
		scxfs_rmap_map_extent(tp, ip, whichfork, new);

	/* convert to a btree if necessary */
	if (scxfs_bmap_needs_btree(ip, whichfork)) {
		int	tmp_logflags;	/* partial log flag return val */

		ASSERT(cur == NULL);
		error = scxfs_bmap_extents_to_btree(tp, ip, curp, 0,
				&tmp_logflags, whichfork);
		*logflagsp |= tmp_logflags;
		cur = *curp;
		if (error)
			goto done;
	}

	/* clear out the allocated field, done with it now in any case. */
	if (cur)
		cur->bc_private.b.allocated = 0;

	scxfs_bmap_check_leaf_extents(cur, ip, whichfork);
done:
	*logflagsp |= rval;
	return error;
}

/*
 * Functions used in the extent read, allocate and remove paths
 */

/*
 * Adjust the size of the new extent based on di_extsize and rt extsize.
 */
int
scxfs_bmap_extsize_align(
	scxfs_mount_t	*mp,
	scxfs_bmbt_irec_t	*gotp,		/* next extent pointer */
	scxfs_bmbt_irec_t	*prevp,		/* previous extent pointer */
	scxfs_extlen_t	extsz,		/* align to this extent size */
	int		rt,		/* is this a realtime inode? */
	int		eof,		/* is extent at end-of-file? */
	int		delay,		/* creating delalloc extent? */
	int		convert,	/* overwriting unwritten extent? */
	scxfs_fileoff_t	*offp,		/* in/out: aligned offset */
	scxfs_extlen_t	*lenp)		/* in/out: aligned length */
{
	scxfs_fileoff_t	orig_off;	/* original offset */
	scxfs_extlen_t	orig_alen;	/* original length */
	scxfs_fileoff_t	orig_end;	/* original off+len */
	scxfs_fileoff_t	nexto;		/* next file offset */
	scxfs_fileoff_t	prevo;		/* previous file offset */
	scxfs_fileoff_t	align_off;	/* temp for offset */
	scxfs_extlen_t	align_alen;	/* temp for length */
	scxfs_extlen_t	temp;		/* temp for calculations */

	if (convert)
		return 0;

	orig_off = align_off = *offp;
	orig_alen = align_alen = *lenp;
	orig_end = orig_off + orig_alen;

	/*
	 * If this request overlaps an existing extent, then don't
	 * attempt to perform any additional alignment.
	 */
	if (!delay && !eof &&
	    (orig_off >= gotp->br_startoff) &&
	    (orig_end <= gotp->br_startoff + gotp->br_blockcount)) {
		return 0;
	}

	/*
	 * If the file offset is unaligned vs. the extent size
	 * we need to align it.  This will be possible unless
	 * the file was previously written with a kernel that didn't
	 * perform this alignment, or if a truncate shot us in the
	 * foot.
	 */
	div_u64_rem(orig_off, extsz, &temp);
	if (temp) {
		align_alen += temp;
		align_off -= temp;
	}

	/* Same adjustment for the end of the requested area. */
	temp = (align_alen % extsz);
	if (temp)
		align_alen += extsz - temp;

	/*
	 * For large extent hint sizes, the aligned extent might be larger than
	 * MAXEXTLEN. In that case, reduce the size by an extsz so that it pulls
	 * the length back under MAXEXTLEN. The outer allocation loops handle
	 * short allocation just fine, so it is safe to do this. We only want to
	 * do it when we are forced to, though, because it means more allocation
	 * operations are required.
	 */
	while (align_alen > MAXEXTLEN)
		align_alen -= extsz;
	ASSERT(align_alen <= MAXEXTLEN);

	/*
	 * If the previous block overlaps with this proposed allocation
	 * then move the start forward without adjusting the length.
	 */
	if (prevp->br_startoff != NULLFILEOFF) {
		if (prevp->br_startblock == HOLESTARTBLOCK)
			prevo = prevp->br_startoff;
		else
			prevo = prevp->br_startoff + prevp->br_blockcount;
	} else
		prevo = 0;
	if (align_off != orig_off && align_off < prevo)
		align_off = prevo;
	/*
	 * If the next block overlaps with this proposed allocation
	 * then move the start back without adjusting the length,
	 * but not before offset 0.
	 * This may of course make the start overlap previous block,
	 * and if we hit the offset 0 limit then the next block
	 * can still overlap too.
	 */
	if (!eof && gotp->br_startoff != NULLFILEOFF) {
		if ((delay && gotp->br_startblock == HOLESTARTBLOCK) ||
		    (!delay && gotp->br_startblock == DELAYSTARTBLOCK))
			nexto = gotp->br_startoff + gotp->br_blockcount;
		else
			nexto = gotp->br_startoff;
	} else
		nexto = NULLFILEOFF;
	if (!eof &&
	    align_off + align_alen != orig_end &&
	    align_off + align_alen > nexto)
		align_off = nexto > align_alen ? nexto - align_alen : 0;
	/*
	 * If we're now overlapping the next or previous extent that
	 * means we can't fit an extsz piece in this hole.  Just move
	 * the start forward to the first valid spot and set
	 * the length so we hit the end.
	 */
	if (align_off != orig_off && align_off < prevo)
		align_off = prevo;
	if (align_off + align_alen != orig_end &&
	    align_off + align_alen > nexto &&
	    nexto != NULLFILEOFF) {
		ASSERT(nexto > prevo);
		align_alen = nexto - align_off;
	}

	/*
	 * If realtime, and the result isn't a multiple of the realtime
	 * extent size we need to remove blocks until it is.
	 */
	if (rt && (temp = (align_alen % mp->m_sb.sb_rextsize))) {
		/*
		 * We're not covering the original request, or
		 * we won't be able to once we fix the length.
		 */
		if (orig_off < align_off ||
		    orig_end > align_off + align_alen ||
		    align_alen - temp < orig_alen)
			return -EINVAL;
		/*
		 * Try to fix it by moving the start up.
		 */
		if (align_off + temp <= orig_off) {
			align_alen -= temp;
			align_off += temp;
		}
		/*
		 * Try to fix it by moving the end in.
		 */
		else if (align_off + align_alen - temp >= orig_end)
			align_alen -= temp;
		/*
		 * Set the start to the minimum then trim the length.
		 */
		else {
			align_alen -= orig_off - align_off;
			align_off = orig_off;
			align_alen -= align_alen % mp->m_sb.sb_rextsize;
		}
		/*
		 * Result doesn't cover the request, fail it.
		 */
		if (orig_off < align_off || orig_end > align_off + align_alen)
			return -EINVAL;
	} else {
		ASSERT(orig_off >= align_off);
		/* see MAXEXTLEN handling above */
		ASSERT(orig_end <= align_off + align_alen ||
		       align_alen + extsz > MAXEXTLEN);
	}

#ifdef DEBUG
	if (!eof && gotp->br_startoff != NULLFILEOFF)
		ASSERT(align_off + align_alen <= gotp->br_startoff);
	if (prevp->br_startoff != NULLFILEOFF)
		ASSERT(align_off >= prevp->br_startoff + prevp->br_blockcount);
#endif

	*lenp = align_alen;
	*offp = align_off;
	return 0;
}

#define SCXFS_ALLOC_GAP_UNITS	4

void
scxfs_bmap_adjacent(
	struct scxfs_bmalloca	*ap)	/* bmap alloc argument struct */
{
	scxfs_fsblock_t	adjust;		/* adjustment to block numbers */
	scxfs_agnumber_t	fb_agno;	/* ag number of ap->firstblock */
	scxfs_mount_t	*mp;		/* mount point structure */
	int		nullfb;		/* true if ap->firstblock isn't set */
	int		rt;		/* true if inode is realtime */

#define	ISVALID(x,y)	\
	(rt ? \
		(x) < mp->m_sb.sb_rblocks : \
		SCXFS_FSB_TO_AGNO(mp, x) == SCXFS_FSB_TO_AGNO(mp, y) && \
		SCXFS_FSB_TO_AGNO(mp, x) < mp->m_sb.sb_agcount && \
		SCXFS_FSB_TO_AGBNO(mp, x) < mp->m_sb.sb_agblocks)

	mp = ap->ip->i_mount;
	nullfb = ap->tp->t_firstblock == NULLFSBLOCK;
	rt = SCXFS_IS_REALTIME_INODE(ap->ip) &&
		scxfs_alloc_is_userdata(ap->datatype);
	fb_agno = nullfb ? NULLAGNUMBER : SCXFS_FSB_TO_AGNO(mp,
							ap->tp->t_firstblock);
	/*
	 * If allocating at eof, and there's a previous real block,
	 * try to use its last block as our starting point.
	 */
	if (ap->eof && ap->prev.br_startoff != NULLFILEOFF &&
	    !isnullstartblock(ap->prev.br_startblock) &&
	    ISVALID(ap->prev.br_startblock + ap->prev.br_blockcount,
		    ap->prev.br_startblock)) {
		ap->blkno = ap->prev.br_startblock + ap->prev.br_blockcount;
		/*
		 * Adjust for the gap between prevp and us.
		 */
		adjust = ap->offset -
			(ap->prev.br_startoff + ap->prev.br_blockcount);
		if (adjust &&
		    ISVALID(ap->blkno + adjust, ap->prev.br_startblock))
			ap->blkno += adjust;
	}
	/*
	 * If not at eof, then compare the two neighbor blocks.
	 * Figure out whether either one gives us a good starting point,
	 * and pick the better one.
	 */
	else if (!ap->eof) {
		scxfs_fsblock_t	gotbno;		/* right side block number */
		scxfs_fsblock_t	gotdiff=0;	/* right side difference */
		scxfs_fsblock_t	prevbno;	/* left side block number */
		scxfs_fsblock_t	prevdiff=0;	/* left side difference */

		/*
		 * If there's a previous (left) block, select a requested
		 * start block based on it.
		 */
		if (ap->prev.br_startoff != NULLFILEOFF &&
		    !isnullstartblock(ap->prev.br_startblock) &&
		    (prevbno = ap->prev.br_startblock +
			       ap->prev.br_blockcount) &&
		    ISVALID(prevbno, ap->prev.br_startblock)) {
			/*
			 * Calculate gap to end of previous block.
			 */
			adjust = prevdiff = ap->offset -
				(ap->prev.br_startoff +
				 ap->prev.br_blockcount);
			/*
			 * Figure the startblock based on the previous block's
			 * end and the gap size.
			 * Heuristic!
			 * If the gap is large relative to the piece we're
			 * allocating, or using it gives us an invalid block
			 * number, then just use the end of the previous block.
			 */
			if (prevdiff <= SCXFS_ALLOC_GAP_UNITS * ap->length &&
			    ISVALID(prevbno + prevdiff,
				    ap->prev.br_startblock))
				prevbno += adjust;
			else
				prevdiff += adjust;
			/*
			 * If the firstblock forbids it, can't use it,
			 * must use default.
			 */
			if (!rt && !nullfb &&
			    SCXFS_FSB_TO_AGNO(mp, prevbno) != fb_agno)
				prevbno = NULLFSBLOCK;
		}
		/*
		 * No previous block or can't follow it, just default.
		 */
		else
			prevbno = NULLFSBLOCK;
		/*
		 * If there's a following (right) block, select a requested
		 * start block based on it.
		 */
		if (!isnullstartblock(ap->got.br_startblock)) {
			/*
			 * Calculate gap to start of next block.
			 */
			adjust = gotdiff = ap->got.br_startoff - ap->offset;
			/*
			 * Figure the startblock based on the next block's
			 * start and the gap size.
			 */
			gotbno = ap->got.br_startblock;
			/*
			 * Heuristic!
			 * If the gap is large relative to the piece we're
			 * allocating, or using it gives us an invalid block
			 * number, then just use the start of the next block
			 * offset by our length.
			 */
			if (gotdiff <= SCXFS_ALLOC_GAP_UNITS * ap->length &&
			    ISVALID(gotbno - gotdiff, gotbno))
				gotbno -= adjust;
			else if (ISVALID(gotbno - ap->length, gotbno)) {
				gotbno -= ap->length;
				gotdiff += adjust - ap->length;
			} else
				gotdiff += adjust;
			/*
			 * If the firstblock forbids it, can't use it,
			 * must use default.
			 */
			if (!rt && !nullfb &&
			    SCXFS_FSB_TO_AGNO(mp, gotbno) != fb_agno)
				gotbno = NULLFSBLOCK;
		}
		/*
		 * No next block, just default.
		 */
		else
			gotbno = NULLFSBLOCK;
		/*
		 * If both valid, pick the better one, else the only good
		 * one, else ap->blkno is already set (to 0 or the inode block).
		 */
		if (prevbno != NULLFSBLOCK && gotbno != NULLFSBLOCK)
			ap->blkno = prevdiff <= gotdiff ? prevbno : gotbno;
		else if (prevbno != NULLFSBLOCK)
			ap->blkno = prevbno;
		else if (gotbno != NULLFSBLOCK)
			ap->blkno = gotbno;
	}
#undef ISVALID
}

static int
scxfs_bmap_longest_free_extent(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		ag,
	scxfs_extlen_t		*blen,
	int			*notinit)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	struct scxfs_perag	*pag;
	scxfs_extlen_t		longest;
	int			error = 0;

	pag = scxfs_perag_get(mp, ag);
	if (!pag->pagf_init) {
		error = scxfs_alloc_pagf_init(mp, tp, ag, SCXFS_ALLOC_FLAG_TRYLOCK);
		if (error)
			goto out;

		if (!pag->pagf_init) {
			*notinit = 1;
			goto out;
		}
	}

	longest = scxfs_alloc_longest_free_extent(pag,
				scxfs_alloc_min_freelist(mp, pag),
				scxfs_ag_resv_needed(pag, SCXFS_AG_RESV_NONE));
	if (*blen < longest)
		*blen = longest;

out:
	scxfs_perag_put(pag);
	return error;
}

static void
scxfs_bmap_select_minlen(
	struct scxfs_bmalloca	*ap,
	struct scxfs_alloc_arg	*args,
	scxfs_extlen_t		*blen,
	int			notinit)
{
	if (notinit || *blen < ap->minlen) {
		/*
		 * Since we did a BUF_TRYLOCK above, it is possible that
		 * there is space for this request.
		 */
		args->minlen = ap->minlen;
	} else if (*blen < args->maxlen) {
		/*
		 * If the best seen length is less than the request length,
		 * use the best as the minimum.
		 */
		args->minlen = *blen;
	} else {
		/*
		 * Otherwise we've seen an extent as big as maxlen, use that
		 * as the minimum.
		 */
		args->minlen = args->maxlen;
	}
}

STATIC int
scxfs_bmap_btalloc_nullfb(
	struct scxfs_bmalloca	*ap,
	struct scxfs_alloc_arg	*args,
	scxfs_extlen_t		*blen)
{
	struct scxfs_mount	*mp = ap->ip->i_mount;
	scxfs_agnumber_t		ag, startag;
	int			notinit = 0;
	int			error;

	args->type = SCXFS_ALLOCTYPE_START_BNO;
	args->total = ap->total;

	startag = ag = SCXFS_FSB_TO_AGNO(mp, args->fsbno);
	if (startag == NULLAGNUMBER)
		startag = ag = 0;

	while (*blen < args->maxlen) {
		error = scxfs_bmap_longest_free_extent(args->tp, ag, blen,
						     &notinit);
		if (error)
			return error;

		if (++ag == mp->m_sb.sb_agcount)
			ag = 0;
		if (ag == startag)
			break;
	}

	scxfs_bmap_select_minlen(ap, args, blen, notinit);
	return 0;
}

STATIC int
scxfs_bmap_btalloc_filestreams(
	struct scxfs_bmalloca	*ap,
	struct scxfs_alloc_arg	*args,
	scxfs_extlen_t		*blen)
{
	struct scxfs_mount	*mp = ap->ip->i_mount;
	scxfs_agnumber_t		ag;
	int			notinit = 0;
	int			error;

	args->type = SCXFS_ALLOCTYPE_NEAR_BNO;
	args->total = ap->total;

	ag = SCXFS_FSB_TO_AGNO(mp, args->fsbno);
	if (ag == NULLAGNUMBER)
		ag = 0;

	error = scxfs_bmap_longest_free_extent(args->tp, ag, blen, &notinit);
	if (error)
		return error;

	if (*blen < args->maxlen) {
		error = scxfs_filestream_new_ag(ap, &ag);
		if (error)
			return error;

		error = scxfs_bmap_longest_free_extent(args->tp, ag, blen,
						     &notinit);
		if (error)
			return error;

	}

	scxfs_bmap_select_minlen(ap, args, blen, notinit);

	/*
	 * Set the failure fallback case to look in the selected AG as stream
	 * may have moved.
	 */
	ap->blkno = args->fsbno = SCXFS_AGB_TO_FSB(mp, ag, 0);
	return 0;
}

/* Update all inode and quota accounting for the allocation we just did. */
static void
scxfs_bmap_btalloc_accounting(
	struct scxfs_bmalloca	*ap,
	struct scxfs_alloc_arg	*args)
{
	if (ap->flags & SCXFS_BMAPI_COWFORK) {
		/*
		 * COW fork blocks are in-core only and thus are treated as
		 * in-core quota reservation (like delalloc blocks) even when
		 * converted to real blocks. The quota reservation is not
		 * accounted to disk until blocks are remapped to the data
		 * fork. So if these blocks were previously delalloc, we
		 * already have quota reservation and there's nothing to do
		 * yet.
		 */
		if (ap->wasdel) {
			scxfs_mod_delalloc(ap->ip->i_mount, -(int64_t)args->len);
			return;
		}

		/*
		 * Otherwise, we've allocated blocks in a hole. The transaction
		 * has acquired in-core quota reservation for this extent.
		 * Rather than account these as real blocks, however, we reduce
		 * the transaction quota reservation based on the allocation.
		 * This essentially transfers the transaction quota reservation
		 * to that of a delalloc extent.
		 */
		ap->ip->i_delayed_blks += args->len;
		scxfs_trans_mod_dquot_byino(ap->tp, ap->ip, SCXFS_TRANS_DQ_RES_BLKS,
				-(long)args->len);
		return;
	}

	/* data/attr fork only */
	ap->ip->i_d.di_nblocks += args->len;
	scxfs_trans_log_inode(ap->tp, ap->ip, SCXFS_ILOG_CORE);
	if (ap->wasdel) {
		ap->ip->i_delayed_blks -= args->len;
		scxfs_mod_delalloc(ap->ip->i_mount, -(int64_t)args->len);
	}
	scxfs_trans_mod_dquot_byino(ap->tp, ap->ip,
		ap->wasdel ? SCXFS_TRANS_DQ_DELBCOUNT : SCXFS_TRANS_DQ_BCOUNT,
		args->len);
}

STATIC int
scxfs_bmap_btalloc(
	struct scxfs_bmalloca	*ap)	/* bmap alloc argument struct */
{
	scxfs_mount_t	*mp;		/* mount point structure */
	scxfs_alloctype_t	atype = 0;	/* type for allocation routines */
	scxfs_extlen_t	align = 0;	/* minimum allocation alignment */
	scxfs_agnumber_t	fb_agno;	/* ag number of ap->firstblock */
	scxfs_agnumber_t	ag;
	scxfs_alloc_arg_t	args;
	scxfs_fileoff_t	orig_offset;
	scxfs_extlen_t	orig_length;
	scxfs_extlen_t	blen;
	scxfs_extlen_t	nextminlen = 0;
	int		nullfb;		/* true if ap->firstblock isn't set */
	int		isaligned;
	int		tryagain;
	int		error;
	int		stripe_align;

	ASSERT(ap->length);
	orig_offset = ap->offset;
	orig_length = ap->length;

	mp = ap->ip->i_mount;

	/* stripe alignment for allocation is determined by mount parameters */
	stripe_align = 0;
	if (mp->m_swidth && (mp->m_flags & SCXFS_MOUNT_SWALLOC))
		stripe_align = mp->m_swidth;
	else if (mp->m_dalign)
		stripe_align = mp->m_dalign;

	if (ap->flags & SCXFS_BMAPI_COWFORK)
		align = scxfs_get_cowextsz_hint(ap->ip);
	else if (scxfs_alloc_is_userdata(ap->datatype))
		align = scxfs_get_extsz_hint(ap->ip);
	if (align) {
		error = scxfs_bmap_extsize_align(mp, &ap->got, &ap->prev,
						align, 0, ap->eof, 0, ap->conv,
						&ap->offset, &ap->length);
		ASSERT(!error);
		ASSERT(ap->length);
	}


	nullfb = ap->tp->t_firstblock == NULLFSBLOCK;
	fb_agno = nullfb ? NULLAGNUMBER : SCXFS_FSB_TO_AGNO(mp,
							ap->tp->t_firstblock);
	if (nullfb) {
		if (scxfs_alloc_is_userdata(ap->datatype) &&
		    scxfs_inode_is_filestream(ap->ip)) {
			ag = scxfs_filestream_lookup_ag(ap->ip);
			ag = (ag != NULLAGNUMBER) ? ag : 0;
			ap->blkno = SCXFS_AGB_TO_FSB(mp, ag, 0);
		} else {
			ap->blkno = SCXFS_INO_TO_FSB(mp, ap->ip->i_ino);
		}
	} else
		ap->blkno = ap->tp->t_firstblock;

	scxfs_bmap_adjacent(ap);

	/*
	 * If allowed, use ap->blkno; otherwise must use firstblock since
	 * it's in the right allocation group.
	 */
	if (nullfb || SCXFS_FSB_TO_AGNO(mp, ap->blkno) == fb_agno)
		;
	else
		ap->blkno = ap->tp->t_firstblock;
	/*
	 * Normal allocation, done through scxfs_alloc_vextent.
	 */
	tryagain = isaligned = 0;
	memset(&args, 0, sizeof(args));
	args.tp = ap->tp;
	args.mp = mp;
	args.fsbno = ap->blkno;
	args.oinfo = SCXFS_RMAP_OINFO_SKIP_UPDATE;

	/* Trim the allocation back to the maximum an AG can fit. */
	args.maxlen = min(ap->length, mp->m_ag_max_usable);
	blen = 0;
	if (nullfb) {
		/*
		 * Search for an allocation group with a single extent large
		 * enough for the request.  If one isn't found, then adjust
		 * the minimum allocation size to the largest space found.
		 */
		if (scxfs_alloc_is_userdata(ap->datatype) &&
		    scxfs_inode_is_filestream(ap->ip))
			error = scxfs_bmap_btalloc_filestreams(ap, &args, &blen);
		else
			error = scxfs_bmap_btalloc_nullfb(ap, &args, &blen);
		if (error)
			return error;
	} else if (ap->tp->t_flags & SCXFS_TRANS_LOWMODE) {
		if (scxfs_inode_is_filestream(ap->ip))
			args.type = SCXFS_ALLOCTYPE_FIRST_AG;
		else
			args.type = SCXFS_ALLOCTYPE_START_BNO;
		args.total = args.minlen = ap->minlen;
	} else {
		args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
		args.total = ap->total;
		args.minlen = ap->minlen;
	}
	/* apply extent size hints if obtained earlier */
	if (align) {
		args.prod = align;
		div_u64_rem(ap->offset, args.prod, &args.mod);
		if (args.mod)
			args.mod = args.prod - args.mod;
	} else if (mp->m_sb.sb_blocksize >= PAGE_SIZE) {
		args.prod = 1;
		args.mod = 0;
	} else {
		args.prod = PAGE_SIZE >> mp->m_sb.sb_blocklog;
		div_u64_rem(ap->offset, args.prod, &args.mod);
		if (args.mod)
			args.mod = args.prod - args.mod;
	}
	/*
	 * If we are not low on available data blocks, and the
	 * underlying logical volume manager is a stripe, and
	 * the file offset is zero then try to allocate data
	 * blocks on stripe unit boundary.
	 * NOTE: ap->aeof is only set if the allocation length
	 * is >= the stripe unit and the allocation offset is
	 * at the end of file.
	 */
	if (!(ap->tp->t_flags & SCXFS_TRANS_LOWMODE) && ap->aeof) {
		if (!ap->offset) {
			args.alignment = stripe_align;
			atype = args.type;
			isaligned = 1;
			/*
			 * Adjust for alignment
			 */
			if (blen > args.alignment && blen <= args.maxlen)
				args.minlen = blen - args.alignment;
			args.minalignslop = 0;
		} else {
			/*
			 * First try an exact bno allocation.
			 * If it fails then do a near or start bno
			 * allocation with alignment turned on.
			 */
			atype = args.type;
			tryagain = 1;
			args.type = SCXFS_ALLOCTYPE_THIS_BNO;
			args.alignment = 1;
			/*
			 * Compute the minlen+alignment for the
			 * next case.  Set slop so that the value
			 * of minlen+alignment+slop doesn't go up
			 * between the calls.
			 */
			if (blen > stripe_align && blen <= args.maxlen)
				nextminlen = blen - stripe_align;
			else
				nextminlen = args.minlen;
			if (nextminlen + stripe_align > args.minlen + 1)
				args.minalignslop =
					nextminlen + stripe_align -
					args.minlen - 1;
			else
				args.minalignslop = 0;
		}
	} else {
		args.alignment = 1;
		args.minalignslop = 0;
	}
	args.minleft = ap->minleft;
	args.wasdel = ap->wasdel;
	args.resv = SCXFS_AG_RESV_NONE;
	args.datatype = ap->datatype;
	if (ap->datatype & SCXFS_ALLOC_USERDATA_ZERO)
		args.ip = ap->ip;

	error = scxfs_alloc_vextent(&args);
	if (error)
		return error;

	if (tryagain && args.fsbno == NULLFSBLOCK) {
		/*
		 * Exact allocation failed. Now try with alignment
		 * turned on.
		 */
		args.type = atype;
		args.fsbno = ap->blkno;
		args.alignment = stripe_align;
		args.minlen = nextminlen;
		args.minalignslop = 0;
		isaligned = 1;
		if ((error = scxfs_alloc_vextent(&args)))
			return error;
	}
	if (isaligned && args.fsbno == NULLFSBLOCK) {
		/*
		 * allocation failed, so turn off alignment and
		 * try again.
		 */
		args.type = atype;
		args.fsbno = ap->blkno;
		args.alignment = 0;
		if ((error = scxfs_alloc_vextent(&args)))
			return error;
	}
	if (args.fsbno == NULLFSBLOCK && nullfb &&
	    args.minlen > ap->minlen) {
		args.minlen = ap->minlen;
		args.type = SCXFS_ALLOCTYPE_START_BNO;
		args.fsbno = ap->blkno;
		if ((error = scxfs_alloc_vextent(&args)))
			return error;
	}
	if (args.fsbno == NULLFSBLOCK && nullfb) {
		args.fsbno = 0;
		args.type = SCXFS_ALLOCTYPE_FIRST_AG;
		args.total = ap->minlen;
		if ((error = scxfs_alloc_vextent(&args)))
			return error;
		ap->tp->t_flags |= SCXFS_TRANS_LOWMODE;
	}
	if (args.fsbno != NULLFSBLOCK) {
		/*
		 * check the allocation happened at the same or higher AG than
		 * the first block that was allocated.
		 */
		ASSERT(ap->tp->t_firstblock == NULLFSBLOCK ||
		       SCXFS_FSB_TO_AGNO(mp, ap->tp->t_firstblock) <=
		       SCXFS_FSB_TO_AGNO(mp, args.fsbno));

		ap->blkno = args.fsbno;
		if (ap->tp->t_firstblock == NULLFSBLOCK)
			ap->tp->t_firstblock = args.fsbno;
		ASSERT(nullfb || fb_agno <= args.agno);
		ap->length = args.len;
		/*
		 * If the extent size hint is active, we tried to round the
		 * caller's allocation request offset down to extsz and the
		 * length up to another extsz boundary.  If we found a free
		 * extent we mapped it in starting at this new offset.  If the
		 * newly mapped space isn't long enough to cover any of the
		 * range of offsets that was originally requested, move the
		 * mapping up so that we can fill as much of the caller's
		 * original request as possible.  Free space is apparently
		 * very fragmented so we're unlikely to be able to satisfy the
		 * hints anyway.
		 */
		if (ap->length <= orig_length)
			ap->offset = orig_offset;
		else if (ap->offset + ap->length < orig_offset + orig_length)
			ap->offset = orig_offset + orig_length - ap->length;
		scxfs_bmap_btalloc_accounting(ap, &args);
	} else {
		ap->blkno = NULLFSBLOCK;
		ap->length = 0;
	}
	return 0;
}

/*
 * scxfs_bmap_alloc is called by scxfs_bmapi to allocate an extent for a file.
 * It figures out where to ask the underlying allocator to put the new extent.
 */
STATIC int
scxfs_bmap_alloc(
	struct scxfs_bmalloca	*ap)	/* bmap alloc argument struct */
{
	if (SCXFS_IS_REALTIME_INODE(ap->ip) &&
	    scxfs_alloc_is_userdata(ap->datatype))
		return scxfs_bmap_rtalloc(ap);
	return scxfs_bmap_btalloc(ap);
}

/* Trim extent to fit a logical block range. */
void
scxfs_trim_extent(
	struct scxfs_bmbt_irec	*irec,
	scxfs_fileoff_t		bno,
	scxfs_filblks_t		len)
{
	scxfs_fileoff_t		distance;
	scxfs_fileoff_t		end = bno + len;

	if (irec->br_startoff + irec->br_blockcount <= bno ||
	    irec->br_startoff >= end) {
		irec->br_blockcount = 0;
		return;
	}

	if (irec->br_startoff < bno) {
		distance = bno - irec->br_startoff;
		if (isnullstartblock(irec->br_startblock))
			irec->br_startblock = DELAYSTARTBLOCK;
		if (irec->br_startblock != DELAYSTARTBLOCK &&
		    irec->br_startblock != HOLESTARTBLOCK)
			irec->br_startblock += distance;
		irec->br_startoff += distance;
		irec->br_blockcount -= distance;
	}

	if (end < irec->br_startoff + irec->br_blockcount) {
		distance = irec->br_startoff + irec->br_blockcount - end;
		irec->br_blockcount -= distance;
	}
}

/*
 * Trim the returned map to the required bounds
 */
STATIC void
scxfs_bmapi_trim_map(
	struct scxfs_bmbt_irec	*mval,
	struct scxfs_bmbt_irec	*got,
	scxfs_fileoff_t		*bno,
	scxfs_filblks_t		len,
	scxfs_fileoff_t		obno,
	scxfs_fileoff_t		end,
	int			n,
	int			flags)
{
	if ((flags & SCXFS_BMAPI_ENTIRE) ||
	    got->br_startoff + got->br_blockcount <= obno) {
		*mval = *got;
		if (isnullstartblock(got->br_startblock))
			mval->br_startblock = DELAYSTARTBLOCK;
		return;
	}

	if (obno > *bno)
		*bno = obno;
	ASSERT((*bno >= obno) || (n == 0));
	ASSERT(*bno < end);
	mval->br_startoff = *bno;
	if (isnullstartblock(got->br_startblock))
		mval->br_startblock = DELAYSTARTBLOCK;
	else
		mval->br_startblock = got->br_startblock +
					(*bno - got->br_startoff);
	/*
	 * Return the minimum of what we got and what we asked for for
	 * the length.  We can use the len variable here because it is
	 * modified below and we could have been there before coming
	 * here if the first part of the allocation didn't overlap what
	 * was asked for.
	 */
	mval->br_blockcount = SCXFS_FILBLKS_MIN(end - *bno,
			got->br_blockcount - (*bno - got->br_startoff));
	mval->br_state = got->br_state;
	ASSERT(mval->br_blockcount <= len);
	return;
}

/*
 * Update and validate the extent map to return
 */
STATIC void
scxfs_bmapi_update_map(
	struct scxfs_bmbt_irec	**map,
	scxfs_fileoff_t		*bno,
	scxfs_filblks_t		*len,
	scxfs_fileoff_t		obno,
	scxfs_fileoff_t		end,
	int			*n,
	int			flags)
{
	scxfs_bmbt_irec_t	*mval = *map;

	ASSERT((flags & SCXFS_BMAPI_ENTIRE) ||
	       ((mval->br_startoff + mval->br_blockcount) <= end));
	ASSERT((flags & SCXFS_BMAPI_ENTIRE) || (mval->br_blockcount <= *len) ||
	       (mval->br_startoff < obno));

	*bno = mval->br_startoff + mval->br_blockcount;
	*len = end - *bno;
	if (*n > 0 && mval->br_startoff == mval[-1].br_startoff) {
		/* update previous map with new information */
		ASSERT(mval->br_startblock == mval[-1].br_startblock);
		ASSERT(mval->br_blockcount > mval[-1].br_blockcount);
		ASSERT(mval->br_state == mval[-1].br_state);
		mval[-1].br_blockcount = mval->br_blockcount;
		mval[-1].br_state = mval->br_state;
	} else if (*n > 0 && mval->br_startblock != DELAYSTARTBLOCK &&
		   mval[-1].br_startblock != DELAYSTARTBLOCK &&
		   mval[-1].br_startblock != HOLESTARTBLOCK &&
		   mval->br_startblock == mval[-1].br_startblock +
					  mval[-1].br_blockcount &&
		   mval[-1].br_state == mval->br_state) {
		ASSERT(mval->br_startoff ==
		       mval[-1].br_startoff + mval[-1].br_blockcount);
		mval[-1].br_blockcount += mval->br_blockcount;
	} else if (*n > 0 &&
		   mval->br_startblock == DELAYSTARTBLOCK &&
		   mval[-1].br_startblock == DELAYSTARTBLOCK &&
		   mval->br_startoff ==
		   mval[-1].br_startoff + mval[-1].br_blockcount) {
		mval[-1].br_blockcount += mval->br_blockcount;
		mval[-1].br_state = mval->br_state;
	} else if (!((*n == 0) &&
		     ((mval->br_startoff + mval->br_blockcount) <=
		      obno))) {
		mval++;
		(*n)++;
	}
	*map = mval;
}

/*
 * Map file blocks to filesystem blocks without allocation.
 */
int
scxfs_bmapi_read(
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		bno,
	scxfs_filblks_t		len,
	struct scxfs_bmbt_irec	*mval,
	int			*nmap,
	int			flags)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp;
	struct scxfs_bmbt_irec	got;
	scxfs_fileoff_t		obno;
	scxfs_fileoff_t		end;
	struct scxfs_iext_cursor	icur;
	int			error;
	bool			eof = false;
	int			n = 0;
	int			whichfork = scxfs_bmapi_whichfork(flags);

	ASSERT(*nmap >= 1);
	ASSERT(!(flags & ~(SCXFS_BMAPI_ATTRFORK|SCXFS_BMAPI_ENTIRE|
			   SCXFS_BMAPI_COWFORK)));
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_SHARED|SCXFS_ILOCK_EXCL));

	if (unlikely(SCXFS_TEST_ERROR(
	    (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	     SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE),
	     mp, SCXFS_ERRTAG_BMAPIFORMAT))) {
		SCXFS_ERROR_REPORT("scxfs_bmapi_read", SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	SCXFS_STATS_INC(mp, xs_blk_mapr);

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	if (!ifp) {
		/* No CoW fork?  Return a hole. */
		if (whichfork == SCXFS_COW_FORK) {
			mval->br_startoff = bno;
			mval->br_startblock = HOLESTARTBLOCK;
			mval->br_blockcount = len;
			mval->br_state = SCXFS_EXT_NORM;
			*nmap = 1;
			return 0;
		}

		/*
		 * A missing attr ifork implies that the inode says we're in
		 * extents or btree format but failed to pass the inode fork
		 * verifier while trying to load it.  Treat that as a file
		 * corruption too.
		 */
#ifdef DEBUG
		scxfs_alert(mp, "%s: inode %llu missing fork %d",
				__func__, ip->i_ino, whichfork);
#endif /* DEBUG */
		return -EFSCORRUPTED;
	}

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(NULL, ip, whichfork);
		if (error)
			return error;
	}

	if (!scxfs_iext_lookup_extent(ip, ifp, bno, &icur, &got))
		eof = true;
	end = bno + len;
	obno = bno;

	while (bno < end && n < *nmap) {
		/* Reading past eof, act as though there's a hole up to end. */
		if (eof)
			got.br_startoff = end;
		if (got.br_startoff > bno) {
			/* Reading in a hole.  */
			mval->br_startoff = bno;
			mval->br_startblock = HOLESTARTBLOCK;
			mval->br_blockcount =
				SCXFS_FILBLKS_MIN(len, got.br_startoff - bno);
			mval->br_state = SCXFS_EXT_NORM;
			bno += mval->br_blockcount;
			len -= mval->br_blockcount;
			mval++;
			n++;
			continue;
		}

		/* set up the extent map to return. */
		scxfs_bmapi_trim_map(mval, &got, &bno, len, obno, end, n, flags);
		scxfs_bmapi_update_map(&mval, &bno, &len, obno, end, &n, flags);

		/* If we're done, stop now. */
		if (bno >= end || n >= *nmap)
			break;

		/* Else go on to the next record. */
		if (!scxfs_iext_next_extent(ifp, &icur, &got))
			eof = true;
	}
	*nmap = n;
	return 0;
}

/*
 * Add a delayed allocation extent to an inode. Blocks are reserved from the
 * global pool and the extent inserted into the inode in-core extent tree.
 *
 * On entry, got refers to the first extent beyond the offset of the extent to
 * allocate or eof is specified if no such extent exists. On return, got refers
 * to the extent record that was inserted to the inode fork.
 *
 * Note that the allocated extent may have been merged with contiguous extents
 * during insertion into the inode fork. Thus, got does not reflect the current
 * state of the inode fork on return. If necessary, the caller can use lastx to
 * look up the updated record in the inode fork.
 */
int
scxfs_bmapi_reserve_delalloc(
	struct scxfs_inode	*ip,
	int			whichfork,
	scxfs_fileoff_t		off,
	scxfs_filblks_t		len,
	scxfs_filblks_t		prealloc,
	struct scxfs_bmbt_irec	*got,
	struct scxfs_iext_cursor	*icur,
	int			eof)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	scxfs_extlen_t		alen;
	scxfs_extlen_t		indlen;
	int			error;
	scxfs_fileoff_t		aoff = off;

	/*
	 * Cap the alloc length. Keep track of prealloc so we know whether to
	 * tag the inode before we return.
	 */
	alen = SCXFS_FILBLKS_MIN(len + prealloc, MAXEXTLEN);
	if (!eof)
		alen = SCXFS_FILBLKS_MIN(alen, got->br_startoff - aoff);
	if (prealloc && alen >= len)
		prealloc = alen - len;

	/* Figure out the extent size, adjust alen */
	if (whichfork == SCXFS_COW_FORK) {
		struct scxfs_bmbt_irec	prev;
		scxfs_extlen_t		extsz = scxfs_get_cowextsz_hint(ip);

		if (!scxfs_iext_peek_prev_extent(ifp, icur, &prev))
			prev.br_startoff = NULLFILEOFF;

		error = scxfs_bmap_extsize_align(mp, got, &prev, extsz, 0, eof,
					       1, 0, &aoff, &alen);
		ASSERT(!error);
	}

	/*
	 * Make a transaction-less quota reservation for delayed allocation
	 * blocks.  This number gets adjusted later.  We return if we haven't
	 * allocated blocks already inside this loop.
	 */
	error = scxfs_trans_reserve_quota_nblks(NULL, ip, (long)alen, 0,
						SCXFS_QMOPT_RES_REGBLKS);
	if (error)
		return error;

	/*
	 * Split changing sb for alen and indlen since they could be coming
	 * from different places.
	 */
	indlen = (scxfs_extlen_t)scxfs_bmap_worst_indlen(ip, alen);
	ASSERT(indlen > 0);

	error = scxfs_mod_fdblocks(mp, -((int64_t)alen), false);
	if (error)
		goto out_unreserve_quota;

	error = scxfs_mod_fdblocks(mp, -((int64_t)indlen), false);
	if (error)
		goto out_unreserve_blocks;


	ip->i_delayed_blks += alen;
	scxfs_mod_delalloc(ip->i_mount, alen + indlen);

	got->br_startoff = aoff;
	got->br_startblock = nullstartblock(indlen);
	got->br_blockcount = alen;
	got->br_state = SCXFS_EXT_NORM;

	scxfs_bmap_add_extent_hole_delay(ip, whichfork, icur, got);

	/*
	 * Tag the inode if blocks were preallocated. Note that COW fork
	 * preallocation can occur at the start or end of the extent, even when
	 * prealloc == 0, so we must also check the aligned offset and length.
	 */
	if (whichfork == SCXFS_DATA_FORK && prealloc)
		scxfs_inode_set_eofblocks_tag(ip);
	if (whichfork == SCXFS_COW_FORK && (prealloc || aoff < off || alen > len))
		scxfs_inode_set_cowblocks_tag(ip);

	return 0;

out_unreserve_blocks:
	scxfs_mod_fdblocks(mp, alen, false);
out_unreserve_quota:
	if (SCXFS_IS_QUOTA_ON(mp))
		scxfs_trans_unreserve_quota_nblks(NULL, ip, (long)alen, 0,
						SCXFS_QMOPT_RES_REGBLKS);
	return error;
}

static int
scxfs_bmapi_allocate(
	struct scxfs_bmalloca	*bma)
{
	struct scxfs_mount	*mp = bma->ip->i_mount;
	int			whichfork = scxfs_bmapi_whichfork(bma->flags);
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(bma->ip, whichfork);
	int			tmp_logflags = 0;
	int			error;

	ASSERT(bma->length > 0);

	/*
	 * For the wasdelay case, we could also just allocate the stuff asked
	 * for in this bmap call but that wouldn't be as good.
	 */
	if (bma->wasdel) {
		bma->length = (scxfs_extlen_t)bma->got.br_blockcount;
		bma->offset = bma->got.br_startoff;
		scxfs_iext_peek_prev_extent(ifp, &bma->icur, &bma->prev);
	} else {
		bma->length = SCXFS_FILBLKS_MIN(bma->length, MAXEXTLEN);
		if (!bma->eof)
			bma->length = SCXFS_FILBLKS_MIN(bma->length,
					bma->got.br_startoff - bma->offset);
	}

	/*
	 * Set the data type being allocated. For the data fork, the first data
	 * in the file is treated differently to all other allocations. For the
	 * attribute fork, we only need to ensure the allocated range is not on
	 * the busy list.
	 */
	if (!(bma->flags & SCXFS_BMAPI_METADATA)) {
		bma->datatype = SCXFS_ALLOC_NOBUSY;
		if (whichfork == SCXFS_DATA_FORK) {
			if (bma->offset == 0)
				bma->datatype |= SCXFS_ALLOC_INITIAL_USER_DATA;
			else
				bma->datatype |= SCXFS_ALLOC_USERDATA;
		}
		if (bma->flags & SCXFS_BMAPI_ZERO)
			bma->datatype |= SCXFS_ALLOC_USERDATA_ZERO;
	}

	bma->minlen = (bma->flags & SCXFS_BMAPI_CONTIG) ? bma->length : 1;

	/*
	 * Only want to do the alignment at the eof if it is userdata and
	 * allocation length is larger than a stripe unit.
	 */
	if (mp->m_dalign && bma->length >= mp->m_dalign &&
	    !(bma->flags & SCXFS_BMAPI_METADATA) && whichfork == SCXFS_DATA_FORK) {
		error = scxfs_bmap_isaeof(bma, whichfork);
		if (error)
			return error;
	}

	error = scxfs_bmap_alloc(bma);
	if (error)
		return error;

	if (bma->blkno == NULLFSBLOCK)
		return 0;
	if ((ifp->if_flags & SCXFS_IFBROOT) && !bma->cur)
		bma->cur = scxfs_bmbt_init_cursor(mp, bma->tp, bma->ip, whichfork);
	/*
	 * Bump the number of extents we've allocated
	 * in this call.
	 */
	bma->nallocs++;

	if (bma->cur)
		bma->cur->bc_private.b.flags =
			bma->wasdel ? SCXFS_BTCUR_BPRV_WASDEL : 0;

	bma->got.br_startoff = bma->offset;
	bma->got.br_startblock = bma->blkno;
	bma->got.br_blockcount = bma->length;
	bma->got.br_state = SCXFS_EXT_NORM;

	/*
	 * In the data fork, a wasdelay extent has been initialized, so
	 * shouldn't be flagged as unwritten.
	 *
	 * For the cow fork, however, we convert delalloc reservations
	 * (extents allocated for speculative preallocation) to
	 * allocated unwritten extents, and only convert the unwritten
	 * extents to real extents when we're about to write the data.
	 */
	if ((!bma->wasdel || (bma->flags & SCXFS_BMAPI_COWFORK)) &&
	    (bma->flags & SCXFS_BMAPI_PREALLOC))
		bma->got.br_state = SCXFS_EXT_UNWRITTEN;

	if (bma->wasdel)
		error = scxfs_bmap_add_extent_delay_real(bma, whichfork);
	else
		error = scxfs_bmap_add_extent_hole_real(bma->tp, bma->ip,
				whichfork, &bma->icur, &bma->cur, &bma->got,
				&bma->logflags, bma->flags);

	bma->logflags |= tmp_logflags;
	if (error)
		return error;

	/*
	 * Update our extent pointer, given that scxfs_bmap_add_extent_delay_real
	 * or scxfs_bmap_add_extent_hole_real might have merged it into one of
	 * the neighbouring ones.
	 */
	scxfs_iext_get_extent(ifp, &bma->icur, &bma->got);

	ASSERT(bma->got.br_startoff <= bma->offset);
	ASSERT(bma->got.br_startoff + bma->got.br_blockcount >=
	       bma->offset + bma->length);
	ASSERT(bma->got.br_state == SCXFS_EXT_NORM ||
	       bma->got.br_state == SCXFS_EXT_UNWRITTEN);
	return 0;
}

STATIC int
scxfs_bmapi_convert_unwritten(
	struct scxfs_bmalloca	*bma,
	struct scxfs_bmbt_irec	*mval,
	scxfs_filblks_t		len,
	int			flags)
{
	int			whichfork = scxfs_bmapi_whichfork(flags);
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(bma->ip, whichfork);
	int			tmp_logflags = 0;
	int			error;

	/* check if we need to do unwritten->real conversion */
	if (mval->br_state == SCXFS_EXT_UNWRITTEN &&
	    (flags & SCXFS_BMAPI_PREALLOC))
		return 0;

	/* check if we need to do real->unwritten conversion */
	if (mval->br_state == SCXFS_EXT_NORM &&
	    (flags & (SCXFS_BMAPI_PREALLOC | SCXFS_BMAPI_CONVERT)) !=
			(SCXFS_BMAPI_PREALLOC | SCXFS_BMAPI_CONVERT))
		return 0;

	/*
	 * Modify (by adding) the state flag, if writing.
	 */
	ASSERT(mval->br_blockcount <= len);
	if ((ifp->if_flags & SCXFS_IFBROOT) && !bma->cur) {
		bma->cur = scxfs_bmbt_init_cursor(bma->ip->i_mount, bma->tp,
					bma->ip, whichfork);
	}
	mval->br_state = (mval->br_state == SCXFS_EXT_UNWRITTEN)
				? SCXFS_EXT_NORM : SCXFS_EXT_UNWRITTEN;

	/*
	 * Before insertion into the bmbt, zero the range being converted
	 * if required.
	 */
	if (flags & SCXFS_BMAPI_ZERO) {
		error = scxfs_zero_extent(bma->ip, mval->br_startblock,
					mval->br_blockcount);
		if (error)
			return error;
	}

	error = scxfs_bmap_add_extent_unwritten_real(bma->tp, bma->ip, whichfork,
			&bma->icur, &bma->cur, mval, &tmp_logflags);
	/*
	 * Log the inode core unconditionally in the unwritten extent conversion
	 * path because the conversion might not have done so (e.g., if the
	 * extent count hasn't changed). We need to make sure the inode is dirty
	 * in the transaction for the sake of fsync(), even if nothing has
	 * changed, because fsync() will not force the log for this transaction
	 * unless it sees the inode pinned.
	 *
	 * Note: If we're only converting cow fork extents, there aren't
	 * any on-disk updates to make, so we don't need to log anything.
	 */
	if (whichfork != SCXFS_COW_FORK)
		bma->logflags |= tmp_logflags | SCXFS_ILOG_CORE;
	if (error)
		return error;

	/*
	 * Update our extent pointer, given that
	 * scxfs_bmap_add_extent_unwritten_real might have merged it into one
	 * of the neighbouring ones.
	 */
	scxfs_iext_get_extent(ifp, &bma->icur, &bma->got);

	/*
	 * We may have combined previously unwritten space with written space,
	 * so generate another request.
	 */
	if (mval->br_blockcount < len)
		return -EAGAIN;
	return 0;
}

static inline scxfs_extlen_t
scxfs_bmapi_minleft(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			fork)
{
	if (tp && tp->t_firstblock != NULLFSBLOCK)
		return 0;
	if (SCXFS_IFORK_FORMAT(ip, fork) != SCXFS_DINODE_FMT_BTREE)
		return 1;
	return be16_to_cpu(SCXFS_IFORK_PTR(ip, fork)->if_broot->bb_level) + 1;
}

/*
 * Log whatever the flags say, even if error.  Otherwise we might miss detecting
 * a case where the data is changed, there's an error, and it's not logged so we
 * don't shutdown when we should.  Don't bother logging extents/btree changes if
 * we converted to the other format.
 */
static void
scxfs_bmapi_finish(
	struct scxfs_bmalloca	*bma,
	int			whichfork,
	int			error)
{
	if ((bma->logflags & scxfs_ilog_fext(whichfork)) &&
	    SCXFS_IFORK_FORMAT(bma->ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS)
		bma->logflags &= ~scxfs_ilog_fext(whichfork);
	else if ((bma->logflags & scxfs_ilog_fbroot(whichfork)) &&
		 SCXFS_IFORK_FORMAT(bma->ip, whichfork) != SCXFS_DINODE_FMT_BTREE)
		bma->logflags &= ~scxfs_ilog_fbroot(whichfork);

	if (bma->logflags)
		scxfs_trans_log_inode(bma->tp, bma->ip, bma->logflags);
	if (bma->cur)
		scxfs_btree_del_cursor(bma->cur, error);
}

/*
 * Map file blocks to filesystem blocks, and allocate blocks or convert the
 * extent state if necessary.  Details behaviour is controlled by the flags
 * parameter.  Only allocates blocks from a single allocation group, to avoid
 * locking problems.
 */
int
scxfs_bmapi_write(
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* incore inode */
	scxfs_fileoff_t		bno,		/* starting file offs. mapped */
	scxfs_filblks_t		len,		/* length to map in file */
	int			flags,		/* SCXFS_BMAPI_... */
	scxfs_extlen_t		total,		/* total blocks needed */
	struct scxfs_bmbt_irec	*mval,		/* output: map values */
	int			*nmap)		/* i/o: mval size/count */
{
	struct scxfs_bmalloca	bma = {
		.tp		= tp,
		.ip		= ip,
		.total		= total,
	};
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp;
	scxfs_fileoff_t		end;		/* end of mapped file region */
	bool			eof = false;	/* after the end of extents */
	int			error;		/* error return */
	int			n;		/* current extent index */
	scxfs_fileoff_t		obno;		/* old block number (offset) */
	int			whichfork;	/* data or attr fork */

#ifdef DEBUG
	scxfs_fileoff_t		orig_bno;	/* original block number value */
	int			orig_flags;	/* original flags arg value */
	scxfs_filblks_t		orig_len;	/* original value of len arg */
	struct scxfs_bmbt_irec	*orig_mval;	/* original value of mval */
	int			orig_nmap;	/* original value of *nmap */

	orig_bno = bno;
	orig_len = len;
	orig_flags = flags;
	orig_mval = mval;
	orig_nmap = *nmap;
#endif
	whichfork = scxfs_bmapi_whichfork(flags);

	ASSERT(*nmap >= 1);
	ASSERT(*nmap <= SCXFS_BMAP_MAX_NMAP);
	ASSERT(tp != NULL);
	ASSERT(len > 0);
	ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_LOCAL);
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(!(flags & SCXFS_BMAPI_REMAP));

	/* zeroing is for currently only for data extents, not metadata */
	ASSERT((flags & (SCXFS_BMAPI_METADATA | SCXFS_BMAPI_ZERO)) !=
			(SCXFS_BMAPI_METADATA | SCXFS_BMAPI_ZERO));
	/*
	 * we can allocate unwritten extents or pre-zero allocated blocks,
	 * but it makes no sense to do both at once. This would result in
	 * zeroing the unwritten extent twice, but it still being an
	 * unwritten extent....
	 */
	ASSERT((flags & (SCXFS_BMAPI_PREALLOC | SCXFS_BMAPI_ZERO)) !=
			(SCXFS_BMAPI_PREALLOC | SCXFS_BMAPI_ZERO));

	if (unlikely(SCXFS_TEST_ERROR(
	    (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	     SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE),
	     mp, SCXFS_ERRTAG_BMAPIFORMAT))) {
		SCXFS_ERROR_REPORT("scxfs_bmapi_write", SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	ifp = SCXFS_IFORK_PTR(ip, whichfork);

	SCXFS_STATS_INC(mp, xs_blk_mapw);

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			goto error0;
	}

	if (!scxfs_iext_lookup_extent(ip, ifp, bno, &bma.icur, &bma.got))
		eof = true;
	if (!scxfs_iext_peek_prev_extent(ifp, &bma.icur, &bma.prev))
		bma.prev.br_startoff = NULLFILEOFF;
	bma.minleft = scxfs_bmapi_minleft(tp, ip, whichfork);

	n = 0;
	end = bno + len;
	obno = bno;
	while (bno < end && n < *nmap) {
		bool			need_alloc = false, wasdelay = false;

		/* in hole or beyond EOF? */
		if (eof || bma.got.br_startoff > bno) {
			/*
			 * CoW fork conversions should /never/ hit EOF or
			 * holes.  There should always be something for us
			 * to work on.
			 */
			ASSERT(!((flags & SCXFS_BMAPI_CONVERT) &&
			         (flags & SCXFS_BMAPI_COWFORK)));

			need_alloc = true;
		} else if (isnullstartblock(bma.got.br_startblock)) {
			wasdelay = true;
		}

		/*
		 * First, deal with the hole before the allocated space
		 * that we found, if any.
		 */
		if (need_alloc || wasdelay) {
			bma.eof = eof;
			bma.conv = !!(flags & SCXFS_BMAPI_CONVERT);
			bma.wasdel = wasdelay;
			bma.offset = bno;
			bma.flags = flags;

			/*
			 * There's a 32/64 bit type mismatch between the
			 * allocation length request (which can be 64 bits in
			 * length) and the bma length request, which is
			 * scxfs_extlen_t and therefore 32 bits. Hence we have to
			 * check for 32-bit overflows and handle them here.
			 */
			if (len > (scxfs_filblks_t)MAXEXTLEN)
				bma.length = MAXEXTLEN;
			else
				bma.length = len;

			ASSERT(len > 0);
			ASSERT(bma.length > 0);
			error = scxfs_bmapi_allocate(&bma);
			if (error)
				goto error0;
			if (bma.blkno == NULLFSBLOCK)
				break;

			/*
			 * If this is a CoW allocation, record the data in
			 * the refcount btree for orphan recovery.
			 */
			if (whichfork == SCXFS_COW_FORK)
				scxfs_refcount_alloc_cow_extent(tp, bma.blkno,
						bma.length);
		}

		/* Deal with the allocated space we found.  */
		scxfs_bmapi_trim_map(mval, &bma.got, &bno, len, obno,
							end, n, flags);

		/* Execute unwritten extent conversion if necessary */
		error = scxfs_bmapi_convert_unwritten(&bma, mval, len, flags);
		if (error == -EAGAIN)
			continue;
		if (error)
			goto error0;

		/* update the extent map to return */
		scxfs_bmapi_update_map(&mval, &bno, &len, obno, end, &n, flags);

		/*
		 * If we're done, stop now.  Stop when we've allocated
		 * SCXFS_BMAP_MAX_NMAP extents no matter what.  Otherwise
		 * the transaction may get too big.
		 */
		if (bno >= end || n >= *nmap || bma.nallocs >= *nmap)
			break;

		/* Else go on to the next record. */
		bma.prev = bma.got;
		if (!scxfs_iext_next_extent(ifp, &bma.icur, &bma.got))
			eof = true;
	}
	*nmap = n;

	error = scxfs_bmap_btree_to_extents(tp, ip, bma.cur, &bma.logflags,
			whichfork);
	if (error)
		goto error0;

	ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE ||
	       SCXFS_IFORK_NEXTENTS(ip, whichfork) >
		SCXFS_IFORK_MAXEXT(ip, whichfork));
	scxfs_bmapi_finish(&bma, whichfork, 0);
	scxfs_bmap_validate_ret(orig_bno, orig_len, orig_flags, orig_mval,
		orig_nmap, *nmap);
	return 0;
error0:
	scxfs_bmapi_finish(&bma, whichfork, error);
	return error;
}

/*
 * Convert an existing delalloc extent to real blocks based on file offset. This
 * attempts to allocate the entire delalloc extent and may require multiple
 * invocations to allocate the target offset if a large enough physical extent
 * is not available.
 */
int
scxfs_bmapi_convert_delalloc(
	struct scxfs_inode	*ip,
	int			whichfork,
	scxfs_fileoff_t		offset_fsb,
	struct scxfs_bmbt_irec	*imap,
	unsigned int		*seq)
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_bmalloca	bma = { NULL };
	struct scxfs_trans	*tp;
	int			error;

	/*
	 * Space for the extent and indirect blocks was reserved when the
	 * delalloc extent was created so there's no need to do so here.
	 */
	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_write, 0, 0,
				SCXFS_TRANS_RESERVE, &tp);
	if (error)
		return error;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, 0);

	if (!scxfs_iext_lookup_extent(ip, ifp, offset_fsb, &bma.icur, &bma.got) ||
	    bma.got.br_startoff > offset_fsb) {
		/*
		 * No extent found in the range we are trying to convert.  This
		 * should only happen for the COW fork, where another thread
		 * might have moved the extent to the data fork in the meantime.
		 */
		WARN_ON_ONCE(whichfork != SCXFS_COW_FORK);
		error = -EAGAIN;
		goto out_trans_cancel;
	}

	/*
	 * If we find a real extent here we raced with another thread converting
	 * the extent.  Just return the real extent at this offset.
	 */
	if (!isnullstartblock(bma.got.br_startblock)) {
		*imap = bma.got;
		*seq = READ_ONCE(ifp->if_seq);
		goto out_trans_cancel;
	}

	bma.tp = tp;
	bma.ip = ip;
	bma.wasdel = true;
	bma.offset = bma.got.br_startoff;
	bma.length = max_t(scxfs_filblks_t, bma.got.br_blockcount, MAXEXTLEN);
	bma.total = SCXFS_EXTENTADD_SPACE_RES(ip->i_mount, SCXFS_DATA_FORK);
	bma.minleft = scxfs_bmapi_minleft(tp, ip, whichfork);
	if (whichfork == SCXFS_COW_FORK)
		bma.flags = SCXFS_BMAPI_COWFORK | SCXFS_BMAPI_PREALLOC;

	if (!scxfs_iext_peek_prev_extent(ifp, &bma.icur, &bma.prev))
		bma.prev.br_startoff = NULLFILEOFF;

	error = scxfs_bmapi_allocate(&bma);
	if (error)
		goto out_finish;

	error = -ENOSPC;
	if (WARN_ON_ONCE(bma.blkno == NULLFSBLOCK))
		goto out_finish;
	error = -EFSCORRUPTED;
	if (WARN_ON_ONCE(!scxfs_valid_startblock(ip, bma.got.br_startblock)))
		goto out_finish;

	SCXFS_STATS_ADD(mp, xs_xstrat_bytes, SCXFS_FSB_TO_B(mp, bma.length));
	SCXFS_STATS_INC(mp, xs_xstrat_quick);

	ASSERT(!isnullstartblock(bma.got.br_startblock));
	*imap = bma.got;
	*seq = READ_ONCE(ifp->if_seq);

	if (whichfork == SCXFS_COW_FORK)
		scxfs_refcount_alloc_cow_extent(tp, bma.blkno, bma.length);

	error = scxfs_bmap_btree_to_extents(tp, ip, bma.cur, &bma.logflags,
			whichfork);
	if (error)
		goto out_finish;

	scxfs_bmapi_finish(&bma, whichfork, 0);
	error = scxfs_trans_commit(tp);
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return error;

out_finish:
	scxfs_bmapi_finish(&bma, whichfork, error);
out_trans_cancel:
	scxfs_trans_cancel(tp);
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return error;
}

int
scxfs_bmapi_remap(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		bno,
	scxfs_filblks_t		len,
	scxfs_fsblock_t		startblock,
	int			flags)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp;
	struct scxfs_btree_cur	*cur = NULL;
	struct scxfs_bmbt_irec	got;
	struct scxfs_iext_cursor	icur;
	int			whichfork = scxfs_bmapi_whichfork(flags);
	int			logflags = 0, error;

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	ASSERT(len > 0);
	ASSERT(len <= (scxfs_filblks_t)MAXEXTLEN);
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(!(flags & ~(SCXFS_BMAPI_ATTRFORK | SCXFS_BMAPI_PREALLOC |
			   SCXFS_BMAPI_NORMAP)));
	ASSERT((flags & (SCXFS_BMAPI_ATTRFORK | SCXFS_BMAPI_PREALLOC)) !=
			(SCXFS_BMAPI_ATTRFORK | SCXFS_BMAPI_PREALLOC));

	if (unlikely(SCXFS_TEST_ERROR(
	    (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	     SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE),
	     mp, SCXFS_ERRTAG_BMAPIFORMAT))) {
		SCXFS_ERROR_REPORT("scxfs_bmapi_remap", SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			return error;
	}

	if (scxfs_iext_lookup_extent(ip, ifp, bno, &icur, &got)) {
		/* make sure we only reflink into a hole. */
		ASSERT(got.br_startoff > bno);
		ASSERT(got.br_startoff - bno >= len);
	}

	ip->i_d.di_nblocks += len;
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

	if (ifp->if_flags & SCXFS_IFBROOT) {
		cur = scxfs_bmbt_init_cursor(mp, tp, ip, whichfork);
		cur->bc_private.b.flags = 0;
	}

	got.br_startoff = bno;
	got.br_startblock = startblock;
	got.br_blockcount = len;
	if (flags & SCXFS_BMAPI_PREALLOC)
		got.br_state = SCXFS_EXT_UNWRITTEN;
	else
		got.br_state = SCXFS_EXT_NORM;

	error = scxfs_bmap_add_extent_hole_real(tp, ip, whichfork, &icur,
			&cur, &got, &logflags, flags);
	if (error)
		goto error0;

	error = scxfs_bmap_btree_to_extents(tp, ip, cur, &logflags, whichfork);

error0:
	if (ip->i_d.di_format != SCXFS_DINODE_FMT_EXTENTS)
		logflags &= ~SCXFS_ILOG_DEXT;
	else if (ip->i_d.di_format != SCXFS_DINODE_FMT_BTREE)
		logflags &= ~SCXFS_ILOG_DBROOT;

	if (logflags)
		scxfs_trans_log_inode(tp, ip, logflags);
	if (cur)
		scxfs_btree_del_cursor(cur, error);
	return error;
}

/*
 * When a delalloc extent is split (e.g., due to a hole punch), the original
 * indlen reservation must be shared across the two new extents that are left
 * behind.
 *
 * Given the original reservation and the worst case indlen for the two new
 * extents (as calculated by scxfs_bmap_worst_indlen()), split the original
 * reservation fairly across the two new extents. If necessary, steal available
 * blocks from a deleted extent to make up a reservation deficiency (e.g., if
 * ores == 1). The number of stolen blocks is returned. The availability and
 * subsequent accounting of stolen blocks is the responsibility of the caller.
 */
static scxfs_filblks_t
scxfs_bmap_split_indlen(
	scxfs_filblks_t			ores,		/* original res. */
	scxfs_filblks_t			*indlen1,	/* ext1 worst indlen */
	scxfs_filblks_t			*indlen2,	/* ext2 worst indlen */
	scxfs_filblks_t			avail)		/* stealable blocks */
{
	scxfs_filblks_t			len1 = *indlen1;
	scxfs_filblks_t			len2 = *indlen2;
	scxfs_filblks_t			nres = len1 + len2; /* new total res. */
	scxfs_filblks_t			stolen = 0;
	scxfs_filblks_t			resfactor;

	/*
	 * Steal as many blocks as we can to try and satisfy the worst case
	 * indlen for both new extents.
	 */
	if (ores < nres && avail)
		stolen = SCXFS_FILBLKS_MIN(nres - ores, avail);
	ores += stolen;

	 /* nothing else to do if we've satisfied the new reservation */
	if (ores >= nres)
		return stolen;

	/*
	 * We can't meet the total required reservation for the two extents.
	 * Calculate the percent of the overall shortage between both extents
	 * and apply this percentage to each of the requested indlen values.
	 * This distributes the shortage fairly and reduces the chances that one
	 * of the two extents is left with nothing when extents are repeatedly
	 * split.
	 */
	resfactor = (ores * 100);
	do_div(resfactor, nres);
	len1 *= resfactor;
	do_div(len1, 100);
	len2 *= resfactor;
	do_div(len2, 100);
	ASSERT(len1 + len2 <= ores);
	ASSERT(len1 < *indlen1 && len2 < *indlen2);

	/*
	 * Hand out the remainder to each extent. If one of the two reservations
	 * is zero, we want to make sure that one gets a block first. The loop
	 * below starts with len1, so hand len2 a block right off the bat if it
	 * is zero.
	 */
	ores -= (len1 + len2);
	ASSERT((*indlen1 - len1) + (*indlen2 - len2) >= ores);
	if (ores && !len2 && *indlen2) {
		len2++;
		ores--;
	}
	while (ores) {
		if (len1 < *indlen1) {
			len1++;
			ores--;
		}
		if (!ores)
			break;
		if (len2 < *indlen2) {
			len2++;
			ores--;
		}
	}

	*indlen1 = len1;
	*indlen2 = len2;

	return stolen;
}

int
scxfs_bmap_del_extent_delay(
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_iext_cursor	*icur,
	struct scxfs_bmbt_irec	*got,
	struct scxfs_bmbt_irec	*del)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_bmbt_irec	new;
	int64_t			da_old, da_new, da_diff = 0;
	scxfs_fileoff_t		del_endoff, got_endoff;
	scxfs_filblks_t		got_indlen, new_indlen, stolen;
	int			state = scxfs_bmap_fork_to_state(whichfork);
	int			error = 0;
	bool			isrt;

	SCXFS_STATS_INC(mp, xs_del_exlist);

	isrt = (whichfork == SCXFS_DATA_FORK) && SCXFS_IS_REALTIME_INODE(ip);
	del_endoff = del->br_startoff + del->br_blockcount;
	got_endoff = got->br_startoff + got->br_blockcount;
	da_old = startblockval(got->br_startblock);
	da_new = 0;

	ASSERT(del->br_blockcount > 0);
	ASSERT(got->br_startoff <= del->br_startoff);
	ASSERT(got_endoff >= del_endoff);

	if (isrt) {
		uint64_t rtexts = SCXFS_FSB_TO_B(mp, del->br_blockcount);

		do_div(rtexts, mp->m_sb.sb_rextsize);
		scxfs_mod_frextents(mp, rtexts);
	}

	/*
	 * Update the inode delalloc counter now and wait to update the
	 * sb counters as we might have to borrow some blocks for the
	 * indirect block accounting.
	 */
	error = scxfs_trans_reserve_quota_nblks(NULL, ip,
			-((long)del->br_blockcount), 0,
			isrt ? SCXFS_QMOPT_RES_RTBLKS : SCXFS_QMOPT_RES_REGBLKS);
	if (error)
		return error;
	ip->i_delayed_blks -= del->br_blockcount;

	if (got->br_startoff == del->br_startoff)
		state |= BMAP_LEFT_FILLING;
	if (got_endoff == del_endoff)
		state |= BMAP_RIGHT_FILLING;

	switch (state & (BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING)) {
	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING:
		/*
		 * Matches the whole extent.  Delete the entry.
		 */
		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		break;
	case BMAP_LEFT_FILLING:
		/*
		 * Deleting the first part of the extent.
		 */
		got->br_startoff = del_endoff;
		got->br_blockcount -= del->br_blockcount;
		da_new = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(ip,
				got->br_blockcount), da_old);
		got->br_startblock = nullstartblock((int)da_new);
		scxfs_iext_update_extent(ip, state, icur, got);
		break;
	case BMAP_RIGHT_FILLING:
		/*
		 * Deleting the last part of the extent.
		 */
		got->br_blockcount = got->br_blockcount - del->br_blockcount;
		da_new = SCXFS_FILBLKS_MIN(scxfs_bmap_worst_indlen(ip,
				got->br_blockcount), da_old);
		got->br_startblock = nullstartblock((int)da_new);
		scxfs_iext_update_extent(ip, state, icur, got);
		break;
	case 0:
		/*
		 * Deleting the middle of the extent.
		 *
		 * Distribute the original indlen reservation across the two new
		 * extents.  Steal blocks from the deleted extent if necessary.
		 * Stealing blocks simply fudges the fdblocks accounting below.
		 * Warn if either of the new indlen reservations is zero as this
		 * can lead to delalloc problems.
		 */
		got->br_blockcount = del->br_startoff - got->br_startoff;
		got_indlen = scxfs_bmap_worst_indlen(ip, got->br_blockcount);

		new.br_blockcount = got_endoff - del_endoff;
		new_indlen = scxfs_bmap_worst_indlen(ip, new.br_blockcount);

		WARN_ON_ONCE(!got_indlen || !new_indlen);
		stolen = scxfs_bmap_split_indlen(da_old, &got_indlen, &new_indlen,
						       del->br_blockcount);

		got->br_startblock = nullstartblock((int)got_indlen);

		new.br_startoff = del_endoff;
		new.br_state = got->br_state;
		new.br_startblock = nullstartblock((int)new_indlen);

		scxfs_iext_update_extent(ip, state, icur, got);
		scxfs_iext_next(ifp, icur);
		scxfs_iext_insert(ip, icur, &new, state);

		da_new = got_indlen + new_indlen - stolen;
		del->br_blockcount -= stolen;
		break;
	}

	ASSERT(da_old >= da_new);
	da_diff = da_old - da_new;
	if (!isrt)
		da_diff += del->br_blockcount;
	if (da_diff) {
		scxfs_mod_fdblocks(mp, da_diff, false);
		scxfs_mod_delalloc(mp, -da_diff);
	}
	return error;
}

void
scxfs_bmap_del_extent_cow(
	struct scxfs_inode	*ip,
	struct scxfs_iext_cursor	*icur,
	struct scxfs_bmbt_irec	*got,
	struct scxfs_bmbt_irec	*del)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, SCXFS_COW_FORK);
	struct scxfs_bmbt_irec	new;
	scxfs_fileoff_t		del_endoff, got_endoff;
	int			state = BMAP_COWFORK;

	SCXFS_STATS_INC(mp, xs_del_exlist);

	del_endoff = del->br_startoff + del->br_blockcount;
	got_endoff = got->br_startoff + got->br_blockcount;

	ASSERT(del->br_blockcount > 0);
	ASSERT(got->br_startoff <= del->br_startoff);
	ASSERT(got_endoff >= del_endoff);
	ASSERT(!isnullstartblock(got->br_startblock));

	if (got->br_startoff == del->br_startoff)
		state |= BMAP_LEFT_FILLING;
	if (got_endoff == del_endoff)
		state |= BMAP_RIGHT_FILLING;

	switch (state & (BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING)) {
	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING:
		/*
		 * Matches the whole extent.  Delete the entry.
		 */
		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		break;
	case BMAP_LEFT_FILLING:
		/*
		 * Deleting the first part of the extent.
		 */
		got->br_startoff = del_endoff;
		got->br_blockcount -= del->br_blockcount;
		got->br_startblock = del->br_startblock + del->br_blockcount;
		scxfs_iext_update_extent(ip, state, icur, got);
		break;
	case BMAP_RIGHT_FILLING:
		/*
		 * Deleting the last part of the extent.
		 */
		got->br_blockcount -= del->br_blockcount;
		scxfs_iext_update_extent(ip, state, icur, got);
		break;
	case 0:
		/*
		 * Deleting the middle of the extent.
		 */
		got->br_blockcount = del->br_startoff - got->br_startoff;

		new.br_startoff = del_endoff;
		new.br_blockcount = got_endoff - del_endoff;
		new.br_state = got->br_state;
		new.br_startblock = del->br_startblock + del->br_blockcount;

		scxfs_iext_update_extent(ip, state, icur, got);
		scxfs_iext_next(ifp, icur);
		scxfs_iext_insert(ip, icur, &new, state);
		break;
	}
	ip->i_delayed_blks -= del->br_blockcount;
}

/*
 * Called by scxfs_bmapi to update file extent records and the btree
 * after removing space.
 */
STATIC int				/* error */
scxfs_bmap_del_extent_real(
	scxfs_inode_t		*ip,	/* incore inode pointer */
	scxfs_trans_t		*tp,	/* current transaction pointer */
	struct scxfs_iext_cursor	*icur,
	scxfs_btree_cur_t		*cur,	/* if null, not a btree */
	scxfs_bmbt_irec_t		*del,	/* data to remove from extents */
	int			*logflagsp, /* inode logging flags */
	int			whichfork, /* data or attr fork */
	int			bflags)	/* bmapi flags */
{
	scxfs_fsblock_t		del_endblock=0;	/* first block past del */
	scxfs_fileoff_t		del_endoff;	/* first offset past del */
	int			do_fx;	/* free extent at end of routine */
	int			error;	/* error return value */
	int			flags = 0;/* inode logging flags */
	struct scxfs_bmbt_irec	got;	/* current extent entry */
	scxfs_fileoff_t		got_endoff;	/* first offset past got */
	int			i;	/* temp state */
	struct scxfs_ifork	*ifp;	/* inode fork pointer */
	scxfs_mount_t		*mp;	/* mount structure */
	scxfs_filblks_t		nblks;	/* quota/sb block count */
	scxfs_bmbt_irec_t		new;	/* new record to be inserted */
	/* REFERENCED */
	uint			qfield;	/* quota field to update */
	int			state = scxfs_bmap_fork_to_state(whichfork);
	struct scxfs_bmbt_irec	old;

	mp = ip->i_mount;
	SCXFS_STATS_INC(mp, xs_del_exlist);

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	ASSERT(del->br_blockcount > 0);
	scxfs_iext_get_extent(ifp, icur, &got);
	ASSERT(got.br_startoff <= del->br_startoff);
	del_endoff = del->br_startoff + del->br_blockcount;
	got_endoff = got.br_startoff + got.br_blockcount;
	ASSERT(got_endoff >= del_endoff);
	ASSERT(!isnullstartblock(got.br_startblock));
	qfield = 0;
	error = 0;

	/*
	 * If it's the case where the directory code is running with no block
	 * reservation, and the deleted block is in the middle of its extent,
	 * and the resulting insert of an extent would cause transformation to
	 * btree format, then reject it.  The calling code will then swap blocks
	 * around instead.  We have to do this now, rather than waiting for the
	 * conversion to btree format, since the transaction will be dirty then.
	 */
	if (tp->t_blk_res == 0 &&
	    SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_EXTENTS &&
	    SCXFS_IFORK_NEXTENTS(ip, whichfork) >=
			SCXFS_IFORK_MAXEXT(ip, whichfork) &&
	    del->br_startoff > got.br_startoff && del_endoff < got_endoff)
		return -ENOSPC;

	flags = SCXFS_ILOG_CORE;
	if (whichfork == SCXFS_DATA_FORK && SCXFS_IS_REALTIME_INODE(ip)) {
		scxfs_filblks_t	len;
		scxfs_extlen_t	mod;

		len = div_u64_rem(del->br_blockcount, mp->m_sb.sb_rextsize,
				  &mod);
		ASSERT(mod == 0);

		if (!(bflags & SCXFS_BMAPI_REMAP)) {
			scxfs_fsblock_t	bno;

			bno = div_u64_rem(del->br_startblock,
					mp->m_sb.sb_rextsize, &mod);
			ASSERT(mod == 0);

			error = scxfs_rtfree_extent(tp, bno, (scxfs_extlen_t)len);
			if (error)
				goto done;
		}

		do_fx = 0;
		nblks = len * mp->m_sb.sb_rextsize;
		qfield = SCXFS_TRANS_DQ_RTBCOUNT;
	} else {
		do_fx = 1;
		nblks = del->br_blockcount;
		qfield = SCXFS_TRANS_DQ_BCOUNT;
	}

	del_endblock = del->br_startblock + del->br_blockcount;
	if (cur) {
		error = scxfs_bmbt_lookup_eq(cur, &got, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
	}

	if (got.br_startoff == del->br_startoff)
		state |= BMAP_LEFT_FILLING;
	if (got_endoff == del_endoff)
		state |= BMAP_RIGHT_FILLING;

	switch (state & (BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING)) {
	case BMAP_LEFT_FILLING | BMAP_RIGHT_FILLING:
		/*
		 * Matches the whole extent.  Delete the entry.
		 */
		scxfs_iext_remove(ip, icur, state);
		scxfs_iext_prev(ifp, icur);
		SCXFS_IFORK_NEXT_SET(ip, whichfork,
			SCXFS_IFORK_NEXTENTS(ip, whichfork) - 1);
		flags |= SCXFS_ILOG_CORE;
		if (!cur) {
			flags |= scxfs_ilog_fext(whichfork);
			break;
		}
		if ((error = scxfs_btree_delete(cur, &i)))
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		break;
	case BMAP_LEFT_FILLING:
		/*
		 * Deleting the first part of the extent.
		 */
		got.br_startoff = del_endoff;
		got.br_startblock = del_endblock;
		got.br_blockcount -= del->br_blockcount;
		scxfs_iext_update_extent(ip, state, icur, &got);
		if (!cur) {
			flags |= scxfs_ilog_fext(whichfork);
			break;
		}
		error = scxfs_bmbt_update(cur, &got);
		if (error)
			goto done;
		break;
	case BMAP_RIGHT_FILLING:
		/*
		 * Deleting the last part of the extent.
		 */
		got.br_blockcount -= del->br_blockcount;
		scxfs_iext_update_extent(ip, state, icur, &got);
		if (!cur) {
			flags |= scxfs_ilog_fext(whichfork);
			break;
		}
		error = scxfs_bmbt_update(cur, &got);
		if (error)
			goto done;
		break;
	case 0:
		/*
		 * Deleting the middle of the extent.
		 */
		old = got;

		got.br_blockcount = del->br_startoff - got.br_startoff;
		scxfs_iext_update_extent(ip, state, icur, &got);

		new.br_startoff = del_endoff;
		new.br_blockcount = got_endoff - del_endoff;
		new.br_state = got.br_state;
		new.br_startblock = del_endblock;

		flags |= SCXFS_ILOG_CORE;
		if (cur) {
			error = scxfs_bmbt_update(cur, &got);
			if (error)
				goto done;
			error = scxfs_btree_increment(cur, 0, &i);
			if (error)
				goto done;
			cur->bc_rec.b = new;
			error = scxfs_btree_insert(cur, &i);
			if (error && error != -ENOSPC)
				goto done;
			/*
			 * If get no-space back from btree insert, it tried a
			 * split, and we have a zero block reservation.  Fix up
			 * our state and return the error.
			 */
			if (error == -ENOSPC) {
				/*
				 * Reset the cursor, don't trust it after any
				 * insert operation.
				 */
				error = scxfs_bmbt_lookup_eq(cur, &got, &i);
				if (error)
					goto done;
				SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
				/*
				 * Update the btree record back
				 * to the original value.
				 */
				error = scxfs_bmbt_update(cur, &old);
				if (error)
					goto done;
				/*
				 * Reset the extent record back
				 * to the original value.
				 */
				scxfs_iext_update_extent(ip, state, icur, &old);
				flags = 0;
				error = -ENOSPC;
				goto done;
			}
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		} else
			flags |= scxfs_ilog_fext(whichfork);
		SCXFS_IFORK_NEXT_SET(ip, whichfork,
			SCXFS_IFORK_NEXTENTS(ip, whichfork) + 1);
		scxfs_iext_next(ifp, icur);
		scxfs_iext_insert(ip, icur, &new, state);
		break;
	}

	/* remove reverse mapping */
	scxfs_rmap_unmap_extent(tp, ip, whichfork, del);

	/*
	 * If we need to, add to list of extents to delete.
	 */
	if (do_fx && !(bflags & SCXFS_BMAPI_REMAP)) {
		if (scxfs_is_reflink_inode(ip) && whichfork == SCXFS_DATA_FORK) {
			scxfs_refcount_decrease_extent(tp, del);
		} else {
			__scxfs_bmap_add_free(tp, del->br_startblock,
					del->br_blockcount, NULL,
					(bflags & SCXFS_BMAPI_NODISCARD) ||
					del->br_state == SCXFS_EXT_UNWRITTEN);
		}
	}

	/*
	 * Adjust inode # blocks in the file.
	 */
	if (nblks)
		ip->i_d.di_nblocks -= nblks;
	/*
	 * Adjust quota data.
	 */
	if (qfield && !(bflags & SCXFS_BMAPI_REMAP))
		scxfs_trans_mod_dquot_byino(tp, ip, qfield, (long)-nblks);

done:
	*logflagsp = flags;
	return error;
}

/*
 * Unmap (remove) blocks from a file.
 * If nexts is nonzero then the number of extents to remove is limited to
 * that value.  If not all extents in the block range can be removed then
 * *done is set.
 */
int						/* error */
__scxfs_bunmapi(
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* incore inode */
	scxfs_fileoff_t		start,		/* first file offset deleted */
	scxfs_filblks_t		*rlen,		/* i/o: amount remaining */
	int			flags,		/* misc flags */
	scxfs_extnum_t		nexts)		/* number of extents max */
{
	struct scxfs_btree_cur	*cur;		/* bmap btree cursor */
	struct scxfs_bmbt_irec	del;		/* extent being deleted */
	int			error;		/* error return value */
	scxfs_extnum_t		extno;		/* extent number in list */
	struct scxfs_bmbt_irec	got;		/* current extent record */
	struct scxfs_ifork	*ifp;		/* inode fork pointer */
	int			isrt;		/* freeing in rt area */
	int			logflags;	/* transaction logging flags */
	scxfs_extlen_t		mod;		/* rt extent offset */
	struct scxfs_mount	*mp;		/* mount structure */
	int			tmp_logflags;	/* partial logging flags */
	int			wasdel;		/* was a delayed alloc extent */
	int			whichfork;	/* data or attribute fork */
	scxfs_fsblock_t		sum;
	scxfs_filblks_t		len = *rlen;	/* length to unmap in file */
	scxfs_fileoff_t		max_len;
	scxfs_agnumber_t		prev_agno = NULLAGNUMBER, agno;
	scxfs_fileoff_t		end;
	struct scxfs_iext_cursor	icur;
	bool			done = false;

	trace_scxfs_bunmap(ip, start, len, flags, _RET_IP_);

	whichfork = scxfs_bmapi_whichfork(flags);
	ASSERT(whichfork != SCXFS_COW_FORK);
	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	if (unlikely(
	    SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	    SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE)) {
		SCXFS_ERROR_REPORT("scxfs_bunmapi", SCXFS_ERRLEVEL_LOW,
				 ip->i_mount);
		return -EFSCORRUPTED;
	}
	mp = ip->i_mount;
	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(len > 0);
	ASSERT(nexts >= 0);

	/*
	 * Guesstimate how many blocks we can unmap without running the risk of
	 * blowing out the transaction with a mix of EFIs and reflink
	 * adjustments.
	 */
	if (tp && scxfs_is_reflink_inode(ip) && whichfork == SCXFS_DATA_FORK)
		max_len = min(len, scxfs_refcount_max_unmap(tp->t_log_res));
	else
		max_len = len;

	if (!(ifp->if_flags & SCXFS_IFEXTENTS) &&
	    (error = scxfs_iread_extents(tp, ip, whichfork)))
		return error;
	if (scxfs_iext_count(ifp) == 0) {
		*rlen = 0;
		return 0;
	}
	SCXFS_STATS_INC(mp, xs_blk_unmap);
	isrt = (whichfork == SCXFS_DATA_FORK) && SCXFS_IS_REALTIME_INODE(ip);
	end = start + len;

	if (!scxfs_iext_lookup_extent_before(ip, ifp, &end, &icur, &got)) {
		*rlen = 0;
		return 0;
	}
	end--;

	logflags = 0;
	if (ifp->if_flags & SCXFS_IFBROOT) {
		ASSERT(SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_BTREE);
		cur = scxfs_bmbt_init_cursor(mp, tp, ip, whichfork);
		cur->bc_private.b.flags = 0;
	} else
		cur = NULL;

	if (isrt) {
		/*
		 * Synchronize by locking the bitmap inode.
		 */
		scxfs_ilock(mp->m_rbmip, SCXFS_ILOCK_EXCL|SCXFS_ILOCK_RTBITMAP);
		scxfs_trans_ijoin(tp, mp->m_rbmip, SCXFS_ILOCK_EXCL);
		scxfs_ilock(mp->m_rsumip, SCXFS_ILOCK_EXCL|SCXFS_ILOCK_RTSUM);
		scxfs_trans_ijoin(tp, mp->m_rsumip, SCXFS_ILOCK_EXCL);
	}

	extno = 0;
	while (end != (scxfs_fileoff_t)-1 && end >= start &&
	       (nexts == 0 || extno < nexts) && max_len > 0) {
		/*
		 * Is the found extent after a hole in which end lives?
		 * Just back up to the previous extent, if so.
		 */
		if (got.br_startoff > end &&
		    !scxfs_iext_prev_extent(ifp, &icur, &got)) {
			done = true;
			break;
		}
		/*
		 * Is the last block of this extent before the range
		 * we're supposed to delete?  If so, we're done.
		 */
		end = SCXFS_FILEOFF_MIN(end,
			got.br_startoff + got.br_blockcount - 1);
		if (end < start)
			break;
		/*
		 * Then deal with the (possibly delayed) allocated space
		 * we found.
		 */
		del = got;
		wasdel = isnullstartblock(del.br_startblock);

		/*
		 * Make sure we don't touch multiple AGF headers out of order
		 * in a single transaction, as that could cause AB-BA deadlocks.
		 */
		if (!wasdel && !isrt) {
			agno = SCXFS_FSB_TO_AGNO(mp, del.br_startblock);
			if (prev_agno != NULLAGNUMBER && prev_agno > agno)
				break;
			prev_agno = agno;
		}
		if (got.br_startoff < start) {
			del.br_startoff = start;
			del.br_blockcount -= start - got.br_startoff;
			if (!wasdel)
				del.br_startblock += start - got.br_startoff;
		}
		if (del.br_startoff + del.br_blockcount > end + 1)
			del.br_blockcount = end + 1 - del.br_startoff;

		/* How much can we safely unmap? */
		if (max_len < del.br_blockcount) {
			del.br_startoff += del.br_blockcount - max_len;
			if (!wasdel)
				del.br_startblock += del.br_blockcount - max_len;
			del.br_blockcount = max_len;
		}

		if (!isrt)
			goto delete;

		sum = del.br_startblock + del.br_blockcount;
		div_u64_rem(sum, mp->m_sb.sb_rextsize, &mod);
		if (mod) {
			/*
			 * Realtime extent not lined up at the end.
			 * The extent could have been split into written
			 * and unwritten pieces, or we could just be
			 * unmapping part of it.  But we can't really
			 * get rid of part of a realtime extent.
			 */
			if (del.br_state == SCXFS_EXT_UNWRITTEN) {
				/*
				 * This piece is unwritten, or we're not
				 * using unwritten extents.  Skip over it.
				 */
				ASSERT(end >= mod);
				end -= mod > del.br_blockcount ?
					del.br_blockcount : mod;
				if (end < got.br_startoff &&
				    !scxfs_iext_prev_extent(ifp, &icur, &got)) {
					done = true;
					break;
				}
				continue;
			}
			/*
			 * It's written, turn it unwritten.
			 * This is better than zeroing it.
			 */
			ASSERT(del.br_state == SCXFS_EXT_NORM);
			ASSERT(tp->t_blk_res > 0);
			/*
			 * If this spans a realtime extent boundary,
			 * chop it back to the start of the one we end at.
			 */
			if (del.br_blockcount > mod) {
				del.br_startoff += del.br_blockcount - mod;
				del.br_startblock += del.br_blockcount - mod;
				del.br_blockcount = mod;
			}
			del.br_state = SCXFS_EXT_UNWRITTEN;
			error = scxfs_bmap_add_extent_unwritten_real(tp, ip,
					whichfork, &icur, &cur, &del,
					&logflags);
			if (error)
				goto error0;
			goto nodelete;
		}
		div_u64_rem(del.br_startblock, mp->m_sb.sb_rextsize, &mod);
		if (mod) {
			scxfs_extlen_t off = mp->m_sb.sb_rextsize - mod;

			/*
			 * Realtime extent is lined up at the end but not
			 * at the front.  We'll get rid of full extents if
			 * we can.
			 */
			if (del.br_blockcount > off) {
				del.br_blockcount -= off;
				del.br_startoff += off;
				del.br_startblock += off;
			} else if (del.br_startoff == start &&
				   (del.br_state == SCXFS_EXT_UNWRITTEN ||
				    tp->t_blk_res == 0)) {
				/*
				 * Can't make it unwritten.  There isn't
				 * a full extent here so just skip it.
				 */
				ASSERT(end >= del.br_blockcount);
				end -= del.br_blockcount;
				if (got.br_startoff > end &&
				    !scxfs_iext_prev_extent(ifp, &icur, &got)) {
					done = true;
					break;
				}
				continue;
			} else if (del.br_state == SCXFS_EXT_UNWRITTEN) {
				struct scxfs_bmbt_irec	prev;
				scxfs_fileoff_t		unwrite_start;

				/*
				 * This one is already unwritten.
				 * It must have a written left neighbor.
				 * Unwrite the killed part of that one and
				 * try again.
				 */
				if (!scxfs_iext_prev_extent(ifp, &icur, &prev))
					ASSERT(0);
				ASSERT(prev.br_state == SCXFS_EXT_NORM);
				ASSERT(!isnullstartblock(prev.br_startblock));
				ASSERT(del.br_startblock ==
				       prev.br_startblock + prev.br_blockcount);
				unwrite_start = max3(start,
						     del.br_startoff - mod,
						     prev.br_startoff);
				mod = unwrite_start - prev.br_startoff;
				prev.br_startoff = unwrite_start;
				prev.br_startblock += mod;
				prev.br_blockcount -= mod;
				prev.br_state = SCXFS_EXT_UNWRITTEN;
				error = scxfs_bmap_add_extent_unwritten_real(tp,
						ip, whichfork, &icur, &cur,
						&prev, &logflags);
				if (error)
					goto error0;
				goto nodelete;
			} else {
				ASSERT(del.br_state == SCXFS_EXT_NORM);
				del.br_state = SCXFS_EXT_UNWRITTEN;
				error = scxfs_bmap_add_extent_unwritten_real(tp,
						ip, whichfork, &icur, &cur,
						&del, &logflags);
				if (error)
					goto error0;
				goto nodelete;
			}
		}

delete:
		if (wasdel) {
			error = scxfs_bmap_del_extent_delay(ip, whichfork, &icur,
					&got, &del);
		} else {
			error = scxfs_bmap_del_extent_real(ip, tp, &icur, cur,
					&del, &tmp_logflags, whichfork,
					flags);
			logflags |= tmp_logflags;
		}

		if (error)
			goto error0;

		max_len -= del.br_blockcount;
		end = del.br_startoff - 1;
nodelete:
		/*
		 * If not done go on to the next (previous) record.
		 */
		if (end != (scxfs_fileoff_t)-1 && end >= start) {
			if (!scxfs_iext_get_extent(ifp, &icur, &got) ||
			    (got.br_startoff > end &&
			     !scxfs_iext_prev_extent(ifp, &icur, &got))) {
				done = true;
				break;
			}
			extno++;
		}
	}
	if (done || end == (scxfs_fileoff_t)-1 || end < start)
		*rlen = 0;
	else
		*rlen = end - start + 1;

	/*
	 * Convert to a btree if necessary.
	 */
	if (scxfs_bmap_needs_btree(ip, whichfork)) {
		ASSERT(cur == NULL);
		error = scxfs_bmap_extents_to_btree(tp, ip, &cur, 0,
				&tmp_logflags, whichfork);
		logflags |= tmp_logflags;
	} else {
		error = scxfs_bmap_btree_to_extents(tp, ip, cur, &logflags,
			whichfork);
	}

error0:
	/*
	 * Log everything.  Do this after conversion, there's no point in
	 * logging the extent records if we've converted to btree format.
	 */
	if ((logflags & scxfs_ilog_fext(whichfork)) &&
	    SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS)
		logflags &= ~scxfs_ilog_fext(whichfork);
	else if ((logflags & scxfs_ilog_fbroot(whichfork)) &&
		 SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE)
		logflags &= ~scxfs_ilog_fbroot(whichfork);
	/*
	 * Log inode even in the error case, if the transaction
	 * is dirty we'll need to shut down the filesystem.
	 */
	if (logflags)
		scxfs_trans_log_inode(tp, ip, logflags);
	if (cur) {
		if (!error)
			cur->bc_private.b.allocated = 0;
		scxfs_btree_del_cursor(cur, error);
	}
	return error;
}

/* Unmap a range of a file. */
int
scxfs_bunmapi(
	scxfs_trans_t		*tp,
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		bno,
	scxfs_filblks_t		len,
	int			flags,
	scxfs_extnum_t		nexts,
	int			*done)
{
	int			error;

	error = __scxfs_bunmapi(tp, ip, bno, &len, flags, nexts);
	*done = (len == 0);
	return error;
}

/*
 * Determine whether an extent shift can be accomplished by a merge with the
 * extent that precedes the target hole of the shift.
 */
STATIC bool
scxfs_bmse_can_merge(
	struct scxfs_bmbt_irec	*left,	/* preceding extent */
	struct scxfs_bmbt_irec	*got,	/* current extent to shift */
	scxfs_fileoff_t		shift)	/* shift fsb */
{
	scxfs_fileoff_t		startoff;

	startoff = got->br_startoff - shift;

	/*
	 * The extent, once shifted, must be adjacent in-file and on-disk with
	 * the preceding extent.
	 */
	if ((left->br_startoff + left->br_blockcount != startoff) ||
	    (left->br_startblock + left->br_blockcount != got->br_startblock) ||
	    (left->br_state != got->br_state) ||
	    (left->br_blockcount + got->br_blockcount > MAXEXTLEN))
		return false;

	return true;
}

/*
 * A bmap extent shift adjusts the file offset of an extent to fill a preceding
 * hole in the file. If an extent shift would result in the extent being fully
 * adjacent to the extent that currently precedes the hole, we can merge with
 * the preceding extent rather than do the shift.
 *
 * This function assumes the caller has verified a shift-by-merge is possible
 * with the provided extents via scxfs_bmse_can_merge().
 */
STATIC int
scxfs_bmse_merge(
	struct scxfs_trans		*tp,
	struct scxfs_inode		*ip,
	int				whichfork,
	scxfs_fileoff_t			shift,		/* shift fsb */
	struct scxfs_iext_cursor		*icur,
	struct scxfs_bmbt_irec		*got,		/* extent to shift */
	struct scxfs_bmbt_irec		*left,		/* preceding extent */
	struct scxfs_btree_cur		*cur,
	int				*logflags)	/* output */
{
	struct scxfs_bmbt_irec		new;
	scxfs_filblks_t			blockcount;
	int				error, i;
	struct scxfs_mount		*mp = ip->i_mount;

	blockcount = left->br_blockcount + got->br_blockcount;

	ASSERT(scxfs_isilocked(ip, SCXFS_IOLOCK_EXCL));
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(scxfs_bmse_can_merge(left, got, shift));

	new = *left;
	new.br_blockcount = blockcount;

	/*
	 * Update the on-disk extent count, the btree if necessary and log the
	 * inode.
	 */
	SCXFS_IFORK_NEXT_SET(ip, whichfork,
			   SCXFS_IFORK_NEXTENTS(ip, whichfork) - 1);
	*logflags |= SCXFS_ILOG_CORE;
	if (!cur) {
		*logflags |= SCXFS_ILOG_DEXT;
		goto done;
	}

	/* lookup and remove the extent to merge */
	error = scxfs_bmbt_lookup_eq(cur, got, &i);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(mp, i == 1);

	error = scxfs_btree_delete(cur, &i);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(mp, i == 1);

	/* lookup and update size of the previous extent */
	error = scxfs_bmbt_lookup_eq(cur, left, &i);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(mp, i == 1);

	error = scxfs_bmbt_update(cur, &new);
	if (error)
		return error;

	/* change to extent format if required after extent removal */
	error = scxfs_bmap_btree_to_extents(tp, ip, cur, logflags, whichfork);
	if (error)
		return error;

done:
	scxfs_iext_remove(ip, icur, 0);
	scxfs_iext_prev(SCXFS_IFORK_PTR(ip, whichfork), icur);
	scxfs_iext_update_extent(ip, scxfs_bmap_fork_to_state(whichfork), icur,
			&new);

	/* update reverse mapping. rmap functions merge the rmaps for us */
	scxfs_rmap_unmap_extent(tp, ip, whichfork, got);
	memcpy(&new, got, sizeof(new));
	new.br_startoff = left->br_startoff + left->br_blockcount;
	scxfs_rmap_map_extent(tp, ip, whichfork, &new);
	return 0;
}

static int
scxfs_bmap_shift_update_extent(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_iext_cursor	*icur,
	struct scxfs_bmbt_irec	*got,
	struct scxfs_btree_cur	*cur,
	int			*logflags,
	scxfs_fileoff_t		startoff)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_bmbt_irec	prev = *got;
	int			error, i;

	*logflags |= SCXFS_ILOG_CORE;

	got->br_startoff = startoff;

	if (cur) {
		error = scxfs_bmbt_lookup_eq(cur, &prev, &i);
		if (error)
			return error;
		SCXFS_WANT_CORRUPTED_RETURN(mp, i == 1);

		error = scxfs_bmbt_update(cur, got);
		if (error)
			return error;
	} else {
		*logflags |= SCXFS_ILOG_DEXT;
	}

	scxfs_iext_update_extent(ip, scxfs_bmap_fork_to_state(whichfork), icur,
			got);

	/* update reverse mapping */
	scxfs_rmap_unmap_extent(tp, ip, whichfork, &prev);
	scxfs_rmap_map_extent(tp, ip, whichfork, got);
	return 0;
}

int
scxfs_bmap_collapse_extents(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		*next_fsb,
	scxfs_fileoff_t		offset_shift_fsb,
	bool			*done)
{
	int			whichfork = SCXFS_DATA_FORK;
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_btree_cur	*cur = NULL;
	struct scxfs_bmbt_irec	got, prev;
	struct scxfs_iext_cursor	icur;
	scxfs_fileoff_t		new_startoff;
	int			error = 0;
	int			logflags = 0;

	if (unlikely(SCXFS_TEST_ERROR(
	    (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	     SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE),
	     mp, SCXFS_ERRTAG_BMAPIFORMAT))) {
		SCXFS_ERROR_REPORT(__func__, SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	ASSERT(scxfs_isilocked(ip, SCXFS_IOLOCK_EXCL | SCXFS_ILOCK_EXCL));

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			return error;
	}

	if (ifp->if_flags & SCXFS_IFBROOT) {
		cur = scxfs_bmbt_init_cursor(mp, tp, ip, whichfork);
		cur->bc_private.b.flags = 0;
	}

	if (!scxfs_iext_lookup_extent(ip, ifp, *next_fsb, &icur, &got)) {
		*done = true;
		goto del_cursor;
	}
	SCXFS_WANT_CORRUPTED_GOTO(mp, !isnullstartblock(got.br_startblock),
				del_cursor);

	new_startoff = got.br_startoff - offset_shift_fsb;
	if (scxfs_iext_peek_prev_extent(ifp, &icur, &prev)) {
		if (new_startoff < prev.br_startoff + prev.br_blockcount) {
			error = -EINVAL;
			goto del_cursor;
		}

		if (scxfs_bmse_can_merge(&prev, &got, offset_shift_fsb)) {
			error = scxfs_bmse_merge(tp, ip, whichfork,
					offset_shift_fsb, &icur, &got, &prev,
					cur, &logflags);
			if (error)
				goto del_cursor;
			goto done;
		}
	} else {
		if (got.br_startoff < offset_shift_fsb) {
			error = -EINVAL;
			goto del_cursor;
		}
	}

	error = scxfs_bmap_shift_update_extent(tp, ip, whichfork, &icur, &got,
			cur, &logflags, new_startoff);
	if (error)
		goto del_cursor;

done:
	if (!scxfs_iext_next_extent(ifp, &icur, &got)) {
		*done = true;
		goto del_cursor;
	}

	*next_fsb = got.br_startoff;
del_cursor:
	if (cur)
		scxfs_btree_del_cursor(cur, error);
	if (logflags)
		scxfs_trans_log_inode(tp, ip, logflags);
	return error;
}

/* Make sure we won't be right-shifting an extent past the maximum bound. */
int
scxfs_bmap_can_insert_extents(
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		off,
	scxfs_fileoff_t		shift)
{
	struct scxfs_bmbt_irec	got;
	int			is_empty;
	int			error = 0;

	ASSERT(scxfs_isilocked(ip, SCXFS_IOLOCK_EXCL));

	if (SCXFS_FORCED_SHUTDOWN(ip->i_mount))
		return -EIO;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	error = scxfs_bmap_last_extent(NULL, ip, SCXFS_DATA_FORK, &got, &is_empty);
	if (!error && !is_empty && got.br_startoff >= off &&
	    ((got.br_startoff + shift) & BMBT_STARTOFF_MASK) < got.br_startoff)
		error = -EINVAL;
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);

	return error;
}

int
scxfs_bmap_insert_extents(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		*next_fsb,
	scxfs_fileoff_t		offset_shift_fsb,
	bool			*done,
	scxfs_fileoff_t		stop_fsb)
{
	int			whichfork = SCXFS_DATA_FORK;
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_btree_cur	*cur = NULL;
	struct scxfs_bmbt_irec	got, next;
	struct scxfs_iext_cursor	icur;
	scxfs_fileoff_t		new_startoff;
	int			error = 0;
	int			logflags = 0;

	if (unlikely(SCXFS_TEST_ERROR(
	    (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	     SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE),
	     mp, SCXFS_ERRTAG_BMAPIFORMAT))) {
		SCXFS_ERROR_REPORT(__func__, SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	ASSERT(scxfs_isilocked(ip, SCXFS_IOLOCK_EXCL | SCXFS_ILOCK_EXCL));

	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			return error;
	}

	if (ifp->if_flags & SCXFS_IFBROOT) {
		cur = scxfs_bmbt_init_cursor(mp, tp, ip, whichfork);
		cur->bc_private.b.flags = 0;
	}

	if (*next_fsb == NULLFSBLOCK) {
		scxfs_iext_last(ifp, &icur);
		if (!scxfs_iext_get_extent(ifp, &icur, &got) ||
		    stop_fsb > got.br_startoff) {
			*done = true;
			goto del_cursor;
		}
	} else {
		if (!scxfs_iext_lookup_extent(ip, ifp, *next_fsb, &icur, &got)) {
			*done = true;
			goto del_cursor;
		}
	}
	SCXFS_WANT_CORRUPTED_GOTO(mp, !isnullstartblock(got.br_startblock),
				del_cursor);

	if (stop_fsb >= got.br_startoff + got.br_blockcount) {
		error = -EIO;
		goto del_cursor;
	}

	new_startoff = got.br_startoff + offset_shift_fsb;
	if (scxfs_iext_peek_next_extent(ifp, &icur, &next)) {
		if (new_startoff + got.br_blockcount > next.br_startoff) {
			error = -EINVAL;
			goto del_cursor;
		}

		/*
		 * Unlike a left shift (which involves a hole punch), a right
		 * shift does not modify extent neighbors in any way.  We should
		 * never find mergeable extents in this scenario.  Check anyways
		 * and warn if we encounter two extents that could be one.
		 */
		if (scxfs_bmse_can_merge(&got, &next, offset_shift_fsb))
			WARN_ON_ONCE(1);
	}

	error = scxfs_bmap_shift_update_extent(tp, ip, whichfork, &icur, &got,
			cur, &logflags, new_startoff);
	if (error)
		goto del_cursor;

	if (!scxfs_iext_prev_extent(ifp, &icur, &got) ||
	    stop_fsb >= got.br_startoff + got.br_blockcount) {
		*done = true;
		goto del_cursor;
	}

	*next_fsb = got.br_startoff;
del_cursor:
	if (cur)
		scxfs_btree_del_cursor(cur, error);
	if (logflags)
		scxfs_trans_log_inode(tp, ip, logflags);
	return error;
}

/*
 * Splits an extent into two extents at split_fsb block such that it is the
 * first block of the current_ext. @ext is a target extent to be split.
 * @split_fsb is a block where the extents is split.  If split_fsb lies in a
 * hole or the first block of extents, just return 0.
 */
STATIC int
scxfs_bmap_split_extent_at(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	scxfs_fileoff_t		split_fsb)
{
	int				whichfork = SCXFS_DATA_FORK;
	struct scxfs_btree_cur		*cur = NULL;
	struct scxfs_bmbt_irec		got;
	struct scxfs_bmbt_irec		new; /* split extent */
	struct scxfs_mount		*mp = ip->i_mount;
	struct scxfs_ifork		*ifp;
	scxfs_fsblock_t			gotblkcnt; /* new block count for got */
	struct scxfs_iext_cursor		icur;
	int				error = 0;
	int				logflags = 0;
	int				i = 0;

	if (unlikely(SCXFS_TEST_ERROR(
	    (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	     SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_BTREE),
	     mp, SCXFS_ERRTAG_BMAPIFORMAT))) {
		SCXFS_ERROR_REPORT("scxfs_bmap_split_extent_at",
				 SCXFS_ERRLEVEL_LOW, mp);
		return -EFSCORRUPTED;
	}

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
		/* Read in all the extents */
		error = scxfs_iread_extents(tp, ip, whichfork);
		if (error)
			return error;
	}

	/*
	 * If there are not extents, or split_fsb lies in a hole we are done.
	 */
	if (!scxfs_iext_lookup_extent(ip, ifp, split_fsb, &icur, &got) ||
	    got.br_startoff >= split_fsb)
		return 0;

	gotblkcnt = split_fsb - got.br_startoff;
	new.br_startoff = split_fsb;
	new.br_startblock = got.br_startblock + gotblkcnt;
	new.br_blockcount = got.br_blockcount - gotblkcnt;
	new.br_state = got.br_state;

	if (ifp->if_flags & SCXFS_IFBROOT) {
		cur = scxfs_bmbt_init_cursor(mp, tp, ip, whichfork);
		cur->bc_private.b.flags = 0;
		error = scxfs_bmbt_lookup_eq(cur, &got, &i);
		if (error)
			goto del_cursor;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, del_cursor);
	}

	got.br_blockcount = gotblkcnt;
	scxfs_iext_update_extent(ip, scxfs_bmap_fork_to_state(whichfork), &icur,
			&got);

	logflags = SCXFS_ILOG_CORE;
	if (cur) {
		error = scxfs_bmbt_update(cur, &got);
		if (error)
			goto del_cursor;
	} else
		logflags |= SCXFS_ILOG_DEXT;

	/* Add new extent */
	scxfs_iext_next(ifp, &icur);
	scxfs_iext_insert(ip, &icur, &new, 0);
	SCXFS_IFORK_NEXT_SET(ip, whichfork,
			   SCXFS_IFORK_NEXTENTS(ip, whichfork) + 1);

	if (cur) {
		error = scxfs_bmbt_lookup_eq(cur, &new, &i);
		if (error)
			goto del_cursor;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, del_cursor);
		error = scxfs_btree_insert(cur, &i);
		if (error)
			goto del_cursor;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, del_cursor);
	}

	/*
	 * Convert to a btree if necessary.
	 */
	if (scxfs_bmap_needs_btree(ip, whichfork)) {
		int tmp_logflags; /* partial log flag return val */

		ASSERT(cur == NULL);
		error = scxfs_bmap_extents_to_btree(tp, ip, &cur, 0,
				&tmp_logflags, whichfork);
		logflags |= tmp_logflags;
	}

del_cursor:
	if (cur) {
		cur->bc_private.b.allocated = 0;
		scxfs_btree_del_cursor(cur, error);
	}

	if (logflags)
		scxfs_trans_log_inode(tp, ip, logflags);
	return error;
}

int
scxfs_bmap_split_extent(
	struct scxfs_inode        *ip,
	scxfs_fileoff_t           split_fsb)
{
	struct scxfs_mount        *mp = ip->i_mount;
	struct scxfs_trans        *tp;
	int                     error;

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_write,
			SCXFS_DIOSTRAT_SPACE_RES(mp, 0), 0, 0, &tp);
	if (error)
		return error;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);

	error = scxfs_bmap_split_extent_at(tp, ip, split_fsb);
	if (error)
		goto out;

	return scxfs_trans_commit(tp);

out:
	scxfs_trans_cancel(tp);
	return error;
}

/* Deferred mapping is only for real extents in the data fork. */
static bool
scxfs_bmap_is_update_needed(
	struct scxfs_bmbt_irec	*bmap)
{
	return  bmap->br_startblock != HOLESTARTBLOCK &&
		bmap->br_startblock != DELAYSTARTBLOCK;
}

/* Record a bmap intent. */
static int
__scxfs_bmap_add(
	struct scxfs_trans		*tp,
	enum scxfs_bmap_intent_type	type,
	struct scxfs_inode		*ip,
	int				whichfork,
	struct scxfs_bmbt_irec		*bmap)
{
	struct scxfs_bmap_intent		*bi;

	trace_scxfs_bmap_defer(tp->t_mountp,
			SCXFS_FSB_TO_AGNO(tp->t_mountp, bmap->br_startblock),
			type,
			SCXFS_FSB_TO_AGBNO(tp->t_mountp, bmap->br_startblock),
			ip->i_ino, whichfork,
			bmap->br_startoff,
			bmap->br_blockcount,
			bmap->br_state);

	bi = kmem_alloc(sizeof(struct scxfs_bmap_intent), KM_NOFS);
	INIT_LIST_HEAD(&bi->bi_list);
	bi->bi_type = type;
	bi->bi_owner = ip;
	bi->bi_whichfork = whichfork;
	bi->bi_bmap = *bmap;

	scxfs_defer_add(tp, SCXFS_DEFER_OPS_TYPE_BMAP, &bi->bi_list);
	return 0;
}

/* Map an extent into a file. */
void
scxfs_bmap_map_extent(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	struct scxfs_bmbt_irec	*PREV)
{
	if (!scxfs_bmap_is_update_needed(PREV))
		return;

	__scxfs_bmap_add(tp, SCXFS_BMAP_MAP, ip, SCXFS_DATA_FORK, PREV);
}

/* Unmap an extent out of a file. */
void
scxfs_bmap_unmap_extent(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	struct scxfs_bmbt_irec	*PREV)
{
	if (!scxfs_bmap_is_update_needed(PREV))
		return;

	__scxfs_bmap_add(tp, SCXFS_BMAP_UNMAP, ip, SCXFS_DATA_FORK, PREV);
}

/*
 * Process one of the deferred bmap operations.  We pass back the
 * btree cursor to maintain our lock on the bmapbt between calls.
 */
int
scxfs_bmap_finish_one(
	struct scxfs_trans		*tp,
	struct scxfs_inode		*ip,
	enum scxfs_bmap_intent_type	type,
	int				whichfork,
	scxfs_fileoff_t			startoff,
	scxfs_fsblock_t			startblock,
	scxfs_filblks_t			*blockcount,
	scxfs_exntst_t			state)
{
	int				error = 0;

	ASSERT(tp->t_firstblock == NULLFSBLOCK);

	trace_scxfs_bmap_deferred(tp->t_mountp,
			SCXFS_FSB_TO_AGNO(tp->t_mountp, startblock), type,
			SCXFS_FSB_TO_AGBNO(tp->t_mountp, startblock),
			ip->i_ino, whichfork, startoff, *blockcount, state);

	if (WARN_ON_ONCE(whichfork != SCXFS_DATA_FORK))
		return -EFSCORRUPTED;

	if (SCXFS_TEST_ERROR(false, tp->t_mountp,
			SCXFS_ERRTAG_BMAP_FINISH_ONE))
		return -EIO;

	switch (type) {
	case SCXFS_BMAP_MAP:
		error = scxfs_bmapi_remap(tp, ip, startoff, *blockcount,
				startblock, 0);
		*blockcount = 0;
		break;
	case SCXFS_BMAP_UNMAP:
		error = __scxfs_bunmapi(tp, ip, startoff, blockcount,
				SCXFS_BMAPI_REMAP, 1);
		break;
	default:
		ASSERT(0);
		error = -EFSCORRUPTED;
	}

	return error;
}

/* Check that an inode's extent does not have invalid flags or bad ranges. */
scxfs_failaddr_t
scxfs_bmap_validate_extent(
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_bmbt_irec	*irec)
{
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_fsblock_t		endfsb;
	bool			isrt;

	isrt = SCXFS_IS_REALTIME_INODE(ip);
	endfsb = irec->br_startblock + irec->br_blockcount - 1;
	if (isrt && whichfork == SCXFS_DATA_FORK) {
		if (!scxfs_verify_rtbno(mp, irec->br_startblock))
			return __this_address;
		if (!scxfs_verify_rtbno(mp, endfsb))
			return __this_address;
	} else {
		if (!scxfs_verify_fsbno(mp, irec->br_startblock))
			return __this_address;
		if (!scxfs_verify_fsbno(mp, endfsb))
			return __this_address;
		if (SCXFS_FSB_TO_AGNO(mp, irec->br_startblock) !=
		    SCXFS_FSB_TO_AGNO(mp, endfsb))
			return __this_address;
	}
	if (irec->br_state != SCXFS_EXT_NORM && whichfork != SCXFS_DATA_FORK)
		return __this_address;
	return NULL;
}
