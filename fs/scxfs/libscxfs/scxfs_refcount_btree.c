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
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_btree.h"
#include "scxfs_refcount_btree.h"
#include "scxfs_alloc.h"
#include "scxfs_error.h"
#include "scxfs_trace.h"
#include "scxfs_trans.h"
#include "scxfs_bit.h"
#include "scxfs_rmap.h"

static struct scxfs_btree_cur *
scxfs_refcountbt_dup_cursor(
	struct scxfs_btree_cur	*cur)
{
	return scxfs_refcountbt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.a.agbp, cur->bc_private.a.agno);
}

STATIC void
scxfs_refcountbt_set_root(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr,
	int			inc)
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	scxfs_agnumber_t		seqno = be32_to_cpu(agf->agf_seqno);
	struct scxfs_perag	*pag = scxfs_perag_get(cur->bc_mp, seqno);

	ASSERT(ptr->s != 0);

	agf->agf_refcount_root = ptr->s;
	be32_add_cpu(&agf->agf_refcount_level, inc);
	pag->pagf_refcount_level += inc;
	scxfs_perag_put(pag);

	scxfs_alloc_log_agf(cur->bc_tp, agbp,
			SCXFS_AGF_REFCOUNT_ROOT | SCXFS_AGF_REFCOUNT_LEVEL);
}

STATIC int
scxfs_refcountbt_alloc_block(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*start,
	union scxfs_btree_ptr	*new,
	int			*stat)
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	struct scxfs_alloc_arg	args;		/* block allocation args */
	int			error;		/* error return value */

	memset(&args, 0, sizeof(args));
	args.tp = cur->bc_tp;
	args.mp = cur->bc_mp;
	args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
	args.fsbno = SCXFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
			scxfs_refc_block(args.mp));
	args.oinfo = SCXFS_RMAP_OINFO_REFC;
	args.minlen = args.maxlen = args.prod = 1;
	args.resv = SCXFS_AG_RESV_METADATA;

	error = scxfs_alloc_vextent(&args);
	if (error)
		goto out_error;
	trace_scxfs_refcountbt_alloc_block(cur->bc_mp, cur->bc_private.a.agno,
			args.agbno, 1);
	if (args.fsbno == NULLFSBLOCK) {
		*stat = 0;
		return 0;
	}
	ASSERT(args.agno == cur->bc_private.a.agno);
	ASSERT(args.len == 1);

	new->s = cpu_to_be32(args.agbno);
	be32_add_cpu(&agf->agf_refcount_blocks, 1);
	scxfs_alloc_log_agf(cur->bc_tp, agbp, SCXFS_AGF_REFCOUNT_BLOCKS);

	*stat = 1;
	return 0;

out_error:
	return error;
}

STATIC int
scxfs_refcountbt_free_block(
	struct scxfs_btree_cur	*cur,
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = cur->bc_mp;
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	scxfs_fsblock_t		fsbno = SCXFS_DADDR_TO_FSB(mp, SCXFS_BUF_ADDR(bp));
	int			error;

	trace_scxfs_refcountbt_free_block(cur->bc_mp, cur->bc_private.a.agno,
			SCXFS_FSB_TO_AGBNO(cur->bc_mp, fsbno), 1);
	be32_add_cpu(&agf->agf_refcount_blocks, -1);
	scxfs_alloc_log_agf(cur->bc_tp, agbp, SCXFS_AGF_REFCOUNT_BLOCKS);
	error = scxfs_free_extent(cur->bc_tp, fsbno, 1, &SCXFS_RMAP_OINFO_REFC,
			SCXFS_AG_RESV_METADATA);
	if (error)
		return error;

	return error;
}

STATIC int
scxfs_refcountbt_get_minrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_refc_mnr[level != 0];
}

STATIC int
scxfs_refcountbt_get_maxrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_refc_mxr[level != 0];
}

STATIC void
scxfs_refcountbt_init_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	key->refc.rc_startblock = rec->refc.rc_startblock;
}

STATIC void
scxfs_refcountbt_init_high_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	__u32			x;

	x = be32_to_cpu(rec->refc.rc_startblock);
	x += be32_to_cpu(rec->refc.rc_blockcount) - 1;
	key->refc.rc_startblock = cpu_to_be32(x);
}

STATIC void
scxfs_refcountbt_init_rec_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*rec)
{
	rec->refc.rc_startblock = cpu_to_be32(cur->bc_rec.rc.rc_startblock);
	rec->refc.rc_blockcount = cpu_to_be32(cur->bc_rec.rc.rc_blockcount);
	rec->refc.rc_refcount = cpu_to_be32(cur->bc_rec.rc.rc_refcount);
}

STATIC void
scxfs_refcountbt_init_ptr_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agf->agf_seqno));

	ptr->s = agf->agf_refcount_root;
}

STATIC int64_t
scxfs_refcountbt_key_diff(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*key)
{
	struct scxfs_refcount_irec	*rec = &cur->bc_rec.rc;
	struct scxfs_refcount_key		*kp = &key->refc;

	return (int64_t)be32_to_cpu(kp->rc_startblock) - rec->rc_startblock;
}

STATIC int64_t
scxfs_refcountbt_diff_two_keys(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return (int64_t)be32_to_cpu(k1->refc.rc_startblock) -
			  be32_to_cpu(k2->refc.rc_startblock);
}

STATIC scxfs_failaddr_t
scxfs_refcountbt_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_btree_block	*block = SCXFS_BUF_TO_BLOCK(bp);
	struct scxfs_perag	*pag = bp->b_pag;
	scxfs_failaddr_t		fa;
	unsigned int		level;

	if (!scxfs_verify_magic(bp, block->bb_magic))
		return __this_address;

	if (!scxfs_sb_version_hasreflink(&mp->m_sb))
		return __this_address;
	fa = scxfs_btree_sblock_v5hdr_verify(bp);
	if (fa)
		return fa;

	level = be16_to_cpu(block->bb_level);
	if (pag && pag->pagf_init) {
		if (level >= pag->pagf_refcount_level)
			return __this_address;
	} else if (level >= mp->m_refc_maxlevels)
		return __this_address;

	return scxfs_btree_sblock_verify(bp, mp->m_refc_mxr[level != 0]);
}

STATIC void
scxfs_refcountbt_read_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	if (!scxfs_btree_sblock_verify_crc(bp))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_refcountbt_verify(bp);
		if (fa)
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}

	if (bp->b_error)
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
}

STATIC void
scxfs_refcountbt_write_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	fa = scxfs_refcountbt_verify(bp);
	if (fa) {
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}
	scxfs_btree_sblock_calc_crc(bp);

}

const struct scxfs_buf_ops scxfs_refcountbt_buf_ops = {
	.name			= "scxfs_refcountbt",
	.magic			= { 0, cpu_to_be32(SCXFS_REFC_CRC_MAGIC) },
	.verify_read		= scxfs_refcountbt_read_verify,
	.verify_write		= scxfs_refcountbt_write_verify,
	.verify_struct		= scxfs_refcountbt_verify,
};

STATIC int
scxfs_refcountbt_keys_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return be32_to_cpu(k1->refc.rc_startblock) <
	       be32_to_cpu(k2->refc.rc_startblock);
}

STATIC int
scxfs_refcountbt_recs_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*r1,
	union scxfs_btree_rec	*r2)
{
	return  be32_to_cpu(r1->refc.rc_startblock) +
		be32_to_cpu(r1->refc.rc_blockcount) <=
		be32_to_cpu(r2->refc.rc_startblock);
}

static const struct scxfs_btree_ops scxfs_refcountbt_ops = {
	.rec_len		= sizeof(struct scxfs_refcount_rec),
	.key_len		= sizeof(struct scxfs_refcount_key),

	.dup_cursor		= scxfs_refcountbt_dup_cursor,
	.set_root		= scxfs_refcountbt_set_root,
	.alloc_block		= scxfs_refcountbt_alloc_block,
	.free_block		= scxfs_refcountbt_free_block,
	.get_minrecs		= scxfs_refcountbt_get_minrecs,
	.get_maxrecs		= scxfs_refcountbt_get_maxrecs,
	.init_key_from_rec	= scxfs_refcountbt_init_key_from_rec,
	.init_high_key_from_rec	= scxfs_refcountbt_init_high_key_from_rec,
	.init_rec_from_cur	= scxfs_refcountbt_init_rec_from_cur,
	.init_ptr_from_cur	= scxfs_refcountbt_init_ptr_from_cur,
	.key_diff		= scxfs_refcountbt_key_diff,
	.buf_ops		= &scxfs_refcountbt_buf_ops,
	.diff_two_keys		= scxfs_refcountbt_diff_two_keys,
	.keys_inorder		= scxfs_refcountbt_keys_inorder,
	.recs_inorder		= scxfs_refcountbt_recs_inorder,
};

/*
 * Allocate a new refcount btree cursor.
 */
struct scxfs_btree_cur *
scxfs_refcountbt_init_cursor(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct scxfs_buf		*agbp,
	scxfs_agnumber_t		agno)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	struct scxfs_btree_cur	*cur;

	ASSERT(agno != NULLAGNUMBER);
	ASSERT(agno < mp->m_sb.sb_agcount);
	cur = kmem_zone_zalloc(scxfs_btree_cur_zone, KM_NOFS);

	cur->bc_tp = tp;
	cur->bc_mp = mp;
	cur->bc_btnum = SCXFS_BTNUM_REFC;
	cur->bc_blocklog = mp->m_sb.sb_blocklog;
	cur->bc_ops = &scxfs_refcountbt_ops;
	cur->bc_statoff = SCXFS_STATS_CALC_INDEX(xs_refcbt_2);

	cur->bc_nlevels = be32_to_cpu(agf->agf_refcount_level);

	cur->bc_private.a.agbp = agbp;
	cur->bc_private.a.agno = agno;
	cur->bc_flags |= SCXFS_BTREE_CRC_BLOCKS;

	cur->bc_private.a.priv.refc.nr_ops = 0;
	cur->bc_private.a.priv.refc.shape_changes = 0;

	return cur;
}

/*
 * Calculate the number of records in a refcount btree block.
 */
int
scxfs_refcountbt_maxrecs(
	int			blocklen,
	bool			leaf)
{
	blocklen -= SCXFS_REFCOUNT_BLOCK_LEN;

	if (leaf)
		return blocklen / sizeof(struct scxfs_refcount_rec);
	return blocklen / (sizeof(struct scxfs_refcount_key) +
			   sizeof(scxfs_refcount_ptr_t));
}

/* Compute the maximum height of a refcount btree. */
void
scxfs_refcountbt_compute_maxlevels(
	struct scxfs_mount		*mp)
{
	mp->m_refc_maxlevels = scxfs_btree_compute_maxlevels(
			mp->m_refc_mnr, mp->m_sb.sb_agblocks);
}

/* Calculate the refcount btree size for some records. */
scxfs_extlen_t
scxfs_refcountbt_calc_size(
	struct scxfs_mount	*mp,
	unsigned long long	len)
{
	return scxfs_btree_calc_size(mp->m_refc_mnr, len);
}

/*
 * Calculate the maximum refcount btree size.
 */
scxfs_extlen_t
scxfs_refcountbt_max_size(
	struct scxfs_mount	*mp,
	scxfs_agblock_t		agblocks)
{
	/* Bail out if we're uninitialized, which can happen in mkfs. */
	if (mp->m_refc_mxr[0] == 0)
		return 0;

	return scxfs_refcountbt_calc_size(mp, agblocks);
}

/*
 * Figure out how many blocks to reserve and how many are used by this btree.
 */
int
scxfs_refcountbt_calc_reserves(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_extlen_t		*ask,
	scxfs_extlen_t		*used)
{
	struct scxfs_buf		*agbp;
	struct scxfs_agf		*agf;
	scxfs_agblock_t		agblocks;
	scxfs_extlen_t		tree_len;
	int			error;

	if (!scxfs_sb_version_hasreflink(&mp->m_sb))
		return 0;


	error = scxfs_alloc_read_agf(mp, tp, agno, 0, &agbp);
	if (error)
		return error;

	agf = SCXFS_BUF_TO_AGF(agbp);
	agblocks = be32_to_cpu(agf->agf_length);
	tree_len = be32_to_cpu(agf->agf_refcount_blocks);
	scxfs_trans_brelse(tp, agbp);

	/*
	 * The log is permanently allocated, so the space it occupies will
	 * never be available for the kinds of things that would require btree
	 * expansion.  We therefore can pretend the space isn't there.
	 */
	if (mp->m_sb.sb_logstart &&
	    SCXFS_FSB_TO_AGNO(mp, mp->m_sb.sb_logstart) == agno)
		agblocks -= mp->m_sb.sb_logblocks;

	*ask += scxfs_refcountbt_max_size(mp, agblocks);
	*used += tree_len;

	return error;
}
