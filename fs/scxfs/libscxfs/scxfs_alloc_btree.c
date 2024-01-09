// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
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
#include "scxfs_alloc_btree.h"
#include "scxfs_alloc.h"
#include "scxfs_extent_busy.h"
#include "scxfs_error.h"
#include "scxfs_trace.h"
#include "scxfs_trans.h"


STATIC struct scxfs_btree_cur *
scxfs_allocbt_dup_cursor(
	struct scxfs_btree_cur	*cur)
{
	return scxfs_allocbt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.a.agbp, cur->bc_private.a.agno,
			cur->bc_btnum);
}

STATIC void
scxfs_allocbt_set_root(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr,
	int			inc)
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	scxfs_agnumber_t		seqno = be32_to_cpu(agf->agf_seqno);
	int			btnum = cur->bc_btnum;
	struct scxfs_perag	*pag = scxfs_perag_get(cur->bc_mp, seqno);

	ASSERT(ptr->s != 0);

	agf->agf_roots[btnum] = ptr->s;
	be32_add_cpu(&agf->agf_levels[btnum], inc);
	pag->pagf_levels[btnum] += inc;
	scxfs_perag_put(pag);

	scxfs_alloc_log_agf(cur->bc_tp, agbp, SCXFS_AGF_ROOTS | SCXFS_AGF_LEVELS);
}

STATIC int
scxfs_allocbt_alloc_block(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*start,
	union scxfs_btree_ptr	*new,
	int			*stat)
{
	int			error;
	scxfs_agblock_t		bno;

	/* Allocate the new block from the freelist. If we can't, give up.  */
	error = scxfs_alloc_get_freelist(cur->bc_tp, cur->bc_private.a.agbp,
				       &bno, 1);
	if (error)
		return error;

	if (bno == NULLAGBLOCK) {
		*stat = 0;
		return 0;
	}

	scxfs_extent_busy_reuse(cur->bc_mp, cur->bc_private.a.agno, bno, 1, false);

	scxfs_trans_agbtree_delta(cur->bc_tp, 1);
	new->s = cpu_to_be32(bno);

	*stat = 1;
	return 0;
}

STATIC int
scxfs_allocbt_free_block(
	struct scxfs_btree_cur	*cur,
	struct scxfs_buf		*bp)
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	scxfs_agblock_t		bno;
	int			error;

	bno = scxfs_daddr_to_agbno(cur->bc_mp, SCXFS_BUF_ADDR(bp));
	error = scxfs_alloc_put_freelist(cur->bc_tp, agbp, NULL, bno, 1);
	if (error)
		return error;

	scxfs_extent_busy_insert(cur->bc_tp, be32_to_cpu(agf->agf_seqno), bno, 1,
			      SCXFS_EXTENT_BUSY_SKIP_DISCARD);
	scxfs_trans_agbtree_delta(cur->bc_tp, -1);
	return 0;
}

/*
 * Update the longest extent in the AGF
 */
STATIC void
scxfs_allocbt_update_lastrec(
	struct scxfs_btree_cur	*cur,
	struct scxfs_btree_block	*block,
	union scxfs_btree_rec	*rec,
	int			ptr,
	int			reason)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(cur->bc_private.a.agbp);
	scxfs_agnumber_t		seqno = be32_to_cpu(agf->agf_seqno);
	struct scxfs_perag	*pag;
	__be32			len;
	int			numrecs;

	ASSERT(cur->bc_btnum == SCXFS_BTNUM_CNT);

	switch (reason) {
	case LASTREC_UPDATE:
		/*
		 * If this is the last leaf block and it's the last record,
		 * then update the size of the longest extent in the AG.
		 */
		if (ptr != scxfs_btree_get_numrecs(block))
			return;
		len = rec->alloc.ar_blockcount;
		break;
	case LASTREC_INSREC:
		if (be32_to_cpu(rec->alloc.ar_blockcount) <=
		    be32_to_cpu(agf->agf_longest))
			return;
		len = rec->alloc.ar_blockcount;
		break;
	case LASTREC_DELREC:
		numrecs = scxfs_btree_get_numrecs(block);
		if (ptr <= numrecs)
			return;
		ASSERT(ptr == numrecs + 1);

		if (numrecs) {
			scxfs_alloc_rec_t *rrp;

			rrp = SCXFS_ALLOC_REC_ADDR(cur->bc_mp, block, numrecs);
			len = rrp->ar_blockcount;
		} else {
			len = 0;
		}

		break;
	default:
		ASSERT(0);
		return;
	}

	agf->agf_longest = len;
	pag = scxfs_perag_get(cur->bc_mp, seqno);
	pag->pagf_longest = be32_to_cpu(len);
	scxfs_perag_put(pag);
	scxfs_alloc_log_agf(cur->bc_tp, cur->bc_private.a.agbp, SCXFS_AGF_LONGEST);
}

STATIC int
scxfs_allocbt_get_minrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_alloc_mnr[level != 0];
}

STATIC int
scxfs_allocbt_get_maxrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_alloc_mxr[level != 0];
}

STATIC void
scxfs_allocbt_init_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	key->alloc.ar_startblock = rec->alloc.ar_startblock;
	key->alloc.ar_blockcount = rec->alloc.ar_blockcount;
}

STATIC void
scxfs_bnobt_init_high_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	__u32			x;

	x = be32_to_cpu(rec->alloc.ar_startblock);
	x += be32_to_cpu(rec->alloc.ar_blockcount) - 1;
	key->alloc.ar_startblock = cpu_to_be32(x);
	key->alloc.ar_blockcount = 0;
}

STATIC void
scxfs_cntbt_init_high_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	key->alloc.ar_blockcount = rec->alloc.ar_blockcount;
	key->alloc.ar_startblock = 0;
}

STATIC void
scxfs_allocbt_init_rec_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*rec)
{
	rec->alloc.ar_startblock = cpu_to_be32(cur->bc_rec.a.ar_startblock);
	rec->alloc.ar_blockcount = cpu_to_be32(cur->bc_rec.a.ar_blockcount);
}

STATIC void
scxfs_allocbt_init_ptr_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agf->agf_seqno));

	ptr->s = agf->agf_roots[cur->bc_btnum];
}

STATIC int64_t
scxfs_bnobt_key_diff(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*key)
{
	scxfs_alloc_rec_incore_t	*rec = &cur->bc_rec.a;
	scxfs_alloc_key_t		*kp = &key->alloc;

	return (int64_t)be32_to_cpu(kp->ar_startblock) - rec->ar_startblock;
}

STATIC int64_t
scxfs_cntbt_key_diff(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*key)
{
	scxfs_alloc_rec_incore_t	*rec = &cur->bc_rec.a;
	scxfs_alloc_key_t		*kp = &key->alloc;
	int64_t			diff;

	diff = (int64_t)be32_to_cpu(kp->ar_blockcount) - rec->ar_blockcount;
	if (diff)
		return diff;

	return (int64_t)be32_to_cpu(kp->ar_startblock) - rec->ar_startblock;
}

STATIC int64_t
scxfs_bnobt_diff_two_keys(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return (int64_t)be32_to_cpu(k1->alloc.ar_startblock) -
			  be32_to_cpu(k2->alloc.ar_startblock);
}

STATIC int64_t
scxfs_cntbt_diff_two_keys(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	int64_t			diff;

	diff =  be32_to_cpu(k1->alloc.ar_blockcount) -
		be32_to_cpu(k2->alloc.ar_blockcount);
	if (diff)
		return diff;

	return  be32_to_cpu(k1->alloc.ar_startblock) -
		be32_to_cpu(k2->alloc.ar_startblock);
}

static scxfs_failaddr_t
scxfs_allocbt_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_btree_block	*block = SCXFS_BUF_TO_BLOCK(bp);
	struct scxfs_perag	*pag = bp->b_pag;
	scxfs_failaddr_t		fa;
	unsigned int		level;
	scxfs_btnum_t		btnum = SCXFS_BTNUM_BNOi;

	if (!scxfs_verify_magic(bp, block->bb_magic))
		return __this_address;

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		fa = scxfs_btree_sblock_v5hdr_verify(bp);
		if (fa)
			return fa;
	}

	/*
	 * The perag may not be attached during grow operations or fully
	 * initialized from the AGF during log recovery. Therefore we can only
	 * check against maximum tree depth from those contexts.
	 *
	 * Otherwise check against the per-tree limit. Peek at one of the
	 * verifier magic values to determine the type of tree we're verifying
	 * against.
	 */
	level = be16_to_cpu(block->bb_level);
	if (bp->b_ops->magic[0] == cpu_to_be32(SCXFS_ABTC_MAGIC))
		btnum = SCXFS_BTNUM_CNTi;
	if (pag && pag->pagf_init) {
		if (level >= pag->pagf_levels[btnum])
			return __this_address;
	} else if (level >= mp->m_ag_maxlevels)
		return __this_address;

	return scxfs_btree_sblock_verify(bp, mp->m_alloc_mxr[level != 0]);
}

static void
scxfs_allocbt_read_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	if (!scxfs_btree_sblock_verify_crc(bp))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_allocbt_verify(bp);
		if (fa)
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}

	if (bp->b_error)
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
}

static void
scxfs_allocbt_write_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	fa = scxfs_allocbt_verify(bp);
	if (fa) {
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}
	scxfs_btree_sblock_calc_crc(bp);

}

const struct scxfs_buf_ops scxfs_bnobt_buf_ops = {
	.name = "scxfs_bnobt",
	.magic = { cpu_to_be32(SCXFS_ABTB_MAGIC),
		   cpu_to_be32(SCXFS_ABTB_CRC_MAGIC) },
	.verify_read = scxfs_allocbt_read_verify,
	.verify_write = scxfs_allocbt_write_verify,
	.verify_struct = scxfs_allocbt_verify,
};

const struct scxfs_buf_ops scxfs_cntbt_buf_ops = {
	.name = "scxfs_cntbt",
	.magic = { cpu_to_be32(SCXFS_ABTC_MAGIC),
		   cpu_to_be32(SCXFS_ABTC_CRC_MAGIC) },
	.verify_read = scxfs_allocbt_read_verify,
	.verify_write = scxfs_allocbt_write_verify,
	.verify_struct = scxfs_allocbt_verify,
};

STATIC int
scxfs_bnobt_keys_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return be32_to_cpu(k1->alloc.ar_startblock) <
	       be32_to_cpu(k2->alloc.ar_startblock);
}

STATIC int
scxfs_bnobt_recs_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*r1,
	union scxfs_btree_rec	*r2)
{
	return be32_to_cpu(r1->alloc.ar_startblock) +
		be32_to_cpu(r1->alloc.ar_blockcount) <=
		be32_to_cpu(r2->alloc.ar_startblock);
}

STATIC int
scxfs_cntbt_keys_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return be32_to_cpu(k1->alloc.ar_blockcount) <
		be32_to_cpu(k2->alloc.ar_blockcount) ||
		(k1->alloc.ar_blockcount == k2->alloc.ar_blockcount &&
		 be32_to_cpu(k1->alloc.ar_startblock) <
		 be32_to_cpu(k2->alloc.ar_startblock));
}

STATIC int
scxfs_cntbt_recs_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*r1,
	union scxfs_btree_rec	*r2)
{
	return be32_to_cpu(r1->alloc.ar_blockcount) <
		be32_to_cpu(r2->alloc.ar_blockcount) ||
		(r1->alloc.ar_blockcount == r2->alloc.ar_blockcount &&
		 be32_to_cpu(r1->alloc.ar_startblock) <
		 be32_to_cpu(r2->alloc.ar_startblock));
}

static const struct scxfs_btree_ops scxfs_bnobt_ops = {
	.rec_len		= sizeof(scxfs_alloc_rec_t),
	.key_len		= sizeof(scxfs_alloc_key_t),

	.dup_cursor		= scxfs_allocbt_dup_cursor,
	.set_root		= scxfs_allocbt_set_root,
	.alloc_block		= scxfs_allocbt_alloc_block,
	.free_block		= scxfs_allocbt_free_block,
	.update_lastrec		= scxfs_allocbt_update_lastrec,
	.get_minrecs		= scxfs_allocbt_get_minrecs,
	.get_maxrecs		= scxfs_allocbt_get_maxrecs,
	.init_key_from_rec	= scxfs_allocbt_init_key_from_rec,
	.init_high_key_from_rec	= scxfs_bnobt_init_high_key_from_rec,
	.init_rec_from_cur	= scxfs_allocbt_init_rec_from_cur,
	.init_ptr_from_cur	= scxfs_allocbt_init_ptr_from_cur,
	.key_diff		= scxfs_bnobt_key_diff,
	.buf_ops		= &scxfs_bnobt_buf_ops,
	.diff_two_keys		= scxfs_bnobt_diff_two_keys,
	.keys_inorder		= scxfs_bnobt_keys_inorder,
	.recs_inorder		= scxfs_bnobt_recs_inorder,
};

static const struct scxfs_btree_ops scxfs_cntbt_ops = {
	.rec_len		= sizeof(scxfs_alloc_rec_t),
	.key_len		= sizeof(scxfs_alloc_key_t),

	.dup_cursor		= scxfs_allocbt_dup_cursor,
	.set_root		= scxfs_allocbt_set_root,
	.alloc_block		= scxfs_allocbt_alloc_block,
	.free_block		= scxfs_allocbt_free_block,
	.update_lastrec		= scxfs_allocbt_update_lastrec,
	.get_minrecs		= scxfs_allocbt_get_minrecs,
	.get_maxrecs		= scxfs_allocbt_get_maxrecs,
	.init_key_from_rec	= scxfs_allocbt_init_key_from_rec,
	.init_high_key_from_rec	= scxfs_cntbt_init_high_key_from_rec,
	.init_rec_from_cur	= scxfs_allocbt_init_rec_from_cur,
	.init_ptr_from_cur	= scxfs_allocbt_init_ptr_from_cur,
	.key_diff		= scxfs_cntbt_key_diff,
	.buf_ops		= &scxfs_cntbt_buf_ops,
	.diff_two_keys		= scxfs_cntbt_diff_two_keys,
	.keys_inorder		= scxfs_cntbt_keys_inorder,
	.recs_inorder		= scxfs_cntbt_recs_inorder,
};

/*
 * Allocate a new allocation btree cursor.
 */
struct scxfs_btree_cur *			/* new alloc btree cursor */
scxfs_allocbt_init_cursor(
	struct scxfs_mount	*mp,		/* file system mount point */
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_buf		*agbp,		/* buffer for agf structure */
	scxfs_agnumber_t		agno,		/* allocation group number */
	scxfs_btnum_t		btnum)		/* btree identifier */
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	struct scxfs_btree_cur	*cur;

	ASSERT(btnum == SCXFS_BTNUM_BNO || btnum == SCXFS_BTNUM_CNT);

	cur = kmem_zone_zalloc(scxfs_btree_cur_zone, KM_NOFS);

	cur->bc_tp = tp;
	cur->bc_mp = mp;
	cur->bc_btnum = btnum;
	cur->bc_blocklog = mp->m_sb.sb_blocklog;

	if (btnum == SCXFS_BTNUM_CNT) {
		cur->bc_statoff = SCXFS_STATS_CALC_INDEX(xs_abtc_2);
		cur->bc_ops = &scxfs_cntbt_ops;
		cur->bc_nlevels = be32_to_cpu(agf->agf_levels[SCXFS_BTNUM_CNT]);
		cur->bc_flags = SCXFS_BTREE_LASTREC_UPDATE;
	} else {
		cur->bc_statoff = SCXFS_STATS_CALC_INDEX(xs_abtb_2);
		cur->bc_ops = &scxfs_bnobt_ops;
		cur->bc_nlevels = be32_to_cpu(agf->agf_levels[SCXFS_BTNUM_BNO]);
	}

	cur->bc_private.a.agbp = agbp;
	cur->bc_private.a.agno = agno;

	if (scxfs_sb_version_hascrc(&mp->m_sb))
		cur->bc_flags |= SCXFS_BTREE_CRC_BLOCKS;

	return cur;
}

/*
 * Calculate number of records in an alloc btree block.
 */
int
scxfs_allocbt_maxrecs(
	struct scxfs_mount	*mp,
	int			blocklen,
	int			leaf)
{
	blocklen -= SCXFS_ALLOC_BLOCK_LEN(mp);

	if (leaf)
		return blocklen / sizeof(scxfs_alloc_rec_t);
	return blocklen / (sizeof(scxfs_alloc_key_t) + sizeof(scxfs_alloc_ptr_t));
}

/* Calculate the freespace btree size for some records. */
scxfs_extlen_t
scxfs_allocbt_calc_size(
	struct scxfs_mount	*mp,
	unsigned long long	len)
{
	return scxfs_btree_calc_size(mp->m_alloc_mnr, len);
}
