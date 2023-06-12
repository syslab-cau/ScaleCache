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
#include "scxfs_bit.h"
#include "scxfs_mount.h"
#include "scxfs_btree.h"
#include "scxfs_ialloc.h"
#include "scxfs_ialloc_btree.h"
#include "scxfs_alloc.h"
#include "scxfs_error.h"
#include "scxfs_trace.h"
#include "scxfs_trans.h"
#include "scxfs_rmap.h"


STATIC int
scxfs_inobt_get_minrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return M_IGEO(cur->bc_mp)->inobt_mnr[level != 0];
}

STATIC struct scxfs_btree_cur *
scxfs_inobt_dup_cursor(
	struct scxfs_btree_cur	*cur)
{
	return scxfs_inobt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.a.agbp, cur->bc_private.a.agno,
			cur->bc_btnum);
}

STATIC void
scxfs_inobt_set_root(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*nptr,
	int			inc)	/* level change */
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agbp);

	agi->agi_root = nptr->s;
	be32_add_cpu(&agi->agi_level, inc);
	scxfs_ialloc_log_agi(cur->bc_tp, agbp, SCXFS_AGI_ROOT | SCXFS_AGI_LEVEL);
}

STATIC void
scxfs_finobt_set_root(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*nptr,
	int			inc)	/* level change */
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agbp);

	agi->agi_free_root = nptr->s;
	be32_add_cpu(&agi->agi_free_level, inc);
	scxfs_ialloc_log_agi(cur->bc_tp, agbp,
			   SCXFS_AGI_FREE_ROOT | SCXFS_AGI_FREE_LEVEL);
}

STATIC int
__scxfs_inobt_alloc_block(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*start,
	union scxfs_btree_ptr	*new,
	int			*stat,
	enum scxfs_ag_resv_type	resv)
{
	scxfs_alloc_arg_t		args;		/* block allocation args */
	int			error;		/* error return value */
	scxfs_agblock_t		sbno = be32_to_cpu(start->s);

	memset(&args, 0, sizeof(args));
	args.tp = cur->bc_tp;
	args.mp = cur->bc_mp;
	args.oinfo = SCXFS_RMAP_OINFO_INOBT;
	args.fsbno = SCXFS_AGB_TO_FSB(args.mp, cur->bc_private.a.agno, sbno);
	args.minlen = 1;
	args.maxlen = 1;
	args.prod = 1;
	args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
	args.resv = resv;

	error = scxfs_alloc_vextent(&args);
	if (error)
		return error;

	if (args.fsbno == NULLFSBLOCK) {
		*stat = 0;
		return 0;
	}
	ASSERT(args.len == 1);

	new->s = cpu_to_be32(SCXFS_FSB_TO_AGBNO(args.mp, args.fsbno));
	*stat = 1;
	return 0;
}

STATIC int
scxfs_inobt_alloc_block(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*start,
	union scxfs_btree_ptr	*new,
	int			*stat)
{
	return __scxfs_inobt_alloc_block(cur, start, new, stat, SCXFS_AG_RESV_NONE);
}

STATIC int
scxfs_finobt_alloc_block(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*start,
	union scxfs_btree_ptr	*new,
	int			*stat)
{
	if (cur->bc_mp->m_finobt_nores)
		return scxfs_inobt_alloc_block(cur, start, new, stat);
	return __scxfs_inobt_alloc_block(cur, start, new, stat,
			SCXFS_AG_RESV_METADATA);
}

STATIC int
__scxfs_inobt_free_block(
	struct scxfs_btree_cur	*cur,
	struct scxfs_buf		*bp,
	enum scxfs_ag_resv_type	resv)
{
	return scxfs_free_extent(cur->bc_tp,
			SCXFS_DADDR_TO_FSB(cur->bc_mp, SCXFS_BUF_ADDR(bp)), 1,
			&SCXFS_RMAP_OINFO_INOBT, resv);
}

STATIC int
scxfs_inobt_free_block(
	struct scxfs_btree_cur	*cur,
	struct scxfs_buf		*bp)
{
	return __scxfs_inobt_free_block(cur, bp, SCXFS_AG_RESV_NONE);
}

STATIC int
scxfs_finobt_free_block(
	struct scxfs_btree_cur	*cur,
	struct scxfs_buf		*bp)
{
	if (cur->bc_mp->m_finobt_nores)
		return scxfs_inobt_free_block(cur, bp);
	return __scxfs_inobt_free_block(cur, bp, SCXFS_AG_RESV_METADATA);
}

STATIC int
scxfs_inobt_get_maxrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return M_IGEO(cur->bc_mp)->inobt_mxr[level != 0];
}

STATIC void
scxfs_inobt_init_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	key->inobt.ir_startino = rec->inobt.ir_startino;
}

STATIC void
scxfs_inobt_init_high_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	__u32			x;

	x = be32_to_cpu(rec->inobt.ir_startino);
	x += SCXFS_INODES_PER_CHUNK - 1;
	key->inobt.ir_startino = cpu_to_be32(x);
}

STATIC void
scxfs_inobt_init_rec_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*rec)
{
	rec->inobt.ir_startino = cpu_to_be32(cur->bc_rec.i.ir_startino);
	if (scxfs_sb_version_hassparseinodes(&cur->bc_mp->m_sb)) {
		rec->inobt.ir_u.sp.ir_holemask =
					cpu_to_be16(cur->bc_rec.i.ir_holemask);
		rec->inobt.ir_u.sp.ir_count = cur->bc_rec.i.ir_count;
		rec->inobt.ir_u.sp.ir_freecount = cur->bc_rec.i.ir_freecount;
	} else {
		/* ir_holemask/ir_count not supported on-disk */
		rec->inobt.ir_u.f.ir_freecount =
					cpu_to_be32(cur->bc_rec.i.ir_freecount);
	}
	rec->inobt.ir_free = cpu_to_be64(cur->bc_rec.i.ir_free);
}

/*
 * initial value of ptr for lookup
 */
STATIC void
scxfs_inobt_init_ptr_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr)
{
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agi->agi_seqno));

	ptr->s = agi->agi_root;
}

STATIC void
scxfs_finobt_init_ptr_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr)
{
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agi->agi_seqno));
	ptr->s = agi->agi_free_root;
}

STATIC int64_t
scxfs_inobt_key_diff(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*key)
{
	return (int64_t)be32_to_cpu(key->inobt.ir_startino) -
			  cur->bc_rec.i.ir_startino;
}

STATIC int64_t
scxfs_inobt_diff_two_keys(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return (int64_t)be32_to_cpu(k1->inobt.ir_startino) -
			  be32_to_cpu(k2->inobt.ir_startino);
}

static scxfs_failaddr_t
scxfs_inobt_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_btree_block	*block = SCXFS_BUF_TO_BLOCK(bp);
	scxfs_failaddr_t		fa;
	unsigned int		level;

	if (!scxfs_verify_magic(bp, block->bb_magic))
		return __this_address;

	/*
	 * During growfs operations, we can't verify the exact owner as the
	 * perag is not fully initialised and hence not attached to the buffer.
	 *
	 * Similarly, during log recovery we will have a perag structure
	 * attached, but the agi information will not yet have been initialised
	 * from the on disk AGI. We don't currently use any of this information,
	 * but beware of the landmine (i.e. need to check pag->pagi_init) if we
	 * ever do.
	 */
	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		fa = scxfs_btree_sblock_v5hdr_verify(bp);
		if (fa)
			return fa;
	}

	/* level verification */
	level = be16_to_cpu(block->bb_level);
	if (level >= M_IGEO(mp)->inobt_maxlevels)
		return __this_address;

	return scxfs_btree_sblock_verify(bp,
			M_IGEO(mp)->inobt_mxr[level != 0]);
}

static void
scxfs_inobt_read_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	if (!scxfs_btree_sblock_verify_crc(bp))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_inobt_verify(bp);
		if (fa)
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}

	if (bp->b_error)
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
}

static void
scxfs_inobt_write_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	fa = scxfs_inobt_verify(bp);
	if (fa) {
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}
	scxfs_btree_sblock_calc_crc(bp);

}

const struct scxfs_buf_ops scxfs_inobt_buf_ops = {
	.name = "scxfs_inobt",
	.magic = { cpu_to_be32(SCXFS_IBT_MAGIC), cpu_to_be32(SCXFS_IBT_CRC_MAGIC) },
	.verify_read = scxfs_inobt_read_verify,
	.verify_write = scxfs_inobt_write_verify,
	.verify_struct = scxfs_inobt_verify,
};

const struct scxfs_buf_ops scxfs_finobt_buf_ops = {
	.name = "scxfs_finobt",
	.magic = { cpu_to_be32(SCXFS_FIBT_MAGIC),
		   cpu_to_be32(SCXFS_FIBT_CRC_MAGIC) },
	.verify_read = scxfs_inobt_read_verify,
	.verify_write = scxfs_inobt_write_verify,
	.verify_struct = scxfs_inobt_verify,
};

STATIC int
scxfs_inobt_keys_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return be32_to_cpu(k1->inobt.ir_startino) <
		be32_to_cpu(k2->inobt.ir_startino);
}

STATIC int
scxfs_inobt_recs_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*r1,
	union scxfs_btree_rec	*r2)
{
	return be32_to_cpu(r1->inobt.ir_startino) + SCXFS_INODES_PER_CHUNK <=
		be32_to_cpu(r2->inobt.ir_startino);
}

static const struct scxfs_btree_ops scxfs_inobt_ops = {
	.rec_len		= sizeof(scxfs_inobt_rec_t),
	.key_len		= sizeof(scxfs_inobt_key_t),

	.dup_cursor		= scxfs_inobt_dup_cursor,
	.set_root		= scxfs_inobt_set_root,
	.alloc_block		= scxfs_inobt_alloc_block,
	.free_block		= scxfs_inobt_free_block,
	.get_minrecs		= scxfs_inobt_get_minrecs,
	.get_maxrecs		= scxfs_inobt_get_maxrecs,
	.init_key_from_rec	= scxfs_inobt_init_key_from_rec,
	.init_high_key_from_rec	= scxfs_inobt_init_high_key_from_rec,
	.init_rec_from_cur	= scxfs_inobt_init_rec_from_cur,
	.init_ptr_from_cur	= scxfs_inobt_init_ptr_from_cur,
	.key_diff		= scxfs_inobt_key_diff,
	.buf_ops		= &scxfs_inobt_buf_ops,
	.diff_two_keys		= scxfs_inobt_diff_two_keys,
	.keys_inorder		= scxfs_inobt_keys_inorder,
	.recs_inorder		= scxfs_inobt_recs_inorder,
};

static const struct scxfs_btree_ops scxfs_finobt_ops = {
	.rec_len		= sizeof(scxfs_inobt_rec_t),
	.key_len		= sizeof(scxfs_inobt_key_t),

	.dup_cursor		= scxfs_inobt_dup_cursor,
	.set_root		= scxfs_finobt_set_root,
	.alloc_block		= scxfs_finobt_alloc_block,
	.free_block		= scxfs_finobt_free_block,
	.get_minrecs		= scxfs_inobt_get_minrecs,
	.get_maxrecs		= scxfs_inobt_get_maxrecs,
	.init_key_from_rec	= scxfs_inobt_init_key_from_rec,
	.init_high_key_from_rec	= scxfs_inobt_init_high_key_from_rec,
	.init_rec_from_cur	= scxfs_inobt_init_rec_from_cur,
	.init_ptr_from_cur	= scxfs_finobt_init_ptr_from_cur,
	.key_diff		= scxfs_inobt_key_diff,
	.buf_ops		= &scxfs_finobt_buf_ops,
	.diff_two_keys		= scxfs_inobt_diff_two_keys,
	.keys_inorder		= scxfs_inobt_keys_inorder,
	.recs_inorder		= scxfs_inobt_recs_inorder,
};

/*
 * Allocate a new inode btree cursor.
 */
struct scxfs_btree_cur *				/* new inode btree cursor */
scxfs_inobt_init_cursor(
	struct scxfs_mount	*mp,		/* file system mount point */
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_buf		*agbp,		/* buffer for agi structure */
	scxfs_agnumber_t		agno,		/* allocation group number */
	scxfs_btnum_t		btnum)		/* ialloc or free ino btree */
{
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agbp);
	struct scxfs_btree_cur	*cur;

	cur = kmem_zone_zalloc(scxfs_btree_cur_zone, KM_NOFS);

	cur->bc_tp = tp;
	cur->bc_mp = mp;
	cur->bc_btnum = btnum;
	if (btnum == SCXFS_BTNUM_INO) {
		cur->bc_nlevels = be32_to_cpu(agi->agi_level);
		cur->bc_ops = &scxfs_inobt_ops;
		cur->bc_statoff = SCXFS_STATS_CALC_INDEX(xs_ibt_2);
	} else {
		cur->bc_nlevels = be32_to_cpu(agi->agi_free_level);
		cur->bc_ops = &scxfs_finobt_ops;
		cur->bc_statoff = SCXFS_STATS_CALC_INDEX(xs_fibt_2);
	}

	cur->bc_blocklog = mp->m_sb.sb_blocklog;

	if (scxfs_sb_version_hascrc(&mp->m_sb))
		cur->bc_flags |= SCXFS_BTREE_CRC_BLOCKS;

	cur->bc_private.a.agbp = agbp;
	cur->bc_private.a.agno = agno;

	return cur;
}

/*
 * Calculate number of records in an inobt btree block.
 */
int
scxfs_inobt_maxrecs(
	struct scxfs_mount	*mp,
	int			blocklen,
	int			leaf)
{
	blocklen -= SCXFS_INOBT_BLOCK_LEN(mp);

	if (leaf)
		return blocklen / sizeof(scxfs_inobt_rec_t);
	return blocklen / (sizeof(scxfs_inobt_key_t) + sizeof(scxfs_inobt_ptr_t));
}

/*
 * Convert the inode record holemask to an inode allocation bitmap. The inode
 * allocation bitmap is inode granularity and specifies whether an inode is
 * physically allocated on disk (not whether the inode is considered allocated
 * or free by the fs).
 *
 * A bit value of 1 means the inode is allocated, a value of 0 means it is free.
 */
uint64_t
scxfs_inobt_irec_to_allocmask(
	struct scxfs_inobt_rec_incore	*rec)
{
	uint64_t			bitmap = 0;
	uint64_t			inodespbit;
	int				nextbit;
	uint				allocbitmap;

	/*
	 * The holemask has 16-bits for a 64 inode record. Therefore each
	 * holemask bit represents multiple inodes. Create a mask of bits to set
	 * in the allocmask for each holemask bit.
	 */
	inodespbit = (1 << SCXFS_INODES_PER_HOLEMASK_BIT) - 1;

	/*
	 * Allocated inodes are represented by 0 bits in holemask. Invert the 0
	 * bits to 1 and convert to a uint so we can use scxfs_next_bit(). Mask
	 * anything beyond the 16 holemask bits since this casts to a larger
	 * type.
	 */
	allocbitmap = ~rec->ir_holemask & ((1 << SCXFS_INOBT_HOLEMASK_BITS) - 1);

	/*
	 * allocbitmap is the inverted holemask so every set bit represents
	 * allocated inodes. To expand from 16-bit holemask granularity to
	 * 64-bit (e.g., bit-per-inode), set inodespbit bits in the target
	 * bitmap for every holemask bit.
	 */
	nextbit = scxfs_next_bit(&allocbitmap, 1, 0);
	while (nextbit != -1) {
		ASSERT(nextbit < (sizeof(rec->ir_holemask) * NBBY));

		bitmap |= (inodespbit <<
			   (nextbit * SCXFS_INODES_PER_HOLEMASK_BIT));

		nextbit = scxfs_next_bit(&allocbitmap, 1, nextbit + 1);
	}

	return bitmap;
}

#if defined(DEBUG) || defined(SCXFS_WARN)
/*
 * Verify that an in-core inode record has a valid inode count.
 */
int
scxfs_inobt_rec_check_count(
	struct scxfs_mount		*mp,
	struct scxfs_inobt_rec_incore	*rec)
{
	int				inocount = 0;
	int				nextbit = 0;
	uint64_t			allocbmap;
	int				wordsz;

	wordsz = sizeof(allocbmap) / sizeof(unsigned int);
	allocbmap = scxfs_inobt_irec_to_allocmask(rec);

	nextbit = scxfs_next_bit((uint *) &allocbmap, wordsz, nextbit);
	while (nextbit != -1) {
		inocount++;
		nextbit = scxfs_next_bit((uint *) &allocbmap, wordsz,
				       nextbit + 1);
	}

	if (inocount != rec->ir_count)
		return -EFSCORRUPTED;

	return 0;
}
#endif	/* DEBUG */

static scxfs_extlen_t
scxfs_inobt_max_size(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno)
{
	scxfs_agblock_t		agblocks = scxfs_ag_block_count(mp, agno);

	/* Bail out if we're uninitialized, which can happen in mkfs. */
	if (M_IGEO(mp)->inobt_mxr[0] == 0)
		return 0;

	/*
	 * The log is permanently allocated, so the space it occupies will
	 * never be available for the kinds of things that would require btree
	 * expansion.  We therefore can pretend the space isn't there.
	 */
	if (mp->m_sb.sb_logstart &&
	    SCXFS_FSB_TO_AGNO(mp, mp->m_sb.sb_logstart) == agno)
		agblocks -= mp->m_sb.sb_logblocks;

	return scxfs_btree_calc_size(M_IGEO(mp)->inobt_mnr,
				(uint64_t)agblocks * mp->m_sb.sb_inopblock /
					SCXFS_INODES_PER_CHUNK);
}

/* Read AGI and create inobt cursor. */
int
scxfs_inobt_cur(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_btnum_t		which,
	struct scxfs_btree_cur	**curpp,
	struct scxfs_buf		**agi_bpp)
{
	struct scxfs_btree_cur	*cur;
	int			error;

	ASSERT(*agi_bpp == NULL);
	ASSERT(*curpp == NULL);

	error = scxfs_ialloc_read_agi(mp, tp, agno, agi_bpp);
	if (error)
		return error;

	cur = scxfs_inobt_init_cursor(mp, tp, *agi_bpp, agno, which);
	if (!cur) {
		scxfs_trans_brelse(tp, *agi_bpp);
		*agi_bpp = NULL;
		return -ENOMEM;
	}
	*curpp = cur;
	return 0;
}

static int
scxfs_inobt_count_blocks(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_btnum_t		btnum,
	scxfs_extlen_t		*tree_blocks)
{
	struct scxfs_buf		*agbp = NULL;
	struct scxfs_btree_cur	*cur = NULL;
	int			error;

	error = scxfs_inobt_cur(mp, tp, agno, btnum, &cur, &agbp);
	if (error)
		return error;

	error = scxfs_btree_count_blocks(cur, tree_blocks);
	scxfs_btree_del_cursor(cur, error);
	scxfs_trans_brelse(tp, agbp);

	return error;
}

/*
 * Figure out how many blocks to reserve and how many are used by this btree.
 */
int
scxfs_finobt_calc_reserves(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_extlen_t		*ask,
	scxfs_extlen_t		*used)
{
	scxfs_extlen_t		tree_len = 0;
	int			error;

	if (!scxfs_sb_version_hasfinobt(&mp->m_sb))
		return 0;

	error = scxfs_inobt_count_blocks(mp, tp, agno, SCXFS_BTNUM_FINO, &tree_len);
	if (error)
		return error;

	*ask += scxfs_inobt_max_size(mp, agno);
	*used += tree_len;
	return 0;
}

/* Calculate the inobt btree size for some records. */
scxfs_extlen_t
scxfs_iallocbt_calc_size(
	struct scxfs_mount	*mp,
	unsigned long long	len)
{
	return scxfs_btree_calc_size(M_IGEO(mp)->inobt_mnr, len);
}
