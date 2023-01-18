// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 Red Hat, Inc.
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
#include "scxfs_trans.h"
#include "scxfs_alloc.h"
#include "scxfs_btree.h"
#include "scxfs_rmap.h"
#include "scxfs_rmap_btree.h"
#include "scxfs_trace.h"
#include "scxfs_error.h"
#include "scxfs_extent_busy.h"
#include "scxfs_ag_resv.h"

/*
 * Reverse map btree.
 *
 * This is a per-ag tree used to track the owner(s) of a given extent. With
 * reflink it is possible for there to be multiple owners, which is a departure
 * from classic SCXFS. Owner records for data extents are inserted when the
 * extent is mapped and removed when an extent is unmapped.  Owner records for
 * all other block types (i.e. metadata) are inserted when an extent is
 * allocated and removed when an extent is freed. There can only be one owner
 * of a metadata extent, usually an inode or some other metadata structure like
 * an AG btree.
 *
 * The rmap btree is part of the free space management, so blocks for the tree
 * are sourced from the agfl. Hence we need transaction reservation support for
 * this tree so that the freelist is always large enough. This also impacts on
 * the minimum space we need to leave free in the AG.
 *
 * The tree is ordered by [ag block, owner, offset]. This is a large key size,
 * but it is the only way to enforce unique keys when a block can be owned by
 * multiple files at any offset. There's no need to order/search by extent
 * size for online updating/management of the tree. It is intended that most
 * reverse lookups will be to find the owner(s) of a particular block, or to
 * try to recover tree and file data from corrupt primary metadata.
 */

static struct scxfs_btree_cur *
scxfs_rmapbt_dup_cursor(
	struct scxfs_btree_cur	*cur)
{
	return scxfs_rmapbt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.a.agbp, cur->bc_private.a.agno);
}

STATIC void
scxfs_rmapbt_set_root(
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
scxfs_rmapbt_alloc_block(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*start,
	union scxfs_btree_ptr	*new,
	int			*stat)
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	int			error;
	scxfs_agblock_t		bno;

	/* Allocate the new block from the freelist. If we can't, give up.  */
	error = scxfs_alloc_get_freelist(cur->bc_tp, cur->bc_private.a.agbp,
				       &bno, 1);
	if (error)
		return error;

	trace_scxfs_rmapbt_alloc_block(cur->bc_mp, cur->bc_private.a.agno,
			bno, 1);
	if (bno == NULLAGBLOCK) {
		*stat = 0;
		return 0;
	}

	scxfs_extent_busy_reuse(cur->bc_mp, cur->bc_private.a.agno, bno, 1,
			false);

	scxfs_trans_agbtree_delta(cur->bc_tp, 1);
	new->s = cpu_to_be32(bno);
	be32_add_cpu(&agf->agf_rmap_blocks, 1);
	scxfs_alloc_log_agf(cur->bc_tp, agbp, SCXFS_AGF_RMAP_BLOCKS);

	scxfs_ag_resv_rmapbt_alloc(cur->bc_mp, cur->bc_private.a.agno);

	*stat = 1;
	return 0;
}

STATIC int
scxfs_rmapbt_free_block(
	struct scxfs_btree_cur	*cur,
	struct scxfs_buf		*bp)
{
	struct scxfs_buf		*agbp = cur->bc_private.a.agbp;
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	scxfs_agblock_t		bno;
	int			error;

	bno = scxfs_daddr_to_agbno(cur->bc_mp, SCXFS_BUF_ADDR(bp));
	trace_scxfs_rmapbt_free_block(cur->bc_mp, cur->bc_private.a.agno,
			bno, 1);
	be32_add_cpu(&agf->agf_rmap_blocks, -1);
	scxfs_alloc_log_agf(cur->bc_tp, agbp, SCXFS_AGF_RMAP_BLOCKS);
	error = scxfs_alloc_put_freelist(cur->bc_tp, agbp, NULL, bno, 1);
	if (error)
		return error;

	scxfs_extent_busy_insert(cur->bc_tp, be32_to_cpu(agf->agf_seqno), bno, 1,
			      SCXFS_EXTENT_BUSY_SKIP_DISCARD);
	scxfs_trans_agbtree_delta(cur->bc_tp, -1);

	scxfs_ag_resv_rmapbt_free(cur->bc_mp, cur->bc_private.a.agno);

	return 0;
}

STATIC int
scxfs_rmapbt_get_minrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_rmap_mnr[level != 0];
}

STATIC int
scxfs_rmapbt_get_maxrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_rmap_mxr[level != 0];
}

STATIC void
scxfs_rmapbt_init_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	key->rmap.rm_startblock = rec->rmap.rm_startblock;
	key->rmap.rm_owner = rec->rmap.rm_owner;
	key->rmap.rm_offset = rec->rmap.rm_offset;
}

/*
 * The high key for a reverse mapping record can be computed by shifting
 * the startblock and offset to the highest value that would still map
 * to that record.  In practice this means that we add blockcount-1 to
 * the startblock for all records, and if the record is for a data/attr
 * fork mapping, we add blockcount-1 to the offset too.
 */
STATIC void
scxfs_rmapbt_init_high_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	uint64_t		off;
	int			adj;

	adj = be32_to_cpu(rec->rmap.rm_blockcount) - 1;

	key->rmap.rm_startblock = rec->rmap.rm_startblock;
	be32_add_cpu(&key->rmap.rm_startblock, adj);
	key->rmap.rm_owner = rec->rmap.rm_owner;
	key->rmap.rm_offset = rec->rmap.rm_offset;
	if (SCXFS_RMAP_NON_INODE_OWNER(be64_to_cpu(rec->rmap.rm_owner)) ||
	    SCXFS_RMAP_IS_BMBT_BLOCK(be64_to_cpu(rec->rmap.rm_offset)))
		return;
	off = be64_to_cpu(key->rmap.rm_offset);
	off = (SCXFS_RMAP_OFF(off) + adj) | (off & ~SCXFS_RMAP_OFF_MASK);
	key->rmap.rm_offset = cpu_to_be64(off);
}

STATIC void
scxfs_rmapbt_init_rec_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*rec)
{
	rec->rmap.rm_startblock = cpu_to_be32(cur->bc_rec.r.rm_startblock);
	rec->rmap.rm_blockcount = cpu_to_be32(cur->bc_rec.r.rm_blockcount);
	rec->rmap.rm_owner = cpu_to_be64(cur->bc_rec.r.rm_owner);
	rec->rmap.rm_offset = cpu_to_be64(
			scxfs_rmap_irec_offset_pack(&cur->bc_rec.r));
}

STATIC void
scxfs_rmapbt_init_ptr_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agf->agf_seqno));

	ptr->s = agf->agf_roots[cur->bc_btnum];
}

STATIC int64_t
scxfs_rmapbt_key_diff(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*key)
{
	struct scxfs_rmap_irec	*rec = &cur->bc_rec.r;
	struct scxfs_rmap_key	*kp = &key->rmap;
	__u64			x, y;
	int64_t			d;

	d = (int64_t)be32_to_cpu(kp->rm_startblock) - rec->rm_startblock;
	if (d)
		return d;

	x = be64_to_cpu(kp->rm_owner);
	y = rec->rm_owner;
	if (x > y)
		return 1;
	else if (y > x)
		return -1;

	x = SCXFS_RMAP_OFF(be64_to_cpu(kp->rm_offset));
	y = rec->rm_offset;
	if (x > y)
		return 1;
	else if (y > x)
		return -1;
	return 0;
}

STATIC int64_t
scxfs_rmapbt_diff_two_keys(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	struct scxfs_rmap_key	*kp1 = &k1->rmap;
	struct scxfs_rmap_key	*kp2 = &k2->rmap;
	int64_t			d;
	__u64			x, y;

	d = (int64_t)be32_to_cpu(kp1->rm_startblock) -
		       be32_to_cpu(kp2->rm_startblock);
	if (d)
		return d;

	x = be64_to_cpu(kp1->rm_owner);
	y = be64_to_cpu(kp2->rm_owner);
	if (x > y)
		return 1;
	else if (y > x)
		return -1;

	x = SCXFS_RMAP_OFF(be64_to_cpu(kp1->rm_offset));
	y = SCXFS_RMAP_OFF(be64_to_cpu(kp2->rm_offset));
	if (x > y)
		return 1;
	else if (y > x)
		return -1;
	return 0;
}

static scxfs_failaddr_t
scxfs_rmapbt_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_btree_block	*block = SCXFS_BUF_TO_BLOCK(bp);
	struct scxfs_perag	*pag = bp->b_pag;
	scxfs_failaddr_t		fa;
	unsigned int		level;

	/*
	 * magic number and level verification
	 *
	 * During growfs operations, we can't verify the exact level or owner as
	 * the perag is not fully initialised and hence not attached to the
	 * buffer.  In this case, check against the maximum tree depth.
	 *
	 * Similarly, during log recovery we will have a perag structure
	 * attached, but the agf information will not yet have been initialised
	 * from the on disk AGF. Again, we can only check against maximum limits
	 * in this case.
	 */
	if (!scxfs_verify_magic(bp, block->bb_magic))
		return __this_address;

	if (!scxfs_sb_version_hasrmapbt(&mp->m_sb))
		return __this_address;
	fa = scxfs_btree_sblock_v5hdr_verify(bp);
	if (fa)
		return fa;

	level = be16_to_cpu(block->bb_level);
	if (pag && pag->pagf_init) {
		if (level >= pag->pagf_levels[SCXFS_BTNUM_RMAPi])
			return __this_address;
	} else if (level >= mp->m_rmap_maxlevels)
		return __this_address;

	return scxfs_btree_sblock_verify(bp, mp->m_rmap_mxr[level != 0]);
}

static void
scxfs_rmapbt_read_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	if (!scxfs_btree_sblock_verify_crc(bp))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_rmapbt_verify(bp);
		if (fa)
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}

	if (bp->b_error)
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
}

static void
scxfs_rmapbt_write_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	fa = scxfs_rmapbt_verify(bp);
	if (fa) {
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}
	scxfs_btree_sblock_calc_crc(bp);

}

const struct scxfs_buf_ops scxfs_rmapbt_buf_ops = {
	.name			= "scxfs_rmapbt",
	.magic			= { 0, cpu_to_be32(SCXFS_RMAP_CRC_MAGIC) },
	.verify_read		= scxfs_rmapbt_read_verify,
	.verify_write		= scxfs_rmapbt_write_verify,
	.verify_struct		= scxfs_rmapbt_verify,
};

STATIC int
scxfs_rmapbt_keys_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	uint32_t		x;
	uint32_t		y;
	uint64_t		a;
	uint64_t		b;

	x = be32_to_cpu(k1->rmap.rm_startblock);
	y = be32_to_cpu(k2->rmap.rm_startblock);
	if (x < y)
		return 1;
	else if (x > y)
		return 0;
	a = be64_to_cpu(k1->rmap.rm_owner);
	b = be64_to_cpu(k2->rmap.rm_owner);
	if (a < b)
		return 1;
	else if (a > b)
		return 0;
	a = SCXFS_RMAP_OFF(be64_to_cpu(k1->rmap.rm_offset));
	b = SCXFS_RMAP_OFF(be64_to_cpu(k2->rmap.rm_offset));
	if (a <= b)
		return 1;
	return 0;
}

STATIC int
scxfs_rmapbt_recs_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*r1,
	union scxfs_btree_rec	*r2)
{
	uint32_t		x;
	uint32_t		y;
	uint64_t		a;
	uint64_t		b;

	x = be32_to_cpu(r1->rmap.rm_startblock);
	y = be32_to_cpu(r2->rmap.rm_startblock);
	if (x < y)
		return 1;
	else if (x > y)
		return 0;
	a = be64_to_cpu(r1->rmap.rm_owner);
	b = be64_to_cpu(r2->rmap.rm_owner);
	if (a < b)
		return 1;
	else if (a > b)
		return 0;
	a = SCXFS_RMAP_OFF(be64_to_cpu(r1->rmap.rm_offset));
	b = SCXFS_RMAP_OFF(be64_to_cpu(r2->rmap.rm_offset));
	if (a <= b)
		return 1;
	return 0;
}

static const struct scxfs_btree_ops scxfs_rmapbt_ops = {
	.rec_len		= sizeof(struct scxfs_rmap_rec),
	.key_len		= 2 * sizeof(struct scxfs_rmap_key),

	.dup_cursor		= scxfs_rmapbt_dup_cursor,
	.set_root		= scxfs_rmapbt_set_root,
	.alloc_block		= scxfs_rmapbt_alloc_block,
	.free_block		= scxfs_rmapbt_free_block,
	.get_minrecs		= scxfs_rmapbt_get_minrecs,
	.get_maxrecs		= scxfs_rmapbt_get_maxrecs,
	.init_key_from_rec	= scxfs_rmapbt_init_key_from_rec,
	.init_high_key_from_rec	= scxfs_rmapbt_init_high_key_from_rec,
	.init_rec_from_cur	= scxfs_rmapbt_init_rec_from_cur,
	.init_ptr_from_cur	= scxfs_rmapbt_init_ptr_from_cur,
	.key_diff		= scxfs_rmapbt_key_diff,
	.buf_ops		= &scxfs_rmapbt_buf_ops,
	.diff_two_keys		= scxfs_rmapbt_diff_two_keys,
	.keys_inorder		= scxfs_rmapbt_keys_inorder,
	.recs_inorder		= scxfs_rmapbt_recs_inorder,
};

/*
 * Allocate a new allocation btree cursor.
 */
struct scxfs_btree_cur *
scxfs_rmapbt_init_cursor(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct scxfs_buf		*agbp,
	scxfs_agnumber_t		agno)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(agbp);
	struct scxfs_btree_cur	*cur;

	cur = kmem_zone_zalloc(scxfs_btree_cur_zone, KM_NOFS);
	cur->bc_tp = tp;
	cur->bc_mp = mp;
	/* Overlapping btree; 2 keys per pointer. */
	cur->bc_btnum = SCXFS_BTNUM_RMAP;
	cur->bc_flags = SCXFS_BTREE_CRC_BLOCKS | SCXFS_BTREE_OVERLAPPING;
	cur->bc_blocklog = mp->m_sb.sb_blocklog;
	cur->bc_ops = &scxfs_rmapbt_ops;
	cur->bc_nlevels = be32_to_cpu(agf->agf_levels[SCXFS_BTNUM_RMAP]);
	cur->bc_statoff = SCXFS_STATS_CALC_INDEX(xs_rmap_2);

	cur->bc_private.a.agbp = agbp;
	cur->bc_private.a.agno = agno;

	return cur;
}

/*
 * Calculate number of records in an rmap btree block.
 */
int
scxfs_rmapbt_maxrecs(
	int			blocklen,
	int			leaf)
{
	blocklen -= SCXFS_RMAP_BLOCK_LEN;

	if (leaf)
		return blocklen / sizeof(struct scxfs_rmap_rec);
	return blocklen /
		(2 * sizeof(struct scxfs_rmap_key) + sizeof(scxfs_rmap_ptr_t));
}

/* Compute the maximum height of an rmap btree. */
void
scxfs_rmapbt_compute_maxlevels(
	struct scxfs_mount		*mp)
{
	/*
	 * On a non-reflink filesystem, the maximum number of rmap
	 * records is the number of blocks in the AG, hence the max
	 * rmapbt height is log_$maxrecs($agblocks).  However, with
	 * reflink each AG block can have up to 2^32 (per the refcount
	 * record format) owners, which means that theoretically we
	 * could face up to 2^64 rmap records.
	 *
	 * That effectively means that the max rmapbt height must be
	 * SCXFS_BTREE_MAXLEVELS.  "Fortunately" we'll run out of AG
	 * blocks to feed the rmapbt long before the rmapbt reaches
	 * maximum height.  The reflink code uses ag_resv_critical to
	 * disallow reflinking when less than 10% of the per-AG metadata
	 * block reservation since the fallback is a regular file copy.
	 */
	if (scxfs_sb_version_hasreflink(&mp->m_sb))
		mp->m_rmap_maxlevels = SCXFS_BTREE_MAXLEVELS;
	else
		mp->m_rmap_maxlevels = scxfs_btree_compute_maxlevels(
				mp->m_rmap_mnr, mp->m_sb.sb_agblocks);
}

/* Calculate the refcount btree size for some records. */
scxfs_extlen_t
scxfs_rmapbt_calc_size(
	struct scxfs_mount	*mp,
	unsigned long long	len)
{
	return scxfs_btree_calc_size(mp->m_rmap_mnr, len);
}

/*
 * Calculate the maximum refcount btree size.
 */
scxfs_extlen_t
scxfs_rmapbt_max_size(
	struct scxfs_mount	*mp,
	scxfs_agblock_t		agblocks)
{
	/* Bail out if we're uninitialized, which can happen in mkfs. */
	if (mp->m_rmap_mxr[0] == 0)
		return 0;

	return scxfs_rmapbt_calc_size(mp, agblocks);
}

/*
 * Figure out how many blocks to reserve and how many are used by this btree.
 */
int
scxfs_rmapbt_calc_reserves(
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

	if (!scxfs_sb_version_hasrmapbt(&mp->m_sb))
		return 0;

	error = scxfs_alloc_read_agf(mp, tp, agno, 0, &agbp);
	if (error)
		return error;

	agf = SCXFS_BUF_TO_AGF(agbp);
	agblocks = be32_to_cpu(agf->agf_length);
	tree_len = be32_to_cpu(agf->agf_rmap_blocks);
	scxfs_trans_brelse(tp, agbp);

	/*
	 * The log is permanently allocated, so the space it occupies will
	 * never be available for the kinds of things that would require btree
	 * expansion.  We therefore can pretend the space isn't there.
	 */
	if (mp->m_sb.sb_logstart &&
	    SCXFS_FSB_TO_AGNO(mp, mp->m_sb.sb_logstart) == agno)
		agblocks -= mp->m_sb.sb_logblocks;

	/* Reserve 1% of the AG or enough for 1 block per record. */
	*ask += max(agblocks / 100, scxfs_rmapbt_max_size(mp, agblocks));
	*used += tree_len;

	return error;
}
