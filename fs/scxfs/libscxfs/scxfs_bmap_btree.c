// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
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
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_alloc.h"
#include "scxfs_btree.h"
#include "scxfs_bmap_btree.h"
#include "scxfs_bmap.h"
#include "scxfs_error.h"
#include "scxfs_quota.h"
#include "scxfs_trace.h"
#include "scxfs_rmap.h"

/*
 * Convert on-disk form of btree root to in-memory form.
 */
void
scxfs_bmdr_to_bmbt(
	struct scxfs_inode	*ip,
	scxfs_bmdr_block_t	*dblock,
	int			dblocklen,
	struct scxfs_btree_block	*rblock,
	int			rblocklen)
{
	struct scxfs_mount	*mp = ip->i_mount;
	int			dmxr;
	scxfs_bmbt_key_t		*fkp;
	__be64			*fpp;
	scxfs_bmbt_key_t		*tkp;
	__be64			*tpp;

	scxfs_btree_init_block_int(mp, rblock, SCXFS_BUF_DADDR_NULL,
				 SCXFS_BTNUM_BMAP, 0, 0, ip->i_ino,
				 SCXFS_BTREE_LONG_PTRS);
	rblock->bb_level = dblock->bb_level;
	ASSERT(be16_to_cpu(rblock->bb_level) > 0);
	rblock->bb_numrecs = dblock->bb_numrecs;
	dmxr = scxfs_bmdr_maxrecs(dblocklen, 0);
	fkp = SCXFS_BMDR_KEY_ADDR(dblock, 1);
	tkp = SCXFS_BMBT_KEY_ADDR(mp, rblock, 1);
	fpp = SCXFS_BMDR_PTR_ADDR(dblock, 1, dmxr);
	tpp = SCXFS_BMAP_BROOT_PTR_ADDR(mp, rblock, 1, rblocklen);
	dmxr = be16_to_cpu(dblock->bb_numrecs);
	memcpy(tkp, fkp, sizeof(*fkp) * dmxr);
	memcpy(tpp, fpp, sizeof(*fpp) * dmxr);
}

void
scxfs_bmbt_disk_get_all(
	struct scxfs_bmbt_rec	*rec,
	struct scxfs_bmbt_irec	*irec)
{
	uint64_t		l0 = get_unaligned_be64(&rec->l0);
	uint64_t		l1 = get_unaligned_be64(&rec->l1);

	irec->br_startoff = (l0 & scxfs_mask64lo(64 - BMBT_EXNTFLAG_BITLEN)) >> 9;
	irec->br_startblock = ((l0 & scxfs_mask64lo(9)) << 43) | (l1 >> 21);
	irec->br_blockcount = l1 & scxfs_mask64lo(21);
	if (l0 >> (64 - BMBT_EXNTFLAG_BITLEN))
		irec->br_state = SCXFS_EXT_UNWRITTEN;
	else
		irec->br_state = SCXFS_EXT_NORM;
}

/*
 * Extract the blockcount field from an on disk bmap extent record.
 */
scxfs_filblks_t
scxfs_bmbt_disk_get_blockcount(
	scxfs_bmbt_rec_t	*r)
{
	return (scxfs_filblks_t)(be64_to_cpu(r->l1) & scxfs_mask64lo(21));
}

/*
 * Extract the startoff field from a disk format bmap extent record.
 */
scxfs_fileoff_t
scxfs_bmbt_disk_get_startoff(
	scxfs_bmbt_rec_t	*r)
{
	return ((scxfs_fileoff_t)be64_to_cpu(r->l0) &
		 scxfs_mask64lo(64 - BMBT_EXNTFLAG_BITLEN)) >> 9;
}

/*
 * Set all the fields in a bmap extent record from the uncompressed form.
 */
void
scxfs_bmbt_disk_set_all(
	struct scxfs_bmbt_rec	*r,
	struct scxfs_bmbt_irec	*s)
{
	int			extent_flag = (s->br_state != SCXFS_EXT_NORM);

	ASSERT(s->br_state == SCXFS_EXT_NORM || s->br_state == SCXFS_EXT_UNWRITTEN);
	ASSERT(!(s->br_startoff & scxfs_mask64hi(64-BMBT_STARTOFF_BITLEN)));
	ASSERT(!(s->br_blockcount & scxfs_mask64hi(64-BMBT_BLOCKCOUNT_BITLEN)));
	ASSERT(!(s->br_startblock & scxfs_mask64hi(64-BMBT_STARTBLOCK_BITLEN)));

	put_unaligned_be64(
		((scxfs_bmbt_rec_base_t)extent_flag << 63) |
		 ((scxfs_bmbt_rec_base_t)s->br_startoff << 9) |
		 ((scxfs_bmbt_rec_base_t)s->br_startblock >> 43), &r->l0);
	put_unaligned_be64(
		((scxfs_bmbt_rec_base_t)s->br_startblock << 21) |
		 ((scxfs_bmbt_rec_base_t)s->br_blockcount &
		  (scxfs_bmbt_rec_base_t)scxfs_mask64lo(21)), &r->l1);
}

/*
 * Convert in-memory form of btree root to on-disk form.
 */
void
scxfs_bmbt_to_bmdr(
	struct scxfs_mount	*mp,
	struct scxfs_btree_block	*rblock,
	int			rblocklen,
	scxfs_bmdr_block_t	*dblock,
	int			dblocklen)
{
	int			dmxr;
	scxfs_bmbt_key_t		*fkp;
	__be64			*fpp;
	scxfs_bmbt_key_t		*tkp;
	__be64			*tpp;

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		ASSERT(rblock->bb_magic == cpu_to_be32(SCXFS_BMAP_CRC_MAGIC));
		ASSERT(uuid_equal(&rblock->bb_u.l.bb_uuid,
		       &mp->m_sb.sb_meta_uuid));
		ASSERT(rblock->bb_u.l.bb_blkno ==
		       cpu_to_be64(SCXFS_BUF_DADDR_NULL));
	} else
		ASSERT(rblock->bb_magic == cpu_to_be32(SCXFS_BMAP_MAGIC));
	ASSERT(rblock->bb_u.l.bb_leftsib == cpu_to_be64(NULLFSBLOCK));
	ASSERT(rblock->bb_u.l.bb_rightsib == cpu_to_be64(NULLFSBLOCK));
	ASSERT(rblock->bb_level != 0);
	dblock->bb_level = rblock->bb_level;
	dblock->bb_numrecs = rblock->bb_numrecs;
	dmxr = scxfs_bmdr_maxrecs(dblocklen, 0);
	fkp = SCXFS_BMBT_KEY_ADDR(mp, rblock, 1);
	tkp = SCXFS_BMDR_KEY_ADDR(dblock, 1);
	fpp = SCXFS_BMAP_BROOT_PTR_ADDR(mp, rblock, 1, rblocklen);
	tpp = SCXFS_BMDR_PTR_ADDR(dblock, 1, dmxr);
	dmxr = be16_to_cpu(dblock->bb_numrecs);
	memcpy(tkp, fkp, sizeof(*fkp) * dmxr);
	memcpy(tpp, fpp, sizeof(*fpp) * dmxr);
}

STATIC struct scxfs_btree_cur *
scxfs_bmbt_dup_cursor(
	struct scxfs_btree_cur	*cur)
{
	struct scxfs_btree_cur	*new;

	new = scxfs_bmbt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.b.ip, cur->bc_private.b.whichfork);

	/*
	 * Copy the firstblock, dfops, and flags values,
	 * since init cursor doesn't get them.
	 */
	new->bc_private.b.flags = cur->bc_private.b.flags;

	return new;
}

STATIC void
scxfs_bmbt_update_cursor(
	struct scxfs_btree_cur	*src,
	struct scxfs_btree_cur	*dst)
{
	ASSERT((dst->bc_tp->t_firstblock != NULLFSBLOCK) ||
	       (dst->bc_private.b.ip->i_d.di_flags & SCXFS_DIFLAG_REALTIME));

	dst->bc_private.b.allocated += src->bc_private.b.allocated;
	dst->bc_tp->t_firstblock = src->bc_tp->t_firstblock;

	src->bc_private.b.allocated = 0;
}

STATIC int
scxfs_bmbt_alloc_block(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*start,
	union scxfs_btree_ptr	*new,
	int			*stat)
{
	scxfs_alloc_arg_t		args;		/* block allocation args */
	int			error;		/* error return value */

	memset(&args, 0, sizeof(args));
	args.tp = cur->bc_tp;
	args.mp = cur->bc_mp;
	args.fsbno = cur->bc_tp->t_firstblock;
	scxfs_rmap_ino_bmbt_owner(&args.oinfo, cur->bc_private.b.ip->i_ino,
			cur->bc_private.b.whichfork);

	if (args.fsbno == NULLFSBLOCK) {
		args.fsbno = be64_to_cpu(start->l);
		args.type = SCXFS_ALLOCTYPE_START_BNO;
		/*
		 * Make sure there is sufficient room left in the AG to
		 * complete a full tree split for an extent insert.  If
		 * we are converting the middle part of an extent then
		 * we may need space for two tree splits.
		 *
		 * We are relying on the caller to make the correct block
		 * reservation for this operation to succeed.  If the
		 * reservation amount is insufficient then we may fail a
		 * block allocation here and corrupt the filesystem.
		 */
		args.minleft = args.tp->t_blk_res;
	} else if (cur->bc_tp->t_flags & SCXFS_TRANS_LOWMODE) {
		args.type = SCXFS_ALLOCTYPE_START_BNO;
	} else {
		args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
	}

	args.minlen = args.maxlen = args.prod = 1;
	args.wasdel = cur->bc_private.b.flags & SCXFS_BTCUR_BPRV_WASDEL;
	if (!args.wasdel && args.tp->t_blk_res == 0) {
		error = -ENOSPC;
		goto error0;
	}
	error = scxfs_alloc_vextent(&args);
	if (error)
		goto error0;

	if (args.fsbno == NULLFSBLOCK && args.minleft) {
		/*
		 * Could not find an AG with enough free space to satisfy
		 * a full btree split.  Try again and if
		 * successful activate the lowspace algorithm.
		 */
		args.fsbno = 0;
		args.type = SCXFS_ALLOCTYPE_FIRST_AG;
		error = scxfs_alloc_vextent(&args);
		if (error)
			goto error0;
		cur->bc_tp->t_flags |= SCXFS_TRANS_LOWMODE;
	}
	if (WARN_ON_ONCE(args.fsbno == NULLFSBLOCK)) {
		*stat = 0;
		return 0;
	}

	ASSERT(args.len == 1);
	cur->bc_tp->t_firstblock = args.fsbno;
	cur->bc_private.b.allocated++;
	cur->bc_private.b.ip->i_d.di_nblocks++;
	scxfs_trans_log_inode(args.tp, cur->bc_private.b.ip, SCXFS_ILOG_CORE);
	scxfs_trans_mod_dquot_byino(args.tp, cur->bc_private.b.ip,
			SCXFS_TRANS_DQ_BCOUNT, 1L);

	new->l = cpu_to_be64(args.fsbno);

	*stat = 1;
	return 0;

 error0:
	return error;
}

STATIC int
scxfs_bmbt_free_block(
	struct scxfs_btree_cur	*cur,
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = cur->bc_mp;
	struct scxfs_inode	*ip = cur->bc_private.b.ip;
	struct scxfs_trans	*tp = cur->bc_tp;
	scxfs_fsblock_t		fsbno = SCXFS_DADDR_TO_FSB(mp, SCXFS_BUF_ADDR(bp));
	struct scxfs_owner_info	oinfo;

	scxfs_rmap_ino_bmbt_owner(&oinfo, ip->i_ino, cur->bc_private.b.whichfork);
	scxfs_bmap_add_free(cur->bc_tp, fsbno, 1, &oinfo);
	ip->i_d.di_nblocks--;

	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
	scxfs_trans_mod_dquot_byino(tp, ip, SCXFS_TRANS_DQ_BCOUNT, -1L);
	return 0;
}

STATIC int
scxfs_bmbt_get_minrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	if (level == cur->bc_nlevels - 1) {
		struct scxfs_ifork	*ifp;

		ifp = SCXFS_IFORK_PTR(cur->bc_private.b.ip,
				    cur->bc_private.b.whichfork);

		return scxfs_bmbt_maxrecs(cur->bc_mp,
					ifp->if_broot_bytes, level == 0) / 2;
	}

	return cur->bc_mp->m_bmap_dmnr[level != 0];
}

int
scxfs_bmbt_get_maxrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	if (level == cur->bc_nlevels - 1) {
		struct scxfs_ifork	*ifp;

		ifp = SCXFS_IFORK_PTR(cur->bc_private.b.ip,
				    cur->bc_private.b.whichfork);

		return scxfs_bmbt_maxrecs(cur->bc_mp,
					ifp->if_broot_bytes, level == 0);
	}

	return cur->bc_mp->m_bmap_dmxr[level != 0];

}

/*
 * Get the maximum records we could store in the on-disk format.
 *
 * For non-root nodes this is equivalent to scxfs_bmbt_get_maxrecs, but
 * for the root node this checks the available space in the dinode fork
 * so that we can resize the in-memory buffer to match it.  After a
 * resize to the maximum size this function returns the same value
 * as scxfs_bmbt_get_maxrecs for the root node, too.
 */
STATIC int
scxfs_bmbt_get_dmaxrecs(
	struct scxfs_btree_cur	*cur,
	int			level)
{
	if (level != cur->bc_nlevels - 1)
		return cur->bc_mp->m_bmap_dmxr[level != 0];
	return scxfs_bmdr_maxrecs(cur->bc_private.b.forksize, level == 0);
}

STATIC void
scxfs_bmbt_init_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	key->bmbt.br_startoff =
		cpu_to_be64(scxfs_bmbt_disk_get_startoff(&rec->bmbt));
}

STATIC void
scxfs_bmbt_init_high_key_from_rec(
	union scxfs_btree_key	*key,
	union scxfs_btree_rec	*rec)
{
	key->bmbt.br_startoff = cpu_to_be64(
			scxfs_bmbt_disk_get_startoff(&rec->bmbt) +
			scxfs_bmbt_disk_get_blockcount(&rec->bmbt) - 1);
}

STATIC void
scxfs_bmbt_init_rec_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*rec)
{
	scxfs_bmbt_disk_set_all(&rec->bmbt, &cur->bc_rec.b);
}

STATIC void
scxfs_bmbt_init_ptr_from_cur(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_ptr	*ptr)
{
	ptr->l = 0;
}

STATIC int64_t
scxfs_bmbt_key_diff(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*key)
{
	return (int64_t)be64_to_cpu(key->bmbt.br_startoff) -
				      cur->bc_rec.b.br_startoff;
}

STATIC int64_t
scxfs_bmbt_diff_two_keys(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	uint64_t		a = be64_to_cpu(k1->bmbt.br_startoff);
	uint64_t		b = be64_to_cpu(k2->bmbt.br_startoff);

	/*
	 * Note: This routine previously casted a and b to int64 and subtracted
	 * them to generate a result.  This lead to problems if b was the
	 * "maximum" key value (all ones) being signed incorrectly, hence this
	 * somewhat less efficient version.
	 */
	if (a > b)
		return 1;
	if (b > a)
		return -1;
	return 0;
}

static scxfs_failaddr_t
scxfs_bmbt_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_btree_block	*block = SCXFS_BUF_TO_BLOCK(bp);
	scxfs_failaddr_t		fa;
	unsigned int		level;

	if (!scxfs_verify_magic(bp, block->bb_magic))
		return __this_address;

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		/*
		 * XXX: need a better way of verifying the owner here. Right now
		 * just make sure there has been one set.
		 */
		fa = scxfs_btree_lblock_v5hdr_verify(bp, SCXFS_RMAP_OWN_UNKNOWN);
		if (fa)
			return fa;
	}

	/*
	 * numrecs and level verification.
	 *
	 * We don't know what fork we belong to, so just verify that the level
	 * is less than the maximum of the two. Later checks will be more
	 * precise.
	 */
	level = be16_to_cpu(block->bb_level);
	if (level > max(mp->m_bm_maxlevels[0], mp->m_bm_maxlevels[1]))
		return __this_address;

	return scxfs_btree_lblock_verify(bp, mp->m_bmap_dmxr[level != 0]);
}

static void
scxfs_bmbt_read_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	if (!scxfs_btree_lblock_verify_crc(bp))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_bmbt_verify(bp);
		if (fa)
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}

	if (bp->b_error)
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
}

static void
scxfs_bmbt_write_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;

	fa = scxfs_bmbt_verify(bp);
	if (fa) {
		trace_scxfs_btree_corrupt(bp, _RET_IP_);
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}
	scxfs_btree_lblock_calc_crc(bp);
}

const struct scxfs_buf_ops scxfs_bmbt_buf_ops = {
	.name = "scxfs_bmbt",
	.magic = { cpu_to_be32(SCXFS_BMAP_MAGIC),
		   cpu_to_be32(SCXFS_BMAP_CRC_MAGIC) },
	.verify_read = scxfs_bmbt_read_verify,
	.verify_write = scxfs_bmbt_write_verify,
	.verify_struct = scxfs_bmbt_verify,
};


STATIC int
scxfs_bmbt_keys_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_key	*k1,
	union scxfs_btree_key	*k2)
{
	return be64_to_cpu(k1->bmbt.br_startoff) <
		be64_to_cpu(k2->bmbt.br_startoff);
}

STATIC int
scxfs_bmbt_recs_inorder(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*r1,
	union scxfs_btree_rec	*r2)
{
	return scxfs_bmbt_disk_get_startoff(&r1->bmbt) +
		scxfs_bmbt_disk_get_blockcount(&r1->bmbt) <=
		scxfs_bmbt_disk_get_startoff(&r2->bmbt);
}

static const struct scxfs_btree_ops scxfs_bmbt_ops = {
	.rec_len		= sizeof(scxfs_bmbt_rec_t),
	.key_len		= sizeof(scxfs_bmbt_key_t),

	.dup_cursor		= scxfs_bmbt_dup_cursor,
	.update_cursor		= scxfs_bmbt_update_cursor,
	.alloc_block		= scxfs_bmbt_alloc_block,
	.free_block		= scxfs_bmbt_free_block,
	.get_maxrecs		= scxfs_bmbt_get_maxrecs,
	.get_minrecs		= scxfs_bmbt_get_minrecs,
	.get_dmaxrecs		= scxfs_bmbt_get_dmaxrecs,
	.init_key_from_rec	= scxfs_bmbt_init_key_from_rec,
	.init_high_key_from_rec	= scxfs_bmbt_init_high_key_from_rec,
	.init_rec_from_cur	= scxfs_bmbt_init_rec_from_cur,
	.init_ptr_from_cur	= scxfs_bmbt_init_ptr_from_cur,
	.key_diff		= scxfs_bmbt_key_diff,
	.diff_two_keys		= scxfs_bmbt_diff_two_keys,
	.buf_ops		= &scxfs_bmbt_buf_ops,
	.keys_inorder		= scxfs_bmbt_keys_inorder,
	.recs_inorder		= scxfs_bmbt_recs_inorder,
};

/*
 * Allocate a new bmap btree cursor.
 */
struct scxfs_btree_cur *				/* new bmap btree cursor */
scxfs_bmbt_init_cursor(
	struct scxfs_mount	*mp,		/* file system mount point */
	struct scxfs_trans	*tp,		/* transaction pointer */
	struct scxfs_inode	*ip,		/* inode owning the btree */
	int			whichfork)	/* data or attr fork */
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_btree_cur	*cur;
	ASSERT(whichfork != SCXFS_COW_FORK);

	cur = kmem_zone_zalloc(scxfs_btree_cur_zone, KM_NOFS);

	cur->bc_tp = tp;
	cur->bc_mp = mp;
	cur->bc_nlevels = be16_to_cpu(ifp->if_broot->bb_level) + 1;
	cur->bc_btnum = SCXFS_BTNUM_BMAP;
	cur->bc_blocklog = mp->m_sb.sb_blocklog;
	cur->bc_statoff = SCXFS_STATS_CALC_INDEX(xs_bmbt_2);

	cur->bc_ops = &scxfs_bmbt_ops;
	cur->bc_flags = SCXFS_BTREE_LONG_PTRS | SCXFS_BTREE_ROOT_IN_INODE;
	if (scxfs_sb_version_hascrc(&mp->m_sb))
		cur->bc_flags |= SCXFS_BTREE_CRC_BLOCKS;

	cur->bc_private.b.forksize = SCXFS_IFORK_SIZE(ip, whichfork);
	cur->bc_private.b.ip = ip;
	cur->bc_private.b.allocated = 0;
	cur->bc_private.b.flags = 0;
	cur->bc_private.b.whichfork = whichfork;

	return cur;
}

/*
 * Calculate number of records in a bmap btree block.
 */
int
scxfs_bmbt_maxrecs(
	struct scxfs_mount	*mp,
	int			blocklen,
	int			leaf)
{
	blocklen -= SCXFS_BMBT_BLOCK_LEN(mp);

	if (leaf)
		return blocklen / sizeof(scxfs_bmbt_rec_t);
	return blocklen / (sizeof(scxfs_bmbt_key_t) + sizeof(scxfs_bmbt_ptr_t));
}

/*
 * Calculate number of records in a bmap btree inode root.
 */
int
scxfs_bmdr_maxrecs(
	int			blocklen,
	int			leaf)
{
	blocklen -= sizeof(scxfs_bmdr_block_t);

	if (leaf)
		return blocklen / sizeof(scxfs_bmdr_rec_t);
	return blocklen / (sizeof(scxfs_bmdr_key_t) + sizeof(scxfs_bmdr_ptr_t));
}

/*
 * Change the owner of a btree format fork fo the inode passed in. Change it to
 * the owner of that is passed in so that we can change owners before or after
 * we switch forks between inodes. The operation that the caller is doing will
 * determine whether is needs to change owner before or after the switch.
 *
 * For demand paged transactional modification, the fork switch should be done
 * after reading in all the blocks, modifying them and pinning them in the
 * transaction. For modification when the buffers are already pinned in memory,
 * the fork switch can be done before changing the owner as we won't need to
 * validate the owner until the btree buffers are unpinned and writes can occur
 * again.
 *
 * For recovery based ownership change, there is no transactional context and
 * so a buffer list must be supplied so that we can record the buffers that we
 * modified for the caller to issue IO on.
 */
int
scxfs_bmbt_change_owner(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork,
	scxfs_ino_t		new_owner,
	struct list_head	*buffer_list)
{
	struct scxfs_btree_cur	*cur;
	int			error;

	ASSERT(tp || buffer_list);
	ASSERT(!(tp && buffer_list));
	if (whichfork == SCXFS_DATA_FORK)
		ASSERT(ip->i_d.di_format == SCXFS_DINODE_FMT_BTREE);
	else
		ASSERT(ip->i_d.di_aformat == SCXFS_DINODE_FMT_BTREE);

	cur = scxfs_bmbt_init_cursor(ip->i_mount, tp, ip, whichfork);
	if (!cur)
		return -ENOMEM;
	cur->bc_private.b.flags |= SCXFS_BTCUR_BPRV_INVALID_OWNER;

	error = scxfs_btree_change_owner(cur, new_owner, buffer_list);
	scxfs_btree_del_cursor(cur, error);
	return error;
}

/* Calculate the bmap btree size for some records. */
unsigned long long
scxfs_bmbt_calc_size(
	struct scxfs_mount	*mp,
	unsigned long long	len)
{
	return scxfs_btree_calc_size(mp->m_bmap_dmnr, len);
}
