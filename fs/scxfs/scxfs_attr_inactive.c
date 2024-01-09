// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
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
#include "scxfs_da_format.h"
#include "scxfs_da_btree.h"
#include "scxfs_inode.h"
#include "scxfs_attr_remote.h"
#include "scxfs_trans.h"
#include "scxfs_bmap.h"
#include "scxfs_attr.h"
#include "scxfs_attr_leaf.h"
#include "scxfs_quota.h"
#include "scxfs_dir2.h"

/*
 * Look at all the extents for this logical region,
 * invalidate any buffers that are incore/in transactions.
 */
STATIC int
scxfs_attr3_leaf_freextent(
	struct scxfs_trans	**trans,
	struct scxfs_inode	*dp,
	scxfs_dablk_t		blkno,
	int			blkcnt)
{
	struct scxfs_bmbt_irec	map;
	struct scxfs_buf		*bp;
	scxfs_dablk_t		tblkno;
	scxfs_daddr_t		dblkno;
	int			tblkcnt;
	int			dblkcnt;
	int			nmap;
	int			error;

	/*
	 * Roll through the "value", invalidating the attribute value's
	 * blocks.
	 */
	tblkno = blkno;
	tblkcnt = blkcnt;
	while (tblkcnt > 0) {
		/*
		 * Try to remember where we decided to put the value.
		 */
		nmap = 1;
		error = scxfs_bmapi_read(dp, (scxfs_fileoff_t)tblkno, tblkcnt,
				       &map, &nmap, SCXFS_BMAPI_ATTRFORK);
		if (error) {
			return error;
		}
		ASSERT(nmap == 1);
		ASSERT(map.br_startblock != DELAYSTARTBLOCK);

		/*
		 * If it's a hole, these are already unmapped
		 * so there's nothing to invalidate.
		 */
		if (map.br_startblock != HOLESTARTBLOCK) {

			dblkno = SCXFS_FSB_TO_DADDR(dp->i_mount,
						  map.br_startblock);
			dblkcnt = SCXFS_FSB_TO_BB(dp->i_mount,
						map.br_blockcount);
			bp = scxfs_trans_get_buf(*trans,
					dp->i_mount->m_ddev_targp,
					dblkno, dblkcnt, 0);
			if (!bp)
				return -ENOMEM;
			scxfs_trans_binval(*trans, bp);
			/*
			 * Roll to next transaction.
			 */
			error = scxfs_trans_roll_inode(trans, dp);
			if (error)
				return error;
		}

		tblkno += map.br_blockcount;
		tblkcnt -= map.br_blockcount;
	}

	return 0;
}

/*
 * Invalidate all of the "remote" value regions pointed to by a particular
 * leaf block.
 * Note that we must release the lock on the buffer so that we are not
 * caught holding something that the logging code wants to flush to disk.
 */
STATIC int
scxfs_attr3_leaf_inactive(
	struct scxfs_trans	**trans,
	struct scxfs_inode	*dp,
	struct scxfs_buf		*bp)
{
	struct scxfs_attr_leafblock *leaf;
	struct scxfs_attr3_icleaf_hdr ichdr;
	struct scxfs_attr_leaf_entry *entry;
	struct scxfs_attr_leaf_name_remote *name_rmt;
	struct scxfs_attr_inactive_list *list;
	struct scxfs_attr_inactive_list *lp;
	int			error;
	int			count;
	int			size;
	int			tmp;
	int			i;
	struct scxfs_mount	*mp = bp->b_mount;

	leaf = bp->b_addr;
	scxfs_attr3_leaf_hdr_from_disk(mp->m_attr_geo, &ichdr, leaf);

	/*
	 * Count the number of "remote" value extents.
	 */
	count = 0;
	entry = scxfs_attr3_leaf_entryp(leaf);
	for (i = 0; i < ichdr.count; entry++, i++) {
		if (be16_to_cpu(entry->nameidx) &&
		    ((entry->flags & SCXFS_ATTR_LOCAL) == 0)) {
			name_rmt = scxfs_attr3_leaf_name_remote(leaf, i);
			if (name_rmt->valueblk)
				count++;
		}
	}

	/*
	 * If there are no "remote" values, we're done.
	 */
	if (count == 0) {
		scxfs_trans_brelse(*trans, bp);
		return 0;
	}

	/*
	 * Allocate storage for a list of all the "remote" value extents.
	 */
	size = count * sizeof(scxfs_attr_inactive_list_t);
	list = kmem_alloc(size, 0);

	/*
	 * Identify each of the "remote" value extents.
	 */
	lp = list;
	entry = scxfs_attr3_leaf_entryp(leaf);
	for (i = 0; i < ichdr.count; entry++, i++) {
		if (be16_to_cpu(entry->nameidx) &&
		    ((entry->flags & SCXFS_ATTR_LOCAL) == 0)) {
			name_rmt = scxfs_attr3_leaf_name_remote(leaf, i);
			if (name_rmt->valueblk) {
				lp->valueblk = be32_to_cpu(name_rmt->valueblk);
				lp->valuelen = scxfs_attr3_rmt_blocks(dp->i_mount,
						    be32_to_cpu(name_rmt->valuelen));
				lp++;
			}
		}
	}
	scxfs_trans_brelse(*trans, bp);	/* unlock for trans. in freextent() */

	/*
	 * Invalidate each of the "remote" value extents.
	 */
	error = 0;
	for (lp = list, i = 0; i < count; i++, lp++) {
		tmp = scxfs_attr3_leaf_freextent(trans, dp,
				lp->valueblk, lp->valuelen);

		if (error == 0)
			error = tmp;	/* save only the 1st errno */
	}

	kmem_free(list);
	return error;
}

/*
 * Recurse (gasp!) through the attribute nodes until we find leaves.
 * We're doing a depth-first traversal in order to invalidate everything.
 */
STATIC int
scxfs_attr3_node_inactive(
	struct scxfs_trans **trans,
	struct scxfs_inode *dp,
	struct scxfs_buf	*bp,
	int		level)
{
	scxfs_da_blkinfo_t *info;
	scxfs_da_intnode_t *node;
	scxfs_dablk_t child_fsb;
	scxfs_daddr_t parent_blkno, child_blkno;
	int error, i;
	struct scxfs_buf *child_bp;
	struct scxfs_da_node_entry *btree;
	struct scxfs_da3_icnode_hdr ichdr;

	/*
	 * Since this code is recursive (gasp!) we must protect ourselves.
	 */
	if (level > SCXFS_DA_NODE_MAXDEPTH) {
		scxfs_trans_brelse(*trans, bp);	/* no locks for later trans */
		return -EIO;
	}

	node = bp->b_addr;
	dp->d_ops->node_hdr_from_disk(&ichdr, node);
	parent_blkno = bp->b_bn;
	if (!ichdr.count) {
		scxfs_trans_brelse(*trans, bp);
		return 0;
	}
	btree = dp->d_ops->node_tree_p(node);
	child_fsb = be32_to_cpu(btree[0].before);
	scxfs_trans_brelse(*trans, bp);	/* no locks for later trans */

	/*
	 * If this is the node level just above the leaves, simply loop
	 * over the leaves removing all of them.  If this is higher up
	 * in the tree, recurse downward.
	 */
	for (i = 0; i < ichdr.count; i++) {
		/*
		 * Read the subsidiary block to see what we have to work with.
		 * Don't do this in a transaction.  This is a depth-first
		 * traversal of the tree so we may deal with many blocks
		 * before we come back to this one.
		 */
		error = scxfs_da3_node_read(*trans, dp, child_fsb, -1, &child_bp,
					  SCXFS_ATTR_FORK);
		if (error)
			return error;

		/* save for re-read later */
		child_blkno = SCXFS_BUF_ADDR(child_bp);

		/*
		 * Invalidate the subtree, however we have to.
		 */
		info = child_bp->b_addr;
		switch (info->magic) {
		case cpu_to_be16(SCXFS_DA_NODE_MAGIC):
		case cpu_to_be16(SCXFS_DA3_NODE_MAGIC):
			error = scxfs_attr3_node_inactive(trans, dp, child_bp,
							level + 1);
			break;
		case cpu_to_be16(SCXFS_ATTR_LEAF_MAGIC):
		case cpu_to_be16(SCXFS_ATTR3_LEAF_MAGIC):
			error = scxfs_attr3_leaf_inactive(trans, dp, child_bp);
			break;
		default:
			error = -EIO;
			scxfs_trans_brelse(*trans, child_bp);
			break;
		}
		if (error)
			return error;

		/*
		 * Remove the subsidiary block from the cache and from the log.
		 */
		error = scxfs_da_get_buf(*trans, dp, 0, child_blkno, &child_bp,
				       SCXFS_ATTR_FORK);
		if (error)
			return error;
		scxfs_trans_binval(*trans, child_bp);

		/*
		 * If we're not done, re-read the parent to get the next
		 * child block number.
		 */
		if (i + 1 < ichdr.count) {
			error = scxfs_da3_node_read(*trans, dp, 0, parent_blkno,
						 &bp, SCXFS_ATTR_FORK);
			if (error)
				return error;
			node = bp->b_addr;
			btree = dp->d_ops->node_tree_p(node);
			child_fsb = be32_to_cpu(btree[i + 1].before);
			scxfs_trans_brelse(*trans, bp);
		}
		/*
		 * Atomically commit the whole invalidate stuff.
		 */
		error = scxfs_trans_roll_inode(trans, dp);
		if (error)
			return  error;
	}

	return 0;
}

/*
 * Indiscriminately delete the entire attribute fork
 *
 * Recurse (gasp!) through the attribute nodes until we find leaves.
 * We're doing a depth-first traversal in order to invalidate everything.
 */
static int
scxfs_attr3_root_inactive(
	struct scxfs_trans	**trans,
	struct scxfs_inode	*dp)
{
	struct scxfs_da_blkinfo	*info;
	struct scxfs_buf		*bp;
	scxfs_daddr_t		blkno;
	int			error;

	/*
	 * Read block 0 to see what we have to work with.
	 * We only get here if we have extents, since we remove
	 * the extents in reverse order the extent containing
	 * block 0 must still be there.
	 */
	error = scxfs_da3_node_read(*trans, dp, 0, -1, &bp, SCXFS_ATTR_FORK);
	if (error)
		return error;
	blkno = bp->b_bn;

	/*
	 * Invalidate the tree, even if the "tree" is only a single leaf block.
	 * This is a depth-first traversal!
	 */
	info = bp->b_addr;
	switch (info->magic) {
	case cpu_to_be16(SCXFS_DA_NODE_MAGIC):
	case cpu_to_be16(SCXFS_DA3_NODE_MAGIC):
		error = scxfs_attr3_node_inactive(trans, dp, bp, 1);
		break;
	case cpu_to_be16(SCXFS_ATTR_LEAF_MAGIC):
	case cpu_to_be16(SCXFS_ATTR3_LEAF_MAGIC):
		error = scxfs_attr3_leaf_inactive(trans, dp, bp);
		break;
	default:
		error = -EIO;
		scxfs_trans_brelse(*trans, bp);
		break;
	}
	if (error)
		return error;

	/*
	 * Invalidate the incore copy of the root block.
	 */
	error = scxfs_da_get_buf(*trans, dp, 0, blkno, &bp, SCXFS_ATTR_FORK);
	if (error)
		return error;
	scxfs_trans_binval(*trans, bp);	/* remove from cache */
	/*
	 * Commit the invalidate and start the next transaction.
	 */
	error = scxfs_trans_roll_inode(trans, dp);

	return error;
}

/*
 * scxfs_attr_inactive kills all traces of an attribute fork on an inode. It
 * removes both the on-disk and in-memory inode fork. Note that this also has to
 * handle the condition of inodes without attributes but with an attribute fork
 * configured, so we can't use scxfs_inode_hasattr() here.
 *
 * The in-memory attribute fork is removed even on error.
 */
int
scxfs_attr_inactive(
	struct scxfs_inode	*dp)
{
	struct scxfs_trans	*trans;
	struct scxfs_mount	*mp;
	int			lock_mode = SCXFS_ILOCK_SHARED;
	int			error = 0;

	mp = dp->i_mount;
	ASSERT(! SCXFS_NOT_DQATTACHED(mp, dp));

	scxfs_ilock(dp, lock_mode);
	if (!SCXFS_IFORK_Q(dp))
		goto out_destroy_fork;
	scxfs_iunlock(dp, lock_mode);

	lock_mode = 0;

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_attrinval, 0, 0, 0, &trans);
	if (error)
		goto out_destroy_fork;

	lock_mode = SCXFS_ILOCK_EXCL;
	scxfs_ilock(dp, lock_mode);

	if (!SCXFS_IFORK_Q(dp))
		goto out_cancel;

	/*
	 * No need to make quota reservations here. We expect to release some
	 * blocks, not allocate, in the common case.
	 */
	scxfs_trans_ijoin(trans, dp, 0);

	/*
	 * Invalidate and truncate the attribute fork extents. Make sure the
	 * fork actually has attributes as otherwise the invalidation has no
	 * blocks to read and returns an error. In this case, just do the fork
	 * removal below.
	 */
	if (scxfs_inode_hasattr(dp) &&
	    dp->i_d.di_aformat != SCXFS_DINODE_FMT_LOCAL) {
		error = scxfs_attr3_root_inactive(&trans, dp);
		if (error)
			goto out_cancel;

		error = scxfs_itruncate_extents(&trans, dp, SCXFS_ATTR_FORK, 0);
		if (error)
			goto out_cancel;
	}

	/* Reset the attribute fork - this also destroys the in-core fork */
	scxfs_attr_fork_remove(dp, trans);

	error = scxfs_trans_commit(trans);
	scxfs_iunlock(dp, lock_mode);
	return error;

out_cancel:
	scxfs_trans_cancel(trans);
out_destroy_fork:
	/* kill the in-core attr fork before we drop the inode lock */
	if (dp->i_afp)
		scxfs_idestroy_fork(dp, SCXFS_ATTR_FORK);
	if (lock_mode)
		scxfs_iunlock(dp, lock_mode);
	return error;
}
