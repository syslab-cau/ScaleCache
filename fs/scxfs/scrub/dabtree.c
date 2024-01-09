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
#include "scxfs_log_format.h"
#include "scxfs_trans.h"
#include "scxfs_inode.h"
#include "scxfs_dir2.h"
#include "scxfs_dir2_priv.h"
#include "scxfs_attr_leaf.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/dabtree.h"

/* Directory/Attribute Btree */

/*
 * Check for da btree operation errors.  See the section about handling
 * operational errors in common.c.
 */
bool
xchk_da_process_error(
	struct xchk_da_btree	*ds,
	int			level,
	int			*error)
{
	struct scxfs_scrub	*sc = ds->sc;

	if (*error == 0)
		return true;

	switch (*error) {
	case -EDEADLOCK:
		/* Used to restart an op with deadlock avoidance. */
		trace_xchk_deadlock_retry(sc->ip, sc->sm, *error);
		break;
	case -EFSBADCRC:
	case -EFSCORRUPTED:
		/* Note the badness but don't abort. */
		sc->sm->sm_flags |= SCXFS_SCRUB_OFLAG_CORRUPT;
		*error = 0;
		/* fall through */
	default:
		trace_xchk_file_op_error(sc, ds->dargs.whichfork,
				scxfs_dir2_da_to_db(ds->dargs.geo,
					ds->state->path.blk[level].blkno),
				*error, __return_address);
		break;
	}
	return false;
}

/*
 * Check for da btree corruption.  See the section about handling
 * operational errors in common.c.
 */
void
xchk_da_set_corrupt(
	struct xchk_da_btree	*ds,
	int			level)
{
	struct scxfs_scrub	*sc = ds->sc;

	sc->sm->sm_flags |= SCXFS_SCRUB_OFLAG_CORRUPT;

	trace_xchk_fblock_error(sc, ds->dargs.whichfork,
			scxfs_dir2_da_to_db(ds->dargs.geo,
				ds->state->path.blk[level].blkno),
			__return_address);
}

/* Find an entry at a certain level in a da btree. */
STATIC void *
xchk_da_btree_entry(
	struct xchk_da_btree	*ds,
	int			level,
	int			rec)
{
	char			*ents;
	struct scxfs_da_state_blk	*blk;
	void			*baddr;

	/* Dispatch the entry finding function. */
	blk = &ds->state->path.blk[level];
	baddr = blk->bp->b_addr;
	switch (blk->magic) {
	case SCXFS_ATTR_LEAF_MAGIC:
	case SCXFS_ATTR3_LEAF_MAGIC:
		ents = (char *)scxfs_attr3_leaf_entryp(baddr);
		return ents + (rec * sizeof(struct scxfs_attr_leaf_entry));
	case SCXFS_DIR2_LEAFN_MAGIC:
	case SCXFS_DIR3_LEAFN_MAGIC:
		ents = (char *)ds->dargs.dp->d_ops->leaf_ents_p(baddr);
		return ents + (rec * sizeof(struct scxfs_dir2_leaf_entry));
	case SCXFS_DIR2_LEAF1_MAGIC:
	case SCXFS_DIR3_LEAF1_MAGIC:
		ents = (char *)ds->dargs.dp->d_ops->leaf_ents_p(baddr);
		return ents + (rec * sizeof(struct scxfs_dir2_leaf_entry));
	case SCXFS_DA_NODE_MAGIC:
	case SCXFS_DA3_NODE_MAGIC:
		ents = (char *)ds->dargs.dp->d_ops->node_tree_p(baddr);
		return ents + (rec * sizeof(struct scxfs_da_node_entry));
	}

	return NULL;
}

/* Scrub a da btree hash (key). */
int
xchk_da_btree_hash(
	struct xchk_da_btree		*ds,
	int				level,
	__be32				*hashp)
{
	struct scxfs_da_state_blk		*blks;
	struct scxfs_da_node_entry	*entry;
	scxfs_dahash_t			hash;
	scxfs_dahash_t			parent_hash;

	/* Is this hash in order? */
	hash = be32_to_cpu(*hashp);
	if (hash < ds->hashes[level])
		xchk_da_set_corrupt(ds, level);
	ds->hashes[level] = hash;

	if (level == 0)
		return 0;

	/* Is this hash no larger than the parent hash? */
	blks = ds->state->path.blk;
	entry = xchk_da_btree_entry(ds, level - 1, blks[level - 1].index);
	parent_hash = be32_to_cpu(entry->hashval);
	if (parent_hash < hash)
		xchk_da_set_corrupt(ds, level);

	return 0;
}

/*
 * Check a da btree pointer.  Returns true if it's ok to use this
 * pointer.
 */
STATIC bool
xchk_da_btree_ptr_ok(
	struct xchk_da_btree	*ds,
	int			level,
	scxfs_dablk_t		blkno)
{
	if (blkno < ds->lowest || (ds->highest != 0 && blkno >= ds->highest)) {
		xchk_da_set_corrupt(ds, level);
		return false;
	}

	return true;
}

/*
 * The da btree scrubber can handle leaf1 blocks as a degenerate
 * form of leafn blocks.  Since the regular da code doesn't handle
 * leaf1, we must multiplex the verifiers.
 */
static void
xchk_da_btree_read_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_da_blkinfo	*info = bp->b_addr;

	switch (be16_to_cpu(info->magic)) {
	case SCXFS_DIR2_LEAF1_MAGIC:
	case SCXFS_DIR3_LEAF1_MAGIC:
		bp->b_ops = &scxfs_dir3_leaf1_buf_ops;
		bp->b_ops->verify_read(bp);
		return;
	default:
		/*
		 * scxfs_da3_node_buf_ops already know how to handle
		 * DA*_NODE, ATTR*_LEAF, and DIR*_LEAFN blocks.
		 */
		bp->b_ops = &scxfs_da3_node_buf_ops;
		bp->b_ops->verify_read(bp);
		return;
	}
}
static void
xchk_da_btree_write_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_da_blkinfo	*info = bp->b_addr;

	switch (be16_to_cpu(info->magic)) {
	case SCXFS_DIR2_LEAF1_MAGIC:
	case SCXFS_DIR3_LEAF1_MAGIC:
		bp->b_ops = &scxfs_dir3_leaf1_buf_ops;
		bp->b_ops->verify_write(bp);
		return;
	default:
		/*
		 * scxfs_da3_node_buf_ops already know how to handle
		 * DA*_NODE, ATTR*_LEAF, and DIR*_LEAFN blocks.
		 */
		bp->b_ops = &scxfs_da3_node_buf_ops;
		bp->b_ops->verify_write(bp);
		return;
	}
}
static void *
xchk_da_btree_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_da_blkinfo	*info = bp->b_addr;

	switch (be16_to_cpu(info->magic)) {
	case SCXFS_DIR2_LEAF1_MAGIC:
	case SCXFS_DIR3_LEAF1_MAGIC:
		bp->b_ops = &scxfs_dir3_leaf1_buf_ops;
		return bp->b_ops->verify_struct(bp);
	default:
		bp->b_ops = &scxfs_da3_node_buf_ops;
		return bp->b_ops->verify_struct(bp);
	}
}

static const struct scxfs_buf_ops xchk_da_btree_buf_ops = {
	.name = "xchk_da_btree",
	.verify_read = xchk_da_btree_read_verify,
	.verify_write = xchk_da_btree_write_verify,
	.verify_struct = xchk_da_btree_verify,
};

/* Check a block's sibling. */
STATIC int
xchk_da_btree_block_check_sibling(
	struct xchk_da_btree	*ds,
	int			level,
	int			direction,
	scxfs_dablk_t		sibling)
{
	int			retval;
	int			error;

	memcpy(&ds->state->altpath, &ds->state->path,
			sizeof(ds->state->altpath));

	/*
	 * If the pointer is null, we shouldn't be able to move the upper
	 * level pointer anywhere.
	 */
	if (sibling == 0) {
		error = scxfs_da3_path_shift(ds->state, &ds->state->altpath,
				direction, false, &retval);
		if (error == 0 && retval == 0)
			xchk_da_set_corrupt(ds, level);
		error = 0;
		goto out;
	}

	/* Move the alternate cursor one block in the direction given. */
	error = scxfs_da3_path_shift(ds->state, &ds->state->altpath,
			direction, false, &retval);
	if (!xchk_da_process_error(ds, level, &error))
		return error;
	if (retval) {
		xchk_da_set_corrupt(ds, level);
		return error;
	}
	if (ds->state->altpath.blk[level].bp)
		xchk_buffer_recheck(ds->sc,
				ds->state->altpath.blk[level].bp);

	/* Compare upper level pointer to sibling pointer. */
	if (ds->state->altpath.blk[level].blkno != sibling)
		xchk_da_set_corrupt(ds, level);
	if (ds->state->altpath.blk[level].bp) {
		scxfs_trans_brelse(ds->dargs.trans,
				ds->state->altpath.blk[level].bp);
		ds->state->altpath.blk[level].bp = NULL;
	}
out:
	return error;
}

/* Check a block's sibling pointers. */
STATIC int
xchk_da_btree_block_check_siblings(
	struct xchk_da_btree	*ds,
	int			level,
	struct scxfs_da_blkinfo	*hdr)
{
	scxfs_dablk_t		forw;
	scxfs_dablk_t		back;
	int			error = 0;

	forw = be32_to_cpu(hdr->forw);
	back = be32_to_cpu(hdr->back);

	/* Top level blocks should not have sibling pointers. */
	if (level == 0) {
		if (forw != 0 || back != 0)
			xchk_da_set_corrupt(ds, level);
		return 0;
	}

	/*
	 * Check back (left) and forw (right) pointers.  These functions
	 * absorb error codes for us.
	 */
	error = xchk_da_btree_block_check_sibling(ds, level, 0, back);
	if (error)
		goto out;
	error = xchk_da_btree_block_check_sibling(ds, level, 1, forw);

out:
	memset(&ds->state->altpath, 0, sizeof(ds->state->altpath));
	return error;
}

/* Load a dir/attribute block from a btree. */
STATIC int
xchk_da_btree_block(
	struct xchk_da_btree		*ds,
	int				level,
	scxfs_dablk_t			blkno)
{
	struct scxfs_da_state_blk		*blk;
	struct scxfs_da_intnode		*node;
	struct scxfs_da_node_entry	*btree;
	struct scxfs_da3_blkinfo		*hdr3;
	struct scxfs_da_args		*dargs = &ds->dargs;
	struct scxfs_inode		*ip = ds->dargs.dp;
	scxfs_ino_t			owner;
	int				*pmaxrecs;
	struct scxfs_da3_icnode_hdr	nodehdr;
	int				error = 0;

	blk = &ds->state->path.blk[level];
	ds->state->path.active = level + 1;

	/* Release old block. */
	if (blk->bp) {
		scxfs_trans_brelse(dargs->trans, blk->bp);
		blk->bp = NULL;
	}

	/* Check the pointer. */
	blk->blkno = blkno;
	if (!xchk_da_btree_ptr_ok(ds, level, blkno))
		goto out_nobuf;

	/* Read the buffer. */
	error = scxfs_da_read_buf(dargs->trans, dargs->dp, blk->blkno, -2,
			&blk->bp, dargs->whichfork,
			&xchk_da_btree_buf_ops);
	if (!xchk_da_process_error(ds, level, &error))
		goto out_nobuf;
	if (blk->bp)
		xchk_buffer_recheck(ds->sc, blk->bp);

	/*
	 * We didn't find a dir btree root block, which means that
	 * there's no LEAF1/LEAFN tree (at least not where it's supposed
	 * to be), so jump out now.
	 */
	if (ds->dargs.whichfork == SCXFS_DATA_FORK && level == 0 &&
			blk->bp == NULL)
		goto out_nobuf;

	/* It's /not/ ok for attr trees not to have a da btree. */
	if (blk->bp == NULL) {
		xchk_da_set_corrupt(ds, level);
		goto out_nobuf;
	}

	hdr3 = blk->bp->b_addr;
	blk->magic = be16_to_cpu(hdr3->hdr.magic);
	pmaxrecs = &ds->maxrecs[level];

	/* We only started zeroing the header on v5 filesystems. */
	if (scxfs_sb_version_hascrc(&ds->sc->mp->m_sb) && hdr3->hdr.pad)
		xchk_da_set_corrupt(ds, level);

	/* Check the owner. */
	if (scxfs_sb_version_hascrc(&ip->i_mount->m_sb)) {
		owner = be64_to_cpu(hdr3->owner);
		if (owner != ip->i_ino)
			xchk_da_set_corrupt(ds, level);
	}

	/* Check the siblings. */
	error = xchk_da_btree_block_check_siblings(ds, level, &hdr3->hdr);
	if (error)
		goto out;

	/* Interpret the buffer. */
	switch (blk->magic) {
	case SCXFS_ATTR_LEAF_MAGIC:
	case SCXFS_ATTR3_LEAF_MAGIC:
		scxfs_trans_buf_set_type(dargs->trans, blk->bp,
				SCXFS_BLFT_ATTR_LEAF_BUF);
		blk->magic = SCXFS_ATTR_LEAF_MAGIC;
		blk->hashval = scxfs_attr_leaf_lasthash(blk->bp, pmaxrecs);
		if (ds->tree_level != 0)
			xchk_da_set_corrupt(ds, level);
		break;
	case SCXFS_DIR2_LEAFN_MAGIC:
	case SCXFS_DIR3_LEAFN_MAGIC:
		scxfs_trans_buf_set_type(dargs->trans, blk->bp,
				SCXFS_BLFT_DIR_LEAFN_BUF);
		blk->magic = SCXFS_DIR2_LEAFN_MAGIC;
		blk->hashval = scxfs_dir2_leaf_lasthash(ip, blk->bp, pmaxrecs);
		if (ds->tree_level != 0)
			xchk_da_set_corrupt(ds, level);
		break;
	case SCXFS_DIR2_LEAF1_MAGIC:
	case SCXFS_DIR3_LEAF1_MAGIC:
		scxfs_trans_buf_set_type(dargs->trans, blk->bp,
				SCXFS_BLFT_DIR_LEAF1_BUF);
		blk->magic = SCXFS_DIR2_LEAF1_MAGIC;
		blk->hashval = scxfs_dir2_leaf_lasthash(ip, blk->bp, pmaxrecs);
		if (ds->tree_level != 0)
			xchk_da_set_corrupt(ds, level);
		break;
	case SCXFS_DA_NODE_MAGIC:
	case SCXFS_DA3_NODE_MAGIC:
		scxfs_trans_buf_set_type(dargs->trans, blk->bp,
				SCXFS_BLFT_DA_NODE_BUF);
		blk->magic = SCXFS_DA_NODE_MAGIC;
		node = blk->bp->b_addr;
		ip->d_ops->node_hdr_from_disk(&nodehdr, node);
		btree = ip->d_ops->node_tree_p(node);
		*pmaxrecs = nodehdr.count;
		blk->hashval = be32_to_cpu(btree[*pmaxrecs - 1].hashval);
		if (level == 0) {
			if (nodehdr.level >= SCXFS_DA_NODE_MAXDEPTH) {
				xchk_da_set_corrupt(ds, level);
				goto out_freebp;
			}
			ds->tree_level = nodehdr.level;
		} else {
			if (ds->tree_level != nodehdr.level) {
				xchk_da_set_corrupt(ds, level);
				goto out_freebp;
			}
		}

		/* XXX: Check hdr3.pad32 once we know how to fix it. */
		break;
	default:
		xchk_da_set_corrupt(ds, level);
		goto out_freebp;
	}

out:
	return error;
out_freebp:
	scxfs_trans_brelse(dargs->trans, blk->bp);
	blk->bp = NULL;
out_nobuf:
	blk->blkno = 0;
	return error;
}

/* Visit all nodes and leaves of a da btree. */
int
xchk_da_btree(
	struct scxfs_scrub		*sc,
	int				whichfork,
	xchk_da_btree_rec_fn		scrub_fn,
	void				*private)
{
	struct xchk_da_btree		ds = {};
	struct scxfs_mount		*mp = sc->mp;
	struct scxfs_da_state_blk		*blks;
	struct scxfs_da_node_entry	*key;
	void				*rec;
	scxfs_dablk_t			blkno;
	int				level;
	int				error;

	/* Skip short format data structures; no btree to scan. */
	if (SCXFS_IFORK_FORMAT(sc->ip, whichfork) != SCXFS_DINODE_FMT_EXTENTS &&
	    SCXFS_IFORK_FORMAT(sc->ip, whichfork) != SCXFS_DINODE_FMT_BTREE)
		return 0;

	/* Set up initial da state. */
	ds.dargs.dp = sc->ip;
	ds.dargs.whichfork = whichfork;
	ds.dargs.trans = sc->tp;
	ds.dargs.op_flags = SCXFS_DA_OP_OKNOENT;
	ds.state = scxfs_da_state_alloc();
	ds.state->args = &ds.dargs;
	ds.state->mp = mp;
	ds.sc = sc;
	ds.private = private;
	if (whichfork == SCXFS_ATTR_FORK) {
		ds.dargs.geo = mp->m_attr_geo;
		ds.lowest = 0;
		ds.highest = 0;
	} else {
		ds.dargs.geo = mp->m_dir_geo;
		ds.lowest = ds.dargs.geo->leafblk;
		ds.highest = ds.dargs.geo->freeblk;
	}
	blkno = ds.lowest;
	level = 0;

	/* Find the root of the da tree, if present. */
	blks = ds.state->path.blk;
	error = xchk_da_btree_block(&ds, level, blkno);
	if (error)
		goto out_state;
	/*
	 * We didn't find a block at ds.lowest, which means that there's
	 * no LEAF1/LEAFN tree (at least not where it's supposed to be),
	 * so jump out now.
	 */
	if (blks[level].bp == NULL)
		goto out_state;

	blks[level].index = 0;
	while (level >= 0 && level < SCXFS_DA_NODE_MAXDEPTH) {
		/* Handle leaf block. */
		if (blks[level].magic != SCXFS_DA_NODE_MAGIC) {
			/* End of leaf, pop back towards the root. */
			if (blks[level].index >= ds.maxrecs[level]) {
				if (level > 0)
					blks[level - 1].index++;
				ds.tree_level++;
				level--;
				continue;
			}

			/* Dispatch record scrubbing. */
			rec = xchk_da_btree_entry(&ds, level,
					blks[level].index);
			error = scrub_fn(&ds, level, rec);
			if (error)
				break;
			if (xchk_should_terminate(sc, &error) ||
			    (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT))
				break;

			blks[level].index++;
			continue;
		}


		/* End of node, pop back towards the root. */
		if (blks[level].index >= ds.maxrecs[level]) {
			if (level > 0)
				blks[level - 1].index++;
			ds.tree_level++;
			level--;
			continue;
		}

		/* Hashes in order for scrub? */
		key = xchk_da_btree_entry(&ds, level, blks[level].index);
		error = xchk_da_btree_hash(&ds, level, &key->hashval);
		if (error)
			goto out;

		/* Drill another level deeper. */
		blkno = be32_to_cpu(key->before);
		level++;
		if (level >= SCXFS_DA_NODE_MAXDEPTH) {
			/* Too deep! */
			xchk_da_set_corrupt(&ds, level - 1);
			break;
		}
		ds.tree_level--;
		error = xchk_da_btree_block(&ds, level, blkno);
		if (error)
			goto out;
		if (blks[level].bp == NULL)
			goto out;

		blks[level].index = 0;
	}

out:
	/* Release all the buffers we're tracking. */
	for (level = 0; level < SCXFS_DA_NODE_MAXDEPTH; level++) {
		if (blks[level].bp == NULL)
			continue;
		scxfs_trans_brelse(sc->tp, blks[level].bp);
		blks[level].bp = NULL;
	}

out_state:
	scxfs_da_state_free(ds.state);
	return error;
}
