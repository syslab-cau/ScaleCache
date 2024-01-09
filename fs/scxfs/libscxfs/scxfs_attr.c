// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_defer.h"
#include "scxfs_da_format.h"
#include "scxfs_da_btree.h"
#include "scxfs_attr_sf.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_bmap.h"
#include "scxfs_bmap_btree.h"
#include "scxfs_attr.h"
#include "scxfs_attr_leaf.h"
#include "scxfs_attr_remote.h"
#include "scxfs_quota.h"
#include "scxfs_trans_space.h"
#include "scxfs_trace.h"

/*
 * scxfs_attr.c
 *
 * Provide the external interfaces to manage attribute lists.
 */

/*========================================================================
 * Function prototypes for the kernel.
 *========================================================================*/

/*
 * Internal routines when attribute list fits inside the inode.
 */
STATIC int scxfs_attr_shortform_addname(scxfs_da_args_t *args);

/*
 * Internal routines when attribute list is one block.
 */
STATIC int scxfs_attr_leaf_get(scxfs_da_args_t *args);
STATIC int scxfs_attr_leaf_addname(scxfs_da_args_t *args);
STATIC int scxfs_attr_leaf_removename(scxfs_da_args_t *args);

/*
 * Internal routines when attribute list is more than one block.
 */
STATIC int scxfs_attr_node_get(scxfs_da_args_t *args);
STATIC int scxfs_attr_node_addname(scxfs_da_args_t *args);
STATIC int scxfs_attr_node_removename(scxfs_da_args_t *args);
STATIC int scxfs_attr_fillstate(scxfs_da_state_t *state);
STATIC int scxfs_attr_refillstate(scxfs_da_state_t *state);


STATIC int
scxfs_attr_args_init(
	struct scxfs_da_args	*args,
	struct scxfs_inode	*dp,
	const unsigned char	*name,
	int			flags)
{

	if (!name)
		return -EINVAL;

	memset(args, 0, sizeof(*args));
	args->geo = dp->i_mount->m_attr_geo;
	args->whichfork = SCXFS_ATTR_FORK;
	args->dp = dp;
	args->flags = flags;
	args->name = name;
	args->namelen = strlen((const char *)name);
	if (args->namelen >= MAXNAMELEN)
		return -EFAULT;		/* match IRIX behaviour */

	args->hashval = scxfs_da_hashname(args->name, args->namelen);
	return 0;
}

int
scxfs_inode_hasattr(
	struct scxfs_inode	*ip)
{
	if (!SCXFS_IFORK_Q(ip) ||
	    (ip->i_d.di_aformat == SCXFS_DINODE_FMT_EXTENTS &&
	     ip->i_d.di_anextents == 0))
		return 0;
	return 1;
}

/*========================================================================
 * Overall external interface routines.
 *========================================================================*/

/*
 * Retrieve an extended attribute and its value.  Must have ilock.
 * Returns 0 on successful retrieval, otherwise an error.
 */
int
scxfs_attr_get_ilocked(
	struct scxfs_inode	*ip,
	struct scxfs_da_args	*args)
{
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL));

	if (!scxfs_inode_hasattr(ip))
		return -ENOATTR;
	else if (ip->i_d.di_aformat == SCXFS_DINODE_FMT_LOCAL)
		return scxfs_attr_shortform_getvalue(args);
	else if (scxfs_bmap_one_block(ip, SCXFS_ATTR_FORK))
		return scxfs_attr_leaf_get(args);
	else
		return scxfs_attr_node_get(args);
}

/*
 * Retrieve an extended attribute by name, and its value if requested.
 *
 * If ATTR_KERNOVAL is set in @flags, then the caller does not want the value,
 * just an indication whether the attribute exists and the size of the value if
 * it exists. The size is returned in @valuelenp,
 *
 * If the attribute is found, but exceeds the size limit set by the caller in
 * @valuelenp, return -ERANGE with the size of the attribute that was found in
 * @valuelenp.
 *
 * If ATTR_ALLOC is set in @flags, allocate the buffer for the value after
 * existence of the attribute has been determined. On success, return that
 * buffer to the caller and leave them to free it. On failure, free any
 * allocated buffer and ensure the buffer pointer returned to the caller is
 * null.
 */
int
scxfs_attr_get(
	struct scxfs_inode	*ip,
	const unsigned char	*name,
	unsigned char		**value,
	int			*valuelenp,
	int			flags)
{
	struct scxfs_da_args	args;
	uint			lock_mode;
	int			error;

	ASSERT((flags & (ATTR_ALLOC | ATTR_KERNOVAL)) || *value);

	SCXFS_STATS_INC(ip->i_mount, xs_attr_get);

	if (SCXFS_FORCED_SHUTDOWN(ip->i_mount))
		return -EIO;

	error = scxfs_attr_args_init(&args, ip, name, flags);
	if (error)
		return error;

	/* Entirely possible to look up a name which doesn't exist */
	args.op_flags = SCXFS_DA_OP_OKNOENT;
	if (flags & ATTR_ALLOC)
		args.op_flags |= SCXFS_DA_OP_ALLOCVAL;
	else
		args.value = *value;
	args.valuelen = *valuelenp;

	lock_mode = scxfs_ilock_attr_map_shared(ip);
	error = scxfs_attr_get_ilocked(ip, &args);
	scxfs_iunlock(ip, lock_mode);
	*valuelenp = args.valuelen;

	/* on error, we have to clean up allocated value buffers */
	if (error) {
		if (flags & ATTR_ALLOC) {
			kmem_free(args.value);
			*value = NULL;
		}
		return error;
	}
	*value = args.value;
	return 0;
}

/*
 * Calculate how many blocks we need for the new attribute,
 */
STATIC int
scxfs_attr_calc_size(
	struct scxfs_da_args	*args,
	int			*local)
{
	struct scxfs_mount	*mp = args->dp->i_mount;
	int			size;
	int			nblks;

	/*
	 * Determine space new attribute will use, and if it would be
	 * "local" or "remote" (note: local != inline).
	 */
	size = scxfs_attr_leaf_newentsize(args, local);
	nblks = SCXFS_DAENTER_SPACE_RES(mp, SCXFS_ATTR_FORK);
	if (*local) {
		if (size > (args->geo->blksize / 2)) {
			/* Double split possible */
			nblks *= 2;
		}
	} else {
		/*
		 * Out of line attribute, cannot double split, but
		 * make room for the attribute value itself.
		 */
		uint	dblocks = scxfs_attr3_rmt_blocks(mp, args->valuelen);
		nblks += dblocks;
		nblks += SCXFS_NEXTENTADD_SPACE_RES(mp, dblocks, SCXFS_ATTR_FORK);
	}

	return nblks;
}

STATIC int
scxfs_attr_try_sf_addname(
	struct scxfs_inode	*dp,
	struct scxfs_da_args	*args)
{

	struct scxfs_mount	*mp = dp->i_mount;
	int			error, error2;

	error = scxfs_attr_shortform_addname(args);
	if (error == -ENOSPC)
		return error;

	/*
	 * Commit the shortform mods, and we're done.
	 * NOTE: this is also the error path (EEXIST, etc).
	 */
	if (!error && (args->flags & ATTR_KERNOTIME) == 0)
		scxfs_trans_ichgtime(args->trans, dp, SCXFS_ICHGTIME_CHG);

	if (mp->m_flags & SCXFS_MOUNT_WSYNC)
		scxfs_trans_set_sync(args->trans);

	error2 = scxfs_trans_commit(args->trans);
	args->trans = NULL;
	return error ? error : error2;
}

/*
 * Set the attribute specified in @args.
 */
int
scxfs_attr_set_args(
	struct scxfs_da_args	*args)
{
	struct scxfs_inode	*dp = args->dp;
	struct scxfs_buf          *leaf_bp = NULL;
	int			error;

	/*
	 * If the attribute list is non-existent or a shortform list,
	 * upgrade it to a single-leaf-block attribute list.
	 */
	if (dp->i_d.di_aformat == SCXFS_DINODE_FMT_LOCAL ||
	    (dp->i_d.di_aformat == SCXFS_DINODE_FMT_EXTENTS &&
	     dp->i_d.di_anextents == 0)) {

		/*
		 * Build initial attribute list (if required).
		 */
		if (dp->i_d.di_aformat == SCXFS_DINODE_FMT_EXTENTS)
			scxfs_attr_shortform_create(args);

		/*
		 * Try to add the attr to the attribute list in the inode.
		 */
		error = scxfs_attr_try_sf_addname(dp, args);
		if (error != -ENOSPC)
			return error;

		/*
		 * It won't fit in the shortform, transform to a leaf block.
		 * GROT: another possible req'mt for a double-split btree op.
		 */
		error = scxfs_attr_shortform_to_leaf(args, &leaf_bp);
		if (error)
			return error;

		/*
		 * Prevent the leaf buffer from being unlocked so that a
		 * concurrent AIL push cannot grab the half-baked leaf
		 * buffer and run into problems with the write verifier.
		 * Once we're done rolling the transaction we can release
		 * the hold and add the attr to the leaf.
		 */
		scxfs_trans_bhold(args->trans, leaf_bp);
		error = scxfs_defer_finish(&args->trans);
		scxfs_trans_bhold_release(args->trans, leaf_bp);
		if (error) {
			scxfs_trans_brelse(args->trans, leaf_bp);
			return error;
		}
	}

	if (scxfs_bmap_one_block(dp, SCXFS_ATTR_FORK))
		error = scxfs_attr_leaf_addname(args);
	else
		error = scxfs_attr_node_addname(args);
	return error;
}

/*
 * Remove the attribute specified in @args.
 */
int
scxfs_attr_remove_args(
	struct scxfs_da_args      *args)
{
	struct scxfs_inode	*dp = args->dp;
	int			error;

	if (!scxfs_inode_hasattr(dp)) {
		error = -ENOATTR;
	} else if (dp->i_d.di_aformat == SCXFS_DINODE_FMT_LOCAL) {
		ASSERT(dp->i_afp->if_flags & SCXFS_IFINLINE);
		error = scxfs_attr_shortform_remove(args);
	} else if (scxfs_bmap_one_block(dp, SCXFS_ATTR_FORK)) {
		error = scxfs_attr_leaf_removename(args);
	} else {
		error = scxfs_attr_node_removename(args);
	}

	return error;
}

int
scxfs_attr_set(
	struct scxfs_inode	*dp,
	const unsigned char	*name,
	unsigned char		*value,
	int			valuelen,
	int			flags)
{
	struct scxfs_mount	*mp = dp->i_mount;
	struct scxfs_da_args	args;
	struct scxfs_trans_res	tres;
	int			rsvd = (flags & ATTR_ROOT) != 0;
	int			error, local;

	SCXFS_STATS_INC(mp, xs_attr_set);

	if (SCXFS_FORCED_SHUTDOWN(dp->i_mount))
		return -EIO;

	error = scxfs_attr_args_init(&args, dp, name, flags);
	if (error)
		return error;

	args.value = value;
	args.valuelen = valuelen;
	args.op_flags = SCXFS_DA_OP_ADDNAME | SCXFS_DA_OP_OKNOENT;
	args.total = scxfs_attr_calc_size(&args, &local);

	error = scxfs_qm_dqattach(dp);
	if (error)
		return error;

	/*
	 * If the inode doesn't have an attribute fork, add one.
	 * (inode must not be locked when we call this routine)
	 */
	if (SCXFS_IFORK_Q(dp) == 0) {
		int sf_size = sizeof(scxfs_attr_sf_hdr_t) +
			SCXFS_ATTR_SF_ENTSIZE_BYNAME(args.namelen, valuelen);

		error = scxfs_bmap_add_attrfork(dp, sf_size, rsvd);
		if (error)
			return error;
	}

	tres.tr_logres = M_RES(mp)->tr_attrsetm.tr_logres +
			 M_RES(mp)->tr_attrsetrt.tr_logres * args.total;
	tres.tr_logcount = SCXFS_ATTRSET_LOG_COUNT;
	tres.tr_logflags = SCXFS_TRANS_PERM_LOG_RES;

	/*
	 * Root fork attributes can use reserved data blocks for this
	 * operation if necessary
	 */
	error = scxfs_trans_alloc(mp, &tres, args.total, 0,
			rsvd ? SCXFS_TRANS_RESERVE : 0, &args.trans);
	if (error)
		return error;

	scxfs_ilock(dp, SCXFS_ILOCK_EXCL);
	error = scxfs_trans_reserve_quota_nblks(args.trans, dp, args.total, 0,
				rsvd ? SCXFS_QMOPT_RES_REGBLKS | SCXFS_QMOPT_FORCE_RES :
				       SCXFS_QMOPT_RES_REGBLKS);
	if (error)
		goto out_trans_cancel;

	scxfs_trans_ijoin(args.trans, dp, 0);
	error = scxfs_attr_set_args(&args);
	if (error)
		goto out_trans_cancel;
	if (!args.trans) {
		/* shortform attribute has already been committed */
		goto out_unlock;
	}

	/*
	 * If this is a synchronous mount, make sure that the
	 * transaction goes to disk before returning to the user.
	 */
	if (mp->m_flags & SCXFS_MOUNT_WSYNC)
		scxfs_trans_set_sync(args.trans);

	if ((flags & ATTR_KERNOTIME) == 0)
		scxfs_trans_ichgtime(args.trans, dp, SCXFS_ICHGTIME_CHG);

	/*
	 * Commit the last in the sequence of transactions.
	 */
	scxfs_trans_log_inode(args.trans, dp, SCXFS_ILOG_CORE);
	error = scxfs_trans_commit(args.trans);
out_unlock:
	scxfs_iunlock(dp, SCXFS_ILOCK_EXCL);
	return error;

out_trans_cancel:
	if (args.trans)
		scxfs_trans_cancel(args.trans);
	goto out_unlock;
}

/*
 * Generic handler routine to remove a name from an attribute list.
 * Transitions attribute list from Btree to shortform as necessary.
 */
int
scxfs_attr_remove(
	struct scxfs_inode	*dp,
	const unsigned char	*name,
	int			flags)
{
	struct scxfs_mount	*mp = dp->i_mount;
	struct scxfs_da_args	args;
	int			error;

	SCXFS_STATS_INC(mp, xs_attr_remove);

	if (SCXFS_FORCED_SHUTDOWN(dp->i_mount))
		return -EIO;

	error = scxfs_attr_args_init(&args, dp, name, flags);
	if (error)
		return error;

	/*
	 * we have no control over the attribute names that userspace passes us
	 * to remove, so we have to allow the name lookup prior to attribute
	 * removal to fail.
	 */
	args.op_flags = SCXFS_DA_OP_OKNOENT;

	error = scxfs_qm_dqattach(dp);
	if (error)
		return error;

	/*
	 * Root fork attributes can use reserved data blocks for this
	 * operation if necessary
	 */
	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_attrrm,
			SCXFS_ATTRRM_SPACE_RES(mp), 0,
			(flags & ATTR_ROOT) ? SCXFS_TRANS_RESERVE : 0,
			&args.trans);
	if (error)
		return error;

	scxfs_ilock(dp, SCXFS_ILOCK_EXCL);
	/*
	 * No need to make quota reservations here. We expect to release some
	 * blocks not allocate in the common case.
	 */
	scxfs_trans_ijoin(args.trans, dp, 0);

	error = scxfs_attr_remove_args(&args);
	if (error)
		goto out;

	/*
	 * If this is a synchronous mount, make sure that the
	 * transaction goes to disk before returning to the user.
	 */
	if (mp->m_flags & SCXFS_MOUNT_WSYNC)
		scxfs_trans_set_sync(args.trans);

	if ((flags & ATTR_KERNOTIME) == 0)
		scxfs_trans_ichgtime(args.trans, dp, SCXFS_ICHGTIME_CHG);

	/*
	 * Commit the last in the sequence of transactions.
	 */
	scxfs_trans_log_inode(args.trans, dp, SCXFS_ILOG_CORE);
	error = scxfs_trans_commit(args.trans);
	scxfs_iunlock(dp, SCXFS_ILOCK_EXCL);

	return error;

out:
	if (args.trans)
		scxfs_trans_cancel(args.trans);
	scxfs_iunlock(dp, SCXFS_ILOCK_EXCL);
	return error;
}

/*========================================================================
 * External routines when attribute list is inside the inode
 *========================================================================*/

/*
 * Add a name to the shortform attribute list structure
 * This is the external routine.
 */
STATIC int
scxfs_attr_shortform_addname(scxfs_da_args_t *args)
{
	int newsize, forkoff, retval;

	trace_scxfs_attr_sf_addname(args);

	retval = scxfs_attr_shortform_lookup(args);
	if ((args->flags & ATTR_REPLACE) && (retval == -ENOATTR)) {
		return retval;
	} else if (retval == -EEXIST) {
		if (args->flags & ATTR_CREATE)
			return retval;
		retval = scxfs_attr_shortform_remove(args);
		if (retval)
			return retval;
		/*
		 * Since we have removed the old attr, clear ATTR_REPLACE so
		 * that the leaf format add routine won't trip over the attr
		 * not being around.
		 */
		args->flags &= ~ATTR_REPLACE;
	}

	if (args->namelen >= SCXFS_ATTR_SF_ENTSIZE_MAX ||
	    args->valuelen >= SCXFS_ATTR_SF_ENTSIZE_MAX)
		return -ENOSPC;

	newsize = SCXFS_ATTR_SF_TOTSIZE(args->dp);
	newsize += SCXFS_ATTR_SF_ENTSIZE_BYNAME(args->namelen, args->valuelen);

	forkoff = scxfs_attr_shortform_bytesfit(args->dp, newsize);
	if (!forkoff)
		return -ENOSPC;

	scxfs_attr_shortform_add(args, forkoff);
	return 0;
}


/*========================================================================
 * External routines when attribute list is one block
 *========================================================================*/

/*
 * Add a name to the leaf attribute list structure
 *
 * This leaf block cannot have a "remote" value, we only call this routine
 * if bmap_one_block() says there is only one block (ie: no remote blks).
 */
STATIC int
scxfs_attr_leaf_addname(
	struct scxfs_da_args	*args)
{
	struct scxfs_inode	*dp;
	struct scxfs_buf		*bp;
	int			retval, error, forkoff;

	trace_scxfs_attr_leaf_addname(args);

	/*
	 * Read the (only) block in the attribute list in.
	 */
	dp = args->dp;
	args->blkno = 0;
	error = scxfs_attr3_leaf_read(args->trans, args->dp, args->blkno, -1, &bp);
	if (error)
		return error;

	/*
	 * Look up the given attribute in the leaf block.  Figure out if
	 * the given flags produce an error or call for an atomic rename.
	 */
	retval = scxfs_attr3_leaf_lookup_int(bp, args);
	if ((args->flags & ATTR_REPLACE) && (retval == -ENOATTR)) {
		scxfs_trans_brelse(args->trans, bp);
		return retval;
	} else if (retval == -EEXIST) {
		if (args->flags & ATTR_CREATE) {	/* pure create op */
			scxfs_trans_brelse(args->trans, bp);
			return retval;
		}

		trace_scxfs_attr_leaf_replace(args);

		/* save the attribute state for later removal*/
		args->op_flags |= SCXFS_DA_OP_RENAME;	/* an atomic rename */
		args->blkno2 = args->blkno;		/* set 2nd entry info*/
		args->index2 = args->index;
		args->rmtblkno2 = args->rmtblkno;
		args->rmtblkcnt2 = args->rmtblkcnt;
		args->rmtvaluelen2 = args->rmtvaluelen;

		/*
		 * clear the remote attr state now that it is saved so that the
		 * values reflect the state of the attribute we are about to
		 * add, not the attribute we just found and will remove later.
		 */
		args->rmtblkno = 0;
		args->rmtblkcnt = 0;
		args->rmtvaluelen = 0;
	}

	/*
	 * Add the attribute to the leaf block, transitioning to a Btree
	 * if required.
	 */
	retval = scxfs_attr3_leaf_add(bp, args);
	if (retval == -ENOSPC) {
		/*
		 * Promote the attribute list to the Btree format, then
		 * Commit that transaction so that the node_addname() call
		 * can manage its own transactions.
		 */
		error = scxfs_attr3_leaf_to_node(args);
		if (error)
			return error;
		error = scxfs_defer_finish(&args->trans);
		if (error)
			return error;

		/*
		 * Commit the current trans (including the inode) and start
		 * a new one.
		 */
		error = scxfs_trans_roll_inode(&args->trans, dp);
		if (error)
			return error;

		/*
		 * Fob the whole rest of the problem off on the Btree code.
		 */
		error = scxfs_attr_node_addname(args);
		return error;
	}

	/*
	 * Commit the transaction that added the attr name so that
	 * later routines can manage their own transactions.
	 */
	error = scxfs_trans_roll_inode(&args->trans, dp);
	if (error)
		return error;

	/*
	 * If there was an out-of-line value, allocate the blocks we
	 * identified for its storage and copy the value.  This is done
	 * after we create the attribute so that we don't overflow the
	 * maximum size of a transaction and/or hit a deadlock.
	 */
	if (args->rmtblkno > 0) {
		error = scxfs_attr_rmtval_set(args);
		if (error)
			return error;
	}

	/*
	 * If this is an atomic rename operation, we must "flip" the
	 * incomplete flags on the "new" and "old" attribute/value pairs
	 * so that one disappears and one appears atomically.  Then we
	 * must remove the "old" attribute/value pair.
	 */
	if (args->op_flags & SCXFS_DA_OP_RENAME) {
		/*
		 * In a separate transaction, set the incomplete flag on the
		 * "old" attr and clear the incomplete flag on the "new" attr.
		 */
		error = scxfs_attr3_leaf_flipflags(args);
		if (error)
			return error;

		/*
		 * Dismantle the "old" attribute/value pair by removing
		 * a "remote" value (if it exists).
		 */
		args->index = args->index2;
		args->blkno = args->blkno2;
		args->rmtblkno = args->rmtblkno2;
		args->rmtblkcnt = args->rmtblkcnt2;
		args->rmtvaluelen = args->rmtvaluelen2;
		if (args->rmtblkno) {
			error = scxfs_attr_rmtval_remove(args);
			if (error)
				return error;
		}

		/*
		 * Read in the block containing the "old" attr, then
		 * remove the "old" attr from that block (neat, huh!)
		 */
		error = scxfs_attr3_leaf_read(args->trans, args->dp, args->blkno,
					   -1, &bp);
		if (error)
			return error;

		scxfs_attr3_leaf_remove(bp, args);

		/*
		 * If the result is small enough, shrink it all into the inode.
		 */
		if ((forkoff = scxfs_attr_shortform_allfit(bp, dp))) {
			error = scxfs_attr3_leaf_to_shortform(bp, args, forkoff);
			/* bp is gone due to scxfs_da_shrink_inode */
			if (error)
				return error;
			error = scxfs_defer_finish(&args->trans);
			if (error)
				return error;
		}

		/*
		 * Commit the remove and start the next trans in series.
		 */
		error = scxfs_trans_roll_inode(&args->trans, dp);

	} else if (args->rmtblkno > 0) {
		/*
		 * Added a "remote" value, just clear the incomplete flag.
		 */
		error = scxfs_attr3_leaf_clearflag(args);
	}
	return error;
}

/*
 * Remove a name from the leaf attribute list structure
 *
 * This leaf block cannot have a "remote" value, we only call this routine
 * if bmap_one_block() says there is only one block (ie: no remote blks).
 */
STATIC int
scxfs_attr_leaf_removename(
	struct scxfs_da_args	*args)
{
	struct scxfs_inode	*dp;
	struct scxfs_buf		*bp;
	int			error, forkoff;

	trace_scxfs_attr_leaf_removename(args);

	/*
	 * Remove the attribute.
	 */
	dp = args->dp;
	args->blkno = 0;
	error = scxfs_attr3_leaf_read(args->trans, args->dp, args->blkno, -1, &bp);
	if (error)
		return error;

	error = scxfs_attr3_leaf_lookup_int(bp, args);
	if (error == -ENOATTR) {
		scxfs_trans_brelse(args->trans, bp);
		return error;
	}

	scxfs_attr3_leaf_remove(bp, args);

	/*
	 * If the result is small enough, shrink it all into the inode.
	 */
	if ((forkoff = scxfs_attr_shortform_allfit(bp, dp))) {
		error = scxfs_attr3_leaf_to_shortform(bp, args, forkoff);
		/* bp is gone due to scxfs_da_shrink_inode */
		if (error)
			return error;
		error = scxfs_defer_finish(&args->trans);
		if (error)
			return error;
	}
	return 0;
}

/*
 * Look up a name in a leaf attribute list structure.
 *
 * This leaf block cannot have a "remote" value, we only call this routine
 * if bmap_one_block() says there is only one block (ie: no remote blks).
 *
 * Returns 0 on successful retrieval, otherwise an error.
 */
STATIC int
scxfs_attr_leaf_get(scxfs_da_args_t *args)
{
	struct scxfs_buf *bp;
	int error;

	trace_scxfs_attr_leaf_get(args);

	args->blkno = 0;
	error = scxfs_attr3_leaf_read(args->trans, args->dp, args->blkno, -1, &bp);
	if (error)
		return error;

	error = scxfs_attr3_leaf_lookup_int(bp, args);
	if (error != -EEXIST)  {
		scxfs_trans_brelse(args->trans, bp);
		return error;
	}
	error = scxfs_attr3_leaf_getvalue(bp, args);
	scxfs_trans_brelse(args->trans, bp);
	return error;
}

/*========================================================================
 * External routines when attribute list size > geo->blksize
 *========================================================================*/

/*
 * Add a name to a Btree-format attribute list.
 *
 * This will involve walking down the Btree, and may involve splitting
 * leaf nodes and even splitting intermediate nodes up to and including
 * the root node (a special case of an intermediate node).
 *
 * "Remote" attribute values confuse the issue and atomic rename operations
 * add a whole extra layer of confusion on top of that.
 */
STATIC int
scxfs_attr_node_addname(
	struct scxfs_da_args	*args)
{
	struct scxfs_da_state	*state;
	struct scxfs_da_state_blk	*blk;
	struct scxfs_inode	*dp;
	struct scxfs_mount	*mp;
	int			retval, error;

	trace_scxfs_attr_node_addname(args);

	/*
	 * Fill in bucket of arguments/results/context to carry around.
	 */
	dp = args->dp;
	mp = dp->i_mount;
restart:
	state = scxfs_da_state_alloc();
	state->args = args;
	state->mp = mp;

	/*
	 * Search to see if name already exists, and get back a pointer
	 * to where it should go.
	 */
	error = scxfs_da3_node_lookup_int(state, &retval);
	if (error)
		goto out;
	blk = &state->path.blk[ state->path.active-1 ];
	ASSERT(blk->magic == SCXFS_ATTR_LEAF_MAGIC);
	if ((args->flags & ATTR_REPLACE) && (retval == -ENOATTR)) {
		goto out;
	} else if (retval == -EEXIST) {
		if (args->flags & ATTR_CREATE)
			goto out;

		trace_scxfs_attr_node_replace(args);

		/* save the attribute state for later removal*/
		args->op_flags |= SCXFS_DA_OP_RENAME;	/* atomic rename op */
		args->blkno2 = args->blkno;		/* set 2nd entry info*/
		args->index2 = args->index;
		args->rmtblkno2 = args->rmtblkno;
		args->rmtblkcnt2 = args->rmtblkcnt;
		args->rmtvaluelen2 = args->rmtvaluelen;

		/*
		 * clear the remote attr state now that it is saved so that the
		 * values reflect the state of the attribute we are about to
		 * add, not the attribute we just found and will remove later.
		 */
		args->rmtblkno = 0;
		args->rmtblkcnt = 0;
		args->rmtvaluelen = 0;
	}

	retval = scxfs_attr3_leaf_add(blk->bp, state->args);
	if (retval == -ENOSPC) {
		if (state->path.active == 1) {
			/*
			 * Its really a single leaf node, but it had
			 * out-of-line values so it looked like it *might*
			 * have been a b-tree.
			 */
			scxfs_da_state_free(state);
			state = NULL;
			error = scxfs_attr3_leaf_to_node(args);
			if (error)
				goto out;
			error = scxfs_defer_finish(&args->trans);
			if (error)
				goto out;

			/*
			 * Commit the node conversion and start the next
			 * trans in the chain.
			 */
			error = scxfs_trans_roll_inode(&args->trans, dp);
			if (error)
				goto out;

			goto restart;
		}

		/*
		 * Split as many Btree elements as required.
		 * This code tracks the new and old attr's location
		 * in the index/blkno/rmtblkno/rmtblkcnt fields and
		 * in the index2/blkno2/rmtblkno2/rmtblkcnt2 fields.
		 */
		error = scxfs_da3_split(state);
		if (error)
			goto out;
		error = scxfs_defer_finish(&args->trans);
		if (error)
			goto out;
	} else {
		/*
		 * Addition succeeded, update Btree hashvals.
		 */
		scxfs_da3_fixhashpath(state, &state->path);
	}

	/*
	 * Kill the state structure, we're done with it and need to
	 * allow the buffers to come back later.
	 */
	scxfs_da_state_free(state);
	state = NULL;

	/*
	 * Commit the leaf addition or btree split and start the next
	 * trans in the chain.
	 */
	error = scxfs_trans_roll_inode(&args->trans, dp);
	if (error)
		goto out;

	/*
	 * If there was an out-of-line value, allocate the blocks we
	 * identified for its storage and copy the value.  This is done
	 * after we create the attribute so that we don't overflow the
	 * maximum size of a transaction and/or hit a deadlock.
	 */
	if (args->rmtblkno > 0) {
		error = scxfs_attr_rmtval_set(args);
		if (error)
			return error;
	}

	/*
	 * If this is an atomic rename operation, we must "flip" the
	 * incomplete flags on the "new" and "old" attribute/value pairs
	 * so that one disappears and one appears atomically.  Then we
	 * must remove the "old" attribute/value pair.
	 */
	if (args->op_flags & SCXFS_DA_OP_RENAME) {
		/*
		 * In a separate transaction, set the incomplete flag on the
		 * "old" attr and clear the incomplete flag on the "new" attr.
		 */
		error = scxfs_attr3_leaf_flipflags(args);
		if (error)
			goto out;

		/*
		 * Dismantle the "old" attribute/value pair by removing
		 * a "remote" value (if it exists).
		 */
		args->index = args->index2;
		args->blkno = args->blkno2;
		args->rmtblkno = args->rmtblkno2;
		args->rmtblkcnt = args->rmtblkcnt2;
		args->rmtvaluelen = args->rmtvaluelen2;
		if (args->rmtblkno) {
			error = scxfs_attr_rmtval_remove(args);
			if (error)
				return error;
		}

		/*
		 * Re-find the "old" attribute entry after any split ops.
		 * The INCOMPLETE flag means that we will find the "old"
		 * attr, not the "new" one.
		 */
		args->flags |= SCXFS_ATTR_INCOMPLETE;
		state = scxfs_da_state_alloc();
		state->args = args;
		state->mp = mp;
		state->inleaf = 0;
		error = scxfs_da3_node_lookup_int(state, &retval);
		if (error)
			goto out;

		/*
		 * Remove the name and update the hashvals in the tree.
		 */
		blk = &state->path.blk[ state->path.active-1 ];
		ASSERT(blk->magic == SCXFS_ATTR_LEAF_MAGIC);
		error = scxfs_attr3_leaf_remove(blk->bp, args);
		scxfs_da3_fixhashpath(state, &state->path);

		/*
		 * Check to see if the tree needs to be collapsed.
		 */
		if (retval && (state->path.active > 1)) {
			error = scxfs_da3_join(state);
			if (error)
				goto out;
			error = scxfs_defer_finish(&args->trans);
			if (error)
				goto out;
		}

		/*
		 * Commit and start the next trans in the chain.
		 */
		error = scxfs_trans_roll_inode(&args->trans, dp);
		if (error)
			goto out;

	} else if (args->rmtblkno > 0) {
		/*
		 * Added a "remote" value, just clear the incomplete flag.
		 */
		error = scxfs_attr3_leaf_clearflag(args);
		if (error)
			goto out;
	}
	retval = error = 0;

out:
	if (state)
		scxfs_da_state_free(state);
	if (error)
		return error;
	return retval;
}

/*
 * Remove a name from a B-tree attribute list.
 *
 * This will involve walking down the Btree, and may involve joining
 * leaf nodes and even joining intermediate nodes up to and including
 * the root node (a special case of an intermediate node).
 */
STATIC int
scxfs_attr_node_removename(
	struct scxfs_da_args	*args)
{
	struct scxfs_da_state	*state;
	struct scxfs_da_state_blk	*blk;
	struct scxfs_inode	*dp;
	struct scxfs_buf		*bp;
	int			retval, error, forkoff;

	trace_scxfs_attr_node_removename(args);

	/*
	 * Tie a string around our finger to remind us where we are.
	 */
	dp = args->dp;
	state = scxfs_da_state_alloc();
	state->args = args;
	state->mp = dp->i_mount;

	/*
	 * Search to see if name exists, and get back a pointer to it.
	 */
	error = scxfs_da3_node_lookup_int(state, &retval);
	if (error || (retval != -EEXIST)) {
		if (error == 0)
			error = retval;
		goto out;
	}

	/*
	 * If there is an out-of-line value, de-allocate the blocks.
	 * This is done before we remove the attribute so that we don't
	 * overflow the maximum size of a transaction and/or hit a deadlock.
	 */
	blk = &state->path.blk[ state->path.active-1 ];
	ASSERT(blk->bp != NULL);
	ASSERT(blk->magic == SCXFS_ATTR_LEAF_MAGIC);
	if (args->rmtblkno > 0) {
		/*
		 * Fill in disk block numbers in the state structure
		 * so that we can get the buffers back after we commit
		 * several transactions in the following calls.
		 */
		error = scxfs_attr_fillstate(state);
		if (error)
			goto out;

		/*
		 * Mark the attribute as INCOMPLETE, then bunmapi() the
		 * remote value.
		 */
		error = scxfs_attr3_leaf_setflag(args);
		if (error)
			goto out;
		error = scxfs_attr_rmtval_remove(args);
		if (error)
			goto out;

		/*
		 * Refill the state structure with buffers, the prior calls
		 * released our buffers.
		 */
		error = scxfs_attr_refillstate(state);
		if (error)
			goto out;
	}

	/*
	 * Remove the name and update the hashvals in the tree.
	 */
	blk = &state->path.blk[ state->path.active-1 ];
	ASSERT(blk->magic == SCXFS_ATTR_LEAF_MAGIC);
	retval = scxfs_attr3_leaf_remove(blk->bp, args);
	scxfs_da3_fixhashpath(state, &state->path);

	/*
	 * Check to see if the tree needs to be collapsed.
	 */
	if (retval && (state->path.active > 1)) {
		error = scxfs_da3_join(state);
		if (error)
			goto out;
		error = scxfs_defer_finish(&args->trans);
		if (error)
			goto out;
		/*
		 * Commit the Btree join operation and start a new trans.
		 */
		error = scxfs_trans_roll_inode(&args->trans, dp);
		if (error)
			goto out;
	}

	/*
	 * If the result is small enough, push it all into the inode.
	 */
	if (scxfs_bmap_one_block(dp, SCXFS_ATTR_FORK)) {
		/*
		 * Have to get rid of the copy of this dabuf in the state.
		 */
		ASSERT(state->path.active == 1);
		ASSERT(state->path.blk[0].bp);
		state->path.blk[0].bp = NULL;

		error = scxfs_attr3_leaf_read(args->trans, args->dp, 0, -1, &bp);
		if (error)
			goto out;

		if ((forkoff = scxfs_attr_shortform_allfit(bp, dp))) {
			error = scxfs_attr3_leaf_to_shortform(bp, args, forkoff);
			/* bp is gone due to scxfs_da_shrink_inode */
			if (error)
				goto out;
			error = scxfs_defer_finish(&args->trans);
			if (error)
				goto out;
		} else
			scxfs_trans_brelse(args->trans, bp);
	}
	error = 0;

out:
	scxfs_da_state_free(state);
	return error;
}

/*
 * Fill in the disk block numbers in the state structure for the buffers
 * that are attached to the state structure.
 * This is done so that we can quickly reattach ourselves to those buffers
 * after some set of transaction commits have released these buffers.
 */
STATIC int
scxfs_attr_fillstate(scxfs_da_state_t *state)
{
	scxfs_da_state_path_t *path;
	scxfs_da_state_blk_t *blk;
	int level;

	trace_scxfs_attr_fillstate(state->args);

	/*
	 * Roll down the "path" in the state structure, storing the on-disk
	 * block number for those buffers in the "path".
	 */
	path = &state->path;
	ASSERT((path->active >= 0) && (path->active < SCXFS_DA_NODE_MAXDEPTH));
	for (blk = path->blk, level = 0; level < path->active; blk++, level++) {
		if (blk->bp) {
			blk->disk_blkno = SCXFS_BUF_ADDR(blk->bp);
			blk->bp = NULL;
		} else {
			blk->disk_blkno = 0;
		}
	}

	/*
	 * Roll down the "altpath" in the state structure, storing the on-disk
	 * block number for those buffers in the "altpath".
	 */
	path = &state->altpath;
	ASSERT((path->active >= 0) && (path->active < SCXFS_DA_NODE_MAXDEPTH));
	for (blk = path->blk, level = 0; level < path->active; blk++, level++) {
		if (blk->bp) {
			blk->disk_blkno = SCXFS_BUF_ADDR(blk->bp);
			blk->bp = NULL;
		} else {
			blk->disk_blkno = 0;
		}
	}

	return 0;
}

/*
 * Reattach the buffers to the state structure based on the disk block
 * numbers stored in the state structure.
 * This is done after some set of transaction commits have released those
 * buffers from our grip.
 */
STATIC int
scxfs_attr_refillstate(scxfs_da_state_t *state)
{
	scxfs_da_state_path_t *path;
	scxfs_da_state_blk_t *blk;
	int level, error;

	trace_scxfs_attr_refillstate(state->args);

	/*
	 * Roll down the "path" in the state structure, storing the on-disk
	 * block number for those buffers in the "path".
	 */
	path = &state->path;
	ASSERT((path->active >= 0) && (path->active < SCXFS_DA_NODE_MAXDEPTH));
	for (blk = path->blk, level = 0; level < path->active; blk++, level++) {
		if (blk->disk_blkno) {
			error = scxfs_da3_node_read(state->args->trans,
						state->args->dp,
						blk->blkno, blk->disk_blkno,
						&blk->bp, SCXFS_ATTR_FORK);
			if (error)
				return error;
		} else {
			blk->bp = NULL;
		}
	}

	/*
	 * Roll down the "altpath" in the state structure, storing the on-disk
	 * block number for those buffers in the "altpath".
	 */
	path = &state->altpath;
	ASSERT((path->active >= 0) && (path->active < SCXFS_DA_NODE_MAXDEPTH));
	for (blk = path->blk, level = 0; level < path->active; blk++, level++) {
		if (blk->disk_blkno) {
			error = scxfs_da3_node_read(state->args->trans,
						state->args->dp,
						blk->blkno, blk->disk_blkno,
						&blk->bp, SCXFS_ATTR_FORK);
			if (error)
				return error;
		} else {
			blk->bp = NULL;
		}
	}

	return 0;
}

/*
 * Retrieve the attribute data from a node attribute list.
 *
 * This routine gets called for any attribute fork that has more than one
 * block, ie: both true Btree attr lists and for single-leaf-blocks with
 * "remote" values taking up more blocks.
 *
 * Returns 0 on successful retrieval, otherwise an error.
 */
STATIC int
scxfs_attr_node_get(scxfs_da_args_t *args)
{
	scxfs_da_state_t *state;
	scxfs_da_state_blk_t *blk;
	int error, retval;
	int i;

	trace_scxfs_attr_node_get(args);

	state = scxfs_da_state_alloc();
	state->args = args;
	state->mp = args->dp->i_mount;

	/*
	 * Search to see if name exists, and get back a pointer to it.
	 */
	error = scxfs_da3_node_lookup_int(state, &retval);
	if (error) {
		retval = error;
		goto out_release;
	}
	if (retval != -EEXIST)
		goto out_release;

	/*
	 * Get the value, local or "remote"
	 */
	blk = &state->path.blk[state->path.active - 1];
	retval = scxfs_attr3_leaf_getvalue(blk->bp, args);

	/*
	 * If not in a transaction, we have to release all the buffers.
	 */
out_release:
	for (i = 0; i < state->path.active; i++) {
		scxfs_trans_brelse(args->trans, state->path.blk[i].bp);
		state->path.blk[i].bp = NULL;
	}

	scxfs_da_state_free(state);
	return retval;
}

/* Returns true if the attribute entry name is valid. */
bool
scxfs_attr_namecheck(
	const void	*name,
	size_t		length)
{
	/*
	 * MAXNAMELEN includes the trailing null, but (name/length) leave it
	 * out, so use >= for the length check.
	 */
	if (length >= MAXNAMELEN)
		return false;

	/* There shouldn't be any nulls here */
	return !memchr(name, 0, length);
}
