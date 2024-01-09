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
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_inode_item.h"
#include "scxfs_btree.h"
#include "scxfs_bmap_btree.h"
#include "scxfs_bmap.h"
#include "scxfs_error.h"
#include "scxfs_trace.h"
#include "scxfs_da_format.h"
#include "scxfs_da_btree.h"
#include "scxfs_dir2_priv.h"
#include "scxfs_attr_leaf.h"

kmem_zone_t *scxfs_ifork_zone;

STATIC int scxfs_iformat_local(scxfs_inode_t *, scxfs_dinode_t *, int, int);
STATIC int scxfs_iformat_extents(scxfs_inode_t *, scxfs_dinode_t *, int);
STATIC int scxfs_iformat_btree(scxfs_inode_t *, scxfs_dinode_t *, int);

/*
 * Copy inode type and data and attr format specific information from the
 * on-disk inode to the in-core inode and fork structures.  For fifos, devices,
 * and sockets this means set i_rdev to the proper value.  For files,
 * directories, and symlinks this means to bring in the in-line data or extent
 * pointers as well as the attribute fork.  For a fork in B-tree format, only
 * the root is immediately brought in-core.  The rest will be read in later when
 * first referenced (see scxfs_iread_extents()).
 */
int
scxfs_iformat_fork(
	struct scxfs_inode	*ip,
	struct scxfs_dinode	*dip)
{
	struct inode		*inode = VFS_I(ip);
	struct scxfs_attr_shortform *atp;
	int			size;
	int			error = 0;
	scxfs_fsize_t             di_size;

	switch (inode->i_mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		ip->i_d.di_size = 0;
		inode->i_rdev = scxfs_to_linux_dev_t(scxfs_dinode_get_rdev(dip));
		break;

	case S_IFREG:
	case S_IFLNK:
	case S_IFDIR:
		switch (dip->di_format) {
		case SCXFS_DINODE_FMT_LOCAL:
			di_size = be64_to_cpu(dip->di_size);
			size = (int)di_size;
			error = scxfs_iformat_local(ip, dip, SCXFS_DATA_FORK, size);
			break;
		case SCXFS_DINODE_FMT_EXTENTS:
			error = scxfs_iformat_extents(ip, dip, SCXFS_DATA_FORK);
			break;
		case SCXFS_DINODE_FMT_BTREE:
			error = scxfs_iformat_btree(ip, dip, SCXFS_DATA_FORK);
			break;
		default:
			return -EFSCORRUPTED;
		}
		break;

	default:
		return -EFSCORRUPTED;
	}
	if (error)
		return error;

	if (scxfs_is_reflink_inode(ip)) {
		ASSERT(ip->i_cowfp == NULL);
		scxfs_ifork_init_cow(ip);
	}

	if (!SCXFS_DFORK_Q(dip))
		return 0;

	ASSERT(ip->i_afp == NULL);
	ip->i_afp = kmem_zone_zalloc(scxfs_ifork_zone, KM_NOFS);

	switch (dip->di_aformat) {
	case SCXFS_DINODE_FMT_LOCAL:
		atp = (scxfs_attr_shortform_t *)SCXFS_DFORK_APTR(dip);
		size = be16_to_cpu(atp->hdr.totsize);

		error = scxfs_iformat_local(ip, dip, SCXFS_ATTR_FORK, size);
		break;
	case SCXFS_DINODE_FMT_EXTENTS:
		error = scxfs_iformat_extents(ip, dip, SCXFS_ATTR_FORK);
		break;
	case SCXFS_DINODE_FMT_BTREE:
		error = scxfs_iformat_btree(ip, dip, SCXFS_ATTR_FORK);
		break;
	default:
		error = -EFSCORRUPTED;
		break;
	}
	if (error) {
		kmem_zone_free(scxfs_ifork_zone, ip->i_afp);
		ip->i_afp = NULL;
		if (ip->i_cowfp)
			kmem_zone_free(scxfs_ifork_zone, ip->i_cowfp);
		ip->i_cowfp = NULL;
		scxfs_idestroy_fork(ip, SCXFS_DATA_FORK);
	}
	return error;
}

void
scxfs_init_local_fork(
	struct scxfs_inode	*ip,
	int			whichfork,
	const void		*data,
	int64_t			size)
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	int			mem_size = size, real_size = 0;
	bool			zero_terminate;

	/*
	 * If we are using the local fork to store a symlink body we need to
	 * zero-terminate it so that we can pass it back to the VFS directly.
	 * Overallocate the in-memory fork by one for that and add a zero
	 * to terminate it below.
	 */
	zero_terminate = S_ISLNK(VFS_I(ip)->i_mode);
	if (zero_terminate)
		mem_size++;

	if (size) {
		real_size = roundup(mem_size, 4);
		ifp->if_u1.if_data = kmem_alloc(real_size, KM_NOFS);
		memcpy(ifp->if_u1.if_data, data, size);
		if (zero_terminate)
			ifp->if_u1.if_data[size] = '\0';
	} else {
		ifp->if_u1.if_data = NULL;
	}

	ifp->if_bytes = size;
	ifp->if_flags &= ~(SCXFS_IFEXTENTS | SCXFS_IFBROOT);
	ifp->if_flags |= SCXFS_IFINLINE;
}

/*
 * The file is in-lined in the on-disk inode.
 */
STATIC int
scxfs_iformat_local(
	scxfs_inode_t	*ip,
	scxfs_dinode_t	*dip,
	int		whichfork,
	int		size)
{
	/*
	 * If the size is unreasonable, then something
	 * is wrong and we just bail out rather than crash in
	 * kmem_alloc() or memcpy() below.
	 */
	if (unlikely(size > SCXFS_DFORK_SIZE(dip, ip->i_mount, whichfork))) {
		scxfs_warn(ip->i_mount,
	"corrupt inode %Lu (bad size %d for local fork, size = %d).",
			(unsigned long long) ip->i_ino, size,
			SCXFS_DFORK_SIZE(dip, ip->i_mount, whichfork));
		scxfs_inode_verifier_error(ip, -EFSCORRUPTED,
				"scxfs_iformat_local", dip, sizeof(*dip),
				__this_address);
		return -EFSCORRUPTED;
	}

	scxfs_init_local_fork(ip, whichfork, SCXFS_DFORK_PTR(dip, whichfork), size);
	return 0;
}

/*
 * The file consists of a set of extents all of which fit into the on-disk
 * inode.
 */
STATIC int
scxfs_iformat_extents(
	struct scxfs_inode	*ip,
	struct scxfs_dinode	*dip,
	int			whichfork)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	int			state = scxfs_bmap_fork_to_state(whichfork);
	int			nex = SCXFS_DFORK_NEXTENTS(dip, whichfork);
	int			size = nex * sizeof(scxfs_bmbt_rec_t);
	struct scxfs_iext_cursor	icur;
	struct scxfs_bmbt_rec	*dp;
	struct scxfs_bmbt_irec	new;
	int			i;

	/*
	 * If the number of extents is unreasonable, then something is wrong and
	 * we just bail out rather than crash in kmem_alloc() or memcpy() below.
	 */
	if (unlikely(size < 0 || size > SCXFS_DFORK_SIZE(dip, mp, whichfork))) {
		scxfs_warn(ip->i_mount, "corrupt inode %Lu ((a)extents = %d).",
			(unsigned long long) ip->i_ino, nex);
		scxfs_inode_verifier_error(ip, -EFSCORRUPTED,
				"scxfs_iformat_extents(1)", dip, sizeof(*dip),
				__this_address);
		return -EFSCORRUPTED;
	}

	ifp->if_bytes = 0;
	ifp->if_u1.if_root = NULL;
	ifp->if_height = 0;
	if (size) {
		dp = (scxfs_bmbt_rec_t *) SCXFS_DFORK_PTR(dip, whichfork);

		scxfs_iext_first(ifp, &icur);
		for (i = 0; i < nex; i++, dp++) {
			scxfs_failaddr_t	fa;

			scxfs_bmbt_disk_get_all(dp, &new);
			fa = scxfs_bmap_validate_extent(ip, whichfork, &new);
			if (fa) {
				scxfs_inode_verifier_error(ip, -EFSCORRUPTED,
						"scxfs_iformat_extents(2)",
						dp, sizeof(*dp), fa);
				return -EFSCORRUPTED;
			}

			scxfs_iext_insert(ip, &icur, &new, state);
			trace_scxfs_read_extent(ip, &icur, state, _THIS_IP_);
			scxfs_iext_next(ifp, &icur);
		}
	}
	ifp->if_flags |= SCXFS_IFEXTENTS;
	return 0;
}

/*
 * The file has too many extents to fit into
 * the inode, so they are in B-tree format.
 * Allocate a buffer for the root of the B-tree
 * and copy the root into it.  The i_extents
 * field will remain NULL until all of the
 * extents are read in (when they are needed).
 */
STATIC int
scxfs_iformat_btree(
	scxfs_inode_t		*ip,
	scxfs_dinode_t		*dip,
	int			whichfork)
{
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_bmdr_block_t	*dfp;
	struct scxfs_ifork	*ifp;
	/* REFERENCED */
	int			nrecs;
	int			size;
	int			level;

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	dfp = (scxfs_bmdr_block_t *)SCXFS_DFORK_PTR(dip, whichfork);
	size = SCXFS_BMAP_BROOT_SPACE(mp, dfp);
	nrecs = be16_to_cpu(dfp->bb_numrecs);
	level = be16_to_cpu(dfp->bb_level);

	/*
	 * blow out if -- fork has less extents than can fit in
	 * fork (fork shouldn't be a btree format), root btree
	 * block has more records than can fit into the fork,
	 * or the number of extents is greater than the number of
	 * blocks.
	 */
	if (unlikely(SCXFS_IFORK_NEXTENTS(ip, whichfork) <=
					SCXFS_IFORK_MAXEXT(ip, whichfork) ||
		     nrecs == 0 ||
		     SCXFS_BMDR_SPACE_CALC(nrecs) >
					SCXFS_DFORK_SIZE(dip, mp, whichfork) ||
		     SCXFS_IFORK_NEXTENTS(ip, whichfork) > ip->i_d.di_nblocks) ||
		     level == 0 || level > SCXFS_BTREE_MAXLEVELS) {
		scxfs_warn(mp, "corrupt inode %Lu (btree).",
					(unsigned long long) ip->i_ino);
		scxfs_inode_verifier_error(ip, -EFSCORRUPTED,
				"scxfs_iformat_btree", dfp, size,
				__this_address);
		return -EFSCORRUPTED;
	}

	ifp->if_broot_bytes = size;
	ifp->if_broot = kmem_alloc(size, KM_NOFS);
	ASSERT(ifp->if_broot != NULL);
	/*
	 * Copy and convert from the on-disk structure
	 * to the in-memory structure.
	 */
	scxfs_bmdr_to_bmbt(ip, dfp, SCXFS_DFORK_SIZE(dip, ip->i_mount, whichfork),
			 ifp->if_broot, size);
	ifp->if_flags &= ~SCXFS_IFEXTENTS;
	ifp->if_flags |= SCXFS_IFBROOT;

	ifp->if_bytes = 0;
	ifp->if_u1.if_root = NULL;
	ifp->if_height = 0;
	return 0;
}

/*
 * Reallocate the space for if_broot based on the number of records
 * being added or deleted as indicated in rec_diff.  Move the records
 * and pointers in if_broot to fit the new size.  When shrinking this
 * will eliminate holes between the records and pointers created by
 * the caller.  When growing this will create holes to be filled in
 * by the caller.
 *
 * The caller must not request to add more records than would fit in
 * the on-disk inode root.  If the if_broot is currently NULL, then
 * if we are adding records, one will be allocated.  The caller must also
 * not request that the number of records go below zero, although
 * it can go to zero.
 *
 * ip -- the inode whose if_broot area is changing
 * ext_diff -- the change in the number of records, positive or negative,
 *	 requested for the if_broot array.
 */
void
scxfs_iroot_realloc(
	scxfs_inode_t		*ip,
	int			rec_diff,
	int			whichfork)
{
	struct scxfs_mount	*mp = ip->i_mount;
	int			cur_max;
	struct scxfs_ifork	*ifp;
	struct scxfs_btree_block	*new_broot;
	int			new_max;
	size_t			new_size;
	char			*np;
	char			*op;

	/*
	 * Handle the degenerate case quietly.
	 */
	if (rec_diff == 0) {
		return;
	}

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	if (rec_diff > 0) {
		/*
		 * If there wasn't any memory allocated before, just
		 * allocate it now and get out.
		 */
		if (ifp->if_broot_bytes == 0) {
			new_size = SCXFS_BMAP_BROOT_SPACE_CALC(mp, rec_diff);
			ifp->if_broot = kmem_alloc(new_size, KM_NOFS);
			ifp->if_broot_bytes = (int)new_size;
			return;
		}

		/*
		 * If there is already an existing if_broot, then we need
		 * to realloc() it and shift the pointers to their new
		 * location.  The records don't change location because
		 * they are kept butted up against the btree block header.
		 */
		cur_max = scxfs_bmbt_maxrecs(mp, ifp->if_broot_bytes, 0);
		new_max = cur_max + rec_diff;
		new_size = SCXFS_BMAP_BROOT_SPACE_CALC(mp, new_max);
		ifp->if_broot = kmem_realloc(ifp->if_broot, new_size,
				KM_NOFS);
		op = (char *)SCXFS_BMAP_BROOT_PTR_ADDR(mp, ifp->if_broot, 1,
						     ifp->if_broot_bytes);
		np = (char *)SCXFS_BMAP_BROOT_PTR_ADDR(mp, ifp->if_broot, 1,
						     (int)new_size);
		ifp->if_broot_bytes = (int)new_size;
		ASSERT(SCXFS_BMAP_BMDR_SPACE(ifp->if_broot) <=
			SCXFS_IFORK_SIZE(ip, whichfork));
		memmove(np, op, cur_max * (uint)sizeof(scxfs_fsblock_t));
		return;
	}

	/*
	 * rec_diff is less than 0.  In this case, we are shrinking the
	 * if_broot buffer.  It must already exist.  If we go to zero
	 * records, just get rid of the root and clear the status bit.
	 */
	ASSERT((ifp->if_broot != NULL) && (ifp->if_broot_bytes > 0));
	cur_max = scxfs_bmbt_maxrecs(mp, ifp->if_broot_bytes, 0);
	new_max = cur_max + rec_diff;
	ASSERT(new_max >= 0);
	if (new_max > 0)
		new_size = SCXFS_BMAP_BROOT_SPACE_CALC(mp, new_max);
	else
		new_size = 0;
	if (new_size > 0) {
		new_broot = kmem_alloc(new_size, KM_NOFS);
		/*
		 * First copy over the btree block header.
		 */
		memcpy(new_broot, ifp->if_broot,
			SCXFS_BMBT_BLOCK_LEN(ip->i_mount));
	} else {
		new_broot = NULL;
		ifp->if_flags &= ~SCXFS_IFBROOT;
	}

	/*
	 * Only copy the records and pointers if there are any.
	 */
	if (new_max > 0) {
		/*
		 * First copy the records.
		 */
		op = (char *)SCXFS_BMBT_REC_ADDR(mp, ifp->if_broot, 1);
		np = (char *)SCXFS_BMBT_REC_ADDR(mp, new_broot, 1);
		memcpy(np, op, new_max * (uint)sizeof(scxfs_bmbt_rec_t));

		/*
		 * Then copy the pointers.
		 */
		op = (char *)SCXFS_BMAP_BROOT_PTR_ADDR(mp, ifp->if_broot, 1,
						     ifp->if_broot_bytes);
		np = (char *)SCXFS_BMAP_BROOT_PTR_ADDR(mp, new_broot, 1,
						     (int)new_size);
		memcpy(np, op, new_max * (uint)sizeof(scxfs_fsblock_t));
	}
	kmem_free(ifp->if_broot);
	ifp->if_broot = new_broot;
	ifp->if_broot_bytes = (int)new_size;
	if (ifp->if_broot)
		ASSERT(SCXFS_BMAP_BMDR_SPACE(ifp->if_broot) <=
			SCXFS_IFORK_SIZE(ip, whichfork));
	return;
}


/*
 * This is called when the amount of space needed for if_data
 * is increased or decreased.  The change in size is indicated by
 * the number of bytes that need to be added or deleted in the
 * byte_diff parameter.
 *
 * If the amount of space needed has decreased below the size of the
 * inline buffer, then switch to using the inline buffer.  Otherwise,
 * use kmem_realloc() or kmem_alloc() to adjust the size of the buffer
 * to what is needed.
 *
 * ip -- the inode whose if_data area is changing
 * byte_diff -- the change in the number of bytes, positive or negative,
 *	 requested for the if_data array.
 */
void
scxfs_idata_realloc(
	struct scxfs_inode	*ip,
	int64_t			byte_diff,
	int			whichfork)
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	int64_t			new_size = ifp->if_bytes + byte_diff;

	ASSERT(new_size >= 0);
	ASSERT(new_size <= SCXFS_IFORK_SIZE(ip, whichfork));

	if (byte_diff == 0)
		return;

	if (new_size == 0) {
		kmem_free(ifp->if_u1.if_data);
		ifp->if_u1.if_data = NULL;
		ifp->if_bytes = 0;
		return;
	}

	/*
	 * For inline data, the underlying buffer must be a multiple of 4 bytes
	 * in size so that it can be logged and stay on word boundaries.
	 * We enforce that here.
	 */
	ifp->if_u1.if_data = kmem_realloc(ifp->if_u1.if_data,
			roundup(new_size, 4), KM_NOFS);
	ifp->if_bytes = new_size;
}

void
scxfs_idestroy_fork(
	scxfs_inode_t	*ip,
	int		whichfork)
{
	struct scxfs_ifork	*ifp;

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	if (ifp->if_broot != NULL) {
		kmem_free(ifp->if_broot);
		ifp->if_broot = NULL;
	}

	/*
	 * If the format is local, then we can't have an extents
	 * array so just look for an inline data array.  If we're
	 * not local then we may or may not have an extents list,
	 * so check and free it up if we do.
	 */
	if (SCXFS_IFORK_FORMAT(ip, whichfork) == SCXFS_DINODE_FMT_LOCAL) {
		if (ifp->if_u1.if_data != NULL) {
			kmem_free(ifp->if_u1.if_data);
			ifp->if_u1.if_data = NULL;
		}
	} else if ((ifp->if_flags & SCXFS_IFEXTENTS) && ifp->if_height) {
		scxfs_iext_destroy(ifp);
	}

	if (whichfork == SCXFS_ATTR_FORK) {
		kmem_zone_free(scxfs_ifork_zone, ip->i_afp);
		ip->i_afp = NULL;
	} else if (whichfork == SCXFS_COW_FORK) {
		kmem_zone_free(scxfs_ifork_zone, ip->i_cowfp);
		ip->i_cowfp = NULL;
	}
}

/*
 * Convert in-core extents to on-disk form
 *
 * In the case of the data fork, the in-core and on-disk fork sizes can be
 * different due to delayed allocation extents. We only copy on-disk extents
 * here, so callers must always use the physical fork size to determine the
 * size of the buffer passed to this routine.  We will return the size actually
 * used.
 */
int
scxfs_iextents_copy(
	struct scxfs_inode	*ip,
	struct scxfs_bmbt_rec	*dp,
	int			whichfork)
{
	int			state = scxfs_bmap_fork_to_state(whichfork);
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_iext_cursor	icur;
	struct scxfs_bmbt_irec	rec;
	int64_t			copied = 0;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL | SCXFS_ILOCK_SHARED));
	ASSERT(ifp->if_bytes > 0);

	for_each_scxfs_iext(ifp, &icur, &rec) {
		if (isnullstartblock(rec.br_startblock))
			continue;
		ASSERT(scxfs_bmap_validate_extent(ip, whichfork, &rec) == NULL);
		scxfs_bmbt_disk_set_all(dp, &rec);
		trace_scxfs_write_extent(ip, &icur, state, _RET_IP_);
		copied += sizeof(struct scxfs_bmbt_rec);
		dp++;
	}

	ASSERT(copied > 0);
	ASSERT(copied <= ifp->if_bytes);
	return copied;
}

/*
 * Each of the following cases stores data into the same region
 * of the on-disk inode, so only one of them can be valid at
 * any given time. While it is possible to have conflicting formats
 * and log flags, e.g. having SCXFS_ILOG_?DATA set when the fork is
 * in EXTENTS format, this can only happen when the fork has
 * changed formats after being modified but before being flushed.
 * In these cases, the format always takes precedence, because the
 * format indicates the current state of the fork.
 */
void
scxfs_iflush_fork(
	scxfs_inode_t		*ip,
	scxfs_dinode_t		*dip,
	scxfs_inode_log_item_t	*iip,
	int			whichfork)
{
	char			*cp;
	struct scxfs_ifork	*ifp;
	scxfs_mount_t		*mp;
	static const short	brootflag[2] =
		{ SCXFS_ILOG_DBROOT, SCXFS_ILOG_ABROOT };
	static const short	dataflag[2] =
		{ SCXFS_ILOG_DDATA, SCXFS_ILOG_ADATA };
	static const short	extflag[2] =
		{ SCXFS_ILOG_DEXT, SCXFS_ILOG_AEXT };

	if (!iip)
		return;
	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	/*
	 * This can happen if we gave up in iformat in an error path,
	 * for the attribute fork.
	 */
	if (!ifp) {
		ASSERT(whichfork == SCXFS_ATTR_FORK);
		return;
	}
	cp = SCXFS_DFORK_PTR(dip, whichfork);
	mp = ip->i_mount;
	switch (SCXFS_IFORK_FORMAT(ip, whichfork)) {
	case SCXFS_DINODE_FMT_LOCAL:
		if ((iip->ili_fields & dataflag[whichfork]) &&
		    (ifp->if_bytes > 0)) {
			ASSERT(ifp->if_u1.if_data != NULL);
			ASSERT(ifp->if_bytes <= SCXFS_IFORK_SIZE(ip, whichfork));
			memcpy(cp, ifp->if_u1.if_data, ifp->if_bytes);
		}
		break;

	case SCXFS_DINODE_FMT_EXTENTS:
		ASSERT((ifp->if_flags & SCXFS_IFEXTENTS) ||
		       !(iip->ili_fields & extflag[whichfork]));
		if ((iip->ili_fields & extflag[whichfork]) &&
		    (ifp->if_bytes > 0)) {
			ASSERT(SCXFS_IFORK_NEXTENTS(ip, whichfork) > 0);
			(void)scxfs_iextents_copy(ip, (scxfs_bmbt_rec_t *)cp,
				whichfork);
		}
		break;

	case SCXFS_DINODE_FMT_BTREE:
		if ((iip->ili_fields & brootflag[whichfork]) &&
		    (ifp->if_broot_bytes > 0)) {
			ASSERT(ifp->if_broot != NULL);
			ASSERT(SCXFS_BMAP_BMDR_SPACE(ifp->if_broot) <=
			        SCXFS_IFORK_SIZE(ip, whichfork));
			scxfs_bmbt_to_bmdr(mp, ifp->if_broot, ifp->if_broot_bytes,
				(scxfs_bmdr_block_t *)cp,
				SCXFS_DFORK_SIZE(dip, mp, whichfork));
		}
		break;

	case SCXFS_DINODE_FMT_DEV:
		if (iip->ili_fields & SCXFS_ILOG_DEV) {
			ASSERT(whichfork == SCXFS_DATA_FORK);
			scxfs_dinode_put_rdev(dip,
					linux_to_scxfs_dev_t(VFS_I(ip)->i_rdev));
		}
		break;

	default:
		ASSERT(0);
		break;
	}
}

/* Convert bmap state flags to an inode fork. */
struct scxfs_ifork *
scxfs_iext_state_to_fork(
	struct scxfs_inode	*ip,
	int			state)
{
	if (state & BMAP_COWFORK)
		return ip->i_cowfp;
	else if (state & BMAP_ATTRFORK)
		return ip->i_afp;
	return &ip->i_df;
}

/*
 * Initialize an inode's copy-on-write fork.
 */
void
scxfs_ifork_init_cow(
	struct scxfs_inode	*ip)
{
	if (ip->i_cowfp)
		return;

	ip->i_cowfp = kmem_zone_zalloc(scxfs_ifork_zone,
				       KM_NOFS);
	ip->i_cowfp->if_flags = SCXFS_IFEXTENTS;
	ip->i_cformat = SCXFS_DINODE_FMT_EXTENTS;
	ip->i_cnextents = 0;
}

/* Default fork content verifiers. */
struct scxfs_ifork_ops scxfs_default_ifork_ops = {
	.verify_attr	= scxfs_attr_shortform_verify,
	.verify_dir	= scxfs_dir2_sf_verify,
	.verify_symlink	= scxfs_symlink_shortform_verify,
};

/* Verify the inline contents of the data fork of an inode. */
scxfs_failaddr_t
scxfs_ifork_verify_data(
	struct scxfs_inode	*ip,
	struct scxfs_ifork_ops	*ops)
{
	/* Non-local data fork, we're done. */
	if (ip->i_d.di_format != SCXFS_DINODE_FMT_LOCAL)
		return NULL;

	/* Check the inline data fork if there is one. */
	switch (VFS_I(ip)->i_mode & S_IFMT) {
	case S_IFDIR:
		return ops->verify_dir(ip);
	case S_IFLNK:
		return ops->verify_symlink(ip);
	default:
		return NULL;
	}
}

/* Verify the inline contents of the attr fork of an inode. */
scxfs_failaddr_t
scxfs_ifork_verify_attr(
	struct scxfs_inode	*ip,
	struct scxfs_ifork_ops	*ops)
{
	/* There has to be an attr fork allocated if aformat is local. */
	if (ip->i_d.di_aformat != SCXFS_DINODE_FMT_LOCAL)
		return NULL;
	if (!SCXFS_IFORK_PTR(ip, SCXFS_ATTR_FORK))
		return __this_address;
	return ops->verify_attr(ip);
}
