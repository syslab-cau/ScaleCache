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
#include "scxfs_inode.h"
#include "scxfs_icache.h"
#include "scxfs_dir2.h"
#include "scxfs_dir2_priv.h"
#include "scrub/scrub.h"
#include "scrub/common.h"

/* Set us up to scrub parents. */
int
xchk_setup_parent(
	struct scxfs_scrub	*sc,
	struct scxfs_inode	*ip)
{
	return xchk_setup_inode_contents(sc, ip, 0);
}

/* Parent pointers */

/* Look for an entry in a parent pointing to this inode. */

struct xchk_parent_ctx {
	struct dir_context	dc;
	scxfs_ino_t		ino;
	scxfs_nlink_t		nlink;
};

/* Look for a single entry in a directory pointing to an inode. */
STATIC int
xchk_parent_actor(
	struct dir_context	*dc,
	const char		*name,
	int			namelen,
	loff_t			pos,
	u64			ino,
	unsigned		type)
{
	struct xchk_parent_ctx	*spc;

	spc = container_of(dc, struct xchk_parent_ctx, dc);
	if (spc->ino == ino)
		spc->nlink++;
	return 0;
}

/* Count the number of dentries in the parent dir that point to this inode. */
STATIC int
xchk_parent_count_parent_dentries(
	struct scxfs_scrub	*sc,
	struct scxfs_inode	*parent,
	scxfs_nlink_t		*nlink)
{
	struct xchk_parent_ctx	spc = {
		.dc.actor = xchk_parent_actor,
		.dc.pos = 0,
		.ino = sc->ip->i_ino,
		.nlink = 0,
	};
	size_t			bufsize;
	loff_t			oldpos;
	uint			lock_mode;
	int			error = 0;

	/*
	 * If there are any blocks, read-ahead block 0 as we're almost
	 * certain to have the next operation be a read there.  This is
	 * how we guarantee that the parent's extent map has been loaded,
	 * if there is one.
	 */
	lock_mode = scxfs_ilock_data_map_shared(parent);
	if (parent->i_d.di_nextents > 0)
		error = scxfs_dir3_data_readahead(parent, 0, -1);
	scxfs_iunlock(parent, lock_mode);
	if (error)
		return error;

	/*
	 * Iterate the parent dir to confirm that there is
	 * exactly one entry pointing back to the inode being
	 * scanned.
	 */
	bufsize = (size_t)min_t(loff_t, SCXFS_READDIR_BUFSIZE,
			parent->i_d.di_size);
	oldpos = 0;
	while (true) {
		error = scxfs_readdir(sc->tp, parent, &spc.dc, bufsize);
		if (error)
			goto out;
		if (oldpos == spc.dc.pos)
			break;
		oldpos = spc.dc.pos;
	}
	*nlink = spc.nlink;
out:
	return error;
}

/*
 * Given the inode number of the alleged parent of the inode being
 * scrubbed, try to validate that the parent has exactly one directory
 * entry pointing back to the inode being scrubbed.
 */
STATIC int
xchk_parent_validate(
	struct scxfs_scrub	*sc,
	scxfs_ino_t		dnum,
	bool			*try_again)
{
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_inode	*dp = NULL;
	scxfs_nlink_t		expected_nlink;
	scxfs_nlink_t		nlink;
	int			error = 0;

	*try_again = false;

	if (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT)
		goto out;

	/* '..' must not point to ourselves. */
	if (sc->ip->i_ino == dnum) {
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out;
	}

	/*
	 * If we're an unlinked directory, the parent /won't/ have a link
	 * to us.  Otherwise, it should have one link.
	 */
	expected_nlink = VFS_I(sc->ip)->i_nlink == 0 ? 0 : 1;

	/*
	 * Grab this parent inode.  We release the inode before we
	 * cancel the scrub transaction.  Since we're don't know a
	 * priori that releasing the inode won't trigger eofblocks
	 * cleanup (which allocates what would be a nested transaction)
	 * if the parent pointer erroneously points to a file, we
	 * can't use DONTCACHE here because DONTCACHE inodes can trigger
	 * immediate inactive cleanup of the inode.
	 *
	 * If _iget returns -EINVAL then the parent inode number is garbage
	 * and the directory is corrupt.  If the _iget returns -EFSCORRUPTED
	 * or -EFSBADCRC then the parent is corrupt which is a cross
	 * referencing error.  Any other error is an operational error.
	 */
	error = scxfs_iget(mp, sc->tp, dnum, SCXFS_IGET_UNTRUSTED, 0, &dp);
	if (error == -EINVAL) {
		error = -EFSCORRUPTED;
		xchk_fblock_process_error(sc, SCXFS_DATA_FORK, 0, &error);
		goto out;
	}
	if (!xchk_fblock_xref_process_error(sc, SCXFS_DATA_FORK, 0, &error))
		goto out;
	if (dp == sc->ip || !S_ISDIR(VFS_I(dp)->i_mode)) {
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out_rele;
	}

	/*
	 * We prefer to keep the inode locked while we lock and search
	 * its alleged parent for a forward reference.  If we can grab
	 * the iolock, validate the pointers and we're done.  We must
	 * use nowait here to avoid an ABBA deadlock on the parent and
	 * the child inodes.
	 */
	if (scxfs_ilock_nowait(dp, SCXFS_IOLOCK_SHARED)) {
		error = xchk_parent_count_parent_dentries(sc, dp, &nlink);
		if (!xchk_fblock_xref_process_error(sc, SCXFS_DATA_FORK, 0,
				&error))
			goto out_unlock;
		if (nlink != expected_nlink)
			xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out_unlock;
	}

	/*
	 * The game changes if we get here.  We failed to lock the parent,
	 * so we're going to try to verify both pointers while only holding
	 * one lock so as to avoid deadlocking with something that's actually
	 * trying to traverse down the directory tree.
	 */
	scxfs_iunlock(sc->ip, sc->ilock_flags);
	sc->ilock_flags = 0;
	error = xchk_ilock_inverted(dp, SCXFS_IOLOCK_SHARED);
	if (error)
		goto out_rele;

	/* Go looking for our dentry. */
	error = xchk_parent_count_parent_dentries(sc, dp, &nlink);
	if (!xchk_fblock_xref_process_error(sc, SCXFS_DATA_FORK, 0, &error))
		goto out_unlock;

	/* Drop the parent lock, relock this inode. */
	scxfs_iunlock(dp, SCXFS_IOLOCK_SHARED);
	error = xchk_ilock_inverted(sc->ip, SCXFS_IOLOCK_EXCL);
	if (error)
		goto out_rele;
	sc->ilock_flags = SCXFS_IOLOCK_EXCL;

	/*
	 * If we're an unlinked directory, the parent /won't/ have a link
	 * to us.  Otherwise, it should have one link.  We have to re-set
	 * it here because we dropped the lock on sc->ip.
	 */
	expected_nlink = VFS_I(sc->ip)->i_nlink == 0 ? 0 : 1;

	/* Look up '..' to see if the inode changed. */
	error = scxfs_dir_lookup(sc->tp, sc->ip, &scxfs_name_dotdot, &dnum, NULL);
	if (!xchk_fblock_process_error(sc, SCXFS_DATA_FORK, 0, &error))
		goto out_rele;

	/* Drat, parent changed.  Try again! */
	if (dnum != dp->i_ino) {
		scxfs_irele(dp);
		*try_again = true;
		return 0;
	}
	scxfs_irele(dp);

	/*
	 * '..' didn't change, so check that there was only one entry
	 * for us in the parent.
	 */
	if (nlink != expected_nlink)
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
	return error;

out_unlock:
	scxfs_iunlock(dp, SCXFS_IOLOCK_SHARED);
out_rele:
	scxfs_irele(dp);
out:
	return error;
}

/* Scrub a parent pointer. */
int
xchk_parent(
	struct scxfs_scrub	*sc)
{
	struct scxfs_mount	*mp = sc->mp;
	scxfs_ino_t		dnum;
	bool			try_again;
	int			tries = 0;
	int			error = 0;

	/*
	 * If we're a directory, check that the '..' link points up to
	 * a directory that has one entry pointing to us.
	 */
	if (!S_ISDIR(VFS_I(sc->ip)->i_mode))
		return -ENOENT;

	/* We're not a special inode, are we? */
	if (!scxfs_verify_dir_ino(mp, sc->ip->i_ino)) {
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out;
	}

	/*
	 * The VFS grabs a read or write lock via i_rwsem before it reads
	 * or writes to a directory.  If we've gotten this far we've
	 * already obtained IOLOCK_EXCL, which (since 4.10) is the same as
	 * getting a write lock on i_rwsem.  Therefore, it is safe for us
	 * to drop the ILOCK here in order to do directory lookups.
	 */
	sc->ilock_flags &= ~(SCXFS_ILOCK_EXCL | SCXFS_MMAPLOCK_EXCL);
	scxfs_iunlock(sc->ip, SCXFS_ILOCK_EXCL | SCXFS_MMAPLOCK_EXCL);

	/* Look up '..' */
	error = scxfs_dir_lookup(sc->tp, sc->ip, &scxfs_name_dotdot, &dnum, NULL);
	if (!xchk_fblock_process_error(sc, SCXFS_DATA_FORK, 0, &error))
		goto out;
	if (!scxfs_verify_dir_ino(mp, dnum)) {
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out;
	}

	/* Is this the root dir?  Then '..' must point to itself. */
	if (sc->ip == mp->m_rootip) {
		if (sc->ip->i_ino != mp->m_sb.sb_rootino ||
		    sc->ip->i_ino != dnum)
			xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out;
	}

	do {
		error = xchk_parent_validate(sc, dnum, &try_again);
		if (error)
			goto out;
	} while (try_again && ++tries < 20);

	/*
	 * We gave it our best shot but failed, so mark this scrub
	 * incomplete.  Userspace can decide if it wants to try again.
	 */
	if (try_again && tries == 20)
		xchk_set_incomplete(sc);
out:
	/*
	 * If we failed to lock the parent inode even after a retry, just mark
	 * this scrub incomplete and return.
	 */
	if ((sc->flags & XCHK_TRY_HARDER) && error == -EDEADLOCK) {
		error = 0;
		xchk_set_incomplete(sc);
	}
	return error;
}
