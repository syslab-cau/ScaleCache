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
#include "scxfs_symlink.h"
#include "scrub/scrub.h"
#include "scrub/common.h"

/* Set us up to scrub a symbolic link. */
int
xchk_setup_symlink(
	struct scxfs_scrub	*sc,
	struct scxfs_inode	*ip)
{
	/* Allocate the buffer without the inode lock held. */
	sc->buf = kmem_zalloc_large(SCXFS_SYMLINK_MAXLEN + 1, 0);
	if (!sc->buf)
		return -ENOMEM;

	return xchk_setup_inode_contents(sc, ip, 0);
}

/* Symbolic links. */

int
xchk_symlink(
	struct scxfs_scrub	*sc)
{
	struct scxfs_inode	*ip = sc->ip;
	struct scxfs_ifork	*ifp;
	loff_t			len;
	int			error = 0;

	if (!S_ISLNK(VFS_I(ip)->i_mode))
		return -ENOENT;
	ifp = SCXFS_IFORK_PTR(ip, SCXFS_DATA_FORK);
	len = ip->i_d.di_size;

	/* Plausible size? */
	if (len > SCXFS_SYMLINK_MAXLEN || len <= 0) {
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out;
	}

	/* Inline symlink? */
	if (ifp->if_flags & SCXFS_IFINLINE) {
		if (len > SCXFS_IFORK_DSIZE(ip) ||
		    len > strnlen(ifp->if_u1.if_data, SCXFS_IFORK_DSIZE(ip)))
			xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
		goto out;
	}

	/* Remote symlink; must read the contents. */
	error = scxfs_readlink_bmap_ilocked(sc->ip, sc->buf);
	if (!xchk_fblock_process_error(sc, SCXFS_DATA_FORK, 0, &error))
		goto out;
	if (strnlen(sc->buf, SCXFS_SYMLINK_MAXLEN) < len)
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
out:
	return error;
}
