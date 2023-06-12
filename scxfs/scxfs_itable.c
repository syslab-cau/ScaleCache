// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
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
#include "scxfs_btree.h"
#include "scxfs_ialloc.h"
#include "scxfs_ialloc_btree.h"
#include "scxfs_iwalk.h"
#include "scxfs_itable.h"
#include "scxfs_error.h"
#include "scxfs_icache.h"
#include "scxfs_health.h"

/*
 * Bulk Stat
 * =========
 *
 * Use the inode walking functions to fill out struct scxfs_bulkstat for every
 * allocated inode, then pass the stat information to some externally provided
 * iteration function.
 */

struct scxfs_bstat_chunk {
	bulkstat_one_fmt_pf	formatter;
	struct scxfs_ibulk	*breq;
	struct scxfs_bulkstat	*buf;
};

/*
 * Fill out the bulkstat info for a single inode and report it somewhere.
 *
 * bc->breq->lastino is effectively the inode cursor as we walk through the
 * filesystem.  Therefore, we update it any time we need to move the cursor
 * forward, regardless of whether or not we're sending any bstat information
 * back to userspace.  If the inode is internal metadata or, has been freed
 * out from under us, we just simply keep going.
 *
 * However, if any other type of error happens we want to stop right where we
 * are so that userspace will call back with exact number of the bad inode and
 * we can send back an error code.
 *
 * Note that if the formatter tells us there's no space left in the buffer we
 * move the cursor forward and abort the walk.
 */
STATIC int
scxfs_bulkstat_one_int(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_ino_t		ino,
	struct scxfs_bstat_chunk	*bc)
{
	struct scxfs_icdinode	*dic;		/* dinode core info pointer */
	struct scxfs_inode	*ip;		/* incore inode pointer */
	struct inode		*inode;
	struct scxfs_bulkstat	*buf = bc->buf;
	int			error = -EINVAL;

	if (scxfs_internal_inum(mp, ino))
		goto out_advance;

	error = scxfs_iget(mp, tp, ino,
			 (SCXFS_IGET_DONTCACHE | SCXFS_IGET_UNTRUSTED),
			 SCXFS_ILOCK_SHARED, &ip);
	if (error == -ENOENT || error == -EINVAL)
		goto out_advance;
	if (error)
		goto out;

	ASSERT(ip != NULL);
	ASSERT(ip->i_imap.im_blkno != 0);
	inode = VFS_I(ip);

	dic = &ip->i_d;

	/* scxfs_iget returns the following without needing
	 * further change.
	 */
	buf->bs_projectid = scxfs_get_projid(ip);
	buf->bs_ino = ino;
	buf->bs_uid = dic->di_uid;
	buf->bs_gid = dic->di_gid;
	buf->bs_size = dic->di_size;

	buf->bs_nlink = inode->i_nlink;
	buf->bs_atime = inode->i_atime.tv_sec;
	buf->bs_atime_nsec = inode->i_atime.tv_nsec;
	buf->bs_mtime = inode->i_mtime.tv_sec;
	buf->bs_mtime_nsec = inode->i_mtime.tv_nsec;
	buf->bs_ctime = inode->i_ctime.tv_sec;
	buf->bs_ctime_nsec = inode->i_ctime.tv_nsec;
	buf->bs_btime = dic->di_crtime.t_sec;
	buf->bs_btime_nsec = dic->di_crtime.t_nsec;
	buf->bs_gen = inode->i_generation;
	buf->bs_mode = inode->i_mode;

	buf->bs_xflags = scxfs_ip2xflags(ip);
	buf->bs_extsize_blks = dic->di_extsize;
	buf->bs_extents = dic->di_nextents;
	scxfs_bulkstat_health(ip, buf);
	buf->bs_aextents = dic->di_anextents;
	buf->bs_forkoff = SCXFS_IFORK_BOFF(ip);
	buf->bs_version = SCXFS_BULKSTAT_VERSION_V5;

	if (dic->di_version == 3) {
		if (dic->di_flags2 & SCXFS_DIFLAG2_COWEXTSIZE)
			buf->bs_cowextsize_blks = dic->di_cowextsize;
	}

	switch (dic->di_format) {
	case SCXFS_DINODE_FMT_DEV:
		buf->bs_rdev = sysv_encode_dev(inode->i_rdev);
		buf->bs_blksize = BLKDEV_IOSIZE;
		buf->bs_blocks = 0;
		break;
	case SCXFS_DINODE_FMT_LOCAL:
		buf->bs_rdev = 0;
		buf->bs_blksize = mp->m_sb.sb_blocksize;
		buf->bs_blocks = 0;
		break;
	case SCXFS_DINODE_FMT_EXTENTS:
	case SCXFS_DINODE_FMT_BTREE:
		buf->bs_rdev = 0;
		buf->bs_blksize = mp->m_sb.sb_blocksize;
		buf->bs_blocks = dic->di_nblocks + ip->i_delayed_blks;
		break;
	}
	scxfs_iunlock(ip, SCXFS_ILOCK_SHARED);
	scxfs_irele(ip);

	error = bc->formatter(bc->breq, buf);
	if (error == -ECANCELED)
		goto out_advance;
	if (error)
		goto out;

out_advance:
	/*
	 * Advance the cursor to the inode that comes after the one we just
	 * looked at.  We want the caller to move along if the bulkstat
	 * information was copied successfully; if we tried to grab the inode
	 * but it's no longer allocated; or if it's internal metadata.
	 */
	bc->breq->startino = ino + 1;
out:
	return error;
}

/* Bulkstat a single inode. */
int
scxfs_bulkstat_one(
	struct scxfs_ibulk	*breq,
	bulkstat_one_fmt_pf	formatter)
{
	struct scxfs_bstat_chunk	bc = {
		.formatter	= formatter,
		.breq		= breq,
	};
	int			error;

	ASSERT(breq->icount == 1);

	bc.buf = kmem_zalloc(sizeof(struct scxfs_bulkstat),
			KM_MAYFAIL);
	if (!bc.buf)
		return -ENOMEM;

	error = scxfs_bulkstat_one_int(breq->mp, NULL, breq->startino, &bc);

	kmem_free(bc.buf);

	/*
	 * If we reported one inode to userspace then we abort because we hit
	 * the end of the buffer.  Don't leak that back to userspace.
	 */
	if (error == -ECANCELED)
		error = 0;

	return error;
}

static int
scxfs_bulkstat_iwalk(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_ino_t		ino,
	void			*data)
{
	int			error;

	error = scxfs_bulkstat_one_int(mp, tp, ino, data);
	/* bulkstat just skips over missing inodes */
	if (error == -ENOENT || error == -EINVAL)
		return 0;
	return error;
}

/*
 * Check the incoming lastino parameter.
 *
 * We allow any inode value that could map to physical space inside the
 * filesystem because if there are no inodes there, bulkstat moves on to the
 * next chunk.  In other words, the magic agino value of zero takes us to the
 * first chunk in the AG, and an agino value past the end of the AG takes us to
 * the first chunk in the next AG.
 *
 * Therefore we can end early if the requested inode is beyond the end of the
 * filesystem or doesn't map properly.
 */
static inline bool
scxfs_bulkstat_already_done(
	struct scxfs_mount	*mp,
	scxfs_ino_t		startino)
{
	scxfs_agnumber_t		agno = SCXFS_INO_TO_AGNO(mp, startino);
	scxfs_agino_t		agino = SCXFS_INO_TO_AGINO(mp, startino);

	return agno >= mp->m_sb.sb_agcount ||
	       startino != SCXFS_AGINO_TO_INO(mp, agno, agino);
}

/* Return stat information in bulk (by-inode) for the filesystem. */
int
scxfs_bulkstat(
	struct scxfs_ibulk	*breq,
	bulkstat_one_fmt_pf	formatter)
{
	struct scxfs_bstat_chunk	bc = {
		.formatter	= formatter,
		.breq		= breq,
	};
	int			error;

	if (scxfs_bulkstat_already_done(breq->mp, breq->startino))
		return 0;

	bc.buf = kmem_zalloc(sizeof(struct scxfs_bulkstat),
			KM_MAYFAIL);
	if (!bc.buf)
		return -ENOMEM;

	error = scxfs_iwalk(breq->mp, NULL, breq->startino, breq->flags,
			scxfs_bulkstat_iwalk, breq->icount, &bc);

	kmem_free(bc.buf);

	/*
	 * We found some inodes, so clear the error status and return them.
	 * The lastino pointer will point directly at the inode that triggered
	 * any error that occurred, so on the next call the error will be
	 * triggered again and propagated to userspace as there will be no
	 * formatted inodes in the buffer.
	 */
	if (breq->ocount > 0)
		error = 0;

	return error;
}

/* Convert bulkstat (v5) to bstat (v1). */
void
scxfs_bulkstat_to_bstat(
	struct scxfs_mount		*mp,
	struct scxfs_bstat		*bs1,
	const struct scxfs_bulkstat	*bstat)
{
	/* memset is needed here because of padding holes in the structure. */
	memset(bs1, 0, sizeof(struct scxfs_bstat));
	bs1->bs_ino = bstat->bs_ino;
	bs1->bs_mode = bstat->bs_mode;
	bs1->bs_nlink = bstat->bs_nlink;
	bs1->bs_uid = bstat->bs_uid;
	bs1->bs_gid = bstat->bs_gid;
	bs1->bs_rdev = bstat->bs_rdev;
	bs1->bs_blksize = bstat->bs_blksize;
	bs1->bs_size = bstat->bs_size;
	bs1->bs_atime.tv_sec = bstat->bs_atime;
	bs1->bs_mtime.tv_sec = bstat->bs_mtime;
	bs1->bs_ctime.tv_sec = bstat->bs_ctime;
	bs1->bs_atime.tv_nsec = bstat->bs_atime_nsec;
	bs1->bs_mtime.tv_nsec = bstat->bs_mtime_nsec;
	bs1->bs_ctime.tv_nsec = bstat->bs_ctime_nsec;
	bs1->bs_blocks = bstat->bs_blocks;
	bs1->bs_xflags = bstat->bs_xflags;
	bs1->bs_extsize = SCXFS_FSB_TO_B(mp, bstat->bs_extsize_blks);
	bs1->bs_extents = bstat->bs_extents;
	bs1->bs_gen = bstat->bs_gen;
	bs1->bs_projid_lo = bstat->bs_projectid & 0xFFFF;
	bs1->bs_forkoff = bstat->bs_forkoff;
	bs1->bs_projid_hi = bstat->bs_projectid >> 16;
	bs1->bs_sick = bstat->bs_sick;
	bs1->bs_checked = bstat->bs_checked;
	bs1->bs_cowextsize = SCXFS_FSB_TO_B(mp, bstat->bs_cowextsize_blks);
	bs1->bs_dmevmask = 0;
	bs1->bs_dmstate = 0;
	bs1->bs_aextents = bstat->bs_aextents;
}

struct scxfs_inumbers_chunk {
	inumbers_fmt_pf		formatter;
	struct scxfs_ibulk	*breq;
};

/*
 * INUMBERS
 * ========
 * This is how we export inode btree records to userspace, so that SCXFS tools
 * can figure out where inodes are allocated.
 */

/*
 * Format the inode group structure and report it somewhere.
 *
 * Similar to scxfs_bulkstat_one_int, lastino is the inode cursor as we walk
 * through the filesystem so we move it forward unless there was a runtime
 * error.  If the formatter tells us the buffer is now full we also move the
 * cursor forward and abort the walk.
 */
STATIC int
scxfs_inumbers_walk(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	const struct scxfs_inobt_rec_incore *irec,
	void			*data)
{
	struct scxfs_inumbers	inogrp = {
		.xi_startino	= SCXFS_AGINO_TO_INO(mp, agno, irec->ir_startino),
		.xi_alloccount	= irec->ir_count - irec->ir_freecount,
		.xi_allocmask	= ~irec->ir_free,
		.xi_version	= SCXFS_INUMBERS_VERSION_V5,
	};
	struct scxfs_inumbers_chunk *ic = data;
	int			error;

	error = ic->formatter(ic->breq, &inogrp);
	if (error && error != -ECANCELED)
		return error;

	ic->breq->startino = SCXFS_AGINO_TO_INO(mp, agno, irec->ir_startino) +
			SCXFS_INODES_PER_CHUNK;
	return error;
}

/*
 * Return inode number table for the filesystem.
 */
int
scxfs_inumbers(
	struct scxfs_ibulk	*breq,
	inumbers_fmt_pf		formatter)
{
	struct scxfs_inumbers_chunk ic = {
		.formatter	= formatter,
		.breq		= breq,
	};
	int			error = 0;

	if (scxfs_bulkstat_already_done(breq->mp, breq->startino))
		return 0;

	error = scxfs_inobt_walk(breq->mp, NULL, breq->startino, breq->flags,
			scxfs_inumbers_walk, breq->icount, &ic);

	/*
	 * We found some inode groups, so clear the error status and return
	 * them.  The lastino pointer will point directly at the inode that
	 * triggered any error that occurred, so on the next call the error
	 * will be triggered again and propagated to userspace as there will be
	 * no formatted inode groups in the buffer.
	 */
	if (breq->ocount > 0)
		error = 0;

	return error;
}

/* Convert an inumbers (v5) struct to a inogrp (v1) struct. */
void
scxfs_inumbers_to_inogrp(
	struct scxfs_inogrp		*ig1,
	const struct scxfs_inumbers	*ig)
{
	/* memset is needed here because of padding holes in the structure. */
	memset(ig1, 0, sizeof(struct scxfs_inogrp));
	ig1->xi_startino = ig->xi_startino;
	ig1->xi_alloccount = ig->xi_alloccount;
	ig1->xi_allocmask = ig->xi_allocmask;
}
