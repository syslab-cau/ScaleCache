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
#include "scxfs_rtalloc.h"
#include "scxfs_inode.h"
#include "scrub/scrub.h"
#include "scrub/common.h"

/* Set us up with the realtime metadata locked. */
int
xchk_setup_rt(
	struct scxfs_scrub	*sc,
	struct scxfs_inode	*ip)
{
	int			error;

	error = xchk_setup_fs(sc, ip);
	if (error)
		return error;

	sc->ilock_flags = SCXFS_ILOCK_EXCL | SCXFS_ILOCK_RTBITMAP;
	sc->ip = sc->mp->m_rbmip;
	scxfs_ilock(sc->ip, sc->ilock_flags);

	return 0;
}

/* Realtime bitmap. */

/* Scrub a free extent record from the realtime bitmap. */
STATIC int
xchk_rtbitmap_rec(
	struct scxfs_trans	*tp,
	struct scxfs_rtalloc_rec	*rec,
	void			*priv)
{
	struct scxfs_scrub	*sc = priv;
	scxfs_rtblock_t		startblock;
	scxfs_rtblock_t		blockcount;

	startblock = rec->ar_startext * tp->t_mountp->m_sb.sb_rextsize;
	blockcount = rec->ar_extcount * tp->t_mountp->m_sb.sb_rextsize;

	if (startblock + blockcount <= startblock ||
	    !scxfs_verify_rtbno(sc->mp, startblock) ||
	    !scxfs_verify_rtbno(sc->mp, startblock + blockcount - 1))
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, 0);
	return 0;
}

/* Scrub the realtime bitmap. */
int
xchk_rtbitmap(
	struct scxfs_scrub	*sc)
{
	int			error;

	/* Invoke the fork scrubber. */
	error = xchk_metadata_inode_forks(sc);
	if (error || (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT))
		return error;

	error = scxfs_rtalloc_query_all(sc->tp, xchk_rtbitmap_rec, sc);
	if (!xchk_fblock_process_error(sc, SCXFS_DATA_FORK, 0, &error))
		goto out;

out:
	return error;
}

/* Scrub the realtime summary. */
int
xchk_rtsummary(
	struct scxfs_scrub	*sc)
{
	struct scxfs_inode	*rsumip = sc->mp->m_rsumip;
	struct scxfs_inode	*old_ip = sc->ip;
	uint			old_ilock_flags = sc->ilock_flags;
	int			error = 0;

	/*
	 * We ILOCK'd the rt bitmap ip in the setup routine, now lock the
	 * rt summary ip in compliance with the rt inode locking rules.
	 *
	 * Since we switch sc->ip to rsumip we have to save the old ilock
	 * flags so that we don't mix up the inode state that @sc tracks.
	 */
	sc->ip = rsumip;
	sc->ilock_flags = SCXFS_ILOCK_EXCL | SCXFS_ILOCK_RTSUM;
	scxfs_ilock(sc->ip, sc->ilock_flags);

	/* Invoke the fork scrubber. */
	error = xchk_metadata_inode_forks(sc);
	if (error || (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT))
		goto out;

	/* XXX: implement this some day */
	xchk_set_incomplete(sc);
out:
	/* Switch back to the rtbitmap inode and lock flags. */
	scxfs_iunlock(sc->ip, sc->ilock_flags);
	sc->ilock_flags = old_ilock_flags;
	sc->ip = old_ip;
	return error;
}


/* xref check that the extent is not free in the rtbitmap */
void
xchk_xref_is_used_rt_space(
	struct scxfs_scrub	*sc,
	scxfs_rtblock_t		fsbno,
	scxfs_extlen_t		len)
{
	scxfs_rtblock_t		startext;
	scxfs_rtblock_t		endext;
	scxfs_rtblock_t		extcount;
	bool			is_free;
	int			error;

	if (xchk_skip_xref(sc->sm))
		return;

	startext = fsbno;
	endext = fsbno + len - 1;
	do_div(startext, sc->mp->m_sb.sb_rextsize);
	do_div(endext, sc->mp->m_sb.sb_rextsize);
	extcount = endext - startext + 1;
	scxfs_ilock(sc->mp->m_rbmip, SCXFS_ILOCK_SHARED | SCXFS_ILOCK_RTBITMAP);
	error = scxfs_rtalloc_extent_is_free(sc->mp, sc->tp, startext, extcount,
			&is_free);
	if (!xchk_should_check_xref(sc, &error, NULL))
		goto out_unlock;
	if (is_free)
		xchk_ino_xref_set_corrupt(sc, sc->mp->m_rbmip->i_ino);
out_unlock:
	scxfs_iunlock(sc->mp->m_rbmip, SCXFS_ILOCK_SHARED | SCXFS_ILOCK_RTBITMAP);
}
