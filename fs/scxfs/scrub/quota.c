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
#include "scxfs_quota.h"
#include "scxfs_qm.h"
#include "scrub/scrub.h"
#include "scrub/common.h"

/* Convert a scrub type code to a DQ flag, or return 0 if error. */
static inline uint
xchk_quota_to_dqtype(
	struct scxfs_scrub	*sc)
{
	switch (sc->sm->sm_type) {
	case SCXFS_SCRUB_TYPE_UQUOTA:
		return SCXFS_DQ_USER;
	case SCXFS_SCRUB_TYPE_GQUOTA:
		return SCXFS_DQ_GROUP;
	case SCXFS_SCRUB_TYPE_PQUOTA:
		return SCXFS_DQ_PROJ;
	default:
		return 0;
	}
}

/* Set us up to scrub a quota. */
int
xchk_setup_quota(
	struct scxfs_scrub	*sc,
	struct scxfs_inode	*ip)
{
	uint			dqtype;
	int			error;

	if (!SCXFS_IS_QUOTA_RUNNING(sc->mp) || !SCXFS_IS_QUOTA_ON(sc->mp))
		return -ENOENT;

	dqtype = xchk_quota_to_dqtype(sc);
	if (dqtype == 0)
		return -EINVAL;
	sc->flags |= XCHK_HAS_QUOTAOFFLOCK;
	mutex_lock(&sc->mp->m_quotainfo->qi_quotaofflock);
	if (!scxfs_this_quota_on(sc->mp, dqtype))
		return -ENOENT;
	error = xchk_setup_fs(sc, ip);
	if (error)
		return error;
	sc->ip = scxfs_quota_inode(sc->mp, dqtype);
	scxfs_ilock(sc->ip, SCXFS_ILOCK_EXCL);
	sc->ilock_flags = SCXFS_ILOCK_EXCL;
	return 0;
}

/* Quotas. */

struct xchk_quota_info {
	struct scxfs_scrub	*sc;
	scxfs_dqid_t		last_id;
};

/* Scrub the fields in an individual quota item. */
STATIC int
xchk_quota_item(
	struct scxfs_dquot	*dq,
	uint			dqtype,
	void			*priv)
{
	struct xchk_quota_info	*sqi = priv;
	struct scxfs_scrub	*sc = sqi->sc;
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_disk_dquot	*d = &dq->q_core;
	struct scxfs_quotainfo	*qi = mp->m_quotainfo;
	scxfs_fileoff_t		offset;
	unsigned long long	bsoft;
	unsigned long long	isoft;
	unsigned long long	rsoft;
	unsigned long long	bhard;
	unsigned long long	ihard;
	unsigned long long	rhard;
	unsigned long long	bcount;
	unsigned long long	icount;
	unsigned long long	rcount;
	scxfs_ino_t		fs_icount;
	scxfs_dqid_t		id = be32_to_cpu(d->d_id);

	/*
	 * Except for the root dquot, the actual dquot we got must either have
	 * the same or higher id as we saw before.
	 */
	offset = id / qi->qi_dqperchunk;
	if (id && id <= sqi->last_id)
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, offset);

	sqi->last_id = id;

	/* Did we get the dquot type we wanted? */
	if (dqtype != (d->d_flags & SCXFS_DQ_ALLTYPES))
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, offset);

	if (d->d_pad0 != cpu_to_be32(0) || d->d_pad != cpu_to_be16(0))
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, offset);

	/* Check the limits. */
	bhard = be64_to_cpu(d->d_blk_hardlimit);
	ihard = be64_to_cpu(d->d_ino_hardlimit);
	rhard = be64_to_cpu(d->d_rtb_hardlimit);

	bsoft = be64_to_cpu(d->d_blk_softlimit);
	isoft = be64_to_cpu(d->d_ino_softlimit);
	rsoft = be64_to_cpu(d->d_rtb_softlimit);

	/*
	 * Warn if the hard limits are larger than the fs.
	 * Administrators can do this, though in production this seems
	 * suspect, which is why we flag it for review.
	 *
	 * Complain about corruption if the soft limit is greater than
	 * the hard limit.
	 */
	if (bhard > mp->m_sb.sb_dblocks)
		xchk_fblock_set_warning(sc, SCXFS_DATA_FORK, offset);
	if (bsoft > bhard)
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, offset);

	if (ihard > M_IGEO(mp)->maxicount)
		xchk_fblock_set_warning(sc, SCXFS_DATA_FORK, offset);
	if (isoft > ihard)
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, offset);

	if (rhard > mp->m_sb.sb_rblocks)
		xchk_fblock_set_warning(sc, SCXFS_DATA_FORK, offset);
	if (rsoft > rhard)
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, offset);

	/* Check the resource counts. */
	bcount = be64_to_cpu(d->d_bcount);
	icount = be64_to_cpu(d->d_icount);
	rcount = be64_to_cpu(d->d_rtbcount);
	fs_icount = percpu_counter_sum(&mp->m_icount);

	/*
	 * Check that usage doesn't exceed physical limits.  However, on
	 * a reflink filesystem we're allowed to exceed physical space
	 * if there are no quota limits.
	 */
	if (scxfs_sb_version_hasreflink(&mp->m_sb)) {
		if (mp->m_sb.sb_dblocks < bcount)
			xchk_fblock_set_warning(sc, SCXFS_DATA_FORK,
					offset);
	} else {
		if (mp->m_sb.sb_dblocks < bcount)
			xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK,
					offset);
	}
	if (icount > fs_icount || rcount > mp->m_sb.sb_rblocks)
		xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK, offset);

	/*
	 * We can violate the hard limits if the admin suddenly sets a
	 * lower limit than the actual usage.  However, we flag it for
	 * admin review.
	 */
	if (id != 0 && bhard != 0 && bcount > bhard)
		xchk_fblock_set_warning(sc, SCXFS_DATA_FORK, offset);
	if (id != 0 && ihard != 0 && icount > ihard)
		xchk_fblock_set_warning(sc, SCXFS_DATA_FORK, offset);
	if (id != 0 && rhard != 0 && rcount > rhard)
		xchk_fblock_set_warning(sc, SCXFS_DATA_FORK, offset);

	return 0;
}

/* Check the quota's data fork. */
STATIC int
xchk_quota_data_fork(
	struct scxfs_scrub	*sc)
{
	struct scxfs_bmbt_irec	irec = { 0 };
	struct scxfs_iext_cursor	icur;
	struct scxfs_quotainfo	*qi = sc->mp->m_quotainfo;
	struct scxfs_ifork	*ifp;
	scxfs_fileoff_t		max_dqid_off;
	int			error = 0;

	/* Invoke the fork scrubber. */
	error = xchk_metadata_inode_forks(sc);
	if (error || (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT))
		return error;

	/* Check for data fork problems that apply only to quota files. */
	max_dqid_off = ((scxfs_dqid_t)-1) / qi->qi_dqperchunk;
	ifp = SCXFS_IFORK_PTR(sc->ip, SCXFS_DATA_FORK);
	for_each_scxfs_iext(ifp, &icur, &irec) {
		if (xchk_should_terminate(sc, &error))
			break;
		/*
		 * delalloc extents or blocks mapped above the highest
		 * quota id shouldn't happen.
		 */
		if (isnullstartblock(irec.br_startblock) ||
		    irec.br_startoff > max_dqid_off ||
		    irec.br_startoff + irec.br_blockcount - 1 > max_dqid_off) {
			xchk_fblock_set_corrupt(sc, SCXFS_DATA_FORK,
					irec.br_startoff);
			break;
		}
	}

	return error;
}

/* Scrub all of a quota type's items. */
int
xchk_quota(
	struct scxfs_scrub	*sc)
{
	struct xchk_quota_info	sqi;
	struct scxfs_mount	*mp = sc->mp;
	struct scxfs_quotainfo	*qi = mp->m_quotainfo;
	uint			dqtype;
	int			error = 0;

	dqtype = xchk_quota_to_dqtype(sc);

	/* Look for problem extents. */
	error = xchk_quota_data_fork(sc);
	if (error)
		goto out;
	if (sc->sm->sm_flags & SCXFS_SCRUB_OFLAG_CORRUPT)
		goto out;

	/*
	 * Check all the quota items.  Now that we've checked the quota inode
	 * data fork we have to drop ILOCK_EXCL to use the regular dquot
	 * functions.
	 */
	scxfs_iunlock(sc->ip, sc->ilock_flags);
	sc->ilock_flags = 0;
	sqi.sc = sc;
	sqi.last_id = 0;
	error = scxfs_qm_dqiterate(mp, dqtype, xchk_quota_item, &sqi);
	sc->ilock_flags = SCXFS_ILOCK_EXCL;
	scxfs_ilock(sc->ip, sc->ilock_flags);
	if (!xchk_fblock_process_error(sc, SCXFS_DATA_FORK,
			sqi.last_id * qi->qi_dqperchunk, &error))
		goto out;

out:
	return error;
}
