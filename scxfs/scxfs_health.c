// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trace.h"
#include "scxfs_health.h"

/*
 * Warn about metadata corruption that we detected but haven't fixed, and
 * make sure we're not sitting on anything that would get in the way of
 * recovery.
 */
void
scxfs_health_unmount(
	struct scxfs_mount	*mp)
{
	struct scxfs_perag	*pag;
	scxfs_agnumber_t		agno;
	unsigned int		sick = 0;
	unsigned int		checked = 0;
	bool			warn = false;

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return;

	/* Measure AG corruption levels. */
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		pag = scxfs_perag_get(mp, agno);
		scxfs_ag_measure_sickness(pag, &sick, &checked);
		if (sick) {
			trace_scxfs_ag_unfixed_corruption(mp, agno, sick);
			warn = true;
		}
		scxfs_perag_put(pag);
	}

	/* Measure realtime volume corruption levels. */
	scxfs_rt_measure_sickness(mp, &sick, &checked);
	if (sick) {
		trace_scxfs_rt_unfixed_corruption(mp, sick);
		warn = true;
	}

	/*
	 * Measure fs corruption and keep the sample around for the warning.
	 * See the note below for why we exempt FS_COUNTERS.
	 */
	scxfs_fs_measure_sickness(mp, &sick, &checked);
	if (sick & ~SCXFS_SICK_FS_COUNTERS) {
		trace_scxfs_fs_unfixed_corruption(mp, sick);
		warn = true;
	}

	if (warn) {
		scxfs_warn(mp,
"Uncorrected metadata errors detected; please run scxfs_repair.");

		/*
		 * We discovered uncorrected metadata problems at some point
		 * during this filesystem mount and have advised the
		 * administrator to run repair once the unmount completes.
		 *
		 * However, we must be careful -- when FSCOUNTERS are flagged
		 * unhealthy, the unmount procedure omits writing the clean
		 * unmount record to the log so that the next mount will run
		 * recovery and recompute the summary counters.  In other
		 * words, we leave a dirty log to get the counters fixed.
		 *
		 * Unfortunately, scxfs_repair cannot recover dirty logs, so if
		 * there were filesystem problems, FSCOUNTERS was flagged, and
		 * the administrator takes our advice to run scxfs_repair,
		 * they'll have to zap the log before repairing structures.
		 * We don't really want to encourage this, so we mark the
		 * FSCOUNTERS healthy so that a subsequent repair run won't see
		 * a dirty log.
		 */
		if (sick & SCXFS_SICK_FS_COUNTERS)
			scxfs_fs_mark_healthy(mp, SCXFS_SICK_FS_COUNTERS);
	}
}

/* Mark unhealthy per-fs metadata. */
void
scxfs_fs_mark_sick(
	struct scxfs_mount	*mp,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_FS_PRIMARY));
	trace_scxfs_fs_mark_sick(mp, mask);

	spin_lock(&mp->m_sb_lock);
	mp->m_fs_sick |= mask;
	mp->m_fs_checked |= mask;
	spin_unlock(&mp->m_sb_lock);
}

/* Mark a per-fs metadata healed. */
void
scxfs_fs_mark_healthy(
	struct scxfs_mount	*mp,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_FS_PRIMARY));
	trace_scxfs_fs_mark_healthy(mp, mask);

	spin_lock(&mp->m_sb_lock);
	mp->m_fs_sick &= ~mask;
	mp->m_fs_checked |= mask;
	spin_unlock(&mp->m_sb_lock);
}

/* Sample which per-fs metadata are unhealthy. */
void
scxfs_fs_measure_sickness(
	struct scxfs_mount	*mp,
	unsigned int		*sick,
	unsigned int		*checked)
{
	spin_lock(&mp->m_sb_lock);
	*sick = mp->m_fs_sick;
	*checked = mp->m_fs_checked;
	spin_unlock(&mp->m_sb_lock);
}

/* Mark unhealthy realtime metadata. */
void
scxfs_rt_mark_sick(
	struct scxfs_mount	*mp,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_RT_PRIMARY));
	trace_scxfs_rt_mark_sick(mp, mask);

	spin_lock(&mp->m_sb_lock);
	mp->m_rt_sick |= mask;
	mp->m_rt_checked |= mask;
	spin_unlock(&mp->m_sb_lock);
}

/* Mark a realtime metadata healed. */
void
scxfs_rt_mark_healthy(
	struct scxfs_mount	*mp,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_RT_PRIMARY));
	trace_scxfs_rt_mark_healthy(mp, mask);

	spin_lock(&mp->m_sb_lock);
	mp->m_rt_sick &= ~mask;
	mp->m_rt_checked |= mask;
	spin_unlock(&mp->m_sb_lock);
}

/* Sample which realtime metadata are unhealthy. */
void
scxfs_rt_measure_sickness(
	struct scxfs_mount	*mp,
	unsigned int		*sick,
	unsigned int		*checked)
{
	spin_lock(&mp->m_sb_lock);
	*sick = mp->m_rt_sick;
	*checked = mp->m_rt_checked;
	spin_unlock(&mp->m_sb_lock);
}

/* Mark unhealthy per-ag metadata. */
void
scxfs_ag_mark_sick(
	struct scxfs_perag	*pag,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_AG_PRIMARY));
	trace_scxfs_ag_mark_sick(pag->pag_mount, pag->pag_agno, mask);

	spin_lock(&pag->pag_state_lock);
	pag->pag_sick |= mask;
	pag->pag_checked |= mask;
	spin_unlock(&pag->pag_state_lock);
}

/* Mark per-ag metadata ok. */
void
scxfs_ag_mark_healthy(
	struct scxfs_perag	*pag,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_AG_PRIMARY));
	trace_scxfs_ag_mark_healthy(pag->pag_mount, pag->pag_agno, mask);

	spin_lock(&pag->pag_state_lock);
	pag->pag_sick &= ~mask;
	pag->pag_checked |= mask;
	spin_unlock(&pag->pag_state_lock);
}

/* Sample which per-ag metadata are unhealthy. */
void
scxfs_ag_measure_sickness(
	struct scxfs_perag	*pag,
	unsigned int		*sick,
	unsigned int		*checked)
{
	spin_lock(&pag->pag_state_lock);
	*sick = pag->pag_sick;
	*checked = pag->pag_checked;
	spin_unlock(&pag->pag_state_lock);
}

/* Mark the unhealthy parts of an inode. */
void
scxfs_inode_mark_sick(
	struct scxfs_inode	*ip,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_INO_PRIMARY));
	trace_scxfs_inode_mark_sick(ip, mask);

	spin_lock(&ip->i_flags_lock);
	ip->i_sick |= mask;
	ip->i_checked |= mask;
	spin_unlock(&ip->i_flags_lock);
}

/* Mark parts of an inode healed. */
void
scxfs_inode_mark_healthy(
	struct scxfs_inode	*ip,
	unsigned int		mask)
{
	ASSERT(!(mask & ~SCXFS_SICK_INO_PRIMARY));
	trace_scxfs_inode_mark_healthy(ip, mask);

	spin_lock(&ip->i_flags_lock);
	ip->i_sick &= ~mask;
	ip->i_checked |= mask;
	spin_unlock(&ip->i_flags_lock);
}

/* Sample which parts of an inode are unhealthy. */
void
scxfs_inode_measure_sickness(
	struct scxfs_inode	*ip,
	unsigned int		*sick,
	unsigned int		*checked)
{
	spin_lock(&ip->i_flags_lock);
	*sick = ip->i_sick;
	*checked = ip->i_checked;
	spin_unlock(&ip->i_flags_lock);
}

/* Mappings between internal sick masks and ioctl sick masks. */

struct ioctl_sick_map {
	unsigned int		sick_mask;
	unsigned int		ioctl_mask;
};

static const struct ioctl_sick_map fs_map[] = {
	{ SCXFS_SICK_FS_COUNTERS,	SCXFS_FSOP_GEOM_SICK_COUNTERS},
	{ SCXFS_SICK_FS_UQUOTA,	SCXFS_FSOP_GEOM_SICK_UQUOTA },
	{ SCXFS_SICK_FS_GQUOTA,	SCXFS_FSOP_GEOM_SICK_GQUOTA },
	{ SCXFS_SICK_FS_PQUOTA,	SCXFS_FSOP_GEOM_SICK_PQUOTA },
	{ 0, 0 },
};

static const struct ioctl_sick_map rt_map[] = {
	{ SCXFS_SICK_RT_BITMAP,	SCXFS_FSOP_GEOM_SICK_RT_BITMAP },
	{ SCXFS_SICK_RT_SUMMARY,	SCXFS_FSOP_GEOM_SICK_RT_SUMMARY },
	{ 0, 0 },
};

static inline void
xfgeo_health_tick(
	struct scxfs_fsop_geom		*geo,
	unsigned int			sick,
	unsigned int			checked,
	const struct ioctl_sick_map	*m)
{
	if (checked & m->sick_mask)
		geo->checked |= m->ioctl_mask;
	if (sick & m->sick_mask)
		geo->sick |= m->ioctl_mask;
}

/* Fill out fs geometry health info. */
void
scxfs_fsop_geom_health(
	struct scxfs_mount		*mp,
	struct scxfs_fsop_geom		*geo)
{
	const struct ioctl_sick_map	*m;
	unsigned int			sick;
	unsigned int			checked;

	geo->sick = 0;
	geo->checked = 0;

	scxfs_fs_measure_sickness(mp, &sick, &checked);
	for (m = fs_map; m->sick_mask; m++)
		xfgeo_health_tick(geo, sick, checked, m);

	scxfs_rt_measure_sickness(mp, &sick, &checked);
	for (m = rt_map; m->sick_mask; m++)
		xfgeo_health_tick(geo, sick, checked, m);
}

static const struct ioctl_sick_map ag_map[] = {
	{ SCXFS_SICK_AG_SB,	SCXFS_AG_GEOM_SICK_SB },
	{ SCXFS_SICK_AG_AGF,	SCXFS_AG_GEOM_SICK_AGF },
	{ SCXFS_SICK_AG_AGFL,	SCXFS_AG_GEOM_SICK_AGFL },
	{ SCXFS_SICK_AG_AGI,	SCXFS_AG_GEOM_SICK_AGI },
	{ SCXFS_SICK_AG_BNOBT,	SCXFS_AG_GEOM_SICK_BNOBT },
	{ SCXFS_SICK_AG_CNTBT,	SCXFS_AG_GEOM_SICK_CNTBT },
	{ SCXFS_SICK_AG_INOBT,	SCXFS_AG_GEOM_SICK_INOBT },
	{ SCXFS_SICK_AG_FINOBT,	SCXFS_AG_GEOM_SICK_FINOBT },
	{ SCXFS_SICK_AG_RMAPBT,	SCXFS_AG_GEOM_SICK_RMAPBT },
	{ SCXFS_SICK_AG_REFCNTBT,	SCXFS_AG_GEOM_SICK_REFCNTBT },
	{ 0, 0 },
};

/* Fill out ag geometry health info. */
void
scxfs_ag_geom_health(
	struct scxfs_perag		*pag,
	struct scxfs_ag_geometry		*ageo)
{
	const struct ioctl_sick_map	*m;
	unsigned int			sick;
	unsigned int			checked;

	ageo->ag_sick = 0;
	ageo->ag_checked = 0;

	scxfs_ag_measure_sickness(pag, &sick, &checked);
	for (m = ag_map; m->sick_mask; m++) {
		if (checked & m->sick_mask)
			ageo->ag_checked |= m->ioctl_mask;
		if (sick & m->sick_mask)
			ageo->ag_sick |= m->ioctl_mask;
	}
}

static const struct ioctl_sick_map ino_map[] = {
	{ SCXFS_SICK_INO_CORE,	SCXFS_BS_SICK_INODE },
	{ SCXFS_SICK_INO_BMBTD,	SCXFS_BS_SICK_BMBTD },
	{ SCXFS_SICK_INO_BMBTA,	SCXFS_BS_SICK_BMBTA },
	{ SCXFS_SICK_INO_BMBTC,	SCXFS_BS_SICK_BMBTC },
	{ SCXFS_SICK_INO_DIR,	SCXFS_BS_SICK_DIR },
	{ SCXFS_SICK_INO_XATTR,	SCXFS_BS_SICK_XATTR },
	{ SCXFS_SICK_INO_SYMLINK,	SCXFS_BS_SICK_SYMLINK },
	{ SCXFS_SICK_INO_PARENT,	SCXFS_BS_SICK_PARENT },
	{ 0, 0 },
};

/* Fill out bulkstat health info. */
void
scxfs_bulkstat_health(
	struct scxfs_inode		*ip,
	struct scxfs_bulkstat		*bs)
{
	const struct ioctl_sick_map	*m;
	unsigned int			sick;
	unsigned int			checked;

	bs->bs_sick = 0;
	bs->bs_checked = 0;

	scxfs_inode_measure_sickness(ip, &sick, &checked);
	for (m = ino_map; m->sick_mask; m++) {
		if (checked & m->sick_mask)
			bs->bs_checked |= m->ioctl_mask;
		if (sick & m->sick_mask)
			bs->bs_sick |= m->ioctl_mask;
	}
}
